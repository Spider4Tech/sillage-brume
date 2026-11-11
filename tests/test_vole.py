# -*- coding: utf-8 -*-
"""Sillage-SIG v0.5 (VOLE-in-the-Head, sillage/c/vole.c) par son API publique (sillage.h, sillage_c.py, SillageVOLE).

1. Tailles : celles des profils (SPEC § 4 bis), pk = graine ‖ y, sk = pk ‖ positions.
2. Conformité au prototype : avec l'aléa déterministe du KAT (sl_vole_kat), keygen puis signature de « kat » redonnent les
   empreintes de prototypes/vole/vole_kat.h (SHAKE256(pk ‖ σ), 16 octets) pour les quatre profils. La bibliothèque et le
   banc d'essai partagent la source (vole.c inclus par vole_proto.c) : ce contrôle vérifie l'API (encodages de pk et sk,
   ordre des tirages) et le gel du format.
3. Fonctionnement : signatures valides acceptées ; sel imposé déterministe (même sel et même message → même signature,
   autre message → autre signature) ; altérations (premier et dernier octet, octets au hasard), autre message, autre clé,
   longueurs invalides (0, ±1, double), pk de mauvaise taille, profil invalide : tout est rejeté ou refusé.
Les contrôles cryptographiques (attaques, théorèmes, SUF, liaison, injection d'échecs) sont dans c:vole_proto, ctgrind dans
c_vole_valgrind, dudect dans c_vole_temps.
"""
import hashlib
import os
import random
import re

from tests.commun import RACINE, sauver
from sillage import sillage_c as C
from sillage import SillageVOLE

ATTENDU = {"VOLE-128": (106, 182, 4235), "VOLE-256": (211, 363, 16122), "VOLE-128f": (106, 182, 5193), "VOLE-256f": (211, 363, 20467)}
ORDRE_KAT = ["VOLE-128", "VOLE-256", None, "VOLE-128f", "VOLE-256f"]      # ordre de vole_kat.h (None : modèle réduit)


def kat_prototype():
    t = open(os.path.join(RACINE, "prototypes", "vole", "vole_kat.h"), encoding="utf-8").read()
    vals = re.findall(r'"([0-9a-f]{32})"', t)
    return {p: v for p, v in zip(ORDRE_KAT, vals) if p}


def empreinte(profil):
    C.vole_kat(1, 0)
    try:
        pk, sk = C.vole_keygen(profil)
        sig = C.vole_sign(profil, sk, b"kat")
    finally:
        C.vole_kat(0)
    return hashlib.shake_256(pk + sig).hexdigest(16)


def run():
    c, m = {}, {}
    rng = random.Random(0x5EED)
    kat = kat_prototype()
    m["empreintes"] = {}
    ok_t = ok_k = True
    for profil, (lpk, lsk, lsig) in ATTENDU.items():
        t = C.vole_tailles(profil)
        ok_t &= (t["pk"], t["sk"], t["sig"]) == (lpk, lsk, lsig)
        e = empreinte(profil)
        m["empreintes"][profil] = e
        ok_k &= e == kat[profil]
    c["tailles_des_quatre_profils"] = ok_t
    c["kat_egaux_au_prototype_quatre_profils"] = ok_k
    for profil in ("VOLE-128", "VOLE-128f", "VOLE-256f", "VOLE-256"):
        S = SillageVOLE(profil)
        pk, sk = S.keygen()
        msg = b"message de test v0.5"
        sig = S.sign(sk, msg)
        bon = S.verify(pk, msg, sig)
        sel = bytes(range(32))
        s1, s2, s3 = S.sign(sk, msg, sel), S.sign(sk, msg, sel), S.sign(sk, b"autre", sel)
        det = s1 == s2 and s1 != s3 and S.verify(pk, msg, s1) and S.verify(pk, b"autre", s3)
        rej = 0
        essais = [0, len(sig) - 1] + [rng.randrange(len(sig)) for _ in range(14)]
        for i in essais:
            b = bytearray(sig)
            b[i] ^= 1 << rng.randrange(8)
            rej += not S.verify(pk, msg, bytes(b))
        pk2, _ = S.keygen()
        longueurs = [b"", sig[:-1], sig + b"\0", sig + sig, sig[:len(sig) // 2]]
        refus = (not S.verify(pk, b"message de test v0.4", sig) and not S.verify(pk2, msg, sig)
                 and all(not S.verify(pk, msg, x) for x in longueurs)
                 and not S.verify(pk[:-1], msg, sig) and not S.verify(pk + b"\0", msg, sig))
        c[f"{profil}_signature_valide_acceptee"] = bon
        c[f"{profil}_sel_impose_deterministe"] = det
        c[f"{profil}_alterations_rejetees"] = rej == len(essais)
        c[f"{profil}_autre_message_autre_cle_longueurs_invalides_rejetes"] = refus
    # profil invalide et tailles de sk incorrectes : refusés sans lecture hors limites
    try:
        SillageVOLE("VOLE-512")
        c["profil_inconnu_refuse"] = False
    except ValueError:
        c["profil_inconnu_refuse"] = True
    c["profil_c_invalide_refuse"] = (C.lib().sl_vole_keygen(7, C._buf(512), C._buf(512)) == -1
                                     and C.lib().sl_vole_verify(-1, C._buf(512), b"", C._sz(0), C._buf(8), C._sz(8)) == 0)
    try:
        C.vole_sign("VOLE-128", b"\0" * 10, b"m")
        c["sk_de_mauvaise_taille_refusee"] = False
    except ValueError:
        c["sk_de_mauvaise_taille_refusee"] = True
    out = {"controles": c, "mesures": m}
    sauver("vole", out)
    return out


if __name__ == "__main__":
    r = run()
    print(r["controles"])
