# -*- coding: utf-8 -*-
"""API publique (sillage/rapide.py, servie par le C) contre les classes de référence
Python : interopérabilité dans les deux sens, mêmes erreurs sur entrées malformées ; repli
de la borne δ quand une fenêtre compte ≥ 16 bits ; estimateur ISD en C contre sa référence."""
import os
from concurrent.futures import ThreadPoolExecutor

from tests.commun import sauver
import sillage
from sillage import sillage_common as SC
from sillage.brume512 import Brume512 as RefB, brume512_hash as ref_hash, brume512_hash_arbre as ref_arbre
from sillage.sillage_kem import SillageKEM as RefK, borne_echec_log2
from sillage.sillage_sig import SillageSIG as RefS
from sillage import sillage_c as C


def _leve(exc, f, *a):
    try:
        f(*a)
        return False
    except exc:
        return True


def kem(c, lvl):
    A, R = sillage.SillageKEM(lvl), RefK(lvl)
    pk, sk = A.keygen()
    ct, ss = A.encaps(pk)
    c[f"{lvl}_aller_retour"] = A.decaps(sk, ct) == ss
    c[f"{lvl}_ref_lit_c"] = R.decaps(sk, ct) == ss
    ct2, ss2 = R.encaps(pk)
    c[f"{lvl}_c_lit_ref"] = A.decaps(sk, ct2) == ss2
    pk3, sk3 = R.keygen()
    ct3, ss3 = A.encaps(pk3)
    c[f"{lvl}_cle_ref"] = A.decaps(sk3, ct3) == ss3 == R.decaps(sk3, ct3)
    u, v = ct
    n = A.p["n"]
    malformes = [(u ^ 1, v), (u, v ^ 1), (u | 1 << (n + 5), v), (-u - 1, v), (u, v | 1 << A.p["n2"]), (0, 0)]
    c[f"{lvl}_rejet_implicite_identique"] = all(A.decaps(sk, m) == R.decaps(sk, m) != ss for m in malformes)
    c[f"{lvl}_sans_cascade_reference"] = (lambda a: (lambda p, s: (lambda t, z: a.decaps(s, t) == z)(*a.encaps(p)))(*a.keygen()))(
        sillage.SillageKEM(lvl, cascade=False))
    return sk


def sig(c, lvl):
    A, R = sillage.SillageSIG(lvl), RefS(lvl)
    pk, sk = A.keygen()
    s = A.sign(sk, pk, b"m")
    c[f"{lvl}_aller_retour"] = A.verify(pk, b"m", s) and not A.verify(pk, b"n", s)
    c[f"{lvl}_ref_lit_c"] = R.verify(pk, b"m", s)
    s2 = R.sign(sk, pk, b"m")
    c[f"{lvl}_sel_impose_identique"] = A.sign(sk, pk, b"m", bytes(32)) == R.sign(sk, pk, b"m", bytes(32))
    c[f"{lvl}_c_lit_ref"] = A.verify(pk, b"m", s2)
    alteree = bytearray(s)
    alteree[len(s) // 2] ^= 1
    c[f"{lvl}_rejets"] = not (A.verify(pk, b"m", bytes(alteree)) or A.verify(pk, b"m", s[:-1])
                              or A.verify(pk, b"m", b"") or A.verify(pk, b"m", bytes(len(s))))


def brume(c):
    for prof in ("BRUME-512", "BRUME-512-256"):
        cle, no = os.urandom(64), os.urandom(24)
        A, R = sillage.Brume512(prof, key=cle), RefB(prof, key=cle)
        pt, aad = os.urandom(1000), b"aad"
        ct, tag = A.encrypt(no, pt, aad)
        c[f"{prof}_meme_chiffre"] = (ct, tag) == R.encrypt(no, pt, aad)
        c[f"{prof}_dechiffre"] = A.decrypt(no, ct, tag, aad) == pt
        c[f"{prof}_rejets"] = (_leve(sillage.Brume512TagError, A.decrypt, no, ct, tag[:-1], aad)
                               and _leve(sillage.Brume512TagError, A.decrypt, no, ct, bytes(len(tag)), aad)
                               and _leve(ValueError, A.encrypt, no[:-1], pt))
        t = A.encrypt_te(no, pt, aad)
        c[f"{prof}_te_identique"] = t == R.encrypt_te(no, pt, aad)
        ct2, par, tag2, meta = t
        err = bytearray(ct2)
        err[3] ^= 0x5A
        pa, co = A.decrypt_te(no, bytes(err), par, tag2, meta, aad)
        pb, cb = R.decrypt_te(no, bytes(err), par, tag2, meta, aad)
        c[f"{prof}_te_correction"] = pa == pt == pb and co == cb
        err[4] ^= 0x33
        c[f"{prof}_te_alteration_multiple"] = _leve(sillage.Brume512TamperError, A.decrypt_te, no, bytes(err), par, tag2, meta, aad)
        c[f"{prof}_te_meta"] = _leve(sillage.Brume512TamperError, A.decrypt_te, no, ct2, par, tag2, meta[:-1], aad)
    m = os.urandom(5000)
    c["hachage_identique"] = sillage.brume512_hash(m, 100) == ref_hash(m, 100)
    c["hachage_arbre_identique"] = sillage.brume512_hash_arbre(m, 64) == ref_arbre(m, 64)
    c["hachage_tours_reduits_reference"] = sillage.brume512_hash(m[:64], 32, 3) == ref_hash(m[:64], 32, 3)


def borne(c, m, sk128):
    """Clé ordinaire, et vecteurs groupés : c > 15 sur un hyperplan, borne nulle des deux côtés."""
    R = RefK("Sillage-128")
    p, nb = R.p, (R.p["n"] + 7) // 8
    x, y = sk128[0], sk128[1]
    ecarts = [abs(C.kem_borne("Sillage-128", a.to_bytes(nb, "little"), b.to_bytes(nb, "little"))
                  - borne_echec_log2(a, b, p))
              for a, b in ((x, y), ((1 << 40) - 1 | x, y), (x, ((1 << 15) - 1) << 1000 | y), (((1 << 64) - 1) << 40000, y))]
    m["borne_ecarts"] = ecarts
    c["borne_conforme_et_cles_groupees_rejetees"] = max(ecarts) < 1e-6


def isd(c, m):
    ecart = 0.0
    for a in ((3400, 1700, 170), (6800, 3400, 340), (136118, 68059, 148), (488086, 244043, 278), (1000, 500, 60)):
        n, k, w = a
        t = (lambda l: k, lambda l: k + l)
        for dumer in (False, True):
            ref = SC._deux_listes(n, k, w, t[dumer], 400, 1000)
            ecart = max(ecart, abs(C.isd_deux_listes(n, k, w, dumer, 400, 1000)[0] - ref[0]))
            ref = SC._deux_listes(n, k, w, t[dumer], 400, 1000, lambda L: SC.EXPOSANT_WALK_LISTE * L)
            ecart = max(ecart, abs(C.isd_deux_listes(n, k, w, dumer, 400, 1000, SC.EXPOSANT_WALK_LISTE)[0] - ref[0]))
        ecart = max(ecart, abs(C.isd_bjmm(n, k, w, 400, 100, 1500)[0] - SC._bjmm_ref(n, k, w)[0]))
        pr = SC._lb(n, w) - SC._lb(n - k, w)
        dep = pr / 2 + SC._gauss(n, k)
        ecart = max(ecart, abs(C.isd_bjmm_quantique(n, k, w, SC.EXPOSANT_WALK_BJMM, dep) - SC._bjmm_quantique_ref(n, k, w, dep)))
    m["isd_ecart_max_bits"] = ecart
    c["isd_c_conforme_a_la_reference"] = ecart < 1e-7


def concurrence(c):
    """Threads Python (le GIL est relâché pendant les appels C) sur des clés différentes :
    les caches du C sont par thread."""
    def travail(i):
        K, S = sillage.SillageKEM("Sillage-128"), sillage.SillageSIG("Sillage-SIG-128")
        ok = True
        for _ in range(6):
            pk, sk = K.keygen()
            ct, ss = K.encaps(pk)
            ok &= K.decaps(sk, ct) == ss
            pks, sks = S.keygen()
            ok &= S.verify(pks, b"m", S.sign(sks, pks, b"m"))
        return ok
    with ThreadPoolExecutor(8) as ex:
        c["appels_concurrents"] = all(ex.map(travail, range(8)))


def run():
    c, m = {}, {}
    concurrence(c)
    sk = kem(c, "Sillage-128")
    kem(c, "Sillage-256")
    sig(c, "Sillage-SIG-128")
    sig(c, "Sillage-SIG-256")
    brume(c)
    borne(c, m, sk)
    isd(c, m)
    out = {"controles": {k: bool(v) for k, v in c.items()}, "mesures": m}
    sauver("api_c", out)
    return out


if __name__ == "__main__":
    print(run())
