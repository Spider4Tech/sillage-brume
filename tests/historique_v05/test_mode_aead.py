# -*- coding: utf-8 -*-
"""Vérification mécanique du modèle de preuve du mode AEAD (docs/PROOFS.md,
§ 4.3).

La preuve modélise BRUME-AEAD comme un duplex à clé ABSORBANT LE CHIFFRÉ :
une suite d'appels  Z ← débit(S) ; S ← P(S ⊕ (σ ‖ 0) ⊕ dom·e_127)  dont
les entrées (σ, dom) sont données par la fonction de codage `chemin`
(Lemme 2), le flux d'un bloc étant le débit lu avant son absorption. Ce
test vérifie que :
  1. ce modèle abstrait, écrit indépendamment de brume512.py à partir de la
     preuve, redonne EXACTEMENT les chiffrés et les tags de Brume512 (les
     deux profils, longueurs variées) — Lemme 1 : « débit remplacé par le
     clair » ≡ « débit XOR chiffré » ;
  2. `chemin` est injective en (nonce, AAD, chiffré) et sans préfixe
     (aucun chemin complet n'est préfixe strict d'un autre) — Lemme 2 ;
  3. un déchiffrement refusé ne libère aucun clair (hypothèse « pas de
     RUP » de la preuve).
"""
import itertools
import os

import numpy as np

from tests.commun import sauver
from sillage import brume512 as B
from sillage.brume512 import Brume512, Brume512TagError

PROFILS = {"BRUME-512": (32, 16, 128), "BRUME-512-256": (16, 32, 256)}   # débit (o), tag (o), λ
DOM_AAD, DOM_TEXTE, DOM_FINAL = 1, 2, 4


def _pad(d, rb):
    """d ‖ 0x01 ‖ 0* découpé en blocs de rb octets (au moins un bloc)."""
    d = d + b"\x01" + b"\x00" * ((-len(d) - 1) % rb)
    return [d[i:i + rb] for i in range(0, len(d), rb)]


def chemin(profil, cle, nonce, aad, ct):
    """Lemme 2 : suite des entrées (σ, dom) du duplex pour (clé, nonce, AAD,
    chiffré). Les appels de données absorbent le CHIFFRÉ."""
    rb = PROFILS[profil][0]
    seq = []
    blocs = _pad(cle + nonce, rb)
    seq += [(b, 0) for b in blocs]
    a = _pad(aad, rb)
    seq += [(b, 0) for b in a[:-1]] + [(a[-1], DOM_AAD)]
    seq += [(b, 0) for b in _pad(ct, rb)]
    seq.append((b"\x00" * rb, DOM_TEXTE))
    seq.append((_pad(len(ct).to_bytes(8, "little"), rb)[0], DOM_FINAL))
    return seq


class Duplex:
    """S ← P(S ⊕ σ ‖ 0 ⊕ dom·e_127) ; débit lu avant chaque absorption."""

    def __init__(self, profil):
        self.rb, tl, lam = PROFILS[profil]
        etat = bytearray(64)
        etat[60:64] = bytes((2 * self.rb, tl, lam & 0xFF, 3))
        self.S = self._P(bytes(etat))

    @staticmethod
    def _P(s):
        return B._pack_nibbles(B.brume_v1(B._unpack_bytes(s)))

    def debit(self):
        return self.S[:self.rb]

    def appel(self, sigma, dom):
        s = bytearray(self.S)
        for i, x in enumerate(sigma):
            s[i] ^= x
        s[63] ^= dom << 4
        self.S = self._P(bytes(s))


def chiffrer_modele(profil, cle, nonce, aad, pt):
    """AEAD reconstruite depuis la preuve : le chiffré du bloc i est
    clair ⊕ débit lu avant son absorption ; l'entrée σ est ce chiffré."""
    rb, tl, _ = PROFILS[profil]
    d = Duplex(profil)
    # phase clé ‖ nonce et AAD : entrées indépendantes du chiffré
    for sigma, dom in chemin(profil, cle, nonce, aad, b"")[:len(_pad(cle + nonce, rb)) + len(_pad(aad, rb))]:
        d.appel(sigma, dom)
    ct = bytearray()
    for i in range(0, len(pt) + 1, rb):
        bloc = pt[i:i + rb]
        c = bytes(x ^ z for x, z in zip(bloc, d.debit()))
        ct += c
        d.appel(_pad(c, rb)[0] if len(c) < rb else c, 0)
    for sigma, dom in chemin(profil, cle, nonce, aad, bytes(ct))[-2:]:
        d.appel(sigma, dom)
    tag = bytearray()
    while len(tag) < tl:
        tag += d.debit()
        if len(tag) < tl:
            d.appel(b"", 0)
    return bytes(ct), bytes(tag[:tl])


def tag_modele(profil, cle, nonce, aad, ct):
    """Tag calculé uniquement à partir du chemin (le récepteur connaît C)."""
    rb, tl, _ = PROFILS[profil]
    d = Duplex(profil)
    for sigma, dom in chemin(profil, cle, nonce, aad, ct):
        d.appel(sigma, dom)
    tag = bytearray()
    while len(tag) < tl:
        tag += d.debit()
        if len(tag) < tl:
            d.appel(b"", 0)
    return bytes(tag[:tl])


def run():
    c, m = {}, {}
    rng = np.random.default_rng(42)
    # 1. modèle de preuve ≡ implémentation
    for prof, (rb, tl, _) in PROFILS.items():
        ok = ok_tag = True
        for L in list(range(0, 3 * rb + 2)) + [200, 1000]:
            k, n, a, p = os.urandom(64), os.urandom(24), os.urandom(int(rng.integers(0, 2 * rb + 2))), os.urandom(L)
            ref = Brume512(prof, key=k).encrypt(n, p, a)
            ok &= chiffrer_modele(prof, k, n, a, p) == ref
            ok_tag &= tag_modele(prof, k, n, a, ref[0]) == ref[1]
        c[f"{prof}_modele_de_preuve_identique"] = ok
        c[f"{prof}_tag_fonction_du_seul_chemin"] = ok_tag
    # 2. injectivité et absence de préfixe du codage (exhaustif sur petites longueurs)
    k, n = bytes(64), bytes(24)
    for prof, (rb, _, _) in PROFILS.items():
        vus, chemins = {}, []
        alpha = [b"", b"\x00", b"\x01", b"\x80", b"\x01\x00", b"\x00\x01"]
        mots = set(alpha)
        for la in (rb - 1, rb, rb + 1, 2 * rb - 1, 2 * rb):
            mots |= {b"\x00" * la, b"\x01" + b"\x00" * (la - 1), b"\x00" * (la - 1) + b"\x01"}
        mots = sorted(mots)
        coll = 0
        for aad, ct in itertools.product(mots, mots):
            ch = tuple(chemin(prof, k, n, aad, ct))
            coll += ch in vus and vus[ch] != (aad, ct)
            vus[ch] = (aad, ct)
            chemins.append(ch)
        prefixe = sum(1 for x in chemins for y in chemins if len(x) < len(y) and y[:len(x)] == x)
        m[f"{prof}_chemins_testes"] = len(chemins)
        c[f"{prof}_codage_injectif"] = coll == 0
        c[f"{prof}_codage_sans_prefixe"] = prefixe == 0
    # 3. pas de libération de clair non vérifié
    br = Brume512("BRUME-512", key=os.urandom(64))
    nn = os.urandom(24)
    ct, tag = br.encrypt(nn, b"secret" * 10)
    try:
        br.decrypt(nn, ct, bytes([tag[0] ^ 1]) + tag[1:])
        c["refus_sans_liberation_de_clair"] = False
    except Brume512TagError:
        c["refus_sans_liberation_de_clair"] = True
    out = {"controles": c, "mesures": m}
    sauver("mode_aead", out)
    return out


if __name__ == "__main__":
    r = run()
    print(r["controles"])
    print(r["mesures"])
