# -*- coding: utf-8 -*-
"""Sillage-KEM : Lemme 3 et identités de la preuve du Théorème 1 (PROOFS § 2.1, § 2.3), vérifiés bit à bit.

1. Le code : P place chaque valeur de [0, 128) exactement D fois, et chacun des 254 supports S_{u,b} a 64·D bits.
2. Identité du bruit : v ⊕ (u·x)|_{n2} ⊕ cw(μ) = (r1·y ⊕ r2·x)|_{n2} ⊕ e1 ⊕ π(e2). Les termes r1·x·h s'annulent, et
   N ne dépend pas de μ. On la vérifie sur de vraies encapsulations, avec les aléas recalculés depuis (μ, H(pk)).
3. Majoration du Lemme 3 : pour chaque bloc et chacun des 254 supports, wt(N ∩ S) ≤ T1 + T2 + Te. T1 et T2 sont
   les nombres de paires (a, b) ∈ r1 × y et r2 × x qui tombent dans S, et Te le nombre de bits de e1 et de π(e2)
   dans S. Témoin : sans T2, la majoration tombe en défaut, donc le contrôle peut échouer.
4. Condition d'échec : un bloc mal décodé a au moins 32·D bits de bruit sur un S_{u,b}. On la vérifie sur des
   blocs à bruit lourd (de nombreux échecs). Le seuil est atteint : un bruit de 32·D bits exactement, placé sur la
   différence de deux mots de code, provoque un échec.
5. Le décodeur (transformée de Walsh) est à maximum de vraisemblance. Sa distance au mot reçu égale le minimum
   sur les 256 mots du bloc (force brute). Sur les chiffrés réels, sa marge vaut max_S wt(N ∩ S) − 32·D.
"""
import os
import sys

import numpy as np

from tests.commun import sauver
from sillage.sillage_kem import SillageKEM, PARAMS, _positions, _walsh, _mot, rm_encode, rm_decode
from sillage.sillage_common import ring_mul, shake, sparse_from_seed, apply_perm_int, random_bytes


def bits(v: int, n: int) -> np.ndarray:
    return np.unpackbits(np.frombuffer(v.to_bytes((n + 7) // 8, "little"), np.uint8), bitorder="little")[:n]


def supports(pos: np.ndarray) -> np.ndarray:
    """Matrice (254, L) : ligne (u, b) = indicatrice de S_{u,b} = {q : <u, P[q]> = b}, u ≠ 0."""
    par = np.array([[bin(u & i).count("1") & 1 for i in range(128)] for u in range(1, 128)], np.uint8)
    ip = par[:, pos]                                     # (127, L) : <u, P[q]>
    return np.concatenate((1 - ip, ip)).astype(np.int32)


def par_bloc(positions: np.ndarray, n2: int, L: int, k8: int, S: np.ndarray) -> np.ndarray:
    """Pour un multiensemble de positions de [0, n), nombre de celles qui tombent dans chaque S de chaque bloc :
    tableau (k8, 254). Les positions ≥ n2 sont hors de v."""
    positions = positions[positions < n2]
    h = np.zeros((k8, L), np.int32)
    np.add.at(h, (positions // L, positions % L), 1)
    return h @ S.T


def paires(a: np.ndarray, b: np.ndarray, n: int) -> np.ndarray:
    return ((a[:, None] + b[None, :]) % n).ravel()


def une_encaps(kem, pk, sk, mu):
    """Chiffré réel et, recalculés comme dans _encrypt, ses aléas."""
    p = kem.p
    n, n2, k = p["n"], p["n2"], p["k"]
    u, v = kem._encrypt(pk, mu)
    coins = shake(mu.to_bytes(k // 8, "little") + kem._pk_hash(pk), 32, b"SILLAGE-KEM|coins")
    r1 = sparse_from_seed(coins, p["w"], n, b"SILLAGE-KEM|r1")
    r2 = sparse_from_seed(coins, p["w"], n, b"SILLAGE-KEM|r2")
    e1 = sparse_from_seed(coins, p["we"], n2, b"SILLAGE-KEM|e1")
    pe2 = apply_perm_int(sparse_from_seed(coins, p["we"], n2, b"SILLAGE-KEM|e2"), kem._byte_perm(pk[0]), n2 // 8)
    return u, v, r1, r2, e1, pe2


def niveau(lvl: str, essais: int, blocs_lourds: int):
    c, m = {}, {}
    kem = SillageKEM(lvl)
    p = kem.p
    n, n2, D, k8 = p["n"], p["n2"], p["D"], p["k"] // 8
    L, masque = 128 * D, (1 << p["n2"]) - 1
    pos = np.array(_positions(D))
    S = supports(pos)
    c["P_chaque_valeur_D_fois"] = bool((np.bincount(pos, minlength=128) == D).all())
    c["supports_254_de_64D_bits"] = S.shape == (254, L) and bool((S.sum(axis=1) == 64 * D).all())

    pk, sk = kem.keygen()
    x, y = sk[0], sk[1]
    px, py = np.flatnonzero(bits(x, n)), np.flatnonzero(bits(y, n))
    identite = majoration = temoin_sans_T2 = marge_ok = 0
    marge_min = 1 << 30
    for _ in range(essais):
        mu = int.from_bytes(random_bytes(k8), "little")
        u, v, r1, r2, e1, pe2 = une_encaps(kem, pk, sk, mu)
        N = v ^ (ring_mul(u, x, n) & masque) ^ rm_encode(mu, p)
        N_formule = ((ring_mul(r1, y, n) ^ ring_mul(r2, x, n)) & masque) ^ e1 ^ pe2
        identite += N == N_formule
        pn = np.flatnonzero(bits(N, n2))
        pr1, pr2 = np.flatnonzero(bits(r1, n)), np.flatnonzero(bits(r2, n))
        bruit = par_bloc(pn, n2, L, k8, S)
        T1 = par_bloc(paires(pr1, py, n), n2, L, k8, S)
        T2 = par_bloc(paires(pr2, px, n), n2, L, k8, S)
        Te = par_bloc(np.concatenate((np.flatnonzero(bits(e1, n2)), np.flatnonzero(bits(pe2, n2)))), n2, L, k8, S)
        majoration += bool((bruit <= T1 + T2 + Te).all())
        temoin_sans_T2 += bool((bruit > T1 + Te).any())
        marge_min = min(marge_min, int(32 * D - bruit.max()))
        mu_d, marge = rm_decode(N ^ rm_encode(mu, p), p)
        marge_ok += mu_d == mu and marge == int(bruit.max()) - 32 * D
    c["bruit_egal_a_la_formule_de_la_preuve"] = identite == essais
    c["lemme_3_majoration_sur_chaque_support_de_chaque_bloc"] = majoration == essais
    c["temoin_majoration_sans_T2_mise_en_defaut"] = temoin_sans_T2 == essais
    c["marge_egale_max_du_bruit_sur_S_moins_32D"] = marge_ok == essais
    m["encapsulations"] = essais
    m["ecart_min_au_seuil_32D"] = marge_min

    # Blocs à bruit lourd : condition d'échec et maximum de vraisemblance.
    rng = np.random.default_rng(int.from_bytes(os.urandom(8), "little"))
    mots = np.array([bits(_mot(s, D), L) for s in range(256)], np.uint8)          # (256, L)
    echecs = cond_ok = ml_ok = 0
    for _ in range(blocs_lourds):
        octets = rng.integers(0, 256, k8)
        mu = sum(int(o) << (8 * j) for j, o in enumerate(octets))
        poids = rng.integers(int(0.40 * L), int(0.52 * L), k8)
        Nb = np.zeros((k8, L), np.uint8)
        for j in range(k8):
            Nb[j, rng.choice(L, int(poids[j]), replace=False)] = 1
        nv = rm_encode(mu, p) ^ int.from_bytes(np.packbits(Nb.ravel(), bitorder="little").tobytes(), "little")
        mu_d = rm_decode(nv, p)[0]
        recu = mots[octets] ^ Nb                                                    # (k8, L)
        dist = (recu[:, None, :] != mots[None, :, :]).sum(axis=2)                   # (k8, 256)
        max_S = (Nb.astype(np.int32) @ S.T).max(axis=1)                            # (k8,)
        for j in range(k8):
            d = (mu_d >> (8 * j)) & 255
            ml_ok += dist[j, d] == dist[j].min()
            if d != octets[j]:
                echecs += 1
                cond_ok += max_S[j] >= 32 * D
    c["tout_bloc_mal_decode_a_32D_bits_sur_un_support"] = cond_ok == echecs
    c["blocs_lourds_avec_echecs_le_controle_porte"] = echecs >= blocs_lourds
    c["decodeur_a_maximum_de_vraisemblance"] = ml_ok == blocs_lourds * k8
    m.update(blocs_lourds=blocs_lourds * k8, blocs_mal_decodes=echecs)

    # Seuil atteint : 32·D bits de bruit sur la différence de deux mots suffisent à faire échouer le bloc 0.
    seuil = []
    for s in (1, 77, 200):
        for s2 in (s ^ 0x80, s ^ 0x01):                 # même u, b opposé : tout le bloc ; u différent : un S_{u,b}
            diff = np.flatnonzero(mots[s] ^ mots[s2])
            Nb = np.zeros(L, np.uint8)
            Nb[diff[:len(diff) // 2]] = 1
            nv = rm_encode(s, p) ^ int.from_bytes(np.packbits(Nb, bitorder="little").tobytes(), "little")
            d = rm_decode(nv, p)[0] & 255
            seuil.append((int(Nb.sum()), int((Nb.astype(np.int32) @ S.T).max()), d != s))
    c["seuil_32D_atteint_par_un_bruit_construit"] = any(e and mx == 32 * D for _, mx, e in seuil)
    m["bruits_construits"] = [dict(poids=w, max_S=mx, echec=e) for w, mx, e in seuil]
    return c, m


def run(e128=24, e256=6, lourds=40):
    c, m = {}, {}
    for lvl, e, b in (("Sillage-128", e128, lourds), ("Sillage-256", e256, lourds // 4)):
        cc, mm = niveau(lvl, e, b)
        c.update({f"{lvl}_{k}": v for k, v in cc.items()})
        m[lvl] = mm
    out = {"controles": c, "mesures": m}
    sauver("kem_lemme3", out)
    return out


if __name__ == "__main__":
    a = [int(x) for x in sys.argv[1:]]
    out = run(*a)
    for k, v in out["controles"].items():
        print(f"{'OK ' if v else 'ÉCHEC'} {k}")
    print(out["mesures"])
