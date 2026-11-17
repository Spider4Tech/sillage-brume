# -*- coding: utf-8 -*-
"""Attaques intégrales et algébriques : cubes de nibbles et de bits sur tours
réduits, intégrale 2^20 sur un voisinage du graphe, bornes de degré
(Boura–Canteaut) et portée des distingueurs zero-sum « inside-out »."""
import math

import numpy as np

from tests.commun import sauver
from sillage import brume512 as B
from tests.noyau_c import permute

N = B.N


def anf_degre(f):
    a = list(f)
    for i in range(4):
        for x in range(16):
            if x >> i & 1:
                a[x] ^= a[x ^ (1 << i)]
    return max((bin(x).count("1") for x in range(16) if a[x]), default=0)


def degre_sbox(S):
    return max(anf_degre([(bin(b & S[x]).count("1") & 1) for x in range(16)])
               for b in range(1, 16))


def bornes_degre(deg_s, n=512, m=4, R=40):
    """deg après r tours ≤ min(deg_s·d, n - (n - d)/ (m-1)) (Boura–Canteaut,
    S-box m bits, couche non linéaire de n bits)."""
    d, out = 1, []
    for _ in range(R):
        d = min(deg_s * d, n - math.ceil((n - d) / (m - 1)) if d < n - 1 else n - 1, n - 1)
        out.append(d)
    return out


def cube_somme(R, X):
    return np.bitwise_xor.reduce(permute(X, R), axis=0)


def run():
    rng = np.random.default_rng(2026)
    c, m = {}, {}
    # 1. cubes de d nibbles (16^d entrées), 6 contextes
    nib = {}
    for d in (1, 2, 3):
        row = {}
        for R in range(1, 8):
            zs = 0
            for _ in range(6):
                base = rng.integers(0, 16, N, dtype=np.uint8)
                pos = rng.choice(N, d, replace=False)
                vals = np.array(np.unravel_index(np.arange(16 ** d), (16,) * d)).T.astype(np.uint8)
                X = np.repeat(base[None], 16 ** d, 0)
                X[:, pos] = vals
                zs += int(not cube_somme(R, X).any())
            row[R] = zs
        nib[d] = row
    m["cubes_nibbles_zero_somme_sur_6"] = nib
    # 2. cubes de k bits, nombre moyen de bits de sortie à somme nulle (aléatoire ≈ 256)
    bits = {}
    for R in range(3, 7):
        row = {}
        for k in (8, 12, 16):
            z = []
            for _ in range(3):
                pos = rng.choice(512, k, replace=False)
                base = rng.integers(0, 16, N, dtype=np.uint8)
                mm = np.arange(1 << k)
                X = np.repeat(base[None], 1 << k, 0)
                for j, b in enumerate(pos):
                    X[:, b // 4] ^= (((mm >> j) & 1) << (b % 4)).astype(np.uint8)
                s = cube_somme(R, X)
                z.append(512 - int(np.unpackbits(s[:, None], axis=1)[:, 4:].sum()))
            row[k] = float(np.mean(z))
        bits[R] = row
    m["cubes_bits_sorties_nulles_sur_512"] = bits
    # 3. intégrale 2^20 sur un sommet et 4 voisins
    nbrs = [0] + [int(j) for j in np.nonzero(B.ADJ[0])[0][:4]]
    integ = {}
    for R in (4, 5, 6):
        acc = np.zeros(N, np.uint8)
        base = rng.integers(0, 16, N, dtype=np.uint8)
        allm = np.arange(1 << 20)
        for c0 in range(0, 1 << 20, 1 << 16):
            mm = allm[c0:c0 + (1 << 16)]
            X = np.repeat(base[None], len(mm), 0)
            for j, p in enumerate(nbrs):
                X[:, p] = ((mm >> (4 * j)) & 15).astype(np.uint8)
            acc ^= cube_somme(R, X)
        integ[R] = int((acc == 0).sum())
    m["integrale_2^20_voisinage_nibbles_nuls_sur_128"] = integ
    # portée empirique : dernier tour avec un distingueur (≫ 8 nibbles nuls
    # attendus au hasard, ou cube 100 % nul)
    portee = max([R for R, v in integ.items() if v > 24] +
                 [R for d in nib for R, v in nib[d].items() if v == 6] +
                 [R for R in bits for k, v in bits[R].items() if v > 300] + [0])
    m["portee_empirique_tours"] = portee
    c["distingueurs_empiriques_inferieurs_a_8_tours"] = portee < 8
    # 4. bornes de degré
    S = B.SBOX.tolist()
    Sinv = [0] * 16
    for x in range(16):
        Sinv[S[x]] = x
    ds, dsi = degre_sbox(S), degre_sbox(Sinv)
    fw, bw = bornes_degre(ds), bornes_degre(dsi)
    rf = sum(1 for d in fw if d < 511)
    rb = sum(1 for d in bw if d < 511)
    m["degre_sbox"], m["degre_sbox_inverse"] = ds, dsi
    m["bornes_degre_directes"] = fw[:14]
    m["tours_degre_incomplet_direct"] = rf
    m["tours_degre_incomplet_inverse"] = rb
    m["portee_zero_sum_inside_out_tours"] = rf + rb
    c["zero_sum_inside_out_ne_couvre_pas_32_tours"] = rf + rb < B.N_ROUNDS
    m["marge_zero_sum_tours"] = B.N_ROUNDS - (rf + rb)
    out = {"controles": c, "mesures": m}
    sauver("integral_degre", out)
    return out


if __name__ == "__main__":
    print(run())
