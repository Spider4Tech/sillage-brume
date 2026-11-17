# -*- coding: utf-8 -*-
"""Agrégation de trails (linear hull, différentielles) — au-delà des trails.

1. Bornes PROUVÉES à 2 tours (Park, Sung, Lee, Lim 2003), pour toute couche
   linéaire de branch number β (ici β_d = β_l = 8, certifié) et S-box
   bijectives, en modèle de Markov (clés de tour indépendantes) :
       MEDP_2 ≤ max_u Σ_v DP(u,v)^β_d,   MELP_2 ≤ max_u Σ_v LP(u,v)^β_l.
   Pour R ≥ 2 tours, MEDP_R ≤ MEDP_2 (Σ_c DP_B(c, b) = 1 pour une bijection).
2. Mesure : approximation linéaire à 2 tours à 8 S-box actives (minimum
   imposé par B = 8) — corrélation mesurée vs prédiction du trail ; la
   différentielle à 2 tours est mesurée dans test_diff_lin_empirique.
3. Marge : à 32 tours, une caractéristique coûte ≥ 2^-256 et un trail
   ≥ 2^-128 ; les meilleurs trails trouvés à 14 tours coûtent 2^-2830 /
   2^-1417 : il faudrait ≥ 2^2500 trails de même extrémités, de même signe,
   pour combler l'écart.
"""
import itertools
import math

import numpy as np

from tests.commun import sauver, tables_sbox
from sillage import brume512 as B
from tests.noyau_c import permute

N = B.N
DDT, LAT = tables_sbox(B.SBOX)
PAR = np.array([bin(i).count("1") & 1 for i in range(16)], np.uint8)


def park(beta=8):
    dp = DDT / 16.0
    lp = (LAT / 8.0) ** 2
    medp = max((dp[u] ** beta).sum() for u in range(1, 16))
    melp = max((lp[u] ** beta).sum() for u in range(1, 16))
    return math.log2(medp), math.log2(melp)


def _inverse_gf2(A):
    n = A.shape[0]
    M = np.concatenate([A.copy() % 2, np.eye(n, dtype=np.uint8)], axis=1)
    r = 0
    for col in range(n):
        piv = r + int(np.argmax(M[r:, col]))
        assert M[piv, col], "singulière"
        M[[r, piv]] = M[[piv, r]]
        nz = np.nonzero(M[:, col])[0]
        nz = nz[nz != r]
        M[nz] ^= M[r]
        r += 1
    return M[:, n:]


def _bits(v):
    return np.unpackbits(v[:, None], axis=1, bitorder="little")[:, :4].ravel()


def _nibbles(b):
    return np.packbits(b.reshape(-1, 4), axis=1, bitorder="little").ravel()


def trail_lineaire_2_tours():
    """Trail à 8 S-box actives (minimum, B = 8) : γ2 (1 nibble, entrée S-box
    du tour 2) ; α1 = Mᵀγ2 (7 nibbles, sorties S-box du tour 1) ; δ = meilleurs
    masques d'entrée ; α2 = meilleur masque de sortie pour γ2 ; masque final
    β = (Mᵀ)^{-1} α2 (dense, aucune S-box après)."""
    T = np.zeros((4 * N, 4 * N), np.uint8)             # matrice binaire de Mᵀ_bin
    for i in range(4 * N):
        e = np.zeros(4 * N, np.uint8); e[i] = 1
        T[:, i] = _bits(B.diffuse_T(_nibbles(e)))
    Tinv = _inverse_gf2(T)
    g = 1
    gam2 = np.zeros(N, np.uint8); gam2[0] = g
    alpha1 = B.diffuse_T(gam2)
    delta = np.zeros(N, np.uint8)
    pred = 1.0
    for j in np.nonzero(alpha1)[0]:
        d = int(np.argmax(np.abs(LAT[alpha1[j]])))
        delta[j] = d
        pred *= LAT[alpha1[j], d] / 8
    a2 = int(np.argmax(np.abs(LAT[:, g])))
    pred *= LAT[a2, g] / 8
    alpha2 = np.zeros(N, np.uint8); alpha2[0] = a2
    beta = _nibbles((Tinv @ _bits(alpha2)) % 2)
    assert (B.diffuse_T(beta) == alpha2).all()
    return delta, beta, int((alpha1 != 0).sum()) + 1, pred


def run():
    rng = np.random.default_rng(23)
    c, m = {}, {}
    md, ml = park()
    m["park_MEDP_2_tours_log2"] = round(md, 2)
    m["park_MELP_2_tours_log2"] = round(ml, 2)
    c["park_bornes_calculees"] = md <= -12 and ml <= -6
    delta, beta, actives, pred = trail_lineaire_2_tours()
    m["trail_2_tours_sbox_actives"] = actives
    S = 1 << 22
    acc = 0
    for _ in range(S // (1 << 16)):
        X = rng.integers(0, 16, (1 << 16, N), dtype=np.uint8)
        Y = permute(X, 2)
        a = PAR[delta[None, :] & (X ^ B.RC[0])].sum(1) & 1
        b = PAR[beta[None, :] & Y].sum(1) & 1
        acc += int((1 - 2 * (a ^ b).astype(np.int64)).sum())
    mes = acc / S
    sd = 1 / math.sqrt(S)
    m["lin_2_tours"] = {"correlation_mesuree": round(mes, 6),
                        "prediction_trail_abs": abs(pred), "ecart_type": round(sd, 6),
                        "facteur_hull": round(abs(mes) / abs(pred), 2) if pred else None}
    # le hull (signe inclus) ne doit pas amplifier massivement la corrélation
    c["hull_2_tours_pas_d_amplification_massive"] = abs(mes) <= 4 * abs(pred) + 5 * sd
    # Le contrôle ci-dessus est unilatéral : des masques mal construits (convention de LAT, transposition, constantes)
    # donneraient une corrélation nulle et le feraient passer. La mesure doit donc aussi VOIR la corrélation prédite.
    c["hull_2_tours_correlation_du_trail_detectee"] = abs(mes) >= 5 * sd and abs(mes) >= abs(pred) / 4
    m["marge_bits"] = {"diff_14_tours_trouve": 2830, "diff_32_tours_prouve": 256,
                       "lin_14_tours_trouve": 1417, "lin_32_tours_prouve": 128}
    out = {"controles": c, "mesures": m}
    sauver("hull", out)
    return out


if __name__ == "__main__":
    print(run())
