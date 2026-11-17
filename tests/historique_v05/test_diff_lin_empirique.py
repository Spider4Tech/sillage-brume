# -*- coding: utf-8 -*-
"""Validation expérimentale des modèles différentiel et linéaire sur tours
réduits : prédiction DDT/LAT vs mesure, adjonction binaire, effet de
regroupement (différentielle vs caractéristique) sur 2 tours."""
import math

import numpy as np

from tests.commun import sauver, tables_sbox
from sillage import brume512 as B
from tests.noyau_c import permute

N = B.N
DDT, LAT = tables_sbox(B.SBOX)
PAR = np.array([bin(i).count("1") & 1 for i in range(16)], np.uint8)


def dot(mask, x):
    return PAR[mask[None, :] & x].sum(1) & 1


def run():
    rng = np.random.default_rng(11)
    c, m = {}, {}
    # 1. adjonction <mu, M v> = <M^T_bin mu, v>
    v = rng.integers(0, 16, (3000, N), dtype=np.uint8)
    mu = rng.integers(0, 16, (3000, N), dtype=np.uint8)
    lhs = PAR[mu & B.diffuse_batch(v)].sum(1) & 1
    rhs = PAR[B.diffuse_T_batch(mu) & v].sum(1) & 1
    c["adjonction_binaire_exacte"] = bool((lhs == rhs).all())
    # 2. différentiel 1 tour : Δ = a au nibble 0 → b (DDT = 4) → M·b ; p = 1/4
    a = 1
    b = int(np.argmax(DDT[a]))
    din = np.zeros(N, np.uint8); din[0] = a
    dout = np.zeros(N, np.uint8); dout[0] = b
    dout = B.diffuse(dout)
    S = 1 << 16
    X = rng.integers(0, 16, (S, N), dtype=np.uint8)
    Y1 = permute(X, 1) ; Y2 = permute(X ^ din, 1)
    # les constantes de tour n'affectent pas la différence ; mais RC[0] est
    # XORé AVANT la S-box : la probabilité sur x aléatoire reste DDT/16
    p = float(((Y1 ^ Y2) == dout).all(1).mean())
    m["diff_1_tour"] = {"mesure": round(p, 4), "predite": DDT[a, b] / 16}
    c["diff_1_tour_conforme"] = abs(p - DDT[a, b] / 16) < 5 * math.sqrt(0.25 * 0.75 / S)
    # 3. linéaire 1 tour : masque de sortie β (1 nibble) → α = M^T β (7 nibbles)
    #    → masques d'entrée γ_j = argmax |LAT[α_j]| ; |corr| prédite = Π |LAT|/8
    beta = np.zeros(N, np.uint8); beta[3] = 5
    alpha = B.diffuse_T(beta)
    gamma = np.zeros(N, np.uint8)
    pred = 1.0
    for j in np.nonzero(alpha)[0]:
        g = int(np.argmax(np.abs(LAT[alpha[j]])))   # LAT[α][γ] : <α,S(x)> vs <γ,x>
        gamma[j] = g
        pred *= LAT[alpha[j], g] / 8
    S = 1 << 20
    acc = 0
    for _ in range(S // (1 << 16)):
        X = rng.integers(0, 16, (1 << 16, N), dtype=np.uint8)
        Y = permute(X, 1)
        # RC[0] avant la S-box : <γ, x ⊕ rc> = <γ,x> ⊕ cste → signe global
        acc += int((1 - 2 * (dot(gamma, X ^ B.RC[0]) ^ dot(beta, Y)).astype(np.int64)).sum())
    corr = acc / S
    m["lin_1_tour"] = {"mesure": round(corr, 5), "predite": pred, "ecart_type": round(1 / math.sqrt(S), 5)}
    c["lin_1_tour_conforme"] = abs(corr - pred) < 5 / math.sqrt(S)
    # 4. regroupement 2 tours : différence la plus fréquente après 2 tours
    #    depuis 1 nibble actif vs meilleure caractéristique (2^-2 · 2^-14)
    #    Sélection puis comptage sur des échantillons INDÉPENDANTS. L'ancienne version ne cumulait, lot par lot,
    #    que les 5 différences les plus fréquentes du lot : les occurrences hors de ce top 5 étaient perdues, ce qui
    #    sous-estimait la fréquence maximale et rendait le contrôle (unilatéral, contre une amplification) aveugle.
    #    Choisir et compter sur les mêmes paires biaiserait au contraire vers le haut.
    best_char = math.log2(DDT[a, b] / 16) + 7 * math.log2(DDT[1:].max() / 16)
    sel = {}
    for _ in range(16):                                  # sélection : 2^20 paires
        X = rng.integers(0, 16, (1 << 16, N), dtype=np.uint8)
        D = permute(X, 2) ^ permute(X ^ din, 2)
        u, k = np.unique(D, axis=0, return_counts=True)
        for t in np.nonzero(k > 1)[0]:
            key = u[t].tobytes()
            sel[key] = sel.get(key, 0) + int(k[t])
    cands = [np.frombuffer(kk, np.uint8) for kk, _ in sorted(sel.items(), key=lambda e: -e[1])[:8]]
    S = 1 << 21
    cnt = [0] * len(cands)
    for _ in range(S // (1 << 16)):                      # comptage exact : 2^21 paires nouvelles
        X = rng.integers(0, 16, (1 << 16, N), dtype=np.uint8)
        D = permute(X, 2) ^ permute(X ^ din, 2)
        for i, cd in enumerate(cands):
            cnt[i] += int((D == cd).all(1).sum())
    top = max(cnt, default=0)
    m["diff_2_tours"] = {"meilleure_frequence_log2": round(math.log2(top / S), 2) if top > 1 else None,
                         "meilleure_caracteristique_log2": best_char,
                         "echantillons_log2": 21}
    c["diff_2_tours_pas_d_effet_de_groupe_massif"] = math.log2(max(top, 1) / S) <= best_char + 4
    out = {"controles": c, "mesures": m}
    sauver("diff_lin_empirique", out)
    return out


if __name__ == "__main__":
    print(run())
