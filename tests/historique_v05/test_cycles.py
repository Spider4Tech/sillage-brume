# -*- coding: utf-8 -*-
"""Recherche générale de cycles itératifs (au-delà du motif 1->7->1).

On itère la trajectoire greedy Δ -> M·OPTOUT(Δ) (resp. M^T puis OPTIN pour
le linéaire) depuis un grand nombre d'états creux, et on détecte les cycles.
Un cycle de coût moyen faible serait une caractéristique itérative exploitable.
"""
import json, os, sys
import tests.commun  # noqa: F401  (chemin racine)
import numpy as np
from tests.commun import sauver  # noqa: F401
from sillage.brume512 import (GMUL, SBOX, N, E_I, E_C, E_SEG, E_I_T, E_C_T, E_SEG_T, GMUL_T)

def tables():
    s = np.array(SBOX, np.uint8); X = np.arange(16)
    ddt = np.zeros((16, 16), np.int32)
    for a in range(16):
        d = s[X] ^ s[X ^ a]
        for v in range(16): ddt[a, v] = int((d == v).sum())
    lat = np.zeros((16, 16), np.int32)
    for a in range(16):
        for l in range(16):
            c = sum(1 for x in range(16) if ((bin(a & int(s[x])).count('1') ^ bin(l & x).count('1')) & 1) == 0)
            lat[a, l] = c - 8
    return ddt, lat
DDT, LAT = tables()
OPTOUT = np.array([int(np.argmax(DDT[a])) for a in range(16)], np.uint8)
COST = np.array([8 - 2*int(np.log2(max(DDT[a]))) if DDT[a].max() > 1 else 99 for a in range(16)], np.int64)
OPTIN = np.array([int(np.argmax(np.abs(LAT[a]))) for a in range(16)], np.uint8)
COSTLIN = np.array([6 - 2*int(np.log2(max(np.abs(LAT[a])))) if np.abs(LAT[a]).max() > 1 else 99 for a in range(16)], np.int64)

def diffuse(s, weighted=True):
    contrib = GMUL[E_C, s[:, E_I]] if weighted else s[:, E_I]
    return np.bitwise_xor.reduceat(contrib, E_SEG[:-1], axis=1)
def diffuseT(s, weighted=True):
    contrib = GMUL_T[E_C_T, s[:, E_I_T]] if weighted else s[:, E_I_T]
    return np.bitwise_xor.reduceat(contrib, E_SEG_T[:-1], axis=1)

def hashes(S):
    return np.array([hash(S[i].tobytes()) for i in range(len(S))], dtype=np.int64)

def search_cycles(n_starts=4000, rounds=80, weighted=True, direction="diff", seed=0):
    rng = np.random.default_rng(seed)
    w = rng.integers(1, 9, n_starts)
    S = np.zeros((n_starts, N), np.uint8)
    for i in range(n_starts):
        pos = rng.choice(N, size=w[i], replace=False)
        S[i, pos] = rng.integers(1, 16, size=w[i], dtype=np.uint8)
    if direction == "diff":
        S = diffuse(OPTOUT[S], weighted)
    else:
        a = diffuseT(S, weighted); S = OPTIN[a]
    cost = np.zeros(n_starts, np.int64)
    H = np.zeros((rounds, n_starts), np.int64)
    C = np.zeros((rounds, n_starts), np.int64)
    for r in range(rounds):
        H[r] = hashes(S); C[r] = cost
        if direction == "diff":
            cost = cost + COST[S].sum(1); S = diffuse(OPTOUT[S], weighted)
        else:
            a = diffuseT(S, weighted); cost = cost + COSTLIN[a].sum(1); S = OPTIN[a]
    cycles = []
    for r in range(1, rounds):
        same = (H[:r] == H[r][None, :]).any(axis=0)
        for i in np.nonzero(same)[0]:
            r0 = int(np.nonzero(H[:r, i] == H[r, i])[0][0])
            per = r - r0
            if per <= 0: continue
            avg = (C[r, i] - C[r0, i]) / per
            cycles.append({"start": int(i), "round_debut": r0, "round": r,
                           "periode": per, "cout_moyen_demi_bits": float(avg)})
    # déduplique par période
    best = {}
    for c in cycles:
        k = c["periode"]
        if k not in best or c["cout_moyen_demi_bits"] < best[k]["cout_moyen_demi_bits"]:
            best[k] = c
    return {"n_starts": n_starts, "rounds": rounds, "cycles": list(best.values()),
            "n_cycles_detectes": len(cycles)}

def run():
    out = {}
    for name, kw in (("v1_diff", dict(weighted=True, direction="diff")),
                     ("v1_lin", dict(weighted=True, direction="lin")),
                     ("v0_diff_temoin", dict(weighted=False, direction="diff"))):
        out[name] = search_cycles(n_starts=3000, rounds=80, **kw)
        print(name, out[name]["n_cycles_detectes"], out[name]["cycles"][:3], flush=True)
    # Contrôles. L'ancienne version exigeait seulement « tout cycle trouvé coûte ≥ la borne wide-trail » : sans cycle
    # trouvé, all([]) était vrai, et un cycle trouvé, étant une vraie caractéristique, ne pouvait pas passer sous la
    # borne prouvée. Le contrôle ne pouvait donc pas échouer. On exige maintenant (1) que le détecteur trouve les
    # cycles du témoin v0 (graphe non pondéré), (2) qu'aucun cycle itératif glouton n'existe pour v1 : une assertion
    # qui peut échouer, puisqu'elle échoue sur le témoin.
    cyc = lambda k: [c["cout_moyen_demi_bits"] for c in out[k]["cycles"]]
    out["mesures"] = {k: {"cycles_detectes": out[k]["n_cycles_detectes"], "couts_moyens_demi_bits": sorted(cyc(k))[:5]}
                      for k in ("v1_diff", "v1_lin", "v0_diff_temoin")}
    out["controles"] = {
        "temoin_v0_cycles_detectes": out["v0_diff_temoin"]["n_cycles_detectes"] > 0,
        "v1_diff_aucun_cycle_iteratif_glouton": out["v1_diff"]["n_cycles_detectes"] == 0,
        "v1_lin_aucun_cycle_iteratif_glouton": out["v1_lin"]["n_cycles_detectes"] == 0,
    }
    sauver("cycles", out)
    return out


if __name__ == "__main__":
    run()
