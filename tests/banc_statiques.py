# -*- coding: utf-8 -*-
"""
statiques.py — Statiques cryptanalytiques de BRUME v1.
======================================================

1. S-box  : DDT, LAT, uniformité différentielle U, nonlinéarité NL,
            degré algébrique, immunité algébrique, points fixes.
2. Graphe : spectre (λ* vs borne d'Alon–Boppana 2√5), maille (girth),
            intersections de voisinages, branch number du diffuseur M :
            B(w) = min_{wt(x) <= w} wt(x) + wt(Mx), calculée EXACTEMENT
            pour wt(x) <= 2 (énumération complète : 1.83 M vecteurs).
3. Prémisses du lemme wide-trail (ratios distincts, chevauchements <= 5)
   + échantillonnage massif des poids 3-6.

Sorties : resultats/statiques.json, resultats/fig1_sbox.png,
          resultats/fig2_graphe.png
"""
import json
import os
from collections import deque
from itertools import combinations
from math import sqrt

import numpy as np
from tests.commun import plt, RESULTATS

from sillage.brume512 import (GMUL, SBOX, ADJ, ADJ_I, N, DEG, diffuse_batch,
                   diffuse_T_batch, TF)

OUT = RESULTATS
os.makedirs(OUT, exist_ok=True)
AB = 2 * sqrt(5)


# ---------------------------------------------------------------------------
# S-box
# ---------------------------------------------------------------------------


def sbox_tables():
    X = np.arange(16, dtype=np.uint8)
    s = SBOX
    ddt = np.zeros((16, 16), dtype=np.int32)
    for a in range(16):
        d = s[X] ^ s[X ^ a]
        for v in range(16):
            ddt[a, v] = int((d == v).sum())
    lat = np.zeros((16, 16), dtype=np.int32)      # lat[α=sortie, λ=entrée]
    for al in range(16):
        for lam in range(16):
            cnt = 0
            for x in range(16):
                if (bin(al & int(s[x])).count("1") % 2 ==
                        bin(lam & x).count("1") % 2):
                    cnt += 1
            lat[al, lam] = cnt - 8
    return ddt, lat


def sbox_metrics(ddt, lat):
    s = SBOX
    U = int(ddt[1:].max())
    NL = 8 - int(np.abs(lat[1:]).max())
    fixes = [int(x) for x in range(16) if s[x] == x]
    # degré algébrique des 4 composants (Möbius)
    bits = (((s[:, None] >> np.arange(4)[None, :]) & 1).astype(np.int32))
    INC = np.zeros((16, 16), dtype=np.int32)
    for A_ in range(16):
        for x_ in range(16):
            if (x_ & A_) == x_:
                INC[A_, x_] = 1
    coef = (INC @ bits) % 2
    POP = np.array([bin(a).count("1") for a in range(16)])
    deg = int(max(POP[A_] for A_ in range(16) if coef[A_, :].any()))
    # immunité algébrique : aucun annihilateur de degré <= 1
    ai = 2
    for k in range(4):
        f = bits[:, k]
        for m in range(4):
            half1 = np.array([(x >> m) & 1 for x in range(16)], dtype=bool)
            for hh in (half1, ~half1):
                sub = f[hh]
                if sub.min() == sub.max():
                    ai = 1
    return {
        "U_uniformite_differentielle": U,
        "NL_nonlinearite": NL,
        "points_fixes": fixes,
        "degre_algebrique": deg,
        "immunite_algebrique": ai,
        "proba_diff_max_par_sbox": f"2^{int(np.log2(U)) - 4}",
        "correlation_max_par_sbox": f"2^{int(np.log2(np.abs(lat[1:]).max())) - 3}",
        "nb_entrees_ddt_4": int((ddt[1:] == 4).sum()),
        "nb_entrees_lat_abs4": int((np.abs(lat[1:]) == 4).sum()),
    }


# ---------------------------------------------------------------------------
# Graphe
# ---------------------------------------------------------------------------


def girth():
    nbr = [np.nonzero(ADJ[x])[0].tolist() for x in range(N)]
    g = 10 ** 9
    for src in range(N):
        dist = [-1] * N
        par = [-1] * N
        dist[src] = 0
        q = deque([src])
        while q:
            x = q.popleft()
            for y in nbr[x]:
                if dist[y] < 0:
                    dist[y] = dist[x] + 1
                    par[y] = x
                    q.append(y)
                elif par[x] != y:
                    g = min(g, dist[x] + dist[y] + 1)
    return g


def graph_metrics():
    ev = np.linalg.eigvalsh(ADJ.astype(float))
    ev_sorted = np.sort(ev)
    lam_star = float(np.abs(ev_sorted[1:-1]).max())
    biparti = abs(ev_sorted[0] + DEG) < 1e-9
    inter = ADJ.astype(np.int32) @ ADJ.astype(np.int32)
    adj_off = ADJ - np.eye(N, dtype=np.uint8)
    chev = inter + 2 * adj_off.astype(np.int32)
    iu = np.triu_indices(N, 1)
    cvals = inter[iu]
    hvals = chev[iu]
    return {
        "groupe": TF.GROUP,
        "generateurs": list(TF.GENS),
        "lambda_etoile": round(lam_star, 4),
        "alon_boppana_2sqrt5": round(AB, 4),
        "ramanujan": bool(lam_star <= AB),
        "biparti": bool(biparti),
        "degre": DEG,
        "girth": girth(),
        "max_intersections_voisinages": int(cvals.max()),
        "max_chev": int(hvals.max()),
        "histogramme_chev": {str(k): int((hvals == k).sum())
                             for k in np.unique(hvals)},
    }


# ---------------------------------------------------------------------------
# Branch number du diffuseur : B(w) = min_{wt(x) <= w} wt(x) + wt(Mx)
# ---------------------------------------------------------------------------


def _pairs_and_vals():
    pairs = np.array(list(combinations(range(N), 2)), dtype=np.int32)
    vals = np.array([(a, b) for a in range(1, 16) for b in range(1, 16)],
                    dtype=np.uint8)
    return pairs, vals


def branch_numbers(batch_pairs=1000):
    """B(2) exact + distribution ; poids 1 analytique."""
    pairs, vals = _pairs_and_vals()
    hist = {}
    bmin = 10 ** 9
    P = len(pairs)
    V = len(vals)
    for st in range(0, P, batch_pairs):
        pr = pairs[st:st + batch_pairs]
        m = len(pr)
        rows = np.arange(m * V)
        pr_idx = rows // V
        v_idx = rows % V
        state = np.zeros((m * V, N), dtype=np.uint8)
        s0 = pr[pr_idx, 0]
        s1 = pr[pr_idx, 1]
        v0 = vals[v_idx, 0]
        v1 = vals[v_idx, 1]
        state[rows, s0] = v0
        state[rows, s1] = v1
        out = diffuse_batch(state)
        wt = (out != 0).sum(axis=1) + 2
        bmin = min(bmin, int(wt.min()))
        u, c = np.unique(wt, return_counts=True)
        for k_, c_ in zip(u, c):
            hist[int(k_)] = hist.get(int(k_), 0) + int(c_)
    return {"B1_exact": 1 + DEG,
            "B2_exact_min": bmin,
            "histogramme_wt_x_plus_wt_Mx_poids2": hist}


def verify_lemme_premisses():
    """Re-vérification exhaustive des prémisses du lemme des ratios."""
    LN = [sorted(set(np.nonzero(ADJ[j])[0].tolist()) | {j}) for j in range(N)]
    from sillage.select_params import Constraintes
    C = Constraintes(LN)
    COEF = np.array(TF.COEF, dtype=np.uint8)
    n, bad = C.collect(COEF)
    return {
        "violations_contraintes_coefficients": n,
        "premisse_ratios_distincts": n == 0,
        "premisse_chev_le_5": graph_metrics()["max_chev"] <= 5,
    }


def sample_weights(n_per=100_000, seed=7):
    """Échantillonnage : min de wt(x) + wt(Mx) pour wt(x) = 3..6."""
    rng = np.random.default_rng(seed)
    out = {}
    for w in (3, 4, 5, 6):
        bmin = 10 ** 9
        done = 0
        while done < n_per:
            m = min(50_000, n_per - done)
            sup = np.sort(rng.integers(0, N, size=(m, w)), axis=1)
            ok = (np.diff(sup, axis=1) > 0).all(axis=1)
            sup = sup[ok]
            m2 = len(sup)
            if m2 == 0:
                continue
            state = np.zeros((m2, N), dtype=np.uint8)
            rows = np.arange(m2)[:, None]
            vals = rng.integers(1, 16, size=(m2, w)).astype(np.uint8)
            state[rows, sup] = vals
            outw = diffuse_batch(state)
            tot = (outw != 0).sum(axis=1) + w
            bmin = min(bmin, int(tot.min()))
            done += m2
        out[f"min_observé_poids_{w}"] = bmin
    return out


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------


def fig_sbox(ddt, lat):
    if plt is None:
        return
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6),
                             constrained_layout=True)
    for ax, T, titre in ((axes[0], ddt, "DDT — table des différences"),
                         (axes[1], lat, "LAT — table des approximations")):
        im = ax.imshow(T, cmap="viridis")
        ax.set_xticks(range(16))
        ax.set_yticks(range(16))
        ax.set_title(titre, fontsize=11)
        ax.set_xlabel("différence/masque de sortie" if T is ddt
                      else "masque d'entrée λ")
        ax.set_ylabel("différence d'entrée a" if T is ddt
                      else "composant de sortie α")
        fig.colorbar(im, ax=ax, shrink=0.85)
    fig.suptitle("S-box BRUME v1 : U = 4 (max DDT), max|LAT| = 4 (NL = 4)",
                 fontsize=12)
    fig.savefig(f"{OUT}/fig1_sbox.png", dpi=150)
    plt.close(fig)


def fig_graphe(gm, b2):
    if plt is None:
        return
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.4),
                             constrained_layout=True)
    ax = axes[0]
    ev = np.sort(np.linalg.eigvalsh(ADJ.astype(float)))
    ax.bar(range(len(ev)), ev, width=1.0, color="#33608c")
    ax.axhline(DEG, color="k", lw=0.8)
    ax.axhline(2 * sqrt(5), color="crimson", ls="--",
               label="Alon–Boppana 2√5")
    ax.axhline(-2 * sqrt(5), color="crimson", ls="--")
    ax.set_title(f"Spectre du graphe (λ* = {gm['lambda_etoile']})")
    ax.set_xlabel("indice de valeur propre")
    ax.set_ylabel("valeur propre")
    ax.legend(fontsize=8)
    ax = axes[1]
    ax.imshow(ADJ, cmap="Greys", interpolation="nearest")
    ax.set_title(f"Matrice d'adjacence — Cayley({gm['groupe']}), "
                 f"maille {gm['girth']}")
    ax = axes[2]
    hist = b2["histogramme_wt_x_plus_wt_Mx_poids2"]
    ks = sorted(hist)
    ax.bar(ks, [hist[k] for k in ks], color="#4a7c59")
    ax.axvline(b2["B2_exact_min"], color="crimson", ls="--",
               label=f"B(2) = {b2['B2_exact_min']}")
    ax.set_yscale("log")
    ax.set_xlabel("wt(x) + wt(Mx)  (x de poids 2)")
    ax.set_ylabel("nombre de vecteurs (log)")
    ax.set_title("Branch number du diffuseur (exact, poids ≤ 2)")
    ax.legend(fontsize=8)
    fig.suptitle("Graphe de diffusion BRUME v1", fontsize=12)
    fig.savefig(f"{OUT}/fig2_graphe.png", dpi=150)
    plt.close(fig)


def run():
    ddt, lat = sbox_tables()
    sm = sbox_metrics(ddt, lat)
    print("  S-box :", json.dumps(sm, ensure_ascii=False))
    gm = graph_metrics()
    print("  Graphe :", json.dumps(gm, ensure_ascii=False))
    b2 = branch_numbers()
    print("  Branch numbers :", json.dumps(b2))
    lemme = verify_lemme_premisses()
    print("  Lemme wide-trail :", json.dumps(lemme, ensure_ascii=False))
    echant = sample_weights()
    print("  Échantillonnage poids 3-6 :", json.dumps(echant))
    fig_sbox(ddt, lat)
    fig_graphe(gm, b2)
    res = {"sbox": sm, "graphe": gm, "branch_numbers": b2,
           "lemme_wide_trail": lemme, "echantillonnage_poids": echant}
    with open(f"{OUT}/statiques.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    return res


if __name__ == "__main__":
    print("=== Statiques BRUME v1 ===")
    run()
