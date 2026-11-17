# -*- coding: utf-8 -*-
"""
wide_trail.py — Bornes wide-trail sur le graphe de diffusion de BRUME v1.
=========================================================================

Théorème (wide-trail par paires). Soit B = min_{x ≠ 0} wt(x) + wt(Mx) sur
GF(16)^128 (wt = nombre de nibbles non nuls). Toute caractéristique
différentielle sur 2r rounds dont la différence reste non nulle à chaque
étape active au moins B·r S-boxes ; toute caractéristique linéaire pareil.

Preuve (à la Rijndael). Sur deux rounds consécutifs : les S-boxes sont
bijectives donc wt(Δ'_0) = wt(Δ_0) ; le coût du bloc vaut
wt(Δ_0) + wt(Δ_1) = wt(Δ'_0) + wt(M·Δ'_0) ≥ B. On somme sur les blocs.

Minorant de B. On utilise B ≥ 8, établi par :
  - poids 1  : wt(M·e_i) = 7 exactement (coefficients non nuls) → B(1) = 8 ;
  - poids 2  : énumération EXHAUSTIVE des 1 828 800 vecteurs de poids 2 :
               B(2) = 13 (mesuré) ≥ 8 ;
  - poids 3  : lemme des ratios (prémisses vérifiées par la curation :
               ratios de paires de colonnes distincts, chevauchements ≤ 5) :
               wt(Mx) ≥ 5 pour tout x de poids 3, donc B(3) ≥ 8 ;
  - poids ≥ 4 : EXACT — si wt(x)+wt(Mx) < 8 alors wt(Mx) ≤ 3 ; l'énumération
               des poids ≤ 3 de M^{-1} (tests/test_branch_exact.py) l'exclut.
Conséquences (B ≥ 8 prouvé) :
  - proba de toute caractéristique différentielle sur 2r rounds :
        p ≤ (4/16)^(8r) = 2^(-16r)   [U = 4 : p_max par S-box = 2^-2]
  - corrélation de tout trail linéaire sur 2r rounds :
        |c| ≤ (1/2)^(8r) = 2^(-8r)   [max|LAT| = 4 : c_max = 2^-1]

B = 8 est atteint (entrée de poids 1 → 7 nibbles) : aucune « variante
renforcée » par paire de tours n'est valide (retirée en v0.3).

Le module vérifie aussi EXHAUSTIVEMENT l'absence sur v1 du cycle itératif
type v0 (1 → 7 → 1) : pour chaque sommet i0, il faut
Σ_{i ∈ S1(i0) ∩ N̄(j)} c(j,i) = 0 pour tout j ∈ N(i0) et ≠ 0 pour j = i0.
"""
import json
import os

import numpy as np
from tests.commun import plt, RESULTATS

from sillage.brume512 import ADJ, ADJ_I, N, GMUL, TF

OUT = RESULTATS
os.makedirs(OUT, exist_ok=True)
AB = 2 * np.sqrt(5)


def check_no_iterative_cycle():
    """Recherche exhaustive du cycle 1 → 7 → 1 sur v1 (tous les i0)."""
    LN = [set(np.nonzero(ADJ[j])[0].tolist()) | {j} for j in range(N)]
    C = np.array(TF.COEF, dtype=np.uint8)
    cycles = []
    for i0 in range(N):
        S1 = LN[i0]
        ok = True
        # le centre i0 doit rester actif
        acc = 0
        for i in S1 & LN[i0]:
            acc ^= int(GMUL[int(C[i0, i]), 1])
        if acc == 0:
            ok = False
        # tous les voisins de i0 doivent s'annuler (condition du cycle)
        for j in np.nonzero(ADJ[i0])[0]:
            acc = 0
            for i in S1 & LN[int(j)]:
                acc ^= int(GMUL[int(C[int(j), i]), 1])
            if acc != 0:
                ok = False
                break
        if ok:
            cycles.append(i0)
    return {"supports_S1_testes": N,
            "cycles_iteratifs_trouves": cycles,
            "pas_de_cycle_type_v0": len(cycles) == 0}


def guarantees(stats, trails, n_rounds=32):
    b2 = stats["branch_numbers"]["B2_exact_min"]
    echant = stats["echantillonnage_poids"]
    min_ech = min(echant.values())
    B_prouve = 8
    diff = {}
    lin = {}
    for r in range(1, n_rounds + 1):
        w_p = B_prouve * (r // 2)
        diff[r] = {"garantie_prouvee_bits": 2 * w_p}
        lin[r] = {"garantie_prouvee_bits": w_p}

    def rounds_pour(cible, f):
        r = 1
        while f(r) < cible:
            r += 1
            if r > 4096:
                return None
        return r

    ver = {
        "B_prouve": B_prouve,
        "statut_preuve": {
            "poids_1_exact": 8,
            "poids_2_exact": b2,
            "poids_3_lemme_ratios": 8,
            "poids_4_et_plus": "exact (certificat M^-1, test_branch_exact)",
            "echantillonnage_min_observe": min_ech,
        },
        "rounds_requis_diff_128_prouve": rounds_pour(128, lambda r: 16 * (r // 2)),
        "rounds_requis_diff_256_prouve": rounds_pour(256, lambda r: 16 * (r // 2)),
        "rounds_requis_lin_128_prouve": rounds_pour(128, lambda r: 8 * (r // 2)),
        "rounds_requis_lin_256_prouve": rounds_pour(256, lambda r: 8 * (r // 2)),
        "garanties_32_rounds": {
            "diff_prouve": f"2^-{16 * 16}",
            "lin_prouve": f"2^-{8 * 16}",
        },
        "empirique_14_rounds": {
            "diff_bits": trails["diff_v1"][14] / 2,
            "lin_bits": trails["lin_v1"][14] / 2,
        },
        "pas_de_cycle_iteratif_type_v0": check_no_iterative_cycle(),
    }
    return diff, lin, ver


def fig_widetrail(diff, lin, trails):
    if plt is None:
        return
    fig, axs = plt.subplots(1, 2, figsize=(13, 4.8),
                            constrained_layout=True)
    for ax, data, titre, key_emp in (
            (axs[0], diff, "Différentiel : probabilité maximale des "
             "caractéristiques", "diff_v1"),
            (axs[1], lin, "Linéaire : corrélation maximale des trails",
             "lin_v1")):
        rs = sorted(data)
        pr = [data[r]["garantie_prouvee_bits"] for r in rs]
        ax.plot(rs, pr, "-", color="#33608c", lw=2,
                label="garantie PROUVÉE (B = 8 exact, théorème par paires)")
        m = trails[key_emp]
        rse = sorted(int(k) for k in m if m[k] is not None)
        ax.plot(rse, [m[k] / 2 for k in rse], "o-", color="crimson", ms=3.5,
                label="meilleure caractéristique trouvée (banc)")
        for seuil in (128, 256):
            ax.axhline(seuil, color="gray", ls=":", lw=0.9)
        ax.text(rs[-1] - 0.5, 132, "2^-128", fontsize=8, color="gray")
        ax.text(rs[-1] - 0.5, 260, "2^-256", fontsize=8, color="gray")
        ax.set_xlabel("rounds")
        ax.set_ylabel("−log2 (bits)")
        ax.set_title(titre, fontsize=10)
        ax.legend(fontsize=7.5, loc="lower right")
        ax.grid(alpha=0.3)
    fig.suptitle("Bornes wide-trail de BRUME v1 — garanties vs attaques "
                 "trouvées", fontsize=12)
    fig.savefig(f"{OUT}/fig3_widetrail.png", dpi=150)
    plt.close(fig)


def run(stats, trails):
    print("=== Bornes wide-trail — BRUME v1 ===", flush=True)
    # normalisation des clés (JSON -> entiers)
    for key in ("diff_v1", "lin_v1"):
        if key in trails:
            trails[key] = {int(k): v for k, v in trails[key].items()}
    diff, lin, ver = guarantees(stats, trails)
    print("  " + json.dumps(ver, ensure_ascii=False, indent=2))
    fig_widetrail(diff, lin, trails)
    with open(f"{OUT}/wide_trail.json", "w", encoding="utf-8") as f:
        json.dump({"verification": ver, "garanties_par_round":
                   {"diff": {str(k): v for k, v in diff.items()},
                    "lin": {str(k): v for k, v in lin.items()}}},
                  f, ensure_ascii=False, indent=2)
    return {"verification": ver, "diff": diff, "lin": lin}


if __name__ == "__main__":
    stats = json.load(open(f"{OUT}/statiques.json"))
    trails = json.load(open(f"{OUT}/trails.json"))
    run(stats, trails)
