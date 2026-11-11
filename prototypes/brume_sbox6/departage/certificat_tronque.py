#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Certificats par modèle tronqué (activité des S-box) — PROTOCOLE.md § 4.1 et § 5.

Le modèle tronqué est une RELAXATION COMPLÈTE de la permutation réduite : une variable binaire
par S-box et par tour (128 × R), le support exact de M lu dans sillage/brume512.py (jamais
recopié), et pour chaque sortie v de M avec s = Σ_{k ∈ N[v]} x_r[k] :
    s = 0  ⇒  x_{r+1}[v] = 0 ;   s = 1  ⇒  x_{r+1}[v] = 1 ;   s ≥ 2  ⇒  libre (annulation GF(16)).
Toute caractéristique réelle (différentielle par M, linéaire par M^T, dont le support est le
même car l'adjacence est symétrique) satisfait ces contraintes. Un optimum PROUVÉ (statut
OPTIMAL ou INFEASIBLE de CP-SAT) de la relaxation est donc une borne inférieure valide pour la
permutation. La relaxation ne sert jamais à produire une attaque.

Ce script n'est un solveur que pour le modèle tronqué ; tout le calcul exact sur les valeurs
est en C (departage.c). Il tourne dans le conteneur qui a OR-Tools.
"""
import json
import sys
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(RACINE))

from ortools.sat.python import cp_model  # noqa: E402

from sillage import brume512 as B  # noqa: E402

N = B.N


def voisinages():
    """N[v] = entrées k avec M[v][k] != 0 (support exact de M, ligne v)."""
    nv = []
    for v in range(N):
        nv.append(sorted(int(B.E_I[e]) for e in range(B.E_SEG[v], B.E_SEG[v + 1])))
    return nv


def faits_branchement():
    """Faits EXACTS sur la vraie matrice M (coefficients GF(16)), établis par
    tests/test_branch_exact.py et relus dans resultats/branch_exact.json (jamais recopiés) :
    min_{wt(x)=w} wt(x)+wt(Mx) pour w = 1, 2, 3, et de même pour M^-1 (plafonné à 99)."""
    d = json.loads((RACINE / "resultats" / "branch_exact.json").read_text())["mesures"]
    return ({int(k): int(v) for k, v in d["M"].items()},
            {int(k): int(v) for k, v in d["M_inv"].items()})


def modele(R, nv, sym=True):
    """Relaxation tronquée complète + faits exacts de branchement.

    Contraintes, toutes valides pour toute caractéristique réelle :
      (a) troncature : s = 0 ⇒ inactif, s = 1 ⇒ actif, s ≥ 2 ⇒ libre ;
      (b) M inversible et S bijective : aucune couche n'est vide ;
      (c) poids d'entrée w ≤ 3 ⇒ poids de sortie ≥ minM[w] − w (exact, test_branch_exact) ;
      (d) poids de sortie w ≤ 3 ⇒ poids d'entrée ≥ minMinv[w] − w (exact, M^-1) ;
      (e) sym : le support de M est un graphe de Cayley (D_128), sommet-transitif ; on peut
          imposer qu'une S-box donnée du PREMIER tour soit active (x0[0] = 1) sans perte de
          généralité — seulement quand la question porte sur un minimum sur tous les motifs.
    """
    minM, minMi = faits_branchement()
    m = cp_model.CpModel()
    x = [[m.NewBoolVar(f"x{r}_{v}") for v in range(N)] for r in range(R)]
    W = [sum(x[r]) for r in range(R)]
    for r in range(R):
        m.Add(W[r] >= 1)
    for r in range(R - 1):
        for v in range(N):
            K = nv[v]
            s = sum(x[r][k] for k in K)
            m.Add(x[r + 1][v] <= s)
            for k in K:
                m.Add(x[r + 1][v] >= x[r][k] - sum(x[r][kk] for kk in K if kk != k))
        for w in (1, 2, 3):
            e_in = m.NewBoolVar(f"in{r}_{w}")
            m.Add(W[r] == w).OnlyEnforceIf(e_in)
            m.Add(W[r] != w).OnlyEnforceIf(e_in.Not())
            m.Add(W[r + 1] >= minM[w] - w).OnlyEnforceIf(e_in)
            e_out = m.NewBoolVar(f"out{r}_{w}")
            m.Add(W[r + 1] == w).OnlyEnforceIf(e_out)
            m.Add(W[r + 1] != w).OnlyEnforceIf(e_out.Not())
            m.Add(W[r] >= min(N, minMi[w] - w)).OnlyEnforceIf(e_out)
    if sym:
        m.Add(x[0][0] == 1)
    return m, x


def resoudre(m, limite, graine=0):
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = limite
    s.parameters.num_search_workers = 12
    s.parameters.random_seed = graine
    t = time.time()
    st = s.Solve(m)
    return s, st, time.time() - t


def statut_audit(nom_statut):
    """Règle d'audit (PROTOCOLE.md § 3) : seule une preuve du solveur qualifie le résultat."""
    if nom_statut == "OPTIMAL":
        return "PROUVE_OPTIMAL"
    if nom_statut == "INFEASIBLE":
        return "PROUVE_INFAISABLE"
    return "NON_PROUVE"


def certificat_d2(nv, limite):
    """Aucun motif à 2 tours avec 2 ≤ w0 ≤ 7 et w1 ≤ 7 (⇒ DP2 ≤ 2^-16 hors poids 1)."""
    m, x = modele(2, nv)
    w0, w1 = sum(x[0]), sum(x[1])
    m.Add(w0 >= 2)
    m.Add(w0 <= 7)
    m.Add(w1 <= 7)
    s, st, dt = resoudre(m, limite)
    nom = s.StatusName(st)
    return {"question": "existe-t-il un motif 2 tours avec 2 <= w0 <= 7 et w1 <= 7 ?",
            "statut_solveur": nom, "statut_audit": statut_audit(nom), "duree_s": round(dt, 2),
            "consequence": ("si PROUVE_INFAISABLE : pour toute entree de poids >= 2, DP2(alpha,beta) <= "
                            "min(4^-w0, 4^-w1) <= 2^-16, donc le maximum global de DP2 est le maximum "
                            "sur les entrees de poids 1 si celui-ci est >= 2^-16")}


def min_actives(R, nv, w0min, limite, sens="premier"):
    """min Σ actives sur R tours, avec au moins w0min S-box actives au premier tour."""
    m, x = modele(R, nv)
    tot = sum(sum(x[r]) for r in range(R))
    m.Add(sum(x[0]) >= w0min)
    m.Minimize(tot)
    s, st, dt = resoudre(m, limite)
    nom = s.StatusName(st)
    out = {"tours": R, "w0_min": w0min, "statut_solveur": nom, "statut_audit": statut_audit(nom),
           "duree_s": round(dt, 2), "objectif": None, "borne": None, "motif": None}
    if st in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        out["objectif"] = int(s.ObjectiveValue())
        out["borne"] = int(s.BestObjectiveBound())
        out["motif"] = [int(sum(s.Value(v) for v in x[r])) for r in range(R)]
    return out


def main():
    limite = float(sys.argv[1]) if len(sys.argv) > 1 else 600.0
    sortie = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(".")
    nv = voisinages()
    res = {
        "modele": {
            "type": "relaxation tronquee complete (128 S-box par tour, support exact de M) + faits exacts de branchement (resultats/branch_exact.json) + symetrie de Cayley (x0[0]=1)",
            "source_du_support": "sillage/brume512.py (E_I, E_SEG)",
            "variables_par_tour": N,
            "valide_pour": "caracteristiques differentielles (M) et lineaires (M^T, meme support, tours inverses)",
            "limite_s": limite,
        },
        "C2_d2_poids_ge2": certificat_d2(nv, limite),
        "min_actives_2t_w0ge1": min_actives(2, nv, 1, limite),
        "min_actives_3t_w0ge1": min_actives(3, nv, 1, limite),
        "min_actives_3t_w0ge2": min_actives(3, nv, 2, limite),
    }
    sortie.mkdir(parents=True, exist_ok=True)
    (sortie / "certificat_tronque.json").write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(json.dumps(res, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
