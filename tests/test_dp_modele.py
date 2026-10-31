# -*- coding: utf-8 -*-
"""Cadre de division property EXACTE (tests/dp_cpsat.py) : validation.

La recherche exacte complète (couvrir les 512 bits, ou prouver UNSAT) est
trop coûteuse pour la batterie (≈ 18 min pour UNE piste à 12 tours ; les
requêtes UNSAT ciblées à 11 tours ne concluent pas en 25 min). Ce test
valide le cadre lui-même, à bas coût :
  1. cohérence : pour 2 ≤ R ≤ 10, les fenêtres de poids sont incompatibles
     (borne basse > borne haute à une frontière de tours) — le modèle est
     infaisable, ce qui redonne la portée « par le degré » (R = 1 n'a pas
     de frontière intérieure ; le modèle complet est testé à R = 10) ;
  2. complétude : chaque piste connue (cache, revérifiée par `verifier`),
     imposée au modèle, est acceptée — le modèle n'exclut pas de vraie
     piste respectant les fenêtres ;
  3. fenêtres : poids des pistes connues, couche par couche, comparés aux
     fenêtres (une piste hors fenêtre traverserait un coefficient nul) ;
  4. coupes par nibble (`coupes=True`) : wt(u) ≤ 3·[v ≠ 0] + [v = F] et
     cw(v) ≤ 3·[u ≠ F] + [u = 0], vérifiées exhaustivement sur toutes les
     tables exactes (S et S⁻¹, toutes les constantes de tour) ; le modèle
     avec coupes accepte les pistes connues.
"""
import json
import os

from ortools.sat.python import cp_model

from tests.commun import sauver, RESULTATS
from tests.dp_cpsat import ModeleCP, imposer
from tests.dp_sat import degres
from tests.pistes_monomiales import verifier, NB, N, _couches, table
from sillage import brume512 as B


def coupes_valides():
    """Chaque transition permise u → v de chaque table exacte respecte les
    deux coupes linéaires de dp_cpsat.ModeleCP._coupes_nibble."""
    w = lambda x: bin(x).count("1")
    n = 0
    for sens in ("direct", "inverse"):
        S, _ = _couches(sens)
        cs = {(0, 0)} | {(int(B.RC[r][q]), 0) if sens == "direct" else (0, int(B.RC[r][q]))
                         for r in range(B.N_ROUNDS) for q in range(N)}
        for c0, c1 in cs:
            T = table(S, c0, c1)
            for u in range(16):
                for v in range(16):
                    if T[u, v]:
                        n += 1
                        if w(u) > 3 * (v != 0) + (v == 15) or 4 - w(v) > 3 * (u != 15) + (u == 0):
                            return False, n
    return True, n


def fenetres(R):
    D = degres()
    return [(max(0, NB - D[t]) if t < R else 1, D[R - t]) for t in range(R + 1)]


def run():
    c, m = {}, {}
    D = degres()
    incoherent = {}
    for R in range(1, 13):
        f = fenetres(R)
        incoherent[R] = any(lo > hi for lo, hi in f[1:R])
    m["fenetres_incompatibles_par_R"] = incoherent
    c["fenetres_incompatibles_pour_2_le_R_le_10"] = all(incoherent[R] for R in range(2, 11))
    c["fenetres_compatibles_a_partir_de_11"] = not incoherent[11] and not incoherent[12]
    for sens in ("direct", "inverse"):                 # infaisabilité effective à 10 tours
        M = ModeleCP(10, sens, inactif=0)
        s = cp_model.CpSolver()
        s.parameters.max_time_in_seconds = 120
        s.parameters.num_workers = 4
        c[f"modele_infaisable_a_10_tours_{sens}"] = s.Solve(M.m) == cp_model.INFEASIBLE
    cache = json.load(open(os.path.join(RESULTATS, "pistes_division.json")))
    acceptees, testees, hors = 0, 0, 0
    for k, v in sorted(cache.items())[:6]:             # échantillon (modèle complet : coûteux)
        sens, R, _ = k.split("|")
        R = int(R)
        if not verifier(v["piste"], R, sens):
            continue
        testees += 1
        poids = [len(e[1]) for e in v["piste"][::2]]   # états avant chaque couche S (direct) / L (inverse)
        f = fenetres(R)
        hors += sum(1 for t, w in enumerate(poids[:R + 1]) if not (f[t][0] <= w <= f[t][1]) and 0 < t < R)
        M = ModeleCP(R, sens, inactif=0, fenetres=False, coupes=True)
        imposer(M, v["piste"])
        s = cp_model.CpSolver()
        s.parameters.max_time_in_seconds = 120
        s.parameters.num_workers = 4
        acceptees += s.Solve(M.m) in (cp_model.OPTIMAL, cp_model.FEASIBLE)
    m["pistes_connues"] = {"testees": testees, "acceptees_par_le_modele": acceptees,
                           "couches_hors_fenetre": hors}
    c["modele_accepte_les_pistes_verifiees"] = testees > 0 and acceptees == testees
    ok, n = coupes_valides()
    m["coupes_transitions_verifiees"] = n
    c["coupes_par_nibble_valides_pour_toutes_les_tables"] = ok
    out = {"controles": c, "mesures": m}
    sauver("dp_modele", out)
    return out


if __name__ == "__main__":
    print(json.dumps(run(), indent=1, ensure_ascii=False))
