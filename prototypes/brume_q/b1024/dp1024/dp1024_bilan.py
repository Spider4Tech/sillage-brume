# -*- coding: utf-8 -*-
"""Bilan de la division property de BRUME-1024q, recalculé et REVÉRIFIÉ à partir des fichiers du dépôt :
  - borne basse prouvée : degré de Boura–Canteaut (n = 1 024, γ = 3), r_bc tours par sens ;
  - sens direct : une piste vérifiée vers chacun des 1 024 bits au tour Rd (resultats/pistes_couverture_1024q.json, pistes
    reconstruites depuis leurs sources de resultats/pistes_division_1024q.json) ;
  - sens inverse : une piste vérifiée vers chacun des 1 024 bits au tour Ri (resultats/pistes_inverse_1024q.json :
    certificats (bit, graine), pistes reconstruites par dp1024_inverse.construire) ;
  - témoins : `verifier` rejette des pistes invalides dérivées d'une piste valide, dans les deux sens.
Si les 1 024 bits ont une piste au tour R, la division property ne prouve plus aucun bit équilibré à R tours.
    python3 dp1024_bilan.py [travailleurs]      → resultats/division_property_1024q.json"""
import copy
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor

_ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _ICI)
import dp1024_inverse as I  # noqa: E402

P, NB = I.P, I.NB
RES = os.path.dirname(I.SORTIE)
from tests.test_division_property import bornes_degre  # noqa: E402

_SRC = {}


def _init():
    _SRC.update(json.load(open(os.path.join(RES, "pistes_division_1024q.json"))))


def _direct(a):
    R, j, e = a
    p = _SRC[e["source"]]["piste"][:e["coupe"] + 1] + e["suffixe"]
    return j, P.verifier(p, R, "direct") and p[-1][1] == [j] and p[0][1] == list(range(1, NB))


def _inverse(a):
    R, j, g = a
    p = I.construire(R, j, g)
    return j, p is not None and P.verifier(p, R, "inverse") and p[-1][1] == [j] and p[0][1] == list(range(1, NB))


def temoins(p0, R, sens):
    """Pistes invalides dérivées de p0 (valide) : chacune doit être rejetée."""
    _, L = P._couches(sens)
    mut = {}
    q = copy.deepcopy(p0); q[0][1] = q[0][1][2:]; mut["depart_incomplet"] = q
    iL = next(i for i, e in enumerate(p0) if e[0] == "L")
    q = copy.deepcopy(p0); a_, _k = q[iL][2][0]
    q[iL][2][0] = [a_, next(j for j in range(NB) if not L[j, a_])]; mut["arete_hors_support"] = q
    q = copy.deepcopy(p0); q[iL][2] = q[iL][2][1:]; mut["arete_retiree"] = q
    iS = next(i for i, e in enumerate(p0) if e[0] == "S")
    q = copy.deepcopy(p0); nib = q[iS - 1][1][0] // 4
    q[iS][1] = [b for b in q[iS][1] if b // 4 != nib]; mut["sbox_entree_active_sortie_nulle"] = q
    q = copy.deepcopy(p0); fin = q[-1][1][0]; q[-1][1] = sorted({fin, (fin + 1) % NB}); mut["arrivee_sur_deux_bits"] = q
    mut["un_tour_de_moins"] = copy.deepcopy(p0[:-2])
    return {nom: not P.verifier(x, R if nom != "un_tour_de_moins" else R - 1, sens) for nom, x in mut.items()}


def main():
    w = int(sys.argv[1]) if len(sys.argv) > 1 else os.cpu_count()
    t0 = time.time()
    c, m = {}, {}
    bc = bornes_degre(n=NB, R=20)
    r_bc = sum(1 for d in bc if d < NB - 1)
    m["degre_boura_canteaut"] = bc[:14]
    m["tours_equilibres_prouves_par_degre"] = r_bc
    couv = json.load(open(os.path.join(RES, "pistes_couverture_1024q.json")))
    inv = json.load(open(os.path.join(RES, "pistes_inverse_1024q.json")))
    _init()
    hauts = {}
    with ProcessPoolExecutor(w, initializer=_init) as ex:
        for sens, taches, f in (
                ("direct", [(int(k.split("|")[1]), int(j), e) for k, d in couv.items() if k.startswith("direct|")
                            for j, e in d.items()], _direct),
                ("inverse", [(int(R), int(j), g) for R, d in inv["certificats"].items() for j, g in d.items()],
                 _inverse)):
            par_tour = {}
            for (R, _, _), (j, ok) in zip(taches, ex.map(f, taches, chunksize=8)):
                if ok:
                    par_tour.setdefault(R, set()).add(j)
            complets = sorted(R for R, s in par_tour.items() if len(s) == NB)
            m[f"{sens}_bits_avec_piste_verifiee_par_tour"] = {R: len(s) for R, s in sorted(par_tour.items())}
            hauts[sens] = complets[0] - 1 if complets else None
            m[f"{sens}_portee_DP"] = {"min_prouve": r_bc, "max_verifie": hauts[sens],
                                      "exacte": hauts[sens] == r_bc}
            print(f"{sens} : {m[f'{sens}_bits_avec_piste_verifiee_par_tour']} → portée DP entre {r_bc} et {hauts[sens]}",
                  flush=True)
    src = json.load(open(os.path.join(RES, "pistes_division_1024q.json")))
    kd = next(k for k in sorted(src) if k.startswith("direct|13|"))
    tv = {"direct": temoins(src[kd]["piste"], 13, "direct"), "inverse": temoins(inv["exemple"]["piste"], 12, "inverse")}
    m["temoins_verifier_pistes_invalides_rejetees"] = tv
    c["verifier_rejette_les_pistes_invalides_deux_sens"] = all(all(v.values()) for v in tv.values())
    c["exemple_inverse_complet_verifie"] = P.verifier(inv["exemple"]["piste"], 12, "inverse")
    c["division_property_bornee_dans_les_deux_sens"] = all(v is not None for v in hauts.values())
    c["portee_inverse_exacte"] = hauts["inverse"] == r_bc
    tot = sum(hauts.values()) if c["division_property_bornee_dans_les_deux_sens"] else None
    m["portee_inside_out"] = {"min": 2 * r_bc, "max": tot}
    m["marge_tours_min"] = None if tot is None else I._B.N_ROUNDS - tot
    m["duree_s"] = round(time.time() - t0)
    json.dump({"nom": "division_property_1024q", "controles": c, "mesures": m}, open(os.path.join(
        RES, "division_property_1024q.json"), "w"), indent=1, ensure_ascii=False)
    print(json.dumps({"controles": c, "mesures": m}, ensure_ascii=False))
    return 0 if all(c.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
