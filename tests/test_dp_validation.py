# -*- coding: utf-8 -*-
"""Division property contre la réalité : validation croisée sur petits cubes.

Le Théorème 12 sexies repose sur le modèle de pistes monomiales exactes
(tables des S-box avec constantes, règle copie/XOR de L). On le confronte
ici à des sommes de cube RÉELLES (noyau C) : cubes de 2^16 entrées (4
nibbles actifs, autres bits nuls), tours réduits, dans les deux sens.

Pour chaque bit de sortie j, la requête exacte (tests/dp_queue.py, sans
fenêtres basses) dit s'il existe une piste du cube vers j :
  - pas de piste (UNSAT) → la DP PROUVE j équilibré : la somme mesurée
    DOIT être nulle (sinon le modèle serait faux) ;
  - piste → la DP ne prouve rien ; la somme peut être nulle (pistes en
    nombre pair, ou hasard : probabilité 1/2 pour un bit aléatoire).
Contrôles : aucune contradiction (zéro bit « prouvé équilibré » de somme non
nulle) et, tour par tour, la DP explique une part des sommes nulles.
Les cas sans piste (direct 3 et 4, inverse 2) sont exhaustifs sur les 512
bits ; dans les autres, chaque requête coûte 4 à 17 s : on interroge 48 bits
de somme NON NULLE (ceux qui contrediraient le modèle s'ils étaient prouvés
équilibrés) et 16 bits de somme nulle.
"""
import json
import os
import random
from concurrent.futures import ProcessPoolExecutor

import numpy as np

from tests.commun import sauver
from tests import noyau_c
from tests.dp_queue import queue
from tests.pistes_monomiales import NB, plan

CAS = [("direct", 3), ("direct", 4), ("direct", 5), ("inverse", 2), ("inverse", 3), ("inverse", 4)]
EXHAUSTIFS = {("direct", 3), ("direct", 4), ("inverse", 2)}


def _requete(arg):
    sens, R, cube, j = arg
    suf, st = queue(sens, R, 0, cube, j, temps_max=60, bas=False)
    return j, st


def run(n_cubes=2):
    rng = random.Random(7)
    noyau_c.conformite()
    c, m = {}, {}
    contradictions = 0
    resume = {}
    with ProcessPoolExecutor(os.cpu_count()) as ex:
        for sens, R in CAS:
            lignes = []
            for _ in range(n_cubes):
                nibs = rng.sample(range(128), 4)
                cube = sorted(4 * q + b for q in nibs for b in range(4))
                somme = noyau_c.cube(np.zeros(128, np.uint8), cube, R, 0 if sens == "direct" else 1)
                nul = {j for j in range(NB) if not (int(somme[j >> 2]) >> (j & 3)) & 1}
                if (sens, R) in EXHAUSTIFS:
                    bits = list(range(NB))
                else:
                    nn = sorted(set(range(NB)) - nul)
                    bits = rng.sample(nn, min(48, len(nn))) + rng.sample(sorted(nul), min(16, len(nul)))
                st = dict(ex.map(_requete, [(sens, R, cube, j) for j in bits], chunksize=1))
                prouves = {j for j, s in st.items() if s == "unsat"}
                pistes = sum(1 for s in st.values() if s == "piste")
                indecis = sum(1 for s in st.values() if s == "temps")
                contra = len(prouves - nul)
                contradictions += contra
                lignes.append({"nibbles": nibs, "bits_interroges": len(bits), "bits_somme_nulle": len(nul),
                               "bits_prouves_equilibres": len(prouves), "bits_avec_piste": pistes,
                               "contradictions": contra, "indecis": indecis})
            resume[f"{sens}_{R}"] = lignes
    m["cas"] = resume
    m["contradictions_total"] = contradictions
    c["aucun_bit_prouve_equilibre_de_somme_non_nulle"] = contradictions == 0
    # une requête indécise (temps dépassé) ne compte jamais comme preuve : elle
    # ne peut pas masquer une contradiction, seulement réduire l'échantillon
    c["au_moins_85_pct_des_requetes_decidees"] = all(
        l["indecis"] <= 0.15 * l["bits_interroges"] for v in resume.values() for l in v)
    m["requetes_indecises"] = sum(l["indecis"] for v in resume.values() for l in v)
    c["dp_explique_les_sommes_nulles_au_tour_3_direct"] = all(
        l["bits_prouves_equilibres"] == l["bits_somme_nulle"] == 512 for l in resume["direct_3"])
    c["dp_prouve_des_bits_equilibres_au_tour_4_direct"] = all(l["bits_prouves_equilibres"] > 0 for l in resume["direct_4"])
    out = {"controles": c, "mesures": m}
    sauver("dp_validation", out)
    return out


if __name__ == "__main__":
    print(json.dumps(run(), indent=1, ensure_ascii=False))
