# -*- coding: utf-8 -*-
"""Division property : portée EXACTE (piste 6), par décomposition.

La borne basse (10 tours par sens, Boura–Canteaut) vaut pour tout cube. Si
chacun des 512 bits de sortie admet une piste monomiale vérifiée au tour
11, la division property ne prédit plus aucun bit équilibré à 11 tours :
la portée vaut alors EXACTEMENT 10 tours dans ce sens.

Décomposition (tests/dp_queue.py) : on garde le préfixe d'une piste
vérifiée jusqu'à une couche i0, et CP-SAT construit un suffixe exact vers
un bit cible imposé. Le modèle ne contient que les bits atteignables depuis
l'état fixé et co-atteignables depuis la cible.
  1. bases : pistes du cache (`pistes_division.json`) tronquées en i0 et
     complétées vers un bit quelconque au tour 11 (les pistes inverses du
     cache sont déjà à 11 tours) ;
  2. couverture : pour chaque bit j, complétion depuis une base, de la
     coupe la plus tardive (requête la moins chère) à la plus précoce.
Chaque piste est REVÉRIFIÉE par `verifier` (cube 0). Cache compact
`resultats/pistes_exactes.json` (source, coupe, suffixe) ; au lancement
suivant, les pistes en cache sont reconstruites et revérifiées, et seules
les manquantes sont recherchées.

Tous les cubes : une piste complétée partage avec sa source l'état X après
la première couche linéaire (indice 2 en direct, 1 en inverse). Le
recollement de toutes les pistes sources sur les 512 cubes est vérifié par
`test_dp_tous_cubes` ; par le Lemme 12 ter (localité des règles), il
s'applique tel quel aux pistes complétées. Le test contrôle que chaque piste
a le X d'une source recollée et revérifie entièrement un échantillon de
pistes recollées sur des cubes tirés au hasard.
"""
import json
import os
import random
import time
from concurrent.futures import ProcessPoolExecutor

from tests.commun import sauver, RESULTATS
from tests.dp_queue import completer
from tests.pistes_monomiales import NB, verifier

CACHE_BASE = os.path.join(RESULTATS, "pistes_division.json")
CACHE = os.path.join(RESULTATS, "pistes_exactes.json")
R_CIBLE = 11
# coupes (indices de couche) essayées, de la plus tardive à la plus précoce,
# avec leur budget en secondes ; plan direct : (S, L) par tour, inverse : (L, S)
COUPES_BASE = {"direct": [(12, 300), (10, 300)]}
COUPES = {"direct": [(18, 20), (16, 40), (14, 90), (12, 240)], "inverse": [(18, 20), (16, 90), (14, 240)]}
INDICE_X = {"direct": 2, "inverse": 1}


def compacter(p, source, i0):
    """Une piste complétée = préfixe de sa source jusqu'à i0, puis suffixe."""
    return {"source": source, "coupe": i0, "suffixe": p[i0 + 1:]}


def reconstruire(e, sources):
    return list(sources[e["source"]][:e["coupe"] + 1]) + list(e["suffixe"])


def _base(arg):
    sens, cle, piste, i0, t = arg
    p, st = completer(piste, R_CIBLE, sens, i0, None, temps_max=t, threads=2)
    return cle, i0, p, st


def _cible(arg):
    sens, j, bases = arg
    for i0, t in COUPES[sens]:
        for cle, piste in bases:
            p, st = completer(piste, R_CIBLE, sens, i0, j, temps_max=t)
            if p is not None:
                return j, cle, i0, p
    return j, None, None, None


def _echantillon(arg):
    from tests.test_dp_tous_cubes import recoller
    sens, p, a = arg
    p2 = recoller(p, R_CIBLE, sens, a)
    return p2 is not None and verifier(p2, R_CIBLE, sens, inactif=a)


def run(travailleurs=None, journal=print):
    t0 = time.time()
    w = travailleurs or os.cpu_count()
    base_cache = json.load(open(CACHE_BASE))
    sources = {k: v["piste"] for k, v in base_cache.items()
               if verifier(v["piste"], int(k.split("|")[1]), k.split("|")[0])}
    cache = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
    cache.setdefault("bases", {})
    cache.setdefault("pistes", {})
    sauver_cache = lambda: json.dump(cache, open(CACHE, "w"))
    m, c = {}, {}
    for sens in ("direct", "inverse"):
        # 1. bases au tour 11
        bases = {}
        for k, e in cache["bases"].items():
            if k.startswith(sens) and e["source"] in sources:
                p = reconstruire(e, sources)
                if verifier(p, R_CIBLE, sens):
                    bases[k] = p
        if not bases:
            src = [(k, p) for k, p in sorted(sources.items()) if k.startswith(sens)]
            if sens == "inverse":
                bases = {k: p for k, p in src if int(k.split("|")[1]) == R_CIBLE}
                for k in bases:
                    cache["bases"][k] = {"source": k, "coupe": len(bases[k]) - 1, "suffixe": []}
            else:
                taches = [(sens, k, p, i0, t) for k, p in src for i0, t in COUPES_BASE[sens]]
                with ProcessPoolExecutor(max(1, w // 2)) as ex:
                    for k, i0, p, st in ex.map(_base, taches):
                        journal(f"  base {k} coupe {i0} : {st}")
                        if p is not None:
                            bases[f"{k}@{i0}"] = p
                            cache["bases"][f"{k}@{i0}"] = compacter(p, k, i0)
            sauver_cache()
        m[f"{sens}_bases_11_tours"] = len(bases)
        # 2. couverture des 512 bits (sources des complétions : les bases)
        couverts = {}
        for k, e in cache["pistes"].items():
            s_, j = k.split("|")
            if s_ == sens and e["source"] in bases:
                p = reconstruire(e, bases)
                if verifier(p, R_CIBLE, sens) and p[-1][1] == [int(j)]:
                    couverts[int(j)] = p
        for p in bases.values():
            couverts.setdefault(p[-1][1][0], p)
        manquants = [j for j in range(NB) if j not in couverts]
        journal(f"  {sens} : {len(couverts)} bits déjà couverts, {len(manquants)} à chercher")
        lb = sorted(bases.items())
        echecs = []
        if manquants:
            with ProcessPoolExecutor(w) as ex:
                for j, cle, i0, p in ex.map(_cible, [(sens, j, lb) for j in manquants]):
                    if p is None:
                        echecs.append(j)
                        continue
                    couverts[j] = p
                    cache["pistes"][f"{sens}|{j}"] = compacter(p, cle, i0)
                    if len(couverts) % 32 == 0:
                        sauver_cache()
                        journal(f"  {sens} : {len(couverts)}/512 ({time.time() - t0:.0f} s)")
            sauver_cache()
        m[f"{sens}_bits_couverts_au_tour_11"] = len(couverts)
        m[f"{sens}_bits_sans_piste_trouvee"] = sorted(echecs)
        complet = len(couverts) == NB
        c[f"{sens}_couverture_complete_au_tour_11_cube_0"] = complet
        m[f"{sens}_portee_DP_cube_0"] = {"min_prouve": 10, "max_verifie": 10 if complet else None}
        # 3. tous les cubes
        ix = INDICE_X[sens]
        X_src = {tuple(p[ix][1]) for k, p in sources.items() if k.startswith(sens)}
        c[f"{sens}_pistes_issues_de_sources_recollees"] = all(tuple(p[ix][1]) in X_src for p in couverts.values())
        rng = random.Random(0)
        ech = [(rng.choice(sorted(couverts)), rng.randrange(NB)) for _ in range(48)]
        with ProcessPoolExecutor(w) as ex:
            oks = list(ex.map(_echantillon, [(sens, couverts[j], a) for j, a in ech]))
        m[f"{sens}_echantillon_recolle_tous_cubes"] = {"teste": len(oks), "verifie": sum(oks)}
        c[f"{sens}_echantillon_recolle_verifie"] = all(oks)
    ok = all(c[f"{s}_couverture_complete_au_tour_11_cube_0"] and c[f"{s}_pistes_issues_de_sources_recollees"]
             for s in ("direct", "inverse"))
    m["portee_DP_exacte_tous_cubes"] = {"direct": 10, "inverse": 10, "inside_out": 20} if ok else None
    m["duree_s"] = round(time.time() - t0)
    out = {"controles": c, "mesures": m}
    sauver("dp_exact", out)
    return out


if __name__ == "__main__":
    print(json.dumps(run(), indent=1, ensure_ascii=False))
