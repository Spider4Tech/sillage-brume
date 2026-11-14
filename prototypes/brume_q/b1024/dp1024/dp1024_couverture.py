# -*- coding: utf-8 -*-
"""Division property de BRUME-1024q : couverture des 1 024 bits de sortie au tour R (même méthode que l'étape 2 de
tests/test_dp_exact.py). Pour chaque bit j, on garde le préfixe d'une piste vérifiée du cache (sens|R|…) jusqu'à une
coupe i0, et CP-SAT construit un suffixe exact vers le bit j IMPOSÉ ; de la coupe la plus tardive (requête la moins
chère) à la plus précoce. Chaque piste est REVÉRIFIÉE par `verifier` (dans `completer`). Si les 1 024 bits ont une piste
au tour R, la division property ne prouve plus aucun bit équilibré à R tours : portée ≤ R − 1 dans ce sens.

    python3 dp1024_couverture.py R sens [travailleurs]
Cache compact (source, coupe, suffixe) : $DP_COUV ou resultats/pistes_couverture_1024q.json ; reprise : les pistes en
cache sont reconstruites et revérifiées, seules les manquantes sont cherchées."""
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor

_ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _ICI)
import dp1024_exact as X  # noqa: E402

P, Q, NB = X.P, X.Q, X.NB
COUV = os.environ.get("DP_COUV", os.path.join(os.path.dirname(X.CACHE), "pistes_couverture_1024q.json"))
_SOURCES = {}


def _init(sources):
    _SOURCES.update(sources)


def _cible(arg):
    R, sens, j, coupes = arg
    t0 = time.time()
    for i0, t in coupes:
        for cle, piste in _SOURCES.items():
            if i0 >= len(piste) - 1:
                continue
            p, st = Q.completer(piste, R, sens, i0, j, temps_max=t, threads=1)
            if p is not None:
                return j, {"source": cle, "coupe": i0, "suffixe": p[i0 + 1:]}, time.time() - t0
    return j, None, time.time() - t0


def main():
    R, sens = int(sys.argv[1]), sys.argv[2]
    w = int(sys.argv[3]) if len(sys.argv) > 3 else os.cpu_count()
    cache = json.load(open(X.CACHE))
    sources = {k: v["piste"] for k, v in sorted(cache.items())
               if k.startswith(f"{sens}|{R}|") and P.verifier(v["piste"], R, sens)}
    print(f"{sens} R={R} : {len(sources)} piste(s) source vérifiée(s)", flush=True)
    if not sources:
        return 1
    couv = json.load(open(COUV)) if os.path.exists(COUV) else {}
    faits = {}
    for j, e in couv.get(f"{sens}|{R}", {}).items():
        if e["source"] in sources:
            p = sources[e["source"]][:e["coupe"] + 1] + e["suffixe"]
            if P.verifier(p, R, sens) and p[-1][1] == [int(j)]:
                faits[int(j)] = e
    for b in {v[-1][1][0] for v in sources.values()}:
        faits.setdefault(b, {"source": next(k for k, v in sources.items() if v[-1][1][0] == b), "coupe": 2 * R,
                             "suffixe": []})
    print(f"  déjà couverts : {len(faits)}", flush=True)
    coupes = [(2 * R - 4, 20), (2 * R - 6, 60), (2 * R - 8, 180), (2 * R - 10, 400)]
    if os.environ.get("DP_COUPES"):                  # « i0:budget,… », par exemple pour les bits restants
        coupes = [tuple(int(x) for x in c.split(":")) for c in os.environ["DP_COUPES"].split(",")]
    print(f"  coupes (indice de couche, budget s) : {coupes}", flush=True)
    manque = [j for j in range(NB) if j not in faits]
    t0, n = time.time(), 0
    with ProcessPoolExecutor(w, initializer=_init, initargs=(sources,)) as ex:
        for j, e, dt in ex.map(_cible, [(R, sens, j, coupes) for j in manque]):
            n += 1
            if e is not None:
                faits[j] = e
            if e is None or n % 32 == 0:
                print(f"  bit {j} : {'coupe ' + str(e['coupe']) if e else 'AUCUNE PISTE'} ({dt:.0f} s) ; "
                      f"{len(faits)}/{NB} couverts, {time.time() - t0:.0f} s", flush=True)
            if n % 16 == 0:
                couv[f"{sens}|{R}"] = {str(k): v for k, v in sorted(faits.items())}
                json.dump(couv, open(COUV, "w"))
    couv[f"{sens}|{R}"] = {str(k): v for k, v in sorted(faits.items())}
    json.dump(couv, open(COUV, "w"))
    print(f"{sens} R={R} : {len(faits)}/{NB} bits couverts → portée DP ≤ {R - 1 if len(faits) == NB else '?'}",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
