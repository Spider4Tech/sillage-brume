# -*- coding: utf-8 -*-
"""Division property de BRUME-1024q : pistes par préfixe de faisceau + complétion EXACTE (CP-SAT), comme
tests/test_dp_exact.py pour BRUME-512 (décomposition de tests/dp_queue.py, chargé tel quel sur les paramètres 1024).

Pourquoi : la recherche par faisceau seule (dp1024.py, largeur 16) ne trouve aucune piste à 12, 13 ni 14 tours dans le
sens direct (10 graines par tour, 14 novembre). Ici le faisceau ne construit que le PRÉFIXE (couches 0 … i0 − 1, poids
minimal), et CP-SAT cherche un suffixe exact de la couche i0 vers un bit isolé au tour R (n'importe lequel, ou un bit
imposé). Le modèle ne garde que les bits atteignables depuis l'état fixé et co-atteignables depuis la cible, avec les
fenêtres de degré de Boura–Canteaut (n = 1 024). Toute piste obtenue est REVÉRIFIÉE par `verifier` (pistes1024).

    python3 dp1024_exact.py R sens [travailleurs] [graines] [budget_s]
Sortie : pistes vérifiées ajoutées au cache de dp1024.py (clé « sens|R|x<graine>.<coupe>.<rang> »), que dp1024.py
reprend ensuite (couverture par prolongement). Cache : $DP_CACHE ou resultats/pistes_division_1024q.json."""
import json
import os
import random
import sys
import time
import types
from concurrent.futures import ProcessPoolExecutor

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.normpath(os.path.join(_ICI, "..", "..", "..", ".."))
sys.path.insert(0, _ICI)
sys.path.insert(0, _RACINE)
import pistes1024 as P  # noqa: E402

NB = P.NB
TH = int(os.environ.get("DP_THREADS", "1"))  # fils CP-SAT par requête
G0 = int(os.environ.get("DP_GRAINE0", "0"))      # première graine (lots de graines disjoints)
COUPES_K = [int(k) for k in os.environ.get("DP_RESTE", "3,4,5").split(",")]  # tours restants aux coupes
CACHE = os.environ.get("DP_CACHE", os.path.join(_RACINE, "resultats", "pistes_division_1024q.json"))


def degres(R=40, n=NB, m=4, ds=3):
    """Borne de Boura–Canteaut (même formule que tests/dp_sat.degres, n = 1 024)."""
    d, out = 1, [1]
    for _ in range(R):
        d = min(ds * d, n - -(-(n - d) // (m - 1)) if d < n - 1 else n - 1, n - 1)
        out.append(d)
    return out


# tests/dp_queue.py sur les paramètres de BRUME-1024q : seules les deux lignes d'import changent
_SRC = os.path.join(_RACINE, "tests", "dp_queue.py")
_t = open(_SRC).read()
for a, b in (("from tests.dp_sat import degres\n", ""),
             ("from tests.pistes_monomiales import NB, N, _couches, table, plan, verifier",
              "from pistes1024 import NB, N, _couches, table, plan, verifier")):
    assert _t.count(a) == 1
    _t = _t.replace(a, b)
Q = types.ModuleType("dp_queue1024")
Q.__file__ = _SRC
Q.degres = degres
exec(compile(_t, _SRC, "exec"), Q.__dict__)
assert Q.NB == 1024


def prefixes(R, sens, i0, graine, largeur=16, tirages=4):
    """Faisceau de P.construire_faisceau arrêté avant la couche i0 : liste de pistes de longueur i0 + 1."""
    rng = random.Random(graine)
    S, L = P._couches(sens)
    U0 = set(range(NB)) - {0}
    faisceau = [(U0, [("depart", sorted(U0))])]
    couches = P.plan(R, sens)
    for idx, c in enumerate(couches[:i0]):
        nouveaux = []
        for U, piste in faisceau:
            for _ in range(tirages):
                if c[0] == "S":
                    V = P._sbox(U, S, c[1], c[2], rng)
                    if V is not None:
                        nouveaux.append((V, piste + [("S", sorted(V))]))
                else:
                    res = P._lin(U, L, rng)
                    if res is not None:
                        nouveaux.append((res[0], piste + [("L", sorted(res[0]), res[1])]))
        if not nouveaux:
            return []
        rng.shuffle(nouveaux)
        nouveaux.sort(key=lambda e: len(e[0]))
        uniques, vus = [], set()
        for U, p in nouveaux:
            if frozenset(U) not in vus:
                vus.add(frozenset(U))
                uniques.append((U, p))
            if len(uniques) == largeur:
                break
        faisceau = uniques
    return [p for _, p in faisceau]


def _tache(arg):
    R, sens, i0, g, budget, k = arg
    t0 = time.time()
    pre = prefixes(R, sens, i0, g)
    sts = []
    for rang, p in enumerate(pre[:k]):
        try:
            q, st = Q.completer(p, R, sens, i0, None, temps_max=budget, threads=TH)
        except RuntimeError as e:                     # suffixe rejeté par le vérificateur : défaut, à signaler
            return R, sens, i0, g, rang, None, f"ERREUR {e}", time.time() - t0, len(p[-1][1])
        if q is not None:
            return R, sens, i0, g, rang, q, st, time.time() - t0, len(p[-1][1])
        sts.append(st)
    return (R, sens, i0, g, None, None, "rien (" + ", ".join(sts) + ")", time.time() - t0,
            min((len(p[-1][1]) for p in pre), default=-1))


def main():
    R, sens = int(sys.argv[1]), sys.argv[2]
    w = int(sys.argv[3]) if len(sys.argv) > 3 else os.cpu_count()
    ng = int(sys.argv[4]) if len(sys.argv) > 4 else w
    budget = float(sys.argv[5]) if len(sys.argv) > 5 else 120
    D = degres()
    # coupes : il reste k tours (2k couches) ; on part de la coupe la plus tardive dont la fenêtre haute D(k) admet
    # le poids minimal attendu, la plus tardive étant la requête la moins chère
    coupes = [2 * (R - k) for k in COUPES_K if R - k > 0]
    print(f"{sens} R={R} : coupes {coupes} (fenêtres hautes D(k) = {[D[k] for k in COUPES_K]}), {ng} graines, "
          f"budget {budget:.0f} s, {w} processus", flush=True)
    cache = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
    trouve = 0
    with ProcessPoolExecutor(w) as ex:
        for R_, s_, i0, g, rang, q, st, dt, poids in ex.map(
                _tache, [(R, sens, i0, g, budget, 2) for i0 in coupes for g in range(G0, G0 + ng)]):
            print(f"  coupe {i0} graine {g} : {st}" + (f" (préfixe {rang}, bit {q[-1][1][0]})" if q else "")
                  + f" ; poids du préfixe {poids} ; {dt:.0f} s", flush=True)
            if q is not None and P.verifier(q, R, sens):
                cache = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
                cache[f"{sens}|{R}|x{g}.{i0}.{rang}"] = {"bit": q[-1][1][0], "piste": q}
                json.dump(cache, open(CACHE, "w"))
                trouve += 1
    print(f"{sens} R={R} : {trouve} piste(s) vérifiée(s)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
