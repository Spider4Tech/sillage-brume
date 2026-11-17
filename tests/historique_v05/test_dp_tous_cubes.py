# -*- coding: utf-8 -*-
"""Division property : bornes hautes valables pour LES 512 CUBES (piste 6).

`test_division_property` couvre les 512 bits de sortie pour un seul cube
(bit 0 inactif). Un attaquant choisit le cube ; ce test étend la borne à
tous les cubes de dimension 511, donc à tous les cubes (un cube plus petit
est inclus dans un cube de dimension 511, et le monôme x^J divise un monôme
présent dès que x^I le divise, pour J ⊆ I).

Lemme de recollement. Une piste du cube 0 et une piste du cube a peuvent
partager tout leur suffixe dès la première couche linéaire, car celle-ci
déplace librement les bits inactifs :
  - inverse (L puis S) : la piste τ du cube 0 a pour état après L₁ un
    ensemble X = tout \\ {k}. Pour le cube a, il suffit d'un couplage
    parfait entre tout \\ {a} et X dans le graphe biparti de L ;
  - direct (S puis L) : l'état de τ après L₁ est X de co-poids c. Pour le
    cube a (nibble q), on choisit une sortie v de la S-box du nibble q
    compatible avec la table exacte, puis une affectation surjective de X
    sur U₁ (chaque sortie active reçoit une arête, chaque entrée active en
    émet au moins une) : couplage saturant U₁, puis sorties restantes
    rattachées à un voisin quelconque.
Le suffixe de τ (mêmes positions, mêmes constantes de tour) reste valide.
Chaque piste recollée est REVÉRIFIÉE par `verifier(…, inactif=a)`, qui ne
connaît pas la construction. La couverture se propage ensuite exactement
comme dans `test_division_property` (prolongement d'un tour par le terme
linéaire de la S-box, plus les pistes directes recollées de chaque tour).
"""
import json
import os
from concurrent.futures import ProcessPoolExecutor

import networkx as nx
import numpy as np

from tests.commun import sauver, RESULTATS
from tests.pistes_monomiales import NB, N, _couches, table, plan, verifier, extension
from tests.test_division_property import bornes_degre

CACHE = os.path.join(RESULTATS, "pistes_division.json")
_L = {}


def _lin(sens):
    if sens not in _L:
        _L[sens] = _couches(sens)
    return _L[sens]


def affecter(U, X, L):
    """Arêtes (a, k) de L avec : chaque k ∈ X reçoit exactement une arête,
    chaque a ∈ U en émet au moins une, toutes de source dans U. None sinon."""
    if len(X) < len(U):
        return None
    G = nx.Graph()
    G.add_nodes_from((("a", a) for a in U), bipartite=0)
    G.add_nodes_from((("k", k) for k in X), bipartite=1)
    Ul = np.array(sorted(U))
    for k in X:
        for a in Ul[L[k, Ul] == 1]:
            G.add_edge(("a", int(a)), ("k", k))
    cpl = nx.bipartite.hopcroft_karp_matching(G, top_nodes=[("a", a) for a in U])
    aretes = []
    for a in U:
        if ("a", a) not in cpl:
            return None                       # entrée active non couverte
        aretes.append((a, cpl[("a", a)][1]))
    pris = {k for _, k in aretes}
    for k in X:
        if k not in pris:                     # sortie en plus : un voisin actif quelconque
            vois = [n for n in G[("k", k)]]
            if not vois:
                return None
            aretes.append((vois[0][1], k))
    return aretes


def recoller(piste, R, sens, a):
    """Piste du cube a ayant le même suffixe que `piste` (cube 0) à partir de
    l'état après la première couche linéaire, ou None."""
    S, L = _lin(sens)
    tout = set(range(NB))
    U0 = tout - {a}
    if sens == "inverse":
        X = set(piste[1][1])
        ar = affecter(U0, X, L)
        if ar is None:
            return None
        return [("depart", sorted(U0)), ("L", sorted(X), ar)] + piste[2:]
    from sillage import brume512 as B
    X = set(piste[2][1])
    q, b = divmod(a, 4)
    T = table(S, int(B.RC[0][q]), 0)
    u = 15 ^ (1 << b)
    for v in sorted((v for v in range(16) if T[u, v]), key=lambda v: -bin(v).count("1")):
        U1 = (tout - set(range(4 * q, 4 * q + 4))) | {4 * q + i for i in range(4) if v >> i & 1}
        ar = affecter(U1, X, L)
        if ar is not None:
            return [("depart", sorted(U0)), ("S", sorted(U1)), ("L", sorted(X), ar)] + piste[3:]
    return None


def _cube(arg):
    """Pour un cube a : bits atteints par tour, par recollement de chaque piste
    du cache, chaque piste recollée étant revérifiée."""
    a, pistes = arg
    atteints, echecs = {}, 0
    for sens, R, bit, p in pistes:
        p2 = recoller(p, R, sens, a)
        if p2 is None or not verifier(p2, R, sens, inactif=a):
            echecs += 1
            continue
        atteints.setdefault(sens, {}).setdefault(R, set()).add(bit)
    return a, {s: {R: sorted(v) for R, v in d.items()} for s, d in atteints.items()}, echecs


def couverture(sens, par_tour, etape):
    """Tour R* où les 512 bits ont une piste (None si non atteint)."""
    if not par_tour:
        return None, {}
    R = min(par_tour)
    couverts, couv = set(par_tour[R]), {R: len(par_tour[R])}
    while len(couverts) < NB and R < min(par_tour) + 12:
        couverts = etape(couverts, R) | set(par_tour.get(R + 1, ()))
        R += 1
        couv[R] = len(couverts)
    return (R if len(couverts) == NB else None), couv


def run(cubes=None, travailleurs=None):
    cache = json.load(open(CACHE))
    pistes = []
    for k, v in sorted(cache.items()):
        sens, R, _ = k.split("|")
        if verifier(v["piste"], int(R), sens):
            pistes.append((sens, int(R), v["bit"], v["piste"]))
    cubes = list(range(NB)) if cubes is None else cubes
    res = {}
    with ProcessPoolExecutor(travailleurs or os.cpu_count()) as ex:
        for a, att, ech in ex.map(_cube, [(a, pistes) for a in cubes], chunksize=4):
            res[a] = (att, ech)
    r_bc = sum(1 for d in bornes_degre() if d < NB - 1)
    m, c = {"cubes": len(cubes), "pistes_du_cache": len(pistes)}, {}
    etapes = {s: extension(s) for s in ("direct", "inverse")}
    bornes = {}
    for sens in ("direct", "inverse"):
        rstar, pire, couvs = {}, None, {}
        for a in cubes:
            par_tour = {R: v for R, v in res[a][0].get(sens, {}).items()}
            Rs, couv = couverture(sens, par_tour, etapes[sens])
            rstar[a] = Rs
            couvs[a] = couv
        ok = all(v is not None for v in rstar.values())
        bornes[sens] = max(rstar.values()) - 1 if ok else None
        hist = {}
        for v in rstar.values():
            hist[str(v)] = hist.get(str(v), 0) + 1
        m[f"{sens}_tour_de_couverture_complete"] = hist
        m[f"{sens}_portee_DP_tous_cubes"] = {"min_prouve": r_bc, "max_verifie": bornes[sens]}
        m[f"{sens}_couverture_cube_0"] = couvs.get(0, {})
        c[f"{sens}_couverture_complete_pour_tous_les_cubes"] = ok
    m["recollements_rejetes"] = sum(e for _, e in res.values())
    m["recollements_reussis"] = len(cubes) * len(pistes) - m["recollements_rejetes"]
    ok = all(v is not None for v in bornes.values())
    m["portee_inside_out_tous_cubes"] = {"min": 2 * r_bc, "max": sum(bornes.values()) if ok else None}
    ref = json.load(open(os.path.join(RESULTATS, "division_property.json")))["mesures"]
    c["memes_bornes_que_pour_le_cube_0"] = ok and all(
        bornes[s] == ref[f"{s}_portee_DP"]["max_verifie"] for s in bornes)
    out = {"controles": c, "mesures": m}
    if cubes == list(range(NB)):
        sauver("dp_tous_cubes", out)
    return out


if __name__ == "__main__":
    import sys
    import time
    t = time.time()
    arg = [int(x) for x in sys.argv[1:]] or None
    print(json.dumps(run(arg), indent=1, ensure_ascii=False))
    print(f"{time.time() - t:.0f} s")
