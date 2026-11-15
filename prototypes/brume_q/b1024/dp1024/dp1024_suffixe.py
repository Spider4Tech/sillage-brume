# -*- coding: utf-8 -*-
"""Division property de BRUME-1024q, sens DIRECT, tour R : trancher par la fin de la piste.

Toute piste monomiale de R tours partant du cube {0..1023} − {0} a, après t tours, un poids d'au moins
1 024 − D(t), D(t) étant la borne de degré de Boura–Canteaut de t tours inverses (fenêtre basse, la même que pour
BRUME-512, `tests/test_division_property.bornes_degre`). Elle a aussi un poids d'au plus D(R − t) (fenêtre haute).
Donc : s'il n'existe AUCUNE suite de R − t* tours (règles exactes : tables des monômes de la S-box avec la constante du
tour, copie/XOR de la couche linéaire) qui parte d'un ensemble quelconque de poids ≥ 1 024 − D(t*) et finisse sur le
bit j, alors aucune piste de R tours n'aboutit au bit j : le bit j est ÉQUILIBRÉ à R tours (division property).
Réciproquement, une suite trouvée n'est qu'une fin possible : il reste à la raccorder au cube (dp1024_prefixe).

Le modèle n'est restreint que par des faits prouvés : le cône arrière du bit j (bits qui peuvent influencer j par les
règles), et les fenêtres de poids. Il est exact par ailleurs.

    python3 dp1024_suffixe.py R t* bits [secondes] [fils]          bits : « tous », « a-b » ou « j,k,… »
    python3 dp1024_suffixe.py valider                              contrôle sur des pistes connues de 13 tours
Sortie : une ligne JSON par bit (sat / unsat / indécis, temps, poids de la suite trouvée)."""
import json
import os
import sys
import time

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.normpath(os.path.join(_ICI, "..", "..", "..", ".."))
sys.path.insert(0, _ICI)
sys.path.insert(0, _RACINE)
import numpy as np  # noqa: E402
import pistes1024 as P  # noqa: E402
from tests.test_division_property import bornes_degre  # noqa: E402

NB, N = P.NB, P.N
S, L = P._couches("direct")
D = [1] + bornes_degre(n=NB, R=40)          # D[t] : borne de degré de t tours (D[0] = 1)
COLS = [np.nonzero(L[k])[0].tolist() for k in range(NB)]   # entrées a reliées à la sortie k


def bas(t):
    return max(1, NB - D[t])


def haut(R, t):
    return D[R - t] if R - t > 0 else 1


def cones(R, t0, j):
    """Bits autorisés : X[t] après la couche L du tour t (t0 ≤ t ≤ R), Y[t] après la couche S du tour t (t > t0).
    j : un bit, ou un ensemble de bits (fin imposée)."""
    X = {R: set(j) if isinstance(j, (set, frozenset, list, tuple)) else {j}}
    Y = {}
    for t in range(R, t0, -1):
        Y[t] = {a for k in X[t] for a in COLS[k]}
        nib = {a // 4 for a in Y[t]}
        X[t - 1] = {4 * q + b for q in nib for b in range(4)}
    return X, Y


def modele(R, t0, j, depart=None, fenetres_debut=True):
    from ortools.sat.python import cp_model
    m = cp_model.CpModel()
    X, Y = cones(R, t0, j)
    x = {t: {a: m.NewBoolVar(f"x{t}_{a}") for a in X[t]} for t in range(t0, R + 1)}
    y = {t: {a: m.NewBoolVar(f"y{t}_{a}") for a in Y[t]} for t in range(t0 + 1, R + 1)}
    z = m.NewConstant(0)
    E = {}
    for t in range(t0 + 1, R + 1):
        rc = P.B.RC[t - 1]                                   # tour t (1-indicé) : constante RC[t − 1]
        for q in sorted({a // 4 for a in X[t - 1]}):
            T = P.table(S, int(rc[q]), 0)
            ins = [x[t - 1].get(4 * q + b, z) for b in range(4)]
            outs = [y[t].get(4 * q + b, z) for b in range(4)]
            permis = [[u >> b & 1 for b in range(4)] + [v >> b & 1 for b in range(4)]
                      for u in range(16) for v in range(16) if T[u, v]]
            m.AddAllowedAssignments(ins + outs, permis)
        # couche linéaire : chaque sortie active reçoit exactement une arête d'une entrée active ; chaque entrée active
        # en émet au moins une
        e = {}
        E[t] = e
        for k in X[t]:
            for a in COLS[k]:
                if a in y[t]:
                    e[a, k] = m.NewBoolVar("")
                    m.AddImplication(e[a, k], y[t][a])
            m.Add(sum(e[a, k] for a in COLS[k] if (a, k) in e) == x[t][k])
        for a in y[t]:
            sortants = [e[a, k] for k in X[t] if (a, k) in e]
            m.Add(sum(sortants) >= y[t][a]) if sortants else m.Add(y[t][a] == 0)
        for k in X[t]:
            for a in COLS[k]:
                if (a, k) in e:
                    m.AddImplication(e[a, k], x[t][k])
    fin = set(j) if isinstance(j, (set, frozenset, list, tuple)) else {j}
    Rtot = R if len(fin) == 1 else None                   # fenêtres hautes seulement si la fin est un bit
    for t in range(t0, R + 1):                            # fenêtres de poids prouvées
        if t > 0 or fenetres_debut:
            m.Add(sum(x[t].values()) >= bas(t))
        if Rtot is not None:
            m.Add(sum(x[t].values()) <= haut(R, t))
    for a, v in x[R].items():
        m.Add(v == int(a in fin))
    if depart is not None:                                # contrôle : départ imposé
        assert set(depart) <= set(x[t0]), "départ hors du cône arrière"
        for a, v in x[t0].items():
            m.Add(v == int(a in depart))
    m._aretes = E                                         # arêtes, pour reconstruire la piste
    return m, x, y


def resoudre(R, t0, j, secondes=600, fils=1, depart=None):
    from ortools.sat.python import cp_model
    t = time.time()
    m, x, y = modele(R, t0, j, depart)
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = secondes
    s.parameters.num_workers = fils
    st = s.Solve(m)
    nom = {cp_model.OPTIMAL: "sat", cp_model.FEASIBLE: "sat", cp_model.INFEASIBLE: "unsat"}.get(st, "indecis")
    res = {"R": R, "t0": t0, "bit": j, "resultat": nom, "s": round(time.time() - t, 1), "bas_t0": bas(t0)}
    if nom == "sat":
        res["poids"] = [sum(s.Value(v) for v in x[u].values()) for u in range(t0, R + 1)]
        res["depart"] = sorted(a for a, v in x[t0].items() if s.Value(v))
    return res


def valider():
    """Le modèle doit accepter la fin de pistes de 13 tours vérifiées (départ imposé à leur couche t0)."""
    cache = json.load(open(os.path.join(_RACINE, "resultats", "pistes_division_1024q.json")))
    n = ok = 0
    for cle, e in sorted(cache.items()):
        if not cle.startswith("direct|13|"):
            continue
        piste = e["piste"]
        if not P.verifier(piste, 13, "direct"):
            continue
        j = piste[-1][1][0]
        for t0 in (9, 10):
            depart = set(piste[2 * t0][1])                  # couche après la couche L du tour t0
            r = resoudre(13, t0, j, 120, 2, depart)
            n += 1
            ok += r["resultat"] == "sat"
            print(json.dumps({"cle": cle, "t0": t0, "bit": j, "poids_depart": len(depart), "resultat": r["resultat"]}),
                  flush=True)
        if n >= 8:
            break
    print(f"validation : {ok}/{n} fins de pistes connues acceptées par le modèle", flush=True)
    return 0 if ok == n and n > 0 else 1


def main():
    if sys.argv[1] == "valider":
        return valider()
    if sys.argv[1] == "complete":                         # complete R j tm s1 s2 fils → resultats/pistes_12_1024q.json
        R, j, tm = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
        s1, s2, fils = float(sys.argv[5]), float(sys.argv[6]), int(sys.argv[7])
        p = piste_complete(R, j, tm, s1, s2, fils, journal=lambda s: print(s, flush=True))
        if p is not None:
            f = os.environ.get("DP_PISTES12", os.path.join(_RACINE, "resultats", f"pistes_{R}_1024q.json"))
            d = json.load(open(f)) if os.path.exists(f) else {}
            d[f"direct|{R}|complet.{j}.{tm}"] = {"bit": j, "piste": p}
            json.dump(d, open(f, "w"))
        return 0 if p is not None else 1
    R, t0 = int(sys.argv[1]), int(sys.argv[2])
    sel = sys.argv[3]
    secondes = float(sys.argv[4]) if len(sys.argv) > 4 else 600
    fils = int(sys.argv[5]) if len(sys.argv) > 5 else 1
    if sel == "tous":
        bits = range(NB)
    elif "-" in sel:
        a, b = map(int, sel.split("-"))
        bits = range(a, b)
    else:
        bits = [int(v) for v in sel.split(",")]
    for j in bits:
        print(json.dumps(resoudre(R, t0, j, secondes, fils)), flush=True)
    return 0



def piste_complete(R, j, tm, s1=900, s2=3600, fils=8, journal=print):
    """Fin libre depuis la couche tm (fenêtres), puis début imposé : du cube (couche 0) jusqu'à l'ensemble de départ de la
    fin. Rend une piste au format de la suite, VÉRIFIÉE par `verifier`, ou None."""
    from ortools.sat.python import cp_model
    t = time.time()
    m1, x1, y1 = modele(R, tm, j)
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = s1
    s.parameters.num_workers = fils
    if s.Solve(m1) not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        journal(f"bit {j} : pas de fin trouvée depuis la couche {tm} ({time.time() - t:.0f} s)")
        return None
    A = sorted(a for a, v in x1[tm].items() if s.Value(v))
    fin = [[sorted(a for a, v in y1[u].items() if s.Value(v)), sorted(a for a, v in x1[u].items() if s.Value(v)),
            sorted([a, k] for (a, k), v in m1._aretes[u].items() if s.Value(v))] for u in range(tm + 1, R + 1)]
    journal(f"bit {j} : fin trouvée depuis la couche {tm}, poids {len(A)} ({time.time() - t:.0f} s) ; début …")
    cube = set(range(NB)) - {0}
    m2, x2, y2 = modele(tm, 0, set(A), depart=cube, fenetres_debut=False)
    s2_ = cp_model.CpSolver()
    s2_.parameters.max_time_in_seconds = s2
    s2_.parameters.num_workers = fils
    st = s2_.Solve(m2)
    if st not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        journal(f"bit {j} : début {'impossible' if st == cp_model.INFEASIBLE else 'non trouvé'} pour cette fin "
                f"({time.time() - t:.0f} s)")
        return None
    piste = [["depart", sorted(cube)]]
    for u in range(1, tm + 1):
        piste.append(["S", sorted(a for a, v in y2[u].items() if s2_.Value(v))])
        piste.append(["L", sorted(a for a, v in x2[u].items() if s2_.Value(v)),
                      sorted([a, k] for (a, k), v in m2._aretes[u].items() if s2_.Value(v))])
    for Yu, Xu, Eu in fin:
        piste.append(["S", Yu])
        piste.append(["L", Xu, Eu])
    ok = P.verifier(piste, R, "direct") and piste[-1][1] == [j]
    journal(f"bit {j} : piste de {R} tours {'VÉRIFIÉE' if ok else 'REJETÉE par verifier'} ({time.time() - t:.0f} s), "
            f"poids {[len(e[1]) for e in piste[::2]]}")
    return piste if ok else None


if __name__ == "__main__":
    sys.exit(main())
