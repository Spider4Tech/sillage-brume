# -*- coding: utf-8 -*-
"""Division property : complétion exacte des derniers tours d'une piste
(décomposition de la piste 6).

On garde le préfixe d'une piste vérifiée jusqu'à la couche i0, et l'on
demande à CP-SAT un suffixe exact (mêmes règles que `verifier`) qui mène
de l'état fixé à la couche i0 vers un bit de sortie IMPOSÉ. Le modèle ne
contient que les bits à la fois atteignables depuis l'état fixé et
co-atteignables depuis le bit cible : quelques milliers de variables au
lieu de millions, d'où des requêtes de l'ordre de la seconde.

Toute piste obtenue (préfixe + suffixe) est revérifiée par `verifier`.
"""
import numpy as np
from ortools.sat.python import cp_model

from tests.dp_sat import degres
from tests.pistes_monomiales import NB, N, _couches, table, plan, verifier

_C = {}


def _lin(sens):
    if sens not in _C:
        S, L = _couches(sens)
        _C[sens] = (S, L, [set(map(int, np.nonzero(L[:, a])[0])) for a in range(NB)],
                    [set(map(int, np.nonzero(L[k])[0])) for k in range(NB)])
    return _C[sens]


def _nib(bits):
    return {4 * (b // 4) + i for b in bits for i in range(4)}


def queue(sens, R, i0, etat, cible, temps_max=30, threads=1, bas=True):
    """Suffixe exact de la couche i0 (état `etat`) au bit `cible` au tour R :
    renvoie la liste des étapes (comme dans une piste) ou None (pas de
    suffixe, ou temps dépassé : distingué par le second élément).
    bas=False : sans les fenêtres basses, qui supposent un cube de dimension
    511 (les fenêtres hautes, D(tours restants), valent pour toute piste)."""
    S, L, sorties, entrees = _lin(sens)
    couches = plan(R, sens)
    reste = couches[i0:]
    av = [set(etat)]
    for c in reste:                                  # atteignables
        if c[0] == "S":
            av.append(_nib(av[-1]))
        else:
            av.append(set().union(*(sorties[a] for a in av[-1])))
    ar = [None] * len(av)                            # co-atteignables depuis la cible
    ar[-1] = {cible} if cible is not None else set(range(NB))
    for i in range(len(reste) - 1, -1, -1):
        if reste[i][0] == "S":
            ar[i] = _nib(ar[i + 1])
        else:
            ar[i] = set().union(*(entrees[k] for k in ar[i + 1]))
    act = [av[i] & ar[i] for i in range(len(av))]
    if not set(etat) <= act[0]:
        return None, "unsat"                         # aucun chemin structurel : pas de piste
    m = cp_model.CpModel()
    X = []
    for i, A in enumerate(act):
        X.append({b: m.NewBoolVar("") for b in A})
    val = lambda i, b: X[i].get(b, 0)
    for b in X[0]:
        m.Add(X[0][b] == (1 if b in etat else 0))
    aretes = []
    for i, c in enumerate(reste):
        if c[0] == "S":
            nibs = {b // 4 for b in act[i]} | {b // 4 for b in act[i + 1]}
            for q in nibs:
                T = table(S, int(c[1][q]) if c[1] is not None else 0, int(c[2][q]) if c[2] is not None else 0)
                xs = [val(i, 4 * q + j) for j in range(4)]
                ys = [val(i + 1, 4 * q + j) for j in range(4)]
                tup = [[u >> j & 1 for j in range(4)] + [w >> j & 1 for j in range(4)]
                       for u in range(16) for w in range(16) if T[u, w]
                       and all(not (u >> j & 1) or not isinstance(xs[j], int) for j in range(4))
                       and all(not (w >> j & 1) or not isinstance(ys[j], int) for j in range(4))]
                vx = [v if not isinstance(v, int) else m.NewConstant(0) for v in xs]
                vy = [v if not isinstance(v, int) else m.NewConstant(0) for v in ys]
                m.AddAllowedAssignments(vx + vy, tup)
                # coupes par nibble (valides pour toutes les tables, test_dp_modele) :
                # wt(u) ≤ 3·[v ≠ 0] + [v = F], cw(v) ≤ 3·[u ≠ F] + [u = 0]
                nzv, plv, nzu, plu = (m.NewBoolVar("") for _ in range(4))
                m.AddMaxEquality(nzv, vy); m.AddMinEquality(plv, vy)
                m.AddMaxEquality(nzu, vx); m.AddMinEquality(plu, vx)
                m.Add(sum(vx) <= 3 * nzv + plv)
                m.Add(4 - sum(vy) <= 3 * (1 - plu) + (1 - nzu))
            aretes.append(None)
        else:
            E = {}
            for k in act[i + 1]:
                vs = []
                for a in entrees[k] & act[i]:
                    e = m.NewBoolVar("")
                    E[(k, a)] = e
                    m.AddImplication(e, X[i][a])
                    vs.append(e)
                m.Add(sum(vs) == X[i + 1][k])
            for a in act[i]:
                out = [E[(k, a)] for k in sorties[a] & act[i + 1]]
                if out:                                  # forme linéaire (relaxation LP forte)
                    m.Add(sum(out) >= X[i][a])
                else:
                    m.Add(X[i][a] == 0)
            # redondant : chaque sortie reçoit une arête, chaque entrée en émet ≥ 1
            m.Add(sum(X[i + 1].values()) >= sum(X[i].values()))
            aretes.append(E)
    D = degres()
    for i in range(1, len(act) - 1):                 # fenêtres (indices globaux)
        g = i0 + i
        faits = sum(1 for c in couches[:g] if c[0] == "S")
        rest = sum(1 for c in couches[g:] if c[0] == "S")
        if X[i]:
            if D[rest] < NB - 1:
                m.Add(sum(X[i].values()) <= D[rest])
            lo = max(NB - 3 ** faits if 3 ** faits < NB else 0, NB - D[faits]) if bas else 0
            if lo > 0:
                m.Add(sum(X[i].values()) >= lo)
    m.Add(sum(X[-1].values()) == 1)
    if cible is not None:
        m.Add(X[-1][cible] == 1)
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = temps_max
    s.parameters.num_workers = threads
    st = s.Solve(m)
    if st == cp_model.INFEASIBLE:
        return None, "unsat"
    if st not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        return None, "temps"
    etape = lambda i: sorted(b for b, v in X[i].items() if s.Value(v))
    suf = []
    for i, c in enumerate(reste):
        if c[0] == "S":
            suf.append(("S", etape(i + 1)))
        else:
            suf.append(("L", etape(i + 1), [(a, k) for (k, a), e in aretes[i].items() if s.Value(e)]))
    return suf, "piste"


def completer(piste, R, sens, i0, cible, inactif=0, **kw):
    """Piste complète (préfixe de `piste` jusqu'à la couche i0, puis suffixe
    exact vers `cible`), revérifiée ; (None, statut) sinon."""
    suf, st = queue(sens, R, i0, piste[i0][1], cible, **kw)
    if suf is None:
        return None, st
    p = list(piste[:i0 + 1]) + suf
    if not verifier(p, R, sens, inactif=inactif):
        raise RuntimeError("suffixe CP-SAT rejeté par le vérificateur indépendant")
    return p, st
