# -*- coding: utf-8 -*-
"""Division property EXACTE — même modèle que tests/dp_sat.py, résolu par
CP-SAT (OR-Tools) : contraintes de table pour les S-box, sommes natives
pour la couche linéaire et les fenêtres de poids, recherche parallèle.

Règles (identiques à pistes_monomiales.verifier), bit inactif libre (au
plus un), fenêtres de poids sans perte de correction : voir dp_sat.py.
Fenêtre supplémentaire (théorème de Boura–Canteaut, IEEE-IT 2013,
deg(G∘F) ≤ n − ⌈(n − deg G)/deg(F⁻¹)⌉) : le monôme du cube (degré 511)
n'apparaît dans le produit des bits actifs v de la couche t que si
n − ⌈(n − |v|)/D′(t)⌉ ≥ 511, soit |v| ≥ 512 − D′(t), où D′(t) borne le
degré des t premiers tours inversés (S⁻¹ de degré 3). Une piste qui viole
cette fenêtre traverse un coefficient nul : même argument de parité.
Chaque piste trouvée est revérifiée indépendamment par `verifier`.
"""
import time

import numpy as np
from ortools.sat.python import cp_model

from tests.dp_sat import degres
from tests.pistes_monomiales import NB, N, _couches, plan, table


class ModeleCP:
    def __init__(self, R, sens, inactif=None, fenetres=True, bc_inverse=True, cible=None, coupes=False):
        self.R, self.sens = R, sens
        S, L = _couches(sens)
        m = self.m = cp_model.CpModel()
        couches = plan(R, sens)
        self.etats = [[m.NewBoolVar(f"x0_{b}") for b in range(NB)]]
        self.aretes = []
        for idx, c in enumerate(couches):
            x = self.etats[-1]
            y = [m.NewBoolVar(f"x{idx + 1}_{b}") for b in range(NB)]
            if c[0] == "S":
                for q in range(N):
                    T = table(S, int(c[1][q]) if c[1] is not None else 0, int(c[2][q]) if c[2] is not None else 0)
                    tup = [[u >> b & 1 for b in range(4)] + [w >> b & 1 for b in range(4)]
                           for u in range(16) for w in range(16) if T[u, w]]
                    m.AddAllowedAssignments(x[4 * q:4 * q + 4] + y[4 * q:4 * q + 4], tup)
                    if coupes:
                        self._coupes_nibble(x[4 * q:4 * q + 4], y[4 * q:4 * q + 4])
                self.aretes.append(None)
            else:
                A = {}
                for k in range(NB):
                    entr = [int(a) for a in np.nonzero(L[k])[0]]
                    av = []
                    for a in entr:
                        var = m.NewBoolVar(f"a{idx}_{k}_{a}")
                        A[(k, a)] = var
                        av.append(var)
                        m.AddImplication(var, x[a])
                    m.Add(sum(av) == y[k])              # sortie active ⇔ exactement une arête
                for a in range(NB):
                    sort = [A[(k, a)] for k in np.nonzero(L[:, a])[0]]
                    m.AddBoolOr(sort).OnlyEnforceIf(x[a])
                self.aretes.append(A)
            self.etats.append(y)
        x0 = self.etats[0]
        if inactif is None:
            m.Add(sum(x0) >= NB - 1)
        else:
            for b in range(NB):
                m.Add(x0[b] == (0 if b == inactif else 1))
        if fenetres:
            D = degres()
            restants = [sum(1 for c in couches[i:] if c[0] == "S") for i in range(len(couches) + 1)]
            faits = [sum(1 for c in couches[:i] if c[0] == "S") for i in range(len(couches) + 1)]
            for i, e in enumerate(self.etats):
                if 0 < i < len(self.etats) - 1:
                    if D[restants[i]] < NB - 1:
                        m.Add(sum(e) <= D[restants[i]])
                    bas = NB - 3 ** faits[i] if 3 ** faits[i] < NB else 0
                    if bc_inverse:                      # D′ = D (S et S⁻¹ de degré 3)
                        bas = max(bas, NB - D[faits[i]])
                    if bas > 0:
                        m.Add(sum(e) >= bas)
        self.sortie = self.etats[-1]
        m.Add(sum(self.sortie) == 1)
        if cible is not None:                  # bit de sortie imposé
            m.Add(self.sortie[cible] == 1)

    def _coupes_nibble(self, u, v):
        """Coupes linéaires redondantes (déjà impliquées par la table, mais
        visibles par la relaxation LP) : wt(u) ≤ 3·[v ≠ 0] + [v = F] et
        cw(v) ≤ 3·[u ≠ F] + [u = 0]. Valables pour toutes les tables exactes
        (S et S⁻¹ de degré 3, toutes constantes : vérifié par
        tests/test_dp_modele.py). Elles rendent la borne de Boura–Canteaut
        accessible au LP entre deux couches quelconques."""
        m = self.m
        def ou(bits):
            z = m.NewBoolVar("")
            m.AddMaxEquality(z, bits)
            return z
        def et(bits):
            z = m.NewBoolVar("")
            m.AddMinEquality(z, bits)
            return z
        nzv, plv, nzu, plu = ou(v), et(v), ou(u), et(u)
        m.Add(sum(u) <= 3 * nzv + plv)
        m.Add(4 - sum(v) <= 3 * (1 - plu) + (1 - nzu))

    def piste(self, sol):
        etat = lambda i: sorted(b for b in range(NB) if sol.Value(self.etats[i][b]))
        p = [("depart", etat(0))]
        for idx, A in enumerate(self.aretes):
            if A is None:
                p.append(("S", etat(idx + 1)))
            else:
                p.append(("L", etat(idx + 1), [(a, k) for (k, a), var in A.items() if sol.Value(var)]))
        return p


def piste_vers(R, sens, inactif, cible, verifier, temps_max=1800, threads=12, coupes=False):
    """Requête ciblée : existe-t-il une piste du cube (bit `inactif` à 0)
    vers le bit `cible` au tour R ? Renvoie ('piste', p), ('unsat', None) —
    bit PROUVÉ équilibré pour ce cube — ou ('temps', None)."""
    M = ModeleCP(R, sens, inactif=inactif, cible=cible, coupes=coupes)
    sol = cp_model.CpSolver()
    sol.parameters.max_time_in_seconds = temps_max
    sol.parameters.num_workers = threads
    st = sol.Solve(M.m)
    if st == cp_model.INFEASIBLE:
        return "unsat", None, sol.WallTime()
    if st in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        p = M.piste(sol)
        if not verifier(p, R, sens, inactif=inactif):
            raise RuntimeError("piste CP-SAT rejetée par le vérificateur indépendant")
        return "piste", p, sol.WallTime()
    return "temps", None, sol.WallTime()


def imposer(M, piste):
    """Fixe le modèle sur une piste donnée (test de complétude)."""
    for i, (_, etat, *_r) in enumerate(piste):
        actifs = set(etat)
        for b in range(NB):
            M.m.Add(M.etats[i][b] == (1 if b in actifs else 0))
    for A, etape in zip(M.aretes, piste[1:]):
        if A is not None:
            pris = {(k, a) for a, k in etape[2]}
            for (k, a), var in A.items():
                M.m.Add(var == (1 if (k, a) in pris else 0))


def couverture(R, sens, couverts, verifier, inactif=None, temps_max=3600, journal=print, threads=12,
               sauvegarde=None):
    """Comme dp_sat.couverture : (couverts, equilibres, pistes, statut, s)."""
    t0 = time.time()
    M = ModeleCP(R, sens, inactif)
    couverts, pistes = set(couverts), []
    interdits = M.m.NewBoolVar("rien")          # sert de pivot pour les interdictions
    M.m.Add(interdits == 0)
    while len(couverts) < NB:
        reste = temps_max - (time.time() - t0)
        if reste <= 0:
            return couverts, None, pistes, "temps", time.time() - t0
        for j in couverts:
            M.m.Add(M.sortie[j] == 0)
        couverts_ajoutes = set(couverts)
        sol = cp_model.CpSolver()
        sol.parameters.max_time_in_seconds = reste
        sol.parameters.num_workers = threads
        st = sol.Solve(M.m)
        if st == cp_model.INFEASIBLE:
            return couverts, sorted(set(range(NB)) - couverts), pistes, "unsat", time.time() - t0
        if st not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            return couverts, None, pistes, "temps", time.time() - t0
        p = M.piste(sol)
        j = p[-1][1][0]
        depart = set(range(NB)) - set(p[0][1])
        ina = next(iter(depart)) if depart else 0
        if not verifier(p, R, sens, inactif=ina):
            raise RuntimeError("piste CP-SAT rejetée par le vérificateur indépendant")
        couverts.add(j)
        pistes.append((ina, j, p))
        if sauvegarde:                           # au fil de l'eau : rien n'est perdu à l'arrêt
            import json
            json.dump([{"inactif": i_, "bit": j_, "piste": p_} for i_, j_, p_ in pistes], open(sauvegarde, "w"))
        journal(f"  {sens} R={R} : bit {j} (inactif {ina}) — {len(couverts)}/512, {time.time() - t0:.0f} s")
        del couverts_ajoutes
    return couverts, [], pistes, "complet", time.time() - t0
