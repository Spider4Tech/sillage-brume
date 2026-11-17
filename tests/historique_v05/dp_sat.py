# -*- coding: utf-8 -*-
"""Division property bit à bit EXACTE par SAT (pysat / CaDiCaL).

Modèle des pistes monomiales (Hu–Wang–Wang 2020), mêmes règles que
`pistes_monomiales.verifier` :
  - S-box (constante de tour exacte) : (u, v) autorisé ssi x^u apparaît dans
    Π_{b ∈ v} S(x ⊕ c0)_b ⊕ c1 — table complète, transitions par le terme
    constant comprises ;
  - couche linéaire (matrice binaire L) : une variable par arête (k ← a) ;
    chaque sortie active reçoit EXACTEMENT une arête, chaque entrée active
    en émet AU MOINS une (copie puis XOR).
Le cube d'entrée est « tous les bits sauf UN » ; le bit inactif est une
VARIABLE (au plus un bit à 0), si bien qu'une réponse UNSAT vaut pour tous
les cubes de dimension 511 à la fois — et 511 est la plus grande dimension
utile (le cube complet est trivialement équilibré pour une permutation).

Fenêtres de poids (contraintes redondantes, SANS perte de correction) :
  - depuis la fin : un monôme x^u de la couche t apparaît dans le bit de
    sortie seulement si |u| ≤ deg ≤ D(R − t) (borne de Boura–Canteaut, la
    même que pour la portée « par le degré ») ;
  - depuis le cube : les règles de transition bornent le nombre de bits
    inactifs par 3^t après t tours (S-box : ≤ 3 bits inactifs en sortie
    d'un nibble partiel, 0 pour un nibble plein ; couche linéaire : le
    poids ne décroît pas).
Le coefficient du monôme du cube dans le bit de sortie est la parité du
nombre de pistes passant par des monômes de coefficient non nul ; une
piste hors fenêtre traverse un coefficient nul (degré insuffisant) et sa
contribution s'annule (décomposition c = Σ_u d_u·e_u couche par couche).
Donc : UNSAT avec fenêtres ⇒ bit équilibré ; et toute piste trouvée est
une vraie piste (les fenêtres ne font qu'élaguer).

Énumération incrémentale : tant que le solveur trouve une piste vers un bit
de sortie non couvert, on la revérifie indépendamment puis on interdit ce
bit. UNSAT ⇒ aucun bit restant n'a de piste depuis aucun cube : ces bits
sont équilibrés (distingueur prouvé). Couverture complète ⇒ aucun
distingueur DP à ce nombre de tours, pour aucun cube de dimension 511.
"""
import time

import numpy as np
from pysat.card import CardEnc, EncType
from pysat.formula import IDPool
from pysat.solvers import Solver

from tests.pistes_monomiales import NB, N, _couches, plan, table


def degres(R=40, n=NB, m=4, ds=3):
    """D(s) : borne de Boura–Canteaut du degré de s tours (D(0) = 1)."""
    d, out = 1, [1]
    for _ in range(R):
        d = min(ds * d, n - -(-(n - d) // (m - 1)) if d < n - 1 else n - 1, n - 1)
        out.append(d)
    return out


class ModeleDP:
    def __init__(self, R, sens, inactif=None, fenetres=True):
        """inactif=None : bit inactif libre (au plus un) ; sinon imposé."""
        self.R, self.sens = R, sens
        S, L = _couches(sens)
        self.L = L
        self.pool = IDPool()
        self.cl = []
        v = self.pool.id
        self.etats = [[v(("x", 0, b)) for b in range(NB)]]
        self.aretes = []
        couches = plan(R, sens)
        cur = self.etats[0]
        for idx, c in enumerate(couches):
            nxt = [v(("x", idx + 1, b)) for b in range(NB)]
            if c[0] == "S":
                self._sbox(cur, nxt, S, c[1], c[2])
                self.aretes.append(None)
            else:
                self.aretes.append(self._lin(cur, nxt, idx))
            self.etats.append(nxt)
            cur = nxt
        x0 = self.etats[0]
        if inactif is None:                      # au plus un bit inactif
            self.cl += CardEnc.atmost([-x for x in x0], 1, vpool=self.pool,
                                      encoding=EncType.seqcounter).clauses
        else:
            self.cl += [[x0[b]] if b != inactif else [-x0[b]] for b in range(NB)]
        if fenetres:
            self._fenetres(couches)
        sortie = self.etats[-1]                  # exactement un bit de sortie
        self.cl += [sortie[:]]
        self.cl += CardEnc.atmost(sortie, 1, vpool=self.pool, encoding=EncType.seqcounter).clauses

    def _fenetres(self, couches):
        D = degres()
        restants = [sum(1 for c in couches[i:] if c[0] == "S") for i in range(len(couches) + 1)]
        faits = [sum(1 for c in couches[:i] if c[0] == "S") for i in range(len(couches) + 1)]
        for i, e in enumerate(self.etats):
            if 0 < i < len(self.etats) - 1:
                if D[restants[i]] < NB - 1:      # poids ≤ D(tours restants)
                    self.cl += CardEnc.atmost(e, D[restants[i]], vpool=self.pool,
                                              encoding=EncType.seqcounter).clauses
                if 3 ** faits[i] < NB // 2:      # bits inactifs ≤ 3^(tours faits)
                    self.cl += CardEnc.atmost([-x for x in e], 3 ** faits[i], vpool=self.pool,
                                              encoding=EncType.seqcounter).clauses

    def _sbox(self, x, y, S, c0, c1):
        for q in range(N):
            T = table(S, int(c0[q]) if c0 is not None else 0, int(c1[q]) if c1 is not None else 0)
            xs, ys = x[4 * q:4 * q + 4], y[4 * q:4 * q + 4]
            for u in range(16):
                for w in range(16):
                    if not T[u, w]:              # interdit (u, w)
                        self.cl.append([-xs[b] if u >> b & 1 else xs[b] for b in range(4)]
                                       + [-ys[b] if w >> b & 1 else ys[b] for b in range(4)])

    def _lin(self, x, y, idx):
        v = self.pool.id
        A = {}
        for k in range(NB):
            entr = [int(a) for a in np.nonzero(self.L[k])[0]]
            av = [v(("a", idx, k, a)) for a in entr]
            for a, var in zip(entr, av):
                A[(k, a)] = var
                self.cl.append([-var, x[a]])     # arête ⇒ entrée active
            self.cl.append([-y[k]] + av)         # sortie active ⇒ ≥ 1 arête
            for var in av:
                self.cl.append([-var, y[k]])
            self.cl += CardEnc.atmost(av, 1, vpool=self.pool, encoding=EncType.seqcounter).clauses
        for a in range(NB):                      # entrée active ⇒ ≥ 1 arête sortante
            sort = [A[(k, a)] for k in np.nonzero(self.L[:, a])[0]]
            self.cl.append([-x[a]] + sort)
        return A

    def piste(self, modele):
        """Piste au format de pistes_monomiales.verifier."""
        val = set(l for l in modele if l > 0)
        etat = lambda i: sorted(b for b in range(NB) if self.etats[i][b] in val)
        p = [("depart", etat(0))]
        for idx, A in enumerate(self.aretes):
            if A is None:
                p.append(("S", etat(idx + 1)))
            else:
                p.append(("L", etat(idx + 1), [(a, k) for (k, a), var in A.items() if var in val]))
        return p


def couverture(R, sens, couverts, verifier, inactif=None, temps_max=3600, journal=print, solveur="cd15"):
    """Complète `couverts` (bits de sortie ayant une piste au tour R).

    Renvoie (couverts, equilibres, pistes, statut, secondes) ; statut :
    'complet' (512 couverts), 'unsat' (les bits restants sont PROUVÉS
    équilibrés) ou 'temps' (budget épuisé, résultat partiel)."""
    t0 = time.time()
    m = ModeleDP(R, sens, inactif)
    sortie = m.etats[-1]
    couverts, pistes = set(couverts), []
    with Solver(name=solveur, bootstrap_with=m.cl) as s:
        for j in couverts:
            s.add_clause([-sortie[j]])
        while len(couverts) < NB:
            if time.time() - t0 > temps_max:
                return couverts, None, pistes, "temps", time.time() - t0
            if not s.solve():
                return couverts, sorted(set(range(NB)) - couverts), pistes, "unsat", time.time() - t0
            p = m.piste(s.get_model())
            j = p[-1][1][0]
            depart = set(range(NB)) - set(p[0][1])
            ina = next(iter(depart)) if depart else 0
            if not verifier(p, R, sens, inactif=ina):
                raise RuntimeError("piste SAT rejetée par le vérificateur indépendant")
            couverts.add(j)
            pistes.append((ina, j, p))
            s.add_clause([-sortie[j]])
            journal(f"  {sens} R={R} : bit {j} (inactif {ina}) — {len(couverts)}/512, {time.time() - t0:.0f} s")
    return couverts, [], pistes, "complet", time.time() - t0
