# -*- coding: utf-8 -*-
"""Construction et vérification de pistes monomiales (division property).

Construction gloutonne guidée par la structure : la couche linéaire est
résolue par un flot de coût minimal (chaque bit d'entrée actif → une sortie
distincte, chaque sortie active ← exactement une arête) qui, tant que le
poids W dépasse 3·128, minimise les nibbles pleins (trous dans des nibbles
distincts), puis empaquette les bits par 3 dans le moins de nibbles
possible ; la S-box choisit la sortie de poids minimal autorisée par sa
table de monômes (constante de tour exacte). Toute piste renvoyée est
revérifiée pas à pas par `verifier`, indépendamment de la construction.
"""
import random

import networkx as nx
import numpy as np

from sillage import brume512 as B

N = B.N
NB = 4 * N


def anf(f):
    """Transformée de Möbius d'une fonction booléenne à 4 variables."""
    a = list(f)
    for i in range(4):
        for x in range(16):
            if x >> i & 1:
                a[x] ^= a[x ^ (1 << i)]
    return a


def matrice_binaire(Mn):
    """Matrice 512×512 sur GF(2) d'une couche linéaire GF(16)^128."""
    L = np.zeros((NB, NB), np.uint8)
    for j in range(N):
        for i in range(N):
            c = int(Mn[j, i])
            if c:
                for k in range(4):
                    img = int(B.GMUL[c, 1 << k])
                    for r in range(4):
                        if img >> r & 1:
                            L[4 * j + r, 4 * i + k] = 1
    return L


def _couches(sens):
    S = B.SBOX.tolist()
    Mn = np.zeros((N, N), np.uint8)
    for j in range(N):
        for k in range(B.E_SEG[j], B.E_SEG[j + 1]):
            Mn[j, B.E_I[k]] = B.E_C[k]
    if sens == "inverse":
        Sinv = [0] * 16
        for x in range(16):
            Sinv[S[x]] = x
        S = Sinv
        Mn = B._gauss_gf16_inverse(Mn)
    return S, matrice_binaire(Mn)


_T = {}


def table(S, c0, c1):
    key = (tuple(S), c0, c1)
    if key not in _T:
        T = np.zeros((16, 16), bool)
        for v in range(16):
            f = [int(all(((S[x ^ c0] ^ c1) >> b) & 1 for b in range(4) if v >> b & 1)) for x in range(16)]
            a = anf(f)
            for u in range(16):
                T[u, v] = bool(a[u])
        _T[key] = T
    return _T[key]


def plan(R, sens):
    """Suite des couches : ('S', c0, c1) ou ('L',)."""
    out = []
    for r in range(R):
        if sens == "direct":
            out += [("S", B.RC[r], None), ("L",)]
        else:
            out += [("L",), ("S", None, B.RC[B.N_ROUNDS - 1 - r])]
    return out


def _sbox(U, S, c0, c1, rng):
    V, choix = set(), []
    for q in range(N):
        u = sum(1 << b for b in range(4) if 4 * q + b in U)
        if not u:
            continue
        T = table(S, int(c0[q]) if c0 is not None else 0, int(c1[q]) if c1 is not None else 0)
        cands = [v for v in range(1, 16) if T[u, v]]
        if not cands:
            return None
        wmin = min(bin(v).count("1") for v in cands)
        v = rng.choice([v for v in cands if bin(v).count("1") == wmin])
        V.update(4 * q + b for b in range(4) if v >> b & 1)
    return V


def _empaqueter(A, L, rng):
    """W ≤ 3·128 : choisit gloutonnement les nibbles cibles qui absorbent le
    plus de bits actifs (≤ 3 chacun, sorties distinctes), puis complète."""
    restants = set(A)
    pris, aretes = set(), []
    portee = {a: {} for a in A}                 # a -> {nibble: [sorties]}
    for a in A:
        for k in np.nonzero(L[:, a])[0]:
            portee[a].setdefault(int(k) // 4, []).append(int(k))
    while restants:
        score = {}
        for a in restants:
            for q, ks in portee[a].items():
                if any(k not in pris for k in ks):
                    score[q] = score.get(q, 0) + 1
        if not score:
            return None
        meilleur = max(score.values())
        q = rng.choice([q for q, v in score.items() if v == meilleur])
        libres = [k for k in range(4 * q, 4 * q + 4) if k not in pris]
        cands = [a for a in restants if q in portee[a]]
        rng.shuffle(cands)
        n_pris = 0
        for a in cands:                          # affectation simple, ≤ 3 par nibble
            if n_pris >= 3:
                break
            ks = [k for k in portee[a][q] if k in libres]
            if ks:
                k = rng.choice(ks)
                libres.remove(k); pris.add(k)
                aretes.append((a, k)); restants.discard(a); n_pris += 1
    return pris, aretes


def _lin(A, L, rng, cible_un_nibble=False, sortie_unique=False):
    """Flot de coût minimal : renvoie (V, arêtes) ou None."""
    A = sorted(A)
    W = len(A)
    if W <= 3 * N and not cible_un_nibble and not sortie_unique:
        return _empaqueter(A, L, rng)
    if sortie_unique:
        if W != 1:
            return None
        k = int(rng.choice(np.nonzero(L[:, A[0]])[0]))
        return {k}, [(A[0], k)]
    nibbles = list(range(N))
    if cible_un_nibble:
        rng.shuffle(nibbles)
        essais = [[q] for q in nibbles]
    else:
        essais = [nibbles]
    prio = {q: rng.random() for q in range(N)}
    for autorises in essais:
        G = nx.DiGraph()
        G.add_node("s", demand=-W)
        G.add_node("t", demand=W)
        for a in A:
            G.add_edge("s", ("a", a), capacity=1, weight=0)
            for k in np.nonzero(L[:, a])[0]:
                if k // 4 in autorises:
                    G.add_edge(("a", a), ("o", int(k)), capacity=1, weight=0)
        for q in autorises:
            for b in range(4):
                if G.has_node(("o", 4 * q + b)):
                    G.add_edge(("o", 4 * q + b), ("n", q), capacity=1, weight=0)
            if W > 3 * N:      # minimiser les nibbles pleins
                G.add_edge(("n", q), "t", capacity=3, weight=0)
                G.add_edge(("n", q), ("n4", q), capacity=1, weight=1000)
                G.add_edge(("n4", q), "t", capacity=1, weight=0)
            else:              # empaqueter par 3 dans les nibbles prioritaires
                G.add_edge(("n", q), "t", capacity=3, weight=int(1000 * prio[q]))
        try:
            flux = nx.min_cost_flow(G)
        except nx.NetworkXUnfeasible:
            continue
        aretes = [(a, k[1]) for a in A for k, f in flux[("a", a)].items() if f]
        return {k for _, k in aretes}, aretes
    return None


def construire(R, sens, inactif=0, graine=0):
    """Tente une piste du cube (tous bits sauf `inactif`) vers un bit isolé
    au tour R. Renvoie (bit, piste) ou (None, None)."""
    rng = random.Random(graine)
    S, L = _couches(sens)
    U = set(range(NB)) - {inactif}
    piste = [("depart", sorted(U))]
    couches = plan(R, sens)
    for idx, c in enumerate(couches):
        reste = couches[idx + 1:]
        if c[0] == "S":
            U = _sbox(U, S, c[1], c[2], rng)
            if U is None:
                return None, None
            piste.append(("S", sorted(U)))
        else:
            if not reste:
                res = _lin(U, L, rng, sortie_unique=True)
            elif len(reste) == 1 or (len(reste) == 2 and reste[1][0] == "L" and len(U) <= 3):
                # avant la dernière S-box (inverse) ou S+L finales (direct) : un seul nibble
                res = _lin(U, L, rng, cible_un_nibble=len(U) <= 3) if len(U) <= 3 else None
            else:
                res = _lin(U, L, rng)
            if res is None:
                return None, None
            U, aretes = res
            piste.append(("L", sorted(U), aretes))
    if len(U) != 1:
        return None, None
    return next(iter(U)), piste


def verifier(piste, R, sens, inactif=0):
    """Vérification indépendante : chaque transition respecte les règles
    exactes (table des monômes de la S-box, copie/XOR de la couche linéaire)."""
    S, L = _couches(sens)
    couches = plan(R, sens)
    U = set(piste[0][1])
    if U != set(range(NB)) - {inactif} and not (set(range(NB)) - {inactif}) <= U:
        return False
    for c, etape in zip(couches, piste[1:]):
        V = set(etape[1])
        if c[0] == "S":
            for q in range(N):
                u = sum(1 << b for b in range(4) if 4 * q + b in U)
                v = sum(1 << b for b in range(4) if 4 * q + b in V)
                T = table(S, int(c[1][q]) if c[1] is not None else 0, int(c[2][q]) if c[2] is not None else 0)
                if not T[u, v]:
                    return False
        else:
            aretes = etape[2]
            if any(not L[k, a] or a not in U or k not in V for a, k in aretes):
                return False
            if {a for a, _ in aretes} != U:
                return False
            entrants = [k for _, k in aretes]
            if sorted(entrants) != sorted(V) or len(set(entrants)) != len(entrants):
                return False
        U = V
    return len(U) == 1


def construire_faisceau(R, sens, inactif=0, graine=0, largeur=8, tirages=4):
    """Recherche par faisceau : à chaque couche, `tirages` choix aléatoires
    par état, on garde les `largeur` états de poids minimal. Renvoie
    (bit, piste) d'une piste vers un bit isolé au tour R, ou (None, None)."""
    rng = random.Random(graine)
    S, L = _couches(sens)
    U0 = set(range(NB)) - {inactif}
    faisceau = [(U0, [("depart", sorted(U0))])]
    couches = plan(R, sens)
    for idx, c in enumerate(couches):
        reste = couches[idx + 1:]
        nouveaux = []
        for U, piste in faisceau:
            for _ in range(tirages):
                if c[0] == "S":
                    V = _sbox(U, S, c[1], c[2], rng)
                    if V is not None:
                        nouveaux.append((V, piste + [("S", sorted(V))]))
                    continue
                if not reste:
                    res = _lin(U, L, rng, sortie_unique=True)
                elif (len(reste) == 1 or (len(reste) == 2 and reste[1][0] == "L")) and len(U) <= 3:
                    res = _lin(U, L, rng, cible_un_nibble=True)
                    if res is None:
                        res = _lin(U, L, rng)
                else:
                    res = _lin(U, L, rng)
                if res is not None:
                    nouveaux.append((res[0], piste + [("L", sorted(res[0]), res[1])]))
        if not nouveaux:
            return None, None
        rng.shuffle(nouveaux)
        nouveaux.sort(key=lambda e: len(e[0]))
        uniques, vus = [], set()
        for U, p in nouveaux:
            cle = frozenset(U)
            if cle not in vus:
                vus.add(cle)
                uniques.append((U, p))
            if len(uniques) == largeur:
                break
        faisceau = uniques
    for U, piste in faisceau:
        if len(U) == 1:
            return next(iter(U)), piste
    return None, None


def extension(sens):
    """Prolongement d'une piste finissant sur un bit isolé, d'un tour :
    terme linéaire de la S-box (constante exacte) puis arête de L (direct),
    ou arête de L^{-1} puis terme linéaire de S^{-1} (inverse)."""
    S, L = _couches(sens)

    def terme_lin(c0, c1, a, b):
        return bool(anf([((S[x ^ c0] ^ c1) >> b) & 1 for x in range(16)])[1 << a])

    def etape(bits, r):
        out = set()
        for p in bits:
            if sens == "direct":
                q, a = divmod(p, 4)
                for b in range(4):
                    if terme_lin(int(B.RC[r][q]), 0, a, b):
                        out.update(int(k) for k in np.nonzero(L[:, 4 * q + b])[0])
            else:
                for k in np.nonzero(L[:, p])[0]:
                    q2, a2 = divmod(int(k), 4)
                    for b in range(4):
                        if terme_lin(0, int(B.RC[B.N_ROUNDS - 1 - r][q2]), a2, b):
                            out.add(4 * q2 + b)
        return out
    return etape
