# -*- coding: utf-8 -*-
"""Cryptanalyse de BRUME-512 : structure du graphe, algèbre, activité, annulation de pistes.
  1. Graphe : 4-cycles, voisins communs, expansion, paires rotationnelles et rotationnelles-XOR (quasi-symétrie
     du groupe), sous-corps, Frobenius.
  2. Couche linéaire : polynôme minimal binaire, degrés de ses facteurs, plus petit sous-espace invariant.
  3. S-box : relations quadratiques, polynôme univarié, sous-corps ; 3 bis. Frobenius (M ⊕ M⁽²⁾, table Frobenius-XOR, un tour).
  4. Activité : borne basse prouvée par CP-SAT sur r tours (modèle tronqué valide), d'où mieux que 128 à 32 tours.
  5. Algébrique : récupération d'état par SAT sur tours réduits ; estimation de régularité (hypothèse semi-régulière).
  6. Pistes monomiales sur mini-BRUME (resultats/mini_brume_instances.json) : un bit à somme réelle nulle mais qui
     possède une piste est une ANNULATION : c'est ce que la division property ne peut pas voir.
Modèle réduit pour le point 6 : il éclaire, il ne prouve rien pour 512 bits. Budgets : SILLAGE_INTENSITE."""
import functools
import itertools
import json
import math
import multiprocessing as mp
import os
import random
import time

import numpy as np
from ortools.sat.python import cp_model
from pysat.card import CardEnc, EncType
from pysat.solvers import Cadical153, Glucose4

from tests.commun import sauver, RACINE
from sillage import brume512 as B

N = B.N
C = np.array(B.TF.COEF, dtype=np.uint8)
GM = B.GMUL
TRAVAILLEURS = int(os.environ.get("SILLAGE_THREADS", "6"))
INT = float(os.environ.get("SILLAGE_INTENSITE", "1"))


def _bits4(x):
    return [(x >> i) & 1 for i in range(4)]


# ---------------- 1. graphe ----------------

def graphe():
    m = {}
    sup = C != 0
    adj = sup & ~np.eye(N, dtype=bool)
    a2 = adj.astype(int) @ adj.astype(int)
    off = a2 - np.diag(np.diag(a2))
    m["voisins_communs_max_sans_diagonale"] = int(off.max())
    s2 = sup.astype(int).T @ sup.astype(int)
    m["colonnes_de_M_intersection_max"] = int((s2 - np.diag(np.diag(s2))).max())
    m["cycles_longueur_4"] = int(((off * (off - 1)) // 2).sum() // 4)
    # expansion : plus petit voisinage de M pour |S| = k (exact k ≤ 3, recherche locale au-delà)
    masques = [int(sum(1 << int(j) for j in np.nonzero(sup[:, i])[0])) for i in range(N)]   # colonne i : sorties de i
    exact = {}
    for k in (1, 2, 3):
        exact[k] = min(functools.reduce(lambda a, b: a | b, (masques[i] for i in c)).bit_count()
                       for c in itertools.combinations(range(N), k))
    m["voisinage_min_exact"] = exact
    rng = random.Random(3)
    local = {}
    for k in (4, 8, 16, 32, 48, 64):
        best = 129
        for _ in range(int(40 * INT)):
            S = rng.sample(range(N), k)
            amel = True
            while amel:
                amel = False
                for pos in range(k):
                    autres = 0
                    for q, i in enumerate(S):
                        if q != pos:
                            autres |= masques[i]
                    choix = min((i for i in range(N) if i not in S), key=lambda i: (autres | masques[i]).bit_count())
                    avant = (autres | masques[S[pos]]).bit_count()
                    if (autres | masques[choix]).bit_count() < avant:
                        S[pos] = choix
                        amel = True
            v = 0
            for i in S:
                v |= masques[i]
            best = min(best, v.bit_count())
        local[k] = best
    m["voisinage_min_local_borne_haute"] = local
    # quasi-symétrie : translations du groupe, coefficients et constantes
    meilleur_coef, meilleur_rc, rang_min = 0.0, 0.0, 1 << 30
    nz = [(j, i) for j in range(N) for i in range(N) if C[j, i]]
    for h in range(1, N):
        for gauche in (True, False):
            op = (lambda a: B.group_op(h, a)) if gauche else (lambda a: B.group_op(a, h))
            pi = [op(a) for a in range(N)]
            egaux = sum(C[pi[j], pi[i]] == C[j, i] for j, i in nz)
            meilleur_coef = max(meilleur_coef, egaux / len(nz))
            for r in range(B.N_ROUNDS):
                eg = sum(int(B.RC[r][pi[v]]) == int(B.RC[r][v]) for v in range(N))
                meilleur_rc = max(meilleur_rc, eg / N)
            # rang de M ⊕ T M T⁻¹ sur GF(16) : ce qu'un écart rotationnel doit absorber à chaque tour
            D = np.array(C)
            D2 = np.zeros_like(D)
            for j in range(N):
                for i in range(N):
                    D2[pi[j], pi[i]] = C[j, i]
            rang_min = min(rang_min, _rang_gf16(D ^ D2))
    m["quasi_symetrie"] = dict(coefficients_egaux_max=round(meilleur_coef, 3), attendu_hasard=round(1 / 15, 3), constantes_egales_max=round(meilleur_rc, 3),
                               rang_min_M_xor_translate_sur_GF16=rang_min, cout_rotationnel_xor_min_par_tour_bits=rang_min)
    # sous-corps et Frobenius
    gf4 = {x for x in range(16) if int(GM[GM[GM[x, x], GM[x, x]], 1]) == x}
    frob = C == GM[C, C]
    m["sous_corps"] = dict(coefficients_dans_GF4=round(float(np.mean([int(C[j, i]) in gf4 for j, i in nz])), 3),
                           coefficients_fixes_par_frobenius=round(float(np.mean([frob[j, i] for j, i in nz])), 3))
    return m


def _rang_gf16(A):
    A = A.copy()
    r = 0
    inv = B.GINV
    for c in range(A.shape[1]):
        p = next((i for i in range(r, A.shape[0]) if A[i, c]), None)
        if p is None:
            continue
        A[[r, p]] = A[[p, r]]
        A[r] = GM[inv[A[r, c]], A[r]]
        for i in np.nonzero(A[:, c])[0]:
            if i != r:
                A[i] ^= GM[A[i, c], A[r]]
        r += 1
    return r


# ---------------- 2. couche linéaire ----------------

def _pmod(a, f):
    d = f.bit_length()
    while a.bit_length() >= d:
        a ^= f << (a.bit_length() - d)
    return a


def _pmul(a, b, f):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a.bit_length() == f.bit_length():
            a ^= f
    return r


def _pgcd(a, b):
    while b:
        a, b = b, _pmod(a, b)
    return a


def _pdiv(a, b):
    q, d = 0, b.bit_length()
    while a.bit_length() >= d:
        s = a.bit_length() - d
        q |= 1 << s
        a ^= b << s
    return q


def _massey(s):
    C_, B_, L, m, n = 1, 1, 0, 1, len(s)
    for i in range(n):
        d = s[i]
        for j in range(1, L + 1):
            d ^= (C_ >> j) & 1 & s[i - j]
        if d:
            T = C_
            C_ ^= B_ << m
            if 2 * L <= i:
                L, B_, m = i + 1 - L, T, 1
            else:
                m += 1
        else:
            m += 1
    return C_, L


def lineaire():
    """Polynôme minimal de M binaire (512 bits) : Krylov + Berlekamp–Massey sur plusieurs suites, ppcm, puis degrés
    des facteurs (factorisation en degrés distincts). Un facteur de petit degré donnerait un petit sous-espace invariant."""
    rng = np.random.default_rng(11)
    pm = 1
    for essai in range(4):
        x = rng.integers(0, 16, N, dtype=np.uint8)
        p = rng.integers(0, 16, N, dtype=np.uint8)
        s = []
        for _ in range(1040):
            acc = 0
            for a, b in zip(x.tolist(), p.tolist()):
                acc ^= bin(a & b).count("1") & 1
            s.append(acc)
            x = B.diffuse(x)
        c, L = _massey(s)
        # réciproque : polynôme minimal de la suite
        f = sum(((c >> i) & 1) << (L - i) for i in range(L + 1))
        pm = _ppcm(pm, f)
    deg = pm.bit_length() - 1
    # puissances de M : vérifie que pm annule M sur un vecteur
    x = rng.integers(0, 16, N, dtype=np.uint8)
    acc = np.zeros(N, dtype=np.uint8)
    y = x.copy()
    for i in range(deg + 1):
        if (pm >> i) & 1:
            acc ^= y
        y = B.diffuse(y)
    annule = not acc.any()
    # multiplicités et degrés distincts
    reste, facteurs, d = pm, {}, 0
    xp = 2
    while reste.bit_length() - 1 >= 2 * (d + 1) and d < 300:
        d += 1
        xp = _pmul(xp, xp, reste) if reste.bit_length() > 2 else 0
        g = _pgcd(xp ^ 2, reste)
        while g.bit_length() > 1:
            n = (g.bit_length() - 1) // d
            facteurs[d] = facteurs.get(d, 0) + n
            while True:
                q = _pdiv(reste, g)
                if _pmod(reste, g) == 0:
                    reste = q
                g2 = _pgcd(g, reste)
                if g2.bit_length() == 1 or g2 != g:
                    g = g2 if g2.bit_length() > 1 else 1
                    break
            if reste.bit_length() > 1:
                xp = _pmod(xp, reste)
    if reste.bit_length() > 1:
        facteurs[reste.bit_length() - 1] = facteurs.get(reste.bit_length() - 1, 0) + 1
    # vecteurs propres sur GF(16) de M et de sa transposée : seul un vecteur CREUX pourrait porter une piste peu coûteuse
    propres = []
    for lam in range(1, 16):
        for nom, A in (("M", C), ("Mt", C.T)):
            K = A ^ (np.eye(N, dtype=np.uint8) * lam).astype(np.uint8)
            for v in _noyau_gf16(K):
                propres.append(dict(matrice=nom, valeur_propre=lam, poids=int(np.count_nonzero(v))))
    return dict(degre_polynome_minimal=deg, polynome_annule_M=annule, facteurs_par_degre={str(k): v for k, v in sorted(facteurs.items())},
                M_cyclique=deg == 512 and all(v == 1 for v in facteurs.values()), sous_espaces_invariants=2 ** sum(facteurs.values()),
                plus_petit_sous_espace_invariant=min(facteurs) if facteurs else None, vecteurs_propres_GF16=propres)


def _noyau_gf16(A):
    A = A.copy()
    n = A.shape[1]
    r, pivots = 0, []
    inv = B.GINV
    for c in range(n):
        p = next((i for i in range(r, A.shape[0]) if A[i, c]), None)
        if p is None:
            continue
        A[[r, p]] = A[[p, r]]
        A[r] = GM[inv[A[r, c]], A[r]]
        for i in np.nonzero(A[:, c])[0]:
            if i != r:
                A[i] ^= GM[A[i, c], A[r]]
        pivots.append(c)
        r += 1
    libres = [c for c in range(n) if c not in pivots]
    res = []
    for fl in libres:
        v = np.zeros(n, dtype=np.uint8)
        v[fl] = 1
        for i, c in enumerate(pivots):
            v[c] = A[i, fl]
        res.append(v)
    return res


def _ppcm(a, b):
    g = _pgcd(a, b)
    q = _pdiv(b, g)
    r = 0
    i = 0
    while q >> i:
        if (q >> i) & 1:
            r ^= a << i
        i += 1
    return r


# ---------------- 3. S-box ----------------

def sbox():
    S = [int(x) for x in B.SBOX]
    # relations de degré ≤ 2 en (x, y) : 1 + 8 + 28 = 37 monômes
    mon = [()] + [(i,) for i in range(8)] + list(itertools.combinations(range(8), 2))
    M = []
    for x in range(16):
        v = _bits4(x) + _bits4(S[x])
        M.append([int(all(v[i] for i in m)) for m in mon])
    A = np.array(M, dtype=np.uint8)
    r = 0
    A2 = A.copy()
    for c in range(A2.shape[1]):
        p = next((i for i in range(r, 16) if A2[i, c]), None)
        if p is None:
            continue
        A2[[r, p]] = A2[[p, r]]
        for i in range(16):
            if i != r and A2[i, c]:
                A2[i] ^= A2[r]
        r += 1
    # polynôme univarié sur GF(16), par interpolation de Lagrange
    coefs = []
    for k in range(16):
        s = 0
        for x in range(16):
            p = 1
            e = (15 - k) if k else 0
            for _ in range(e):
                p = int(GM[p, x])
            if k == 0:
                p = 1 if x == 0 else 0
            s ^= int(GM[S[x], p])
        coefs.append(s)
    coefs[15] = 0
    t = 0
    for x in range(16):
        t ^= S[x]
    coefs[15] = t
    gf4 = [x for x in range(16) if int(GM[GM[GM[x, x], GM[x, x]], 1]) == x]
    frob = sum(S[int(GM[x, x])] == int(GM[S[x], S[x]]) for x in range(16))
    return dict(relations_quadratiques=len(mon) - r, degre_univarie=max(i for i, c in enumerate(coefs) if c), termes_univaries=sum(1 for c in coefs if c),
                images_de_GF4_dans_GF4=sum(S[x] in gf4 for x in gf4), points_frobenius_equivariants=frob)


# ---------------- 3 bis. Frobenius ----------------

def frobenius(n_etats=4096, graine=1):
    """F(x) = x² sur chaque nibble. M est GF(16)-linéaire (coefficients dans GF(16)), mais elle ne commute avec F que si tous ses
    coefficients sont dans GF(2) : F(M(y)) = M⁽²⁾(F(y)), où M⁽²⁾ élève chaque coefficient au carré. Une relation entre x et F(x)
    traverse la couche linéaire avec l'écart (M ⊕ M⁽²⁾)·F(y), fonction linéaire de l'état inconnu : son rang sur GF(16) est ce que
    l'attaquant paie à chaque tour (4 bits par unité de rang). Témoin : coefficients dans GF(2), S-box x ↦ x⁴ et constantes nulles,
    qui commutent avec F ; le détecteur doit alors voir un rang nul et des écarts nuls partout."""
    rng = np.random.default_rng(graine)
    Fr = lambda v: GM[v, v]
    S = np.array(B.SBOX, dtype=np.uint8)
    RC0 = np.array(B.RC[0], dtype=np.uint8)
    y = rng.integers(0, 16, (8, N), dtype=np.uint8)
    lin16 = all(np.array_equal(np.bitwise_xor.reduce(GM[C, GM[a, v]], axis=1), GM[a, np.bitwise_xor.reduce(GM[C, v], axis=1)])
                for a in range(16) for v in y)

    def ecart_un_tour(Cm, Sb, rc):
        X = rng.integers(0, 16, (n_etats, N), dtype=np.uint8)
        tour = lambda x: np.bitwise_xor.reduce(GM[Cm[None, :, :], Sb[x ^ rc][:, None, :]], axis=2)
        d = tour(Fr(X)) ^ Fr(tour(X))
        return float((d == 0).sum(1).mean())

    temoin_C = (C != 0).astype(np.uint8)
    temoin_S = np.array([int(GM[GM[x, x], GM[x, x]]) for x in range(16)], dtype=np.uint8)
    # table Frobenius-XOR de la S-box : T[a][b] = #{u : S(F(u) ⊕ a) = F(S(u)) ⊕ b} ; T[0][0] = points équivariants
    T = np.zeros((16, 16), int)
    for a in range(16):
        for u in range(16):
            T[a, S[Fr(u) ^ a] ^ Fr(S[u])] += 1
    return dict(M_lineaire_sur_GF16=lin16,
                coefficients_dans_GF2=int(((C != 0) & (Fr(C) == C)).sum()), coefficients_non_nuls=int((C != 0).sum()),
                rang_M_xor_M2_sur_GF16=_rang_gf16(C ^ Fr(C)), rang_temoin=_rang_gf16(temoin_C ^ Fr(temoin_C)),
                table_sbox_max=int(T.max()), table_sbox_points_equivariants=int(T[0, 0]),
                constantes_dans_GF2=int(sum(int(c) in (0, 1) for r in B.RC for c in r)),
                nibbles_nuls_un_tour=round(ecart_un_tour(C, S, RC0), 3),
                nibbles_nuls_un_tour_temoin=round(ecart_un_tour(temoin_C, temoin_S, np.zeros(N, np.uint8)), 3))


# ---------------- 4. activité ----------------

def _profil_faible():
    """Min wt(Mx) pour wt(x) ≤ 3, et min wt(x) pour wt(Mx) ≤ 3 (Proposition 10) : ils renforcent le modèle."""
    return {1: 7, 2: 11, 3: 14}, {1: 111, 2: 97, 3: 96}


def activite(r, temps):
    """Borne basse du nombre de S-box actives sur r tours : modèle tronqué (toute caractéristique y entre, donc son
    minimum minore le vrai), renforcé par les valeurs exactes de la Proposition 10."""
    md = cp_model.CpModel()
    a = [[md.NewBoolVar(f"a{t}_{v}") for v in range(N)] for t in range(r)]
    entrants = [[i for i in range(N) if C[v, i]] for v in range(N)]
    for t in range(r - 1):
        for v in range(N):
            ent = entrants[v]
            # sortie active ⇒ au moins une entrée active
            md.AddBoolOr([a[t][i] for i in ent] + [a[t + 1][v].Not()])
            # une seule entrée active ⇒ sortie active (coefficient inversible)
            for i in ent:
                md.AddBoolOr([a[t][i].Not()] + [a[t][j] for j in ent if j != i] + [a[t + 1][v]])
    f, g = _profil_faible()
    w = [sum(a[t]) for t in range(r)]
    for t in range(r):
        md.Add(w[t] >= 1)
    for t in range(r - 1):
        md.Add(w[t] + w[t + 1] >= 8)
        for k, val in f.items():
            b = md.NewBoolVar("")
            md.Add(w[t] == k).OnlyEnforceIf(b)
            md.Add(w[t] != k).OnlyEnforceIf(b.Not())
            md.Add(w[t + 1] >= val).OnlyEnforceIf(b)
        for k, val in g.items():
            b = md.NewBoolVar("")
            md.Add(w[t + 1] == k).OnlyEnforceIf(b)
            md.Add(w[t + 1] != k).OnlyEnforceIf(b.Not())
            md.Add(w[t] >= val).OnlyEnforceIf(b)
    md.Minimize(sum(w))
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = temps
    s.parameters.num_workers = TRAVAILLEURS
    st = s.Solve(md)
    return dict(tours=r, borne_basse=int(math.ceil(s.BestObjectiveBound())), meilleure_solution=int(s.ObjectiveValue()) if st in (cp_model.OPTIMAL, cp_model.FEASIBLE) else None,
                optimal=st == cp_model.OPTIMAL, secondes=round(s.WallTime(), 1))


# ---------------- 5. algébrique ----------------

def _cnf_de(interdits, nb=8):
    """CNF interdisant un ensemble d'affectations de nb variables : impliquants premiers, couverture gloutonne."""
    cubes = {(v, 0) for v in interdits}
    premiers = set()
    while cubes:
        suiv, utilises = set(), set()
        for v, m in cubes:
            for b in range(nb):
                if m >> b & 1:
                    continue
                autre = (v ^ (1 << b), m)
                if autre in cubes:
                    suiv.add((v & ~(1 << b), m | (1 << b)))
                    utilises.add((v, m))
                    utilises.add(autre)
        premiers |= cubes - utilises
        cubes = suiv
    cov = {p: {u for u in interdits if (u & ~p[1]) == (p[0] & ~p[1])} for p in premiers}
    reste, res = set(interdits), []
    while reste:
        p = max(cov, key=lambda q: len(cov[q] & reste))
        res.append(p)
        reste -= cov[p]
    return res


def _clauses_sbox():
    """CNF de y = S(x) sur 8 variables."""
    S = [int(x) for x in B.SBOX]
    return _cnf_de({x | (y << 4) for x in range(16) for y in range(16) if S[x] != y})


def _xor_clauses(lits, rhs, nouvelle, ajouter):
    """x1 ⊕ … ⊕ xk = rhs, par tronçons de 4 variables."""
    lits = list(lits)
    while len(lits) > 4:
        t = nouvelle()
        _xor_court(lits[:3] + [t], 0, ajouter)
        lits = lits[3:] + [t]
    _xor_court(lits, rhs, ajouter)


def _xor_court(lits, rhs, ajouter):
    for signes in itertools.product((0, 1), repeat=len(lits)):
        if (sum(signes) & 1) != rhs:
            ajouter([(-v if s else v) for v, s in zip(lits, signes)])


def _recuperation(r, connus_cap, graine, q):
    """État de 512 bits : débit (64 nibbles) et `connus_cap` nibbles de capacité connus, reste inconnu. On connaît le débit
    de sortie après r tours. Le solveur doit retrouver l'entrée."""
    rng = np.random.default_rng(graine)
    x0 = rng.integers(0, 16, N, dtype=np.uint8)
    sortie = B.brume_v1(x0.copy(), rounds=r)
    cptr = [0]
    def nv():
        cptr[0] += 1
        return cptr[0]
    cl = []
    aj = cl.append
    bits = [[nv() for _ in range(4)] for _ in range(N)]
    for n in range(64 + connus_cap):
        for b in range(4):
            aj([bits[n][b] if (int(x0[n]) >> b) & 1 else -bits[n][b]])
    tmpl = _clauses_sbox()
    etat = bits
    for t in range(r):
        y = [[nv() for _ in range(4)] for _ in range(N)]
        for n in range(N):
            rc = int(B.RC[t][n])
            v8 = [etat[n][b] if not (rc >> b) & 1 else -etat[n][b] for b in range(4)] + y[n]
            for val, mas in tmpl:
                c = []
                for i in range(8):
                    if not (mas >> i) & 1:
                        c.append(-v8[i] if (val >> i) & 1 else v8[i])
                aj(c)
        z = [[nv() for _ in range(4)] for _ in range(N)]
        for v in range(N):
            for b in range(4):
                ent = [z[v][b]]
                for i in range(N):
                    c = int(C[v, i])
                    if not c:
                        continue
                    for k in range(4):
                        if (int(GM[c, 1 << k]) >> b) & 1:
                            ent.append(y[i][k])
                _xor_clauses(ent, 0, nv, aj)
        etat = z
    for n in range(64):
        for b in range(4):
            aj([etat[n][b] if (int(sortie[n]) >> b) & 1 else -etat[n][b]])
    t0 = time.time()
    with Cadical153(bootstrap_with=cl) as s:
        ok = s.solve()
        mod = set(l for l in s.get_model() if l > 0) if ok else set()
    rec = np.array([sum(((bits[n][b] in mod) << b) for b in range(4)) for n in range(N)], dtype=np.uint8)
    juste = ok and np.array_equal(B.brume_v1(rec.copy(), rounds=r)[:64], sortie[:64])
    q.put((juste, time.time() - t0, len(cl), cptr[0]))


def attaque_un_tour():
    """1 tour : y = M·S(x ⊕ RC). Les sorties de S-box inconnues sont linéaires dans le débit de sortie, donc pas besoin de solveur :
    64 nibbles inconnus, 64 équations sur GF(16). Montre qu'une attaque dédiée bat SAT et l'estimation semi-régulière."""
    rng = np.random.default_rng(5)
    x = rng.integers(0, 16, N, dtype=np.uint8)
    y = B.brume_v1(x.copy(), rounds=1)
    rc = B.RC[0]
    s = B.SBOX[x ^ rc]
    A = C[:64, 64:]
    r = _rang_gf16(A)
    # second membre : y_v ⊕ Σ_{i < 64} M[v, i]·s_i (le débit d'entrée est connu)
    b = y[:64].copy()
    for v in range(64):
        for i in range(64):
            if C[v, i]:
                b[v] ^= GM[C[v, i], s[i]]
    M_ = np.concatenate([A, b[:, None]], axis=1)
    inv = B.GINV
    ligne = 0
    pivots = []
    for c in range(64):
        p = next((i for i in range(ligne, 64) if M_[i, c]), None)
        if p is None:
            continue
        M_[[ligne, p]] = M_[[p, ligne]]
        M_[ligne] = GM[inv[M_[ligne, c]], M_[ligne]]
        for i in np.nonzero(M_[:, c])[0]:
            if i != ligne:
                M_[i] ^= GM[M_[i, c], M_[ligne]]
        pivots.append(c)
        ligne += 1
    sinv = np.argsort(B.SBOX)
    rec = None
    if r == 64:
        sc = M_[:, 64]
        rec = x.copy()
        rec[64:] = sinv[sc] ^ rc[64:]
    return dict(rang_du_bloc_debit_capacite=r, bits_inconnus_apres_resolution=4 * (64 - r), etat_retrouve=bool(rec is not None and np.array_equal(rec, x)))


def recuperation_sat(tours, inconnus, temps, parallele=1):
    """(tours, nibbles de capacité inconnus) → secondes, ou résolu = False si le solveur n'a pas fini dans le temps donné."""
    a_faire = [(r, inc) for r in tours for inc in inconnus]
    res, act = [], []
    while a_faire or act:
        while a_faire and len(act) < parallele:
            r, inc = a_faire.pop(0)
            q = mp.Queue()
            p = mp.Process(target=_recuperation, args=(r, 64 - inc, 100 * r + inc, q))
            p.start()
            act.append((p, q, r, inc, time.time()))
        for e in list(act):
            p, q, r, inc, t0 = e
            if p.is_alive() and time.time() - t0 < temps:
                continue
            if p.is_alive():
                p.terminate()
                p.join()
                res.append(dict(tours=r, bits_inconnus=4 * inc, resolu=False, secondes=None))
            else:
                p.join()
                juste, dt, nc, nvv = q.get()
                res.append(dict(tours=r, bits_inconnus=4 * inc, resolu=bool(juste), secondes=round(dt, 2), clauses=nc, variables=nvv))
            act.remove(e)
        time.sleep(0.2)
    return sorted(res, key=lambda x: (x["tours"], x["bits_inconnus"]))


def regularite(tours):
    """Degré de régularité d'un système quadratique booléen SEMI-RÉGULIER de même forme : 21 équations par S-box, 512 variables
    nouvelles par tour. Coût ≈ C(v, d)^2,37. Hypothèse invérifiable pour un système structuré : c'est une estimation."""
    res = {}
    for r in tours:
        v, m = 256 + 512 * r - 256, 21 * 128 * r         # capacité inconnue, puis états intermédiaires, sortie à moitié connue
        v = 256 + 512 * (r - 1) + 256 if r >= 1 else 256  # le débit de sortie est connu
        # coefficient de (1 + z)^v / (1 + z²)^m : premier ≤ 0
        coef, d = [1], 0
        binom = 1
        serie = []
        c2 = [1]                                          # 1/(1+z²)^m en z²
        for d in range(0, 2 * v):
            binom = 1 if d == 0 else binom * (v - d + 1) // d
            if d % 2 == 0:
                k = d // 2
                c2.append(0)
                c2[k] = 1 if k == 0 else -c2[k - 1] * (m + k - 1) // k
            val = sum(math.comb(v, d - 2 * k) * c2[k] for k in range(d // 2 + 1) if d - 2 * k >= 0)
            if val <= 0:
                break
        lc = math.log2(math.comb(v, d)) if d <= v else v
        res[str(r)] = dict(variables=v, equations=m, degre_regularite=d, log2_cout=round(2.37 * lc, 1))
    return res


# ---------------- 6. pistes monomiales sur mini-BRUME ----------------

def _table_sbox_exacte(c):
    """(u, v) permis ⇔ le coefficient de x^u dans Π_{b∈v} S_b(x ⊕ c) est non nul."""
    S = [int(B.SBOX[x ^ c]) for x in range(16)]
    perm = set()
    for v in range(16):
        f = [1 if (S[x] & v) == v else 0 for x in range(16)]
        a = f[:]
        for b in range(4):
            for x in range(16):
                if x >> b & 1:
                    a[x] ^= a[x ^ (1 << b)]
        for u in range(16):
            if a[u]:
                perm.add((u, v))
    return perm


_CNF_S = {}


def _degres_bc(n, R):
    """Boura–Canteaut, S-box 4 bits de degré 3 : D(0) = 1, …"""
    D = [1]
    for _ in range(R):
        d = D[-1]
        D.append(min(3 * d, n - (n - d + 2) // 3))
    return D


def _cnf_sbox_monomes(c):
    if c not in _CNF_S:
        perm = _table_sbox_exacte(c)
        _CNF_S[c] = _cnf_de({u | (v << 4) for u in range(16) for v in range(16) if (u, v) not in perm})
    return _CNF_S[c]


def _cnf_piste(inst, R, i_inactif, j):
    """CNF d'une piste monomiale de x^(tout sauf i) vers le bit j après R tours ; None si les fenêtres de poids l'excluent déjà."""
    n = inst["nibbles"]
    nb = 4 * n
    M = inst["M"]
    B2 = np.zeros((nb, nb), dtype=np.uint8)                # y_k = ⊕ B2[k][l] x_l
    for v in range(n):
        for i in range(n):
            c = M[v * n + i]
            if not c:
                continue
            for l in range(4):
                val = int(GM[c, 1 << l])
                for k in range(4):
                    if (val >> k) & 1:
                        B2[4 * v + k, 4 * i + l] = 1
    cp = [0]

    def nv():
        cp[0] += 1
        return cp[0]
    cl = []
    x = [nv() for _ in range(nb)]
    for b in range(nb):
        cl.append([x[b]] if b != i_inactif else [-x[b]])
    D = _degres_bc(nb, R)

    def fenetre(lits, t):
        """Conditions nécessaires déjà prouvées : poids ≥ n − D(t) et ≤ D(R − t). Elles ne changent pas la réponse."""
        bas, haut = nb - D[t], D[R - t]
        if bas > haut:
            return False
        for enc, borne in ((CardEnc.atleast, bas), (CardEnc.atmost, haut)):
            if 0 < borne < nb:
                c_ = enc(lits=lits, bound=borne, top_id=cp[0], encoding=EncType.seqcounter)
                cp[0] = max(cp[0], c_.nv)
                cl.extend(c_.clauses)
        return True
    for t in range(R):
        if t and not fenetre(x, t):
            return None
        y = [nv() for _ in range(nb)]
        for k in range(n):
            v8 = [x[4 * k + b] for b in range(4)] + [y[4 * k + b] for b in range(4)]
            for val, mas in _cnf_sbox_monomes(inst["rc"][t * n + k]):
                cl.append([-v8[q] if (val >> q) & 1 else v8[q] for q in range(8) if not (mas >> q) & 1])
        s = [nv() for _ in range(nb)]
        sort = [[] for _ in range(nb)]
        for k in range(nb):
            ent = [nv() for _ in np.nonzero(B2[k])[0]]
            for e, l in zip(ent, np.nonzero(B2[k])[0].tolist()):
                sort[l].append(e)
                cl.append([-e, s[k]])
            cl.append([-s[k]] + ent)                        # bit de sortie actif : une arête entrante
            for a, b_ in itertools.combinations(ent, 2):
                cl.append([-a, -b_])                        # au plus une
        for l in range(nb):
            cl.append([-y[l]] + sort[l])                    # bit d'entrée actif : au moins une arête sortante
            for e in sort[l]:
                cl.append([-e, y[l]])
        x = s
    for b in range(nb):
        cl.append([x[b]] if b == j else [-x[b]])
    return cl


def _piste_existe(inst, R, i_inactif, j, conflits=2_000_000):
    """True, False, ou None si le budget de conflits est épuisé."""
    cl = _cnf_piste(inst, R, i_inactif, j)
    if cl is None:
        return False
    with Glucose4(bootstrap_with=cl) as sol:
        sol.conf_budget(conflits)
        return sol.solve_limited()


def annulations(instances, echantillon):
    """Pour chaque instance et chaque tour où toutes les sommes réelles sont nulles au-delà de Boura–Canteaut : ces bits
    ont-ils une piste ? Si oui, leur somme nulle vient d'annulations, invisibles pour la division property."""
    res = []
    rng = random.Random(9)
    for k, inst in enumerate(instances):
        n = 4 * inst["nibbles"]
        nz = inst["bits_non_nuls_par_tour"]
        zero = 0
        while zero < len(nz) and nz[zero] == 0:
            zero += 1                                      # zero = portée réelle (tous les bits nuls)
        for R in (zero, zero + 1):
            if R < 1:
                continue
            paires = [(rng.randrange(n), rng.randrange(n)) for _ in range(echantillon)]
            o, nn, ind = 0, 0, 0
            for i, j in paires:
                v = _piste_existe(inst, R, i, j, int(300_000 * INT))
                o += v is True
                nn += v is False
                ind += v is None
            res.append(dict(instance=k, bits=n, tours=R, portee_reelle=zero, somme_nulle_partout=R <= zero, pistes_trouvees=o, sans_piste=nn, indecises=ind))
    return res


def run():
    c, m = {}, {}
    t0 = time.time()
    m["graphe"] = graphe()
    q = m["graphe"]["quasi_symetrie"]
    c["graphe_sans_cycle_de_longueur_4"] = m["graphe"]["cycles_longueur_4"] == 0
    c["coefficients_sans_quasi_symetrie"] = q["coefficients_egaux_max"] < 0.2
    c["constantes_jamais_invariantes_par_translation"] = q["constantes_egales_max"] < 1
    c["ecart_rotationnel_de_rang_eleve"] = q["rang_min_M_xor_translate_sur_GF16"] >= 64
    m["lineaire"] = lineaire()
    c["polynome_minimal_annule_M"] = m["lineaire"]["polynome_annule_M"]
    # les invariants de M existent (sa factorisation le dit) : ce qui compte est qu'aucun vecteur propre ne soit creux
    c["M_cyclique_invariants_tous_connus"] = m["lineaire"]["M_cyclique"]
    c["aucun_vecteur_propre_creux"] = all(v["poids"] >= 64 for v in m["lineaire"]["vecteurs_propres_GF16"])
    m["sbox"] = sbox()
    c["sbox_21_relations_quadratiques"] = m["sbox"]["relations_quadratiques"] == 21
    fb = m["frobenius"] = frobenius()
    c["M_lineaire_sur_GF16"] = fb["M_lineaire_sur_GF16"]
    # rang plein : une relation de Frobenius coûte 4 × 128 = 512 bits par tour ; le témoin (coefficients dans GF(2)) donne 0
    c["M_ne_commute_pas_avec_frobenius"] = fb["rang_M_xor_M2_sur_GF16"] >= 64 and fb["rang_temoin"] == 0
    # après un tour, R(F(x)) ⊕ F(R(x)) a 128/16 = 8 nibbles nuls en moyenne, comme au hasard ; le témoin en a 128
    c["frobenius_un_tour_comme_le_hasard"] = abs(fb["nibbles_nuls_un_tour"] - 8) < 0.5 and fb["nibbles_nuls_un_tour_temoin"] == N
    budget = 30 * INT
    acts = [activite(r, budget) for r in (2, 3, 4, 5, 6)]
    m["activite"] = acts
    c["activite_2_tours_vaut_8"] = acts[0]["borne_basse"] == 8
    c["activite_coherente_avec_les_trails_trouves"] = all(a["borne_basse"] <= u for a, u in zip(acts, (8, 44, 134, 257, 383)))
    par_r = {a["tours"]: a["borne_basse"] for a in acts}
    m["activite_32_tours_certifiee"] = {str(r): (32 // r) * b + par_r.get(32 % r, 0) for r, b in par_r.items()}
    c["activite_32_tours_au_moins_128"] = max(m["activite_32_tours_certifiee"].values()) >= 128
    m["attaque_un_tour"] = attaque_un_tour()
    c["attaque_un_tour_coherente"] = m["attaque_un_tour"]["etat_retrouve"] or m["attaque_un_tour"]["rang_du_bloc_debit_capacite"] < 64
    m["recuperation_sat"] = recuperation_sat((1, 2, 3, 4), (4, 8, 16, 32, 64), 20 * INT, TRAVAILLEURS)
    resolus = {r["tours"] for r in m["recuperation_sat"] if r["resolu"] and r["bits_inconnus"] == 256}
    m["recuperation_sat_256_bits_tours"] = max(resolus, default=0)
    c["recuperation_sat_controle_petite_capacite"] = any(r["resolu"] for r in m["recuperation_sat"])
    c["recuperation_sat_loin_de_32_tours"] = m["recuperation_sat_256_bits_tours"] <= 8
    m["regularite_semi_reguliere"] = regularite((1, 2, 3, 4, 6, 8))
    chemin = os.path.join(RACINE, "resultats", "mini_brume_instances.json")
    if os.path.exists(chemin):
        inst = json.load(open(chemin))
        m["annulations"] = annulations(inst, max(2, int(4 * INT)))
        # au tour suivant, environ la moitié des sommes sont non nulles : des pistes doivent exister
        c["pistes_coherentes_avec_les_sommes_reelles"] = all(a["somme_nulle_partout"] or a["pistes_trouvees"] + a["indecises"] > 0 for a in m["annulations"])
        m["annulations_observees"] = sum(a["pistes_trouvees"] for a in m["annulations"] if a["somme_nulle_partout"])
    m["secondes"] = round(time.time() - t0, 1)
    out = {"controles": {k: bool(v) for k, v in c.items()}, "mesures": m}
    sauver("brume_algebre", out)
    return out


if __name__ == "__main__":
    mp.set_start_method("fork")
    r = run()
    print(json.dumps(r["controles"], ensure_ascii=False))
    print(json.dumps(r["mesures"], ensure_ascii=False, default=str)[:9000])
