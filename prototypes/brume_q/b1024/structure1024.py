# -*- coding: utf-8 -*-
"""Analyse structurelle de BRUME-1024q (niveau 1 du plan de cryptanalyse, 14 novembre 2026) : les analyses de la suite
pour BRUME-512 (tests/test_brume_algebre.py, tests/test_symetries_invariants.py) portées à 256 nibbles, plus une recherche
d'invariants non linéaires. Chaque détecteur est d'abord mis à l'épreuve sur un témoin où la propriété existe.

  1. Frobenius F(x) = x² par nibble : M commute-t-elle avec F (M(F(y)) = F(M(y))) ? Rang de M ⊕ M⁽²⁾ sur GF(16) (ce
     qu'une relation entre x et F(x) paie à chaque tour), coefficients et constantes dans GF(2), table Frobenius-XOR de la
     S-box, écart mesuré sur un tour. Témoin : coefficients dans GF(2), S-box x ↦ x⁴, constantes nulles.
  2. Invariants non linéaires : toutes les fonctions g = ⊕_q f_q(x_q) (somme de fonctions quelconques de chaque nibble :
     3 840 monômes) telles que g(R_r(x)) = g(x) ⊕ ε, pour chaque tour r, puis pour tous les tours à la fois. Système
     linéaire sur GF(2) résolu exactement (échantillons aléatoires, deux fois plus que d'inconnues ; un invariant
     vérifie toutes les équations, donc le noyau contient tous les invariants de la famille). Témoins : M = I, S = id,
     constantes nulles (tout g est invariant) ; M = I seule (les invariants de la S-box apparaissent).
  3. Sous-espaces invariants : sous-espaces affines de la S-box stables, puis stables par M (invariant subspace).
  4. Couche linéaire : polynôme minimal de M binaire (Berlekamp–Massey), degrés de ses facteurs, plus petit sous-espace
     invariant ; vecteurs propres de M et Mᵀ sur GF(16) (un vecteur propre creux porterait une piste peu coûteuse).
  5. Quasi-symétries du groupe D₂₅₆ : pour chaque translation h (à gauche et à droite), fraction des coefficients et
     des constantes conservés, et rang de M ⊕ T M T⁻¹ sur GF(16) (coût par tour d'une différence « rotationnelle »).
  6. Constantes : distinctes, non périodiques ; S-box : structures linéaires, auto-équivalences (même S-box que la suite).
    python3 structure1024.py      (depuis la racine du dépôt ; numpy, ortools et pysat : conteneur tgh)
Sortie : resultats/structure_1024q.json"""
import itertools
import json
import os
import sys
import time

import numpy as np

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.normpath(os.path.join(_ICI, "..", "..", ".."))
sys.path.insert(0, os.path.join(_ICI, "dp1024"))
sys.path.insert(0, _RACINE)
import b1024_module as B  # noqa: E402
import gf16 as B512  # noqa: E402  (v0.6 : corps GF(16), sans BRUME-512)
TA = B512  # v0.6 : les fonctions génériques sur GF(16) et GF(2)[X] de tests/test_brume_algebre.py sont dans gf16.py

N, NB = B.N, 4 * B.N
GM = B512.GMUL
C = B.matrice()
S = np.array(B.SBOX, dtype=np.uint8)
RC = [np.array(r, dtype=np.uint8) for r in B.RC[:B.N_ROUNDS]]
Fr = lambda v: GM[v, v]   # noqa: E731


def lin_gf16(Cm, Y):
    """Y : (n, 256) nibbles → M·Y sur GF(16), par lots."""
    out = np.zeros_like(Y)
    for j in range(N):
        nz = np.nonzero(Cm[j])[0]
        acc = np.zeros(Y.shape[0], dtype=np.uint8)
        for i in nz:
            acc ^= GM[Cm[j, i], Y[:, i]]
        out[:, j] = acc
    return out


def tour(X, r, Cm=C, Sb=S, rc=None):
    rc = RC[r] if rc is None else rc
    return lin_gf16(Cm, Sb[X ^ rc[None, :]])


# ---------------- 1. Frobenius ----------------
def frobenius(n_etats=2048, graine=1):
    rng = np.random.default_rng(graine)
    Y = rng.integers(0, 16, (8, N), dtype=np.uint8)
    lin16 = all(np.array_equal(lin_gf16(C, GM[a, Y]), GM[a, lin_gf16(C, Y)]) for a in range(16))

    def ecart(Cm, Sb, rc):
        X = rng.integers(0, 16, (n_etats, N), dtype=np.uint8)
        d = tour(Fr(X), 0, Cm, Sb, rc) ^ Fr(tour(X, 0, Cm, Sb, rc))
        return float((d == 0).sum(1).mean())

    tC = (C != 0).astype(np.uint8)
    tS = np.array([int(GM[GM[x, x], GM[x, x]]) for x in range(16)], dtype=np.uint8)
    T = np.zeros((16, 16), int)
    for a in range(16):
        for u in range(16):
            T[a, S[Fr(u) ^ a] ^ Fr(S[u])] += 1
    return dict(
        M_lineaire_sur_GF16=lin16,
        coefficients_dans_GF2=int(((C != 0) & (Fr(C) == C)).sum()), coefficients_non_nuls=int((C != 0).sum()),
        rang_M_xor_M2_sur_GF16=TA._rang_gf16(C ^ Fr(C)), rang_temoin=TA._rang_gf16(tC ^ Fr(tC)),
        table_sbox_max=int(T.max()), table_sbox_points_equivariants=int(T[0, 0]),
        constantes_dans_GF2=int(sum(int(c) in (0, 1) for r in RC for c in r)), constantes_total=len(RC) * N,
        nibbles_egaux_un_tour=round(ecart(C, S, RC[0]), 2), attendu_hasard=round(N / 16, 2),
        nibbles_egaux_un_tour_temoin=round(ecart(tC, tS, np.zeros(N, np.uint8)), 2))


# ---------------- 2. invariants non linéaires (sommes de fonctions de nibbles) ----------------
MASQUES = list(range(1, 16))   # monôme x^u d'un nibble, u ≠ 0


def traits(X):
    """X (n, 256) → (n, 3840) bits : pour chaque nibble q et chaque u, le monôme x_q^u (= [x_q & u == u])."""
    return np.concatenate([((X & u) == u)[:, :, None] for u in MASQUES], axis=2).reshape(X.shape[0], -1)


def noyau_gf2(A):
    """Base du noyau de A (lignes = équations, colonnes = inconnues) sur GF(2) ; élimination sur lignes empaquetées."""
    m, n = A.shape
    P = np.packbits(A.astype(np.uint8), axis=1)            # (m, ⌈n/8⌉)
    piv, r = [], 0
    for c in range(n):
        o, s = c >> 3, 7 - (c & 7)
        col = (P[r:, o] >> s) & 1
        lignes = np.nonzero(col)[0]
        if not len(lignes):
            continue
        p = r + lignes[0]
        if p != r:
            P[[r, p]] = P[[p, r]]
        autres = np.nonzero((P[:, o] >> s) & 1)[0]
        autres = autres[autres != r]
        P[autres] ^= P[r]
        piv.append(c)
        r += 1
        if r == m:
            break
    U = np.unpackbits(P[:r], axis=1)[:, :n]
    ens = set(piv)
    base = []
    for fl in (c for c in range(n) if c not in ens):
        v = np.zeros(n, np.uint8)
        v[fl] = 1
        for i, c in enumerate(piv):
            v[c] = U[i, fl]
        base.append(v)
    return base


def invariants(tours, Cm=C, Sb=S, rcs=None, n_ech=None, graine=7):
    """Dimension de l'espace des g = ⊕ f_q(x_q) (3 840 coefficients) avec g(R_r(x)) ⊕ g(x) = ε pour chaque r de `tours`
    (même g pour tous). Inconnues : 3 840 coefficients et ε (un ε par tour). Rend (dimension, nombre d'équations)."""
    rng = np.random.default_rng(graine)
    nt = len(tours)
    n_inc = 15 * N + nt
    n_ech = n_ech or (2 * n_inc + 64) // nt + 1
    blocs = []
    for k, r in enumerate(tours):
        X = rng.integers(0, 16, (n_ech, N), dtype=np.uint8)
        rc = (rcs[k] if rcs is not None else RC[r])
        D = traits(lin_gf16(Cm, Sb[X ^ rc[None, :]])) ^ traits(X)
        eps = np.zeros((n_ech, nt), np.uint8)
        eps[:, k] = 1
        blocs.append(np.concatenate([D, eps], axis=1))
    A = np.concatenate(blocs, axis=0)
    base = noyau_gf2(A)
    # g = 0 (avec ε = 0) n'est pas compté : la dimension utile est celle du noyau (0 si seul le vecteur nul)
    return len(base), A.shape[0]


def invariants_sbox():
    """Fonctions f de 4 bits avec f(S(x ⊕ c)) = f(x) ⊕ ε pour TOUTES les constantes c ∈ GF(16) : invariants d'une S-box
    isolée, constante de tour quelconque (ce qu'un invariant non linéaire de type Todo–Leander–Sasaki exploite)."""
    out = []
    for f in range(1 << 16):
        tt = [(f >> x) & 1 for x in range(16)]
        if all(len({tt[int(S[x ^ c])] ^ tt[x] for x in range(16)}) == 1 for c in range(16)):
            out.append(f)
    return [f for f in out if f not in (0, 0xFFFF)]


# ---------------- 3. sous-espaces invariants (comme la suite) ----------------
def sous_espaces(dim):
    out = set()
    for base in itertools.combinations(range(1, 16), dim):
        span, ok = {0}, True
        for b in base:
            new = {x ^ b for x in span}
            if new & span:
                ok = False
                break
            span |= new
        if ok:
            out.add(tuple(sorted(span)))
    return out


def sous_espaces_invariants():
    Sl = S.tolist()
    inv = []
    for dim in (1, 2, 3):
        for V in sous_espaces(dim):
            for a in range(16):
                img = {Sl[x ^ a] for x in V}
                b = min(img)
                if {y ^ b for y in img} == set(V):
                    inv.append((dim, V, a, b))
    dangereux = []
    rng = np.random.default_rng(0)
    for dim, V, a, b in inv:
        Vs = np.array(V, np.uint8)
        x = Vs[rng.integers(0, len(Vs), (64, N))]
        if np.isin(lin_gf16(C, x), Vs).all():
            dangereux.append(V)
    return len(inv), dangereux


# ---------------- 4. couche linéaire ----------------
def lineaire():
    rng = np.random.default_rng(11)
    pm = 1
    L_suite = 2 * NB + 32
    for _ in range(4):
        x = rng.integers(0, 16, (1, N), dtype=np.uint8)
        p = rng.integers(0, 16, N, dtype=np.uint8)
        s = []
        for _ in range(L_suite):
            s.append(int(np.bitwise_xor.reduce(np.array([bin(int(a) & int(b)).count("1") & 1
                                                         for a, b in zip(x[0], p)], np.uint8))))
            x = lin_gf16(C, x)
        cc, L = TA._massey(s)
        f = sum(((cc >> i) & 1) << (L - i) for i in range(L + 1))
        pm = TA._ppcm(pm, f)
    deg = pm.bit_length() - 1
    x = rng.integers(0, 16, (1, N), dtype=np.uint8)
    acc, y = np.zeros_like(x), x.copy()
    for i in range(deg + 1):
        if (pm >> i) & 1:
            acc ^= y
        y = lin_gf16(C, y)
    annule = not acc.any()
    # degrés des facteurs (factorisation en degrés distincts)
    reste, facteurs, d, xp = pm, {}, 0, 2
    while reste.bit_length() - 1 >= 2 * (d + 1) and d < 600:
        d += 1
        xp = TA._pmul(xp, xp, reste) if reste.bit_length() > 2 else 0
        g = TA._pgcd(xp ^ 2, reste)
        if g.bit_length() > 1:
            facteurs[d] = facteurs.get(d, 0) + (g.bit_length() - 1) // d
            while TA._pgcd(g, reste).bit_length() > 1:
                h = TA._pgcd(g, reste)
                reste = TA._pdiv(reste, h)
            xp = TA._pmod(xp, reste) if reste.bit_length() > 1 else 0
    if reste.bit_length() > 1:
        facteurs[reste.bit_length() - 1] = facteurs.get(reste.bit_length() - 1, 0) + 1
    propres = []
    I = np.eye(N, dtype=np.uint8)
    for lam in range(1, 16):
        for nom, A in (("M", C), ("Mt", C.T.copy())):
            for v in TA._noyau_gf16(A ^ (I * lam).astype(np.uint8)):
                propres.append(dict(matrice=nom, valeur_propre=lam, poids=int(np.count_nonzero(v))))
    return dict(degre_polynome_minimal=deg, polynome_annule_M=annule,
                facteurs_par_degre={str(k): v for k, v in sorted(facteurs.items())},
                plus_petit_facteur=min(facteurs) if facteurs else None, vecteurs_propres_GF16=propres)


# ---------------- 5. quasi-symétries du groupe ----------------
def op(x, y):
    """Produit de D₂₅₆ cohérent avec nbr() : (f, i) = r^i s₀^f ; (fx, ix)(fy, iy) = (fx ⊕ fy, ix + (−1)^fx·iy)."""
    fx, ix, fy, iy = x // 128, x % 128, y // 128, y % 128
    return 128 * (fx ^ fy) + (ix + (iy if fx == 0 else -iy)) % 128


def quasi_symetries():
    assert all(op(v, 128 + k) == B.nbr(v, k) for v in range(N) for k in B.K), "produit du groupe incohérent avec nbr"
    nz = [(j, i) for j in range(N) for i in range(N) if C[j, i]]
    meilleur_coef, meilleur_rc, rang_min, n_rangs = 0.0, 0.0, 1 << 30, 0
    t0 = time.time()
    for h in range(1, N):
        for gauche in (True, False):
            pi = [op(h, a) if gauche else op(a, h) for a in range(N)]
            egaux = sum(C[pi[j], pi[i]] == C[j, i] for j, i in nz)
            meilleur_coef = max(meilleur_coef, egaux / len(nz))
            for r in range(len(RC)):
                meilleur_rc = max(meilleur_rc, float(np.mean(RC[r][pi] == RC[r])))
            D2 = np.zeros_like(C)
            D2[np.ix_(pi, pi)] = C
            rang_min = min(rang_min, TA._rang_gf16(C ^ D2))
            n_rangs += 1
    return dict(translations=n_rangs, coefficients_conserves_max=round(meilleur_coef, 4), attendu_hasard=round(1 / 15, 4),
                constantes_conservees_max=round(meilleur_rc, 4), rang_min_M_xor_translatee_GF16=int(rang_min),
                duree_s=round(time.time() - t0))


# ---------------- 6. constantes et S-box ----------------
def divers():
    rc = np.array(RC)
    Sl = S.tolist()
    lin = [(a, b) for a in range(1, 16) for b in range(1, 16)
           if len({bin(b & (Sl[x] ^ Sl[x ^ a])).count("1") & 1 for x in range(16)}) == 1]
    return dict(rc_distinctes=len({r.tobytes() for r in RC}) == len(RC),
                rc_non_periodiques=not any(np.array_equal(rc[:-p], rc[p:]) for p in range(1, len(RC) // 2)),
                rc_non_constantes_par_tour=all(len(set(r.tolist())) > 1 for r in RC),
                sbox_structures_lineaires=len(lin))


def main():
    t0 = time.time()
    c, m = {}, {}
    fr = frobenius()
    m["frobenius"] = fr
    c["frobenius_temoin_detecte"] = fr["rang_temoin"] == 0 and fr["nibbles_egaux_un_tour_temoin"] == N
    c["M_lineaire_sur_GF16"] = fr["M_lineaire_sur_GF16"]
    c["frobenius_M_ne_commute_pas_rang_plein"] = fr["rang_M_xor_M2_sur_GF16"] == N
    c["frobenius_un_tour_comme_le_hasard"] = abs(fr["nibbles_egaux_un_tour"] - N / 16) < 2
    print("Frobenius :", json.dumps(fr), flush=True)
    # invariants : témoins d'abord
    I = np.eye(N, dtype=np.uint8)
    ident = np.arange(16, dtype=np.uint8)
    zero = np.zeros(N, np.uint8)
    d_t1, _ = invariants([0], Cm=I, Sb=ident, rcs=[zero])
    d_t2, _ = invariants([0], Cm=I, Sb=S, rcs=[zero])
    isb = invariants_sbox()
    m["invariants_temoins"] = dict(M_I_S_id_constantes_nulles=d_t1, M_I_seule=d_t2, attendu_temoin1=15 * N)
    c["invariants_temoin_tout_invariant_detecte"] = d_t1 == 15 * N
    print("témoins :", m["invariants_temoins"], flush=True)
    dims = {}
    for r in range(len(RC)):
        dims[r], neq = invariants([r])
    m["invariants_par_tour"] = {"dimensions": dims, "equations_par_tour": neq, "inconnues": 15 * N + 1}
    d_all, neq_all = invariants(list(range(len(RC))), n_ech=(2 * (15 * N + 32) + 64) // 32 + 1)
    m["invariants_tous_tours"] = dict(dimension=d_all, equations=neq_all)
    m["invariants_sbox_toutes_constantes"] = [hex(f) for f in isb]
    c["aucun_invariant_somme_de_nibbles_par_tour"] = all(v == 0 for v in dims.values())
    print("invariants par tour :", dims, " tous les tours :", d_all, " S-box :", len(isb), flush=True)
    n_inv, dang = sous_espaces_invariants()
    m["sbox_sous_espaces_affines_stables"] = n_inv
    m["sous_espaces_stables_par_M"] = [list(v) for v in dang]
    c["pas_d_invariant_subspace_S_et_M"] = not dang
    li = lineaire()
    m["lineaire"] = li
    c["polynome_minimal_annule_M"] = li["polynome_annule_M"]
    print("couche linéaire :", {k: v for k, v in li.items() if k != "vecteurs_propres_GF16"},
          "vecteurs propres :", len(li["vecteurs_propres_GF16"]), flush=True)
    qs = quasi_symetries()
    m["quasi_symetries"] = qs
    c["quasi_symetries_cout_par_tour_eleve"] = qs["rang_min_M_xor_translatee_GF16"] >= 32
    print("quasi-symétries :", qs, flush=True)
    dv = divers()
    m["divers"] = dv
    c["constantes_distinctes_non_periodiques"] = dv["rc_distinctes"] and dv["rc_non_periodiques"] and dv["rc_non_constantes_par_tour"]
    c["sbox_sans_structure_lineaire"] = dv["sbox_structures_lineaires"] == 0
    m["duree_s"] = round(time.time() - t0)
    out = {"nom": "structure_1024q", "controles": c, "mesures": m}
    json.dump(out, open(os.path.join(_RACINE, "resultats", "structure_1024q.json"), "w"), indent=1, ensure_ascii=False)
    print(json.dumps(c, ensure_ascii=False))
    return 0 if all(c.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
