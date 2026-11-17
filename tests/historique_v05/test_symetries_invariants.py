# -*- coding: utf-8 -*-
"""Symétries et invariants : actions du groupe préservant les coefficients,
raffinement de Weisfeiler-Lehman (asymétrie), constantes de tour, sous-espaces
invariants de la S-box, structures linéaires, invariants de la couche
linéaire (ordre de M borné), auto-équivalences linéaires de la S-box."""
import itertools

import numpy as np

from tests.commun import sauver
from sillage import brume512 as B

N = B.N
C = np.array(B.TF.COEF, dtype=np.uint8)


def translations():
    g, d = [], []
    nz = [(j, i) for j in range(N) for i in range(N) if C[j, i]]
    for h in range(1, N):
        if all(C[B.group_op(h, j), B.group_op(h, i)] == C[j, i] for j, i in nz):
            g.append(h)
        if all(C[B.group_op(j, h), B.group_op(i, h)] == C[j, i] for j, i in nz):
            d.append(h)
    return g, d


def wl(rounds=30):
    color = [0] * N
    hist = []
    for _ in range(rounds):
        sig = [tuple(sorted((int(C[j, i]), color[i]) for i in range(N) if C[j, i]))
               + tuple(sorted((int(C[i, j]), color[i]) for i in range(N) if C[i, j]))
               for j in range(N)]
        mp = {s: k for k, s in enumerate(sorted(set(sig)))}
        new = [mp[s] for s in sig]
        hist.append(len(set(new)))
        if new == color:
            break
        color = new
    return len(set(color)), hist


def sous_espaces(dim):
    out = set()
    for base in itertools.combinations(range(1, 16), dim):
        span = {0}
        ok = True
        for b in base:
            new = {x ^ b for x in span}
            if new & span:
                ok = False
                break
            span |= new
        if ok:
            out.add(tuple(sorted(span)))
    return out


def run():
    c, m = {}, {}
    g, d = translations()
    m["translations_gauche_invariantes"], m["translations_droite_invariantes"] = g, d
    c["aucune_translation_invariante"] = not g and not d
    ncol, hist = wl()
    m["wl_couleurs"] = hist
    c["graphe_pondere_asymetrique_WL"] = ncol == N
    rc = np.array(B.RC)
    c["rc_distinctes"] = len({r.tobytes() for r in B.RC}) == B.N_ROUNDS
    c["rc_non_periodiques"] = not any(np.array_equal(rc[:-p], rc[p:]) for p in range(1, 16))
    c["rc_non_constantes_par_tour"] = all(len(set(r.tolist())) > 1 for r in B.RC)
    # S-box : sous-espaces affines V + a stables (S(V+a) = V+b) de dim 1..3
    S = B.SBOX.tolist()
    inv = []
    for dim in (1, 2, 3):
        for V in sous_espaces(dim):
            for a in range(16):
                img = {S[x ^ a] for x in V}
                b = min(img)
                if {y ^ b for y in img} == set(V):
                    inv.append((dim, V, a, b))
    m["sbox_sous_espaces_affines_stables"] = len(inv)
    m["sbox_exemples"] = [list(map(str, x)) for x in inv[:5]]
    # Un sous-espace V stable par S ET par la diffusion (coordonnée par
    # coordonnée V^128 avec M·V^128 ⊆ V^128) donnerait un invariant
    # « invariant subspace » ; on teste chaque V stable sous l'action de M.
    dangereux = []
    for dim, V, a, b in inv:
        Vs = np.array(V, np.uint8)
        x = Vs[np.random.default_rng(0).integers(0, len(Vs), (64, N))]
        if np.isin(B.diffuse_batch(x), Vs).all():
            dangereux.append(V)
    m["sous_espaces_stables_par_M"] = [list(v) for v in dangereux]
    c["pas_d_invariant_subspace_S_et_M"] = not dangereux
    # structures linéaires
    lin = [(a, b) for a in range(1, 16) for b in range(1, 16)
           if len({bin(b & (S[x] ^ S[x ^ a])).count("1") & 1 for x in range(16)}) == 1]
    c["sbox_sans_structure_lineaire"] = not lin
    # auto-équivalences linéaires A·S·B = S (A, B ∈ GL(4,2)) : nombre
    gl = []
    for cols in itertools.permutations(range(1, 16), 4):
        span = {0}
        ok = True
        for b in cols:
            new = {x ^ b for x in span}
            if new & span:
                ok = False
                break
            span |= new
        if ok:
            gl.append(cols)
    app = lambda cols, x: (cols[0] if x & 1 else 0) ^ (cols[1] if x & 2 else 0) ^ \
        (cols[2] if x & 4 else 0) ^ (cols[3] if x & 8 else 0)
    Sinv = [0] * 16
    for x in range(16):
        Sinv[S[x]] = x
    auto = 0
    for Bc in gl:
        # A = S ∘ B^{-1} ∘ S^{-1} doit être linéaire : on teste A(u^v)=A(u)^A(v)
        A = [S[app(Bc, Sinv[y])] for y in range(16)]
        if A[0] == 0 and all(A[u ^ v] == A[u] ^ A[v] for u in range(16) for v in range(16)):
            auto += 1
    m["sbox_auto_equivalences_lineaires"] = auto
    c["sbox_auto_equivalences_triviales"] = auto == 1
    # ordre de M (borné) : un petit ordre ferait de M^k = I un invariant
    M = np.zeros((N, N), np.uint8)
    for j in range(N):
        for k in range(B.E_SEG[j], B.E_SEG[j + 1]):
            M[j, B.E_I[k]] = B.E_C[k]
    P = np.eye(N, dtype=np.uint8)
    ordre = None
    for k in range(1, 257):
        P = np.bitwise_xor.reduce(B.GMUL[P[:, :, None], M[None, :, :]], axis=1)
        if np.array_equal(P, np.eye(N, dtype=np.uint8)):
            ordre = k
            break
    m["ordre_M_inferieur_256"] = ordre
    c["ordre_M_superieur_256"] = ordre is None
    out = {"controles": c, "mesures": m}
    sauver("symetries_invariants", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
