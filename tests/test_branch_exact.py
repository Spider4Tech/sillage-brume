# -*- coding: utf-8 -*-
"""Certificat EXACT du branch number de la diffusion (différentiel et linéaire).

Si wt(x)+wt(Mx) < 8 alors wt(x) ≤ 3 ou wt(Mx) ≤ 3 : énumérer les poids ≤ 3
de M ET de M^{-1} couvre tous les vecteurs (réduction par scalaire GF(16)).
Linéaire : M^T_bin = (G⊗I) M^T (G^{-1}⊗I) (G = Gram de la trace) → mêmes
motifs d'activité que M^T sur GF(16), certifiés de la même façon.
"""
import numpy as np

from tests.commun import sauver
from sillage import brume512 as B

GM, N = B.GMUL, B.N


def matrice_M():
    full = np.zeros((N, N), np.uint8)
    for j in range(N):
        for k in range(B.E_SEG[j], B.E_SEG[j + 1]):
            full[j, B.E_I[k]] = B.E_C[k]
    return full


def min_poids_jusqua_3(Mat, plafond=99):
    """min_{1≤wt(x)≤3} wt(x)+wt(Mat·x) par poids (plafonné : seul < 8 compte)."""
    cols = Mat.T
    Cs = GM[np.arange(16)[:, None, None], cols[None]]
    out = {1: int((cols != 0).sum(1).min()) + 1}
    b2 = b3 = plafond
    for i in range(N):
        for j in range(i + 1, N):
            u = cols[i][None] ^ Cs[1:, j]
            b2 = min(b2, int((u != 0).sum(1).min()) + 2)
            if j + 1 < N:
                v = u[:, None, None, :] ^ Cs[1:, j + 1:][None]
                b3 = min(b3, int((v != 0).sum(-1).min()) + 3)
    out[2], out[3] = b2, b3
    return out


def trace(a):
    t, x = 0, a
    for _ in range(4):
        t ^= x
        x = int(GM[x, x])
    return t & 1


def run():
    M = matrice_M()
    Minv = B._gauss_gf16_inverse(M)
    m = {}
    for nom, Mat in (("M", M), ("M_inv", Minv), ("MT", M.T.copy()), ("MT_inv", Minv.T.copy())):
        m[nom] = min_poids_jusqua_3(Mat)
        print(nom, m[nom], flush=True)
    bd = min(min(m["M"].values()), min(m["M_inv"].values()), 8)
    bl = min(min(m["MT"].values()), min(m["MT_inv"].values()), 8)
    mat = lambda c: np.array([[(GM[c, 1 << k] >> r) & 1 for k in range(4)] for r in range(4)], np.uint8)
    G = np.array([[trace(int(GM[1 << r, 1 << k])) for k in range(4)] for r in range(4)], np.uint8)
    conj = all(((mat(c).T @ G) % 2 == (G @ mat(c)) % 2).all() for c in range(16))
    # cohérence : la table GMUL_T du paquet est bien la transposée binaire
    gt = all(int(B.GMUL_T[c, mu]) == int(sum(((mat(c).T @ [(mu >> b) & 1 for b in range(4)])[r] % 2) << r
                                         for r in range(4)))
             for c in range(16) for mu in range(16))
    out = {"mesures": m,
           "B_differentiel": bd, "B_lineaire": bl,
           "controles": {"B_diff_egal_8": bd == 8, "B_lin_egal_8": bl == 8,
                         "conjugaison_trace": conj, "GMUL_T_transposee_binaire": gt}}
    sauver("branch_exact", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
