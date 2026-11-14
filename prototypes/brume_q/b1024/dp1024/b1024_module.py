# -*- coding: utf-8 -*-
"""Paramètres de BRUME-1024q sous l'interface de `sillage.brume512` utilisée par tests/pistes_monomiales.py et
tests/dp_queue.py (N, N_ROUNDS, SBOX, GMUL, RC, E_SEG, E_I, E_C, _gauss_gf16_inverse).

Tout est relu dans les en-têtes C dont se sert brume1024.c : b1024_tables.h (graphe, coefficients, constantes) et
sillage/c/brume512_tables.h (S-box BR_SBOX). Rien n'est recopié à la main. La conformité est contrôlée par dp1024.py
(permutation recalculée ici contre les vecteurs de brume1024.c, gpu/vecteurs_b1024.c)."""
import os
import re

import numpy as np

from sillage import brume512 as _B512

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.normpath(os.path.join(_ICI, "..", "..", "..", ".."))


def _tableau(texte, nom):
    m = re.search(r"\b" + nom + r"\[[^=]*=\s*\{(.*?)\};", texte, re.S)
    return [int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1))]


_T = open(os.path.join(_ICI, "..", "b1024_tables.h")).read()
_T512 = open(os.path.join(_RACINE, "sillage", "c", "brume512_tables.h")).read()

N = int(re.search(r"#define B1_N (\d+)", _T).group(1))           # 256 nibbles
M = int(re.search(r"#define B1_M (\d+)", _T).group(1))           # 128 par moitié
N_ROUNDS = 32                                                    # profil BRUME-1024q (R1 = 32 dans brume1024.c)
K = _tableau(_T, "B1_K")
CS = _tableau(_T, "B1_CS")
CG = np.array(_tableau(_T, "B1_CG"), dtype=np.uint8).reshape(6, N)
_RCB = np.array(_tableau(_T, "B1_RC"), dtype=np.uint8).reshape(-1, N)
RC = [_RCB[r] & 0xF for r in range(_RCB.shape[0])]
SBOX = np.array(_tableau(_T512, "BR_SBOX"), dtype=np.uint8)
GMUL = _B512.GMUL
_gauss_gf16_inverse = _B512._gauss_gf16_inverse
assert N == 256 and M == 128 and len(K) == 6 and len(SBOX) == 16 and len(RC) >= N_ROUNDS


def nbr(v, k):
    """Même voisinage que nbr() de brume1024.c."""
    i, f = v % M, v // M
    return (i + k) % M + M if f == 0 else ((i - k) % M + M) % M


# ligne v de M : diagonale B1_CS[v], puis six voisins (décalages B1_K) de coefficients B1_CG[g][v]
E_SEG, E_I, E_C = [0], [], []
for _v in range(N):
    E_I.append(_v)
    E_C.append(CS[_v])
    for _g in range(6):
        E_I.append(nbr(_v, K[_g]))
        E_C.append(int(CG[_g, _v]))
    E_SEG.append(len(E_I))
E_SEG, E_I, E_C = np.array(E_SEG), np.array(E_I), np.array(E_C, dtype=np.uint8)


def matrice():
    Mn = np.zeros((N, N), np.uint8)
    for j in range(N):
        for k in range(E_SEG[j], E_SEG[j + 1]):
            Mn[j, E_I[k]] = E_C[k]
    return Mn


def tour(x, r):
    """Un tour sur 256 nibbles (liste d'entiers) : S-box après constante, puis M (comme ref_tour)."""
    y = [int(SBOX[x[j] ^ RC[r][j]]) for j in range(N)]
    out = []
    for v in range(N):
        a = 0
        for k in range(E_SEG[v], E_SEG[v + 1]):
            a ^= int(GMUL[E_C[k], y[E_I[k]]])
        out.append(a)
    return out
