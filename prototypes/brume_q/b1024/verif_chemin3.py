# -*- coding: utf-8 -*-
"""Contre-vérification indépendante de agregation34.c (ETUDE_GROUPE_STRUCTURE.md § A) : meilleur chemin différentiel à
3 tours de forme [1, 7, ·] depuis (v, a), par énumération exhaustive en numpy à partir du module de référence
(b1024_module : matrice M, S-box), sans rien partager avec le code C. Poids en bits = 4 − log2 DDT ; au tour 2, le meilleur
poids de chaque nibble actif. Résultat attendu (15 nov.) : (144, 1) → 87 bits (le balayage), (115, 12) → 89 bits (départ
de la meilleure caractéristique de trails1024.py).
    python3 verif_chemin3.py [v a] …"""
import sys, os, math
R = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
sys.path.insert(0, R + "/prototypes/brume_q/b1024/dp1024"); sys.path.insert(0, R)
import numpy as np
import b1024_module as B
from sillage import brume512 as B512
G = B512.GMUL; M = B.matrice(); S = B.SBOX; N = 256
DDT = np.zeros((16, 16), int)
for x in range(16):
    for d in range(1, 16):
        DDT[d, S[x] ^ S[x ^ d]] += 1
W = np.full((16, 16), np.inf)
W[DDT > 0] = 4 - np.log2(DDT[DDT > 0]); W[0, 0] = 0
MINW = np.array([0.0] + [W[x, 1:].min() for x in range(1, 16)])
assert DDT[1:].max() == 4
def col(i, y):  # contribution de y au nibble i après M : vecteur 256
    return np.array([G[M[j, i], y] if M[j, i] else 0 for j in range(N)], np.uint8)
def meilleur(v, a):
    best = math.inf
    for y0 in range(1, 16):
        if not DDT[a, y0]: continue
        w0 = W[a, y0]
        x1 = col(v, y0); act = np.nonzero(x1)[0]; assert len(act) == 7
        X = np.zeros((1, N), np.uint8); P = np.array([w0])
        for j in act:
            ys = [y for y in range(1, 16) if DDT[x1[j], y]]
            C = np.stack([col(j, y) for y in ys]); wj = np.array([W[x1[j], y] for y in ys])
            X = (X[:, None, :] ^ C[None, :, :]).reshape(-1, N); P = (P[:, None] + wj[None, :]).reshape(-1)
        tot = P + MINW[X].sum(1)
        best = min(best, tot.min())
    return best
ARGS = [int(x) for x in sys.argv[1:]] or [144, 1, 115, 12]
for v, a in zip(ARGS[::2], ARGS[1::2]):
    print(f"v={v} a={a} : meilleur chemin 3 tours = {meilleur(v, a)} bits", flush=True)
