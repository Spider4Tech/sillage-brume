"""F2 face à Dobraunig–Mennink 2019 : la probabilité EXACTE de s-collision de l adversaire de f2_lemme2.c (f2_exact.py)
comparée aux termes correspondants de DM19, tels que Mennink 2023 les réécrit (théorème 2, (6a), avec le max de sa note 1) :
  [C(Mu,2) + Mu·Om]/2^b (deux appels « full » ; full contre fix) + [ν·Om + max((ν_fix − 1)/2, 0)·Om]/2^c (appels « fix »,
  ν_fix = Om, toutes les requêtes à drapeau visant la même valeur externe) + 2ν/2^c (multicollision, N = 0), ν = ν^{Mu}_{r,c}.
La borne de DMV17 (p. 622) est dépassée de ×1,03 à ×1,18 par cet adversaire ; celle de DM19 doit le couvrir."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from math import comb
from f2_exact import exact
from nu_exact import nu
r, c = 4, 16
b = r + c
for Mu, Om in [(16, 8), (16, 1), (32, 4), (4, 8), (8, 8), (24, 16)]:
    pa, _ = exact(r, c, Mu, Om, True)
    v = nu(Mu, r, c)
    dm19 = (comb(Mu, 2) + Mu * Om) / 2 ** b + (v * Om + max((Om - 1) / 2, 0) * Om) / 2 ** c + 2 * v / 2 ** c
    sans_mc = (comb(Mu, 2) + Mu * Om) / 2 ** b + (v * Om + max((Om - 1) / 2, 0) * Om) / 2 ** c
    print(f"Mu={Mu:2d} Om={Om:2d} : exact {float(pa):.4e} | DM19 (19)+(18c) {dm19:.4e} (sans mc {sans_mc:.4e}) | ν={v} | "
          f"exact/DM19 = {float(pa)/dm19:.3f}")
