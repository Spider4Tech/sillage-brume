"""Exact evaluation of Proposition 3 of the paper (gap 2, real world): for the adversary R with G guesses, v checks and
F = nu_bar + 1 forced queries (q = 1, L = Omega = 0, M = 1 + v + F, N <= v G + F),
    Pr_O(mu_fw >= F) >= G/2^c - G (2^((1-r) v) + 4 v^2 / 2^b) - 2^-r - v (v+1) / 2^b,
to be compared with the bound nu / 2^c claimed in Section 6.4 of DMV17 for Pr(mu_fw > T_fw), T_fw = L + Omega + nu^{2(M-L)}_{r,c}.
nu is replaced by the upper bound nu_bar (see thm1_bounds.py), which only makes the claimed bound larger.
G is taken as large as N + M <= 0.1 * 2^c allows.   Usage: f3_bound.py r c v"""
from fractions import Fraction as Fr
import sys
from thm1_bounds import nu_bar
r, c, v = map(int, sys.argv[1:4]); b = r + c
F = 2
while True:                                   # F = nu_bar(2M) + 1 with M = 1 + v + F
    nb = nu_bar(2 * (1 + v + F), r, c)
    if F == nb + 1: break
    F = nb + 1
M = 1 + v + F
G = (2 ** c // 10 - M - F) // v
N = v * G + F
assert 10 * (N + M) <= 2 ** c and G <= 2 ** c
low = Fr(G, 2 ** c) - G * (Fr(1, 2 ** ((r - 1) * v)) + Fr(4 * v * v, 2 ** b)) - Fr(1, 2 ** r) - Fr(v * (v + 1), 2 ** b)
claim = Fr(nb, 2 ** c)
print(f"b={b} r={r} c={c} v={v}: nu_bar={nb} F={F} M={M} G=2^{G.bit_length() - 1}.. N<=vG+F ; proven Pr_O(mu_fw > T_fw) >= {float(low):.6f} ;"
      f" claimed <= nu/2^c <= {float(claim):.3e} ; exceeded (exact comparison): {low > claim}")
