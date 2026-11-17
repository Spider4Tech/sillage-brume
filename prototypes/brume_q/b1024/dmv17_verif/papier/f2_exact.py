"""Gap 1 (the count S in the proof of Lemma 2 of DMV17), EXACT computation with rational numbers, no sampling.
Ideal world of Lemma 2 (IXIF, inner parts given by RO'): every query below has a new path, so its t = RO(Path)||RO'(Path)
is uniform on 2^b values and independent of the others.
  - Mu "free" queries (flag = false, sigma = 0): state s = t; its outer part is uniform and is seen by the adversary.
  - then Om flagged queries (flag = true, outer(sigma) = alpha, inner(sigma) = 0): s = (alpha, inner(t)).
    adversary: alpha = the most frequent outer part among the free queries;  control: alpha uniform.
So L = 0, Omega = Om, M = Mu + Om.  Given the final loads m_v of the 2^r outer values, the states are collision free with
probability prod_v g(m_v), g(m) = prod_{i<m} (1 - i/2^c).  We sum over the partitions of Mu (sorted loads).
Compared with the two bounds written in the proof (Section 5 of DMV17), with S = C(L+Omega+1, 2) and L = 0:
  first:  (C(M,2) - C(Om+1,2))/2^b + C(Om+1,2)/2^c ;   final (weaker):  (C(M,2) - C(L+1,2))/2^b + C(Om+1,2)/2^c = C(M,2)/2^b + C(Om+1,2)/2^c,
and with the s-collision part of the bound of Lemma 2' of the paper, taken literally with L = 0 and Omega = Om:
  C(L+Omega+1,2)/2^c + [(L+Omega) C(M-L,2) + C(M,2)]/2^b = C(Om+1,2)/2^c + (Om+1) C(M,2)/2^b.
Usage: f2_exact.py            (table for r = 4, c = 16)
       f2_exact.py small      (the example r = 1, Mu = 4, Om = 1 of the paper, as an exact polynomial in eps = 2^-c)"""
from fractions import Fraction as Fr
from math import comb, factorial
from collections import Counter
import sys

def partitions(n, k, maxp=None):
    if maxp is None: maxp = n
    if n == 0: yield (); return
    if k == 0: return
    for p in range(min(n, maxp), 0, -1):
        for rest in partitions(n - p, k - 1, p):
            yield (p,) + rest

def exact(r, c, Mu, Om, adversary=True):
    """Returns (Pr[s-collision], E[load of alpha among the free queries])."""
    B, Q = 2 ** r, 2 ** c
    g = [Fr(1)]
    for i in range(Mu + Om + 1): g.append(g[-1] * (1 - Fr(i, Q)))
    tot, pnc, Eload = Fr(0), Fr(0), Fr(0)
    for lam in partitions(Mu, B):
        loads = list(lam) + [0] * (B - len(lam))
        nvec = factorial(B)
        for m in Counter(loads).values(): nvec //= factorial(m)       # number of load vectors with these values
        w = Fr(nvec * factorial(Mu), B ** Mu)
        for x in loads: w /= factorial(x)                             # multinomial probability of one such vector
        tot += w
        base = Fr(1)
        for x in loads: base *= g[x]
        if adversary:
            a = max(loads)
            pnc += w * base / g[a] * g[a + Om]; Eload += w * a
        else:
            pnc += w * sum(base / g[x] * g[x + Om] for x in loads) / B; Eload += w * Fr(sum(loads), B)
    assert tot == 1
    return 1 - pnc, Eload

def written_bound(r, c, Mu, Om, final=True):
    M, S = Mu + Om, comb(Om + 1, 2)
    return Fr(comb(M, 2) - (0 if final else S), 2 ** (r + c)) + Fr(S, 2 ** c)

def corrected_bound(r, c, Mu, Om):
    M = Mu + Om
    return Fr(comb(Om + 1, 2), 2 ** c) + Fr(Om * comb(M, 2) + comb(M, 2), 2 ** (r + c))

if __name__ == "__main__" and len(sys.argv) == 1:
    r, c = 4, 16
    ok = True
    print(f"r={r} c={c}")
    for Mu, Om in [(4, 8), (8, 8), (16, 1), (16, 8), (24, 16), (32, 4), (2, 30), (40, 2)]:
        pa, Ea = exact(r, c, Mu, Om, True); pc, _ = exact(r, c, Mu, Om, False)
        wb, cb = written_bound(r, c, Mu, Om), corrected_bound(r, c, Mu, Om)
        ok &= pa <= cb
        print(f"Mu={Mu:2d} Om={Om:2d} : adversary {float(pa):.6e} | control {float(pc):.6e} (below final: {pc <= wb}) | final written bound {float(wb):.6e} |"
              f" adversary/final {float(pa / wb):.4f} | exceeds: {pa > wb} | first written bound {float(written_bound(r, c, Mu, Om, False)):.6e} | E[load] {float(Ea):.4f} = {Ea} | Lemma 2' {float(cb):.6e} | holds: {pa <= cb}")
    print("Lemma 2' (s-collision part) holds in all cases:", ok)

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "small":
    # r = 1, Mu = 8, Om = 1: the 8 free outer parts are 8 fair bits, X of them equal to 0; the flagged query joins the larger
    # side.  Pr[no collision] = sum_x C(8,x)/2^8 * g(max(x,8-x)+1) * g(min(x,8-x)), a polynomial in eps = 2^-c.
    def mul(p, q):
        out = [Fr(0)] * (len(p) + len(q) - 1)
        for i, a in enumerate(p):
            for j, b in enumerate(q): out[i + j] += a * b
        return out
    def g(m):
        p = [Fr(1)]
        for i in range(m): p = mul(p, [Fr(1), Fr(-i)])
        return p
    Mu = 8
    P = [Fr(0)] * (Mu + 2)
    for x in range(Mu + 1):
        t = mul(g(max(x, Mu - x) + 1), g(min(x, Mu - x)))
        for i, a in enumerate(t): P[i] += Fr(comb(Mu, x), 2 ** Mu) * a
    coll = [-a for a in P]; coll[0] += 1
    print("r=1 Mu=8 Om=1: Pr[s-collision] as a polynomial in eps = 2^-c, coefficients of eps^0, eps^1, ... :", [str(a) for a in coll])
    print("final written bound: C(9,2)/2^(c+1) + 1/2^c = 19 * eps ; first written bound: (C(9,2) - 1)/2^(c+1) + 1/2^c = 37/2 * eps")
    for c in (8, 11, 12, 16, 64):
        pa, _ = exact(1, c, Mu, 1, True); wb = written_bound(1, c, Mu, 1)
        e = Fr(1, 2 ** c); assert pa == sum(a * e ** i for i, a in enumerate(coll))
        print(f"c={c}: exact {float(pa):.6e}  final written bound {float(wb):.6e}  ratio {float(pa / wb):.6f}  exceeds: {pa > wb}")
