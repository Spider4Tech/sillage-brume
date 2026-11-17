"""Exact (rational) evaluation of the two sides of Proposition 2 of the paper:
  B  = the bound of Theorem 1 of Daemen-Mennink-Van Assche (ASIACRYPT 2017) for the resources of the distinguisher D,
       with nu replaced by the upper bound nu_bar (so B is an UPPER bound on the bound claimed by Theorem 1);
  LB = the proven lower bound on the advantage of D (Proposition 2):
       LB = [C(Om+1,2)(1 - rho) + Om(1 - pi0 - rho)] / 2^c - Om M / 2^b - [C(Om,2) + Om(1 + C(Mu,2)/2^r)] / 2^(v r),
     with gamma = 2^b/(2^b - M), mubar = 1 + gamma C(Mu,2)/2^r,
       rho = gamma C(M,2)/2^b + (gamma/2^c) [Om(1 + mubar) + C(Om,2) + (gamma/2^r)(v Om + (v-1) C(Om,2))],
       pi0 = prod_{i=1}^{Mu-1} (2^b - i 2^c)/(2^b - i)  (or an upper bound of it when Mu is large).
For the world RD (Lemma 2 of DMV17) the bound B2 = C(Om+1,2)/2^c + M(M-1)/2^b is printed as well.
D: q = 1, u = 1, N = 0, L = 0, Omega flagged queries, v checks, M = Mu + v + v*Omega + 1 construction queries.
Usage: thm1_bounds.py r c k Mu Omega v      (prints B, LB, and LB - B, all exact, then as floats in units of 2^-c)"""
from fractions import Fraction as Fr
from math import comb
import sys

def nu_bar(n, r, c):
    """Smallest x >= 1 with C(n, x+1) / 2^(r x) <= x / 2^c.  Since Pr(mu > x) <= C(n, x+1) / 2^(r x) for n uniform balls in
    2^r bins (union bound over the (x+1)-subsets), this x satisfies the defining inequality of nu^n_{r,c}: nu <= nu_bar."""
    x = 1
    while Fr(comb(n, x + 1), 2 ** (r * x)) > Fr(x, 2 ** c):
        x += 1
    return x

def nu_low(n, r, c):
    """A lower bound on nu^n_{r,c}: x+1 for the largest x <= 63 such that Pr(mu > y) > y/2^c for every y <= x is certified by
    Pr(mu > y) >= Pr(mu > x) >= S1 - S2 (Bonferroni), where S1 = C(n,x+1)/B^x is the sum over the (x+1)-subsets of the
    probability that the subset falls in one bin, and S2 the sum over the pairs of distinct subsets (overlap j) of the
    probability that both do: B^-(2x+1-j) for j >= 1 and B^-(2x) for j = 0."""
    B, best = 2 ** r, 1
    for x in range(1, min(n, 64)):
        k1 = x + 1
        S1 = Fr(comb(n, k1), B ** x)
        S2 = sum(Fr(comb(n, k1) * comb(k1, j) * comb(n - k1, k1 - j) // 2, B ** (2 * x + 1 - j) if j else B ** (2 * x)) for j in range(k1))
        if S1 - S2 > Fr(x, 2 ** c): best = x + 1          # then Pr(mu > y) > y/2^c for all y <= x
    return best

def sides(r, c, k, Mu, Om, v):
    b = r + c
    M = Mu + v + v * Om + 1
    assert r < b and k <= b and 10 * M <= 2 ** c, "hypotheses of Theorem 1 (r < b, k <= b, N + M <= 0.1 * 2^c)"
    nb = nu_bar(2 * M, r, c)
    # Theorem 1 with N = 0, L = 0, q = q_iv = u = 1, H_min = k:
    B = (Fr(2 * nb, 2 ** c) + Fr(comb(Om + 1, 2), 2 ** c) + Fr(M - 1, 2 ** b - 1) + Fr(M * (M - 1), 2 ** b)
         + Fr(M - 1, 2 ** (k + min(c, b - k))))
    # Proposition 2:
    # pi0 >= Pr[the outer parts of Mu draws without replacement from Z_2^b are pairwise distinct]
    #      = prod_{i=1}^{Mu-1} (2^b - i 2^c) / (2^b - i)
    if Mu <= 100000:
        pi0 = Fr(1)
        for i in range(1, Mu):
            pi0 *= Fr(2 ** b - i * 2 ** c, 2 ** b - i)
    else:
        # prod (1 - i/2^r) <= exp(-x), x = C(Mu,2)/2^r, and exp(-x) <= 1 / (1 + x + ... + x^n/n!);
        # prod 2^b / (2^b - i) <= (1 - Mu/2^b)^(-Mu) <= 1 / (1 - Mu^2/2^b).
        x = Fr(comb(Mu, 2), 2 ** r); S = Fr(0); term = Fr(1)
        for n in range(1, 60):
            S += term; term = term * x / n
        pi0 = 1 / (S * (1 - Fr(Mu * Mu, 2 ** b)))
    gam = Fr(2 ** b, 2 ** b - M)                                   # gamma
    mubar = 1 + gam * Fr(comb(Mu, 2), 2 ** r)                     # bound on E[|T|] (real worlds)
    rho = gam * Fr(comb(M, 2), 2 ** b) + gam / 2 ** c * (Om * (1 + mubar) + comb(Om, 2)
                                                         + gam / 2 ** r * (v * Om + (v - 1) * comb(Om, 2)))
    fp = (comb(Om, 2) + Om * (1 + Fr(comb(Mu, 2), 2 ** r))) / 2 ** (v * r)   # bound on Pr[D = 1] in the ideal world
    LB = (comb(Om + 1, 2) * (1 - rho) + Om * (1 - pi0 - rho)) / 2 ** c - Fr(Om * M, 2 ** b) - fp
    B2 = Fr(comb(Om + 1, 2), 2 ** c) + Fr(M * (M - 1), 2 ** b)   # Lemma 2 with L = 0
    assert M <= 2 ** (b - 1) and Mu <= 2 ** r, "hypotheses of Proposition 2"
    return M, nb, B, LB, pi0, rho, fp, B2

def repaired(r, c, k, M, Om):
    """Bound of Theorem 1' of the paper for N = 0, L = 0, q = q_iv = u = 1, H_min = k, with m the smallest integer such that beta_m <= m/2^c:
    2 beta_m + 2 Lambda + (M-1)/(2^b-1) + (M-1)/2^(k+min(c,b-k)),
    Lambda = C(Om+1,2)/2^c + [Om C(M,2) + 2 C(M,2)]/2^b, beta_m = C(M, m+1) 2^((1-r) m)."""
    b = r + c
    Lam = Fr(comb(Om + 1, 2), 2 ** c) + Fr((Om + 2) * comb(M, 2), 2 ** b)
    rest = 2 * Lam + Fr(M - 1, 2 ** b - 1) + Fr(M - 1, 2 ** (k + min(c, b - k)))
    m = 1
    while Fr(comb(M, m + 1), 2 ** ((r - 1) * m)) > Fr(m, 2 ** c): m += 1      # smallest m with beta_m <= m / 2^c
    return m, rest + 2 * Fr(comb(M, m + 1), 2 ** ((r - 1) * m))

if __name__ == "__main__":
    r, c, k, Mu, Om, v = map(int, sys.argv[1:7])
    M, nb, B, LB, pi0, rho, fp, B2 = sides(r, c, k, Mu, Om, v)
    u = 2 ** c
    print(f"b={r + c} r={r} c={c} k={k} Mu={Mu} Omega={Om} v={v} M={M} nu_bar={nb}")
    print(f"  Theorem 1 bound  B  <= {float(B):.9e} = {float(B * u):.4f} / 2^c")
    print(f"  proven advantage LB  = {float(LB):.9e} = {float(LB * u):.4f} / 2^c   (pi0={float(pi0):.6f} rho={float(rho):.3e} fp={float(fp):.3e})")
    print(f"  LB - B = {float((LB - B) * u):.4f} / 2^c ; LB / B = {float(LB / B):.6f} ; violated (exact comparison): {LB > B}")
    m1, R1 = repaired(r, c, k, M, Om)
    print(f"  Theorem 1' (repaired, N = 0, L = 0, q = u = 1, m = {m1}) = {float(R1 * u):.4f} / 2^c ; / B = {float(R1 / B):.4f} ; LB below it: {LB <= R1}")
    if Mu <= 100000:
        print(f"  comparison with a term Omega nu^M/2^c: nu^M_(r,c) >= {nu_low(M, r, c)} ; E|T| <= 2 + C(Mu,3)/2^(2r) = {float(2 + Fr(comb(Mu, 3), 2 ** (2 * r))):.4f} (uniform outer parts)")
    print(f"  Lemma 2 bound    B2  = {float(B2):.9e} = {float(B2 * u):.4f} / 2^c ; LB - B2 = {float((LB - B2) * u):.4f} / 2^c ; violated: {LB > B2}")
