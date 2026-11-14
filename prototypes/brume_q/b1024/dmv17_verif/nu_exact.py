# ν^{M}_{r,c} de DMV17 (définition 2), calcul exact : plus petit x tel que Pr(charge max > x) ≤ x/2^c, M boules dans 2^r tiroirs
from fractions import Fraction
from math import factorial
import sys
def pr_max_le(n, bins, x):
    poly = [Fraction(1, factorial(k)) for k in range(x + 1)]
    res = [Fraction(1)]
    for _ in range(bins):
        new = [Fraction(0)] * min(len(res) + x, n + 1)
        for i, a in enumerate(res):
            for k, b in enumerate(poly):
                if i + k < len(new):
                    new[i + k] += a * b
        res = new
    return (res[n] if n < len(res) else Fraction(0)) * factorial(n) / Fraction(bins) ** n
def nu(M, r, c):
    x = 1
    while 1 - pr_max_le(M, 2 ** r, x) > Fraction(x, 2 ** c):
        x += 1
    return x
if __name__ == "__main__":
    M, r, c = map(int, sys.argv[1:4])
    print(nu(M, r, c))
