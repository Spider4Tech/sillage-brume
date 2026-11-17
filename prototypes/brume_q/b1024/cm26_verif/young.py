"""Partitions, Young diagrams and standard tableaux, in exact arithmetic (used by cpo_exact.py and
representations.py). Conventions of [CM] § 3.4: lambda is a nonincreasing tuple, lambda' its conjugate,
f^lambda the number of standard Young tableaux, f^{lambda/mu} that of the skew shape, c(lambda) the total
content sum (j - i) over the boxes."""
from functools import lru_cache
from math import factorial


def partitions(n, maxpart=None):
    """All partitions of n, largest parts first, as tuples."""
    if maxpart is None:
        maxpart = n
    if n == 0:
        yield ()
        return
    for k in range(min(n, maxpart), 0, -1):
        for rest in partitions(n - k, k):
            yield (k,) + rest


def conj(lam):
    return tuple(sum(1 for p in lam if p > c) for c in range(lam[0])) if lam else ()


def col(lam, c):
    """Height of column c (1-indexed), that is lambda'_c; 0 beyond the first row."""
    return sum(1 for p in lam if p >= c)


def hook_dim(lam):
    """f^lambda by the hook-length formula ([CM] Prop. 3.8 (i))."""
    n = sum(lam)
    lc = conj(lam)
    prod = 1
    for i, p in enumerate(lam):
        for j in range(p):
            prod *= (p - j - 1) + (lc[j] - i - 1) + 1
    return factorial(n) // prod


def _norm(lam):
    return tuple(p for p in lam if p > 0)


@lru_cache(maxsize=None)
def skew_count(lam, mu):
    """f^{lambda/mu}: number of standard tableaux of the skew shape, by removing a corner of lambda
    that is not in mu (independent of the hook-length formula)."""
    lam, mu = _norm(lam), _norm(mu)
    if len(mu) > len(lam) or any(m > l for m, l in zip(mu, lam)):
        return 0
    if lam == mu:
        return 1
    tot = 0
    for i in range(len(lam)):
        nxt = lam[i + 1] if i + 1 < len(lam) else 0
        mi = mu[i] if i < len(mu) else 0
        if lam[i] > nxt and lam[i] - 1 >= mi:
            tot += skew_count(lam[:i] + (lam[i] - 1,) + lam[i + 1:], mu)
    return tot


def content(lam):
    return sum(j - i for i, p in enumerate(lam) for j in range(p))


def horizontal_strip(lam, alpha):
    """lambda/alpha is a horizontal strip (alpha inside lambda, at most one box per column)."""
    a = alpha + (0,) * (len(lam) - len(alpha))
    if len(alpha) > len(lam) or any(x > y for x, y in zip(a, lam)):
        return False
    return all(lam[i + 1] <= a[i] for i in range(len(lam) - 1))


def add_box(lam, i):
    """lambda with one box added at the end of row i (0-indexed), or None if not a partition."""
    l = list(lam) + [0]
    l[i] += 1
    if i > 0 and l[i] > l[i - 1]:
        return None
    return _norm(tuple(l))
