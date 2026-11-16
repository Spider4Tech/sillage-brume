#!/usr/bin/env python3
"""Arithmetic of SPONGE_QROM.md § 4-5, redone in high precision (decimal, 400 digits).

 1. [CM] (88): a_N(T) <= sqrt 2 and e_N(T) <= 88 T / sqrt N for N >= 16, 1 <= T <= sqrt(N)/4, with
    delta_N from [CM] (80). Checked for every T at small N, and at N = 2^1024 on a range of T.
 2. The simple form of Theorem S is above its sharp form (the analogue of [CM] (92), (93)).
 3. Thresholds for success 1/2, sharp and simple forms, ours and the article's.
Exit code 0 if every check passes.
"""
import sys
from decimal import Decimal as D, getcontext
getcontext().prec = 400
R2 = D(2).sqrt()

def a_N(N, T): return (D(N) / D(N - T)).sqrt()
def delta(N, T): return 60 * D(T) / D(N - T + 1).sqrt() + D(T * (T + 1)) / D(2 * (N - 2 * T + 1))
def e_N(N, T): return D(T) * (D(2) / D(N - T)).sqrt() + delta(N, T)

def fin(r, c, d, T, kcap, col):
    """Sharp form: [a_N (digest amplitude + capacity amplitude) + e_N]^2. kcap = 4 ([CM]) or 8 (ours) for
    collisions; 4 or 4 sqrt 2 for preimages."""
    N = 1 << (r + c); t = D(T)
    dig = (4 * R2 / 3) * t ** D("1.5") / D(2) ** (D(d) / 2) if col else 2 * R2 * t / D(2) ** (D(d) / 2)
    capa = kcap * t ** D("1.5") / D(2) ** (D(c) / 2)
    return (a_N(N, T) * (dig + capa) + e_N(N, T)) ** 2

def simple(r, c, d, T, coefs):
    t = D(T)
    return coefs[0] * t ** coefs[3] / D(2) ** d + coefs[1] * t ** 3 / D(2) ** c + coefs[2] * t ** 2 / D(2) ** (r + c)

def seuil(f):
    lo, hi = D(0), D(511)
    for _ in range(80):
        m = (lo + hi) / 2
        lo, hi = (m, hi) if f(int(D(2) ** m)) < D("0.5") else (lo, m)
    return float(lo)

def main():
    ok = True
    def verdict(nom, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print(f"  [{'ok' if cond else 'ECHEC'}] {nom}{' : ' + detail if detail else ''}")

    e = True; n = 0
    for b in range(4, 25):
        N = 1 << b
        Tmax = int(D(N).sqrt() / 4)
        for T in range(1, Tmax + 1) if Tmax <= 300 else list(range(1, 100)) + [Tmax - 1, Tmax]:
            n += 1
            e &= 3 * T - 1 <= N and a_N(N, T) <= R2 and e_N(N, T) <= 88 * D(T) / D(N).sqrt()
    N = 1 << 1024
    for lt in (0, 1, 10, 64, 100, 124, 125, 126, 128, 200, 300, 400, 509, 510):
        T = 1 << lt; n += 1
        e &= 3 * T - 1 <= N and a_N(N, T) <= R2 and e_N(N, T) <= 88 * D(T) / D(N).sqrt()
    verdict("[CM] (88) : a_N <= sqrt 2, e_N <= 88 T / sqrt N", e, f"{n} couples (N, T), dont N = 2^1024 jusqu'a T = 2^510")

    r, c, d = 640, 384, 512
    ours_col = (D(64) / 3, D(384), D(23232), 3); ours_pre = (D(48), D(192), D(23232), 2)
    e = True
    for lt in (1, 20, 64, 100, 120, 124, 125, 126, 128, 160, 200, 255, 256, 300, 400, 510):
        T = 1 << lt
        e &= fin(r, c, d, T, 8, True) <= simple(r, c, d, T, ours_col)
        e &= fin(r, c, d, T, 4 * R2, False) <= simple(r, c, d, T, ours_pre)
    verdict("forme simple >= forme fine (theoreme S), T = 2^1 ... 2^510", e)

    s = {
        "collision, notre eponge, forme simple": seuil(lambda T: simple(r, c, d, T, ours_col)),
        "collision, notre eponge, forme fine": seuil(lambda T: fin(r, c, d, T, 8, True)),
        "collision, article, forme simple (95)": seuil(lambda T: simple(r, c, d, T, (D(32), D(128), D(32768), 3))),
        "collision, article, forme fine (93)": seuil(lambda T: fin(r, c, d, T, 4, True)),
        "preimage, notre eponge, forme simple": seuil(lambda T: simple(r, c, d, T, ours_pre)),
        "preimage, notre eponge, forme fine": seuil(lambda T: fin(r, c, d, T, 4 * R2, False)),
        "preimage, article, forme simple (94)": seuil(lambda T: simple(r, c, d, T, (D(64), D(128), D(32768), 2))),
        "preimage, article, forme fine (92)": seuil(lambda T: fin(r, c, d, T, 4, False)),
    }
    print("  seuils de succes 1/2, log2 T (requetes d'echange ; requetes XOR standard : un bit de moins) :")
    for k, v in s.items(): print(f"    {k:42s} {v:.2f}")
    att = {"collision, notre eponge, forme simple": 124.81, "collision, notre eponge, forme fine": 125.67,
           "collision, article, forme simple (95)": 125.33, "preimage, notre eponge, forme simple": 125.14,
           "preimage, notre eponge, forme fine": 126.00}
    verdict("valeurs citees dans SPONGE_QROM.md", all(abs(s[k] - v) < 0.006 for k, v in att.items()))
    print("TOUT PASSE" if ok else "ECHEC")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
