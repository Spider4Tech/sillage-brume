"""Gap 2, real world: independent re-implementation of f3_kd.c (Python + numpy, PCG64 generator, other seeds), and a
heuristic prediction of the success probability. Real world O = (KD_K, f), b = r + c, r = 4, k = 4, f a random permutation.
Resources: q = 1, L = Omega = 0, M = 3 + F, N + M <= 0.1 * 2^c. T_fw = nu^{2M}_{r,c} (nu_exact.py), F = T_fw + 1 forced queries.
Usage: python3 f3_kd_check.py c trials seed"""
import sys, math
import numpy as np
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from nu_exact import nu

r, k = 4, 4
c, T, seed = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
b = r + c
F = 1
while True:                       # F = nu(2M) + 1 with M = 3 + F
    M = 3 + F
    v = nu(2 * M, r, c)
    if F == v + 1: break
    F = v + 1
NU, M = F - 1, 3 + F
NMAX = int(0.1 * 2 ** c) - M
rng = np.random.default_rng(seed)
succ = cand_n = 0
for e in range(T):
    f = rng.permutation(2 ** b)
    K = int(rng.integers(16))
    s = int(f[K << c])            # Init(delta, iv = 0), sigma = 0
    Zs, sbs = [s >> c], [0]
    s = int(f[s]); Zs.append(s >> c); sbs.append(0)
    s = int(f[s]); Zs.append(s >> c); sbs.append(0)
    N, cand = 0, -1
    for x in rng.permutation(2 ** c):
        if N + 2 + F > NMAX: break
        y = int(f[(Zs[0] << c) | int(x)]); N += 1
        if (y >> c) != Zs[1]: continue
        y2 = int(f[y]); N += 1
        if (y2 >> c) == Zs[2]:
            cand = y2; break
    cur = cand
    for i in range(F):
        sig = 0
        if cand >= 0:
            p = int(f[cur]); N += 1
            sig = ((p >> c) ^ 0) << c   # alpha = 0
            cur = p ^ sig
        s = int(f[s]); Zs.append(s >> c); sbs.append(sig >> c); s ^= sig
    assert N + M <= 0.1 * 2 ** c
    cnt = {}
    for z, sb in zip(Zs, sbs):
        cnt[z ^ sb] = cnt.get(z ^ sb, 0) + 1
    succ += max(cnt.values()) > NU
    cand_n += cand >= 0
p = succ / T
sd = math.sqrt(p * (1 - p) / T)
# heuristic prediction: guesses in random order; mean cost per guess 1 + 2^-r queries; a false candidate passes both checks
# with probability about 2^-2r and stops the search; success requires meeting the true one before a false one.
G = (NMAX - 2 - F) / (1 + 2 ** -r)
q = 2 ** (-2 * r)
pred = sum((1 / 2 ** c) * (1 - q) ** (i - 1) for i in range(1, int(G) + 1))
claim = NU / 2 ** c
print(f"c={c} nu={NU} F={F} M={M} N<={NMAX} trials={T} seed={seed} : Pr_O(mu_fw > {NU}) = {p:.5f} +- {sd:.5f} ;"
      f" heuristic prediction {pred:.5f} ; claimed nu/2^c = {claim:.6f} ; ratio {p / claim:.1f}")
