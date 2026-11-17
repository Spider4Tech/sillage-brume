#!/usr/bin/env python3
"""Exact check (rational arithmetic) of the combinatorial and representation-theoretic formulas of [CM] § 4
(Carolan-Majenz, arXiv 2609.28469) for every partition up to a size NMAX, far beyond what cpo_exact.py
can build as matrices. cpo_exact.py checks at N <= 7 that the operators have these spectra; this script
checks, from the formulas alone, the steps that turn the spectra into the bounds.

    python3 representations.py [NMAX]       (default 20)

 1. Lemma 4.9: the scalar (36) C(N,r) f^{lam/(m)} / f^lam equals the product (33) for lam = (m, mu);
    (34) its minimum is N/m, reached at mu = (1^r) only; (35) its maximum is <= exp(r/(N - 2r + 1)).
 2. Lemma 4.11: for alpha |- j <= N/2 and lam/alpha a horizontal n-strip (n = N - j),
    e_alpha(lam) = c(lam) - c(alpha) - C(n,2) + j is 0 for lam = (n, alpha) and >= n - j + 1 otherwise;
    Pieri dimension count sum_lam f^lam = C(N, j) f^alpha.
 3. Lemma 4.15: (72)-(73) 1 - h_alpha/g = 1/(m - d + 2 + eta'_d) <= 1/(m - r + 2); (74)-(75)
    f^lam/(N f^alpha) equals its product and is <= 1/(m - mu_1) <= 1/(m - r); hence (76) <= 2/m when
    m >= 2r + 2. Branching: sum over the parents lam of f^lam = N f^alpha (norm of v^alpha <= 1).
 4. Lemma 4.16: (78) g_nu/g_lam equals its product; (79) 0 <= 1 - rho <= 1/(m-r+2) + r/((m-r+1)(m-r+2))
    <= 4/m when m >= 2r + 2.
 5. The constants: (27), (29), Prop. 4.8, Lemma 4.15, (31).
Exit code 0 if every check passes.
"""
import math, sys
from fractions import Fraction as F
from young import partitions, hook_dim, skew_count, conj, col, content, horizontal_strip

NMAX = int(sys.argv[1]) if len(sys.argv) > 1 else 20
ok = True


def verdict(nom, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(f"  [{'ok' if cond else 'ECHEC'}] {nom}{' : ' + detail if detail else ''}", flush=True)


def g_formula(m, mu):
    """(33): prod_{c=1}^m (1 + mu'_c / (m - c + 1))."""
    p = F(1)
    for c in range(1, m + 1):
        p *= 1 + F(col(mu, c), m - c + 1)
    return p


def g36(N, r, lam):
    m = N - r
    return F(math.comb(N, r) * skew_count(lam, (m,)), hook_dim(lam))


# 1. Lemma 4.9
n33 = 0; e33 = e34 = e35 = True; pire35 = 0.0
for N in range(1, NMAX + 1):
    for r in range(0, N):
        m = N - r
        gs = []
        for mu in partitions(r, m):
            lam = (m,) + mu
            g = g_formula(m, mu)
            e33 &= g == g36(N, r, lam)
            n33 += 1
            gs.append((g, mu))
        gmin = min(gs)
        e34 &= gmin[0] == F(N, m) and gmin[1] == (1,) * r and sum(1 for g, _ in gs if g == gmin[0]) == 1
        if 2 * r <= N - 1:
            gmax = max(g for g, _ in gs)
            e35 &= float(gmax) <= math.exp(r / (N - 2 * r + 1)) * (1 + 1e-15)
            pire35 = max(pire35, math.log(float(gmax)) / (r / (N - 2 * r + 1)) if r else 0)
    # rows lam_1 > m give non-zero (36), lam_1 < m give zero: H_<=r = blocks lam_1 >= N - r
    for r in range(0, N + 1):
        m = N - r
        for lam in partitions(N):
            s = skew_count(lam, (m,)) if m > 0 else 1
            e33 &= (s != 0) == (lam[0] >= m)
verdict(f"lemme 4.9 : (36) = (33) pour tout lam = (m, mu), N <= {NMAX}", e33, f"{n33} partitions ; (36) non nul ssi lam_1 >= m")
verdict("(34) : minimum N/m, atteint en mu = (1^r) seulement", e34)
verdict("(35) : maximum <= exp(r/(N - 2r + 1)) pour r <= (N - 1)/2", e35, f"log g_max / (r/(N-2r+1)) <= {pire35:.3f}")

# 2. Lemma 4.11
e47 = True; n47 = 0; serre = 0; ecart_min = None
for N in range(2, NMAX + 1):
    parts_N = list(partitions(N))
    for j in range(1, N // 2 + 1):
        n = N - j
        for alpha in partitions(j):
            lams = [lam for lam in parts_N if horizontal_strip(lam, alpha)]
            e47 &= sum(hook_dim(l) for l in lams) == math.comb(N, j) * hook_dim(alpha)        # Pieri
            base = (n,) + alpha
            e47 &= base in lams
            for lam in lams:
                e = content(lam) - content(alpha) - math.comb(n, 2) + j
                n47 += 1
                if lam == base:
                    e47 &= e == 0
                else:
                    e47 &= e >= n - j + 1
                    serre += e == n - j + 1
                    ecart_min = e - (n - j + 1) if ecart_min is None else min(ecart_min, e - (n - j + 1))
verdict(f"lemme 4.11 : e_alpha = 0 en (n, alpha), >= n - j + 1 ailleurs ; Pieri, N <= {NMAX}", e47,
        f"{n47} bandes horizontales ; plus petit e_alpha hors base = n - j + 1 + {ecart_min} (borne de l'article non atteinte : {serre == 0})")

# 3. Lemma 4.15
e73 = e75 = ebr = True; n73 = n75 = 0
for N in range(3, NMAX + 1):
    for r in range(1, N):
        m = N - r
        # alpha = (m, eta), eta |- r - 1, parents lam = (m, mu), mu = eta + one box in column d
        for eta in partitions(r - 1, m):
            alpha = (m,) + eta
            h = F(math.comb(N - 1, r - 1) * skew_count(alpha, (m,)), hook_dim(alpha))
            somme = 0
            for i in range(len(eta) + 1):
                mu = list(eta) + [0]
                mu[i] += 1
                if i > 0 and mu[i] > mu[i - 1]:
                    continue
                mu = tuple(p for p in mu if p)
                if mu[0] > m:
                    continue
                d = mu[i]                       # the new box is in column d
                lam = (m,) + mu
                g = g_formula(m, mu)
                lhs = 1 - h / g
                rhs = F(1, m - d + 1 + col(eta, d) + 1)
                e73 &= lhs == rhs and (m - r + 2 <= 0 or rhs <= F(1, m - r + 2))
                n73 += 1
            # all parents of alpha (any first row): branching sum = N f^alpha
            for i in range(len(alpha) + 1):
                l2 = list(alpha) + [0]
                l2[i] += 1
                if i > 0 and l2[i] > l2[i - 1]:
                    continue
                somme += hook_dim(tuple(p for p in l2 if p))
            ebr &= somme == N * hook_dim(alpha)
        # alpha_1 = m - 1: alpha = (m - 1, mu), unique parent lam = (m, mu)
        for mu in (partitions(r, m - 1) if m >= 2 else ()):
            alpha = (m - 1,) + mu
            lam = (m,) + mu
            v = F(hook_dim(lam), N * hook_dim(alpha))
            p = F(1)
            for c in range(1, m):
                p *= F(m - c + col(mu, c), m - c + 1 + col(mu, c))
            mu1 = mu[0] if mu else 0
            e75 &= v == p and v <= F(1, m - mu1)
            if m > r:
                e75 &= F(1, m - mu1) <= F(1, m - r)
            n75 += 1
verdict(f"lemme 4.15 (72)-(73) : 1 - h_alpha/g = 1/(m - d + 2 + eta'_d) <= 1/(m - r + 2), N <= {NMAX}", e73, f"{n73} cas")
verdict("lemme 4.15 (74)-(75) : f^lam/(N f^alpha) = produit <= 1/(m - mu_1) <= 1/(m - r)", e75, f"{n75} cas")
verdict("branchement : sum des parents f^lam = N f^alpha", ebr)
e76 = all(F(1, m - r + 2) <= F(2, m) and F(1, m - r) <= F(2, m) for m in range(2, 4 * NMAX) for r in range(0, (m - 2) // 2 + 1))
verdict("(76) : les deux cas donnent <= 2/m quand m >= 2r + 2", e76)

# 4. Lemma 4.16
e78 = e79 = True; n78 = 0; pire79 = F(0)
for N in range(3, NMAX + 1):
    for r in range(1, N):
        m = N - r
        for mu in partitions(r, m):
            g_lam = g_formula(m, mu)
            mc = conj(mu)
            for d in range(1, len(mc) + 1):
                # removable box in column d: bottom of column d, its row i = mu'_d - 1, removable if
                # mu_{i} == d and (row i + 1 shorter)
                i = mc[d - 1] - 1
                if mu[i] != d:
                    continue
                mu2 = list(mu); mu2[i] -= 1
                mu2 = tuple(p for p in mu2 if p)
                nu_rest = mu2
                if nu_rest and nu_rest[0] > m + 1:
                    continue
                g_nu = g_formula(m + 1, nu_rest)
                rho = g_nu / g_lam
                qd = m - d + 1
                p = F(qd, qd + 1)
                for c in range(1, m + 1):
                    if c == d:
                        continue
                    qc = m - c + 1
                    mcc = col(mu, c)
                    p *= 1 - F(mcc, (qc + 1) * (qc + mcc))
                e78 &= rho == p
                n78 += 1
                if m >= 2 * r + 2:                     # hypothesis of Lemma 4.16 (3r + 2 <= N)
                    borne = F(1, m - r + 2) + F(r, (m - r + 1) * (m - r + 2))
                    e79 &= 0 <= 1 - rho <= borne <= F(4, m)
                    pire79 = max(pire79, (1 - rho) * m)
verdict(f"lemme 4.16 (78) : g_nu/g_lam = produit, N <= {NMAX}", e78, f"{n78} canaux")
verdict("(79) : 0 <= 1 - rho <= 1/(m-r+2) + r/((m-r+1)(m-r+2)) <= 4/m si m >= 2r + 2", e79,
        f"max m(1 - rho) = {float(pire79):.3f} (borne 4)")

# 5. constants
c = []
c.append(("(27) sqrt64 + sqrt32 + sqrt24 < 20", math.sqrt(64) + math.sqrt(32) + math.sqrt(24) < 20))
c.append(("(29) 2 kappa^2 + kappa^2 = 3 * 400 = 1200", 3 * 20 ** 2 == 1200))
c.append(("prop. 4.8 : 3 * 1200 = 3600 = 60^2", 3 * 1200 == 60 ** 2))
c.append(("lemme 4.15 : 2(6 + e) < 18 et 2(6 + e^2) < 27", 2 * (6 + math.e) < 18 and 2 * (6 + math.e ** 2) < 27))
c.append(("(23) : 2 * 8 = 16 <= 64 et 2 * 22 = 44 <= 64", 16 <= 64 and 44 <= 64))
c.append(("lemme 4.16 : 16 N/m^2 <= 24/m quand 3r + 2 <= N (N <= 3m/2)", all(F(16 * N, (N - r) ** 2) <= F(24, N - r) for N in range(2, 3000) for r in range(0, (N - 2) // 3 + 1))))
c.append(("lemme 4.15 : 4N/m^2 <= 6/m quand 3r + 2 <= N", all(F(4 * N, (N - r) ** 2) <= F(6, N - r) for N in range(2, 3000) for r in range(0, (N - 2) // 3 + 1))))
s31 = True
for N in range(3, 400):
    for q in range(1, (N + 1) // 3 + 1):
        if 3 * q - 1 > N:
            continue
        som = sum(60 / math.sqrt(N - j) + (j + 1) / (N - 2 * j - 1) for j in range(q))
        s31 &= som <= 60 * q / math.sqrt(N - q + 1) + q * (q + 1) / (2 * (N - 2 * q + 1)) + 1e-12
c.append(("(31) : la somme des pas (12) est bornee par la formule (31), N < 400", s31))
# Lemma 4.15: e bound used for ||G_r|| when 3r + 2 <= N: exp(r/(N - 2r + 1)) <= e
c.append(("lemme 4.15 : ||G_r|| <= e quand 3r + 2 <= N", all(r / (N - 2 * r + 1) <= 1 for N in range(2, 2000) for r in range(0, (N - 2) // 3 + 1))))
s413c = s413r = True
for m in range(1, 300):
    M = m + 1
    for r in range(0, m + 1):
        s413c &= F(1, m) + F(r, m * m) + F(4, M) + F(r, m * m * M) + F(r - 1, M ** 3) <= F(8, m)          # (59)-(62)
        s413r &= F(1, m * m) + F(9, m * m) + F(9, M) + F(1, m * m) + F(max(r - 1, 0), M * M) <= F(22, m)  # (63)-(66)
        s413r &= F(1, m * m) + F(max(r - 1, 0), M * M) <= F(2, m)                                        # (66)
c.append(("lemme 4.13 : (59)-(62) <= 8/m et (63)-(66) <= 22/m pour r <= m, m < 300", s413c and s413r))
for nom, v in c:
    verdict(nom, v)
print("TOUT PASSE" if ok else "ECHEC")
sys.exit(0 if ok else 1)
