#!/usr/bin/env python3
"""Exact check of the compressed permutation oracle of Carolan-Majenz ([CM], arXiv 2609.28469, § 3.3-§ 5)
on small N: every object is built from its definition, as a matrix, and every identity and inequality
of § 4 and § 5 is evaluated. See CM_VERIFICATION.md.

    python3 cpo_exact.py N RMAX [q_hybride]

Database levels 0..RMAX are built (RMAX = N for everything; smaller for N = 7). The checks at level r need
r + 1 <= RMAX. Each line reports the worst value found against the bound of the article, and whether the
article's hypothesis (3r + 2 <= N, j <= N/2, ...) holds: inequalities are also evaluated outside their
hypothesis, for information, but only lines inside it count. Exit code 0 if every counted check passes.
Needs numpy and scipy.
"""
import itertools, math, sys, time
import numpy as np
import scipy.sparse as sp
from scipy.sparse.linalg import svds
from young import partitions, hook_dim, skew_count, conj, content, horizontal_strip

T0 = time.time()
N = int(sys.argv[1])
RMAX = int(sys.argv[2])
QH = int(sys.argv[3]) if len(sys.argv) > 3 else 0
TOL = 1e-9
ok = True
lignes = []


def verdict(nom, cond, detail="", compte=True):
    global ok
    if compte:
        ok &= bool(cond)
    etat = ("ok" if cond else "ECHEC") if compte else ("info" if cond else "info: depasse")
    print(f"  [{etat}] {nom}{' : ' + detail if detail else ''}", flush=True)


def norm(a):
    if a.size == 0:
        return 0.0
    if sp.issparse(a):
        a = a.toarray()
    return float(np.linalg.norm(a, 2))


def lmax(h):
    return float(np.linalg.eigvalsh(h)[-1]) if h.size else 0.0


def lmin(h):
    return float(np.linalg.eigvalsh(h)[0]) if h.size else 0.0


def fam(ts):
    """Col^2 and Row^2 of a family (T_y), [CM] (14)."""
    if not ts or ts[0].size == 0:
        return 0.0, 0.0
    c2 = lmax(sum(t.T @ t for t in ts))
    rows, cols = ts[0].shape
    if rows <= len(ts) * cols:
        r2 = lmax(sum(t @ t.T for t in ts))
    else:
        h = np.hstack(ts)
        r2 = lmax(h.T @ h)
    return c2, r2


print(f"N = {N}, niveaux 0..{RMAX}", flush=True)

# ---------------------------------------------------------------- spaces P and L
perms = list(itertools.permutations(range(N)))
pidx = {p: i for i, p in enumerate(perms)}
NF = len(perms)
niv = []                                   # niv[r] = list of partial permutations (tuples, -1 = undefined)
for r in range(RMAX + 1):
    lr = []
    for dom in itertools.combinations(range(N), r):
        for img in itertools.permutations(range(N), r):
            f = [-1] * N
            for u, v in zip(dom, img):
                f[u] = v
            lr.append(tuple(f))
    niv.append(lr)
off = np.cumsum([0] + [len(l) for l in niv])
NL = int(off[-1])
gidx = {}
for r, lr in enumerate(niv):
    for i, f in enumerate(lr):
        gidx[f] = int(off[r]) + i
lev = np.concatenate([np.full(len(l), r) for r, l in enumerate(niv)])
allf = [f for l in niv for f in l]
print(f"  dim P = {NF}, dim L(<= {RMAX}) = {NL}", flush=True)


def sel(r):
    return slice(int(off[r]), int(off[r + 1]))


def embed(r, X):
    """A block of level r (rows I_r) as rows of the whole L."""
    out = np.zeros((NL, X.shape[1]))
    out[sel(r)] = X
    return out


# ---------------------------------------------------------------- synthesis E_r and the levels H_r
E = []
for r in range(RMAX + 1):
    m = N - r
    rows, cols = [], []
    for pi, p in enumerate(perms):
        for dom in itertools.combinations(range(N), r):
            f = [-1] * N
            for u in dom:
                f[u] = p[u]
            rows.append(pi)
            cols.append(gidx[tuple(f)] - int(off[r]))
    E.append(sp.csr_matrix((np.full(len(rows), 1 / math.sqrt(math.factorial(m))), (rows, cols)),
                           shape=(NF, len(niv[r]))))

parts = list(partitions(N))
fdim = {lam: hook_dim(lam) for lam in parts}
Pi_le, W, g_eig = [], [], []
pire_k = pire_g = 0.0
spec_ok = formule_ok = True
for r in range(RMAX + 1):
    m = N - r
    K = (E[r] @ E[r].T).toarray()
    # [CM] proof of Lemma 4.9: <pi|E E^+|sigma> = C(agree(pi, sigma), r) / m!
    if r <= 3 or NF <= 720:
        for _ in range(200):
            a, b = np.random.randint(NF, size=2)
            ag = sum(1 for u in range(N) if perms[a][u] == perms[b][u])
            formule_ok &= abs(K[a, b] - math.comb(ag, r) / math.factorial(m)) < 1e-12
    ev, U = np.linalg.eigh(K)
    att = []                                                   # (36): C(N, r) f^{lam/(m)} / f^lam
    for lam in parts:
        if lam[0] >= m:
            att += [math.comb(N, r) * skew_count(lam, (m,)) / fdim[lam]] * fdim[lam] ** 2
    att = np.sort(np.array(att + [0.0] * (NF - len(att))))
    pire_k = max(pire_k, float(np.max(np.abs(np.sort(ev) - att))))
    P = U[:, ev > 1e-9] @ U[:, ev > 1e-9].T
    Pi_le.append(P)
    prev = Pi_le[r - 1] if r else np.zeros_like(P)
    spec_ok &= norm(P @ prev - prev) < 1e-8
    Pr = P - prev
    u, s, _ = np.linalg.svd(Pr @ U[:, ev > 1e-9], full_matrices=False)
    Wr = u[:, s > 0.5]
    W.append(Wr)
    spec_ok &= abs(Wr.shape[1] - sum(fdim[l] ** 2 for l in parts if l[0] == m)) == 0
    g = Wr.T @ K @ Wr                                           # G_r on H_r
    ge = np.linalg.eigvalsh(g)
    g_eig.append(ge)
    att = []
    for lam in parts:
        if lam[0] == m:
            mu = lam[1:]
            gv = 1.0
            for c in range(1, m + 1):
                gv *= 1 + (sum(1 for p in mu if p >= c)) / (m - c + 1)
            att += [gv] * fdim[lam] ** 2
    pire_g = max(pire_g, float(np.max(np.abs(ge - np.sort(att)))) if len(att) else 0.0)
verdict("lemme 4.9 : <pi|E E^+|sigma> = C(accord, r)/m!", formule_ok)
verdict("lemme 4.9 (36) : spectre de E_r E_r^+ = C(N,r) f^{lam/(m)}/f^lam, multiplicites (f^lam)^2",
        pire_k < 1e-8, f"ecart max {pire_k:.1e}")
verdict("H_<=r emboites ; H_r = blocs lam_1 = N - r (dimensions)", spec_ok)
verdict("lemme 4.9 (33) : spectre de G_r = produit des (1 + mu'_c/(m - c + 1))", pire_g < 1e-8,
        f"ecart max {pire_g:.1e}")
b34 = all(abs(ge[0] - N / (N - r)) < 1e-9 for r, ge in enumerate(g_eig) if len(ge))
b35 = all(ge[-1] <= math.exp(r / (N - 2 * r + 1)) + 1e-12 for r, ge in enumerate(g_eig) if len(ge) and 2 * r <= N - 1)
verdict("(34) : lambda_min(G_r) = N/(N - r)", b34)
verdict("(35) : ||G_r|| <= exp(r/(N - 2r + 1)) pour r <= (N - 1)/2", b35,
        " ; ".join(f"r={r}: {ge[-1]:.4f} <= {math.exp(r / (N - 2 * r + 1)):.4f}"
                   for r, ge in enumerate(g_eig) if len(ge) and 2 * r <= N - 1))

# ---------------------------------------------------------------- V, V~ (9)
Vw, Vtw, gin = [], [], []        # V_r W_r, V~_r W_r (|I_r| x d_r), and g^{-1}, g^{1/2}
for r in range(RMAX + 1):
    Wr = W[r]
    g = Wr.T @ ((E[r] @ (E[r].T @ Wr)))
    ev, U = np.linalg.eigh(g)
    gi = U @ np.diag(1 / ev) @ U.T
    gih = U @ np.diag(ev ** -0.5) @ U.T
    gh = U @ np.diag(ev ** 0.5) @ U.T
    Vw.append(E[r].T @ (Wr @ gi))
    Vtw.append(E[r].T @ (Wr @ gih))
    gin.append((g, gi, gh, gih))
e37 = e38 = e39 = e40 = e41 = 0.0
for r in range(RMAX + 1):
    Wr = W[r]
    g, gi, gh, gih = gin[r]
    d = Wr.shape[1]
    if d == 0:
        continue
    e37 = max(e37, norm(Wr.T @ (E[r] @ Vw[r]) - np.eye(d)), norm(Vw[r].T @ Vw[r] - gi))
    e37 = max(e37, norm(Vw[r]) - 1)
    e38 = max(e38, norm(Vtw[r].T @ Vtw[r] - np.eye(d)), norm(E[r] @ Vtw[r] - Wr @ gh))
    q, _ = np.linalg.qr(E[r].T @ Wr)                               # projector on K_r = ran Gamma^+
    PK = q @ q.T
    e38 = max(e38, norm(Vtw[r] @ Vtw[r].T - PK))
    e40 = max(e40, norm(E[r] @ Vw[r] - Wr), norm(Vw[r] @ (Wr.T @ E[r].toarray()) - PK))
    e39 = max(e39, norm(E[r] @ Vw[r] - Pi_le[r] @ (E[r] @ Vw[r]) + (Pi_le[r - 1] @ (E[r] @ Vw[r]) if r else 0)))
    e41 = max(e41, norm(gih @ g @ gih - np.eye(d)))
verdict("lemme 4.10 (37) : Gamma V = I, V^+V = G^-1, ||V|| <= 1", e37 < 1e-8, f"{e37:.1e}")
verdict("lemme 4.10 (38) : V~ isometrie, V~ V~^+ = Pi_K, E V~ = G^1/2", e38 < 1e-8, f"{e38:.1e}")
verdict("lemme 4.10 (39) : E_r a = Gamma_r a dans H_r pour a dans K_r", e39 < 1e-8, f"{e39:.1e}")
verdict("lemme 4.10 (40) : E V = I_H, Pi_K = V Gamma", e40 < 1e-8, f"{e40:.1e}")
verdict("lemme 4.10 (41) : POVM sur H_r", e41 < 1e-8, f"{e41:.1e}")
sN = np.full(NF, 1 / math.sqrt(NF))
img = np.zeros(NL)
for r in range(RMAX + 1):
    img[sel(r)] = Vtw[r] @ (W[r].T @ sN)
verdict("theoreme 4.2 (10) : V~|S_N> = |vide>", abs(img[0] - 1) < 1e-9 and np.linalg.norm(img[1:]) < 1e-9)


def Vfull(tilde=False):
    out = np.zeros((NL, NF))
    for r in range(RMAX + 1):
        out[sel(r)] = (Vtw if tilde else Vw)[r] @ W[r].T
    return out


V = Vfull()
Vt = Vfull(True)

# ---------------------------------------------------------------- incidence maps (42), (43): zero sums (39)
def incidence(j):
    """B^dom_j and B^im_j : L_j -> C^{(h, b)} and C^{(h, u)}, h in I_{j-1}."""
    M = N - j + 1
    rows_i, rows_d = {}, {}
    ri, ci, rd, cd = [], [], [], []
    for k, f in enumerate(niv[j]):
        for u in range(N):
            if f[u] < 0:
                continue
            h = list(f); b = h[u]; h[u] = -1; h = tuple(h)
            ki = rows_i.setdefault((h, b), len(rows_i))      # (B^im a)_{h,b} = sum over u of a_{h[u->b]}
            kd = rows_d.setdefault((h, u), len(rows_d))      # (B^dom a)_{h,u} = sum over b of a_{h[u->b]}
            ri.append(ki); ci.append(k); rd.append(kd); cd.append(k)
    s = 1 / math.sqrt(M)
    Bi = sp.csr_matrix((np.full(len(ri), s), (ri, ci)), shape=(len(rows_i), len(niv[j])))
    Bd = sp.csr_matrix((np.full(len(rd), s), (rd, cd)), shape=(len(rows_d), len(niv[j])))
    return Bd, Bi


Binc = [None] + [incidence(j) for j in range(1, RMAX + 1)]
e = max((norm(Binc[r][0] @ Vw[r]) + norm(Binc[r][1] @ Vw[r])) for r in range(1, RMAX + 1) if W[r].shape[1])
verdict("(39) : sommes nulles (domaine et image) sur K_r, r = 1..RMAX", e < 1e-8, f"{e:.1e}")

# Lemma 4.11
for j in range(1, RMAX + 1):
    if 2 * j > N:
        continue
    n = N - j
    Bd, Bi = Binc[j]
    DD = (Bd.T @ Bd + Bi.T @ Bi).toarray()
    # (46): (2j I + A_d + A_i)/(n + 1)
    Ad = np.zeros_like(DD); Ai = np.zeros_like(DD)
    for k, f in enumerate(niv[j]):
        dom = [u for u in range(N) if f[u] >= 0]
        free_d = [u for u in range(N) if f[u] < 0]
        free_i = [v for v in range(N) if v not in f]
        for u in dom:
            for u2 in free_d:
                g = list(f); g[u2] = g[u]; g[u] = -1
                Ad[gidx[tuple(g)] - int(off[j]), k] += 1
            for v2 in free_i:
                g = list(f); g[u] = v2
                Ai[gidx[tuple(g)] - int(off[j]), k] += 1
    e46 = norm(DD - (2 * j * np.eye(len(DD)) + Ad + Ai) / (n + 1))
    ev = np.linalg.eigvalsh(DD)
    att = []
    for alpha in partitions(j):
        lams = [lam for lam in partitions(N) if horizontal_strip(lam, alpha)]
        for lam in lams:
            for mu in lams:
                ea = lambda l: content(l) - content(alpha) - math.comb(n, 2) + j
                att += [(ea(lam) + ea(mu)) / (n + 1)] * (fdim[lam] * fdim[mu])
    e47 = float(np.max(np.abs(ev - np.sort(att)))) if len(att) == len(ev) else float("inf")
    c = (n - j + 1) / (n + 1)
    PK = Vtw[j] @ Vtw[j].T
    e44 = lmin(DD - c * (np.eye(len(DD)) - PK))
    noyau = int(np.sum(ev < 1e-9))
    verdict(f"lemme 4.11, j = {j} : (46) exacte, spectre = (47), (44) d^+d >= {c:.3f}(I - Pi_K), noyau = K_j",
            e46 < 1e-9 and e47 < 1e-8 and e44 > -1e-9 and noyau == W[j].shape[1],
            f"(46) {e46:.1e}, (47) {e47:.1e}, lambda_min {e44:.2e}, dim noyau {noyau} = dim K {W[j].shape[1]}")

# ---------------------------------------------------------------- the oracles
def build_C(x):
    rows, cols, vals = [], [], []
    vu = np.zeros(NL, bool)
    for gh_, h in enumerate(allf):
        if h[x] >= 0 or lev[gh_] >= RMAX:
            continue
        Y = [v for v in range(N) if v not in h]
        s = len(Y)
        hy = []
        for v in Y:
            f = list(h); f[x] = v
            hy.append(gidx[tuple(f)])
        blk = [gh_] + hy
        for a in blk:
            vu[a] = True
        for k, a in enumerate(hy):
            rows += [gh_, a]; cols += [a, gh_]; vals += [1 / math.sqrt(s)] * 2
            for k2, b in enumerate(hy):
                rows.append(a); cols.append(b); vals.append((1.0 if k == k2 else 0.0) - 1 / s)
    for a in np.where(~vu)[0]:          # only bases at level RMAX, never used (blocks incomplete)
        rows.append(a); cols.append(a); vals.append(1.0)
    return sp.csr_matrix((vals, (rows, cols)), shape=(NL, NL))


def qL(x, y):
    return np.array([1.0 if f[x] == y else 0.0 for f in allf])


def qP(x, y):
    return np.array([1.0 if p[x] == y else 0.0 for p in perms])


x = 0
C = build_C(x)
QL = [qL(x, y) for y in range(N)]
QLb = np.array([1.0 if f[x] < 0 else 0.0 for f in allf])
QP = [qP(x, y) for y in range(N)]
Mop = [C @ sp.diags(QL[y]) @ C for y in range(N)]
Mb = C @ sp.diags(QLb) @ C
low = lev < RMAX
e = norm((C @ C - sp.identity(NL))[:, low]) + norm((C - C.T))
verdict("C_x unitaire et autoadjoint ; M_perp + sum M_y = I (definition 3.6)", e < 1e-9 and
        norm((Mb + sum(Mop) - sp.identity(NL))[:, low]) < 1e-9)
e = norm(Mb @ V) if RMAX == N else norm(Mb @ (V @ Pi_le[RMAX - 1]))
verdict("preuve de la prop. 4.8 : M_perp V = 0 (harmonicite), donc sum_y D_y = 0 (28)", e < 1e-8, f"{e:.1e}")

# Lemma 4.5 and Lemma 4.6
eb = e17 = 0.0
for r in range(RMAX):
    Pr = W[r]
    for y in range(N):
        out = QP[y][:, None] * Pr
        hors = out - sum((W[j] @ (W[j].T @ out)) for j in (r - 1, r, r + 1) if 0 <= j <= RMAX)
        eb = max(eb, norm(hors))
        a = Vw[r]
        Ma = Mop[y] @ embed(r, a)
        lhs = sum(E[j] @ Ma[sel(j)] for j in (r - 1, r, r + 1) if 0 <= j <= RMAX)
        e17 = max(e17, norm(lhs - QP[y][:, None] * (E[r] @ a)))
verdict("lemme 4.5 : Q_y H_r dans H_{r-1} + H_r + H_{r+1}", eb < 1e-8, f"{eb:.1e}")
verdict("lemme 4.6 (17) : sum_j E_j L_j M_y a = Q_y E_r a sur K_r", e17 < 1e-8, f"{e17:.1e}")

# ---------------------------------------------------------------- one-query bounds, level by level
PKt = [Vtw[r] @ Vtw[r].T for r in range(RMAX + 1)]
print("  niveau par niveau (x = 0 ; y parcourt [N]) :", flush=True)
for r in range(RMAX):
    m = N - r
    d = W[r].shape[1]
    if d == 0:
        continue
    hyp = 3 * r + 2 <= N
    Wr = W[r]
    z_p, z_0, h_0, h_m, Th, e26, e12, e69, e76, e77, Hpos = [], [], [], [], [], 0.0, 0.0, 0.0, 0.0, 0.0, True
    e26m_max = 0.0
    e48 = 0.0
    Cfam = []
    sH00 = np.zeros((d, d))
    for y in range(N):
        a = Vw[r]                                    # a = V_r psi, psi in H_r (basis W_r)
        Ma = Mop[y] @ embed(r, a)
        bp = Ma[sel(r + 1)]
        b0 = Ma[sel(r)]
        bm = Ma[sel(r - 1)] if r else np.zeros((0, d))
        Qpsi = QP[y][:, None] * Wr
        zp = bp - PKt[r + 1] @ bp
        z0 = b0 - PKt[r] @ b0
        h0 = PKt[r] @ b0 - Vw[r] @ (Wr.T @ Qpsi)
        hm = bm - Vw[r - 1] @ (W[r - 1].T @ Qpsi) if r else np.zeros((0, d))
        z_p.append(zp); z_0.append(z0); h_0.append(h0); h_m.append(hm)
        # Lemma 4.12: b^- in K_{r-1}
        if r:
            e12 = max(e12, norm(bm - PKt[r - 1] @ bm))
        # (26): d^j = L_j (M_y V - V Q_y) Pi_r
        D = Ma - V @ Qpsi
        d1 = D[sel(r + 1)] - zp
        d0 = D[sel(r)] - (z0 - Vw[r] @ (Wr.T @ (E[r + 1] @ zp)))        # (26), second line
        e26 = max(e26, norm(d1), norm(d0))
        if r:                                                             # (26), third line
            dm = D[sel(r - 1)] + Vw[r - 1] @ (W[r - 1].T @ (E[r] @ z0 + E[r + 1] @ zp))
            e26m = norm(dm)
        else:
            e26m = 0.0
        e26m_max = max(e26m_max, e26m)
        # (48)-(51): the components of M_y a, a in K_r, coefficient by coefficient
        M_ = m + 1
        pred = np.zeros_like(Ma)
        for k, f in enumerate(niv[r]):
            if f[x] < 0:
                if y not in f:
                    for z in range(N):
                        if z in f:
                            continue
                        g_ = list(f); g_[x] = z
                        pred[gidx[tuple(g_)]] = a[k] / math.sqrt(m) * ((1.0 if z == y else 0.0) - 1 / m)   # (48)
                    pred[int(off[r]) + k] = a[k] / m                                                       # (49)
            else:
                h_ = list(f); z = h_[x]; h_[x] = -1
                if y not in h_:
                    hy = list(h_); hy[x] = y
                    pred[int(off[r]) + k] = a[gidx[tuple(hy)] - int(off[r])] * ((1.0 if z == y else 0.0) - 1 / M_)  # (50)
        if r:
            for k, h_ in enumerate(niv[r - 1]):
                if h_[x] < 0 and y not in h_:
                    hy = list(h_); hy[x] = y
                    pred[int(off[r - 1]) + k] = a[gidx[tuple(hy)] - int(off[r])] / math.sqrt(M_)               # (51)
        e48 = max(e48, norm(pred - Ma))
        # Lemma 4.13: Theta
        parts_ = [Binc[r + 1][1] @ bp, Binc[r + 1][0] @ bp]
        if r:
            parts_ += [Binc[r][1] @ b0, Binc[r][0] @ b0]
        Th.append(np.vstack(parts_))
        # Lemma 4.14 (69) on K_r
        R11 = np.array([1.0 if f[x] == y else 0.0 for f in niv[r]])                 # (67)
        R00 = np.array([1.0 if (f[x] < 0 and y not in f) else 0.0 for f in niv[r]])
        Kb = Vtw[r]
        lhs = Kb.T @ (Mop[y][sel(r), sel(r)] @ Kb)
        rhs = Kb.T @ ((R00 / m + R11)[:, None] * Kb)
        e69 = max(e69, norm(lhs - rhs))
        # (76) and positivity, (77)
        g, gi, gh, gih = gin[r]
        A = Wr.T @ Qpsi
        H11 = (Wr.T @ E[r].toarray()) @ (R11[:, None] * (E[r].T @ Wr))
        H00 = (Wr.T @ E[r].toarray()) @ (R00[:, None] * (E[r].T @ Wr)) / m
        if r:
            e76 = max(e76, norm(A - H11 @ gi))
            gr = gin[r - 1][0]
            qyr = W[r - 1].T @ Qpsi
            e77 = max(e77, norm(hm - Vw[r - 1] @ (gr @ qyr @ gi - qyr)))
        Cfam.append(H00 @ gi)
        sH00 += H00
        Hpos &= lmax(np.linalg.inv(np.linalg.cholesky(g)) @ H00 @ np.linalg.inv(np.linalg.cholesky(g)).T) <= 1 / m + 1e-9
    # Theta acts on K_r: restrict to an orthonormal basis of K_r (the columns of V~_r); here the inputs are
    # V_r psi = V~_r g^{-1/2} psi, so compose with g^{1/2} on the right to obtain the operator on K_r.
    g, gi, gh, gih = gin[r]
    Thk = [t @ gh for t in Th]
    c_t, r_t = fam(Thk)
    c_zp, r_zp = fam([np.vstack([a_, b_]) for a_, b_ in zip(z_p, z_0)])
    c_h0, r_h0 = fam(h_0)
    c_hm, r_hm = fam(h_m) if r else (0.0, 0.0)
    verdict(f"r = {r} (m = {m}) : identites (26), deux premieres lignes", e26 < 1e-8, f"{e26:.1e}")
    if r:
        verdict(f"r = {r} : lemme 4.12 (b^- dans K_r-1) et (26), troisieme ligne", e12 < 1e-8 and e26m_max < 1e-8,
                f"{e12:.1e}, {e26m_max:.1e} ; hypothese 3r + 2 <= N {'oui' if hyp else 'non'}", compte=hyp)
    verdict(f"r = {r} : lemme 4.14 (69), (77)", e69 < 1e-8 and e77 < 1e-8, f"{e69:.1e}, {e77:.1e}")
    for nom, val, borne in (("lemme 4.13 Col(Theta)^2", c_t, 8), ("lemme 4.13 Row(Theta)^2", r_t, 22),
                            ("(23) Col(z)^2", c_zp, 64), ("(23) Row(z)^2", r_zp, 64),
                            ("(24) Col(h0)^2", c_h0, 32), ("(24) Row(h0)^2", r_h0, 32),
                            ("(25) Col(h-)^2", c_hm, 24), ("(25) Row(h-)^2", r_hm, 24)):
        h_ = (r <= m) if nom.startswith("lemme 4.13") else hyp
        verdict(f"r = {r} : {nom} = {val * m:.3f}/m <= {borne}/m", val <= borne / m + 1e-12,
                f"hypothese {'oui' if h_ else 'non'}", compte=h_)
    verdict(f"r = {r} : formules (48)-(51) des composantes de M_y a", e48 < 1e-8, f"{e48:.1e}")
    Lc = np.linalg.inv(np.linalg.cholesky(g))
    c_c, r_c = fam(Cfam)
    sH = lmax(Lc @ sH00 @ Lc.T)
    verdict(f"r = {r} : lemme 4.15, sum_y H00 <= G ({sH:.4f} <= 1) ; Col(C)^2 = {c_c * m:.3f}/m <= e/m ; "
            f"Row(C)^2 = {r_c * m:.3f}/m <= e^2/m", sH <= 1 + 1e-9 and c_c <= math.e / m and r_c <= math.e ** 2 / m,
            f"hypothese {'oui' if hyp else 'non'}", compte=hyp)
    if r:
        verdict(f"r = {r} : (76) ||A - H11 G^-1|| = {e76 * m:.3f}/m <= 2/m ; H00 <= G/m", e76 <= 2 / m + 1e-12 and Hpos,
                f"hypothese {'oui' if hyp else 'non'}", compte=hyp)

# ---------------------------------------------------------------- Prop. 4.8, (11), (12), (29), (30)
S = []
for y in range(N):
    s_ = np.eye(N + 1)
    s_[[0, 1 + y]] = s_[[1 + y, 0]]
    S.append(s_)


def erreur(t, tilde, inverse=False):
    """|| (cpO_x (I (x) V) - (I (x) V) P_x)(I (x) Pi_<=t) ||, from the definitions; Pi_t only if t < 0."""
    Vm = Vt if tilde else V
    lv = [abs(t) - 1] if t < 0 else list(range(t + 1))
    Wt = np.hstack([W[r] for r in lv])
    rows_lv = lev <= (max(lv) + 1)
    if inverse:       # cpO^-1_x = F cpO_x F, P^-1_x = Inv P (x as image) Inv
        Fl = np.array([gidx[tuple(f.index(v) if v in f else -1 for v in range(N))] for f in allf])
        Fp = np.array([pidx[tuple(p.index(v) for v in range(N))] for p in perms])
        Mi = [sp.csr_matrix(Mop[y])[Fl][:, Fl] for y in range(N)]
        Mbi = sp.csr_matrix(Mb)[Fl][:, Fl]
        Qi = [QP[y][Fp] for y in range(N)]
    else:
        Mi, Mbi, Qi = Mop, Mb, QP
    MV = [(Mi[y] @ (Vm @ Wt))[rows_lv] for y in range(N)]
    MbV = (Mbi @ (Vm @ Wt))[rows_lv]
    VQ = [(Vm @ (Qi[y][:, None] * Wt))[rows_lv] for y in range(N)]
    nr, nc = MbV.shape
    B = np.zeros(((N + 1) * nr, (N + 1) * nc))
    for ao in range(N + 1):
        for ai in range(N + 1):
            blk = (MbV if ao == ai else 0) + sum(S[y][ao, ai] * (MV[y] - VQ[y]) for y in range(N))
            if not isinstance(blk, int):
                B[ao * nr:(ao + 1) * nr, ai * nc:(ai + 1) * nc] = blk
    return math.sqrt(max(lmax(B.T @ B), 0.0))


print("  une requete (Prop. 4.8, theoreme 4.2) :", flush=True)
for t in range(RMAX):
    taille = (N + 1) ** 2 * sum(W[r].shape[1] for r in range(t + 1)) * int(np.sum(lev <= t + 1))
    if taille > 4e8:
        print(f"    t = {t} : omis (taille)")
        continue
    hyp = 3 * t + 2 <= N
    e_v = erreur(t, False)
    e_vt = erreur(t, True)
    e_inv = erreur(t, True, inverse=True)
    b11 = 60 / math.sqrt(N - t)
    b12 = b11 + (t + 1) / (N - 2 * t - 1) if N - 2 * t - 1 > 0 else float("inf")
    r_ = t
    e29 = erreur(-(t + 1), False) ** 2
    verdict(f"t = {t} : (11) {e_v:.4f} <= {b11:.2f} ; (12) {e_vt:.4f} (inverse {e_inv:.4f}) <= {b12:.2f} ; "
            f"(29) {e29:.4f} <= {1200 / (N - t):.1f}",
            e_v <= b11 and e_vt <= b12 and e_inv <= b12 and e29 <= 1200 / (N - t),
            f"hypothese {'oui' if hyp else 'non'}", compte=hyp)
e30 = max((norm(Vtw[r] - Vw[r]), r) for r in range(1, RMAX + 1) if 2 * r <= N - 1) if N >= 3 else (0, 0)
verdict("(30) ||(V~ - V) Pi_s|| <= s/(2(N - 2s + 1))",
        all(norm(Vtw[r] - Vw[r]) <= r / (2 * (N - 2 * r + 1)) + 1e-12 for r in range(1, RMAX + 1) if 2 * r <= N - 1))
Fl = np.array([gidx[tuple(f.index(v) if v in f else -1 for v in range(N))] for f in allf])
Fp = np.array([pidx[tuple(p.index(v) for v in range(N))] for p in perms])
verdict("theoreme 4.2 : F V = V Inv, F V~ = V~ Inv", norm(V[Fl] - V[:, Fp]) < 1e-9 and norm(Vt[Fl] - Vt[:, Fp]) < 1e-9)

# ---------------------------------------------------------------- § 5: (82) and Lemma 5.2
for q in range(RMAX):
    s = N - q
    low = np.where(lev <= q)[0]
    pire = max(norm((Mop[y] - sp.diags(QL[y]))[:, low]) for y in range(N))
    # on L_<=q the subspaces based at |h| <= q - 1 are whole (sine of the angle, s = N - |h|), those based
    # at |h| = q only through |h> (norm 1/sqrt(N - q)); the article bounds both by sqrt(2/(N - q))
    exact = max([1 / math.sqrt(N - q)] + [math.sqrt(2 / (N - k) - 1 / (N - k) ** 2) for k in range(q)])
    verdict(f"lemme 5.1 (82), q = {q} : ||(M - Q) L_<=q|| = {pire:.4f} (valeur exacte attendue {exact:.4f}) <= {math.sqrt(2 / (N - q)):.4f}",
            abs(pire - exact) < 1e-9 and pire <= math.sqrt(2 / (N - q)) + 1e-12)

props = {
    "preimage de 0": lambda f: any(v == 0 for v in f),
    "collision de y // 2": lambda f: len([v for v in f if v >= 0]) != len({v // 2 for v in f if v >= 0}),
    "point fixe": lambda f: any(f[u] == u for u in range(N)),
}
Cs = [C] + [build_C(xx) for xx in range(1, N)]
for nom, prop in props.items():
    inB = np.array([1.0 if prop(f) else 0.0 for f in allf])
    pire_rapport = 0.0
    bon = True
    for t in range(RMAX):
        hs = [f for f, l in zip(allf, lev) if l <= t and not prop(f)]
        st = 0
        for h in hs:
            for u in range(N):
                if h[u] >= 0:
                    continue
                st = max(st, sum(1 for v in range(N) if v not in h and prop(tuple(v if k == u else h[k] for k in range(N)))))
            for v in range(N):
                if v in h:
                    continue
                st = max(st, sum(1 for u in range(N) if h[u] < 0 and prop(tuple(v if k == u else h[k] for k in range(N)))))
        low = np.where(lev <= t)[0]
        borne = 2 * math.sqrt(2 * st / (N - t))
        rows_t = np.where(lev <= t + 1)[0]
        for xx in range(N):
            Cx = Cs[xx]
            for direction in (0, 1):
                Cd = Cx if direction == 0 else Cx[Fl][:, Fl]
                Q = [qL(xx, y) for y in range(N)]
                if direction:
                    Q = [q_[Fl] for q_ in Q]
                Qb = 1 - sum(Q)
                cpO = sp.kron(sp.identity(N + 1), Cd @ sp.diags(Qb) @ Cd)          # definition (4)
                for y in range(N):
                    cpO = cpO + sp.kron(sp.csr_matrix(S[y]), Cd @ sp.diags(Q[y]) @ Cd)
                cpO = sp.csr_matrix(cpO)
                rsel = np.concatenate([a * NL + rows_t for a in range(N + 1)])
                csel = np.concatenate([a * NL + low for a in range(N + 1)])
                Bop = sp.diags(np.tile(inB, N + 1)) @ cpO @ sp.diags(np.tile(1 - inB, N + 1))
                Bop = Bop[rsel][:, csel]
                if Bop.nnz == 0:
                    val = 0.0
                elif min(Bop.shape) <= 3000:
                    val = norm(Bop)
                else:
                    val = float(svds(Bop, k=1, return_singular_vectors=False)[0])
                bon &= val <= borne + 1e-9
                if borne > 0:
                    pire_rapport = max(pire_rapport, val / borne)
                elif val > 1e-9:
                    bon = False
    verdict(f"lemme 5.2, propriete « {nom} » : ||B cpO (I - B) L_<=t|| <= 2 sqrt(2 s_t/(N - t)), t < {RMAX}, "
            f"tout x, avant et inverse", bon, f"pire rapport {pire_rapport:.3f}")

# ---------------------------------------------------------------- hybrid argument, a random algorithm
if QH:
    rng = np.random.default_rng(20261116)
    dacc = N * 2 * (N + 1) * 2               # X (x) direction (x) A (x) work qubit
    Ux_c = []
    for xx in range(N):
        tab = np.array([f[xx] for f in allf])
        Ux_c.append(tab)
    imgP = np.array([[p[xx] for xx in range(N)] for p in perms])
    invP = np.array([[p.index(v) for v in range(N)] for p in perms])
    flipL = Fl

    def haar(n):
        z = rng.normal(size=(n, n)) + 1j * rng.normal(size=(n, n))
        qq, rr = np.linalg.qr(z)
        return qq * (np.diag(rr) / abs(np.diag(rr)))

    def requete_c(st):
        out = np.empty_like(st)
        for xx in range(N):
            for dr in range(2):
                blk = st[xx, dr]                              # (N+1, 2, NL)
                if dr == 1:
                    blk = blk[..., flipL]
                Cm = Cs[xx]
                blk = (Cm @ blk.reshape(-1, NL).T).T.reshape(blk.shape)
                ans = Ux_c[xx]
                b2 = blk.copy()
                for v in range(N):
                    msk = ans == v
                    b2[0][..., msk] = blk[1 + v][..., msk]
                    b2[1 + v][..., msk] = blk[0][..., msk]
                blk = (Cm @ b2.reshape(-1, NL).T).T.reshape(b2.shape)
                if dr == 1:
                    blk = blk[..., flipL]
                out[xx, dr] = blk
        return out

    def requete_p(st):
        out = np.empty_like(st)
        for xx in range(N):
            for dr in range(2):
                ans = imgP[:, xx] if dr == 0 else invP[:, xx]
                blk = st[xx, dr]
                b2 = blk.copy()
                for v in range(N):
                    msk = ans == v
                    b2[0][..., msk] = blk[1 + v][..., msk]
                    b2[1 + v][..., msk] = blk[0][..., msk]
                out[xx, dr] = b2
        return out

    for essai in range(3):
        psi0 = np.zeros(dacc, complex); psi0[0] = 1
        stc = np.zeros((dacc, NL), complex); stc[:, 0] = psi0
        stp = np.outer(psi0, sN).astype(complex)
        delta = 0.0
        sh = (N, 2, N + 1, 2)
        for j in range(QH):
            Uacc = haar(dacc)
            stc = Uacc @ stc
            stp = Uacc @ stp
            stc = requete_c(stc.reshape(sh + (NL,))).reshape(dacc, NL)
            stp = requete_p(stp.reshape(sh + (NF,))).reshape(dacc, NF)
            dj = np.linalg.norm(stc - stp @ Vt.T)
            borne = 60 * (j + 1) / math.sqrt(N - j) + (j + 1) * (j + 2) / (2 * (N - 2 * (j + 1) + 1))
            rc = stc @ stc.conj().T
            rp = stp @ stp.conj().T
            avantage = 0.5 * np.sum(np.abs(np.linalg.eigvalsh(rc - rp)))
            verdict(f"argument hybride, algorithme aleatoire {essai}, q = {j + 1} : delta = {dj:.4f} <= (31) {borne:.2f} ; "
                    f"avantage {avantage:.4f} <= 2 delta", dj <= borne and avantage <= 2 * dj + 1e-9,
                    f"normes {np.linalg.norm(stc):.6f} {np.linalg.norm(stp):.6f} ; hypothese 3q - 1 <= N : "
                    f"{'oui' if 3 * (j + 1) - 1 <= N else 'non'}", compte=3 * (j + 1) - 1 <= N)

print(f"  duree {time.time() - T0:.0f} s")
print("TOUT PASSE" if ok else "ECHEC")
sys.exit(0 if ok else 1)
