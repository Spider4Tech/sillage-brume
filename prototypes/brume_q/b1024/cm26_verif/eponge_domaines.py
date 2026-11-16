#!/usr/bin/env python3
"""Reduced-model check of SPONGE_QROM.md (adaptation of Carolan-Majenz, arXiv 2609.28469, Lemma 5.4 and
Theorem 5.5, to the BRUME-1024q sponge: fixed first call P(IV), domain offsets XORed into the capacity of
the last call).

Everything is computed from the definitions of the document (reachable set, bad events, final edges),
not from the case analysis of its proof. Small widths: rate r, capacity c, digest d <= r bits.

Checks:
 1. counting: for databases h not in B, the exact number of extensions h[x->y] in B (forward, and
    inverse) never exceeds the bound of Lemma A;
 2. injectivity: in a database that is not bad, two distinct (blocks, domain) with a transcript in the
    database end on distinct final edges, and a collision among them puts the database in B_col;
 3. monotony: B_pre and B_col are increasing;
 4. witnesses: without the event I2 the injectivity fails (a database is exhibited), and with one
    domain only the bound of the article's shape is recovered;
 5. the two sums used for the constants.
Exit code 0 if every check passes.
"""
import math, random, sys

R, C, DG = 3, 8, 3                      # rate, capacity, digest bits
B = R + C
N = 1 << B
DOMS = (0, 0x80, 0x90, 0xA0)            # domain offsets in the capacity (dom*16 on the last byte)
DPM = sorted({a ^ b for a in DOMS for b in DOMS})          # D xor D
IVC = 0x05                              # capacity part of the IV (the frame); rate part is 0
IV = IVC                                # state = rate << C | capacity ; rate 0

def cap(s): return s & ((1 << C) - 1)
def rate(s): return s >> C
def dig(s): return rate(s) >> (R - DG)

def reach(h):
    """Reachable capacities from IVC in the graph x_C -> y_C."""
    out = {}
    for x, y in h.items():
        out.setdefault(cap(x), []).append(cap(y))
    seen, todo = {IVC}, [IVC]
    while todo:
        u = todo.pop()
        for v in out.get(u, ()):
            if v not in seen:
                seen.add(v); todo.append(v)
    return seen

def i1(h, rs):
    ends = set()
    for x, y in h.items():
        if cap(x) in rs:
            v = cap(y)
            if v == IVC or v in ends: return True
            ends.add(v)
    return False

def i2(rs, doms):
    nz = {a ^ b for a in doms for b in doms} - {0}
    return any((u ^ e) in rs for u in rs for e in nz)

def finals(h, rs, doms):
    return [(x, y) for x, y in h.items() if any((cap(x) ^ dl) in rs for dl in doms)]

def b_col(h, doms=DOMS):
    rs = reach(h)
    if i1(h, rs) or i2(rs, doms): return True
    ds = [dig(y) for _, y in finals(h, rs, doms)]
    return len(ds) != len(set(ds))

def b_pre(h, w, doms=DOMS):
    rs = reach(h)
    if i1(h, rs): return True
    return any(dig(y) == w for _, y in finals(h, rs, doms))

def borne_col(t, doms=DOMS):
    k, kpm = len(doms), len({a ^ b for a in doms for b in doms})
    return t * (1 << (B - DG)) + (kpm * (t + 1) + k * t) * (1 << R)

def borne_pre(t, doms=DOMS):
    k = len(doms)
    return (1 << (B - DG)) + max(k * t + t + 1, k * (t + 1)) * (1 << R)

def base_adverse(rng, t, doms):
    """A database built to load the counts: chains from the root, final edges, strays."""
    h, im = {}, set()
    def put(x, y):
        if x in h or y in im: return False
        h[x] = y; im.add(y); return True
    tries = 0
    while len(h) < t and tries < 50 * (t + 1):
        tries += 1
        rs = sorted(reach(h))
        m = rng.random()
        if m < 0.55:   xc = rng.choice(rs)
        elif m < 0.85: xc = rng.choice(rs) ^ rng.choice(doms)
        else:          xc = rng.randrange(1 << C)
        x = (rng.randrange(1 << R) << C) | xc
        if len(h) == 0 and rng.random() < 0.7: x = IV
        m = rng.random()
        if m < 0.25 and h: yc = cap(rng.choice(list(h))) ^ rng.choice(doms)
        else:              yc = rng.randrange(1 << C)
        put(x, (rng.randrange(1 << R) << C) | yc)
    return h

def transcripts(h, doms):
    """All (blocks, domain, final edge) whose sponge transcript lies in h. Blocks are the padded
    blocks; the padding is taken injective, as in the article."""
    res = []
    if IV not in h: return res
    stack = [((), h[IV], {IV})]
    while stack:
        blocks, s, used = stack.pop()
        for x, y in h.items():
            if cap(x) == cap(s) and x not in used:               # inner call
                stack.append((blocks + (rate(x) ^ rate(s),), y, used | {x}))
            for dl in doms:                                      # last call
                if cap(x) == cap(s) ^ dl:
                    res.append((blocks + (rate(x) ^ rate(s),), dl, (x, y)))
    return res

def main():
    rng = random.Random(20261116)
    ok = True
    def verdict(nom, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print(f"  [{'ok' if cond else 'ECHEC'}] {nom}{' : ' + detail if detail else ''}")

    print(f"modele reduit : r = {R}, c = {C}, d = {DG}, N = {N}, |D| = {len(DOMS)}, |D+D| = {len(DPM)}")

    # 1. counting
    pire_c = pire_p = 0.0; n_c = n_p = 0; viol = 0; non_triviaux = 0
    for essai in range(1500):
        t = rng.choice((0, 1, 1, 2, 2, 3, 3, 4, 5, 6))
        h = base_adverse(rng, t, DOMS)
        t = len(h)
        w = rng.randrange(1 << DG)
        im = set(h.values())
        libres_y = [y for y in range(N) if y not in im]
        libres_x = [x for x in range(N) if x not in h]
        rs = reach(h)
        if not b_col(h):
            bc = borne_col(t); non_triviaux += bc < N
            cands = [rng.choice(sorted(rs)), rng.choice(sorted(rs)) ^ rng.choice(DOMS), rng.randrange(1 << C)]
            for xc in cands:
                x = (rng.randrange(1 << R) << C) | xc
                if x in h: continue
                n = 0
                for y in libres_y:
                    h[x] = y; n += b_col(h); del h[x]
                n_c += 1; pire_c = max(pire_c, n / bc); viol += n > bc
            y = rng.choice(libres_y)
            n = 0
            for x in libres_x:
                h[x] = y; n += b_col(h); del h[x]
            n_c += 1; pire_c = max(pire_c, n / bc); viol += n > bc
        if not b_pre(h, w):
            bp = borne_pre(t)
            xc = rng.choice(sorted(rs)) ^ rng.choice(DOMS)
            x = (rng.randrange(1 << R) << C) | xc
            if x not in h:
                n = 0
                for y in libres_y:
                    h[x] = y; n += b_pre(h, w); del h[x]
                n_p += 1; pire_p = max(pire_p, n / bp); viol += n > bp
            y = rng.choice(libres_y)
            n = 0
            for x in libres_x:
                h[x] = y; n += b_pre(h, w); del h[x]
            n_p += 1; pire_p = max(pire_p, n / bp); viol += n > bp
    verdict("comptage (lemme A)", viol == 0,
            f"{n_c} cas collision (pire rapport {pire_c:.3f}), {n_p} cas preimage (pire {pire_p:.3f}), "
            f"{non_triviaux} bases ou la borne est < N")

    # 2. injectivity
    n_tr = n_col = echec = 0
    for essai in range(4000):
        h = base_adverse(rng, rng.randrange(2, 9), DOMS)
        rs = reach(h)
        if i1(h, rs) or i2(rs, DOMS): continue
        tr = transcripts(h, DOMS)
        vus = {}
        for blocks, dl, e in tr:
            n_tr += 1
            if e in vus and vus[e] != (blocks, dl): echec += 1
            vus[e] = (blocks, dl)
        ds = {}
        for blocks, dl, e in tr:
            if dig(e[1]) in ds and ds[dig(e[1])] != (blocks, dl):
                n_col += 1
                if not b_col(h): echec += 1
            ds[dig(e[1])] = (blocks, dl)
    verdict("injectivite et temoin de collision", echec == 0 and n_tr > 1000 and n_col > 50,
            f"{n_tr} transcriptions, {n_col} collisions, toutes dans B_col")

    # 3. monotony
    echec = n = 0
    for essai in range(3000):
        h = base_adverse(rng, rng.randrange(1, 8), DOMS)
        w = rng.randrange(1 << DG)
        g = dict(h)
        x, y = rng.randrange(N), rng.randrange(N)
        if x in g or y in set(g.values()): continue
        g[x] = y; n += 1
        if b_col(h) and not b_col(g): echec += 1
        if b_pre(h, w) and not b_pre(g, w): echec += 1
    verdict("proprietes croissantes", echec == 0, f"{n} extensions")

    # 4. witnesses
    # without I2: root -> u, root -> u' with u ^ u' = 0x80 ^ 0x90; one edge is final for both domains
    s0 = (1 << C) | 0x40
    h = {IV: s0,
         (0 << C) | 0x40: (2 << C) | 0x21,            # s0 xor block 1  ->  capacity 0x21
         (3 << C) | 0x40: (5 << C) | 0x31,            # s0 xor block 2  ->  capacity 0x31 = 0x21 ^ 0x10
         (7 << C) | 0xA1: (6 << C) | 0x77}            # 0xA1 = 0x21 ^ 0x80 = 0x31 ^ 0x90
    rs = reach(h)
    tr = [(b, dl) for b, dl, e in transcripts(h, DOMS) if e == ((7 << C) | 0xA1, (6 << C) | 0x77)]
    verdict("temoin : sans I2, une arete finale sert deux (message, domaine)",
            (not i1(h, rs)) and i2(rs, DOMS) and len(set(tr)) == 2, f"{sorted(set(tr))}")
    un = (0,)
    viol = 0; pire = 0.0
    for essai in range(300):
        h = base_adverse(rng, rng.randrange(0, 6), un)
        if b_col(h, un): continue
        t = len(h); bc = t * (1 << (B - DG)) + (2 * t + 1) * (1 << R)       # article, eq. (90)
        x = (rng.randrange(1 << R) << C) | rng.choice(sorted(reach(h)))
        if x in h: continue
        im = set(h.values()); n = 0
        for y in range(N):
            if y in im: continue
            h[x] = y; n += b_col(h, un); del h[x]
        viol += n > bc; pire = max(pire, n / bc)
    verdict("temoin : un seul domaine, borne (90) de l'article", viol == 0, f"pire rapport {pire:.3f}")
    verdict("formule generale = (90) pour D = {0}", borne_col(3, un) == 3 * (1 << (B - DG)) + 7 * (1 << R))

    # 5. sums
    s11 = s5 = 0.0; e = True
    for q in range(1, 200001):
        s11 += math.sqrt(11 * (q - 1) + 7); s5 += math.sqrt(5 * (q - 1) + 4)
        e &= s11 <= 2 * math.sqrt(2) * q ** 1.5 and s5 <= 2 * q ** 1.5
    verdict("sommes : sum sqrt(11t+7) <= 2 sqrt2 q^1.5 et sum sqrt(5t+4) <= 2 q^1.5 (q <= 200000)", e)

    # explicit numbers for BRUME-1024q
    r, c, d = 640, 384, 512
    def seuil(coefs):          # T with sum coef * T^e / 2^n = 1/2, by bisection on log2 T
        lo, hi = 0.0, 600.0
        for _ in range(200):
            m = (lo + hi) / 2
            p = sum(2.0 ** (math.log2(k) + e * m - n) for k, e, n in coefs)
            lo, hi = (m, hi) if p < 0.5 else (lo, m)
        return lo
    print(f"  seuils p = 1/2 (log2 T), r = {r}, c = {c}, d = {d} :")
    print(f"    collision, notre eponge   : {seuil([(64/3, 3, d), (384, 3, c), (23232, 2, r + c)]):.2f}")
    print(f"    collision, article (95)   : {seuil([(32, 3, d), (128, 3, c), (32768, 2, r + c)]):.2f}")
    print(f"    preimage, notre eponge    : {seuil([(48, 2, d), (192, 3, c), (23232, 2, r + c)]):.2f}")
    print(f"    preimage, article (94)    : {seuil([(64, 2, d), (128, 3, c), (32768, 2, r + c)]):.2f}")
    print("TOUT PASSE" if ok else "ECHEC")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
