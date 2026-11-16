#!/usr/bin/env python3
"""End-to-end classical check of SPONGE_QROM.md at sizes where the bound is not trivial.

A classical adversary is a special case of a quantum one. Classically, with lazy sampling of the
permutation, the probability that the database enters a property B within q queries is at most
sum_{t<q} s_t / (N - t): each new answer is uniform among N - t values and at most s_t of them are bad.
So Lemma A is checked as a whole: an adversary that grows the tree and asks final edges is simulated,
the property is evaluated from its definition (module eponge_domaines), and the measured frequency is
compared with that sum. Also: the same adversary against a sponge with one domain only, to see what the
domains cost in reality, and the frequency of the new event I2 alone.
Exit code 0 if every check passes.
"""
import math, random, sys
import eponge_domaines as m

def partie(rng, q, doms, r, c):
    h, im = {}, set()
    def reponse():
        while True:
            y = rng.randrange(1 << (r + c))
            if y not in im: im.add(y); return y
    h[m.IV] = reponse()
    rs = [m.IVC, m.cap(h[m.IV])]
    while len(h) < q:
        u = rng.choice(rs)
        final = len(doms) > 1 and rng.random() < 0.3
        x = (rng.randrange(1 << r) << c) | (u ^ (rng.choice(doms[1:]) if final else 0))
        if x in h: continue
        h[x] = reponse()
        if not final and m.cap(h[x]) not in rs: rs.append(m.cap(h[x]))
    return h

def mesure(rng, n, q, doms, r, c, d):
    m.R, m.C, m.DG = r, c, d
    m.B = r + c; m.N = 1 << m.B
    col = seul_i2 = 0
    for _ in range(n):
        h = partie(rng, q, doms, r, c)
        col += m.b_col(h, doms)
        reach = m.reach(h)
        seul_i2 += (not m.i1(h, reach)) and m.i2(reach, doms)
    k, kpm = len(doms), len({a ^ b for a in doms for b in doms})
    borne = sum((t * 2 ** (r + c - d) + (kpm * (t + 1) + k * t) * 2 ** r) / (2 ** (r + c) - t) for t in range(q))
    return col / n, seul_i2 / n, borne

def main():
    rng = random.Random(20261116)
    ok = True
    def verdict(nom, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print(f"  [{'ok' if cond else 'ECHEC'}] {nom}{' : ' + detail if detail else ''}")
    r, c, d, n = 12, 14, 12, 20000
    doms4 = (0, 0x2000, 0x2400, 0x2800)                  # |D + D| = 7, as 8, 9, 10
    print(f"r = {r}, c = {c}, d = {d}, {n} parties par ligne")
    res = {}
    for q in (8, 16, 24, 32):
        f4, i2, b4 = mesure(rng, n, q, doms4, r, c, d)
        f1, _, b1 = mesure(rng, n, q, (0,), r, c, d)
        res[q] = (f4, i2, b4, f1, b1)
        s4 = 4 * math.sqrt(max(f4, 1 / n) / n); s1 = 4 * math.sqrt(max(f1, 1 / n) / n)
        print(f"    q = {q:2d} : quatre domaines {f4:.4f} (I2 seul {i2:.4f}) <= borne {b4:.4f} ; "
              f"un domaine {f1:.4f} <= borne [CM] {b1:.4f}")
        verdict(f"q = {q} : frequence mesuree <= somme des s_t/(N-t)", f4 <= b4 + s4 and f1 <= b1 + s1,
                f"rapports {f4 / b4:.2f} et {f1 / b1:.2f}")
    f4, i2, b4, f1, b1 = res[32]
    verdict("la borne n'est pas vide : la frequence mesuree depasse 0,3 fois la borne", f4 > 0.3 * b4 and f1 > 0.3 * b1)
    verdict("l'evenement I2 se produit et les domaines coutent en realite", i2 > 0.02 and f4 > 1.3 * f1,
            f"q = 32 : {f4 / f1:.2f} fois plus souvent qu'avec un seul domaine ; rapport des bornes {b4 / b1:.2f}")
    print("TOUT PASSE" if ok else "ECHEC")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
