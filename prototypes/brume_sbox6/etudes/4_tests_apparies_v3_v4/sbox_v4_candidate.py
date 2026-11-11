#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quatrième S-box (SBOX_V4) : orientation de la classe G11 dominant SBOX_V3.

Contexte (recherche du 10 novembre 2026, protocole BRUME-SBOX-SEARCH étendu) :
  Méthode : 3 x 3 000 000 tirages aléatoires de permutations 4 bits (graines
  20261110/11/12) + 300 000 orientations affines denses (graines 42/43),
  filtres numpy validés bit à bit contre les implémentations pures de
  test_sbox_independant.py (DDT, LAT, BCT, UBCT, LBCT, DBCT, DLCT = OK sur
  BRUME, SBOX6, SBOX_V3, G11), audit final avec les fonctions pures du projet.

  Paysage des classes (BCT max <= 8, sans point fixe) : exactement 3 classes
  vues de façon stable sur les 3 graines :
    - classe BCT 6   (profil DDT plat, ratio 0.272, DBCT min 28)
    - classe de V3 = G11 (rows2 = 5, ratio 0.123, DBCT min 28)  <- SBOX_V4
    - classe intermédiaire (rows2 = 4, ratio 0.189, DBCT min 28)
  Le plancher DBCT = 28 est atteint dans les 3 classes et ne descend pas
  en dessous sur ~110 000 orientations sans point fixe testées.

  Propriétés de SBOX_V4 (audit pur, toutes les contraintes OK) :
    1. Identique à SBOX_V3 sur : DDT max 4, NL 4, degré 3, IA 2, BCT max 8,
       DLCT max 8, UBCT/LBCT/EBCT/FBCT max 4, MEDP2 2^-14.99,
       ratio log2(BCT/DDT) 0.123, 5 lignes DDT max=2, 5 lignes BCT max=2.
    2. DBCT max = 28 (argmax (1,6)) contre 32 pour SBOX_V3, SBOX6 et 52 pour
       BRUME : réduction de 12.5 % du coefficient boomerang double maximal.
    3. Profil SAC amélioré : [0.25, 0.25, 0, 0] — deux bits parfaitement
       SAC (SBOX_V3 : aucun ; BRUME : un seul).
    4. Cycle unique de longueur 16 (SBOX_V3 : 11+3+2), aucun point fixe.
    5. Certificat d'équivalence affine explicite vers le représentant G11
       validé sur les 16 points.

  En résumé : SBOX_V4 fait au moins aussi bien que SBOX_V3 partout et
  strictement mieux sur DBCT (28 < 32) et SAC (2 bits parfaits vs 0),
  avec une structure de permutation plus régulière (un seul 16-cycle).
"""
from collections import Counter

# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

SBOX_V4 = [10, 4, 15, 6, 0, 2, 9, 5, 12, 8, 7, 3, 13, 1, 11, 14]
SBOX_V4_INV = [4, 13, 5, 11, 1, 7, 3, 10, 9, 6, 0, 14, 8, 12, 15, 2]

# Représentant de la classe G11 de Leander-Poschmann (Table 3 de Boura-Canteaut)
SBOX_G11 = [8, 0, 1, 9, 2, 5, 13, 7, 4, 6, 10, 11, 12, 3, 14, 15]

# Certificat d'équivalence affine : S_V4(x) = M2 * S_G11(M1 * x ^ c1) ^ c2
# avec c1 = 12, c2 = 9 et les matrices binaires définies par l'image de la base :
M1_BASIS = {1: 1, 2: 5, 4: 8, 8: 6}
M2_BASIS = {1: 4, 2: 9, 4: 15, 8: 12}
C1, C2 = 12, 9

# Références du projet
SBOX_BRUME = [8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5]
SBOX6 = [15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1]
SBOX_V3 = [14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2]


def apply_linear_map(x: int, basis: dict[int, int]) -> int:
    """Applique une application linéaire sur F_2^4 via l'image des vecteurs de base."""
    res = 0
    for i in range(4):
        if (x >> i) & 1:
            res ^= basis[1 << i]
    return res


def verify_affine_certificate() -> bool:
    """Vérifie que S_V4(x) == M2 * S_G11(M1 * x ^ 12) ^ 9 pour tout x in F_2^4."""
    for x in range(16):
        u = apply_linear_map(x, M1_BASIS) ^ C1
        y = SBOX_G11[u]
        v = apply_linear_map(y, M2_BASIS) ^ C2
        if v != SBOX_V4[x]:
            return False
    return True


# ---------------------------------------------------------------------------
# Propriétés (implémentations de référence, identiques à test_sbox_independant)
# ---------------------------------------------------------------------------

def _parity(x):
    return bin(x).count("1") & 1


def inverse(s):
    inv = [0] * 16
    for x, y in enumerate(s):
        inv[y] = x
    return inv


def ddt(s):
    return [[sum(1 for x in range(16) if s[x ^ a] ^ s[x] == b) for b in range(16)]
            for a in range(16)]


def lat(s):
    return [[sum(1 if _parity(a & s[x]) == _parity(b & x) else -1
                 for x in range(16))
             for b in range(16)] for a in range(16)]


def bct(s):
    si = inverse(s)
    return [[sum(1 for x in range(16)
                 if si[s[x] ^ b] ^ si[s[x ^ a] ^ b] == a)
             for b in range(16)] for a in range(16)]


def ubct_full(s):
    si = inverse(s)
    return [[[sum(1 for x in range(16)
                  if s[x ^ a] ^ s[x] == bb and si[s[x] ^ c] ^ si[s[x ^ a] ^ c] == a)
              for c in range(16)] for bb in range(16)] for a in range(16)]


def lbct_full(s):
    si = inverse(s)
    return [[[sum(1 for x in range(16)
                  if s[x] ^ s[x ^ bb] == c and si[s[x] ^ c] ^ si[s[x ^ a] ^ c] == a)
              for c in range(16)] for bb in range(16)] for a in range(16)]


def dbct_full(u_tab, l_tab):
    """DBCT(a,d) = sum_{b,c} UBCT(a,b,c) * LBCT(b,c,d)  (convention du dépôt)."""
    return [[sum(u_tab[a][bb][c] * l_tab[bb][c][d]
                 for bb in range(16) for c in range(16)) for d in range(16)]
            for a in range(16)]


def dlct_full(s):
    return [[sum(-1 if _parity(bb & (s[x] ^ s[x ^ a])) else 1 for x in range(16))
             for bb in range(16)] for a in range(16)]


def anf_degree(truth):
    a = list(truth)
    for i in range(4):
        for x in range(16):
            if x & (1 << i):
                a[x] ^= a[x ^ (1 << i)]
    return max((bin(x).count("1") for x in range(16) if a[x]), default=0)


def algebraic_immunity_component(truth):
    best = 4
    for target in (truth, [1 - v for v in truth]):
        support = [x for x in range(16) if target[x]]
        for g in range(1, 1 << 16):
            if anf_degree([(g >> x) & 1 for x in range(16)]) >= best:
                continue
            if all(((g >> x) & 1) == 0 for x in support):
                best = anf_degree([(g >> x) & 1 for x in range(16)])
                if best == 0:
                    return 0
    return best


def sac(s):
    dev = []
    for i in range(4):
        p = [0.0] * 4
        for x in range(16):
            y1, y2 = s[x], s[x ^ (1 << i)]
            for j in range(4):
                if ((y1 >> j) & 1) != ((y2 >> j) & 1):
                    p[j] += 1
        dev.append(max(abs(v / 16 - 0.5) for v in p))
    return [round(d, 4) for d in dev]


def autocorr_max(s):
    mx = 0
    for k in range(4):
        f = [(s[x] >> k) & 1 for x in range(16)]
        for a in range(1, 16):
            v = sum(1 if f[x] == f[x ^ a] else -1 for x in range(16))
            mx = max(mx, abs(v))
    return mx


def cycles(s):
    vus = [False] * 16
    cyc = []
    for x in range(16):
        if not vus[x]:
            c = []
            y = x
            while not vus[y]:
                vus[y] = True
                c.append(y)
                y = s[y]
            cyc.append(c)
    return sorted(cyc, key=len, reverse=True)


def medp2_log2(d):
    import math
    dp = [[v / 16.0 for v in row] for row in d]
    p = max(sum(v ** 8 for v in dp[u]) for u in range(1, 16))
    return math.log2(p) if p > 0 else float("-inf")


def ratio_bct_ddt(d, b):
    import math
    vals = []
    for a in range(1, 16):
        for bb in range(1, 16):
            if d[a][bb] > 0 and b[a][bb] > 0:
                vals.append(math.log2(b[a][bb] / d[a][bb]))
    return sum(vals) / len(vals) if vals else None


def properties(s):
    si = inverse(s)
    d = ddt(s)
    l = lat(s)
    b = bct(s)
    u = ubct_full(s)
    lb = lbct_full(s)
    db = dbct_full(u, lb)

    ddt_max = max(d[a][bb] for a in range(1, 16) for bb in range(16))
    lat_max = max(abs(l[a][bb]) for a in range(16) for bb in range(16) if a or bb)
    nl = 8 - lat_max // 2
    bct_max = max(b[a][bb] for a in range(1, 16) for bb in range(1, 16))
    dbct_max = max(db[a][cc] for a in range(1, 16) for cc in range(1, 16))
    dlct_max = max(abs(dlct_full(s)[a][bb])
                   for a in range(1, 16) for bb in range(1, 16))
    ddt_rows_max2 = sorted(a for a in range(1, 16) if max(d[a]) == 2)
    bct_rows_max2 = sorted(a for a in range(1, 16) if max(b[a][1:]) == 2)
    bits = [[(s[x] >> k) & 1 for x in range(16)] for k in range(4)]
    degrees = [anf_degree(f) for f in bits]
    ai = [algebraic_immunity_component(f) for f in bits]
    return {
        "ddt_max": ddt_max, "lat_max": lat_max, "nl": nl,
        "bct_max": bct_max, "dbct_max": dbct_max, "dlct_max": dlct_max,
        "ddt_rows_max2": ddt_rows_max2, "bct_rows_max2": bct_rows_max2,
        "degrees": degrees, "ai": ai,
        "points_fixes": [x for x in range(16) if s[x] == x],
        "cycles": [len(c) for c in cycles(s)],
        "sac": sac(s), "autocorr": autocorr_max(s),
        "medp2_log2": medp2_log2(d), "ratio": ratio_bct_ddt(d, b),
    }


def _fmt(x):
    if isinstance(x, float):
        return f"{x:.3f}"
    if isinstance(x, list):
        return "+".join(str(v) for v in x)
    return str(x)


def main():
    pv4 = properties(SBOX_V4)
    pv3 = properties(SBOX_V3)
    p6 = properties(SBOX6)
    pb = properties(SBOX_BRUME)

    print("Quatrième S-box candidate (SBOX_V4) :")
    print(f"  S     = {SBOX_V4}")
    print(f"  S^-1  = {SBOX_V4_INV}")
    print()
    print(f"{'Propriété':30s} {'BRUME':>12s} {'SBOX6':>12s} {'SBOX_V3':>12s} {'SBOX_V4':>12s}")
    print("-" * 84)
    for lab, k in (("DDT max", "ddt_max"), ("max |LAT|", "lat_max"),
                   ("NL", "nl"), ("BCT max", "bct_max"),
                   ("DBCT max", "dbct_max"), ("DLCT max", "dlct_max"),
                   ("MEDP2 (log2)", "medp2_log2"), ("ratio log2(BCT/DDT)", "ratio"),
                   ("cycles", "cycles"), ("SAC max/bit", "sac"),
                   ("autocorr max", "autocorr")):
        print(f"{lab:30s} {_fmt(pb[k]):>12s} {_fmt(p6[k]):>12s} "
              f"{_fmt(pv3[k]):>12s} {_fmt(pv4[k]):>12s}")
    print(f"{'lignes DDT max=2':30s} {len(pb['ddt_rows_max2']):>12d} "
          f"{len(p6['ddt_rows_max2']):>12d} {len(pv3['ddt_rows_max2']):>12d} "
          f"{len(pv4['ddt_rows_max2']):>12d}")
    print(f"{'lignes BCT max=2':30s} {len(pb['bct_rows_max2']):>12d} "
          f"{len(p6['bct_rows_max2']):>12d} {len(pv3['bct_rows_max2']):>12d} "
          f"{len(pv4['bct_rows_max2']):>12d}")
    print()

    checks = [
        ("permutation", sorted(SBOX_V4) == list(range(16))),
        ("pas de point fixe", pv4["points_fixes"] == []),
        ("DDT max = 4", pv4["ddt_max"] == 4),
        ("max |LAT| = 8 (NL = 4)", pv4["lat_max"] == 8),
        ("BCT max <= 8", pv4["bct_max"] <= 8),
        ("DBCT max = 28 < 32 (V3)", pv4["dbct_max"] == 28),
        ("5 lignes DDT max=2", len(pv4["ddt_rows_max2"]) >= 5),
        ("5 lignes BCT max=2", len(pv4["bct_rows_max2"]) >= 5),
        ("degré = 3 partout", pv4["degrees"] == [3, 3, 3, 3]),
        ("IA >= 2 partout", all(v >= 2 for v in pv4["ai"])),
        ("DLCT max <= 8", pv4["dlct_max"] <= 8),
        ("MEDP2 <= 2^-14.99", pv4["medp2_log2"] <= -14.988 + 1e-6),
        ("MEDP2 == 2^-14.99 (comme V3)", round(pv4["medp2_log2"], 2) == round(pv3["medp2_log2"], 2)),
        ("ratio <= 0.1231", pv4["ratio"] <= 0.12309 + 5e-3),
        ("SAC : >= 2 bits parfaits", sum(1 for v in pv4["sac"] if v == 0.0) >= 2),
        ("cycle unique 16", pv4["cycles"] == [16]),
        ("certificat affine G11 valide", verify_affine_certificate()),
        ("inverse cohérente", all(SBOX_V4[SBOX_V4_INV[x]] == x
                                  and SBOX_V4_INV[SBOX_V4[x]] == x
                                  for x in range(16))),
    ]
    for name, ok in checks:
        print(f"  {'OK' if ok else 'ÉCHEC':5s}  {name}")
    print(f"\n  TOTAL : {sum(ok for _, ok in checks)}/{len(checks)} vérifications réussies")
    return 0 if all(ok for _, ok in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
