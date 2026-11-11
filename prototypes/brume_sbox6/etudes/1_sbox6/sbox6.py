#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prototype : S-box 4 bits à uniformité boomerang 6 (cible optimale pour DU = 4).

S-box retenue : SBOX6 = RECTANGLE(x) XOR 6.
La translation de sortie est une transformation affine : elle conserve la DDT,
la LAT, le degré algébrique et l'immunité algébrique, et permute seulement les
indices de la BCT. Elle retire le point fixe x = 12 de la S-box RECTANGLE.

Le script vérifie exhaustivement :
  - bijectivité, absence de point fixe ;
  - DDT max = 4, max |LAT| = 8 (NL = 4) ;
  - BCT max = 6 (cible), distribution complète ;
  - degré algébrique = 3 pour les quatre composantes ;
  - immunité algébrique >= 2 (calcul exact, annulateurs de degré <= 1).
Sortie : 0 si tous les contrôles passent, 1 sinon.

Référence : C. Boura, A. Canteaut, « On the Boomerang Uniformity of
Cryptographic Sboxes », IACR ToSC 2018(3) : pour une permutation 4 bits de
DU 4, l'uniformité boomerang minimale est 6.
"""
from collections import Counter

# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

SBOX6 = [15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1]
SBOX6_INV = [8, 15, 1, 7, 9, 11, 10, 5, 13, 14, 12, 4, 2, 3, 6, 0]

# S-box actuelle de BRUME, pour comparaison.
SBOX_BRUME = [8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5]


# ---------------------------------------------------------------------------
# Propriétés
# ---------------------------------------------------------------------------

def _parity(x):
    return bin(x).count("1") & 1


def ddt(s):
    """Table de différences : DDT[a][b] = #{x : S(x) ^ S(x^a) = b}."""
    return [[sum(1 for x in range(16) if s[x] ^ s[x ^ a] == b)
             for b in range(16)] for a in range(16)]


def lat(s):
    """Table linéaire : LAT[a][b] = somme_x (-1)^(a.x ^ b.S(x))."""
    return [[sum(1 if _parity(a & x) == _parity(b & s[x]) else -1
                 for x in range(16))
             for b in range(16)] for a in range(16)]


def bct(s):
    """Table de connectivité boomerang, définition standard."""
    si = [0] * 16
    for x, y in enumerate(s):
        si[y] = x
    return [[sum(1 for x in range(16)
                 if si[s[x] ^ b] ^ si[s[x ^ a] ^ b] == a)
             for b in range(16)] for a in range(16)]


def anf_degree(truth):
    """Degré algébrique d'une fonction booléenne de 4 variables (Möbius)."""
    a = list(truth)
    for i in range(4):
        for x in range(16):
            if x & (1 << i):
                a[x] ^= a[x ^ (1 << i)]
    return max((bin(x).count("1") for x in range(16) if a[x]), default=0)


_DEGREES = [anf_degree([(g >> x) & 1 for x in range(16)])
            for g in range(1 << 16)]


def algebraic_immunity_component(truth):
    """AI exacte d'une composante : degré minimal d'un annulateur non nul de f
    ou de 1+f. Une fonction g est un annulateur de f si f(x) = 1 => g(x) = 0."""
    best = 4
    for target in (truth, [1 - v for v in truth]):
        support = [x for x in range(16) if target[x]]
        for g in range(1, 1 << 16):
            if _DEGREES[g] >= best:
                continue
            if all(((g >> x) & 1) == 0 for x in support):
                best = _DEGREES[g]
                if best == 0:
                    return 0
    return best


def properties(s):
    """Calcule toutes les propriétés utiles et renvoie un dictionnaire."""
    assert sorted(s) == list(range(16)), "la table n'est pas une permutation"
    si = [0] * 16
    for x, y in enumerate(s):
        si[y] = x
    assert all(s[si[x]] == x and si[s[x]] == x for x in range(16)), \
        "table inverse incohérente"

    d = ddt(s)
    l = lat(s)
    b = bct(s)

    ddt_max = max(d[a][bb] for a in range(1, 16) for bb in range(16))
    lat_max = max(abs(l[a][bb]) for a in range(16) for bb in range(16)
                  if a or bb)
    nl = 8 - lat_max // 2
    bct_max = max(b[a][bb] for a in range(1, 16) for bb in range(1, 16))
    bct_vals = [b[a][bb] for a in range(1, 16) for bb in range(1, 16)]
    bct_hist = Counter(bct_vals)

    bits = [[(s[x] >> k) & 1 for x in range(16)] for k in range(4)]
    degrees = [anf_degree(f) for f in bits]
    ai = [algebraic_immunity_component(f) for f in bits]
    fixed = [x for x in range(16) if s[x] == x]

    n_ddt_max = sum(1 for a in range(1, 16) for bb in range(16)
                    if d[a][bb] == ddt_max)
    n_lat_max = sum(1 for a in range(16) for bb in range(16)
                    if (a or bb) and abs(l[a][bb]) == lat_max)

    return {
        "ddt": d,
        "lat": l,
        "bct": b,
        "ddt_max": ddt_max,
        "lat_max": lat_max,
        "nl": nl,
        "bct_max": bct_max,
        "bct_hist": bct_hist,
        "bct_mean": sum(bct_vals) / len(bct_vals),
        "bct_argmax": [(a, bb) for a in range(1, 16) for bb in range(1, 16)
                       if b[a][bb] == bct_max],
        "degrees": degrees,
        "ai": ai,
        "fixed": fixed,
        "n_ddt_max": n_ddt_max,
        "n_lat_max": n_lat_max,
    }


def _fmt_hist(hist):
    return ", ".join(f"{v}:{hist[v]}" for v in sorted(hist))


def main():
    p6 = properties(SBOX6)
    pb = properties(SBOX_BRUME)

    print("S-box prototype : RECTANGLE(x) XOR 6")
    print(f"  S     = {SBOX6}")
    print(f"  S^-1  = {SBOX6_INV}")
    print()
    print(f"{'Propriété':28s} {'BRUME':>10s} {'SBOX6':>10s}")
    print("-" * 50)
    print(f"{'uniformité différentielle':28s} {pb['ddt_max']:>10d} {p6['ddt_max']:>10d}")
    print(f"{'max |LAT|':28s} {pb['lat_max']:>10d} {p6['lat_max']:>10d}")
    print(f"{'non-linéarité NL':28s} {pb['nl']:>10d} {p6['nl']:>10d}")
    print(f"{'uniformité boomerang':28s} {pb['bct_max']:>10d} {p6['bct_max']:>10d}")
    print(f"{'degré algébrique':28s} {str(pb['degrees']):>10s} {str(p6['degrees']):>10s}")
    print(f"{'immunité algébrique':28s} {str(pb['ai']):>10s} {str(p6['ai']):>10s}")
    print(f"{'points fixes':28s} {str(pb['fixed']):>10s} {str(p6['fixed']):>10s}")
    print(f"{'entrées DDT max':28s} {pb['n_ddt_max']:>10d} {p6['n_ddt_max']:>10d}")
    print(f"{'entrées |LAT| max':28s} {pb['n_lat_max']:>10d} {p6['n_lat_max']:>10d}")
    print(f"{'moyenne BCT':28s} {pb['bct_mean']:>10.2f} {p6['bct_mean']:>10.2f}")
    print()
    print(f"BCT SBOX6 (225 coefficients non triviaux) : {_fmt_hist(p6['bct_hist'])}")
    print(f"BCT SBOX6 max = {p6['bct_max']} atteint {len(p6['bct_argmax'])} fois, "
          f"par exemple {p6['bct_argmax'][:6]}")
    print()

    checks = [
        ("permutation", sorted(SBOX6) == list(range(16))),
        ("pas de point fixe", not p6["fixed"]),
        ("DDT max = 4", p6["ddt_max"] == 4),
        ("max |LAT| = 8 (NL = 4)", p6["lat_max"] == 8),
        ("BCT max = 6", p6["bct_max"] == 6),
        ("degré = 3 partout", p6["degrees"] == [3, 3, 3, 3]),
        ("AI >= 2 partout", all(v >= 2 for v in p6["ai"])),
        ("inverse cohérente", all(SBOX6[SBOX6_INV[x]] == x
                                  and SBOX6_INV[SBOX6[x]] == x
                                  for x in range(16))),
    ]
    for name, ok in checks:
        print(f"  {'OK' if ok else 'ÉCHEC':5s}  {name}")
    return 0 if all(ok for _, ok in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
