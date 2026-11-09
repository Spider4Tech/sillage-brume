#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Définition et vérification exacte des S-boxes BRUME, SBOX6 et SBOX_V3.

Ce module vérifie les propriétés locales des permutations 4 bits et le
certificat d'équivalence affine G11 de SBOX_V3. Il ne prétend pas démontrer
la sécurité multi-tours de BRUME-512.

Dépendance : bibliothèque standard Python uniquement.
"""
from __future__ import annotations

from collections import Counter
from typing import Sequence

# ---------------------------------------------------------------------------
# Tables de substitution
# ---------------------------------------------------------------------------

SBOX_V3 = [14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2]
SBOX_V3_INV = [10, 13, 15, 2, 9, 11, 3, 12, 7, 1, 6, 5, 8, 14, 0, 4]

# Représentant G11 utilisé dans le certificat affine.
SBOX_G11 = [8, 0, 1, 9, 2, 5, 13, 7, 4, 6, 10, 11, 12, 3, 14, 15]

# Certificat : S_V3(x) = M2(S_G11(M1(x) XOR 9)) XOR 5.
# Les dictionnaires donnent l'image des vecteurs de base 1, 2, 4 et 8.
M1_BASIS = {1: 3, 2: 9, 4: 13, 8: 2}
M2_BASIS = {1: 5, 2: 10, 4: 1, 8: 6}
AFFINE_C1 = 9
AFFINE_C2 = 5

SBOX_BRUME = [8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5]
SBOX_BRUME_INV = [6, 2, 13, 10, 5, 15, 7, 11, 0, 1, 3, 14, 4, 8, 12, 9]

SBOX6 = [15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1]
SBOX6_INV = [8, 15, 1, 7, 9, 11, 10, 5, 13, 14, 12, 4, 2, 3, 6, 0]


# ---------------------------------------------------------------------------
# Outils sur F_2^4
# ---------------------------------------------------------------------------

def _validate_sbox(sbox: Sequence[int], name: str = "S-box") -> None:
    if len(sbox) != 16:
        raise ValueError(f"{name}: 16 sorties sont requises")
    if any(not isinstance(v, int) or not 0 <= v < 16 for v in sbox):
        raise ValueError(f"{name}: chaque sortie doit être un entier de 0 à 15")
    if sorted(sbox) != list(range(16)):
        raise ValueError(f"{name}: la table n'est pas une permutation")


def inverse_table(sbox: Sequence[int]) -> list[int]:
    _validate_sbox(sbox)
    inv = [0] * 16
    for x, y in enumerate(sbox):
        inv[y] = x
    return inv


def apply_linear_map(x: int, basis: dict[int, int]) -> int:
    """Applique une application linéaire F_2^4 -> F_2^4 depuis sa base."""
    if not 0 <= x < 16:
        raise ValueError("x doit appartenir à F_2^4")
    if set(basis) != {1, 2, 4, 8}:
        raise ValueError("La base doit définir les images de 1, 2, 4 et 8")
    result = 0
    for bit in (1, 2, 4, 8):
        if x & bit:
            result ^= basis[bit]
    return result


def linear_map_is_invertible(basis: dict[int, int]) -> bool:
    """Une application linéaire sur F_2^4 est inversible ssi ses 16 images
    sont toutes distinctes.
    """
    try:
        images = [apply_linear_map(x, basis) for x in range(16)]
    except (KeyError, ValueError):
        return False
    return len(set(images)) == 16


def verify_affine_certificate() -> bool:
    """Vérifie le certificat affine G11 sur les 16 entrées, matrices incluses."""
    if not linear_map_is_invertible(M1_BASIS):
        return False
    if not linear_map_is_invertible(M2_BASIS):
        return False
    if sorted(SBOX_G11) != list(range(16)):
        return False
    for x in range(16):
        u = apply_linear_map(x, M1_BASIS) ^ AFFINE_C1
        y = SBOX_G11[u]
        v = apply_linear_map(y, M2_BASIS) ^ AFFINE_C2
        if v != SBOX_V3[x]:
            return False
    return True


# ---------------------------------------------------------------------------
# Tables cryptographiques locales
# ---------------------------------------------------------------------------

def _parity(x: int) -> int:
    return x.bit_count() & 1


def ddt(sbox: Sequence[int]) -> list[list[int]]:
    _validate_sbox(sbox)
    return [
        [sum(1 for x in range(16) if (sbox[x] ^ sbox[x ^ a]) == b)
         for b in range(16)]
        for a in range(16)
    ]


def lat(sbox: Sequence[int]) -> list[list[int]]:
    _validate_sbox(sbox)
    return [
        [sum(1 if _parity(a & sbox[x]) == _parity(b & x) else -1
             for x in range(16))
         for b in range(16)]
        for a in range(16)
    ]


def bct(sbox: Sequence[int]) -> list[list[int]]:
    _validate_sbox(sbox)
    inv = inverse_table(sbox)
    return [
        [sum(1 for x in range(16)
             if (inv[sbox[x] ^ b] ^ inv[sbox[x ^ a] ^ b]) == a)
         for b in range(16)]
        for a in range(16)
    ]


def anf_degree(truth: Sequence[int]) -> int:
    """Degré ANF exact d'une fonction booléenne donnée par sa table."""
    if len(truth) != 16 or any(v not in (0, 1) for v in truth):
        raise ValueError("La fonction doit avoir 16 valeurs booléennes")
    coeffs = list(truth)
    for bit in (1, 2, 4, 8):
        for x in range(16):
            if x & bit:
                coeffs[x] ^= coeffs[x ^ bit]
    return max((i.bit_count() for i, c in enumerate(coeffs) if c), default=0)


_ALL_BOOLEAN_DEGREES = [
    anf_degree([(g >> x) & 1 for x in range(16)])
    for g in range(1 << 16)
]


def algebraic_immunity_component(truth: Sequence[int]) -> int:
    """Immunité algébrique exacte d'une fonction booléenne de 4 variables.

    Recherche un annihilateur non nul de f ou de f+1. Les fonctions
    booléennes sont représentées ici par leurs 16 valeurs.
    """
    if len(truth) != 16 or any(v not in (0, 1) for v in truth):
        raise ValueError("La fonction doit avoir 16 valeurs booléennes")
    best = 4
    for target in (list(truth), [1 - v for v in truth]):
        support = [x for x, value in enumerate(target) if value]
        for g in range(1, 1 << 16):
            degree = _ALL_BOOLEAN_DEGREES[g]
            if degree >= best:
                continue
            if all(((g >> x) & 1) == 0 for x in support):
                best = degree
                if best == 0:
                    return 0
    return best


def component_function(sbox: Sequence[int], output_mask: int) -> list[int]:
    """Composante booléenne x -> <output_mask, S(x)> mod 2."""
    if not 1 <= output_mask < 16:
        raise ValueError("Le masque de sortie doit être non nul")
    return [_parity(output_mask & sbox[x]) for x in range(16)]


def properties(sbox: Sequence[int], name: str = "S-box") -> dict:
    """Calcule les critères locaux exacts pour une permutation 4 bits."""
    _validate_sbox(sbox, name)
    inv = inverse_table(sbox)
    d = ddt(sbox)
    l = lat(sbox)
    b = bct(sbox)

    ddt_max = max(d[a][bb] for a in range(1, 16) for bb in range(16))
    lat_max = max(abs(l[a][bb]) for a in range(16) for bb in range(16)
                  if a or bb)
    bct_values = [b[a][bb] for a in range(1, 16) for bb in range(1, 16)]
    bct_max = max(bct_values)

    component_degrees = {}
    component_ai = {}
    for mask in range(1, 16):
        truth = component_function(sbox, mask)
        component_degrees[str(mask)] = anf_degree(truth)
        component_ai[str(mask)] = algebraic_immunity_component(truth)

    ddt_row_max = {str(a): max(d[a]) for a in range(1, 16)}
    bct_row_max = {str(a): max(b[a][1:]) for a in range(1, 16)}
    fixed_points = [x for x in range(16) if sbox[x] == x]

    return {
        "name": name,
        "sbox": list(sbox),
        "inverse": inv,
        "ddt": d,
        "lat": l,
        "bct": b,
        "ddt_max": ddt_max,
        "lat_max_abs": lat_max,
        "nonlinearity": 8 - lat_max // 2,
        "bct_max": bct_max,
        "bct_histogram_nontrivial": dict(sorted(Counter(bct_values).items())),
        "bct_mean_nontrivial": sum(bct_values) / len(bct_values),
        "ddt_row_max": ddt_row_max,
        "bct_row_max": bct_row_max,
        "ddt_rows_max_2": [a for a in range(1, 16) if max(d[a]) == 2],
        "bct_rows_max_2": [a for a in range(1, 16) if max(b[a][1:]) == 2],
        "component_degrees_all_nonzero_masks": component_degrees,
        "component_ai_all_nonzero_masks": component_ai,
        "component_degree_histogram": dict(sorted(Counter(component_degrees.values()).items())),
        "component_ai_histogram": dict(sorted(Counter(component_ai.values()).items())),
        "fixed_points": fixed_points,
    }


def main() -> int:
    candidates = [
        ("BRUME", SBOX_BRUME, SBOX_BRUME_INV),
        ("SBOX6", SBOX6, SBOX6_INV),
        ("SBOX_V3", SBOX_V3, SBOX_V3_INV),
    ]
    props = {}
    failed = False

    print("Vérification locale des S-boxes 4 bits")
    print(f"Certificat affine G11 : {'OK' if verify_affine_certificate() else 'ÉCHEC'}")
    print()

    for name, sbox, declared_inverse in candidates:
        p = properties(sbox, name)
        props[name] = p
        inverse_ok = p["inverse"] == declared_inverse
        if not inverse_ok:
            failed = True

    rows = [
        ("DDT max", lambda p: str(p["ddt_max"])),
        ("max |LAT|", lambda p: str(p["lat_max_abs"])),
        ("non-linéarité", lambda p: str(p["nonlinearity"])),
        ("BCT max", lambda p: str(p["bct_max"])),
        ("lignes DDT max = 2", lambda p: str(len(p["ddt_rows_max_2"]))),
        ("lignes BCT max = 2", lambda p: str(len(p["bct_rows_max_2"]))),
        ("degré max des 15 composantes", lambda p: str(max(p["component_degrees_all_nonzero_masks"].values()))),
        ("AI min des 15 composantes", lambda p: str(min(p["component_ai_all_nonzero_masks"].values()))),
        ("points fixes", lambda p: str(p["fixed_points"])),
    ]
    print("\nComparaison")
    print(f"{'Critère':30s} {'BRUME':>10s} {'SBOX6':>10s} {'SBOX_V3':>10s}")
    print("-" * 64)
    for label, getter in rows:
        print(f"{label:30s} {getter(props['BRUME']):>10s} {getter(props['SBOX6']):>10s} {getter(props['SBOX_V3']):>10s}")

    print("\nHistogrammes BCT non triviaux")
    for name in ("BRUME", "SBOX6", "SBOX_V3"):
        print(f"  {name:8s}: {props[name]['bct_histogram_nontrivial']}")

    v3 = props["SBOX_V3"]
    checks = [
        ("table V3 bijective", sorted(SBOX_V3) == list(range(16))),
        ("inverse V3 déclarée cohérente", v3["inverse"] == SBOX_V3_INV),
        ("aucun point fixe V3", not v3["fixed_points"]),
        ("DU(V3) = 4", v3["ddt_max"] == 4),
        ("max |LAT(V3)| = 8", v3["lat_max_abs"] == 8),
        ("BCT max(V3) = 8", v3["bct_max"] == 8),
        ("5 lignes DDT de maximum 2", len(v3["ddt_rows_max_2"]) == 5),
        ("5 lignes BCT de maximum 2", len(v3["bct_rows_max_2"]) == 5),
        ("degré 3 pour les 15 composantes", set(v3["component_degrees_all_nonzero_masks"].values()) == {3}),
        ("AI 2 pour les 15 composantes", set(v3["component_ai_all_nonzero_masks"].values()) == {2}),
        ("certificat affine G11", verify_affine_certificate()),
        ("matrices M1 et M2 inversibles", linear_map_is_invertible(M1_BASIS) and linear_map_is_invertible(M2_BASIS)),
    ]
    print("\nContrôles SBOX_V3")
    for label, ok in checks:
        print(f"  {'OK' if ok else 'ÉCHEC':5s} {label}")
        failed |= not ok

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
