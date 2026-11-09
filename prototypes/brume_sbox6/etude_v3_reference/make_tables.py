#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Famille 0/1 : tables locales exactes et bornes structurelles."""
from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np

from . import common as C

SORTIE = Path(__file__).resolve().parents[3] / "resultats" / "etude_v3_vs_brume_reference_20261109"


def anf_coefficients(sbox):
    """Coefficients d'ANF des 4 coordonnées booléennes de la S-box."""
    out = np.zeros((4, 16), dtype=np.uint8)
    for bit in range(4):
        vals = np.array([(int(sbox[x]) >> bit) & 1 for x in range(16)], dtype=np.uint8)
        f = vals.copy()
        # transformée de Möbius sur {0,1}^4
        for i in range(4):
            for x in range(16):
                if (x >> i) & 1:
                    f[x] ^= f[x ^ (1 << i)]
        out[bit] = f
    return out


def algebraic_degree(sbox):
    anf = anf_coefficients(sbox)
    deg = 0
    for bit in range(4):
        for x in range(16):
            if anf[bit, x]:
                deg = max(deg, int(x).bit_count())
    return deg, anf


def park_bounds(sbox, beta=8):
    d = C.ddt(sbox) / 16.0
    l = (C.lat(sbox) / 8.0)
    lp = l * l
    medp = max((d[u] ** beta).sum() for u in range(1, 16))
    melp = max((lp[u] ** beta).sum() for u in range(1, 16))
    return {"MEDP_2_log2": math.log2(medp), "MELP_2_log2": math.log2(melp),
            "beta": beta}


def profile(sbox):
    d = C.ddt(sbox)
    l = C.lat(sbox)
    rows = []
    for a in range(1, 16):
        vals = d[a]
        mx = int(vals.max())
        rows.append({
            "a": a, "max": mx,
            "argmax": [int(b) for b in np.nonzero(vals == mx)[0]],
            "support_size": int((vals > 0).sum()),
            "counts": {str(k): int((vals == k).sum()) for k in range(1, 17) if (vals == k).any()},
        })
    lrows = []
    for u in range(1, 16):
        vals = np.abs(l[u])
        mx = int(vals.max())
        lrows.append({
            "u": u, "max": mx,
            "argmax": [int(v) for v in np.nonzero(vals == mx)[0]],
            "support_size": int((vals > 0).sum()),
            "counts": {str(k): int((vals == k).sum()) for k in range(1, 9) if (vals == k).any()},
        })
    return rows, lrows


def matrix_weight_stats(mat):
    nz = mat != 0
    return {
        "row_weights": sorted(set(int(x) for x in nz.sum(axis=1))),
        "col_weights": sorted(set(int(x) for x in nz.sum(axis=0))),
        "total_nonzero": int(nz.sum()),
        "density": float(nz.mean()),
    }


def run():
    SORTIE.mkdir(parents=True, exist_ok=True)
    our = {}
    for name, sbox in (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3)):
        d = C.ddt(sbox)
        l = C.lat(sbox)
        bc = C.bct(sbox)
        deg, anf = algebraic_degree(sbox)
        dprof, lprof = profile(sbox)
        our[name] = {
            "sbox": list(map(int, sbox)),
            "inverse": C.inverse(sbox),
            "ddt": d.tolist(),
            "lat": l.tolist(),
            "bct": bc.tolist(),
            "ddt_max": int(d[1:].max()),
            "ddt_max_count": int((d[1:] == d[1:].max()).sum()),
            "lat_max": int(np.abs(l[1:]).max()),
            "lat_max_count": int((np.abs(l[1:]) == np.abs(l[1:]).max()).sum()),
            "bct_max": int(bc[1:, 1:].max()),
            "bct_max_count": int((bc[1:, 1:] == bc[1:, 1:].max()).sum()),
            "differential_uniformity": int(d[1:].max()),
            "linearity": int(np.abs(l[1:]).max()),
            "algebraic_degree": deg,
            "anf": anf.tolist(),
            "fixed_points": [int(x) for x in range(16) if int(sbox[x]) == x],
            "differential_profile": dprof,
            "linear_profile": lprof,
            "min_diff_cost_half_bits": C.minimum_diff_cost_per_active(sbox),
            "min_lin_cost_half_bits": C.minimum_lin_cost_per_active(sbox),
            "park": park_bounds(sbox),
        }
    # matrices de diffusion
    minv = C.B._gauss_gf16_inverse(C.M.astype(np.uint8))
    diff = {
        "M": matrix_weight_stats(C.M),
        "M_inv": matrix_weight_stats(minv),
        "M_T_gf16": matrix_weight_stats(C.M.T),
        "branch_number_M": 8,
        "branch_number_note": ("branch number 8 certifié par énumération des "
                               "supports (tests/test_branch_exact.py)"),
        "n_nibbles": C.N,
        "n_bits": C.NB,
        "round_constants_hex": [C.state_to_hex(r) for r in C.RC],
    }
    out = {"candidates": our, "diffusion": diff,
           "conventions": {
               "diff_cost_half_bits": "-2 log2(DDT/16) ; 4 si DDT=4, 6 si DDT=2",
               "lin_cost_half_bits": "-2 log2(|LAT|/8) ; 2 si |LAT|=4, 4 si |LAT|=2",
               "lat_index": "LAT[u,v] = somme_x (-1)^{u·S(x) + v·x}, u=sortie, v=entrée",
               "linear_propagation": "adjoint binaire M^T_bin, pas la transposée GF(16)",
           }}
    (SORTIE / "01_tables_locales.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1))
    return out


if __name__ == "__main__":
    out = run()
    for name in ("BRUME", "V3"):
        c = out["candidates"][name]
        print(name, "DDTmax", c["ddt_max"], "LATmax", c["lat_max"],
              "BCTmax", c["bct_max"], "deg", c["algebraic_degree"],
              "Park", c["park"])
