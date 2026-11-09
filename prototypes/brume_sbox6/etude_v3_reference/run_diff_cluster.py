#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Famille 2 : effet différentiel / regroupement de trails.

Pour chaque horizon R ∈ {6,8,10,12,14}, on agrège les 100 meilleures
caractéristiques différentielles par couple (α, β).  La somme de leurs
probabilités est une borne INFÉRIEURE de la probabilité différentielle
DP_R(α,β) ; l'écart au meilleur trail mesure le regroupement détecté.

À 2 tours, la valeur exacte est calculée par énumération (hull_2r.py) et
comparée à une mesure Monte-Carlo sur la permutation réelle.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from . import common as C
from . import trail_search as T

SORTIE = Path(__file__).resolve().parents[3] / "resultats" / "etude_v3_vs_brume_reference_20261109"


def load_or_build(name, sbox, r, topk=100, force=False):
    path = SORTIE / f"trails_diff_{name}_R{r}.json"
    if path.exists() and not force:
        return json.loads(path.read_text())
    trails = T.beam_trails_topk(sbox, r, k=topk, beam_width=400,
                                local_width=1200)
    payload = {
        "candidate": name, "kind": "diff", "rounds": r,
        "beam_width": 400, "local_width": 1200,
        "best_half_bits": trails[0].total_cost_half_bits,
        "best_bits": trails[0].total_cost_bits,
        "costs_half_bits": [x.total_cost_half_bits for x in trails],
        "fd_bound": T.certified_wide_trail_bound(sbox, r, "diff"),
        "trails": [x.to_dict() for x in trails],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False))
    return payload


def _log2_sum_neg(bits):
    """log2(sum 2^-b), robuste au sous-flux IEEE."""
    bits = list(bits)
    if not bits:
        return float("-inf")
    m = min(bits)
    return -m + math.log2(sum(2.0 ** (-(b - m)) for b in bits))


def aggregate(payload):
    rows = []
    for t in payload["trails"]:
        alpha = t["input_difference_hex"]
        beta = "".join(format(int(v), "x")
                       for v in t["rounds_detail"][-1]["after_diffusion"])
        rows.append({"alpha": alpha, "beta": beta,
                     "bits": t["total_cost_bits"]})
    rows.sort(key=lambda z: z["bits"])
    mass_log2 = _log2_sum_neg([z["bits"] for z in rows])
    groups = {}
    for z in rows:
        g = groups.setdefault((z["alpha"], z["beta"]),
                              {"n": 0, "bits": [], "best_bits": z["bits"]})
        g["n"] += 1
        g["bits"].append(z["bits"])
        g["best_bits"] = min(g["best_bits"], z["bits"])
    glist = []
    for (a, b), g in groups.items():
        glist.append({"alpha_hex": a, "beta_hex": b, "n_trails": g["n"],
                      "best_bits": g["best_bits"],
                      "dp_lower_bound_log2": _log2_sum_neg(g["bits"])})
    glist.sort(key=lambda z: -z["dp_lower_bound_log2"])
    multi = [g for g in glist if g["n_trails"] > 1]
    return {
        "rounds": payload["rounds"],
        "best_bits": rows[0]["bits"],
        "best_log2": -rows[0]["bits"],
        "top100_mass_log2": mass_log2,
        "gain_over_best_trail_bits": mass_log2 + rows[0]["bits"],
        "n_groups": len(glist),
        "n_multi_trail_groups": len(multi),
        "max_group": glist[0] if glist else None,
        "groups": glist,
        "fd_bound": payload.get("fd_bound"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, nargs="+", default=[6, 8, 10, 12, 14])
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    out = {"method": ("somme des probabilités des 100 meilleures pistes, "
                      "regroupées par (α,β) ; borne inférieure de DP_R"),
           "candidates": {}}
    for name, sbox in (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3)):
        out["candidates"][name] = {}
        for r in args.rounds:
            payload = load_or_build(name, sbox, r, force=args.force)
            agg = aggregate(payload)
            out["candidates"][name][f"R{r}"] = agg
            print(f"{name} R={r}: best {agg['best_bits']:.1f} bits, "
                  f"top100 mass 2^-{ -agg['top100_mass_log2']:.2f}, "
                  f"gain {agg['gain_over_best_trail_bits']:.3f} bits, "
                  f"groupes multiples {agg['n_multi_trail_groups']}", flush=True)
    (SORTIE / "04_effet_differentiel_clustering.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
