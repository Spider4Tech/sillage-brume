#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Famille 1 : validation exacte CP-SAT sur petits nombres de tours."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from . import common as C
from . import trail_search as T

SORTIE = Path(__file__).resolve().parents[4] / "resultats" / "etude_v3_vs_brume_reference_20261109"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, nargs="+", default=[2, 3, 4])
    ap.add_argument("--time-limit", type=float, default=120.0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", type=Path,
                    default=SORTIE / "02_cpsat_petits_tours.json")
    args = ap.parse_args()
    out = {"method": ("CP-SAT mot-niveau, DDT exacte, diffusion GF(16) bit "
                      "à bit ; objectif = coût total en demi-bits"),
           "time_limit_s": args.time_limit,
           "results": {}}
    for name, sbox in (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3)):
        for r in args.rounds:
            t0 = time.time()
            res = T.exact_cpsat(sbox, r, time_limit=args.time_limit,
                                workers=args.workers)
            res["candidate"] = name
            res["rounds"] = r
            if "trail" in res:
                tr = res["trail"]
                res["trail"] = {
                    "total_cost_half_bits": tr.total_cost_half_bits,
                    "total_cost_bits": tr.total_cost_bits,
                    "valid": res.get("trail_valid"),
                    "input_difference_hex": C.state_to_hex(
                        __import__("numpy").asarray(tr.round_inputs[0], dtype="uint8")),
                }
            res["elapsed_s"] = time.time() - t0
            out["results"][f"{name}_R{r}"] = res
            print(name, r, res.get("status"), res.get("objective"),
                  res.get("best_bound"), f"{res['elapsed_s']:.0f}s", flush=True)
            args.out.write_text(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
