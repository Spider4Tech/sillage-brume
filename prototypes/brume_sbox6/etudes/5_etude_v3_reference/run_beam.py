#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Campagne de faisceau différentiel (top 100) pour BRUME et V3.

Écrit un JSON par candidate et par horizon dans le dossier de résultats.
"""
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
    ap.add_argument("--rounds", type=int, nargs="+", default=[8, 10, 12, 14])
    ap.add_argument("--beam-width", type=int, default=600)
    ap.add_argument("--local-width", type=int, default=1500)
    ap.add_argument("--topk", type=int, default=100)
    ap.add_argument("--outdir", type=Path, default=SORTIE)
    args = ap.parse_args()
    args.outdir.mkdir(parents=True, exist_ok=True)
    (args.outdir / "logs").mkdir(exist_ok=True)
    for name, sbox in (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3)):
        for r in args.rounds:
            t0 = time.time()
            trails = T.beam_trails_topk(sbox, r, k=args.topk,
                                        beam_width=args.beam_width,
                                        local_width=args.local_width)
            payload = {
                "candidate": name,
                "kind": "diff",
                "rounds": r,
                "beam_width": args.beam_width,
                "local_width": args.local_width,
                "best_half_bits": trails[0].total_cost_half_bits,
                "best_bits": trails[0].total_cost_bits,
                "costs_half_bits": [x.total_cost_half_bits for x in trails],
                "fd_bound": T.certified_wide_trail_bound(sbox, r, "diff"),
                "trails": [x.to_dict() for x in trails],
            }
            path = args.outdir / f"trails_diff_{name}_R{r}.json"
            path.write_text(json.dumps(payload, ensure_ascii=False))
            print(f"{name} R={r}: {trails[0].total_cost_bits:.1f} bits "
                  f"({time.time() - t0:.0f}s) -> {path}", flush=True)


if __name__ == "__main__":
    main()
