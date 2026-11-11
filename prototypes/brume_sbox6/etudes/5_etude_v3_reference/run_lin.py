#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Campagne de caractéristiques LINÉAIRES (top 100) pour BRUME et V3.

Deux moteurs sont fusionnés :

* le glouton arrière du dépôt, appliqué aux 1920 masques de sortie de
  poids 1 (``greedy_all_sources(..., kind='lin')``), puis reconstruit en
  ordre direct et vérifié avec ``verifier_trail_lin`` ;
* un faisceau direct (``beam_lin_trails_topk``), également vérifié.

Les coques sont regroupées par couple (masque d'entrée, masque de sortie) :
la somme signée des corrélations donne une borne inférieure de la
corrélation de coque ; la somme des carrés donne une borne inférieure de
la puissance linéaire.
"""
from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path

import numpy as np

from . import common as C
from . import trail_search as T

SORTIE = Path(__file__).resolve().parents[4] / "resultats" / "etude_v3_vs_brume_reference_20261109"


def _signature(tr: C.Trail):
    return (tuple(map(tuple, tr.round_inputs)), tuple(map(tuple, tr.round_outputs)))


def _trail_correlation(tr: C.Trail, sbox):
    l = C.lat(sbox)
    c = 1.0
    for r in range(tr.rounds):
        u = np.asarray(tr.round_inputs[r], dtype=np.uint8)
        v = np.asarray(tr.round_outputs[r], dtype=np.uint8)
        for i in np.nonzero(u)[0]:
            c *= int(l[int(v[i]), int(u[i])]) / 8.0
    return c


def campaign(name: str, sbox, rounds: int, topk: int = 100,
             beam_width: int = 0, local_width: int = 800):
    t0 = time.time()
    trails = []
    # 1) glouton arrière sur toutes les sources de poids 1
    back = T.greedy_all_sources(sbox, rounds, kind="lin", topk=max(topk * 4, 200))
    for bt in back:
        ft, final_mask = T.lin_trail_to_forward(bt, sbox)
        ok, msg = C.verifier_trail_lin(ft, sbox)
        if not ok:
            raise RuntimeError(f"piste arrière invalide: {msg}")
        ft.final_mask = C.state_to_list(final_mask)
        trails.append(ft)
    # 2) faisceau direct
    if beam_width:
        fw = T.beam_lin_trails_topk(sbox, rounds, k=topk,
                                    beam_width=beam_width,
                                    local_width=local_width)
        for ft in fw:
            ft.final_mask = C.state_to_list(T.lin_trail_final_mask(ft))
            trails.append(ft)
    # déduplication + tri
    trails.sort(key=lambda x: x.total_cost_half_bits)
    seen = set()
    uniq = []
    for tr in trails:
        sig = _signature(tr)
        if sig in seen:
            continue
        seen.add(sig)
        uniq.append(tr)
        if len(uniq) >= topk:
            break
    # coques par (u_in, u_out)
    groups = {}
    for tr in uniq:
        u_in = tuple(tr.round_inputs[0])
        u_out = tuple(tr.final_mask)
        key = (u_in, u_out)
        g = groups.setdefault(key, {"u_in": u_in, "u_out": u_out,
                                    "n_trails": 0, "correlation_signed": 0.0,
                                    "squared_sum": 0.0, "costs_bits": []})
        c = _trail_correlation(tr, sbox)
        g["n_trails"] += 1
        g["correlation_signed"] += c
        g["squared_sum"] += c * c
        g["costs_bits"].append(tr.total_cost_bits)
    group_rows = []
    for g in groups.values():
        group_rows.append({
            "u_in_hex": C.state_to_hex(np.asarray(g["u_in"], dtype=np.uint8)),
            "u_out_hex": C.state_to_hex(np.asarray(g["u_out"], dtype=np.uint8)),
            "n_trails": g["n_trails"],
            "best_cost_bits": min(g["costs_bits"]),
            "correlation_signed_sum": g["correlation_signed"],
            "correlation_abs_sum": abs(g["correlation_signed"]),
            "squared_sum": g["squared_sum"],
            "log2_abs_hull": (math.log2(abs(g["correlation_signed"]))
                              if g["correlation_signed"] else None),
        })
    group_rows.sort(key=lambda z: z["best_cost_bits"])
    payload = {
        "candidate": name,
        "kind": "lin",
        "rounds": rounds,
        "beam_width": beam_width,
        "local_width": local_width,
        "n_trails": len(uniq),
        "best_half_bits": uniq[0].total_cost_half_bits,
        "best_bits": uniq[0].total_cost_bits,
        "best_correlation_abs": abs(_trail_correlation(uniq[0], sbox)),
        "costs_half_bits": [x.total_cost_half_bits for x in uniq],
        "total_squared_correlation_topk": sum(
            _trail_correlation(x, sbox) ** 2 for x in uniq),
        "fd_bound": T.certified_wide_trail_bound(sbox, rounds, "lin"),
        "groups": group_rows,
        "trails": [x.to_dict() for x in uniq],
    }
    print(f"{name} R={rounds}: {uniq[0].total_cost_bits:.1f} bits "
          f"({time.time() - t0:.0f}s, {len(uniq)} pistes)", flush=True)
    return payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, nargs="+", default=[8, 10, 12, 14])
    ap.add_argument("--topk", type=int, default=100)
    ap.add_argument("--beam-width", type=int, default=200)
    ap.add_argument("--local-width", type=int, default=800)
    ap.add_argument("--outdir", type=Path, default=SORTIE)
    ap.add_argument("--no-beam", action="store_true")
    args = ap.parse_args()
    args.outdir.mkdir(parents=True, exist_ok=True)
    bwd = 0 if args.no_beam else args.beam_width
    for name, sbox in (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3)):
        for r in args.rounds:
            payload = campaign(name, sbox, r, topk=args.topk,
                               beam_width=bwd, local_width=args.local_width)
            path = args.outdir / f"trails_lin_{name}_R{r}.json"
            path.write_text(json.dumps(payload, ensure_ascii=False))


if __name__ == "__main__":
    main()
