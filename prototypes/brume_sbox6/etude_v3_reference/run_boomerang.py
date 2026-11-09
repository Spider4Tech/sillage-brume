#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Famille 4 : boomerang / rectangle.

Pour une caractéristique différentielle de R tours, on place le switch sur
une couche de S-box intermédiaire ``s`` :

  * partie haute : tours 0..s-1, probabilité p0 ;
  * switch : couche s, différence d'entrée β = round_inputs[s],
    différence de sortie γ = round_outputs[s] ;
    probabilité exacte = ∏ BCT[β_i, γ_i] / 16 ;
  * partie basse : tours s+1..R-1, probabilité p1 (la diffusion du tour s
    est linéaire et déterministe).

L'estimation caractéristique vaut p0 · switch · p1.  On rapporte aussi le
rapport switch / probabilité de la couche S-box du trail, qui mesure
l'interaction des S-box actives (renforcement ou pénalité).

Validation :
  * table BCT exacte et vérification Monte-Carlo du switch sur la couche ;
  * simulation de quartets complète (chiffrement + déchiffrement) aux
    petits nombres de tours, où la probabilité reste mesurable.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np

from . import common as C
from .run_diff_cluster import load_or_build

SORTIE = Path(__file__).resolve().parents[3] / "resultats" / "etude_v3_vs_brume_reference_20261109"


def ddt_prob(sbox, a, b):
    return int(C.ddt(sbox)[a, b]) / 16.0


def trail_prob_round(sbox, tr, r):
    p = 1.0
    for t in tr["rounds_detail"][r]["transitions"]:
        p *= ddt_prob(sbox, int(t["a"]), int(t["b"]))
    return p


def bct_switch(sbox, beta, gamma):
    bc = C.bct(sbox)
    sw = 1.0
    rows = []
    for i in range(C.N):
        a, b = int(beta[i]), int(gamma[i])
        if a == 0 and b == 0:
            continue
        k = int(bc[a, b])
        sw *= k / 16.0
        rows.append({"pos": i, "beta": a, "gamma": b, "bct": k,
                     "switch": k / 16.0})
    return sw, rows


def analyse_trail(sbox, tr, split):
    R = tr["rounds"]
    p0 = 1.0
    for r in range(split):
        p0 *= trail_prob_round(sbox, tr, r)
    p1 = 1.0
    for r in range(split + 1, R):
        p1 *= trail_prob_round(sbox, tr, r)
    beta = np.asarray(tr["rounds_detail"][split]["input"], dtype=np.uint8)
    gamma = np.asarray(tr["rounds_detail"][split]["sbox_output"], dtype=np.uint8)
    p_layer = trail_prob_round(sbox, tr, split)
    sw, rows = bct_switch(sbox, beta, gamma)
    est = p0 * p1 * sw
    return {
        "split_sbox_layer": split,
        "p0_log2": math.log2(p0) if p0 else None,
        "p1_log2": math.log2(p1) if p1 else None,
        "p_switch_layer_trail_log2": math.log2(p_layer) if p_layer else None,
        "switch_log2": math.log2(sw) if sw else None,
        "switch_over_trail_layer": (sw / p_layer) if p_layer else None,
        "estimate_log2": math.log2(est) if est else None,
        "estimate": est,
        "beta_hex": C.state_to_hex(beta),
        "gamma_hex": C.state_to_hex(gamma),
        "n_active_switch": len(rows),
        "active_switch": rows,
        "beta_support": C.nonzero(beta),
        "gamma_support": C.nonzero(gamma),
    }


def verify_switch_mc(sbox, beta, gamma, samples=1 << 16, seed=0):
    """Vérifie ∏ BCT/16 par échantillonnage des S-box actives."""
    bc = C.bct(sbox)
    si = C.inverse(sbox)
    s = np.asarray(sbox, dtype=np.uint8)
    rng = np.random.default_rng(seed)
    active = [i for i in range(C.N) if int(beta[i]) or int(gamma[i])]
    if not active:
        return {"samples": samples, "empirical": 1.0, "exact": 1.0}
    x = rng.integers(0, 16, size=(samples, len(active)), dtype=np.uint8)
    ok = np.ones(samples, dtype=bool)
    for col, i in enumerate(active):
        a, b = int(beta[i]), int(gamma[i])
        xx = x[:, col]
        lhs = np.asarray(si, dtype=np.uint8)[(np.asarray(s, dtype=np.uint8)[xx] ^ b) & 0xF]
        rhs = np.asarray(si, dtype=np.uint8)[(np.asarray(s, dtype=np.uint8)[xx ^ a] ^ b) & 0xF]
        ok &= ((lhs ^ rhs) == a)
    emp = float(ok.mean())
    exact = float(np.prod([int(bc[int(beta[i]), int(gamma[i])]) / 16.0
                           for i in active]))
    return {"samples": samples, "empirical": emp, "exact": exact,
            "standard_error": math.sqrt(max(emp * (1 - emp), 0) / samples)}


def quartet_sim(sbox, alpha, delta, rounds, samples=1 << 16, chunk=4096,
                seed=0):
    """Simulation complète du quartet boomerang sur ``rounds`` tours."""
    rng = np.random.default_rng(seed)
    hits = 0
    done = 0
    alpha = np.asarray(alpha, dtype=np.uint8)
    delta = np.asarray(delta, dtype=np.uint8)
    while done < samples:
        n = min(chunk, samples - done)
        P = rng.integers(0, 16, size=(n, C.N), dtype=np.uint8)
        Pp = P ^ alpha[None, :]
        Cc = C.permutation_batch(P, sbox, rounds)
        Ccp = C.permutation_batch(Pp, sbox, rounds)
        Cs = Cc ^ delta[None, :]
        Csp = Ccp ^ delta[None, :]
        Ps = C.permutation_inverse_batch(Cs, sbox, rounds, chunk=n)
        Psp = C.permutation_inverse_batch(Csp, sbox, rounds, chunk=n)
        hits += int(((Ps ^ Psp) == alpha[None, :]).all(axis=1).sum())
        done += n
    p = hits / samples
    return {"samples": samples, "hits": hits, "probability": p,
            "log2": math.log2(p) if p else None,
            "standard_error": math.sqrt(max(p * (1 - p), 0) / samples)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, nargs="+",
                    default=[2, 3, 4, 6, 8, 10, 12, 14])
    ap.add_argument("--quartet-rounds", type=int, nargs="+", default=[2])
    ap.add_argument("--samples", type=int, default=1 << 16)
    args = ap.parse_args()
    out = {"method": ("switch BCT exact sur une couche de S-box ; "
                      "estimation p0·switch·p1 ; quartets simulés"),
           "candidates": {}}
    for name, sbox in (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3)):
        out["candidates"][name] = {}
        for R in args.rounds:
            payload = load_or_build(name, sbox, R)
            best = None
            per_trail = []
            # On essaie TOUTES les positions de switch (0..R-1) et on garde
            # la meilleure estimation p0·switch·p1 pour chaque piste.
            for tr in payload["trails"][:100]:
                best_for_trail = None
                best_split = None
                for split in range(int(tr["rounds"])):
                    an = analyse_trail(sbox, tr, split)
                    if (best_for_trail is None or
                            (an["estimate"] or 0) > (best_for_trail["estimate"] or 0)):
                        best_for_trail = an
                        best_split = split
                if best_for_trail is None:
                    continue
                per_trail.append(best_for_trail)
                if best is None or (best_for_trail["estimate"] or 0) > (best["estimate"] or 0):
                    best = best_for_trail
            rec = {
                "split_sbox_layer": best["split_sbox_layer"] if best else None,
                "best": best,
                "n_trails_analysed": len(per_trail),
                "estimates_log2": [a["estimate_log2"] for a in per_trail],
            }
            if R in args.quartet_rounds:
                tr = payload["trails"][0]
                alpha = np.asarray(tr["rounds_detail"][0]["input"], dtype=np.uint8)
                delta = np.asarray(tr["rounds_detail"][-1]["after_diffusion"],
                                   dtype=np.uint8)
                rec["quartet"] = quartet_sim(sbox, alpha, delta, R,
                                             samples=args.samples)
                rec["quartet"]["alpha_hex"] = C.state_to_hex(alpha)
                rec["quartet"]["delta_hex"] = C.state_to_hex(delta)
                rec["quartet"]["full_trail_log2"] = -tr["total_cost_bits"]
                rec["quartet"]["switch_estimate_log2"] = (best["estimate_log2"]
                                                         if best else None)
            if best is not None:
                beta = np.asarray([int(c, 16) for c in best["beta_hex"]],
                                  dtype=np.uint8)
                gamma = np.asarray([int(c, 16) for c in best["gamma_hex"]],
                                   dtype=np.uint8)
                rec["switch_mc"] = verify_switch_mc(sbox, beta, gamma,
                                                    samples=min(1 << 16, args.samples))
            out["candidates"][name][f"R{R}"] = rec
            b = rec["best"]

            def _fmt(x):
                return "n/a" if x is None else f"{x:.2f}"

            if b is None:
                print(f"{name} R={R}: aucune piste exploitable", flush=True)
            else:
                print(f"{name} R={R}: switch 2^{_fmt(b['switch_log2'])} "
                      f"(ratio {_fmt(b['switch_over_trail_layer'])}), "
                      f"estimate 2^{_fmt(b['estimate_log2'])}", flush=True)
    (SORTIE / "07_boomerang_rectangle.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
