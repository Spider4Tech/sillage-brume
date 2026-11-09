#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Famille 5 : propriété intégrale / division property.

1. Table de division property BIT-À-BIT exacte de la S-box, calculée par
   transformée de Möbius de tous les monômes de S(x).
2. Modèle CP-SAT de propagation : tables S-box exactes + contraintes de
   parité de la couche linéaire (adjoint binaire).  On cherche un vecteur
   de division property de sortie avec le plus de bits à 1.
3. Intégrales empiriques vérifiées : somme XOR sur 2^t valeurs d'un
   sous-espace de t bits, pour t = 4, 8, 12, 16 et R = 1..4.  Les bits
   dont la somme est nulle sur plusieurs bases aléatoires sont des
   distingueurs intégraux vérifiés.
4. Degré algébrique exact de la S-box (et de son inverse).
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np

from . import common as C

SORTIE = Path(__file__).resolve().parents[3] / "resultats" / "etude_v3_vs_brume_reference_20261109"


# ---------------------------------------------------------------------------
# Division property bit-à-bit de la S-box
# ---------------------------------------------------------------------------

def _mobius(vals):
    f = np.asarray(vals, dtype=np.uint8).copy()
    for i in range(4):
        for x in range(16):
            if (x >> i) & 1:
                f[x] ^= f[x ^ (1 << i)]
    return f


def div_table(sbox):
    """``table[k]`` = masques de sortie l possibles pour le masque d'entrée k."""
    s = np.asarray(sbox, dtype=np.uint8)
    table = {}
    for k in range(16):
        allowed = []
        for l in range(16):
            vals = np.ones(16, dtype=np.uint8)
            for bit in range(4):
                if (l >> bit) & 1:
                    vals &= (s >> bit) & 1
            anf = _mobius(vals)
            ok = False
            for u in range(16):
                if anf[u] and (u & ~k) == 0:
                    ok = True
                    break
            if ok:
                allowed.append(l)
        table[k] = allowed
    return table


def algebraic_degree_sbox(sbox):
    s = np.asarray(sbox, dtype=np.uint8)
    deg = 0
    per_bit = []
    for bit in range(4):
        vals = (s >> bit) & 1
        anf = _mobius(vals)
        d = max((int(u).bit_count() for u in range(16) if anf[u]), default=0)
        per_bit.append(d)
        deg = max(deg, d)
    return deg, per_bit


# ---------------------------------------------------------------------------
# Propagation CP-SAT
# ---------------------------------------------------------------------------

def division_sat(sbox, active_nibbles, rounds, time_limit=30.0,
                 workers=8, maximize=True):
    try:
        from ortools.sat.python import cp_model
    except Exception as exc:  # pragma: no cover
        return {"status": "unavailable", "error": str(exc)}
    table = div_table(sbox)
    rows = [(k >> q) & 1 for q in range(4)] if False else None
    tuples = []
    for k, ls in table.items():
        kb = [(k >> q) & 1 for q in range(4)]
        for l in ls:
            lb = [(l >> q) & 1 for q in range(4)]
            tuples.append(kb + lb)
    # matrice binaire de la diffusion L (sortie j dépend de l'entrée i)
    Lrows = [[] for _ in range(4 * C.N)]
    for i in range(C.N):
        for k in range(4):
            st = np.zeros(C.N, dtype=np.uint8)
            st[i] = 1 << k
            out = C.diffuse(st)
            bit_index = 4 * i + k
            for j in range(C.N):
                for b in range(4):
                    if (int(out[j]) >> b) & 1:
                        Lrows[bit_index].append(4 * j + b)
    m = cp_model.CpModel()
    # variables de division property par tour : k_r (entrée S-box)
    K = []
    for r in range(rounds):
        kr = [m.NewBoolVar(f"k{r}_{i}") for i in range(4 * C.N)]
        K.append(kr)
    # couche S-box
    Ls = []
    for r in range(rounds):
        lr = [m.NewBoolVar(f"l{r}_{i}") for i in range(4 * C.N)]
        Ls.append(lr)
        for i in range(C.N):
            m.AddAllowedAssignments(
                K[r][4 * i:4 * i + 4] + lr[4 * i:4 * i + 4], tuples)
    # couche linéaire : entre l_r et K[r+1], puis l_{R-1} et la sortie O
    O = [m.NewBoolVar(f"o_{i}") for i in range(4 * C.N)]
    for r in range(rounds):
        nxt = K[r + 1] if r + 1 < rounds else O
        for i in range(4 * C.N):
            terms = [nxt[j] for j in Lrows[i]]
            p = m.NewBoolVar(f"p{r}_{i}")
            if terms:
                m.AddBoolXOr(terms + [p.Not()])
            else:
                m.Add(p == 0)
            m.Add(p <= Ls[r][i])
    # entrée : active_nibbles premiers nibbles complètement actifs
    for i in range(4 * C.N):
        nib = i // 4
        m.Add(K[0][i] == (1 if nib < active_nibbles else 0))
    if maximize:
        m.Maximize(sum(O))
    out = {"rounds": rounds, "active_nibbles": active_nibbles,
           "model_vars": len(m.Proto().variables)}
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = float(time_limit)
    solver.parameters.num_workers = workers
    status = solver.Solve(m)
    out["status"] = solver.StatusName(status)
    out["wall_time"] = solver.WallTime()
    if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        vals = [1 if solver.Value(v) else 0 for v in O]
        out["balanced_bits"] = int(sum(vals))
        out["balanced_positions"] = [i for i, v in enumerate(vals) if v]
        out["objective"] = solver.ObjectiveValue()
        out["best_bound"] = solver.BestObjectiveBound()
    return out


# ---------------------------------------------------------------------------
# Intégrale empirique
# ---------------------------------------------------------------------------

def integral_empirical(sbox, t_bits, rounds, bases=3, seed=0):
    rng = np.random.default_rng(seed)
    n = 1 << t_bits
    idx = np.arange(n, dtype=np.uint32)
    active_nib = t_bits // 4
    per_base = []
    for _ in range(bases):
        base = rng.integers(0, 16, size=C.N, dtype=np.uint8)
        states = np.tile(base, (n, 1))
        for b in range(t_bits):
            pos, bit = b // 4, b % 4
            vals = ((idx >> b) & 1).astype(np.uint8)
            states[:, pos] = (states[:, pos] & np.uint8(~(1 << bit) & 0xF)) | (vals << bit)
        y = C.permutation_batch(states, sbox, rounds)
        xor_sum = np.bitwise_xor.reduce(y, axis=0)
        balanced = set()
        for i in range(C.N):
            for b in range(4):
                if ((int(xor_sum[i]) >> b) & 1) == 0:
                    balanced.add(4 * i + b)
        per_base.append(balanced)
    robust = set.intersection(*per_base) if per_base else set()
    union = set.union(*per_base) if per_base else set()
    return {
        "t_bits": t_bits, "active_nibbles": active_nib,
        "rounds": rounds, "bases": bases,
        "balanced_counts": [len(s) for s in per_base],
        "robust_balanced_count": len(robust),
        "union_balanced_count": len(union),
        "robust_balanced_bits": sorted(robust),
        "union_balanced_bits": sorted(union),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds-emp", type=int, nargs="+", default=[1, 2, 3, 4])
    ap.add_argument("--t-bits", type=int, nargs="+", default=[4, 8, 12, 16])
    ap.add_argument("--sat-t-bits", type=int, nargs="+", default=[4, 8])
    ap.add_argument("--bases", type=int, default=3)
    ap.add_argument("--sat-rounds", type=int, nargs="+", default=[1, 2])
    ap.add_argument("--sat-time", type=float, default=20.0)
    args = ap.parse_args()
    out = {"method": ("table de division property bit-à-bit exacte ; modèle "
                      "CP-SAT S-box + parité de diffusion ; intégrales "
                      "empiriques XOR sur 2^t valeurs"),
           "candidates": {}}
    for name, sbox in (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3)):
        tab = div_table(sbox)
        deg, per_bit = algebraic_degree_sbox(sbox)
        deg_inv, per_bit_inv = algebraic_degree_sbox(C.inverse(sbox))
        rec = {
            "div_table": {str(k): v for k, v in tab.items()},
            "algebraic_degree": deg,
            "algebraic_degree_per_output_bit": per_bit,
            "algebraic_degree_inverse": deg_inv,
            "algebraic_degree_inverse_per_output_bit": per_bit_inv,
            "sat": {},
            "empirical": {},
        }
        for t in args.sat_t_bits:
            for r in args.sat_rounds:
                key = f"t{t}_R{r}"
                rec["sat"][key] = division_sat(
                    sbox, t // 4, r, time_limit=args.sat_time, workers=8)
                print(name, "SAT", key, rec["sat"][key].get("status"),
                      rec["sat"][key].get("balanced_bits"),
                      rec["sat"][key].get("best_bound"), flush=True)
        for t in args.t_bits:
            for r in args.rounds_emp:
                key = f"t{t}_R{r}"
                rec["empirical"][key] = integral_empirical(
                    sbox, t, r, bases=args.bases)
                print(name, "EMP", key,
                      rec["empirical"][key]["robust_balanced_count"], flush=True)
        out["candidates"][name] = rec
    (SORTIE / "08_propriete_integrale_division.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
