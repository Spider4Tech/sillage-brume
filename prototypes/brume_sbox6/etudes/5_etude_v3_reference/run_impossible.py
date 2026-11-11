#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Famille 6 : différentielles impossibles et corrélations nulles.

Différentiel
------------
* R = 2 : vérification EXACTE pour un couple (α,β) donné en énumérant les
  sorties de S-box du premier tour (support de DDT[α_i]) et en testant la
  compatibilité avec b1 = M^{-1}β.  Aucun trail => différentielle
  impossible (probabilité exactement 0).
* Famille certifiée poids 1 → poids 1 : le support avant le tour 2 vaut
  exactement supp(M[:,i]) (7 nibbles) alors que le support requis par β
  est supp(M^{-1}β) (dense) ; il ne peut pas être contenu.  On vérifie un
  échantillon par énumération exhaustive.
* R ≥ 3 : modèle CP-SAT d'existence de trail avec α et β fixés ; UNSAT =
  preuve d'impossibilité, SAT = témoin, timeout = indéterminé.

Linéaire (corrélation nulle)
----------------------------
* R = 2 : critère de support exact.  Pour u0 de poids 1, les supports
  possibles de u1 = (M^T_bin)^{-1} v0 sont calculés pour les 15 valeurs
  v0 ; pour u2, v1 = M^T_bin u2 a un support de 7 nibbles.  Si ce support
  n'est inclus dans aucun support u1 possible, aucun trail => corrélation
  exactement nulle.
* Les annulations de coque (somme signée nulle) sont aussi recherchées
  par évaluation exacte.
"""
from __future__ import annotations

import argparse
import itertools
import json
import math
import random
from pathlib import Path

import numpy as np

from . import common as C
from . import trail_search as T
from . import hull_2r as H

SORTIE = Path(__file__).resolve().parents[4] / "resultats" / "etude_v3_vs_brume_reference_20261109"
MINV = C.B._gauss_gf16_inverse(C.M.astype(np.uint8))


def mul_gf16(mat, vec):
    out = np.zeros(C.N, dtype=np.uint8)
    for i in range(C.N):
        if vec[i]:
            out ^= C.B.GMUL[int(vec[i]), mat[:, i]]
    return out


def diff_2r_exists(sbox, alpha, beta, max_combos=1 << 20):
    """Existence exacte d'un trail à 2 tours pour (α,β)."""
    d = C.ddt(sbox)
    alpha = np.asarray(alpha, dtype=np.uint8)
    beta = np.asarray(beta, dtype=np.uint8)
    b1 = mul_gf16(MINV, beta)
    active = np.nonzero(alpha)[0]
    choices = []
    for i in active:
        a = int(alpha[i])
        row = [(b, int(d[a, b])) for b in range(1, 16) if d[a, b] > 0]
        if not row:
            return False, 0, None
        choices.append(row)
    count = 0
    witness = None
    for combo in itertools.product(*choices):
        b0 = np.zeros(C.N, dtype=np.uint8)
        for i, (bv, _) in zip(active, combo):
            b0[i] = bv
        u1 = C.diffuse(b0)
        # Vérification sur TOUTES les positions : DDT[0,b]=0 pour b≠0, donc
        # les supports de u1 et b1 doivent coïncider.
        ok = not np.any(d[u1, b1] == 0)
        if ok:
            count += 1
            if witness is None:
                witness = {"b0": b0, "u1": u1, "b1": b1}
        if count > max_combos:
            break
    return count > 0, count, witness


def support_after_inv_diffusion(support):
    """Sur-approximation du support de M^{-1} x pour x supporté sur support."""
    out = set()
    for i in support:
        out.update(int(j) for j in np.nonzero(MINV[:, i])[0])
    return out


def diff_trail_exists_cpsat(sbox, alpha, beta, rounds, time_limit=20.0,
                            workers=8, hint=None):
    """Existence d'un trail différentiel à ``rounds`` tours avec α,β fixés."""
    try:
        from ortools.sat.python import cp_model
    except Exception as exc:  # pragma: no cover
        return {"status": "unavailable", "error": str(exc)}
    d = C.ddt(sbox)
    rows = []
    for a in range(16):
        for b in range(16):
            k = int(d[a, b])
            if a == 0 and b == 0:
                c = 0
            elif k > 0:
                c = int(round(-2.0 * math.log2(k / 16.0)))
            else:
                continue
            rows.append(tuple([(a >> q) & 1 for q in range(4)] +
                              [(b >> q) & 1 for q in range(4)] + [c]))
    m = cp_model.CpModel()
    A, Bv = [], []
    for r in range(rounds):
        ar, br = [], []
        for i in range(C.N):
            a = [m.NewBoolVar(f"a{r}_{i}_{k}") for k in range(4)]
            b = [m.NewBoolVar(f"b{r}_{i}_{k}") for k in range(4)]
            c = m.NewIntVar(0, 8, f"c{r}_{i}")
            m.AddAllowedAssignments(a + b + [c], rows)
            ar.append(a); br.append(b)
        A.append(ar); Bv.append(br)
    for r in range(rounds - 1):
        for j in range(C.N):
            for k in range(4):
                terms = []
                for e in range(C.B.E_SEG[j], C.B.E_SEG[j + 1]):
                    i = int(C.B.E_I[e]); co = int(C.B.E_C[e])
                    for kp in range(4):
                        if (C.B.GMUL[co, 1 << kp] >> k) & 1:
                            terms.append(Bv[r][i][kp])
                if not terms:
                    m.Add(A[r + 1][j][k] == 0)
                else:
                    m.AddBoolXOr(terms + [A[r + 1][j][k].Not()])
    alpha = np.asarray(alpha, dtype=np.uint8)
    beta = np.asarray(beta, dtype=np.uint8)
    for i in range(C.N):
        for k in range(4):
            m.Add(A[0][i][k] == ((int(alpha[i]) >> k) & 1))
    # β = M · B[-1]
    one = m.NewBoolVar("one")
    m.Add(one == 1)
    for j in range(C.N):
        for k in range(4):
            terms = []
            for e in range(C.B.E_SEG[j], C.B.E_SEG[j + 1]):
                i = int(C.B.E_I[e]); co = int(C.B.E_C[e])
                for kp in range(4):
                    if (C.B.GMUL[co, 1 << kp] >> k) & 1:
                        terms.append(Bv[-1][i][kp])
            target = (int(beta[j]) >> k) & 1
            if not terms:
                m.Add(0 == target)
            elif target:
                m.AddBoolXOr(terms)
            else:
                m.AddBoolXOr(terms + [one])
    if hint is not None and hint.rounds == rounds:
        for r in range(rounds):
            arow = np.asarray(hint.round_inputs[r], dtype=np.uint8)
            brow = np.asarray(hint.round_outputs[r], dtype=np.uint8)
            for i in range(C.N):
                for k in range(4):
                    m.AddHint(A[r][i][k], int((int(arow[i]) >> k) & 1))
                    m.AddHint(Bv[r][i][k], int((int(brow[i]) >> k) & 1))
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = float(time_limit)
    solver.parameters.num_workers = workers
    st = solver.Solve(m)
    res = {"status": solver.StatusName(st), "wall_time": solver.WallTime(),
           "rounds": rounds}
    res["impossible"] = (st == cp_model.INFEASIBLE)
    res["exists"] = (st in (cp_model.FEASIBLE, cp_model.OPTIMAL))
    return res


def random_mask(rng, weight, max_val=15):
    st = np.zeros(C.N, dtype=np.uint8)
    pos = rng.choice(C.N, size=weight, replace=False)
    for p in pos:
        st[int(p)] = int(rng.integers(1, max_val + 1))
    return st


def zero_correlation_2r_support(sbox, max_examples=20):
    """Recherche exhaustive des corrélations nulles à 2 tours, poids 1.

    Pour chaque u0 de poids 1 et chaque u2 de poids 1, on teste si le
    support de v1 = M^T_bin u2 est inclus dans au moins un support
    u1 = (M^T_bin)^{-1} v0 possible.  Sinon : zéro exact.
    """
    l = C.lat(sbox)
    # supports u1 possibles par (pos,val) de u0
    support_u1 = {}
    for pos in range(C.N):
        for val in range(1, 16):
            u0 = np.zeros(C.N, dtype=np.uint8)
            u0[pos] = val
            sups = []
            for v0val in range(1, 16):
                v0 = np.zeros(C.N, dtype=np.uint8)
                v0[pos] = v0val
                if int(l[v0val, val]) == 0:
                    continue
                u1 = C.diffuse_T_inv(v0)
                sups.append(frozenset(C.nonzero(u1)))
            support_u1[(pos, val)] = sups
    zeros = []
    total = 0
    n_zero = 0
    for pos0 in range(C.N):
        for val0 in range(1, 16):
            sups = support_u1[(pos0, val0)]
            for pos2 in range(C.N):
                for val2 in range(1, 16):
                    total += 1
                    u2 = np.zeros(C.N, dtype=np.uint8)
                    u2[pos2] = val2
                    v1 = C.diffuse_T(u2)
                    sv1 = frozenset(C.nonzero(v1))
                    if any(sv1 <= s for s in sups):
                        continue
                    n_zero += 1
                    if len(zeros) < max_examples:
                        zeros.append({"u0_pos": pos0, "u0_val": val0,
                                      "u2_pos": pos2, "u2_val": val2,
                                      "v1_support": sorted(sv1),
                                      "n_u1_supports": len(sups)})
    return {"n_tested": total, "n_zero_certified": n_zero,
            "examples": zeros, "note": "support criterion (certified)"}


def zero_correlation_2r_exact_scan(sbox, sample=200, seed=0):
    """Évalue exactement la coque 2 tours sur un échantillon de poids 1-4."""
    rng = np.random.default_rng(seed)
    bc = C.bct(sbox)
    l = C.lat(sbox)
    rows = []
    for t in (1, 2, 3, 4):
        for _ in range(sample):
            u0 = random_mask(rng, t)
            u2 = random_mask(rng, t)
            c, n, details = H.hull_lin_2r(sbox, u0, u2, with_rc=True)
            if c == 0:
                rows.append({"weight": t, "u0_hex": C.state_to_hex(u0),
                             "u2_hex": C.state_to_hex(u2), "n_paths": n,
                             "hull_correlation": 0.0})
    return rows


def positive_r2_witnesses(name, sbox, max_trails=5):
    """Témoins explicites pour des paires (α,β) RÉALISABLES à 2 tours.

    On part des meilleures pistes R=2 de la campagne (si le fichier existe)
    et on vérifie : support DDT sur α, support DDT sur u1, u1 = M·b0,
    β = M·b1.  C'est la contrepartie constructive du certificat
    d'impossibilité.
    """
    path = SORTIE / f"trails_diff_{name}_R2.json"
    if not path.exists():
        return {"available": False}
    d = json.loads(path.read_text())
    ddt = C.ddt(sbox)
    M = C.M.astype(np.uint8)
    rows = []
    for tr in d["trails"][:max_trails]:
        alpha = np.asarray(tr["rounds_detail"][0]["input"], dtype=np.uint8)
        beta = np.asarray(tr["rounds_detail"][-1]["after_diffusion"],
                          dtype=np.uint8)
        exists, n, wit = diff_2r_exists(sbox, alpha, beta)
        rec = {"alpha_hex": C.state_to_hex(alpha),
               "beta_hex": C.state_to_hex(beta),
               "exists": bool(exists), "n_trails": int(n)}
        if exists and wit is not None:
            b0 = np.asarray(wit["b0"], dtype=np.uint8)
            u1 = np.asarray(wit["u1"], dtype=np.uint8)
            b1 = np.asarray(wit["b1"], dtype=np.uint8)
            ok_fwd = bool(np.array_equal(C.diffuse(b0), u1))
            ok_sb0 = bool(np.all(ddt[alpha, b0] > 0))
            ok_sb1 = bool(np.all(ddt[u1, b1] > 0))
            ok_beta = bool(np.array_equal(mul_gf16(M, b1), beta))
            rec.update({
                "b0_hex": C.state_to_hex(b0),
                "u1_hex": C.state_to_hex(u1),
                "b1_hex": C.state_to_hex(b1),
                "check_forward_u1_eq_M_b0": ok_fwd,
                "check_ddt_round1": ok_sb0,
                "check_ddt_round2": ok_sb1,
                "check_beta_eq_M_b1": ok_beta,
                "witness_valid": ok_fwd and ok_sb0 and ok_sb1 and ok_beta,
                "active_positions_round1": C.nonzero(alpha),
                "active_positions_round2": C.nonzero(u1),
            })
        rows.append(rec)
    return {"available": True, "trails": rows,
            "all_exist": all(r["exists"] for r in rows),
            "all_witness_valid": all(r.get("witness_valid", False) for r in rows)}


def verify_zero_examples(sbox, examples, k=5):
    """Vérifie explicitement la corrélation nulle de paires certifiées."""
    rows = []
    for ex in examples[:k]:
        u0 = np.zeros(C.N, dtype=np.uint8)
        u0[int(ex["u0_pos"])] = int(ex["u0_val"])
        u2 = np.zeros(C.N, dtype=np.uint8)
        u2[int(ex["u2_pos"])] = int(ex["u2_val"])
        corr, n_paths, _ = H.hull_lin_2r(sbox, u0, u2, with_rc=True)
        rows.append({
            "u0_pos": ex["u0_pos"], "u0_val": ex["u0_val"],
            "u2_pos": ex["u2_pos"], "u2_val": ex["u2_val"],
            "hull_correlation": corr, "n_paths": n_paths,
            "zero_confirmed": (corr == 0),
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=500)
    ap.add_argument("--cpsat-time", type=float, default=15.0)
    ap.add_argument("--out", type=Path,
                    default=SORTIE / "09_impossible_differentiel_zero_correlation.json")
    args = ap.parse_args()
    rng = np.random.default_rng(2026)
    out = {"method": ("R=2 : énumération exacte ; famille poids 1→1 "
                      "certifiée par support ; R≥3 : CP-SAT avec α,β fixés ; "
                      "zéro-corrélation linéaire par critère de support à 2 tours"),
           "candidates": {}}
    for name, sbox in (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3)):
        rec = {"diff_impossible": {}, "zero_correlation": {}}
        # Famille poids 1 -> poids 1, R=2 : certificat de support
        # support avant tour 2 pour alpha en position i
        fwd_support = {}
        for i in range(C.N):
            sup = frozenset(int(j) for j in np.nonzero(C.M[:, i])[0])
            fwd_support[i] = sup
        # support requis par beta en position j
        req_support = {}
        for j in range(C.N):
            for val in range(1, 16):
                beta = np.zeros(C.N, dtype=np.uint8)
                beta[j] = val
                b1 = mul_gf16(MINV, beta)
                req_support[(j, val)] = frozenset(C.nonzero(b1))
        impossible_count = 0
        total_pairs = 0
        examples = []
        for i in range(C.N):
            for j in range(C.N):
                for val in range(1, 16):
                    total_pairs += 1
                    req = req_support[(j, val)]
                    if not req <= fwd_support[i]:
                        impossible_count += 1
                        if len(examples) < 10:
                            examples.append({
                                "alpha_pos": i, "beta_pos": j, "beta_val": val,
                                "forward_support_size": len(fwd_support[i]),
                                "required_support_size": len(req),
                                "missing": sorted(req - fwd_support[i])[:10],
                            })
        # vérification exhaustive d'un échantillon
        verified = []
        for _ in range(min(args.samples, 200)):
            i = int(rng.integers(0, C.N)); j = int(rng.integers(0, C.N))
            val = int(rng.integers(1, 16))
            alpha = np.zeros(C.N, dtype=np.uint8); alpha[i] = int(rng.integers(1, 16))
            beta = np.zeros(C.N, dtype=np.uint8); beta[j] = val
            exists, n, wit = diff_2r_exists(sbox, alpha, beta)
            verified.append({"alpha_pos": i, "beta_pos": j,
                             "exists": bool(exists), "n_trails": int(n)})
        rec["diff_impossible"]["R2_weight1"] = {
            "total_pairs": total_pairs,
            "impossible_pairs_certified": impossible_count,
            "examples": examples,
            "sample_verified": verified,
            "sample_all_impossible": all(not v["exists"] for v in verified),
        }
        print(name, "R2 weight1 impossible", impossible_count, "/", total_pairs,
              "sample ok", rec["diff_impossible"]["R2_weight1"]["sample_all_impossible"],
              flush=True)
        # poids 1..4 échantillonnés, R=2 exact
        for t in (1, 2, 3, 4):
            res = []
            for _ in range(max(50, args.samples // 5)):
                alpha = random_mask(rng, t)
                beta = random_mask(rng, t)
                exists, n, wit = diff_2r_exists(sbox, alpha, beta)
                res.append({"alpha": C.state_to_hex(alpha),
                            "beta": C.state_to_hex(beta),
                            "exists": bool(exists), "n_trails": int(n)})
            rec["diff_impossible"][f"R2_weight{t}_sampled"] = {
                "sampled": len(res),
                "impossible": sum(1 for z in res if not z["exists"]),
                "examples_impossible": [z for z in res if not z["exists"]][:5],
                "examples_possible": [z for z in res if z["exists"]][:3],
            }
        # R=3/4 : CP-SAT sur quelques couples
        for R in (3, 4):
            res = []
            for _ in range(6):
                alpha = random_mask(rng, int(rng.integers(1, 3)))
                beta = random_mask(rng, int(rng.integers(1, 3)))
                cp = diff_trail_exists_cpsat(sbox, alpha, beta, R,
                                             time_limit=args.cpsat_time)
                cp["alpha"] = C.state_to_hex(alpha)
                cp["beta"] = C.state_to_hex(beta)
                res.append(cp)
            rec["diff_impossible"][f"R{R}_cpsat_sample"] = res
        # zéro-corrélation linéaire à 2 tours
        rec["zero_correlation"]["R2_support_weight1"] = zero_correlation_2r_support(sbox)
        rec["zero_correlation"]["R2_exact_sample"] = zero_correlation_2r_exact_scan(sbox,
                                                                                     sample=args.samples // 5)
        rec["zero_correlation"]["R2_zero_explicit"] = verify_zero_examples(
            sbox, rec["zero_correlation"]["R2_support_weight1"]["examples"])
        # témoins constructifs pour des paires réalisables à R=2
        rec["diff_impossible"]["R2_positive_witnesses"] = positive_r2_witnesses(name, sbox)
        out["candidates"][name] = rec
    args.out.write_text(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
