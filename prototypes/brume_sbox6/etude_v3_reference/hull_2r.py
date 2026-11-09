#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Effet différentiel et coque linéaire EXACTS à 2 tours.

Différentiel
------------
Pour ``alpha -> beta`` sur 2 tours, la décomposition par la différence
intermédiaire est une partition exacte des entrées.  La probabilité vaut

    DP(alpha,beta) = somme_{b0} prod_i DDT[alpha_i,b0_i]/16
                                * prod_j DDT[u1_j,b1_j]/16,
    u1 = M b0,   b1 = M^{-1} beta.

C'est donc la valeur exacte pour la permutation (les constantes de tour
n'affectent pas les différences), pas seulement un modèle de Markov.

Linéaire
--------
On utilise l'adjoint BINAIRE de la diffusion (``C.diffuse_T``), pas la
transposée GF(16).  Pour ``u0 -> u2`` sur 2 tours :

    v1 = M^T_bin u2              (masque de sortie S-box du tour 2)
    v0 parcourt les masques de sortie du tour 1, support ⊆ support(u0)
    u1 = (M^T_bin)^{-1} v0       (masque d'entrée S-box du tour 2)
    corrélation = somme_{v0} prod LAT[v0,u0]/8 * prod LAT[v1,u1]/8.

Les constantes de tour ajoutent le signe ``(-1)^{u0·RC0}`` au tour 1 et
``(-1)^{u1·RC1}`` au tour 2 : le second dépend du chemin, d'où de possibles
renforcements/annulations par rapport au modèle de Markov sans constantes.
"""
from __future__ import annotations

import itertools
import json
import math
from pathlib import Path

import numpy as np

from . import common as C
from . import trail_search as T

SORTIE = Path(__file__).resolve().parents[3] / "resultats" / "etude_v3_vs_brume_reference_20261109"


def _mul_vec(mat: np.ndarray, vec: np.ndarray) -> np.ndarray:
    out = np.zeros(C.N, dtype=np.uint8)
    for i in range(C.N):
        v = int(vec[i])
        if v:
            out ^= C.B.GMUL[v, mat[:, i]]
    return out.astype(np.uint8)


MINV = C.B._gauss_gf16_inverse(C.M.astype(np.uint8))


def hull_diff_2r(sbox, alpha: np.ndarray, beta: np.ndarray,
                 max_combinations: int = 2_000_000):
    """Somme exacte des trails différentiels à 2 tours (= DP exacte)."""
    d = C.ddt(sbox)
    alpha = np.asarray(alpha, dtype=np.uint8)
    beta = np.asarray(beta, dtype=np.uint8)
    b1 = _mul_vec(MINV, beta)
    active = np.nonzero(alpha)[0]
    choices = []
    for i in active:
        a = int(alpha[i])
        row = [(b, int(d[a, b])) for b in range(1, 16) if d[a, b] > 0]
        if not row:
            return 0.0, 0
        choices.append(row)
    total = 0.0
    count = 0
    for combo in itertools.product(*choices):
        b0 = np.zeros(C.N, dtype=np.uint8)
        p = 1.0
        for i, (bv, k) in zip(active, combo):
            b0[i] = bv
            p *= k / 16.0
        u1 = C.diffuse(b0)
        # Vérification sur TOUTES les positions : DDT[0,b]=0 pour b≠0,
        # donc les supports de u1 et b1 doivent coïncider.
        kk = d[u1, b1].astype(np.float64)
        if np.any(kk == 0):
            continue
        p *= float(np.prod(kk / 16.0))
        if p:
            total += p
            count += 1
            if count > max_combinations:
                raise RuntimeError("trop de combinaisons")
    return total, count


def _parity(mask: np.ndarray, value: np.ndarray) -> int:
    par = np.array([int(i).bit_count() & 1 for i in range(16)], dtype=np.uint8)
    return int(par[(np.asarray(mask, dtype=np.uint8) & np.asarray(value, dtype=np.uint8)) & 0xF].sum() & 1)


def hull_lin_2r(sbox, u0: np.ndarray, u2: np.ndarray,
                with_rc: bool = True):
    """Somme exacte (signée) des trails linéaires à 2 tours.

    Renvoie ``(correlation, n_paths, details)``.  ``details`` contient les
    contributions signées par chemin (pour illustrer renforcement et
    annulation).
    """
    l = C.lat(sbox)
    u0 = np.asarray(u0, dtype=np.uint8)
    u2 = np.asarray(u2, dtype=np.uint8)
    v1 = C.diffuse_T(u2)                  # masque de sortie S-box tour 2
    active = np.nonzero(u0)[0]
    total = 0.0
    count = 0
    details = []
    sign1 = (-1) ** _parity(u0, C.RC[0]) if with_rc else 1
    for combo in itertools.product(*[range(1, 16) for _ in active]):
        v0 = np.zeros(C.N, dtype=np.uint8)
        corr = 1.0
        ok = True
        for i, bv in zip(active, combo):
            v0[i] = bv
            k = int(l[bv, int(u0[i])])
            if k == 0:
                ok = False
                break
            corr *= k / 8.0
        if not ok:
            continue
        u1 = C.diffuse_T_inv(v0)
        # Vérification sur TOUTES les positions : LAT[0,b]=0 pour b≠0, donc
        # les supports de v1 et u1 doivent coïncider.
        kk = l[v1, u1]
        if np.any(kk == 0):
            continue
        corr *= float(np.prod(kk.astype(np.float64) / 8.0))
        sign = sign1
        if with_rc:
            sign *= (-1) ** _parity(u1, C.RC[1])
            corr *= sign
        total += corr
        count += 1
        details.append({
            "v0": C.state_to_list(v0),
            "u1": C.state_to_list(u1),
            "correlation_signed": corr,
            "sign_rc": int(sign),
        })
    return total, count, details


def empirical_dp(sbox, alpha: np.ndarray, beta: np.ndarray,
                 samples: int = 1 << 20, chunk: int = 1 << 17,
                 seed: int = 12345):
    """Estimation Monte-Carlo de DP(alpha,beta) sur la permutation réelle."""
    rng = np.random.default_rng(seed)
    alpha = np.asarray(alpha, dtype=np.uint8)
    beta = np.asarray(beta, dtype=np.uint8)
    hits = 0
    done = 0
    while done < samples:
        n = min(chunk, samples - done)
        x = rng.integers(0, 16, size=(n, C.N), dtype=np.uint8)
        y1 = C.permutation_batch(x, sbox, 2)
        y2 = C.permutation_batch(x ^ alpha[None, :], sbox, 2)
        hits += int(((y1 ^ y2) == beta[None, :]).all(axis=1).sum())
        done += n
    p = hits / samples
    se = math.sqrt(max(p * (1 - p), 0.0) / samples)
    return {"samples": samples, "hits": hits, "probability": p,
            "log2": math.log2(p) if p else None, "standard_error": se}


def empirical_correlation(sbox, u0: np.ndarray, u2: np.ndarray,
                          samples: int = 1 << 20, chunk: int = 1 << 17,
                          seed: int = 54321):
    """Estimation Monte-Carlo de la corrélation linéaire réelle (RC inclus)."""
    rng = np.random.default_rng(seed)
    u0 = np.asarray(u0, dtype=np.uint8)
    u2 = np.asarray(u2, dtype=np.uint8)
    par = np.array([int(i).bit_count() & 1 for i in range(16)], dtype=np.uint8)
    acc = 0
    done = 0
    while done < samples:
        n = min(chunk, samples - done)
        x = rng.integers(0, 16, size=(n, C.N), dtype=np.uint8)
        y = C.permutation_batch(x, sbox, 2)
        a = par[(u0[None, :] & (x ^ C.RC[0][None, :])) & 0xF].sum(axis=1) & 1
        b = par[(u2[None, :] & y) & 0xF].sum(axis=1) & 1
        acc += int((1 - 2 * (a ^ b).astype(np.int64)).sum())
        done += n
    c = acc / samples
    se = 1.0 / math.sqrt(samples)
    return {"samples": samples, "correlation": c, "abs": abs(c),
            "standard_error": se}


def forward_lin_trail_from_mask(sbox, u0: np.ndarray, rounds: int = 2):
    """Caractéristique linéaire directe (masques u -> v -> u suivant)."""
    l = C.lat(sbox)
    state = np.asarray(u0, dtype=np.uint8).copy()
    inputs, outputs, costs, trans = [], [], [], []
    for _ in range(rounds):
        u = state.copy()
        v = np.zeros(C.N, dtype=np.uint8)
        tr = []
        for i in np.nonzero(u)[0]:
            uv = int(u[i])
            vv = int(np.argmax(np.abs(l[:, uv])))
            v[i] = vv
            k = abs(int(l[vv, uv]))
            tr.append({"pos": int(i), "u": uv, "v": vv, "lat_abs": k,
                       "cost_half_bits": int(round(-2.0 * math.log2(k / 8.0)))})
        inputs.append(C.state_to_list(u))
        outputs.append(C.state_to_list(v))
        costs.append(int(sum(t["cost_half_bits"] for t in tr)))
        trans.append(tr)
        state = C.diffuse_T_inv(v)
    trail = C.Trail(rounds=rounds, input_difference=inputs[0],
                    round_inputs=inputs, round_outputs=outputs,
                    round_costs=costs, transitions=trans,
                    total_cost_half_bits=int(sum(costs)), kind="lin")
    return trail, np.asarray(inputs[0], dtype=np.uint8), state


def best_forward_lin_weight1(sbox, rounds: int = 2):
    best = None
    for pos in range(C.N):
        for val in range(1, 16):
            u0 = np.zeros(C.N, dtype=np.uint8)
            u0[pos] = val
            tr, u_in, u_out = forward_lin_trail_from_mask(sbox, u0, rounds)
            if best is None or tr.total_cost_half_bits < best[0].total_cost_half_bits:
                best = (tr, u_in, u_out)
    return best


def _trail_correlation(tr: C.Trail, sbox, with_rc: bool = True) -> float:
    l = C.lat(sbox)
    corr = 1.0
    for r in range(tr.rounds):
        u = np.asarray(tr.round_inputs[r], dtype=np.uint8)
        v = np.asarray(tr.round_outputs[r], dtype=np.uint8)
        for i in np.nonzero(u)[0]:
            corr *= int(l[int(v[i]), int(u[i])]) / 8.0
        if with_rc:
            corr *= (-1) ** _parity(u, C.RC[r])
    return corr


def analyse_diff_2r(sbox, topk: int = 100, empirical_n: int = 1 << 20):
    """Coques différentielles exactes pour les meilleures pistes à 2 tours."""
    trails = T.beam_trails_topk(sbox, 2, k=topk, beam_width=300,
                                local_width=1200)
    rows = []
    for tr in trails:
        alpha = np.asarray(tr.round_inputs[0], dtype=np.uint8)
        beta = C.diffuse(np.asarray(tr.round_outputs[-1], dtype=np.uint8))
        p_hull, n_paths = hull_diff_2r(sbox, alpha, beta)
        p_trail = 2.0 ** (-tr.total_cost_bits)
        rows.append({
            "alpha_hex": C.state_to_hex(alpha),
            "beta_hex": C.state_to_hex(beta),
            "trail_cost_bits": tr.total_cost_bits,
            "trail_probability": p_trail,
            "hull_probability_exact": p_hull,
            "hull_log2": math.log2(p_hull) if p_hull else None,
            "n_paths": n_paths,
            "amplification": (p_hull / p_trail) if p_trail else None,
        })
    rows.sort(key=lambda z: z["trail_cost_bits"])
    best_amp = max(rows, key=lambda z: z["amplification"] or 0.0)
    # mesure empirique sur les exemples les plus intéressants
    picks = [rows[0], best_amp]
    uniq = []
    for z in picks:
        if z["alpha_hex"] not in [q["alpha_hex"] for q in uniq]:
            uniq.append(z)
    for z in uniq:
        alpha = np.array([int(c, 16) for c in z["alpha_hex"]], dtype=np.uint8)
        beta = np.array([int(c, 16) for c in z["beta_hex"]], dtype=np.uint8)
        z["empirical"] = empirical_dp(sbox, alpha, beta, samples=empirical_n)
    return {"rows": rows, "best_trail": rows[0], "best_amplification": best_amp,
            "top100_probability_sum": sum(2.0 ** (-r["trail_cost_bits"]) for r in rows)}


def analyse_lin_2r(sbox, empirical_n: int = 1 << 20, candidates: int = 1920):
    """Coques linéaires exactes à 2 tours sur les 1920 masques d'entrée poids 1."""
    rows = []
    l = C.lat(sbox)
    for pos in range(C.N):
        for val in range(1, 16):
            if len(rows) >= candidates:
                break
            u0 = np.zeros(C.N, dtype=np.uint8)
            u0[pos] = val
            tr, u_in, u_out = forward_lin_trail_from_mask(sbox, u0, 2)
            c_trail = _trail_correlation(tr, sbox, with_rc=True)
            c_hull, n_paths, details = hull_lin_2r(sbox, u0, u_out, with_rc=True)
            c_markov, _, _ = hull_lin_2r(sbox, u0, u_out, with_rc=False)
            rows.append({
                "u0_hex": C.state_to_hex(u0),
                "u2_hex": C.state_to_hex(u_out),
                "trail_cost_bits": tr.total_cost_bits,
                "trail_correlation_signed": c_trail,
                "hull_correlation_signed_rc": c_hull,
                "hull_correlation_signed_markov": c_markov,
                "n_paths": n_paths,
                "amplification_abs": (abs(c_hull) / abs(c_trail)) if c_trail else None,
                "path_correlations": [d["correlation_signed"] for d in details],
            })
    rows.sort(key=lambda z: z["trail_cost_bits"])
    nonzero = [z for z in rows if abs(z["hull_correlation_signed_rc"]) > 0]
    zeros = [z for z in rows if z["hull_correlation_signed_rc"] == 0]
    best_amp = max(nonzero, key=lambda z: z["amplification_abs"] or 0.0) if nonzero else None
    # sélection d'exemples mesurés empiriquement
    picks = []
    if rows:
        picks.append(rows[0])
    if best_amp is not None:
        picks.append(best_amp)
    if zeros:
        picks.append(zeros[0])
    uniq = []
    for z in picks:
        if z["u0_hex"] not in [q["u0_hex"] for q in uniq] or z["u2_hex"] not in [q["u2_hex"] for q in uniq]:
            uniq.append(z)
    for z in uniq:
        u0 = np.array([int(c, 16) for c in z["u0_hex"]], dtype=np.uint8)
        u2 = np.array([int(c, 16) for c in z["u2_hex"]], dtype=np.uint8)
        z["empirical"] = empirical_correlation(sbox, u0, u2, samples=empirical_n)
    return {"rows": rows[:1000], "best_trail": rows[0] if rows else None,
            "best_amplification": best_amp,
            "n_exact_zero_correlations": len(zeros),
            "zero_examples": zeros[:10],
            "n_nonzero": len(nonzero)}


def run(samples: int = 1 << 20):
    SORTIE.mkdir(parents=True, exist_ok=True)
    out = {
        "note": ("Coques exactes à 2 tours. Différentiel : DP exacte de la "
                 "permutation. Linéaire : adjoint binaire, constantes de tour "
                 "incluses ; la coque Markov est aussi reportée."),
        "samples": samples,
    }
    for name, sbox in (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3)):
        out[name] = {
            "diff_2r": analyse_diff_2r(sbox, empirical_n=samples),
            "lin_2r": analyse_lin_2r(sbox, empirical_n=samples),
        }
    (SORTIE / "03_effet_differentiel_coque_2t.json").write_text(
        json.dumps(out["BRUME"]["diff_2r"], ensure_ascii=False, indent=1))
    (SORTIE / "03_effet_differentiel_coque_2t_V3.json").write_text(
        json.dumps(out["V3"]["diff_2r"], ensure_ascii=False, indent=1))
    (SORTIE / "06_coque_lineaire_2t.json").write_text(
        json.dumps({k: v for k, v in out.items() if k != "note"} |
                   {"note": out["note"]}, ensure_ascii=False, indent=1))
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=1 << 20)
    args = ap.parse_args()
    res = run(args.samples)
    print(json.dumps({k: (list(v.keys()) if isinstance(v, dict) else v)
                      for k, v in res.items()}, ensure_ascii=False, indent=1))
