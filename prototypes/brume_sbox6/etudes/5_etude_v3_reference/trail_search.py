#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recherche de caractéristiques différentielles et linéaires.

Trois moteurs complémentaires sont fournis :

1. ``greedy_trail`` / ``greedy_lin_trail`` : le moteur glouton du dépôt
   (choix de la transition DDT/LAT maximale à chaque S-box).  Référence
   historique.
2. ``beam_trail`` : faisceau hiérarchique.  À chaque tour, pour un état
   donné, on combine les sorties possibles des S-box actives par un
   faisceau local (les annulations de la diffusion GF(16) sont donc
   réellement prises en compte), puis on garde les meilleurs états
   globaux selon ``coût + borne inférieure``.  C'est un branch-and-bound
   heuristique, pas une preuve d'optimalité.
3. ``exact_cpsat`` : modèle CP-SAT exact au niveau des mots (différences
   GF(16) exactes, contraintes de table DDT, XOR de diffusion bit à bit).
   Il peut prouver l'optimalité à petit nombre de tours, ou fournir une
   solution réalisable et une borne inférieure (best bound) au-delà.

Les coûts sont des entiers de demi-bits.  Toute caractéristique renvoyée
est revérifiée par ``verifier_trail`` avant d'être écrite.
"""
from __future__ import annotations

import math
import time
from typing import Sequence

import numpy as np

from . import common as C


# ---------------------------------------------------------------------------
# Vérification indépendante
# ---------------------------------------------------------------------------

def verifier_trail(trail: C.Trail, sbox: Sequence[int]) -> tuple[bool, str]:
    d = C.ddt(sbox)
    for r in range(trail.rounds):
        a = np.asarray(trail.round_inputs[r], dtype=np.uint8)
        b = np.asarray(trail.round_outputs[r], dtype=np.uint8)
        trans = trail.transitions[r]
        if len(trans) != int((a != 0).sum()):
            return False, f"r={r}: nombre de transitions incohérent"
        for t in trans:
            i = int(t["pos"])
            av, bv = int(t["a"]), int(t["b"])
            if int(a[i]) != av or int(b[i]) != bv:
                return False, f"r={r}, i={i}: transition incohérente"
            k = int(d[av, bv])
            if k == 0:
                return False, f"r={r}, i={i}: DDT nul"
            expected = int(round(-2.0 * math.log2(k / 16.0)))
            if int(t["cost_half_bits"]) != expected:
                return False, f"r={r}, i={i}: coût faux"
        if int(sum(int(t["cost_half_bits"]) for t in trans)) != trail.round_costs[r]:
            return False, f"r={r}: coût de tour faux"
        if np.any((a == 0) & (b != 0)) or np.any((a != 0) & (b == 0)):
            return False, f"r={r}: support incohérent"
        if r + 1 < trail.rounds:
            out = C.diffuse(b)
            if not np.array_equal(out, np.asarray(trail.round_inputs[r + 1], dtype=np.uint8)):
                return False, f"r={r}: diffusion incohérente"
    if sum(trail.round_costs) != trail.total_cost_half_bits:
        return False, "coût total incohérent"
    return True, "ok"


# ---------------------------------------------------------------------------
# Moteur glouton (référence)
# ---------------------------------------------------------------------------

def _greedy_tables(sbox: Sequence[int]):
    d = C.ddt(sbox)
    l = C.lat(sbox)
    optout = np.zeros(16, dtype=np.uint8)
    cost = np.zeros(16, dtype=np.int64)
    for a in range(16):
        b = int(np.argmax(d[a]))
        optout[a] = b
        k = int(d[a, b])
        cost[a] = int(round(-2.0 * math.log2(k / 16.0))) if k else 99
    optin = np.zeros(16, dtype=np.uint8)
    costlin = np.zeros(16, dtype=np.int64)
    for a in range(16):
        b = int(np.argmax(np.abs(l[a])))
        optin[a] = b
        k = abs(int(l[a, b]))
        costlin[a] = int(round(-2.0 * math.log2(k / 8.0))) if k else 99
    return d, l, optout, cost, optin, costlin


def greedy_trail(sbox: Sequence[int], rounds: int, source_pos: int = 0,
                 source_val: int = 1) -> C.Trail:
    d, l, optout, cost, optin, costlin = _greedy_tables(sbox)
    state = np.zeros(C.N, dtype=np.uint8)
    state[source_pos] = source_val
    inputs, outputs, costs, transitions = [], [], [], []
    for r in range(rounds):
        a = state.copy()
        b = optout[a]
        tr = []
        for i in np.nonzero(a)[0]:
            av, bv = int(a[i]), int(b[i])
            tr.append({"pos": int(i), "a": av, "b": bv,
                       "ddt": int(d[av, bv]),
                       "cost_half_bits": int(round(-2.0 * math.log2(d[av, bv] / 16.0)))})
        inputs.append(C.state_to_list(a))
        outputs.append(C.state_to_list(b))
        costs.append(int(sum(t["cost_half_bits"] for t in tr)))
        transitions.append(tr)
        state = C.diffuse(b)
    return C.Trail(rounds=rounds, input_difference=inputs[0], round_inputs=inputs,
                   round_outputs=outputs, round_costs=costs, transitions=transitions,
                   total_cost_half_bits=int(sum(costs)), kind="diff")


def greedy_all_sources(sbox: Sequence[int], rounds: int, kind: str = "diff",
                       topk: int = 100) -> list[C.Trail]:
    """Applique le moteur glouton à toutes les sources de poids 1.

    Renvoie les ``topk`` meilleures caractéristiques distinctes, triées par
    coût croissant.  C'est la référence historique du dépôt, étendue à
    toutes les sources de poids 1.
    """
    initial = _initial_weight1()
    trails = []
    for st in initial:
        if kind == "diff":
            tr = greedy_trail_from_state(sbox, rounds, st)
        else:
            tr = greedy_lin_trail_from_state(sbox, rounds, st)
        trails.append(tr)
    trails.sort(key=lambda t: t.total_cost_half_bits)
    # déduplique par (entrée, sortie) complète
    seen = set()
    out = []
    for tr in trails:
        key = (tuple(tr.round_inputs[0]), tuple(tr.round_outputs[-1]))
        if key in seen:
            continue
        seen.add(key)
        out.append(tr)
        if len(out) >= topk:
            break
    return out


def greedy_trail_from_state(sbox: Sequence[int], rounds: int,
                            state: np.ndarray) -> C.Trail:
    d, l, optout, cost, optin, costlin = _greedy_tables(sbox)
    state = np.asarray(state, dtype=np.uint8).copy()
    inputs, outputs, costs, transitions = [], [], [], []
    for r in range(rounds):
        a = state.copy()
        b = optout[a]
        tr = []
        for i in np.nonzero(a)[0]:
            av, bv = int(a[i]), int(b[i])
            tr.append({"pos": int(i), "a": av, "b": bv,
                       "ddt": int(d[av, bv]),
                       "cost_half_bits": int(round(-2.0 * math.log2(d[av, bv] / 16.0)))})
        inputs.append(C.state_to_list(a))
        outputs.append(C.state_to_list(b))
        costs.append(int(sum(t["cost_half_bits"] for t in tr)))
        transitions.append(tr)
        state = C.diffuse(b)
    return C.Trail(rounds=rounds, input_difference=inputs[0], round_inputs=inputs,
                   round_outputs=outputs, round_costs=costs, transitions=transitions,
                   total_cost_half_bits=int(sum(costs)), kind="diff")


def greedy_lin_trail_from_state(sbox: Sequence[int], rounds: int,
                                state: np.ndarray) -> C.Trail:
    d, l, optout, cost, optin, costlin = _greedy_tables(sbox)
    state = np.asarray(state, dtype=np.uint8).copy()
    inputs, outputs, costs, transitions = [], [], [], []
    for r in range(rounds):
        alpha = C.diffuse_T(state)
        b = optin[alpha]
        tr = []
        for i in np.nonzero(alpha)[0]:
            u = int(alpha[i]); v = int(b[i])
            k = abs(int(l[u, v]))
            tr.append({"pos": int(i), "u": u, "v": v, "lat_abs": k,
                       "cost_half_bits": int(round(-2.0 * math.log2(k / 8.0)))})
        inputs.append(C.state_to_list(alpha))
        outputs.append(C.state_to_list(b))
        costs.append(int(sum(t["cost_half_bits"] for t in tr)))
        transitions.append(tr)
        state = b
    return C.Trail(rounds=rounds, input_difference=inputs[0], round_inputs=inputs,
                   round_outputs=outputs, round_costs=costs, transitions=transitions,
                   total_cost_half_bits=int(sum(costs)), kind="lin")


def greedy_lin_trail(sbox: Sequence[int], rounds: int, source_pos: int = 0,
                     source_val: int = 1) -> C.Trail:
    """Trail linéaire dans la convention du dépôt (recherche arrière)."""
    d, l, optout, cost, optin, costlin = _greedy_tables(sbox)
    state = np.zeros(C.N, dtype=np.uint8)
    state[source_pos] = source_val
    inputs, outputs, costs, transitions = [], [], [], []
    for r in range(rounds):
        alpha = C.diffuse_T(state)
        b = optin[alpha]
        tr = []
        for i in np.nonzero(alpha)[0]:
            u = int(alpha[i]); v = int(b[i])
            k = abs(int(l[u, v]))
            tr.append({"pos": int(i), "u": u, "v": v, "lat_abs": k,
                       "cost_half_bits": int(round(-2.0 * math.log2(k / 8.0)))})
        inputs.append(C.state_to_list(alpha))
        outputs.append(C.state_to_list(b))
        costs.append(int(sum(t["cost_half_bits"] for t in tr)))
        transitions.append(tr)
        state = b
    return C.Trail(rounds=rounds, input_difference=inputs[0], round_inputs=inputs,
                   round_outputs=outputs, round_costs=costs, transitions=transitions,
                   total_cost_half_bits=int(sum(costs)), kind="lin")


# ---------------------------------------------------------------------------
# Faisceau différentiel
# ---------------------------------------------------------------------------

def _initial_weight1() -> np.ndarray:
    st = np.zeros((C.N * 15, C.N), dtype=np.uint8)
    rows = np.arange(C.N * 15)
    st[rows, rows // 15] = (rows % 15 + 1).astype(np.uint8)
    return st


def _initial_weight2(limit: int | None = None, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    pairs = np.array([(i, j) for i in range(C.N) for j in range(i + 1, C.N)],
                     dtype=np.int32)
    vals = np.array([(a, b) for a in range(1, 16) for b in range(1, 16)],
                    dtype=np.uint8)
    total = len(pairs) * len(vals)
    idx = (np.arange(total) if limit is None
           else rng.choice(total, size=min(limit, total), replace=False))
    st = np.zeros((len(idx), C.N), dtype=np.uint8)
    for row, k in enumerate(idx):
        p = int(k) // len(vals)
        v = int(k) % len(vals)
        st[row, pairs[p, 0]] = vals[v, 0]
        st[row, pairs[p, 1]] = vals[v, 1]
    return st


def _expand_diff_state(state: np.ndarray, sbox_cands, local_width: int,
                       remaining: int, min_cost: int):
    """Développe un état différentiel.

    Renvoie ``(next_input, sbox_output, cost, score)`` ou ``None``.
    ``next_input = M · sbox_output`` ; les annulations sont donc exactes.
    """
    active = np.nonzero(state)[0]
    if len(active) == 0:
        return None
    partial = np.zeros((1, C.N), dtype=np.uint8)      # M · b partiel
    partial_b = np.zeros((1, C.N), dtype=np.uint8)    # b partiel
    pcost = np.zeros(1, dtype=np.int64)
    active = sorted(active.tolist(), key=lambda i: -int(state[i]))
    for pos in active:
        a = int(state[pos])
        cands = sbox_cands[a]
        if not cands:
            return None
        bs = np.array([int(b) for b, _, _ in cands], dtype=np.uint8)
        cs = np.array([int(c) for _, c, _ in cands], dtype=np.int64)
        contrib = C.CONTRIB_DIFF[pos, bs]              # (C, 128)
        new = partial[:, None, :] ^ contrib[None, :, :]
        newb = np.repeat(partial_b[:, None, :], len(bs), axis=1)
        newb[:, :, pos] = bs[None, :]
        P, K = partial.shape[0], len(bs)
        new = new.reshape(P * K, C.N)
        newb = newb.reshape(P * K, C.N)
        ncost = np.repeat(pcost, K) + np.tile(cs, P)
        w = (new != 0).sum(axis=1)
        score = ncost + 4 * w
        if len(score) > local_width:
            keep = np.argpartition(score, local_width - 1)[:local_width]
            new, newb, ncost = new[keep], newb[keep], ncost[keep]
        partial, partial_b, pcost = new, newb, ncost
    w = (partial != 0).sum(axis=1)
    score = pcost + C.h_cost(w, remaining, min_cost)
    return partial, partial_b, pcost, score


def beam_trails_topk(sbox: Sequence[int], rounds: int, k: int = 100,
                     beam_width: int = 400, local_width: int = 1500,
                     initial_states: np.ndarray | None = None,
                     seed: int = 0) -> list[C.Trail]:
    """Faisceau différentiel : renvoie les ``k`` meilleures pistes distinctes.

    Les pistes sont triées par coût croissant et revérifiées une par une.
    """
    cands = C.ddt_candidates(sbox)
    min_cost = C.minimum_diff_cost_per_active(sbox)
    if initial_states is None:
        initial_states = _initial_weight1()
    initial_states = np.asarray(initial_states, dtype=np.uint8)
    states = initial_states.copy()
    costs = np.zeros(len(states), dtype=np.int64)
    histories = [[] for _ in range(len(states))]

    for r in range(rounds):
        remaining = rounds - r - 1
        all_s, all_b, all_c, all_sc, all_h = [], [], [], [], []
        for idx in range(len(states)):
            res = _expand_diff_state(states[idx], cands, local_width, remaining,
                                     min_cost)
            if res is None:
                continue
            ns, nb, pc, sc = res
            tot = costs[idx] + pc
            gs = tot + C.h_cost((ns != 0).sum(axis=1), remaining, min_cost)
            all_s.append(ns); all_b.append(nb); all_c.append(tot)
            all_sc.append(gs)
            all_h.extend([histories[idx] + [(states[idx].copy(), nb[j].copy())]
                          for j in range(len(ns))])
        if not all_s:
            raise RuntimeError("faisceau vide")
        S = np.concatenate(all_s, axis=0)
        B = np.concatenate(all_b, axis=0)
        Cst = np.concatenate(all_c, axis=0)
        Sc = np.concatenate(all_sc, axis=0)
        view = np.ascontiguousarray(S).view(
            np.dtype((np.void, S.dtype.itemsize * S.shape[1]))).ravel()
        order = np.lexsort((Sc, view))
        _, first = np.unique(view[order], return_index=True)
        keep = order[first]
        S, B, Cst, Sc = S[keep], B[keep], Cst[keep], Sc[keep]
        all_h = [all_h[j] for j in keep]
        if len(Sc) > beam_width:
            keep = np.argpartition(Sc, beam_width - 1)[:beam_width]
            S, B, Cst, Sc = S[keep], B[keep], Cst[keep], Sc[keep]
            all_h = [all_h[j] for j in keep]
        states, costs, histories = S, Cst, all_h

    order = np.argsort(costs)
    out = []
    d = C.ddt(sbox)
    for idx in order[:k]:
        hist = histories[int(idx)]
        inputs = [C.state_to_list(x[0]) for x in hist]
        outputs = [C.state_to_list(x[1]) for x in hist]
        costs_r, transitions = [], []
        for a_list, b_list in zip(inputs, outputs):
            a = np.asarray(a_list, dtype=np.uint8)
            b = np.asarray(b_list, dtype=np.uint8)
            tr = []
            for i in np.nonzero(a)[0]:
                av, bv = int(a[i]), int(b[i])
                kk = int(d[av, bv])
                tr.append({"pos": int(i), "a": av, "b": bv, "ddt": kk,
                           "cost_half_bits": int(round(-2.0 * math.log2(kk / 16.0)))})
            costs_r.append(int(sum(t["cost_half_bits"] for t in tr)))
            transitions.append(tr)
        trail = C.Trail(rounds=rounds, input_difference=inputs[0],
                        round_inputs=inputs, round_outputs=outputs,
                        round_costs=costs_r, transitions=transitions,
                        total_cost_half_bits=int(sum(costs_r)), kind="diff")
        ok, msg = verifier_trail(trail, sbox)
        if not ok:
            raise RuntimeError(f"piste top-k invalide : {msg}")
        out.append(trail)
    return out


def beam_trail(sbox: Sequence[int], rounds: int, beam_width: int = 400,
               local_width: int = 1500, initial_states: np.ndarray | None = None,
               seed: int = 0, kind: str = "diff") -> C.Trail:
    """Faisceau.  ``kind='diff'`` ou ``'lin'``.

    Pour le linéaire, on suit la convention du dépôt : alpha = M^T s,
    puis choix de la ligne LAT alpha vers un masque d'entrée b, et
    s := b au tour suivant.
    """
    if kind == "lin":
        return _beam_lin(sbox, rounds, beam_width, local_width,
                         initial_states, seed)
    return beam_trails_topk(sbox, rounds, k=1, beam_width=beam_width,
                            local_width=local_width,
                            initial_states=initial_states, seed=seed)[0]
    rng = np.random.default_rng(seed)
    cands = C.ddt_candidates(sbox)
    min_cost = C.minimum_diff_cost_per_active(sbox)
    if initial_states is None:
        initial_states = _initial_weight1()
    initial_states = np.asarray(initial_states, dtype=np.uint8)
    states = initial_states.copy()
    costs = np.zeros(len(states), dtype=np.int64)
    # historiques : liste de (input, output) par état conservé
    histories = [[] for _ in range(len(states))]

    for r in range(rounds):
        remaining = rounds - r - 1
        all_s, all_b, all_c, all_sc, all_h = [], [], [], [], []
        for idx in range(len(states)):
            res = _expand_diff_state(states[idx], cands, local_width, remaining,
                                     min_cost)
            if res is None:
                continue
            ns, nb, pc, sc = res
            tot = costs[idx] + pc
            gs = tot + C.h_cost((ns != 0).sum(axis=1), remaining, min_cost)
            all_s.append(ns); all_b.append(nb); all_c.append(tot)
            all_sc.append(gs)
            # historiques : on duplique la liste pour chaque enfant
            all_h.extend([histories[idx] + [(states[idx].copy(), nb[k].copy())]
                          for k in range(len(ns))])
        if not all_s:
            raise RuntimeError("faisceau vide")
        S = np.concatenate(all_s, axis=0)
        B = np.concatenate(all_b, axis=0)
        Cst = np.concatenate(all_c, axis=0)
        Sc = np.concatenate(all_sc, axis=0)
        # déduplication par état, coût minimal
        view = np.ascontiguousarray(S).view(
            np.dtype((np.void, S.dtype.itemsize * S.shape[1]))).ravel()
        order = np.lexsort((Sc, view))
        _, first = np.unique(view[order], return_index=True)
        keep = order[first]
        S, B, Cst, Sc = S[keep], B[keep], Cst[keep], Sc[keep]
        all_h = [all_h[k] for k in keep]
        if len(Sc) > beam_width:
            keep = np.argpartition(Sc, beam_width - 1)[:beam_width]
            S, B, Cst, Sc = S[keep], B[keep], Cst[keep], Sc[keep]
            all_h = [all_h[k] for k in keep]
        states, costs, histories = S, Cst, all_h

    best = int(np.argmin(costs))
    hist = histories[best]
    inputs = [C.state_to_list(x[0]) for x in hist]
    outputs = [C.state_to_list(x[1]) for x in hist]
    costs_r = []
    transitions = []
    d = C.ddt(sbox)
    for a_list, b_list in zip(inputs, outputs):
        a = np.asarray(a_list, dtype=np.uint8)
        b = np.asarray(b_list, dtype=np.uint8)
        tr = []
        for i in np.nonzero(a)[0]:
            av, bv = int(a[i]), int(b[i])
            k = int(d[av, bv])
            tr.append({"pos": int(i), "a": av, "b": bv, "ddt": k,
                       "cost_half_bits": int(round(-2.0 * math.log2(k / 16.0)))})
        costs_r.append(int(sum(t["cost_half_bits"] for t in tr)))
        transitions.append(tr)
    trail = C.Trail(rounds=rounds, input_difference=inputs[0],
                    round_inputs=inputs, round_outputs=outputs,
                    round_costs=costs_r, transitions=transitions,
                    total_cost_half_bits=int(sum(costs_r)), kind="diff")
    ok, msg = verifier_trail(trail, sbox)
    if not ok:
        raise RuntimeError(f"caractéristique de faisceau invalide : {msg}")
    return trail


def greedy_lin_trail_forward(sbox: Sequence[int], rounds: int,
                             source_pos: int = 0,
                             source_val: int = 1) -> C.Trail:
    """Caractéristique linéaire en ordre DIRECT (masques u_r -> v_r).

    À chaque S-box active (masque d'entrée ``u``), on choisit le masque de
    sortie ``v`` maximisant ``|LAT[v,u]|``.  Le masque d'entrée du tour
    suivant est ``(M^T_bin)^{-1} v``.
    """
    l = C.lat(sbox)
    state = np.zeros(C.N, dtype=np.uint8)
    state[source_pos] = source_val
    inputs, outputs, costs, transitions = [], [], [], []
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
        transitions.append(tr)
        state = C.diffuse_T_inv(v)
    return C.Trail(rounds=rounds, input_difference=inputs[0],
                   round_inputs=inputs, round_outputs=outputs,
                   round_costs=costs, transitions=transitions,
                   total_cost_half_bits=int(sum(costs)), kind="lin")


def lin_trail_final_mask(tr: C.Trail) -> np.ndarray:
    """Masque de sortie final d'une piste linéaire directe."""
    return C.diffuse_T_inv(np.asarray(tr.round_outputs[-1], dtype=np.uint8))


def lin_trail_to_forward(tr: C.Trail, sbox: Sequence[int]):
    """Convertit une piste linéaire arrière (convention du dépôt) en piste
    directe vérifiable.

    Dans une piste arrière ``round_inputs[r]`` est le masque de SORTIE de la
    S-box du tour (R-r) et ``round_outputs[r]`` son masque d'ENTRÉE.  On
    renvoie ``(trail_direct, masque_de_sortie_final)``.
    """
    R = tr.rounds
    inputs = [tr.round_outputs[R - 1 - t] for t in range(R)]
    outputs = [tr.round_inputs[R - 1 - t] for t in range(R)]
    l = C.lat(sbox)
    costs_r, transitions = [], []
    for u_list, v_list in zip(inputs, outputs):
        u = np.asarray(u_list, dtype=np.uint8)
        v = np.asarray(v_list, dtype=np.uint8)
        trs = []
        for i in np.nonzero(u)[0]:
            uv, vv = int(u[i]), int(v[i])
            k = abs(int(l[vv, uv]))
            trs.append({"pos": int(i), "u": uv, "v": vv, "lat_abs": k,
                        "cost_half_bits": int(round(-2.0 * math.log2(k / 8.0)))})
        costs_r.append(int(sum(t["cost_half_bits"] for t in trs)))
        transitions.append(trs)
    final_mask = C.diffuse_T_inv(np.asarray(tr.round_inputs[0], dtype=np.uint8))
    direct = C.Trail(rounds=R, input_difference=inputs[0],
                     round_inputs=inputs, round_outputs=outputs,
                     round_costs=costs_r, transitions=transitions,
                     total_cost_half_bits=int(sum(costs_r)), kind="lin")
    return direct, final_mask


def _expand_lin_state(state: np.ndarray, sbox_cands, local_width: int,
                      remaining: int, min_cost: int):
    """Développe un état linéaire direct ``u`` (masque d'entrée S-box).

    Pour chaque S-box active on choisit un masque de sortie ``v`` ; le
    prochain masque d'entrée est ``(M^T_bin)^{-1} v``.  Les annulations
    binaires de l'inverse sont accumulées exactement via CONTRIB_TINV.
    """
    active = np.nonzero(state)[0]
    if len(active) == 0:
        return None
    partial_v = np.zeros((1, C.N), dtype=np.uint8)
    partial_u = np.zeros((1, C.N), dtype=np.uint8)
    pcost = np.zeros(1, dtype=np.int64)
    for pos in active:
        u = int(state[pos])
        cands = sbox_cands[u]
        if not cands:
            return None
        vs = np.array([int(v) for v, _, _ in cands], dtype=np.uint8)
        cs = np.array([int(c) for _, c, _ in cands], dtype=np.int64)
        contrib = C.CONTRIB_TINV[pos, vs]
        P, K = partial_v.shape[0], len(vs)
        new_v = np.repeat(partial_v[:, None, :], K, axis=1)
        new_v[:, :, pos] = vs[None, :]
        new_v = new_v.reshape(P * K, C.N)
        new_u = partial_u[:, None, :] ^ contrib[None, :, :]
        new_u = new_u.reshape(P * K, C.N)
        ncost = np.repeat(pcost, K) + np.tile(cs, P)
        w = (new_u != 0).sum(axis=1)
        score = ncost + 4 * w
        if len(score) > local_width:
            keep = np.argpartition(score, local_width - 1)[:local_width]
            new_v, new_u, ncost = new_v[keep], new_u[keep], ncost[keep]
        partial_v, partial_u, pcost = new_v, new_u, ncost
    w = (partial_u != 0).sum(axis=1)
    score = pcost + C.h_cost(w, remaining, min_cost)
    return partial_u, partial_v, pcost, score


def beam_lin_trails_topk(sbox: Sequence[int], rounds: int, k: int = 100,
                         beam_width: int = 300, local_width: int = 1000,
                         initial_states: np.ndarray | None = None) -> list[C.Trail]:
    """Faisceau linéaire direct : renvoie les ``k`` meilleures pistes."""
    cands = C.lat_out_candidates(sbox)
    min_cost = C.minimum_lin_cost_per_active(sbox)
    if initial_states is None:
        initial_states = _initial_weight1()
    initial_states = np.asarray(initial_states, dtype=np.uint8)
    states = initial_states.copy()
    costs = np.zeros(len(states), dtype=np.int64)
    histories = [[] for _ in range(len(states))]

    for r in range(rounds):
        remaining = rounds - r - 1
        all_u, all_v, all_c, all_sc, all_h = [], [], [], [], []
        for idx in range(len(states)):
            res = _expand_lin_state(states[idx], cands, local_width,
                                    remaining, min_cost)
            if res is None:
                continue
            nu, nv, pc, sc = res
            tot = costs[idx] + pc
            gs = tot + C.h_cost((nu != 0).sum(axis=1), remaining, min_cost)
            all_u.append(nu); all_v.append(nv); all_c.append(tot)
            all_sc.append(gs)
            all_h.extend([histories[idx] + [(states[idx].copy(), nv[j].copy())]
                          for j in range(len(nu))])
        if not all_u:
            raise RuntimeError("faisceau linéaire vide")
        S = np.concatenate(all_u, axis=0)
        V = np.concatenate(all_v, axis=0)
        Cst = np.concatenate(all_c, axis=0)
        Sc = np.concatenate(all_sc, axis=0)
        view = np.ascontiguousarray(S).view(
            np.dtype((np.void, S.dtype.itemsize * S.shape[1]))).ravel()
        order = np.lexsort((Sc, view))
        _, first = np.unique(view[order], return_index=True)
        keep = order[first]
        S, V, Cst, Sc = S[keep], V[keep], Cst[keep], Sc[keep]
        all_h = [all_h[j] for j in keep]
        if len(Sc) > beam_width:
            keep = np.argpartition(Sc, beam_width - 1)[:beam_width]
            S, V, Cst, Sc = S[keep], V[keep], Cst[keep], Sc[keep]
            all_h = [all_h[j] for j in keep]
        states, costs, histories = S, Cst, all_h

    order = np.argsort(costs)
    out = []
    l = C.lat(sbox)
    for idx in order[:k]:
        hist = histories[int(idx)]
        inputs = [C.state_to_list(x[0]) for x in hist]
        outputs = [C.state_to_list(x[1]) for x in hist]
        costs_r, transitions = [], []
        for u_list, v_list in zip(inputs, outputs):
            u = np.asarray(u_list, dtype=np.uint8)
            v = np.asarray(v_list, dtype=np.uint8)
            tr = []
            for i in np.nonzero(u)[0]:
                uv, vv = int(u[i]), int(v[i])
                kk = abs(int(l[vv, uv]))
                tr.append({"pos": int(i), "u": uv, "v": vv, "lat_abs": kk,
                           "cost_half_bits": int(round(-2.0 * math.log2(kk / 8.0)))})
            costs_r.append(int(sum(t["cost_half_bits"] for t in tr)))
            transitions.append(tr)
        trail = C.Trail(rounds=rounds, input_difference=inputs[0],
                        round_inputs=inputs, round_outputs=outputs,
                        round_costs=costs_r, transitions=transitions,
                        total_cost_half_bits=int(sum(costs_r)), kind="lin")
        ok, msg = C.verifier_trail_lin(trail, sbox)
        if not ok:
            raise RuntimeError(f"piste linéaire top-k invalide : {msg}")
        out.append(trail)
    return out


def _beam_lin(sbox: Sequence[int], rounds: int, beam_width: int,
              local_width: int, initial_states: np.ndarray | None,
              seed: int) -> C.Trail:
    """Faisceau linéaire (convention arrière du dépôt)."""
    cands = C.lat_candidates(sbox)
    min_cost = C.minimum_lin_cost_per_active(sbox)
    if initial_states is None:
        initial_states = _initial_weight1()
    initial_states = np.asarray(initial_states, dtype=np.uint8)
    states = initial_states.copy()
    costs = np.zeros(len(states), dtype=np.int64)
    histories = [[] for _ in range(len(states))]

    for r in range(rounds):
        remaining = rounds - r - 1
        all_s, all_b, all_c, all_sc, all_h = [], [], [], [], []
        for idx in range(len(states)):
            # alpha = M^T s ; les positions actives de alpha déterminent
            # les S-box du tour.
            alpha = C.diffuse_T(states[idx])
            res = _expand_lin_alpha(alpha, cands, local_width, remaining, min_cost)
            if res is None:
                continue
            nb, pc, next_alpha = res       # nb = masque d'entrée choisi
            tot = costs[idx] + pc
            gs = tot + C.h_cost((next_alpha != 0).sum(axis=1), remaining, min_cost)
            all_s.append(nb); all_b.append(nb); all_c.append(tot)
            all_sc.append(gs)
            all_h.extend([histories[idx] + [(alpha.copy(), nb[k].copy())]
                          for k in range(len(nb))])
        if not all_s:
            raise RuntimeError("faisceau linéaire vide")
        S = np.concatenate(all_s, axis=0)
        Cst = np.concatenate(all_c, axis=0)
        Sc = np.concatenate(all_sc, axis=0)
        view = np.ascontiguousarray(S).view(
            np.dtype((np.void, S.dtype.itemsize * S.shape[1]))).ravel()
        order = np.lexsort((Sc, view))
        _, first = np.unique(view[order], return_index=True)
        keep = order[first]
        S, Cst, Sc = S[keep], Cst[keep], Sc[keep]
        all_h = [all_h[k] for k in keep]
        if len(Sc) > beam_width:
            keep = np.argpartition(Sc, beam_width - 1)[:beam_width]
            S, Cst, Sc = S[keep], Cst[keep], Sc[keep]
            all_h = [all_h[k] for k in keep]
        states, costs, histories = S, Cst, all_h

    best = int(np.argmin(costs))
    hist = histories[best]
    inputs = [C.state_to_list(x[0]) for x in hist]
    outputs = [C.state_to_list(x[1]) for x in hist]
    costs_r = []
    transitions = []
    l = C.lat(sbox)
    for a_list, b_list in zip(inputs, outputs):
        alpha = np.asarray(a_list, dtype=np.uint8)
        b = np.asarray(b_list, dtype=np.uint8)
        tr = []
        for i in np.nonzero(alpha)[0]:
            u, v = int(alpha[i]), int(b[i])
            k = abs(int(l[u, v]))
            tr.append({"pos": int(i), "u": u, "v": v, "lat_abs": k,
                       "cost_half_bits": int(round(-2.0 * math.log2(k / 8.0)))})
        costs_r.append(int(sum(t["cost_half_bits"] for t in tr)))
        transitions.append(tr)
    trail = C.Trail(rounds=rounds, input_difference=inputs[0],
                    round_inputs=inputs, round_outputs=outputs,
                    round_costs=costs_r, transitions=transitions,
                    total_cost_half_bits=int(sum(costs_r)), kind="lin")
    return trail


def _expand_lin_alpha(alpha: np.ndarray, sbox_cands, local_width: int,
                      remaining: int, min_cost: int):
    """Choisit un masque d'entrée b par S-box active de alpha.

    Le prochain état est b ; le score local est coût + 4·poids(M^T b).
    M^T b est accumulé par contributions, sans appel de diffusion global.
    """
    active = np.nonzero(alpha)[0]
    if len(active) == 0:
        return None
    partial = np.zeros((1, C.N), dtype=np.uint8)     # b partiel (prochain état)
    partial_t = np.zeros((1, C.N), dtype=np.uint8)   # M^T b partiel
    pcost = np.zeros(1, dtype=np.int64)
    for pos in active:
        a = int(alpha[pos])
        cands = sbox_cands[a]
        if not cands:
            return None
        bs = np.array([int(b) for b, _, _ in cands], dtype=np.uint8)
        cs = np.array([int(c) for _, c, _ in cands], dtype=np.int64)
        contrib = C.CONTRIB_T[pos, bs]
        P, K = partial.shape[0], len(bs)
        new = np.repeat(partial[:, None, :], K, axis=1)
        new[:, :, pos] = bs[None, :]
        new = new.reshape(P * K, C.N)
        new_t = partial_t[:, None, :] ^ contrib[None, :, :]
        new_t = new_t.reshape(P * K, C.N)
        ncost = np.repeat(pcost, K) + np.tile(cs, P)
        w = (new_t != 0).sum(axis=1)
        score = ncost + 4 * w
        if len(score) > local_width:
            keep = np.argpartition(score, local_width - 1)[:local_width]
            new, new_t, ncost = new[keep], new_t[keep], ncost[keep]
        partial, partial_t, pcost = new, new_t, ncost
    return partial, pcost, partial_t


# ---------------------------------------------------------------------------
# CP-SAT exact (petits nombres de tours, ou borne)
# ---------------------------------------------------------------------------

def exact_cpsat(sbox: Sequence[int], rounds: int, time_limit: float = 60.0,
                initial_mode: str = "weight1", objective: str = "cost",
                upper_bound: int | None = None, workers: int = 12,
                log: bool = False, hint: C.Trail | None = None):
    """Modèle exact au niveau des mots.

    Renvoie un dictionnaire avec le statut, l'objectif, la meilleure borne
    et éventuellement une caractéristique extraite.
    """
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
                cost = 0
            elif k > 0:
                cost = int(round(-2.0 * math.log2(k / 16.0)))
            else:
                continue
            rows.append(tuple([(a >> q) & 1 for q in range(4)]
                              + [(b >> q) & 1 for q in range(4)] + [cost]))

    m = cp_model.CpModel()
    A, Bv, Cv = [], [], []
    for r in range(rounds):
        ar, br, cr = [], [], []
        for i in range(C.N):
            a = [m.NewBoolVar(f"a{r}_{i}_{k}") for k in range(4)]
            b = [m.NewBoolVar(f"b{r}_{i}_{k}") for k in range(4)]
            c = m.NewIntVar(0, 8, f"c{r}_{i}")
            m.AddAllowedAssignments(a + b + [c], rows)
            ar.append(a); br.append(b); cr.append(c)
        A.append(ar); Bv.append(br); Cv.append(cr)
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
    if initial_mode == "weight1":
        act = [m.NewBoolVar(f"act{i}") for i in range(C.N)]
        for i in range(C.N):
            m.AddMaxEquality(act[i], A[0][i])
        m.Add(sum(act) == 1)
    elif initial_mode == "weight2":
        act = [m.NewBoolVar(f"act{i}") for i in range(C.N)]
        for i in range(C.N):
            m.AddMaxEquality(act[i], A[0][i])
        m.Add(sum(act) == 2)
    elif initial_mode == "free":
        act = [m.NewBoolVar(f"act{i}") for i in range(C.N)]
        for i in range(C.N):
            m.AddMaxEquality(act[i], A[0][i])
        m.Add(sum(act) >= 1)
    else:
        raise ValueError(initial_mode)

    if objective == "cost":
        m.Minimize(sum(sum(Cv[r]) for r in range(rounds)))
    elif objective == "active":
        act_all = []
        for r in range(rounds):
            for i in range(C.N):
                z = m.NewBoolVar(f"z{r}_{i}")
                m.AddMaxEquality(z, A[r][i])
                act_all.append(z)
        m.Minimize(sum(act_all))
    else:
        raise ValueError(objective)

    if upper_bound is not None:
        m.Add(sum(sum(Cv[r]) for r in range(rounds)) <= int(upper_bound))

    if hint is not None and hint.rounds == rounds:
        for r in range(rounds):
            arow = np.asarray(hint.round_inputs[r], dtype=np.uint8)
            brow = np.asarray(hint.round_outputs[r], dtype=np.uint8)
            for i in range(C.N):
                for k in range(4):
                    m.AddHint(A[r][i][k], int((int(arow[i]) >> k) & 1))
                    m.AddHint(Bv[r][i][k], int((int(brow[i]) >> k) & 1))
                m.AddHint(Cv[r][i], int(hint.round_costs[r] if False else
                                        sum(int(t["cost_half_bits"]) for t in hint.transitions[r]
                                            if int(t["pos"]) == i)))

    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = float(time_limit)
    solver.parameters.num_workers = workers
    if log:
        solver.parameters.log_search_progress = True
    status = solver.Solve(m)
    out = {
        "status": solver.StatusName(status),
        "objective": None,
        "best_bound": None,
        "wall_time": solver.WallTime(),
        "rounds": rounds,
        "objective_kind": objective,
        "initial_mode": initial_mode,
    }
    if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        out["objective"] = solver.ObjectiveValue()
        out["best_bound"] = solver.BestObjectiveBound()

        def val(vars_):
            return sum((1 if solver.Value(x) else 0) << k for k, x in enumerate(vars_))

        a = [[val(A[r][i]) for i in range(C.N)] for r in range(rounds)]
        b = [[val(Bv[r][i]) for i in range(C.N)] for r in range(rounds)]
        c = [[int(solver.Value(Cv[r][i])) for i in range(C.N)] for r in range(rounds)]
        inputs = [[int(x) for x in row] for row in a]
        outputs = [[int(x) for x in row] for row in b]
        costs = [int(sum(row)) for row in c]
        trans = []
        for r in range(rounds):
            tr = []
            for i in range(C.N):
                if a[r][i]:
                    tr.append({"pos": i, "a": int(a[r][i]), "b": int(b[r][i]),
                               "ddt": int(d[a[r][i], b[r][i]]),
                               "cost_half_bits": int(c[r][i])})
            trans.append(tr)
        tr = C.Trail(rounds=rounds, input_difference=inputs[0],
                     round_inputs=inputs, round_outputs=outputs,
                     round_costs=costs, transitions=trans,
                     total_cost_half_bits=int(sum(costs)), kind="diff")
        ok, msg = verifier_trail(tr, sbox)
        out["trail"] = tr
        out["trail_valid"] = bool(ok)
        out["trail_error"] = msg
    elif status == cp_model.INFEASIBLE:
        out["infeasible"] = True
    return out


# ---------------------------------------------------------------------------
# Borne inférieure certifiée
# ---------------------------------------------------------------------------

def certified_wide_trail_bound(sbox: Sequence[int], rounds: int,
                               kind: str = "diff") -> dict:
    """Borne wide-trail certifiée (branch number 8, test_branch_exact).

    Chaque paire de tours consécutifs contient au moins 8 S-box actives ;
    chaque S-box active coûte au moins le minimum de la ligne DDT (resp.
    LAT).  Pour un nombre impair de tours, on ajoute une S-box au premier
    tour (la source est non nulle).
    """
    active = 8 * (rounds // 2) + (rounds % 2)
    if kind == "diff":
        per = C.minimum_diff_cost_per_active(sbox)
    else:
        per = C.minimum_lin_cost_per_active(sbox)
    return {
        "rounds": rounds,
        "active_sboxes_min": active,
        "min_cost_per_active_half_bits": per,
        "lower_bound_half_bits": active * per,
        "lower_bound_bits": active * per / 2.0,
        "method": "branch number B=8 certifié (test_branch_exact.py)",
    }
