# -*- coding: utf-8 -*-
"""Recherche de trails par faisceau (beam search) au-delà du greedy.

Le banc d'origine ne garde qu'une seule transition par S-box (argmax DDT/LAT).
Ici on échantillonne L transitions par état (pondérées par la DDT/LAT) et on
conserve les K meilleurs états par round : si le greedy est optimal, le beam
ne fait pas mieux ; sinon il exhibe un trail plus favorable à l'attaquant.
"""
import json, os, sys, time
import tests.commun  # noqa: F401  (chemin racine)
import numpy as np
from tests.commun import sauver  # noqa: F401
from sillage.brume512 import (GMUL, SBOX, N, E_I, E_C, E_SEG, E_I_T, E_C_T, E_SEG_T, GMUL_T)

def sbox_tables():
    s = np.array(SBOX, dtype=np.uint8); X = np.arange(16)
    ddt = np.zeros((16, 16), np.int32)
    for a in range(16):
        d = s[X] ^ s[X ^ a]
        for v in range(16): ddt[a, v] = int((d == v).sum())
    lat = np.zeros((16, 16), np.int32)
    for a in range(16):
        for l in range(16):
            c = sum(1 for x in range(16) if ((bin(a & int(s[x])).count('1') ^ bin(l & x).count('1')) & 1) == 0)
            lat[a, l] = c - 8
    return ddt, lat

DDT, LAT = sbox_tables()
OPTOUT = np.array([int(np.argmax(DDT[a])) for a in range(16)], np.uint8)
COST = np.array([8 - 2*int(np.log2(max(DDT[a]))) if DDT[a].max() > 1 else 99 for a in range(16)], np.int64)
OPTIN = np.array([int(np.argmax(np.abs(LAT[a]))) for a in range(16)], np.uint8)
COSTLIN = np.array([6 - 2*int(np.log2(max(np.abs(LAT[a])))) if np.abs(LAT[a]).max() > 1 else 99 for a in range(16)], np.int64)

def diffuse(state):
    return np.bitwise_xor.reduceat(GMUL[E_C, state[:, E_I]], E_SEG[:-1], axis=1)
def diffuseT(state):
    return np.bitwise_xor.reduceat(GMUL_T[E_C_T, state[:, E_I_T]], E_SEG_T[:-1], axis=1)

def sources_w1():
    st = np.zeros((128*15, N), np.uint8); rows = np.arange(128*15)
    st[rows, rows//15] = (rows % 15 + 1).astype(np.uint8)
    return st

def sample_outputs(state_row, rng, L):
    """L sorties possibles pour chaque nibble actif (pondérées DDT)."""
    act = np.nonzero(state_row)[0]
    out = np.zeros((L, N), np.uint8)
    # inclut le greedy
    out[0, act] = OPTOUT[state_row[act]]
    for k in range(1, L):
        for j in act:
            a = int(state_row[j]); row = DDT[a].astype(float)
            p = row / row.sum()
            out[k, j] = int(rng.choice(16, p=p))
    return out

def beam(rounds=12, K=300, L=14, seed=5):
    rng = np.random.default_rng(seed)
    S = sources_w1(); costs = np.zeros(len(S), np.int64)
    best = {}
    for r in range(rounds):
        children, cc = [], []
        # limite le nombre d'états développés (les K meilleurs)
        idx = np.argsort(costs)[:K]
        for i in idx:
            s = S[i]; c = costs[i]
            outs = sample_outputs(s, rng, L)
            cadd = COST[outs].sum(1)
            nxt = diffuse(outs)
            children.append(nxt); cc.append(c + cadd)
        S = np.concatenate(children); costs = np.concatenate(cc)
        # filtre les états nuls
        alive = S.any(1)
        S, costs = S[alive], costs[alive]
        best[r+1] = int(costs.min())
    return best

def sample_inputs(alpha_row, rng, L):
    """Pour les masques linéaires : L entrées possibles (pondérées |LAT|)."""
    act = np.nonzero(alpha_row)[0]
    out = np.zeros((L, N), np.uint8)
    out[0, act] = OPTIN[alpha_row[act]]
    for k in range(1, L):
        for j in act:
            a = int(alpha_row[j]); col = np.abs(LAT[a]).astype(float)
            p = col / col.sum()
            out[k, j] = int(rng.choice(16, p=p))
    return out

def beam_lin(rounds=12, K=300, L=14, seed=6):
    rng = np.random.default_rng(seed)
    S = sources_w1(); costs = np.zeros(len(S), np.int64)
    best = {}
    for r in range(rounds):
        children, cc = [], []
        idx = np.argsort(costs)[:K]
        for i in idx:
            s = S[i]; c = costs[i]
            alpha = diffuseT(s[None, :])[0]
            cadd = int(COSTLIN[alpha].sum())
            inp = sample_inputs(alpha, rng, L)
            children.append(inp); cc.append(np.full(L, c + cadd, np.int64))
        S = np.concatenate(children); costs = np.concatenate(cc)
        alive = S.any(1); S, costs = S[alive], costs[alive]
        best[r+1] = int(costs.min())
    return best

def run():
    out = {}
    t0 = time.time()
    out["diff_beam_demi_bits"] = beam(rounds=14, K=220, L=9, seed=5)
    print("beam diff", out["diff_beam_demi_bits"], "t=", round(time.time()-t0,1), flush=True)
    out["lin_beam_demi_bits"] = beam_lin(rounds=14, K=220, L=9, seed=6)
    print("beam lin", out["lin_beam_demi_bits"], "t=", round(time.time()-t0,1), flush=True)
    # borne wide-trail (B = 8) : 2r tours → ≥ 8r S-box ; diff 2 bits/S-box
    # (4 demi-bits), lin 1 bit/S-box (2 demi-bits)
    d, l = out["diff_beam_demi_bits"], out["lin_beam_demi_bits"]
    out["controles"] = {
        "beam_diff_respecte_wide_trail": all(v >= 4 * 8 * (r // 2) for r, v in d.items()),
        "beam_lin_respecte_wide_trail": all(v >= 2 * 8 * (r // 2) for r, v in l.items()),
    }
    sauver("beam_trails", out)
    return out


if __name__ == "__main__":
    run()
