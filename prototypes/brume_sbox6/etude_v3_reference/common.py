#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Outils communs pour la comparaison SBOX_V3 / BRUME classique.

Le modèle de permutation est exactement celui de ``sillage/brume512.py`` :
état de 128 nibbles, S-box 4 bits, diffusion GF(16) M = A + I (branch
number 8, degré 6), constantes de tour SHAKE256.  Seule la table de
substitution change entre les deux candidates :

  * ``BRUME`` : S-box de référence du dépôt ;
  * ``V3``    : SBOX_V3 du prototype.

Conventions de coût (identiques au reste du dépôt) :

  * différentiel : ``w = -log2(DDT[a][b] / 16)`` bits, conservé en
    demi-bits entiers (DDT vaut 2 ou 4 pour ces deux S-boxes) ;
  * linéaire     : ``w = -log2(|LAT[u][v]| / 8)`` bits, conservé en
    demi-bits entiers (|LAT| vaut 2 ou 4).

Aucune approximation flottante n'intervient dans les recherches : les
coûts sont des entiers exacts.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
if str(RACINE) not in sys.path:
    sys.path.insert(0, str(RACINE))

from sillage import brume512 as B  # noqa: E402

SBOX_BRUME = [8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5]
SBOX_V3 = [14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2]
CANDIDATES = {"BRUME": SBOX_BRUME, "V3": SBOX_V3}

N = B.N
NB = 4 * N
RC = B.RC


# ---------------------------------------------------------------------------
# Tables locales exactes
# ---------------------------------------------------------------------------

def inverse(sbox: Sequence[int]) -> list[int]:
    inv = [0] * 16
    for x, y in enumerate(sbox):
        inv[y] = x
    return inv


def ddt(sbox: Sequence[int]) -> np.ndarray:
    """DDT[a, b] = #{x : S(x) ^ S(x^a) = b}."""
    x = np.arange(16, dtype=np.uint8)
    s = np.asarray(sbox, dtype=np.uint8)
    d = np.zeros((16, 16), dtype=np.int16)
    for a in range(16):
        diff = s[x] ^ s[x ^ a]
        for b in range(16):
            d[a, b] = int((diff == b).sum())
    return d


def lat(sbox: Sequence[int]) -> np.ndarray:
    """LAT[u, v] = sum_x (-1)^{u·S(x) ^ v·x} (convention du dépôt)."""
    s = np.asarray(sbox, dtype=np.uint8)
    x = np.arange(16, dtype=np.uint8)
    par = np.array([int(i).bit_count() & 1 for i in range(16)], dtype=np.uint8)
    out = np.zeros((16, 16), dtype=np.int16)
    for u in range(16):
        for v in range(16):
            matches = int((par[u & s] == par[v & x]).sum())
            out[u, v] = matches - 8
    return out


def bct(sbox: Sequence[int]) -> np.ndarray:
    """Table de connectivité boomerang standard."""
    si = inverse(sbox)
    s = np.asarray(sbox, dtype=np.uint8)
    out = np.zeros((16, 16), dtype=np.int16)
    for a in range(16):
        for b in range(16):
            out[a, b] = sum(
                1 for x in range(16)
                if (si[int(s[x]) ^ b] ^ si[int(s[x ^ a]) ^ b]) == a
            )
    return out


def ddt_candidates(sbox: Sequence[int]):
    """Candidats de sortie par différence d'entrée, coût en demi-bits."""
    d = ddt(sbox)
    cands = {}
    for a in range(16):
        row = []
        for b in range(16):
            k = int(d[a, b])
            if k == 0:
                continue
            # -2 log2(k/16) = 4 si k=4, 6 si k=2, 8 si k=1...
            cost = int(round(-2.0 * math.log2(k / 16.0)))
            row.append((b, cost, k))
        cands[a] = row
    return cands


def lat_candidates(sbox: Sequence[int]):
    """Candidats de masque de sortie par masque d'entrée (sens direct).

    ``l[alpha][beta] = LAT[alpha, beta]`` : alpha est le masque de sortie
    de la S-box (u), beta le masque d'entrée (v) selon la convention du
    dépôt.  Le coût demi-bits est ``-2 log2(|LAT|/8)``.
    """
    l = lat(sbox)
    cands = {}
    for a in range(16):
        row = []
        for b in range(16):
            k = abs(int(l[a, b]))
            if k == 0:
                continue
            cost = int(round(-2.0 * math.log2(k / 8.0)))
            row.append((b, cost, k))
        cands[a] = row
    return cands


# ---------------------------------------------------------------------------
# Diffusion GF(16)
# ---------------------------------------------------------------------------

def matrice_M() -> np.ndarray:
    m = np.zeros((N, N), dtype=np.uint8)
    for j in range(N):
        for e in range(B.E_SEG[j], B.E_SEG[j + 1]):
            m[j, int(B.E_I[e])] = B.E_C[e]
    return m


M = matrice_M()


def diffuse(state: np.ndarray) -> np.ndarray:
    """state (128,) ou (B,128) uint8 -> M·state."""
    st = np.asarray(state, dtype=np.uint8)
    if st.ndim == 1:
        return B.diffuse_batch(st[None, :])[0]
    return B.diffuse_batch(st)


def diffuse_T(state: np.ndarray) -> np.ndarray:
    st = np.asarray(state, dtype=np.uint8)
    if st.ndim == 1:
        return B.diffuse_T_batch(st[None, :])[0]
    return B.diffuse_T_batch(st)


def diffuse_batch(state: np.ndarray) -> np.ndarray:
    return diffuse(state)


def diffuse_T_batch(state: np.ndarray) -> np.ndarray:
    return diffuse_T(state)


def colonne_M(i: int) -> np.ndarray:
    """M[:, i] (128 nibbles), contribution d'un nibble d'entrée."""
    return M[:, i].copy()


def contribuer(i: int, valeur: int) -> np.ndarray:
    """M[:,i] · valeur dans GF(16)."""
    return B.GMUL[int(valeur), M[:, i]].astype(np.uint8)


# Contributions précalculées pour le moteur de beam différentiel.
CONTRIB_DIFF = np.zeros((N, 16, N), dtype=np.uint8)
for _i in range(N):
    for _v in range(16):
        CONTRIB_DIFF[_i, _v] = contribuer(_i, _v)

# Contributions pour le moteur linéaire.
#
# ATTENTION : la propagation des masques linéaires n'utilise PAS la
# transposée GF(16) de M, mais l'adjoint BINAIRE de la diffusion, car le
# produit scalaire des masques est la parité du ET bit à bit :
#     <v, M x> = <M^T_bin v, x>.
# ``B.diffuse_T_batch`` implémente exactement M^T_bin (table GMUL_T).
# L'ancienne version utilisait GMUL[v, M.T[:, i]] (transposée GF(16)) :
# les motifs d'activité diffèrent, ce qui faussait le score du faisceau.
CONTRIB_T = np.zeros((N, 16, N), dtype=np.uint8)
for _i in range(N):
    for _v in range(16):
        # Contribution du nibble _i (valeur _v) à M^T_bin · état.
        CONTRIB_T[_i, _v] = B.GMUL_T[M[_i, :], _v].astype(np.uint8)


# ---------------------------------------------------------------------------
# Inverse de l'adjoint binaire de la diffusion (pour les coques linéaires)
# ---------------------------------------------------------------------------

def _binary_matrix_diffuse_T() -> np.ndarray:
    """Matrice binaire 512x512 de M^T_bin (lignes = bits de sortie)."""
    n = 4 * N
    mat = np.zeros((n, n), dtype=np.uint8)
    for i in range(N):
        for k in range(4):
            st = np.zeros(N, dtype=np.uint8)
            st[i] = 1 << k
            out = B.diffuse_T_batch(st[None, :])[0]
            for j in range(N):
                for b in range(4):
                    mat[4 * j + b, 4 * i + k] = (int(out[j]) >> b) & 1
    return mat


def _inverse_binary(mat: np.ndarray) -> np.ndarray:
    """Inverse d'une matrice binaire inversible (Gauss-Jordan, Python ints)."""
    n = mat.shape[0]
    rows = []
    for r in range(n):
        x = 0
        for c in range(n):
            if mat[r, c]:
                x |= 1 << c
        rows.append(x | (1 << (n + r)))
    for col in range(n):
        piv = None
        for r in range(col, n):
            if (rows[r] >> col) & 1:
                piv = r
                break
        if piv is None:
            raise ValueError("matrice binaire singulière")
        rows[col], rows[piv] = rows[piv], rows[col]
        for r in range(n):
            if r != col and ((rows[r] >> col) & 1):
                rows[r] ^= rows[col]
    mask = (1 << n) - 1
    inv_rows = [(rows[r] >> n) & mask for r in range(n)]
    # colonnes de l'inverse (utiles pour appliquer à un vecteur)
    cols = [0] * n
    for c in range(n):
        x = 0
        for r in range(n):
            if (inv_rows[r] >> c) & 1:
                x |= 1 << r
        cols[c] = x
    return np.asarray(cols, dtype=object)


_COLS_TINV = None


def _cols_tinv():
    global _COLS_TINV
    if _COLS_TINV is None:
        _COLS_TINV = _inverse_binary(_binary_matrix_diffuse_T())
    return _COLS_TINV


def diffuse_T_inv(state: np.ndarray) -> np.ndarray:
    """Applique (M^T_bin)^{-1} à un masque linéaire (128 nibbles)."""
    st = np.asarray(state, dtype=np.uint8).ravel()
    cols = _cols_tinv()
    x = 0
    for i in range(N):
        v = int(st[i]) & 0xF
        if v:
            for k in range(4):
                if (v >> k) & 1:
                    x ^= int(cols[4 * i + k])
    out = np.zeros(N, dtype=np.uint8)
    for j in range(N):
        out[j] = (x >> (4 * j)) & 0xF
    return out


# Contributions de l'inverse binaire : (M^T_bin)^{-1} e_i · v.
CONTRIB_TINV = np.zeros((N, 16, N), dtype=np.uint8)
for _i in range(N):
    for _v in range(16):
        st = np.zeros(N, dtype=np.uint8)
        st[_i] = _v
        CONTRIB_TINV[_i, _v] = diffuse_T_inv(st)


def lat_out_candidates(sbox: Sequence[int]):
    """Candidats de masque de SORTIE v pour un masque d'ENTRÉE u.

    ``LAT[v, u]`` (v = sortie, u = entrée).  Coût demi-bits
    ``-2 log2(|LAT[v,u]| / 8)``.
    """
    l = lat(sbox)
    cands = {}
    for u in range(16):
        row = []
        for v in range(16):
            k = abs(int(l[v, u]))
            if k == 0:
                continue
            cost = int(round(-2.0 * math.log2(k / 8.0)))
            row.append((v, cost, k))
        cands[u] = row
    return cands


def verifier_trail_lin(trail: "Trail", sbox: Sequence[int]) -> tuple[bool, str]:
    """Vérifie indépendamment une caractéristique linéaire en ordre DIRECT.

    Champs attendus : ``round_inputs[r][i]`` = masque d'entrée de la S-box,
    ``round_outputs[r][i]`` = masque de sortie de la S-box.
    La cohérence de diffusion exige ``v_r = M^T_bin u_{r+1}``.
    """
    l = lat(sbox)
    for r in range(trail.rounds):
        u = np.asarray(trail.round_inputs[r], dtype=np.uint8)
        v = np.asarray(trail.round_outputs[r], dtype=np.uint8)
        trans = trail.transitions[r]
        if len(trans) != int((u != 0).sum()):
            return False, f"r={r}: nombre de transitions incohérent"
        for t in trans:
            i = int(t["pos"])
            uv, vv = int(t["u"]), int(t["v"])
            if int(u[i]) != uv or int(v[i]) != vv:
                return False, f"r={r}, i={i}: transition incohérente"
            k = abs(int(l[vv, uv]))
            if k == 0:
                return False, f"r={r}, i={i}: LAT nul"
            expected = int(round(-2.0 * math.log2(k / 8.0)))
            if int(t["cost_half_bits"]) != expected:
                return False, f"r={r}, i={i}: coût faux"
        if int(sum(int(t["cost_half_bits"]) for t in trans)) != trail.round_costs[r]:
            return False, f"r={r}: coût de tour faux"
        if np.any((u == 0) & (v != 0)) or np.any((u != 0) & (v == 0)):
            return False, f"r={r}: support incohérent"
        if r + 1 < trail.rounds:
            nxt = np.asarray(trail.round_inputs[r + 1], dtype=np.uint8)
            if not np.array_equal(diffuse_T(nxt), v):
                return False, f"r={r}: diffusion linéaire incohérente"
    if sum(trail.round_costs) != trail.total_cost_half_bits:
        return False, "coût total incohérent"
    return True, "ok"


# ---------------------------------------------------------------------------
# Permutation réelle (pour les mesures empiriques)
# ---------------------------------------------------------------------------

def _tables_tour(sbox: Sequence[int], n_rounds: int):
    """Tables fusionnées T_r[arête, x] = c · S(x ^ RC[r][i])."""
    s = np.asarray(sbox, dtype=np.uint8)
    edges = np.arange(len(B.E_I))
    out = []
    for r in range(n_rounds):
        out.append(B.GMUL[B.E_C[:, None], s[np.arange(16)[None, :] ^ RC[r][B.E_I][:, None]]])
    return out, edges


_MINV_CACHE = {}


def _minv_gf16():
    key = "minv"
    if key not in _MINV_CACHE:
        _MINV_CACHE[key] = B._gauss_gf16_inverse(M.astype(np.uint8))
    return _MINV_CACHE[key]


def permutation_inverse_batch(states: np.ndarray, sbox: Sequence[int],
                              rounds: int, chunk: int = 2048) -> np.ndarray:
    """Inverse de ``permutation_batch`` (mêmes tours, mêmes RC).

    La diffusion inverse est dense ; on traite par lots pour borner la
    mémoire.  Utilisé uniquement pour les simulations de quartets à petit
    nombre de tours.
    """
    st = np.asarray(states, dtype=np.uint8)
    squeeze = st.ndim == 1
    if squeeze:
        st = st[None, :]
    sinv = np.asarray(inverse(sbox), dtype=np.uint8)
    minv = _minv_gf16()
    out = np.empty_like(st)
    for start in range(0, len(st), chunk):
        x = st[start:start + chunk].copy()
        for r in reversed(range(rounds)):
            y = np.empty_like(x)
            for j in range(N):
                row = minv[j]
                y[:, j] = np.bitwise_xor.reduce(
                    B.GMUL[row[None, :], x], axis=1)
            x = sinv[y] ^ RC[r][None, :]
        out[start:start + chunk] = x
    return out[0] if squeeze else out


def permutation_batch(states: np.ndarray, sbox: Sequence[int], rounds: int) -> np.ndarray:
    """Applique ``rounds`` tours BRUME (S-box + diffusion) à un batch."""
    st = np.asarray(states, dtype=np.uint8)
    if st.ndim == 1:
        st = st[None, :]
        squeeze = True
    else:
        squeeze = False
    tables, edges = _tables_tour(sbox, rounds)
    s = (st & 0xF).astype(np.uint8)
    for r in range(rounds):
        s = np.bitwise_xor.reduceat(tables[r][edges, s[:, B.E_I]], B.E_SEG[:-1], axis=1)
    return s[0] if squeeze else s


# ---------------------------------------------------------------------------
# Coûts et bornes
# ---------------------------------------------------------------------------

def cost_diff_half_bits(a: int, b: int, sbox: Sequence[int]):
    d = ddt(sbox)
    k = int(d[int(a), int(b)])
    return None if k == 0 else int(round(-2.0 * math.log2(k / 16.0)))


def cost_lin_half_bits(u: int, v: int, sbox: Sequence[int]):
    l = lat(sbox)
    k = abs(int(l[int(u), int(v)]))
    return None if k == 0 else int(round(-2.0 * math.log2(k / 8.0)))


def minimum_diff_cost_per_active(sbox: Sequence[int]) -> int:
    d = ddt(sbox)
    return min(int(round(-2.0 * math.log2(int(d[a].max()) / 16.0)))
               for a in range(1, 16))


def minimum_lin_cost_per_active(sbox: Sequence[int]) -> int:
    l = lat(sbox)
    return min(int(round(-2.0 * math.log2(abs(l[a]).max() / 8.0)))
               for a in range(1, 16))


def wide_trail_lower_bound_diff(rounds: int, sbox: Sequence[int]) -> int:
    """Borne wide-trail certifiée : B = 8, 8 S-box actives par 2 tours.

    Chaque paire de tours consécutifs contient au moins B = 8 S-box actives
    (branch number certifié dans tests/test_branch_exact.py).  Chaque S-box
    active coûte au moins le minimum de sa ligne DDT.  La borne est valable
    pour toute caractéristique différentielle.
    """
    active = 8 * (rounds // 2)
    if rounds % 2:
        active += 1  # une source non nulle au tour impair
    return active * minimum_diff_cost_per_active(sbox)


def wide_trail_lower_bound_lin(rounds: int, sbox: Sequence[int]) -> int:
    active = 8 * (rounds // 2)
    if rounds % 2:
        active += 1
    return active * minimum_lin_cost_per_active(sbox)


def lower_bound_active_sequence(w, remaining: int, branch: int = 8):
    """Nombre minimal de S-box actives sur ``remaining`` tours partant d'un
    état à ``w`` nibbles actifs (relaxation par branch number).

    À chaque tour, z ≥ w sorties actives, puis w' ≥ max(1, B − z).  Le
    minimum est obtenu pour z = w : w' = max(1, B − w).  C'est une borne
    inférieure valide (on relaxe la contrainte que les sorties de S-box
    aient le poids voulu).

    Accepte un entier ou un tableau numpy (vectorisé).
    """
    arr = np.asarray(w, dtype=np.int64)
    scalar = arr.ndim == 0
    cur = arr.copy() if not scalar else arr
    total = np.zeros_like(cur)
    for _ in range(remaining):
        total = total + np.maximum(1, cur)
        cur = np.where(cur < branch, np.maximum(1, branch - cur), 1)
    return int(total) if scalar else total


def h_cost(w, remaining: int, min_cost: int = 4, branch: int = 8):
    return min_cost * lower_bound_active_sequence(w, remaining, branch)


# ---------------------------------------------------------------------------
# Sérialisation
# ---------------------------------------------------------------------------

def state_to_list(state: np.ndarray) -> list[int]:
    return [int(v) for v in np.asarray(state, dtype=np.uint8).ravel()]


def state_to_hex(state: np.ndarray) -> str:
    return "".join(format(int(v), "x") for v in np.asarray(state, dtype=np.uint8).ravel())


def nonzero(state: np.ndarray) -> list[int]:
    return [int(i) for i in np.nonzero(np.asarray(state).ravel())[0]]


@dataclass
class Trail:
    rounds: int
    input_difference: list[int]
    round_inputs: list[list[int]]
    round_outputs: list[list[int]]
    round_costs: list[int]
    transitions: list[list[dict]]
    total_cost_half_bits: int
    kind: str = "diff"

    @property
    def total_cost_bits(self) -> float:
        return self.total_cost_half_bits / 2.0

    def to_dict(self, compact: bool = False) -> dict:
        rounds_detail = []
        for r in range(self.rounds):
            detail = {
                "round": r + 1,
                "input": self.round_inputs[r],
                "sbox_output": self.round_outputs[r],
                "active_positions": nonzero(np.asarray(self.round_inputs[r])),
                "cost_half_bits": self.round_costs[r],
                "cost_bits": self.round_costs[r] / 2.0,
                "transitions": self.transitions[r],
            }
            if not compact:
                detail["input_hex"] = state_to_hex(np.asarray(self.round_inputs[r]))
                detail["sbox_output_hex"] = state_to_hex(np.asarray(self.round_outputs[r]))
                detail["after_diffusion"] = state_to_list(
                    diffuse(np.asarray(self.round_outputs[r], dtype=np.uint8))
                )
            rounds_detail.append(detail)
        return {
            "rounds": self.rounds,
            "kind": self.kind,
            "input_difference": self.input_difference,
            "input_difference_hex": state_to_hex(np.asarray(self.input_difference)),
            "total_cost_half_bits": self.total_cost_half_bits,
            "total_cost_bits": self.total_cost_bits,
            "probability_log2": -self.total_cost_bits,
            "rounds_detail": rounds_detail,
        }


def fmt_log2(half_bits: int) -> str:
    return f"2^-{half_bits / 2.0:.3f}"
