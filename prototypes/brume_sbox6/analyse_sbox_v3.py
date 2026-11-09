#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyse comparative BRUME / SBOX6 / SBOX_V3 (protocole v3 corrigé).

Calcule exactement les tables locales de chaque S-box, puis réutilise
``tests/banc_trails.py`` pour les recherches différentielles et linéaires
heuristiques. Le modèle boomerang par piste est une heuristique distincte ;
les coûts BCT sont conservés en flottants, sans arrondi prématuré.

Ce programme ne constitue pas une preuve de sécurité de la permutation
complète et ne lance pas lui-même le banc expérimental C. Les mesures C sont
intégrées uniquement si ``--c-json`` est fourni.

Dépendances : numpy et le dépôt BRUME contenant tests/banc_trails.py et
sillage/brume512.py.

Exemples :
    python3 prototypes/brume_sbox6/analyse_sbox_v3.py
    python3 prototypes/brume_sbox6/analyse_sbox_v3.py --rounds 14 --w2 8
    python3 prototypes/brume_sbox6/analyse_sbox_v3.py --c-json resultats/brume_attaques.json
    python3 prototypes/brume_sbox6/analyse_sbox_v3.py --no-json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import numpy as np

RACINE = Path(__file__).resolve().parents[2]
if str(RACINE) not in sys.path:
    sys.path.insert(0, str(RACINE))

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sbox_v3 import (  # noqa: E402
    SBOX_BRUME,
    SBOX6,
    SBOX_V3,
    verify_affine_certificate,
)
from tests import banc_trails as bt  # noqa: E402
from sillage.brume512 import N  # noqa: E402

SORTIE_DEFAUT = Path(__file__).resolve().with_name("analyse_sbox_v3.json")
VERSION_PROTOCOLE = "BRUME-SBOX-SEARCH v3-corrige"

if N != 128:
    raise RuntimeError(f"Le moteur BRUME attendu utilise 128 nibbles, N={N} reçu")


# ---------------------------------------------------------------------------
# Tables exactes
# ---------------------------------------------------------------------------

def _parite(x: int) -> int:
    return int(x).bit_count() & 1


def _valider_sbox(sbox: Sequence[int]) -> None:
    if len(sbox) != 16 or sorted(sbox) != list(range(16)):
        raise ValueError("Chaque candidate doit être une permutation de 0..15")


def inverse(sbox: Sequence[int]) -> list[int]:
    _valider_sbox(sbox)
    inv = [0] * 16
    for x, y in enumerate(sbox):
        inv[y] = x
    return inv


def ddt(sbox: Sequence[int]) -> list[list[int]]:
    _valider_sbox(sbox)
    return [
        [sum(1 for x in range(16) if (sbox[x] ^ sbox[x ^ a]) == b)
         for b in range(16)]
        for a in range(16)
    ]


def lat(sbox: Sequence[int]) -> list[list[int]]:
    _valider_sbox(sbox)
    return [
        [sum(1 if _parite(a & sbox[x]) == _parite(b & x) else -1
             for x in range(16))
         for b in range(16)]
        for a in range(16)
    ]


def bct(sbox: Sequence[int]) -> list[list[int]]:
    inv = inverse(sbox)
    return [
        [sum(1 for x in range(16)
             if (inv[sbox[x] ^ b] ^ inv[sbox[x ^ a] ^ b]) == a)
         for b in range(16)]
        for a in range(16)
    ]


def lbct(sbox: Sequence[int]) -> list[list[list[int]]]:
    inv = inverse(sbox)
    return [[[
        sum(1 for x in range(16)
            if (sbox[x] ^ sbox[x ^ bb]) == c
            and (inv[sbox[x] ^ c] ^ inv[sbox[x ^ a] ^ c]) == a)
        for c in range(16)]
        for bb in range(16)]
        for a in range(16)]


def ubct(sbox: Sequence[int]) -> list[list[list[int]]]:
    inv = inverse(sbox)
    return [[[
        sum(1 for x in range(16)
            if (sbox[x] ^ sbox[x ^ a]) == bb
            and (inv[sbox[x] ^ c] ^ inv[sbox[x ^ a] ^ c]) == a)
        for c in range(16)]
        for bb in range(16)]
        for a in range(16)]


def ebct(sbox: Sequence[int]) -> dict[tuple[int, int, int, int], int]:
    table: dict[tuple[int, int, int, int], int] = {}
    for a in range(16):
        for bb in range(16):
            for c in range(16):
                for d in range(16):
                    count = 0
                    for x in range(16):
                        if (
                            (sbox[x] ^ sbox[x ^ a]) == bb
                            and (sbox[x] ^ sbox[x ^ c]) == d
                            and (sbox[x ^ a ^ c] ^ sbox[x ^ a]) == d
                        ):
                            count += 1
                    table[(a, bb, c, d)] = count
    return table


def fbct(sbox: Sequence[int]) -> list[list[int]]:
    return [
        [sum(1 for x in range(16)
             if (sbox[x ^ a ^ bb] ^ sbox[x ^ bb] ^ sbox[x ^ a] ^ sbox[x]) == 0)
         for bb in range(16)]
        for a in range(16)
    ]


def dbct(l_tab: list, u_tab: list) -> list[list[int]]:
    return [
        [sum(u_tab[a][bb][c] * l_tab[bb][c][d]
             for bb in range(16) for c in range(16))
         for d in range(16)]
        for a in range(16)
    ]


def dlct_repo(sbox: Sequence[int]) -> list[list[int]]:
    return [
        [sum(1 if _parite(bb & (sbox[x] ^ sbox[x ^ a])) else -1
             for x in range(16))
         for bb in range(16)]
        for a in range(16)
    ]


def _hist(values) -> dict[str, int]:
    return {str(k): int(v) for k, v in sorted(Counter(values).items())}


def proprietes(sbox: Sequence[int], nom: str) -> dict:
    """Calcule les propriétés locales et les histogrammes sans ambiguïté.

    DDT ``hist`` contient les 225 coefficients non triviaux (a != 0, b != 0).
    ``hist_including_zero_output`` donne également les 15 cases b = 0, ce qui
    explique pourquoi son total vaut 240.
    """
    _valider_sbox(sbox)
    d = ddt(sbox)
    l = lat(sbox)
    b = bct(sbox)
    ltab = lbct(sbox)
    utab = ubct(sbox)
    etab = ebct(sbox)
    ftab = fbct(sbox)
    dtab = dbct(ltab, utab)
    dlt = dlct_repo(sbox)

    ddt_nontrivial = [d[a][bb] for a in range(1, 16) for bb in range(1, 16)]
    ddt_all_output = [d[a][bb] for a in range(1, 16) for bb in range(16)]
    lat_nontrivial = [abs(l[a][bb]) for a in range(16) for bb in range(16)
                      if a or bb]
    bct_values = [b[a][bb] for a in range(1, 16) for bb in range(1, 16)]

    bct_row_max = {a: max(b[a][1:]) for a in range(1, 16)}
    ddt_row_max = {a: max(d[a]) for a in range(1, 16)}
    ddt_row_n4 = {a: sum(1 for value in d[a] if value == 4)
                  for a in range(1, 16)}

    ratio_values = []
    ratio_zero_bct = []
    for a in range(1, 16):
        for bb in range(1, 16):
            if d[a][bb] > 0:
                if b[a][bb] > 0:
                    ratio_values.append(math.log2(b[a][bb] / d[a][bb]))
                else:
                    ratio_zero_bct.append([a, bb, d[a][bb]])

    lbct_nonzero = [ltab[a][bb][c] for a in range(1, 16)
                    for bb in range(1, 16) for c in range(1, 16)]
    lbct_a_neq_b = [ltab[a][bb][c] for a in range(1, 16)
                    for bb in range(1, 16) for c in range(1, 16) if a != bb]
    ubct_nonzero = [utab[a][bb][c] for a in range(1, 16)
                    for bb in range(1, 16) for c in range(1, 16)]
    ubct_a_neq_b = [utab[a][bb][c] for a in range(1, 16)
                    for bb in range(1, 16) for c in range(1, 16) if a != bb]
    ebct_nonzero = [value for key, value in etab.items() if all(key)]
    fbct_a_neq_b = [ftab[a][bb] for a in range(1, 16)
                    for bb in range(1, 16) if a != bb]
    dbct_nonzero = [dtab[a][cc] for a in range(1, 16) for cc in range(1, 16)]
    dlct_nonzero = [abs(dlt[a][bb]) for a in range(1, 16) for bb in range(1, 16)]

    dp = np.asarray(d, dtype=np.float64) / 16.0
    lp = (np.asarray(l, dtype=np.float64) / 16.0) ** 2
    medp2 = max(float((dp[u] ** 8).sum()) for u in range(1, 16))
    melp2 = max(float((lp[u] ** 8).sum()) for u in range(1, 16))

    inv = inverse(sbox)
    return {
        "nom": nom,
        "sbox": list(sbox),
        "inverse": inv,
        "sha256_sbox_bytes": hashlib.sha256(bytes(sbox)).hexdigest(),
        "ddt": {
            "hist": _hist(ddt_nontrivial),
            "hist_including_zero_output": _hist(ddt_all_output),
            "nontrivial_entries": len(ddt_nontrivial),
            "max": max(ddt_nontrivial),
            "row_max": {str(k): int(v) for k, v in ddt_row_max.items()},
            "row_n4": {str(k): int(v) for k, v in ddt_row_n4.items()},
            "row_n4_hist": _hist(ddt_row_n4.values()),
            "rows_max_2": [a for a, value in ddt_row_max.items() if value == 2],
            "row_profiles": {str(a): _hist(d[a]) for a in range(1, 16)},
        },
        "lat": {
            "hist_abs_nontrivial": _hist(lat_nontrivial),
            "max_abs": max(lat_nontrivial),
            "nonlinearity": 8 - max(lat_nontrivial) // 2,
            "entries_at_max_abs": sum(1 for value in lat_nontrivial
                                       if value == max(lat_nontrivial)),
        },
        "bct": {
            "hist": _hist(bct_values),
            "nontrivial_entries": len(bct_values),
            "max": max(bct_values),
            "mean": sum(bct_values) / len(bct_values),
            "row_max": {str(k): int(v) for k, v in bct_row_max.items()},
            "row_max_hist": _hist(bct_row_max.values()),
            "rows_max_2": [a for a, value in bct_row_max.items() if value == 2],
            "ratio_bct_ddt_mean_log2": (
                sum(ratio_values) / len(ratio_values) if ratio_values else None
            ),
            "ratio_bct_ddt_max_log2": max(ratio_values) if ratio_values else None,
            "ddt_positive_bct_zero_transitions": ratio_zero_bct,
            "ratio_definition": "mean log2(BCT[a,b]/DDT[a,b]) for a,b != 0 and DDT[a,b] > 0",
        },
        "lbct": {
            "hist_nonzero": _hist(lbct_nonzero),
            "max_nonzero": max(lbct_nonzero),
            "hist_a_neq_b": _hist(lbct_a_neq_b),
            "max_a_neq_b": max(lbct_a_neq_b),
        },
        "ubct": {
            "hist_nonzero": _hist(ubct_nonzero),
            "max_nonzero": max(ubct_nonzero),
            "hist_a_neq_b": _hist(ubct_a_neq_b),
            "max_a_neq_b": max(ubct_a_neq_b),
        },
        "ebct": {"hist_nonzero": _hist(ebct_nonzero),
                 "max_nonzero": max(ebct_nonzero)},
        "fbct": {"hist_a_neq_b": _hist(fbct_a_neq_b),
                 "max_a_neq_b": max(fbct_a_neq_b)},
        "dbct": {"hist_nonzero": _hist(dbct_nonzero),
                 "max_nonzero": max(dbct_nonzero),
                 "mean_nonzero": sum(dbct_nonzero) / len(dbct_nonzero)},
        "dlct": {"hist_nonzero": _hist(dlct_nonzero),
                 "max_nonzero": max(dlct_nonzero)},
        "park": {
            "MEDP2_log2": math.log2(medp2),
            "MELP2_log2": math.log2(melp2),
        },
        "ddt_max_entries": sum(1 for a in range(1, 16) for bb in range(16)
                                if d[a][bb] == max(ddt_nontrivial)),
        "lat_max_entries": sum(1 for a in range(16) for bb in range(16)
                                if (a or bb) and abs(l[a][bb]) == max(lat_nontrivial)),
    }


# ---------------------------------------------------------------------------
# Moteur de trails différentiel / linéaire du dépôt
# ---------------------------------------------------------------------------

def tables_pour_moteur(sbox: Sequence[int]):
    """Construit les tables selon la convention de tests/banc_trails.py.

    La LAT transmise au moteur vaut Walsh/2 : ses valeurs non nulles sont
    normalement ±2 ou ±4 pour une permutation 4 bits.
    """
    _valider_sbox(sbox)
    x = np.arange(16, dtype=np.uint8)
    s = np.asarray(sbox, dtype=np.uint8)
    d = np.zeros((16, 16), dtype=np.int32)
    for a in range(16):
        diff = s[x] ^ s[x ^ a]
        for value in range(16):
            d[a, value] = int((diff == value).sum())
    parity = np.array([int(i).bit_count() & 1 for i in range(16)])
    l = np.zeros((16, 16), dtype=np.int32)
    for out_mask in range(16):
        for in_mask in range(16):
            matches = int((parity[out_mask & s] == parity[in_mask & x]).sum())
            l[out_mask, in_mask] = matches - 8
    return d, l


def installer_tables(sbox: Sequence[int]):
    d, l = tables_pour_moteur(sbox)
    bt.DDT, bt.LAT = d, l
    bt.OPTOUT, bt.COST, bt.OPTIN, bt.COSTLIN = bt.build_greedy_tables(d, l)
    return d, l


def trails_greedy(sbox: Sequence[int], n_rounds: int, w2_rounds: int = 0,
                  verbose: bool = False) -> dict:
    installer_tables(sbox)
    md, meta_d = bt.sweep("diff", n_rounds=n_rounds,
                          w2_rounds=w2_rounds, verbose=verbose)
    ml, meta_l = bt.sweep("lin", n_rounds=n_rounds,
                          w2_rounds=w2_rounds, verbose=verbose)
    diff_costs = {str(k): int(v) for k, v in md.items()}
    lin_costs = {str(k): int(v) for k, v in ml.items()}
    return {
        # diff / lin conservés comme alias pour compatibilité avec les JSON v1/v2.
        "diff": diff_costs,
        "lin": lin_costs,
        "diff_cost_half_bits": diff_costs,
        "lin_cost_half_bits": lin_costs,
        "meta_diff": {str(k): v for k, v in meta_d.items()},
        "meta_lin": {str(k): v for k, v in meta_l.items()},
    }


def detail_trail_weight1(sbox: Sequence[int], kind: str, source, n_rounds: int):
    """Rejoue seulement une source poids 1, reconstruite sans échantillonnage.

    Le replay des sources poids 3 dépend de la taille/graine interne du moteur
    du dépôt. Pour éviter un replay potentiellement différent, ces sources ne
    sont pas rejouées ici.
    """
    if not isinstance(source, (list, tuple)) or len(source) != 2:
        return {"replay_available": False, "reason": "format de source inconnu"}
    if source[0] != "w1":
        return {
            "replay_available": False,
            "reason": "source non-poids-1 : échantillon non reconstruit ici",
            "source": source,
        }
    installer_tables(sbox)
    detail = bt.replay_trail("w1", int(source[1]), kind, n_rounds)
    active = [int(row["sboxes_actives"]) for row in detail]
    total = sum(active)
    cost_half_bits = sum(int(row["cout_demi_bits"]) for row in detail)

    counts = None
    if kind == "diff":
        # DDT=4 coûte 4 demi-bits ; DDT=2 coûte 6 demi-bits.
        numerator = cost_half_bits - 4 * total
        if numerator < 0 or numerator % 2:
            raise ArithmeticError("Coût différentiel incompatible avec DDT 2/4")
        n_ddt2 = numerator // 2
        n_ddt4 = total - n_ddt2
        if not 0 <= n_ddt2 <= total:
            raise ArithmeticError("Décompte DDT2/4 impossible")
        counts = {"ddt4": n_ddt4, "ddt2": n_ddt2}
    elif kind == "lin":
        # Convention dépôt : LAT_repo=4 coûte 2 demi-bits ; LAT_repo=2
        # coûte 4 demi-bits. Résoudre N=n4+n2 et C=2*n4+4*n2.
        if cost_half_bits % 2:
            raise ArithmeticError("Coût linéaire non pair en demi-bits")
        n_lat2 = cost_half_bits // 2 - total
        n_lat4 = total - n_lat2
        if not 0 <= n_lat2 <= total:
            raise ArithmeticError("Décompte LAT_repo=2/4 impossible")
        counts = {"lat_repo_abs4": n_lat4, "lat_repo_abs2": n_lat2}
    else:
        raise ValueError("kind doit être 'diff' ou 'lin'")

    return {
        "replay_available": True,
        "source": source,
        "rounds": n_rounds,
        "active_sboxes_per_round": active,
        "active_sboxes_total": total,
        "cost_half_bits": cost_half_bits,
        "cost_bits": cost_half_bits / 2.0,
        "sbox_transition_counts": counts,
    }


# ---------------------------------------------------------------------------
# Sources et modèle boomerang heuristique
# ---------------------------------------------------------------------------

def _sources_w1() -> np.ndarray:
    states = np.zeros((N * 15, N), dtype=np.uint8)
    rows = np.arange(N * 15)
    states[rows, rows // 15] = (rows % 15 + 1).astype(np.uint8)
    return states


def _sources_w3(n: int = 50_000, seed: int = 11) -> np.ndarray:
    """Génère exactement n sources poids 3, avec 3 positions distinctes.

    L'échantillonnage des supports est uniforme par tirage de trois indices
    puis rejet des doublons internes. Les supports peuvent réapparaître dans
    des lignes différentes : il s'agit d'un échantillonnage avec remise.
    """
    if n <= 0:
        return np.zeros((0, N), dtype=np.uint8)
    rng = np.random.default_rng(seed)
    supports = []
    while len(supports) < n:
        batch_size = max(1024, 2 * (n - len(supports)))
        candidate = np.sort(rng.integers(0, N, size=(batch_size, 3)), axis=1)
        valid = (candidate[:, 0] != candidate[:, 1]) & (candidate[:, 1] != candidate[:, 2])
        supports.extend(candidate[valid].tolist())
    sup = np.asarray(supports[:n], dtype=np.int64)
    states = np.zeros((n, N), dtype=np.uint8)
    rows = np.arange(n)[:, None]
    states[rows, sup] = rng.integers(1, 16, size=(n, 3)).astype(np.uint8)
    return states


def _tables_boomerang(sbox: Sequence[int]):
    """Tables gloutonnes DDT/BCT avec coûts exacts en demi-bits (flottants).

    Pour un coefficient k sur 16 entrées, le coût en bits est
    -log2(k/16). Le code retourne deux fois ce coût, donc en demi-bits.
    Aucune approximation entière/arrondi n'est appliquée.
    """
    d = ddt(sbox)
    b = bct(sbox)

    optout = np.zeros(16, dtype=np.uint8)
    ddt_cost_half_bits = np.zeros(16, dtype=np.float64)
    for a in range(16):
        bb = int(np.argmax(d[a]))
        optout[a] = bb
        coefficient = int(d[a][bb])
        ddt_cost_half_bits[a] = (
            2.0 * math.log2(16.0 / coefficient) if coefficient > 0 else math.inf
        )

    bct_best_output = np.zeros(16, dtype=np.uint8)
    bct_cost_half_bits = np.zeros(16, dtype=np.float64)
    for a in range(1, 16):
        coefficient, bb = max((int(b[a][bb]), bb) for bb in range(1, 16))
        bct_best_output[a] = bb
        bct_cost_half_bits[a] = (
            2.0 * math.log2(16.0 / coefficient) if coefficient > 0 else math.inf
        )

    return optout, ddt_cost_half_bits, bct_best_output, bct_cost_half_bits


def trails_boomerang_switch(sbox: Sequence[int], max_r: int = 7) -> dict[str, float]:
    """Modèle heuristique : piste DDT, switch BCT, piste DDT.

    Les résultats sont des coûts de pistes simples, pas une probabilité de
    distingueur boomerang complet ni une borne de sécurité.
    """
    if max_r < 0:
        raise ValueError("max_r doit être positif ou nul")
    optout, ddt_cost, bct_best, bct_cost = _tables_boomerang(sbox)
    result: dict[str, float] = {}

    for initial in (_sources_w1(), _sources_w3()):
        for r in range(1, max_r + 1):
            state = initial.copy()
            cost = np.zeros(len(state), dtype=np.float64)
            for _ in range(r):
                cost += ddt_cost[state].sum(axis=1)
                state = optout[state]
                state = bt.diffuse_batch_w(state, True)

            delta = state
            beta = bct_best[delta]
            cost += bct_cost[delta].sum(axis=1)
            lower = bt.diffuse_batch_w(beta, True)
            for _ in range(r - 1):
                cost += ddt_cost[lower].sum(axis=1)
                lower = optout[lower]
                lower = bt.diffuse_batch_w(lower, True)

            alive = lower.any(axis=1)
            if alive.any():
                best = float(cost[alive].min())
                key = str(2 * r)
                result[key] = min(result.get(key, math.inf), best)

    return {key: round(value, 9) for key, value in sorted(result.items(), key=lambda x: int(x[0]))}


def trails_bct_greedy(sbox: Sequence[int], n_rounds: int = 14) -> dict[str, float]:
    """Stress test glouton utilisant une entrée BCT maximale à chaque S-box."""
    _, _, bct_best, bct_cost = _tables_boomerang(sbox)
    result: dict[str, float] = {}
    for initial in (_sources_w1(), _sources_w3()):
        state = initial.copy()
        cost = np.zeros(len(state), dtype=np.float64)
        for r in range(n_rounds):
            cost += bct_cost[state].sum(axis=1)
            state = bct_best[state]
            state = bt.diffuse_batch_w(state, True)
            alive = state.any(axis=1)
            if alive.any():
                best = float(cost[alive].min())
                key = str(r + 1)
                result[key] = min(result.get(key, math.inf), best)
    return {key: round(value, 9) for key, value in sorted(result.items(), key=lambda x: int(x[0]))}


# ---------------------------------------------------------------------------
# Métadonnées et programme principal
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _half_bits_summary(cost_map: dict, rounds: int, kind: str) -> str:
    values = cost_map.get(str(rounds))
    if values is None:
        return "n/a"
    bits = float(values) / 2.0
    return f"2^-{bits:.3f} bits" if kind == "probability" else f"corr=2^-{bits:.3f}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=14,
                        help="nombre de tours pour les recherches DDT/LAT (1..32)")
    parser.add_argument("--w2", type=int, default=0,
                        help="recherche exhaustive poids 2 jusqu'à ce nombre de tours (0=désactivée)")
    parser.add_argument("--c-json", type=Path, default=None,
                        help="JSON brut du banc C à intégrer ; aucune mesure n'est codée en dur")
    parser.add_argument("--c-raw-csv", type=Path, default=None,
                        help="CSV brut du banc C à référencer et hacher")
    parser.add_argument("--output", type=Path, default=SORTIE_DEFAUT,
                        help=f"fichier JSON de sortie (défaut : {SORTIE_DEFAUT})")
    parser.add_argument("--no-json", action="store_true",
                        help="ne pas écrire le JSON d'analyse")
    parser.add_argument("--verbose", action="store_true",
                        help="afficher le détail des recherches de pistes")
    args = parser.parse_args()

    if not 1 <= args.rounds <= 32:
        parser.error("--rounds doit être compris entre 1 et 32")
    if not 0 <= args.w2 <= args.rounds:
        parser.error("--w2 doit être compris entre 0 et --rounds")
    if args.c_json is not None and not args.c_json.is_file():
        parser.error(f"JSON C introuvable : {args.c_json}")
    if args.c_raw_csv is not None and not args.c_raw_csv.is_file():
        parser.error(f"CSV C introuvable : {args.c_raw_csv}")

    candidate_defs = [
        (SBOX_BRUME, "BRUME", "brume"),
        (SBOX6, "SBOX6", "sbox6"),
        (SBOX_V3, "SBOX_V3", "sbox_v3"),
    ]
    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "protocol": VERSION_PROTOCOLE,
        "scope_note": (
            "Tables locales exactes ; pistes multi-tours heuristiques ; "
            "les mesures C ne sont intégrées que via --c-json."
        ),
        "parameters": {
            "rounds_differential_linear": args.rounds,
            "weight2_exhaustive_rounds_requested": args.w2,
            "weight2_search_enabled": args.w2 > 0,
            "weight3_sampling": "configuration du tests/banc_trails.py du dépôt ; à archiver avec le commit",
            "boomerang_switch_model": "une piste gloutonne DDT / switch BCT / DDT ; coûts exacts flottants en demi-bits",
            "state_nibbles": N,
            "affine_certificate_g11_valid": verify_affine_certificate(),
        },
        "c_campaign": None,
        "c_raw_csv": None,
        "candidates": {},
        # Alias historiques conservés pour faciliter les comparaisons avec v1/v2.
        "brume": None,
        "sbox6": None,
        "sbox_v3": None,
        "trails": {},
        "boomerang_switch_trails_half_bits": {},
        "boomerang_trails": {},
        "bct_greedy_stress_half_bits": {},
        "bct_greedy": {},
    }

    if not result["parameters"]["affine_certificate_g11_valid"]:
        raise RuntimeError("Le certificat affine G11 de SBOX_V3 a échoué")

    if args.c_json is not None:
        with args.c_json.open("r", encoding="utf-8") as handle:
            c_payload = json.load(handle)
        result["c_campaign"] = {
            "source_path": str(args.c_json.resolve()),
            "sha256": _sha256_file(args.c_json),
            "data": c_payload,
        }
    if args.c_raw_csv is not None:
        result["c_raw_csv"] = {
            "source_path": str(args.c_raw_csv.resolve()),
            "sha256": _sha256_file(args.c_raw_csv),
        }

    print(f"Protocole : {VERSION_PROTOCOLE}")
    print(f"Horizon : {args.rounds} tours ; poids 2 demandé jusqu'à {args.w2} tour(s)")

    for sbox, name, key in candidate_defs:
        properties = proprietes(sbox, name)
        result["candidates"][name] = properties
        result[{"BRUME": "brume", "SBOX6": "sbox6", "SBOX_V3": "sbox_v3"}[name]] = properties

        print(f"\n=== {name} ===")
        print(
            f"DDT max={properties['ddt']['max']} ; "
            f"LAT max={properties['lat']['max_abs']} "
            f"(NL={properties['lat']['nonlinearity']}) ; "
            f"BCT max={properties['bct']['max']} ; "
            f"DBCT max={properties['dbct']['max_nonzero']}"
        )
        print("DDT non trivial :", properties["ddt"]["hist"])
        print("BCT non trivial :", properties["bct"]["hist"])
        print("Lignes DDT max 2 :", properties["ddt"]["rows_max_2"])
        print("Lignes BCT max 2 :", properties["bct"]["rows_max_2"])

        print("Recherche différentielle / linéaire ...", flush=True)
        trail_result = trails_greedy(
            sbox, args.rounds, w2_rounds=args.w2, verbose=args.verbose
        )
        result["trails"][name] = trail_result

        round_key = str(args.rounds)
        for kind, meta_key in (("diff", "meta_diff"), ("lin", "meta_lin")):
            meta = trail_result[meta_key]
            source = meta.get(round_key)
            if source is None:
                continue
            detail = detail_trail_weight1(sbox, kind, source, args.rounds)
            result["trails"][name][f"detail_{kind}"] = detail

        print("Coût différentiel (demi-bits) :",
              trail_result["diff_cost_half_bits"].get(round_key, "n/a"))
        print("Coût linéaire (demi-bits) :",
              trail_result["lin_cost_half_bits"].get(round_key, "n/a"))

        max_even_rounds = min(14, (args.rounds // 2) * 2)
        max_r = max_even_rounds // 2
        print("Recherche boomerang switch (heuristique) ...", flush=True)
        btr = trails_boomerang_switch(sbox, max_r=max_r)
        result["boomerang_switch_trails_half_bits"][name] = btr
        result["boomerang_trails"][name] = btr

        print("Stress BCT glouton ...", flush=True)
        bct_stress = trails_bct_greedy(sbox, n_rounds=args.rounds)
        result["bct_greedy_stress_half_bits"][name] = bct_stress
        result["bct_greedy"][name] = bct_stress

    # Résumé cohérent avec l'horizon demandé : aucune référence fixe à 14 tours.
    rounds = args.rounds
    even_rounds = (rounds // 2) * 2
    print("\n" + "=" * 82)
    print(f"Comparaison à {rounds} tour(s) — coûts heuristiques en exposants")
    print("=" * 82)
    print(f"{'Métrique':34s} {'BRUME':>14s} {'SBOX6':>14s} {'SBOX_V3':>14s}")
    print("-" * 82)

    names = ("BRUME", "SBOX6", "SBOX_V3")
    for label, getter in (
        ("BCT maximal", lambda n: str(result["candidates"][n]["bct"]["max"])),
        ("DBCT maximal", lambda n: str(result["candidates"][n]["dbct"]["max_nonzero"])),
        ("Lignes DDT max = 2", lambda n: str(len(result["candidates"][n]["ddt"]["rows_max_2"]))),
        ("Lignes BCT max = 2", lambda n: str(len(result["candidates"][n]["bct"]["rows_max_2"]))),
        ("Différentiel (piste)", lambda n: _half_bits_summary(
            result["trails"][n]["diff_cost_half_bits"], rounds, "probability")),
        ("Linéaire (piste)", lambda n: _half_bits_summary(
            result["trails"][n]["lin_cost_half_bits"], rounds, "correlation")),
        (f"Boomerang switch ({even_rounds} tours)", lambda n: (
            "n/a" if even_rounds == 0 else _half_bits_summary(
                result["boomerang_switch_trails_half_bits"][n], even_rounds, "probability")
        )),
        ("MEDP2 (log2)", lambda n: f"{result['candidates'][n]['park']['MEDP2_log2']:.3f}"),
    ):
        values = [getter(name) for name in names]
        print(f"{label:34s} {values[0]:>14s} {values[1]:>14s} {values[2]:>14s}")

    if not args.no_json:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        print(f"\nJSON écrit : {args.output.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
