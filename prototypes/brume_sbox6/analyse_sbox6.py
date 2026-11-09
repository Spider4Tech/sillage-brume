#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyse_sbox6.py — analyse différentielle, linéaire, boomerang et trails de SBOX6.

Le script compare la S-box prototype SBOX6 (RECTANGLE décalée, BCT max = 6)
à la S-box actuelle de BRUME (BCT max = 10). Il calcule :

  1. les tables exactes : DDT, LAT, BCT, LBCT, UBCT, EBCT, FBCT, DBCT, DLCT ;
  2. les profils par ligne de la DDT et de la BCT (ce qui distingue vraiment
     les deux S-box, à histogrammes globaux identiques) ;
  3. les meilleurs trails différentiels et linéaires greedy sur 1 à 14 tours
     du chiffrement réel, avec la couche linéaire de BRUME ;
  4. un modèle de trail boomerang : trails DDT en haut et en bas, passage
     central évalué par la BCT (le « switch ») ;
  5. un test de stress « BCT greedy » où chaque couche de S-box est évaluée
     par la BCT, pour mesurer l'effet de la forme des lignes de BCT.

Les résultats sont écrits dans analyse_sbox6.json. Le script ne modifie ni
sillage/ ni tests/. Il réutilise le moteur de trails de tests/banc_trails.py
et la couche linéaire de sillage/brume512.py.

Usage :
    python3 prototypes/brume_sbox6/analyse_sbox6.py
    python3 prototypes/brume_sbox6/analyse_sbox6.py --rounds 10 --w2 6
    python3 prototypes/brume_sbox6/analyse_sbox6.py --no-json

Avertissement : les trails sont des trails *greedy* (choix local du meilleur
écart/masque de sortie position par position), comme dans tests/banc_trails.py.
Ce sont des caractéristiques valides, donc des bornes inférieures sur la
probabilité ; ils ne prouvent pas l'absence de trails meilleurs. Le modèle
boomerang est un modèle de trail à un seul chemin, pas une attaque complète.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter

import numpy as np

RACINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if RACINE not in sys.path:
    sys.path.insert(0, RACINE)

# Import du prototype (même répertoire).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sbox6 import SBOX6, SBOX_BRUME  # noqa: E402

from tests import banc_trails as bt  # noqa: E402
from sillage.brume512 import N       # noqa: E402

SORTIE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "analyse_sbox6.json")


# ---------------------------------------------------------------------------
# Tables exactes
# ---------------------------------------------------------------------------

def _parite(x: int) -> int:
    return bin(x).count("1") & 1


def inverse(sbox):
    inv = [0] * 16
    for x, y in enumerate(sbox):
        inv[y] = x
    return inv


def ddt(sbox):
    """DDT[a][b] = #{x : S(x) ^ S(x^a) = b}."""
    return [[sum(1 for x in range(16) if sbox[x] ^ sbox[x ^ a] == b)
             for b in range(16)] for a in range(16)]


def lat(sbox):
    """LAT[alpha][lambda] = somme_x (-1)^(alpha.S(x) ^ lambda.x).

    Convention identique à tests/banc_statiques.py : alpha est le masque de
    sortie, lambda le masque d'entrée.
    """
    return [[sum(1 if _parite(al & sbox[x]) == _parite(lam & x) else -1
                 for x in range(16))
             for lam in range(16)] for al in range(16)]


def bct(sbox):
    """BCT[a][b] = #{x : S^-1(S(x)^b) ^ S^-1(S(x^a)^b) = a}."""
    inv = inverse(sbox)
    return [[sum(1 for x in range(16)
                 if inv[sbox[x] ^ b] ^ inv[sbox[x ^ a] ^ b] == a)
             for b in range(16)] for a in range(16)]


def lbct(sbox):
    """Lower Boomerang Connectivity Table (Garg et al., DCC 2025).

    LBCT[a][b][c] = #{x : S(x)^S(x^b)=c et
                          S^-1(S(x)^c)^S^-1(S(x^a)^c)=a}.
    """
    inv = inverse(sbox)
    return [[[sum(1 for x in range(16)
                  if sbox[x] ^ sbox[x ^ b] == c
                  and inv[sbox[x] ^ c] ^ inv[sbox[x ^ a] ^ c] == a)
              for c in range(16)] for b in range(16)] for a in range(16)]


def ubct(sbox):
    """Upper Boomerang Connectivity Table.

    UBCT[a][b][c] = #{x : S(x)^S(x^a)=b et
                          S^-1(S(x)^c)^S^-1(S(x^a)^c)=a}.
    """
    inv = inverse(sbox)
    return [[[sum(1 for x in range(16)
                  if sbox[x] ^ sbox[x ^ a] == b
                  and inv[sbox[x] ^ c] ^ inv[sbox[x ^ a] ^ c] == a)
              for c in range(16)] for b in range(16)] for a in range(16)]


def ebct(sbox):
    """Extended Boomerang Connectivity Table (16^4 entrées)."""
    table = {}
    for a in range(16):
        for b in range(16):
            for c in range(16):
                for d in range(16):
                    n = 0
                    for x in range(16):
                        if (sbox[x] ^ sbox[x ^ a] == b
                                and sbox[x] ^ sbox[x ^ c] == d
                                and sbox[x ^ a ^ c] ^ sbox[x ^ a] == d):
                            n += 1
                    table[(a, b, c, d)] = n
    return table


def fbct(sbox):
    """Feistel/second-order boomerang table (ici pour une permutation).

    FBCT[a][b] = #{x : S(x^a^b)^S(x^b)^S(x^a)^S(x) = 0}.
    Son maximum pour a != b, ab != 0 est l'uniformité différentielle du
    second ordre (aussi appelée « boomerang difference table »).
    """
    return [[sum(1 for x in range(16)
                 if sbox[x ^ a ^ b] ^ sbox[x ^ b] ^ sbox[x ^ a] ^ sbox[x] == 0)
             for b in range(16)] for a in range(16)]


def dbct(sbox, l_tab, u_tab):
    """Double Boomerang Connectivity Table.

    DBCT[a][d] = somme_{b,c} UBCT[a][b][c] * LBCT[b][c][d].
    """
    return [[sum(u_tab[a][b][c] * l_tab[b][c][d]
                 for b in range(16) for c in range(16))
             for d in range(16)] for a in range(16)]


def dlct_repo(sbox):
    """DLCT au sens du test C de BRUME.

    DLCT[a][b] = somme_x (-1)^(b.(S(x)^S(x^a))).
    C'est la transformée de Walsh de la dérivée ; le maximum non trivial
    vaut 8 par Parseval pour une permutation 4 bits.
    """
    return [[sum(1 if _parite(b & (sbox[x] ^ sbox[x ^ a])) else -1
                 for x in range(16))
             for b in range(16)] for a in range(16)]


def _hist(values):
    return {str(k): int(v) for k, v in sorted(Counter(values).items())}


def _max_non_trivial(table):
    return max(table[a][b] for a in range(1, 16) for b in range(1, 16))


def proprietes(sbox, nom):
    d = ddt(sbox)
    l = lat(sbox)
    b = bct(sbox)
    ltab = lbct(sbox)
    utab = ubct(sbox)
    etab = ebct(sbox)
    ftab = fbct(sbox)
    dtab = dbct(sbox, ltab, utab)
    dlt = dlct_repo(sbox)

    bct_vals = [b[a][bb] for a in range(1, 16) for bb in range(1, 16)]
    # Lignes de BCT : maximum atteint pour chaque différence d'entrée.
    bct_row_max = {a: max(b[a][1:]) for a in range(1, 16)}
    # Lignes de DDT : maximum et nombre d'entrées au maximum.
    ddt_row_max = {a: max(d[a]) for a in range(1, 16)}
    ddt_row_n4 = {a: sum(1 for v in d[a] if v == 4) for a in range(1, 16)}

    # Ratios BCT/DDT sur les transitions différentielles possibles.
    ratios = []
    for a in range(1, 16):
        for bb in range(1, 16):
            if d[a][bb] > 0:
                ratios.append(math.log2(b[a][bb] / d[a][bb]))

    lbct_nonzero = [ltab[a][bb][c] for a in range(16) for bb in range(16)
                    for c in range(16) if a and bb and c]
    lbct_ab = [ltab[a][bb][c] for a in range(16) for bb in range(16)
               for c in range(16) if a and bb and c and a != bb]
    ubct_nonzero = [utab[a][bb][c] for a in range(16) for bb in range(16)
                    for c in range(16) if a and bb and c]
    ubct_ab = [utab[a][bb][c] for a in range(16) for bb in range(16)
               for c in range(16) if a and bb and c and a != bb]
    ebct_nonzero = [v for k, v in etab.items() if all(k)]
    fbct_ab = [ftab[a][bb] for a in range(16) for bb in range(16)
               if a and bb and a != bb]
    dbct_nz = [dtab[a][cc] for a in range(1, 16) for cc in range(1, 16)]
    dlct_nz = [abs(dlt[a][bb]) for a in range(1, 16) for bb in range(1, 16)]

    # Bornes de Park & al. à 2 tours (branch number 8).
    # LAT est ici la somme signée complète (max 8) : la corrélation vaut
    # LAT/16, d'où le facteur 16. Le moteur de trails utilise la convention
    # de tests/banc_statiques.py (moitié de la somme, max 4) et LAT/8.
    dp = np.array(d, dtype=float) / 16.0
    lp = (np.array(l, dtype=float) / 16.0) ** 2
    medp2 = max(float((dp[u] ** 8).sum()) for u in range(1, 16))
    melp2 = max(float((lp[u] ** 8).sum()) for u in range(1, 16))

    return {
        "nom": nom,
        "sbox": list(sbox),
        "ddt": {
            "hist": _hist([d[a][bb] for a in range(1, 16) for bb in range(16)]),
            "max": max(d[a][bb] for a in range(1, 16) for bb in range(16)),
            "row_max": {str(k): v for k, v in ddt_row_max.items()},
            "row_n4": {str(k): v for k, v in ddt_row_n4.items()},
            "row_n4_hist": _hist(list(ddt_row_n4.values())),
            "row_profiles": {str(a): _hist(d[a]) for a in range(1, 16)},
        },
        "lat": {
            "hist": _hist([abs(l[a][bb]) for a in range(16) for bb in range(16)
                           if a or bb]),
            "max": max(abs(l[a][bb]) for a in range(16) for bb in range(16)
                       if a or bb),
            "nl": 8 - max(abs(l[a][bb]) for a in range(16) for bb in range(16)
                          if a or bb) // 2,
        },
        "bct": {
            "hist": _hist(bct_vals),
            "max": max(bct_vals),
            "mean": sum(bct_vals) / len(bct_vals),
            "row_max": {str(k): v for k, v in bct_row_max.items()},
            "row_max_hist": _hist(list(bct_row_max.values())),
            "ratio_bct_ddt_mean_log2": sum(ratios) / len(ratios),
            "ratio_bct_ddt_max_log2": max(ratios),
        },
        "lbct": {
            "hist_nonzero": _hist(lbct_nonzero),
            "max_nonzero": max(lbct_nonzero),
            "hist_a_neq_b": _hist(lbct_ab),
            "max_a_neq_b": max(lbct_ab),
        },
        "ubct": {
            "hist_nonzero": _hist(ubct_nonzero),
            "max_nonzero": max(ubct_nonzero),
            "hist_a_neq_b": _hist(ubct_ab),
            "max_a_neq_b": max(ubct_ab),
        },
        "ebct": {
            "hist_nonzero": _hist(ebct_nonzero),
            "max_nonzero": max(ebct_nonzero),
        },
        "fbct": {
            "hist_a_neq_b": _hist(fbct_ab),
            "max_a_neq_b": max(fbct_ab),
        },
        "dbct": {
            "hist_nonzero": _hist(dbct_nz),
            "max_nonzero": max(dbct_nz),
            "mean_nonzero": sum(dbct_nz) / len(dbct_nz),
        },
        "dlct": {
            "hist_nonzero": _hist(dlct_nz),
            "max_nonzero": max(dlct_nz),
        },
        "park": {
            "MEDP2_log2": math.log2(medp2),
            "MELP2_log2": math.log2(melp2),
        },
        "ddt_max_entries": sum(1 for a in range(1, 16) for bb in range(16)
                               if d[a][bb] == 4),
        "lat_max_entries": sum(1 for a in range(16) for bb in range(16)
                               if (a or bb) and abs(l[a][bb]) == 8),
    }


# ---------------------------------------------------------------------------
# Moteur de trails (réutilise tests/banc_trails.py)
# ---------------------------------------------------------------------------

def tables_pour_moteur(sbox):
    """DDT et LAT dans la convention exacte de tests/banc_statiques.py."""
    x = np.arange(16, dtype=np.uint8)
    s = np.asarray(sbox, dtype=np.uint8)
    d = np.zeros((16, 16), dtype=np.int32)
    for a in range(16):
        diff = s[x] ^ s[x ^ a]
        for v in range(16):
            d[a, v] = int((diff == v).sum())
    par = np.array([bin(i).count("1") & 1 for i in range(16)])
    l = np.zeros((16, 16), dtype=np.int32)
    for al in range(16):
        for lam in range(16):
            l[al, lam] = int((par[al & s] == par[lam & x]).sum()) - 8
    return d, l


def installer_tables(sbox):
    d, l = tables_pour_moteur(sbox)
    bt.DDT, bt.LAT = d, l
    bt.OPTOUT, bt.COST, bt.OPTIN, bt.COSTLIN = bt.build_greedy_tables(d, l)
    return d, l


def trails_greedy(sbox, n_rounds, w2_rounds=0, verbose=False):
    installer_tables(sbox)
    md, meta_d = bt.sweep("diff", n_rounds=n_rounds, w2_rounds=w2_rounds,
                          verbose=verbose)
    ml, meta_l = bt.sweep("lin", n_rounds=n_rounds, w2_rounds=w2_rounds,
                          verbose=verbose)
    return {
        "diff": {str(k): int(v) for k, v in md.items()},
        "lin": {str(k): int(v) for k, v in ml.items()},
        "meta_diff": {str(k): v for k, v in meta_d.items()},
        "meta_lin": {str(k): v for k, v in meta_l.items()},
    }


def detail_trail(sbox, kind, source, n_rounds):
    """Rejoue un trail et renvoie les S-box actives et les coûts par tour."""
    installer_tables(sbox)
    tag, row = source
    detail = bt.replay_trail(tag, int(row), kind, n_rounds)
    return detail


def _sources_w1():
    st = np.zeros((128 * 15, N), dtype=np.uint8)
    rows = np.arange(128 * 15)
    st[rows, rows // 15] = (rows % 15 + 1).astype(np.uint8)
    return st


def _sources_w3(n=50_000, seed=11):
    rng = np.random.default_rng(seed)
    sup = np.sort(rng.integers(0, N, size=(n, 3)), axis=1)
    ok = (np.diff(sup, axis=1) > 0).all(axis=1)
    sup = sup[ok]
    state = np.zeros((len(sup), N), dtype=np.uint8)
    rows = np.arange(len(sup))[:, None]
    state[rows, sup] = rng.integers(1, 16, size=(len(sup), 3)).astype(np.uint8)
    return state


def _tables_boomerang(sbox):
    d = ddt(sbox)
    b = bct(sbox)
    optout = np.zeros(16, dtype=np.uint8)
    cost = np.zeros(16, dtype=np.int64)
    for a in range(16):
        bb = int(np.argmax(d[a]))
        optout[a] = bb
        k = int(d[a][bb])
        cost[a] = 8 - 2 * int(math.log2(k)) if k > 1 else 99
    bopt = np.zeros(16, dtype=np.uint8)
    bcost = np.zeros(16, dtype=np.int64)
    for a in range(1, 16):
        v, bb = max((b[a][bb], bb) for bb in range(1, 16))
        bopt[a] = bb
        bcost[a] = 2 * int(round(math.log2(16.0 / v))) if v > 0 else 999
    return optout, cost, bopt, bcost


def trails_boomerang_switch(sbox, max_r=7):
    """Modèle de trail boomerang sur 2r tours.

    Découpage : E = E1 o E0, E0 = r tours complets, E1 = r tours complets.
    Le switch est la première couche de S-box de E1 :
      - trail haut : DDT sur r tours, de Delta à delta ;
      - switch : BCT[delta][beta] (une S-box active par position) ;
      - trail bas : DDT sur les r-1 tours restants, après la couche linéaire.
    Le coût est en demi-bits ; la probabilité du trail vaut 2^(-coût/2).
    """
    optout, cost, bopt, bcost = _tables_boomerang(sbox)
    res = {}
    for state0 in (_sources_w1(), _sources_w3()):
        for r in range(1, max_r + 1):
            u = state0.copy()
            c = np.zeros(len(u), dtype=np.int64)
            for _ in range(r):
                c += cost[u].sum(axis=1)
                u = optout[u]
                u = bt.diffuse_batch_w(u, True)
            delta = u
            beta = bopt[delta]
            c += bcost[delta].sum(axis=1)
            lo = bt.diffuse_batch_w(beta, True)
            for _ in range(r - 1):
                c += cost[lo].sum(axis=1)
                lo = optout[lo]
                lo = bt.diffuse_batch_w(lo, True)
            vivant = lo.any(axis=1)
            if vivant.any():
                j = np.nonzero(vivant)[0][np.argmin(c[vivant])]
                res[2 * r] = min(res.get(2 * r, 10 ** 9), int(c[j]))
    return {str(k): v for k, v in sorted(res.items())}


def trails_bct_greedy(sbox, n_rounds=14):
    """Test de stress : chaque couche de S-box est évaluée par la BCT.

    Ce n'est pas un trail boomerang complet ; c'est un modèle où chaque
    S-box active choisit la meilleure transition BCT. Il mesure la facilité
    avec laquelle un trail peut rester sur des entrées BCT élevées.
    """
    _, _, bopt, bcost = _tables_boomerang(sbox)
    res = {}
    for state0 in (_sources_w1(), _sources_w3()):
        state = state0.copy()
        c = np.zeros(len(state), dtype=np.int64)
        for r in range(n_rounds):
            c += bcost[state].sum(axis=1)
            state = bopt[state]
            state = bt.diffuse_batch_w(state, True)
            vivant = state.any(axis=1)
            if vivant.any():
                j = np.nonzero(vivant)[0][np.argmin(c[vivant])]
                res[r + 1] = min(res.get(r + 1, 10 ** 9), int(c[j]))
    return {str(k): v for k, v in sorted(res.items())}


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rounds", type=int, default=14,
                    help="horizon des trails greedy (défaut : 14)")
    ap.add_argument("--w2", type=int, default=0,
                    help="horizon des trails poids 2 exhaustifs (0 = désactivé)")
    ap.add_argument("--no-json", action="store_true",
                    help="ne pas écrire analyse_sbox6.json")
    args = ap.parse_args()

    resultat = {
        "date": "2026-11-08",
        "sbox6": None,
        "brume": None,
        "trails": {},
        "boomerang_trails": {},
        "bct_greedy": {},
        "hypotheses": [
            "trails greedy par position, comme tests/banc_trails.py",
            "poids 1 exhaustif, poids 3 échantillonné (50 000), "
            "poids 2 exhaustif seulement si --w2 > 0",
            "coûts en demi-bits : probabilité 2^(-coût/2) pour un trail "
            "différentiel, corrélation 2^(-coût/2) pour un trail linéaire",
            "modèle boomerang à un seul trail, pas une attaque complète",
        ],
    }

    for sbox, nom in ((SBOX_BRUME, "BRUME"), (SBOX6, "SBOX6")):
        p = proprietes(sbox, nom)
        resultat["brume" if nom == "BRUME" else "sbox6"] = p

        print(f"\n=== {nom} ===")
        print(f"DDT max {p['ddt']['max']}, LAT max {p['lat']['max']} "
              f"(NL {p['lat']['nl']}), BCT max {p['bct']['max']}")
        print("DDT hist :", p["ddt"]["hist"])
        print("LAT hist :", p["lat"]["hist"])
        print("BCT hist :", p["bct"]["hist"])
        print("BCT row max :", p["bct"]["row_max_hist"])
        print("BCT/DDT ratio log2 : moyenne %.3f, max %.3f"
              % (p["bct"]["ratio_bct_ddt_mean_log2"],
                 p["bct"]["ratio_bct_ddt_max_log2"]))
        print("LBCT max %d, UBCT max %d, EBCT max %d, FBCT max %d, "
              "DBCT max %d, DLCT max %d"
              % (p["lbct"]["max_nonzero"], p["ubct"]["max_nonzero"],
                 p["ebct"]["max_nonzero"], p["fbct"]["max_a_neq_b"],
                 p["dbct"]["max_nonzero"], p["dlct"]["max_nonzero"]))
        print("MEDP2 = 2^%.2f, MELP2 = 2^%.2f"
              % (p["park"]["MEDP2_log2"], p["park"]["MELP2_log2"]))

        print("  trails greedy ...", flush=True)
        tr = trails_greedy(sbox, args.rounds, w2_rounds=args.w2)
        resultat["trails"][nom] = tr
        print("  diff :", tr["diff"])
        print("  lin  :", tr["lin"])

        # Détail du meilleur trail au plus grand horizon.
        r = args.rounds
        for kind in ("diff", "lin"):
            meta = tr["meta_diff" if kind == "diff" else "meta_lin"]
            if str(r) in meta and meta[str(r)] is not None:
                source = meta[str(r)]
                detail = detail_trail(sbox, kind, source, r)
                actives = [x["sboxes_actives"] for x in detail]
                total = sum(actives)
                cout = sum(x["cout_demi_bits"] for x in detail)
                valeurs = None
                if kind == "diff":
                    # Coût 4 par S-box à DDT 4, coût 6 par S-box à DDT 2.
                    n2 = (cout - 4 * total) // 2
                    valeurs = {"ddt4": total - n2, "ddt2": n2}
                else:
                    # Coût 2 par S-box à |LAT| 4, coût 0 par S-box à |LAT| 8.
                    n4 = cout // 2
                    valeurs = {"lat4": n4, "lat8": total - n4}
                resultat["trails"][nom][f"detail_{kind}"] = {
                    "source": source,
                    "rounds": r,
                    "sboxes_actives_par_tour": actives,
                    "sboxes_actives_total": total,
                    "couts_par_tour": [x["cout_demi_bits"] for x in detail],
                    "cout_total_demi_bits": cout,
                    "valeurs_sbox": valeurs,
                }
                print(f"  détail {kind} : {total} S-box actives, "
                      f"source {source}")

        print("  trails boomerang (switch BCT) ...", flush=True)
        resultat["boomerang_trails"][nom] = trails_boomerang_switch(sbox, 7)
        print("  ", resultat["boomerang_trails"][nom])

        print("  stress BCT greedy ...", flush=True)
        resultat["bct_greedy"][nom] = trails_bct_greedy(sbox, args.rounds)
        print("  ", resultat["bct_greedy"][nom])

    # Tableau comparatif compact.
    print("\n=== Comparaison ===")
    print(f"{'grandeur':34s} {'BRUME':>12s} {'SBOX6':>12s}")
    for cle, libelle in [
        ("ddt_max", "DDT max"),
        ("lat_max", "LAT max"),
        ("nl", "non-linéarité"),
        ("bct_max", "BCT max"),
        ("bct_mean", "BCT moyenne"),
        ("lbct", "LBCT max"),
        ("ubct", "UBCT max"),
        ("ebct", "EBCT max"),
        ("fbct", "FBCT max"),
        ("dbct", "DBCT max"),
        ("dlct", "DLCT max"),
    ]:
        if cle in ("ddt_max", "lat_max", "nl"):
            a = resultat["brume"]["ddt" if cle.startswith("ddt") else "lat"][
                "max" if cle != "nl" else "nl"]
            b = resultat["sbox6"]["ddt" if cle.startswith("ddt") else "lat"][
                "max" if cle != "nl" else "nl"]
        elif cle in ("bct_max", "bct_mean"):
            k = "max" if cle.endswith("max") else "mean"
            a = resultat["brume"]["bct"][k]
            b = resultat["sbox6"]["bct"][k]
        elif cle in ("lbct", "ubct"):
            a = resultat["brume"][cle]["max_nonzero"]
            b = resultat["sbox6"][cle]["max_nonzero"]
        elif cle == "ebct":
            a = resultat["brume"]["ebct"]["max_nonzero"]
            b = resultat["sbox6"]["ebct"]["max_nonzero"]
        elif cle == "fbct":
            a = resultat["brume"]["fbct"]["max_a_neq_b"]
            b = resultat["sbox6"]["fbct"]["max_a_neq_b"]
        elif cle == "dbct":
            a = resultat["brume"]["dbct"]["max_nonzero"]
            b = resultat["sbox6"]["dbct"]["max_nonzero"]
        else:
            a = resultat["brume"]["dlct"]["max_nonzero"]
            b = resultat["sbox6"]["dlct"]["max_nonzero"]
        print(f"{libelle:34s} {a:>12} {b:>12}")

    if not args.no_json:
        with open(SORTIE, "w", encoding="utf-8") as f:
            json.dump(resultat, f, ensure_ascii=False, indent=1, default=str)
        print("\nRésultats écrits dans", SORTIE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
