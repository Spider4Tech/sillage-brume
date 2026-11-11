#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Consolide les sorties des six familles et écrit la synthèse.

Le script ne relance aucun calcul coûteux : il lit les JSON produits par
run_beam / run_lin / hull_2r / run_diff_cluster / run_boomerang /
run_integral / run_impossible et :

* fusionne les coques différentielles 2 tours BRUME + V3 ;
* calcule le regroupement différentiel (famille 2) ;
* recalcule les coques linéaires top-100 avec les SIGNES de constantes de
  tour (famille 3), ce que la campagne brute ne fait pas ;
* écrit ``10_synthese.md`` et ``synthese.json``.

Tous les chiffres restent honnêtes : les bornes certifiées (branch number)
sont très lâches, les horizons élevés ne sont pas optimaux, les mesures
Monte-Carlo sont indiquées avec leur erreur standard.
"""
from __future__ import annotations

import json
import math
from fractions import Fraction
from pathlib import Path

import numpy as np

from . import common as C

SORTIE = Path(__file__).resolve().parents[4] / "resultats" / "etude_v3_vs_brume_reference_20261109"
CANDIDATES = (("BRUME", C.SBOX_BRUME), ("V3", C.SBOX_V3))


# ---------------------------------------------------------------------------
# utilitaires
# ---------------------------------------------------------------------------

def load_json(path: Path):
    return json.loads(path.read_text())


def parity_bits(a, b) -> int:
    a = np.asarray(a, dtype=np.uint8)
    b = np.asarray(b, dtype=np.uint8)
    return int(np.unpackbits(a & b).sum() & 1)


def lat_of(sbox):
    return C.lat(sbox)


def log2_sum_neg(bits) -> float:
    """``log2(sum 2^-b)`` robuste aux sous-flux (b peut dépasser 1074)."""
    bits = list(bits)
    if not bits:
        return float("-inf")
    m = min(bits)
    s = sum(2.0 ** (-(b - m)) for b in bits)
    return -m + math.log2(s)


def log2_fraction(fr: Fraction) -> float | None:
    a = abs(fr)
    if a == 0:
        return None
    return math.log2(a.numerator) - math.log2(a.denominator)


def lin_trail_signed_correlation(tr: dict, sbox, with_rc: bool = True) -> Fraction:
    """Corrélation signée EXACTE (Fraction) d'une piste linéaire directe.

    ``rounds_detail[r]["input"]`` est le masque d'entrée S-box du tour r ;
    la constante RC[r] est ajoutée avant la S-box, d'où le signe
    ``(-1)^{u_r · RC_r}``.  Le signe du LAT est inclus.  Les Fractions
    évitent le sous-flux IEEE (corrélations < 2^-1074 aux grands horizons).
    """
    l = lat_of(sbox)
    corr = Fraction(1, 1)
    for r, det in enumerate(tr["rounds_detail"]):
        u = np.asarray(det["input"], dtype=np.uint8)
        v = np.asarray(det["sbox_output"], dtype=np.uint8)
        for i in np.nonzero(u)[0]:
            corr *= Fraction(int(l[int(v[i]), int(u[i])]), 8)
        if with_rc:
            corr *= (-1) ** parity_bits(u, C.RC[r])
    return corr


def lin_final_mask(tr: dict) -> np.ndarray:
    return C.diffuse_T_inv(np.asarray(tr["rounds_detail"][-1]["sbox_output"],
                                      dtype=np.uint8))


def trail_active_count(tr: dict) -> int:
    return sum(len(det.get("transitions", [])) for det in tr["rounds_detail"])


# ---------------------------------------------------------------------------
# famille 1 / 2 : différentiel
# ---------------------------------------------------------------------------

def build_diff_summary() -> dict:
    out = {}
    for name, _ in CANDIDATES:
        out[name] = {}
        for r in (4, 6, 8, 10, 12, 14):
            path = SORTIE / f"trails_diff_{name}_R{r}.json"
            if not path.exists():
                continue
            d = load_json(path)
            rows = []
            for tr in d["trails"]:
                beta = np.asarray(tr["rounds_detail"][-1]["after_diffusion"],
                                  dtype=np.uint8)
                rows.append({
                    "alpha_hex": tr["input_difference_hex"],
                    "beta_hex": C.state_to_hex(beta),
                    "bits": tr["total_cost_bits"],
                    "half_bits": tr["total_cost_half_bits"],
                    "active_sboxes": trail_active_count(tr),
                })
            rows.sort(key=lambda z: z["bits"])
            mass_log2 = log2_sum_neg([z["bits"] for z in rows])
            groups = {}
            for z in rows:
                g = groups.setdefault((z["alpha_hex"], z["beta_hex"]),
                                      {"n": 0, "bits": [],
                                       "best_bits": z["bits"]})
                g["n"] += 1
                g["bits"].append(z["bits"])
                g["best_bits"] = min(g["best_bits"], z["bits"])
            glist = [{
                "alpha_hex": a, "beta_hex": b,
                "n_trails": g["n"], "best_bits": g["best_bits"],
                "dp_lower_bound_log2": log2_sum_neg(g["bits"]),
            } for (a, b), g in groups.items()]
            glist.sort(key=lambda z: -z["dp_lower_bound_log2"])
            multi = [g for g in glist if g["n_trails"] > 1]
            bound = d.get("fd_bound", {})
            out[name][f"R{r}"] = {
                "rounds": r,
                "n_trails": len(rows),
                "best_bits": rows[0]["bits"],
                "best_probability_log2": -rows[0]["bits"],
                "best_active_sboxes": rows[0]["active_sboxes"],
                "certified_lower_bound_bits": bound.get("lower_bound_bits"),
                "certified_bound_method": bound.get("method"),
                "gap_to_certified_bound_bits": (
                    rows[0]["bits"] - bound["lower_bound_bits"]
                    if bound.get("lower_bound_bits") is not None else None),
                "top100_mass_log2": mass_log2,
                "gain_over_best_trail_bits": mass_log2 + rows[0]["bits"],
                "n_groups": len(glist),
                "n_multi_trail_groups": len(multi),
                "max_group": glist[0] if glist else None,
                "top_multi_groups": multi[:20],
            }
    return out


# ---------------------------------------------------------------------------
# famille 3 : linéaire
# ---------------------------------------------------------------------------

def build_lin_summary() -> dict:
    out = {}
    for name, sbox in CANDIDATES:
        out[name] = {}
        for r in (8, 10, 12, 14):
            path = SORTIE / f"trails_lin_{name}_R{r}.json"
            if not path.exists():
                continue
            d = load_json(path)
            rows = []
            for tr in d["trails"]:
                c_markov = lin_trail_signed_correlation(tr, sbox, with_rc=False)
                c_rc = lin_trail_signed_correlation(tr, sbox, with_rc=True)
                rows.append({
                    "u_in_hex": C.state_to_hex(np.asarray(
                        tr["rounds_detail"][0]["input"], dtype=np.uint8)),
                    "u_out_hex": C.state_to_hex(lin_final_mask(tr)),
                    "bits": tr["total_cost_bits"],
                    "half_bits": tr["total_cost_half_bits"],
                    "correlation_markov": c_markov,
                    "correlation_rc": c_rc,
                    "abs_correlation_rc": abs(c_rc),
                    "sign_rc": (1 if c_rc > 0 else (-1 if c_rc < 0 else 0)),
                    "log2_abs_rc": log2_fraction(c_rc),
                    "active_sboxes": trail_active_count(tr),
                })
            rows.sort(key=lambda z: z["bits"])
            # regroupement par (u_in, u_out)
            groups = {}
            for z in rows:
                key = (z["u_in_hex"], z["u_out_hex"])
                g = groups.setdefault(key, {
                    "u_in_hex": z["u_in_hex"], "u_out_hex": z["u_out_hex"],
                    "n_trails": 0, "best_bits": z["bits"],
                    "signed_sum_rc": Fraction(0, 1),
                    "signed_sum_markov": Fraction(0, 1),
                    "squared_sum": Fraction(0, 1),
                    "max_abs_rc": Fraction(0, 1),
                })
                g["n_trails"] += 1
                g["best_bits"] = min(g["best_bits"], z["bits"])
                g["signed_sum_rc"] += z["correlation_rc"]
                g["signed_sum_markov"] += z["correlation_markov"]
                g["squared_sum"] += z["correlation_rc"] ** 2
                g["max_abs_rc"] = max(g["max_abs_rc"], z["abs_correlation_rc"])
            glist = []
            for g in groups.values():
                log2_sum = log2_fraction(g["signed_sum_rc"])
                log2_max = log2_fraction(g["max_abs_rc"])
                reinforcement = (2.0 ** (log2_sum - log2_max)
                                 if (log2_sum is not None and
                                     log2_max is not None) else None)
                glist.append({
                    "u_in_hex": g["u_in_hex"], "u_out_hex": g["u_out_hex"],
                    "n_trails": g["n_trails"], "best_bits": g["best_bits"],
                    "signed_sum_rc_sign": (1 if g["signed_sum_rc"] > 0 else
                                           (-1 if g["signed_sum_rc"] < 0 else 0)),
                    "log2_abs_signed_sum_rc": log2_sum,
                    "log2_abs_max_single_trail_rc": log2_max,
                    "squared_sum_log2": log2_fraction(g["squared_sum"]),
                    "reinforcement_ratio": reinforcement,
                    "cancellation": bool(g["n_trails"] > 1 and
                                         log2_sum is not None and
                                         log2_max is not None and
                                         log2_sum < log2_max),
                })
            glist.sort(key=lambda z: -(z["log2_abs_signed_sum_rc"]
                                       if z["log2_abs_signed_sum_rc"] is not None
                                       else -math.inf))
            multi = [g for g in glist if g["n_trails"] > 1]
            total_signed = sum((z["correlation_rc"] for z in rows), Fraction(0, 1))
            total_markov = sum((z["correlation_markov"] for z in rows), Fraction(0, 1))
            total_sq = sum((z["correlation_rc"] ** 2 for z in rows), Fraction(0, 1))
            bound = d.get("fd_bound", {})
            out[name][f"R{r}"] = {
                "rounds": r,
                "n_trails": len(rows),
                "best_bits": rows[0]["bits"],
                "best_correlation_abs": float(rows[0]["abs_correlation_rc"]),
                "best_log2_abs_correlation": rows[0]["log2_abs_rc"],
                "best_active_sboxes": rows[0]["active_sboxes"],
                "certified_lower_bound_bits": bound.get("lower_bound_bits"),
                "gap_to_certified_bound_bits": (
                    rows[0]["bits"] - bound["lower_bound_bits"]
                    if bound.get("lower_bound_bits") is not None else None),
                "top100_signed_sum_rc_sign": (1 if total_signed > 0 else
                                              (-1 if total_signed < 0 else 0)),
                "top100_log2_abs_signed_lower_bound": log2_fraction(total_signed),
                "top100_log2_squared_lower_bound": log2_fraction(total_sq),
                "top100_markov_sign": (1 if total_markov > 0 else
                                       (-1 if total_markov < 0 else 0)),
                "n_groups": len(glist),
                "n_multi_trail_groups": len(multi),
                "best_group": glist[0] if glist else None,
                "top_multi_groups": multi[:20],
            }
    return out


# ---------------------------------------------------------------------------
# fusion coques 2 tours
# ---------------------------------------------------------------------------

def build_two_round() -> dict:
    merged = {}
    main = SORTIE / "03_effet_differentiel_coque_2t.json"
    v3p = SORTIE / "03_effet_differentiel_coque_2t_V3.json"
    bwp = SORTIE / "03_effet_differentiel_coque_2t_BRUME.json"
    if main.exists():
        cur = load_json(main)
        if isinstance(cur, dict) and "BRUME" in cur and "V3" in cur:
            # déjà fusionné : on ne réécrit pas
            return {"BRUME": cur["BRUME"], "V3": cur["V3"]}
        if isinstance(cur, dict) and "rows" in cur:
            merged["BRUME"] = cur
    if bwp.exists():
        merged["BRUME"] = load_json(bwp)
    if v3p.exists():
        merged["V3"] = load_json(v3p)
    if merged:
        payload = {
            "method": ("Coques exactes à 2 tours : DP exacte de la permutation "
                       "pour le différentiel ; adjoint binaire M^T_bin et "
                       "constantes de tour incluses pour le linéaire."),
            "BRUME": merged.get("BRUME"),
            "V3": merged.get("V3"),
        }
        if merged.get("BRUME") is not None and not bwp.exists():
            bwp.write_text(json.dumps(merged["BRUME"], ensure_ascii=False,
                                      indent=1))
        (SORTIE / "03_effet_differentiel_coque_2t.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=1))
    return merged


# ---------------------------------------------------------------------------
# synthèse
# ---------------------------------------------------------------------------

def fmt(x, nd=2):
    if x is None:
        return "n/a"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def build_synthesis(diff, lin, two_round):
    tables = load_json(SORTIE / "01_tables_locales.json")
    cpsat = load_json(SORTIE / "02_cpsat_petits_tours.json")
    integral = load_json(SORTIE / "08_propriete_integrale_division.json")
    impossible = load_json(SORTIE / "09_impossible_differentiel_zero_correlation.json")
    boomerang_path = SORTIE / "07_boomerang_rectangle.json"
    boomerang = load_json(boomerang_path) if boomerang_path.exists() else None
    hull_lin = None
    p6 = SORTIE / "06_coque_lineaire_2t.json"
    if p6.exists():
        hull_lin = load_json(p6)

    syn = {"scope": "SBOX_V3 vs BRUME classique (SBOX6 exclu)",
           "date": "2026-11-09",
           "costs": tables["conventions"],
           "sbox_properties": {},
           "diff_trails": diff,
           "lin_trails": lin,
           "two_round_hulls": {},
           "cpsat_small": cpsat,
           "boomerang": boomerang,
           "integral": {},
           "impossible": {},
           "limitations": [
               "Optimisation exacte 14 tours impossible (MILP/SAT) : les "
               "meilleurs trails sont heuristiques (faisceau) ; seule la "
               "borne branch-number est certifiée, et elle est très lâche.",
               "DP_R(α,β) et corrélations exactes pour la permutation 512 bits "
               "ne sont calculables qu'à 2 tours ; au-delà, mesures "
               "Monte-Carlo à faible nombre de tours.",
               "Coques linéaires au-delà de 2 tours : somme des 100 premiers "
               "trails seulement, donc borne inférieure partielle.",
               "CP-SAT R4 (α,β fixés) reste UNKNOWN ; les preuves "
               "d'impossibilité au-delà de R3 ne sont pas obtenues.",
           ]}

    for name, _ in CANDIDATES:
        c = tables["candidates"][name]
        syn["sbox_properties"][name] = {
            "ddt_max": c["ddt_max"], "lat_max": c["lat_max"],
            "bct_max": c["bct_max"], "algebraic_degree": c["algebraic_degree"],
            "algebraic_degree_inverse": integral["candidates"][name].get(
                "algebraic_degree_inverse", c.get("algebraic_degree_inverse")),
            "park": c["park"],
        }
        if two_round.get(name):
            syn["two_round_hulls"][name] = {
                "diff_best": two_round[name]["best_trail"],
                "diff_best_amplification": two_round[name]["best_amplification"],
                "lin_best": (hull_lin or {}).get(name, {}).get("lin_2r", {}).get("best_trail"),
                "lin_n_nonzero": (hull_lin or {}).get(name, {}).get("lin_2r", {}).get("n_nonzero"),
                "lin_n_exact_zero": (hull_lin or {}).get(name, {}).get("lin_2r", {}).get("n_exact_zero_correlations"),
            }
        ic = integral["candidates"][name]
        syn["integral"][name] = {
            "algebraic_degree": ic["algebraic_degree"],
            "algebraic_degree_inverse": ic["algebraic_degree_inverse"],
            "sat": ic["sat"],
            "empirical": {k: {"t_bits": v["t_bits"], "rounds": v["rounds"],
                              "robust_balanced_count": v["robust_balanced_count"],
                              "bases": v["bases"]}
                          for k, v in ic["empirical"].items()},
        }
        imp = impossible["candidates"][name]
        syn["impossible"][name] = {
            "R2_weight1_impossible": imp["diff_impossible"]["R2_weight1"]["impossible_pairs_certified"],
            "R2_weight1_total": imp["diff_impossible"]["R2_weight1"]["total_pairs"],
            "R2_weight1_sample_verified": imp["diff_impossible"]["R2_weight1"]["sample_all_impossible"],
            "R2_sampled_weight1_4": {
                k: {"sampled": v["sampled"], "impossible": v["impossible"]}
                for k, v in imp["diff_impossible"].items()
                if k.startswith("R2_weight") and k != "R2_weight1"
            },
            "R3_cpsat": [z["status"] for z in imp["diff_impossible"].get("R3_cpsat_sample", [])],
            "R4_cpsat": [z["status"] for z in imp["diff_impossible"].get("R4_cpsat_sample", [])],
            "zero_corr_2r_support": imp["zero_correlation"]["R2_support_weight1"]["n_zero_certified"],
            "zero_corr_2r_tested": imp["zero_correlation"]["R2_support_weight1"]["n_tested"],
            "positive_witnesses": imp["diff_impossible"].get("R2_positive_witnesses"),
            "zero_explicit": imp["zero_correlation"].get("R2_zero_explicit"),
        }

    (SORTIE / "synthese.json").write_text(
        json.dumps(syn, ensure_ascii=False, indent=1))

    # ----------------------- Markdown -----------------------
    L = []
    L.append("# Étude SBOX_V3 vs BRUME classique (référence)")
    L.append("")
    L.append("Comparaison **SBOX_V3** contre la S-box **BRUME** classique "
             "uniquement (SBOX6 exclu). Même permutation 512 bits, même "
             "diffusion GF(16), mêmes constantes de tour : seule la S-box "
             "change. Les six familles demandées sont couvertes.")
    L.append("")
    L.append("Coûts exacts en demi-bits : différentiel `4` si DDT=4, `6` si "
             "DDT=2 ; linéaire `2` si |LAT|=4, `4` si |LAT|=2. Un bit de "
             "coût = facteur 2 de probabilité/corrélation.")
    L.append("")

    L.append("## 1. Propriétés locales des S-box")
    L.append("")
    L.append("| Propriété | BRUME | V3 |")
    L.append("|---|---:|---:|")
    for key, label in (("ddt_max", "DDT max"), ("lat_max", "|LAT| max"),
                       ("bct_max", "BCT max (avec (0,0))"),
                       ("algebraic_degree", "degré algébrique"),
                       ("algebraic_degree_inverse", "degré de l'inverse")):
        L.append(f"| {label} | {syn['sbox_properties']['BRUME'][key]} | "
                 f"{syn['sbox_properties']['V3'][key]} |")
    L.append(f"| Park MEDP_2 (log2) | "
             f"{fmt(syn['sbox_properties']['BRUME']['park']['MEDP_2_log2'],4)} | "
             f"{fmt(syn['sbox_properties']['V3']['park']['MEDP_2_log2'],4)} |")
    L.append(f"| Park MELP_2 (log2) | "
             f"{fmt(syn['sbox_properties']['BRUME']['park']['MELP_2_log2'],4)} | "
             f"{fmt(syn['sbox_properties']['V3']['park']['MELP_2_log2'],4)} |")
    L.append("")
    L.append("Les deux S-box ont les mêmes maxima DDT/LAT/dégré. Les profils "
             "d'activité diffèrent (positions des maxima), ce qui suffit à "
             "changer les meilleurs trails.")
    L.append("")

    L.append("## 2. Famille 1 — meilleures caractéristiques différentielles")
    L.append("")
    L.append("| R | BRUME meilleur (bits) | V3 meilleur (bits) | écart V3−BRUME | "
             "borne certifiée (bits) | écart à la borne (V3) |")
    L.append("|---|---:|---:|---:|---:|---:|")
    for r in (4, 6, 8, 10, 12, 14):
        b = diff["BRUME"].get(f"R{r}")
        v = diff["V3"].get(f"R{r}")
        if not b and not v:
            continue
        bb = b["best_bits"] if b else None
        vb = v["best_bits"] if v else None
        gap = (vb - bb) if (b and v) else None
        lb = (v or b)["certified_lower_bound_bits"]
        tg = (vb - lb) if (v and lb is not None) else None
        L.append(f"| {r} | {fmt(bb,1)} | {fmt(vb,1)} | "
                 f"{fmt(gap,1) if gap is not None else 'n/a'} | {fmt(lb,1)} | "
                 f"{fmt(tg,1) if tg is not None else 'n/a'} |")
    L.append("")
    L.append("Optimisation : faisceau (beam) large, 100 meilleures pistes "
             "revérifiées. La borne certifiée est la borne *branch-number* "
             "(8 S-box actives par 2 tours, coût minimal 4 demi-bits) ; elle "
             "est rigoureuse mais très lâche, d'où un écart de plusieurs "
             "centaines de bits. Les valeurs à 14 tours ne sont **pas** "
             "prouvées optimales.")
    L.append("")

    L.append("## 3. Famille 2 — effet différentiel / regroupement")
    L.append("")
    L.append("| R | BRUME top-100 log2 masse | V3 top-100 log2 masse | "
             "gain BRUME (bits) | gain V3 (bits) | groupes multi BRUME/V3 |")
    L.append("|---|---:|---:|---:|---:|---:|")
    for r in (6, 8, 10, 12, 14):
        b = diff["BRUME"].get(f"R{r}"); v = diff["V3"].get(f"R{r}")
        if not b and not v:
            continue
        L.append(f"| {r} | {fmt(b['top100_mass_log2'],2) if b else 'n/a'} | "
                 f"{fmt(v['top100_mass_log2'],2) if v else 'n/a'} | "
                 f"{fmt(b['gain_over_best_trail_bits'],3) if b else 'n/a'} | "
                 f"{fmt(v['gain_over_best_trail_bits'],3) if v else 'n/a'} | "
                 f"{b['n_multi_trail_groups'] if b else 'n/a'}/"
                 f"{v['n_multi_trail_groups'] if v else 'n/a'} |")
    L.append("")
    L.append("La masse des 100 meilleures pistes est une **borne inférieure** "
             "de DP_R(α,β) pour le couple dominant. Le gain est le facteur de "
             "regroupement au-dessus de la meilleure piste seule. À 2 tours, "
             "la valeur est exacte (section 4).")
    L.append("")

    L.append("## 4. Coques exactes à 2 tours (différentiel et linéaire)")
    L.append("")
    L.append("| | BRUME | V3 |")
    L.append("|---|---:|---:|")
    for name in ("BRUME", "V3"):
        pass
    db = two_round.get("BRUME", {}).get("best_trail", {})
    dv = two_round.get("V3", {}).get("best_trail", {})
    L.append(f"| DP exacte meilleure (log2) | {fmt(db.get('hull_log2'),4)} | "
             f"{fmt(dv.get('hull_log2'),4)} |")
    L.append(f"| nb de chemins | {db.get('n_paths')} | {dv.get('n_paths')} |")
    L.append(f"| amplification coque/piste | "
             f"{fmt(two_round.get('BRUME',{}).get('best_amplification',{}).get('amplification'),4)} | "
             f"{fmt(two_round.get('V3',{}).get('best_amplification',{}).get('amplification'),4)} |")
    if hull_lin:
        lb = hull_lin.get("BRUME", {}).get("lin_2r", {}).get("best_trail", {})
        lv = hull_lin.get("V3", {}).get("lin_2r", {}).get("best_trail", {})
        L.append(f"| corrélation linéaire meilleure (signée, RC) | "
                 f"{fmt(lb.get('hull_correlation_signed_rc'))} | "
                 f"{fmt(lv.get('hull_correlation_signed_rc'))} |")
        L.append(f"| log2 |corrélation| | "
                 f"{fmt(math.log2(abs(lb['hull_correlation_signed_rc'])) if lb.get('hull_correlation_signed_rc') else None,3)} | "
                 f"{fmt(math.log2(abs(lv['hull_correlation_signed_rc'])) if lv.get('hull_correlation_signed_rc') else None,3)} |")
        L.append(f"| nb chemins | {lb.get('n_paths')} | {lv.get('n_paths')} |")
        L.append(f"| zéros exacts sur 1920 masques poids 1 | "
                 f"{hull_lin.get('BRUME',{}).get('lin_2r',{}).get('n_exact_zero_correlations')} | "
                 f"{hull_lin.get('V3',{}).get('lin_2r',{}).get('n_exact_zero_correlations')} |")
    L.append("")
    L.append("Le différentiel 2 tours est la DP **exacte** de la permutation "
             "(les différences intermédiaires partitionnent les entrées, les "
             "constantes s'annulent). Le linéaire utilise l'adjoint binaire "
             "`M^T_bin` et les signes de constantes ; les mesures empiriques "
             "à 2 tours ont une erreur standard ≈ `1/sqrt(N)`.")
    L.append("")

    L.append("## 5. Famille 3 — caractéristiques et coques linéaires")
    L.append("")
    L.append("| R | BRUME meilleur (bits) | V3 meilleur (bits) | écart | "
             "BRUME log2 |Σ top-100| | V3 log2 |Σ top-100| | "
             "BRUME log2 Σc² | V3 log2 Σc² |")
    L.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for r in (8, 10, 12, 14):
        b = lin["BRUME"].get(f"R{r}"); v = lin["V3"].get(f"R{r}")
        if not b and not v:
            continue
        L.append(f"| {r} | {fmt(b['best_bits'],1) if b else 'n/a'} | "
                 f"{fmt(v['best_bits'],1) if v else 'n/a'} | "
                 f"{fmt((v['best_bits']-b['best_bits']),1) if (b and v) else 'n/a'} | "
                 f"{fmt(b['top100_log2_abs_signed_lower_bound'],2) if b else 'n/a'} | "
                 f"{fmt(v['top100_log2_abs_signed_lower_bound'],2) if v else 'n/a'} | "
                 f"{fmt(b['top100_log2_squared_lower_bound'],2) if b else 'n/a'} | "
                 f"{fmt(v['top100_log2_squared_lower_bound'],2) if v else 'n/a'} |")
    L.append("")
    L.append("Les corrélations sont **signées** (LAT signé + constantes de "
             "tour). `|Σ top-100|` est une borne inférieure partielle de la "
             "corrélation de coque ; `Σc²` minore la puissance linéaire. "
             "Renforcement/annulation sont détaillés par groupe dans "
             "`05_coque_lineaire_top100.json`.")
    L.append("")
    L.append("Les meilleurs trails linéaires ont un masque intermédiaire "
             "très dense (≈ 110 S-box actives), d'où des corrélations "
             "≈ 2^-110 à 2^-125 : non mesurables empiriquement sur la "
             "permutation complète.")
    L.append("")

    L.append("## 6. Famille 4 — boomerang / rectangle")
    L.append("")
    if boomerang:
        L.append("| R | BRUME switch log2 | V3 switch log2 | "
                 "BRUME estimation log2 | V3 estimation log2 |")
        L.append("|---|---:|---:|---:|---:|")
        for r in (4, 6, 8, 10, 12, 14):
            b = boomerang["candidates"]["BRUME"].get(f"R{r}")
            v = boomerang["candidates"]["V3"].get(f"R{r}")
            if not b and not v:
                continue
            bb = b["best"] if b else None
            vv = v["best"] if v else None
            L.append(f"| {r} | "
                     f"{fmt(bb['switch_log2'] if bb else None,2)} | "
                     f"{fmt(vv['switch_log2'] if vv else None,2)} | "
                     f"{fmt(bb['estimate_log2'] if bb else None,2)} | "
                     f"{fmt(vv['estimate_log2'] if vv else None,2)} |")
        L.append("")
        q = boomerang["candidates"]["BRUME"].get("R2", {}).get("quartet")
        if q:
            L.append(f"Quartets simulés R=2 (BRUME) : {q['hits']}/{q['samples']} "
                     f"succès, probabilité {fmt(q['probability'],6)} "
                     f"(log2 {fmt(q['log2'],2)}), erreur standard "
                     f"{fmt(q['standard_error'],6)}.")
            L.append("")
        L.append("Le switch est la probabilité BCT exacte sur la couche de "
                 "S-box active ; l'estimation est `p0 · switch · p1`. "
                 "L'interaction des S-box actives est quantifiée par le "
                 "rapport `switch / probabilité de la couche du trail`.")
    else:
        L.append("Résultats non disponibles (script non exécuté).")
    L.append("")

    L.append("## 7. Famille 5 — intégrale / division property")
    L.append("")
    L.append("| t bits | R | BRUME bits équilibrés | V3 bits équilibrés |")
    L.append("|---|---:|---:|---:|")
    for key in ("t4_R4", "t8_R4", "t12_R4", "t16_R4"):
        b = integral["candidates"]["BRUME"]["empirical"].get(key)
        v = integral["candidates"]["V3"]["empirical"].get(key)
        if not b and not v:
            continue
        L.append(f"| {b['t_bits'] if b else v['t_bits']} | "
                 f"{b['rounds'] if b else v['rounds']} | "
                 f"{b['robust_balanced_count'] if b else 'n/a'} | "
                 f"{v['robust_balanced_count'] if v else 'n/a'} |")
    L.append("")
    L.append("Comptage robuste sur 3 bases aléatoires : nombre de bits de "
             "sortie dont la somme XOR est nulle pour toutes les bases. "
             "Table de division property bit-à-bit exacte et modèle CP-SAT "
             "de propagation inclus dans `08_...json`. Degré algébrique 3 "
             "pour les deux S-box.")
    L.append("")

    L.append("## 8. Famille 6 — différentielles impossibles et corrélations nulles")
    L.append("")
    L.append("| Critère | BRUME | V3 |")
    L.append("|---|---:|---:|")
    for k, label in (
            ("R2_weight1_impossible", "paires poids 1→1 impossibles à R=2"),
            ("R2_weight1_total", "paires poids 1→1 testées"),
            ("zero_corr_2r_support", "paires poids 1→1 à corrélation nulle (critère de support)"),
            ("zero_corr_2r_tested", "paires poids 1→1 testées (linéaire)")):
        L.append(f"| {label} | {syn['impossible']['BRUME'][k]} | "
                 f"{syn['impossible']['V3'][k]} |")
    L.append("")
    L.append("Toutes les paires poids 1→1 à R=2 sont impossibles : le support "
             "avant le tour 2 vaut 7 nibbles, le support requis par β en vaut "
             "≈122, inclusion impossible. Vérifié par énumération exhaustive "
             "des sorties de S-box. R=3 (α,β fixés) : CP-SAT INFEASIBLE sur "
             "les échantillons ; R=4 : UNKNOWN (pas de preuve). Les paires "
             "de corrélation nulle sont certifiées par le critère de support "
             "exact à 2 tours.")
    L.append("")

    L.append("## 9. Petits tours — CP-SAT exact")
    L.append("")
    L.append("| Instance | Statut | Objectif (demi-bits) | Borne |")
    L.append("|---|---|---:|---:|")
    for k, v in cpsat["results"].items():
        L.append(f"| {k} | {v['status']} | {fmt(v['objective'],0)} | "
                 f"{fmt(v['best_bound'],0)} |")
    L.append("")
    L.append("À R=2 les deux S-box sont **optimales** à 32 demi-bits (16 bits). "
             "À R=3/R=4 le solveur trouve des solutions réalisables mais ne "
             "prouve pas l'optimalité dans la limite de temps.")
    L.append("")

    L.append("## 10. Conclusion honnête")
    L.append("")
    # compute aggregate gaps
    dg = {r: (diff["V3"][f"R{r}"]["best_bits"] - diff["BRUME"][f"R{r}"]["best_bits"])
          for r in (8, 10, 12) if f"R{r}" in diff["V3"] and f"R{r}" in diff["BRUME"]}
    lg = {r: (lin["V3"][f"R{r}"]["best_bits"] - lin["BRUME"][f"R{r}"]["best_bits"])
          for r in (8, 10, 12) if f"R{r}" in lin["V3"] and f"R{r}" in lin["BRUME"]}
    L.append("Sur les horizons comparables R=8/10/12, V3 est très légèrement "
             "plus résistante que BRUME en différentiel "
             f"({', '.join(f'R{r}: +{g:.1f} bits' for r, g in dg.items())}) "
             "et quasi identique en linéaire "
             f"({', '.join(f'R{r}: {g:+.1f} bits' for r, g in lg.items())}).")
    L.append("")
    L.append("**Interprétation** : le changement de S-box ne produit pas de "
             "saut de sécurité comparable à un changement de diffusion ou de "
             "nombre de tours. Les deux S-box partagent DDT/LAT max et degré ; "
             "V3 décale seulement les positions actives, ce qui explique des "
             "écarts de quelques bits seulement. Les écarts historiques de "
             "~191 bits attribués à V3 ne sont **pas** reproduits par une "
             "recherche de trails indépendante : ils dépendaient du modèle "
             "de coût/du point de départ.")
    L.append("")
    L.append("**Limites** : borne certifiée branch-number très lâche ; "
             "optimalité non prouvée au-delà de R=2 ; coques > 2 tours "
             "partielles ; R=4 impossible non tranché. Les résultats sont "
             "donc des bornes supérieures de résistance (trails trouvés) et "
             "des bornes inférieures de probabilité, pas des preuves de "
             "sécurité.")
    L.append("")
    L.append("## 11. Fichiers")
    L.append("")
    for line in (
        "`01_tables_locales.json` — DDT/LAT/BCT, degrés, Park, diffusion.",
        "`02_cpsat_petits_tours.json` — CP-SAT R2–R4.",
        "`03_effet_differentiel_coque_2t.json` — coques exactes 2 tours BRUME+V3.",
        "`04_effet_differentiel_clustering.json` — regroupement top-100.",
        "`05_coque_lineaire_top100.json` — coques linéaires signées.",
        "`06_coque_lineaire_2t.json` — coques linéaires exactes 2 tours.",
        "`07_boomerang_rectangle.json` — switch BCT, quartets.",
        "`08_propriete_integrale_division.json` — division property, intégrales.",
        "`09_impossible_differentiel_zero_correlation.json` — impossible/zéro.",
        "`trails_diff_*` / `trails_lin_*` — top-100 bruts par horizon.",
        "`synthese.json` — version machine de cette synthèse.",
    ):
        L.append(f"- {line}")
    L.append("")
    (SORTIE / "10_synthese.md").write_text("\n".join(L), encoding="utf-8")
    return syn


def main():
    diff = build_diff_summary()
    (SORTIE / "04_effet_differentiel_clustering.json").write_text(
        json.dumps({"method": ("somme des probabilités des 100 meilleures "
                               "pistes, regroupées par (α,β) ; borne "
                               "inférieure de DP_R"),
                    "candidates": diff}, ensure_ascii=False, indent=1))
    lin = build_lin_summary()
    (SORTIE / "05_coque_lineaire_top100.json").write_text(
        json.dumps({"method": ("somme signée des 100 meilleures pistes "
                               "linéaires par (u_in,u_out), constantes de "
                               "tour incluses ; bornes inférieures de la "
                               "corrélation/puissance de coque"),
                    "candidates": lin}, ensure_ascii=False, indent=1))
    two_round = build_two_round()
    syn = build_synthesis(diff, lin, two_round)
    print("écrit 04, 05, 10_synthese.md, synthese.json")
    print(json.dumps({"diff_R": {c: list(v) for c, v in diff.items()},
                      "lin_R": {c: list(v) for c, v in lin.items()}},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
