#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyse des CSV du banc BRUME-512 apparié.

- Agrège les 2x2 par graine/tour/nibble en sommant les combinaisons.
- Réalise les comparaisons appariées par McNemar (correction de continuité
  pour les compteurs fréquents ; binomial exact pour les événements rares).
- Calcule aussi, à titre de diagnostic, les écarts au modèle marginal p=1/16.
- Applique Bonferroni à des familles de tests déclarées séparément.

Bibliothèque standard Python uniquement.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

PAIR_ORDER = (
    "BRUME_vs_SBOX6",
    "BRUME_vs_SBOX_V3",
    "SBOX6_vs_SBOX_V3",
)
PAIR_MEMBERS = {
    "BRUME_vs_SBOX6": ("BRUME", "SBOX6"),
    "BRUME_vs_SBOX_V3": ("BRUME", "SBOX_V3"),
    "SBOX6_vs_SBOX_V3": ("SBOX6", "SBOX_V3"),
}
CANDIDATES = ("BRUME", "SBOX6", "SBOX_V3")
ALPHA_FAMILY = 1.0 / 1024.0


def normal_two_sided_p(z: float) -> float:
    return math.erfc(abs(z) / math.sqrt(2.0))


def normal_threshold(family_size: int) -> float:
    """z tel que P(|Z|>=z) = alpha_family / family_size."""
    target = ALPHA_FAMILY / max(1, family_size)
    lo, hi = 0.0, 16.0
    for _ in range(100):
        mid = (lo + hi) / 2.0
        if normal_two_sided_p(mid) > target:
            lo = mid
        else:
            hi = mid
    return hi


def mcnemar_asymptotic(n01: int, n10: int) -> Tuple[float, float]:
    """McNemar bilatéral avec correction de continuité."""
    discordant = n01 + n10
    difference = n10 - n01
    if discordant == 0 or difference == 0:
        return 0.0, 1.0
    corrected = max(0.0, abs(difference) - 1.0)
    z = math.copysign(corrected / math.sqrt(discordant), difference)
    return z, normal_two_sided_p(z)


def exact_binomial_two_sided(n01: int, n10: int) -> float:
    """p exact bilatéral de McNemar, conditionnel aux discordances."""
    n = n01 + n10
    if n == 0:
        return 1.0
    tail = min(n01, n10)
    # Calcul log-somme-exp de 2 * P(Bin(n, 1/2) <= tail).
    logs = [
        math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
        - n * math.log(2.0)
        for k in range(tail + 1)
    ]
    maximum = max(logs)
    log_sum = maximum + math.log(sum(math.exp(v - maximum) for v in logs))
    return min(1.0, 2.0 * math.exp(log_sum))


def mcnemar(n01: int, n10: int, exact_cutoff: int = 20000) -> Tuple[float, float, str]:
    discordant = n01 + n10
    if discordant <= exact_cutoff:
        z, _ = mcnemar_asymptotic(n01, n10)
        return z, exact_binomial_two_sided(n01, n10), "binomial_exact"
    z, p = mcnemar_asymptotic(n01, n10)
    return z, p, "asymptotic_cc"


def read_csv_files(paths: Iterable[Path], required: Tuple[str, ...]):
    for path in sorted(paths):
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError(f"CSV vide ou sans en-tête: {path}")
            missing = [name for name in required if name not in reader.fieldnames]
            if missing:
                raise ValueError(f"Colonnes manquantes dans {path}: {missing}")
            for line_no, row in enumerate(reader, start=2):
                try:
                    yield path, line_no, row
                except Exception as exc:  # pragma: no cover - garde-fou
                    raise ValueError(f"{path}:{line_no}: {exc}") from exc


def as_int(row: dict, name: str, path: Path, line: int) -> int:
    try:
        return int(row[name])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{path}:{line}: entier invalide pour {name}: {row.get(name)!r}") from exc


def write_csv(path: Path, fieldnames: List[str], rows: Iterable[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def fmt_p(p: float) -> str:
    if p == 0.0:
        return "<1e-300"
    return f"{p:.3e}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("result_dir", type=Path, help="Dossier produit par run_comparaison_appariee.sh")
    args = ap.parse_args()
    root = args.result_dir.resolve()
    if not root.is_dir():
        ap.error(f"dossier introuvable: {root}")

    meta_path = root / "campaign_metadata.json"
    metadata = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    zero_paths = [
        p for p in root.glob("paired_zero_*.csv")
        if re.fullmatch(r"paired_zero_[0-9a-fA-F]{64}\.csv", p.name)
    ]
    exact_paths = [
        p for p in root.glob("paired_exact_*.csv")
        if re.fullmatch(r"paired_exact_[0-9a-fA-F]{64}\.csv", p.name)
    ]
    if not zero_paths or not exact_paths:
        ap.error("il faut au moins un paired_zero_*.csv et un paired_exact_*.csv")

    # key -> [n00,n01,n10,n11], N total, set of combinations
    zero_agg = defaultdict(lambda: {"counts": [0, 0, 0, 0], "N": 0, "combos": set()})
    exact_agg = defaultdict(lambda: {"counts": [0, 0, 0, 0], "N": 0, "combos": set()})
    seeds = set()
    rounds_seen = set()
    combos_seen = set()

    zero_required = (
        "seed_hex", "round", "combination", "pair", "variant_a", "variant_b",
        "output_nibble", "quartets", "n00", "n01", "n10", "n11",
    )
    for path, line, row in read_csv_files(zero_paths, zero_required):
        seed = row["seed_hex"].lower()
        rnd = as_int(row, "round", path, line)
        combo = as_int(row, "combination", path, line)
        nibble = as_int(row, "output_nibble", path, line)
        N = as_int(row, "quartets", path, line)
        counts = [as_int(row, k, path, line) for k in ("n00", "n01", "n10", "n11")]
        pair = row["pair"]
        if pair not in PAIR_MEMBERS:
            raise ValueError(f"{path}:{line}: paire inconnue {pair}")
        if (row["variant_a"], row["variant_b"]) != PAIR_MEMBERS[pair]:
            raise ValueError(f"{path}:{line}: ordre des variantes incohérent pour {pair}")
        if N <= 0 or sum(counts) != N:
            raise ValueError(f"{path}:{line}: n00+n01+n10+n11 ne vaut pas quartets")
        key = (seed, rnd, pair, nibble)
        acc = zero_agg[key]
        for i, value in enumerate(counts):
            acc["counts"][i] += value
        acc["N"] += N
        acc["combos"].add(combo)
        seeds.add(seed)
        rounds_seen.add(rnd)
        combos_seen.add(combo)

    exact_required = (
        "seed_hex", "round", "combination", "pair", "variant_a", "variant_b",
        "quartets", "n00", "n01", "n10", "n11",
    )
    for path, line, row in read_csv_files(exact_paths, exact_required):
        seed = row["seed_hex"].lower()
        rnd = as_int(row, "round", path, line)
        combo = as_int(row, "combination", path, line)
        N = as_int(row, "quartets", path, line)
        counts = [as_int(row, k, path, line) for k in ("n00", "n01", "n10", "n11")]
        pair = row["pair"]
        if pair not in PAIR_MEMBERS:
            raise ValueError(f"{path}:{line}: paire inconnue {pair}")
        if (row["variant_a"], row["variant_b"]) != PAIR_MEMBERS[pair]:
            raise ValueError(f"{path}:{line}: ordre des variantes incohérent pour {pair}")
        if N <= 0 or sum(counts) != N:
            raise ValueError(f"{path}:{line}: n00+n01+n10+n11 ne vaut pas quartets")
        key = (seed, rnd, pair)
        acc = exact_agg[key]
        for i, value in enumerate(counts):
            acc["counts"][i] += value
        acc["N"] += N
        acc["combos"].add(combo)
        seeds.add(seed)
        rounds_seen.add(rnd)
        combos_seen.add(combo)

    # Contrôle de complétude / cohérence entre jeux de fichiers.
    seeds_sorted = sorted(seeds)
    if not seeds_sorted:
        ap.error("aucune graine trouvée")
    n_seeds = len(seeds_sorted)
    max_round = max(rounds_seen)
    expected_combos = int(metadata.get("combinations", len(combos_seen)))
    if expected_combos != len(combos_seen):
        raise ValueError(f"métadonnées: {expected_combos} combinaisons, CSV: {len(combos_seen)}")
    expected_rounds = int(metadata.get("rounds", max_round))
    if expected_rounds != len(rounds_seen):
        raise ValueError(f"métadonnées: {expected_rounds} tours, CSV: {len(rounds_seen)}")
    if rounds_seen != set(range(1, expected_rounds + 1)):
        raise ValueError(f"tours manquants ou inattendus dans les CSV: {sorted(rounds_seen)}")
    if combos_seen != set(range(expected_combos)):
        raise ValueError(f"combinaisons manquantes ou inattendues dans les CSV: {sorted(combos_seen)}")
    expected_seed_count = int(metadata.get("seed_count", n_seeds))
    if expected_seed_count != n_seeds:
        raise ValueError(f"métadonnées: {expected_seed_count} graines, CSV: {n_seeds}")

    for key, acc in zero_agg.items():
        if len(acc["combos"]) != expected_combos:
            raise ValueError(f"données incomplètes pour zéro: {key}, combos={len(acc['combos'])}")
    for key, acc in exact_agg.items():
        if len(acc["combos"]) != expected_combos:
            raise ValueError(f"données incomplètes pour exact: {key}, combos={len(acc['combos'])}")

    # Tailles de familles : chaque test est (graine,tour,pair,nibble),
    # après agrégation des combinaisons dans un seul échantillon apparié.
    family_zero = len(PAIR_ORDER) * n_seeds * expected_rounds * 128
    family_marginal = len(CANDIDATES) * n_seeds * expected_rounds * 128
    family_exact = len(PAIR_ORDER) * n_seeds * expected_rounds
    threshold_zero = normal_threshold(family_zero)
    threshold_marginal = normal_threshold(family_marginal)
    threshold_exact = normal_threshold(family_exact)

    zero_rows = []
    candidate_marginals: Dict[Tuple[str, int, str, int], Tuple[int, int]] = {}
    for (seed, rnd, pair, nibble), acc in sorted(zero_agg.items()):
        n00, n01, n10, n11 = acc["counts"]
        N = acc["N"]
        variant_a, variant_b = PAIR_MEMBERS[pair]
        zeros_a = n10 + n11
        zeros_b = n01 + n11
        discordant = n01 + n10
        z, p, method = mcnemar(n01, n10)
        p_adj = min(1.0, p * family_zero)
        row = {
            "seed_hex": seed, "round": rnd, "pair": pair,
            "variant_a": variant_a, "variant_b": variant_b,
            "output_nibble": nibble, "quartets": N,
            "n00": n00, "n01": n01, "n10": n10, "n11": n11,
            "zeros_a": zeros_a, "zeros_b": zeros_b,
            "rate_a": zeros_a / N, "rate_b": zeros_b / N,
            "rate_a_minus_b": (zeros_a - zeros_b) / N,
            "discordant": discordant, "mcnemar_z_cc": z,
            "p_raw": p, "p_bonferroni": p_adj,
            "test_method": method,
            "significant": p_adj <= ALPHA_FAMILY,
            "family_size": family_zero,
            "combinations": len(acc["combos"]),
        }
        zero_rows.append(row)
        for candidate, count in ((variant_a, zeros_a), (variant_b, zeros_b)):
            ckey = (seed, rnd, candidate, nibble)
            prior = candidate_marginals.get(ckey)
            current = (count, N)
            if prior is not None and prior != current:
                raise ValueError(
                    f"marginales appariées incohérentes pour {ckey}: {prior} != {current}"
                )
            candidate_marginals[ckey] = current

    zero_fields = [
        "seed_hex", "round", "pair", "variant_a", "variant_b", "output_nibble",
        "quartets", "n00", "n01", "n10", "n11", "zeros_a", "zeros_b",
        "rate_a", "rate_b", "rate_a_minus_b", "discordant", "mcnemar_z_cc",
        "p_raw", "p_bonferroni", "test_method", "significant", "family_size", "combinations",
    ]
    write_csv(root / "paired_zero_mcnemar.csv", zero_fields, zero_rows)

    marginal_rows = []
    for (seed, rnd, candidate, nibble), (zeros, N) in sorted(candidate_marginals.items()):
        expected = N / 16.0
        variance = N * 15.0 / 256.0
        z = (zeros - expected) / math.sqrt(variance)
        p = normal_two_sided_p(z)
        p_adj = min(1.0, p * family_marginal)
        marginal_rows.append({
            "seed_hex": seed, "round": rnd, "candidate": candidate,
            "output_nibble": nibble, "quartets": N,
            "zero_count": zeros, "zero_rate": zeros / N,
            "expected_under_p_1_16": expected, "z_vs_p_1_16": z,
            "p_raw_normal": p, "p_bonferroni": p_adj,
            "significant": p_adj <= ALPHA_FAMILY,
            "family_size": family_marginal,
        })
    marginal_fields = [
        "seed_hex", "round", "candidate", "output_nibble", "quartets", "zero_count",
        "zero_rate", "expected_under_p_1_16", "z_vs_p_1_16", "p_raw_normal",
        "p_bonferroni", "significant", "family_size",
    ]
    write_csv(root / "candidate_zero_marginals.csv", marginal_fields, marginal_rows)

    exact_rows = []
    candidate_exact: Dict[Tuple[str, int, str], Tuple[int, int]] = {}
    for (seed, rnd, pair), acc in sorted(exact_agg.items()):
        n00, n01, n10, n11 = acc["counts"]
        N = acc["N"]
        variant_a, variant_b = PAIR_MEMBERS[pair]
        exact_a = n10 + n11
        exact_b = n01 + n11
        z, p, method = mcnemar(n01, n10)
        p_adj = min(1.0, p * family_exact)
        exact_rows.append({
            "seed_hex": seed, "round": rnd, "pair": pair,
            "variant_a": variant_a, "variant_b": variant_b,
            "quartets": N, "n00": n00, "n01": n01, "n10": n10, "n11": n11,
            "exact_a": exact_a, "exact_b": exact_b,
            "rate_a": exact_a / N, "rate_b": exact_b / N,
            "rate_a_minus_b": (exact_a - exact_b) / N,
            "discordant": n01 + n10, "mcnemar_z_cc": z,
            "p_raw": p, "p_bonferroni": p_adj,
            "test_method": method, "significant": p_adj <= ALPHA_FAMILY,
            "family_size": family_exact, "combinations": len(acc["combos"]),
        })
        for candidate, count in ((variant_a, exact_a), (variant_b, exact_b)):
            ckey = (seed, rnd, candidate)
            prior = candidate_exact.get(ckey)
            current = (count, N)
            if prior is not None and prior != current:
                raise ValueError(f"comptes de retours exacts incohérents pour {ckey}")
            candidate_exact[ckey] = current

    exact_fields = [
        "seed_hex", "round", "pair", "variant_a", "variant_b", "quartets",
        "n00", "n01", "n10", "n11", "exact_a", "exact_b", "rate_a", "rate_b",
        "rate_a_minus_b", "discordant", "mcnemar_z_cc", "p_raw", "p_bonferroni",
        "test_method", "significant", "family_size", "combinations",
    ]
    write_csv(root / "paired_exact_mcnemar.csv", exact_fields, exact_rows)

    candidate_exact_rows = []
    for (seed, rnd, candidate), (count, N) in sorted(candidate_exact.items()):
        candidate_exact_rows.append({
            "seed_hex": seed, "round": rnd, "candidate": candidate,
            "quartets": N, "exact_return_count": count, "exact_return_rate": count / N,
        })
    write_csv(
        root / "candidate_exact_returns.csv",
        ["seed_hex", "round", "candidate", "quartets", "exact_return_count", "exact_return_rate"],
        candidate_exact_rows,
    )

    # Synthèse lisible, avec les seuils et les résultats les plus marquants.
    significant_paired = [r for r in zero_rows if r["significant"]]
    significant_paired_r3 = [r for r in significant_paired if r["round"] >= 3]
    confirmatory_paired = [r for r in zero_rows if r["round"] >= 3]
    significant_marginal = [r for r in marginal_rows if r["significant"]]
    significant_marginal_r3 = [r for r in significant_marginal if r["round"] >= 3]
    confirmatory_marginal = [r for r in marginal_rows if r["round"] >= 3]
    significant_exact = [r for r in exact_rows if r["significant"]]
    # Les tours 1 et 2 sont des contrôles structurels : on les garde dans
    # les familles de tests mais on ne les met pas en tête des tableaux.
    top_paired = sorted(confirmatory_paired, key=lambda r: r["p_bonferroni"])[:12]
    top_marginal = sorted(confirmatory_marginal, key=lambda r: r["p_bonferroni"])[:12]

    # Agrégation descriptive des retours exacts par S-box (sans inférence de sécurité).
    exact_totals = {c: 0 for c in CANDIDATES}
    for row in candidate_exact_rows:
        exact_totals[row["candidate"]] += row["exact_return_count"]

    lines = [
        "# Rapport du banc BRUME-512 apparié",
        "",
        "## Configuration vérifiée",
        "",
        f"- Graines : **{n_seeds}**",
        f"- Tours : **{expected_rounds}**",
        f"- Combinaisons par tour et graine : **{expected_combos}**",
        f"- Quartets par combinaison : **2^{metadata.get('log2_quartets_per_combination', 'inconnu')}**",
        f"- Générateur déclaré : **{metadata.get('random_generator', 'non précisé')}**",
        f"- Total des quartets appariés par candidate : **{sum(int(r['quartets']) for r in candidate_exact_rows if r['candidate'] == CANDIDATES[0])}**",
        "",
        "Les trois candidates reçoivent les mêmes états aléatoires, les mêmes différences d'entrée et les mêmes différences injectées. Les comptes 2x2 sont donc appariés quartet par quartet.",
        "",
        "## Corrections multiples",
        "",
        f"- Comparaisons appariées par nibble : famille de **{family_zero:,}** tests ; seuil normal bilatéral **{threshold_zero:.6f}**.",
        f"- Biais marginaux contre p=1/16 : famille de **{family_marginal:,}** tests ; seuil normal bilatéral **{threshold_marginal:.6f}**.",
        f"- Comparaisons appariées des retours exacts : famille de **{family_exact:,}** tests ; seuil normal bilatéral indicatif **{threshold_exact:.6f}**.",
        f"- Risque familial ciblé : **1/1024** ; correction de Bonferroni.",
        "",
        "## Résultats appariés par nibble",
        "",
        f"- Tests significatifs après Bonferroni : **{len(significant_paired)} / {len(zero_rows)}**.",
        f"- Tests significatifs à partir du tour 3 : **{len(significant_paired_r3)} / {len(confirmatory_paired)}**.",
        "- Les combinaisons sont traitées comme des strates de géométrie distinctes : les discordances `n01` et `n10` sont additionnées pour le score de McNemar stratifié (score CMH pour paires appariées). Un binomial conditionnel exact est utilisé quand il y a au plus 20 000 discordances.",
        "- Le signe de `rate_a_minus_b` indique quelle candidate produit le plus souvent un nibble de différence nul. Cela ne constitue pas, à lui seul, un classement de sécurité.",
        "",
        "| Paire | Graine | Tour | Nibble | Taux A | Taux B | Z McNemar | p corrigée |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in top_paired:
        lines.append(
            f"| {r['pair']} | {r['seed_hex'][:8]} | {r['round']} | {r['output_nibble']} | "
            f"{r['rate_a']:.6g} | {r['rate_b']:.6g} | {r['mcnemar_z_cc']:.3f} | {fmt_p(r['p_bonferroni'])} |"
        )

    lines += [
        "",
        "## Biais marginaux par candidate",
        "",
        f"- Tests significatifs contre le modèle marginal p=1/16 après Bonferroni : **{len(significant_marginal)} / {len(marginal_rows)}**.",
        f"- Parmi les tours 3 et suivants : **{len(significant_marginal_r3)} / {len(confirmatory_marginal)}**.",
        "- Ces tests utilisent l'approximation binomiale normale héritée du protocole précédent ; les comparaisons appariées ci-dessus constituent l'analyse principale entre candidates.",
        "",
        "| Candidate | Graine | Tour | Nibble | Taux nul | Z vs 1/16 | p corrigée |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for r in top_marginal:
        lines.append(
            f"| {r['candidate']} | {r['seed_hex'][:8]} | {r['round']} | {r['output_nibble']} | "
            f"{r['zero_rate']:.6g} | {r['z_vs_p_1_16']:.3f} | {fmt_p(r['p_bonferroni'])} |"
        )

    lines += [
        "",
        "## Retours exacts de l'état complet",
        "",
        "| Candidate | Nombre de retours exacts observés |",
        "|---|---:|",
    ]
    for candidate in CANDIDATES:
        lines.append(f"| {candidate} | {exact_totals[candidate]} |")
    lines += [
        "",
        f"Comparaisons exactes significatives après correction : **{len(significant_exact)} / {len(exact_rows)}**.",
        "Les événements exacts sont rares ; le test binomial conditionnel exact est utilisé lorsque le nombre de discordances est inférieur ou égal à 20 000, sinon McNemar asymptotique avec correction de continuité.",
        "",
        "## Limites d'interprétation",
        "",
        "1. Ce banc compare trois variantes sur une famille précise de différences et sur un maximum de tours réduit. Il ne prouve pas la sécurité des 32 tours.",
        "2. McNemar teste l'égalité des taux d'événement appariés ; il ne prouve pas qu'une S-box est plus sûre dans l'absolu.",
        "3. Un nibble nul est un événement marginal. Les 128 coordonnées d'un même quartet sont dépendantes ; Bonferroni corrige le nombre de tests, mais le modèle p=1/16 reste une référence exploratoire.",
        "4. Les graines ChaCha20 rendent la génération reproductible et séparent les flux par tour/combinaison/quartet ; elles ne remplacent pas l'analyse cryptographique des hypothèses du protocole.",
        "5. Les tours 1 et 2 sont conservés comme contrôles structurels ; ils restent inclus dans Bonferroni, mais ne sont pas mis en avant dans les tableaux de comparaison à partir du tour 3.",
        "",
        "## Fichiers produits",
        "",
        "- `paired_zero_mcnemar.csv` : contingences et comparaisons appariées (McNemar stratifié par combinaison) par nibble.",
        "- `candidate_zero_marginals.csv` : fréquence du nibble nul par candidate.",
        "- `paired_exact_mcnemar.csv` : comparaisons appariées des retours exacts.",
        "- `candidate_exact_returns.csv` : comptes de retours exacts par candidate.",
        "",
    ]
    (root / "synthese_appariee.md").write_text("\n".join(lines), encoding="utf-8")

    summary_json = {
        "seed_count": n_seeds,
        "rounds": expected_rounds,
        "combinations": expected_combos,
        "familywise_alpha": ALPHA_FAMILY,
        "family_size_paired_zero": family_zero,
        "family_size_marginal_zero": family_marginal,
        "family_size_exact_return": family_exact,
        "threshold_z_paired_zero": threshold_zero,
        "threshold_z_marginal_zero": threshold_marginal,
        "threshold_z_exact_return_normal_reference": threshold_exact,
        "significant_paired_zero_tests": len(significant_paired),
        "total_paired_zero_tests": len(zero_rows),
        "significant_paired_zero_tests_round_ge_3": len(significant_paired_r3),
        "total_paired_zero_tests_round_ge_3": len(confirmatory_paired),
        "significant_marginal_tests": len(significant_marginal),
        "total_marginal_tests": len(marginal_rows),
        "significant_marginal_tests_round_ge_3": len(significant_marginal_r3),
        "total_marginal_tests_round_ge_3": len(confirmatory_marginal),
        "significant_exact_tests": len(significant_exact),
        "total_exact_tests": len(exact_rows),
        "exact_returns_by_candidate": exact_totals,
    }
    (root / "synthese_appariee.json").write_text(
        json.dumps(summary_json, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print(f"Analyse terminée : {root}")
    print(f"  graines={n_seeds}, tours={expected_rounds}, combinaisons={expected_combos}")
    print(f"  seuil McNemar par nibble={threshold_zero:.6f} (famille {family_zero})")
    print(f"  significatifs appariés={len(significant_paired)}/{len(zero_rows)}")
    print(f"  retours exacts={exact_totals}")
    print(f"  rapport: {root / 'synthese_appariee.md'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERREUR: {exc}", file=sys.stderr)
        raise SystemExit(1)
