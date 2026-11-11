#!/usr/bin/env python3
"""Agrège et audite une campagne lourde BRUME / SBOX6 / SBOX_V3.

Lit les sous-dossiers CANDIDATE/seed_* produits par tester_sbox_compare.sh.
Vérifie les métadonnées, les CSV et l'identité des paramètres d'entrée entre
candidates pour chaque graine. Produit synthese.json, synthese.md et CSV.
"""
from __future__ import annotations
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

CANDIDATES = ("BRUME", "SBOX6", "SBOX_V3")
INPUT_COLUMNS = (
    "round", "combination", "input_nibble", "alpha",
    "delta_source_nibble", "delta_value", "combination_seed", "seed_base",
)


def load_run(root: Path, candidate: str, seed: str):
    folder = root / candidate / f"seed_{seed}"
    meta_path = folder / "campaign_metadata.json"
    json_path = folder / "brume_attaques.json"
    csv_path = folder / "brume_attaques_boomerang_raw.csv"
    for path in (meta_path, json_path, csv_path):
        if not path.is_file():
            raise FileNotFoundError(f"Fichier manquant : {path}")
    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    result = json.loads(json_path.read_text(encoding="utf-8"))
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    return folder, metadata, result, rows


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} DOSSIER_CAMPAGNE", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    config_path = root / "configuration.txt"
    if not config_path.is_file():
        raise FileNotFoundError(config_path)
    config = {}
    for line in config_path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            config[key.strip()] = value.strip()
    seeds = config["SEEDS"].split()
    lq = int(config["LQ"])
    nc = int(config["NC"])
    family = int(config["FAMILY"])
    threads = int(config["THREADS"])
    expected_rows = 8 * nc * 128

    runs = {}
    audit = {"all_metadata_match": True, "all_csv_rows_match": True,
             "input_geometry_matches_across_candidates": True,
             "expected_rows_per_csv": expected_rows, "csv_rows": {},
             "matched_geometry_by_seed": {}}

    for seed in seeds:
        for candidate in CANDIDATES:
            folder, metadata, result, rows = load_run(root, candidate, seed)
            key = (candidate, seed)
            runs[key] = (metadata, result, rows)
            expected = {
                "candidate": candidate,
                "log2_quartets_per_combination": lq,
                "combinations_per_round": nc,
                "seed_base": seed,
                "family_size_for_bonferroni": family,
                "omp_num_threads": threads,
            }
            mismatches = {k: (metadata.get(k), v) for k, v in expected.items()
                          if metadata.get(k) != v and not (
                              k == "seed_base" and str(metadata.get(k)).lower() == str(v).lower()
                          )}
            if mismatches:
                audit["all_metadata_match"] = False
                raise ValueError(f"Métadonnées incohérentes pour {candidate}/{seed}: {mismatches}")
            audit["csv_rows"][f"{candidate}/{seed}"] = len(rows)
            if len(rows) != expected_rows:
                audit["all_csv_rows_match"] = False
                raise ValueError(
                    f"CSV incomplet pour {candidate}/{seed}: {len(rows)} lignes, {expected_rows} attendues"
                )

        # Vérifier que les trois candidates ont les mêmes différences d'entrée
        # et les mêmes flux/numéros de combinaison pour une graine donnée.
        signatures = {}
        for candidate in CANDIDATES:
            rows = runs[(candidate, seed)][2]
            signatures[candidate] = [tuple(row[col] for col in INPUT_COLUMNS) for row in rows]
        reference = signatures[CANDIDATES[0]]
        ok = all(signatures[name] == reference for name in CANDIDATES[1:])
        audit["matched_geometry_by_seed"][seed] = ok
        if not ok:
            audit["input_geometry_matches_across_candidates"] = False
            raise ValueError(
                f"Entrées non appariées pour la graine {seed}; comparer les campagnes serait invalide"
            )

    # Résumé statistique C par candidate et profondeur.
    c_summary = []
    for candidate in CANDIDATES:
        for round_number in range(1, 9):
            z_values = []
            significant_count = 0
            exact_returns = []
            thresholds = []
            for seed in seeds:
                _meta, payload, _rows = runs[(candidate, seed)]
                boomerang = payload["mesures"]["boomerang"]
                round_data = next(x for x in payload["mesures"]["boomerang_par_tours"]
                                  if int(x["tours"]) == round_number)
                z_values.append(float(round_data["z_max"]))
                significant_count += int(bool(round_data["significatif"]))
                exact_returns.append(int(round_data["retours_exacts"]))
                thresholds.append(float(boomerang["seuil_z_bilateral_bonferroni"]))
            c_summary.append({
                "candidate": candidate,
                "round": round_number,
                "seeds": len(seeds),
                "z_mean": statistics.mean(z_values),
                "z_median": statistics.median(z_values),
                "z_min": min(z_values),
                "z_max": max(z_values),
                "significant_seeds": significant_count,
                "exact_returns_mean": statistics.mean(exact_returns),
                "threshold_min": min(thresholds),
                "threshold_max": max(thresholds),
            })

    # Résumé des trails de l'analyse corrigée : coûts en demi-bits,
    # les coûts BCT sont des flottants et ne sont pas arrondis prématurément.
    trails_path = root / "analyse_trails.json"
    trail_summary = None
    if trails_path.is_file():
        trail_payload = json.loads(trails_path.read_text(encoding="utf-8"))
        trail_summary = {}
        candidates_obj = trail_payload.get("candidates", {})
        for name in CANDIDATES:
            cand = candidates_obj.get(name, {})
            trail_diff = trail_payload.get("trails", {}).get(name, {})
            diff = trail_diff.get("diff_cost_half_bits", trail_diff.get("diff", {}))
            linear = trail_diff.get("lin_cost_half_bits", trail_diff.get("lin", {}))
            r = str(config.get("ROUNDS", 14))
            boom = trail_payload.get("boomerang_switch_trails_half_bits", {}).get(name, {})
            trail_summary[name] = {
                "ddt_max": cand.get("ddt", {}).get("max"),
                "ddt_rows_max_2": cand.get("ddt", {}).get("rows_max_2"),
                "bct_max": cand.get("bct", {}).get("max"),
                "bct_rows_max_2": cand.get("bct", {}).get("rows_max_2"),
                "dbct_max": cand.get("dbct", {}).get("max_nonzero"),
                "MEDP2_log2": cand.get("park", {}).get("MEDP2_log2"),
                "diff_cost_half_bits_at_horizon": diff.get(r),
                "linear_cost_half_bits_at_horizon": linear.get(r),
                "boomerang_switch_cost_half_bits_at_14": boom.get("14"),
            }

    summary = {
        "protocol": "BRUME-SBOX-COMPARE-HEAVY v1",
        "configuration": config,
        "audit": audit,
        "boomerang_c_summary": c_summary,
        "trail_summary": trail_summary,
        "interpretation": (
            "Comparaison empirique à tours réduits et recherches de trails heuristiques. "
            "Ce résultat n'est pas une preuve de sécurité pour BRUME-512 à 32 tours."
        ),
    }
    (root / "synthese.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                                         encoding="utf-8")

    csv_path = root / "synthese_boomerang.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(c_summary[0].keys()))
        writer.writeheader()
        writer.writerows(c_summary)

    lines = [
        "# Synthèse de la campagne lourde BRUME",
        "",
        "## Paramètres",
        "",
        f"- Quartets par combinaison : 2^{lq}",
        f"- Combinaisons par tour : {nc}",
        f"- Graines : {', '.join(seeds)} ({len(seeds)})",
        f"- Taille de famille Bonferroni : {family}",
        f"- Seuils statistiques par run : {c_summary[0]['threshold_min']:.6f} à {c_summary[0]['threshold_max']:.6f}",
        f"- Nombre de lignes CSV attendu par run : {expected_rows}",
        "",
        "## Audit",
        "",
        f"- Métadonnées cohérentes : {audit['all_metadata_match']}",
        f"- CSV complets : {audit['all_csv_rows_match']}",
        f"- Géométrie des entrées identique entre candidates pour chaque graine : {audit['input_geometry_matches_across_candidates']}",
        "",
        "## Boomerang C : scores Z par profondeur",
        "",
        "Le tableau donne la moyenne et la médiane des maxima Z sur les graines. La colonne `significatif` compte les graines dépassant le seuil corrigé de chaque campagne.",
        "",
        "| Candidate | Tours | Z moyen | Z médian | Z min–max | Graines significatives | Retours exacts moyens |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for item in c_summary:
        lines.append(
            f"| {item['candidate']} | {item['round']} | {item['z_mean']:.3f} | "
            f"{item['z_median']:.3f} | {item['z_min']:.3f}–{item['z_max']:.3f} | "
            f"{item['significant_seeds']}/{item['seeds']} | {item['exact_returns_mean']:.1f} |"
        )

    lines += ["", "## Trails multi-tours", ""]
    if trail_summary:
        lines += [
            "Les coûts ci-dessous sont des coûts de caractéristiques heuristiques en demi-bits. Le switch boomerang a été recalculé avec `2*log2(16/BCT)` en flottant, sans arrondi intermédiaire.",
            "",
            "| Candidate | DDT max | Lignes DDT max 2 | BCT max | Lignes BCT max 2 | DBCT max | Coût diff. à l'horizon (demi-bits) | Coût lin. à l'horizon (demi-bits) | Switch boomerang 14 tours (demi-bits) |",
            "|---|---:|---|---:|---|---:|---:|---:|---:|",
        ]
        for name in CANDIDATES:
            x = trail_summary[name]
            lines.append(
                f"| {name} | {x['ddt_max']} | {x['ddt_rows_max_2']} | {x['bct_max']} | "
                f"{x['bct_rows_max_2']} | {x['dbct_max']} | {x['diff_cost_half_bits_at_horizon']} | "
                f"{x['linear_cost_half_bits_at_horizon']} | {x['boomerang_switch_cost_half_bits_at_14']} |"
            )
    else:
        lines.append("Analyse des trails absente ; consulter `analyse_trails.log`.")

    lines += [
        "",
        "## Lecture",
        "",
        "Ne pas classer les S-boxes à partir du seul BCT maximal ou d'un seul `z_max`. "
        "SBOX6 a BCT max 6, mais le profil des lignes DDT/BCT et les meilleures pistes multi-tours "
        "peuvent être moins favorables que ceux de SBOX_V3. Les résultats de pistes restent heuristiques.",
        "",
        "Les tests C explorent uniquement les profondeurs codées dans le banc (`RB`, actuellement 8 tours). "
        "Ils ne démontrent pas la sécurité de la permutation à 32 tours.",
        "",
    ]
    (root / "synthese.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"Audit CSV/métadonnées : OK ({len(seeds)} graines, {len(CANDIDATES)} candidates)")
    print(f"Synthèse : {root / 'synthese.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
