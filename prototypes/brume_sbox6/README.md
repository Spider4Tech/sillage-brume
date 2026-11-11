# Recherche d'une S-box pour BRUME-512 (8 – 11 novembre 2026)

Ce dossier rassemble les études qui ont conduit au changement de S-box de la **v0.5** : `891AC406DF37E2B5` (v0.4) est
remplacée par `AD412650BFEC7893`. La décision vient du départage (`departage/`), selon une règle fixée avant les calculs.
Toutes les candidates appartiennent à la même famille optimale des S-box 4 bits (U = 4, NL = 4, degré 3) : seuls des
effets à 2 et 3 tours les distinguent.

## Chronologie

| Étape | Dossier | Candidate | Conclusion |
|---|---|---|---|
| 1. SBOX6 | [`etudes/1_sbox6/`](etudes/1_sbox6/) | `F2CDB7E30465A891` | BCT maximale 6 au lieu de 10, mais profil DDT et BCT plat, et meilleures caractéristiques multi-tours pour l'attaquant. Écartée (`ANALYSE.md`, revue Codex `analyse-codex-resultat.md`) |
| 2. SBOX_V3 et campagne lourde | [`etudes/2_sbox_v3_comparaison_lourde/`](etudes/2_sbox_v3_comparaison_lourde/) | `E936FBA8C40571D2` | Compromis Pareto : BCT sans 10, propriétés différentielles de BRUME conservées (`ANALYSE_V3.md`, revue Codex `rapport-codex-sboxv3.md`). Campagne lourde à 5 graines (`resultats/campagne_lourde_*/synthese.md`) |
| 3. Tests appariés BRUME / SBOX6 / V3 | [`etudes/3_tests_apparies/`](etudes/3_tests_apparies/) | — | Mêmes quartets évalués avec les trois S-box, tests de McNemar (`resultats/paired_*/synthese_appariee.md`) |
| 4. SBOX_V4 et tests appariés BRUME / V3 / V4 | [`etudes/4_tests_apparies_v3_v4/`](etudes/4_tests_apparies_v3_v4/) | `A4F60295C873D1BE` | V4, vérifiée par `sbox_v4_candidate.py`, comparée de la même façon |
| 5. Étude de référence V3 contre BRUME | [`etudes/5_etude_v3_reference/`](etudes/5_etude_v3_reference/) | — | Scripts Python (coque, faisceau, boomerang, intégrales, différentielles impossibles). Leurs sorties vont dans `resultats/etude_v3_vs_brume_reference_20261109/` à la racine, qui n'est pas publiée |
| **6. Départage** | [`departage/`](departage/) | **`AD412650BFEC7893` (CAND_A1)** | Règle R1–R4 fixée d'avance (`PROTOCOLE.md`) ; huit S-box ; B3 sur GPU et balayage exhaustif ; `RAPPORT.md`. **Retenue pour la v0.5** |

## Après l'adoption (v0.5)

La batterie (`python3 -m tests.run_all`) confirme le changement :
- propriétés certifiées identiques ;
- BCT maximale 8 au lieu de 10 ;
- boomerang à 3 tours de z = 14,8 à z = 6,9, à 2^20 quartets ;
- portée exacte de la division property inchangée, 10 tours par sens ;
- aucun distingueur au-delà de la portée connue.

`tests/test_select_params.py` lit `departage/RAPPORT.md` pour vérifier que la S-box en service est bien la candidate retenue.
Voir SPEC § 2.1, PROOFS § 4 et AUDIT_REPORT (2026-11-11).

## Contenu et rangement

- Chaque étude garde ses sources, sa documentation et, dans `resultats/`, ses synthèses : JSON et MD, métadonnées de
  campagne (empreintes SHA-256 des sources), graines, journaux.
- Les sorties brutes ne sont pas publiées : CSV de plusieurs Mo, binaires compilés, copies des sources dans chaque dossier
  de résultats, archives zip. Les fichiers qui étaient suivis restent dans l'historique git, au commit `4160aa6`. Le
  dossier complet d'avant le rangement du 11 novembre 2026 est archivé hors du dépôt
  (`orion_archive_brume_sbox6_20261111.tar.gz`).
- `departage/resultats/` (44 Mo, sorties du départage) reste sur disque et n'est pas publié (`.gitignore`) ; `RAPPORT.md`
  cite ses dossiers.
- Les scripts ont été déplacés avec leurs voisins de dépendance, et leur recherche de la racine du dépôt est ajustée. Ce sont
  des études closes : les relancer n'est pas nécessaire pour la v0.5.
