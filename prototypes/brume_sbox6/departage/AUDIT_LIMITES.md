# Audit des limites des résultats antérieurs (S-box BRUME / SBOX6 / SBOX_V3 / SBOX_V4)

Rédigé le 10 novembre 2026, selon la règle du `PROTOCOLE.md` § 3. Une recherche (MILP, CP-SAT, SAT,
B&B) n'est dite *exacte* que si son modèle représente la permutation complète **et** si le solveur
prouve l'optimalité. Chaque ligne cite la source et la valeur brute relue, puis donne le statut
corrigé.

## 1. Requalifications

| # | Source | Affirmation | Valeur brute relue | Statut corrigé | Raison |
|---|---|---|---|---|---|
| A1 | `ANALYSE_V3.md` § 1 et § 4 | « Meilleure piste diff. 14 tours 2^-2830 / 2^-2600 / 2^-3021 », « V3 +191 bits » | moteur glouton `tests/banc_trails.py` | HEURISTIQUE | Une piste gloutonne est une valeur atteinte, pas une borne. L'écart de 191 bits compare deux exécutions gloutonnes, il ne mesure aucune sécurité. |
| A2 | `ANALYSE_V3.md` § 4.1 | « coût mesuré en demi-bits (probabilité 2^{-coût/2}) » | 1088×2 + 218×3 = 2830 | erreur d'unité | Le calcul est en bits, pas en demi-bits. Les valeurs du tableau sont en bits. |
| A3 | `ANALYSE_V3.md` § 4.2 | « piste boomerang 14 tours 2^-2941 » | glouton + switch BCT | HEURISTIQUE | Une caractéristique avec switch n'est pas une probabilité de boomerang. B3 mesure ≈ 2^-8 à 3 tours (§ 2). |
| A4 | `ANALYSE_V3.md` § 1, `sbox_v4_candidate.py` | « MEDP2 = 2^-14.99 » | max_a Σ_b (DDT/16)^8 | BORNE (générique) | Borne de type « branch number » qui ignore M. La valeur exacte pour M est D2 (§ 2). |
| A5 | `02_cpsat_petits_tours.json` | R2 = 32 demi-bits, `OPTIMAL` | `initial_mode` = `weight1` | EXACT_RESTREINT → EXACT | Modèle restreint au poids 1, donc exact restreint. La valeur égale la borne certifiée 8 S-box × 2 bits (branch number 8, `branch_exact.json`), ce qui la promeut en EXACT. |
| A6 | `02_cpsat_petits_tours.json` | R3, R4 | `FEASIBLE`, objectif 166/532 (BRUME), 180/520 (V3), `best_bound` 32 / 28 | HEURISTIQUE | Optimalité non prouvée (écart de 134 à 504 demi-bits). V3 R3 = 90 bits, alors que l'optimum prouvé restreint vaut **86** bits (D3) : la solution `FEASIBLE` n'était pas optimale. |
| A7 | `04_effet_differentiel_clustering.json` | « gain de coque 5 à 6,6 bits » | `n_multi_trail_groups` = 0 partout | requalifié : **aucun effet de coque observé** | Les 100 pistes ont 100 couples (α, β) distincts. Sommer leurs probabilités ne donne la probabilité d'aucun différentiel. |
| A8 | `07_boomerang_rectangle.json` | boomerang 2 tours : 0 retour sur 65 536 (BRUME) | estimation 2^-13,4 sur (α, δ) choisis par pistes | EMPIRIQUE, non informatif | Les différences étaient mal choisies. B2 exact atteint 2^-1,6 hors couples triviaux, et 957 couples reviennent avec probabilité 1. |
| A9 | `08_propriete_integrale_division.json` | division property SAT, t = 4 et 8, R = 1–2 | BRUME `FEASIBLE` objectif 0, borne 492–512 ; V3 `OPTIMAL` 512 à R2 | NON PROUVÉ (BRUME), non comparable | Les deux candidates n'ont pas le même statut de solveur : la comparaison n'a pas de sens. Seule la portée DP du dépôt (10 tours par sens, BRUME seule) est établie. |
| A10 | `09_impossible_differentiel_zero_correlation.json` | impossibles à 3 tours | CP-SAT `INFEASIBLE` avec α, β fixés | EXACT pour ces (α, β) | Modèle à α et β fixés : c'est un énoncé exact sur des couples précis, pas sur tous les couples. |
| A11 | `sbox_v4_candidate.py` | « SBOX_V4 fait au moins aussi bien que SBOX_V3 partout » | propriétés locales seulement | vrai localement, **faux en multi-tours** | Sur le boomerang à 3 tours mesuré, V4 est la pire des quatre (§ 2). |
| A12 | `brume_tests_apparies_v3_v4/.../synthese_appariee.md` | 1 728 / 15 360 tests significatifs | 1 seul à partir du tour 3 | EMPIRIQUE, non discriminant | L'événement « nibble nul » ne cible aucune différence optimisée. Les « retours exacts » viennent surtout des 957 couples triviaux à 2 tours. |
| A13 | `ANALYSE_V3.md` § 3.2 | « une seule classe affine atteint BCT = 6 » | — | faux (G3 et G5, Boura–Canteaut) | Déjà relevé dans `rapport-codex-sboxv3.md`. La conclusion structurelle tient pour les deux classes. |

## 2. Nouvelles valeurs (banc `departage`, statuts du protocole)

Les chiffres définitifs et les sorties brutes sont dans `RAPPORT.md` (run du 11 novembre 2026). En résumé :

- D2, L2 et B2 sont EXACT_RESTREINT. Chaque valeur est exacte pour la permutation à 2 tours, et les
  contrôles empiriques sont compatibles à 4 σ. D2 est promu EXACT par le certificat C2 (INFEASIBLE prouvé).
- D3 et L3 sont EXACT_RESTREINT (optimum prouvé avec 1 S-box active au premier ou au dernier tour).
  Le certificat tronqué ne peut pas les promouvoir : la relaxation admet un motif à 30 S-box actives
  ([4, 21, 5]), donc C3 ≤ 30, alors qu'il faudrait C3 ≥ 42 (D3) et C3 ≥ 39 (L3).
- B3 est EMPIRIQUE. La reformulation rapide est identique, quartet par quartet, à l'inversion complète.
  Les comptes GPU sont identiques à l'unité près aux comptes C (344 / 344 lignes à 2^26).
- INT : à 64 bases, les profils de bits robustes sont identiques pour les 8 S-box (18 configurations).
  Les écarts vus à 3 bases étaient du bruit (un bit déséquilibré y paraît nul avec probabilité 1/8).

## 3. Ce que le banc ne prouve pas

1. Rien sur 32 tours. Les mesures portent sur 2 et 3 tours.
2. Les restrictions (poids 1 en entrée, une S-box active en sortie) sont des choix d'attaquant
   raisonnables, pas exhaustifs. Un motif plus large peut donner mieux à l'attaquant tant qu'aucun
   certificat ne couvre le complément.
3. ~~Le prédicteur B3 (MODELE) n'explore pas les j′ à portée de N[i] : B3 mesuré est un minorant de la
   meilleure probabilité de boomerang à 3 tours.~~ **Levé le 11 novembre 2026** pour α et δ′ de poids 1 :
   le balayage GPU exhaustif des 3 686 400 combinaisons (i, a, j′, δ′) retrouve le même maximum et le même
   argument que le prédicteur pour les 8 S-box (`RAPPORT.md` § 5). Les différences de poids ≥ 2 restent
   hors mesure.
4. INT est empirique : une somme nulle sur 64 bases n'est pas une preuve d'équilibre. À 3 bases (run
   complet), un bit déséquilibré paraît nul avec probabilité 1/8 : ces comptes ne doivent pas servir à
   comparer des S-box.
