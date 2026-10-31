# Synthèse de la batterie SILLAGE v0.4

533/534 contrôles réussis — 53 tests — 3530 s (2026-10-31 18:57).

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 10/10 | 11.7 s | OK |

## Modes BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `aead` | 12/12 | 4.5 s | OK |
| `te` | 12/12 | 4.4 s | OK |
| `hachage` | 7/7 | 14.5 s | OK |
| `mode_aead` | 9/9 | 2.3 s | OK |
| `aead_modele` | 12/12 | 10.1 s | OK |
| `hachage_arbre` | 16/16 | 44.8 s | OK |
| `indiff_arbre` | 15/15 | 6.3 s | OK |
| `aead_parallele` | 27/27 | 41.9 s | OK |

## Permutation BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `branch_exact` | 4/4 | 44.4 s | OK |
| `banc_cryptanalyse` | 8/8 | 21.4 s | OK |
| `diff_lin_empirique` | 4/4 | 6.7 s | OK |
| `cycles` | 2/2 | 4.2 s | OK |
| `beam_trails` | 2/2 | 94.0 s | OK |
| `integral_degre` | 2/2 | 3.9 s | OK |
| `symetries_invariants` | 9/9 | 2.1 s | OK |
| `hull` | 2/2 | 5.3 s | OK |
| `division_property` | 2/2 | 260.3 s | OK |
| `diffusion_stats` | 3/3 | 11.1 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | 48.5 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 26.5 s | OK |
| `sig_modele` | 22/22 | 112.0 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 26/27 | 14.0 s | ÉCHEC : Sillage-256_D_minimal |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 1.0 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 38/38 | 114.9 s | OK |
| `c_fuzz` | 3/3 | 22.8 s | OK |
| `c_sig_valgrind` | 3/3 | 183.9 s | OK |
| `c_kem_valgrind` | 3/3 | 53.0 s | OK |
| `api_c` | 42/42 | 67.4 s | OK |
| `c_simd` | 3/3 | 34.7 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_integral` | 3/3 | 63.7 s | OK |
| `c_diff_lin` | 5/5 | 219.2 s | OK |
| `c_sac` | 5/5 | 41.9 s | OK |
| `c_statistiques` | 4/4 | 79.6 s | OK |
| `c_kem_bruit` | 9/9 | 107.5 s | OK |
| `c_cube_init` | 3/3 | 33.1 s | OK |
| `c_degre` | 5/5 | 368.7 s | OK |
| `c_temps` | 13/13 | 74.5 s | OK |
| `dp_modele` | 6/6 | 25.7 s | OK |
| `dp_tous_cubes` | 3/3 | 406.9 s | OK |
| `dp_exact` | 6/6 | 37.4 s | OK |
| `dp_validation` | 4/4 | 1110.4 s | OK |
| `structure_miss` | 4/4 | 2.5 s | OK |
| `isd_reel` | 5/5 | 58.2 s | OK |
| `isd_comparaison` | 5/5 | 243.9 s | OK |
| `diffusion_support` | 10/10 | 12.7 s | OK |
| `kem_distributions` | 11/11 | 12.1 s | OK |
| `sig_flux` | 5/5 | 0.9 s | OK |
| `brume_attaques` | 9/9 | 39.9 s | OK |
| `mini_brume` | 4/4 | 70.7 s | OK |
| `vole_proto` | 30/30 | 13.7 s | OK |
| `compression_sig` | 2/2 | 17.0 s | OK |
| `brume_algebre` | 15/15 | 199.7 s | OK |
