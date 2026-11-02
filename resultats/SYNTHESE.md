# Synthèse de la batterie SILLAGE v0.4

534/534 contrôles réussis — 53 tests — 3559 s (2026-10-31 21:13).

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 10/10 | 7.8 s | OK |

## Modes BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `aead` | 12/12 | 0.6 s | OK |
| `te` | 12/12 | 0.6 s | OK |
| `hachage` | 7/7 | 14.8 s | OK |
| `mode_aead` | 9/9 | 2.4 s | OK |
| `aead_modele` | 12/12 | 10.2 s | OK |
| `hachage_arbre` | 16/16 | 37.5 s | OK |
| `indiff_arbre` | 15/15 | 6.3 s | OK |
| `aead_parallele` | 27/27 | 44.6 s | OK |

## Permutation BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `branch_exact` | 4/4 | 46.5 s | OK |
| `banc_cryptanalyse` | 8/8 | 19.9 s | OK |
| `diff_lin_empirique` | 4/4 | 6.6 s | OK |
| `cycles` | 2/2 | 4.0 s | OK |
| `beam_trails` | 2/2 | 102.1 s | OK |
| `integral_degre` | 2/2 | 4.0 s | OK |
| `symetries_invariants` | 9/9 | 2.2 s | OK |
| `hull` | 2/2 | 6.0 s | OK |
| `division_property` | 2/2 | 271.9 s | OK |
| `diffusion_stats` | 3/3 | 10.8 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | 54.8 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 29.1 s | OK |
| `sig_modele` | 22/22 | 105.6 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 27/27 | 78.8 s | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 1.4 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 38/38 | 105.0 s | OK |
| `c_fuzz` | 3/3 | 21.8 s | OK |
| `c_sig_valgrind` | 3/3 | 171.5 s | OK |
| `c_kem_valgrind` | 3/3 | 62.8 s | OK |
| `api_c` | 42/42 | 65.4 s | OK |
| `c_simd` | 3/3 | 39.2 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_integral` | 3/3 | 64.3 s | OK |
| `c_diff_lin` | 5/5 | 222.8 s | OK |
| `c_sac` | 5/5 | 41.9 s | OK |
| `c_statistiques` | 4/4 | 79.4 s | OK |
| `c_kem_bruit` | 9/9 | 107.0 s | OK |
| `c_cube_init` | 3/3 | 33.3 s | OK |
| `c_degre` | 5/5 | 368.8 s | OK |
| `c_temps` | 13/13 | 74.6 s | OK |
| `dp_modele` | 6/6 | 25.5 s | OK |
| `dp_tous_cubes` | 3/3 | 425.5 s | OK |
| `dp_exact` | 6/6 | 37.4 s | OK |
| `dp_validation` | 4/4 | 1110.2 s | OK |
| `structure_miss` | 4/4 | 2.5 s | OK |
| `isd_reel` | 5/5 | 58.0 s | OK |
| `isd_comparaison` | 5/5 | 241.7 s | OK |
| `diffusion_support` | 10/10 | 12.5 s | OK |
| `kem_distributions` | 11/11 | 13.2 s | OK |
| `sig_flux` | 5/5 | 1.0 s | OK |
| `brume_attaques` | 9/9 | 39.3 s | OK |
| `mini_brume` | 4/4 | 70.6 s | OK |
| `vole_proto` | 30/30 | 13.3 s | OK |
| `compression_sig` | 2/2 | 17.0 s | OK |
| `brume_algebre` | 15/15 | 199.3 s | OK |
