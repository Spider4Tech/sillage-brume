# Synthèse de la batterie SILLAGE v0.4

502/502 contrôles réussis — 51 tests — 3604 s (2026-10-31 12:38).

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 10/10 | 11.7 s | OK |

## Modes BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `aead` | 12/12 | 4.4 s | OK |
| `te` | 12/12 | 4.4 s | OK |
| `hachage` | 7/7 | 14.5 s | OK |
| `mode_aead` | 9/9 | 2.3 s | OK |
| `aead_modele` | 12/12 | 10.1 s | OK |
| `hachage_arbre` | 16/16 | 44.0 s | OK |
| `indiff_arbre` | 15/15 | 6.4 s | OK |
| `aead_parallele` | 27/27 | 42.6 s | OK |

## Permutation BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `branch_exact` | 4/4 | 47.7 s | OK |
| `banc_cryptanalyse` | 8/8 | 21.4 s | OK |
| `diff_lin_empirique` | 4/4 | 6.6 s | OK |
| `cycles` | 2/2 | 4.1 s | OK |
| `beam_trails` | 2/2 | 87.2 s | OK |
| `integral_degre` | 2/2 | 4.0 s | OK |
| `symetries_invariants` | 9/9 | 2.2 s | OK |
| `hull` | 2/2 | 5.2 s | OK |
| `division_property` | 2/2 | 250.0 s | OK |
| `diffusion_stats` | 3/3 | 10.7 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | 48.2 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 29.3 s | OK |
| `sig_modele` | 22/22 | 86.8 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 27/27 | 16.2 s | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 1.5 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 38/38 | 99.6 s | OK |
| `c_fuzz` | 3/3 | 21.5 s | OK |
| `c_sig_valgrind` | 3/3 | 207.7 s | OK |
| `c_kem_valgrind` | 3/3 | 55.4 s | OK |
| `api_c` | 42/42 | 63.1 s | OK |
| `c_simd` | 3/3 | 31.9 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_integral` | 3/3 | 63.6 s | OK |
| `c_diff_lin` | 5/5 | 220.9 s | OK |
| `c_sac` | 5/5 | 41.9 s | OK |
| `c_statistiques` | 4/4 | 79.5 s | OK |
| `c_kem_bruit` | 9/9 | 107.2 s | OK |
| `c_cube_init` | 3/3 | 32.9 s | OK |
| `c_degre` | 5/5 | 369.2 s | OK |
| `c_temps` | 13/13 | 74.9 s | OK |
| `dp_modele` | 6/6 | 25.5 s | OK |
| `dp_tous_cubes` | 3/3 | 430.2 s | OK |
| `dp_exact` | 6/6 | 37.3 s | OK |
| `dp_validation` | 4/4 | 1142.4 s | OK |
| `structure_miss` | 4/4 | 6.6 s | OK |
| `isd_reel` | 5/5 | 62.1 s | OK |
| `isd_comparaison` | 5/5 | 247.8 s | OK |
| `diffusion_support` | 10/10 | 18.0 s | OK |
| `kem_distributions` | 11/11 | 17.6 s | OK |
| `sig_flux` | 5/5 | 3.7 s | OK |
| `brume_attaques` | 9/9 | 45.2 s | OK |
| `mini_brume` | 4/4 | 78.1 s | OK |
| `brume_algebre` | 15/15 | 200.9 s | OK |
