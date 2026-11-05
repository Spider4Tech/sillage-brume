# Synthèse de la batterie SILLAGE v0.4

574/574 contrôles réussis — 59 tests — 3699 s (2026-11-04 23:18).

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 10/10 | 11.8 s | OK |

## Modes BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `aead` | 12/12 | 4.5 s | OK |
| `te` | 12/12 | 4.4 s | OK |
| `hachage` | 7/7 | 14.6 s | OK |
| `mode_aead` | 9/9 | 2.3 s | OK |
| `aead_modele` | 12/12 | 10.1 s | OK |
| `hachage_arbre` | 16/16 | 44.8 s | OK |
| `indiff_arbre` | 15/15 | 6.3 s | OK |
| `aead_parallele` | 27/27 | 44.6 s | OK |

## Permutation BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `branch_exact` | 4/4 | 46.6 s | OK |
| `banc_cryptanalyse` | 8/8 | 21.9 s | OK |
| `diff_lin_empirique` | 4/4 | 6.7 s | OK |
| `cycles` | 2/2 | 4.6 s | OK |
| `beam_trails` | 2/2 | 97.6 s | OK |
| `integral_degre` | 2/2 | 4.2 s | OK |
| `symetries_invariants` | 9/9 | 2.1 s | OK |
| `hull` | 2/2 | 5.4 s | OK |
| `division_property` | 2/2 | 254.3 s | OK |
| `diffusion_stats` | 3/3 | 12.3 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | 51.2 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 29.0 s | OK |
| `sig_modele` | 22/22 | 79.2 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 27/27 | 76.8 s | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 1.1 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 38/38 | 104.2 s | OK |
| `c_fuzz` | 3/3 | 26.7 s | OK |
| `c_sig_valgrind` | 3/3 | 169.5 s | OK |
| `c_kem_valgrind` | 3/3 | 54.1 s | OK |
| `api_c` | 42/42 | 57.3 s | OK |
| `c_simd` | 3/3 | 32.7 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_integral` | 3/3 | 63.7 s | OK |
| `c_diff_lin` | 5/5 | 221.1 s | OK |
| `c_sac` | 5/5 | 41.9 s | OK |
| `c_statistiques` | 5/5 | 80.7 s | OK |
| `c_kem_bruit` | 9/9 | 107.1 s | OK |
| `c_cube_init` | 3/3 | 33.0 s | OK |
| `c_degre` | 5/5 | 368.3 s | OK |
| `c_temps` | 13/13 | 76.2 s | OK |
| `dp_modele` | 6/6 | 25.5 s | OK |
| `dp_tous_cubes` | 3/3 | 425.8 s | OK |
| `dp_exact` | 6/6 | 37.0 s | OK |
| `dp_validation` | 4/4 | 1106.0 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `revue_c` | 6/6 | 0.0 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `structure_miss` | 4/4 | 2.5 s | OK |
| `isd_reel` | 5/5 | 58.3 s | OK |
| `isd_comparaison` | 5/5 | 243.3 s | OK |
| `diffusion_support` | 10/10 | 13.7 s | OK |
| `kem_distributions` | 11/11 | 11.9 s | OK |
| `h1p_fourier` | 6/6 | 0.0 s | OK |
| `invariants` | 5/5 | 0.2 s | OK |
| `kem_rejet` | 6/6 | 59.3 s | OK |
| `brume_gd2` | 4/4 | 29.1 s | OK |
| `sig_flux` | 5/5 | 1.0 s | OK |
| `sig_kz` | 10/10 | 20.5 s | OK |
| `brume_attaques` | 9/9 | 38.1 s | OK |
| `mini_brume` | 6/6 | 118.9 s | OK |
| `vole_proto` | 30/30 | 13.7 s | OK |
| `compression_sig` | 2/2 | 17.0 s | OK |
| `brume_algebre` | 15/15 | 199.7 s | OK |
