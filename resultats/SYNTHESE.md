# Synthèse de la batterie SILLAGE v0.4

597/597 contrôles réussis — 60 tests — 4258 s (2026-11-05 15:06).

Hôte, sauf `c_sig_valgrind` et `c_kem_valgrind`, rejoués dans le conteneur tgh (2026-11-05 15:25) : l'hôte n'a pas Valgrind.

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 10/10 | 7.9 s | OK |

## Modes BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `aead` | 12/12 | 0.3 s | OK |
| `te` | 12/12 | 0.3 s | OK |
| `hachage` | 9/9 | 14.8 s | OK |
| `mode_aead` | 9/9 | 2.0 s | OK |
| `aead_modele` | 14/14 | 12.2 s | OK |
| `hachage_arbre` | 16/16 | 38.7 s | OK |
| `indiff_arbre` | 15/15 | 6.2 s | OK |
| `aead_parallele` | 27/27 | 47.6 s | OK |

## Permutation BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `branch_exact` | 5/5 | 72.5 s | OK |
| `banc_cryptanalyse` | 8/8 | 18.1 s | OK |
| `diff_lin_empirique` | 4/4 | 7.0 s | OK |
| `cycles` | 3/3 | 4.4 s | OK |
| `beam_trails` | 2/2 | 114.8 s | OK |
| `integral_degre` | 2/2 | 3.5 s | OK |
| `symetries_invariants` | 9/9 | 1.8 s | OK |
| `hull` | 3/3 | 6.0 s | OK |
| `division_property` | 3/3 | 230.8 s | OK |
| `diffusion_stats` | 5/5 | 10.8 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | 44.2 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 29.4 s | OK |
| `sig_modele` | 22/22 | 91.2 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 31/31 | 69.4 s | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 0.4 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 38/38 | 89.1 s | OK |
| `c_fuzz` | 5/5 | 23.4 s | OK |
| `c_sig_valgrind` | 3/3 | 120.0 s | OK |
| `c_kem_valgrind` | 3/3 | 28.3 s | OK |
| `api_c` | 42/42 | 57.8 s | OK |
| `c_simd` | 2/2 | 15.8 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_integral` | 3/3 | 63.3 s | OK |
| `c_diff_lin` | 5/5 | 218.6 s | OK |
| `c_sac` | 5/5 | 41.3 s | OK |
| `c_statistiques` | 5/5 | 80.5 s | OK |
| `c_kem_bruit` | 9/9 | 119.3 s | OK |
| `c_cube_init` | 4/4 | 32.8 s | OK |
| `c_degre` | 5/5 | 367.9 s | OK |
| `c_temps` | 13/13 | 69.9 s | OK |
| `dp_modele` | 6/6 | 24.0 s | OK |
| `dp_tous_cubes` | 3/3 | 559.6 s | OK |
| `dp_exact` | 6/6 | 38.7 s | OK |
| `dp_validation` | 4/4 | 1096.0 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `revue_c` | 6/6 | 0.0 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `structure_miss` | 4/4 | 2.5 s | OK |
| `isd_reel` | 5/5 | 58.3 s | OK |
| `isd_comparaison` | 5/5 | 243.8 s | OK |
| `diffusion_support` | 10/10 | 13.7 s | OK |
| `kem_distributions` | 11/11 | 11.8 s | OK |
| `h1p_fourier` | 6/6 | 0.0 s | OK |
| `invariants` | 5/5 | 0.2 s | OK |
| `kem_rejet` | 6/6 | 61.5 s | OK |
| `kem_theta` | 7/7 | 457.6 s | OK |
| `brume_gd2` | 4/4 | 29.2 s | OK |
| `sig_flux` | 5/5 | 1.0 s | OK |
| `sig_kz` | 10/10 | 20.3 s | OK |
| `brume_attaques` | 9/9 | 41.0 s | OK |
| `mini_brume` | 6/6 | 116.9 s | OK |
| `vole_proto` | 30/30 | 13.3 s | OK |
| `compression_sig` | 2/2 | 19.2 s | OK |
| `brume_algebre` | 15/15 | 199.4 s | OK |
