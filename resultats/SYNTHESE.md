# Synthèse de la batterie SILLAGE v0.5

800/800 contrôles réussis — 70 tests — 13185 s cumulées (2026-11-11 19:56). Batterie complète du 11 novembre 2026 (14 h 01 – 16 h 44), puis relance de 9 tests corrigés ou complétés (marqués « relancé »).

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` (relancé) | 10/10 | 38.9 s | OK |

## Modes BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `aead` | 12/12 | 9.2 s | OK |
| `te` | 12/12 | 9.1 s | OK |
| `hachage` | 9/9 | 21.6 s | OK |
| `mode_aead` | 9/9 | 3.7 s | OK |
| `aead_modele` | 14/14 | 16.8 s | OK |
| `hachage_arbre` | 16/16 | 64.9 s | OK |
| `indiff_arbre` | 15/15 | 8.5 s | OK |
| `aead_parallele` (relancé) | 27/27 | 99.1 s | OK |

## Permutation BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `branch_exact` | 5/5 | 97.0 s | OK |
| `banc_cryptanalyse` | 8/8 | 31.3 s | OK |
| `diff_lin_empirique` | 4/4 | 10.8 s | OK |
| `cycles` | 3/3 | 6.8 s | OK |
| `beam_trails` | 2/2 | 131.9 s | OK |
| `integral_degre` | 2/2 | 6.0 s | OK |
| `symetries_invariants` | 9/9 | 3.2 s | OK |
| `hull` | 3/3 | 7.6 s | OK |
| `division_property` (relancé) | 3/3 | 296.0 s | OK |
| `diffusion_stats` | 5/5 | 17.0 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | 62.8 s | OK |
| `kem_lemme3` | 20/20 | 31.3 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 42.2 s | OK |
| `sig_modele` | 22/22 | 153.3 s | OK |
| `sig_hvzk` | 10/10 | 19.1 s | OK |

## Sillage-SIG v0.5 (VOLE)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `vole` | 21/21 | 118.2 s | OK |
| `vole_kz` (relancé) | 3/3 | 89.3 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 31/31 | 127.6 s | OK |
| `bornes_preuves` | 30/30 | 5.8 s | OK |
| `select_params` | 17/17 | 173.9 s | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 3.2 s | OK |
| `erreurs_api` (relancé) | 26/26 | 78.0 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 38/38 | 119.6 s | OK |
| `c_fuzz` | 5/5 | 37.8 s | OK |
| `c_sig_valgrind` | 3/3 | 246.6 s | OK |
| `c_kem_valgrind` | 3/3 | 62.5 s | OK |
| `c_vole_valgrind` | 5/5 | 55.6 s | OK |
| `api_c` | 42/42 | 68.6 s | OK |
| `c_simd` | 3/3 | 40.6 s | OK |
| `c_limites` | 9/9 | 5.8 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_integral` | 3/3 | 76.0 s | OK |
| `c_diff_lin` | 5/5 | 274.7 s | OK |
| `c_sac` | 5/5 | 52.8 s | OK |
| `c_statistiques` | 5/5 | 102.7 s | OK |
| `c_kem_bruit` | 9/9 | 146.3 s | OK |
| `c_cube_init` | 4/4 | 41.2 s | OK |
| `c_degre` | 5/5 | 411.4 s | OK |
| `c_temps` | 13/13 | 77.8 s | OK |
| `c_vole_temps` | 3/3 | 17.8 s | OK |
| `dp_modele` | 6/6 | 18.6 s | OK |
| `dp_tous_cubes` (relancé) | 3/3 | 1332.0 s | OK |
| `dp_exact` | 6/6 | 2974.7 s | OK |
| `dp_validation` (relancé) | 4/4 | 3921.3 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `revue_c` | 6/6 | 0.0 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `structure_miss` | 4/4 | 2.5 s | OK |
| `isd_reel` | 5/5 | 59.0 s | OK |
| `isd_comparaison` | 5/5 | 247.3 s | OK |
| `diffusion_support` | 10/10 | 13.8 s | OK |
| `kem_distributions` | 11/11 | 11.8 s | OK |
| `h1p_fourier` | 6/6 | 0.0 s | OK |
| `invariants` | 5/5 | 0.2 s | OK |
| `kem_rejet` | 6/6 | 61.9 s | OK |
| `kem_theta` | 7/7 | 467.6 s | OK |
| `brume_gd2` | 4/4 | 32.3 s | OK |
| `sig_flux` | 5/5 | 0.9 s | OK |
| `sig_kz` | 10/10 | 20.5 s | OK |
| `brume_attaques` | 8/8 | 42.5 s | OK |
| `mini_brume` | 6/6 | 117.1 s | OK |
| `vole_proto` (relancé) | 86/86 | 30.2 s | OK |
| `compression_sig` | 2/2 | 17.1 s | OK |
| `brume_algebre` (relancé) | 18/18 | 192.3 s | OK |
