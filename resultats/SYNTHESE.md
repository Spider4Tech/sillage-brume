# Synthèse de la batterie SILLAGE v0.5

800/800 contrôles réussis — 70 tests (2026-11-13 12:16).

**Synthèse reconstituée.** La machine s'est éteinte pendant le dernier test (`brume_algebre`), avant que `run_all` n'écrive la synthèse. Les 69 autres tests étaient finis ; `brume_algebre` a été relancé seul le 2026-11-13 à 19:07. Les contrôles viennent de `resultats/<test>.json` ; les durées par test sont perdues (n.d.) ; le code retour est déduit du journal (aucune trace d'exception).

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 10/10 | n.d. | OK |

## Modes BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `aead` | 12/12 | n.d. | OK |
| `te` | 12/12 | n.d. | OK |
| `hachage` | 9/9 | n.d. | OK |
| `mode_aead` | 9/9 | n.d. | OK |
| `aead_modele` | 14/14 | n.d. | OK |
| `hachage_arbre` | 16/16 | n.d. | OK |
| `indiff_arbre` | 15/15 | n.d. | OK |
| `aead_parallele` | 27/27 | n.d. | OK |

## Permutation BRUME

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `branch_exact` | 5/5 | n.d. | OK |
| `banc_cryptanalyse` | 8/8 | n.d. | OK |
| `diff_lin_empirique` | 4/4 | n.d. | OK |
| `cycles` | 3/3 | n.d. | OK |
| `beam_trails` | 2/2 | n.d. | OK |
| `integral_degre` | 2/2 | n.d. | OK |
| `symetries_invariants` | 9/9 | n.d. | OK |
| `hull` | 3/3 | n.d. | OK |
| `division_property` | 3/3 | n.d. | OK |
| `diffusion_stats` | 5/5 | n.d. | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | n.d. | OK |
| `kem_lemme3` | 20/20 | n.d. | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | n.d. | OK |
| `sig_modele` | 22/22 | n.d. | OK |
| `sig_hvzk` | 10/10 | n.d. | OK |

## Sillage-SIG v0.5 (VOLE)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `vole` | 21/21 | n.d. | OK |
| `vole_kz` | 3/3 | n.d. | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 31/31 | n.d. | OK |
| `bornes_preuves` | 30/30 | n.d. | OK |
| `select_params` | 17/17 | n.d. | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | n.d. | OK |
| `erreurs_api` | 26/26 | n.d. | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 38/38 | n.d. | OK |
| `c_fuzz` | 5/5 | n.d. | OK |
| `c_sig_valgrind` | 3/3 | n.d. | OK |
| `c_kem_valgrind` | 3/3 | n.d. | OK |
| `c_vole_valgrind` | 5/5 | n.d. | OK |
| `api_c` | 42/42 | n.d. | OK |
| `c_simd` | 3/3 | n.d. | OK |
| `c_limites` | 9/9 | n.d. | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_integral` | 3/3 | n.d. | OK |
| `c_diff_lin` | 5/5 | n.d. | OK |
| `c_sac` | 5/5 | n.d. | OK |
| `c_statistiques` | 5/5 | n.d. | OK |
| `c_kem_bruit` | 9/9 | n.d. | OK |
| `c_cube_init` | 4/4 | n.d. | OK |
| `c_degre` | 5/5 | n.d. | OK |
| `c_temps` | 13/13 | n.d. | OK |
| `c_vole_temps` | 3/3 | n.d. | OK |
| `dp_modele` | 6/6 | n.d. | OK |
| `dp_tous_cubes` | 3/3 | n.d. | OK |
| `dp_exact` | 6/6 | n.d. | OK |
| `dp_validation` | 4/4 | n.d. | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `revue_c` | 6/6 | n.d. | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `structure_miss` | 4/4 | n.d. | OK |
| `isd_reel` | 5/5 | n.d. | OK |
| `isd_comparaison` | 5/5 | n.d. | OK |
| `diffusion_support` | 10/10 | n.d. | OK |
| `kem_distributions` | 11/11 | n.d. | OK |
| `h1p_fourier` | 6/6 | n.d. | OK |
| `invariants` | 5/5 | n.d. | OK |
| `kem_rejet` | 6/6 | n.d. | OK |
| `kem_theta` | 7/7 | n.d. | OK |
| `brume_gd2` | 4/4 | n.d. | OK |
| `sig_flux` | 5/5 | n.d. | OK |
| `sig_kz` | 10/10 | n.d. | OK |
| `brume_attaques` | 8/8 | n.d. | OK |
| `mini_brume` | 6/6 | n.d. | OK |
| `vole_proto` | 86/86 | n.d. | OK |
| `compression_sig` | 2/2 | n.d. | OK |
| `brume_algebre` | 18/18 | n.d. | OK |
