# Synthèse de la batterie SILLAGE v0.6

615/617 contrôles réussis — 44 tests — 2206 s (2026-11-17 21:59).

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 11/11 | 8.2 s | OK |

## BRUME-1024q : modes

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `brume1024_api` | 12/12 | 0.6 s | OK |
| `brume1024_api_portable` | 13/13 | 0.6 s | OK |
| `brume1024` | 33/33 | 9.1 s | OK |
| `b1024_seconde_implementation` | 6/6 | 431.6 s | OK |
| `b1024_preuves` | 12/12 | 509.6 s | OK |

## BRUME-1024q : permutation

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `b1024_certificats` | 1/1 | 0.7 s | OK |
| `b1024_structure` | 15/15 | 341.5 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | 35.7 s | OK |
| `kem_lemme3` | 20/20 | 15.9 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 19.6 s | OK |
| `sig_modele` | 22/22 | 120.3 s | OK |
| `sig_hvzk` | 10/10 | 28.6 s | OK |

## Sillage-SIG v0.5 (VOLE)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `vole` | 21/21 | 28.1 s | OK |
| `vole_kz` | 3/3 | 89.0 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 31/31 | 95.6 s | OK |
| `bornes_preuves` | 26/26 | 2.1 s | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 0.7 s | OK |
| `erreurs_api` | 21/21 | 28.0 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 32/32 | 38.7 s | OK |
| `c_fuzz` | 5/5 | 66.1 s | OK |
| `c_sig_valgrind` | 3/3 | 320.3 s | OK |
| `c_kem_valgrind` | 3/3 | 109.7 s | OK |
| `c_vole_valgrind` | 5/5 | 130.1 s | OK |
| `c_brume1024_valgrind` | 5/5 | 71.6 s | OK |
| `api_c` | 35/35 | 124.8 s | OK |
| `c_limites` | 9/9 | 38.6 s | OK |
| `revue_c` | 6/6 | 0.1 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `b1024_statistiques` | 4/4 | 242.4 s | OK |
| `b1024_etudes` | 4/4 | 151.4 s | OK |
| `temps1024` | 10/12 | 49.3 s | ÉCHEC : permutation_portable_sans_fuite_detectee, execution_sans_erreur |
| `c_kem_bruit` | 9/9 | 105.6 s | OK |
| `c_temps` | 13/13 | 244.6 s | OK |
| `c_vole_temps` | 3/3 | 17.2 s | OK |
| `isd_reel` | 5/5 | 55.7 s | OK |
| `isd_comparaison` | 5/5 | 227.9 s | OK |
| `kem_distributions` | 11/11 | 11.3 s | OK |
| `h1p_fourier` | 6/6 | 0.0 s | OK |
| `kem_rejet` | 6/6 | 68.3 s | OK |
| `kem_theta` | 7/7 | 456.1 s | OK |
| `sig_flux` | 5/5 | 1.1 s | OK |
| `sig_kz` | 10/10 | 20.4 s | OK |
| `vole_proto` | 86/86 | 27.7 s | OK |
| `compression_sig` | 2/2 | 17.0 s | OK |
