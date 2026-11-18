# Synthèse de la batterie SILLAGE v0.6

570/570 contrôles réussis — 46 tests — 2515 s (2026-11-18 10:14).

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 10/10 | 8.8 s | OK |

## BRUME-1024q : modes

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `brume1024_api` | 12/12 | 0.6 s | OK |
| `brume1024_api_portable` | 13/13 | 0.6 s | OK |
| `brume1024` | 33/33 | 11.3 s | OK |
| `b1024_seconde_implementation` | 6/6 | 390.4 s | OK |
| `b1024_preuves` | 12/12 | 457.3 s | OK |

## BRUME-1024q : permutation

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `b1024_certificats` | 1/1 | 0.8 s | OK |
| `b1024_structure` | 15/15 | 303.5 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 16/16 | 28.7 s | OK |
| `kem_lemme3` | 10/10 | 18.4 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 17.5 s | OK |
| `sig_modele` | 22/22 | 98.9 s | OK |
| `sig_hvzk` | 10/10 | 39.5 s | OK |

## Sillage-SIG v0.5 (VOLE)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `vole` | 14/14 | 14.2 s | OK |
| `vole_kz` | 3/3 | 72.3 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 25/25 | 64.9 s | OK |
| `bornes_preuves` | 26/26 | 2.0 s | OK |
| `modele_portes` | 6/6 | 1.7 s | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 0.9 s | OK |
| `erreurs_api` | 21/21 | 28.7 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 28/28 | 33.6 s | OK |
| `c_fuzz` | 5/5 | 54.1 s | OK |
| `c_sig_valgrind` | 3/3 | 293.3 s | OK |
| `c_kem_valgrind` | 3/3 | 123.5 s | OK |
| `c_vole_valgrind` | 4/4 | 100.0 s | OK |
| `c_brume1024_valgrind` | 5/5 | 59.5 s | OK |
| `c_gadget_ssb` | 11/11 | 104.2 s | OK |
| `api_c` | 29/29 | 76.9 s | OK |
| `c_limites` | 9/9 | 5.6 s | OK |
| `revue_c` | 7/7 | 0.2 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `b1024_statistiques` | 4/4 | 242.2 s | OK |
| `b1024_etudes` | 4/4 | 301.7 s | OK |
| `temps1024` | 11/11 | 36.5 s | OK |
| `c_kem_bruit` | 5/5 | 47.3 s | OK |
| `c_temps` | 11/11 | 369.6 s | OK |
| `c_vole_temps` | 3/3 | 18.0 s | OK |
| `isd_reel` | 5/5 | 61.4 s | OK |
| `isd_comparaison` | 5/5 | 237.0 s | OK |
| `kem_distributions` | 6/6 | 6.7 s | OK |
| `h1p_fourier` | 6/6 | 0.0 s | OK |
| `kem_rejet` | 3/3 | 40.6 s | OK |
| `kem_theta` | 7/7 | 629.5 s | OK |
| `sig_flux` | 5/5 | 1.2 s | OK |
| `sig_kz` | 10/10 | 20.2 s | OK |
| `vole_proto` | 86/86 | 28.9 s | OK |
| `compression_sig` | 2/2 | 17.2 s | OK |
