# Synthèse de la batterie SILLAGE v0.6

627/627 contrôles réussis — 45 tests — 2382 s (2026-11-18 07:39).

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 11/11 | 7.6 s | OK |

## BRUME-1024q : modes

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `brume1024_api` | 12/12 | 11.0 s | OK |
| `brume1024_api_portable` | 13/13 | 4.0 s | OK |
| `brume1024` | 33/33 | 21.6 s | OK |
| `b1024_seconde_implementation` | 6/6 | 400.6 s | OK |
| `b1024_preuves` | 12/12 | 476.9 s | OK |

## BRUME-1024q : permutation

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `b1024_certificats` | 1/1 | 0.5 s | OK |
| `b1024_structure` | 15/15 | 327.1 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | 33.7 s | OK |
| `kem_lemme3` | 20/20 | 15.0 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 17.9 s | OK |
| `sig_modele` | 22/22 | 64.7 s | OK |
| `sig_hvzk` | 10/10 | 30.4 s | OK |

## Sillage-SIG v0.5 (VOLE)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `vole` | 21/21 | 22.8 s | OK |
| `vole_kz` | 3/3 | 87.9 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 31/31 | 81.1 s | OK |
| `bornes_preuves` | 26/26 | 2.8 s | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 1.3 s | OK |
| `erreurs_api` | 21/21 | 61.2 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 32/32 | 52.5 s | OK |
| `c_fuzz` | 5/5 | 71.7 s | OK |
| `c_sig_valgrind` | 3/3 | 305.7 s | OK |
| `c_kem_valgrind` | 3/3 | 96.9 s | OK |
| `c_vole_valgrind` | 5/5 | 115.8 s | OK |
| `c_brume1024_valgrind` | 5/5 | 61.0 s | OK |
| `c_gadget_ssb` | 11/11 | 96.5 s | OK |
| `api_c` | 35/35 | 74.4 s | OK |
| `c_limites` | 9/9 | 4.9 s | OK |
| `revue_c` | 6/6 | 21.7 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `b1024_statistiques` | 4/4 | 241.7 s | OK |
| `b1024_etudes` | 4/4 | 301.9 s | OK |
| `temps1024` | 11/11 | 44.0 s | OK |
| `c_kem_bruit` | 9/9 | 107.5 s | OK |
| `c_temps` | 13/13 | 242.8 s | OK |
| `c_vole_temps` | 3/3 | 18.0 s | OK |
| `isd_reel` | 5/5 | 70.7 s | OK |
| `isd_comparaison` | 5/5 | 246.3 s | OK |
| `kem_distributions` | 11/11 | 23.2 s | OK |
| `h1p_fourier` | 6/6 | 9.1 s | OK |
| `kem_rejet` | 6/6 | 66.6 s | OK |
| `kem_theta` | 7/7 | 448.9 s | OK |
| `sig_flux` | 5/5 | 9.0 s | OK |
| `sig_kz` | 10/10 | 29.5 s | OK |
| `vole_proto` | 86/86 | 29.3 s | OK |
| `compression_sig` | 2/2 | 17.1 s | OK |
