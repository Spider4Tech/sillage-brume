# Synthèse de la batterie SILLAGE v0.6

616/616 contrôles réussis — 44 tests — 2177 s (2026-11-18 01:50).

**Relance.** Batterie complète du 18 novembre 2026 (01 h 14 – 01 h 50), sur les sources finales (noyau portable non inliné,
`docs/AUDIT_REPORT.md`, changements du 17 novembre). Elle a donné 615/616 : le contrôle de l'outil de rebond
(`rebond1024.py controle`, cas R = 3, m = 1) dépendait du temps réel du solveur et a manqué de budget pour couper un chemin
irréalisable. Il est passé en temps déterministe ; `b1024_etudes` a été relancé seul (4/4), marqué « relancé ».

Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.

## Fonctionnel

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `fonctionnel` | 11/11 | 21.4 s | OK |

## BRUME-1024q : modes

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `brume1024_api` | 12/12 | 0.5 s | OK |
| `brume1024_api_portable` | 13/13 | 0.6 s | OK |
| `brume1024` | 33/33 | 11.2 s | OK |
| `b1024_seconde_implementation` | 6/6 | 406.9 s | OK |
| `b1024_preuves` | 12/12 | 485.4 s | OK |

## BRUME-1024q : permutation

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `b1024_certificats` | 1/1 | 0.6 s | OK |
| `b1024_structure` | 15/15 | 320.2 s | OK |

## Sillage-KEM

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `kem` | 31/31 | 45.3 s | OK |
| `kem_lemme3` | 20/20 | 13.6 s | OK |

## Sillage-SIG

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `sig` | 37/37 | 17.6 s | OK |
| `sig_modele` | 22/22 | 73.5 s | OK |
| `sig_hvzk` | 10/10 | 28.9 s | OK |

## Sillage-SIG v0.5 (VOLE)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `vole` | 21/21 | 24.3 s | OK |
| `vole_kz` | 3/3 | 72.8 s | OK |

## Paramètres

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `isd_parametres` | 31/31 | 79.9 s | OK |
| `bornes_preuves` | 26/26 | 3.1 s | OK |

## Robustesse

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `robustesse` | 1/1 | 1.2 s | OK |
| `erreurs_api` | 21/21 | 50.3 s | OK |

## Implémentation C

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `c_impl` | 32/32 | 51.4 s | OK |
| `c_fuzz` | 5/5 | 70.5 s | OK |
| `c_sig_valgrind` | 3/3 | 315.0 s | OK |
| `c_kem_valgrind` | 3/3 | 102.2 s | OK |
| `c_vole_valgrind` | 5/5 | 121.6 s | OK |
| `c_brume1024_valgrind` | 5/5 | 59.2 s | OK |
| `api_c` | 35/35 | 72.8 s | OK |
| `c_limites` | 9/9 | 6.2 s | OK |
| `revue_c` | 6/6 | 0.1 s | OK |

## Intensif (C)

| Test | Contrôles | Durée | Statut |
|---|---|---|---|
| `b1024_statistiques` | 4/4 | 252.1 s | OK |
| `b1024_etudes` (relancé) | 4/4 | 151.9 s | OK |
| `temps1024` | 11/11 | 36.8 s | OK |
| `c_kem_bruit` | 9/9 | 104.4 s | OK |
| `c_temps` | 13/13 | 243.9 s | OK |
| `c_vole_temps` | 3/3 | 17.2 s | OK |
| `isd_reel` | 5/5 | 54.7 s | OK |
| `isd_comparaison` | 5/5 | 227.4 s | OK |
| `kem_distributions` | 11/11 | 16.2 s | OK |
| `h1p_fourier` | 6/6 | 0.0 s | OK |
| `kem_rejet` | 6/6 | 68.7 s | OK |
| `kem_theta` | 7/7 | 452.2 s | OK |
| `sig_flux` | 5/5 | 1.1 s | OK |
| `sig_kz` | 10/10 | 20.5 s | OK |
| `vole_proto` | 86/86 | 27.7 s | OK |
| `compression_sig` | 2/2 | 17.1 s | OK |
