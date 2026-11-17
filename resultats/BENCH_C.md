# Benchmark de l'implémentation C — SILLAGE v0.6

AMD Ryzen 5 5600G with Radeon Graphics, **un seul cœur** (sauf les lignes « tous les cœurs ») ; gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, `-O3 -march=native` ; Python 3.12.3 pour la référence — 2026-11-17 22:10.
KEM et SIG conformes octet pour octet au Python (`tests/test_c_impl.py`) ; BRUME-1024q contrôlée par les KAT de sa spécification (`tests/c/brume1024_api.c`). Allers-retours vérifiés : **tous OK**.

Permutation BRUME-1024q (1 024 bits, 32 tours) : **0.771 µs** en AVX2 constant-time (1,297,017 permutations/s) ; référence dense 755.70 µs ; par lots de 32 états : 725 ns par état.
Message de 64 o (AEAD BRUME-1024q) : **2.35 µs** avec la clé à chaque appel, 2.33 µs avec un contexte de clé (la clé est dans tout l'état : rien à précalculer).

## KEM et signature

| Opération | C | Python | Facteur |
|---|---|---|---|
| Sillage-128 keygen | 5.23 ms | 158 ms | ×30 |
| Sillage-128 encaps | 0.191 ms | 3.51 ms | ×18 |
| Sillage-128 decaps | 0.311 ms | 17.6 ms | ×57 |
| Sillage-128 encaps pk changeante | 0.261 ms | — | — |
| Sillage-256 keygen | 26 ms | 677 ms | ×26 |
| Sillage-256 encaps | 1.19 ms | 16.6 ms | ×14 |
| Sillage-256 decaps | 1.85 ms | 58.1 ms | ×31 |
| Sillage-256 encaps pk changeante | 1.45 ms | — | — |
| Sillage-SIG-128 keygen | 0.279 ms | 18.9 ms | ×68 |
| Sillage-SIG-128 sign | 34.9 ms | 2.05 s | ×59 |
| Sillage-SIG-128 verify | 34.7 ms | 2.08 s | ×60 |
| Sillage-SIG-128 sign tous les coeurs | 5.45 ms | — | — |
| Sillage-SIG-128 verify tous les coeurs | 5.37 ms | — | — |
| Sillage-SIG-256 keygen | 1.05 ms | 75.6 ms | ×72 |
| Sillage-SIG-256 sign | 122 ms | 6.63 s | ×54 |
| Sillage-SIG-256 verify | 120 ms | 6.77 s | ×56 |
| Sillage-SIG-256 sign tous les coeurs | 18.7 ms | — | — |
| Sillage-SIG-256 verify tous les coeurs | 17.8 ms | — | — |

Tailles : Sillage-128 pk 6,285 o / ct 9,837 o, Sillage-256 pk 21,283 o / ct 35,587 o ; Sillage-SIG-128 signature 8,522 o, Sillage-SIG-256 signature 34,867 o.

## Chiffrement selon la taille (contenu aléatoire)

| Taille | AEAD | Mio/s | TE chiffr. | TE corr. | Hachage (64 o) | Hybride KEM+AEAD |
|---|---|---|---|---|---|---|
| 0 o | 0.00233 ms | — | 0.00233 ms | — | 0.00079 ms | 0.194 ms |
| 16 o | 0.00233 ms | 6.55 | 0.00247 ms | 0.00264 ms | 0.00079 ms | 0.194 ms |
| 64 o | 0.00233 ms | 26.20 | 0.00249 ms | 0.00263 ms | 0.00079 ms | 0.194 ms |
| 256 o | 0.00457 ms | 53.42 | 0.00561 ms | 0.00646 ms | 0.00303 ms | 0.195 ms |
| 1 Kio | 0.0113 ms | 86.12 | 0.0157 ms | 0.0198 ms | 0.00979 ms | 0.202 ms |
| 4 Kio | 0.0407 ms | 95.91 | 0.058 ms | 0.0744 ms | 0.039 ms | 0.232 ms |
| 16 Kio | 0.156 ms | 100.31 | 0.45 ms | 0.731 ms | 0.156 ms | 0.347 ms |
| 64 Kio | 0.618 ms | 101.06 | 1.83 ms | 3.03 ms | 0.623 ms | 0.809 ms |
| 256 Kio | 2.47 ms | 101.35 | 7.37 ms | 12.2 ms | 2.5 ms | 2.66 ms |
| 1 Mio | 9.9 ms | 101.02 | 29.8 ms | 48.7 ms | 9.83 ms | 10.1 ms |
| 4 Mio | 39.6 ms | 101.08 | 117 ms | 195 ms | 26.5 ms | 39.8 ms |
| 16 Mio | 158 ms | 101.27 | 471 ms | 782 ms | 70.1 ms | 158 ms |

## Chiffrement multi-messages (AEAD BRUME-1024q, lots de 32 et 256 états, 32 Mio au total)

| Taille d'un message | Messages | 1 cœur | Tous les cœurs | Tous les cœurs, clé commune | Hachage, tous les cœurs |
|---|---|---|---|---|---|
| 64 o | 524,288 | 73 Mo/s | **265 Mo/s** (12 threads) | **177 Mo/s** | 507 Mo/s |
| 1 Kio | 32,768 | 186 Mo/s | **515 Mo/s** (12 threads) | **565 Mo/s** | 662 Mo/s |
| 16 Kio | 2,048 | 207 Mo/s | **523 Mo/s** (12 threads) | **674 Mo/s** | 671 Mo/s |
| 1 Mio | 32 | 94 Mo/s | **402 Mo/s** (12 threads) | **613 Mo/s** | 610 Mo/s |

## Hachage d'un seul gros message : XOF (éponge) et condensé par défaut (arbre)

| Taille | XOF (1 cœur) | Condensé, 1 cœur | Condensé, tous les cœurs |
|---|---|---|---|
| 1 Mio | 106 Mo/s | 107 Mo/s | **596 Mo/s** (12 threads) |
| 16 Mio | 106 Mo/s | 240 Mo/s | **873 Mo/s** (12 threads) |

Le condensé par défaut `sl_hash` (SPEC § 3.4) est l'éponge seule jusqu'à 8 Kio et un arbre au-delà ; le XOF `sl_xof` est une autre fonction (autre domaine, autres KAT).

## AEAD d'un seul message : séquentiel et AEAD parallèle (BRUME-1024qp)

| Taille | Séquentiel (1 cœur) | Parallèle, 1 cœur | Parallèle, tous les cœurs |
|---|---|---|---|
| 16 Kio | 105 Mo/s | 101 Mo/s | **101 Mo/s** (12 threads) |
| 256 Kio | 106 Mo/s | 102 Mo/s | **556 Mo/s** (12 threads) |
| 1 Mio | 105 Mo/s | 101 Mo/s | **594 Mo/s** (12 threads) |
| 16 Mio | 106 Mo/s | 103 Mo/s | **627 Mo/s** (12 threads) |

## Selon la nature du contenu (16 Mio)

| Nature | AEAD | Mio/s | Hachage | Aller-retour |
|---|---|---|---|---|
| texte | 159 ms | 100.70 | 70.5 ms | OK |
| aleatoire | 158 ms | 101.27 | 70.1 ms | OK |
| zeros | 158 ms | 101.29 | 70.8 ms | OK |
| json | 158 ms | 101.06 | 70.4 ms | OK |

Coût fixe du schéma hybride (Sillage-128 + BRUME-1024q) : encapsulation ≈ 0.191 ms, décapsulation (ré-encapsulation FO comprise) ≈ 0.311 ms.

BRUME-1024q (permutation, AEAD, hachage), KEM et SIG (côté signataire) : **constant-time** (vérifié par dudect, `tests/test_c_temps.py` et `tests/c/temps1024.c`, et par ctgrind). Sauf mention contraire, un seul cœur.
