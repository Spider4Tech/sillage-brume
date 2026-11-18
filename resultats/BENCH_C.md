# Benchmark de l'implémentation C — SILLAGE v0.6

AMD Ryzen 5 5600G with Radeon Graphics, **un seul cœur** (sauf les lignes « tous les cœurs ») ; gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, `-O3 -march=native` ; Python 3.12.3 pour la référence — 2026-11-18 10:19.
KEM et SIG conformes octet pour octet au Python (`tests/test_c_impl.py`) ; BRUME-1024q contrôlée par les KAT de sa spécification (`tests/c/brume1024_api.c`). Allers-retours vérifiés : **tous OK**.

Permutation BRUME-1024q (1 024 bits, 32 tours) : **0.770 µs** en AVX2 constant-time (1,297,859 permutations/s) ; référence dense 1176.26 µs ; par lots de 32 états : 681 ns par état.
Message de 64 o (AEAD BRUME-1024q) : **2.32 µs** avec la clé à chaque appel, 2.32 µs avec un contexte de clé (la clé est dans tout l'état : rien à précalculer).

## KEM et signature

| Opération | C | Python | Facteur |
|---|---|---|---|
| Sillage-256 keygen | 27.4 ms | 676 ms | ×25 |
| Sillage-256 encaps | 1.18 ms | 16.4 ms | ×14 |
| Sillage-256 decaps | 1.84 ms | 58.7 ms | ×32 |
| Sillage-256 encaps pk changeante | 1.43 ms | — | — |
| Sillage-SIG-128 keygen | 0.276 ms | 19.2 ms | ×70 |
| Sillage-SIG-128 sign | 35 ms | 2.06 s | ×59 |
| Sillage-SIG-128 verify | 34.8 ms | 2.07 s | ×60 |
| Sillage-SIG-128 sign tous les coeurs | 5.39 ms | — | — |
| Sillage-SIG-128 verify tous les coeurs | 5.36 ms | — | — |
| Sillage-SIG-256 keygen | 1.05 ms | 75.2 ms | ×72 |
| Sillage-SIG-256 sign | 124 ms | 6.56 s | ×53 |
| Sillage-SIG-256 verify | 122 ms | 6.79 s | ×56 |
| Sillage-SIG-256 sign tous les coeurs | 18.3 ms | — | — |
| Sillage-SIG-256 verify tous les coeurs | 17.9 ms | — | — |

Tailles : Sillage-256 pk 21,283 o / ct 35,587 o ; Sillage-SIG-128 signature 8,522 o, Sillage-SIG-256 signature 34,867 o.

## Chiffrement selon la taille (contenu aléatoire)

| Taille | AEAD | Mio/s | TE chiffr. | TE corr. | Hachage (64 o) | Hybride KEM+AEAD |
|---|---|---|---|---|---|---|
| 0 o | 0.00232 ms | — | 0.00233 ms | — | 0.00079 ms | 1.18 ms |
| 16 o | 0.00232 ms | 6.58 | 0.00246 ms | 0.00263 ms | 0.00079 ms | 1.18 ms |
| 64 o | 0.00232 ms | 26.31 | 0.00247 ms | 0.00263 ms | 0.00079 ms | 1.18 ms |
| 256 o | 0.00457 ms | 53.42 | 0.00567 ms | 0.00679 ms | 0.00307 ms | 1.18 ms |
| 1 Kio | 0.0115 ms | 85.07 | 0.0156 ms | 0.02 ms | 0.00977 ms | 1.2 ms |
| 4 Kio | 0.0407 ms | 96.05 | 0.0576 ms | 0.0754 ms | 0.039 ms | 1.22 ms |
| 16 Kio | 0.156 ms | 100.33 | 0.442 ms | 0.755 ms | 0.156 ms | 1.33 ms |
| 64 Kio | 0.619 ms | 101.01 | 1.82 ms | 3.11 ms | 0.623 ms | 1.79 ms |
| 256 Kio | 2.47 ms | 101.25 | 7.3 ms | 12.5 ms | 2.49 ms | 3.64 ms |
| 1 Mio | 9.87 ms | 101.33 | 29.2 ms | 49.9 ms | 9.2 ms | 11 ms |
| 4 Mio | 39.4 ms | 101.44 | 117 ms | 200 ms | 25.3 ms | 40.6 ms |
| 16 Mio | 158 ms | 101.31 | 468 ms | 806 ms | 69.1 ms | 159 ms |

## Chiffrement multi-messages (AEAD BRUME-1024q, lots de 32 et 256 états, 32 Mio au total)

| Taille d'un message | Messages | 1 cœur | Tous les cœurs | Tous les cœurs, clé commune | Hachage, tous les cœurs |
|---|---|---|---|---|---|
| 64 o | 524,288 | 73 Mo/s | **266 Mo/s** (12 threads) | **175 Mo/s** | 505 Mo/s |
| 1 Kio | 32,768 | 188 Mo/s | **530 Mo/s** (12 threads) | **570 Mo/s** | 666 Mo/s |
| 16 Kio | 2,048 | 208 Mo/s | **538 Mo/s** (12 threads) | **668 Mo/s** | 668 Mo/s |
| 1 Mio | 32 | 98 Mo/s | **408 Mo/s** (12 threads) | **609 Mo/s** | 606 Mo/s |

## Hachage d'un seul gros message : XOF (éponge) et condensé par défaut (arbre)

| Taille | XOF (1 cœur) | Condensé, 1 cœur | Condensé, tous les cœurs |
|---|---|---|---|
| 1 Mio | 107 Mo/s | 114 Mo/s | **597 Mo/s** (12 threads) |
| 16 Mio | 107 Mo/s | 244 Mo/s | **838 Mo/s** (12 threads) |

Le condensé par défaut `sl_hash` (SPEC § 3.4) est l'éponge seule jusqu'à 8 Kio et un arbre au-delà ; le XOF `sl_xof` est une autre fonction (autre domaine, autres KAT).

## AEAD d'un seul message : séquentiel et AEAD parallèle (BRUME-1024qp)

| Taille | Séquentiel (1 cœur) | Parallèle, 1 cœur | Parallèle, tous les cœurs |
|---|---|---|---|
| 16 Kio | 105 Mo/s | 101 Mo/s | **101 Mo/s** (12 threads) |
| 256 Kio | 106 Mo/s | 103 Mo/s | **543 Mo/s** (12 threads) |
| 1 Mio | 106 Mo/s | 103 Mo/s | **608 Mo/s** (12 threads) |
| 16 Mio | 106 Mo/s | 103 Mo/s | **626 Mo/s** (12 threads) |

## Selon la nature du contenu (16 Mio)

| Nature | AEAD | Mio/s | Hachage | Aller-retour |
|---|---|---|---|---|
| texte | 158 ms | 101.37 | 67.9 ms | OK |
| aleatoire | 158 ms | 101.31 | 69.1 ms | OK |
| zeros | 160 ms | 99.99 | 68.6 ms | OK |
| json | 158 ms | 101.23 | 69.1 ms | OK |

Coût fixe du schéma hybride (Sillage-256 + BRUME-1024q) : encapsulation ≈ 1.18 ms, décapsulation (ré-encapsulation FO comprise) ≈ 1.84 ms.

BRUME-1024q (permutation, AEAD, hachage), KEM et SIG (côté signataire) : **constant-time** (vérifié par dudect, `tests/test_c_temps.py` et `tests/c/temps1024.c`, et par ctgrind). Sauf mention contraire, un seul cœur.
