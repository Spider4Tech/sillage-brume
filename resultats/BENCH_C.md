# Benchmark de l'implémentation C — SILLAGE v0.4

AMD Ryzen 5 5600G with Radeon Graphics, **un seul cœur** (sauf les lignes « tous les cœurs ») ; gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, `-O3 -march=native` ; Python 3.12.3 pour la référence — 2026-10-31 13:11.
Implémentation C conforme octet pour octet au Python (`tests/test_c_impl.py`). Allers-retours vérifiés : **tous OK**.

Permutation BRUME-512 (32 tours) : **0.390 µs** en AVX2 constant-time (2,562,788 permutations/s) ; référence par tables 4.88 µs ; par lots de 32 états : 193 ns par état.
Message de 64 o (AEAD-128) : 3.39 µs avec la clé à chaque appel, **2.65 µs** avec un contexte de clé précalculé.

## KEM et signature

| Opération | C | Python | Facteur |
|---|---|---|---|
| Sillage-128 keygen | 6.27 ms | 154 ms | ×25 |
| Sillage-128 encaps | 0.206 ms | 3.45 ms | ×17 |
| Sillage-128 decaps | 0.317 ms | 17.8 ms | ×56 |
| Sillage-128 encaps pk changeante | 0.263 ms | — | — |
| Sillage-256 keygen | 26.7 ms | 676 ms | ×25 |
| Sillage-256 encaps | 1.19 ms | 16.3 ms | ×14 |
| Sillage-256 decaps | 1.86 ms | 58.6 ms | ×32 |
| Sillage-256 encaps pk changeante | 1.44 ms | — | — |
| Sillage-SIG-128 keygen | 0.276 ms | 18.3 ms | ×66 |
| Sillage-SIG-128 sign | 34.4 ms | 2.06 s | ×60 |
| Sillage-SIG-128 verify | 34.3 ms | 2.06 s | ×60 |
| Sillage-SIG-128 sign tous les coeurs | 5.47 ms | — | — |
| Sillage-SIG-128 verify tous les coeurs | 6.5 ms | — | — |
| Sillage-SIG-256 keygen | 1.04 ms | 74.7 ms | ×72 |
| Sillage-SIG-256 sign | 121 ms | 6.6 s | ×54 |
| Sillage-SIG-256 verify | 121 ms | 6.59 s | ×55 |
| Sillage-SIG-256 sign tous les coeurs | 18.4 ms | — | — |
| Sillage-SIG-256 verify tous les coeurs | 17.8 ms | — | — |

Tailles : Sillage-128 pk 6,285 o / ct 9,837 o, Sillage-256 pk 21,283 o / ct 35,587 o ; Sillage-SIG-128 signature 8,522 o, Sillage-SIG-256 signature 34,867 o.

## Chiffrement selon la taille (contenu aléatoire)

| Taille | AEAD-128 | Mio/s | Python | Facteur | AEAD-256 | Mio/s | TE chiffr. | TE corr. | Hachage | Hybride KEM+AEAD |
|---|---|---|---|---|---|---|---|---|---|---|
| 0 o | 0.00266 ms | — | 2.53 ms | ×951 | 0.00413 ms | — | 0.00266 ms | — | 0.00077 ms | 0.2 ms |
| 16 o | 0.00266 ms | 5.74 | 2.49 ms | ×936 | 0.00449 ms | 3.40 | 0.00281 ms | 0.00281 ms | 0.00077 ms | 0.2 ms |
| 64 o | 0.00339 ms | 18.00 | 3.13 ms | ×923 | 0.00561 ms | 10.88 | 0.00356 ms | 0.00356 ms | 0.0015 ms | 0.2 ms |
| 256 o | 0.0056 ms | 43.60 | 4.99 ms | ×891 | 0.01 ms | 24.34 | 0.00671 ms | 0.00661 ms | 0.00371 ms | 0.202 ms |
| 1 Kio | 0.0144 ms | 67.96 | 12.4 ms | ×865 | 0.0278 ms | 35.12 | 0.0192 ms | 0.0186 ms | 0.0126 ms | 0.211 ms |
| 4 Kio | 0.0497 ms | 78.64 | 42.1 ms | ×848 | 0.0986 ms | 39.61 | 0.0687 ms | 0.0667 ms | 0.0481 ms | 0.245 ms |
| 16 Kio | 0.191 ms | 81.93 | 162 ms | ×848 | 0.384 ms | 40.74 | 0.482 ms | 0.482 ms | 0.19 ms | 0.388 ms |
| 64 Kio | 0.76 ms | 82.19 | 640 ms | ×842 | 1.53 ms | 40.76 | 2 ms | 1.99 ms | 0.763 ms | 0.959 ms |
| 256 Kio | 3 ms | 83.30 | 2.54 s | ×848 | 6.05 ms | 41.30 | 7.93 ms | 7.87 ms | 3.02 ms | 3.2 ms |
| 1 Mio | 12 ms | 83.20 | 10.2 s | ×845 | 24.2 ms | 41.31 | 31.7 ms | 31.4 ms | 12.1 ms | 12.2 ms |
| 4 Mio | 48 ms | 83.28 | — | — | 96.8 ms | 41.32 | 127 ms | 126 ms | 48.3 ms | 48.2 ms |
| 16 Mio | 193 ms | 82.88 | — | — | 392 ms | 40.82 | 509 ms | 511 ms | 194 ms | 193 ms |

## Chiffrement multi-messages (AEAD-128, lots de 32, 32 Mio au total)

| Taille d'un message | Messages | 1 cœur | Tous les cœurs | Tous les cœurs, clé commune | Hachage, tous les cœurs |
|---|---|---|---|---|---|
| 64 o | 524,288 | 32 Mo/s | **157 Mo/s** (12 threads) | **195 Mo/s** | 369 Mo/s |
| 1 Kio | 32,768 | 105 Mo/s | **623 Mo/s** (12 threads) | **654 Mo/s** | 810 Mo/s |
| 16 Kio | 2,048 | 126 Mo/s | **685 Mo/s** (12 threads) | **690 Mo/s** | 786 Mo/s |
| 1 Mio | 32 | 125 Mo/s | **498 Mo/s** (12 threads) | **493 Mo/s** | 496 Mo/s |

## Hachage d'un seul gros message : séquentiel et arborescent

| Taille | Séquentiel (1 cœur) | Arbre, 1 cœur | Arbre, tous les cœurs |
|---|---|---|---|
| 1 Mio | 78 Mo/s | 150 Mo/s | **496 Mo/s** (12 threads) |
| 16 Mio | 86 Mo/s | 161 Mo/s | **793 Mo/s** (12 threads) |

Le hachage arborescent (`sl_hash_arbre`, PREUVES § 4.4) est une fonction distincte du hachage séquentiel (autres KAT).

## AEAD d'un seul message : séquentiel et duplex parallèle (BRUME-512p)

| Taille | Séquentiel (1 cœur) | Parallèle, 1 cœur | Parallèle, tous les cœurs |
|---|---|---|---|
| 16 Kio | 86 Mo/s | 82 Mo/s | **171 Mo/s** (12 threads) |
| 256 Kio | 86 Mo/s | 151 Mo/s | **454 Mo/s** (12 threads) |
| 1 Mio | 86 Mo/s | 151 Mo/s | **522 Mo/s** (12 threads) |
| 16 Mio | 86 Mo/s | 150 Mo/s | **777 Mo/s** (12 threads) |

## Selon la nature du contenu (16 Mio)

| Nature | AEAD-128 | Mio/s | Hachage | Aller-retour |
|---|---|---|---|---|
| texte | 193 ms | 83.04 | 194 ms | OK |
| aleatoire | 193 ms | 82.88 | 194 ms | OK |
| zeros | 192 ms | 83.18 | 193 ms | OK |
| json | 193 ms | 83.04 | 193 ms | OK |

Coût fixe du schéma hybride (Sillage-128 + BRUME-512) : encapsulation ≈ 0.197 ms, décapsulation (ré-encapsulation FO comprise) ≈ 0.316 ms.

BRUME-512 (permutation, AEAD, hachage), KEM et SIG (côté signataire) : **constant-time** (vérifié par dudect, `tests/test_c_temps.py`). Sauf mention contraire, un seul cœur.
