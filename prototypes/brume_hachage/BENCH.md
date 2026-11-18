# Bench comparatif : KEM et signatures avec BRUME-1024q à la place de SHAKE256

Prototype `prototypes/brume_hachage` (hors suite). Même code du KEM et des signatures, seule la couche de hachage change (README.md). Mesuré le 18/11/2026, AMD Ryzen 5 5600G with Radeon Graphics, gcc (GCC) 16.2.1 20261029 (Red Hat 16.2.1-3), 12 threads pour les colonnes « tous les cœurs » ; sinon un cœur. Tous les allers-retours vérifiés, une signature et un chiffré altérés refusés : **oui**. À c = 384, l'éponge du prototype est égale bit à bit à `sl_xof` de la bibliothèque : **oui**.

Le facteur est le temps de la variante BRUME divisé par celui de SHAKE256 (×2 = deux fois plus lent) ; pour les débits, SHAKE256 divisé par BRUME. « Perm. » : permutations BRUME-1024q par opération.

| Opération | SHAKE256 | BRUME c = 384 | facteur | BRUME c = 512 | facteur | Perm. c = 384 | Perm. c = 512 |
|---|---|---|---|---|---|---|---|
| Hachage 64 o → 32 o | 0.285 µs | 0.814 µs | ×2.85 | 1.58 µs | ×5.53 | 1 | 2 |
| Absorption (64 Kio) | 471 Mo/s | 102 Mo/s | ×4.63 | 82.10 Mo/s | ×5.74 |  |  |
| Extraction | 592 Mo/s | 106 Mo/s | ×5.59 | 84.10 Mo/s | ×7.04 |  |  |
| Flux d'entiers (mode compteur) | 526 Mo/s | 79.10 Mo/s | ×6.65 | 79.40 Mo/s | ×6.62 |  |  |
| KEM-256 keygen | 29.09 ms | 28.36 ms | ×0.97 | 28.27 ms | ×0.97 | 1622 | 1697 |
| KEM-256 encaps | 0.947 ms | 1.31 ms | ×1.39 | 1.40 ms | ×1.48 | 843 | 1020 |
| KEM-256 decaps | 1.54 ms | 2.36 ms | ×1.53 | 2.58 ms | ×1.67 | 1289 | 1577 |
| KEM-256 encaps, pk changeante | 1.20 ms | 2.78 ms | ×2.31 | 2.97 ms | ×2.48 |  |  |
| VOLE-256 keygen | 7.98 ms | 121 ms | ×15.14 | 122 ms | ×15.25 |  |  |
| VOLE-256 sign | 99.33 ms | 869 ms | ×8.75 | 996 ms | ×10.03 | 1023458 | 1273769 |
| VOLE-256 verify | 90.59 ms | 825 ms | ×9.11 | 965 ms | ×10.65 | 995548 | 1185442 |
| VOLE-256 sign, tous les cœurs | 20.65 ms | 149 ms | ×7.22 | 175 ms | ×8.48 |  |  |
| VOLE-256 verify, tous les cœurs | 19.01 ms | 145 ms | ×7.63 | 169 ms | ×8.92 |  |  |
| VOLE-256f keygen | 8.09 ms | 121 ms | ×14.96 | 121 ms | ×14.97 |  |  |
| VOLE-256f sign | 33.63 ms | 210 ms | ×6.23 | 223 ms | ×6.63 | 233974 | 263422 |
| VOLE-256f verify | 26.75 ms | 200 ms | ×7.49 | 215 ms | ×8.05 | 232944 | 251639 |
| VOLE-256f sign, tous les cœurs | 6.43 ms | 35.93 ms | ×5.59 | 41.88 ms | ×6.51 |  |  |
| VOLE-256f verify, tous les cœurs | 5.24 ms | 34.38 ms | ×6.57 | 39.57 ms | ×7.56 |  |  |
| Sillage-SIG-128 (v0.4) keygen | 0.270 ms | 1.42 ms | ×5.25 | 2.50 ms | ×9.27 |  |  |
| Sillage-SIG-128 (v0.4) sign | 34.84 ms | 348 ms | ×10.00 | 523 ms | ×15.01 |  |  |
| Sillage-SIG-128 (v0.4) verify | 34.98 ms | 349 ms | ×9.97 | 522 ms | ×14.93 |  |  |
| Sillage-SIG-128 (v0.4) sign, tous les cœurs | 5.33 ms | 57.60 ms | ×10.80 | 87.17 ms | ×16.34 |  |  |
| Sillage-SIG-256 (v0.4) keygen | 1.03 ms | 5.21 ms | ×5.07 | 7.38 ms | ×7.17 |  |  |
| Sillage-SIG-256 (v0.4) sign | 124 ms | 1489 ms | ×12.02 | 1794 ms | ×14.48 |  |  |
| Sillage-SIG-256 (v0.4) verify | 123 ms | 1489 ms | ×12.10 | 1789 ms | ×14.53 |  |  |
| Sillage-SIG-256 (v0.4) sign, tous les cœurs | 18.07 ms | 235 ms | ×12.98 | 284 ms | ×15.75 |  |  |

Tailles (inchangées par la variante) : VOLE-256 16122 o, VOLE-256f 20467 o, SIG-128 v0.4 8522 o, SIG-256 v0.4 34867 o.
