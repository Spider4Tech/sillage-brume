# Benchmark par taille — SILLAGE v0.4

Python 3.12.3, numpy 2.5.4 — 2026-10-30 20:19. Allers-retours vérifiés : **tous OK**.

## Débit selon la taille (contenu aléatoire)

| Taille | AEAD-128 chiffr. | AEAD-128 déchiffr. | Kio/s | AEAD-256 | Kio/s | TE chiffr. | TE corr. | Hachage | Hybride KEM+AEAD |
|---|---|---|---|---|---|---|---|---|---|
| 0 o | 2.53 ms | 2.5 ms | — | 3.68 ms | — | 2.47 ms | 0.0 ms | 0.61 ms | 6.19 ms |
| 16 o | 2.49 ms | 2.52 ms | 6.3 | 4.01 ms | 3.9 | 2.48 ms | 2.49 ms | 0.61 ms | 6.0 ms |
| 64 o | 3.13 ms | 3.17 ms | 20.0 | 4.94 ms | 12.6 | 3.11 ms | 3.14 ms | 1.23 ms | 6.63 ms |
| 256 o | 4.99 ms | 5.0 ms | 50.1 | 8.67 ms | 28.8 | 5.04 ms | 5.05 ms | 3.08 ms | 8.5 ms |
| 1 Kio | 12.43 ms | 12.58 ms | 80.4 | 23.54 ms | 42.5 | 12.75 ms | 12.9 ms | 10.5 ms | 15.95 ms |
| 4 Kio | 42.14 ms | 42.05 ms | 94.9 | 83.0 ms | 48.2 | 43.66 ms | 44.06 ms | 40.16 ms | 45.77 ms |
| 16 Kio | 161.74 ms | 161.39 ms | 98.9 | 321.58 ms | 49.8 | 167.31 ms | 168.49 ms | 157.95 ms | 165.38 ms |
| 64 Kio | 640.37 ms | 644.41 ms | 99.9 | 1274.81 ms | 50.2 | 657.99 ms | 659.74 ms | 628.14 ms | 644.0 ms |
| 256 Kio | 2544.58 ms | 2546.63 ms | 100.6 | 5086.16 ms | 50.3 | 2632.54 ms | 2633.17 ms | 2503.0 ms | 2548.22 ms |
| 1 Mio | 10150.83 ms | 10136.32 ms | 100.9 | 20327.87 ms | 50.4 | 10506.19 ms | 10603.1 ms | 10008.68 ms | 10154.43 ms |

## Selon la nature du contenu (1 Kio et la plus grande taille)

| Nature | Taille | AEAD-128 | Entropie clair | Entropie chiffré | Aller-retour |
|---|---|---|---|---|---|
| texte | 1 Kio | 12.45 ms | 4.42 | 7.8 | OK |
| texte | 1 Mio | 10167.9 ms | 4.41 | 8.0 | OK |
| aleatoire | 1 Kio | 12.43 ms | 7.81 | 7.8 | OK |
| aleatoire | 1 Mio | 10150.83 ms | 8.0 | 8.0 | OK |
| zeros | 1 Kio | 12.55 ms | 0.0 | 7.82 | OK |
| zeros | 1 Mio | 10213.65 ms | 0.0 | 8.0 | OK |
| json | 1 Kio | 12.57 ms | 4.55 | 7.78 | OK |
| json | 1 Mio | 10231.23 ms | 4.65 | 8.0 | OK |

Coût fixe du schéma hybride : encapsulation ≈ 3.52 ms, décapsulation (avec ré-encapsulation FO) ≈ 17.99 ms, surcoût de transmission 9,853 o (chiffré KEM + tag). Mode TE : +7 o par bloc de 64 o (10,9 %).

Implémentation Python/numpy de référence (non optimisée, non constant-time).
