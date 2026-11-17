# BRUME-1024q — outils de recherche (v0.6)

Depuis la v0.6, BRUME-1024q est la permutation de la suite :
- **code** : `sillage/c/brume1024.c` et `sillage/c/brume1024_*.h` (ce dossier n'en garde que des renvois :
  `brume1024.c` → `tests/c/brume1024.c` → la bibliothèque ; `b1024_*.h` et `kat_b1024.h` → leurs équivalents) ;
- **documentation** (spécification, preuves, études, feuille de route) : `docs/brume1024/` (README : `docs/brume1024/README.md`) ;
- **contrôles** : la batterie (`tests/c/brume1024*.c`, `tests/c/temps1024.c`, `tests/c/ct1024.c`, `tests/test_b1024_*.py`,
  `tests/test_c_brume1024_valgrind.py`).

Ce dossier garde les **outils** qui ont servi à concevoir et à analyser la permutation, et qui servent encore aux
campagnes longues. Ils incluent la bibliothèque (`#include "brume1024.c"`, compilés avec `-DSANS_MAIN -I sillage/c
-I tests/c -I prototypes/brume_q/b1024`, liés à `sillage/c/commun.c`) : ce qu'ils mesurent est la fonction de la suite.

| Outils | Rôle | Dans la batterie |
|---|---|---|
| `gen_b1024.c`, `gen_bitslice.c`, `gen_lot_variantes.c`, `circuit_sbox.c` | génération des tables, du noyau bitslicé et du circuit de S-box | `test_b1024_seconde_implementation` (tables redonnées à l'identique) |
| `spec_ref.c`, `controle_portable.c` | seconde implémentation d'après la SPEC ; noyau portable contre une référence dense indépendante | idem |
| `structure1024.py`, `invariants_quad1024.c`, `agregation2.c`, `agregation34.c`, `tronquees1024.py`, `tronquees_verif.c`, `verif_chemin3.py`, `trails1024.py` | structure, invariants, agrégation, différentielles tronquées, meilleures caractéristiques | `test_b1024_structure` (les trois premiers) |
| `stats1024.c`, `cubes_degre.c` | batterie statistique, cubes et degré | `test_b1024_statistiques` (le premier) |
| `dp1024/` | division property exacte | — (campagnes longues) |
| `algebrique1024.py`, `rebond1024.py`, `rebond_verif.c`, `dl_verif.c` | études du 17 novembre (`docs/brume1024/ALGEBRIQUE.md`, `REBOND.md`, `DIFF_LIN.md`) | `test_b1024_etudes` (contrôles des outils) |
| `v06_verif/`, `q1_verif/`, `cm26_verif/` | contrôles mécaniques des preuves (AEAD parallèle, Q1, borne quantique du hachage, Carolan–Majenz) | `test_b1024_preuves` |
| `dmv17_verif/` | article sur le théorème 1 de DMV17, programmes et sorties | — |
| `gpu/` | boomerang sur GPU | — (lanceurs GPU) |
| `campagne_*.sh`, `campagne_aead.c`, `mutants.c`, `mutation_songbird.sh`, `bench_*.c` | campagnes longues, score de mutation, bancs | — |
| `gf16.py` | corps GF(16) des outils Python (repris de `brume512.py`, archivé) | — |
