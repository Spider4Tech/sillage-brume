# Historique v0.5 : BRUME-512 et ses tests (archivés en v0.6)

En v0.6 (17 novembre 2026), BRUME-1024q remplace BRUME-512 dans la suite (`docs/MIGRATION_V06.md`, décisions D1 et D4).
Ce dossier garde, tels qu'ils étaient, le code et les tests de BRUME-512 ; **la batterie (`python3 -m tests.run_all`) ne
les lance plus**.

| Contenu | Origine en v0.5 |
|---|---|
| `brume512.py`, `brume512_tables.py`, `select_params.py` | `sillage/` (référence Python de BRUME-512, sélection des paramètres) |
| `c/` : `brume512.c`, `brume512_avx2.c`, `brume512_simd.h`, `brume512_tables.h`, `gen_tables.py` | `sillage/c/` |
| `test_*.py` (modes, permutation, cryptanalyse de BRUME-512), `banc_*.py`, `dp_*.py`, `pistes_monomiales.py`, `nuit_brume.py`, `bench_perf.py`, `bench_tailles.py`, `BENCH_TAILLES.md` | `tests/`, `resultats/` |
| `c_tests/` : `brume_ref.h`, `structure_miss.c`, `diffusion_support.c`, `invariants.c`, `brume_gd2.c`, `brume_attaques.c`, `mini_brume.c`, `simd_conformite.c`, `sat_trails.c`, `nuit_cryptanalyse.c` | `tests/c/` |
| `gpu/`, `scripts/` (campagnes GPU et mesures spéciales de BRUME-512) | `tests/gpu/`, `scripts/` |
| `PROOFS_v05_section4.md`, `SPEC_v05_section2.md` | § 4 de `docs/PROOFS.md` et § 2 de `docs/SPEC.md` de la v0.5 |

**Rejouer la v0.5.** Les tests de ce dossier importent `sillage.brume512` et les liaisons C de BRUME-512, qui ne sont
plus dans la bibliothèque : ils se rejouent sur l'état du dépôt avant la v0.6 (commit `9192de0`, branche `main` du
17 novembre 2026), dont la batterie donnait 800/800 (`resultats/SYNTHESE.md` de ce commit).

**Ce qui sert encore.** Trois moteurs de la v0.5 sont réutilisés tels quels par les outils de BRUME-1024q, qui
remplacent seulement leur module de paramètres : `pistes_monomiales.py` et `dp_queue.py` (division property,
`prototypes/brume_q/b1024/dp1024/`), et `c_tests/brume_ref.h` avec `c/brume512_tables.h` (S-box et GF(16) du générateur
`prototypes/brume_q/b1024/gen_b1024.c`). `tests/noyau_c.py` (resté dans `tests/`, pour le test de bruit du KEM) relit
`brume512.py` d'ici pour ses contrôles de conformité.
