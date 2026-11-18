# BRUME-1024q comme fonction de hachage du KEM et des signatures (prototype, hors suite)

**Question (18 novembre 2026).** Que coûte le passage du KEM et des signatures de SHAKE256 à BRUME-1024q comme fonction
de hachage ? Deux variantes sont mesurées : la capacité de la suite (c = 384), et c = 512, la variante de catégorie 5
pour les préimages (`docs/NIST_CATEGORIES.md` § 4).

**Statut.** Prototype de mesure : ni spécifié, ni relu, sans KAT. Les clés et les signatures produites ne sont **pas**
compatibles avec la suite, puisque la fonction de hachage change. La bibliothèque n'est pas modifiée.

## Construction

Toutes les fonctions de hachage du KEM (`kem.c`), de la signature VOLE (`vole.c`, v0.5) et de la signature v0.4
(`sig.c`) passent par la couche SHAKE de `sillage/c/commun.c`. `hachage_brume.c` remplace cette couche, et seulement
elle. Le reste du code de la bibliothèque est compilé tel quel. Le bench est le même programme pour les trois variantes
(`bench_hachage.c`) : les écarts mesurés viennent donc du hachage seul.

| Fonction de la couche | SHAKE256 (bibliothèque) | BRUME-1024q (prototype) |
|---|---|---|
| `sl_shake_init/absorb/final/squeeze`, `sl_shake_dom` | Keccak-f[1600], débit 136 o | éponge de la SPEC (§ 3.1 cadre en mode 5, § 3.2 bourrage, domaine XOF 0) sur `sl_brume_permute` (constant-time) ; débit 80 o (c = 384) ou 64 o (c = 512) ; IV calculé une fois |
| `sl_flux_*` (entiers pseudo-aléatoires) | mode compteur, 4 blocs de 64 o par Keccak à 4 voies | même mode compteur, 4 éponges |
| `sl_shake4` (4 hachages en parallèle) | Keccak à 4 voies (AVX2) | 4 éponges à la suite : un lot de 32 états ne coûte que 681 ns par état contre 770 (`resultats/BENCH_C.md`) |
| `sl_creux`, `sl_echanges`, `sl_perm` | — | recopiés sans changement (ils ne dépendent que du flux) |

À c = 384, l'éponge du prototype est **égale bit à bit à `sl_xof`** de la bibliothèque, qui suit les KAT de la SPEC § 4 :
le bench le vérifie sur 10 longueurs. À c = 512, la construction est la même, avec un octet de débit de 128 dans le cadre
(r/4) au lieu de 160. Ce profil n'existe pas dans la SPEC.

    make bench        # les 5 exécutions, puis BENCH.md (environ 6 minutes sur un 5600G)

## Résultats (`BENCH.md`, Ryzen 5 5600G, un cœur sauf mention)

| Opération | SHAKE256 | BRUME c = 384 | BRUME c = 512 |
|---|---|---|---|
| Hachage 64 o → 32 o | 0,29 µs | 0,81 µs (×2,9) | 1,58 µs (×5,5) |
| Débit en absorption | 471 Mo/s | 102 Mo/s (÷4,6) | 82 Mo/s (÷5,7) |
| KEM-256 encaps / decaps | 0,95 / 1,54 ms | 1,31 / 2,36 ms (×1,4 / ×1,5) | 1,40 / 2,58 ms (×1,5 / ×1,7) |
| KEM-256 keygen | 29,1 ms | 28,4 ms (inchangé) | 28,3 ms |
| VOLE-256 sign / verify | 99 / 91 ms | 869 / 825 ms (×8,8 / ×9,1) | 996 / 965 ms (×10,0 / ×10,7) |
| VOLE-256 sign, 12 threads | 20,7 ms | 149 ms (×7,2) | 175 ms (×8,5) |
| VOLE-256f sign / verify | 34 / 27 ms | 210 / 200 ms (×6,2 / ×7,5) | 223 / 215 ms (×6,6 / ×8,1) |
| VOLE keygen (les deux profils) | 8 ms | 121 ms (×15) | 122 ms (×15) |
| SIG-256 v0.4 sign | 124 ms | 1 489 ms (×12) | 1 794 ms (×14) |

**Lecture.**
- **Le KEM supporte bien le changement** : +40 à 70 % en encapsulation et décapsulation, rien en génération de clés,
  qui est dominée par l'inversion polynomiale. Une encapsulation fait 843 permutations à c = 384, soit environ 0,65 ms
  des 1,31 ms.
- **Les signatures sont 6 à 15 fois plus lentes.** Elles sont faites de hachages : une signature VOLE-256 demande
  environ 10^6 permutations, soit 0,79 s des 0,87 s. SHAKE256 gagne sur deux points. Keccak-f[1600] coûte moins cher
  que BRUME-1024q (0,29 µs contre 0,81 µs pour un hachage court). Surtout, le Keccak à 4 voies de la bibliothèque fait
  4 hachages pour à peu près le prix d'un, alors que BRUME-1024q n'a pas de version à 4 voies plus rapide : son lot de
  32 états ne gagne que 12 %.
- **c = 512 coûte 6 à 17 % de plus que c = 384** sur le KEM et VOLE (20 à 50 % sur la signature v0.4), et le double
  sur un hachage court : 64 o d'entrée plus le domaine dépassent un bloc de 64 o, donc 2 permutations au lieu d'une.

## Ce que cela changerait pour la sécurité (non évalué ici)

- **c = 384 abaisse la borne générique de l'éponge à 2^192** (collisions internes), contre 2^256 pour SHAKE256
  (c = 512). Cela suffit au KEM-256, qui est en catégorie 3 et limité par l'ISD. Pour VOLE-256, qui vise λ = 256 :
  si une attaque générique sur l'éponge s'applique à ses engagements ou à ses défis, elle coûte 2^192 appels, soit
  2^210,8 portes, sous les 2^272 de la catégorie 5. Avec les seuils JNRV, VOLE-256 sortirait alors de la catégorie 5.
  Ce point n'est pas analysé ici. **c = 512 rend la même borne générique que SHAKE256.**
- Les preuves de la signature (`docs/PROOFS.md` § 3 bis) et du KEM (QROM) modélisent la fonction de hachage comme un
  oracle aléatoire. La substitution passerait par l'indifférentiabilité de l'éponge BRUME-1024q, qui est prouvée dans le
  modèle de la permutation idéale, comme pour SHAKE. Mais la cryptanalyse de BRUME-1024q est la nôtre seule, alors que
  celle de Keccak est publique et ancienne.
- Dans le modèle en portes (`tests/modele_portes.py`), un oracle BRUME-1024q coûte 2^21,6 portes en profondeur 2^11,8,
  contre 2^20,3 et 2^10,4 pour Keccak-f. Les attaques de Grover sur les défis de VOLE coûteraient 1,3 à 2,7 bits de
  plus, alors qu'il en manque 10,2 pour la catégorie 5 avec les seuils de 2016 : cela ne suffit pas.

**Conclusion.** Remplacer SHAKE256 par BRUME-1024q dans le KEM est envisageable (×1,4 à ×1,7, avec c = 512 pour garder
la borne de SHAKE256). Dans les signatures, c'est prohibitif (×6 à ×15). La suite n'y gagnerait qu'une primitive de
moins, au prix d'une fonction de hachage moins étudiée.
