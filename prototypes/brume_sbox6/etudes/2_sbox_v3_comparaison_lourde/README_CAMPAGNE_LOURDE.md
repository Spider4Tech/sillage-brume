# Campagne lourde BRUME / SBOX6 / SBOX_V3

Cette campagne reprend les raisons pour lesquelles SBOX6 avait été mise de côté :
son BCT maximal est meilleur (6), mais son profil DDT est uniforme (aucune ligne
DDT max 2), toutes ses lignes BCT ont un maximum 6, et les anciennes recherches
gloutonnes de caractéristiques différentielles multi-tours lui donnaient une
meilleure caractéristique pour l'attaquant que BRUME et SBOX_V3.

Les anciens chiffres différentiels archivés donnent, à 14 tours, des coûts de
caractéristique de 2600 bits pour SBOX6 contre 2830 pour BRUME et 3021 pour V3.
Ce sont des résultats de recherche gloutonne, pas une preuve d'optimalité.
Les anciens coûts de switch boomerang doivent être recalculés : le présent
analyseur corrigé conserve les coûts BCT en flottants (`2*log2(16/BCT)`) sans
arrondi prématuré.

## Installation

Depuis la racine du dépôt BRUME :

```sh
cp /chemin/vers/brume_campagne_lourde/analyse_sbox_v3.py prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/analyse_sbox_v3.py
cp /chemin/vers/brume_campagne_lourde/sbox_v3.py prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/sbox_v3.py
cp /chemin/vers/brume_campagne_lourde/tester_sbox_compare.sh prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/tester_sbox_compare.sh
cp /chemin/vers/brume_campagne_lourde/run_comparaison_lourde.sh prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/run_comparaison_lourde.sh
cp /chemin/vers/brume_campagne_lourde/aggregate_comparaison_lourde.py prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/aggregate_comparaison_lourde.py
chmod +x prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/*.sh prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/aggregate_comparaison_lourde.py
```

Dépendances : `numpy`, le dépôt complet avec `tests/banc_trails.py`, `sillage/brume512.py`,
`tests/c/brume_attaques.c`, `tests/c/Makefile` et `sillage/c/`.

## Lancement conseillé

```sh
OMP_NUM_THREADS=8 prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/run_comparaison_lourde.sh
```

Réglages par défaut :

- 2^20 quartets par combinaison ;
- 32 combinaisons par tour ;
- 5 graines (`0xB00` à `0xB04`) ;
- 3 candidates ;
- `family_size = 15` (3 candidates × 5 graines) ;
- 8 tours pour le banc C ;
- analyse différentielle/linéaire jusqu'à 14 tours ;
- recherche exhaustive de sources de poids 2 jusqu'à 8 tours, selon `tests/banc_trails.py`.

Cela représente 10 fois plus de quartets cumulés que la comparaison précédente
à 3 candidates, une graine, 16 combinaisons et 2^20 quartets. La charge C totale
théorique est de 3 × 5 × 8 × 32 × 2^20 quartets, soit environ 4,03 milliards
quartets. Prévoir une exécution longue.

## Modifier la charge

Les paramètres peuvent être surchargés par variables d'environnement :

```sh
LQ=21 NC=32 ROUNDS=14 W2=8 OMP_NUM_THREADS=8 \
SEEDS="0xB00 0xB01 0xB02 0xB03 0xB04" \
prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/run_comparaison_lourde.sh
```

Ne pas diminuer `FAMILY` : par défaut il est calculé à `3 × nombre_de_graines`.
Si tu ajoutes des graines, le script ajuste la correction Bonferroni.

## Ce que la campagne compare

1. Propriétés exactes des tables locales : DDT, LAT, BCT, LBCT, UBCT, EBCT,
   FBCT, DBCT, DLCT et bornes MEDP2/MELP2.
2. Pistes différentielles et linéaires sur 14 tours, avec le moteur du dépôt ;
   sources de poids 1 exhaustives, poids 2 exhaustif jusqu'à `W2`, poids 3 selon
   l'échantillonnage configuré dans `tests/banc_trails.py`.
3. Pistes boomerang DDT / switch BCT / DDT, avec coûts flottants exacts en
   demi-bits. Cela reste un modèle de piste gloutonne, pas une probabilité
   d'attaque boomerang complète.
4. Campagne C boomerang sur 1 à 8 tours, 32 combinaisons par tour et 5 graines.
5. Contrôle automatique que les trois candidates utilisent les mêmes paramètres
   d'entrée et les mêmes flux déterministes pour chaque graine.

Le rapport final est `synthese.md`, accompagné de `synthese.json` et
`synthese_boomerang.csv`.

## Limites à conserver dans l'interprétation

- Le banc C reste limité à `RB=8` tours ; il ne démontre rien directement sur 32 tours.
- Les scores Z utilisent l'approximation de variance sous permutation aléatoire du
  banc actuel. L'agrégateur rapporte les scores et les graines qui dépassent le
  seuil corrigé ; il ne transforme pas une mesure exploratoire en preuve.
- Le C du dépôt utilise encore SplitMix64 pour produire les états. Les graines
  multiples augmentent la reproductibilité de l'exploration, mais ne remplacent
  pas une version du banc fondée sur ChaCha20 ou un générateur cryptographique
  validé avant une publication scientifique.
- Le poids 3 dépend de la configuration de `tests/banc_trails.py` et reste
  échantillonné. Ce pack n'en modifie pas silencieusement le nombre de sources.
- Les pistes gloutonnes sont des caractéristiques valides trouvées par la
  recherche ; elles ne prouvent pas qu'aucune meilleure caractéristique n'existe.
