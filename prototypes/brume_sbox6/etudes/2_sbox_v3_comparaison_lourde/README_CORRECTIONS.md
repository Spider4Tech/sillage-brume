# BRUME-SBOX-SEARCH v3 corrigé

Ce dossier contient les quatre sources corrigées à partir des fichiers fournis :

- `sbox_v3.py` — définition, propriétés locales et certificat affine G11 ;
- `analyse_sbox_v3.py` — analyse comparative BRUME / SBOX6 / SBOX_V3 ;
- `tester_sbox_v3_attaques.sh` — campagne expérimentale C pour SBOX_V3 ;
- `brume_attaques.c` — banc C corrigé, à installer dans `tests/c/` du dépôt BRUME.

Ce dossier ne remplace pas le dépôt complet : il faut conserver les autres fichiers du projet, notamment `tests/banc_trails.py`, `sillage/brume512.py`, `sillage/c/`, `brume_ref.h`, `resultat.h` et les Makefiles.

## Installation dans le dépôt BRUME

Depuis la racine du dépôt :

```sh
cp /chemin/vers/brume_sbox_search_v3_corrige/sbox_v3.py prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/sbox_v3.py
cp /chemin/vers/brume_sbox_search_v3_corrige/analyse_sbox_v3.py prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/analyse_sbox_v3.py
cp /chemin/vers/brume_sbox_search_v3_corrige/tester_sbox_v3_attaques.sh prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/tester_sbox_v3_attaques.sh
cp /chemin/vers/brume_sbox_search_v3_corrige/brume_attaques.c tests/c/brume_attaques.c
chmod +x prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/sbox_v3.py
chmod +x prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/analyse_sbox_v3.py
chmod +x prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/tester_sbox_v3_attaques.sh
```

Faire un commit ou une sauvegarde avant de remplacer `tests/c/brume_attaques.c`.

## Vérification locale de la S-box

Depuis la racine du dépôt :

```sh
python3 prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/sbox_v3.py
```

Le vérificateur contrôle notamment : bijectivité, inverse, DU, LAT, BCT, profils des lignes DDT/BCT, absence de points fixes, degré et immunité algébrique des 15 composantes booléennes non nulles, et certificat affine G11.

## Analyse comparative

```sh
python3 prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/analyse_sbox_v3.py --rounds 14
```

Recherche optionnelle exhaustive de sources de poids 2 jusqu'à huit tours :

```sh
python3 prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/analyse_sbox_v3.py --rounds 14 --w2 8
```

Le script attend `numpy` et les modules du dépôt. Il conserve les noms historiques `diff`, `lin`, `boomerang_trails` et `bct_greedy` dans le JSON, tout en ajoutant des champs qui précisent les unités.

Le champ DDT `hist` contient désormais les 225 coefficients non triviaux (`a != 0`, `b != 0`). Le champ `hist_including_zero_output` contient les 240 coefficients (`a != 0`, tous les `b`) afin d'éviter l'ambiguïté des anciens histogrammes.

Les mesures C ne sont plus codées en dur dans le script Python. Pour joindre une campagne C réellement exécutée :

```sh
python3 prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/analyse_sbox_v3.py \
  --rounds 14 \
  --c-json prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/resultats/sbox_v3_lq20_nc16_seed0xB00_family1/brume_attaques.json \
  --c-raw-csv prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/resultats/sbox_v3_lq20_nc16_seed0xB00_family1/brume_attaques_boomerang_raw.csv \
  --output prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/analyse_sbox_v3_campaign.json
```

Adapter le chemin au dossier réellement créé par le script shell.

## Campagne C SBOX_V3

Depuis la racine du dépôt :

```sh
OMP_NUM_THREADS=8 prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/tester_sbox_v3_attaques.sh 20 16 0xB00 1
```

Arguments :

1. `log2_quartets` : nombre de quartets par combinaison (`2^LQ`) ;
2. `combinaisons` : nombre de combinaisons testées par profondeur ;
3. `seed` : graine de base (décimal ou hexadécimal) ;
4. `taille_famille` : facteur supplémentaire de correction multiple.

Pour comparer trois variantes dans une même famille statistique, utiliser `taille_famille=3` pour chacune des trois campagnes comparables. Si plusieurs graines, tailles d'échantillons ou analyses sont examinées puis sélectionnées, elles doivent également être comptées dans la famille de tests ou faire l'objet d'un protocole préenregistré.

Le script crée un dossier de sortie dédié et refuse d'écraser un dossier existant. Il conserve :

- le JSON produit par `brume_attaques.c` ;
- le CSV brut des comptes par tour, combinaison et nibble ;
- les journaux de compilation et d'exécution ;
- le header C exact utilisé pour la campagne ;
- les métadonnées et empreintes SHA-256.

## Corrections principales

### Analyse Python

- Les coûts DDT/BCT des pistes boomerang sont calculés en flottants : `2*log2(16/coefficient)` en demi-bits. Aucun arrondi du logarithme n'est appliqué avant l'accumulation.
- Le replay détaillé est effectué uniquement pour les sources de poids 1. Les sources échantillonnées de poids 3 ne sont pas rejouées à partir d'un nouvel échantillon qui pourrait différer de celui du moteur.
- Le décompte des transitions linéaires distingue correctement les coefficients LAT internes 2 et 4.
- L'horizon est dynamique ; aucun accès fixe à la clé `"14"` n'est effectué quand `--rounds` est différent.
- Les mesures du banc C ne sont plus recopiées depuis des chiffres précédents : elles sont intégrées seulement par `--c-json`.
- La provenance des tables et des données C est hachée en SHA-256.

### Banc C

- Le seuil de Bonferroni utilise une queue normale bilatérale, cohérente avec le test `fabs(z)`.
- La graine, la taille de la famille statistique et le nombre de threads demandés sont enregistrés.
- Le générateur d'états a été simplifié pour consommer un mot SplitMix64 par bloc de 16 nibbles. La séquence pseudo-aléatoire est donc différente de celle des anciennes campagnes ; les anciens scores z doivent être recalculés avec la nouvelle version pour une comparaison contrôlée. Ce changement ne constitue pas, à lui seul, une correction d'un biais statistique démontré dans l'ancien générateur.
- Les comptes bruts par nibble sont écrits dans `resultats/brume_attaques_boomerang_raw.csv`.
- Les résultats indiquent explicitement les profondeurs testées (1 à `RB`, actuellement 8). Les contrôles tautologiques qui prétendaient conclure sur 32 tours ont été supprimés.
- Les profondeurs de l'analyse par ensembles indiquent leur horizon réel : `RS` tours par sens, soit au maximum `2*RS` tours cumulés.

## Portée et limites

Ces corrections améliorent la cohérence numérique, la statistique et la reproductibilité du banc. Elles ne démontrent pas la sécurité de SBOX_V3 ni celle de la permutation BRUME-512 à 32 tours.

Les coûts boomerang produits par `analyse_sbox_v3.py` restent ceux d'un modèle heuristique à piste unique (DDT / switch BCT / DDT), pas les probabilités d'une attaque boomerang complète. Les tests C sont des mesures empiriques à nombre de tours réduit, sous un modèle nul approché par une permutation aléatoire et une statistique normale. La conclusion doit rester limitée aux configurations réellement testées.

## Vérifications effectuées sur les fichiers livrés

- `python -m py_compile` sur les deux scripts Python ;
- exécution de `sbox_v3.py` et vérification de ses contrôles locaux ;
- exécution de `analyse_sbox_v3.py --rounds 1 --no-json` avec un moteur de test simulé, pour vérifier l'intégration et les branches de sortie ;
- `sh -n` sur le script shell ;
- compilation syntaxique de `brume_attaques.c` avec OpenMP, avec et sans `-mavx2`, à l'aide d'en-têtes de dépendances temporaires ;
- exécution C réduite avec des fonctions de référence simulées pour vérifier l'écriture du CSV et le chemin d'exécution.

Le test C n'a pas été exécuté avec le vrai `brume_ref.h`, `resultat.h`, les matrices et les constantes du dépôt BRUME, car ces dépendances ne faisaient pas partie des fichiers fournis ici. Une campagne réelle doit être lancée dans le dépôt complet.
