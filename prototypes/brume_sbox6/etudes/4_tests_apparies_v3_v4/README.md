# BRUME-512 — banc apparié BRUME / SBOX_V3 / SBOX_V4

Ce paquet ajoute un test apparié pour comparer **BRUME**, **SBOX_V3** et **SBOX_V4** sur les mêmes données aléatoires.

Contrairement aux trois campagnes séparées précédentes, un quartet est généré une seule fois, puis évalué avec BRUME, SBOX_V3 et SBOX_V4. Pour chaque paire de candidates, le programme conserve les quatre effectifs conjoints nécessaires à McNemar :

- `n00` : l'événement n'arrive avec aucune des deux candidates ;
- `n01` : il arrive uniquement avec la candidate B ;
- `n10` : il arrive uniquement avec la candidate A ;
- `n11` : il arrive avec les deux candidates.

L'événement principal est « le nibble de différence au retour est nul ». Un second CSV applique la même méthode à l'événement « la différence complète de 128 nibbles revient exactement à la différence d'entrée ».

Le générateur est **ChaCha20 conforme au vecteur de test RFC 8439**. Chaque flux est indexé par la graine de 256 bits, le tour, la combinaison et le numéro de quartet. Le même flux est réutilisé pour les trois candidates ; l'ordre d'exécution et le nombre de threads ne changent donc pas les entrées.

## Fichiers

- `brume_attaques_paired.c` : moteur C, matrice BRUME, trois candidates (BRUME, V3, V4), ChaCha20, exécution OpenMP et tableaux 2x2 appariés.
- `run_comparaison_appariee.sh` : compilation, génération de cinq graines reproductibles, exécution et archivage.
- `analyse_pairee.py` : agrégation et tests de McNemar avec corrections de Bonferroni.

Le script utilise la matrice, les coefficients GF(16) et les constantes de tour du fichier généré `sillage/c/brume512_tables.h` du dépôt. Il ne modifie pas ce fichier.

## Installation

Décompresse le paquet à côté de tes autres scripts, par exemple :

```bash
cd prototypes/brume_sbox6/etudes/4_tests_apparies_v3_v4
chmod +x run_comparaison_appariee.sh analyse_pairee.py
```

Le lanceur cherche `sillage/c/brume512_tables.h` en remontant dans le dépôt. Si le fichier se trouve ailleurs :

```bash
BRUME_TABLES_HEADER=/chemin/vers/brume512_tables.h ./run_comparaison_appariee.sh
```

Prérequis : `cc` (GCC recommandé), OpenMP, Python 3.9+ et une machine dont la mémoire suffit aux tables (moins de quelques Mo). `-march=native` active les instructions disponibles sur la machine de compilation ; le code possède aussi un chemin scalaire sans AVX2.

## Lancement

### Petit test de fonctionnement

À faire avant une longue campagne :

```bash
./run_comparaison_appariee.sh 10 4 3 4
```

Cela lance 5 graines, 4 combinaisons, 3 tours et 2^10 quartets par combinaison.

### Campagne soutenue recommandée

```bash
./run_comparaison_appariee.sh 18 32 8 8
```

Paramètres : 5 graines, 32 combinaisons, 8 tours, 2^18 quartets par combinaison. Cela représente 335 544 320 quartets appariés ; chaque quartet est testé avec BRUME, SBOX_V3 et SBOX_V4.

### Campagne lourde

Après validation de la campagne soutenue :

```bash
./run_comparaison_appariee.sh 20 32 8 8
```

Cela représente 1 342 177 280 quartets appariés, soit 4 026 531 840 évaluations de candidate (sans compter le travail des états jumeaux). Le coût de calcul est important. Ne commence pas directement par celle-ci sur une machine dont tu ne connais pas encore les performances.

Arguments du lanceur :

```text
run_comparaison_appariee.sh [LQ] [COMBINATIONS] [ROUNDS] [THREADS] [OUTDIR]
```

Les cinq clés ChaCha20 sont obtenues par SHA-256 à partir des mêmes étiquettes v1 que le banc précédent et sont enregistrées dans `seeds.txt`. Elles sont volontairement conservées pour réutiliser exactement les mêmes flux d'entrée lors de la comparaison BRUME/V3/V4. Elles sont fixes : relancer une campagne avec les mêmes paramètres reproduit les mêmes entrées.

Le jeu de candidates est désormais **BRUME + SBOX_V3 + SBOX_V4**. SBOX6 est retirée du moteur C, des paires McNemar, du rapport et des métadonnées. Le binaire vérifie la bijectivité et construit lui-même l'inverse de chacune des trois candidates avant les tests. Pour les propriétés locales détaillées de V4, conserve aussi le vérificateur `sbox_v4_candidate.py` que tu as déjà.

## Résultats

Le dossier de sortie contient, pour chaque graine :

- `paired_zero_<seed>.csv` : tables 2x2 appariées pour chacun des 128 nibbles de sortie ;
- `paired_exact_<seed>.csv` : tables 2x2 appariées pour les retours exacts de l'état complet.

L'analyse crée :

- `paired_zero_mcnemar.csv` : McNemar entre candidates, par graine/tour/nibble, après agrégation des combinaisons ;
- `candidate_zero_marginals.csv` : taux de nibble nul par candidate, comparé à la référence exploratoire `p=1/16` ;
- `paired_exact_mcnemar.csv` : McNemar des retours exacts complets ;
- `candidate_exact_returns.csv` : nombre de retours exacts par candidate ;
- `synthese_appariee.md` et `synthese_appariee.json` : synthèse finale.

### Lire McNemar

Pour une paire A/B, `n01` et `n10` sont les discordances. Si les deux candidates ont le même taux d'événement, ces deux valeurs doivent être proches. Le signe de `rate_a_minus_b` donne le sens de l'écart :

- positif : l'événement « nibble nul » est plus fréquent avec A ;
- négatif : il est plus fréquent avec B.

L'analyse applique Bonferroni séparément à chaque famille : tests appariés par nibble, taux marginaux contre `1/16`, puis retours exacts. Pour les comparaisons appariées par nibble, les résultats des `NC` géométries sont combinés dans un score stratifié (type Cochran–Mantel–Haenszel pour paires) : le nombre de tests corrigés est donc `3 paires × graines × tours × 128`, et non multiplié une seconde fois par `NC`. Les p-values par combinaison ne sont pas considérées comme des tests séparés. Les tailles exactes sont enregistrées dans `campaign_metadata.json`.

Pour la configuration soutenue `18 32 8 8`, les familles appariées par nibble et marginale contiennent chacune `3 × 5 × 8 × 128 = 15 360` tests. La famille des retours exacts contient `3 × 5 × 8 = 120` tests. Le seuil bilatéral normal de la première famille est proche de `5,4084` avec le risque familial cible `1/1024`.

## Interprétation et limites

1. **McNemar compare des taux d'événement, pas la sécurité générale.** Un taux de nibbles nuls plus haut ne signifie pas automatiquement qu'une candidate est plus faible ; il faut examiner les différences, la géométrie et les trajectoires associées.
2. La référence marginale `p=1/16` reste le modèle de permutation aléatoire utilisé dans le protocole précédent. La structure de BRUME peut s'en écarter ; elle doit être traitée comme un indicateur, pas comme une loi universelle.
3. Les 128 nibbles d'un même quartet ne sont pas indépendants. Bonferroni corrige le risque lié au nombre de tests, mais ne rend pas les observations cryptographiquement indépendantes.
4. Les résultats sont limités aux tours demandés (8 par défaut). Ils ne prouvent rien sur la permutation complète de 32 tours.
5. Les cinq graines améliorent la reproductibilité et la robustesse empirique, mais elles ne remplacent pas une recherche de caractéristiques optimale ni une preuve cryptographique.
6. Les tours 1 et 2 sont gardés comme contrôles structurels ; les très grands biais observés à ces profondeurs ne doivent pas servir à classer les S-boxes.

Le rapport doit être interprété conjointement avec les recherches différentielles, linéaires et boomerang multi-tours. En particulier, il ne remet pas à lui seul en cause les résultats antérieurs défavorables à la candidate SBOX6, volontairement exclue de cette comparaison.
