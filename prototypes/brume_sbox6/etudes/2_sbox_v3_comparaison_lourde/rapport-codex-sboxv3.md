J'ai regardé les deux documents. Et cette fois, le résultat est nettement plus intéressant que SBOX6.

SBOX_V3 semble être un meilleur compromis cryptanalytique que les deux précédentes candidates. Elle récupère les bonnes propriétés différentielles de BRUME, élimine ses coefficients BCT à 10 et conserve l'amélioration de DBCT obtenue avec SBOX6.

Mais il y a un point dans la démonstration mathématique que je voudrais corriger avant de valider définitivement votre conclusion.

## 1. Vérification indépendante de SBOX_V3

J'ai repris la table de substitution et sa table inverse, puis recalculé les principales propriétés sur les 16 entrées.

Résultats confirmés

| Propriété                           | Résultat recalculé                             |
| ----------------------------------- | ---------------------------------------------- |
| Bijectivité                         | Oui                                            |
| Cohérence de l'inverse              | Oui                                            |
| Uniformité différentielle           | 4                                              |
| Non-linéarité                       | 4                                              |
| Maximum LAT                         | 8                                              |
| Maximum BCT                         | 8                                              |
| Maximum DBCT annoncé                | 32, à confirmer par reproduction de son calcul |
| Degré algébrique des 4 composantes  | 3                                              |
| Immunité algébrique des composantes | 2                                              |
| Points fixes                        | 0                                              |

J'ai également retrouvé exactement les distributions suivantes :

DDT :

\\[ \\{0:135,\quad 2:90,\quad 4:15\\} \\]

BCT :

\\[ \\{0:100,\quad 2:85,\quad 4:30,\quad6:5,\quad8:5\\} \\]

Et surtout, j'ai retrouvé les cinq différences d'entrée ayant une ligne DDT dont le maximum est seulement 2 :

\\[ \boxed{\\{3,4,5,12,14\\}} \\]

Les cinq lignes correspondantes de la BCT ont également un maximum de 2.

Ces résultats confirment les principaux résultats locaux de votre rapport.&#x20;

ANALYSE_V3.md



## 2. Une correction importante concernant la classification affine

Votre rapport affirme qu'une seule classe affine atteint BCT = 6.

Cette affirmation n'est pas exacte.

J'ai vérifié la classification publiée par Boura et Canteaut, notamment leur tableau 3 sur les permutations de quatre bits de DU = 4.

Ce tableau présente deux classes distinctes avec :

\\[ BCT\_{\max}=6 \\]

Elles correspondent aux classes G3 et G5 de la classification de Leander–Poschmann.

Leurs profils DDT sont cependant identiques sur le point qui nous intéresse : chaque différence d'entrée non nulle possède une transition DDT-4.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://d-nb.info\&sz=32)

d-nb.info+1



Il faut donc modifier votre démonstration :

- Il n'existe pas une unique classe affine à BCT = 6.
- Il existe au moins deux classes distinctes dans cette classification.
- Les deux ont un profil DDT sans ligne de maximum 2.

Votre conclusion structurelle peut donc rester valable, mais sa justification doit porter sur les deux classes, et non sur une classe unique.

Autre correction : votre SBOX_V3 correspond, au niveau du spectre BCT, à la quatrième permutation du tableau 3 de Boura–Canteaut, associée à la classe G11 de Leander–Poschmann. Ce n'est pas une classe 18 dans leur classification à 16 classes.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://d-nb.info\&sz=32)

d-nb.info



Cette distinction est importante pour que votre rapport soit reproductible par d'autres cryptanalystes.

## 3. J'ai également retrouvé le certificat d'équivalence affine de V3

J'ai poussé la vérification un peu plus loin : j'ai recherché une transformation affine reliant votre table à celle du représentant G11 publié.

J'ai trouvé une correspondance exacte.

En notant \\(S\_{G11}\\) le représentant :

```
[8, 0, 1, 9, 2, 5, 13, 7,
 4, 6, 10, 11, 12, 3, 14, 15]
```

On obtient :

\\[ S\_{V3}(x)=M_2S\_{G11}(M_1x\oplus9)\oplus5 \\]

Les images des quatre vecteurs de base sont :

| Base | \\(M_1\\) | \\(M_2\\) |
| ---- | --------- | --------- |
| 1    | 3         | 5         |
| 2    | 9         | 10        |
| 4    | 13        | 1         |
| 8    | 2         | 6         |

Les additions et multiplications par les matrices sont ici comprises comme des opérations sur les vecteurs binaires.

La relation a été vérifiée sur les 16 entrées.

C'est une information intéressante à ajouter à `ANALYSE_V3.md` : elle fournit un certificat d'équivalence affine reproductible, plutôt que de simplement identifier la classe à partir de son spectre BCT.

## 4. Deux autres améliorations mathématiques du rapport

### Correction de la formule DDT

Votre section 3.1 contient une petite erreur dans la transformation des indices.

Pour :

\\[ S'(x)=M_2S(M_1x\oplus c_1)\oplus c_2 \\]

la bonne relation est :

\\[ \boxed{ DDT\_{S'}[a,b] = DDT_S[M_1a,M_2^{-1}b] } \\]

et non \\(DDT_S[M_1a,M_2b]\\).

Votre formule BCT utilise déjà correctement \\(M_2^{-1}\\).

Cette correction ne change pas votre conclusion sur l'invariance des profils, mais elle est nécessaire pour une démonstration formelle correcte.

### Le rapport BCT/DDT

J'ai également recalculé cet indicateur :

| S-box   | Moyenne de \\(\log_2(BCT/DDT)\\) |
| ------- | -------------------------------- |
| BRUME   | 0,207205                         |
| SBOX6   | 0,452846                         |
| SBOX_V3 | 0,123093                         |

Les valeurs de votre rapport sont donc exactes.

Une moyenne plus faible signifie ici que les coefficients BCT sont, en moyenne géométrique, moins élevés relativement aux coefficients DDT correspondants.

C'est favorable à V3 dans cette comparaison.

Je conserverais néanmoins l'appellation ratio relatif de commutation. Ce n'est pas un coût cryptanalytique universel et il ne permet pas à lui seul de conclure à une meilleure résistance boomerang.

Il faut continuer à regarder les transitions effectivement utilisées par les caractéristiques.

## 5. Ce qui me convainc le plus : la distribution des lignes

Voici le profil complet que j'obtiens pour V3.

DDT : 15 lignes non nulles

Nombre de lignes selon leur profil DDT.

0246Max 2Max 4, 1 sortie à 4Max 4, 2 sorties à 4

BCT : maximum par ligne

Distribution des maxima BCT des 15 lignes non triviales.

0246268

C'est précisément ce qui rend V3 intéressante : elle ne cherche pas à minimiser uniquement une valeur extrême.

Elle conserve des chemins différentiels coûteux tout en réduisant les transitions boomerang les plus défavorables de BRUME.

Le profil est nettement moins uniforme que celui de SBOX6.

## 6. Attention aux résultats multi-tours

C'est maintenant le principal point à approfondir.

Votre moteur annonce :

\\[ P\_{\mathrm{diff,V3}}=2^{-3021} \\]

et :

\\[ P\_{\mathrm{boom,V3}}=2^{-2941} \\]

Ces résultats sont très favorables par rapport à BRUME et SBOX6 dans les recherches effectuées.&#x20;

ANALYSE_V3.md



Il faut néanmoins conserver trois distinctions :

Premièrement, les pistes gloutonnes ne sont pas nécessairement optimales. Le fait de trouver une piste à \\(2^{-3021}\\) ne démontre pas qu'aucune piste plus probable n'existe. La recherche doit être étendue et ses limites documentées.

Deuxièmement, une piste boomerang n'est pas une attaque boomerang complète. Le coût d'une caractéristique avec un switch BCT ne donne pas directement le coût d'un distingueur réel.

Troisièmement, le test expérimental à trois tours ne montre pas d'amélioration par rapport à BRUME.

C'est même le résultat qui m'interpelle le plus :

| Campagne                               | BRUME | SBOX_V3 |
| -------------------------------------- | ----- | ------- |
| \\(2^{20}\\) quartets, 16 combinaisons | 13,4  | 14,8    |
| \\(2^{20}\\) quartets, 64 combinaisons | 19,9  | 19,9    |
| \\(2^{22}\\) quartets, 16 combinaisons | 27,6  | 27,6    |

Les signaux sont comparables, voire légèrement plus élevés pour V3 dans le premier essai.

Ainsi, l'amélioration de 165 bits de la piste boomerang à 14 tours ne se traduit pas par une amélioration démontrée du distingueur à trois tours.&#x20;

ANALYSE_V3.md



Pour les quatre tours et davantage, votre protocole ne détecte pas de signal significatif. C'est encourageant, mais ce constat ne couvre pas toutes les différences intermédiaires ni toutes les attaques boomerang possibles.

## 7. SBOX_V3 est-elle réellement Pareto-optimale ?

Je nuancerais le titre.

Parmi les trois candidates étudiées, V3 représente un excellent compromis.

Mais elle n'est pas meilleure sur tous les critères :

| Critère                                    | Candidate avantagée                 |
| ------------------------------------------ | ----------------------------------- |
| BCT maximal                                | SBOX6                               |
| DBCT maximal                               | Égalité SBOX6 / V3                  |
| Nombre de lignes DDT max 2                 | SBOX_V3                             |
| Coût des meilleures pistes différentielles | SBOX_V3                             |
| Coût des pistes boomerang recherchées      | SBOX_V3                             |
| MEDP2                                      | SBOX6                               |
| Résultat du test boomerang à trois tours   | SBOX6 dans les campagnes présentées |
| Résistance linéaire recherchée             | Équivalence annoncée                |

Il existe donc un véritable compromis.

Pour revendiquer une optimalité de Pareto globale, il faudrait préciser :

- l'ensemble des S-boxes et orientations affine réellement explorées ;
- les objectifs optimisés ;
- les contraintes imposées ;
- le nombre de candidates évaluées ;
- les candidates non dominées obtenues.

En l'état, je qualifierais V3 de candidate non dominée parmi les trois versions testées, plutôt que de solution globalement optimale.

## 8. La prochaine étape scientifique que je recommande

Je ne chercherais pas immédiatement une SBOX_V4.

Je travaillerais d'abord à consolider V3.

Voici le protocole que je retiendrais :

## BRUME-SBOX-SEARCH v2

Priorité de recherche

Étape 1 — Certification mathématique

1. Corriger et publier le certificat d'équivalence affine G11.
2. Vérifier les invariants DDT/BCT de toutes les transformations utilisées.
3. Reproduire DBCT, LBCT, UBCT et les autres tables raffinées.

Étape 2 — Cryptanalyse multi-tours

1. Améliorer la recherche différentielle avec une recherche exacte ou un branch-and-bound sur les profondeurs réduites.
2. Étudier les hulls différentiels et linéaires, pas uniquement les caractéristiques individuelles.
3. Explorer plusieurs modèles boomerang et leurs probabilités réelles.

Étape 3 — Validation expérimentale

1. Multiplier les différences intermédiaires étudiées dans le test C.
2. Utiliser plusieurs échantillons indépendants et publier les comptes bruts, les intervalles de confiance et les corrections statistiques.
3. Tester les distingueur à quatre, cinq et six tours avec un protocole clairement défini.

Étape 4 — Comparaison finale

Évaluer les trois S-boxes avec exactement les mêmes scripts, paramètres, graines et configurations de compilation.

Un élément manque encore pour que je puisse considérer l'expérimentation comme entièrement reproductible : les deux documents sont fournis, mais pas les scripts et données brutes mentionnés dans leur inventaire.

Les fichiers les plus importants pour le prochain audit sont `analyse_sbox_v3.py`, `analyse_sbox_v3.json`, `sbox_v3.py` et `tester_sbox_v3_attaques.sh`.

## Mon verdict

Candidate à conserver et approfondir

Je trouve SBOX_V3 plus intéressante que SBOX6 pour l'architecture actuelle de BRUME.

Le passage de BCT 10 à 8, la réduction du DBCT à 32 et surtout l'amélioration des pistes différentielles et boomerang recherchées constituent un ensemble de résultats cohérent.

Il y a aussi une vraie réussite méthodologique : vous avez identifié qu'un critère local optimal pouvait dégrader le comportement multi-tours, puis construit une candidate qui retrouve un meilleur équilibre.

Je conserverais donc :

- BRUME comme référence historique.
- SBOX6 comme expérience démontrant les limites de l'optimisation BCT.
- SBOX_V3 comme candidate principale pour la prochaine campagne cryptanalytique.

Je ne l'intégrerais pas encore dans la version de production de BRUME. La résistance de la permutation complète à 32 tours reste à établir.

La prochaine avancée décisive ne sera probablement pas une quatrième S-box. Ce sera une validation indépendante des propriétés multi-tours de V3, avec une recherche moins dépendante des heuristiques gloutonnes.

C'est à ce moment-là que nous saurons si V3 est simplement une excellente candidate sur le papier ou une amélioration cryptographique réellement robuste.
