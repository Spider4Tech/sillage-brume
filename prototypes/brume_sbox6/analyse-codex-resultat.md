J'ai examiné les deux fichiers. Il y a un résultat particulièrement intéressant : SBOX6 atteint bien l'objectif BCT = 6, mais les essais montrent que cette amélioration locale dégrade plusieurs propriétés cryptanalytiques de BRUME.

Et surtout, votre analyse met en évidence quelque chose d'important pour la conception de BRUME-512 : optimiser le pire coefficient d'une S-box ne revient pas nécessairement à améliorer la résistance de la permutation.

## 1. Comparaison BRUME / SBOX6

Voici les résultats centraux de votre expérimentation du 8 novembre 2026.

| Critère                                   | BRUME            | SBOX6            | Verdict         |
| ----------------------------------------- | ---------------- | ---------------- | --------------- |
| BCT maximal                               | 10               | 6                | SBOX6           |
| DBCT maximal                              | 52               | 32               | SBOX6           |
| MEDP2                                     | \\(2^{-14,99}\\) | \\(2^{-15,97}\\) | SBOX6           |
| Meilleure piste différentielle à 14 tours | \\(2^{-2830}\\)  | \\(2^{-2600}\\)  | BRUME           |
| Meilleure piste boomerang à 14 tours      | \\(2^{-2776}\\)  | \\(2^{-2486}\\)  | BRUME           |
| Piste linéaire à 14 tours                 | \\(2^{-1417}\\)  | \\(2^{-1421}\\)  | Quasi identique |

ANALYSE.md



Amélioration confirmée

&#x20;SBOX6 réduit effectivement la BCT maximale de 10 à 6.





Régression constatée

&#x20;Les meilleures pistes différentielles et boomerang trouvées deviennent sensiblement plus favorables à l'attaquant.



## 2. Pourquoi SBOX6 est paradoxalement moins intéressante

C'est le résultat le plus important de votre document.

La différence se situe dans la distribution des transitions, pas dans leur maximum.

BRUME :

Trois différences d'entrée possèdent une ligne DDT dont le maximum est seulement 2 :

\\[ a\in\\{1,2,9\\} \\]

Pour ces différences, aucune sortie ne donne une transition différentielle de probabilité \\(4/16\\).

SBOX6 :

Toutes les différences d'entrée non nulles possèdent exactement une sortie avec :

\\[ DDT[a,b]=4 \\]

La distribution est donc beaucoup plus uniforme.

Et cette uniformité profite à la recherche de caractéristiques.

Création du graphique en cours

Sur les meilleures pistes différentielles trouvées à 14 tours :

- BRUME utilise 1 306 S-boxes actives, dont 218 transitions DDT-2.
- SBOX6 utilise 1 300 S-boxes actives, toutes avec des transitions DDT-4.

Le coût de BRUME est donc :

\\[ 1088\times2+218\times3=2830 \\]

Celui de SBOX6 :

\\[ 1300\times2=2600 \\]

On retrouve exactement les 230 bits d'écart.

Cela signifie que la nouvelle S-box permet de construire une piste dont la probabilité est \\(2^{230}\\) fois supérieure à celle de la meilleure piste BRUME trouvée par le même moteur.

C'est un résultat expérimental particulièrement convaincant, même s'il ne démontre pas que ces pistes sont les meilleures possibles.&#x20;

ANALYSE.md

ANALYSE.md



## 3. Le résultat boomerang mérite une attention particulière

La nouvelle S-box améliore deux indicateurs :

\\[ BCT\_{\max}:10\rightarrow6 \\]

\\[ DBCT\_{\max}:52\rightarrow32 \\]

Pourtant, la recherche de pistes boomerang donne :

\\[ BRUME:2^{-2776} \\]

\\[ SBOX6:2^{-2486} \\]

Soit un écart de 290 bits en faveur de BRUME.

L'expérience sur trois tours est également intéressante.

| Expérience                             | BRUME | SBOX6 |
| -------------------------------------- | ----- | ----- |
| \\(2^{20}\\) quartets, 16 combinaisons | 13,4  | 4,6   |
| \\(2^{20}\\) quartets, 64 combinaisons | 19,9  | 14,5  |
| \\(2^{22}\\) quartets, 16 combinaisons | 27,6  | 10,5  |

Le seuil statistique pour la dernière expérience est 5,30.

SBOX6 conserve donc un distingueur boomerang sur trois tours. Il est plus faible, mais il n'a pas disparu.

Aucun signal significatif n'est rapporté à quatre tours ou davantage dans ces campagnes. Cela ne démontre pas l'absence de telles attaques.&#x20;

ANALYSE.md



## 4. Deux corrections scientifiques à apporter au rapport

J'ai également relevé deux points qui méritent une correction.

Première correction : l'interprétation du rapport BCT/DDT.

Le rapport indique :

\\[ \operatorname{moyenne}\left(\log_2(BCT/DDT)\right) \\]

BRUME : 0,207

SBOX6 : 0,453

Il interprète cette augmentation comme un coût moyen supérieur pour les transitions boomerang de SBOX6.

Cette interprétation semble inversée.

Puisque BCT/16 représente la probabilité de la transition de commutation et DDT/16 celle de la transition différentielle, un rapport BCT/DDT plus élevé signifie que la transition boomerang est relativement plus probable.

L'écart entre les deux moyennes est de 0,246 bit, soit un facteur géométrique d'environ 1,186, et non une multiplication par deux du coût cryptographique.

Je recommande de remplacer cet indicateur par une analyse explicite du coût de commutation :

\\[ C\_{\mathrm{switch}}=-\log_2(BCT[a,b]/16) \\]

et de comparer ses valeurs sur les transitions réellement empruntées par les pistes.

Cela ne remet pas en cause le résultat des recherches de pistes, mais améliore la rigueur de son interprétation.&#x20;

ANALYSE.md



Deuxième correction : l'histogramme DDT.

Le rapport indique 225 entrées non triviales, mais les fréquences annoncées totalisent :

\\[ 135+90+15=240 \\]

Il s'agit en réalité des 15 lignes non nulles avec les 16 colonnes, y compris la différence de sortie nulle.

Pour 225 entrées avec différences d'entrée et de sortie toutes deux non nulles, l'histogramme correct est :

\\[ \\{0:120,\\;2:90,\\;4:15\\} \\]

J'ai recalculé les tables à partir des deux permutations fournies dans le JSON : les distributions sont cohérentes avec cette distinction.&#x20;

ANALYSE.md



## 5. Ma recommandation pour la suite de BRUME



Recommandation

&#x20;Conserver la S-box BRUME actuelle comme référence.



Je ne remplacerais pas cette S-box par SBOX6.

Cela ne signifie pas qu'il faut abandonner l'objectif BCT = 6. Il faut simplement rechercher une S-box qui améliore la résistance boomerang sans sacrifier la distribution différentielle favorable de BRUME.

Je proposerais une nouvelle recherche avec plusieurs objectifs simultanés :

| Critère                           | Objectif                                       |
| --------------------------------- | ---------------------------------------------- |
| DU                                | 4                                              |
| BCT maximum                       | 6                                              |
| DBCT maximum                      | Minimiser                                      |
| Lignes DDT sans transition à 4    | En conserver                                   |
| Distribution des maxima BCT       | Éviter un profil uniformément défavorable      |
| Pistes différentielles à 14 tours | Faire mieux que BRUME                          |
| Pistes boomerang à 14 tours       | Faire mieux que BRUME                          |
| MEDP2                             | Maintenir ou améliorer                         |
| Résistance linéaire               | Ne pas dégrader                                |
| Distingueurs expérimentaux        | Tester à \\(2^{20}\\) et \\(2^{22}\\) quartets |

Je déconseille de fabriquer un score unique avec des coefficients arbitraires. Il vaut mieux conserver un classement multicritère et identifier les candidats non dominés, c'est-à-dire le front de Pareto.

### 6. Un point à ne surtout pas perdre de vue

Votre rapport précise que le moteur de recherche utilise une stratégie gloutonne, exhaustive pour les sources de poids 1, échantillonnée pour celles de poids 3, et exhaustive pour celles de poids 2 uniquement jusqu'à huit tours.

Les pistes obtenues sont valides, mais ne constituent pas une preuve d'optimalité.&#x20;

ANALYSE.md



Par ailleurs, les bornes wide-trail annoncées pour les 32 tours restent identiques avec SBOX6 : \\(2^{-256}\\) en différentiel et \\(2^{-128}\\) en linéaire. Elles reposent sur les mêmes paramètres DU, LAT et branch number.

Cela ne signifie pas que les deux S-boxes ont le même comportement sur les pistes réduites, comme vos propres expériences le démontrent.&#x20;

ANALYSE.md



## 6. La prochaine expérience que je recommande

Je donnerais à cette étape un nom : BRUME-SBOX-SEARCH v1.

Son objectif serait de découvrir une troisième S-box qui combine les avantages de BRUME et de SBOX6 sans reproduire leurs défauts respectifs.

Le protocole devrait produire automatiquement, pour chaque candidate :

1. Les tables DDT, LAT, BCT, LBCT, UBCT, EBCT, FBCT et DBCT.
2. La distribution des maxima de chaque ligne, et pas seulement les maxima globaux.
3. Les meilleures pistes différentielles, linéaires et boomerang jusqu'à 14 tours.
4. Les expériences de distingueur boomerang à trois et quatre tours.
5. Une comparaison automatique avec BRUME et SBOX6.

Le résultat recherché n'est pas simplement une S-box ayant BCT = 6.

C'est une S-box ayant BCT = 6 tout en conservant une distribution différentielle et une résistance multi-tours au moins aussi bonnes que BRUME.

C'est beaucoup plus exigeant, mais c'est la piste de recherche que vos résultats justifient désormais.

Mon verdict : votre expérimentation SBOX6 est réussie, même si la candidate n'est pas retenue. Elle montre précisément pourquoi une optimisation cryptographique doit porter sur le comportement global de la primitive et non sur un indicateur isolé.
