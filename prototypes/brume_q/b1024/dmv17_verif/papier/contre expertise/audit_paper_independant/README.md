# Audit indépendant de `paper.tex` – 16 novembre 2026

Les cinq scripts Python ci-joints constituent des **recalculs indépendants** des expressions numériques présentes dans le manuscrit. Ils ne sont **pas** les programmes revendiqués par les auteurs et ne remplacent **pas** une preuve mathématique ni une revue scientifique indépendante.

## Exécution

Python 3.11+ et `sympy` sont nécessaires pour les fichiers `recalcul_contre_exemples.py` et `recalcul_collision_f2.py`. Le reste emploie la bibliothèque standard.

```bash
python3 -m pip install sympy
python3 recalcul_contre_exemples.py
python3 recalcul_collision_f2.py
python3 recalcul_borne_f3.py
python3 recalcul_nu.py
python3 recalcul_reparation.py
```

## Correspondance

- `recalcul_contre_exemples.py` : polynôme de l'exemple vérifiable à la main ; cinq instances de la Proposition distingueur, arithmétique rationnelle, comparaison LB > B.
- `recalcul_collision_f2.py` : huit lignes du tableau des collisions `f2`, sommes exactes sur les profils d'occupation, y compris le contrôle.
- `recalcul_borne_f3.py` : trois bornes inférieures formelles de la récupération d'état.
- `recalcul_nu.py` : seuils exacts `nu` pour les trois petites instances (distribution d'occupation exacte).
- `recalcul_reparation.py` : taille de la borne réparée sur les cinq instances, comparaison à la borne initiale.

## Limitations et réserves

1. Le code ne certifie pas les raisonnements de probabilité sous-jacents : une formule peut être évaluée correctement et reposer néanmoins sur une proposition mal démontrée.
2. Les simulations déclarées dans le manuscrit ne peuvent pas être auditées faute des sources C/Python et des résultats bruts annoncés en annexe.
3. Une simulation indépendante de la stratégie `R_{G,v,F}` à budget fixe a suggéré une différence méthodologique avec le taux publié. Aucun code de cette simulation n'est inclus dans cette archive ; elle constitue un point à investiguer, pas une preuve de fraude ni une réfutation de la proposition formelle.
4. L'exploration des cinq paramètres choisis ne prouve pas un résultat général sur la taille du plus grand écart possible ni sur la sécurité d'un schéma déployé.
