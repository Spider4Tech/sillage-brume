# Rapport du banc BRUME-512 apparié

## Configuration vérifiée

- Graines : **5**
- Tours : **3**
- Combinaisons par tour et graine : **4**
- Quartets par combinaison : **2^10**
- Générateur déclaré : **ChaCha20 RFC 8439, 256-bit key, 96-bit nonce, counter indexed by quartet**
- Total des quartets appariés par candidate : **61440**

Les trois candidates reçoivent les mêmes états aléatoires, les mêmes différences d'entrée et les mêmes différences injectées. Les comptes 2x2 sont donc appariés quartet par quartet.

## Corrections multiples

- Comparaisons appariées par nibble : famille de **5,760** tests ; seuil normal bilatéral **5.229965**.
- Biais marginaux contre p=1/16 : famille de **5,760** tests ; seuil normal bilatéral **5.229965**.
- Comparaisons appariées des retours exacts : famille de **45** tests ; seuil normal bilatéral indicatif **4.246626**.
- Risque familial ciblé : **1/1024** ; correction de Bonferroni.

## Résultats appariés par nibble

- Tests significatifs après Bonferroni : **1 / 5760**.
- Tests significatifs à partir du tour 3 : **0 / 1920**.
- Les combinaisons sont traitées comme des strates de géométrie distinctes : les discordances `n01` et `n10` sont additionnées pour le score de McNemar stratifié (score CMH pour paires appariées). Un binomial conditionnel exact est utilisé quand il y a au plus 20 000 discordances.
- Le signe de `rate_a_minus_b` indique quelle candidate produit le plus souvent un nibble de différence nul. Cela ne constitue pas, à lui seul, un classement de sécurité.

| Paire | Graine | Tour | Nibble | Taux A | Taux B | Z McNemar | p corrigée |
|---|---|---:|---:|---:|---:|---:|---:|
| BRUME_vs_SBOX6 | 0088549f | 3 | 0 | 0.0708008 | 0.0627441 | 1.433 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 1 | 0.0620117 | 0.0629883 | -0.137 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 2 | 0.064209 | 0.0620117 | 0.364 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 3 | 0.0554199 | 0.0649414 | -1.755 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 4 | 0.0710449 | 0.0605469 | 1.858 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 5 | 0.064209 | 0.064209 | 0.000 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 6 | 0.0629883 | 0.0600586 | 0.511 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 7 | 0.0600586 | 0.0576172 | 0.415 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 8 | 0.0612793 | 0.057373 | 0.699 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 9 | 0.0678711 | 0.0612793 | 1.157 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 10 | 0.0668945 | 0.0593262 | 1.365 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 11 | 0.0627441 | 0.0610352 | 0.279 | 1.000e+00 |

## Biais marginaux par candidate

- Tests significatifs contre le modèle marginal p=1/16 après Bonferroni : **3840 / 5760**.
- Parmi les tours 3 et suivants : **0 / 1920**.
- Ces tests utilisent l'approximation binomiale normale héritée du protocole précédent ; les comparaisons appariées ci-dessus constituent l'analyse principale entre candidates.

| Candidate | Graine | Tour | Nibble | Taux nul | Z vs 1/16 | p corrigée |
|---|---|---:|---:|---:|---:|---:|
| BRUME | 0088549f | 3 | 0 | 0.0708008 | 2.195 | 1.000e+00 |
| BRUME | 0088549f | 3 | 1 | 0.0620117 | -0.129 | 1.000e+00 |
| BRUME | 0088549f | 3 | 2 | 0.064209 | 0.452 | 1.000e+00 |
| BRUME | 0088549f | 3 | 3 | 0.0554199 | -1.872 | 1.000e+00 |
| BRUME | 0088549f | 3 | 4 | 0.0710449 | 2.259 | 1.000e+00 |
| BRUME | 0088549f | 3 | 5 | 0.064209 | 0.452 | 1.000e+00 |
| BRUME | 0088549f | 3 | 6 | 0.0629883 | 0.129 | 1.000e+00 |
| BRUME | 0088549f | 3 | 7 | 0.0600586 | -0.645 | 1.000e+00 |
| BRUME | 0088549f | 3 | 8 | 0.0612793 | -0.323 | 1.000e+00 |
| BRUME | 0088549f | 3 | 9 | 0.0678711 | 1.420 | 1.000e+00 |
| BRUME | 0088549f | 3 | 10 | 0.0668945 | 1.162 | 1.000e+00 |
| BRUME | 0088549f | 3 | 11 | 0.0627441 | 0.065 | 1.000e+00 |

## Retours exacts de l'état complet

| Candidate | Nombre de retours exacts observés |
|---|---:|
| BRUME | 23359 |
| SBOX6 | 23358 |
| SBOX_V3 | 23267 |

Comparaisons exactes significatives après correction : **5 / 45**.
Les événements exacts sont rares ; le test binomial conditionnel exact est utilisé lorsque le nombre de discordances est inférieur ou égal à 20 000, sinon McNemar asymptotique avec correction de continuité.

## Limites d'interprétation

1. Ce banc compare trois variantes sur une famille précise de différences et sur un maximum de tours réduit. Il ne prouve pas la sécurité des 32 tours.
2. McNemar teste l'égalité des taux d'événement appariés ; il ne prouve pas qu'une S-box est plus sûre dans l'absolu.
3. Un nibble nul est un événement marginal. Les 128 coordonnées d'un même quartet sont dépendantes ; Bonferroni corrige le nombre de tests, mais le modèle p=1/16 reste une référence exploratoire.
4. Les graines ChaCha20 rendent la génération reproductible et séparent les flux par tour/combinaison/quartet ; elles ne remplacent pas l'analyse cryptographique des hypothèses du protocole.
5. Les tours 1 et 2 sont conservés comme contrôles structurels ; ils restent inclus dans Bonferroni, mais ne sont pas mis en avant dans les tableaux de comparaison à partir du tour 3.

## Fichiers produits

- `paired_zero_mcnemar.csv` : contingences et comparaisons appariées (McNemar stratifié par combinaison) par nibble.
- `candidate_zero_marginals.csv` : fréquence du nibble nul par candidate.
- `paired_exact_mcnemar.csv` : comparaisons appariées des retours exacts.
- `candidate_exact_returns.csv` : comptes de retours exacts par candidate.
