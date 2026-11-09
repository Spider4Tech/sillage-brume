# Rapport du banc BRUME-512 apparié

## Configuration vérifiée

- Graines : **5**
- Tours : **8**
- Combinaisons par tour et graine : **32**
- Quartets par combinaison : **2^20**
- Générateur déclaré : **ChaCha20 RFC 8439, 256-bit key, 96-bit nonce, counter indexed by quartet**
- Total des quartets appariés par candidate : **1342177280**

Les trois candidates reçoivent les mêmes états aléatoires, les mêmes différences d'entrée et les mêmes différences injectées. Les comptes 2x2 sont donc appariés quartet par quartet.

## Corrections multiples

- Comparaisons appariées par nibble : famille de **15,360** tests ; seuil normal bilatéral **5.408434**.
- Biais marginaux contre p=1/16 : famille de **15,360** tests ; seuil normal bilatéral **5.408434**.
- Comparaisons appariées des retours exacts : famille de **120** tests ; seuil normal bilatéral indicatif **4.461520**.
- Risque familial ciblé : **1/1024** ; correction de Bonferroni.

## Résultats appariés par nibble

- Tests significatifs après Bonferroni : **1753 / 15360**.
- Tests significatifs à partir du tour 3 : **4 / 11520**.
- Les combinaisons sont traitées comme des strates de géométrie distinctes : les discordances `n01` et `n10` sont additionnées pour le score de McNemar stratifié (score CMH pour paires appariées). Un binomial conditionnel exact est utilisé quand il y a au plus 20 000 discordances.
- Le signe de `rate_a_minus_b` indique quelle candidate produit le plus souvent un nibble de différence nul. Cela ne constitue pas, à lui seul, un classement de sécurité.

| Paire | Graine | Tour | Nibble | Taux A | Taux B | Z McNemar | p corrigée |
|---|---|---:|---:|---:|---:|---:|---:|
| SBOX6_vs_SBOX_V3 | 0088549f | 3 | 67 | 0.0627368 | 0.0622736 | 7.836 | 7.139e-11 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 67 | 0.0623888 | 0.0627368 | -5.885 | 6.099e-05 |
| BRUME_vs_SBOX6 | 04007bd0 | 3 | 95 | 0.062875 | 0.0625358 | 5.731 | 1.536e-04 |
| BRUME_vs_SBOX_V3 | 04007bd0 | 3 | 95 | 0.062875 | 0.0625536 | 5.430 | 8.663e-04 |
| BRUME_vs_SBOX_V3 | 0088549f | 3 | 24 | 0.0627026 | 0.062383 | 5.405 | 9.943e-04 |
| BRUME_vs_SBOX_V3 | 0088549f | 3 | 62 | 0.0625255 | 0.0628154 | -4.899 | 1.476e-02 |
| SBOX6_vs_SBOX_V3 | 0088549f | 3 | 62 | 0.0625255 | 0.0628154 | -4.898 | 1.486e-02 |
| BRUME_vs_SBOX_V3 | a21b5433 | 3 | 28 | 0.0626552 | 0.0623739 | 4.759 | 2.991e-02 |
| BRUME_vs_SBOX_V3 | 0088549f | 3 | 59 | 0.0625955 | 0.0623332 | 4.440 | 1.384e-01 |
| SBOX6_vs_SBOX_V3 | aba56d3c | 3 | 21 | 0.0626903 | 0.0624284 | 4.430 | 1.449e-01 |
| BRUME_vs_SBOX6 | aba56d3c | 3 | 12 | 0.0626565 | 0.0624007 | 4.327 | 2.319e-01 |
| BRUME_vs_SBOX_V3 | 04007bd0 | 3 | 81 | 0.06242 | 0.0626695 | -4.221 | 3.744e-01 |

## Biais marginaux par candidate

- Tests significatifs contre le modèle marginal p=1/16 après Bonferroni : **3844 / 15360**.
- Parmi les tours 3 et suivants : **4 / 11520**.
- Ces tests utilisent l'approximation binomiale normale héritée du protocole précédent ; les comparaisons appariées ci-dessus constituent l'analyse principale entre candidates.

| Candidate | Graine | Tour | Nibble | Taux nul | Z vs 1/16 | p corrigée |
|---|---|---:|---:|---:|---:|---:|
| BRUME | 04007bd0 | 3 | 95 | 0.062875 | 8.974 | 4.394e-15 |
| SBOX_V3 | 0088549f | 3 | 62 | 0.0628154 | 7.548 | 6.810e-10 |
| SBOX6 | 0088549f | 3 | 67 | 0.0627368 | 5.668 | 2.224e-04 |
| SBOX_V3 | 0088549f | 3 | 67 | 0.0622736 | -5.417 | 9.293e-04 |
| SBOX_V3 | 0088549f | 3 | 100 | 0.0622942 | -4.924 | 1.304e-02 |
| BRUME | 0088549f | 3 | 24 | 0.0627026 | 4.848 | 1.914e-02 |
| BRUME | 0088549f | 3 | 20 | 0.0626941 | 4.644 | 5.243e-02 |
| SBOX6 | aba56d3c | 3 | 21 | 0.0626903 | 4.554 | 8.071e-02 |
| BRUME | 04007bd0 | 3 | 47 | 0.0626802 | 4.313 | 2.478e-01 |
| BRUME | aba56d3c | 3 | 124 | 0.0623298 | -4.073 | 7.130e-01 |
| SBOX_V3 | 04007bd0 | 3 | 81 | 0.0626695 | 4.057 | 7.626e-01 |
| BRUME | 0088549f | 3 | 0 | 0.0624782 | -0.521 | 1.000e+00 |

## Retours exacts de l'état complet

| Candidate | Nombre de retours exacts observés |
|---|---:|
| BRUME | 189111138 |
| SBOX6 | 189102253 |
| SBOX_V3 | 188547220 |

Comparaisons exactes significatives après correction : **17 / 120**.
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
