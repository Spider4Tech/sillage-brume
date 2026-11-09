# Rapport du banc BRUME-512 apparié

## Configuration vérifiée

- Graines : **5**
- Tours : **8**
- Combinaisons par tour et graine : **32**
- Quartets par combinaison : **2^18**
- Générateur déclaré : **ChaCha20 RFC 8439, 256-bit key, 96-bit nonce, counter indexed by quartet**
- Total des quartets appariés par candidate : **335544320**

Les trois candidates reçoivent les mêmes états aléatoires, les mêmes différences d'entrée et les mêmes différences injectées. Les comptes 2x2 sont donc appariés quartet par quartet.

## Corrections multiples

- Comparaisons appariées par nibble : famille de **15,360** tests ; seuil normal bilatéral **5.408434**.
- Biais marginaux contre p=1/16 : famille de **15,360** tests ; seuil normal bilatéral **5.408434**.
- Comparaisons appariées des retours exacts : famille de **120** tests ; seuil normal bilatéral indicatif **4.461520**.
- Risque familial ciblé : **1/1024** ; correction de Bonferroni.

## Résultats appariés par nibble

- Tests significatifs après Bonferroni : **1749 / 15360**.
- Tests significatifs à partir du tour 3 : **0 / 11520**.
- Les combinaisons sont traitées comme des strates de géométrie distinctes : les discordances `n01` et `n10` sont additionnées pour le score de McNemar stratifié (score CMH pour paires appariées). Un binomial conditionnel exact est utilisé quand il y a au plus 20 000 discordances.
- Le signe de `rate_a_minus_b` indique quelle candidate produit le plus souvent un nibble de différence nul. Cela ne constitue pas, à lui seul, un classement de sécurité.

| Paire | Graine | Tour | Nibble | Taux A | Taux B | Z McNemar | p corrigée |
|---|---|---:|---:|---:|---:|---:|---:|
| SBOX6_vs_SBOX_V3 | 0088549f | 3 | 67 | 0.0627229 | 0.0622151 | 4.296 | 2.675e-01 |
| BRUME_vs_SBOX_V3 | a21b5433 | 3 | 28 | 0.0627193 | 0.0622189 | 4.234 | 3.523e-01 |
| BRUME_vs_SBOX_V3 | 04007bd0 | 4 | 90 | 0.062218 | 0.0626962 | -4.047 | 7.979e-01 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 0 | 0.0623906 | 0.0625007 | -0.931 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 1 | 0.0624511 | 0.0624206 | 0.257 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 2 | 0.0625594 | 0.062549 | 0.087 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 3 | 0.0625443 | 0.0623944 | 1.268 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 4 | 0.0624142 | 0.0625451 | -1.107 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 5 | 0.0624323 | 0.0625254 | -0.787 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 6 | 0.0625886 | 0.0624137 | 1.478 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 7 | 0.0623707 | 0.0625699 | -1.685 | 1.000e+00 |
| BRUME_vs_SBOX6 | 0088549f | 3 | 8 | 0.0624499 | 0.0624927 | -0.361 | 1.000e+00 |

## Biais marginaux par candidate

- Tests significatifs contre le modèle marginal p=1/16 après Bonferroni : **3840 / 15360**.
- Parmi les tours 3 et suivants : **0 / 11520**.
- Ces tests utilisent l'approximation binomiale normale héritée du protocole précédent ; les comparaisons appariées ci-dessus constituent l'analyse principale entre candidates.

| Candidate | Graine | Tour | Nibble | Taux nul | Z vs 1/16 | p corrigée |
|---|---|---:|---:|---:|---:|---:|
| BRUME | 04007bd0 | 3 | 95 | 0.0629041 | 4.835 | 2.041e-02 |
| BRUME | 0088549f | 3 | 20 | 0.0628837 | 4.591 | 6.761e-02 |
| SBOX6 | 0088549f | 5 | 50 | 0.0621554 | -4.124 | 5.729e-01 |
| BRUME | 0088549f | 3 | 0 | 0.0623906 | -1.309 | 1.000e+00 |
| BRUME | 0088549f | 3 | 1 | 0.0624511 | -0.585 | 1.000e+00 |
| BRUME | 0088549f | 3 | 2 | 0.0625594 | 0.710 | 1.000e+00 |
| BRUME | 0088549f | 3 | 3 | 0.0625443 | 0.531 | 1.000e+00 |
| BRUME | 0088549f | 3 | 4 | 0.0624142 | -1.027 | 1.000e+00 |
| BRUME | 0088549f | 3 | 5 | 0.0624323 | -0.810 | 1.000e+00 |
| BRUME | 0088549f | 3 | 6 | 0.0625886 | 1.060 | 1.000e+00 |
| BRUME | 0088549f | 3 | 7 | 0.0623707 | -1.548 | 1.000e+00 |
| BRUME | 0088549f | 3 | 8 | 0.0624499 | -0.599 | 1.000e+00 |

## Retours exacts de l'état complet

| Candidate | Nombre de retours exacts observés |
|---|---:|
| BRUME | 47280553 |
| SBOX6 | 47273776 |
| SBOX_V3 | 47136901 |

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
