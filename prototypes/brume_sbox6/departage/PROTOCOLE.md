# Protocole de départage BRUME / SBOX_V3 / SBOX_V4 / candidates (BRUME-SBOX-SEARCH v3)

Rédigé le 10 novembre 2026. Ce protocole remplace, pour le choix de la S-box, les critères des
campagnes précédentes (`ANALYSE_V3.md`, `brume_tests_apparies*`). Il ne retient que les mesures qui
peuvent **réellement** départager des S-box 4 bits optimales dans la permutation BRUME-512, et il
fixe **avant les calculs** les statuts des résultats et la règle de décision.

Les quatre S-box de référence :

| Nom | Table (hexadécimal, S(0)…S(15)) |
|---|---|
| BRUME (en service) | `891AC406DF37E2B5` |
| SBOX6 (écartée : profil DDT/BCT plat) | `F2CDB7E30465A891` |
| SBOX_V3 | `E936FBA8C40571D2` |
| SBOX_V4 | `A4F60295C873D1BE` |

## 1. Ce qui ne départage pas (et pourquoi on cesse de s'en servir)

1. **Les tables locales seules.** DU = 4, NL = 4, degré 3 et IA 2 sont communs aux quatre S-box ; DBCT,
   SAC et cycles ne pilotent aucune attaque multi-tours mesurée ici. Ils restent des filtres, pas des
   critères de classement.
2. **Les pistes gloutonnes ou en faisceau à 14 tours** (`ANALYSE_V3.md` § 4). Une piste trouvée par
   une heuristique est une valeur atteinte par l'attaquant, pas une borne : comparer deux heuristiques
   compare les heuristiques. Ces valeurs sont requalifiées HEURISTIQUE (§ 6).
3. **Les bornes par nombre minimal de S-box actives.** Elles valent 2 bits par S-box active pour toute
   S-box de DU = 4 et sont donc identiques pour toutes les candidates.
4. **Le taux de « nibble nul » au retour** (banc apparié). Après le tour 2, il ne sépare plus rien
   (1 test significatif sur 11 520). Les « retours exacts » sont dominés par une structure
   indépendante de la S-box : **957 couples (i, j′)** vérifient M[j′][i] = M⁻¹[i][j′] = 0, et le
   boomerang à 2 tours y revient avec probabilité 1 (§ 4.3).
5. **Les intégrales (INT), constaté après calcul (11 novembre 2026).** À 64 bases, les profils de bits
   robustes sont identiques pour les 8 S-box testées, à chaque tour et dans les 18 configurations
   (`RAPPORT.md` § 6). La mesure reste dans le banc comme contrôle, mais elle ne classe plus.
6. **La permutation complète à 32 tours.** Aucune mesure ne la touche. Toutes les mesures portent
   sur 2 ou 3 tours, là où les S-box diffèrent de façon mesurable ou prouvable.

## 2. Ce qui départage

| Code | Mesure | Tours | Statut visé | Sens favorable |
|---|---|---|---|---|
| D2 | max DP(α → β), coque complète, α de poids 1 | 2 | EXACT_RESTREINT → EXACT par le certificat C2 | plus petit |
| L2 | max \|C(u0 → u2)\|, coque complète avec constantes, 1 S-box active au tour 2 | 2 | EXACT_RESTREINT | plus petit |
| B2 | probabilité de retour du boomerang, α et δ′ de poids 1, pour **tous** (i, a, j′, δ′) | 2 | EXACT_RESTREINT | plus petit |
| D3 | meilleure caractéristique différentielle, 1 S-box active au tour 1 | 3 | EXACT_RESTREINT ; EXACT si C3 le couvre | plus grand (coût) |
| L3 | meilleure caractéristique linéaire, 1 S-box active au tour 3 | 3 | EXACT_RESTREINT ; EXACT si C3 le couvre | plus grand (coût) |
| B3 | probabilité de retour du boomerang à 3 tours | 3 | EMPIRIQUE (sélection par prédicteur de Markov) | plus petit |
| INT | bits de somme nulle sur toutes les bases (cubes de 4 à 24 bits) | 1–5 | EMPIRIQUE | plus petit |

Les « effets différentiels cumulés » sont D2 (somme exacte de toutes les caractéristiques d'un couple
(α, β)). La « coque linéaire » est L2, constantes de tour comprises (les signes peuvent annuler). Les
« rectangles boomerang » sont B2 (exact) et B3 (mesuré). Le rectangle amplifié, à clair choisi
seulement, se déduit des mêmes probabilités de piste ; à n = 512 il n'est pas mesurable. La
« recherche intégrale » est INT (cubes réels sur la permutation), avec la table de division de
chaque S-box (`local`).

## 3. Statuts et audit des limites

Chaque résultat écrit porte un champ `statut`, une `restriction` explicite et la `preuve` qui le fonde.

- **EXACT** : le modèle représente **toutes** les contraintes de la permutation réduite à R tours :
  les 128 S-box de chaque tour, la vraie matrice M avec ses coefficients GF(16), les vraies tables
  DDT, LAT et BCT, et les constantes quand elles comptent (corrélations). Aucune restriction ne
  porte sur l'espace de recherche. **Et** l'optimalité est prouvée : statut `OPTIMAL` avec écart nul,
  `INFEASIBLE`, ou énumération / B&B exhaustif à borne admissible. **Et** le témoin est revérifié
  indépendamment sur la permutation.
- **EXACT_RESTREINT** : optimum prouvé d'un sous-problème nommé (par exemple « entrée de poids 1 »).
  C'est une valeur **atteinte par l'attaquant** : une borne inférieure sur la meilleure probabilité, ou
  une borne supérieure sur le coût minimal. **Ce n'est jamais une borne de sécurité.**
- **BORNE** : optimum ou infaisabilité **prouvés** d'une relaxation complète (§ 5). C'est une borne
  de sécurité valide, mais pas une valeur atteinte.
- **HEURISTIQUE** : solution réalisable sans preuve d'optimalité (glouton, faisceau, `FEASIBLE`,
  limite de temps atteinte, `best_bound` différent de l'objectif).
- **EMPIRIQUE** : fréquence mesurée sur la permutation réelle, avec un intervalle de Wilson à 4 σ.
- **MODELE** : valeur calculée sous l'hypothèse de Markov (indépendance des tours), sans preuve
  pour la permutation. Elle sert à **sélectionner** les différences à mesurer, jamais de résultat.

**Règle d'audit (MILP, CP-SAT, SAT, B&B).** Une recherche n'est qualifiée d'*exacte* que si les
deux conditions sont réunies :

1. le modèle représente la permutation complète. Un modèle restreint (poids d'entrée imposé,
   sous-ensemble de tours, de positions ou de valeurs) donne au mieux EXACT_RESTREINT. Un modèle
   relâché (troncature) donne au mieux BORNE ;
2. le solveur **prouve** l'optimalité. `FEASIBLE`, `UNKNOWN`, une limite de temps atteinte ou un
   écart non nul entre l'objectif et la borne donnent HEURISTIQUE, quelle que soit la qualité de la
   solution.

**Promotion.** Un EXACT_RESTREINT devient EXACT si une BORNE prouvée couvre tout le complément de
la restriction avec une valeur au moins aussi bonne. Exemple : D2 sur les entrées de poids 1, plus
le certificat C2 sur les entrées de poids ≥ 2.

**Fidélité du modèle.** Elle est contrôlée à chaque exécution (`departage controle`) :
- la S-box BRUME du banc est égale à `BR_SBOX` ;
- la permutation reconstruite donne, sur 32 tours et 2 000 états, les mêmes sorties octet pour
  octet que `sl_brume_permute_ref` (libsillage.so) ;
- M · M⁻¹ = I ;
- l'adjoint binaire Mᵀ est vérifié par l'identité ⟨u, Mx⟩ = ⟨Mᵀu, x⟩ ;
- l'aller-retour avant/arrière est vérifié pour chaque S-box ;
- les conditions d'indépendance invoquées sont vérifiées : le rang de M[N[i], ¬i] vaut 7 pour tout i.

## 4. Mesures

### 4.1 D2 — coque différentielle exacte à 2 tours

Pour α = a·e_i, la S-box S1 en i passe de a à b. S2 reçoit M[j][i]·b en chaque j ∈ N[i] (7 S-box) et
sort d_j, puis β = M·d. Les 7 entrées de S2 sont uniformes et indépendantes de x_i, puisque
rang M[N[i], ¬i] = 7. Donc, exactement :

  DP(α, β) = Σ_b DDT[a][b]/16 · Π_{j∈N[i]} DDT[M[j][i]·b][d_j]/16.

C'est la somme de **toutes** les caractéristiques du couple (α, β), car b est la seule variable
libre. Le maximum sur β s'obtient par un B&B à borne admissible (Σ_b P_b · Π des maxima de ligne
restants), en arithmétique entière exacte. Contrôle : les 3 plus grandes valeurs sont mesurées
sur la permutation réelle à 2 tours (2²⁴ paires).

**Certificat C2.** Pour une entrée de poids w0 ≥ 2, DP ≤ min(4^−w0, 4^−w1). CP-SAT prouve, sur la
relaxation tronquée complète, qu'**aucun** motif ne vérifie 2 ≤ w0 ≤ 7 et w1 ≤ 7. Hors des entrées
de poids 1, on a donc DP ≤ 2⁻¹⁶. Comme le maximum sur les entrées de poids 1 est ≥ 2⁻¹⁶, D2
devient EXACT pour toutes les entrées.

### 4.2 L2 — coque linéaire exacte à 2 tours

Masque de sortie u2 = (M⁻¹)ᵀ(λ e_j). En sortie de S2, le masque vaut alors λ au nibble j. L'entrée
μ de S2 est la seule variable libre, et w1 = Mᵀ(μ e_j) :

  C(u0, u2) = Σ_μ (−1)^{μ·rc1_j} LAT[μ][λ]/16 · Π_{k∈N[j]} (−1)^{u0_k·rc0_k} LAT[u0_k][w1_k(μ)]/16.

C'est une identité exacte (théorème de la coque linéaire, sans hypothèse d'indépendance). Les
constantes comptent : celles du tour 2 sont à l'intérieur de la somme. On calcule le maximum de
|C| par B&B exact, pour la fenêtre (tours 1–2) et pour chaque fenêtre (r, r+1). Contrôle :
corrélations mesurées sur 2²⁴ entrées, comparées à 4 σ.

### 4.3 B2 — boomerang exact à 2 tours

On pose α = a·e_i, δ = M(δ′ e_j′), c1 = M[j′][i] et c2 = M⁻¹[i][j′]. Le retour exige que les
deux paires du bas aient la même différence γ en entrée de S2 (sinon M⁻¹ la propage à plus de
100 nibbles), puis la condition BCT en S1 :

  P = 2⁻⁸ Σ_{x,t} [γ(t) = γ(t ⊕ c1·b(x))] · [S⁻¹(S(x)⊕c2γ(t)) ⊕ S⁻¹(S(x⊕a)⊕c2γ(t)) = a].

Ici γ(t) = t ⊕ S⁻¹(S(t)⊕δ′) et b(x) = S(x)⊕S(x⊕a). La probabilité ne dépend de (i, j′) que par
(c1, c2). La table P[c1][c2][a][δ′] est donc complète et couvre les 3,7 M combinaisons (i, a, j′, δ′).
Le cas (0, 0) est trivial (P = 1, 957 couples). On rapporte le maximum « deux couches actives »
(c1 ≠ 0, c2 ≠ 0), les maxima à une seule couche active, et la moyenne. Contrôle : quartets réels
avec inversion complète (2²⁰ quartets).

### 4.4 B3 — boomerang à 3 tours (mesuré, apparié)

La probabilité à 3 tours est de l'ordre de 2⁻⁸ : elle se mesure. Le retour se reformule exactement
après le tour 1 : Y3 ⊕ Y4 = ε·M[:, i] en entrée de S2, puis S⁻¹(U3_i) ⊕ S⁻¹(U3_i ⊕ ε) = a. Cette
reformulation est vérifiée quartet par quartet contre l'inversion complète (`identite = 0` exigé).

Sélection : les K meilleures combinaisons (i, a, j′, δ′) du prédicteur de Markov (statut MODELE) de
**chaque** S-box. Le prédicteur est restreint aux j′ hors de portée de N[i]. On mesure **toutes les
S-box sur l'union des sélections**, avec les mêmes états d'entrée (flux compteur). La sélection ne
dépend d'aucune mesure. Résultat : max des P mesurées par S-box, avec Wilson 4 σ.

### 4.5 INT — intégrales empiriques appariées

Cubes de k nibbles actifs, en deux géométries : le voisinage fermé N[0] et des positions
aléatoires fixées. On utilise 3 bases aléatoires, avec les mêmes positions et les mêmes bases pour
toutes les S-box, dans le sens direct (tours 1…R) et le sens inverse (tours 32…33−R). Résultat :
le nombre de bits de somme nulle dans **toutes** les bases, par tour. La table de division
conventionnelle de S et S⁻¹ est donnée par `local`.

## 5. Certificats tronqués (BORNE)

`certificat_tronque.py` (OR-Tools CP-SAT) construit la relaxation tronquée **complète** :
- une variable binaire par S-box et par tour ;
- le support exact de M lu dans `sillage/brume512.py` ;
- pour chaque sortie v, avec s = Σ_{k∈N[v]} x_r[k] : s = 0 ⇒ inactive, s = 1 ⇒ active, s ≥ 2 ⇒ libre.

L'adjacence étant symétrique, la même relaxation vaut pour les masques linéaires, tours inversés. On
calcule :
- **C2** : infaisabilité de 2 ≤ w0 ≤ 7, w1 ≤ 7 ;
- le minimum d'actives à 2 et 3 tours ;
- **C3** : le minimum d'actives à 3 tours avec w0 ≥ 2.

Si 2·C3 ≥ D3, alors D3 est l'optimum global à 3 tours (EXACT). Si 1·C3 ≥ L3, de même pour L3.
Seuls les statuts `OPTIMAL` et `INFEASIBLE` sont acceptés.

## 6. Règle de décision (fixée avant les calculs)

Une candidate C est déclarée **meilleure que BRUME** si :

- **R1 (filtres durs)** : DU = 4, max|LAT| = 8, les 15 composantes de degré 3, BCT max ≤ 8, au
  moins 3 lignes DDT de maximum 2 (pas de profil plat) ;
- **R2 (aucune régression)** : D3 ≥ D3(BRUME), L3 ≥ L3(BRUME), D2 ≤ D2(BRUME), L2 ≤ L2(BRUME) sur
  toutes les fenêtres, B2 (deux couches) ≤ B2(BRUME), max B3 mesuré non significativement
  supérieur (Wilson 4 σ), INT : pas plus de bits robustes que BRUME au dernier tour non saturé ;
- **R3 (gain réel)** : strictement meilleure sur au moins une mesure EXACT ou EXACT_RESTREINT, ou
  significativement meilleure sur B3 ;
- **R4** : tous les contrôles passent (`controle`, contrôles empiriques de D2, L2, B2, identité B3,
  revérification des témoins D3 et L3).

**Variante R1′ (ajoutée après coup, le 10 novembre 2026).** BCT max ≤ 10, comme BRUME. Elle a été
introduite après avoir constaté que B3 est la contrainte qui lie. Une candidate admise seulement
sous R1′ (CAND_B1) est signalée comme telle et ne compte pas comme satisfaisant R1.

**Mesure B3 sur GPU (11 novembre 2026).** `b3_gpu.cu` / `b3_gpu_hote.c` reprennent `departage.c` et ne
déportent que le comptage. Chaque mesure GPU est précédée d'un contrôle exact : les comptes C et GPU
doivent être égaux à l'unité près pour la même graine. Le mode `balayage` mesure toutes les
combinaisons (i, a, j′, δ′) au lieu de la sélection du prédicteur (§ 4.4).

Une candidate qui satisfait R1–R4 reste une **proposition** : changer la S-box change l'algorithme
(KAT, cache de division property, preuves). La décision d'adoption revient à l'auteur.

## 7. Reproduction

```bash
cd prototypes/brume_sbox6/departage
./run_departage.sh                 # compile, contrôle, mesures exactes, B3, INT, criblage
distrobox enter tgh -- python3 certificat_tronque.py 900 resultats/<horodatage>
```

Toutes les sorties brutes (CSV par entrée, JSON par mesure) vont dans `resultats/<horodatage>/`,
avec `metadonnees.json` : commit, compilateur, options, empreintes SHA-256 des sources et des tables.
Générateur : un flux à compteur (graine, flux, indice), indépendant du nombre de threads. Toutes
les graines figurent dans les sources.
