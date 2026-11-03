# Preuves de sécurité — SILLAGE v0.4

Ce document rassemble les énoncés et preuves qui fondent les revendications
de la suite. Chaque énoncé précise son modèle (modèle standard, oracle
aléatoire ROM, permutation idéale) et ses hypothèses. Les vérifications
numériques correspondantes sont citées (`tests/…`).

Notations : `λ` paramètre de sécurité ; `negl` négligeable ; `wt` poids de
Hamming ; `R = F2[z]/(z^n − 1)` ; `S_w^n` ensemble des vecteurs de poids w.

---

## 1. Hypothèses

**Structure de l'anneau (invariant de parité).** Pour n premier impair,
`z^n − 1 = (z + 1)·Φ_n(z)` sur F2. Quand 2 engendre (Z/nZ)* (n premier
d'Artin), Φ_n est irréductible et `R ≅ F2 × F_{2^{n−1}}`. La projection sur
F2 est l'évaluation en 1 : `a(1) = wt(a) mod 2`. Elle est compatible avec
le produit, donc pour des secrets de poids fixé w :

    s(1) = x(1)·h(1) ⊕ y(1) = (w mod 2)·(h(1) ⊕ 1),
    u(1) = r1(1)·h(1) ⊕ r2(1) = (w mod 2)·(h(1) ⊕ 1).

La parité de s et de u est donc une fonction publique de h et de la
parité (publique) de w. Elle ne révèle rien sur x, y, r1, r2 au-delà de
w mod 2. Mais elle rend **fausses** les hypothèses qui comparent s ou u à
un élément uniforme de R : un distingueur qui teste la parité gagne avec
un avantage de 1/2. C'est le cas de HQC, dont les hypothèses décisionnelles
sont formulées « avec parité » (DQCSD-P). On fait de même. v n'est pas
concerné : il est tronqué à n₂ < n coordonnées (n − n₂ = 21 349 et 55 315), et la
somme des coordonnées retirées n'est pas connue.

*Historique.* La v0.3 initiale formulait H1 et H2 sans cette contrainte.
Le défaut a été relevé par l'audit externe (point 1). Il est vérifié par `tests/test_kem.py :: invariant_de_parite_*`.
Il ne change ni le schéma ni ses sorties : il change l'énoncé des
hypothèses et le jeu final de la preuve IND-CPA.

Notons `R_β = {a ∈ R : a(1) = β}`, l'ensemble des éléments de parité β, et
`β(h) = (w mod 2)·(h(1) ⊕ 1)`.

**(H1-P) QCSD décisionnel à 2 blocs, avec parité, sur clés acceptées.** Pour `h ← R`
uniforme et `(x, y)` tiré comme par `KeyGen` (uniforme sur `S_w^n × S_w^n`, conditionné par
l'acceptation de § 2.3), la paire `(h, x·h ⊕ y)` est indistinguable de `(h, s)` avec
`s ← R_{β(h)}` uniforme.

*Pourquoi les clés acceptées (correctif du 2026-11-02).* L'acceptation E dépend de (x, y), que
(h, s) détermine. Un énoncé sur des secrets uniformes ne s'étend pas aux secrets acceptés : on a
seulement `|Pr[D | E] − Pr_idéal[D]| ≤ (Adv + ε_rej)/(1 − ε_rej)`, et le terme additif ε_rej
(7,1 % et 5,9 %, mesurés sur 32 768 et 8 192 clés par `tests/c/kem_rejet.c`) n'est pas négligeable. La forme **calculatoire** (retrouver x, y) se transfère, elle :
la loi conditionnée a une densité au plus `1/(1 − ε_rej)` par rapport à la loi uniforme, donc
`Pr_E[A trouve (x, y)] ≤ Pr[A trouve (x, y)]/(1 − ε_rej)`. Les coûts d'ISD restent valables sur clés
acceptées, à log₂(1/(1 − ε_rej)) ≤ 0,11 bit près. L'énoncé décisionnel, lui, est posé sur la loi
réelle des clés : c'est celle que `tests/c/kem_distributions.c` éprouve (600 et 150 clés acceptées).

*Le rejet ne se voit pas dans la clé publique* (`tests/c/kem_rejet.c`, test de détection). Sur 32 768 clés à 128 bits (2 330 rejetées)
et 8 192 à 256 bits (487), tirées exactement comme par `KeyGen`, aucune des cinq statistiques non linéaires de s testées (poids,
transitions aux pas 1 et 2, triplets de uns, `wt(s ∧ z⁷s)`) ne sépare clés acceptées et rejetées : |z| ≤ 1,79 au seuil 4,5, pour un écart de
moyenne détectable de 0,10 et 0,21 écart-type d'une clé. La parité de s est la même pour toutes les clés (Lemme 0). Côté secret, la
borne sépare évidemment les deux classes (z = 151 et 77). Cela ne prouve pas H1-P sur clés acceptées, mais aucune trace du rejet n'apparaît.

**(H2-P) QCSD décisionnel à 3 blocs tronqué, avec parité.** Pour `h ← R`
uniforme, `s ← R_{β(h)}` uniforme, `r1, r2 ← S_w^n` et `e = e1 ⊕ π(e2)`
(`e1, e2 ← S_we^{n2}`, π permutation publique), le quadruplet
`(h, s, r1·h ⊕ r2, (r1·s)|_{n2} ⊕ e)` est indistinguable de `(h, s, u, v)`
avec `u ← R_{β(h)}` et `v ← F2^{n2}` uniformes.

**(H3) SD (décodage de syndrome) pour la SIG.** Pour `H = [H' | I]`, `H'`
uniforme de `r` lignes et `k` colonnes (dérivée d'une graine publique), et
`x ← S_w^n`, retrouver un `x'` de poids ≤ w tel que `H·x' = H·x` est difficile.
La forme systématique est sans perte (un code aléatoire s'y ramène par élimination), et
`log₂ C(n, w) < r` rend la solution unique en général : les poids < w n'ajoutent rien.

**Lemme 0 (spectre linéaire exact de H1-P et H2-P).** Soit `h̄(z) = h(z^{−1})`,
`κ^{(N)}_w(t) = K_w(t)/C(N, w)` le polynôme de Krawtchouk normalisé (`= E[(−1)^{⟨a, x⟩}]` pour
`x ← S_w^N` et `|a| = t`), et `b̃ ∈ R` le vecteur `b ∈ F2^{n2}` posé sur les n2 positions conservées.
Pour tout h, tout s, toute permutation π et tous `a ∈ R`, `b ∈ F2^{n2}` :

    x, y ← S_w^n :                 E[(−1)^{⟨a, x·h ⊕ y⟩}] = κ_w(|a|) · κ_w(|a·h̄|)
    r1, r2 ← S_w^n, e1, e2 ← S_we^{n2} :
        E[(−1)^{⟨a, r1·h ⊕ r2⟩ ⊕ ⟨b, (r1·s)|_{n2} ⊕ e1 ⊕ π(e2)⟩}] = κ_w(|a|) · κ_w(|a·h̄ ⊕ b̃·s̄|) · κ_we^{(n2)}(|b|)²

*Preuve.* `⟨a, r·h⟩ = Σ_k a_k Σ_i r_i h_{k−i} = ⟨a·h̄, r⟩`, et de même `⟨b, (r1·s)|_{n2}⟩ = ⟨b̃·s̄, r1⟩`,
`⟨b, π(e2)⟩ = ⟨π^{−1}(b), e2⟩` avec `|π^{−1}(b)| = |b|`. L'exposant est donc
`⟨a·h̄ ⊕ b̃·s̄, r1⟩ ⊕ ⟨a, r2⟩ ⊕ ⟨b, e1⟩ ⊕ ⟨π^{−1}(b), e2⟩`, somme de formes en des secrets
indépendants : l'espérance est le produit des quatre facteurs. (H1-P : de même avec x, y.) ∎

*Corollaire (seul invariant linéaire, à toutes les tailles).* Pour `0 < w < n`, `|κ_w(t)| = 1` si et
seulement si `t ∈ {0, n}`. (H1-P) : un test de biais ±1 exige `a, a·h̄ ∈ {0, 𝟙}`, donc `a ∈ {0, 𝟙}` :
c'est la parité de s, de signe `(−1)^{β(h)}`, que la loi idéale `R_{β(h)}` reproduit exactement. (H2-P),
pour `0 < we < n2 < n` et n premier d'Artin : il faut `a ∈ {0, 𝟙}`, `b ∈ {0, 𝟙}` et
`a·h̄ ⊕ b̃·s̄ ∈ {0, 𝟙}`. Pour `b = 𝟙`, cela impose `b̃·s̄ ∈ {0, 𝟙}`, soit `b̃·s̄ ≡ 0 mod Φ_n` (car
`𝟙 = Φ_n`). Comme `F2[z]/Φ_n` est un corps et que `b̃ ∉ {0, 𝟙}`, on a alors `s̄ ≡ 0`, c'est-à-dire
`s ∈ {0, 𝟙}`, ce qui arrive avec probabilité `2^{−(n−1)}` pour `s ← R_{β(h)}`. Hors de ce cas, seule la
parité de u est invariante. La mesure du rang sur instances réduites devient un théorème.

*Lecture.* Un distingueur linéaire de (H1-P) demande un a dont a et a·h̄ sont tous deux loin du poids
n/2 : c'est un mot de poids faible du code `{(a, a·h̄)}`, donc un problème de décodage. Pour (H2-P),
c'est un mot de poids faible de `{(a, b, a·h̄ ⊕ b̃·s̄)}`. En estimant le coût de ce mot par Prange
(p = 1) et l'avantage par le biais, rotations de a comprises (`tests/c/h1p_fourier.c`, **heuristique**),
log₂(coût/avantage) ≈ 139,1 (H1-P) et 138,8 (H2-P) pour Sillage-128, et 268,0 et 267,2 pour
Sillage-256 : du même ordre que l'ISD (138,2 et 265,1), et pas en dessous. Le lemme lui-même est
vérifié coefficient par coefficient, en entiers, sur des instances réduites exhaustives.

Le meilleur algorithme connu pour (H1-P), (H2-P) et (H3) est l'ISD. La
contrainte de parité ne fixe qu'un bit, public : elle ne change pas les
coûts d'ISD. Les coûts sont
estimés par `sillage_common.isd_estimate` (Prange, Stern, Dumer, BJMM
optimisés, voir § 5). Pour (H2-P), on prend aussi en compte l'attaque à 3 blocs de
densités inégales (`SillageKEM.security_estimate`) ; elle ne gagne rien sur
les 2 blocs. Les valeurs sont vérifiées par `tests/test_isd_parametres.py`.

---

## 2. Sillage-KEM

### 2.1 Le chiffrement sous-jacent PKE

`KeyGen` : `x, y ← S_w^n` (rejet si la borne de §2.3 dépasse `2^−λ`),
`pk = (σ_h, s = x·h ⊕ y)`. `Enc(pk, μ; ρ)` : `(r1, r2, e1, e2) = Exp(ρ)`,
`u = r1·h ⊕ r2`, `v = cw(μ) ⊕ (r1·s)|_{n2} ⊕ e1 ⊕ π(e2)`. `Dec` :
décodage à maximum de vraisemblance de `v ⊕ (u·x)|_{n2}`. Le code `cw` porte un octet de μ par
bloc de `L = 128·D` bits (§2.3).

**Théorème 1 (IND-CPA).** Sous (H1-P) et (H2-P), PKE est IND-CPA :
`Adv^{IND-CPA}_{PKE}(A) ≤ Adv^{H1-P}(B1) + Adv^{H2-P}(B2)`
(`Adv^{IND-CPA} = |Pr[b' = b] − 1/2|`, comme chez HHK17 ; celui d'un distingueur, `|Pr[1 | réel] − Pr[1 | idéal]|`).

*Preuve.* Jeu 0 : le jeu IND-CPA réel, clés acceptées. Jeu 1 : `s` est remplacé par un
élément uniforme de `R_{β(h)}`. B1 reçoit (h, s), tire b, simule le défi et renvoie [b' = b] ; la
différence est bornée par (H1-P), posée sur la loi des clés acceptées : aucun facteur de rejet
n'intervient. Jeu 2 : `(u, (r1·s)|_{n2} ⊕ e)` est remplacé par
`(u, v')` avec `u ← R_{β(h)}` et `v'` uniformes. La différence est bornée
par (H2-P), puisque `s` suit désormais exactement la loi de (H2-P). Dans
le Jeu 2, `u` ne dépend que de h, et `v = cw(μ_b) ⊕ v'` est uniforme et
indépendant de b : l'avantage est nul. ∎

*Correctif (2026-11-02).* La version précédente bornait le Jeu 1 par `Adv^{H1-P}/(1 − ε_rej)`, avec
H1-P sur des secrets uniformes. Ce facteur vaut pour un événement de recherche, pas pour un avantage de
distinction (voir « Pourquoi les clés acceptées », § 1) : la borne correcte aurait un terme additif
ε_rej non négligeable. H1-P est désormais posée sur la loi réelle des clés.

Comme `|M| = 2^k ≥ 2^λ`, on a aussi
`Adv^{OW-CPA} ≤ Adv^{IND-CPA} + 2^{−k}`.

### 2.2 Transformée FO à rejet implicite

Le KEM est exactement `U^⊥̸(T[PKE, G], H)` au sens de Hofheinz–Hövelmanns–
Kiltz (TCC 2017) :

- `T` : chiffrement dérandomisé, avec `ρ = G(μ, H(pk))` (`SILLAGE-KEM|coins`) ;
- `U^⊥̸` : `K = H(μ, ct)` (`SILLAGE-KEM|ss`). En cas d'échec de décodage
  **ou** d'écart à la ré-encapsulation, `K = H'(σ_rej, ct)`, où `σ_rej` est
  une graine secrète de 256 bits et `H'` est séparée par domaine ;
- les encodages non canoniques (`u ≥ 2^n`, `v ≥ 2^{n2}`) sont rejetés.

**Théorème 2 (IND-CCA, ROM).** Si PKE est δ-correct et IND-CPA, alors pour
tout adversaire IND-CCA `A` faisant `q_G`, `q_H` requêtes aux oracles et
`q_D` requêtes de décapsulation, il existe `B` de même temps tel que

```
Adv^{IND-CCA}_{KEM}(A) ≤ 2·q_G·δ + 3·Adv^{IND-CPA}_{PKE}(B)
                         + (2q_G + q_H + 1)/2^k + q_H/2^{256}
```

(HHK17, Th. 3.2 pour `T` et Th. 3.4 pour `U^⊥̸`, composés ; les constantes
exactes y sont détaillées). En QROM, le même schéma relève des théorèmes de
Bindel–Hamburg–Hövelmanns–Hülsing–Persichetti (TCC 2019) pour `FO^⊥̸`, avec
une perte quadratique.

*Points à vérifier pour appliquer le théorème, tous vérifiés :*
1. Chiffrement déterministe, aléa dérivé de μ : `SillageKEM._encrypt`.
2. Ré-encapsulation complète et comparaison de `(u, v)` dans `decaps` :
   `tests/test_kem.py :: fo_rejette_chiffres_non_honnetes`.
3. Rejet implicite déterministe, lié au chiffré et sans exception :
   `rejet_implicite_deterministe`, `entrees_malformees_sans_exception`.
4. δ-correction prouvée : §2.3.

La réduction IND-CCA ne change pas : elle ne fait appel qu'à la sécurité
IND-CPA de PKE.

Avec `k = λ` et `δ ≤ 2^{−λ}` (§2.3), le terme `2·q_G·δ` reste négligeable
tant que `q_G ≪ 2^{λ−1}`.

**Exigence d'implémentation.** La réduction suppose que l'adversaire
n'apprend rien d'autre que la sortie de Decaps. Une décapsulation qui
sauterait la ré-encapsulation après un échec de décodage révélerait cet
échec au temps de réponse : c'est l'oracle des attaques par réaction
(Guo–Johansson–Stankovski 2016). Les deux implémentations ré-encapsulent
donc toujours et choisissent le secret par masque (contrôle :
`tests/test_c_temps.py`).

### 2.3 δ-correction prouvée (borne de Chernoff certifiée par clé)

`δ = E_{(pk,sk)} [ max_μ Pr_ρ [ Dec(sk, Enc(pk, μ; ρ)) ≠ μ ] ]`.

**Le code.** Le bit q d'un bloc porte `b ⊕ ⟨u, P[q]⟩`, pour l'octet de μ `u | b << 7` (u sur 7
bits). `P` est public : Fisher–Yates sur `[0, 128·D)` (domaine `SILLAGE-KEM|rm`), réduit modulo
128 ; chaque valeur de `[0, 128)` a donc exactement D positions. C'est RM(1,7) répété D fois et
réparti pseudo-aléatoirement. Le décodage calcule la transformée de Walsh des 128 sommes et
retient le plus grand module (à égalité, le plus petit u).

*Pourquoi `P`.* Sans lui, les supports S ci-dessous sont des fenêtres denses ou périodiques, et
la borne certifiée perd jusqu'à 30 bits (mesuré). La sécurité de (H2-P) n'en dépend pas : `cw`
est public, et la preuve IND-CPA le masque par `v'` uniforme.

**Lemme 3.** Soit `S_{u,b} = {q : ⟨u, P[q]⟩ = b}`, `u ≠ 0`, `|S| = 64·D` (254 ensembles).
Le décodage d'un bloc n'échoue que si le bruit y a au moins `32·D` bits sur l'un des `S_{u,b}`. Et
pour tout `S`, ce nombre de bits est au plus `T1 + T2 + Te`, avec `T1 = Σ_{a∈r1} |(S − a) ∩ y|`,
`T2 = Σ_{a∈r2} |(S − a) ∩ x|`, et `Te` le nombre de bits de `e1` et de `π(e2)` qui tombent dans S.

*Preuve.* Le bruit vaut `N = v ⊕ (u·x)|_{n2} ⊕ cw(μ) = (r1·y ⊕ r2·x)|_{n2} ⊕ e1 ⊕ π(e2)`, car les termes
`r1·x·h` s'annulent ; il ne dépend pas de μ. Si un autre mot c' est aussi proche que le bon mot c,
`|S| − 2·wt(N ∩ S) ≤ 0` pour `S = supp(c ⊕ c')`. Si c et c' diffèrent par u, S est un `S_{u,b}`. Sinon
S est le bloc entier, de bruit ≥ L/2, et l'une des deux moitiés `S_{u,0}`, `S_{u,1}` a au moins `|S_{u,b}|/2`
bits, pour tout u. Enfin, le bit j de `r1·y` est la parité du nombre de paires
`(a, b) ∈ r1 × y` avec `a + b ≡ j` : le nombre de bits à 1 dans S est au plus le nombre de paires qui y
tombent, c'est-à-dire `T1` ; de même pour `r2·x`, `e1`, `π(e2)`. ∎

**Théorème 4.** Soit `c_{y,S}(s) = |(S + s) ∩ y|`, `M_{y,S}(θ) = (1/n)·Σ_s e^{θ·c_{y,S}(s)}` (de
même pour x), et `p_e = |S|/n2`. Pour tout `θ > 0`,

```
Pr[échec] ≤ (k/8) · 254 · max_S exp( −θ·32·D + w·ln M_{y,S}(θ) + w·ln M_{x,S}(θ)
                                     + 2·we·ln(1 + p_e(e^θ − 1)) ).
```

*Preuve.* `r1` est un ensemble de w positions distinctes, uniformes sur `Z_n` : les coins viennent
de l'oracle G. Quand a parcourt `Z_n`, `S − a` parcourt tous les translatés de S : `|(S − a) ∩ y|`
suit la loi de `c_{y,S}`. `T1` est donc une somme de w tirages **sans remise** dans le multiensemble
`{c_{y,S}(s)}`. Par le théorème 4 de Hoeffding (1963), `E[e^{θ T1}] ≤ M_{y,S}(θ)^w`. Il en va de même pour
`T2`, et pour `Te` avec 2·we indicatrices de probabilité `p_e` (π est une bijection des positions).
`T1`, `T2`, `e1`, `e2` sont indépendants. On applique Markov à `e^{θ(T1+T2+Te)}`. Un bloc j décale S de
`j·L`, ce qui ne change pas le multiensemble (a parcourt tout `Z_n`), d'où l'union sur les 254 ensembles
et les k/8 blocs. La borne vaut pour tout μ. ∎

*Mise en œuvre.* `borne_echec_log2` et `sl_kem_borne` évaluent la borne à θ public fixé (`theta = 0,7`),
pour les 254 ensembles, en remplaçant `e^{θc}` par `⌈2^{12}·e^{θc}⌉/2^{12}`, qui la majore, et en rejetant
toute clé ayant un `c > 15`. Le C calcule les `c` par transformée de Walsh sur des registres, sans
branchement ni accès mémoire dépendant de la clé (Valgrind) ; seul le pire produit `M_x·M_y` est rendu
public. `keygen` rejette toute clé dont la borne dépasse `2^{−λ}`. On a donc **δ ≤ 2^{−λ} prouvé** pour la
distribution des clés produite. Médianes mesurées sur clés brutes (`resultats/kem.json`) : `2^{−146}` et `2^{−289}` ; rejets 7,1 % et 5,9 % (`tests/c/kem_rejet.c`).

*Correctif v0.3.* La v0.2 justifiait la correction par un z-score gaussien
(bits supposés indépendants). La borne prouvée ci-dessus montre que les
anciens paramètres ne garantissaient qu'environ `2^{−60}` à `2^{−75}`. Le
redimensionnement (§5) rétablit `δ ≤ 2^{−λ}`.

*Changement v0.4 : le code à répétition `[k·d, k, d]` (`d = 531` et `953`) devient ce code.* Le Lemme 3 et
le Théorème 4 gardent leur forme (un groupe G devient un support S, et 2 hyperplans de plus par bloc ne
coûtent que quelques bits d'union) : δ reste prouvé, sans hypothèse d'indépendance. Le gain vient de ce
qu'un bloc de L bits décode 8 bits, avec la solidité d'une répétition de L/2 bits pour un seul.

*Ce que la preuve interdit.* `T1 + T2 + Te` ignore les annulations du XOR : il exige une densité de paires
`2w²/n < 1/2`, d'où `n ≈ 50 000` à w = 75. HQC-128 (4,4 Ko, `n = 17 669`) travaille à une densité de 0,62 avec
un code externe de Reed–Solomon, et son taux d'échec repose sur une hypothèse d'indépendance des positions,
celle qu'on a retirée de la v0.2. Une borne par martingale tenant compte des annulations
(`W = Σ_S (−1)^{N_i}`, contraction exacte, inégalité de Bennett) a été évaluée : elle ne gagne que pour de
petits S et n'améliore pas ces paramètres. Un code externe demanderait une borne jointe sur plusieurs blocs,
que le calcul clé par clé ne fournit pas. Voir `docs/PISTES.md`, piste 8.

---

## 3. Sillage-SIG

MPC-in-the-Head à la SDitH (Feneuil–Joux–Rivain, CRYPTO 2022), partage en hypercube
(Aguilar-Melchor et al., EUROCRYPT 2023), sur le décodage de syndrome **binaire** (H3). Cette section
remplace le protocole de Stern (v0.3, 134 et 536 Ko), retiré en v0.4 : le problème dur est le même, et
aucune hypothèse nouvelle n'est introduite (ni rang, ni erreurs restreintes, ni corps plus grand).

### 3.1 Témoin

`n = 2^e`, `F_poly = GF(2^e)`, `f_i` l'élément d'écriture binaire i, `F(X) = X^n + X = Π_i (X + f_i)`. Donc
`F'(f_i) = 1`. Pour `x ∈ F2^n`, S est le polynôme de degré < n avec `S(f_i) = x_i`.

**Lemme A.** Si `H·x = y` et `wt(x) ≤ w`, il existe Q unitaire de degré w et P de degré < w tels que
`S·Q = P·F`. Réciproquement, si `x_B = y + H'·x_A` et si `S·Q = P·F` avec Q unitaire de degré w, alors
`H·x = y` et `wt(x) ≤ w`.

*Preuve.* Sens direct : `Q = Π_{x_i=1}(X + f_i)` (complété pour atteindre le degré w) annule `S·Q` sur tout
`F_poly`, donc F divise `S·Q`, de degré < n + w. Réciproque : `S(f_i)Q(f_i) = P(f_i)F(f_i) = 0`, donc `x_i = 1`
implique `Q(f_i) = 0`, et Q a au plus w racines. ∎

Mise en œuvre : `P = Σ_{x_i=1} Q/(X + f_i)` (car `F'(f_i) = 1`). Clé secrète `sk = x_A ‖ Q ‖ P`, sans le coefficient
unitaire : `(xb + 2·qb)` octets. Contrôle : `tests/test_sig.py :: temoin_*_bien_forme`.

### 3.2 Une répétition

`K = GF(2^{ep}) ⊃ F_poly`, plongement φ fixé par une racine du polynôme de `F_poly`. `N = 2^D` feuilles, arbre
GGM de graines de `sb` octets : `(fils) = H_a(sel, rep, j, nœud)`.

1. *Parts.* Part de la feuille i : `H_f(sel, rep, i, s_i) = (x_A, Q, P, a, b, c)_i`, avec `a, b, c ∈ K^t`.
   `aux = (x_A, Q, P, a·b + c) + Σ_i (x_A, Q, P, c)_i`, ajouté à la feuille N − 1. Engagements
   `com_i = H_c(sel, rep, i, s_i)`, et `H_c(sel, rep, N−1, s_{N−1}, aux)` pour la dernière. Les parts somment au témoin
   et à un triplet `c = a·b`.
2. *Défi 1.* `(r_j, ε_j) ∈ K²`, `j < t`.
3. *Hypercube.* Pour `d < D`, côté 1 : somme des parts de bit d à 1 ; côté 0 : le reste, qui porte les constantes
   (`y`, le coefficient unitaire `r^w`, et `α·β`). Chaque côté calcule, linéairement dans sa part :
   `x_B = H'·x_A`, `S(r) = Σ_i x_i·L_i(r)` (`L_i(r) = F(r)/(r + f_i)`, et le vecteur unité si `r ∈ F_poly`), `Q(r)`, `P(r)`,
   ```
   α_s = ε·Q_s(r) + a_s,   β_s = S_s(r) + b_s,   v_s = c_s + α·b_s + β·a_s + ε·F(r)·P_s(r) (+ α·β au côté 0).
   ```
   Diffusion : `(α, β)` ouverts et `(α_1, β_1, v_1)^{(d)}` pour chaque d.
4. *Défi 2.* `i* ∈ [0, N)`.
5. *Réponse.* Les D graines sœurs du chemin de `i*`, `com_{i*}`, `aux`, `α`, `β`, avec `aux = 0` si `i* = N − 1` : la seule part
   qu'il corrige est alors cachée, et le vérifieur ne s'en sert pas. Il refuse toute autre valeur (encodage unique, Proposition 9).
   Le vérifieur recalcule toutes les parts sauf `i*`. Pour chaque d, il simule le côté qui ne contient pas `i*`, déduit l'autre (`α_{1−s} = α + α_s`,
   `v_{1−s} = v_s`, car `v_0 + v_1 = 0`), recalcule les engagements et les diffusions, et compare les hachés.

**Proposition 5 (complétude).** `(εQ + a)(S + b) = εQS + εQb + aS + ab`, d'où en caractéristique 2,
`v_0 + v_1 = c + αb + βa + εF·P + αβ = ε(S·Q + P·F) + (a·b + c) = 0` pour un témoin. Vérifié par `verification`.

**Lemme 6 (faux positif).** Soient des parts fixées, de somme `(x̃_A, Q̃, P̃, a, b, c)`, sans témoin (Lemme A :
`T = S̃Q̃ + P̃F ≠ 0`, de degré < n + w). Alors, sur `(r, ε)` uniformes,
`Pr[∀j : ε_j T(r_j) + a_j b_j + c_j = 0] ≤ p = ((n + w)/2^{ep})^t`.

*Preuve.* Pour un j : `Pr[T(r_j) = 0] ≤ (n + w − 1)/2^{ep}` (Schwartz–Zippel), et sinon ε_j est déterminé,
probabilité `2^{−ep}`. Les points sont indépendants. ∎

**Proposition 6 (solidité d'une répétition, hypercube).** Fixons les engagements, `aux` et la diffusion. S'il n'y a pas
de faux positif, au plus une valeur de `i*` passe la vérification, sauf collision de `H_c`.

*Preuve.* Si un engagement n'a pas de préimage connue, seule cette feuille peut être cachée. Sinon les parts sont
définies. Pour chaque d, soit `Faux_d ⊂ {0, 1}` les côtés dont la diffusion engagée diffère du calcul honnête. Si
`Faux_d = ∅`, alors α et β ouverts sont les vrais (somme des deux côtés), et `v_0 = v_1` donne
`ε·T(r) + ab + c = 0` en tout point, un faux positif. Donc `Faux_d ≠ ∅` pour tout d. Le vérifieur ne simule que le
côté sans `i*` : il faut que ce côté soit honnête, donc que `i*` soit du côté faux pour **chaque** d. Cela fixe tous
les bits de `i*`. ∎

L'attaque correspondante est exécutée sur un modèle réduit (N = 8, sans témoin) : acceptée si et seulement si le défi
tombe sur la feuille visée (`tricheur_accepte_ssi_defi_sur_la_cible`). Les faux témoins sont rejetés
(`faux_temoins_rejetes` : `x_A`, Q ou P altérés, préimage dense).

**Proposition 7 (HVZK, ROM).** Pour `(r, ε, i*)` donnés, le simulateur suivant, qui ignore x, produit une transcription
de même loi que la réelle, tant que l'adversaire n'interroge pas le point caché `(sel, rep, nœud)` d'un ancêtre de `i*` ni
sa graine : tirer les graines sœurs, `com_{i*}`, `aux`, `α`, `β` uniformes, puis calculer ce que calcule le vérifieur.

*Lois.* Dans l'exécution réelle, tant que `s_{i*}` n'est pas interrogée, la part cachée est uniforme et indépendante du
reste. `aux` est masqué par ses champs `(x_A, Q, P, c)`, α et β par ses champs `a` et `b`, disjoints : ils sont uniformes
et indépendants. Les graines sœurs sont des sorties de `H_a` sur des ancêtres cachés, donc uniformes. Les valeurs
déduites coïncident, puisque `v_0 + v_1 = 0` chez l'honnête. Si `i* = N − 1`, `aux` n'est pas transmis : le simulateur met 0. Une requête ne vise qu'un `(sel, rep, nœud)`, d'où au plus `q/2^{8·sb}` sur toute l'exécution,
sans gain multi-cible. ∎

Contrairement à Stern, aucun point caché n'est relié à la solution de (H3) : les engagements portent sur des graines
d'entropie pleine. `attaque_graine_reduite_retrouve_la_cle` exécute l'attaque en graines de 16 bits : énumérer la graine
cachée redonne `x_A`, Q et P, puis une falsification. `|graine|` borne donc le niveau, comme `|σ_π|` pour Stern.

### 3.3 Fiat–Shamir en 5 passes

Signature : `sel ‖ h1 ‖ h2 ‖ (chemin ‖ com_{i*} ‖ aux ‖ α ‖ β)_{rep < τ}`, avec
`h1 = H_1(sel, H_pk(pk), H_m(m), (H_com(sel, rep, com_0…com_{N−1}))_rep)`, `(r, ε) = G_1(h1)`,
`h2 = H_2(sel, H_pk(pk), H_m(m), h1, diffusions)`, `i* = G_2(h2)` (D bits uniformes par répétition). Longueur fixe. Hachés
de `ℓ = 2λ` bits ; graines de `λ + 8` bits (§ 5 bis).

La graine maîtresse est `H_mseed(sk, sel, H_m(m))`, sel aléatoire. Un aléa défaillant ne répète donc jamais les graines
d'un message à l'autre : deux défis sur les mêmes graines livreraient le témoin (`meme_sel_autre_message_aucune_graine_commune`).

**Théorème 8 (EUF-CMA, ROM).** Soit F un falsificateur faisant `q_1`, `q_2`, `q_G`, `q_c`, `q_P`, `q_m` requêtes à `H_1`, `H_2`,
`G_1, G_2`, `H_c`, aux dérivations de graines et de parts (`H_a, H_f`), à `H_m`, et `q_S` requêtes de signature. Pour tout
entier `1 ≤ τ1 ≤ τ + 1`, il existe un solveur B de (H3) tel que

```
Adv^{EUF-CMA}(F) ≤ (q_1 + 1)·P[Bin(τ, p) ≥ τ1]                faux positifs
                   + (q_2 + 1)·N^{−(τ−τ1+1)}                  parties cachées
                   + (q_1 + q_2)·q_G/2^ℓ                      défi déjà interrogé
                   + (q_c + q_1 + q_2 + N·τ·(q_S + 1))²/2^ℓ   collisions, préimages tardives
                   + q_m²/2^{ℓ+1}                             collisions de H_m
                   + q_P/2^{8·sb}                             graines cachées
                   + q_S²/2^{257} + q_S·q_G/2^ℓ + q_S(q_S + q_1 + q_2)/2^{256+ℓ}   programmation
                   + 2·Adv^{H3}(B)
```

avec un temps de B égal à celui de F, augmenté de N évaluations de parts et d'une vérification du Lemme A par requête à
`H_1`. **La réduction ne perd aucun facteur en q** : elle n'utilise pas le lemme de bifurcation.

*Preuve.* **Jeu 0** : le jeu réel. B reçoit `(H', y)` et programme les colonnes de H' sous `seed_H` (fraîche).

**Jeu 1** : les signatures sont simulées sans x. Pour chaque répétition, on tire `(r, ε, i*)`, on applique la
Proposition 7, on tire h1, h2 uniformes et l'on programme `G_1, G_2`, `H_1`, `H_2` en conséquence. Les jeux coïncident
sauf si :
1. un point caché est interrogé : `q_P/2^{8·sb}`, avec `q_S²/2^{257}` pour une répétition de sel. Interroger la graine
   maîtresse suppose de poser sk à `H_mseed`, ce qui donne une solution de (H3) reconnaissable par B : d'où un
   premier `Adv^{H3}(B)` (Pr se mesure dans le Jeu 1, où x n'intervient pas) ;
2. un point programmé était déjà défini : `q_S·q_G/2^ℓ` pour `G_1, G_2`, et, l'entrée de `H_1` contenant le sel et
   `q_S(q_S + q_1 + q_2)/2^{256+ℓ}` pour `H_1, H_2`.

**Analyse d'une falsification dans le Jeu 1.** Soit `(m*, sel*, h1*, h2*, …)` une falsification valide. Si `m*` a la même
image par `H_m` qu'un message signé, c'est une collision (`q_m²/2^{ℓ+1}`). Sinon, les entrées de `H_1` et `H_2` n'ont pas
été programmées, et F les a interrogées (au prix d'un terme +1 chacune), `H_1` avant `H_2`, sauf préimage tardive.

Au moment où F interroge `H_1` sur l'entrée de `h1*`, B lit dans la table les préimages des hachés et des engagements. Une
préimage absente à cet instant ne peut apparaître ensuite qu'en atteignant une valeur fixée, ou par collision :
`(q_c + …)²/2^ℓ`. Pour les répétitions dont tous les engagements ont une préimage, B évalue les parts (les `H_f` sont
ainsi fixés avant `G_1(h1*)`), et teste le Lemme A : un témoin est le second `Adv^{H3}(B)`.

Sinon, chaque répétition est sans témoin, et `G_1(h1*)` est uniforme et indépendant des parts (sauf `q_1·q_G/2^ℓ`). Par le
Lemme 6, le nombre de répétitions à faux positif est dominé par `Bin(τ, p)`, et il atteint τ1 avec probabilité au plus
`P[Bin(τ, p) ≥ τ1]` par requête à `H_1`. Sinon, au moins `τ − τ1 + 1` répétitions sont sans faux positif. Pour une requête
à `H_2` (diffusion fixée), la Proposition 6 ne laisse à chacune qu'un seul `i*`, et `G_2(h2)` est uniforme (sauf
`q_2·q_G/2^ℓ`) : probabilité au plus `N^{−(τ−τ1+1)}`. ∎

C'est la borne de l'attaque de Kales–Zaverucha (2020) : grinder `h1` jusqu'à τ1 faux positifs, puis `h2` pour le reste.
Le paramétrage se fait sur les deux termes, pas sur `N^τ` seul.

*Exécution sur modèle réduit* (`tests/test_sig_modele.py`, n = 16, w = 2, GF(16) ⊂ GF(256), N = 4, τ = 3, pk sans témoin de
poids ≤ w, vérifiée par énumération). L'attaque, exécutée, produit des falsifications acceptées par le vrai vérifieur :

| Budget (q_1, q_2), seuil de faux positifs | Fréquence (300 essais) | Borne du Théorème 8 |
|---|---|---|
| (10, 4), seuil 1 | 0,223 | 0,468 |
| (1, 16), sans faux positif | 0,26 | 0,659 |
| (40, 1), seuil 3 | 0,003 | 0,514 |

La borne majore chaque attaque et se trouve atteinte à un facteur ≈ 2 près. Sur les mêmes instances, le Lemme A est vérifié
exhaustivement sur GF(8) (w = 1, 2, 3 : pour tout x et tout Q, `F | S·Q` si et seulement si le poids est permis), l'identité
`v_0 + v_1 = ε·T(r) + a·b + c` sur le vrai calcul des côtés, et le comptage exact du Lemme 6 sur K² : le pire tricheur atteint
0,996 fois la borne. Le vrai vérifieur, défi forcé, n'accepte que la feuille prédite par la Proposition 6, et toutes les feuilles
en cas de faux positif. Les polynômes de `F_poly` et de `K` sont irréductibles (Rabin), et φ est un morphisme, ce que le Lemme 6
suppose.

**Proposition 9 (encodage unique, SUF-CMA).** Avec `aux = 0` exigé si `i* = N − 1`, pour tout F comme au Théorème 8,

```
Adv^{SUF-CMA}(F) ≤ Adv^{EUF-CMA}(F) [borne du Théorème 8] + (q_2 + 1)·N^{−τ} + q_P²/2^{16·sb+1}
```

*Preuve.* Soit `(m*, σ*)` valide, où m* a été signé (sinon Théorème 8) et σ* n'est pas l'une de ses réponses. On exclut les
collisions de hachés, déjà comptées, et de `H_a` (dernier terme). Soit `σ_i = (sel, h1, h2, …)` une réponse pour m*.
Si `(sel*, h1*)` n'est celui d'aucune réponse, l'entrée de `H_1` n'est pas programmée, et l'analyse du Théorème 8 s'applique
telle quelle (une répétition reprenant des engagements simulés a une feuille sans préimage : au plus un `i*`, Proposition 6).
Sinon `h1* = h1` : engagements et hachés sont ceux de `σ_i` (sinon collision), donc chaque répétition a sa feuille cachée, sans
préimage connue (sinon `q_P/2^{8·sb}`), et seul le même `i*` peut passer. Si `h2* ≠ h2`, l'entrée de `H_2` est nouvelle, et
`G_2(h2*)` redonne ces `i*` avec probabilité `N^{−τ}`. Si `h2* = h2`, alors `i*`, la diffusion, α et β (hachés tels quels, encodage
canonique) sont les mêmes ; `com_{i*}` aussi. Un autre chemin de graines donnerait d'autres feuilles, donc une collision de `H_c`
ou de `H_a`. `aux` est lié par `com_{N−1}` si `i* ≠ N − 1`, et fixé à 0 sinon. Donc `σ* = σ_i`. ∎

`N^{−τ}` vaut `2^{−132}` et `2^{−276}`, `q_P²/2^{16·sb}` est négligeable devant `q_P/2^{8·sb}` : le niveau ne change pas.

*Correctif v0.4.* La première rédaction transmettait `aux` tel quel, y compris pour `i* = N − 1`, sans que rien ne le lie : toute
signature dont une répétition cachait la dernière feuille (environ 1 sur 370) restait valide une fois `aux` modifié, soit une
malléabilité. Ni EUF-CMA ni le secret n'étaient touchés. Trouvé en relisant la preuve contre le code, démontré, corrigé.
Contrôles : `encodage_unique_modele` (chaque bit de chaque signature, pour chaque feuille cachée), `c_aux_verrouille`.

**Proposition 10 (liaison à la clé et au message).** Une signature valide pour `(pk, m)` ne l'est pour un autre `(pk', m')`, même
avec `pk'` choisie par l'attaquant, qu'au prix d'une collision de `H_pk`, `H_m` ou `H_1` : `σ` contient `sel` et `h1`, et `h1` haché sur
`(sel, H_pk(pk), H_m(m), …)` est recalculé à la vérification. Coût `2^{ℓ/2} = 2^λ`. C'est la propriété d'exclusivité (CEO, DEO) de Cremers
et al. (2021). La non-resignabilité n'est pas revendiquée : la signature ne dépend de m que par `H_m(m)`.

**Corollaire 8-mu (μ clés).** Soit F visant l'une de μ clés indépendantes, chacune avec sa graine `seed_H`, `q_S` comptant toutes les
signatures. La borne du Théorème 8 vaut avec `2·Adv^{H3-μ}` pour son dernier terme, `Adv^{H3-μ} ≤ μ·Adv^{H3}`, et `μ²/2^{ℓ+1}` en plus
(collision de `H_pk`).

*Preuve.* `h1` et `h2` portent `H_pk(pk)`, `G_1, G_2` en dépendent par eux : une requête ne vise qu'une clé, hors collision. Les points
cachés portent `sel`, tiré au hasard pour chaque signature, et une requête n'en vise qu'un. Les termes en q ne prennent donc aucun facteur μ. La
réduction reçoit μ instances de (H3) et applique le Théorème 8 à la clé visée. ∎

Le facteur μ de la réduction ne correspond à aucune attaque connue : chaque clé a son `H'`, sans précalcul commun, et une ISD ne
vise qu'une matrice à la fois. Partager un budget T entre μ clés donne le même avantage total `T/2^{coût}`.

**Niveau de sécurité (budget de requêtes explicite).** Même notion coût/avantage qu'au § 4.3 : λ bits si
`Adv ≤ 2q/2^λ + 2·Adv^{H3}` pour tout `q ≤ 2^{λ−2}` (q borne chaque compteur), et si (H3) résiste à 2^λ opérations. Avec
`p = ((n + w)/2^{ep})^t` et `q_S ≤ 2^{64}` :

| Terme | SIG-128 (N = 2¹², τ = 11, p = 2^{−131,7}, τ1 = 1) | SIG-256 (N = 2¹², τ = 23, p = 2^{−143,7}, τ1 = 2) |
|---|---|---|
| `(q_1 + 1)·P[Bin(τ, p) ≥ τ1]` | ≤ q·2^{−128,3} | ≤ q·2^{−279,5} |
| `(q_2 + 1)·N^{−(τ−τ1+1)}` | ≤ q·2^{−132} | ≤ q·2^{−264} |
| `q·q_G/2^ℓ`, collisions, `q_m²/2^{ℓ+1}` | ≤ q·2^{−128} | ≤ q·2^{−256} |
| `q_P/2^{8·sb}` | q·2^{−136} | q·2^{−264} |
| `q_S·q_G/2^ℓ` | ≤ q·2^{−192} | ≤ q·2^{−448} |
| ISD sur (H3), § 5 | 160,3 b | 316,2 b |

Contrôle : `tests/test_sig.py :: *_theoreme_8_atteint_lambda`, `*_tau_minimal`.

Le facteur `(q + 1)` n'est pas un artefact de preuve, et la notion reste celle de la v0.3 : falsifier coûte environ `2^λ`
requêtes. Un avantage d'au plus `2^{−λ}` après `2^{64}` requêtes (lecture de l'audit externe, point 4) demanderait
τ = 16, t = 6 et τ = 28, t = 5 ; ce n'est pas la notion retenue, AES-128 ne la satisfaisant pas non plus.

*Historique.* La v0.3 utilisait Stern à défis ternaires (`t = 219` et `438`). Ses corrections (σ_π et hachés de 2λ bits, Proposition 7
sans « engagements cachants par entropie », extraction sans bifurcation) sont reprises ici : `|graine|` et `ℓ` suivent les mêmes
règles, l'extraction lit la table de l'oracle.

---

## 4. BRUME-512

**Théorème 9 (wide-trail par paires).** Si
`B = min_{x≠0} wt(x) + wt(Mx) ≥ 8` (poids en nibbles), toute
caractéristique sur 2r tours active au moins 8r S-box.

*Preuve.* Sur deux tours consécutifs, `wt(Δ_0) + wt(Δ_1) = wt(Δ'_0) + wt(M·Δ'_0) ≥ B`,
car les S-box sont bijectives. On somme sur les r blocs. ∎

**Proposition 10 (B = 8 exactement).** Si `wt(x) + wt(Mx) < 8`, alors
`wt(x) ≤ 3` ou `wt(Mx) ≤ 3`. L'énumération exhaustive des vecteurs de poids
≤ 3 pour M et pour `M^{−1}` (réduite par un scalaire de GF(16)) donne des
minima de 8, 13, 17 et ≥ 99 ; B = 8 est atteint au poids 1. En linéaire,
`L_c^T = G·L_c·G^{−1}` (G : matrice de Gram de la trace), d'où
`M^T_bin = (G⊗I)·M^T·(G^{−1}⊗I)`, qui a les mêmes motifs d'activité. On
certifie de même `M^T` et `(M^T)^{−1}`. Vérification :
`tests/test_branch_exact.py`.

**Corollaire 11.** À 32 tours, toute caractéristique active au moins 128
S-box (certifié, Théorème 9 et Proposition 10). **Dans le modèle de
Markov** (tours indépendants, comme si chaque tour avait une sous-clé
uniforme), sa probabilité est le produit des probabilités locales, donc
≤ `(2^{−2})^{128} = 2^{−256}` (U = 4), et tout trail linéaire a une
corrélation ≤ `(2^{−1})^{128} = 2^{−128}` (max|LAT| = 4).

*Portée.* BRUME-512 est une permutation sans clé, dont les constantes de
tour sont fixes : le modèle de Markov y est une hypothèse, pas un fait.
Ces bornes portent sur une caractéristique, pas sur une différentielle
agrégée (Proposition 12). Ni l'une ni l'autre ne démontre à elle seule la
résistance de la permutation concrète à toutes les attaques
différentielles, linéaires et structurelles, qui reste l'hypothèse de
permutation idéale des preuves de modes.

**Proposition 10 bis (support de la diffusion, certifiée).** Les six
générateurs du graphe de Cayley de D₁₂₈ sont des réflexions, avec
s_a·s_b = r^{a−b}. Le support combinatoire de M^r (diagonale comprise),
vu depuis un nibble, vaut 7, 37, 94 et 127 pour r = 1 à 4, et 128 à
partir de r = 5. 37 et 94 sont exactement les bornes du groupe :
6 réflexions, puis 31 rotations en au plus 2 produits, puis 63
réflexions en au plus 3 produits. Le support de M⁻¹ est dense dès r = 1
(111 à 125 nibbles) et complet dès r = 2. La dépendance réelle par la
permutation (S-box comprises) coïncide avec le support combinatoire :
diffusion complète en 5 tours en direct et 2 en inverse. Le support des
puissances linéaires M^r sur GF(16) n'est jamais complet : environ un
coefficient sur 16 est nul, comme pour toute matrice dense. Mais ces
annulations ne se composent pas à travers les S-box.

*Spectre.* Un graphe engendré par des réflexions est biparti (rotations ↔
réflexions). Son spectre contient donc les valeurs triviales +6 et −6, et
λ* = 3,5076 désigne le plus grand |λ| parmi les 126 autres, sous
2√5 ≈ 4,472. Vérification : `tests/c/diffusion_support.c`.

*Correctif.* Une version de l'artifact annonçait « 7, 49 puis 128 en 3
tours », en supposant une croissance en 7^r. L'audit externe l'a relevé
(seconde passe, point 1). La batterie mesurait déjà 5 tours.

**Proposition 12 (agrégation de trails à 2 tours, Park et al. 2003).** En
modèle de Markov,
`MEDP_2 ≤ max_u Σ_v DP(u,v)^8` et `MELP_2 ≤ max_u Σ_v LP(u,v)^8`. Les
valeurs sont calculées par `tests/test_hull.py`. Pour R ≥ 2 tours,
`MEDP_R ≤ MEDP_2`, car `Σ_c DP_B(c, b) = 1` pour toute bijection B. Au-delà
de ces bornes, l'agrégation se mesure expérimentalement : facteur d'effet
de groupe à 2 tours dans `test_hull` et `test_diff_lin_empirique`. On
dispose en outre d'une marge de plus de 2 500 bits entre les meilleurs
trails trouvés à 14 tours et les seuils prouvés à 32 tours.

**Proposition 12 bis (portée de la division property).** Soit `x^u → y_j`
avec `wt(u) = 511`. (i) *Borne basse.* Tant que la borne de Boura–Canteaut
sur le degré reste < 511 (10 tours dans chaque sens, S-box de degré 3,
m = 4), tous les bits sont équilibrés sur le cube : distingueur à 10 tours
dans chaque sens, donc zero-sum inside-out sur 20 tours. (ii) *Borne
haute.* Si chaque bit de sortie j admet au tour R une piste monomiale
`u → … → e_j` (une suite de transitions dont chacune a un coefficient non
nul dans la table exacte de la S-box avec sa constante, ou dans la matrice
binaire de M), la propriété de division ne prédit plus aucun bit
équilibré. Si la piste vers le bit i est prolongeable d'un tour vers un
ensemble de bits J(i), alors la couverture au tour R+1 contient ∪ J(i), et
une couverture complète se maintient à tout tour suivant (récurrence). On
construit et revérifie ces pistes avec `tests/pistes_monomiales.py`.
**Pour le cube dont le bit 0 est inactif**, on obtient une couverture
complète au tour 15 en direct et au tour 12 en inverse : pour ce cube,
aucun distingueur DP au-delà de 14 tours en direct et de 11 en inverse.
Vérification : `tests/test_division_property.py` (cache des pistes :
`resultats/pistes_division.json`).

*Extension à tous les cubes.* Un attaquant choisit le bit inactif parmi
512, et les coefficients et les constantes de tour cassent toute symétrie
entre les cubes : on ne peut pas transporter les pistes par un
automorphisme. On les transporte par recollement.

**Lemme 12 ter (recollement).** Soit τ une piste vérifiée du cube 0 au
tour R, et X son état après la première couche linéaire L₁. Pour un cube
a, s'il existe un début de piste du cube a qui aboutit exactement à X
après L₁, alors la concaténation de ce début et du suffixe de τ est une
piste vérifiée du cube a vers le même bit, au même tour.

*Preuve.* Les règles de transition sont locales : chacune ne dépend que
de deux états consécutifs, de la position et de la constante du tour. Le
suffixe de τ, à partir de X, est inchangé. ∎

*Construction du début.* La couche linéaire déplace librement les bits
inactifs :
- *Inverse (L puis S).* X = tout ∖ {k}. Il faut une affectation de
  tout ∖ {a} vers X : chaque sortie de X reçoit une arête de L, chaque
  entrée en émet au moins une. Comme |X| = 511, c'est un couplage parfait
  du graphe biparti de L.
- *Direct (S puis L).* On choisit, dans la table exacte de la S-box (avec
  la constante du tour 0), une sortie v pour le nibble du bit a. On
  cherche ensuite une affectation surjective de X sur l'état U₁ obtenu :
  un couplage de Hopcroft–Karp qui sature U₁, puis chaque sortie restante
  de X est rattachée à un voisin actif.

**Corollaire 12 quater (borne haute, tous les cubes).** Pour chacun des
512 cubes de dimension 511, chaque bit de sortie admet une piste vérifiée
au tour 15 en direct et au tour 12 en inverse. Aucun distingueur DP
n'existe donc, quel que soit le cube, au-delà de 14 tours en direct et de
11 en inverse, soit 25 tours inside-out. Cela vaut aussi pour les cubes de
dimension < 511 : un tel cube J est inclus dans un cube I de dimension
511, et un monôme divisible par x^I l'est par x^J.

*Vérification* (`tests/test_dp_tous_cubes.py`). Les 27 pistes du cache
sont recollées pour chacun des 512 cubes, soit 13 824 recollements, et
chaque piste obtenue est revérifiée par `verifier(…, inactif=a)`, qui
ignore la construction. Aucun recollement n'échoue. La couverture se
propage ensuite comme pour le cube 0 : 512 bits au tour 15 (direct) et au
tour 12 (inverse) pour chacun des 512 cubes. Durée : 9 minutes sur 12
threads.

*Recherche exacte* (`tests/dp_cpsat.py`, CP-SAT) : même modèle, bit
inactif laissé libre, fenêtres de poids sans perte de correction (poids
≤ D(R − t) depuis la fin ; poids ≥ 512 − D′(t) depuis le cube, par le
théorème de Boura–Canteaut 2013). Les fenêtres seules rendent le modèle
infaisable pour R ≤ 10 dans les deux sens, ce qui redonne la borne basse.
Le modèle complet est trop gros pour conclure à 11 tours : 1,4 million de
variables en inverse, une piste en 18 minutes à R = 12, et des requêtes
ciblées qui ne concluent pas en 25 minutes. Des coupes linéaires par
nibble (wt(u) ≤ 3·[v ≠ 0] + [v = F], cw(v) ≤ 3·[u ≠ F] + [u = 0],
vérifiées sur les 3 194 transitions de toutes les tables exactes) rendent
la borne de Boura–Canteaut visible par la relaxation LP, sans suffire.

**Lemme 12 quinquies (décomposition).** Soit τ une piste vérifiée et i0
une couche. Toute suite de transitions valides qui part de l'état de τ à
la couche i0 et mène à e_j au tour R donne, accolée au préfixe de τ, une
piste vérifiée vers j au tour R (localité des règles, comme au Lemme
12 ter). Le préfixe de τ peut venir d'une piste d'un nombre de tours
différent : les couches des premiers tours, constantes comprises, sont
les mêmes.

*Mise en œuvre* (`tests/dp_queue.py`). Le suffixe est cherché par CP-SAT
dans un modèle réduit aux bits atteignables depuis l'état fixé et
co-atteignables depuis le bit cible : quelques milliers de variables, et
une seconde environ par requête au lieu de plusieurs heures.

**Théorème 12 sexies (portée exacte de la division property).** Pour
tout cube, et dans chaque sens, la division property bit à bit (pistes
monomiales exactes, constantes comprises) prouve l'équilibre de tous les
bits jusqu'à 10 tours, et d'aucun bit à 11 tours. Sa portée vaut donc
**exactement 10 tours par sens, et 20 tours inside-out**.

*Preuve.* La borne basse est la Proposition 12 bis (i). Pour la borne
haute, `tests/test_dp_exact.py` exhibe, pour le cube 0, une piste
vérifiée vers chacun des 512 bits au tour 11, dans chaque sens :
- *Direct.* Aucune piste à 11 tours n'était connue. On tronque les 9
  pistes du cache (12 et 13 tours) aux couches 10 et 12, et on complète
  vers un bit quelconque au tour 11 : 18 pistes de base à 11 tours. Pour
  chaque bit j, on complète ensuite une base vers j, en partant de la
  coupe la plus tardive (couche 18, puis 16, 14 et 12).
- *Inverse.* On complète les 18 pistes à 11 tours du cache depuis la
  couche 18, puis 16 et 14.

Les 1 024 pistes sont revérifiées par `verifier`, qui ignore leur
construction. Toutes partagent avec une piste du cache l'état qui suit la
première couche linéaire. Le recollement de ces pistes sur les 512 cubes
est vérifié (Corollaire 12 quater) ; par le Lemme 12 ter, il s'applique
tel quel aux pistes complétées. Un échantillon de 96 pistes recollées sur
des cubes tirés au hasard est revérifié entièrement. Les cubes de
dimension < 511 suivent comme au Corollaire 12 quater. ∎

*Portée de l'énoncé.* Une piste montre que la méthode ne prouve plus
l'équilibre. Elle ne montre pas que la somme sur le cube est non nulle,
car des pistes en nombre pair s'annulent. Le distingueur intégral réel
pourrait donc aller au-delà de 10 tours. Le mesurer exactement
demanderait de compter les pistes modulo 2 (prédiction de monômes
complète), ce qui reste hors de portée à cette taille. Empiriquement, les
cubes ne distinguent que 4 tours en direct et 3 en inverse.

Durée : 12 minutes sur 12 threads pour la recherche, 40 s pour revérifier
le cache (`resultats/pistes_exactes.json`).

**Proposition 12 septies (dualité et encadrement par le degré).** Pour une permutation F de n bits, soit
`σ(F, i, j) = ⊕_{x : x_i = 0} F_j(x)`. Alors (i) `σ(F, i, j) = σ(F⁻¹, j, i)`. (ii) Si `F = F2 ∘ F1` et `deg(F1⁻¹) + deg(F2) < n`, alors
`σ(F, i, j) = 0`. Pour BRUME-512, `D(5) + D(5) = 486 < 512` redonne l'équilibre à 10 tours, et `D(5) + D(6) = 665` : le seul argument de degré s'arrête là.

*Preuve.* (i) Soit `a = #{x : x_i = 0, F_j(x) = 1}` et `b = #{x : x_i = 1, F_j(x) = 0}`. `#{x_i = 1, F_j = 1}` vaut `2^{n−1} − a` et `2^{n−1} − b`, donc `a = b`.
Or `σ(F, i, j)` est la parité de a, et `σ(F⁻¹, j, i)` celle de b. (ii) Avec `z = F1(x)`,
`σ = Σ_z (1 + (F1⁻¹)_i(z))·(F2)_j(z)`. Le premier terme est nul, F2 étant équilibrée. Le second est la somme sur tout l'espace d'un polynôme de degré < n, donc nul. ∎

La dualité est vérifiée exactement sur mini-BRUME (`dualite_F_F_inverse_exacte_sur_les_cubes`).

### 4.2 bis Cryptanalyse poursuivie : ce qui est établi, et ce qui ne l'est pas

Trois énoncés d'apparence voisine n'ont pas le même statut :

| Énoncé | Nature | Ce qu'il ne dit pas |
|---|---|---|
| ≥ 128 S-box actives par caractéristique sur 32 tours | **démontré et certifié** (Théorème 9, Proposition 10), propriété de la construction | rien sur les probabilités, ni sur les différentielles agrégées |
| Caractéristique ≤ 2⁻²⁵⁶, trail linéaire ≤ 2⁻¹²⁸ | **modèle de Markov** : une hypothèse, BRUME n'ayant pas de sous-clés | rien sur la permutation concrète ; le modèle est mesurablement inexact (ci-dessous) |
| 20 tours inside-out | **portée exacte de la division property** | ce n'est pas une attaque intégrale réelle sur 20 tours, ni un plafond pour une telle attaque |

Portée intégrale réelle et agrégation au-delà de 2 tours restent **ouvertes** à 512 bits. Ce qui suit les éclaire sans les fermer.

**Modèle exact, mini-BRUME** (`tests/c/mini_brume.c`) : même S-box, même forme de couche linéaire, 24 et 32 bits, tout est calculé exactement. *Ce n'est pas une preuve pour
512 bits* : le graphe et l'échelle changent.

| Question | 24 bits (8 instances) | 32 bits (4 instances) |
|---|---|---|
| Borne de Boura–Canteaut (tours) | 4 | 4 |
| Portée intégrale réelle, tous les bits nuls | 4 | **5** |
| Tour suivant : bits non nuls | ≈ 50 % (hasard) | ≈ 50 % |

À 32 bits, la réalité dépasse donc la borne de degré d'un tour. Cela peut venir de pistes qui s'annulent, ce qui rendrait la division property trompeuse, ou d'une borne trop lâche.
Test direct, solveur SAT aux fenêtres de poids : sur 20 requêtes à 5 tours et 32 bits, **13 sans aucune piste, 0 avec piste, 7 indécises** à 15 minutes. **Aucune annulation n'a été
observée** : là où le calcul aboutit, la division property voit ce tour de plus. Réserve : 7 requêtes restent indécises, et ce résultat, pris à petite échelle, ne garantit pas 512 bits.

*Agrégation et Markov* (nibble d'entrée, loi exacte contre chaîne de Markov et meilleur trail, deux α par instance) :

| Tours | Pic réel / meilleur trail | Réel / Markov, 64 points désignés par le modèle | LP exact / ELP, de même |
|---|---|---|---|
| 2 | ≤ 1,25 | 1,00 | 0,99 à 1,04 |
| 3 | ≤ 3,4 (pic choisi après coup : biaisé vers le haut) | 0,95 à 1,12 | 0,90 à 1,14 |
| ≥ 4 | au niveau du bruit (témoin aléatoire : H_max = 16, réel ≤ 20) | non significatif | non significatif |

L'agrégation reste modérée tant qu'elle se mesure, et Markov suit la réalité à ≈ 15 % près, sans lui être égal : l'écart à 3 tours est statistiquement net (z = 4,6 ; 11 en linéaire). Le signal
disparaît dès 4 tours à cette taille, ce qui ne dit rien de 512 bits, où l'espace n'est pas saturé.

**Boomerang** (`tests/c/brume_attaques.c`). S-box : BCT max = 10 sur 16, donc un passage au milieu coûte `2^{−0,7}` par S-box active, contre `2^{−4}` pour DDT². Mesuré, avec δ = M·(un nibble) :
**3 tours** (z = 14,8 à 2²⁰ quartets, 16 combinaisons), rien à 4 tours et au-delà à cette échelle. Une première version, δ d'un seul nibble, ne voyait que 2 tours : M⁻¹ dense activait d'emblée plus de
100 S-box. En modèle de Markov avec les activités certifiées, `p²q² ≤ 2^{−4(A(r0) + A(r1))}` : avec un seul tour de passage gratuit, `2^{−484}` ; 2²⁵⁶ quartets ne couvrent que 16 tours de trails. Rectangle et
boomerang amplifié ne font pas mieux ici : ils perdent `2^{−b}`, b = 512.

**Différentielles impossibles et corrélations nulles par valeurs.** Par nibble, l'ensemble des valeurs possibles est propagé par DDT ou LAT et par les vrais coefficients. Les valeurs ne gagnent rien sur
l'activité seule : **5 tours** dans les deux cas, aucune contradiction à 6 tours ni au-delà pour un nibble en entrée et en sortie (r1, r2 ≤ 7). 9,9 millions de différences réelles restent dans les ensembles.

**Structure du graphe** (`tests/test_brume_algebre.py`).
- *Annulations.* Aucun cycle de longueur 4, au plus 1 voisin commun sans la diagonale, au plus 2 sorties communes à deux colonnes de M. Voisinage minimal exact de 7, 12, 17 nibbles pour |S| = 1, 2, 3 ; par recherche locale
  (borne haute) 22, 34, 55, 84, 101, 112 pour |S| = 4, 8, 16, 32, 48, 64.
- *Paires rotationnelles.* Une paire exactement symétrique ne survit à aucun tour : `S` étant bijective, l'égalité exigerait des constantes invariantes par translation, or elles coïncident sur au plus 23 % des nibbles. Variante rotationnelle-XOR :
  `M ⊕ T_h M T_h⁻¹` a un rang ≥ 126 sur GF(16) pour toute translation h. Les coefficients coïncident au plus à 9,8 % (6,7 % au hasard).
- *Sous-espaces invariants de M.* Le polynôme minimal binaire est de degré 512, de facteurs de degrés 4, 8, 24 et 476 : M est cyclique, et elle a exactement **16 sous-espaces invariants**, dont un de dimension 4 (vecteur propre sur GF(16), λ = 3).
  Ils existent donc, contrairement à ce que pourrait laisser croire un test limité aux petits ordres. Ils sont inoffensifs tels quels : ces vecteurs ont pour poids 119 et 118 nibbles, la couche S fait quitter à leur droite toute droite affine (vérifié pour chaque tour et sans constante), et une piste qui les suivrait activerait plus de 100 S-box par tour.
- *Invariants non linéaires avec les vraies constantes : exclus* (`tests/c/invariants.c`). Critère de Beierle, Canteaut, Leander et Rotella
  (CRYPTO 2017) : un invariant g commun à la couche S et à toutes les couches « M puis constante » admet pour structures linéaires tout
  `W_M(D)`, plus petit sous-espace stable par M contenant `D = {rc_i ⊕ rc_j}` ; si `dim W_M(D) ≥ n − 1`, g est affine, ce qu'interdit une
  S-box sans composante affine. Avec les 31 constantes intérieures (rc₁ à rc₃₁), **dim W_M(D) = 512** : l'attaque par invariant non linéaire
  (Todo–Leander–Sasaki) et par sous-espace invariant ne s'applique pas, **quelle que soit la S-box**. Trois constantes consécutives suffisent
  (deux : 508), donc toute version réduite d'au moins 4 tours est couverte. Les 15 composantes de la S-box sont de degré 3. Témoin : avec
  L = identité à la place de M, W retombe à span(D), de dimension 30. Hors critère : invariants changeant d'un tour à l'autre et invariants
  en boucle fermée (Beyne, ASIACRYPT 2018).

**Algébrique.** S-box : 21 relations quadratiques, polynôme univarié de degré 14 à 15 termes sur GF(16), un seul point équivariant par Frobenius. Récupération d'état (débit connu en entrée et en sortie, c bits inconnus) :
- **1 tour : cassé**, 256 bits retrouvés par résolution linéaire (bloc débit-capacité de rang 64), sans solveur ;
- SAT, 20 à 25 s par cas : jusqu'à 128 bits inconnus à 2 tours, 16 bits à 3 et 4 tours, rien à 5 tours ; aucun cas à 256 bits, même à 1 tour, où l'attaque dédiée fait pourtant mieux. **SAT sous-estime donc les attaques dédiées.**
- **2 tours : capacité entière (256 bits) retrouvée en ≈ 2^97**, par devinette et détermination (`tests/c/brume_gd2.c`). Tous les générateurs
  relient la moitié A (débit) à la moitié B (capacité) : après 2 tours, chaque nibble de débit ne dépend que de 6 nibbles inconnus, ses voisins
  de B (u + {0, 7, 8, 21, 45, 62} mod 64). En introduisant les 64 inconnues dans un ordre choisi, chaque équation complète filtre d'un
  facteur 16 ; la largeur max (|V| − |E|) vaut 24 (glouton et recuit simulé, 24 sur toutes les graines ; aucune graine de propagation
  pure de taille ≤ 8), d'où 16²⁴ = 2⁹⁶ en énumération en profondeur, mémoire négligeable. Validé sur le vrai BRUME à 2 tours, oracle
  fournissant 21 inconnues : état retrouvé sur 24 états sur 24, une seule solution, nœuds à 1,2 bit du modèle (≈ 2^97,2).
- **3 tours : cette méthode s'arrête.** Chaque nibble de débit dépend alors de 63 des 64 nibbles inconnus.
- *Préimage d'un bloc du hachage réduit* : 1 tour cassé (chaque nibble de sortie ne dépend que d'un nibble de message) ; à 2 tours,
  31 nibbles de message par nibble de sortie, largeur 51, soit 2²⁰⁴, au-dessus de la borne générique de l'éponge (2¹²⁸) : pas d'attaque.
L'estimation par degré de régularité sous hypothèse semi-régulière (2²⁴⁷ à 1 tour) est contredite par cette attaque à 1 tour : ce n'est **pas** un argument de sécurité, et elle n'est pas utilisée comme tel.

**Activité.** CP-SAT sur le modèle tronqué ne prouve à ce budget que 12, 16 et 24 S-box sur 3, 4 et 6 tours, soit le 4r de la Proposition 10 : **128 à 32 tours n'est pas amélioré**. Les trails trouvés sont bien au-dessus (44 à 3 tours).
Modèle exact (`tests/c/sat_trails.c`, méthode de Sun, Wang et Wang, ToSC 2021 : couche linéaire bit à bit, vraie DDT et vraie LAT,
CryptoMiniSat, chaque solution revérifiée hors du solveur) : sur 2 tours, le minimum est **exactement 8** en différentiel et en linéaire,
atteint (1 puis 7 S-box, 7 puis 1) : la borne de branchement est serrée. Sur 3 tours, en différentiel, « ≤ 13 », « ≤ 16 » et « ≤ 20 » restent indécis à
600 s : la méthode ne passe pas l'échelle de 128 S-box par tour, ce que notent aussi ses auteurs pour les états non légers.

Des échelles plus grandes sont prévues dans le volet `tests/nuit_brume.py` de la campagne de nuit.

### 4.3 Sécurité du mode AEAD (preuve)

**Cadre.** P est une permutation aléatoire de {0,1}^b, b = 512, accessible
à l'adversaire dans les deux sens (N requêtes au total). Notations : débit
r, capacité c = b − r, tag τ bits, clé k = 512 bits absorbée en m = k/r
blocs.

| Profil | r | c | τ | m |
|---|---|---|---|---|
| BRUME-512 | 256 | 256 | 128 | 2 |
| BRUME-512-256 | 128 | 384 | 256 | 4 |

**Jeu de sécurité** (AE « tout-en-un », Rogaway–Shrimpton 2006).
- *Monde réel :* (Enc_K, Dec_K, P^±). *Monde idéal :* (Enc$, ⊥, P^±).
  Enc$(N, A, M) renvoie une chaîne uniforme de |M| + τ bits, et ⊥ refuse
  toute requête de déchiffrement.
- *Nonces :* A ne pose jamais deux requêtes de chiffrement avec le même
  nonce. Les requêtes de déchiffrement portent sur des nonces
  quelconques, déjà utilisés ou non. Les nonces font 24 octets, comme ceux de
  XChaCha20 : tirés au hasard, deux d'entre eux coïncident avec probabilité au plus
  `q_e²/2^{193}`. Le Théorème 14 suppose des nonces uniques et ne contient pas ce terme : voir le Corollaire 14 ter.
- *Restriction standard :* A ne soumet pas au déchiffrement un
  quadruplet (N, A, C, T) renvoyé par une requête de chiffrement. Il en
  connaît déjà la réponse. Sans cette restriction, ⊥ se distinguerait
  trivialement. De même, sans perte de généralité, A ne répète pas une
  requête.
- *Formulation équivalente :* le monde idéal mémorise les sorties de
  Enc$, renvoie le clair correspondant quand on lui soumet l'une d'elles,
  et refuse toutes les autres.
- *Budgets :* A fait q_e chiffrements, q_d déchiffrements et N requêtes à
  P^± au total. σ désigne le nombre total d'appels à P effectués par la
  construction pour répondre aux requêtes de chiffrement et de
  déchiffrement. Un déchiffrement refusé ne libère aucun clair (pas de
  RUP).

**Niveau de sécurité.** Le mode offre λ bits de sécurité pour une limite de
données σ ≤ σ_max si, pour tout adversaire,

    Adv^AE(A) ≤ (N + q_d)/2^λ + 2^{−λ}.

C'est la notion coût/avantage usuelle, celle des catégories NIST : pour
un avantage proche de 1, il faut environ 2^λ requêtes. Elle n'exige pas
qu'un adversaire qui fait 2^λ requêtes reste à un avantage de 2^{−λ}.
Aucun AEAD ne satisfait cette exigence-là : la seule recherche de tag
donne q_d/2^τ, et la recherche exhaustive de la clé donne N/2^k, comme
pour AES-128.

**Le mode, écrit comme un duplex.** Un appel d'entrée (σ, dom) fait
`S ← P(S ⊕ (σ ‖ 0^c) ⊕ dom·e₁₂₇)`, où e₁₂₇ désigne le dernier nibble de la
capacité ; le débit de S est lu **avant** l'appel suivant. L'état initial
est S₀ = P(IV_profil), public.

**Lemme 1 (remplacement par le clair = absorption du chiffré).** Notons
Z = débit(S) le flux du bloc i. L'implémentation remplace le débit par le
clair P_i en chiffrement, et par Z ⊕ C_i en déchiffrement. Comme
C_i = P_i ⊕ Z, on a toujours

    nouveau débit = Z ⊕ C_i = P_i.

C'est exactement l'appel (σ = C_i, 0) du duplex, le chiffré étant XORé
dans le débit. Pour le dernier bloc, partiel, de longueur ℓ < r : les ℓ
premiers octets reçoivent Z ⊕ C (même identité), l'octet ℓ reçoit
Z ⊕ 0x01 et les suivants restent inchangés. C'est l'appel
(σ = C ‖ 0x01 ‖ 0*, 0).

Le mode est donc un **duplex à clé qui absorbe le chiffré**. L'entrée σ_i
est choisie après la lecture du flux qui la précède, ce qui est l'usage
standard du duplex (le duplex est une éponge sur l'historique des entrées
bourrées : Bertoni–Daemen–Peeters–Van Assche 2011). Aucun « drapeau
d'écrasement » n'est nécessaire. ∎

**Lemme 2 (codage injectif et sans préfixe).** Soit chemin(N, A, C) la
suite des entrées du duplex :
1. les blocs de (K ‖ N ‖ 0x01 ‖ 0*), sans domaine ;
2. les blocs de (A ‖ 0x01 ‖ 0*), le dernier avec dom = 1 ;
3. les blocs pleins de C, puis (C_fin ‖ 0x01 ‖ 0*), sans domaine ;
4. (0^r, dom = 2) ;
5. (len(C) sur 8 octets ‖ 0x01 ‖ 0*, dom = 4).

Ce codage est injectif en (N, A, C), et aucun chemin complet n'est
préfixe strict d'un autre.

*Preuve.* Les bits de domaine sont dans la capacité, que les données ne
touchent jamais. Ils découpent donc la suite sans ambiguïté :
- la phase clé ‖ nonce a une longueur fixe (88 octets) ;
- l'AAD s'arrête à l'unique appel portant dom = 1 ;
- le chiffré occupe les appels entre celui-là et l'unique appel dom = 2 ;
- le bourrage 10* est injectif.

Enfin, dom = 4 n'apparaît qu'au dernier appel d'un chemin : un chemin qui
en contiendrait un autre comme préfixe strict aurait un appel dom = 4
au milieu, ce qui est impossible. ∎

*Vérification mécanique* : `tests/test_mode_aead.py` reconstruit l'AEAD à
partir de ce seul codage et d'un duplex abstrait. Il retrouve exactement
les chiffrés et les tags de `Brume512` (deux profils, longueurs 0 à
3r + 1, 200 et 1 000), et contrôle l'injectivité et l'absence de préfixe
sur 441 chemins limites par profil.

**Lemme 3 (absorption de la clé).** Notons X₁ = S₀ ⊕ (K₀ ‖ 0) et
X_{j+1} = P(X_j) ⊕ (K_j ‖ 0), avec S_K = P(X_m) l'état après la clé.
Tant qu'aucun événement mauvais ne s'est produit, les réponses de la
construction sont indépendantes de K. La probabilité qu'une requête de A
à P atteigne X_m (en direct) ou S_K (en inverse) est alors au plus

    N/2^k + 2N/2^b + N/2^c.

*Preuve.*
- Une requête directe q ne vaut X_j que si son débit vaut celui de
  P(X_{j−1}) ⊕ K_{j−1} (probabilité 2^−r, car K_{j−1} est uniforme et
  inconnu) et si sa capacité vaut cap(P(X_{j−1})).
- Cette capacité n'est connue de A que s'il a lui-même interrogé X_{j−1}.
  Sinon, elle est uniforme parmi au moins 2^c valeurs.
- Par récurrence, Pr[q = X_j] ≤ 2^−r · (Pr[q′ = X_{j−1}] + 2^−c), avec
  Pr[q = X₁] = 2^−r puisque S₀ est public. D'où
  Pr[q = X_m] ≤ 2^−mr + 2^−c · Σ_{i ≥ 1} 2^−ir ≤ 2^−k + 2^{1−b}.
- En sommant sur les N requêtes, on obtient les deux premiers termes.
- Une requête inverse ne vaut S_K que si elle devine sa capacité, d'où
  N/2^c.

Atteindre un X_j avec j < m n'apprend rien d'utilisable sans les blocs de
clé suivants : c'est pourquoi le terme en N/2^r d'une analyse naïve
disparaît. ∎

**Lemme 4 (pas de collision de capacité).** Considérons les nœuds de la
construction, c'est-à-dire les états atteints par des chemins distincts,
hors phase de clé. La probabilité que deux nœuds distincts aient des
sorties de P de même capacité, ou qu'une requête de A atteigne l'entrée
ou la sortie d'un nœud, est au plus

    σ²/2^{c+1} + 2σN/2^c.

*Preuve.* Chaque sortie de P calculée par la construction sur une entrée
fraîche est uniforme parmi au moins 2^b − σ − N valeurs, d'où le premier
terme pour les C(σ, 2) paires. L'entrée d'un nœud a pour capacité celle
de la sortie du nœud qui le précède, inconnue de A en l'absence
d'événement mauvais : chaque requête de A l'atteint avec probabilité au
plus 2^−c, dans chaque sens, d'où 2σN/2^c. ∎

**Théorème 14 (BRUME-AEAD).** Sous ces hypothèses,

    Adv^AE(A) ≤ σ²/2^{c+1} + 2σN/2^c + N/2^c + N/2^k + 2N/2^b + σ²/2^{b+1} + q_d/2^τ.

*Preuve.* En l'absence des événements des lemmes 3 et 4, chaque nœud
fraîchement atteint renvoie une sortie uniforme (à σ²/2^{b+1} près, pour
le passage de permutation à fonction aléatoire).
- *Confidentialité.* Deux chiffrements de nonces distincts ont des chemins
  qui divergent au plus tard au bloc du nonce (Lemme 2). Leurs flux et
  leurs tags sont donc frais et uniformes, et les chiffrés suivent la loi
  de Enc$.
- *Intégrité.* Un déchiffrement (N, A, C, T) qui ne provient pas d'un
  chiffrement a un chemin distinct de tous les chemins de chiffrement
  (Lemme 2), sinon le tag est déterministe et T est refusé. À partir du
  premier nœud de divergence, tous les nœuds sont frais (Lemme 4), y
  compris celui qui produit le tag après l'appel dom = 4, puisque le
  codage est sans préfixe. T est alors juste avec probabilité 2^−τ (un
  tag sur deux blocs est frais sur les deux).
- *Clair.* Aucun clair n'est libéré avant la vérification du tag.

En sommant, on obtient la borne. ∎

**Corollaire 14 bis (instanciation, terme par terme).** Avec σ ≤ 2^64
blocs (sur toute la durée de vie d'une clé) :

| Terme | BRUME-512 (c = 256, τ = 128) | BRUME-512-256 (c = 384, τ = 256) |
|---|---|---|
| σ²/2^{c+1} | ≤ 2^−129 | ≤ 2^−257 |
| 2σN/2^c | ≤ N·2^−191 | ≤ N·2^−319 |
| N/2^c | N·2^−256 | N·2^−384 |
| N/2^k + 2N/2^b | ≤ N·2^−510 | ≤ N·2^−510 |
| σ²/2^{b+1} | ≤ 2^−385 | ≤ 2^−385 |
| q_d/2^τ | q_d·2^−128 | q_d·2^−256 |
| **Somme** | **≤ (N + q_d)·2^−128 + 2^−128** | **≤ (N + q_d)·2^−256 + 2^−256** |

On obtient donc 128 bits (BRUME-512) et 256 bits (BRUME-512-256), au sens
défini plus haut, pour σ ≤ 2^64. C'est le terme σ²/2^{c+1} qui fixe la
limite de données, pas 2σN/2^c.

**Corollaire 14 ter (politique de nonces).** Le Théorème 14 et le Corollaire 14 bis valent pour des **nonces uniques** par clé
(compteur persistant, qui survit aux redémarrages et n'est pas partagé entre appareils). Avec des nonces **tirés au hasard**, il faut
ajouter à l'avantage `q_e²/2^{193}`, soit `2^{−65}` à `q_e = 2^{64}`.
- *BRUME-512 :* `q_e²/2^{193} ≤ q_e/2^{128}` tant que `q_e ≤ 2^{65}`. Le niveau de 128 bits, au sens coût/avantage, tient donc avec des
  nonces aléatoires jusqu'à `q_e = 2^{64}` chiffrements par clé.
- *BRUME-512-256 :* `q_e²/2^{193} ≤ q_e/2^{256}` n'est vrai pour aucun `q_e ≥ 1`. **Les 256 bits exigent des nonces uniques.** Avec des nonces aléatoires, le niveau plafonne
  par collision à environ 96 bits de requêtes (avantage ≈ 1 vers `q_e = 2^{96}`).

Le code ne choisit pas : le nonce est fourni par l'appelant. Le même corollaire s'applique aux profils parallèles (§ 4.5). Point relevé par
un audit externe : le terme figurait dans le texte du jeu, mais ni dans le théorème ni dans le tableau.

*Lecture du cas limite.* Avec N = 2^128 et σ = 2^64, la borne donne un
avantage d'environ 2^−63 pour BRUME-512. Un adversaire qui a fait 2^128
requêtes n'a donc qu'un avantage de 2^−63, ce qui est cohérent avec 128
bits au sens coût/avantage. La première rédaction (« avantage ≤ 2^−62
environ ; sécurité de 128 bits ») mélangeait les deux lectures et a été
relevée à juste titre par l'audit externe (point 2). Si l'on exigeait un avantage d'au plus 2^−λ à N requêtes, il
faudrait log2 σ + log2 N ≤ c − λ − 1 (ainsi que q_d ≤ 2^{τ−λ}), comme le
calcule l'audit.

**Remarques.**
1. Le mode TE ajoute des parités qui sont une fonction publique du
   chiffré : l'adversaire peut les calculer lui-même. La correction
   préalable au contrôle du tag ne donne donc aucun oracle supplémentaire.
2. La borne est volontairement simple. Les analyses fines du duplex à
   clé, qui remplacent σN/2^c par des termes de multicollision
   (Daemen–Mennink–Van Assche 2017), ne font que l'améliorer.
3. P est modélisée comme une permutation aléatoire. Pour BRUME-512, cela
   repose sur l'absence de distingueur connu sur 32 tours (§ 4.1–4.2 et
   la cryptanalyse du rapport d'audit).
4. *Multi-utilisateur* : voir le Théorème 14-mu ci-dessous.
5. *Séparation entre constructions.* Tout chemin AEAD commence par
   P(IV_profil), dont la capacité porte les paramètres du profil (nibbles
   120 à 126 : débit, longueur de tag, λ et version, non tous nuls). Les éponges de hachage (séquentielle et
   arborescente) commencent par un état de capacité nulle. Les premiers
   appels sont donc distincts, et les chemins ne peuvent se rejoindre que
   par une collision de capacité, déjà comptée dans les termes en
   σ²/2^{c+1} et σN/2^c (σ et N comptés sur toutes les constructions
   utilisant P). SHAKE256 n'est utilisé que par le KEM et la SIG, avec des
   chaînes de domaine propres (« SILLAGE-KEM|… », « SILLAGE-SIG|… »).

**Théorème 14-mu (BRUME-AEAD, μ utilisateurs).** Soient μ clés
indépendantes et uniformes K_1, …, K_μ de k bits et une seule
permutation P. L'adversaire interroge Enc(i, ·) et Dec(i, ·). Il respecte
les nonces pour chaque utilisateur, avec la même restriction que dans le
cas d'un seul utilisateur. Le monde idéal a μ oracles Enc$ indépendants.
σ compte tous les appels à P de la construction, sur tous les
utilisateurs, y compris les m appels d'absorption de chaque clé. Alors

    Adv^{AE-mu}(A) ≤ σ²/2^{c+1} + 2σN/2^c + μN/2^c + μN/2^k + 2μN/2^b
                     + σ²/2^{b+1} + q_d/2^τ + μ²/2^{k+1}.

*Preuve.* On reprend la preuve du Théorème 14 avec trois changements.
1. *Lemme 3, appliqué à chaque utilisateur.* Une requête directe de A
   atteint X^i_m avec une probabilité d'au plus 2^{−k} + 2^{1−b}, et une
   requête inverse atteint l'état S^i_K avec une probabilité d'au plus
   2^{−c}. La borne de l'union sur les μ utilisateurs et les N requêtes
   donne μN/2^k + 2μN/2^b + μN/2^c.
2. *Lemme 4 sur l'ensemble des nœuds.* Les nœuds de tous les
   utilisateurs, y compris ceux de la phase de clé, sont des sorties de
   P sur des entrées distinctes. Les termes σ²/2^{c+1} et 2σN/2^c
   valent donc avec σ total. Deux utilisateurs dont les clés ont un
   préfixe commun partagent les premiers états X_j, mais leurs états
   divergent au premier bloc de clé différent. Ils ne se rejoignent que
   par une collision de capacité, déjà comptée.
3. *Clés identiques.* Si K_i = K_j avec i ≠ j, les deux utilisateurs
   sont confondus dans le monde réel et indépendants dans le monde idéal.
   Cela arrive avec une probabilité d'au plus μ²/2^{k+1}.

Hors de ces événements, chaque nœud fraîchement atteint renvoie une
sortie uniforme, indépendante d'un utilisateur à l'autre. Les arguments
de confidentialité et d'intégrité du Théorème 14 s'appliquent utilisateur
par utilisateur, et le terme q_d/2^τ compte tous les déchiffrements. ∎

*Instanciation.* Pour μ ≤ 2^{64} et σ ≤ 2^{64} au total :
- BRUME-512 : μN/2^c ≤ N·2^{−192} et μ²/2^{k+1} ≤ 2^{−385}, donc
  Adv ≤ (N + q_d)·2^{−128} + 2^{−128} : 128 bits ;
- BRUME-512-256 : μN/2^c ≤ N·2^{−320}, donc 256 bits.

La limite de données porte sur le total des utilisateurs, et non sur
chacun, comme pour tout mode à capacité partagée.

**Attaques exécutées sur duplex réduit** (`tests/test_aead_modele.py`, permutation aléatoire de 16 bits). Les falsifications passent par
le vrai déchiffrement du modèle.

| Terme | Attaque | Fréquence | Attendu | Borne |
|---|---|---|---|---|
| σ²/2^{c+1} | collisions de capacité entre nœuds, σ = 14, c = 8 | 0,307 | | 0,383 |
| 2σN/2^c | clair constant : une requête teste tous les nœuds, puis falsification, N = 8, c = 10 | 0,117 | 0,109 | 0,666 (toute la borne) |
| 2σN/2^c, inverse | requêtes inverses, sans multi-cible, N = 48 | 0,061 | 0,047 | trivial |
| N/2^k | essais de clé en chaîne, m = 2, k = 8, N = 16 | 0,036 | 0,031 | 0,067 |
| μN/2^k | la même, μ = 8 clés, m = 1 | 0,217 | 0,25 | 0,627 |
| q_d/2^τ | tags devinés, q_d = 16 | 0,056 | 0,0625 | 0,0625 |

L'attaque à clair choisi montre que le terme en σN est réel : le débit d'entrée étant choisi constant, une requête teste tous les nœuds à
la fois. Le facteur 2 du terme vient de la somme sur les deux sens. Le terme naïf N/2^r, écarté au Lemme 3, vaudrait 1 sur cette instance, pour 0,036
mesuré. Le terme N/2^c du Lemme 3 est prudent : les requêtes inverses atteignent l'état qui suit la clé en 2^{−b} par requête (mesuré), aucun de ses débits
n'étant connu.

### 4.4 Hachage arborescent (preuve)

**Le mode.** Notons F_d(X, ℓ) l'éponge BRUME-512 (débit 256 bits,
bourrage 10*) dans laquelle le domaine d est XORé dans le dernier nibble
de la capacité juste avant la permutation finale d'absorption ; ℓ est la
longueur de sortie. F_0 est le hachage séquentiel `brume512_hash`. Avec
B = 8 192 octets et des valeurs de chaînage (CV) de n = 256 bits :
- si |M| ≤ B : H(M) = F_SEUL(M, ℓ) ;
- sinon, M = M_0 ‖ … ‖ M_{k−1} (feuilles de B octets, la dernière
  éventuellement plus courte), CV_i = F_FEUILLE(M_i, 32), et
  H(M) = F_RACINE(CV_0 ‖ … ‖ CV_{k−1} ‖ k₆₄ ‖ B₃₂, ℓ).

Domaines : FEUILLE = 8, RACINE = 9, SEUL = 10. Les feuilles sont
indépendantes, d'où le parallélisme (lots de 32 états, tous les cœurs).

**Lemme 15 (domaines indépendants).** Soit D = {0, 8, 9, 10} et
Δ = D ⊕ D = {0, 1, 2, 3, 8, 9, 10} (|Δ| = 7). Si P est une permutation
aléatoire, accessible dans les deux sens, la famille (F_d)_{d ∈ D} est
conjointement indifférentiable de |D| oracles aléatoires indépendants à
sortie extensible (RO_d)_{d ∈ D}, avec un avantage au plus

    7q(q + 1)/2^{c+1} + q²/2^{b+1}

pour q appels à P ou P⁻¹ au total (ceux de l'adversaire et ceux de la
construction). À c = 256, cela vaut environ 7q²/2^{257}.

*Preuve.* On suit Bertoni, Daemen, Peeters et Van Assche (Eurocrypt 2008) : un
simulateur S tient P et P⁻¹ et maintient deux ensembles de capacités.
- **R**, capacités des *nœuds enracinés* : au départ, la capacité nulle de l'état
  initial. Un nœud a pour chemin la suite de blocs qui y mène depuis l'état initial.
- **O**, capacités des entrées posées hors de tout chemin enraciné.

*Requête directe x = (x_r ‖ x_c).*
1. Si x_c = cap(T) ⊕ d avec T enraciné d'absorption et d ∈ D, on pose
   X = chemin(T) ‖ (x_r ⊕ T_r). Pour d ≠ 0 et X bien bourré, l'appel est l'appel
   final de F_d(X) : le débit de la réponse vaut le premier bloc de RO_d(X).
   Pour d = 0, le débit vaut le bloc j de RO_0(X′), où X = X′ ‖ 0^{jr} et où
   X′ est bien bourré ; c'est la lecture standard de l'éponge, car extraire revient
   à absorber un bloc nul et qu'un message bien bourré ne se termine pas par un bloc
   nul. Dans tous les autres cas, le débit est uniforme. La capacité de la réponse
   est uniforme, et cette capacité est ajoutée à R.
2. Si x prolonge un état post-final de F_d(X), d ≠ 0, à débit inchangé, on répond par
   le bloc suivant de RO_d(X), de même.
3. Sinon, on répond uniformément et l'on ajoute x_c à O.

*Requête inverse y.* S répond par un x uniforme, et ajoute x_c à O.

*Événement mauvais.* Il survient si :
- (a) une capacité de réponse ajoutée à R tombe dans (R ⊕ Δ) ∪ (O ⊕ D) ; ou
- (b) la capacité x_c d'une réponse **inverse** tombe dans R ⊕ D.

Hors de cet événement : T et d sont uniques à chaque appel (les cas δ ≠ 0 sont propres
à la séparation par la capacité) ; aucune entrée déjà posée ne devient un
prolongement enraciné ; et aucun chemin enraciné n'aboutit à une réponse choisie par
l'adversaire. Le codage (d, X) est injectif : le bourrage 10* l'est à d fixé, et d se
lit dans la capacité de l'appel. La simulation est donc cohérente avec les (RO_d), et
les réponses sont uniformes.

*Comptage.* Chaque requête ajoute au plus un élément à |R| + |O| : dans le cas 1 ou 2,
x_c est déjà lié à R et seule la réponse s'ajoute ; dans le cas 3 ou en inverse,
seule une entrée s'ajoute. Donc |R| + |O| ≤ i + 1 avant la requête i + 1. Comme la
capacité de chaque réponse est uniforme parmi 2^c valeurs, la probabilité de
l'événement à cette requête est au plus 7(i + 1)/2^c. La somme sur i < q donne
7q(q + 1)/2^{c+1}. Enfin, remplacer l'échantillonnage sans remise de la permutation
par ce tirage coûte q²/2^{b+1}. ∎

*Correctif.* L'ancienne preuve retirait les requêtes inverses au prix de q²/2^{b+1}, sous
le seul remplacement de P par une fonction, et n'en parlait plus. C'est insuffisant :
une réponse inverse dont la capacité vaut cap(T) ⊕ d fixe la sortie de F_d sur un
message, alors que l'oracle l'ignore. C'est un distingueur concret, de probabilité de
l'ordre de q²/2^c, très au-dessus de q²/2^{b+1} (`tests/test_indiff_arbre.py` :
0,0255 contre 0,00019 pour c = 16, b = 24, q = 80). Elle affirmait aussi qu'« un appel
final de F_d porte d ≠ 0 », ce qui est faux pour d = 0 : F_0 se traite comme une
éponge ordinaire. Elle ne comptait pas non plus les entrées déjà posées (O). Le
terme change peu : le facteur 7 reste, q² devient q(q + 1).

*Pourquoi 0 ∈ D.* La famille contient F_0, le hachage séquentiel. Le
lemme établit ainsi l'indépendance de l'arbre par rapport à
`brume512_hash` autant que celle de ses propres nœuds. Pour les seuls
domaines de l'arbre, {8, 9, 10}, on aurait D ⊕ D = {0, 1, 2, 3} et un
facteur 4. On garde 7 pour couvrir F_0.

*Conséquence.* La première esquisse donnait q²/2^{c+1} : elle oubliait les
six valeurs non nulles de Δ. Le facteur 7 est sans effet sur le niveau :
7q(q + 1)/2^{257} ≤ q/2^{128} pour q ≤ 2^{126}.

**Théorème 16 (indifférentiabilité du mode arborescent).** Le mode
ci-dessus est (i) décodable, (ii) complet en message et (iii) à nœud final
séparable, au sens des définitions 5 à 7 de Bertoni–Daemen–Peeters–Van Assche
(« Sufficient conditions for sound tree and sequential hashing modes »,
IJIS 2014). Il est donc indifférentiable d'un oracle aléatoire à sortie extensible,
avec, pour q < 2^n appels à P ou P⁻¹ (coût des requêtes au mode compris),

    Adv ≤ 7q(q + 1)/2^{c+1} + q²/2^{b+1} + q(q − 1)/2^{n+1}

Le premier et le deuxième termes viennent du Lemme 15. Le dernier est le théorème 1 de
BDPV pour des valeurs de chaînage (CV) de n = 256 bits, qui sont bien les n premiers
bits de la sortie de F_FEUILLE. Cela fait 128 bits de sécurité générique (coût/avantage,
pour q ≤ 2^{126}), comme le hachage séquentiel. Les trois conditions de cette version de
BDPV suffisent : la quatrième des premières versions (complétude des paramètres) a été
retirée par ses auteurs, et B est de toute façon fixe et écrit dans la racine.

*Preuve des trois conditions.* On note F(d, X) = F_d(X) : le domaine fait partie du
nœud (bits de cadre), et l'on a une seule fonction interne au sens de BDPV. Une
*instance d'arbre* est une racine et des feuilles qui la précèdent, chacune avec son
domaine et ses bits.
1. *Décodable (déf. 5).* Algorithme Adecode, linéaire, qui ne lit que l'instance :
   - racine de domaine SEUL, de longueur ≤ B et sans autre nœud : **compliante** ;
   - racine de domaine RACINE : lire B dans les 4 derniers octets et k dans les 8
     précédents ; exiger B = 8 192, k ≥ 2 et une longueur de 32k + 12 octets. Sinon :
     incompliante. Les CV sont alors les 32k premiers octets.
   - pour i = 0, …, k − 1 : si le nœud i manque, renvoyer **sous-arbre final compliant**
     et l'indice i, avec la position de sa CV. S'il est présent, exiger le domaine
     FEUILLE et une longueur de B octets (1 à B pour le dernier). Sinon : incompliante.
   - tous présents et rien d'autre : **compliante**.
   Une instance ne peut être à la fois compliante et sous-arbre final, puisque le critère
   est la présence de tous les nœuds. Le test des tailles de feuilles compte : sans lui,
   deux découpages différents du même message auraient la même structure.
2. *Complet en message (déf. 6).* Pour tout |M|, l'arbre contient tous les bits de M,
   et Amessage les concatène dans l'ordre (ou lit le nœud seul).
3. *Nœud final séparable (déf. 7).* Un nœud interne est une feuille, de domaine 8 :
   seule, c'est une instance incompliante, puisque la racine doit porter 9 ou 10.

*Composition.* BDPV donne un simulateur de F à partir de l'oracle du mode, et le Lemme 15
un simulateur de P à partir de F. Leur composition (Maurer–Renner–Holenstein) est
le simulateur du théorème, et les avantages s'ajoutent (BDPV, § 7.1). Chaque nœud coûte
au moins un appel à P : le compteur de nœuds de BDPV est ≤ q, et un appel à P
déclenche au plus une requête à F hors événement mauvais. ∎

*Vérification mécanique.* `tests/test_hachage_arbre.py` : un modèle du
mode, écrit sans `brume512.py` (la liste de ses nœuds), redonne
exactement la référence Python et l'implémentation C sur 13 longueurs
limites (0, 1, 31 à 33, B − 1 à B + 1, 2B, 2B + 31, 3B − 1, 33B + 5,
40B) et deux longueurs de sortie. Il vérifie aussi :
- que le mode diffère du hachage séquentiel, et qu'une entrée de racine, hachée
  comme un message, ne redonne pas la sortie de l'arbre ;
- que six altérations structurelles changent la sortie : échange de
  feuilles, octet déplacé entre deux feuilles, extension, troncature,
  feuille dupliquée, bit changé ;
- que la sortie courte est un préfixe de la sortie longue (oracle extensible), et ne
  dépend pas du nombre de threads ; l'avalanche dans chaque feuille et les KAT.

`tests/test_indiff_arbre.py` (15 contrôles) :
- Adecode et Amessage, tels qu'écrits ci-dessus, sur toutes les instances de petite
  taille, y compris mal formées (k, B, longueurs de feuilles, domaines) ;
- **le simulateur du Lemme 15, composé avec celui du mode**, sur une éponge réduite.
  Un distingueur mêle requêtes directes et inverses, racines sur CV arbitraires,
  et calculs complets (hachage séquentiel, nœud seul, arbres, sorties longues). Sur
  2 532 comparaisons sans événement mauvais, le simulateur redonne exactement les
  oracles ; sur 165 098 comparaisons à capacité réduite, aucune incohérence hors de
  l'événement mauvais ;
- la fréquence de l'événement mauvais reste sous la borne, de près : 0,221 pour 0,251
  (c = 14, q ≈ 34), 0,184 pour 0,207 (c = 18, q ≈ 124) ;
- le distingueur par requêtes inverses évoqué plus haut.

Ces tests éprouvent le simulateur et le comptage. Ils ne remplacent pas la preuve.

*Remarques.*
1. **Statut : preuve complétée, relecture humaine indépendante à faire.** La relecture
   du 2026-10-30, faite par un assistant d'IA (Claude) à partir du texte de BDPV, a
   trouvé et corrigé les défauts indiqués (requêtes inverses, entrées déjà posées, cas
   d = 0, conditions de BDPV non vérifiées selon leurs définitions), puis a éprouvé le
   résultat sur modèle réduit. Ce n'est ni une revue par des pairs ni une preuve formelle
   (Coq, EasyCrypt) : le mode reste une construction de recherche, sans revendication
   de garantie acquise tant qu'un cryptographe tiers ne l'a pas relue.
2. L'arbre n'a qu'un niveau, ce qui suffit jusqu'à 2⁶⁴ feuilles. La
   racine coûte 32 octets par feuille de 8 Kio, soit 0,4 %.
3. Le mode est une nouvelle fonction (nouveaux KAT). Le hachage
   séquentiel est inchangé.

---

### 4.5 Duplex parallèle (BRUME-512p, BRUME-512-256p)

**Statut : preuve rédigée dans le modèle de la permutation aléatoire, reliée au code et éprouvée sur modèle réduit ;
relecture humaine indépendante à faire.** Les profils séquentiels sont inchangés (mêmes KAT). Implémentation :
`Brume512P` (`sillage/brume512.py`), `sl_aead_p_encrypt` et `sl_aead_p_decrypt` (`sillage/c/brume512_avx2.c`).

**Construction.** Mêmes r, c et τ que le profil séquentiel. B = 4 096 octets, |CV| = 2λ bits (32 ou 64 octets).
L'IV porte en plus log₂ B (octet 58) et le mode (octet 59), nuls dans le profil séquentiel. Soit ℓ la longueur du
chiffré et k = max(1, ⌈ℓ/B⌉). On note (σ, dom) un appel du duplex, comme au § 4.3.
- *Tronc.* S₀ = P(IV) ; blocs de (K ‖ N ‖ 0x01 ‖ 0*) ; blocs de (A ‖ 0x01 ‖ 0*), le dernier avec dom = 1. On obtient S_A,
  dont le débit n'est jamais lu.
- *Feuille j < k.* Depuis S_A : (j sur 8 octets ‖ 0x01 ‖ 0*, dom = 5), puis (0^r, dom = 3). Le morceau j du message est
  ensuite chiffré comme au § 4.3 (Lemme 1) : blocs pleins du chiffré sans domaine, puis (C_fin ‖ 0x01 ‖ 0*, dom = 6).
  CV_j = les |CV| premiers bits de l'état final.
- *Racine.* Depuis S_A : blocs de (CV₀ ‖ … ‖ CV_{k−1} ‖ k ‖ ℓ ‖ 0x01 ‖ 0*), k et ℓ sur 8 octets, le dernier bloc avec
  dom = 4. Le tag est extrait comme au § 4.3.

**Lemme 5 (codage en arbre).** Les chemins sont injectifs et aucun chemin n'est préfixe strict d'un autre.

*Preuve.* Le préfixe (K, N, A) se découpe comme au Lemme 2. Après lui, le premier appel d'une feuille porte dom = 5 et celui
d'une racine dom = 0 ou 4 : ces entrées diffèrent par la capacité, que les données ne touchent pas. Deux feuilles d'indices
distincts diffèrent à cet appel. Dans une feuille, dom = 6 n'apparaît qu'au dernier appel, et le bourrage 10* est injectif ; dans une
racine, dom = 4 n'apparaît qu'au dernier appel, et le contenu a une structure de longueur fixe une fois k connu. ∎

*Vérification mécanique* : `tests/test_aead_parallele.py` reconstruit le mode depuis ce seul codage et retrouve les
chiffrés et tags de la référence et du C. Il contrôle aussi le Lemme 5 aux limites des feuilles.

**Théorème 14-p.** Sous les hypothèses du Théorème 14, σ comptant tous les appels à P (tronc, feuilles, racine) :

    Adv^AE(A) ≤ σ²/2^{c+1} + 2σN/2^c + N/2^c + N/2^k + 2N/2^b + σ²/2^{b+1} + q_d/2^τ + σ/2^{|CV|}.

*Preuve.* Les Lemmes 1, 3 et 4 s'appliquent tels quels. Le Lemme 4 porte sur l'arbre des nœuds, et un arbre apparaît
déjà dans le mode séquentiel, où des déchiffrements partagent un préfixe. Le Lemme 5 remplace le Lemme 2. Hors des événements
de ces lemmes, chaque nœud frais renvoie une sortie uniforme.
- *Confidentialité.* Deux chiffrements de nonces distincts ont des S_A issus de chemins distincts. Dans un même message, deux
  feuilles divergent à la fourche. Tous les flux et les tags sont donc frais.
- *Intégrité.* Soit (N, A, C, T) un déchiffrement qui ne provient pas d'un chiffrement. Si aucun chiffrement n'a utilisé (N, A), ou
  si (k, ℓ) diffère de celui du chiffrement, la racine est un chemin frais et T est juste avec probabilité 2^−τ. Sinon, C diffère
  de C* dans une feuille j au moins. Le nœud final de cette feuille est frais, donc CV_j est uniforme : il égale le CV du
  chiffrement avec probabilité au plus 2^−|CV|, ce que la borne de l'union sur les nœuds finaux compte par σ/2^|CV|. Tout autre
  cas donne une racine fraîche, puis 2^−τ.
- *Clair.* Le clair n'est rendu qu'après la vérification du tag, et mis à zéro sinon. ∎

*Multi-utilisateur.* Le Théorème 14-mu s'étend de la même façon, en ajoutant σ/2^|CV| avec σ total.

*Instanciation.* Pour σ ≤ 2^64 : σ/2^|CV| ≤ 2^−192 (BRUME-512p) et 2^−448 (BRUME-512-256p). Ce terme ne domine jamais, et le
Corollaire 14 bis reste valable : **128 et 256 bits, comme les profils séquentiels, sous la même politique de nonces (Corollaire 14 ter)**. Seule la quantité de données pour un même σ baisse :
132 appels pour 128 blocs de données (263 pour 256 en BRUME-512-256p), soit environ 3 %.

**Attaques exécutées sur duplex réduit** (`tests/test_aead_parallele.py`, permutation aléatoire de 20 bits, r = 8, c = 12, 20 000 essais).

| Attaque | Fréquence | Attendu |
|---|---|---|
| Une feuille altérée, CV de 3 bits (terme σ/2^|CV|) | 0,131 | 2⁻³ + 2⁻⁸ = 0,129 |
| Une feuille altérée, CV de 12 bits (terme q_d/2^τ) | 0,0038 | 2⁻¹² + 2⁻⁸ = 0,0042 |
| Deux feuilles échangées, CV de 12 bits | 0,0040 | ≈ 2⁻⁸ |

**Ce que la preuve ne couvre pas : P réelle.** La preuve idéalise P. La fourche donne à l'attaquant un état secret fixe, des
différences connues sur 64 bits et le débit en sortie, pour jusqu'à k feuilles. Elle n'ajoute pas de pouvoir par rapport au mode
séquentiel, qui permet déjà la même chose avec le nonce. Sous une même clé, l'état avant le dernier bloc de nonce est fixe ; l'attaquant
y choisit jusqu'à 192 bits (BRUME-512), et lit le débit après deux appels à P. C'est la raison du second appel (dom = 3) de la fourche :
il donne la même profondeur de deux appels, soit 64 tours, pour moins de bits contrôlés. C'est un argument de structure et non une réduction.
La cryptanalyse existante (§ 4.1, 4.2) reste la seule base pour P réelle, et ne distingue rien au-delà de quelques tours.

**Limites d'emploi.** Comme dans le mode séquentiel, un nonce répété révèle le XOR des clairs, ici feuille par feuille. Le mode est plus lent
sur les messages courts : deux appels de fourche par feuille et un coût de racine (64 octets : 13 Mo/s contre 19). Il n'a d'intérêt qu'au-delà d'environ
16 Kio, et le choix du profil est public.

## 5. Paramètres qui découlent des preuves

| | n | w | D | n₂ | sécurité ISD | δ prouvé (médiane / seuil) | pk | ct |
|---|---|---|---|---|---|---|---|---|
| Sillage-128 | 50 021 | 75 | 14 | 28 672 | 138,2 b | ≈ 2^−146 / 2^−128 | 6 285 o | 9 837 o |
| Sillage-256 | 170 003 | 140 | 28 | 114 688 | 265,1 b | ≈ 2^−289 / 2^−256 | 21 283 o | 35 587 o |

Les niveaux sont **classiques**. Estimation quantique Prange–Grover : 91,7
et 158,4 bits, sous 128 et 256 : aucun niveau quantique n'est revendiqué.
w passe de 74 à 75 et de 139 à 140 pour que tous les coûts d'attaque restent au moins ceux de la v0.3 (137,3 et 264,9 b ;
91,1 et 158,0 b) : à w égal, réduire n abaisse d'un bit environ le coût de l'élimination. `we` est le plus petit gardant
l'attaque à 3 blocs au niveau des 2 blocs.

SIG : `[n, k, w] = [2048, 1434, 103]` et `[4096, 2867, 206]`, N = 2¹², τ = 11 / 23, t = 4, `K = GF(2^{44})` et `GF(2^{48})`. Coût de
falsification 2^{128,3} et 2^{264} (§ 3.3) ; ISD 160,3 / 316,2 bits.

| | pk | sk | signature | v0.3 (Stern) |
|---|---|---|---|---|
| SIG-128 | 109 o | 464 o | **8 522 o** | 133 917 o en moyenne (×15,7) |
| SIG-256 | 186 o | 977 o | **34 867 o** | 536 326 o en moyenne (×15,4) |

*Choix.* Le code est au voisinage de la borne de Gilbert–Varshamov, solution unique attendue (`log₂ C(n, w) < r`). À ISD fixé,
la taille du témoin est `k + 2w·e` bits ; un rendement 0,7 la minimise. `n = 2^e` simplifie F. N = 2¹⁶ donnerait 6,9 Ko
pour un temps ×16.

### Comparaison des ISD (log₂ des opérations, code sans crédit quasi-cyclique)

| Code (n, k, w) | Prange | Stern | Dumer | BJMM | optimum BJMM (p, ε, l) | Grover : Prange | marche : Stern, Dumer | marche : BJMM |
|---|---|---|---|---|---|---|---|---|
| SIG-128 (2048, 1434, 103) | 208,6 | 182,6 | 182,2 | **160,3** | 52, 7, 234 | 114,4 | 92,6, 92,6 | 76,2 |
| SIG-256 (4096, 2867, 206) | 398,8 | 361,8 | 361,0 | **316,2** | 104, 14, 468 | 210,5 | 184,4, 184,4 | 151,5 |
| KEM-128 (100042, 50021, 150) | 182,4 | 159,8 | 159,8 | **154,2** | 6, 2, 78 | 107,3 | 90,9, 90,9 | 82,4 |
| KEM-256 (340006, 170003, 280) | 315,9 | 289,7 | 289,7 | **283,4** | 6, 2, 88 | 175,8 | 156,9, 156,9 | 146,5 |

Modèle : une élimination coûte n·r opérations (amortie), une opération de liste en
coûte 1. C'est volontairement favorable à l'attaquant : mémoire gratuite, y compris
2^{236} éléments pour SIG-256.

*Correctif.* La grille d'origine s'arrêtait à p ≤ 24, ε ≤ 12 et l ≤ 160, et l'optimum
de BJMM pour la SIG en touchait la borne : 160,5 et 327,2 bits étaient surestimés, de 0,8
et 12,3 bits. Les niveaux tiennent toujours (≥ 128 et ≥ 256). L'optimum est désormais
contrôlé à l'intérieur de la grille. Le KEM (p = 6) ne change pas.

*Validation sur attaques réelles* (`tests/c/isd_comparaison.c`, mêmes instances pour
chaque algorithme, chaque solution revérifiée sur H·e = s) :

| n, w | Algorithme | Itérations mesurées | Modèle | Coût mesuré | Modèle |
|---|---|---|---|---|---|
| 240, 13 | Prange | 2^{13,62} | 2^{13,49} | 2^{28,43} | 2^{28,31} |
| 240, 13 | Stern p=2, l=6 | 2^{8,57} | 2^{8,77} | 2^{23,39} | 2^{23,59} |
| 240, 13 | Stern p=4, l=11 | 2^{6,17} | 2^{6,24} | 2^{21,22} | 2^{21,29} |
| 240, 13 | Dumer p=2, l=6 | 2^{8,60} | 2^{8,63} | 2^{23,42} | 2^{23,45} |
| 240, 13 | Dumer p=4, l=11 | 2^{5,73} | 2^{5,78} | 2^{20,83} | 2^{20,87} |
| 240, 13 | BJMM p=4, l=12, ε=0 | 2^{6,73} | 2^{4,42} | 2^{21,69} | 2^{19,45} |
| 240, 13 | BJMM p=4, l=18, ε=2 | 2^{7,26} | 2^{4,93} | 2^{22,55} | 2^{20,63} |

(Mesures complètes pour n = 200, 240, 280 : `resultats/isd_comparaison.json`.)

Prange, Stern et Dumer suivent le modèle à moins de 0,3 bit, en itérations comme en
coût. BJMM demande environ 4,4 à 5 fois plus d'itérations que le modèle (2,1 à 2,3 bits) :
le modèle compte une représentation toujours trouvée, alors que le découpage équilibré et le
filtrage en perdent. Ce biais est prudent. À ces petites tailles, l'élimination domine
encore et BJMM ne rattrape pas Dumer : l'avantage de BJMM aux grandes tailles repose sur
le modèle, pas sur une mesure.

*Confrontation à un estimateur tiers* (CryptographicEstimators 2.1.1, Esser–Bellini ;
valeurs figées dans `tests/test_isd_parametres.py`) :

| Code | Prange | Stern | Dumer | BJMM | Marge minimale de notre estimateur |
|---|---|---|---|---|---|
| SIG-128 | 217,1 | 193,6 | 193,2 | 177,6 | 8,5 b |
| SIG-256 | 408,1 | 373,8 | 373,0 | 342,5 | 9,3 b |
| KEM-128 | 195,5 | 173,9 | 174,0 | 174,0 | 13,1 b |
| KEM-256 | 330,6 | 305,5 | 305,6 | 305,6 | 14,7 b |

Les coûts de cet outil comptent des opérations sur les bits, y compris la taille des
vecteurs et le coût réel de l'élimination. Notre modèle reste systématiquement en dessous :
les niveaux annoncés sont donc prudents, de 8,5 à 26 bits selon le cas et l'algorithme.

---

## 5 bis. Adversaire quantique : ce qui tient et ce qui ne tient pas

Les niveaux 128 et 256 de la suite sont **classiques**. Face à un
adversaire quantique, la situation par composant est la suivante.

| Composant | Meilleure attaque quantique générique | Niveau quantique | Modèle de preuve |
|---|---|---|---|
| Sillage-KEM | ISD accéléré. Prange–Grover : ≈ 92 / 158 bits. Marches quantiques à QRAM gratuite : ≈ 67 / 129 bits | **entre 67 et 92 / entre 129 et 158 bits** selon le modèle | FO à rejet implicite : réductions QROM connues (Jiang et al. 2018 ; Bindel et al. 2019), avec perte quadratique en q et en √δ ; non instanciées ici |
| Sillage-SIG | Grover sur la falsification, √(2^{128,3}) et √(2^{264}) | **≈ 64 / 132 bits** | QROM : Don–Fehr–Majenz–Schaffner (2019, 2022), Aguilar-Melchor–Hülsing et al. (2021, multi-tours), perte en O(q²) ; non instanciée ici |
| BRUME-AEAD | recherche de clé par Grover (k = 512 bits) : 2^{256} | ≥ 128 bits attendu, non prouvé | modèle Q1 (requêtes classiques à la construction, P en superposition) non analysé |
| Hachage | collisions quantiques génériques (Brassard–Høyer–Tapp) : 2^{c/3}, soit environ 2^{85}, avec une mémoire quantique de 2^{85} | ≈ 85 bits pour les collisions (davantage dans les modèles de coût qui comptent la mémoire) | — |

### Instanciation des réductions QROM

Les niveaux ci-dessus viennent des meilleures attaques connues. Les réductions publiées, appliquées telles quelles, **prouvent nettement
moins**. Notation : log₂ du nombre q de requêtes où la borne atteint 1. C'est une borne basse prouvée sous hypothèse, pas une attaque.

*KEM.* Forme de Hövelmanns–Hülsing–Majenz (2022), Théorème 8 et § 1, pour FO à rejet **explicite** en QROM étendu :

```
Adv^{IND-CCA} ≲ 8·q²·δ  +  4·√(d·Adv^{IND-CPA}) + 8·q/√|M|  +  12·q_D·(q_G + 4·q_D)·2^{−γ/2}
```

`Adv^{IND-CPA}` se borne par le coût des attaques connues, `T²/2^{2b}` en requêtes Grover, avec b le niveau quantique et d la profondeur.
La spreadness est rigoureuse : à `r1` fixé, `u` détermine `r2`, donc tout chiffré a une probabilité ≤ `1/C(n, w)`, pour tout h, et
`γ ≥ log₂ C(n, w)`, soit 807 et 1 631 bits : ce terme est négligeable.

| Terme (borne = 1) | Sillage-128 | Sillage-256 |
|---|---|---|
| `8q²δ`, δ ≤ `2^{−λ}` | 62,5 | 126,5 |
| `8q/√|M|`, k = λ | 61 | 125 |
| IND-CPA, b = Prange–Grover, d = q | 59,8 | 104,3 |
| IND-CPA, b = Prange–Grover, d = 2^{40} | 69,7 | 136,4 |
| IND-CPA, b = marche à QRAM gratuite, d = q | 43,2 | 84,7 |
| **Prouvé (d = q)** | **≈ 60** (43 avec QRAM gratuite) | **≈ 104** (85) |

Le terme de correction passe par FFP-CCA ≤ COR : avec la clé, le déchiffrement se simule, d'où `8q²δ`, sans facteur `q_D`, δ étant borné pour chaque clé acceptée
(§ 2.3). C'est une recherche de Grover **avec la clé secrète**, ce qu'un adversaire réel n'a pas ; il ne limite pas ici. `|M| = 2^λ` donne `q/2^{λ/2}`.

*Limite.* Sillage utilise le rejet **implicite**. Les résultats de même forme pour ce cas (Jiang et al. 2018, Bindel et al. 2019, Don et al. 2021) n'ont pas
pu être relus ici, leurs articles étant inaccessibles depuis cette machine : l'application de la borne ci-dessus reste à vérifier par un relecteur.

*SIG.* Don–Fehr–Majenz (CRYPTO 2020), Corollaire 13, pour une preuve à 2n + 1 passes, ici n = 2 :

```
Pr[le FS accepte] ≤ (2q + 3)⁴/2 · ε_int + 2/|C|,     ε_int = (p + (1 − p)/N)^τ ≈ N^{−τ}
```

D'où `8q⁴·N^{−τ} ≤ 1` : **q ≈ 2^{32,2}** et **2^{68,2}**, à comparer aux 2^{64,1} et 2^{132} de l'attaque par Grover. La perte en `q^{2n}` est
optimale pour ce théorème général (leur Corollaire 19), mais rien n'indique qu'elle soit atteinte ici, où l'attaque connue reste en `q²`.

*Limites.* C'est une esquisse. `ε_int` suppose des engagements parfaitement liants, or `H_c` est un oracle : il faudrait instancier la propriété de
*collapsing* de `H_c`. Leur Théorème 23 donne UF-CMA, et sUF-CMA si les réponses sont calculatoirement uniques (la Proposition 9 en est la version
classique), mais sans borne chiffrée, en supposant le protocole preuve de connaissance quantique, ce qui n'a pas été établi ici.

### Sillage-SIG : vérification des paramètres quantiques

Bits en requêtes, puis portes sous MAXDEPTH (`SillageSIG.security_estimate()["quantique"]`) :

| Attaque | SIG-128 | SIG-256 |
|---|---|---|
| Grover sur la falsification | 64,1 | 132,0 |
| Grover sur les graines, √(2^{8·sb}) | 68,0 | 132,0 |
| Collisions de hachés (BHT, QRAM de 2^{ℓ/3}) | 85,3 | 170,7 |
| ISD Prange–Grover | 114,4 | 210,5 |
| ISD à marche quantique (QRAM gratuite) | 76,2 | 151,5 |
| **Effectif** | **64,1** | **132,0** |
| Portes, MAXDEPTH = 2^{40} / 2^{64} / 2^{96} | 2^{114,1} / 2^{90,1} / 2^{82,4} | 2^{245,8} / 2^{221,8} / 2^{189,8} |
| Seuil AES-128 (2^{170}/MAXDEPTH) | 2^{130} / 2^{106} / 2^{74} | |
| Seuil AES-192 (2^{233}/MAXDEPTH) | | 2^{193} / 2^{169} / 2^{137} |
| **Catégorie NIST quantique** | **aucune** (manque ≈ 16 bits à 2^{40} et 2^{64}) | **3** (manque ≈ 12 bits pour la 5) |

*Comparaison à la v0.3 (Stern).* Effectif 64,0 et 128,0 ; portes 2^{113,9} et 2^{242,0} à MAXDEPTH = 2^{40} ; catégories identiques ; ISD
Prange–Grover 110,7 et 200,9 : **tout est conservé ou meilleur**, sauf une ligne qui ne limite pas le niveau : la marche
quantique sur l'ISD, avec QRAM gratuite, passe de 78,7 à 76,2 bits et de 156,7 à 151,5 bits (reste 12 et 19 bits au-dessus de
l'effectif). Les graines font λ + 8 bits pour cette raison : tester une graine ne coûte plus qu'un Keccak, contre un flux entier et
un produit H·u pour σ_π, et le coût en portes tomberait de 4 bits sans ces 8 bits.

Modèle de portes, grossier et favorable à l'attaquant : oracle de falsification de 4
Keccak-f[1600], de 76 800 Toffoli chacune (`h2` et les défis seuls sont recalculés) et de
profondeur 48 ; oracle de graine d'un Keccak ; profondeur totale limitée à MAXDEPTH par N·g·d/MD portes.

*Conséquences.*
- **SIG.** Les profils n'offrent qu'**environ la moitié** de leur niveau nominal.
- **Piste 7.** Il faudrait N^τ ≥ 2^{256}, des graines de 32 octets et, pour l'ISD, w = 204
  (n = 4 080, rendement 1/2, Prange–Grover) ou w = 278 (n = 5 560, marche à QRAM gratuite). Contrôle :
  `tests/test_isd_parametres.py :: sig_niveau_quantique`.
- **KEM.** Il n'atteint pas 128 / 256 bits quantiques en requêtes. La fourchette basse
  suppose une QRAM gratuite et prend le crédit quasi-cyclique entier (log₂ n), ce qui
  majore l'attaque : Grover n'en tire que ½·log₂ n. Le situer dans les catégories NIST
  demanderait un modèle de portes propre à ses tailles, non fait.
- **Hachage.** Avec c = 256, la résistance générique aux collisions
  quantiques est d'environ 2^{85}. Elle est de 2^{128} en classique.

---

## 6. Ce qui reste hors preuve

- La dureté de (H1-P), (H2-P) et (H3) est une hypothèse, appuyée sur les
  estimateurs ISD. Ceux-ci sont validés sur instances réduites
  (`tests/c/isd_reel.c`) : le coût réel de Prange suit la formule à 8 %
  près, et le gain quasi-cyclique mesuré égale le crédit de log₂ n de
  l'estimateur. **Prouvé (Lemme 0) :** le spectre linéaire exact de H1-P et
  de H2-P, d'où la parité de s (resp. de u) seul invariant linéaire, à
  toutes les tailles ; un distingueur linéaire revient à un problème de
  décodage, estimé au niveau de l'ISD (`tests/c/h1p_fourier.c`, heuristique).
  Aucune corrélation entre u, v et s n'est détectée aux tailles réelles
  (`tests/c/kem_distributions.c`). Restent hors preuve : les distingueurs
  non linéaires, et le transfert de H1-P des secrets uniformes aux clés
  acceptées (posé en hypothèse, § 1).
- Hachage arborescent : preuve complétée (Lemme 15, Théorème 16), relue par une IA
  et éprouvée sur modèle réduit ; **relecture humaine indépendante à faire**.
- SIG : le protocole MPC-in-the-Head et le Théorème 8 sont nouveaux en v0.4, ni audités ni relus par un tiers. Ils reprennent des
  constructions publiées (SDitH, hypercube, borne de Kales–Zaverucha) et sont exécutés sur modèle réduit (`tests/test_sig_modele.py`),
  mais l'instance binaire à rendement 0,7 et n = 2^e n'a pas d'analyse tierce propre, en dehors des ISD génériques.
- Agrégation de trails au-delà de 2 tours : on dispose de mesures et d'une
  marge, sans borne prouvée.
- Division property : la portée de la méthode est exacte (10 tours par
  sens, 20 inside-out, tout cube : Théorème 12 sexies). Ce n'est pas une attaque intégrale réelle sur 20 tours.
  Reste ouverte la portée du distingueur intégral réel, qui demanderait de compter les
  pistes modulo 2 ; aucune annulation observée sur modèle réduit (§ 4.2 bis).
- Différentielles impossibles et corrélations nulles (tronquées, motifs de poids ≤ 2) : 5 tours au plus
  (`tests/c/structure_miss.c`). Exploiter les valeurs des coefficients n'y gagne rien pour un nibble en entrée et en sortie
  (`tests/c/brume_attaques.c`) ; ce n'est pas une borne pour des motifs plus lourds, ni pour des ensembles corrélés entre nibbles.
- Boomerang (3 tours mesurés), intégrales, algébrique, structure du graphe (§ 4.2 bis) : des attaques cherchées, sans borne générale.
  Exclus en revanche, par calcul : les invariants non linéaires communs à tous les tours (critère BCLR, dim W_M(D) = 512, § 4.2 bis).
- QROM : réductions instanciées au § 5 bis, sous réserve : rejet implicite du KEM à vérifier, collapsing de `H_c` et preuve de connaissance
  quantique de la SIG non établis. Elles prouvent nettement moins que les niveaux des attaques connues (≈ 60 / 104 bits pour le KEM,
  ≈ 32 / 68 bits pour la SIG), eux-mêmes inférieurs aux niveaux nominaux. KEM multi-utilisateur non instancié.
- Mode AEAD : preuves rédigées (Théorèmes 14 et 14-mu) dans le modèle de
  la permutation aléatoire, et reliées au code par
  `tests/test_mode_aead.py`. Chaque terme est confronté à une attaque exécutée sur duplex réduit
  (`tests/test_aead_modele.py`). Elles n'ont pas été relues par un tiers.
- Duplex parallèle (§ 4.5) : même statut que le mode AEAD séquentiel, pas de relecture par un tiers. NEON : sorties
  vérifiées sous qemu ; temps constant par construction, jamais mesuré, faute de machine ARM.
- Canaux auxiliaires : BRUME-512, le KEM et la SIG en C sont
  constant-time (dudect) ; le Python ne l'est pas. Le KEM et la SIG sont en plus contrôlés par
  Valgrind (aucun branchement ni accès mémoire dépendant d'un secret, `tests/test_c_kem_valgrind.py`,
  `tests/test_c_sig_valgrind.py`). Ce sont des mesures, pas une certification.
