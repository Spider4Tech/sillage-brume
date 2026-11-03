# Pistes pour plus tard — performance et durcissement

Ce document recense ce qui a été **mesuré mais pas adopté**, et à quelles
conditions de sécurité chaque piste pourrait l'être. Règle : aucune piste
qui modifie l'algorithme (et donc les KAT) n'est intégrée sans l'analyse
qui la justifie.

## Ce qui est déjà en place (ne change pas l'algorithme)

| Élément | Effet mesuré | Sécurité |
|---|---|---|
| Permutation AVX2 d'un état (`br_permuter_avx2`) : S-box et log/exp de GF(16) par `vpshufb`, diffusion par rotations d'octets (structure de Cayley de D₁₂₈) | 0,41 µs au lieu de 4,4 µs (×11) ; un message seul : 79 Mio/s | **constant-time** (dudect : \|t\| < 1) ; sorties identiques |
| Permutation : table fusionnée `log∘S` | 0,39 µs (−7 %) | constant-time ; sorties identiques |
| État après P(IV) précalculé ; contexte de clé (`sl_aead_cle`) : état après absorption de la clé | message de 64 o : 3,4 → 2,7 µs ; multi-messages à clé commune : +23 % (64 o) | sorties identiques ; contexte effacé (`sl_effacer`) |
| Keccak-f[1600] déroulé (généré) | SIG ×1,7, KEM ×1,4 | conforme à `hashlib` |
| Cas de base de Karatsuba en `VPCLMULQDQ` par colonnes (seuil 40 mots) | décapsulation ×1,5 (v0.3 : 0,48 / 2,89 ms au lieu de 0,75 / 4,31) | constant-time (dudect) |
| Lots de 32 états (`br_permuter_lot`, transposition SSE) + AEAD/hachage multi-messages sur tous les cœurs | 0,19 µs par état ; AEAD-128 : 105–128 Mo/s par cœur, **624–713 Mo/s** sur 12 threads (messages ≥ 1 Kio) | constant-time ; sorties identiques |
| Décapsulation KEM : ré-encapsulation systématique, choix du secret par masque, décodage sans branchement | supprime un écart de ≈ 0,28 ms entre « échec de décodage » et « succès » | supprime l'oracle des attaques par réaction |
| Tirage creux à nombre de mots FIXE (borne de Chernoff, P(insuffisant) < 2⁻¹²⁸), acceptation sans branchement | même résultat que le tirage par rejet | supprime la fuite par nombre de rejets (« Don't Reject This », CHES 2022) |
| KEM C en représentation dense : écriture des bits par balayage masqué, produit Karatsuba + `PCLMULQDQ` | décapsulation ×2 (mesuré en v0.3 : 0,96 ms et 5,3 ms) ; 0,31 et 1,84 ms en v0.4 | **KEM C constant-time** vis-à-vis de la clé secrète et du μ déchiffré (dudect) |
| Keccak-f[1600] à 4 voies (vecteurs gcc, AVX2) pour le flux d'entiers SHAKE (4 blocs à la fois) | tirages du KEM et GGM de la SIG plus rapides (v0.3 : SIG-128 vérifiait en 12 ms au lieu de 20) | sorties identiques (conformité C/Python) |
| **SIG C constant-time** (piste 3, v0.3 sous Stern, refait pour MPC-in-the-Head en v0.4) : XOR, masques et produits sans retenue, H·x masqué | SIG-128 / 256 signe en 38,5 / 139 ms sur un cœur | dudect : tour t = −0,62, signature t = 0,12 ; témoin t = −2 039 ; Valgrind, `sig_flux` |
| **Hachage arborescent** (piste 5, `brume512_hash_arbre`, `sl_hash_arbre`) : feuilles de 8 Kio par lots de 32, racine sur les CV | 16 Mio : 160 Mo/s sur un cœur (86 en séquentiel), **785 à 850 Mo/s** sur 12 threads | nouvelle fonction, nouveaux KAT ; preuve PREUVES § 4.4 (Théorème 16) ; hachage séquentiel inchangé |
| Écriture des bits et balayages masqués en AVX2, rejet sans branchement, borne δ par table lue en `vpshufb`, API publique servie par le C (`sillage/rapide.py`) | KEM-128 keygen / encaps : 5,98 / 0,20 ms ; KEM-256 : 28,3 / 1,17 ms (v0.4 : borne sur 254 hyperplans) | dudect et Valgrind ; conformité C/Python |
| Signature et vérification en OpenMP (répartition statique), H mémorisé par thread | SIG-128 signe / vérifie : 38,5 / 38,4 ms sur un cœur, 5,9 / 5,9 ms sur 12 threads ; SIG-256 : 139 / 138 ms, 21,1 / 20,7 ms | dudect sur 1 cœur et sur tous ; sorties identiques |
| **Tailles v0.4** (change les formats) : KEM à code RM(1,7) réparti, SIG MPC-in-the-Head, nonce de 24 octets | ct 9 837 / 35 587 o (17 004 / 61 002) ; signature 8 522 / 34 867 o (133 917 / 536 326) | niveaux v0.3 conservés, δ prouvé ; PREUVES § 2.3 et § 3 ; keygen KEM ×16 et vérification SIG ×8 sur un cœur |

## Piste 1 — Duplex parallèle : FAITE

Profils `BRUME-512p` et `BRUME-512-256p` (`Brume512P`, `sl_aead_p_encrypt`), à côté des profils séquentiels, inchangés.
Le message est coupé en feuilles de 4 Kio plutôt que bloc par bloc sur 32 voies. Le découpage par feuilles passe à l'échelle
de tous les cœurs, comme le hachage arborescent, ce que 32 voies fixes ne permettaient pas ; le prix est qu'un lot n'est plein
qu'à partir de 128 Kio. Preuve : PREUVES § 4.5 (Théorème 14-p), 128 et 256 bits conservés pour σ ≤ 2⁶⁴, soit environ 3 % de données en moins.
Tests : `tests/test_aead_parallele.py`, dont les altérations entre feuilles que cette piste exigeait, et un modèle réduit.
Feuilles de 2, 4 et 8 Kio mesurées : 4 Kio donne le meilleur compromis (16 Mio : 150 Mo/s sur un cœur, 777 Mo/s sur 12 threads).
Le séquentiel reste préférable sous 16 Kio.

## Piste 2 — Moins de tours pour la phase de données

**But.** Garder 32 tours pour l'initialisation et la finalisation, et en
utiliser R_d < 32 entre deux blocs de données.

**Gain mesuré.** ×2 pour R_d = 16 (≈ 340 Mo/s par cœur avec la piste 1).

**Ce qui le permettrait (état actuel des résultats) :**
- R_d = 16 : caractéristiques ≤ 2⁻¹²⁸ et corrélation de trail ≤ 2⁻⁶⁴ (le
  carré dépasse la limite de 2⁶⁴ blocs de données) ;
- division property : portée exacte de 10 tours par sens, pour tous les
  cubes (Théorème 12 sexies), soit 6 tours de marge à R_d = 16 ;
- distingueurs empiriques ≤ 5 tours en direct.

La portée inside-out (20 tours exactement) suppose de contrôler l'état au milieu
de la permutation, ce que le duplex à clé ne permet pas.

**Conditions avant adoption.**
- Analyse dédiée de la phase de données : attaquant qui connaît le débit
  (le clair, en mode overwrite) et observe le flux ; cubes et récupération
  d'état sur R_d tours ; différentielles sur des blocs consécutifs.
- Refaire la recherche exacte (piste 6) sur la phase de données à R_d
  tours, avec un attaquant qui contrôle le débit : `tests/test_dp_exact.py`
  s'adapte en changeant le cube de départ.
- Ne pas descendre sous 16 tours en l'état.

## Piste 3 — Fuites résiduelles : FAITE pour la SIG C

La SIG C est constant-time côté signataire, avec des sorties identiques
(`sillage/c/sig.c`, contrôles dans `tests/test_c_temps.py`) :
- π n'est jamais construit. Les échanges de Fisher–Yates (tirés d'un flux
  SHAKE) sont appliqués directement aux plans de bits de u et de
  e, par un balayage masqué : y[k] = x[π(k)] est invariant par les
  échanges ;
- H·u et H·e sont masqués. Le produit des t tours est groupé, ce qui lit
  H une seule fois au lieu de t ;
- le nombre de rejets du tirage restait variable, sur les valeurs rejetées seulement.

Ce qui précède décrit la SIG à Stern de la v0.3. La SIG MPC-in-the-Head de la v0.4 ne tire plus de
permutation : ses secrets ne passent que par des XOR, des masques et des produits sans retenue
(`tests/test_c_sig_valgrind.py`, `tests/c/sig_flux.c`, `tests/test_c_temps.py`).

Restent, sans fuite de secret :
- **π du KEM** (Fisher–Yates par rejet sur σ_h) : σ_h est public ;
- **Python** : non constant-time par nature (entiers longs) ; c'est une
  implémentation de référence.

## Piste 4 — Portages SIMD : NEON FAIT, AVX-512 reste

- **ARM NEON : fait.** Permutation d'un état et lots de 16 (`vqtbl1q_u8`, `vextq_u8`), macros de diffusion générées par
  `gen_tables.py`, borne δ de la keygen, produit sans retenue par PMULL. Sorties identiques sous qemu (`tests/test_c_simd.py`). **Temps constant
  et débit non mesurés** : il faut une vraie machine ARM. Keccak y reste en vecteurs gcc, donc sans gain particulier.
- **AVX-512 (VBMI) :** 64 états par registre, permutations d'octets (`vpermb`) → environ ×2 par cœur pour les lots, et une
  diffusion horizontale plus simple. Non testable sur la machine actuelle.
- **Transposition des lots :** déjà en SSE (`tr16`), rien à gagner.
- **Faits sur x86 :** sortie de `sl_shake4` par transposition AVX2, SIG 10 % plus rapide ; campagne `nuit_cryptanalyse` sur le noyau
  AVX2, sens direct 11 fois plus rapide que les tables (2,26 ns contre 25,7 ns par tour, tous les cœurs). En sens inverse, M⁻¹ est dense et reste en tables.
- **Non retenus :** cœur du KEM et de la SIG, déjà en AVX2 ; `mini_brume` à 32 bits, plafonné par son nombre d'instances et non par le temps.

## Piste 5 — Hachage d'un seul gros message en parallèle : FAITE

`brume512_hash_arbre` (Python) et `sl_hash_arbre` (C). Feuilles de 8 Kio
hachées par lots de 32 sur tous les cœurs, racine sur les valeurs de
chaînage, domaines séparés dans la capacité (FEUILLE, RACINE, SEUL ;
domaine 0 = hachage séquentiel, inchangé). Preuve : PREUVES § 4.4
(décodable, complet, nœud final séparable → indifférentiable, 128 bits).
Test : `tests/test_hachage_arbre.py` (14 contrôles). Débit sur 16 Mio :
160 Mo/s sur un cœur, 785 à 850 Mo/s sur 12 threads.

Prolongements possibles : arbre à plusieurs niveaux (inutile avant 2⁶⁴
feuilles), taille de feuille paramétrable (B figurant déjà dans la racine,
le codage le permet sans ambiguïté).

## Piste 6 — Division property exacte, valable pour tous les cubes : FAITE

**Résultat** (`docs/PREUVES.md`, Théorème 12 sexies). La portée de la
division property vaut **exactement 10 tours par sens, et 20 tours
inside-out, pour tout cube**. Elle était encadrée par 10 ≤ portée ≤ 14
(direct) / ≤ 11 (inverse), et ces bornes hautes n'étaient établies que
pour un cube.

**Ce qui a marché.**
1. *Recollement* (`tests/test_dp_tous_cubes.py`). La première couche
   linéaire déplace librement les bits inactifs : un couplage dans le
   graphe biparti de L transporte chaque piste du cube 0 vers les 511
   autres cubes. Résultat : 13 824 pistes recollées, toutes revérifiées.
2. *Décomposition* (`tests/dp_queue.py`, `tests/test_dp_exact.py`). On
   garde le préfixe d'une piste vérifiée et CP-SAT complète les derniers
   tours vers un bit imposé, dans un modèle réduit aux bits atteignables
   et co-atteignables. Une requête prend environ une seconde, contre
   plusieurs heures pour le modèle complet. Avec des préfixes de pistes à
   12 et 13 tours, on obtient 18 pistes directes à 11 tours, puis une piste
   vers chacun des 512 bits à 11 tours dans chaque sens. Durée : 12 minutes.

**Ce qui n'a pas marché** (à ne pas retenter tel quel) :
- le modèle exact complet en CP-SAT ou en SAT (CaDiCaL), même avec des
  coupes linéaires par nibble : 1,4 million de variables, rien en 25 à
  30 minutes à 11 tours ;
- la recherche par faisceau seule : aucune piste directe à 11 tours.

**Ce qui reste ouvert.** La portée du distingueur intégral réel. Des
pistes en nombre pair s'annulent : il faudrait compter les pistes modulo 2
(prédiction de monômes complète), ce qui est hors de portée à 512 bits.
Empiriquement, les cubes s'arrêtent à 4 tours en direct et 3 en inverse.

## Piste 7 — Sillage-SIG à niveau quantique (paramétrage)

**Constat** (PREUVES § 5 bis). Grover sur la falsification coûte √(2^{128}) : SIG-128 n'offre
qu'environ 64 bits face à un adversaire quantique, et SIG-256 environ 132.

**Option.** De nouveaux profils, qui demandent **plus que doubler τ**
(vérification : PREUVES § 5 bis, `sig_niveau_quantique`) : pour 128 bits
quantiques, N^τ ≥ 2^{256}, graines de 32 octets et w = 204 (n = 4 080, Prange–Grover), ou
w = 278 (n = 5 560) si l'on compte les marches à QRAM gratuite ; hachés de 48 octets
si l'on compte BHT avec QRAM. La preuve QROM (perte en q²) serait à instancier. Ce sont de nouveaux
paramètres. Les profils actuels restent, nommés d'après leur niveau classique.

## Piste 8 — KEM sous le régime de HQC (4,4 Ko)

**Constat.** La preuve de δ (PREUVES § 2.3) majore le bruit sur S par `T1 + T2 + Te`, en ignorant les
annulations du XOR. Elle exige donc `2w²/n < 1/2`. Avec RM(1,7) réparti, le minimum prouvé est de 9,8 Ko.
Sous l'hypothèse d'indépendance des positions, le même code suffirait vers n ≈ 28 000, soit ≈ 6,5 Ko (estimation, sans
code externe), et HQC descend à 4,4 Ko avec un code de Reed–Solomon externe.

**Essayé.** Une martingale sur `W = Σ_S (−1)^{N_i}` donne une contraction exacte `E[W'] = γW` et une borne de Bennett
calculable clé par clé. Elle ignore cependant les corrélations : `|A| ≤ c` est dans le pire des cas, ce qui sature en `n²/(8w²)` et ne bat la
somme simple que pour de petits S (−50 contre −41 bits à n = 40 000, D = 8 ; −84 contre −108 à n = 45 000, D = 16).

**Conditions avant adoption.** Une borne prouvée (pas une simulation) de `Pr[W ≤ 0]` qui tienne compte des annulations, et, pour
un code externe, une borne jointe sur plusieurs blocs (le calcul clé par clé ne couvre pas les unions de supports).
Adopter HQC tel quel réintroduirait l'hypothèse retirée en v0.3.

## Piste 9 — Réduire les tailles

**Signature, découpage.** `aux` 63 et 66 %, graines 26 %, α et β 6 et 3 %, engagements 4 %. Ces champs sont uniformes (Proposition 7) : la compression
ne gagne que les bits de bourrage, 16 o au plus sur SIG-128.

**Signature, paramètres** (`tests/c/compression_sig.c`, deux termes dominants du Théorème 8 ; retrouve les coûts et les tailles du dossier). Temps estimé proportionnel à N·τ :

| N | SIG-128 | Temps | SIG-256 | Temps |
|---|---|---|---|---|
| 2¹³ | 7 896 o (−7 %) | ×1,8 | 32 260 o (−7 %) | ×1,7 |
| 2¹⁵ | 7 422 o (−13 %) | ×6,5 | 30 238 o (−13 %) | ×6,3 |
| 2¹⁶ | 7 032 o (−17 %) | ×11,6 | 27 808 o (−20 %) | ×11 |

Le gain est faible pour ce temps, et chaque variante casse le format : non adopté.

**Signature, changement de protocole : VOLE-in-the-Head sur SD régulier**, à la SDitH v2.0. C'est le seul levier de cette ampleur. Prototype mesuré (`prototypes/vole/vole_proto.c`, Ryzen 5 5600G) :

| | SIG-128 actuelle | VOLE-128 | SIG-256 actuelle | VOLE-256 |
|---|---|---|---|---|
| Signature | 8 522 o | **4 112 o (−52 %)** | 34 867 o | **15 906 o (−54 %)** |
| Clé publique | 109 o | 93 o | 186 o | 185 o |
| Signe, un cœur | 34,4 ms | 16,4 ms | 121 ms | 117,8 ms |
| Vérifie, un cœur | 34,3 ms | 13,2 ms | 121 ms | 93,5 ms |
| Signe, 12 threads | 5,5 ms | 6,4 ms | 18,4 ms | 43,9 ms |
| Vérifie, 12 threads | 6,5 ms | 4,6 ms | 17,8 ms | 23,8 ms |

Moyennes sur 5 clés × 8 messages ; médianes, p90, keygen et message de 1 Mio dans `resultats/vole_proto.json`. Mesures exploratoires, pas une caractérisation statistique. Clé publique : graine de λ bits ‖ y. H est en cache par clé ; sinon, ajouter 2,1 et 10,1 ms sur un cœur. Le temps de signature varie à cause du grinding, sur des valeurs publiques.

*Paramètres.* La réduction (SDitH, Théorème 5.1) ramène RSD `(n, k_rsd, w)` à SD `(n, k_sd, w)`, avec une perte de `log2(C(n, w)/(n/w)^w)`. Avec notre estimateur ISD (mémoire gratuite), la réduction ne garantit aux instances SDitH2 que
108,7 / 155,6 / 198,1 bits, contre 143 / 207 / 272 visés (`prototypes/vole/vole_params.c`). Ce sont des garanties par réduction, pas des coûts d'attaque (voir plus bas). Pour que la réduction tienne chez nous, il faut des codes plus longs : `(18620, 18004, 76)` et `(38456, 37232, 152)`, qui gardent les marges de la SIG actuelle (160 et 316 bits), blocs de 245 et 253, d = 4, μ = (4, 4, 4, 4). τ, κ, T_open et le grinding viennent de SDitH (τκ = 121 et 252).

*Vérifié.* Tailles exactes contre la formule de SDitH, altérations rejetées, faux témoin rejeté, et attaque exécutée sur modèle réduit : sans témoin, α annule le résidu en d points de E, Δ est cherché parmi eux, le vérifieur accepte, pour un coût mesuré de 1 235 essais contre N^τ/d = 1 024.
La spécification range les feuilles en `e·N + i` : avec cette disposition, les chemins ne fusionnent jamais et T_open n'est jamais atteint. Le prototype entrelace (`i·τ + e`), ce qui redonne la probabilité annoncée (0,19 pour 0,2).

**Conditions avant adoption** (aucune n'est remplie) :
- **Théorème EUF-CMA** à écrire pour ce protocole, avec ses propres termes ; rien de § 3 de PREUVES ne s'y transporte. Relecture humaine indispensable.
- **Coût de falsification.** Le terme γ vaut q/2^λ, et ne se règle pas par le grinding. Avec le grinding actuel, le coût est de 2^127 ; un bit de plus donne 2^127,4. Passer 2^128 demande un corps plus grand ou deux tirages de γ, à chiffrer.
- **SD régulier.** § 3 de PREUVES exclut aujourd'hui les erreurs restreintes, et la réduction contient un pas heuristique (solution unique). Attaques directes : voir le tableau ci-dessous. Elles ne menacent pas ces paramètres dans nos modèles, mais ces modèles restent à confronter aux articles complets.
- **Règles de la SIG actuelle** : graines de λ + 8 bits, sel de 32 octets. Le prototype suit SDitH (λ bits). S'y aligner donne environ 4 235 et 16 122 o.
- **Temps constant** : `keygen` et le témoin parcourent désormais tous les blocs sous masque. ctgrind ne détecte rien sur le modèle réduit, seulement (μ = 2, donc sans contrainte de paires) ; son témoin à branchement est détecté. Ni le profil complet, ni dudect, ni le code machine des autres compilateurs ne sont vérifiés.
- **Implémentation de production** : erreurs propagées au lieu de `abort` (mémoire, aléa), injection de ces échecs, dudect, référence indépendante. **QROM** : non analysé.
- **Paramètres** : c'est le meilleur point d'une grille (d = 4, n ≤ 40 000), pas un optimum global ; la monotonie n'est qu'échantillonnée. L'affinage autour du minimum ne gagne que 0,3 % (4 101 o, w = 75) : paramètres inchangés.

*Revue de code (`docs/REVUE_CODE_VOLE.md`).* Traité : V-01 (clé publique de 93 o désormais exacte : graine de λ bits et encodage canonique), V-02 et V-06 (grammaire unique, entiers en petit-boutiste, H4 égale à quatre appels scalaires), V-03 (`siglen`), V-05 (chemins secrets ci-dessus), V-07 (H en cache liée à sa graine), V-08 (effacements), V-09 (code de retour : 1 si un contrôle échoue, 2 si les résultats ne sont pas écrits), V-10 (voir ci-dessous), V-11, V-12, V-14. Partiel : V-04 et V-13, allocations vérifiées et arrêt franc, sans propagation d'erreur ni injection d'échec. Le fichier reste d'un seul tenant.
Contrôles ajoutés : `fmul` contre une référence bit à bit, arbres réduits exhaustifs, contraintes signataire et vérifieur égales sur témoins valides et invalides, chaque frontière de champ, longueurs invalides, KAT identiques sur x86-64 et ARM64 (qemu), fuzzing sous ASan et UBSan (`--fuzz`).

**Attaques directes sur SD régulier** (`tests/c/rsd_attaques.c`, log₂ des opérations, mémoire gratuite) :

| Famille | VOLE-128 (visé 160) | VOLE-256 (visé 316) | SDitH2-L1 (visé 143) |
|---|---|---|---|
| ISD régulier : Prange / Dumer / BJMM de profondeur 2 | 384,6 / 300,0 / 282,4 | 756,0 / 601,3 / 564,4 | 269,1 / 209,8 / 196,4 |
| ISD sans structure / avec les w équations de régularité | 269,2 / **266,1** | 539,5 / **532,8** | 188,4 / **185,5** |
| Combinatoire : rencontre au milieu | 301,6 | 606,7 | 210,9 |
| Algébrique hybride (ω = 2) | 373,2 | 746,5 | 258,8 |
| **Meilleure, marge sur le visé** | **266,1, +106** | **532,8, +217** | **185,5, +43** |

L'anniversaire généralisé n'a pas de listes assez grandes : l'instance a une solution unique. Structure : H vient de SHAKE, sans structure quasi-cyclique ; la forme `[H' | I]` n'a pas d'effet mesuré (3 138 itérations de Prange régulier réel contre 2 846 sur H dense, modèle 2 557) ; colonnes distinctes et denses.

*Lecture.* La réduction limite ces paramètres, pas les attaques directes : les marges dépassent les gains publiés (≈ 30 bits pour l'ISD régulier d'Esser–Santini et pour l'hybride algébrique de Kim et al., sur d'autres paramètres). SDitH2 tient donc aussi face aux attaques connues ; c'est sa garantie par réduction qui ne tient pas dans notre modèle de coût, plus favorable à l'attaquant.

*Limites.* Ces modèles sont les miens, écrits d'après les résumés : je n'ai pas lu les articles complets, et ni la répartition non uniforme des devinettes (Kim et al.) ni la profondeur 3 n'y sont. Validation réelle : Prange régulier, et linéarisation sur 8 petites instances, toutes de degré 2, alors que VOLE-256 prédit le degré 3. Le coût de BJMM et de Dumer réguliers n'est pas confronté à une attaque réelle.

**KEM** (`tests/c/compression_kem.c`, vraie borne δ sur de vraies clés, D, w et θ variables, aucun coût d'attaque sous la v0.3). Avec le critère de choix actuel (5 % de clés
au plus au-delà de 2^−(λ+8)), le gain va de 0 à 0,6 % selon l'exécution, car les clés sont tirées au hasard. En acceptant jusqu'à 10 % de rejets au seuil 2^−λ : environ 9 710 o (−1,3 %, D = 12, θ = 0,8) et 34 800 o (−2 %, D = 22 à 24), mais n et donc pk augmentent
(environ 6 670 et 23 500 o). Baisser D oblige à monter n : les paramètres actuels sont déjà au bon endroit. Non adopté ; seule la piste 8 peut changer l'ordre de grandeur.

## Piste 10 — Noyaux de BRUME-512 : bilan de performance et suites (2026-11-03)

Mesures sur Ryzen 5 5600G (Zen 3), un cœur, gcc 13.3 `-O3 -march=native`, compteurs matériels (`perf_event_open`, cycles
cœur réels). Tout BRUME repose sur deux noyaux : les modes séquentiels (AEAD, hachage, TE : 87 Mo/s) ne coûtent rien de plus que
la permutation d'un état ; les modes par lots (multi-messages, arbre, duplex parallèle : 125 à 160 Mo/s par cœur) sont
limités par le noyau de lots.

| Noyau | Mesure | Limite |
|---|---|---|
| `br_tours_avx2` (un état, 32 tours) | 1 623 cycles, 50,7 par tour, 6 269 instructions, IPC 3,86 | ports FP : ≈ 176 opérations vectorielles par tour pour un plancher de 168, soit 42 cycles à 4 par cycle |
| `br_permuter_lot` (32 états) | 849 cycles par état, 26,5 par état et par tour, IPC 3,53 | chargements : ≈ 1 250 par tour (897 `vpshufb` à opérande mémoire, tables `TG` rechargées), 2 par cycle |

Débits de ce cœur, mesurés : `vpaddb`, `vpminub`, `vpxor` 4 par cycle ; `vpshufb`, `vpalignr` 2 ; `vperm2i128` 1 ;
chargement de 256 bits 2. Pas de GFNI ni d'AVX-512 sur Zen 3.

**Un état : rien à gagner en AVX2.** Par arête et par registre, il faut une rotation, `add`, `sub`, `min`, `vpshufb` et
`xor`. La réduction modulo 15 (`sub` et `min`, un tiers des opérations) ne se supprime pas : une somme de deux logarithmes
couvre [0, 28], qu'aucune table de 16 entrées lue par `vpshufb` ne sait réduire en une instruction. Essayés sans gain :
- clang 18 : +2 % (un état), +26 % (lots) ;
- accumulation regroupée par registre de destination : 10 % d'instructions en moins, même durée (IPC 3,4) ;
- constante 15 masquée au compilateur, qui la repliait en une seconde constante lue en mémoire ;
- partage explicite des `vperm2i128` ; `-fno-schedule-insns` ;
- deux états entrelacés : −3 % seulement (1 569 cycles), ce qui confirme que le noyau est limité par le débit, pas par
  la latence.

**Un état avec GFNI (Zen 4, Intel Ice Lake et suivants) : environ ×2, à mesurer.** GF(16) (polynôme 0x13) est un
sous-corps de GF(2⁸) (polynôme 0x11B de `gf2p8mulb`). Le plongement φ est linéaire sur GF(2) et respecte le produit :
- la S-box peut sortir directement φ(S(x ⊕ rc)) par `vpshufb` ;
- chaque arête devient rotation, `gf2p8mulb` par φ(c) et `xor` (3 opérations au lieu de 6) ;
- φ⁻¹ se fait par un `gf2p8affineqb` par registre et par tour.

Estimation : ≈ 88 opérations par tour au lieu de 168. Avec AVX-512 VBMI, une moitié d'état tient dans un registre et
chaque rotation devient un `vpermb` : ≈ 46 opérations. Non mesurable sur cette machine ; la conformité pourrait se vérifier
sous émulateur (Intel SDE). Voir aussi la piste 4.

**Lots : prototype bitslicé sur 256 états, conforme, −26 %.** Un registre porte un bit de l'état pour 256 états
(plan p = 4·nibble + bit, 16 Kio par état de lot). La multiplication par une constante de GF(16) devient une matrice
binaire 4 × 4, soit quelques XOR, sans table. Au total, 7 146 XOR par tour.
- **S-box en 25 opérations** (décomposition de Shannon sur x₃, `vpandn`), vérifiée sur ses 16 entrées. Le circuit rend
  S(x) ⊕ 8. Le complément du bit 3 est absorbé dans les constantes du tour suivant, puisque M·(y ⊕ e) = M·y ⊕ M·e, et
  compensé en sortie du dernier tour.
- **Tour généré en assembleur**, allocation de registres explicite. Un plan source n'est chargé qu'une fois : opérande
  mémoire s'il sert une fois, registre sinon. Résultat : 4 096 chargements, ≈ 10 900 opérations vectorielles et
  14 500 instructions par tour.
- **Mesure :** sorties identiques à `sl_brume_permute` sur 256 états aléatoires ; **630 cycles par état au lieu de 849**.
  La transposition vers et depuis les plans n'est pas comptée (estimée à 5 à 10 % de plus).

Étapes du prototype, en cycles par état :

| Étape | Cycles par état |
|---|---|
| ANF naïve, code C déroulé | 924 |
| Barrière par nibble (gcc réordonnait les blocs : 680 débordements, 18 Ko de pile) | 680 |
| S-box à 25 opérations | 651 |
| Assembleur généré | 630 |

Essayés sans gain :
- deux ou trois accumulateurs par plan : +4 à +6 %, ce n'est pas la latence ;
- empreinte des sources réduite : −2 %, ce n'est pas la L1D ;
- chaque bloc rejoué sur deux groupes de 256 états : +7 %, les données (64 Kio) débordent de la L1D.

**Limite actuelle : le frontal.** Un tour déroulé fait ≈ 95 Ko de code, plus que la L1i (32 Kio) et le cache
d'opérations. Le même nombre d'instructions rejouées depuis un petit bloc passe en 3 145 cycles par tour au lieu de 6 300
(IPC 4,6 au lieu de 2,9).

Suites possibles :
- **réduire le nombre de XOR** (algorithme de Paar, local à chaque nibble : 4 lignes sur 28 plans), gain estimé de 15 à
  20 % ;
- **encodages plus courts** (pointeurs par générateur, déplacements sur 8 bits) : ≈ −11 % de code seulement.

**Conditions d'adoption :**
- **utile seulement à partir d'environ 180 états par cœur.** Un arbre de 1 Mio n'a que 128 feuilles et y serait plus
  lent. L'ancien noyau resterait pour les petits lots ;
- **aucune sortie ne change** : le format ne fixe pas la largeur des lots de l'arbre ni du duplex parallèle ;
- **temps constant par construction** (opérations booléennes seulement), mais dudect est à refaire ;
- **95 Ko de code généré** à maintenir : le générateur en C serait le seul source.

Prototype : `prototypes/brume_bitslice/` (générateur `gen_asm.c`, S-box `sbox_bs.h`, banc `banc.c`, qui refait les contrôles et les mesures).

## Essayé et écarté

- **BLAKE3 à la place de SHAKE256 dans le KEM et la SIG :** mesuré sur une copie (BLAKE3 1.5.5, AVX2). En appel isolé il est 3 fois plus rapide sur 64 o, mais la SIG hache par lots de quatre (SHAKE : 97 ns par haché, BLAKE3 : 83 ns), et elle ralentit : signature 42,3 contre 34,4 ms à 128 bits (8 voies internes non testées, l'API publique ne les expose pas). KEM : gain d'environ 8 à 10 % à 128 bits, décapsulation 0,28 contre 0,32 ms. Son gain de ×7 ne vaut que sur les gros messages, que le KEM et la SIG ne hachent pas. Sécurité : niveau de 128 bits au plus, donc incompatible avec les hachés de 2λ bits du profil 256 ; 7 tours et moins de recul que SHAKE ; casse tous les KAT. Non adopté.
- **Lots de 64 états (deux registres par nibble) :** 268 ns par état
  contre 196 pour les lots de 32. La pression sur les registres annule le
  gain sur les chargements de tables.

## Déconseillé

- **Réduire la capacité sous 256 bits pour agrandir le débit :** gain de
  25 % au plus, et perte de la borne générique M·N/2^c.
- **Alléger la diffusion ou uniformiser ses coefficients :** cela détruit
  l'asymétrie du graphe pondéré (128 couleurs de Weisfeiler–Lehman), qui
  est au cœur du concept, ainsi que B = 8.
- **Changer de S-box pour gagner en vitesse :** en vectoriel, toute S-box
  de 4 bits coûte une seule instruction. En bitslicé (piste 10), celle-ci coûte 25 opérations sur 4 plans,
  environ 20 % d'un tour : un circuit plus court se cherche à S-box fixée, sans toucher aux KAT.
