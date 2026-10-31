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

## Essayé et écarté

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
  de 4 bits coûte une seule instruction.
