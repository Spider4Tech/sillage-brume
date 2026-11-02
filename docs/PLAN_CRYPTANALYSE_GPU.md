# Plan de cryptanalyse sur GPU — SILLAGE v0.4

Rédigé le 2026-11-02. Matériel : RTX 4070 Ti (12 Gio, pilote 615), Ryzen 5 5600G. Statut : **plan** ; la campagne n° 1 (différentielle-linéaire, `tests/gpu/campagne_dl.cu`) a démarré le 2026-11-02, interrompue par une instabilité matérielle du GPU.

## 0. Objectif et règles du jeu

On attaque la suite comme un cryptanalyste externe. Personne ne casse en une semaine une permutation de 32 tours sur 512 bits, ni
un ISD à 2^138. Le but réaliste est donc triple :

1. **Réduire la marge mesurée.** Trouver les meilleures attaques réelles sur des versions à tours réduits et à paramètres réduits,
   et les pousser le plus loin possible. C'est ainsi qu'on juge les candidats NIST ou Keccak (« crunchy contest »).
2. **Valider les modèles de coût à une échelle 2^15 à 2^20 fois plus grande qu'aujourd'hui.** Les ISD quasi-cycliques ne sont mesurés
   que jusqu'à n = 149 (`tests/c/isd_reel.c`). Les distingueurs de BRUME, eux, s'arrêtent à 2^36 entrées.
3. **Chercher la faille structurelle qu'aucun test à petite échelle ne peut voir.**

Règles :
- **Tout le code est en C et en CUDA C**, dans `tests/gpu/`, et rien en Python (consignes du 2026-10-29 et du 2026-10-31).
- **Chaque noyau GPU est conforme octet pour octet au C** (KAT, `sl_brume_permute_ref` tour par tour) avant toute campagne.
- **Le GPU ne tourne jamais pendant une mesure dudect** (`scripts/runspecial`, volet temps de `scripts/rundenuit.sh`).
- **Les campagnes longues sont reprenables.** Un point de reprise est écrit toutes les 10 min, le JSON est réécrit après chaque
  expérience et la puissance est plafonnée (`nvidia-smi -pl`, à voir depuis l'hôte). Une coupure ne doit plus rien coûter.
- **Les campagnes de plus de 2 h sont préparées, puis lancées par toi**, comme `scripts/rundenuit.sh`.
- **Tout correctif qui changerait les sorties (KAT) t'est soumis avant**, et rien n'est modifié dans `sillage/` sans accord.

## 1. Faiblesses inhérentes au design : où frapper

| # | Composant | Propriété du design | Pourquoi c'est une cible |
|---|---|---|---|
| F1 | BRUME | B = 8 nibbles sur 2 tours, soit **4 S-box actives par tour au minimum sur 128** | La borne prouvée est très basse (3 % des S-box). Toute la marge repose sur l'écart entre cette borne et les vrais meilleurs trails (44 actives mesurées à 3 tours, contre 12 prouvées). Cet écart n'est pas certifié. |
| F2 | BRUME | S-box de 4 bits, **degré 3**, BCT max 10/16 | Le degré croît lentement : la division property tient 10 tours par sens. Le boomerang ne coûte que 2^−0,7 par S-box au milieu. |
| F3 | BRUME | **Permutation sans clé**, constantes fixes (SHAKE) | Le modèle de Markov n'est qu'une hypothèse. Les attaques qui exploitent les valeurs réelles (différentielle-linéaire, clustering, invariants non linéaires) ne sont pas couvertes par les bornes. |
| F4 | BRUME | Couche linéaire creuse en direct (7 termes), **dense en inverse** | Asymétrie : on attaque côté direct (5 tours mesurés contre 3 en inverse). En inside-out, on met le moins de tours côté inverse. |
| F5 | BRUME | Une seule permutation pour tout : hachage, AEAD, oracles G/H du KEM, hachés de la SIG | Un distingueur sur P touche les trois primitives à la fois. Le hachage, sans clé, est le terrain de jeu le plus favorable à l'attaquant. |
| F6 | AEAD | Duplex à **réécriture**, c = 256 en BRUME-512 | Le nonce est séparé du premier flux par 2 permutations complètes, d'où une initialisation hors de portée. En phase de données, entrée et sortie du débit sont connues de part et d'autre d'une seule permutation, ce qui est le cadre de récupération d'état (1 tour déjà cassé). |
| F7 | KEM | Quasi-cyclique, très creux (w = 75, n = 50 021), bruit en cascade e1 ⊕ π(e2), v tronqué | Le crédit QC et l'estimateur ne sont validés que jusqu'à n = 149. BJMM n'est jamais mesuré à une taille où il bat Dumer. |
| F8 | KEM | δ prouvé par une borne de Chernoff à θ fixé, clés rejetées (5 % et 8 %) selon le secret | Si la borne ou sa mise en œuvre (arrondi en 2^12, seuil c > 15) était fausse, les attaques par échecs (GJS, failure boosting) redeviendraient la menace n° 1, comme pour HQC. |
| F9 | SIG | MPCitH sur SD binaire de rendement 0,7, Fiat–Shamir en 5 passes | La borne de Kales–Zaverucha n'est éprouvée que sur un modèle jouet (N = 4, τ = 3). L'instance binaire n'a jamais été analysée par un tiers (PREUVES § 6). |

## 2. Phase 0 — Infrastructure (1 session, prérequis de tout le reste)

**État au 2026-11-02 : points 1 et 2 faits.** CUDA 12.9 (`nvcc`, runtime) est installé dans `tgh`, sans bibliothèque de pilote.
`tests/gpu/brume.cuh` traite un état par fil, sans débordement de registres, et `tests/gpu/brume_gpu.cu` le contrôle
(`make -C tests/gpu && tests/gpu/build/brume_gpu`) :
- **Conformité, 4 contrôles sur 4 :** direct identique à `br_tours_avx2` pour R = 1 à 32 sur 2^20 états ; tours intermédiaires et inverse
  identiques à la référence dense `tests/c/brume_ref.h` ; aller-retour de 32 tours égal à l'identité sur 2^20 états.
- **Débit mesuré :** 2^27,26 permutations complètes par seconde, **2^29,94 à 5 tours**, 2^27,04 à 5 tours en inverse. L'inverse est plus lent,
  M⁻¹ étant dense. C'est environ 60 fois un cœur AVX2 (0,39 µs par permutation). Le découpage en tranches de bits (environ ×4 attendu) reste en
  réserve, à faire si une campagne en est limitée.

1. **CUDA dans la distrobox `tgh`.** `nvcc` y est absent. Installer `cuda-toolkit` (dépôt NVIDIA, Ubuntu 24.04, cible `sm_89`).
2. **`tests/gpu/brume.cuh` : BRUME-512 sur GPU, en tranches de bits (bitslicing)**, de 1 à 32 tours, dans les deux sens.
   - **Coût d'un tour :** la S-box en portes et M en XOR de matrices 4×4 sur GF(2), soit environ 350 opérations par état et par tour.
   - **Débit attendu :** de l'ordre de 2^30 permutations complètes par seconde et de 2^33 à 5 tours, **à mesurer**. Les registres
     sont la contrainte : on travaille en tranches de 16 ou 32 états par fil. Il existe un repli par tables en mémoire partagée.
   - **Contrôle :** conformité à `sl_brume_permute_ref`, tour par tour, sur 2^20 états aléatoires et sur les KAT.
3. **`tests/gpu/gf2.cuh` : élimination de Gauss sur GF(2) par lots** (une matrice par bloc, style M4RI), pour l'ISD.
4. **(Fait.) `scripts/rungpu`, un lanceur calqué sur `scripts/runspecial`** : `--statut`, `--arreter`, reprise, un `BILAN.md` par campagne et
   `resultats/gpu/<campagne>.json`. Il refuse de partir si `scripts/runspecial` ou dudect tourne.
5. **Témoins dans chaque campagne :** une instance à la portée connue, qui doit être détectée, et une instance aléatoire, qui ne doit
   pas l'être.

## 3. Phase 1 — BRUME, distingueurs (priorité haute : F1 à F5)

**Campagne n° 1, lancée le 2026-11-02 à 16 h 17** (`./scripts/rungpu`, `tests/gpu/campagne_dl.cu`, environ 6 h 30) : A2 et A3 sur un même
histogramme des différences alignées, 128 nibbles × 16 valeurs, d'où le χ² par nibble et les 1 920 corrélations différentielles-linéaires.
- **Contrôles :** H0 à 32 tours ; un témoin de sensibilité (biais de 2^−15 imposé sur une case, détecté à 2^32 paires : z = 6,26) ; les
  structures déterministes à 5 tours en direct et 2 en inverse, qui ne contrôlent que l'alignement.
- **Cibles :** 6 tours en direct à 2^40 paires (nibbles 0 et 77), 3 tours en inverse à 2^39, 6 tours à 2^42, 7 tours à 2^40.
- **Sensibilité :** à 2^40 paires, la campagne voit des biais d'environ 2^−19 par case.

**Constat qui réordonne A1.** Un cube simple ne gagne aucun tour grâce au GPU. Avec le premier tour gratuit (nibbles entiers), une somme
nulle demande un degré inférieur à la dimension du cube. Or le degré vaut 27 après 3 tours, ce que 2^28 entrées couvrent déjà, et 81 après 4.
Il faudrait donc des cubes de dimension supérieure à 81, alors que le GPU plafonne vers 46. A1 ne garde d'intérêt que sous des formes non
couvertes par le degré : cubes conditionnels, ou séries de cubes cherchant un biais partiel.

Au débit mesuré (2^29,9 à 5 tours), 2^44 évaluations prennent environ 5 h et 2^48 environ 3,5 jours : A1 vise donc 2^40 à 2^44 par cube, sauf passage au découpage en tranches de bits.

| Attaque | État actuel | Ce que vise le GPU | Budget |
|---|---|---|---|
| **A1. Cubes et zero-sum réels** : cubes de dimension 40 à 48, nibbles choisis par le voisinage du graphe (F4), sens direct ; zero-sum inside-out par partition | 4 tours en direct, 3 en inverse, jusqu'à 2^36 | 5 à 6 tours en direct, 4 en inverse, 9 à 10 inside-out ; mesure de l'écart réel avec la DP (10 + 10) | 2^44 à 2^48 par cube, de 1 à 9 h |
| **A2. Différentielle-linéaire** (DLCT de la S-box, corrélation mesurée sur le vrai P) : **jamais essayée sur BRUME** | — | 5 à 7 tours. C'est souvent la meilleure attaque à tours réduits sur les éponges (Ascon, Keccak), et elle exploite F3 | 2^40 à 2^46 paires par configuration |
| **A3. Différentielles tronquées alignées** et clustering | 5 tours (z = 3,2 sans alignement à 2^34) | 6 tours, à 2^44 paires | ≈ 2 h par point |
| **A4. Boomerang et rectangle** avec δ = M·nibble | 3 tours (z = 14,8 à 2^20 quartets) | 4 tours, à 2^36 à 2^40 quartets | ≈ 1 h |
| **A5. Recherche de trails assistée par GPU** : énumération exhaustive des motifs d'activité de faible poids, branch-and-bound de Matsui parallèle | CP-SAT prouve 12, 16 et 24 S-box sur 3, 4 et 6 tours (le 4r de la borne) ; meilleur trail trouvé : 44 à 3 tours | Le **vrai minimum** d'activité sur 3 et 4 tours, pour remplacer la borne 4r et certifier la marge de F1 | quelques heures |
| **A6. Invariants non linéaires et sous-espaces invariants avec les vraies constantes** (Todo–Leander–Sasaki) : recherche des fonctions g de degré ≤ 2 telles que g ∘ tour = g + constante | Sous-espaces de M seuls (16 trouvés, inoffensifs) | Vérifier qu'aucun invariant ne survit à un tour réel ; il en suffirait d'un pour casser toutes les longueurs | algèbre linéaire, ≈ 1 h |

**Ce qui serait un résultat :** un distingueur à 7 tours ou plus en direct, ou à plus de 12 tours inside-out. Il réduirait la marge
annoncée (24 tours au-delà des distingueurs mesurés) et serait publiable comme résultat de cryptanalyse.

## 4. Phase 2 — BRUME en usage réel (F5, F6)

| Attaque | Modèle | Objectif |
|---|---|---|
| **B1. Collision sur le hachage à tours réduits** : trail différentiel trouvé en A3 et A5, modification de message sur les premiers tours, paradoxe des anniversaires par points distingués sur GPU pour la fin | sans clé | **Une collision réelle sur R tours**, le résultat phare classique. Viser R = 4 à 5 |
| **B2. Préimage par structures linéaires** (Guo–Liu–Song) : choix d'un sous-espace d'entrée qui linéarise 1 à 2 tours, puis énumération GPU | sans clé | 2 à 3 tours, au lieu du seul tour cassé aujourd'hui |
| **B3. Récupération d'état du duplex à tours réduits** : devine-et-détermine, avec énumération GPU de 2^40 à 2^48 hypothèses sur la capacité, puis linéarisation | AEAD, débit connu des deux côtés | 2 tours avec 256 bits inconnus (SAT plafonne à 128), puis 3 tours |
| **B4. Attaques avec réutilisation de nonce** (hors modèle, mais un pro le mesure) : cubes sur un bloc de clair, capacité fixe | AEAD, nonce répété | Fixer le niveau de résistance aux erreurs d'usage ; à documenter comme hors revendication |

L'initialisation de l'AEAD (nonce → 2 permutations complètes → flux) est hors de portée par construction : on le documente comme une
force du design et on n'y passe pas de temps.

## 5. Phase 3 — KEM (F7, F8)

| Attaque | Ce qu'on fait | Pourquoi |
|---|---|---|
| **C1. ISD quasi-cyclique sur GPU**, Prange, Stern, Dumer puis BJMM, sur des instances à **même géométrie** que Sillage-128 (2 blocs, n premier d'Artin, densité 2w²/n = 0,225) pour n de 500 à 4 000 environ, soit 2^35 à 2^50 opérations | Courbe coût réel / modèle sur 15 bits de plus qu'aujourd'hui, extrapolée à n = 50 021 ; gain QC (DOOM, décalages) mesuré à chaque taille | Valide ou corrige les 138,2 bits. Un écart de plus de 3 bits sous le modèle à la plus grande taille imposerait de revoir n ou w |
| **C2. Attaque par échecs sur KEM réduit** : paramètres jouets à δ ≈ 2^−20 et même code RM(1,7) × D ; décapsulations en masse sur GPU (multiplications creuses) ; (a) taux d'échec réel contre la borne de Chernoff ; (b) attaque GJS et failure boosting complète jusqu'à la récupération de la clé | Nombre d'échecs nécessaire pour retrouver x, y | Si la borne est violée, même d'un facteur 2, c'est un défaut critique. Sinon, on a chiffré la marge contre la menace qui a coûté le plus cher à HQC |
| **C3. Distingueurs statistiques de H2-P à taille réelle** : corrélations u / v / s, v tronqué, loi de e1 ⊕ π(e2), sur 2^30 chiffrés au lieu de quelques millions | Tests de détection, comme `kem_distributions.c`, à une échelle ×1 000 | Vise directement le « twist » du bruit en cascade (guide § 2.1) |
| **C4. Fuite par le rejet des clés** : les clés rejetées sont-elles reconnaissables depuis pk ? Corrélation entre rejet et h ou s | Test sur 2^24 clés | Probablement nulle (0,07 bit d'entropie retirée), mais c'est une propriété spécifique à ce design : à fermer |

## 6. Phase 4 — SIG (F9)

| Attaque | Ce qu'on fait | Pourquoi |
|---|---|---|
| **D1. Falsification de Kales–Zaverucha à échelle intermédiaire** : N = 2^8, τ = 4, K = GF(2^16) à GF(2^20), t = 1 à 2 ; broyage de h1 puis de h2 sur GPU, avec le vrai vérifieur C | Coût de falsification mesuré à 2^35 à 2^42, contre le Théorème 8 | Aujourd'hui, la borne n'est éprouvée qu'à N = 4. C'est l'attaque qui fixe τ |
| **D2. ISD sur SD binaire de rendement 0,7 au voisinage de GV**, n de 256 à 640, BJMM compris | Mesurer BJMM là où il dépasse Dumer | PREUVES § 5 : « l'avantage de BJMM aux grandes tailles repose sur le modèle, pas sur une mesure ». Le GPU peut le mesurer |
| **D3. Faux témoins algébriques** : chercher des (Q, P) avec S·Q = P·F pour un S de poids > w, sur GF(2^8) à GF(2^11) | Recherche exhaustive puis aléatoire | Contrôle direct du Lemme A à la taille du vrai F_poly (vérifié aujourd'hui sur GF(8)) |

## 7. Ordre et calendrier

| Étape | Contenu | Durée GPU | Qui lance |
|---|---|---|---|
| 0 | CUDA, `brume.cuh`, `gf2.cuh`, `scripts/rungpu`, conformité, étalonnage | — | moi |
| 1 | A5, A6 (courts), puis A2 et A1 | ≈ 1 nuit | toi |
| 2 | A3, A4, puis B1 avec les trails de l'étape 1 | ≈ 1 nuit | toi |
| 3 | C1 (Prange et Stern, puis BJMM) et D2 : ces deux campagnes partagent `gf2.cuh` | 1 à 2 nuits | toi |
| 4 | C2, D1, C3, C4 | ≈ 1 nuit | toi |
| 5 | B2, B3, B4 | selon les résultats des étapes 1 et 2 | toi |

Après chaque étape : résultats dans `resultats/gpu/`, section dans `docs/RAPPORT_AUDIT.md`, mise à jour du Dossier SILLAGE, et
correction proposée si une faiblesse est trouvée.

## 8. Ce qui n'ira pas sur le GPU

- **dudect et toute mesure de temps :** on mesure le processeur, et une charge GPU ajouterait du bruit.
- **Valgrind, fuzzing guidé et KAT :** ils sont liés au CPU ou instantanés.
- **CP-SAT et SAT (division property, `dp_queue`) :** pas de solveur GPU utile. A5 remplace la partie énumérative.
