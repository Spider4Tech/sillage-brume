# SILLAGE — suite cryptographique expérimentale par décodage bruité

**Prototype de recherche — version 0.4.0 — Python 3.10+, numpy ; une
implémentation C conforme (`sillage/c/`, gcc) ; la batterie de tests utilise
en plus `networkx` (pistes de division property), gcc avec OpenMP (tests
intensifs) et, si présent, `matplotlib`.**

> ⚠️ **AVERTISSEMENT** : ce code est un objet de recherche. Les paramètres
> sont préliminaires, la conception n'a pas subi de cryptanalyse tierce, et rien de
> tout cela ne doit être déployé en production. Il est en revanche conçu pour
> être **lu, attaqué, mesuré et itéré** — c'est sa fonction.

---

## 1. Identité du design

SILLAGE est une suite complète (KEM + chiffrement symétrique + signatures)
unifiée par un seul paradigme :

> **Tout secret vit de l'autre côté d'un canal bruité.** L'adversaire doit
> décoder un canal aléatoire (décodage de syndrome — NP-dur, 45 ans de
> cryptanalyse ; les meilleures attaques quantiques connues sont des ISD
> accélérés par Grover) ;
> le détenteur de clé décode un canal structuré (facile pour lui).

Principe d'ingénierie directeur : **« nouveauté à dégradation sûre »**.
Chaque composante non standard est conçue pour que, si elle était cassée,
elle s'effondre vers le problème dur le mieux étudié — jamais vers une
faiblesse inconnue. Aucune structure nouvelle ne porte la sécurité.

### Pourquoi ces fondements (et pas d'autres)

| Famille | Verdict 2022-2025 |
|---|---|
| Isogénies (SIKE) | morte — cassée en ~1 h sur PC mono-cœur (Castryck–Decru, 2022) |
| Multivarié (Rainbow, GeMSS) | morte (Beullens, 2022) |
| Non-commutatif (tresses, AAG) | morte |
| Chaos / automates cellulaires | track record cryptanalytique désastreux — écarté |
| Réseaux euclidiens (Kyber/Dilithium) | solides mais = le standard actuel (écarté par l'énoncé du projet) |
| **Décodage de codes aléatoires (LPN creux, syndrome)** | **45+ ans, NP-dur, quantum-résistant, sous-exploité** |

---


## 2. Arborescence

```
orion/
├── README.md            ce document
├── docs/
│   ├── guide.md         note de conception d'origine (paradigme SILLAGE)
│   ├── RAPPORT_AUDIT.md audit v0.2 → v0.3 : failles, corrections, preuves
│   ├── PREUVES.md       preuves de sécurité (KEM, SIG, BRUME, mode)
│   ├── PISTES.md        pistes mesurées mais non adoptées (performance, durcissement)
│   ├── AUDIT_EXTERNE.md audit externe (Codex) et réponse point par point
│   └── historique/      rapports d'audit antérieurs
├── sillage/             le paquet (v0.4.0)
│   ├── sillage_common.py   anneaux, creux, permutations, estimateurs ISD
│   ├── sillage_kem.py      Sillage-KEM (LPN creux QC + FO)
│   ├── brume512.py         BRUME-512 : permutation, AEAD duplex, TE, hachage
│   ├── brume512_tables.py  tables figées (S-box, graphe, coefficients)
│   ├── select_params.py    curation reproductible des tables
│   ├── sillage_sig.py      Sillage-SIG (MPC-in-the-Head à hypercube)
│   ├── demo.py             scénario bout en bout
│   ├── rapide.py           API publique servie par le C (repli Python avec avertissement)
│   ├── sillage_c.py        accès Python (ctypes) à l'implémentation C
│   └── c/                  implémentation C : brume512.c, brume512_avx2.c
│                           (noyaux AVX2 et NEON, lots, AEAD parallèle), kem.c, sig.c, isd.c
│                           (estimateurs), commun.c (SHAKE256), bench.c,
│                           Makefile ; en-têtes générés
│                           par gen_tables.py : brume512_tables.h, brume512_simd.h
├── tests/               batterie de tests et de cryptanalyse (run_all.py)
│   ├── noyau_c.py          pont ctypes vers le noyau C (compilation, conformité)
│   └── c/noyau.c           noyau C/OpenMP des tests intensifs (build/ : cache)
└── resultats/           sorties : <test>.json, SYNTHESE.md, logs/, bench_perf.txt,
                         BENCH_TAILLES.md, BENCH_C.md, pistes_division.json (cache)
```

## 3. Utilisation

```bash
python3 -m sillage.demo                 # scénario bout en bout
python3 -m tests.run_all                # batterie complète → resultats/SYNTHESE.md
python3 -m tests.run_all aead kem       # sous-ensemble
python3 -m tests.bench_perf [--quick]   # performances → resultats/bench_perf.txt
python3 -m tests.bench_tailles          # débit par taille → resultats/BENCH_TAILLES.md
python3 -m tests.noyau_c                # conformité et débit du noyau C
python3 -m tests.bench_c                # benchmark de l'implémentation C → resultats/BENCH_C.md
python3 -m tests.empreintes             # empreintes SHA-256 (sources, KAT, résultats) → resultats/EMPREINTES.md
make -C sillage/c                       # bibliothèque C (build/libsillage.so) + build/bench
SILLAGE_INTENSITE=8 python3 -m tests.run_all c_integral c_sac   # tests C poussés ×8
python3 -m sillage.select_params 1 && python3 -m sillage.select_params 2   # tables
```

```python
from sillage import SillageKEM, Brume512, Brume512P, brume512_hash, brume512_hash_arbre, SillageSIG

kem = SillageKEM("Sillage-128")
pk, sk = kem.keygen()
ct, ss = kem.encaps(pk)
assert kem.decaps(sk, ct) == ss

br = Brume512("BRUME-512", key=ss * 2)                # clé 64 octets
c, tag = br.encrypt(nonce24, message, aad=b"ctx")
p = br.decrypt(nonce24, c, tag, aad=b"ctx")           # lève Brume512TagError
ct, pars, tag, meta = br.encrypt_te(nonce24, message)
pt, corriges = br.decrypt_te(nonce24, ct, pars, tag, meta)

brp = Brume512P("BRUME-512p", key=ss * 2)             # gros messages : tous les cœurs, autres chiffrés
c, tag = brp.encrypt(nonce24, gros_fichier)

h = brume512_hash(b"empreinte", 32)
h2 = brume512_hash_arbre(gros_fichier, 32)            # parallèle (C : sl_hash_arbre)

sig = SillageSIG("Sillage-SIG-128")
pk_s, sk_s = sig.keygen()
s = sig.sign(sk_s, pk_s, message)
assert sig.verify(pk_s, message, s)
```

Ces classes sont servies par le C (`sillage/rapide.py`) et reviennent au Python,
avec un avertissement, si la bibliothèque ne se compile pas. Les classes de
référence restent dans `sillage_kem`, `sillage_sig` et `brume512` ; elles servent
de contre-épreuve à `test_c_impl` et `test_api_c`. La bibliothèque est compilée
en `-march=native` : elle n'est valable que sur le CPU qui l'a construite, et
son empreinte de cache inclut les drapeaux du CPU. Ne pas appeler `fork()` sans
`exec` après une signature ou une vérification (OpenMP) : un fils qui rappelle
ces fonctions peut se bloquer.

---

## 4. Architecture (v0.4.0)

### 4.1 Sillage-KEM (`sillage_kem.py`)

- **Anneau** `R = F2[z]/(z^n − 1)`, `n` **premier d'Artin** (2 générateur,
  vérifié par les tests).
- **Clés** : `sk = (x, y)` creux (poids w), `pk = (σ_h, s = x·h ⊕ y)`.
- **Chiffrement déterministe** : `(r1, r2, e1, e2)` dérivés de `(μ, H(pk))` ;
  `u = r1·h ⊕ r2`, `v = cw(μ) ⊕ r1·s ⊕ e1 ⊕ π(e2)` ; le déchiffrement annule
  exactement les `r1·x·h` : `v ⊕ u·x = cw(μ) ⊕ r1·y ⊕ r2·x ⊕ e` (tout creux).
- **Transformée FO à rejet implicite** : `decaps` décode μ, **ré-encapsule**
  et compare ; tout écart → secret pseudo-aléatoire lié à `σ_rej`.
- **Code** RM(1,7) répété D fois par une répartition publique : un bloc de 128·D bits porte un
  octet de μ, décodage à maximum de vraisemblance (transformée de Walsh). Il remplace en v0.4 le
  code à répétition (`d = 531` et `953`), à preuve équivalente : le chiffré est divisé par 1,7.
- **δ-correction PROUVÉE** : borne de Chernoff rigoureuse sur les bascules
  (`borne_echec_log2`, sans hypothèse d'indépendance des bits) ; `keygen`
  rejette toute clé dont la borne dépasse `2^−λ` (5 et 8 % des tirages).
- **Cascade de bruit** `e1 ⊕ π(e2)` : conservée comme objet d'étude, mais
  **neutre** pour la sécurité — π étant publique, `π(e2)` suit la loi de
  `e2`. La sécurité repose entièrement sur `(r1, r2)` et `(x, y)`.

| Profil | n | w | D | pk | ct | sécurité classique | quantique (Prange-Grover) | δ prouvé (clé médiane) |
|---|---|---|---|---|---|---|---|---|
| Sillage-128 | 50 021 | 75 | 14 | 6 285 o | **9 837 o** | **138,2 b** | 91,7 b | ≈ 2⁻¹⁴⁸ (seuil 2⁻¹²⁸) |
| Sillage-256 | 170 003 | 140 | 28 | 21 283 o | **35 587 o** | **265,1 b** | 158,4 b | ≈ 2⁻²⁹⁴ (seuil 2⁻²⁵⁶) |

v0.3, avec le code à répétition : ct de 17 004 et 61 002 o, pk de 8 540 et 30 538 o, 137,3 et 264,9 b, 91,1 et 158,0 b.
HQC-128 atteint 4,4 Ko, mais son taux d'échec repose sur une hypothèse d'indépendance que la preuve
de la v0.3 a retirée ; on ne le suit pas sur ce point (`docs/PREUVES.md` § 2.3, `docs/PISTES.md` piste 8).

Sécurité = min(récupération de clé, de message) : ISD concret (Prange,
Stern, Dumer, BJMM profondeur 2, paramètres optimisés) sur le code QC
`[2n, n]` de poids `2w`, moins `log2 n` (rotations) ou `log2(n)/2` (DOOM),
et attaque à 3 blocs `(u, v)` de densités inégales (aucun gain mesuré).
`n` est le plus petit premier d'Artin (à ~5 % près, vérifié par
`tests/test_isd_parametres.py`) tel que sécurité ≥ celle de la v0.3 **et** δ prouvé
≤ 2^−(λ+8) pour une clé typique. Preuves IND-CPA → IND-CCA (FO à rejet
implicite) et δ-correction : `docs/PREUVES.md`.

**Nommage et niveau quantique.** Les profils sont nommés d'après leur
niveau **classique** (ISD concret). L'estimation quantique Prange–Grover
(91,7 et 158,4 bits, sans contrainte de profondeur) est **inférieure** à
128 et 256 : les profils ne revendiquent pas 128 et 256 bits contre un
adversaire quantique. Les situer dans les catégories NIST demanderait un
modèle de coût en portes quantiques, non fait (`docs/AUDIT_EXTERNE.md`,
point 5).

**Hypothèses avec parité.** L'anneau se décompose en F2 × F_{2^{n−1}} :
la parité de s et de u est une fonction publique de h et de w mod 2. Les
hypothèses décisionnelles sont donc formulées « avec parité » (H1-P,
H2-P, comme HQC). La formulation initiale, sans parité, était
distinguable avec un avantage de 1/2 (audit externe, point 1). Le schéma
et ses sorties sont inchangés.

### 4.2 BRUME-512 (`brume512.py`)

1. **État** : 512 bits = 128 nibbles de GF(16) = GF(2)[x]/(x⁴+x+1).
2. **S-box 4 bits optimale** : U = 4, NL = 4, sans point fixe ni structure
   linéaire, degré 3 sur toutes les composantes, auto-équivalences triviales.
3. **Diffusion** `v' = M·v`, support `A ⊕ I` d'un graphe de Cayley
   6-régulier **non abélien (D₁₂₈)**, engendré par 6 réflexions, donc
   **biparti** (valeurs propres triviales ±6) ; Ramanujan sur les 126
   autres (λ\* = 3,5076 < 2√5) ; coefficients GF(16)\* pondérés arête par
   arête ; **branch number B = 8 certifié exactement** (différentiel et
   linéaire). Support de la diffusion : 7, 37, 94, 127 puis 128 nibbles,
   soit une **diffusion complète en 5 tours** (2 en inverse), certifiée par
   `diffusion_support`.
4. **32 tours**, constantes SHAKE256 (anti-slide).
5. **Hachage** : sponge débit 256 / capacité 256. **Hachage arborescent**
   `brume512_hash_arbre` (nouvelle fonction, nouveaux KAT) : feuilles de
   8 Kio hachées en parallèle, racine sur les valeurs de chaînage, domaines
   séparés dans la capacité ; indifférentiable (PREUVES § 4.4), 128 bits.
   **Statut : preuve complétée, relue par une IA et éprouvée sur modèle réduit ;
   relecture humaine indépendante à faire** (`docs/PREUVES.md` § 4.4).
6. **AEAD duplex à clé, entièrement sur la permutation**, nonce de **24 octets** (comme XChaCha20 : collision en `q²/2¹⁹³` s'il est tiré au hasard, ce qui suffit à BRUME-512 jusqu'à 2⁶⁴ messages ;
   **BRUME-512-256 exige des nonces uniques pour ses 256 bits**, PREUVES Corollaire 14 ter) : IV(profil) → absorption clé ‖ nonce → AAD (10*, domaine) → chiffrement (dernier bloc
   toujours partiel, bourrage 10*) → domaine « texte » → bloc de longueur
   (domaine « final ») → tag extrait par blocs de débit. **Duplex parallèle** `Brume512P`
   (profils `BRUME-512p`, `BRUME-512-256p`, autres chiffrés) : feuilles de 4 Kio, chacune suivie par son duplex à clé issu d'un
   tronc (clé, nonce, AAD), états finaux absorbés par le tronc. Mêmes niveaux pour σ ≤ 2⁶⁴
   (PREUVES § 4.5, Théorème 14-p). **Statut : preuve rédigée et éprouvée sur modèle réduit ; relecture humaine indépendante à faire.**
   Intéressant à partir d'environ 16 Kio ; en dessous, le profil séquentiel est plus rapide.

| Profil | débit | capacité | tag | λ (duplex à clé, M ≤ 2^(c−λ) blocs) |
|---|---|---|---|---|
| BRUME-512 | 256 b | 256 b | 128 b | 128 |
| BRUME-512-256 | 128 b | 384 b | 256 b | 256 (clé 512 b → 2²⁵⁶ après Grover) |

7. **Mode TE** : parités SEC-DED par bit-plan (+10,9 %) : corrige 1 octet
   par bloc de 64, détecte les altérations multiples **accidentelles**. Les
   parités ne sont pas authentifiées : face à un adversaire, seul le tag
   garantit l'intégrité (vérifié par les tests).

### 4.3 Sillage-SIG (`sillage_sig.py`)

- **MPC-in-the-Head** à la SDitH sur le décodage de syndrome **binaire** `H·x = y`, `wt(x) ≤ w`, `H = [H' | I]` :
  même hypothèse (H3) qu'en v0.3, où le protocole de Stern donnait 134 et 536 Ko. `sk = x_A ‖ Q ‖ P`, avec
  `S·Q = P·F` sur `GF(2^e)`, `n = 2^e` ; vérification en t points de `GF(2^{ep})` par un triplet de Beaver.
- **Hypercube** : N = 2¹² feuilles, une seule graine cachée (solidité 1/N), D + 1 simulations par répétition.
- **Fiat–Shamir à 5 passes** : `sel ‖ h1 ‖ h2 ‖ (chemin ‖ engagement ‖ aux ‖ α ‖ β)` par répétition, longueur fixe.
  Graine maîtresse couverte par `(sk, sel, m)` : un aléa défaillant ne répète pas les graines.

| Profil | (n, k, w) | τ | pk | sk | signature | ISD | falsification |
|---|---|---|---|---|---|---|---|
| SIG-128 | (2048, 1434, 103) | 11 | 109 o | 464 o | **8 522 o** | 160,3 b | 128,3 b |
| SIG-256 | (4096, 2867, 206) | 23 | 186 o | 977 o | **34 867 o** | 316,2 b | 264 b |

v0.3 : 133 917 et 536 326 o en moyenne, ISD 159,7 et 314,9 b. Le niveau tient aussi aux graines de `λ + 8` bits
et aux hachés de 2λ bits, et le paramétrage suit l'attaque de Kales–Zaverucha (faux positif, puis partie cachée) :
voir `docs/PREUVES.md` § 3. **Le protocole est nouveau en v0.4, et n'a été relu par aucun tiers.**

---

## 5. Cryptanalyse — batterie de tests (`tests/`)

`python3 -m tests.run_all` exécute tout en parallèle ; chaque test écrit
`resultats/<test>.json` (contrôles booléens + mesures). Synthèse :
`resultats/SYNTHESE.md`.

| Test | Contenu |
|---|---|
| `test_fonctionnel` | auto-tests, KAT (hachage, AEAD), empreintes des tables, aller-retours, démo |
| `test_aead` | toutes altérations (bit par bit, extension, troncature, tag, nonce, AAD, clé) sur toutes les longueurs jusqu'à 3 blocs, régression collision longueur/bloc final |
| `test_te` | correction à chaque position, 2 erreurs/bloc, métadonnées, parités tronquées/recalculées |
| `test_hachage` | padding injectif exhaustif, extensions, unicité, XOF, anniversaires 20 bits, quasi-collisions |
| `test_branch_exact` | certificat exact B = 8 (M, M⁻¹, Mᵀ, (Mᵀ)⁻¹, poids ≤ 3), conjugaison par la trace |
| `test_banc_cryptanalyse` | statiques S-box/graphe, trails différentiels/linéaires gloutons (exhaustif poids ≤ 2), sondes Monte-Carlo, bornes wide-trail |
| `test_diff_lin_empirique` | validation expérimentale DDT/LAT/adjoint sur 1 tour, effet de regroupement sur 2 tours |
| `test_cycles` | caractéristiques itératives (v1 vs témoin v0 non pondéré) |
| `test_beam_trails` | recherche de trails par faisceau au-delà du glouton |
| `test_integral_degre` | cubes de nibbles et de bits, intégrale 2²⁰, bornes de degré (Boura–Canteaut), zero-sum inside-out |
| `test_symetries_invariants` | translations du groupe, Weisfeiler-Lehman, constantes, sous-espaces invariants, auto-équivalences, ordre de M |
| `test_diffusion_stats` | support, avalanche par tour, SAC 512×512 à 32 tours, inverse, batterie statistique (flux AEAD, hachage, compteur) |
| `test_kem` | correction, marge de décodage mesurée, FO, rejet implicite, entrées malformées, densité pk |
| `test_sig` | correction, rejets, non-fuite du témoin, tricheur à préimage dense, uniformité des défis |
| `test_isd_parametres` | cohérence des estimateurs, sécurité et minimalité des paramètres |
| `test_hull` | bornes PROUVÉES MEDP/MELP à 2 tours (Park et al.), facteur d'agrégation mesuré sur un trail à 8 S-box |
| `test_division_property` | division property bit à bit (monomial prediction) : borne basse prouvée par le degré, borne haute par pistes construites puis revérifiées, sens direct et inverse |
| `test_robustesse` | fuzzing de tous les décodeurs, mesures de temps |
| `test_c_integral` | **C** : cubes de 2¹⁶ à 2²⁴ entrées (2²⁸ en intensité 8), nibbles aléatoires / voisinage du graphe / bits isolés, direct et inverse |
| `test_c_diff_lin` | **C** : différentielle à 2 tours (2²⁷ paires) et hull à 2 tours (2²⁸ échantillons) ; balayage tronqué / linéaire aligné sur les S-box, tour par tour, direct et inverse |
| `test_c_sac` | **C** : matrice SAC 512 × 512 complète tour par tour (2¹⁶ échantillons par bit), direct et inverse, et à 32 tours |
| `test_c_statistiques` | **C** : batterie type NIST étendue (34 tests) sur 1 Gio en mode compteur, 512 Mio d'éponges, et en tours réduits (portée statistique) |
| `test_c_sig_valgrind` | **C** : SIG sous Valgrind, erreurs mémoire et fuites sur entrées valides et malformées, aucun branchement ni accès dépendant de la clé, des graines ou des parts (méthode ctgrind, avec témoin) |
| `test_indiff_arbre` | Lemme 15 et Théorème 16 : décodeur de BDPV sur instances de petite taille, simulateur composé sur éponge réduite, événement mauvais sous la borne, distingueur par requêtes inverses |
| `test_c_kem_bruit` | **C** : validation empirique de la borne δ sur 3,4·10⁷ bruits de décodage simulés, recoupés avec le KEM réel |
| `test_c_cube_init` | **C** : attaque par cubes sur l'initialisation réduite de l'AEAD (bits du nonce, état de clé inconnu) : sommes nulles et superpolys linéaires (récupération d'état) |
| `test_c_degre` | **C** : croissance réelle du degré algébrique (sous-espaces aléatoires de dimension 3^r et 3^r + 1), direct et inverse |
| `test_c_impl` | conformité octet pour octet de l'implémentation C (`sillage/c/`) avec le Python : permutation, hachage, AEAD, TE, KEM, SIG, interopérabilité des clés |
| `test_mode_aead` | modèle de la preuve du mode (duplex absorbant le chiffré) ≡ implémentation ; codage injectif et sans préfixe ; pas de libération de clair non vérifié |
| `test_aead_parallele` | duplex parallèle : modèle de la preuve ≡ référence ≡ C ; chemins injectifs et sans préfixe ; altérations entre feuilles (échange, troncature, greffe) ; aucun flux réutilisé ; indépendance du nombre de threads ; falsifications sur duplex réduit |
| `test_c_simd` | **C** : mêmes sorties en AVX2, sans SIMD et en NEON (qemu, si la chaîne croisée est présente) |
| `test_c_fuzz` | **C** : sûreté mémoire (UBSan en mode trap + allocateur à pages de garde validé), 2 000 itérations sur toutes les API, entrées malformées |
| `test_dp_modele` | cadre de division property exacte (CP-SAT) : infaisable pour R ≤ 10, accepte les pistes vérifiées, coupes par nibble valides sur toutes les tables |
| `test_dp_tous_cubes` | bornes de division property étendues aux 512 cubes par recollement (13 824 pistes recollées et revérifiées) |
| `test_hachage_arbre` | hachage arborescent : modèle du mode ≡ Python ≡ C, conditions de la preuve (décodable, complet, nœud final séparable), séparation des domaines, altérations structurelles, déterminisme multi-thread, KAT |
| `test_dp_validation` | division property contre sommes de cube réelles (2¹⁶ entrées, tours réduits, deux sens) : aucun bit prouvé équilibré de somme non nulle |
| `structure_miss` (**C**) | différentielles impossibles et corrélations nulles (miss-in-the-middle, nibbles, motifs de poids ≤ 2), propagation validée sur des différences réelles |
| `isd_comparaison` (**C**) | Prange, Stern, Dumer et BJMM réels sur les mêmes instances réduites, confrontés aux modèles (itérations et coût), solutions revérifiées |
| `isd_reel` (**C**) | attaques ISD réelles (Prange) sur instances réduites : coût conforme aux formules (KEM quasi-cyclique, code aléatoire de la SIG), gain quasi-cyclique mesuré, parité seul invariant linéaire de s |
| `diffusion_support` (**C**) | supports exacts de M^r et (M⁻¹)^r (combinatoire, GF(16), dépendance réelle par la permutation), borne du groupe diédral, spectre du graphe biparti |
| `kem_distributions` (**C**) | H1-P / H2-P : parité de u seul invariant linéaire (instances réduites) ; biais et corrélations u / v / s aux tailles réelles |
| `sig_flux` (**C**) | temps constant de la SIG au niveau du flot de contrôle : traces de blocs de base identiques pour des clés différentes (sig.c instrumenté, tours MPC et signature complète), témoin positif |
| `brume_attaques` (**C**) | S-box (DDT, LAT, BCT, DLCT), boomerang réel sur tours réduits, différentielles impossibles et corrélations nulles par ensembles de valeurs, avec les vrais coefficients |
| `mini_brume` (**C**) | modèle exact à 24 et 32 bits : portée intégrale réelle contre la borne de degré, dualité, loi exacte contre modèle de Markov et meilleur trail, boomerang exact, témoin aléatoire |
| `test_brume_algebre` | structure du graphe, paires rotationnelles, polynôme minimal et invariants de M, S-box, activité (CP-SAT), attaque à 1 tour, récupération d'état par SAT, pistes monomiales sur mini-BRUME (annulations) |
| `test_sig_modele` | SIG sur modèle réduit : corps irréductibles, Lemme A exhaustif, Lemme 6 compté sur K², Proposition 6 avec le vrai vérifieur, attaque de Kales–Zaverucha exécutée sous la borne du Théorème 8, encodage unique (chaque bit, chaque feuille cachée, C compris) |
| `test_aead_modele` | Théorème 14 sur duplex réduit : chaque terme confronté à une attaque exécutée, dont le clair choisi multi-cible (σN/2^c) ; falsifications passées au vrai déchiffrement |
| `test_dp_exact` | portée exacte de la division property : une piste vérifiée vers chacun des 512 bits à 11 tours, dans chaque sens (décomposition préfixe + suffixe CP-SAT) |
| `test_c_kem_valgrind` | **C** : KEM sous Valgrind, erreurs mémoire et fuites, aucun branchement ni accès dépendant d'un secret (méthode ctgrind, avec témoin) |
| `test_api_c` | API publique servie par le C : interopérabilité avec les classes de référence, entrées malformées, borne δ C ≡ référence, estimateurs ISD C ≡ référence, concurrence |
| `test_c_temps` | **C** : temps constant mesuré (méthode dudect) — permutation AVX2, AEAD, décapsulation KEM aux deux niveaux (oracle d'échec de décodage, oracle FO, dépendance à la clé secrète, μ à l'encapsulation, biais du banc), signataire SIG (simulation d'un côté et signature complète, sur un cœur et sur tous) et conformité des chemins constant-time |
| `bench_c` (hors contrôles) | benchmark C un cœur : KEM, SIG, 4 natures × 12 tailles (0 o → 16 Mio), comparé au Python |
| `bench_tailles` (hors contrôles) | chiffrement de 4 natures de contenu × 10 tailles (0 o → 1 Mio) : AEAD-128/256, TE, hachage, hybride KEM+AEAD |

**Dernière exécution (v0.4.0, 2026-10-30) : 410/410 contrôles réussis,
44 tests, 3 213 s** (`aead` relancé seul : son test utilisait encore un nonce de 16 octets). La batterie comprend notamment le modèle de preuve
du mode AEAD, le fuzzing mémoire du C, le temps constant mesuré et le
recherche exacte de la division property (portée pour tous les cubes). Points saillants : B = 8 certifié ;
meilleurs trails à 14 tours 2⁻²⁸³⁰ (diff.) / 2⁻¹⁴¹⁷ (lin.) ; distingueurs
intégraux/cubes limités à 4 tours sur 32 ; division property bit à bit :
portée exacte de 10 tours par sens (20 inside-out) pour
tout cube ; aucune symétrie ni invariant de la ronde trouvés (M seule a 16 sous-espaces invariants, que la S-box quitte : PREUVES § 4.2 bis) ; batterie statistique sans
rejet ; toutes les altérations AEAD rejetées ; KEM : 0 échec de décodage
(max 246 bascules / seuil 448 sur 2²³ bruits), δ prouvé ≤ 2⁻¹²⁸ et 2⁻²⁵⁶ pour chaque clé ; SIG : tricheur à 1/N mesuré, témoin jamais exposé.

---

### Tests intensifs en C (noyau OpenMP)

Le Python plafonnait les tests « boîte noire » (≈ 5 000 permutations/s).
`tests/c/noyau.c` recalcule la permutation avec les tables de
`sillage/brume512.py`, vérifie sa conformité bit à bit (direct 1–32 tours,
inverse) avant tout usage, et atteint ≈ 900 000 permutations/s à 32 tours
(×168, couche S puis table linéaire de 128 Kio). Ce que cela a permis (intensité 1) :

| Mesure | Python (avant) | C (maintenant) | Résultat |
|---|---|---|---|
| Cubes / intégrales | 2²⁰ entrées | 2²⁴ (2²⁸ en ×8), 4 contextes, direct + inverse | distingueur : 4 tours (direct), 2 (inverse) |
| Différentielle 2 tours | ~32 occurrences | 2²⁷ paires, 508 occurrences | facteur de groupe **0,99 ± 0,04** (caractéristique 2⁻¹⁸) |
| Hull linéaire 2 tours | 2²², facteur 1,1 ± 0,12 | 2²⁸ échantillons | facteur hull **1,004 ± 0,016** |
| Différentielles tronquées (alignées S-box) | — | 2²⁴ paires par tour, 3 entrées | biais jusqu'à 5 tours (direct), 2 (inverse) |
| Linéaire à un nibble (aligné) | — | 1 920 masques de sortie par tour | biais à 1 tour seulement (B = 8) |
| SAC 512 × 512 | 500 échantillons, 32 tours | 2¹⁶ par bit, tour par tour | indistinguable dès 5 tours (direct), 2 (inverse) |
| Batterie statistique | 128 Ko, 11 tests | **1 Gio** compteur + 512 Mio éponge, 34 tests | conforme à 32 tours ; échec ≤ 4 tours, conforme dès 5 |
| Borne δ du KEM | — | 2²³ et 2²⁰ bruits simulés (recoupés avec le KEM réel, z = −1,3 et 0,1) | la borne majore la mesure à tout seuil observable : 18,5 et 16,5 bits de marge par mot, 26,4 et 28,8 par hyperplan ; max 246 / seuil 448, 446 / 896 |

Campagne poussée (`SILLAGE_INTENSITE` = 4 à 8, résultats dans
`resultats/<test>_x<k>.json`) :
- cubes de 2²⁸ : 4 tours en direct (inchangé) et **3 en inverse** (+1) ;
- différentielle à 2 tours sur 2²⁹ paires : facteur 1,013 ± 0,022 ;
- hull à 2 tours sur 2³⁰ échantillons : facteur 1,011 ± 0,008 ;
- SAC sur 2¹⁸ échantillons par bit : inchangé ;
- batterie statistique sur 4 Gio en compteur et 2 Gio d'éponges :
  conforme à 32 tours, échec jusqu'à 4 tours ;
- 1,3·10⁸ bruits KEM (code à répétition de la v0.3) : la borne majorait la mesure,
  avec 19 bits de marge ; maximum de 132 bascules pour un seuil de 265. Non refait sur le code RM.

Portée empirique la plus longue : **5 tours dans le sens direct
(différentielle tronquée) et 3 dans le sens inverse (cube de 2²⁸), soit
8 tours inside-out sur 32**, à confronter à la portée exacte de la division property : 20 tours
inside-out (10 par sens), pour tout cube.

Campagne de nuit (`./rundenuit.sh [heures]`, C et shell, synthèse dans
`resultats/NUIT.md` ; après une coupure, `./reprendre_nuit.sh [heures]` reprend à la campagne interrompue, et à l'étape interrompue pour BRUME) : batterie complète (à partir de 6 h), cryptanalyse de BRUME et modèles de preuve à grande échelle (`tests/nuit_brume.py`), fuzzing mémoire (entrées extrêmes du KEM et de la SIG
comprises), dudect sur des plans qui isolent le secret, avec test A/A et
témoins, KEM réel (rejet implicite, recalcul de la borne, pire clé), ISD,
séries de cubes jusqu'à 2³⁶, différentielles tronquées et linéaires alignées.
Chaque famille est testée au-delà de sa portée connue, et ses statistiques
sont calibrées sous l'hypothèse nulle. Le run précédent est archivé dans
`resultats/nuit_archives/`. Le run complet de 8 h du 2026-10-30 est antérieur
à ces plans et à la v0.4 : il ne couvre ni le KEM RM ni la SIG MPC-in-the-Head ; voir `docs/RAPPORT_AUDIT.md` § 14.

Deux analyses complémentaires :
- **attaque par cubes sur l'initialisation réduite de l'AEAD** (bits du
  nonce comme variables, état issu de la clé inconnu) : sommes nulles
  jusqu'à 4 tours, **aucun superpoly linéaire** à aucun tour, donc pas
  d'équation exploitable pour retrouver l'état. Le chemin réel entre le
  nonce et le flux compte 64 tours ;
- **degré algébrique** : il croît au maximum (3, 9, 27 aux tours 1 à 3,
  dans les deux sens, sur des sous-espaces aléatoires), et la borne de
  Boura–Canteaut est toujours respectée. La portée du distingueur par le
  degré (10 tours par sens) n'est donc pas faussée par une croissance
  lente.

### Implémentation C (`sillage/c/`) et benchmark

Portage C complet de la suite : BRUME-512 (permutation, hachage, AEAD
deux profils, TE), Sillage-KEM (FO, borne δ en keygen), Sillage-SIG,
SHAKE256. Elle est **conforme octet pour octet** au Python et
interopérable avec lui (`test_c_impl` : clés, chiffrés et signatures
croisés). `resultats/BENCH_C.md`, sur un seul cœur (Ryzen 5 5600G) :

| Opération | C | Python | Facteur |
|---|---|---|---|
| Permutation BRUME-512 (AVX2, **constant-time**) | 0,39 µs | ≈ 0,3 ms | ×770 |
| AEAD-128, un message de 1 Mio | 12,1 ms (**83 Mio/s**) | 10,2 s | ×840 |
| AEAD-128, message de 64 o (clé / contexte de clé) | 3,4 / **2,7 µs** | 3,1 ms | ×915 |
| AEAD-256, un message de 1 Mio | 24,3 ms (41 Mio/s) | 20,3 s | ×840 |
| AEAD-128 multi-messages (1 Kio / 16 Kio), 12 threads | **628 / 695 Mo/s** (clé commune : 656 / 706) | — | — |
| Hachage multi-messages (1 Kio), 12 threads | 808 Mo/s | — | — |
| Hachage **arborescent** d'un message de 16 Mio : 1 cœur / 12 threads | 161 / **816 Mo/s** (séquentiel : 86) | — | — |
| KEM-128 keygen / encaps / decaps (constant-time) | 5,98 / 0,20 / 0,31 ms | 169 / 3,5 / 17,7 ms | ×17–57 |
| KEM-256 keygen / encaps / decaps (constant-time) | 28,3 / 1,17 / 1,84 ms | 683 / 16,3 / 57,9 ms | ×14–31 |
| SIG-128 signe (constant-time) / vérifie | 38,5 / 38,4 ms | 2,07 / 2,07 s | ×54 |
| SIG-256 signe (constant-time) / vérifie | 139 / 138 ms | 6,56 / 6,58 s | ×47 |
| SIG-128 / SIG-256 signe, 12 threads | **5,9 / 21,1 ms** | — | — |
| SIG-128 / SIG-256 vérifie, 12 threads | **5,9 / 20,7 ms** | — | — |

L'encapsulation mémorise H(pk) par thread : vers une pk qui change à chaque
appel, elle coûte 0,26 / 1,42 ms. La décapsulation recalcule toujours H(pk).

Par rapport à la v0.3 (coût de la taille) : la keygen KEM passe de 0,37 / 1,63 ms à 5,98 / 28,3 ms, car la borne δ
parcourt 254 hyperplans sur tout le cercle. La signature passe de 14,9 / 76,5 ms à 38,5 / 139 ms et la vérification de
4,8 / 21 ms à 38,4 / 138 ms, sur un cœur : l'hypercube développe N = 2¹² feuilles par tour des deux côtés. Encapsulation et
décapsulation sont plus rapides qu'avant, le code RM étant beaucoup plus court que le code à répétition.

**Noyaux AVX2 (mêmes sorties, mêmes KAT).**
- *Un état* : les S-box et le produit dans GF(16) (par logarithme et
  exponentielle) passent par `vpshufb`, avec les tables en registre. La
  diffusion exploite la structure de Cayley de D₁₂₈ : les six générateurs
  sont des réflexions, donc le voisin s'obtient par un échange de moitiés
  et une rotation d'octets. La version à tables prenait 4,4 µs.
- *Lots de 32 états* : 0,19 µs par état. L'AEAD et le hachage
  multi-messages choisissent seuls entre les lots et un message par cœur.
- **Constant-time vérifié** par `test_c_temps` (méthode dudect) : aucune
  dépendance au secret n'est détectée, ni dans la permutation ni dans
  l'AEAD.

Le **KEM C est lui aussi constant-time**. Les vecteurs secrets sont
manipulés en dense, avec un produit Karatsuba + PCLMULQDQ. Le tirage
creux consomme un nombre de mots fixe, ce qui supprime la fuite de type
« Don't Reject This ». La décapsulation ré-encapsule toujours. Le mot RM est
posé par masques et décodé par transformée de Walsh, avec une sélection sans
branchement : la permutation `Q` est publique et le bit bruité n'indexe rien.
La borne δ de la keygen lit sa table publique par `vpshufb` ; seul le pire produit
est déclaré public, puisqu'il décide du rejet de la clé.

Dudect en v0.4 (`|t|` < 4,5) : oracle de décodage t = 0,39 (128) et −2,83 (256), oracle FO
t = −1,00, décapsulation t = −1,47 et 0,60, μ à l'encapsulation t = 0,77, test A/A t = −1,51.
Ces mesures sont plus courtes que la campagne de la v0.3 (1,2 M de mesures par plan) : 3 000 à
20 000 ici. L'effet de cache de la v0.3 sur un chiffré répété, valeur publique, n'a pas été remesuré.

La **SIG C est constant-time côté signataire**. Les secrets ne passent que par des XOR, des masques
et des produits sans retenue dans GF(2^e) et GF(2^ep), sans table indexée par un secret. Le produit
H·x est masqué, et seul le défi, public, choisit les parts révélées. Contrôles : Valgrind
(ctgrind) avec témoin, traces de flot de contrôle (`sig_flux`) et dudect : tour MPC t = −0,62, signature
complète t = 0,12 (400 mesures) et −0,40 sur tous les cœurs, témoin à branchements t = −2 039.
Signature et vérification répartissent les tours par OpenMP en répartition statique. Les pistes de
débit pour un seul flux (duplex parallèle, moins de tours en phase de données) sont mesurées et
non adoptées : leurs conditions de sécurité sont dans `docs/PISTES.md`.

### Performances (implémentation Python/numpy de référence)

Mesures des classes de référence, à titre de comparaison : l'API publique
passe par le C (§ 3).

`resultats/BENCH_TAILLES.md` : 4 natures de contenu (texte, aléatoire,
zéros, JSON) × 10 tailles (0 o → 1 Mio), allers-retours tous vérifiés.

| Taille | AEAD-128 | AEAD-256 | Hachage | Hybride KEM+AEAD |
|---|---|---|---|---|
| 0 o | 2,5 ms | 3,7 ms | 0,6 ms | 6,2 ms |
| 1 Kio | 12,4 ms | 23,5 ms | 10,5 ms | 16,0 ms |
| 64 Kio | 0,64 s | 1,27 s | 0,63 s | 0,64 s |
| 1 Mio | 10,2 s | 20,3 s | 10,0 s | 10,2 s |

Débit asymptotique ≈ 100 Kio/s (AEAD-128, débit 64 o/perm.) et ≈ 50 Kio/s
(AEAD-256, débit 32 o/perm.) ; le mode TE ajoute ≈ 4 % de temps et 10,9 %
de taille ; le KEM ajoute un coût fixe ≈ 3,5 ms (encaps.) / 18 ms
(décaps.) et 9 853 o. La nature du contenu n'influe ni sur le temps ni sur
l'entropie du chiffré (≈ 8 bits/octet, même pour un clair nul).

---

## 6. Statut de sécurité

**Prouvé ou vérifié exhaustivement :**
- B = 8 (différentiel et linéaire) → à 32 tours, caractéristique
  différentielle ≤ 2⁻²⁵⁶ et corrélation de trail linéaire ≤ 2⁻¹²⁸ (pour
  une permutation sans clé, le produit des probabilités locales suppose
  l'indépendance des tours ; ces bornes portent sur une caractéristique,
  pas sur une différentielle agrégée) ;
- propriétés de la S-box, Ramanujan (graphe biparti, ±6 exclus), support
  de la diffusion (complet en 5 tours), asymétrie du graphe pondéré ;
- injectivité des paddings (hachage, AEAD).

**Reposant sur des hypothèses dures :** décodage de syndrome QC (KEM),
décodage de syndrome aléatoire (SIG), modèle de l'oracle aléatoire (FO,
Fiat-Shamir, SHAKE256 dans le KEM et la SIG).

**Prouvé sous hypothèses (docs/PREUVES.md) :** IND-CPA du chiffrement
sous-jacent (QCSD décisionnel avec parité, H1-P / H2-P), IND-CCA du KEM en ROM (FO à rejet
implicite, δ ≤ 2^−λ prouvé clé par clé), complétude / solidité (1/N, faux positif p) /
HVZK du protocole MPC-in-the-Head, EUF-CMA et SUF-CMA de la signature en ROM. Les réductions QROM,
instanciées avec des réserves, prouvent ≈ 60 / 104 bits pour le KEM et ≈ 32 / 68 bits pour la SIG (PREUVES § 5 bis).

**Division property (bit à bit) : portée exacte DE LA MÉTHODE, pour tout
cube — pas celle de toute attaque intégrale.**
- Équilibre prouvé jusqu'à 10 tours par sens (degré de Boura–Canteaut).
- À 11 tours, chacun des 512 bits a une piste monomiale revérifiée, dans
  chaque sens : la méthode ne prouve plus rien. Portée : **exactement 10
  tours par sens, 20 inside-out** (`docs/PREUVES.md`, Théorème 12 sexies).
- Méthode : recollement des pistes sur les 512 cubes, et complétion
  exacte des derniers tours par CP-SAT sur un modèle réduit.
- Reste ouvert : le distingueur intégral réel (pistes comptées modulo 2). 20 tours inside-out n'est **pas**
  une attaque intégrale réelle couvrant 20 tours. Sur mini-BRUME, aucune annulation observée (`docs/PREUVES.md` § 4.2 bis).
- Certificats reproductibles : `resultats/pistes_division.json` et
  `resultats/pistes_exactes.json`, revérifiés par `verifier`
  (`tests/pistes_monomiales.py`, indépendant de la construction).

**Différentielles impossibles et corrélations nulles** (`structure_miss`, `brume_attaques`,
tests C) : 5 tours au plus sur 32, au niveau des nibbles et avec les vraies valeurs de coefficients.

**128 S-box actives, 2⁻²⁵⁶ et 2⁻¹²⁸ : deux statuts.** Les 128 S-box actives sont démontrées. Les probabilités reposent sur le modèle de Markov, une hypothèse
que le modèle exact montre proche, mais pas exacte (`docs/PREUVES.md` § 4.2 bis). Boomerang : 3 tours mesurés. 1 tour : état retrouvé par résolution linéaire.
L'agrégation au-delà de 2 tours reste ouverte.

**Adversaire quantique** (`docs/PREUVES.md` § 5 bis) : les niveaux
nominaux sont classiques. KEM ≈ 91 / 158 bits (Prange–Grover), 67 / 129 avec
des marches quantiques à QRAM gratuite ; SIG ≈ 64 / 132 bits, car Grover s'applique
à Fiat–Shamir et aux graines ; catégorie NIST (MAXDEPTH, modèle grossier) : aucune pour
SIG-128, 3 pour SIG-256 ; collisions de
hachage ≈ 2⁸⁵ ; AEAD : recherche de clé en 2²⁵⁶.

**Ce que ces garanties ne disent pas.** Les propriétés de la couche
linéaire (expansion de Ramanujan, asymétrie de Weisfeiler–Lehman, B = 8)
sont des propriétés structurelles. Avec les bornes de trails et de
division property, elles écartent des familles d'attaques précises. Elles
ne démontrent pas la sécurité de la permutation complète. Celle-ci reste
une hypothèse (permutation idéale dans les preuves de modes), appuyée sur
l'absence de distingueur trouvé et en attente d'une cryptanalyse
indépendante.

**Agrégation de trails :** bornes prouvées à 2 tours (MEDP₂, MELP₂ ≤ 2⁻¹⁵) ;
facteur d'agrégation mesuré ≈ 1,1 ; au-delà, argument de marge (> 2 500
bits entre trails trouvés et seuils prouvés).

**Canaux auxiliaires :** BRUME-512, le KEM et la SIG (côté signataire) en
C sont constant-time, vérifié par dudect (mesures, avec témoins positifs)
et, pour la SIG, par le contrôle du flot de contrôle (`sig_flux` : traces
de blocs de base identiques pour des clés différentes). Le Python ne
l'est pas. Ce sont des vérifications, pas une certification.

---

## 7. Feuille de route

1. **Signatures** : MPCitH fait en v0.4 (×15,7) ; SUF-CMA, multi-utilisateur, modèle réduit et QROM chiffré faits. Reste la relecture tierce du protocole, du Théorème 8 et de l'esquisse QROM.
2. **KEM** : code RM(1,7) fait en v0.4 (×1,7). Reste une borne prouvée sous les annulations du XOR
   (`docs/PISTES.md`, piste 8) ; étude d'une cascade de bruit qui ait un effet réel.
3. **BRUME** : bornes d'agrégation au-delà de 2 tours ; portée intégrale réelle ; recherche d'attaques (boomerang, intégrales, algébriques, impossibles, structure du graphe), commencée, § 4.2 bis ; analyse tierce de
   la conception. (Division property exacte pour tous les cubes : faite,
   10 tours par sens.)
4. **Implémentation C** : faite et conforme. BRUME-512 (AVX2, lots), le
   KEM et la SIG sont constant-time. NEON fait, sorties vérifiées sous qemu : temps constant et débit
   à mesurer sur une vraie machine ARM. Reste AVX-512 (non testable ici).
5. **Débit d'un seul flux** : duplex parallèle fait (PREUVES § 4.5, relecture à faire). Tours réduits en phase de
   données : non adoptés, conditions dans `docs/PISTES.md`.

---

## 8. Journal des défauts trouvés (valeur pédagogique)

| Version | Défaut | Détection | Correction |
|---|---|---|---|
| v0.1 | KEM : terme dense `(r1⊕r2)·x·h` (bruit ≈ n/2) | banc | `r1·s` |
| v0.1 | Diffusion par XOR séquentiel → avalanche 0 % | banc | XOR simultané |
| v0.1 | S-box « Kasami » x¹³ : du = 12 | banc | x²⁵¹ |
| v0.1 | Code TE aveugle aux masques pairs | banc | syndromes par bit-plan |
| v0.2 | Diffusion non pondérée sur groupe d'exposant 2 : cycle 1→7→1 | théorème + banc | D₁₂₈ + coefficients GF(16) |
| v0.2 | AEAD : extension par zéros | auto-test | bloc de longueur |
| **v0.3** | **SIG : défi 2 révélant r et r⊕e → clé livrée par une signature** | audit | Stern conforme |
| **v0.3** | **AEAD : bloc final et bloc de longueur dans le même débit → falsification p = 1** | audit | 10*, domaines, permutation |
| v0.3 | KEM sans ré-encapsulation (pas de FO) | audit | FO à rejet implicite |
| v0.3 | KEM mode `tensor` : pk de densité 0,25 | audit | mode retiré |
| **v0.3** | **KEM : la décapsulation sautait la ré-encapsulation après un échec de décodage → échec visible au temps (≈ 0,28 ms), oracle des attaques par réaction** | inspection + dudect | ré-encapsulation systématique, choix par masque (Python et C) |
| v0.3 | Permutation C par tables indexées par l'état (fuite par le cache) | dudect | noyau AVX2 constant-time (mêmes sorties) |
| **v0.3** | **Preuves KEM : H1 et H2 formulées sans la contrainte de parité (s(1) et u(1) sont publics), donc distinguables avec un avantage de 1/2** | audit externe (Codex) | hypothèses H1-P / H2-P avec parité, preuve IND-CPA refaite ; schéma inchangé |
| v0.3 | Preuve AEAD : instanciation « avantage ≤ 2⁻⁶², 128 bits » mélangeant deux notions ; jeu idéal ambigu | audit externe | notion coût/avantage définie, Corollaire 14 bis terme par terme, restriction standard du jeu AE |
| v0.3 | SIG C : π matérialisé et lu aux indices π(i), lignes de H sautées selon les bits de u et e (fuite par le cache et le temps) | dudect (t ≈ −220 à −460) | Fisher–Yates appliqué par balayage masqué, H·u masqué (mêmes signatures) |
| **v0.4** | **SIG : 134 Ko (Stern) : réponses contenant des vecteurs entiers de n bits, ε = 2/3** | analyse externe de la taille, chiffres revérifiés | MPC-in-the-Head à hypercube, 8,5 Ko, même (H3), marges ISD conservées |
| **v0.4** | **KEM : code à répétition de taux 1/531** | analyse externe, chiffres revérifiés ; son objectif de 5 à 7 Ko supposait une hypothèse d'indépendance | RM(1,7) réparti, δ prouvé, 9,8 Ko |
| v0.4 | Code RM en positions consécutives ou périodiques : la borne certifiée perd jusqu'à 30 bits et varie d'une clé à l'autre (fenêtres denses) | mesure sur clés réelles | répartition publique pseudo-aléatoire des positions |
| v0.4 | SIG : `aux` non lié quand la dernière feuille est cachée (≈ 1 signature sur 370) : signature malléable. EUF-CMA et secret non touchés | relecture de la preuve contre le code, attaque exécutée | `aux = 0` exigé, Proposition 9 (SUF-CMA) |
| v0.4 | `sig_flux` rouge sur la nouvelle SIG : table construite pendant la trace, boucle dupliquée par gcc, hachés comparés après la boucle. Artefacts du test : l'assembleur de `mat_vec_ct` ne contient aucun branchement secret | contrôle de flot, lecture de l'assembleur | test corrigé ; barrières `asm` sur les masques gardées à titre préventif |
| v0.4 | `(double)uint64_t` dans la borne δ : la conversion branche sur x86, selon une valeur dérivée de la clé | Valgrind (ctgrind) | passage par `(double)(int64_t)` |
| v0.3 | KEM C : tirage creux par rejet à durée variable (graine dérivée de μ) → fuite de type « Don't Reject This » | dudect (t = −53) | nombre de mots fixe, acceptation sans branchement (mêmes positions) |
| v0.3 | KEM C : multiplications creuses à décalages secrets (cache) | inspection + dudect | représentation dense, Karatsuba + PCLMULQDQ |
| v0.3 | Documentation : bornes hautes de division property présentées comme générales alors qu'établies pour un seul cube (bit 0 inactif) | relecture (recherche exacte) | portée corrigée, puis bornes établies pour tous les cubes et resserrées à la valeur exacte (10 par sens) |
| v0.3 | Banc dudect KEM : chiffré répété par classe, confondu avec le secret → faux échecs du run de nuit (t = −5,68 / −6,75) | run de nuit + diagnostic par plans séparés | plans à réserves de chiffrés communes, tampon de mesure commun, A/A et témoin ; mécanisme de l'effet de répétition non identifié |
| v0.3 | Campagne de nuit : contrôle « aucun distingueur au-delà de 7/5 » impossible à échouer (tests limités à 6/5) ; tronquées aveugles au biais connu ; borne KEM tautologique | relecture du run | portée par famille, couverture contrôlée, χ² alignés, recalcul naïf indépendant |
| v0.3 | Nouvelle linéaire jointe de la campagne : χ² à 225 ddl au lieu de 255 → p-valeurs trop petites (0,007 à 2 tours, 0,7 une fois corrigé) | campagne de validation (χ² stable de 2²⁴ à 2³⁰) | 255 ddl, contrôle de calibrage sous H₀ (254,88 mesuré) |
| **v0.3** | **SIG-256 : σ_π de 128 bits (une signature donne e en 2¹²⁸) et hachés de 256 bits (collision de H(m) → falsification en 2¹²⁸) : niveau réel ≈ 128 bits au lieu de 256** | relecture du Théorème 8 | \|σ_π\| = λ, hachés de 2λ bits (format SIG-256 modifié), π lié à (sel, i) ; attaque exécutée sur espace réduit |
| v0.3 | Théorème 8 : engagements dits « cachants par entropie », faux aux défis 0 et 1 ; pas de terme pour H(m) ; bifurcation inutile | relecture | Proposition 7 et Théorème 8 réécrits, extraction depuis la table de l'oracle (réduction sans perte en q) |
| v0.3 | C : `H(pk)` mémorisé dans la décapsulation, alerte dudect (t ≈ −69 à 128 bits, −44 à 256) : effet du cache, sur une valeur publique, mais qui masquait toute mesure | dudect, pendant l'optimisation | cache retiré de la décapsulation (t = −0,31 / 1,36), conservé à l'encapsulation |
| v0.3 | Témoin Valgrind de la SIG éliminé par gcc, donc contrôle aveugle ; KEM sans contrôle Valgrind | témoin non détecté | barrière sur le résultat, `test_c_kem_valgrind` |
| v0.3 | C : aléa système non vérifié, caches statiques partagés entre threads, secrets intermédiaires non effacés, histogramme de la borne δ indexé par un secret | relecture pendant l'optimisation | erreur remontée, caches par thread, effacements, compteurs bitslicés |
| v0.3 | C : `tmp[k]` dans `sl_creux` (indice dépendant des rejets, KEM et SIG), `sk[pos]` en keygen ; gcc recréait un branchement sur k ; π(u), g, pos non effacés | Valgrind (ctgrind), non vu par dudect | écriture par balayage masqué, barrière d'optimisation, effacements (mêmes sorties) |
| v0.3 | Lemme 15 : requêtes inverses « retirées » pour q²/2^{b+1} (faux : distingueur concret en q²/2^c), entrées déjà posées non comptées, F_0 mal traité | relecture et simulation | preuve réécrite ; borne 7q(q+1)/2^{c+1} ; conditions de BDPV vérifiées selon leurs définitions |
| v0.3 | ISD SIG : optimum de BJMM sur la borne de grille (p ≤ 24) : 160,5 / 327,2 b annoncés, 159,7 / 314,9 b réels ; Stern et Dumer confondus | relecture | grille à arrêt local, optimum contrôlé, solveurs réels, confrontation à CryptographicEstimators |
| v0.3 | Piste 7 : « t = 438 suffit pour 128 b quantiques » faux | vérification quantique | il faut aussi σ_π de 32 octets et w ≥ 204 |
| v0.3 | SIG : ε = 3/4 (défis {0,1,2,2}), permutation d'octets | audit | défis ternaires, bits |
| v0.3 | Estimateurs « Prange/2,4 » sans fondement (KEM ≈ 300 b pour 128 annoncés) | audit | ISD concret, re-dimensionnement (tailles ÷ 2,5) |
| v0.3 | Propagation linéaire avec masques non convertis | audit | adjoint binaire `GMUL_T` |
| v0.3 | Clé AEAD traitée par SHAKE, jamais par BRUME | audit | duplex à clé sur la permutation |
| v0.3 | Capacité 256 b incompatible avec λ = 256 | audit | profil -256 : capacité 384 |
| **v0.3** | **KEM : δ justifié par un z-score gaussien — borne rigoureuse : 2⁻⁶⁰…2⁻⁷⁵ au lieu de 2⁻¹⁹²** | preuve FO | borne de Chernoff certifiée, validation des clés, re-dimensionnement |
| v0.3 | Permutation : 4 opérations numpy par tour | banc | tables fusionnées (RC+S+GF(16)) : +30 % |

Détail : `docs/RAPPORT_AUDIT.md`.
