# Rapport d'audit SILLAGE — v0.2 → v0.3

Périmètre : KEM, BRUME-512 (permutation, AEAD, TE, hachage), SIG.
Méthode : batterie `tests/` (39 tests, 290 contrôles — **290/290 réussis** le 2026-10-30 —
rejouable : `python3 -m tests.run_all`),
résultats bruts dans `resultats/`. Ce rapport consolide l'audit initial de la
v0.2, les décisions prises sur les points ouverts et le verdict de la
batterie complète contre la v0.3.

## 1. Failles de la v0.2 et corrections

| # | Composant | Faille | Gravité | Correction v0.3 | Test de non-régression |
|---|---|---|---|---|---|
| 1 | SIG | Le défi 2 révélait `r` et `r⊕e` en clair : une signature livrait la clé secrète | Critique | Protocole de Stern conforme (3 engagements, réponse `π(u), π(e)` au défi 2) | `test_sig` : `temoin_absent` |
| 2 | AEAD | Dernier bloc chiffré et bloc de longueur XORés dans le même débit : `(c ⊕ Δ(L,L'), L')` gardait le tag (falsification de probabilité 1) | Critique | Dernier bloc toujours partiel + 10*, domaines séparés, permutation avant la longueur | `test_aead` (toutes longueurs ≤ 3 blocs, L ± 1, L + 8) |
| 3 | KEM | `decaps` sans ré-encapsulation : tout chiffré décodable accepté (IND-CPA au mieux) | Majeur | FO à rejet implicite, aléas dérivés de `(μ, H(pk))` | `test_kem` : `fo_rejette_chiffres_non_honnetes` |
| 4 | KEM | Mode `tensor` : `h = h1·h2` creux, pk de densité 0,25 (z ≈ −180) | Majeur | Mode retiré | `test_kem` : `mode_tensor_refuse` |
| 5 | SIG | Défis `{0,1,2,3}→{0,1,2,2}` : ε = 3/4 ; permutation d'octets (fuite du motif de `e`) | Majeur | Défis ternaires uniformes, permutation de bits, t = ⌈λ/log₂ 1,5⌉ | `test_sig`, `test_isd_parametres` |
| 6 | Paramètres | « Prange / 2,4 » (KEM) et « / 1,35 » (SIG) sans fondement ; KEM ≈ 300 bits réels pour 128 annoncés | Majeur | Estimateurs ISD concrets (Prange, Stern-Dumer, BJMM) ; KEM re-dimensionné : n = 68 059 / 244 043, pk 8,5 / 30,5 Ko, ct 17 / 61 Ko (au lieu de 16,4 / 65,6 et 32,8 / 131 Ko) ; n choisi pour que δ ≤ 2^−λ soit **prouvé** (voir §5) | `test_isd_parametres` |
| 7 | Banc | Propagation linéaire avec la transposée GF(16) au lieu de l'adjoint binaire du LAT | Moyen | `GMUL_T` (adjoint binaire exact) | `test_diff_lin_empirique`, `test_branch_exact` |
| 8 | Banc | Garantie « renforcée » B ≥ 13 (2⁻⁴¹⁶) : fausse, B = 8 est atteint | Moyen | Retirée | `test_banc_cryptanalyse` |
| 9 | AEAD | Clé traitée par SHAKE256, jamais par BRUME | Conception | Duplex à clé entièrement sur la permutation | `test_fonctionnel` (KAT) |
| 10 | AEAD | Capacité 256 bits incompatible avec λ = 256 | Conception | Profil BRUME-512-256 : débit 128, capacité 384 | `test_aead` |
| 11 | TE | Parités tronquées acceptées, métadonnées non contrôlées | Mineur | Contrôles stricts | `test_te` |
| 12 | Divers | `demo.py` / `bench.py` importaient un paquet `sillage` inexistant | Mineur | Arborescence refaite (`sillage/` = paquet) | `test_fonctionnel` : `demo_execution` |

## 2. Décisions sur les points ouverts

- **Estimation de sécurité** : en régime creux (KEM, w ≪ n), toutes les
  variantes ISD ont l'exposant dominant de Prange (BJMM ≈ 0,9 × Prange
  mesuré) ; diviser par 2,4 n'avait pas de sens. Les paramètres KEM sont
  recalculés au plus juste (sécurité ≥ λ + 8 après gain QC, échec de
  décodage ≤ 2^−(λ+64), plus petit n d'Artin) : **tailles divisées par
  ≈ 2,5–3**. Pour la SIG, BJMM donne 160,5 bits : c'est la falsification FS
  (128,1 bits) qui fixe la sécurité.
- **Capacité** : le hachage garde c = 256 (collisions en 2¹²⁸, cible
  standard d'une empreinte de 256 bits). L'AEAD à clé suit la borne du
  duplex à clé `M·N/2^c` : c = 256 pour λ = 128 et c = 384 pour λ = 256.
- **Cascade de bruit** : conservée (idée du projet) mais documentée comme
  **neutre**. π étant publique, `π(e2)` a la loi de `e2`. La rendre active
  supposerait un secret partagé, ce qui est impossible côté encapsulation.
- **TE** : reste un code correcteur de canal. La « tamper-evidence » ne vaut
  que contre les altérations accidentelles ; l'intégrité adversariale repose
  sur le tag (testé : des parités recalculées sont arrêtées par le tag).
- **Canaux auxiliaires** : hors périmètre (Python). Mesuré à titre indicatif :
  écart de temps valide/invalide ≈ 3 % (decrypt) et ≈ 4 % (decaps).

## 3. Résultats de la batterie contre la v0.3

### BRUME-512, permutation

| Propriété | Résultat |
|---|---|
| Branch number (diff. et lin.) | **B = 8 exact** (énumération des poids ≤ 3 de M, M⁻¹, Mᵀ, (Mᵀ)⁻¹) |
| Bornes à 32 tours | caractéristique diff. ≤ 2⁻²⁵⁶, trail lin. ≤ 2⁻¹²⁸ (**prouvées**) |
| Meilleurs trails trouvés, 14 tours | diff. 2⁻²⁸³⁰, lin. 2⁻¹⁴¹⁷ (glouton) ; faisceau : 2⁻²⁷⁵³ / 2⁻¹³⁸⁰ |
| Cycles itératifs | aucun sur v1 (le témoin v0 non pondéré en montre 5 287) |
| Validation des modèles (1 tour) | diff. 0,1263 mesuré / 0,125 prédit ; corrélation 0,0070 / 0,0078 (σ = 0,001) ; adjonction exacte |
| Cubes de nibbles | somme nulle jusqu'à 3 tours ; aléatoire à 4 |
| Cubes de bits (2⁸–2¹⁶) | 4 tours (partiel) ; aléatoire à 5 |
| Intégrale 2²⁰ (voisinage du graphe) | 4 tours (101/128 nibbles nuls) ; 5–6 tours : aléatoire |
| Bornes de degré (Boura–Canteaut) | degré complet (511) au tour 11 ; zero-sum inside-out ≤ 20 tours → **marge de 12 tours** |
| Division property bit à bit | équilibre prouvé jusqu'à 10 tours dans chaque sens ; pistes monomiales vérifiées vers **tous** les bits dès 15 tours (direct) et 12 tours (inverse), **pour le cube au bit 0 inactif** → pour ce cube, aucun distingueur DP au-delà de 14 + 11 = 25 tours inside-out (resserré au § 9 : 10 + 10 = 20, pour tout cube) |
| Agrégation (hull) | MEDP₂ ≤ 2⁻¹⁴·⁹⁹, MELP₂ ≤ 2⁻¹⁵ (**prouvées**, Park et al.) ; facteur d'agrégation mesuré 1,1 sur un trail à 8 S-box |
| Diffusion | support complet en 5 tours (tous les sommets), avalanche complète en 4 |
| SAC 512×512 à 32 tours | moyenne 0,5001, z_max = 4,81 (attendu ≈ 5,1 au hasard) |
| Statistiques (flux AEAD, hachage, compteur) | 33 p-valeurs, min 0,026 : aucun rejet |
| Symétries | aucune translation de D₁₂₈ invariante ; WL : 128 couleurs (asymétrie) ; RC distinctes, non périodiques |
| Invariants | aucun sous-espace stable par S et M ; ordre de M > 256 ; S-box : auto-équivalence triviale seule, sans structure linéaire |

Le distingueur le plus long trouvé couvre **4 tours sur 32**. La portée
d'un distingueur par division property est encadrée entre 20 tours
(prouvé pour tout cube) et 25 tours (vérifié pour le cube au bit 0
inactif), sur 32. *Mise à jour (§ 9) : portée exacte de 20 tours, pour tout
cube.*

### Modes

| Test | Résultat |
|---|---|
| AEAD | toutes les altérations rejetées (bit à bit, extension, troncature, tag, nonce, AAD, clé, collision longueur/bloc final) sur les deux profils |
| TE | correction à chaque position et pour tout masque ; 400 doubles erreurs dans un même bloc : 386 TAMPER, 14 TAG, **0 acceptée** |
| Hachage | padding injectif (exhaustif), extensions distinctes, 65 792 empreintes distinctes, collisions sur 20 bits conformes (5 observées / 8 attendues), avalanche 127,8/256 |

### KEM et SIG

| Test | Résultat |
|---|---|
| KEM correction | 150/150 (128), 25/25 (256) |
| Marge de décodage | max 108 bascules pour un seuil de 265 (128) ; 170 / 476 (256) |
| δ prouvé (Chernoff, par clé) | clé générée 2⁻¹⁶⁷ (128) / 2⁻³⁷⁷ (256) ; pire de 30 clés brutes 2⁻¹³⁸ / 2⁻²⁵⁶ ; keygen rejette toute clé au-dessus de 2^−λ |
| FO | chiffrés non honnêtes décodables → rejet implicite ; rejet déterministe ; entrées malformées sans exception |
| SIG | vérification, rejets, témoin absent, tricheur à préimage dense (poids 862) rejeté, défis uniformes (χ²) |
| Fuzzing | aucune exception non déclarée (decrypt, decrypt_te, verify, decaps) |

## 4. Seconde passe : points ouverts résolus

| Point | Constat | Correction | Test |
|---|---|---|---|
| δ-correction du KEM | l'argument gaussien annonçait 2⁻¹⁹² ; la borne rigoureuse (Hoeffding, tirage sans remise) ne donnait que 2⁻⁶⁰ à 2⁻⁷⁵ | borne de Chernoff certifiée **clé par clé** (`borne_echec_log2`), keygen rejette les clés > 2^−λ, n re-dimensionné à 68 059 / 244 043 | `test_kem`, `test_isd_parametres` |
| Preuves formelles | absentes | `docs/PREUVES.md` : IND-CPA, IND-CCA (FO ⊥̸), Stern (complétude, 3-solidité, HVZK), EUF-CMA, wide-trail, Park, duplex | — |
| Linear hull | non mesuré | bornes prouvées MEDP₂ / MELP₂, mesure de l'agrégation | `test_hull` |
| Division property | non faite (SAT trop lent : > 40 min sans réponse à 11 tours) | pistes monomiales construites (flot de coût minimal + faisceau) puis **revérifiées** pas à pas, prolongées bit à bit par récurrence | `test_division_property` |
| Bornes « renforcées » wide-trail | invalides (B ≥ 13 non établi) | retirées | `test_banc_cryptanalyse` |
| Contrôle trivial | `best_char` comparé à `DDT.max()` (= 16, ligne 0) | `DDT[1:].max()` | `test_diff_lin_empirique` |
| Performances | permutation par boucle de tours | noyau fusionné (table S∘·c par arête et par tour), **+30 %**, KAT inchangé | `bench_perf`, `bench_tailles` |

Benchmark par taille (`resultats/BENCH_TAILLES.md`) : 0 o → 1 Mio, 4
natures de contenu, allers-retours tous vérifiés ; ≈ 100 Kio/s en
AEAD-128 et ≈ 50 Kio/s en AEAD-256 ; coût fixe hybride KEM ≈ 1,7 / 2,2 ms.

## 5. Troisième passe : tests intensifs en C

Noyau C/OpenMP (`tests/c/noyau.c`, chargé par `tests/noyau_c.py`) : tables
reprises de `sillage/brume512.py`, conformité bit à bit vérifiée avant
chaque test, ≈ 700 000 permutations/s à 32 tours (×127 par rapport au
Python). Les tailles d'échantillons sont multipliées par 100 à 8 000.

| Test | Mesure | Résultat |
|---|---|---|
| `test_c_integral` | cubes 2¹⁶–2²⁴ (nibbles aléatoires, voisinage du graphe, bits isolés), direct et inverse | 4 tours (direct), 2 (inverse) ; 5 tours aléatoires même à 2²⁴ ; cohérent avec DP ≤ 14 / 11 |
| `test_c_diff_lin` | différentielle 2 tours sur 2²⁷ paires ; hull 2 tours sur 2²⁸ | facteurs 0,99 ± 0,04 et 1,004 ± 0,016 : **aucun effet d'agrégation** à 2 tours |
| | tronquées et linéaires alignées sur les S-box (couche linéaire extrême retirée) | 5 tours (direct), 2 (inverse) en tronqué ; 1 tour en linéaire à un nibble |
| `test_c_sac` | SAC 512 × 512, 2¹⁶ échantillons par bit, tour par tour | indistinguable dès 5 tours (direct), 2 (inverse) ; conforme à 32 tours |
| `test_c_statistiques` | 34 tests type NIST sur 1 Gio (compteur), 512 Mio (éponges), tours réduits | conforme à 32 tours (p_min 0,054 / 0,024, KS 0,23 / 0,89) ; échec jusqu'à 4 tours, conforme dès 5 |
| `test_c_kem_bruit` | 3,4·10⁷ (128) et 8,4·10⁶ (256) bruits de décodage simulés, recoupés avec le KEM réel | borne δ ≥ mesure à tout seuil observable, marge ≈ 18 bits ; max 129 / 265 et 202 / 476 bascules |

Campagne poussée (intensité ×4 à ×8, `resultats/<test>_x<k>.json`) :

- cubes de 2²⁸ : le sens inverse passe à 3 tours, le direct reste à 4 ;
- différentielle à 2 tours (2²⁹ paires) : facteur 1,013 ± 0,022 ;
- hull à 2 tours (2³⁰ échantillons) : facteur 1,011 ± 0,008 ;
- SAC (2¹⁸ échantillons par bit) : inchangé ;
- batterie statistique sur 4 Gio en compteur et 2 Gio d'éponges : conforme ;
- bruit KEM (1,3·10⁸ tirages) : marge de la borne de 19 bits, maximum de
  132 bascules pour un seuil de 265.

Le distingueur empirique le plus long couvre **5 tours (direct) + 3
(inverse) = 8 tours inside-out sur 32**. La borne δ est valide et prudente :
elle surestime d'environ 2¹⁸ la fréquence mesurée aux seuils observables.
Une borne plus fine permettrait peut-être de réduire n, mais les
paramètres ne reposent que sur la borne prouvée.

## 6. Quatrième passe : implémentation C, analyses complémentaires

**Implémentation C** (`sillage/c/`) : portage complet de la suite (BRUME-512,
AEAD, TE, hachage, KEM avec borne δ en keygen, SIG, SHAKE256),
**conforme octet pour octet** au Python et interopérable dans les deux
sens (`test_c_impl`, 26 contrôles). Benchmark sur un cœur
(`resultats/BENCH_C.md`) :

| Mesure | Résultat |
|---|---|
| Permutation | 4,5 µs ; AEAD-128 à 6,8 Mio/s (×69 à ×78 par rapport au Python), AEAD-256 à 3,4 Mio/s |
| KEM-128 | keygen 1,1 ms, encaps 0,28 ms, decaps 0,41 ms (×4 à ×6) |
| SIG-128 | signature 53 ms, vérification 37 ms (×14 à ×16), environ 129 Ko |

**Analyses complémentaires :**

| Test | Résultat |
|---|---|
| `test_c_cube_init` (cubes de nonce sur l'initialisation réduite) | sommes nulles jusqu'à 4 tours ; **aucun superpoly linéaire** (20 + 20 essais BLR par bit) → pas de récupération d'état ; chemin réel de 64 tours |
| `test_c_degre` (sous-espaces aléatoires) | degré maximal 3, 9, 27 atteint aux tours 1–3, dans les deux sens ; borne de Boura–Canteaut respectée |
| Division property (faisceau élargi, 24 nouvelles pistes vérifiées) | direct ≤ 14, inverse ≤ 11 (avant : 15 et 12) → **inside-out ≤ 25** ; en inverse, 10 ≤ portée ≤ 11 |

**Défauts de méthode corrigés pendant la passe** (dans les tests, pas dans
SILLAGE) :
- une sonde linéaire mono-bit était aveugle par construction ;
- un test de degré sur bits isolés était invalide dans le sens direct ;
- un test de linéarité à 10 essais produisait 1,5 faux positif par tour.

## 7. Cinquième passe : performances sans changer l'algorithme

Objectif : un débit élevé, avec les mêmes sorties et les mêmes KAT, et
sans recul de sécurité.

| Élément | Résultat | Sécurité |
|---|---|---|
| Permutation AVX2 d'un état (structure de Cayley de D₁₂₈ : réflexions → échange de moitiés et rotation d'octets ; S-box et log/exp de GF(16) par `vpshufb`) | 0,41 µs (×11) ; AEAD-128 d'un seul message : 79 Mio/s | **constant-time** (dudect, seuil \|t\| < 4,5) ; elle remplace des tables indexées par l'état |
| Lots de 32 états, AEAD et hachage multi-messages (OpenMP, choix automatique lots ou un message par cœur) | 0,19 µs par état ; AEAD-128 : 624 Mo/s (messages de 1 Kio), 713 Mo/s (16 Kio) sur 12 threads | constant-time |
| Décapsulation KEM (Python et C) | ré-encapsulation systématique, choix par masque, décodage sans branchement | supprime un **oracle d'échec de décodage** (≈ 0,28 ms d'écart), vecteur des attaques par réaction |
| Tirage creux (C) | nombre de mots fixe (P(insuffisant) < 2⁻¹²⁸), acceptation sans branchement ; mêmes positions | supprime la fuite par nombre de rejets (« Don't Reject This », CHES 2022), **détectée par dudect** dans la ré-encapsulation (t = −53) |
| Produits du KEM (C) | représentation dense, Karatsuba + PCLMULQDQ, écriture des bits par balayage masqué ; décapsulation 0,95 / 5,1 ms | **KEM C constant-time** : dudect sous le seuil \|t\| < 4,5 pour l'oracle FO et pour la clé secrète (clés de même σ_h) ; plans refaits à la douzième passe (§ 14) |
| `test_c_impl` (34 contrôles), `test_c_temps` (4 contrôles) | sorties identiques au Python pour tous les chemins (unitaire, AVX2, lots) | — |

Pistes mesurées mais **non adoptées**, car elles modifient l'algorithme
(duplex parallèle, moins de tours en phase de données), et fuites
résiduelles de faible priorité (SIG) : `docs/PISTES.md`, avec les
conditions de sécurité de chacune.

## 8. Sixième passe : preuve du mode, division property exacte, sûreté mémoire

| Élément | Résultat |
|---|---|
| **Preuve du mode AEAD** (`docs/PREUVES.md` § 4.3, Théorème 14) | Lemme 1 : remplacer le débit par le clair revient à absorber le chiffré par XOR ; le mode est un duplex à clé standard, sans drapeau d'écrasement. Lemme 2 : codage injectif et sans préfixe. Lemme 3 : absorption de la clé en N/2ᵏ + 2N/2ᵇ + N/2ᶜ. Lemme 4 : collisions de capacité. Borne AE : σ²/2^{c+1} + 2σN/2ᶜ + N/2ᶜ + N/2ᵏ + q_d/2^τ, soit 128 et 256 bits pour σ ≤ 2⁶⁴ |
| `test_mode_aead` (9 contrôles) | le duplex abstrait de la preuve, écrit sans brume512.py, redonne exactement chiffrés et tags (deux profils) ; codage injectif et sans préfixe sur 441 chemins limites par profil ; aucun clair libéré en cas de refus |
| **Division property exacte** (`tests/dp_cpsat.py`, `tests/dp_sat.py`) | modèle exact (mêmes règles que le vérificateur, bit inactif libre), fenêtres de poids correctes (dont Boura–Canteaut sur F⁻¹), infaisable pour R ≤ 10 ; à R = 12, une piste revérifiée en 18 min ; à 11 tours, les requêtes UNSAT ciblées ne concluent pas en 25 min → **valeur exacte non atteinte** (piste 6) |
| **Correction de portée** | les bornes hautes de division property (14 / 11 / 25) ne valent que pour le cube au bit 0 inactif ; la documentation les présentait comme générales. Seule la borne basse (10 par sens) vaut pour tout cube |
| `test_c_fuzz` (3 contrôles) | sûreté mémoire du C : UBSan en mode trap et allocateur à pages de garde (débordement de tas → faute, écriture dans le bourrage → canari, utilisation après libération → faute), validés sur des erreurs volontaires ; 2 000 itérations sur toutes les API : **aucune erreur mémoire ni comportement indéfini** |
| `test_dp_modele` | cohérence (infaisable pour R ≤ 10), complétude (les pistes vérifiées sont acceptées) |
| Performances, sans changer les sorties | `log∘S` fusionné (−7 %), IV précalculé, contexte de clé, Keccak déroulé, Karatsuba en VPCLMULQDQ ; un message de 1 Mio : 83 Mio/s ; KEM : 0,60 ms en décapsulation ; SIG : 31 ms ; multi-messages : 628 à 705 Mo/s |

## 9. Septième passe : portée exacte de la division property (piste 6)

| Élément | Résultat |
|---|---|
| **Recollement** (`test_dp_tous_cubes`, PREUVES Lemme 12 ter, Corollaire 12 quater) | la première couche linéaire déplace librement les bits inactifs ; un couplage (Hopcroft–Karp) dans le graphe biparti de L transporte chaque piste du cube 0 vers les 511 autres cubes. 27 pistes × 512 cubes = 13 824 recollements, **tous revérifiés**, aucun échec. Les bornes 14 / 11 / 25 valent pour **tous** les cubes |
| **Décomposition** (`tests/dp_queue.py`, Lemme 12 quinquies) | préfixe d'une piste vérifiée + suffixe exact par CP-SAT vers un bit imposé, sur un modèle réduit aux bits atteignables et co-atteignables (environ 1 s par requête, contre plus de 25 min sans conclusion pour le modèle complet) |
| **Portée exacte** (`test_dp_exact`, Théorème 12 sexies) | 18 pistes directes à 11 tours obtenues à partir de préfixes de pistes à 12 et 13 tours, puis une piste vérifiée vers **chacun des 512 bits à 11 tours, dans chaque sens** (1 024 pistes, 12 min). Portée de la division property : **exactement 10 tours par sens, 20 inside-out, pour tout cube** (au lieu de 10 ≤ · ≤ 14 / 11 / 25 pour un seul cube) |
| Coupes par nibble (`test_dp_modele`) | wt(u) ≤ 3·[v ≠ 0] + [v = F] et cw(v) ≤ 3·[u ≠ F] + [u = 0], vérifiées sur les 3 194 transitions de toutes les tables exactes ; elles n'ont pas suffi à faire conclure le modèle complet (UNSAT à 11 tours arrêté : le bit visé a en fait une piste) |
| Limite de l'énoncé | une piste montre que la méthode ne prouve plus l'équilibre, pas que la somme est non nulle (pistes en nombre pair) ; le distingueur intégral réel reste mesuré empiriquement (4 tours en direct, 3 en inverse) |

## 10. Huitième passe : signature constant-time (piste 3), hachage arborescent (piste 5)

| Élément | Résultat |
|---|---|
| **Fuite de la SIG C** (avant) | π matérialisé puis lu aux indices π(i), échanges de Fisher–Yates à indices secrets, lignes de H sautées selon les bits de u et e : un espion de cache pouvait retrouver π dans un tour de défi 2, donc e = π⁻¹(π(e)). Mesure dudect sur l'ancien chemin : t ≈ −220 à −460 |
| **Correction** (`sillage/c/sig.c`) | π n'est plus construit : les échanges de Fisher–Yates (mêmes tirages) sont appliqués par balayage masqué aux plans de bits de u et e, puis H·u et H·e sont masqués (H·u groupé sur les t tours). Signatures identiques (`tests/c/sig_ct.c` : 600 essais, conformité exacte ; interopérabilité Python inchangée) |
| Temps constant mesuré | tour du signataire à échanges donnés : t ≈ 0,4 à 1,8 ; signature complète, clé fixe contre clés aléatoires : t ≈ −0,6 à −1,5 (seuil 4,5) |
| Tirage des échanges | durée variable selon les rejets, qui ne portent que sur les valeurs rejetées du flux (indépendantes de π) ; graine σ_π fraîche de λ bits, non énumérable |
| Keccak-f à 4 voies (AVX2, vecteurs gcc) | flux SHAKE des tirages 4 blocs à la fois, sorties identiques : SIG-128 signe en 29 ms (31 avant, non constant-time), vérifie en 12 ms (20) ; SIG-256 : 166 / 50 ms (130 / 86) |
| **Hachage arborescent** (`brume512_hash_arbre`, `sl_hash_arbre`) | feuilles de 8 Kio par lots de 32 sur tous les cœurs, racine CV ‖ k ‖ B, domaines FEUILLE / RACINE / SEUL dans la capacité. Preuve : PREUVES § 4.4 (Théorème 16, conditions de BDPV 2014). 16 Mio : 160 Mo/s sur un cœur, 785 à 850 Mo/s sur 12 threads (86 en séquentiel) |
| `test_hachage_arbre` (14 contrôles) | modèle du mode ≡ Python ≡ C sur 13 longueurs limites ; décodabilité, complétude, séparabilité vérifiées ; altérations structurelles ; déterminisme multi-thread ; KAT figés |
| `test_c_fuzz` | étendu au hachage arborescent (60 longueurs jusqu'à 5 feuilles, chemin par lots comparé au recalcul feuille par feuille, sous pages de garde) : aucune faute |

## 11. Neuvième passe : audit externe

Rapport reçu sur la première version de l'artifact, reproduit avec la
réponse point par point (non publiés).

| Point | Verdict | Correction |
|---|---|---|
| H1 / H2 du KEM distinguables par la parité (s(1), u(1) publics) | **confirmé**, défaut de preuve | hypothèses H1-P / H2-P avec parité (comme HQC), preuve IND-CPA refaite ; schéma et KAT inchangés ; contrôles de l'invariant dans `test_kem` |
| Borne AEAD et « 128 bits » | rédaction trompeuse, borne juste | notion coût/avantage définie ; Corollaire 14 bis terme par terme (128 / 256 bits pour σ ≤ 2⁶⁴) ; cas N = 2¹²⁸ commenté |
| Jeu idéal AEAD | rédaction ambiguë | restriction standard (pas de déchiffrement d'une sortie de Enc) explicitée |
| SIG : facteur q_H | facteur réel, t justifié au sens coût/avantage | budget terme par terme ; terme de programmation resserré à q_S(q_S + q_H)/2³⁸⁴ |
| Niveau quantique du KEM | formulation | profils nommés d'après le niveau classique ; aucun niveau quantique revendiqué |
| Sécurité globale de BRUME, DP, temps constant, multi-utilisateur | formulations | précisées (README, PREUVES § 4.3 remarques 4 et 5) |
| SIG C non constant-time | déjà corrigé (huitième passe) | — |
| Reproductibilité | ajout | `tests/empreintes.py` → `resultats/EMPREINTES.md` |

## 12. Dixième passe : hypothèses et problèmes ouverts (en C)

Désormais, tout nouveau travail est en C. Le Python reste la référence
figée (KAT). Les tests C natifs écrivent eux-mêmes leur
`resultats/<nom>.json` (`tests/c/resultat.h`, `tests/c/Makefile`), et le
lanceur `run_all` les exécute par un crochet « c:<nom> ».

| Élément | Résultat |
|---|---|
| **H1-P / H2-P / H3 : ISD réel** (`tests/c/isd_reel.c`) | Prange sur instances réduites de même structure. Le coût mesuré suit la formule de l'estimateur, avec des ratios de 0,93 à 1,02 sur trois tailles quasi-cycliques (n premier d'Artin) et deux codes aléatoires. Gain quasi-cyclique (n syndromes décalés) mesuré à ×163 pour n = 149 : il égale le crédit de log₂ n de l'estimateur. Rang des différences de s égal à n − 1 sur 6 premiers d'Artin : **la parité est le seul invariant linéaire** |
| **Différentielles impossibles / corrélations nulles** (`tests/c/structure_miss.c`) | miss-in-the-middle au niveau des nibbles, motifs de poids ≤ 2 : **5 tours** au plus dans les deux cas (marge de 27 tours). Les règles de propagation sont validées sur 1,4·10⁶ prédictions confrontées à des différences réelles (0 violation). Densité du support : M 5,5 %, M⁻¹ 94 % |
| **AEAD multi-utilisateur** (PREUVES Théorème 14-mu) | preuve rédigée en entier : termes du Lemme 3 multipliés par μ, plus μ²/2^{k+1} ; 128 / 256 bits pour μ ≤ 2⁶⁴ et σ ≤ 2⁶⁴ au total |
| **Lemme 15 rédigé en entier** | simulateur et événement mauvais. **Correction** : le terme est 7q²/2^{c+1}, et non q²/2^{c+1}, car avec les domaines dans la capacité, deux capacités qui diffèrent d'une valeur de D ⊕ D rendent un appel ambigu. Le niveau n'en est pas affecté |
| **Adversaire quantique** (PREUVES § 5 bis) | **SIG : ≈ 64 / 128 bits seulement**, car Grover s'applique à Fiat–Shamir en √((3/2)^t) ; KEM ≈ 91 / 158 ; collisions de hachage ≈ 2⁸⁵ (BHT) ; AEAD : clé en 2²⁵⁶. Les profils sont classiques ; des profils SIG quantiques sont notés (piste 7) |

## 13. Onzième passe : audit externe, seconde passe

Rapport et réponse détaillée non publiés.

| Point | Verdict | Correction |
|---|---|---|
| Support de la diffusion « 128 en 3 tours » | **confirmé** : erreur de l'artifact (la batterie mesurait 5 tours) | `diffusion_support` (C) : supports exacts 7, 37, 94, 127, 128 (combinatoire = dépendance réelle par la permutation), bornes du groupe diédral recalculées, M⁻¹ complet en 2 tours ; densité 15/16 des puissances linéaires sur GF(16) ; graphe biparti, λ* = 3,5076 recalculé hors ±6. PREUVES Proposition 10 bis |
| D ⊕ D du Lemme 15 | **en partie** : 7 est juste pour D = {0, 8, 9, 10} (F_0 compris), mais D n'était pas défini dans l'artifact | définition et cas {8, 9, 10} (facteur 4) explicités ; hachage arborescent ramené à « en validation » |
| Modèle des bornes 2⁻²⁵⁶ / 2⁻¹²⁸ | **confirmé** | Corollaire 11 : activité certifiée, probabilités sous le modèle de Markov (hypothèse) ; résumé qualifié |
| H1-P / H2-P | **confirmé** : reste une hypothèse | `kem_distributions` (C) : parité de u seul invariant linéaire de H2-P (5 instances réduites) ; aucun biais ni corrélation u / v / s aux tailles réelles (11 contrôles) |
| Relecture AEAD | **confirmé** | « prouvé, non relu » dans tous les résumés |
| Revue du code constant-time de la SIG | **confirmé** | `sig_flux` (C) : sig.c instrumenté (`-fsanitize-coverage=trace-pc`), 40,3·10⁶ blocs de base identiques pour 6 clés (dont une structurée), génération de clé et fonctions masquées idem, témoin détecté ; sonde de test `-DSL_SONDES` (condensé public imposé), absente du code de production ; code machine de `appliquer_echanges_ct` inspecté (sauts sur compteurs publics) |

## 14. Douzième passe : campagne de nuit du 2026-10-30, corrections

Le run de 8 h (477 min) a signalé 2 échecs dudect sur le KEM, et sa relecture a
montré plusieurs tests sans pouvoir de détection. Le code cryptographique n'a
pas changé ; seuls les bancs et les campagnes ont été corrigés. Les résultats
de ce run restent dans `resultats/NUIT.md` jusqu'au prochain lancement, qui les
archivera.

**Échecs dudect (t = −5,68 / −6,75).** Le plan de `temps.c` opposait un chiffré
fixe à des chiffrés variés et confondait ainsi valeur publique et secret. Plans
séparés, 600 000 mesures par mode :

| Mode | Écart | t |
|---|---|---|
| Valeur du chiffré seule (fixe contre 256 honnêtes) | +197 cycles | −5,23 |
| Accepté / rejeté (256 honnêtes contre 256 aléatoires) | +18 cycles | −0,47 |
| Secret seul (clé fixe contre 64 clés, même chiffré) | −28 cycles | 0,69 |

L'effet vient donc de la répétition d'un chiffré public. **Son mécanisme n'est
pas identifié.** Il n'expose aucun secret dans ces plans, ce qui reste une
mesure et non une preuve.

Nouveaux plans (réserves de chiffrés communes aux classes, recopie dans un
tampon de mesure commun, cœur épinglé) :

| Plan | Mesures | t |
|---|---|---|
| `kem_oracle` : décodage, honnêtes contre aléatoires | 1 200 000 | 0,15 |
| `kem_oracle_fo` : comparaison FO, un bit de v inversé | 1 200 000 | −1,59 |
| `kem_decaps` : clé fixe contre 64 clés de même σ_h | 1 200 000 | −0,56 |
| `kem_encaps` : μ fixe contre aléatoire | 1 200 000 | −2,81 |
| `kem_aa` : biais du banc (A/A) | 600 000 | 0,58 |
| `kem_temoin` : témoin, +300 cycles injectés | 300 000 | **−6,84, détecté** |

Sensibilité : environ ±40 cycles sur 2,5 M, à comparer à une médiane qui varie
de 2,507 à 2,620 M cycles d'un processus à l'autre.

**Défauts de la campagne, corrigés :**

| Défaut | Correction |
|---|---|
| Contrôle « aucun distingueur au-delà de 7/5 » impossible à échouer (tests limités à 6/5) | portée propre à chaque famille et contrôle de couverture : `chaque_famille_testee_au_dela_de_sa_portee_connue`, `aucun_distingueur_au_dela_de_la_portee_connue` |
| Tronquées de nuit (Δ = 0, sans M⁻¹ en sortie) aveugles au biais connu | χ² aligné à 15 ddl ; témoins à 5 tours direct et 2 inverse, détectés (χ² = 15·N : prévisible, M⁴ laisse un nibble hors support) |
| « Distingueur nouveau » à 3 tours inverse, déjà connu | classé en témoin (3³ = 27 < 28) |
| Cubes isolés peu sensibles ; 227 bits nuls (z = −2,56) à 4 tours inverse | séries de 32 cubes (z total, bit le plus déséquilibré, Bonferroni 512) et recontrôle à 2³² |
| Cubes de 2³⁶ jamais lancés | ordonnancement revu, repli à 2³⁴ pour le cube inverse |
| Contrôle de la borne du KEM tautologique | recalcul naïf indépendant sur 1 clé sur 64 |
| Campagne KEM : 57 227 décapsulations réelles seulement, rejet implicite non testé | recoupement 1/64, rejet implicite, pire clé, taux de rejet de keygen |
| Fuzzing pauvre en KEM et SIG | processus dédiés, entrées extrêmes (chiffrés et clés tout 0 / tout 1, u ou v nul, signatures vides ou de longueur maximale, message vide) |
| Dérive ISD aléatoire (1,07 / 1,17 / 1,22, contre 0,92 auparavant) laissée sans verdict | 300 instances à n = 280, écart cumulé (Stouffer), contrôle `pas_de_derive_systematique_de_la_formule` ; gain QC mesuré sur 4 tailles |

**Erreur introduite puis corrigée pendant cette passe.** La nouvelle linéaire
jointe comptait 225 ddl au lieu de 255 (uniforme sur 256 cases, marges connues),
d'où des p-valeurs trop petites (0,007 à 2 tours, 0,7 une fois corrigée). Le
χ² stable de 2²⁴ à 2³⁰ l'a trahie : un vrai biais aurait crû avec l'échantillon.
Le contrôle `statistiques_chi2_calibrees_sous_h0` vérifie désormais la moyenne à
12 tours (254,88 pour 255 ; 14,94 pour 15).

**Vérifié :** campagne de 15 min sur une copie du dépôt, aucun contrôle en échec
(fuzz 271 000 itérations, 0 échec ; KEM 12/12 ; ISD 3/3), puis campagne de
cryptanalyse de 330 s après correction des ddl (5/5). `test_c_temps` : 10/10 ;
`test_c_fuzz` : 3/3.

**Non vérifié :** la campagne complète de 8 h avec ces plans n'a pas été
relancée, donc les cubes de 2³⁶ et les grands échantillons restent à mesurer.
Le contrôle de la dérive ISD n'a porté que sur les petites tailles. ASan et le
fuzzing guidé par couverture restent indisponibles ici (UBSan et pages de garde
seulement).

## 15. Avis de synthèse

**BRUME-512.** Rien de ce qui a été lancé ne l'entame.
- Les bornes prouvées (B = 8 exact, caractéristiques ≤ 2⁻²⁵⁶ et trails
  ≤ 2⁻¹²⁸ à 32 tours) tiennent.
- L'agrégation mesurée est nulle à 2 tours (facteurs 1,01 ± 0,01).
- Tous les distingueurs empiriques s'arrêtent à 5 tours en direct et 3 en
  inverse, soit 8 tours sur 32, avec des échantillons jusqu'à 2³⁰ et des
  flux de 4 Gio.
- La portée de la division property est connue exactement : 10 tours par
  sens, 20 inside-out, pour tout cube (septième passe).
- Le degré croît au maximum, et l'on ne trouve ni symétrie ni invariant.

La marge est confortable : 12 tours au-delà de la portée exacte de la
division property (20 inside-out), 24 au-delà des distingueurs mesurés.
L'incertitude théorique qui fixait le plancher (portée DP directe de 10 à
14 tours) est levée. Le coût est
élevé : environ 140 cycles par octet pour la permutation de référence.

**Sillage-KEM.**
- Correct, IND-CCA en ROM sous QCSD décisionnel avec parité (H1-P / H2-P,
  formulation corrigée après l'audit externe), avec un δ prouvé clé par clé et
  validé empiriquement (borne prudente d'environ 18 à 20 bits).
- La marge de sécurité est modeste : 137 bits estimés pour 128 visés, ce
  qui la rend sensible à tout progrès des algorithmes ISD sur les codes
  quasi-cycliques creux. Ce niveau est classique : l'estimation quantique
  Prange–Grover est de 91 bits.
- La cascade de bruit n'apporte rien à la sécurité.
- Le code à répétition donne des chiffrés de 17 Ko.

**Sillage-SIG.** Stern conforme, sûre sous SD, mais très coûteuse : environ
131 Ko par signature et 29 ms en C, désormais constant-time. C'est le prix d'une base de référence.

**Ce que ces tests ne montrent pas.** Ils couvrent les familles d'attaques
connues : différentielle, linéaire, intégrale/DP, cubes, algébrique,
statistique, génériques. Ne rien trouver est une condition nécessaire,
pas une preuve. Une conception originale (diffusion de Cayley pondérée
sur D₁₂₈) peut avoir des faiblesses structurelles qu'aucun outil
standard ne vise.

**Ce qui augmenterait le plus la confiance :**
1. une cryptanalyse tierce ;
2. une relecture du Lemme 15 et du Théorème 16 (hachage arborescent) ;
3. une relecture tierce de la preuve du mode AEAD (§ 4.3 de PREUVES.md,
   rédigée) et du Théorème 12 sexies.

## 16. Limites assumées

- Les bornes prouvées portent sur les caractéristiques et trails
  individuels, et sur l'agrégation à 2 tours. Au-delà, on dispose d'une
  mesure (facteur 1,1) et d'une marge de plus de 2 500 bits, sans preuve.
- Division property : la portée exacte (10 tours par sens) est celle de
  la méthode fondée sur l'existence de pistes. Le distingueur intégral
  réel, qui dépend de la parité du nombre de pistes, n'est mesuré
  qu'empiriquement.
- Mode AEAD : preuve rédigée (Théorème 14) et reliée au code par
  `test_mode_aead`, mais pas encore relue par un tiers.
- Canaux auxiliaires : BRUME-512, le KEM et la SIG en C sont
  constant-time (vérifiés par dudect) ; l'implémentation Python ne l'est
  pas. Le tirage de Fisher–Yates de la SIG garde une durée variable,
  indépendante de π. L'effet de la répétition d'un chiffré public sur la
  décapsulation (≈ 200 cycles sur 2,5 M, § 14) n'est pas expliqué.
- Niveaux quantiques inférieurs aux niveaux nominaux (PREUVES § 5 bis),
  en particulier pour la SIG (≈ λ/2) ; réductions QROM citées, non
  instanciées.

---

## Errata du 2026-10-30 (relecture de Sillage-SIG, ISD, Théorème 16)

Ces points corrigent les valeurs citées plus haut, qui restent en l'état comme trace.
Détail : `docs/PREUVES.md` § 3, § 4.4, § 5 et § 5 bis ; historique du `README`.

- **SIG-256 valait ≈ 128 bits, pas 256** : σ_π de 128 bits et hachés de 256 bits. Corrigé,
  et format modifié. SIG-128 garde ses tailles.
- **ISD de la SIG :** 159,7 / 314,9 bits, au lieu de 160,5 / 327,2.
- **SIG quantique :** l'attaque par Grover sur σ_π s'ajoute à Fiat–Shamir. « ≈ 128 bits » pour
  SIG-256 n'est vrai qu'après correction. Piste 7 corrigée.
- **Canaux auxiliaires :** deux accès dépendant d'un secret, trouvés par Valgrind et que dudect
  n'avait pas vus. L'un touche aussi le KEM (`sl_creux`).
- **Lemme 15 et Théorème 16 :** preuve complétée, voir le statut au § 4.4. **La relecture faite
  est celle d'une IA ; le point « relecture par un tiers » reste ouvert.**

## Errata du 2026-11-01 (banc dudect)

Les « OK » de `aead` et `kem_decaps` dans `resultats/NUIT.md` du 2026-10-31 ne tenaient qu'à une
seconde mesure. Le run `resultats/special/20261101_131954` (4 valeurs × 3 processus) retrouve des
écarts reproductibles (|t| jusqu'à 26 sur `aead`, 7 sur `kem_decaps`). **Origine non élucidée à
cette date.** Corrections du banc :

- **Seconde mesure :** elle ne blanchit plus un dépassement (`scripts/rundenuit.sh`, `tests/test_c_temps.py`).
  Elle retirait ses valeurs fixes et sa disposition mémoire, donc ne retestait pas la même chose.
- **`kem_decaps` :** la classe aléatoire n'utilisait que 8 clés sur 64 (`idx[i] &= NK - 1`).
  Corrigé ; les mesures antérieures portent sur 8 clés.
- **`aead` :** les classes étaient préparées différemment (deux appels système par entrée pour
  l'une, `memcpy` pour l'autre). Nouveaux plans `aead_sym`, `aead_aa_fixe`, `aead_aa_alea`,
  `kem_decaps_aa`, mesurés par `./scripts/runspecial`, avec et sans ASLR.
- **Verdict de `./scripts/runspecial` :** il se juge sur toutes les graines (permutation du F), plus sur une
  seule graine répétée.

## Errata du 2026-11-02 (AEAD : temps dépendant de la clé, corrigé)

**`kem_decaps` : artefact du banc.** Le plan d'origine recopiait la clé fixe depuis une seule zone mémoire, contre 64 pour la
classe aléatoire. Dans le même binaire, sans ASLR, il dépasse 5 fois sur 9 (t_p50 : 9 sur 9), et le plan symétrique 0 fois sur 9.
`kem_decaps` mesure maintenant le plan symétrique ; l'ancien reste comme témoin (`kem_decaps_asym`).

**`aead` : vraie dépendance à la clé, liée à la position de l'état `w` de `duplex()` et de `sl_aead_cle()` dans une ligne de
cache.** Mesures de `./scripts/runspecial`, 62,5 M ou 12,5 M d'appels par point, seuil |t| = 4,5 :
- **Signe et clé.** Le signe suit la clé (aead_cle dépasse jusqu'à |t| = 29, aead_clair jamais). L'écart est minuscule : 0,2 cycle
  au plus sur environ 13 100.
- **Causalité.** Forcer la disposition de la pile fait apparaître l'écart (6 sur 6) ou disparaître (0 sur 6) à volonté.
- **Grille de positions** (`--bloc grille` et `grille1`). La position du contexte de clé n'a aucun effet. Avec une position de `w`
  imposée, 1 seul dépassement sur 96 mesures (t = 4,63, `w` à 32 octets), alors que les témoins du même run dépassent (t = −6,08 et
  +8,87, signes opposés selon la graine). `w` à 32 octets d'une ligne garde un biais faible, de signe constant quelle que soit la clé
  (24 mesures sur 24 positives, t de 0,8 à 4,6) ; à 0 octet, |t| ≤ 1,98.
- **Correctif.** Tout état `w` de 64 octets sur la pile est aligné sur 64 octets (`sillage/c/brume512.c`, `brume512_avx2.c`). Sorties
  inchangées : `test_c_impl` 38/38.
- **Confirmation** sur le binaire de base corrigé (`--bloc confirme`, run 20261102_152718) : 0 dépassement sur 24 mesures, dans les
  deux dispositions de pile (aead_cle 4 graines, aead_sym 2 graines, 2 passages), |t| ≤ 2,16, signes mêlés ; témoin +300 cycles détecté.

**Mécanisme non identifié** (processeur Zen 3) : l'alignement supprime l'écart, il ne l'explique pas. Une autre microarchitecture ou un
autre compilateur peuvent se comporter autrement ; dudect reste à refaire sur toute nouvelle machine.

## Errata du 2026-11-02 (H1-P / H2-P, revue du code C)

**Théorème 1 : un pas de preuve faux, corrigé.** Le Jeu 1 bornait la perte due au rejet des clés par
un facteur `1/(1 − ε_rej)` sur l'avantage de H1-P. Ce facteur vaut pour un problème de recherche, pas
pour un avantage de distinction : l'acceptation dépend de (x, y), que (h, s) détermine, et la borne
correcte garde un terme additif ε_rej (5 et 8 %). H1-P est maintenant posée sur la loi réelle des clés
acceptées. La version calculatoire, elle, se transfère, avec une perte d'au plus 0,13 bit : les coûts
d'ISD sont inchangés. Le schéma, les KAT et les niveaux sont inchangés (`docs/PREUVES.md` § 1 et § 2.1).

**Lemme 0 (nouveau, prouvé) : spectre linéaire exact de H1-P et H2-P.** Chaque biais linéaire est
un produit de polynômes de Krawtchouk. Corollaire : la parité de s (resp. de u) est le seul invariant
linéaire, à toutes les tailles. Jusqu'ici, ce n'était mesuré que sur instances réduites. Un
distingueur linéaire revient à trouver un mot de poids faible. L'estimation, heuristique, donne
139 bits pour 128 et 267 pour 256, au niveau de l'ISD. Vérification exhaustive en entiers par
`tests/c/h1p_fourier.c` (6 contrôles). Les mesures de l'artefact sont reproduites :
`isd_reel` 5/5 (Prange 2^8,20, 2^10,16, 2^12,36 ; gain QC ×163), `kem_distributions` 11/11.
**H1-P et H2-P restent des hypothèses** : les distingueurs non linéaires sont hors preuve.

**Théorème 16 : relu à nouveau** (Lemme 15, trois conditions de BDPV, composition) ; aucun défaut
trouvé, et `test_indiff_arbre` passe (15/15). C'est encore une relecture d'IA : le statut « en
validation » reste en place jusqu'à une relecture humaine.

**Revue du code C (externe, non publiée), suivi constat par constat :**

| Constat | État | Correction |
|---|---|---|
| C-01 repli scalaire non constant-time | **corrigé** | `#error` sans AVX2 ni NEON ; le repli à tables demande `-DSL_REPLI_NON_CT` (seul `test_c_simd` l'utilise, pour comparer) |
| C-02 longueurs absentes des API | **corrigé à la frontière** | `sillage_c.py` vérifie pk, sk, ct, mu, x, y avant tout appel C ; l'API C garde son contrat de tailles fixes, documenté |
| C-03 profils et niveaux | corrigé (commit 55bb6aa) | — |
| C-04 allocations non vérifiées | **corrigé** | `sl_malloc` / `sl_calloc` : arrêt net plutôt que pointeur nul déréférencé ; `sl_calloc` refuse le débordement de n × taille (lots) |
| C-05 secrets non effacés | corrigé (55bb6aa) | — |
| C-06 caches `_Thread_local` | ouvert | demande une API de contexte ; sans effet tant que le pool OpenMP est stable |
| C-07 TE : capacité, mutation partielle | **corrigé** | validation de tous les blocs avant toute correction (ct intact si −2) ; capacité de `corrections[]` documentée |
| C-08 débordements de longueur | **corrigé** | arrondis `len / B + (len % B != 0)` (TE, arbre, AEAD parallèle) ; `l1 + l2` borné par l'espace d'adressage |
| C-09 préconditions internes | corrigé (55bb6aa) | — |
| C-10 `ferror | fclose` | corrigé (55bb6aa) | — |
| C-11 petit-boutiste | corrigé (55bb6aa) | `_Static_assert` dans `sillage.h` |
| C-12 `-march=native` | ouvert | politique de build ; C-01 rend explicite tout build sans SIMD |
| C-13 tests en CI | **étendu** | la CI lance `revue_c` et contrôle les tables générées |
| C-14 domaine de `sl_kem_borne` | **corrigé** | renvoie 0 (aucune garantie) si le poids de x ou y diffère de w |
| C-15 clé publique non canonique | **corrigé** | `sl_kem_encaps_det` refuse les bits de bourrage de s (−3) |
| C-16 tables générées | **corrigé** | job CI : `make tables` puis `git diff --exit-code` (reproduit à l'octet en local) |
| C-17 `getrandom` / EINTR | corrigé (55bb6aa) | — |
| C-18 en-tête public / interne | ouvert | réorganisation sans effet sur la sûreté |
| C-19 allocateur de garde | corrigé (55bb6aa) | — |

Contrôles : `tests/c/revue_c.c` (6/6) ; `test_api_c`, `test_c_impl`, `test_te`, `test_c_fuzz`, `test_c_simd`,
`test_kem`, `test_fonctionnel`, `test_robustesse`, `test_hachage_arbre`, `test_aead_parallele` réussis.

## Errata du 2026-11-03 (cryptanalyse : invariants, rejet des clés)

**Taux de rejet des clés du KEM : les valeurs citées étaient fausses.** PREUVES § 1 et § 2.3 (et l'errata précédent) donnaient
« 5 % et 8 % » pour Sillage-128 et Sillage-256. Mesuré sur 32 768 et 8 192 clés tirées comme par `KeyGen` (`tests/c/kem_rejet.c`) :
**7,1 % ± 0,14 et 5,9 % ± 0,26**, ordre inversé. Aucune conséquence sur les énoncés : la perte des coûts d'ISD sur clés acceptées vaut
log₂(1/(1 − ε_rej)) ≤ 0,11 bit (0,13 annoncé). Valeurs corrigées dans PREUVES, PROOFS et le plan de cryptanalyse.

**Rejet et clé publique (attaque C4 du plan) : aucune trace.** Cinq statistiques non linéaires de s (poids, transitions aux pas 1 et 2,
triplets de uns, `wt(s ∧ z⁷s)`) ne séparent pas clés acceptées et rejetées : |z| ≤ 1,79 au seuil 4,5 (écart détectable : 0,10 et
0,21 écart-type d'une clé). Test de détection, pas une preuve de H1-P sur clés acceptées.

**Invariants non linéaires de BRUME (attaque A6 du plan) : exclus par calcul.** Critère de Beierle, Canteaut, Leander et Rotella :
dim W_M(D) = 512 avec les 31 constantes intérieures, trois constantes consécutives suffisent ; aucun invariant commun à tous les tours,
quelle que soit la S-box (`tests/c/invariants.c`, PREUVES § 4.2 bis). Restent hors critère les invariants variant d'un tour à l'autre et les
invariants en boucle fermée.

Contrôles : `invariants` 5/5, `kem_rejet` 6/6.
