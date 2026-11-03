# Revue de code C — prototype SILLAGE-VOLE

**Commit de code examiné :** `59672814ed8a70b27464cdae8a95cbc5b398e351`  
**Dépôt :** `Spider4Tech/sillage-brume`  
**Date de revue :** 31 octobre 2026  
**Périmètre :** `tests/c/vole_proto.c`, `tests/c/vole_params.c` et leurs dépendances C directes, ainsi que le harnais de test et les notes de résultats.  
*Depuis cette revue, les fichiers examinés ont été déplacés dans `prototypes/vole/` ; les chemins ci-dessous sont ceux du commit examiné.*

**Nature :** revue statique du code source et de sa cohérence inter-fichiers. Ce document n'est ni une certification, ni une preuve de sécurité, ni un audit cryptographique indépendant du protocole.

---

## 1. Conclusion exécutive

Le commit fournit un prototype expérimental substantiel : génération de clé, construction d'un arbre de graines, production des engagements, agrégation des vues VOLE, vérification, attaque sur modèle réduit, estimation de tailles et chronométrage sont regroupés dans un programme C autonome. Le prototype est suffisamment concret pour permettre une étude de performance et une analyse de construction.

La revue ne justifie toutefois pas une intégration dans le format officiel SILLAGE-SIG. Plusieurs points d'implémentation doivent être réglés avant de traiter le code comme une base stable :

1. **La taille de clé publique VOLE-128 affichée est incorrecte pour les octets réellement engagés dans le transcript : 109 octets sont requis, pas 93**, avec le comportement présent.
2. Les helpers `H()` et `H4()` n'appliquent pas exactement la même convention de domaine. La preuve devra traiter la construction réellement codée, et les transcripts devront être rendus canoniques.
3. `verifier()` ne reçoit pas la longueur du buffer de signature ; il ne peut donc pas valider une entrée externe tronquée ou surlongue.
4. Les allocations dynamiques sont nombreuses et leurs retours ne sont pas systématiquement contrôlés.
5. Le chemin de génération manipule des données secrètes par des divisions, branches et accès mémoire dépendants des secrets ; le prototype ne peut pas être qualifié de constant-time.
6. Le code s'appuie sur des représentations mémoire natives pour plusieurs champs hachés ou sérialisés.
7. Les contrôles du programme sont essentiellement des tests d'aller-retour et des altérations ciblées ; ils ne remplacent pas les KAT, les tests différentiels des contraintes, le fuzzing et les sanitizers.
8. L'outil `vole_params` explore un domaine limité et discret. Il ne démontre pas un optimum global ni la couverture de toutes les attaques pertinentes.

**Décision recommandée :** conserver le prototype comme branche de recherche, ne pas modifier le format officiel SIG, corriger d'abord les écarts de mesure, les contrats mémoire et les encodages, puis compléter les tests indépendants et la preuve.

Un niveau P1 indique un point à corriger avant exposition dans une API ou intégration au format. Il ne signifie pas qu'une attaque cryptographique pratique a été démontrée. Les constats de sécurité théorique (EUF-CMA, QROM, réduction RSD) restent distincts des défauts de code.

---

## 2. Périmètre, méthode et limites de vérification

### 2.1 Sources examinées

- `tests/c/vole_proto.c` : prototype, clés, arbre GGM, agrégation VOLE, contraintes algébriques, signature, vérification, attaque réduite et chronométrage.
- `tests/c/vole_params.c` : calcul de taille, estimation ISD et recherche des paramètres.
- `tests/c/Makefile` : règles de compilation des programmes C et de la cible `compression`.
- `tests/run_all.py` : intégration du prototype à la batterie.
- `tests/c/resultat.h` : enregistrement des contrôles et code de retour.
- `sillage/c/commun.c` et `sillage/c/sillage.h` : SHAKE, H4 parallèle, aléa système et multiplication carryless.
- `sillage/c/isd.c` : estimateurs utilisés par `vole_params`.
- `docs/PISTES.md` : description des mesures et conditions d'adoption.

### 2.2 Ancrage du code

La revue du code C porte sur le contenu au commit `59672814ed8a70b27464cdae8a95cbc5b398e351`.

Au moment de la publication de cette revue, `main` comprend aussi le commit ultérieur `9a7ae4675313062359f2b0822c1396169a00950f`, qui ajoute `tests/c/rsd_attaques.c` et met à jour `docs/PISTES.md` et `tests/c/Makefile`. La comparaison des commits montre que ce changement ultérieur ne modifie ni `vole_proto.c` ni `vole_params.c`. Le nouvel outil `rsd_attaques.c` n'est pas audité dans ce rapport ; les chiffres RSD publiés dans la documentation récente ne sont donc pas validés par cette revue.

### 2.3 Ce qui a été vérifié et ce qui ne l'a pas été

Les constats de flux mémoire, dimensions, appels et encodages sont établis par lecture des sources et recoupement entre fonctions appelantes et appelées.

Le calcul dans GF(2^lambda) a fait l'objet d'un contrôle arithmétique indépendant : les deux polynômes de réduction ont été vérifiés irréductibles sur GF(2), puis 1 000 produits aléatoires par largeur ont été comparés à une multiplication polynomiale de référence, en reproduisant l'algorithme carryless et sa réduction. Ce contrôle valide le modèle mathématique reproduit, pas le binaire C, la compilation, ni les instructions PCLMUL/PMULL.

**Aucune compilation ni exécution du binaire C n'a été réalisée dans cet environnement.** Le clonage local a échoué faute de résolution réseau vers GitHub. Il n'est donc pas affirmé que le build, les tests, les sanitizers, Valgrind, dudect ou les benchmarks ont été exécutés pendant cette revue. Les résultats de performance consignés dans le dépôt sont traités comme des résultats rapportés par le projet, pas comme des mesures reproduites ici.

---

## 3. Constats à corriger

### V-01 — P1 — Taille de clé publique VOLE-128 sous-estimée de 16 octets

**Emplacements :** `tests/c/vole_proto.c`, définition de `vpk_t`, `keygen()`, `developper_H()`, appels `H('m', ...)` et affichage des tailles.

La structure publique de travail contient une graine de 32 octets et un tableau `y` de 256 octets. `keygen()` remplit les 32 octets de graine avec `sl_alea(pk->seed, 32)`. Pour VOLE-128, `developper_H()`/`H4()` ne consomme que `c->Bl` octets de cette graine, avec `Bl = lambda/8 = 16`.

Cependant, `signer()` et `verifier()` hachent la structure entière avec `H('m', pk, sizeof *pk, ...)`. Les 16 derniers octets aléatoires de `seed` sont donc liés au transcript, même s'ils ne servent pas à développer H. Ils doivent être conservés pour reproduire ce transcript. Le tableau `y` est rempli uniquement sur `c->cB` octets ; les octets restants sont initialisés à zéro par `keygen()` et peuvent être reconstruits à partir de la représentation compacte.

L'affichage calcule `c.Bl + c.cB`. Pour VOLE-128, `c.Bl` vaut 16 et `c.cB` vaut 77 : le rapport affiche 93 octets. Or, avec le comportement actuel, il faut conserver 32 octets de `seed` et 77 octets de `y`, soit **109 octets**. Pour VOLE-256, 32 + 153 = 185 octets, ce qui correspond à l'affichage actuel.

**Conséquence :** la comparaison de tailles de clé publique VOLE-128 dans `docs/PISTES.md` est sous-estimée de 16 octets, à moins que le protocole soit modifié pour que les 16 octets surnuméraires de la graine ne soient plus générés ni hachés.

**Correction :** choisir explicitement l'un des deux comportements :
- conserver une graine de 32 octets, l'utiliser et la hacher en entier, et annoncer 109 octets pour VOLE-128 ;
- définir une graine de 16 octets pour VOLE-128, générer exactement cette graine, et hacher une sérialisation compacte canonique de 16 + 77 octets.

Dans les deux cas, ne pas utiliser `sizeof(struct)` comme encodage cryptographique. Définir un encodeur de clé publique explicite et faire passer exactement ses octets au transcript.

**Qualification :** erreur de mesure/encodage démontrée par le code ; ce n'est pas une attaque cryptographique démontrée.

### V-02 — P1 avant preuve — `H()` et `H4()` n'utilisent pas la même convention de domaine

**Emplacements :** `tests/c/vole_proto.c`, `H()` et `H4()` ; `sillage/c/commun.c`, `sl_shake4()`.

`H()` absorbe le préfixe `SILLAGE-VOLE`, puis l'octet de domaine et les champs fournis. `H4()` construit au contraire un message de la forme `salt || dom || idx || seed`, puis appelle `sl_shake4()`. `sl_shake4()` effectue SHAKE sur les octets transmis ; elle n'ajoute pas le préfixe `SILLAGE-VOLE`.

Les domaines visibles de `H4()` (`'H'`, `'n'`, `'l'`) sont distincts des domaines actuellement employés par `H()`. Je ne conclus donc pas qu'une collision exploitable existe. Le constat est plus précis : deux familles de fonctions qui participent au même transcript n'appliquent pas la même convention de préfixe et de séparation.

**Conséquence :** la preuve doit modéliser exactement ces appels et leurs octets, et non une fonction H abstraite qui ne correspondrait pas au code. Une évolution ultérieure des domaines ou une réutilisation des helpers pourrait rendre la séparation ambiguë.

**Correction :** définir une grammaire unique de transcript : identifiant de protocole, version, identifiant de profil/paramètres, domaine, champs typés, longueurs et encodage des entiers. Faire en sorte que les quatre sorties de `H4()` correspondent exactement à quatre appels scalaires à cette grammaire. Ajouter des KAT pour chaque domaine et chaque profil.

Ce point ne démontre pas à lui seul une faiblesse cryptographique ; il empêche de considérer la convention de hachage comme entièrement formalisée.

### V-03 — P1 avant exposition — `verifier()` ne reçoit pas la longueur de la signature

**Emplacements :** `tests/c/vole_proto.c`, `verifier()`, calcul des pointeurs de champs et lecture du compteur.

`verifier()` reçoit un pointeur `sig`, mais aucune longueur. Il calcule les adresses des champs et lit notamment le compteur final sans pouvoir vérifier que le buffer contient réellement les octets attendus.

Dans le harnais actuel, le pointeur provient d'un buffer alloué avec `taille_sig(c)`. La revue ne constate donc pas une lecture hors limites dans cet appel interne nominal. En revanche, le contrat de la fonction ne permet pas de vérifier une signature arbitraire reçue d'un appelant.

**Correction :** ajouter `siglen`, vérifier les pointeurs, exiger une longueur exactement égale à la longueur attendue et valider chaque offset avant toute lecture. Tests requis : longueur nulle, 1, taille-1, taille, taille+1 et troncature à chaque frontière de champ.

### V-04 — P1 avant intégration — Retours d'allocation non contrôlés

**Emplacements :** `repetition()`, `lignes_M()`, `contraintes_poly()`, `contraintes_val()`, `signer()` et `verifier()` dans `tests/c/vole_proto.c`.

Le prototype réalise des allocations dynamiques pour les engagements, les vecteurs, les matrices et les buffers temporaires. Les retours de `malloc()`/`calloc()` ne sont pas contrôlés de façon systématique avant d'être utilisés. Exemples visibles : `S` dans `repetition()`, `rows` dans `lignes_M()`, `acc/A/Bb` dans les fonctions de contraintes et la série de buffers dans `signer()`/`verifier()`.

**Conséquence :** un échec d'allocation peut conduire à un déréférencement de NULL ou à un comportement indéfini. Les paramètres de test fixes ne garantissent pas que toutes les allocations réussiront sur toute machine.

**Correction :** centraliser les allocations, vérifier les multiplications de tailles, propager une erreur explicite, libérer les ressources sur un chemin de sortie unique et ajouter une injection d'échec d'allocation. Ne pas convertir un défaut mémoire en signature partielle.

### V-05 — P1 si exigence constant-time — Données secrètes utilisées dans le flux de génération

**Emplacements :** `bits_temoin()` et `keygen()` dans `tests/c/vole_proto.c`.

`bits_temoin()` convertit des positions dérivées du témoin en chiffres de coordonnées avec division et modulo. Le dividende provient de `pos`, donc de positions liées au secret.

`keygen()` calcule `q` à partir de `pos[i]`, puis branche sur `q < c->k`. Selon cette branche, il lit une colonne `cols` à une adresse dépendant de `q` ou met à jour un bit de `y` dépendant de `q`. Le chemin et les adresses mémoire peuvent donc dépendre des positions secrètes.

**Conséquence :** le code source ne permet pas de qualifier ces chemins de constant-time. Une fuite temporelle ou microarchitecturale est plausible ; aucune attaque pratique n'est démontrée par cette revue.

**Correction :** analyser `keygen()` et la préparation du témoin comme des opérations manipulant des secrets. Remplacer les branchements et accès indexés par une construction à temps et accès mémoire fixes. Vérifier le code machine sur les compilateurs et architectures ciblés, puis conduire une campagne dudect/Valgrind. Les tests devront couvrir les options exactes de compilation retenues.

La documentation du projet signalait déjà la division dans `bits_temoin()` et le branchement de `keygen()` ; la revue confirme ce point et précise la dépendance des accès à `cols`.

### V-06 — P2 — Encodages natifs non canoniques dans le transcript et la signature

**Emplacements :** `H4()`, `H('r', ...)`, `H('m', ...)`, `H('d', ...)` et écriture/lecture de `ctr` dans `tests/c/vole_proto.c`.

Des valeurs sont hachées ou sérialisées depuis leur représentation mémoire native :
- `idx` dans `H4()` ;
- tableau `pos` de `uint16_t` ;
- compteur `ctr` de `uint32_t` ;
- structure `vpk_t` complète.

Le code ne définit pas d'ordre d'octets normatif pour les entiers. La signature écrit `ctr` par `memcpy()` de sa représentation mémoire, et le vérifieur le relit de la même manière. Cela fonctionne sur une architecture donnée, mais lie le format à l'endianness et à la représentation utilisée.

Je ne suppose pas qu'un padding existe dans la définition actuelle de `vpk_t` ; le problème est l'emploi direct d'une représentation C comme sérialisation normative.

**Correction :** encoder explicitement chaque entier (par exemple en little-endian), chaque champ et chaque longueur. Ne jamais hacher `sizeof(struct)` directement. Ajouter des KAT identiques sur x86-64 et ARM64 ; si pertinent, inclure une cible big-endian en émulation.

### V-07 — P2 — `verifier()` accepte une matrice H pré-développée sans prouver son lien avec `pk`

**Emplacement :** signature de `verifier()` et appel à `melanges()`.

`verifier()` reçoit `pk` et `cols`. `pk` contient la graine publique ; `cols` contient les colonnes développées depuis cette graine dans le chemin actuel de `keygen()`. `verifier()` ne vérifie pas que `cols` correspond effectivement à `pk->seed`.

Le programme de test fournit bien les deux objets correspondants, de sorte que le chemin nominal testé est cohérent. Le contrat interne est toutefois fragile : un appelant peut fournir une matrice provenant d'une autre graine.

**Correction :** dans une API définitive, développer H depuis la graine publique ou encapsuler le cache dans un objet opaque portant l'identité de la clé canonique. Ajouter un test qui associe volontairement une matrice à une autre clé et doit échouer.

Ce constat porte sur le contrat et l'intégrité du cache, pas sur une falsification démontrée du test actuel.

### V-08 — P2 — Secrets et intermédiaires non effacés avant `free()`

**Emplacements :** libérations dans `signer()` et `verifier()`.

Plusieurs buffers qui contiennent le témoin, des graines d'arbre, masques ou intermédiaires dérivés du secret sont libérés sans effacement préalable. Le projet expose déjà `sl_effacer()`, mais le prototype ne l'emploie pas dans ces chemins.

**Conséquence :** les contenus peuvent rester en mémoire libérée jusqu'à réutilisation. Ce n'est pas une attaque distante démontrée, mais une lacune d'hygiène mémoire.

**Correction :** classifier les buffers (secret, dérivé sensible, public), effacer les buffers sensibles avec une primitive non supprimée par l'optimiseur avant leur libération et traiter également les sorties anticipées/erreurs.

### V-09 — P2 — Le binaire de test retourne 0 même si un contrôle échoue

**Emplacement :** `tests/c/resultat.h`, `res_ecrire()`.

`res_ecrire()` agrège les booléens dans `ok` et affiche correctement le statut global, mais retourne 0 inconditionnellement à la fin. L'orchestrateur Python inspecte les booléens du JSON et détecte les contrôles faux. Un lancement direct du binaire peut toutefois interpréter le code retour nul comme un succès.

**Correction :** retourner `ok ? 0 : 1` et contrôler les erreurs d'écriture/fermeture. Ce helper est préexistant, mais le nouveau prototype s'appuie dessus.

### V-10 — P2 — Couverture de test insuffisante pour une confiance cryptographique

**Emplacements :** `main()` de `tests/c/vole_proto.c` et entrée du test dans `tests/run_all.py`.

Les contrôles visibles couvrent l'acceptation d'une signature honnête, certaines mutations de champs, un autre message, une clé modifiée, la réduction de taille, une attaque sur modèle réduit et le rejet d'un faux témoin sur ce modèle.

Ils ne suffisent pas à valider indépendamment :
- le calcul du corps fini dans le binaire C ;
- l'équivalence H4/scalaires ;
- l'arbre et le calcul de nombre d'ouvertures sur tous les petits cas ;
- l'équivalence algébrique de `contraintes_poly()` et `contraintes_val()` ;
- les entrées de vérification de longueur arbitraire ;
- les chemins d'échec d'allocation/RNG ;
- la robustesse sous ASan/UBSan et fuzzing.

Les altérations par offset ciblent les principales sections écrites par le signataire. La région des engagements de challenge n'a pas de mutation dédiée garantie ; les flips aléatoires ne remplacent pas un test de chaque champ.

**Correction :** séparer les tests d'invariant des benchmarks ; publier des KAT ; ajouter une référence GF(2^lambda) indépendante ; tester H4 contre quatre sorties scalaires ; tester exhaustivement des arbres réduits ; comparer les fonctions de contraintes par génération aléatoire contrôlée ; ajouter fuzzing du vérifieur après ajout de `siglen` ; exécuter les sanitizers.

Le succès d'un aller-retour signataire-vérifieur ne constitue pas une preuve de solidité.

### V-11 — P2 — Benchmark exploratoire, pas encore caractérisation statistique

**Emplacement :** `main()` de `tests/c/vole_proto.c`.

Le programme mesure 30 signatures par profil sur une seule clé et un message fixe. Il publie une moyenne de signature ; la vérification est chronométrée une seule fois par configuration de threads. Il n'y a pas de médiane, dispersion, percentiles, intervalle de confiance ou échauffement séparé.

La matrice H est développée à l'avance et réutilisée. Son coût est mesuré séparément, ce qui peut correspondre à un scénario cache serveur. Il faut néanmoins publier les scénarios H froid et H chaud distinctement.

**Correction :** mesurer plusieurs clés, plusieurs tailles de message, plusieurs répétitions de vérification et les nombres de threads explicitement fixés. Publier moyenne, médiane, p90/p95 et dispersion. Inclure keygen, coût de développement de H, temps mural et environnement complet (CPU, compilateur, options, OpenMP, fréquence, version du code). Le grinding rend en particulier la distribution du temps de signature pertinente.

### V-12 — P2 — `vole_params` ne prouve pas un optimum global

**Emplacements :** `tests/c/vole_params.c` et fonctions appelées dans `sillage/c/isd.c`.

La grille ne parcourt que `w` de 36 à 240 par pas de 4, fixe `d` à 4 et limite `n` à 40 000. `n` est multiple de `w` et la recherche repose sur une dichotomie qui suppose que le critère estimé évolue de manière monotone. Cette monotonie n'est pas démontrée dans le code. `cout_temoin()` utilise une construction gloutonne des arités `mu` ; le code n'établit pas qu'elle minimise globalement le coût pour tous les candidats.

`sd_cout()` compare Prange, deux-listes et BJMM avec les bornes internes explicites de ses appels. C'est une sélection déterminée d'estimateurs et de plages de paramètres, pas une énumération de toutes les attaques ISD ou spécialisées RSD.

Le contrôle `formule_de_taille_retrouve_sdith2` vérifie la reproduction de tailles de référence par la formule de taille. Il ne valide ni l'optimalité de la grille ni les hypothèses de la réduction RSD.

**Correction :** présenter la sortie comme le meilleur candidat trouvé dans la grille ; enregistrer les bornes et les paramètres d'optimisation ; vérifier la monotonie ; comparer à une recherche exhaustive sur des plages réduites et à une exploration plus dense autour des minima ; distinguer le coût de réduction et le coût d'attaque directe.

### V-13 — P2 — Erreurs RNG transformées en `abort()`

**Emplacements :** appels `sl_alea()` dans `keygen()`, `signer()` et le chemin d'attaque.

Une erreur de `getrandom()` est transformée en `abort()`. Pour un exécutable de recherche, cela provoque un arrêt visible, mais ne fournit pas de contrat d'erreur réutilisable et ne garantit pas le nettoyage des ressources allouées.

**Correction :** propager une erreur, nettoyer et effacer les buffers sensibles, et ne jamais rendre une signature partielle. Ajouter un test avec RNG simulé en échec.

### V-14 — P3 — Allocations inutilisées et responsabilités regroupées

**Emplacements :** `repetition()` et `signer()`.

Le buffer `tmp` alloué dans `repetition()` et le buffer `uu` alloué dans `signer()` sont libérés sans être utilisés. Le même fichier réunit en outre logique du protocole, attaque sur modèle réduit, sérialisation, benchmark et tests.

**Correction :** supprimer les allocations inutilisées et envisager une séparation progressive du code en modules (corps fini, transcript, arbre/engagements, signataire, vérifieur, attaque réduite, benchmark). Faire cette séparation sans changement algorithmique concomitant et comparer les KAT avant/après.

---

## 4. Points positifs vérifiés

### 4.1 Multiplication dans GF(2^lambda)

`fmul()` réalise un produit carryless de mots de 64 bits, suivi d'une réduction. Les polynômes indiqués par les constantes sont :

- 128 bits : x^128 + x^7 + x^2 + x + 1 (constante basse 0x87) ;
- 256 bits : x^256 + x^10 + x^5 + x^2 + 1 (constante basse 0x425).

Le modèle arithmétique indépendant a passé les contrôles d'irréductibilité et 1 000 comparaisons de produits aléatoires par largeur avec une référence en polynômes binaires. Cela soutient la cohérence mathématique de la réduction implémentée.

**Limite :** le binaire C et les backends PCLMUL/PMULL n'ont pas été exécutés ici. Ajouter un test de référence C reste nécessaire.

### 4.2 Dimensions fixes du prototype

Pour PR128, PR256 et PRTOY, les dimensions dérivées utilisées pour les challenges, les graines, les blocs H4, les tableaux WMAX/DMAX, les buffers temporaires de `repetition()` et les vecteurs transposés restent dans les capacités fixes déclarées (WMAX=4, DMAX=6, ch[64] et les buffers locaux correspondants). C'est vrai pour les profils codés en dur, pas pour un futur paramétrage libre. `ctx_init()` devrait refuser toute combinaison dépassant ces capacités ou les remplacer par des allocations vérifiées.

### 4.3 Convention interne de l'arbre entrelacé

Pour les profils actuels, N=2^kappa et L=tau*N. Les feuilles sont placées à l'indice L + i*tau + e, avec i dans [0,N) et e dans [0,tau). L'indice maximal est 2L-1 ; le buffer de 2L nœuds le couvre. `marquer()` et `repetition()` utilisent cette même convention.

Cela confirme une cohérence d'indexation interne. Cela ne démontre pas que cette disposition est celle attendue par la preuve théorique ni que la probabilité d'ouverture du document de référence reste applicable. Une validation exhaustive sur de petits arbres est nécessaire.

### 4.4 Formule de taille de signature

`taille_sig()` correspond aux champs que `signer()` copie effectivement dans le buffer : sel, h3, aux, ut, dw, coefficients ab, ouvertures, engagements sélectionnés et compteur. Pour les deux profils actuels, 4 112 et 15 906 octets correspondent aux dimensions codées.

Cette cohérence ne valide pas le transcript, la sécurité ni la taille de clé publique VOLE-128.

### 4.5 Échantillonnage des positions dans les blocs

`keygen()` emploie un rejet avant réduction modulo. Pour les blocs de taille 245 et 253, le seuil 65536 - 65536 % bloc élimine le biais modulo, sous l'hypothèse d'un tirage uniforme des mots fournis par `sl_alea()`. Les blocs sont disjoints et `q=i*bloc+pos[i]`, donc le mécanisme sélectionne une position dans chaque bloc sans collision entre blocs.

Cela valide ce mécanisme d'échantillonnage dans les paramètres présents, pas la difficulté de RSD ni la qualité cryptographique de la distribution globale.

---

## 5. Recommandations priorisées

### Lot A — À faire avant de republier les chiffres

1. Corriger la taille et l'encodage de la clé publique VOLE-128.
2. Définir une sérialisation canonique de chaque champ du transcript.
3. Unifier la convention de domaine de H() et H4().
4. Ajouter `siglen` au vérifieur et valider les bornes avant toute lecture.
5. Contrôler toutes les allocations et propager les erreurs.
6. Faire retourner un code non nul par `res_ecrire()` si un contrôle échoue.

### Lot B — Tests C à ajouter

1. Référence indépendante de `fmul()` en C, logiciel et backends matériels.
2. KAT pour les domaines H/H4, les clés, les engagements, les défis, les ouvertures et les signatures.
3. Test H4 contre quatre appels scalaires.
4. Tests exhaustifs sur petits arbres pour `marquer()`, reconstruction GGM et nombre d'ouvertures.
5. Tests différentiels de `contraintes_poly()` et `contraintes_val()` sur témoins valides et invalides.
6. Tests de signature tronquée, surlongue et modifiée à chaque frontière.
7. Fuzzing du vérifieur et exécution ASan/UBSan/Valgrind.
8. Échecs d'allocation et de RNG injectés.
9. Matrice H incohérente avec la graine publique.
10. Tests x86-64/ARM64 sur les mêmes KAT.

### Lot C — Sécurité de l'implémentation et du protocole

1. Étude constant-time du keygen et du signataire, avec contrôle du code machine.
2. Classification et effacement des secrets et intermédiaires.
3. Analyse formelle du transcript réellement produit, y compris H4.
4. Preuve EUF-CMA spécifique à cette construction, avec revue humaine indépendante.
5. Analyse des attaques RSD et des hypothèses de réduction, séparée des estimations ISD.
6. Analyse QROM spécifique ; ne pas déduire un niveau quantique de ces benchmarks.

### Lot D — Paramètres et performances

1. Présenter `vole_params` comme une recherche sur grille, pas un optimum global.
2. Vérifier expérimentalement la monotonie avant d'utiliser la dichotomie.
3. Étendre ou documenter les plages d'optimisation des estimateurs.
4. Refaire les benchmarks sur plusieurs clés et tailles de messages.
5. Publier H froid et H chaud, keygen, signature et vérification séparément.
6. Conserver les données brutes, compiler les mêmes sources/options et fixer explicitement les threads.

---

## 6. Tableau de maturité

| Domaine | État confirmé par la revue | Action |
|---|---|---|
| GF(2^lambda) | Modèle arithmétique vérifié sur échantillons ; binaire C non exécuté | KAT C indépendant |
| Clé publique | Décalage de 16 octets dans la taille VOLE-128 | Corriger format et mesure |
| H / H4 | Préfixes et grammaires différents | Canoniser les transcripts |
| Arbre GGM | Indexation interne cohérente | Tests exhaustifs et preuve d'ouverture |
| Contraintes algébriques | Fonctions signataire/vérifieur présentes | Tests différentiels indépendants |
| Vérificateur | Pas de longueur d'entrée | Ajouter siglen et parseur borné |
| Allocations | Retours non contrôlés | Gestion d'erreur centralisée |
| Constant-time | Dépendances secrètes visibles | Audit du code machine et tests de fuite |
| Tests | Contrôles ciblés, sans campagne indépendante complète | KAT, fuzzing, sanitizers |
| Benchmarks | Mesures exploratoires | Distribution multi-clés et multi-messages |
| Paramètres | Grille limitée | Ne pas revendiquer un optimum global |
| Preuve EUF-CMA / QROM | Non fournie pour cette construction | Bloquant cryptographique |

---

## 7. Conclusion

Le prototype est une base de recherche utile. Les tailles de signature codées sont cohérentes avec les champs produits ; le calcul de corps fini est cohérent avec le modèle arithmétique contrôlé ; l'arbre utilise une convention d'indexation cohérente à l'intérieur du code ; l'échantillonnage par bloc évite le biais modulo pour les tailles actuelles.

Les écarts à corriger sont également concrets. Le plus immédiat pour les résultats publiés est la sous-estimation de la clé publique VOLE-128. Pour la qualité logicielle, les limites du vérifieur, les allocations non contrôlées, les encodages natifs et le code de retour des tests doivent être corrigés. Pour la sécurité de l'implémentation, les dépendances secrètes du chemin de génération empêchent une qualification constant-time. Enfin, ces contrôles de code ne remplacent ni une preuve EUF-CMA, ni l'analyse RSD, ni l'analyse QROM.

**Décision : conserver le prototype hors du format officiel, corriger les problèmes de mesure/encodage et de robustesse C, puis poursuivre les tests indépendants et l'analyse mathématique.**

La revue ne conclut ni que le schéma est cassé, ni qu'il est sûr. Elle délimite ce qui a été vérifié dans les sources, ce qui est cohérent, ce qui reste à tester et les conditions minimales à remplir avant d'accorder davantage de confiance au code.
