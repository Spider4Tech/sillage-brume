Le paradigme proposé : « cryptographie par décodage » (nom de travail : SILLAGE)

Un seul principe fédérateur pour toute la suite :

     

    Tout secret vit de l'autre côté d'un canal bruité. L'adversaire doit décoder un canal aléatoire (NP-dur). Le détenteur de clé décode un canal structuré (facile pour lui).

Trois primitives, une seule loi. Et un principe d'ingénierie que je considère essentiel pour votre cas d'usage :

     

    « Nouveauté à dégradation sûre » : chaque composante nouvelle est conçue pour que, si elle était cassée, elle s'effondre vers le problème dur le mieux étudié — jamais vers une faiblesse inconnue.

2.1 — KEM « Sillage-KEM » (échange de clés)

Ossature (famille LPN régime d'Alekhnovich, 2003 — sous-exploitée) :

     Clé publique : (A,B=A⋅S⊕E)
     avec 
    A
     aléatoire 
    n×m
    , 
    S
     secrète uniforme, 
    E
     
    bruit creux (chaque colonne de poids t≈m
    ​
    ).
     Encapsulation : tirage creux R
    , calcul 
    U=AR
    , 
    V=BR⊕EncC​(μ)
     où 
    μ
     est le secret de session et 
    C
     un code correcteur.
     Décapsulation : V⊕SU=ER⊕EncC​(μ)
     — le produit de deux vecteurs creux est 
    encore plus creux, donc C
     décode et rend 
    μ
    .

Aucune structure algébrique exploitable (tout est binaire, bruité, creux). Deux twists de recherche que j'ajoute :

    Cascade de bruit : E=E1​⊕M(E2​)
     avec 
    M
     mélangeur public — deux régimes de bruit indépendants ; une attaque ciblant un régime ne voit plus la distribution attendue. Question de recherche ouverte : gain réel à quantifier.
    Génération tensorielle de A
     : 
    A
     dérivé de tranches d'un 3-tenseur de rang contraint (clé publique compressée + l'attaquant affronte simultanément rang de tenseur et LPN). 
    Mais — et c'est le principe de dégradation sûre — la structure n'est jamais porteuse de sécurité : pire cas, on retombe sur LPN pur.

2.2 — Chiffrement symétrique « BRUME » (le successeur conceptuel d'AES)

L'angle réellement neuf : un chiffrement auto-correcteur — le déchiffrement est un décodage de syndrome. Conséquences natives : toute altération du chiffré est détectée par construction (tamper-evidence intrinsèque, résistance aux attaques en faute).

Architecture de la permutation (mode sponge/duplex, état 512 bits, clé 512 bits → sécurité 256 bits post-Grover) :

     Diffusion : pas de MixColumns — le state vit sur les sommets d'un graphe expandeur de Ramanujan 6-régulier ; opérations linéaires le long des arêtes. Expansion prouvée → bornes de diffusion démontrables, contrairement à un SPN ad hoc.
     Non-linéarité : S-boxes 4 bits co-optimisées (nonlinéarité ≥ 8, immunité algébrique ≥ 4, uniformité différentielle minimale) — un programme de recherche concret en soi.
     Mode : duplex avec tag 128 bits (IND-CCA au-dessus de l'auto-correction, qui elle-même détecte les fautes).

2.3 — Signatures « Sillage-SIG »

Pas de Stern naïf (trop lourd). Base moderne : MPC-in-the-head sur la relation de décodage de syndrome (famille SDitH/PERK — le procesus « signatures additionnelles » du NIST le valide comme sérieux). Mon twist, lui aussi à dégradation sûre : la relation prouvée est e=e1​⊗e2​+en​
 — le témoin se décompose tensoriellement, la communication chute ; si la structure tensorielle était attaquée, le protocole se replie sur le décodage de syndrome ordinaire. Filet de sécurité : couche Merkle sur la permutation BRUME (hachage = l'assomption la plus vieille de toute la cryptographie).
 
 
 
 
 
 info importante
 ceci est dans un but de recherhce experimental et non de production il est donc inutile de mentionner des système cryptographique existant pour remplacer brume ou sillage
 
 code uniquelment en C test compris
 
