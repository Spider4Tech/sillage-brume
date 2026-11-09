# SILLAGE Transfer

Application graphique **mono-fichier en C11** pour envoyer un fichier
**directement d'une machine à l'autre**, chiffré de bout en bout avec la suite
cryptographique **SILLAGE** (AEAD **BRUME-512**).

Deux transports au choix :

- **WebRTC** (par défaut) : ICE + STUN + DataChannel via **libdatachannel**,
  avec un **code de partage à 10 caractères** et une signalisation **PeerJS
  Cloud** ;
- **TCP direct** : l'expéditeur ouvre un port et le destinataire s'y connecte.

Dans les deux cas les données passent **directement entre les deux machines** :
aucun relais de fichiers, aucun stockage intermédiaire, aucun TURN. PeerJS Cloud
ne sert qu'à échanger des descriptions de session (SDP) **signées** ; il ne voit
jamais le fichier, le code ni les clés.

```
                 code / lien / QR
┌──────────────┐ ───────────────────────────► ┌──────────────┐
│  Expéditeur  │                              │ Destinataire │
│              │ ◄══ WebRTC DataChannel ═══► │              │
│              │      ou TCP direct           │              │
└──────────────┘   BRUME-512 + HMAC-SHA256    └──────────────┘
        │                                            │
        └──────── PeerJS Cloud (SDP signés) ─────────┘
                    signalisation seule, sans données
```

## Fonctionnalités

- Interface sombre moderne en français : tableau de bord, envoi, réception,
  historique, page « À propos ».
- Sélection de fichier par **glisser-déposer** ou navigateur intégré.
- **QR code** et **lien de partage** (`sillage://`) générés automatiquement.
- **Code de partage** court : 10 caractères Crockford base32, affiché
  `XXXXX-XXXXX` (sans les lettres I, L, O et U).
- Deux modes de protection :
  - **clé dérivée du code** (aucun mot de passe à saisir) ;
  - **mot de passe** dérivé localement avec **scrypt** — le mot de passe ne
    transite jamais.
- Validité du partage configurable (5 min, 15 min, 1 h, 24 h).
- Invitation **à usage unique** : un seul transfert réussi par partage.
- Choix du serveur PeerJS et du serveur STUN directement dans l'interface.
- Progression, débit, temps restant, annulation.
- Écriture dans un fichier `.part` puis renommage atomique ; permissions `0600`.
- Historique en mémoire pour la session.
- IPv4 et IPv6 pour le transport TCP ; ICE/STUN pour WebRTC.

## Construction

Prérequis (Ubuntu / Debian) :

```bash
sudo apt install build-essential libssl-dev libx11-dev curl git cmake
```

Prérequis (Fedora / RHEL) :

```bash
sudo dnf install gcc gcc-c++ make openssl-devel libX11-devel curl git cmake python3-pip
```

`cmake` est utilisé s'il est présent ; sinon le script l'installe localement
dans `.deps/venv` (via `python3 -m venv`). Puis, depuis ce dossier :

```bash
./build.sh
```

Le binaire est **portable par défaut** (pas de `-march=native`) : il peut être
copié sur une autre machine x86-64 si la version de glibc y est au moins aussi
récente. Pour optimiser pour la machine de compilation :

```bash
NATIVE=1 ./build.sh
```

Le script :

1. télécharge **raylib 6.2** (binaire statique officiel) dans `.deps/` au
   premier build ;
2. clone et compile **libdatachannel 0.24.6** en bibliothèques statiques dans
   `.deps/libdatachannel` (`NO_MEDIA`, client WebSocket **activé** pour PeerJS,
   sans exemples ni tests) ;
3. compile **SILLAGE depuis les sources** (`../sillage/c`) en archive statique
   locale — cela évite les incompatibilités ABI d'un `libsillage.so` déjà
   présent ;
4. compile et lie `sillage_transfer.c` (avec `libstdc++` pour libdatachannel) ;
5. lance `--selftest` à la fin (sauf option `--no-test`).

Options :

```bash
./build.sh --no-test          # construire sans lancer l'autotest
./build.sh --clean            # effacer .deps et reconstruire
./build.sh --package          # construire + créer une archive source autonome
SILLAGE_DIR=/autre/chemin/c ./build.sh
RAYLIB_DIR=/autre/raylib ./build.sh
LIBDATACHANNEL_DIR=/autre/libdatachannel ./build.sh
CC=clang ./build.sh
NATIVE=1 ./build.sh
```

### Envoyer une copie à quelqu'un

Le plus simple est de lui envoyer l'archive source :

```bash
./build.sh --package
```

Cela produit `sillage-transfer-src.tar.gz`, qui contient l'application,
`build.sh`, le README et les sources SILLAGE. Sur sa machine :

```bash
tar xzf sillage-transfer-src.tar.gz
cd sillage-transfer
./build.sh
```

L'archive ne contient ni binaire précompilé ni `.deps` : la compilation se fait
avec les bibliothèques de sa distribution. C'est la méthode recommandée entre
deux distributions différentes (par exemple Ubuntu → Fedora), car un binaire
Linux dépend de la version de glibc et du processeur.

Si vous envoyez malgré tout le binaire, construisez-le sans `NATIVE=1` et avec
une glibc au moins aussi récente que celle de la machine cible.

Le binaire produit est `./sillage-transfer`. Il est compilé pour x86-64 de
base par défaut ; reconstruez-le sur la machine cible si vous le déplacez ou si
vous avez utilisé `NATIVE=1`.

## Utilisation

### Envoyer — WebRTC (par défaut)

1. Choisissez un fichier (glisser-déposer ou **Parcourir**).
2. Laissez **WebRTC** sélectionné.
3. Activez éventuellement **Protéger par mot de passe**.
4. Choisissez la validité du partage.
5. Vérifiez le **serveur PeerJS** (`0.peerjs.com:443` par défaut) et le
   **serveur STUN** (`stun:stun.l.google.com:19302` par défaut).
6. Cliquez sur **Créer le code de partage**.
7. Communiquez le **code** (ou le lien / QR code). L'expéditeur s'enregistre
   aussitôt sur PeerJS Cloud ; le transfert démarre dès que le destinataire
   se connecte.

### Envoyer — TCP direct

1. Choisissez **TCP direct** dans *Mode de connexion*.
2. Vérifiez le **port** (45871 par défaut) et l'**adresse** placée dans le
   lien ; le bouton **Auto** détecte l'adresse IPv4 locale.
3. Cliquez sur **Créer le lien de partage**, puis transmettez le lien ou le QR.

### Recevoir

1. **WebRTC** : saisissez le code `XXXXX-XXXXX` (ou collez le lien), puis
   choisissez le dossier et cliquez sur **Recevoir le fichier**. Si le partage
   est protégé, renseignez le mot de passe.
2. **TCP** : collez le lien `sillage://v1?…`, saisissez le mot de passe s'il est
   requis, choisissez le dossier, puis **Recevoir le fichier**.

Le champ accepte aussi la forme `CODE@hôte:port` pour utiliser un autre serveur
PeerJS (auto-hébergé) que celui configuré par défaut.

> Un seul transfert peut être actif à la fois. Un partage ne sert qu'une seule
> fois : après un transfert réussi, créez-en un nouveau.

### Signalisation PeerJS Cloud

L'application est son propre client **PeerJS** : elle parle directement le
protocole **PeerServer** (`/peerjs?key=…&id=…&token=…&version=1.5.4`) sur une
WebSocket fournie par libdatachannel. Aucun JavaScript, aucune bibliothèque
PeerJS embarquée.

Fonctionnement :

1. l'expéditeur génère un code à 10 caractères, puis s'enregistre sur PeerJS
   Cloud avec un identifiant **dérivé du code** (`sillage-<hex>`). Le serveur ne
   voit donc qu'un identifiant opaque ;
2. le lien, le QR code ou le code est transmis au destinataire ;
3. le destinataire s'enregistre avec un identifiant aléatoire, puis envoie son
   **offre SDP** à l'identifiant de l'expéditeur ;
4. PeerJS relaie l'offre et la réponse ; chaque SDP est signé par
   `HMAC-SHA256(clé d'authentification dérivée du code, rôle || SDP)` ;
5. ICE/STUN établit ensuite une connexion **directe** et le DataChannel prend
   le relais. BRUME-512 chiffre le fichier de bout en bout.

PeerJS Cloud par défaut : `0.peerjs.com:443` (le port 443 active `wss://`).
Pour un serveur **PeerServer auto-hébergé**, indiquez `hôte:port` dans le champ
*Serveur PeerJS* ou via `SILLAGE_PEERJS` ; utilisez le port 443 (ou un port
courant TLS) pour `wss://`, sinon `ws://`. La clé PeerServer par défaut est
`peerjs`, modifiable avec `SILLAGE_PEERJS_KEY`.

> **Ancien relais local.** `--signal-server` et l'auto-démarrage sur
> `127.0.0.1:8787` ne servent plus qu'aux autotests internes et restent
> dépréciés. L'interface graphique utilise toujours PeerJS Cloud.

### Variables d'environnement

| Variable | Rôle | Défaut |
|---|---|---|
| `SILLAGE_PEERJS` | serveur PeerJS `hôte:port` | `0.peerjs.com:443` |
| `SILLAGE_PEERJS_KEY` | clé PeerServer | `peerjs` |
| `SILLAGE_SIGNAL` | alias historique de `SILLAGE_PEERJS` | non défini |
| `SILLAGE_STUN` | serveur STUN (`stun:hôte:port`) | `stun:stun.l.google.com:19302` |
| `SILLAGE_FONT` | police TTF explicite (ex. `.../DejaVuSans.ttf`) | détection automatique |
| `SILLAGE_FONT_BOLD` | variante grasse associée | détection automatique |
| `SILLAGE_NO_MSAA` | `1` désactive l'anticrénelage MSAA | non défini |

Les polices sont cherchées dans les chemins d'Ubuntu, Fedora, Arch et via
`fc-match` (fontconfig), avec Lato, DejaVu Sans, Liberation Sans puis Noto Sans.
Le rendu utilise une police chargée à la taille exacte demandée, sans
redimensionnement flou.

### QR code

Le QR code encode le même lien `sillage://…`. Il peut être lu par un lecteur de
QR code standard puis recopié dans l'application. Cliquez sur le QR code pour
l'agrandir.

## Réseau et pare-feu

### WebRTC

- Aucun port entrant à ouvrir : ICE établit une connexion sortante via STUN.
- Les deux machines doivent pouvoir joindre **PeerJS Cloud** (WebSocket TLS sur
  le port 443) et le **serveur STUN**.
- **Pas de TURN** : derrière un CGNAT ou un NAT symétrique verrouillé, la
  connexion directe peut échouer. Dans ce cas, utilisez le mode **TCP direct**
  avec une redirection de port, ou placez les deux machines sur un réseau où
  elles peuvent se joindre.
- STUN permet de découvrir l'adresse publique ; il ne transporte aucune donnée
  du fichier.

### TCP direct

- L'**expéditeur** écoute sur le port choisi. Le **destinataire** initie la
  connexion sortante.
- Sur un réseau local, l'adresse détectée par **Auto** suffit en général.
- Depuis Internet, il faut :
  - une adresse publique ou un nom de domaine dans le champ d'adresse ;
  - une redirection de port TCP vers la machine de l'expéditeur ;
  - le port autorisé dans le pare-feu, par exemple :
    `sudo ufw allow 45871/tcp`.

Dans les deux cas, les deux machines doivent avoir une horloge approximativement
correcte : la date d'expiration est comparée à l'heure locale.

## Sécurité

### Ce que fait l'outil

- **BRUME-512 AEAD** (profil 0) : clé de 512 bits, nonce de 192 bits, tag de
  128 bits. Chaque trame possède son propre nonce et ses données authentifiées.
- **Authentification par défi-réponse HMAC-SHA256** sur un jeton aléatoire de
  128 bits, avec comparaison à temps constant.
- **SDP authentifiés** : en WebRTC, chaque description de session est scellée
  par `HMAC-SHA256(clé d'authentification, rôle || SDP)`. PeerJS Cloud, même
  malveillant, ne peut pas substituer une session sans être détecté.
- **Dérivation du code** : `scrypt(code, "SILLAGE-WEBRTC-v2")` produit la salle,
  l'identifiant, le jeton, la clé d'authentification et la clé applicative.
  L'identifiant PeerJS de l'expéditeur est dérivé de la salle ; PeerJS ne voit
  donc ni le code ni les clés, seulement un identifiant opaque.
- **Un seul transfert réussi par invitation**, expiration côté expéditeur,
  maximum 10 échecs d'authentification, délai d'inactivité de 60 s.
- Taille maximale : **1 Tio**. Nom de fichier limité à 180 octets et nettoyé
  (pas de traversée de répertoire).
- Fichier reçu écrit en `.part`, synchronisé, puis renommé atomiquement et
  passé en `0600`.

### Code de partage

Le code fait **50 bits** (10 caractères × 5 bits). Il est dérivé avec scrypt
pour qu'une attaque hors ligne sur le code soit coûteuse, mais **50 bits restent
limités** : ne publiez pas le code sur un canal ouvert et préférez un partage
de courte durée.

### Mode clé (sans mot de passe)

En WebRTC, la clé applicative est dérivée du code. En TCP, elle est placée dans
le fragment du lien (`#k=…`). Dans les deux cas, le lien ou le code est un
**secret porteur** : toute personne qui le possède peut récupérer le fichier
tant que l'invitation est valide.

### Mode mot de passe

La clé applicative est dérivée localement avec **scrypt** (`N=2^15`, `r=8`,
`p=1`) à partir du mot de passe et de l'identifiant d'invitation. Le mot de
passe n'est jamais envoyé. Un mauvais mot de passe produit une clé différente
et le déchiffrement AEAD échoue.

### Limites à connaître

- Pas de **forward secrecy** : la clé du lien (ou le mot de passe) suffit à
  déchiffrer la session.
- Pas de confidentialité des métadonnées : PeerJS Cloud voit les identifiants
  de session et les SDP (adresses ICE) ; la taille du fichier et les adresses
  IP des pairs sont exposées sur le réseau.
- Pas de protection contre l'analyse de trafic (pas de padding, pas de
  camouflage du débit).
- Pas de reprise de transfert, pas de transfert de dossier, pas de fichiers
  multiples.
- L'historique et les réglages ne sont pas persistés sur disque.
- Cet outil utilise uniquement la primitive **AEAD** de SILLAGE, pas son KEM ni
  ses signatures.

> **Avertissement** — SILLAGE est une suite cryptographique de **recherche**,
> non auditée. SILLAGE Transfer est expérimental. Ne l'utilisez pas pour des
> secrets critiques sans évaluation indépendante.

## Protocole (résumé)

### Session de données

Le même protocole SILLAGE est utilisé au-dessus du DataChannel WebRTC ou du
socket TCP :

```
HELO  version + id(16)
CHAL  challenge(32) + préfixe de nonce(16)
AUTH  HMAC-SHA256("SLT1AUTH" + id + challenge, jeton(16))
OKAY  total(8) + taille de trame(4)
      → trame chiffrée 0 : métadonnées (nom, taille)
REDY  ← le destinataire accepte
      → trames chiffrées 1..N : données
END!  fin d'envoi
DONE  confirmation de réception
```

Chaque trame : longueur sur 4 octets (big-endian), ciphertext, tag de 16 octets.
Nonce = préfixe aléatoire de 16 octets + index de trame sur 8 octets.
AAD = `"SLT1"` + id(16) + index(8) + longueur(4) + total(8).
Taille de trame : 1 Mio.

### Signalisation PeerJS

Client **PeerServer** natif sur WebSocket (texte) :

```
wss://<hôte>:<port>/peerjs?key=<clé>&id=<id>&token=<token>&version=1.5.4
```

Messages JSON échangés :

```
serveur → client   {"type":"OPEN"}
client → serveur   {"type":"OFFER",  "dst":<id>, "payload":{…}}
serveur → client   {"type":"OFFER",  "src":<id>, "payload":{…}}
client → serveur   {"type":"ANSWER", "dst":<id>, "payload":{…}}
client → serveur   {"type":"HEARTBEAT"}            toutes les 5 s
```

- les types serveur sont en majuscules (`OPEN`, `OFFER`, `ANSWER`, `LEAVE`,
  `EXPIRE`, `ERROR`, `ID-TAKEN`) et ne se confondent pas avec les types SDP ;
- `payload.sdp.sdp` contient le SDP complet et `payload.sillage_sig` le
  HMAC-SHA256 hexadécimal ; PeerJS relaie ces champs sans les interpréter ;
- la négociation est **non trickle** : chaque côté attend
  `RTC_GATHERING_COMPLETE` avant d'envoyer son SDP ;
- l'expéditeur est **callee** (il attend l'offre) ; le destinataire est
  **caller** (il crée le DataChannel et envoie l'offre) ;
- l'identifiant PeerJS de l'expéditeur est `sillage-<hex(salle)>` ; celui du
  destinataire est aléatoire (`sillage-r-<hex>`).

### Format des liens

**WebRTC — v2 :**

```
sillage://v2?m=w&s=<signal hôte:port>&st=<stun>&e=<expiration>&pw=<0|1>#c=<code>
```

- `s` : serveur PeerJS (`hôte:port`, défaut `0.peerjs.com:443`) ;
- `st` : serveur STUN ;
- `e` : expiration en secondes Unix ;
- `pw` : `1` si un mot de passe est requis ;
- `c` : code de partage à 10 caractères.

**TCP — v1 :**

```
sillage://v1?i=<id>&h=<host>&p=<port>&e=<expiration>&pw=<0|1>#t=<token>[&k=<key>]
```

- `i` : identifiant d'invitation, 128 bits en hexadécimal ;
- `t` : jeton d'authentification, 128 bits en hexadécimal ;
- `k` : clé BRUME-512, 512 bits en hexadécimal (absente en mode mot de passe) ;
- `e` : expiration en secondes Unix ;
- `pw` : `1` si un mot de passe est requis.

Le fragment (`#…`) n'est pas envoyé à un serveur, mais peut être conservé par
certaines applications de messagerie. Préférez un canal de confiance.

## Autotest

```bash
./sillage-transfer --selftest
```

Vérifie :

- chiffrement/déchiffrement AEAD et rejet d'un tag altéré ;
- déterminisme et sensibilité au mot de passe de scrypt ;
- génération et analyse d'un lien ;
- encodage du QR code ;
- cinq transferts P2P complets en boucle locale (2 Mio) : TCP avec clé, TCP
  avec mot de passe, WebRTC avec code, WebRTC avec mot de passe, et WebRTC avec
  signalisation locale éphémère, avec comparaison octet par octet.

Test réseau réel (nécessite Internet, passe par PeerJS Cloud) :

```bash
./sillage-transfer --selftest-peerjs
```

Il exécute deux transferts WebRTC complets via `0.peerjs.com` : clé dans le
lien, puis mot de passe scrypt.

## Dépannage

| Symptôme | Piste |
|---|---|
| `Port indisponible` | un autre processus utilise le port ; choisissez-en un autre (≥ 1024). |
| `Impossible de joindre PeerJS Cloud` | pas d'Internet, DNS/proxy/pare-feu bloquant `0.peerjs.com:443`, ou serveur PeerJS personnalisé injoignable. Vérifiez aussi `SILLAGE_PEERJS`. |
| `Ce code de partage est déjà utilisé` | un ancien socket PeerJS détient encore l'identifiant dérivé ; attendez quelques secondes et recréez le partage. |
| `Partage introuvable ou expiré` | code erroné, partage expiré, ou serveurs PeerJS différents entre les deux machines. |
| `La connexion directe n'a pas pu s'établir (NAT restrictif)` | NAT symétrique/CGNAT sans TURN ; essayez un autre réseau ou le mode TCP direct. |
| `Connexion impossible` (TCP) | pare-feu, mauvaise adresse, NAT non configuré, destinataire hors ligne. |
| `mot de passe incorrect ou lien altéré` | mot de passe erroné ou lien tronqué par messagerie. |
| `GLIBC_ABI_GNU2_TLS not found` | ancien `libsillage.so` précompilé ; `./build.sh` recompile SILLAGE localement. |
| `GLIBC_2.xx not found` | binaire compilé sur une distribution plus récente ; envoyez l'archive `--package` et rebuild sur la machine cible. |
| Texte flou ou trop petit | corrigé en 1.1 : polices chargées à la taille exacte et texte agrandi. Si besoin, forcez une police plus lisible : `SILLAGE_FONT=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf ./sillage-transfer`. |
| Pas de fenêtre | raylib desktop nécessite X11 ou XWayland (`DISPLAY`). |
| Caractères manquants | installez Lato, DejaVu Sans ou Liberation Sans ; sinon police par défaut. |
| Image dédoublée ou clignotement | XWayland + NVIDIA (synchronisation explicite incomplète). L'application plafonne à 60 i/s et laisse le compositeur synchroniser sous Wayland ; mettez à jour le pilote ou testez une session Xorg. Si le problème persiste, désactivez l'anticrénelage : `SILLAGE_NO_MSAA=1 ./sillage-transfer`. |
| Curseur qui clignote au survol | corrigé depuis la 1.0 : le curseur n'est appliqué qu'une fois par image, et seulement s'il change. |

## Fichiers

| Fichier | Rôle |
|---|---|
| `sillage_transfer.c` | application complète (interface, réseau, protocole, signalisation, QR code embarqué). |
| `build.sh` | téléchargement de raylib, compilation de libdatachannel et de SILLAGE, édition du binaire. |
| `README.md` | ce document. |
| `.deps/` | cache créé par `build.sh` (raylib, libdatachannel, objets SILLAGE). |
| `sillage-transfer-src.tar.gz` | archive autonome produite par `--package`. |

## Crédits

- Générateur de QR code : **Project Nayuki**, licence MIT (en-tête conservé dans
  le fichier source).
- **raylib** : licence zlib.
- **libdatachannel** : licence MPL-2.0 (WebRTC, ICE, DataChannel).
- **SILLAGE** (BRUME-512) : suite de recherche de ce dépôt, voir `../sillage/`.
- OpenSSL : dérivation scrypt et HMAC-SHA256.
