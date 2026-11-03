# Lancer la campagne de 24 h

Ce programme fait tourner tous les cœurs de la machine pendant 24 h pour tester une suite de cryptographie expérimentale. Il ne touche qu'à son propre dossier, n'envoie rien sur le réseau pendant le calcul et n'a pas besoin de droits administrateur (sauf pour installer les paquets système). C'est du code de recherche : ne pas s'en servir pour protéger de vraies données.

## 1. Installer

```bash
git clone https://github.com/Spider4Tech/sillage-brume.git
cd sillage-brume
./scripts/preparer_campagne.sh --installer
```

Ce script vérifie la machine et installe les paquets Python dans le dossier `.venv`. S'il manque quelque chose, il donne la commande à lancer pour votre distribution. Il faut Linux ; WSL fonctionne, mais sans suivi de température et avec des mesures de temps moins fiables.

### Sous Windows

Installez WSL 2 une fois : `wsl --install -d Ubuntu` dans un PowerShell administrateur, redémarrez, puis ouvrez Ubuntu pour créer l'utilisateur. Clonez ensuite le dépôt et lancez, à la place de `./scripts/runlong` :

```bat
scripts/rundenuit.cmd 10
```

(10 heures ; 8 par défaut.) Le script installe ce qui manque dans WSL (mot de passe Linux demandé), calcule dans un clone `~/sillage-brume` propre à WSL et bloque la veille de Windows. Il prend le code publié sur GitHub, pas les modifications locales du clone Windows.

- **Gardez la fenêtre ouverte :** la fermer arrête le calcul. `Ctrl-C` l'arrête proprement. Relancez `scripts/rundenuit.cmd` pour reprendre, `scripts/rundenuit.cmd 10 -Neuf` pour repartir de zéro.
- **Depuis une autre fenêtre :** `scripts/rundenuit.cmd -Statut`, `scripts/rundenuit.cmd -Arreter`.
- **Résultat :** l'archive est copiée dans le dossier `resultats` du clone Windows.
- **Limites :** pas d'arrêt de sécurité sur la température, surveillez le refroidissement. Sur un portable, laissez le capot ouvert. Suspendez Windows Update pour la durée de la campagne. Le relevé de charge ne voit pas l'activité de Windows, donc les mesures dudect sont moins fiables même sans avertissement. WSL ne dispose par défaut que de la moitié de la mémoire de Windows : si le contrôle au démarrage le signale, augmentez `memory` dans `%UserProfile%\.wslconfig`.

## 2. Vérifier la machine

- **Refroidissement :** 24 h à pleine charge. Dégagez les entrées d'air. Un Ryzen récent peut tenir 90 à 95 °C par conception ; c'est normal.
- **Alimentation :** sur secteur, sans veille automatique (la veille est bloquée quand systemd est présent, pas sous WSL).
- **Stabilité :** un overclocking ou un réglage de mémoire instable peut faire planter la machine ou fausser des résultats. Préférez les réglages d'origine.

## 3. Lancer

```bash
./scripts/runlong
```

Le calcul part en arrière-plan : vous pouvez fermer le terminal. Il faut seulement que la machine reste allumée.

```bash
./scripts/runlong --statut     # où on en est, température, échecs
./scripts/runlong --arreter    # arrêt propre
tail -f resultats/nuit/journal.log    # détail
```

**N'utilisez pas la machine pendant la phase « 2/6 temps constant »**, environ 3 à 4 h : elle mesure des écarts de quelques cycles, et toute autre activité fausse le résultat (le rapport signale une machine occupée). Cette phase commence après environ 3 h. Pour le reste, la machine est très sollicitée mais reste utilisable pour de petites tâches. Ne lancez qu'une campagne à la fois.

## 4. En cas d'arrêt

Après un arrêt, une coupure ou un plantage, relancez simplement :

```bash
./scripts/runlong
```

Le calcul reprend à la campagne interrompue, avec le temps restant. Pour repartir de zéro : `./scripts/runlong --neuf`.

Si la température reste au-dessus de 100 °C pendant 5 minutes, le programme s'arrête de lui-même : laissez refroidir, aérez, puis reprenez. Le seuil se règle avec `SILLAGE_TEMP_MAX=95 ./scripts/runlong`. Une campagne bloquée est arrêtée automatiquement et la suite continue ; c'est indiqué dans le rapport.

## 5. Renvoyer les résultats

À la fin, ou à chaque arrêt, le programme écrit `resultats/campagne_<date>.tar.gz` et affiche son nom. Renvoyez le plus récent.

Il contient les résultats, les journaux et une fiche de la machine (processeur, mémoire, versions de logiciels). Le nom de la machine, votre nom d'utilisateur et les chemins de votre dossier personnel sont retirés des fichiers, et le propriétaire est effacé de l'archive. Le programme refuse de créer l'archive si un de ces chemins y reste. Vous pouvez la regarder avant de l'envoyer : `tar tvzf resultats/campagne_*.tar.gz`.

## 6. Dudect ciblé : `./scripts/runspecial`

`aead` et `kem_decaps` ont dépassé |t| = 4,5 à la première mesure de la campagne du 2026-10-31, puis sont passés à la seconde, qui avait retiré ses valeurs fixes. `./scripts/runspecial` en cherche l'origine : balayage des adresses, clé et clair séparés, préparation identique des deux classes, A/A sans ASLR. Compter ≈ 5 h 45, machine au repos, avec le compilateur de la campagne (`--bloc aead` : ≈ 2 h 10). Options : `./scripts/runspecial --help`. Résultat : `resultats/special/<date>/BILAN.md`.

## 7. Campagne GPU sur une autre carte : `./scripts/rungpu2080`

La campagne GPU n° 1 (`tests/gpu/campagne_dl.cu`, voir `PLAN_CRYPTANALYSE_GPU.md`) tourne aussi sur une carte plus lente, par exemple une
RTX 2080 (Turing). Le binaire est compilé pour sm_75 et sm_89, et du PTX couvre les cartes plus récentes ; chaque lancement de noyau dure
moins de 0,5 s, sous le délai de garde de Windows (TDR, 2 s) quand la carte affiche aussi l'écran ou tourne sous WSL.

- **Prérequis :** pilote NVIDIA et `nvcc` (CUDA 12 ou plus) dans `/usr/local/cuda/bin`, sinon `NVCC=/chemin/nvcc`. Sous WSL 2, installer le
  paquet CUDA « WSL-Ubuntu » de NVIDIA, jamais un pilote Linux dans WSL : c'est celui de Windows qui sert.
- **Lancer :** `./scripts/rungpu2080`. Le script vérifie la conformité du GPU au C, mesure son débit, annonce la durée estimée, puis lance
  le **plan étendu** (les 9 expériences du plan de base et 4 cibles de plus) pour 72 h au plus : `./scripts/rungpu2080 100` pour 100 h.
  Le plan étendu demande ≈ 26 h sur une RTX 4070 Ti ; une 2080 est environ deux à trois fois plus lente.
- **Suivre, arrêter, reprendre :** `./scripts/rungpu2080 --statut`, `--arreter`, puis relancer : la campagne reprend au dernier point de
  reprise (toutes les 10 min). Une campagne du plan de base, même terminée, est complétée par les cibles du plan étendu.
- **Alimentation :** la carte tire sa pleine puissance pendant des heures. Si l'alimentation est juste, plafonner la puissance sur l'hôte
  (`sudo nvidia-smi -pl 180`, par exemple), et vérifier les câbles PCIe.
- **Pas en même temps que dudect** (`runspecial`, `rundenuit.sh`) : la charge du GPU fausserait les mesures de temps ; `rungpu` refuse de
  partir dans ce cas.
- **Résultats :** `resultats/gpu_dl.{json,md}` ; journal, relevés du GPU et reprise : `resultats/gpu/<date>/`. Renvoyer ce dossier et
  les deux fichiers.

## 8. Campagne GPU sur une machine louée, en temps borné : `./scripts/rungpu_cloud`

Pour une instance louée à l'heure, avec une ou plusieurs cartes (Turing, Ada ou Hopper : binaire sm_75, sm_89 et sm_90). Chaque carte
calcule une tranche des paires de **chaque** expérience ; à la fin, les tranches sont additionnées, et le résultat est identique à celui
d'un seul GPU (vérifié : mêmes statistiques, au bit près, pour un GPU et pour deux tranches fusionnées).

1. **Instance :** Ubuntu avec le pilote NVIDIA. `nvidia-smi` affiche « CUDA Version: X.Y » ; installer le compilateur de cette version
   (12.0 au moins) depuis le dépôt NVIDIA :
   ```bash
   wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
   sudo dpkg -i cuda-keyring_1.1-1_all.deb && sudo apt update
   sudo apt install -y build-essential git cuda-nvcc-X-Y cuda-cudart-dev-X-Y     # X-Y : la version affichée, par ex. 12-8
   git clone https://github.com/Spider4Tech/sillage-brume.git && cd sillage-brume
   ```
2. **Lancer :** `./scripts/rungpu_cloud` (10 h au plus). Le script compte les cartes, vérifie la conformité au C, mesure le débit,
   annonce la durée des deux plans et prend le plan étendu s'il tient dans le budget, sinon le plan de base (forcer : `--long` ou
   `--base` ; autre budget : `./scripts/rungpu_cloud 8`). Il tourne en arrière-plan : on peut fermer la session SSH.
3. **Suivre :** `./scripts/rungpu_cloud --statut`. Arrêter : `--arreter` ; relancer reprend, avec le même nombre de cartes.
4. **Récupérer :** à la fin, `resultats/gpu_cloud_<date>.tar.gz` (tranches, journaux, relevés des cartes, `gpu_dl.json` et `.md`
   fusionnés) ; `scp` vers votre machine, puis **supprimer l'instance** : arrêtée, elle reste facturée.

Le travail vaut ≈ 6,5 h de RTX 4070 Ti pour le plan de base et ≈ 26 h pour le plan étendu ; la durée se divise par le nombre de cartes et
par leur vitesse relative, que le script mesure avant de lancer. La campagne n'utilise que des opérations entières et des compteurs en
mémoire partagée : ni les cœurs tenseurs, ni la mémoire HBM, ni la mémoire des cartes à 80 Go n'y servent.
