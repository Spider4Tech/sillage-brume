# Lancer la campagne de 24 h

Ce programme fait tourner tous les cœurs de la machine pendant 24 h pour tester une suite de cryptographie expérimentale. Il ne touche qu'à son propre dossier, n'envoie rien sur le réseau pendant le calcul et n'a pas besoin de droits administrateur (sauf pour installer les paquets système). C'est du code de recherche : ne pas s'en servir pour protéger de vraies données.

## 1. Installer

```bash
git clone https://github.com/Spider4Tech/sillage-brume.git
cd sillage-brume
./preparer_campagne.sh --installer
```

Ce script vérifie la machine et installe les paquets Python dans le dossier `.venv`. S'il manque quelque chose, il donne la commande à lancer pour votre distribution. Il faut Linux ; WSL fonctionne, mais sans suivi de température et avec des mesures de temps moins fiables.

## 2. Vérifier la machine

- **Refroidissement :** 24 h à pleine charge. Dégagez les entrées d'air. Un Ryzen récent peut tenir 90 à 95 °C par conception ; c'est normal.
- **Alimentation :** sur secteur, sans veille automatique (la veille est bloquée quand systemd est présent, pas sous WSL).
- **Stabilité :** un overclocking ou un réglage de mémoire instable peut faire planter la machine ou fausser des résultats. Préférez les réglages d'origine.

## 3. Lancer

```bash
./runlong
```

Le calcul part en arrière-plan : vous pouvez fermer le terminal. Il faut seulement que la machine reste allumée.

```bash
./runlong --statut     # où on en est, température, échecs
./runlong --arreter    # arrêt propre
tail -f resultats/nuit/journal.log    # détail
```

**N'utilisez pas la machine pendant la phase « 2/6 temps constant »**, environ 3 à 4 h : elle mesure des écarts de quelques cycles, et toute autre activité fausse le résultat (le rapport signale une machine occupée). Cette phase commence après environ 3 h. Pour le reste, la machine est très sollicitée mais reste utilisable pour de petites tâches. Ne lancez qu'une campagne à la fois.

## 4. En cas d'arrêt

Après un arrêt, une coupure ou un plantage, relancez simplement :

```bash
./runlong
```

Le calcul reprend à la campagne interrompue, avec le temps restant. Pour repartir de zéro : `./runlong --neuf`.

Si la température reste au-dessus de 100 °C pendant 5 minutes, le programme s'arrête de lui-même : laissez refroidir, aérez, puis reprenez. Le seuil se règle avec `SILLAGE_TEMP_MAX=95 ./runlong`. Une campagne bloquée est arrêtée automatiquement et la suite continue ; c'est indiqué dans le rapport.

## 5. Renvoyer les résultats

À la fin, ou à chaque arrêt, le programme écrit `resultats/campagne_<date>.tar.gz` et affiche son nom. Renvoyez le plus récent.

Il contient les résultats, les journaux et une fiche de la machine (processeur, mémoire, versions de logiciels). Il ne contient ni le nom de la machine ni votre nom d'utilisateur, et les chemins de votre dossier personnel sont retirés des fichiers.
