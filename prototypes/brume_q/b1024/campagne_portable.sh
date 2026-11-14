#!/bin/bash
# Analyses de cryptanalyse sur une machine d'appoint (ROADMAP.md § 3), REPRENABLE : relancer la même commande reprend là
# où l'on était (un fichier par cube ; marqueur de fin pour l'agrégation). Pas de relance automatique.
#   1. agregation2 à 2^31 échantillons : différentielles et coques exactes à 2 tours, 16 confirmations empiriques ;
#   2. cubes_degre : grille d ∈ {8, …, 32}, r ∈ {3, …, 8}, formes boule, nibbles, bits, 4 cubes chacune ;
#   3. d = 36 pour r ∈ {5, 6, 7}, forme boule, 2 cubes (s'il reste du temps).
# Usage : bash campagne_portable.sh <archive des sources>
set -u
ARCHIVE=${1:-$HOME/portable.tgz}
D=~/orion_portable
mkdir -p $D/etat $D/res/cubes
J=$D/res/journal.log
log() { echo "$(date '+%F %T') $*" | tee -a $J; }
log "lancement (ou reprise), charge $(cat /proc/loadavg)"
if [ ! -d $D/src ]; then mkdir -p $D/src && tar xzf "$ARCHIVE" -C $D/src || exit 1; log "sources extraites"; fi
S=$D/src; B=$S/prototypes/brume_q/b1024
INC="-I $S/sillage/c -I $S/tests/c -I $B"
LIB="$S/sillage/c/commun.c $S/sillage/c/brume512.c $S/sillage/c/brume512_avx2.c -lm"
for p in agregation2 cubes_degre; do
  [ -x $D/$p ] || gcc -O3 -march=native -fopenmp -DSANS_MAIN -w $INC $B/$p.c $LIB -o $D/$p || { log "compilation de $p impossible"; exit 1; }
done
gcc --version | head -1 >> $J; grep -m1 "model name" /proc/cpuinfo >> $J

if [ ! -f $D/etat/agregation.fait ]; then
  log "1. agrégation à 2 tours, 2^31 échantillons"
  (cd $D/res && $D/agregation2 31 > agregation2.json.tmp 2> agregation2.err; echo $? > agregation2.rc; mv agregation2.json.tmp agregation2.json)
  log "1. fini, code $(cat $D/res/agregation2.rc) ; $(grep -o '"ok": [a-z]*' $D/res/agregation2.json)"
  touch $D/etat/agregation.fait
fi

log "2. grille de cubes"
for d in 8 12 16 20 24 28 32; do
  for r in 3 4 5 6 7 8; do
    for forme in boule nibbles bits; do
      $D/cubes_degre $D/res/cubes $r $d $forme 4 >> $D/res/cubes.log 2>&1
    done
  done
  log "2. d = $d fini"
done
log "3. d = 36"
for r in 5 6 7; do $D/cubes_degre $D/res/cubes $r 36 boule 2 >> $D/res/cubes.log 2>&1; done

# bilan : pour chaque (r, d, forme), bits de sortie à somme nulle (min et max sur les cubes)
{
  echo "# Cubes sur BRUME-1024q ($(date '+%F %T'))"; echo
  echo "Bits de sortie (sur 1 024) dont la somme sur le cube est nulle : minimum et maximum sur les cubes. Environ 512 : sommes"
  echo "aléatoires (degré atteint) ; 1 024 : somme nulle partout (degré inférieur à d dans ces variables)."; echo
  echo "| tours | dimension | forme | cubes | min | max |"; echo "|---|---|---|---|---|---|"
  cat $D/res/cubes/*.json 2>/dev/null \
    | sed -E 's/.*"tours": ([0-9]+), "dimension": ([0-9]+), "forme": "([a-z]+)".*"bits_de_sortie_a_somme_nulle": ([0-9]+).*/\1 \2 \3 \4/' \
    | sort -n -k1,1 -k2,2 -k3,3 | awk '{k=$1" "$2" "$3; n[k]++; if(!(k in mn)||$4<mn[k])mn[k]=$4; if(!(k in mx)||$4>mx[k])mx[k]=$4; o[k]=NR} END{for(k in n){split(k,a," "); printf "| %s | %s | %s | %d | %d | %d |\n", a[1], a[2], a[3], n[k], mn[k], mx[k]}}' | sort -t'|' -k2,2n -k3,3n
} > $D/res/cubes.md
log "fin ; bilans : $D/res/agregation2.json, $D/res/cubes.md"
