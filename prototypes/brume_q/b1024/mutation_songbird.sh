#!/bin/bash
# Score de mutation, deuxième passe (13 novembre 2026), REPRENABLE : relancer la même commande reprend mutant par mutant.
#   Passe 1 : tous les mutants de brume1024.c (mutants.c) contre la batterie corrigée (BRUME1024_RAPIDE=1). Un mutant
#             survit seulement si le programme sort avec 0 ET affiche exactement « <N> contrôles, tous réussis », N étant le
#             nombre de contrôles de la version non mutée (un contrôle qui disparaît ne passe pas pour une réussite).
#   Passe 2 : chaque survivant recompilé sous ASan et UBSan (-O0), fuites du harnais filtrées (lsan_harnais.supp) : une
#             erreur mémoire, un comportement indéfini ou une fuite non filtrée le tue.
# Usage : [D=dossier] bash mutation_songbird.sh [archive des sources]   (W : processus de la passe 1, 14 ; W2 : de la passe 2, 3 ;
# DEBUT, FIN : lot de survivants ; LISTE, NC : mode d'appoint, passe 2 seule sur une liste)
set -u
ARCHIVE=${1:-/mnt/c/Users/$USER/mut2.tgz}
D=${D:-~/orion_mut2}          # 3e passe (14 nov.) : D=~/orion_mut3
W=${W:-14}
mkdir -p $D/etat $D/mut $D/asan $D/ref/resultats
J=$D/journal.log
log() { echo "$(date '+%F %T') $*" | tee -a $J; }
log "lancement (ou reprise), $W processus, charge $(cat /proc/loadavg)"
if [ ! -d $D/src ]; then mkdir -p $D/src && tar xzf "$ARCHIVE" -C $D/src || exit 1; log "sources extraites"; fi
S=$D/src; B=$S/prototypes/brume_q/b1024
INC="-I $S/sillage/c -I $S/tests/c -I $B"
LIB="$S/sillage/c/commun.c $S/sillage/c/brume512.c $S/sillage/c/brume512_avx2.c -lm"
SUPP="LSAN_OPTIONS=suppressions=$B/lsan_harnais.supp"

# mode « aide » (machine d'appoint) : LISTE = fichier des survivants de la passe 1 (un numéro par ligne), NC = contrôles de
# référence ; seule la passe 2 tourne, sur le lot [DEBUT, FIN) de cette liste
if [ -n "${LISTE:-}" ]; then
  [ -f $D/etat/nc ] || echo ${NC:-22} > $D/etat/nc
  gcc -O2 $B/mutants.c -o $D/mutants || exit 1
  N=$($D/mutants compter $B/brume1024.c)
fi
if [ -z "${LISTE:-}" ] && [ ! -f $D/etat/nc ]; then
  gcc -O2 -march=native -fopenmp -w $INC $B/brume1024.c $LIB -o $D/ref/b || exit 1
  (cd $D/ref && BRUME1024_RAPIDE=1 ./b > sortie.txt 2>&1)
  nc=$(grep -o '[0-9]* contrôles, tous réussis' $D/ref/sortie.txt | cut -d' ' -f1)
  [ -n "$nc" ] || { log "la version non mutée ne passe pas : arrêt"; exit 1; }
  echo $nc > $D/etat/nc
fi
NC=$(cat $D/etat/nc)
[ -x $D/mutants ] || gcc -O2 $B/mutants.c -o $D/mutants || exit 1
N=$($D/mutants compter $B/brume1024.c)
log "référence : $NC contrôles ; $N mutants ; passe 1 : $(ls $D/mut | wc -l) faits"

passe1() {
  local w=$1 k
  for ((k = w; k < N; k += W)); do
    [ -f $D/mut/$k.txt ] && continue
    local t=$D/tmp1_$w; mkdir -p $t/resultats
    local desc r rc; desc=$($D/mutants ecrire $B/brume1024.c $k $t/mutant.c)
    if ! gcc -O2 -march=native -fopenmp -w $INC $t/mutant.c $LIB -o $t/m 2> /dev/null; then
      r=non_compilable
    else
      (cd $t && BRUME1024_RAPIDE=1 OMP_NUM_THREADS=2 timeout 300 ./m > sortie.txt 2>&1); rc=$?
      if [ $rc -eq 0 ] && grep -q "^brume1024 : $NC contrôles, tous réussis" $t/sortie.txt; then r=survit
      elif [ $rc -eq 124 ]; then r=tue_delai
      elif [ $rc -eq 1 ]; then r="tue $(grep -h 'ÉCHEC$' $t/sortie.txt | awk '{print $1}' | head -3 | tr '\n' ',')"
      elif [ $rc -eq 0 ]; then r="tue_nombre_de_controles $(grep -h 'contrôles,' $t/sortie.txt)"
      else r="tue_plantage_$rc"; fi
    fi
    echo "$r | $desc" > $D/mut/$k.tmp && mv $D/mut/$k.tmp $D/mut/$k.txt
  done
}
if [ -z "${LISTE:-}" ] && [ $(ls $D/mut/*.txt 2>/dev/null | wc -l) -lt $N ]; then
  pids=(); for ((w = 0; w < W; w++)); do passe1 $w & pids+=($!); done; wait "${pids[@]}"
fi
[ -z "${LISTE:-}" ] && log "passe 1 finie : $(grep -l '^survit' $D/mut/*.txt | wc -l) survivants sur $(grep -L '^non_compilable' $D/mut/*.txt | wc -l) compilables"

if [ -n "${LISTE:-}" ]; then SURV=($(grep '^[0-9]' "$LISTE")); else
SURV=($(grep -l '^survit' $D/mut/*.txt | xargs -n1 basename | sed 's/\.txt//' | sort -n)); fi
# passe 2 : W2 processus (la compilation sous ASan d'un mutant prend environ 850 Mo : 14 processus saturent les 7 Go de la
# WSL, et les compilations échouent faute de mémoire, 13 novembre) ; lot [DEBUT, FIN) de la liste des survivants.
# Un mutant a déjà compilé en passe 1 : un échec de compilation ici est environnemental. Il est réessayé, puis signalé
# (« asan_echec_environnement »), jamais compté comme résultat.
W2=${W2:-3}; DEBUT=${DEBUT:-0}; FIN=${FIN:-${#SURV[@]}}
passe2() {
  local w=$1 i k
  for ((i = DEBUT + w; i < FIN; i += W2)); do
    k=${SURV[$i]}
    [ -f $D/asan/$k.txt ] && continue
    local t=$D/tmp2_$w; mkdir -p $t/resultats
    local desc r rc essai compile=0; desc=$($D/mutants ecrire $B/brume1024.c $k $t/mutant.c)
    for essai in 1 2 3; do
      if gcc -O0 -g -march=native -fopenmp -fsanitize=address,undefined -fno-omit-frame-pointer -w $INC $t/mutant.c $LIB -o $t/m 2> $t/compil.log; then compile=1; break; fi
      sleep 30
    done
    if [ $compile = 0 ]; then
      r="asan_echec_environnement $(grep -m1 -o 'Killed\|killed\|out of memory\|error: .*' $t/compil.log | head -1)"
    else
      (cd $t && env ASAN_OPTIONS=detect_leaks=1 $SUPP UBSAN_OPTIONS=halt_on_error=1 BRUME1024_RAPIDE=1 OMP_NUM_THREADS=2 \
         timeout 1800 ./m > sortie.txt 2>&1); rc=$?
      if grep -q "ERROR: AddressSanitizer\|ERROR: LeakSanitizer\|runtime error" $t/sortie.txt; then
        r="tue_asan $(grep -h -m1 -o 'ERROR: [A-Za-z]*: [a-z-]*\|runtime error: [a-z ]*' $t/sortie.txt | head -1)"
      elif [ $rc -eq 0 ] && grep -q "^brume1024 : $NC contrôles, tous réussis" $t/sortie.txt; then r=survit_asan
      elif [ $rc -eq 124 ]; then r=tue_delai_asan
      else r="tue_autre_asan_$rc"; fi
    fi
    echo "$r | $desc" > $D/asan/$k.tmp && mv $D/asan/$k.tmp $D/asan/$k.txt
  done
}
log "passe 2 : survivants [$DEBUT, $FIN) sur ${#SURV[@]}, $W2 processus"
pids=(); for ((w = 0; w < W2; w++)); do passe2 $w & pids+=($!); done; wait "${pids[@]}"
log "passe 2 finie"

R=$D/rapport.md
t1=$(grep -l '^tue' $D/mut/*.txt | wc -l); s1=${#SURV[@]}; nc1=$(grep -l '^non_compilable' $D/mut/*.txt | wc -l)
t2=$(grep -l '^tue' $D/asan/*.txt 2>/dev/null | wc -l); s2=$(grep -l '^survit_asan' $D/asan/*.txt 2>/dev/null | wc -l); e2=$(grep -l '^asan_echec' $D/asan/*.txt 2>/dev/null | wc -l)
{
  echo "# Score de mutation, deuxième passe ($(date '+%F %T'))"; echo
  echo "- Référence : $NC contrôles ; mutants : $N ; non compilables : $nc1"
  echo "- Passe 1 (batterie corrigée) : tués $t1, survivants $s1 ; score $(( 1000 * t1 / (t1 + s1) / 10 )).$(( 1000 * t1 / (t1 + s1) % 10 )) %"
  echo "- Passe 2 (survivants sous ASan et UBSan) : tués $t2, survivants $s2, échecs d'environnement (non comptés, à refaire) $e2 ; traités $(ls $D/asan/*.txt 2>/dev/null | wc -l) sur $s1"
  echo "- Score combiné : $(( 1000 * (t1 + t2) / (t1 + s1) / 10 )).$(( 1000 * (t1 + t2) / (t1 + s1) % 10 )) %"
  echo; echo "## Tués par ASan ou UBSan"; echo; grep -h '^tue' $D/asan/*.txt 2>/dev/null | sed 's/^/- /'
  echo; echo "## Survivants finaux (à classer : équivalent, ou test manquant)"; echo; grep -h '^survit_asan' $D/asan/*.txt 2>/dev/null | sed 's/^survit_asan | /- /'
} > $R
log "rapport : $R"
cp $R /mnt/c/Users/$USER/orion_mut2_rapport.md 2>/dev/null
