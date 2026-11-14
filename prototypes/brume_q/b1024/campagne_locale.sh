#!/bin/bash
# Campagne locale de 8 h sur BRUME-1024q (complément de campagne_aead_songbird.sh), REPRENABLE : la machine peut s'éteindre
# sans prévenir. Tout l'état est sur disque dans ~/orion_local8h. Relancer la même commande reprend là où l'on était : les
# unités finies sont sautées, le score de mutation reprend mutant par mutant, l'échéance fixée au premier lancement est gardée.
# Pas de relance automatique.
#   bash campagne_locale.sh <racine du dépôt>     (lancer détaché : setsid nohup bash … > ~/orion_local8h.log 2>&1 &)
# Unités : A diversité des compilateurs (gcc 16 hôte, gcc 13 et clang dans le conteneur tgh) ; B ASan et UBSan (gcc 13) ;
# E grandes longueurs (> 2^32 octets) ; D déterminisme selon le nombre de threads (40 min) ; F score de mutation de
# brume1024.c (7 processus), avec C Valgrind memcheck en parallèle ; H prolongation jusqu'à l'échéance ; G bilan.
set -u
DEPOT=${1:-$PWD}
D=~/orion_local8h
mkdir -p $D/etat $D/res $D/mut
J=$D/res/journal.log
log() { echo "$(date '+%F %T') $*" | tee -a $J; }
[ -f $D/etat/echeance ] || echo $(( $(date +%s) + ${DUREE:-28800} )) > $D/etat/echeance
FIN=$(cat $D/etat/echeance)
reste() { echo $(( FIN - $(date +%s) )); }
fait() { [ -f $D/etat/$1.fait ]; }
marquer() { touch $D/etat/$1.fait; }
log "lancement (ou reprise), échéance $(date -d @$FIN '+%F %T'), charge $(cat /proc/loadavg)"

# sources figées au premier lancement
if [ ! -d $D/src ]; then
  mkdir -p $D/src && (cd $DEPOT && tar cf - sillage/c tests/c/resultat.h tests/c/brume_ref.h prototypes/brume_q/b1024) | (cd $D/src && tar xf -) || exit 1
  log "sources copiées depuis $DEPOT"
fi
S=$D/src; B=$S/prototypes/brume_q/b1024
INC="-I $S/sillage/c -I $S/tests/c -I $B"
LIB="$S/sillage/c/commun.c $S/sillage/c/brume512.c $S/sillage/c/brume512_avx2.c -lm"
TGH() { distrobox enter tgh -- bash -lc "$*"; }

# exécute la batterie dans un dossier propre ; $1 nom, $2 binaire ; rend 0 si 17 contrôles réussis
batterie() {
  local n=$1 exe=$2; mkdir -p $D/res/$n/resultats
  (cd $D/res/$n && BRUME1024_RAPIDE=1 timeout 3600 $exe > sortie.txt 2>&1; echo $? > rc)
  (cd $D/res/$n && timeout 600 $exe kat > kat.h 2>/dev/null; diff -q kat.h $B/kat_b1024.h > /dev/null && echo identiques > kat_compare || echo DIFFÉRENTS > kat_compare)
  log "A/$n : $(grep -h 'contrôles,' $D/res/$n/sortie.txt) ; KAT régénérés $(cat $D/res/$n/kat_compare)"
}

# ---- A. diversité des compilateurs
for cfg in "h_O3|gcc -O3 -march=native|hote" "h_O2|gcc -O2 -march=native|hote" "h_O0|gcc -O0 -march=native|hote" \
           "h_v3|gcc -O3 -march=x86-64-v3|hote" "t_O3|gcc -O3 -march=native|tgh" "t_O2v3|gcc -O2 -march=x86-64-v3|tgh" \
           "t_clang|clang -O3 -march=native|tgh"; do
  IFS='|' read n cc ou <<< "$cfg"
  fait A_$n && continue
  [ $(reste) -lt 3600 ] && break
  exe=$D/res/brume1024_$n
  cmd="$cc -fopenmp -Wno-unused-function $INC $B/brume1024.c $LIB -o $exe"
  if [ $ou = tgh ]; then TGH "$cmd" > $D/res/build_$n.log 2>&1; else $cmd > $D/res/build_$n.log 2>&1; fi
  if [ -x $exe ]; then
    if [ $ou = tgh ]; then
      mkdir -p $D/res/$n/resultats
      TGH "cd $D/res/$n && BRUME1024_RAPIDE=1 timeout 3600 $exe > sortie.txt 2>&1; echo \$? > rc; timeout 600 $exe kat > kat.h 2>/dev/null"
      diff -q $D/res/$n/kat.h $B/kat_b1024.h > /dev/null && echo identiques > $D/res/$n/kat_compare || echo DIFFÉRENTS > $D/res/$n/kat_compare
      log "A/$n : $(grep -h 'contrôles,' $D/res/$n/sortie.txt) ; KAT régénérés $(cat $D/res/$n/kat_compare)"
    else
      batterie $n $exe
    fi
  else
    log "A/$n : compilation impossible ($(tail -1 $D/res/build_$n.log | cut -c1-120))"
  fi
  marquer A_$n
done

# ---- B. ASan et UBSan (gcc 13, conteneur)
if ! fait B && [ $(reste) -gt 3600 ]; then
  mkdir -p $D/res/asan/resultats
  TGH "gcc -O1 -g -march=native -fopenmp -fsanitize=address,undefined -fno-omit-frame-pointer -Wno-unused-function $INC $B/brume1024.c $LIB -o $D/res/brume1024_asan && cd $D/res/asan && ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS=suppressions=$B/lsan_harnais.supp UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 BRUME1024_RAPIDE=1 $D/res/brume1024_asan > sortie.txt 2>&1" > $D/res/build_asan.log 2>&1
  log "B/ASan+UBSan : $(grep -h 'contrôles,' $D/res/asan/sortie.txt) ; $(grep -c 'ERROR: AddressSanitizer\|runtime error\|LeakSanitizer' $D/res/asan/sortie.txt) erreurs"
  marquer B
fi

# outils de la campagne
gcc -O3 -march=native -fopenmp -DSANS_MAIN -Wno-unused-function $INC $B/campagne_aead.c $LIB -o $D/res/campagne_aead 2>> $D/res/build_outils.log
gcc -O2 $B/mutants.c -o $D/res/mutants 2>> $D/res/build_outils.log

# ---- E. grandes longueurs
if ! fait E && [ $(reste) -gt 3600 ]; then
  log "E/grand : début"
  OMP_NUM_THREADS=1 $D/res/campagne_aead grand 1 1 $D/res/grand.json > /dev/null 2>&1
  log "E/grand : $(cat $D/res/grand.json 2>/dev/null)"
  marquer E
fi

# ---- D. déterminisme selon le nombre de threads (40 min, ou ce qui reste moins 2 h)
if ! fait D && [ $(reste) -gt 9000 ]; then
  n=$(ls $D/res/fils_*.json* 2>/dev/null | wc -l)
  log "D/fils : 2 400 s (essai $n)"
  OMP_NUM_THREADS=1 $D/res/campagne_aead fils 2400 $((7000 + n)) $D/res/fils_$n.json > /dev/null 2>&1
  log "D/fils : $(cat $D/res/fils_$n.json 2>/dev/null)"
  marquer D
fi

# ---- C. Valgrind memcheck (en parallèle du score de mutation)
if ! fait C; then
  (
    mkdir -p $D/res/valgrind/resultats
    TGH "gcc -O2 -g -march=native -fopenmp -Wno-unused-function $INC $B/brume1024.c $LIB -o $D/res/brume1024_vg && cd $D/res/valgrind && BRUME1024_RAPIDE=1 OMP_NUM_THREADS=2 timeout $(( $(reste) - 900 )) valgrind --error-exitcode=9 --leak-check=full --suppressions=$B/valgrind.supp $D/res/brume1024_vg > sortie.txt 2> valgrind.log; echo \$? > rc"
    log "C/Valgrind : $(grep -h 'contrôles,' $D/res/valgrind/sortie.txt) ; $(grep -h 'ERROR SUMMARY' $D/res/valgrind/valgrind.log | sed 's/==[0-9]*== //') ; code $(cat $D/res/valgrind/rc)"
    [ -n "$(grep -h 'ERROR SUMMARY' $D/res/valgrind/valgrind.log)" ] && touch $D/etat/C.fait
  ) &
fi

# ---- F. score de mutation (7 processus ; un fichier par mutant ; reprise par mutant)
N=$($D/res/mutants compter $B/brume1024.c)
NC=$(grep -o '[0-9]* contrôles, tous réussis' $D/res/h_O3/sortie.txt | cut -d' ' -f1)   # contrôles de la version non mutée
log "F/mutation : $N mutants, $(ls $D/mut | wc -l) déjà faits"
travailleur() {
  local w=$1 k
  for ((k = w; k < N; k += 7)); do
    [ $(reste) -lt 900 ] && return
    [ -f $D/mut/$k.txt ] && continue
    local t=$D/tmp_$w; mkdir -p $t/resultats
    local desc; desc=$($D/res/mutants ecrire $B/brume1024.c $k $t/mutant.c)
    if ! gcc -O2 -march=native -fopenmp -w $INC $t/mutant.c $LIB -o $t/m 2> /dev/null; then
      echo "non_compilable | $desc" > $D/mut/$k.tmp
    else
      (cd $t && BRUME1024_RAPIDE=1 OMP_NUM_THREADS=2 timeout 180 ./m > sortie.txt 2>&1); local rc=$?
      if [ $rc -eq 0 ] && grep -q "^brume1024 : $NC contrôles, tous réussis" $t/sortie.txt; then r=survit
      elif [ $rc -eq 124 ]; then r=tue_delai
      elif [ $rc -eq 1 ]; then r="tue $(grep -h 'ÉCHEC$' $t/sortie.txt | awk '{print $1}' | head -3 | tr '\n' ',')"
      else r="tue_plantage_$rc"; fi
      echo "$r | $desc" > $D/mut/$k.tmp
    fi
    mv $D/mut/$k.tmp $D/mut/$k.txt
  done
}
if ! fait F; then
  pids=()
  for w in 0 1 2 3 4 5 6; do travailleur $w & pids+=($!); done
  wait "${pids[@]}"
  [ $(ls $D/mut/*.txt 2>/dev/null | wc -l) -ge $N ] && marquer F
  log "F/mutation : $(ls $D/mut/*.txt | wc -l) mutants évalués"
fi

# ---- H. prolongation jusqu'à l'échéance (graines différentes de songbird) : equiv ×2, forge ×2, fils, aval
if fait F && [ $(reste) -gt 1800 ]; then
  n=$(ls $D/res/prolong_* 2>/dev/null | wc -l)
  log "H/prolongation : $(( $(reste) - 900 )) s"
  pids=()
  i=0
  for m in equiv equiv forge forge fils aval; do
    i=$((i + 1))
    OMP_NUM_THREADS=1 $D/res/campagne_aead $m $(( $(reste) - 900 )) $((9000 + 10 * n + i)) $D/res/prolong_${n}_${m}_$i.json > /dev/null 2>&1 & pids+=($!)
  done
  wait "${pids[@]}"
  log "H/prolongation terminée"
fi
wait   # Valgrind

# ---- G. bilan (refait à chaque passage)
R=$D/res/rapport.md
tues=$(cat $D/mut/*.txt 2>/dev/null | grep -c '^tue'); surv=$(cat $D/mut/*.txt 2>/dev/null | grep -c '^survit'); nc=$(cat $D/mut/*.txt 2>/dev/null | grep -c '^non_compilable')
{
  echo "# Campagne locale BRUME-1024q, bilan du $(date '+%F %T')"; echo
  echo '```'; cat $J; echo '```'; echo
  echo "## Score de mutation"; echo
  echo "- mutants évalués : $(ls $D/mut/*.txt 2>/dev/null | wc -l) sur $N ; tués : $tues ; survivants : $surv ; non compilables : $nc"
  [ $((tues + surv)) -gt 0 ] && echo "- score : $(( 1000 * tues / (tues + surv) / 10 )).$(( 1000 * tues / (tues + surv) % 10 )) % des mutants compilables"
  echo; echo "### Survivants (à examiner : test manquant ou mutation équivalente)"; echo
  grep -h '^survit' $D/mut/*.txt 2>/dev/null | sed 's/^survit | /- /'
  echo; echo "## Prolongation et autres modes"; echo
  for f in $D/res/grand.json $D/res/fils_*.json $D/res/prolong_*.json; do [ -f $f ] && echo "- \`$(cat $f)\`"; done
  for f in $D/res/fils_*.json.partiel $D/res/prolong_*.json.partiel; do [ -f $f ] && [ ! -f ${f%.partiel} ] && echo "- (interrompu, point d'étape) \`$(cat $f)\`"; done
} > $R
log "bilan écrit : $R"
