#!/bin/bash
# Campagne de 8 h sur l'AEAD de BRUME-1024q (orientation SpongeWrap). Lancé par une tâche planifiée (WSL meurt avec la
# session SSH). Archive des sources attendue dans $1 (défaut : /mnt/c/Users/$USER/aead8h.tgz). Résultats dans
# ~/orion_aead8h/res, rapport final ~/orion_aead8h/res/rapport.md.
#   Phase 1 (machine au repos) : 17 contrôles de brume1024 (normal, puis sous ASan et UBSan), ctgrind (3 modes), dudect
#   (temps1024, dont aead_ouvrir), témoins.
#   Phase 2 (15 processus jusqu'à l'échéance) : equiv ×3, forge ×4, multi ×2, aval ×3, biais ×3.
#   Phase 3 : bilan.
set -u
ARCHIVE=${1:-/mnt/c/Users/$USER/aead8h.tgz}
DUREE=${DUREE:-28800}
D=~/orion_aead8h
T0=$(date +%s); FIN=$((T0 + DUREE))
rm -rf $D && mkdir -p $D/res && cd $D && tar xzf "$ARCHIVE" || exit 1
J=$D/res/journal.log
log() { echo "$(date '+%F %T') $*" | tee -a $J; }
log "début, échéance $(date -d @$FIN '+%F %T'), charge $(cat /proc/loadavg)"
B=prototypes/brume_q/b1024
F="-O3 -march=native -fopenmp -Wno-unused-function -I sillage/c -I tests/c -I $B"
L="sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm"
mkdir -p tests/c/build resultats
cc $F $B/brume1024.c $L -o tests/c/build/brume1024 &&
cc $F -DSANS_MAIN $B/temps1024.c $L -o tests/c/build/temps1024 &&
cc $F -DSANS_MAIN $B/campagne_aead.c $L -o tests/c/build/campagne_aead &&
gcc -O3 -g -mavx2 -fopenmp -DSANS_MAIN -DSL_VALGRIND -Wno-unused-function -I sillage/c -I tests/c -I $B $B/ct1024.c $L -o tests/c/build/ct1024 ||
{ log "ÉCHEC de compilation"; exit 1; }
gcc --version | head -1 >> $J; grep -m1 "model name" /proc/cpuinfo >> $J

# ---- phase 1 : contrôles, ctgrind, dudect, témoins (machine au repos)
log "phase 1 : contrôles"
tests/c/build/brume1024 > res/brume1024.txt 2>&1; cp resultats/brume1024.json res/ 2>/dev/null
grep -E "contrôles," res/brume1024.txt | tee -a $J
log "phase 1 : contrôles sous ASan et UBSan"
gcc -O1 -g -march=native -fopenmp -fsanitize=address,undefined -fno-omit-frame-pointer -Wno-unused-function -I sillage/c -I tests/c -I $B \
    $B/brume1024.c $L -o tests/c/build/brume1024_asan 2> res/asan_build.log &&
ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS=suppressions=$B/lsan_harnais.supp UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 tests/c/build/brume1024_asan > res/brume1024_asan.txt 2>&1
echo "ASan/UBSan : $(grep -E 'contrôles,' res/brume1024_asan.txt) ; $(grep -c 'ERROR: AddressSanitizer\|runtime error\|LeakSanitizer' res/brume1024_asan.txt) erreurs" | tee -a $J
log "phase 1 : ctgrind"
for mode in memoire secret temoin; do
  F2=""; [ $mode = memoire ] && F2="--leak-check=full --show-leak-kinds=definite,indirect,possible"
  OMP_NUM_THREADS=1 valgrind --error-exitcode=0 --error-limit=no $F2 tests/c/build/ct1024 $mode > res/ct_$mode.out 2> res/ct_$mode.log
  echo "ctgrind $mode : $(grep -h 'ERROR SUMMARY' res/ct_$mode.log | sed 's/==[0-9]*== //') ; $(cat res/ct_$mode.out | tr '\n' ' ')" | tee -a $J
done
log "phase 1 : dudect (un thread, machine au repos)"
OMP_NUM_THREADS=1 taskset -c 2 tests/c/build/temps1024 > res/dudect.txt 2>&1; cp resultats/temps1024.json res/ 2>/dev/null
grep -E "contrôles,|ÉCHEC" res/dudect.txt | tee -a $J
log "phase 1 : témoins (défauts plantés, 120 s chacun, doivent ÉCHOUER)"
for m in forge aval biais; do
  CAMPAGNE_TEMOIN=1 OMP_NUM_THREADS=1 tests/c/build/campagne_aead $m 120 $((1000 + RANDOM)) res/temoin_$m.json &
done
wait
for m in forge aval biais; do echo "témoin $m : $(grep -o '"ok": [a-z]*' res/temoin_$m.json)" | tee -a $J; done

# ---- phase 2 : 15 processus jusqu'à l'échéance (10 min de marge pour le bilan)
RESTE=$((FIN - $(date +%s) - 600))
log "phase 2 : 15 processus pendant $RESTE s"
i=0
for m in equiv equiv equiv forge forge forge forge multi multi aval aval aval biais biais biais; do
  i=$((i + 1))
  OMP_NUM_THREADS=1 tests/c/build/campagne_aead $m $RESTE $((20261113 * 100 + i)) res/${m}_$i.json > /dev/null 2>&1 &
done
wait
log "phase 2 terminée"

# ---- phase 3 : bilan
R=res/rapport.md
{
  echo "# Campagne AEAD BRUME-1024q (orientation SpongeWrap), $(date -d @$T0 '+%F %T') → $(date '+%F %T')"
  echo; echo "## Phase 1"; echo; echo '```'; cat $J; echo '```'
  echo; echo "## Témoins (doivent être \"ok\": false)"; echo; for f in res/temoin_*.json; do echo "- \`$(cat $f)\`"; done
  echo; echo "## Phase 2"; echo; for f in res/equiv_*.json res/forge_*.json res/multi_*.json res/aval_*.json res/biais_*.json; do echo "- \`$(cat $f 2>/dev/null || echo "$f absent")\`"; done
} > $R
ok=1
# même nombre de contrôles, tous réussis, avec et sans sanitizers ; fuites du harnais filtrées par lsan_harnais.supp
NC=$(grep -o '[0-9]* contrôles, tous réussis' res/brume1024.txt | cut -d' ' -f1)
[ -n "$NC" ] || ok=0
grep -q "$NC contrôles, tous réussis" res/brume1024_asan.txt || ok=0
grep -q "ERROR: AddressSanitizer\|runtime error\|LeakSanitizer" res/brume1024_asan.txt && ok=0
grep -q "contrôles, tous réussis" res/dudect.txt || ok=0
grep -q "ERROR SUMMARY: 0 errors" res/ct_secret.log || ok=0
grep -q "ERROR SUMMARY: 0 errors" res/ct_memoire.log || ok=0
grep -q "ERROR SUMMARY: [1-9]" res/ct_temoin.log || ok=0
for f in res/temoin_*.json; do grep -q '"ok": false' $f || ok=0; done
for f in res/equiv_*.json res/forge_*.json res/multi_*.json res/aval_*.json res/biais_*.json; do grep -q '"ok": true' $f 2>/dev/null || ok=0; done
echo >> $R; echo "## Verdict : $([ $ok = 1 ] && echo 'TOUT CONFORME' || echo 'ÉCHEC — voir ci-dessus')" >> $R
log "fin ; verdict $([ $ok = 1 ] && echo conforme || echo ÉCHEC)"
cp -r res /mnt/c/Users/$USER/orion_aead8h_res 2>/dev/null
