#!/usr/bin/env bash
# Campagne de nuit SILLAGE : pousse en C, sur plusieurs heures, ce que la
# batterie (python3 -m tests.run_all) ne peut tester qu'à petite échelle.
#
#   ./rundenuit.sh [heures]        (défaut : 8 ; ex. ./rundenuit.sh 9.5)
#
# Campagnes, dans l'ordre (part du temps total) :
#   0. batterie complète (python3 -m tests.run_all, ≈ 1 h), à partir de 6 h de campagne,
#      pour que la synthèse et la campagne portent sur les mêmes sources
#   1. fuzzing mémoire longue durée, UBSan + pages de garde, un processus
#      par cœur, graines différentes ; un processus sur deux insiste sur le
#      KEM et la SIG (entrées extrêmes comprises) ...................... 8 %
#   2. temps constant (dudect) : permutation, AEAD, KEM (oracle de décodage,
#      oracle FO, clé secrète, μ, niveaux 128 et 256), SIG (tour, signature
#      complète), biais du banc (A/A), témoins positifs ; un dépassement est
#      remesuré, seul un dépassement confirmé est un échec ........ ≈ 25 %
#   3. KEM réel : des dizaines de millions de chiffrés dont le bruit de
#      décodage est recalculé, et une partie décapsulée réellement ; rejet
#      implicite, recalcul de la borne, pire clé ...................... 12 %
#   4. ISD réel (Prange) sur des instances plus grandes, gain QC ...... 8 %
#   5. BRUME et modèles de preuve (tests/nuit_brume.py) : boomerang, impossibles, mini-BRUME
#      exact, activité certifiée, récupération d'état par SAT, annulation de pistes,
#      attaques réduites contre la signature et l'AEAD ............... 30 %
#   6. cryptanalyse à la frontière : séries de cubes, cubes jusqu'à 2^36,
#      différentielles tronquées et linéaires alignées ........... le reste
# Les campagnes s'arrêtent d'elles-mêmes à la fin de leur budget et
# sauvegardent leurs résultats au fil de l'eau : un arrêt (Ctrl-C, coupure)
# ne fait perdre que l'expérience en cours.
#
# Résultats : resultats/NUIT.md (synthèse), resultats/nuit_*.json et .md,
# journal : resultats/nuit/journal.log. Le run précédent est conservé dans
# resultats/nuit_archives/<date>/. La mise en veille est bloquée pendant la
# campagne (systemd-inhibit) si possible.
#
# Reprise après une coupure : ./reprendre_nuit.sh [heures] (SILLAGE_REPRISE=1).
set -u
cd "$(dirname "$(readlink -f "$0")")"

if [ -z "${SILLAGE_NUIT_INHIBE:-}" ] && command -v systemd-inhibit >/dev/null 2>&1 \
   && systemd-inhibit --what=sleep:idle --who=SILLAGE --why=essai true >/dev/null 2>&1; then
    export SILLAGE_NUIT_INHIBE=1
    exec systemd-inhibit --what=sleep:idle --who="SILLAGE" --why="campagne de nuit" "$0" "$@"
fi

REPRISE="${SILLAGE_REPRISE:-0}"
LOG=resultats/nuit/journal.log
if [ "$REPRISE" = 1 ]; then
    # durée d'origine et temps déjà consommé (jusqu'au dernier résultat écrit) : lus dans le journal
    [ -f "$LOG" ] || { echo "rien à reprendre : pas de $LOG" >&2; exit 1; }
    grep -q '\] terminé$' "$LOG" && { echo "la campagne précédente est terminée : rien à reprendre" >&2; exit 1; }
    H0=$(sed -n 's/.*campagne de nuit : \([0-9.]*\) h .*/\1/p' "$LOG" | head -1)
    [ -n "$H0" ] || { echo "$LOG illisible : durée d'origine introuvable" >&2; exit 1; }
    DEBUT0=$(date -d "$(sed -n '1s/^\[\([^]]*\)\].*/\1/p' "$LOG")" +%s)
    # temps consommé : somme des séances du journal, arrêts exclus (chaque séance s'arrête à sa dernière ligne
    # datée : une coupure en pleine campagne compte un peu moins que le réel, ce qui laisse du budget, sans plus)
    USE=$(sed -n 's/^\[\([0-9-]* [0-9:]*\)\] \(.*\)$/\1\t\2/p' "$LOG" | while IFS=$'\t' read -r d m; do
              case $m in "campagne de nuit :"*|"reprise :"*) echo "D $(date -d "$d" +%s)" ;; *) echo "L $(date -d "$d" +%s)" ;; esac
          done | awk '$1 == "D" { if (d) s += l - d; d = $2; l = $2 } $1 == "L" { l = $2 } END { print s + l - d }')
    RESTE_H=$(awk -v h="$H0" -v u="$USE" 'BEGIN { r = h - u / 3600; printf "%.2f", r < 0.5 ? 0.5 : r }')
    H="$H0"
    BUDGET=$(awk -v h="${1:-$RESTE_H}" 'BEGIN { printf "%d", h * 3600 }')
else
    H="${1:-8}"
fi
TOTAL=$(awk -v h="$H" 'BEGIN { printf "%d", h * 3600 }')
if [ "$TOTAL" -lt 60 ]; then echo "durée trop courte : $H h" >&2; exit 1; fi
DEBUT=$(date +%s)
FIN=$((DEBUT + ${BUDGET:-$TOTAL}))     # les parts de budget restent celles de la durée d'origine
NPROC=$(nproc)
MARGE=$(awk -v t="$TOTAL" 'BEGIN { m = t / 20; if (m > 300) m = 300; if (m < 30) m = 30; printf "%d", m }')
mkdir -p resultats/nuit tests/c/build
if [ "$REPRISE" != 1 ]; then
    # conserve le run précédent, terminé ou non (sa date : celle de son journal, unique pour chaque run), données brutes comprises
    if [ -f "$LOG" ]; then
        ARCH=resultats/nuit_archives/$(date -r "$LOG" '+%Y%m%d_%H%M%S')
        mkdir -p "$ARCH"
        cp -p resultats/NUIT.md resultats/nuit_*.json resultats/nuit_*.md resultats/brume_attaques.json resultats/mini_brume*.json \
           resultats/sig_modele.json resultats/aead_modele.json resultats/aead_parallele.json resultats/SYNTHESE.md \
           "$LOG" resultats/nuit/*.jsonl resultats/nuit/etat_* resultats/nuit/sources.sha "$ARCH"/ 2>/dev/null
    fi
    : > "$LOG"
    rm -f resultats/nuit/etat_* resultats/nuit/sources*.sha
fi
# empreinte des sources : une reprise sur du code modifié est signalée, et son complément lancé
empreinte_sources() { cat sillage/c/*.c sillage/c/*.h sillage/*.py tests/*.py tests/c/*.c tests/c/*.h | sha256sum | cut -d' ' -f1; }
SOURCES=$(empreinte_sources)
[ "$REPRISE" = 1 ] || echo "$SOURCES" > resultats/nuit/sources.sha
SRC_CHANGE=0; [ "$REPRISE" = 1 ] && [ "$(cat resultats/nuit/sources.sha 2>/dev/null)" != "$SOURCES" ] && SRC_CHANGE=1

journal() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
# campagne n déjà terminée : la suivante figure au journal (uniquement en reprise)
fait() { [ "$REPRISE" = 1 ] && grep -q "\] $(($1 + 1))/6 " "$LOG"; }
# état d'une campagne, relu par le verdict : ECHEC = interrompue ou code de retour non nul
etat() { echo "$2" > "resultats/nuit/etat_$1"; }
# lancer <fichier de résultats> <libellé> <commande...> ; un résultat d'une séance interrompue ne survit pas (sauf BRUME, qui reprend)
lancer() {
    local nom=$1 lib=$2 rc
    shift 2
    [ "$nom" = nuit_brume ] || rm -f "resultats/$nom.json" "resultats/$nom.md"
    etat "$nom" ECHEC
    "$@" 2>>"$LOG"; rc=$?
    # 1 : contrôle en échec, résultats écrits (le verdict les lit) ; la campagne, elle, a tourné
    if [ "$rc" -eq 0 ] || { [ "$rc" -eq 1 ] && [ -s "resultats/$nom.json" ]; }; then etat "$nom" OK; else journal "$lib : code de retour $rc"; fi
}
part() { awk -v t="$TOTAL" -v p="$1" 'BEGIN { printf "%d", t * p }'; }
reste() { echo $((FIN - $(date +%s))); }
ech() { awk -v n="$1" -v h="$H" 'BEGIN { x = n * h / 8; if (x < 1000) x = 1000; printf "%d", x }'; }

synthese() {
    local fin_reelle ko
    fin_reelle=$(date +%s)
    ko=$(cat resultats/nuit_*.md 2>/dev/null | grep -c '\*\*ÉCHEC\*\*')
    {
        echo "# Campagne de nuit SILLAGE"
        echo
        echo "Début : $(date -d "@${DEBUT0:-$DEBUT}" '+%F %T') — fin : $(date -d "@$fin_reelle" '+%F %T')" \
             "($(( (fin_reelle - ${DEBUT0:-$DEBUT}) / 60 )) min sur $((TOTAL / 60)) prévues)."
        [ "$REPRISE" = 1 ] && echo "Reprise le $(date -d "@$DEBUT" '+%F %T') : les campagnes déjà finies n'ont pas été rejouées, et le temps écoulé compte l'arrêt."
        echo "Machine : $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //'), $NPROC threads."
        echo
        manque=""
        for f in nuit_batterie nuit_fuzz nuit_temps nuit_kem_reel nuit_isd nuit_brume nuit_cryptanalyse; do
            [ "$f" = nuit_batterie ] && [ "$TOTAL" -lt 21600 ] && continue
            if [ ! -f "resultats/$f.md" ]; then manque="$manque $f (non exécutée)"
            elif grep -q ECHEC "resultats/nuit/etat_$f" 2>/dev/null; then manque="$manque $f (interrompue ou en erreur)"; fi
        done
        nl=$(cat resultats/nuit_*.json 2>/dev/null | grep -o 'non lancé' | wc -l)
        nt=$(cat resultats/nuit_*.json 2>/dev/null | grep -o 'non terminé' | wc -l)
        if [ "$ko" -gt 0 ]; then echo "**Verdict : $ko contrôle(s) en ÉCHEC — voir ci-dessous.**"
        elif [ -n "$manque" ] || [ "$nl" -gt 0 ] || [ "$nt" -gt 0 ]; then echo "**Verdict : aucun contrôle en échec, mais campagne INCOMPLÈTE : ce n'est pas une réussite d'ensemble.**"
        else echo "**Verdict : tout a été exécuté, aucun contrôle en échec.**"; fi
        [ -n "$manque" ] && echo && echo "Campagnes manquantes :$manque."
        [ "$nl" -gt 0 ] && echo && echo "Expériences non lancées, faute de budget : $nl (détail dans les sections)."
        [ "$nt" -gt 0 ] && echo && echo "Expériences non terminées : $nt (détail dans les sections)."
        [ "$SRC_CHANGE" = 1 ] && echo && echo "**Sources modifiées depuis le début de la campagne** : les campagnes finies avant la reprise portent sur d'autres sources."
        echo
        for f in nuit_batterie nuit_fuzz nuit_temps nuit_kem_reel nuit_isd nuit_brume nuit_cryptanalyse; do
            if [ -f "resultats/$f.md" ]; then cat "resultats/$f.md"; else echo "## $f"; echo; echo "Non exécuté."; echo; fi
        done
        [ -f resultats/nuit_complement.md ] && cat resultats/nuit_complement.md
        echo "Journal : \`resultats/nuit/journal.log\`."
    } > resultats/NUIT.md
    journal "synthèse écrite : resultats/NUIT.md ($ko échec(s))"
}
trap 'journal "interruption"; synthese; exit 130' INT TERM

if [ "$REPRISE" = 1 ]; then
    journal "reprise : campagne de $H h, $(( (FIN - DEBUT) / 60 )) min disponibles"
else
    journal "campagne de nuit : $H h ($TOTAL s), $NPROC threads"
    rm -f resultats/nuit_*.json resultats/nuit_*.md
fi

# --- 0. construction et conformité ------------------------------------------
journal "construction"
make -s -C sillage/c >>"$LOG" 2>&1 || { journal "ÉCHEC de construction de la bibliothèque"; exit 1; }
make -s -C tests/c all nuit >>"$LOG" 2>&1 || { journal "ÉCHEC de construction des tests C"; exit 1; }
LIB=sillage/c
SRC="$LIB/commun.c $LIB/brume512.c $LIB/brume512_avx2.c"
gcc -O3 -march=native -fopenmp -I $LIB -o tests/c/build/temps tests/c/temps.c $SRC -lm >>"$LOG" 2>&1 \
    || { journal "ÉCHEC de construction de dudect"; exit 1; }
gcc -O1 -g -march=native -fopenmp -fsanitize=undefined,bounds -fsanitize-trap=all -fstack-protector-all \
    -D_FORTIFY_SOURCE=3 -I $LIB -o tests/c/build/fuzz_nuit tests/c/fuzz.c tests/c/garde.c $SRC $LIB/kem.c $LIB/sig.c -lm \
    >>"$LOG" 2>&1 || { journal "ÉCHEC de construction du fuzzer"; exit 1; }
gcc -O3 -march=native -fopenmp -I $LIB -o tests/c/build/sig_ct tests/c/sig_ct.c $SRC -lm >>"$LOG" 2>&1 \
    || { journal "ÉCHEC de construction de sig_ct"; exit 1; }
tests/c/build/sig_ct 50 >>"$LOG" 2>&1 || { journal "ÉCHEC : chemins constant-time de la SIG non conformes"; exit 1; }
journal "construction et conformité : OK"

# --- 0. batterie complète ---------------------------------------------------
if fait 0; then :
elif [ "$TOTAL" -ge 21600 ]; then
    journal "0/6 batterie complète"
    etat nuit_batterie ECHEC
    python3 -m tests.run_all >resultats/nuit/run_all.log 2>&1
    RC=$?
    etat nuit_batterie OK
    {
        echo "## Batterie complète"
        echo
        echo "| Contrôle | Résultat |"; echo "|---|---|"
        echo "| \`batterie_sans_echec\` | $([ "$RC" -eq 0 ] && echo OK || echo '**ÉCHEC**') |"
        echo
        sed -n 3p resultats/SYNTHESE.md
        grep "ÉCHEC" resultats/SYNTHESE.md | sed 's/\*\*//g'
        echo
    } > resultats/nuit_batterie.md
    journal "batterie : $(sed -n 3p resultats/SYNTHESE.md | cut -c1-60)"
else journal "0/6 batterie complète : non lancée (campagne de moins de 6 h)"; fi

# --- 1. fuzzing mémoire -----------------------------------------------------
if ! fait 1; then
B=$(part 0.08); [ "$B" -gt "$(( $(reste) - MARGE ))" ] && B=$(( $(reste) - MARGE )); FINF=$(( $(date +%s) + B ))
journal "1/6 fuzzing mémoire : $B s, $NPROC processus"
etat nuit_fuzz ECHEC
rm -f resultats/nuit/fuzz_*.jsonl resultats/nuit/fuzz_*.err
for p in $(seq 1 "$NPROC"); do
    (
        k=0
        if [ $((p % 2)) -eq 0 ]; then ITF=500; REP=8; else ITF=5000; REP=1; fi   # KEM/SIG, ou toutes les API
        while [ "$(date +%s)" -lt "$FINF" ]; do
            graine=$((p * 1000003 + k))
            if OMP_NUM_THREADS=1 tests/c/build/fuzz_nuit "$ITF" "$graine" "$REP" >>"resultats/nuit/fuzz_$p.jsonl" \
                   2>"resultats/nuit/fuzz_$p.$k.err"; then
                rm -f "resultats/nuit/fuzz_$p.$k.err"
            else
                echo "{\"echec\": true, \"graine\": $graine}" >>"resultats/nuit/fuzz_$p.jsonl"
            fi
            k=$((k + 1))
        done
    ) &
done
wait
LOTS=$(cat resultats/nuit/fuzz_*.jsonl | grep -c '"iterations"')
ECH=$(cat resultats/nuit/fuzz_*.jsonl | grep -c '"echec"')
IT=$(cat resultats/nuit/fuzz_*.jsonl | sed -n 's/.*"iterations": \([0-9]*\).*/\1/p' | awk '{s += $1} END {print s + 0}')
ARB=$(cat resultats/nuit/fuzz_*.jsonl | sed -n 's/.*"hachage_arbre": \([0-9]*\).*/\1/p' | awk '{s += $1} END {print s + 0}')
KS=$(cat resultats/nuit/fuzz_*.jsonl | sed -n 's/.*"kem": \([0-9]*\), "sig": \([0-9]*\).*/\1 \2/p' | awk '{s += $1 + $2} END {print s + 0}')
EXT=$(cat resultats/nuit/fuzz_*.jsonl | sed -n 's/.*"extremes": \([0-9]*\).*/\1/p' | awk '{s += $1} END {print s + 0}')
OKF=$([ "$ECH" -eq 0 ] && [ "$LOTS" -gt 0 ] && echo true || echo false)
cat > resultats/nuit_fuzz.json <<EOF
{
 "controles": {
  "aucune_erreur_memoire_ni_comportement_indefini": $OKF
 },
 "mesures": {
  "lots": $LOTS, "lots_en_echec": $ECH, "iterations_api": $IT, "hachages_arborescents": $ARB, "controles_kem_sig": $KS, "entrees_extremes": $EXT, "processus": $NPROC, "duree_s": $B
 }
}
EOF
{
    echo "## Fuzzing mémoire longue durée (nuit)"
    echo
    echo "$NPROC processus, graines différentes, UBSan en mode trap et allocateur à pages de garde (ni ASan ni guidage par couverture : non disponibles ici)."
    echo
    echo "| Contrôle | Résultat |"; echo "|---|---|"
    echo "| \`aucune_erreur_memoire_ni_comportement_indefini\` | $([ "$OKF" = true ] && echo OK || echo '**ÉCHEC**') |"
    echo
    echo "Lots : $LOTS (dont $ECH en échec) — itérations d'API : $IT — hachages arborescents : $ARB — contrôles KEM/SIG : $KS, dont entrées extrêmes à part : $EXT."
    [ "$ECH" -gt 0 ] && echo "Sorties d'erreur : \`resultats/nuit/fuzz_*.err\`."
    echo
} > resultats/nuit_fuzz.md
journal "fuzzing : $LOTS lots, $IT itérations, $ECH échec(s)"
etat nuit_fuzz OK
fi

# --- 2. temps constant (dudect) ---------------------------------------------
# op:mesures (pour 8 h, proportionnel à la durée):coût estimé d'une mesure en µs
# témoins : *_ref, kem_temoin (fuite attendue) ; indicatifs : permutation_ref,
# kem_ct_public (chiffré public répété, sans contrôle).
if ! fait 2; then
journal "2/6 temps constant (dudect, un seul cœur, rien d'autre ne tourne)"
etat nuit_temps ECHEC
OPS="permutation:$(ech 100000000):1 permutation_ref:$(ech 4000000):10 aead:$(ech 50000000):5 aead_p:$(ech 300000):850 \
kem_aa:$(ech 600000):800 kem_temoin:$(ech 300000):800 kem_oracle:$(ech 1200000):800 kem_oracle_fo:$(ech 1200000):800 \
kem_decaps:$(ech 1200000):800 kem_encaps:$(ech 600000):500 kem_ct_public:$(ech 300000):800 \
kem256_oracle:$(ech 100000):4500 kem256_decaps:$(ech 100000):4500 \
sig_tour:$(ech 3000000):100 sig_tour_ref:$(ech 100000):60 sig_sign:$(ech 60000):40000"
PIN=""; command -v taskset >/dev/null 2>&1 && PIN="taskset -c $((NPROC - 1))"
: > resultats/nuit/temps.jsonl
CT=""; MT=""; TAB=""
for e in $OPS; do
    op=${e%%:*}; r=${e#*:}; n=${r%%:*}; us=${r##*:}
    est=$(awk -v n="$n" -v u="$us" 'BEGIN { printf "%d", n * u / 1e6 }')
    if [ "$est" -gt "$(( $(reste) - MARGE ))" ]; then journal "dudect $op : non lancé (≈ $est s estimés)"; continue; fi
    t0=$(date +%s)
    ligne=$($PIN tests/c/build/temps "$op" "$n" 2>>"$LOG")
    echo "$ligne" >> resultats/nuit/temps.jsonl
    t=$(echo "$ligne" | sed -n 's/.*"t_welch": \([-0-9.]*\).*/\1/p')
    [ -z "$t" ] && t=nan
    case $op in
        *_ref|kem_temoin) attendu="fuite (témoin)"; ok=$(awk -v t="$t" 'BEGIN { print (t == t && (t > 4.5 || t < -4.5)) ? "true" : "false" }') ;;
        *) attendu="\|t\| < 4,5"; ok=$(awk -v t="$t" 'BEGIN { print (t == t && t < 4.5 && t > -4.5) ? "true" : "false" }') ;;
    esac
    # le témoin de 300 cycles n'est détectable qu'à partir de ≈ 200 000 mesures (t ≈ 6,8 à 300 000)
    if [ "$op" = permutation_ref ] || [ "$op" = kem_ct_public ] || { [ "$op" = kem_temoin ] && [ "$n" -lt 200000 ]; }; then     # indicatifs
        attendu="indicatif"; [ "$op" = kem_ct_public ] && { [ "$ok" = true ] && v="|t| < 4,5" || v="|t| ≥ 4,5"; }
        [ "$op" = kem_temoin ] && v="trop peu de mesures"
        [ "$op" = permutation_ref ] && { attendu="fuite (témoin indicatif)"; [ "$ok" = true ] && v="détectée" || v="non détectée"; }
        TAB="$TAB| $op | $n | $t | $attendu | $v |
"
        MT="$MT${MT:+,}
  \"$op\": {\"mesures\": $n, \"t_welch\": $t, \"duree_s\": $(( $(date +%s) - t0 ))}"
        journal "dudect $op : $n mesures, t = $t (indicatif)"
        continue
    fi
    # dépassement : une seconde mesure tranche (11 tests à |t| < 4,5 par nuit)
    t2=""
    case $op in *_ref|kem_temoin) ;; *)
        if [ "$ok" = false ] && [ "$est" -le "$(( $(reste) - MARGE ))" ]; then
            ligne=$($PIN tests/c/build/temps "$op" "$n" 2>>"$LOG")
            echo "$ligne" >> resultats/nuit/temps.jsonl
            t2=$(echo "$ligne" | sed -n 's/.*"t_welch": \([-0-9.]*\).*/\1/p')
            ok=$(awk -v t="$t2" 'BEGIN { print (t == t && t < 4.5 && t > -4.5) ? "true" : "false" }')
        fi ;;
    esac
    nomc=$(case $op in *_ref|kem_temoin) echo "temoin_${op}_fuite_detectee" ;; *) echo "${op}_sans_fuite_detectee" ;; esac)
    CT="$CT${CT:+,}
  \"$nomc\": $ok"
    MT="$MT${MT:+,}
  \"$op\": {\"mesures\": $n, \"t_welch\": $t${t2:+, \"t_seconde_mesure\": $t2}, \"duree_s\": $(( $(date +%s) - t0 ))}"
    TAB="$TAB| $op | $n | $t${t2:+ puis $t2} | $attendu | $([ "$ok" = true ] && echo OK || echo '**ÉCHEC**') |
"
    journal "dudect $op : $n mesures, t = $t${t2:+ puis $t2}"
done
printf '{\n "controles": {%s\n },\n "mesures": {%s\n }\n}\n' "$CT" "$MT" > resultats/nuit_temps.json
{
    echo "## Temps constant, mesures longues (nuit)"
    echo
    echo "Méthode dudect (tests/c/temps.c), seuil \|t\| < 4,5 ; un test statistique détecte des fuites, il ne prouve pas leur absence. Les plans KEM isolent le secret : le chiffré public n'y varie pas selon la classe (kem_ct_public montre l'effet de sa répétition)."
    echo
    echo "| Opération | Mesures | t de Welch | Attendu | Résultat |"; echo "|---|---|---|---|---|"
    printf '%s' "$TAB"
    echo
} > resultats/nuit_temps.md
etat nuit_temps OK
fi

# --- 3. KEM réel --------------------------------------------------------------
B=$(part 0.12); [ "$B" -gt "$(( $(reste) - MARGE ))" ] && B=$(( $(reste) - MARGE ))
if fait 3; then :
elif [ "$B" -gt 20 ]; then
    journal "3/6 KEM réel : $B s"
    lancer nuit_kem_reel "KEM réel" tests/c/build/nuit_kem_reel "$B"
else journal "3/6 KEM réel : non lancé (temps restant insuffisant)"; fi

# --- 4. ISD réel --------------------------------------------------------------
B=$(part 0.08); [ "$B" -gt "$(( $(reste) - MARGE ))" ] && B=$(( $(reste) - MARGE ))
if fait 4; then :
elif [ "$B" -gt 20 ]; then
    journal "4/6 ISD réel : $B s"
    lancer nuit_isd ISD tests/c/build/nuit_isd "$B"
else journal "4/6 ISD réel : non lancé (temps restant insuffisant)"; fi

# --- 5. BRUME et modèles de preuve --------------------------------------------
B=$(part 0.30); [ "$B" -gt "$(( $(reste) - MARGE ))" ] && B=$(( $(reste) - MARGE ))
if fait 5; then :
elif [ "$B" -gt 120 ]; then
    journal "5/6 BRUME et modèles de preuve : $B s"
    lancer nuit_brume BRUME python3 -m tests.nuit_brume "$B" $([ "$REPRISE" = 1 ] && echo --reprise)
else journal "5/6 BRUME : non lancé (temps restant insuffisant)"; fi

# --- 6. cryptanalyse à la frontière (tout le temps restant) -----------------
B=$(( $(reste) - MARGE / 2 ))
if [ "$B" -gt 20 ]; then
    journal "6/6 cryptanalyse à la frontière : $B s"
    lancer nuit_cryptanalyse cryptanalyse tests/c/build/nuit_cryptanalyse "$B"
else journal "6/6 cryptanalyse : non lancée (temps restant insuffisant)"; fi

# --- complément de reprise : le code modifié depuis le début de la campagne n'a pas vu ses campagnes déjà finies
if [ "$SRC_CHANGE" = 1 ] && [ "$(cat resultats/nuit/sources_complement.sha 2>/dev/null)" != "$SOURCES" ]; then
    journal "complément : dudect aead_p et fuzzing de 5 min sur le code actuel"
    etat nuit_complement ECHEC
    ligne=$($(command -v taskset >/dev/null 2>&1 && echo "taskset -c $((NPROC - 1))") tests/c/build/temps aead_p 300000 2>>"$LOG")
    t=$(echo "$ligne" | sed -n 's/.*"t_welch": \([-0-9.]*\).*/\1/p'); [ -z "$t" ] && t=nan
    okt=$(awk -v t="$t" 'BEGIN { print (t == t && t < 4.5 && t > -4.5) ? "true" : "false" }')
    FINF=$(( $(date +%s) + 300 )); ECH=0; LOTS=0
    for p in $(seq 1 "$NPROC"); do
        ( k=0; while [ "$(date +%s)" -lt "$FINF" ]; do
              OMP_NUM_THREADS=1 tests/c/build/fuzz_nuit 500 $((p * 7000003 + k)) 2 >/dev/null 2>&1 && echo ok || echo echec
              k=$((k + 1))
          done ) >"resultats/nuit/compl_$p.txt" &
    done
    wait
    LOTS=$(cat resultats/nuit/compl_*.txt | grep -c '^ok$'); ECH=$(cat resultats/nuit/compl_*.txt | grep -c '^echec$')
    rm -f resultats/nuit/compl_*.txt
    okf=$([ "$ECH" -eq 0 ] && [ "$LOTS" -gt 0 ] && echo true || echo false)
    printf '{\n "controles": {\n  "aead_p_sans_fuite_detectee": %s,\n  "fuzzing_code_actuel_sans_erreur": %s\n },\n "mesures": {"t_aead_p": %s, "lots": %s, "echecs": %s}\n}\n' \
        "$okt" "$okf" "$t" "$LOTS" "$ECH" > resultats/nuit_complement.json
    {
        echo "## Complément de reprise (code ajouté depuis le début de la campagne)"
        echo
        echo "| Contrôle | Résultat |"; echo "|---|---|"
        echo "| \`aead_p_sans_fuite_detectee\` (t = $t, 300 000 mesures) | $([ "$okt" = true ] && echo OK || echo '**ÉCHEC**') |"
        echo "| \`fuzzing_code_actuel_sans_erreur\` ($LOTS lots, $ECH en échec) | $([ "$okf" = true ] && echo OK || echo '**ÉCHEC**') |"
        echo
        echo "Dernière batterie : $(sed -n 3p resultats/SYNTHESE.md)"
        echo
    } > resultats/nuit_complement.md
    etat nuit_complement OK
    echo "$SOURCES" > resultats/nuit/sources_complement.sha
fi

synthese
python3 -m tests.empreintes >>"$LOG" 2>&1 || journal "empreintes : code de retour non nul"
journal "terminé"
