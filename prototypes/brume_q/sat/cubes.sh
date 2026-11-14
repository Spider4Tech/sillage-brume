#!/bin/bash
# Cube-and-conquer sur la CNF de c3_cnf, avec une preuve LRAT vérifiée par cube.
#   cubes.sh mode R K travaux [repertoire]
# Les cubes forment un arbre de décision complet sur les compteurs unaires des couches 0 et 1 :
#   feuille (a, b) : W_0 ≥ 1..a vrais et W_0 ≥ a+1 faux (a < K), de même pour b sur W_1.
# Chaque feuille est prouvée insatisfiable par CaDiCaL (--lrat), et la preuve est vérifiée par lrat_verif
# puis effacée. La complétude des cubes (leur disjonction est une tautologie) est elle-même prouvée de la
# même façon : la CNF « ¬cube_1 ∧ … ∧ ¬cube_n » doit être insatisfiable.
# Il faut cadical (≥ 1.7) et un cc dans le PATH ; à lancer depuis la racine du dépôt.
# Variables : C3BIN (générateur, défaut tests/c/build/c3_cnf ; c3_cnf1024 pour BRUME-1024), PREFIXE (défaut cubes),
# DRAT_TRIM (répertoire des sources de drat-trim : lrat-check y est compilé et sert de SECOND vérificateur, obligatoire).
set -u
mode=$1; R=$2; K=$3; P=$4
C3BIN=${C3BIN:-tests/c/build/c3_cnf}
D=${5:-$HOME/orion_sat}/${PREFIXE:-cubes}_${mode}_R${R}_K$K
mkdir -p "$D"
RACINE=$(pwd)
cc -O2 -o "$D/lrat_verif" prototypes/brume_q/sat/lrat_verif.c || exit 2
cc -O2 -std=gnu99 -DLONGTYPE -o "$D/lrat_check2" "${DRAT_TRIM:-$HOME/outils/drat-trim}/lrat-check.c" || exit 2
BASE=$D/base.cnf
if [ ! -f "$BASE" ]; then
    "$C3BIN" cnf "$mode" "$R" "$K" "$BASE" > "$D/generation.txt" || exit 2
fi
U=$BASE.unaires
uv() { awk -v t="$1" -v k="$2" '$1 == t && $2 == k { print $3 }' "$U"; }
# cubes : une ligne de littéraux par feuille
CUBES=$D/cubes.txt
: > "$CUBES"
for a in $(seq 0 "$K"); do
    for b in $(seq 0 "$K"); do
        l=""
        for k in $(seq 1 "$a"); do l="$l $(uv 0 "$k")"; done
        [ "$a" -lt "$K" ] && l="$l -$(uv 0 $((a + 1)))"
        for k in $(seq 1 "$b"); do l="$l $(uv 1 "$k")"; done
        [ "$b" -lt "$K" ] && l="$l -$(uv 1 $((b + 1)))"
        echo "$a $b$l" >> "$CUBES"
    done
done
# complétude : ∧ ¬cube insatisfiable
nv=$(awk '/^p cnf/ { print $3 }' "$BASE")
{
    echo "p cnf $nv $(wc -l < "$CUBES")"
    awk '{ s = ""; for (i = 3; i <= NF; i++) s = s (-$i) " "; print s "0" }' "$CUBES"
} > "$D/completude.cnf"
cadical -q --lrat=true --binary=false "$D/completude.cnf" "$D/completude.lrat" > "$D/completude.out"
echo "completude: cadical rc=$? ; $("$D/lrat_verif" "$D/completude.cnf" "$D/completude.lrat" | tail -1) ; lrat-check $("$D/lrat_check2" "$D/completude.cnf" "$D/completude.lrat" 2>&1 | grep -c '^c VERIFIED')" > "$D/completude.txt"
cat "$D/completude.txt"
feuille() {
    local a=$1 b=$2; shift 2
    local f=$D/f_${a}_$b
    [ -f "$f.res" ] && return
    local nc
    nc=$(awk '/^p cnf/ { print $4 }' "$BASE")
    {
        echo "p cnf $nv $((nc + $#))"
        grep -v '^[cp]' "$BASE"
        for l in "$@"; do echo "$l 0"; done
    } > "$f.cnf"
    local t0=$SECONDS
    cadical -q --lrat=true --binary=false "$f.cnf" "$f.lrat" > "$f.out"
    local rc=$?
    local v
    if [ $rc -eq 20 ]; then
        v=$("$D/lrat_verif" "$f.cnf" "$f.lrat" | tr '\n' ' ')
        if "$D/lrat_check2" "$f.cnf" "$f.lrat" 2>&1 | grep -q '^c VERIFIED'; then v="$v ; lrat-check VERIFIED"; else v="$v ; lrat-check ECHEC"; fi
    else
        v="SATISFIABLE_OU_ERREUR"
    fi
    echo "$a $b rc=$rc $((SECONDS - t0))s $(du -k "$f.lrat" | cut -f1)ko $v" > "$f.res"
    rm -f "$f.cnf" "$f.lrat"
    [ $rc -eq 20 ] && rm -f "$f.out"
}
export -f feuille
export D BASE nv
nv=$nv xargs -P "$P" -L 1 bash -c 'feuille "$@"' _ < "$CUBES"
cat "$D"/f_*.res > "$D/resultats.txt"
ok=$(grep -c "rc=20 .*lrat_verif VERIFIEE.*lrat-check VERIFIED" "$D/resultats.txt")
tot=$(wc -l < "$CUBES")
echo "feuilles verifiees : $ok / $tot"
grep -v "lrat-check VERIFIED" "$D/resultats.txt" | head
