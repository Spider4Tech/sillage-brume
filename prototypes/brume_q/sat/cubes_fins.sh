#!/bin/bash
# Découpage fin d'un cube parent : toutes les 2^k affectations de k variables (arbre de décision complet), chaque
# feuille prouvée par CaDiCaL (LRAT) et vérifiée par lrat_verif ET lrat-check ; complétude prouvée de même.
#   cubes_fins.sh base.cnf repertoire "littéraux du cube parent" "v1 v2 … vk" travaux [part nparts]
# part / nparts : ne traite que les feuilles d'indice ≡ part (mod nparts) (répartition sur plusieurs machines ; la
# complétude est prouvée par chaque partie).
set -u
BASE=$1; D=$2; PARENT=$3; VARS=($4); P=$5; PART=${6:-0}; NPARTS=${7:-1}
mkdir -p "$D"
RACINE=$(pwd)
cc -O2 -o "$D/lrat_verif" prototypes/brume_q/sat/lrat_verif.c || exit 2
cc -O2 -std=gnu99 -DLONGTYPE -o "$D/lrat_check2" "${DRAT_TRIM:-$HOME/outils/drat-trim}/lrat-check.c" 2> /dev/null || exit 2
k=${#VARS[@]}
nv=$(awk '/^p cnf/ { print $3 }' "$BASE")
nc=$(awk '/^p cnf/ { print $4 }' "$BASE")
grep -v '^[cp]' "$BASE" > "$D/corps.cnf"
: > "$D/cubes.txt"
for ((m = 0; m < (1 << k); m++)); do
    l=""
    for ((b = 0; b < k; b++)); do
        if (( (m >> b) & 1 )); then l="$l ${VARS[b]}"; else l="$l -${VARS[b]}"; fi
    done
    echo "$m$l" >> "$D/cubes.txt"
done
{
    echo "p cnf $nv $((1 << k))"
    awk '{ s = ""; for (i = 2; i <= NF; i++) s = s (-$i) " "; print s "0" }' "$D/cubes.txt"
} > "$D/completude.cnf"
cadical -q --lrat=true --binary=false "$D/completude.cnf" "$D/completude.lrat" > /dev/null
echo "completude ($k variables, $((1 << k)) cubes): rc=$? ; $("$D/lrat_verif" "$D/completude.cnf" "$D/completude.lrat" | tail -1) ; lrat-check $("$D/lrat_check2" "$D/completude.cnf" "$D/completude.lrat" 2>&1 | grep -c '^c VERIFIED')" | tee "$D/completude.txt"
fine() {
    local id=$1; shift
    local f=$D/g_$id
    [ -f "$f.res" ] && return
    {
        echo "p cnf $nv $((nc + $# + $(echo $PARENT | wc -w)))"
        cat "$D/corps.cnf"
        for l in $PARENT "$@"; do echo "$l 0"; done
    } > "$f.cnf"
    local t0=$SECONDS
    cadical -q --lrat=true --binary=false "$f.cnf" "$f.lrat" > "$f.out"
    local rc=$?
    local v="SATISFIABLE_OU_ERREUR"
    if [ $rc -eq 20 ]; then
        v=$("$D/lrat_verif" "$f.cnf" "$f.lrat" | tr '\n' ' ')
        if "$D/lrat_check2" "$f.cnf" "$f.lrat" 2>&1 | grep -q '^c VERIFIED'; then v="$v ; lrat-check VERIFIED"; else v="$v ; lrat-check ECHEC"; fi
    fi
    echo "$id rc=$rc $((SECONDS - t0))s $(du -k "$f.lrat" | cut -f1)ko $v" > "$f.res"
    rm -f "$f.cnf" "$f.lrat"
    [ $rc -eq 20 ] && rm -f "$f.out"
}
export -f fine
export D nv nc PARENT
awk -v p="$PART" -v n="$NPARTS" '$1 % n == p' "$D/cubes.txt" | xargs -P "$P" -L 1 bash -c 'fine "$@"' _
echo "feuilles fines verifiees (partie $PART/$NPARTS) : $(grep -l 'VERIFIEE.*lrat-check VERIFIED' "$D"/g_*.res 2>/dev/null | wc -l)"
