#!/bin/bash
# Raffine des feuilles (a, b) de cubes.sh par le poids de la couche 2 : feuille (a, b, c), c = 0..K (K : « ≥ K »).
# La feuille (a, b) est insatisfiable si ses K + 1 sous-feuilles le sont ET si la chaîne sur W_2 est complète
# (prouvé comme pour cubes.sh). Même vérification LRAT par sous-feuille.
#   sous_cubes.sh mode R K travaux "a1 b1" "a2 b2" …      (depuis la racine, après cubes.sh pour le même mode/R/K)
set -u
mode=$1; R=$2; K=$3; P=$4; shift 4
D=$HOME/orion_sat/${PREFIXE:-cubes}_${mode}_R${R}_K$K
BASE=$D/base.cnf
U=$BASE.unaires
uv() { awk -v t="$1" -v k="$2" '$1 == t && $2 == k { print $3 }' "$U"; }
nv=$(awk '/^p cnf/ { print $3 }' "$BASE")
SC=$D/sous_cubes.txt
: > "$SC"
for ab in "$@"; do
    set -- $ab
    a=$1; b=$2
    base_l=$(grep "^$a $b " "$D/cubes.txt" | cut -d' ' -f3-)
    : > "$D/chaine_${a}_$b.txt"
    for c in $(seq 0 "$K"); do
        l=""
        for k in $(seq 1 "$c"); do l="$l $(uv 2 "$k")"; done
        [ "$c" -lt "$K" ] && l="$l -$(uv 2 $((c + 1)))"
        echo "$l" >> "$D/chaine_${a}_$b.txt"
        echo "${a}_${b}_$c $base_l$l" >> "$SC"
    done
    # complétude de la chaîne sur W_2 (indépendante de (a, b))
    {
        echo "p cnf $nv $((K + 1))"
        awk '{ s = ""; for (i = 1; i <= NF; i++) s = s (-$i) " "; print s "0" }' "$D/chaine_${a}_$b.txt"
    } > "$D/chaine_${a}_$b.cnf"
    cadical -q --lrat=true --binary=false "$D/chaine_${a}_$b.cnf" "$D/chaine_${a}_$b.lrat" > /dev/null
    echo "chaine ($a, $b) : rc=$? ; $("$D/lrat_verif" "$D/chaine_${a}_$b.cnf" "$D/chaine_${a}_$b.lrat" | tail -1) ; lrat-check $("$D/lrat_check2" "$D/chaine_${a}_$b.cnf" "$D/chaine_${a}_$b.lrat" 2>&1 | grep -c '^c VERIFIED')" | tee -a "$D/sous_completude.txt"
done
sfeuille() {
    local id=$1; shift
    local f=$D/s_$id
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
    local v="SATISFIABLE_OU_ERREUR"
    if [ $rc -eq 20 ]; then
        v=$("$D/lrat_verif" "$f.cnf" "$f.lrat" | tr '\n' ' ')
        if "$D/lrat_check2" "$f.cnf" "$f.lrat" 2>&1 | grep -q '^c VERIFIED'; then v="$v ; lrat-check VERIFIED"; else v="$v ; lrat-check ECHEC"; fi
    fi
    echo "$id rc=$rc $((SECONDS - t0))s $(du -k "$f.lrat" | cut -f1)ko $v" > "$f.res"
    rm -f "$f.cnf" "$f.lrat"
    [ $rc -eq 20 ] && rm -f "$f.out"
}
export -f sfeuille
export D BASE nv
xargs -P "$P" -L 1 bash -c 'sfeuille "$@"' _ < "$SC"
cat "$D"/s_*.res > "$D/sous_resultats.txt"
echo "sous-feuilles verifiees : $(grep -c 'rc=20 .*lrat_verif VERIFIEE.*lrat-check VERIFIED' "$D/sous_resultats.txt") / $(wc -l < "$SC")"
