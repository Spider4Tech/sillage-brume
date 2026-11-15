#!/bin/bash
# Unité de la campagne C4 ≥ 28, phase 3 (BRUME-1024, 4 tours) : morceau numéro HC_UNIT_INDEX de cubes_phase3.txt.
# Chaque sous-feuille (a, b, c) restée LIMITE en phase 2 (1 h) est redécoupée par le poids de la couche 3 : morceau
# (a, b, c, d), d = 0..28 (28 : « ≥ 28 »). La sous-feuille (a, b, c) est prouvée si ses 29 morceaux le sont ET si la
# chaîne sur W_3 est complète (completude_W3.sh, prouvé une fois pour toutes). CaDiCaL 1.7.3 produit une preuve LRAT,
# vérifiée par DEUX vérificateurs indépendants (lrat_verif du dépôt, lrat-check de drat-trim), puis effacée.
# Codes : 0 = prouvé et vérifié deux fois, ou LIMITE (2 h) ; 99 = SATISFIABLE (la borne K = 28 tombe pour cette
# relaxation : la campagne s'arrête) ; 3 = erreur ou vérification en échec ; 4 = disque.
set -u
ICI=$(cd "$(dirname "$0")" && pwd); W=$PWD; mkdir -p out
line=$(sed -n "$((HC_UNIT_INDEX + 1))p" "$ICI/cubes_phase3.txt"); set -- $line; a=$1 b=$2 c=$3 d=$4; shift 4
id="${a}_${b}_${c}_$d"
cc -O2 -o "$W/lv" "$ICI/lrat_verif.c" 2>/dev/null && cc -O2 -std=gnu99 -DLONGTYPE -o "$W/lc" "$ICI/lrat-check.c" 2>/dev/null \
  || { echo "$a $b $c $d compilation des vérificateurs impossible" | tee "out/morceau_$id.res"; exit 3; }
cp "$ICI/cadical" "$W/cadical" && chmod +x "$W/cadical"
# En phase 2, une preuve d'une heure pesait 10 à 14 Go : ne pas démarrer sous 60 Go libres (l'unité échoue, reprise).
libre=$(df -Pk "$W" | awk 'NR==2 {print int($4/1048576)}')
[ "$libre" -lt 60 ] && { echo "$a $b $c $d disque presque plein (${libre} Go libres) sur $(hostname)" | tee "out/morceau_$id.res"; exit 4; }
nv=$(awk '/^p cnf/ {print $3}' "$ICI/base.cnf"); nc=$(awk '/^p cnf/ {print $4}' "$ICI/base.cnf")
{ echo "p cnf $nv $((nc + $#))"; grep -v '^[cp]' "$ICI/base.cnf"; for l in "$@"; do echo "$l 0"; done; } > "$W/f.cnf"
t0=$SECONDS
timeout 7200 "$W/cadical" -q --lrat=true --binary=false "$W/f.cnf" "$W/f.lrat" > "$W/f.out"; rc=$?
if [ $rc -eq 20 ]; then
  v=$("$W/lv" "$W/f.cnf" "$W/f.lrat" | tr '\n' ' ')
  if "$W/lc" "$W/f.cnf" "$W/f.lrat" 2>&1 | grep -q '^c VERIFIED'; then v="$v ; lrat-check VERIFIED"; else v="$v ; lrat-check ECHEC"; fi
elif [ $rc -eq 10 ]; then
  v="SATISFIABLE (borne fausse pour ce morceau : modèle dans out/)"; cp "$W/f.out" "out/modele_$id.txt"
elif [ $rc -eq 124 ]; then
  v="LIMITE (2 h) : à redécouper"
else
  v="ERREUR du solveur"
fi
echo "$a $b $c $d rc=$rc $((SECONDS - t0))s $(du -k "$W/f.lrat" 2>/dev/null | cut -f1)ko $(hostname) $v" | tee "out/morceau_$id.res"
rm -f "$W/f.cnf" "$W/f.lrat" "$W/f.out"
case "$v" in *"VERIFIEE"*"lrat-check VERIFIED"*|LIMITE*) exit 0 ;; SATISFIABLE*) exit 99 ;; *) exit 3 ;; esac
