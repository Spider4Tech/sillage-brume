#!/bin/bash
# Unité de la campagne C4 ≥ 28, phase 2 (BRUME-1024, 4 tours) : sous-feuille numéro HC_UNIT_INDEX de sous_cubes.txt.
# Chaque feuille (a, b) restée LIMITE en phase 1 est redécoupée par le poids de la couche 2 : sous-feuille (a, b, c),
# c = 0..28 (28 : « ≥ 28 »), comme prototypes/brume_q/sat/sous_cubes.sh. La feuille (a, b) est prouvée si ses 29
# sous-feuilles le sont ET si la chaîne sur W_2 est complète (completude_W2.sh, prouvé une fois pour toutes).
# CaDiCaL 1.7.3 produit une preuve LRAT, vérifiée par DEUX vérificateurs indépendants (lrat_verif du dépôt, lrat-check
# de drat-trim), puis effacée. Résultat : une ligne dans out/sousfeuille_A_B_C.res et sur la sortie.
# Codes : 0 = prouvée et vérifiée deux fois, ou LIMITE (1 h, à redécouper en phase 3) ; 99 = SATISFIABLE (la borne
# K = 28 tombe pour cette relaxation : la campagne s'arrête) ; 3 = erreur ou vérification en échec ; 4 = disque.
set -u
ICI=$(cd "$(dirname "$0")" && pwd); W=$PWD; mkdir -p out
line=$(sed -n "$((HC_UNIT_INDEX + 1))p" "$ICI/sous_cubes.txt"); set -- $line; a=$1 b=$2 c=$3; shift 3
id="${a}_${b}_$c"
cc -O2 -o "$W/lv" "$ICI/lrat_verif.c" 2>/dev/null && cc -O2 -std=gnu99 -DLONGTYPE -o "$W/lc" "$ICI/lrat-check.c" 2>/dev/null \
  || { echo "$a $b $c compilation des vérificateurs impossible" | tee "out/sousfeuille_$id.res"; exit 3; }
cp "$ICI/cadical" "$W/cadical" && chmod +x "$W/cadical"
# Une preuve LRAT d'une heure peut peser une dizaine de Go : ne pas démarrer sous 30 Go libres (l'unité échoue, reprise).
libre=$(df -Pk "$W" | awk 'NR==2 {print int($4/1048576)}')
[ "$libre" -lt 30 ] && { echo "$a $b $c disque presque plein (${libre} Go libres) sur $(hostname)" | tee "out/sousfeuille_$id.res"; exit 4; }
nv=$(awk '/^p cnf/ {print $3}' "$ICI/base.cnf"); nc=$(awk '/^p cnf/ {print $4}' "$ICI/base.cnf")
{ echo "p cnf $nv $((nc + $#))"; grep -v '^[cp]' "$ICI/base.cnf"; for l in "$@"; do echo "$l 0"; done; } > "$W/f.cnf"
t0=$SECONDS
timeout 3600 "$W/cadical" -q --lrat=true --binary=false "$W/f.cnf" "$W/f.lrat" > "$W/f.out"; rc=$?
if [ $rc -eq 20 ]; then
  v=$("$W/lv" "$W/f.cnf" "$W/f.lrat" | tr '\n' ' ')
  if "$W/lc" "$W/f.cnf" "$W/f.lrat" 2>&1 | grep -q '^c VERIFIED'; then v="$v ; lrat-check VERIFIED"; else v="$v ; lrat-check ECHEC"; fi
elif [ $rc -eq 10 ]; then
  v="SATISFIABLE (borne fausse pour cette sous-feuille : modèle dans out/)"; cp "$W/f.out" "out/modele_$id.txt"
elif [ $rc -eq 124 ]; then
  v="LIMITE (1 h) : à redécouper en phase 3"
else
  v="ERREUR du solveur"
fi
echo "$a $b $c rc=$rc $((SECONDS - t0))s $(du -k "$W/f.lrat" 2>/dev/null | cut -f1)ko $(hostname) $v" | tee "out/sousfeuille_$id.res"
rm -f "$W/f.cnf" "$W/f.lrat" "$W/f.out"
case "$v" in *"VERIFIEE"*"lrat-check VERIFIED"*|LIMITE*) exit 0 ;; SATISFIABLE*) exit 99 ;; *) exit 3 ;; esac
