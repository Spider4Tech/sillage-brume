#!/bin/bash
# Unité de la campagne C4 ≥ 28, phase 1 (BRUME-1024, 4 tours) : feuille numéro HC_UNIT_INDEX de cubes.txt (arbre complet sur
# les compteurs des couches 0 et 1, comme prototypes/brume_q/sat/cubes.sh). CaDiCaL 1.7.3 produit une preuve LRAT,
# vérifiée par DEUX vérificateurs indépendants (lrat_verif du dépôt, lrat-check de drat-trim), puis effacée.
# Résultat : une ligne dans out/feuille_A_B.res et sur la sortie, au format de cubes.sh.
set -u
ICI=$(cd "$(dirname "$0")" && pwd); W=$PWD; mkdir -p out
line=$(sed -n "$((HC_UNIT_INDEX + 1))p" "$ICI/cubes.txt"); set -- $line; a=$1 b=$2; shift 2
cc -O2 -o "$W/lv" "$ICI/lrat_verif.c" 2>/dev/null && cc -O2 -std=gnu99 -DLONGTYPE -o "$W/lc" "$ICI/lrat-check.c" 2>/dev/null \
  || { echo "$a $b compilation des vérificateurs impossible" | tee "out/feuille_${a}_$b.res"; exit 3; }
cp "$ICI/cadical" "$W/cadical" && chmod +x "$W/cadical"
# Une preuve LRAT pèse plusieurs Go : ne pas démarrer sous 15 Go libres (l'unité échoue et sera reprise).
libre=$(df -Pk "$W" | awk 'NR==2 {print int($4/1048576)}')
[ "$libre" -lt 15 ] && { echo "$a $b disque presque plein (${libre} Go libres) sur $(hostname)" | tee "out/feuille_${a}_$b.res"; exit 4; }
nv=$(awk '/^p cnf/ {print $3}' "$ICI/base.cnf"); nc=$(awk '/^p cnf/ {print $4}' "$ICI/base.cnf")
{ echo "p cnf $nv $((nc + $#))"; grep -v '^[cp]' "$ICI/base.cnf"; for l in "$@"; do echo "$l 0"; done; } > "$W/f.cnf"
t0=$SECONDS
# Phase 1 : 20 min au plus par feuille ; une feuille plus dure est marquée LIMITE et sera redécoupée (phase 2).
timeout 1200 "$W/cadical" -q --lrat=true --binary=false "$W/f.cnf" "$W/f.lrat" > "$W/f.out"; rc=$?
if [ $rc -eq 20 ]; then
  v=$("$W/lv" "$W/f.cnf" "$W/f.lrat" | tr '\n' ' ')
  if "$W/lc" "$W/f.cnf" "$W/f.lrat" 2>&1 | grep -q '^c VERIFIED'; then v="$v ; lrat-check VERIFIED"; else v="$v ; lrat-check ECHEC"; fi
elif [ $rc -eq 10 ]; then
  v="SATISFIABLE (borne fausse pour cette feuille : modèle dans out/)"; cp "$W/f.out" "out/modele_${a}_$b.txt"
elif [ $rc -eq 124 ]; then
  v="LIMITE (20 min) : à redécouper en sous-cubes"
else
  v="ERREUR du solveur"
fi
echo "$a $b rc=$rc $((SECONDS - t0))s $(du -k "$W/f.lrat" 2>/dev/null | cut -f1)ko $(hostname) $v" | tee "out/feuille_${a}_$b.res"
rm -f "$W/f.cnf" "$W/f.lrat" "$W/f.out"
# Échec visible (unité en échec, notification) si la feuille n'est pas prouvée et vérifiée deux fois.
case "$v" in *"VERIFIEE"*"lrat-check VERIFIED"*|LIMITE*) exit 0 ;; *) exit 3 ;; esac
