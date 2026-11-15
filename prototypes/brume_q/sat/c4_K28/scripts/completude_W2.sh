#!/bin/bash
# Complétude de la chaîne sur W_2 de la phase 2 : la CNF « ∧ ¬sous-cube_c » (c = 0..28, littéraux de W_2 seuls) doit être
# insatisfiable, preuve LRAT vérifiée par les deux vérificateurs. Indépendante de (a, b) : vaut pour les 10 feuilles.
set -u
ICI=$(cd "$(dirname "$0")" && pwd); W=$PWD; mkdir -p out
cc -O2 -o "$W/lv" "$ICI/lrat_verif.c" && cc -O2 -std=gnu99 -DLONGTYPE -o "$W/lc" "$ICI/lrat-check.c" || exit 3
cp "$ICI/cadical" "$W/cadical" && chmod +x "$W/cadical"
"$W/cadical" -q --lrat=true --binary=false "$ICI/completude_W2.cnf" "$W/c.lrat" > /dev/null; rc=$?
v="completude W2 : cadical rc=$rc ; $("$W/lv" "$ICI/completude_W2.cnf" "$W/c.lrat" | tail -1) ; lrat-check $("$W/lc" "$ICI/completude_W2.cnf" "$W/c.lrat" 2>&1 | grep -c '^c VERIFIED') ; $(hostname)"
echo "$v" | tee out/completude_W2.txt
case "$v" in *"rc=20 ; "*VERIFIEE*"lrat-check 1 "*) exit 0 ;; *) exit 3 ;; esac
