#!/usr/bin/env bash
# Reprend la campagne de nuit là où une coupure l'a arrêtée.
#
#   ./reprendre_nuit.sh [heures]   (défaut : le temps qu'il restait à la campagne d'origine)
#
# Les campagnes finies (lues dans resultats/nuit/journal.log) ne sont pas rejouées. La campagne interrompue
# repart de son début, sauf BRUME, qui repart de l'étape interrompue. Peut être relancé après une nouvelle coupure.
export SILLAGE_REPRISE=1
exec "$(dirname "$(readlink -f "$0")")/rundenuit.sh" "$@"
