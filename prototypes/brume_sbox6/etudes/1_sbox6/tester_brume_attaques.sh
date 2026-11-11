#!/bin/sh
# Prototype : teste la S-box à BCT max 6 dans le test boomerang réduit de BRUME.
#
# Le script ne touche pas au dépôt : il copie tests/c et sillage/c dans un
# répertoire temporaire, remplace la table BR_SBOX par SBOX6, compile
# brume_attaques et l'exécute. Usage :
#
#   prototypes/brume_sbox6/etudes/1_sbox6/tester_brume_attaques.sh [log2_quartets] [combinaisons]
#
# Défauts : 20 16 (environ une minute sur 8 cœurs). Le résultat 3 tours est à
# comparer au seuil de Bonferroni affiché dans le JSON.
set -eu

RACINE=$(CDPATH= cd -- "$(dirname -- "$0")/../../../.. && pwd)
LQ=${1:-20}
NC=${2:-16}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/brume_sbox6.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

echo "== Propriétés de la S-box =="
python3 "$RACINE/prototypes/brume_sbox6/etudes/1_sbox6/sbox6.py"

echo
echo "== Test C réduit (copie temporaire, S-box remplacée) =="
mkdir -p "$TMP/tests" "$TMP/sillage"
cp -r "$RACINE/tests/c" "$TMP/tests/c"
cp -r "$RACINE/sillage/c" "$TMP/sillage/c"
rm -rf "$TMP/tests/c/build"

python3 - "$TMP/sillage/c/brume512_tables.h" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "    8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5"
new = "    15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1"
if old not in s:
    sys.exit("ligne BR_SBOX introuvable dans " + p)
open(p, "w").write(s.replace(old, new, 1))
PY

make -C "$TMP/tests/c" build/brume_attaques >/dev/null
mkdir -p "$TMP/resultats"
cd "$TMP"
"$TMP/tests/c/build/brume_attaques" "$LQ" "$NC"

python3 - "$TMP/resultats/brume_attaques.json" <<'PY'
import json
import sys

d = json.load(open(sys.argv[1]))
print()
print("S-box     :", json.dumps(d["mesures"]["sbox"]))
print("Boomerang :", json.dumps(d["mesures"]["boomerang"]))
for r in d["mesures"]["boomerang_par_tours"]:
    print("  %d tour(s) : z_max = %.1f, retours exacts = %d"
          % (r["tours"], r["z_max"], r["retours_exacts"]))
PY
