#!/bin/sh
# Campagne BRUME-512 identique pour une candidate S-box donnée.
# À placer dans prototypes/brume_sbox6/etudes/2_sbox_v3_comparaison_lourde/.
#
# Usage :
#   tester_sbox_compare.sh CANDIDATE [log2_quartets] [combinaisons] [seed] [taille_famille] [dossier_sortie]
#
# CANDIDATE : BRUME | SBOX6 | SBOX_V3
# Valeurs par défaut : 20 16 0xB00 3
#
# Le dépôt source n'est pas modifié : la table est remplacée dans une copie
# temporaire, puis les sources, journaux, JSON, CSV et empreintes sont archivés.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCRIPT_PATH="$SCRIPT_DIR/$(basename -- "$0")"
PROTO="$SCRIPT_DIR"
RACINE=$(CDPATH= cd -- "$PROTO/../../../.." && pwd)

CANDIDATE=${1:-SBOX_V3}
LQ=${2:-20}
NC=${3:-16}
SEED=${4:-0xB00}
FAMILY=${5:-3}
THREADS=${OMP_NUM_THREADS:-8}

usage() {
    echo "Usage: $0 BRUME|SBOX6|SBOX_V3 [log2_quartets] [combinaisons] [seed] [taille_famille] [dossier_sortie]" >&2
    exit 2
}

case "$CANDIDATE" in
    BRUME|SBOX6|SBOX_V3) ;;
    *) echo "Candidate inconnue : $CANDIDATE" >&2; usage ;;
esac

is_positive_int() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) [ "$1" -gt 0 ] ;;
    esac
}

is_positive_int "$LQ" || usage
is_positive_int "$NC" || usage
is_positive_int "$FAMILY" || usage
is_positive_int "$THREADS" || usage
[ "$LQ" -ge 1 ] && [ "$LQ" -le 60 ] || usage
[ "$NC" -le 1000000 ] || usage
[ "$FAMILY" -le 1000000 ] || usage

OUTDIR=${6:-"$PROTO/resultats/${CANDIDATE}_lq${LQ}_nc${NC}_seed${SEED}_family${FAMILY}"}

command -v python3 >/dev/null 2>&1 || { echo "python3 introuvable" >&2; exit 1; }
command -v make >/dev/null 2>&1 || { echo "make introuvable" >&2; exit 1; }

[ -f "$PROTO/sbox_v3.py" ] || { echo "Fichier introuvable : $PROTO/sbox_v3.py" >&2; exit 1; }
[ -f "$RACINE/tests/c/brume_attaques.c" ] || { echo "Sources C introuvables sous $RACINE/tests/c" >&2; exit 1; }
[ -f "$RACINE/sillage/c/brume512_tables.h" ] || { echo "Header introuvable : $RACINE/sillage/c/brume512_tables.h" >&2; exit 1; }

umask 077
mkdir -p "$(dirname -- "$OUTDIR")"
if [ -e "$OUTDIR" ]; then
    echo "Le dossier de sortie existe déjà : $OUTDIR" >&2
    echo "Choisis un autre dossier pour ne pas écraser une campagne antérieure." >&2
    exit 1
fi
mkdir -p "$OUTDIR"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/brume_sbox_compare.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM

# Archive les sources utilisées avant compilation.
cp "$PROTO/sbox_v3.py" "$OUTDIR/sbox_v3.py"
cp "$SCRIPT_PATH" "$OUTDIR/tester_sbox_compare.sh"
cp "$RACINE/tests/c/brume_attaques.c" "$OUTDIR/brume_attaques.c"
if [ -f "$RACINE/tests/c/Makefile" ]; then
    cp "$RACINE/tests/c/Makefile" "$OUTDIR/tests_c_Makefile"
fi
for header in brume_ref.h resultat.h; do
    if [ -f "$RACINE/tests/c/$header" ]; then
        cp "$RACINE/tests/c/$header" "$OUTDIR/$header"
    fi
done
if command -v cc >/dev/null 2>&1; then
    cc --version 2>/dev/null | sed -n '1p' > "$OUTDIR/compiler_version.txt" || true
fi

# Le validateur fourni calcule les propriétés des trois tables.
python3 "$PROTO/sbox_v3.py" > "$OUTDIR/sbox_v3_validation.log"

# Copie isolée du code nécessaire au build.
mkdir -p "$TMP/tests" "$TMP/sillage" "$TMP/resultats"
cp -R "$RACINE/tests/c" "$TMP/tests/c"
cp -R "$RACINE/sillage/c" "$TMP/sillage/c"
rm -rf "$TMP/tests/c/build"

# Remplacement contrôlé de BR_SBOX dans le header temporaire uniquement.
python3 - "$TMP/sillage/c/brume512_tables.h" "$CANDIDATE" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
candidate = sys.argv[2]
tables = {
    "BRUME":   [8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5],
    "SBOX6":   [15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1],
    "SBOX_V3": [14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2],
}

text = path.read_text(encoding="utf-8")
pattern = re.compile(
    r"(static\s+const\s+uint8_t\s+BR_SBOX\s*\[\s*16\s*\]\s*=\s*\{)(.*?)(\};)",
    re.S,
)
matches = list(pattern.finditer(text))
if len(matches) != 1:
    raise SystemExit(f"Attendu une seule déclaration BR_SBOX, trouvé : {len(matches)}")

m = matches[0]
current = [int(x) for x in re.findall(r"\d+", m.group(2))]
canonical = tables["BRUME"]
if current != canonical:
    raise SystemExit(
        "Remplacement refusé : le header source ne contient pas la table BRUME attendue. "
        f"Table trouvée : {current}"
    )

new_values = ", ".join(str(x) for x in tables[candidate])
replacement = m.group(1) + "\n    " + new_values + "\n" + m.group(3)
text = text[:m.start()] + replacement + text[m.end():]
path.write_text(text, encoding="utf-8")

check = pattern.search(path.read_text(encoding="utf-8"))
actual = [int(x) for x in re.findall(r"\d+", check.group(2))] if check else []
if actual != tables[candidate]:
    raise SystemExit(f"Échec de vérification de {candidate} : {actual}")
print(f"BR_SBOX sélectionnée : {candidate} = {tables[candidate]}")
PY

HEADER_NAME="brume512_tables_${CANDIDATE}.h"
cp "$TMP/sillage/c/brume512_tables.h" "$OUTDIR/$HEADER_NAME"

# Compilation identique pour les trois candidates.
if ! make -C "$TMP/tests/c" build/brume_attaques > "$OUTDIR/build.log" 2>&1; then
    echo "Échec de compilation. Voir $OUTDIR/build.log" >&2
    exit 1
fi

# Même graine, même nombre de quartets, mêmes combinaisons et même famille.
if ! (
    cd "$TMP"
    export OMP_NUM_THREADS="$THREADS"
    "$TMP/tests/c/build/brume_attaques" "$LQ" "$NC" "$SEED" "$FAMILY"
) > "$OUTDIR/run.stdout.log" 2> "$OUTDIR/run.stderr.log"; then
    echo "Échec du test C. Voir les journaux dans $OUTDIR" >&2
    exit 1
fi

[ -s "$TMP/resultats/brume_attaques.json" ] || {
    echo "Le binaire n'a pas produit resultats/brume_attaques.json" >&2
    exit 1
}
[ -s "$TMP/resultats/brume_attaques_boomerang_raw.csv" ] || {
    echo "Le binaire n'a pas produit le CSV brut boomerang" >&2
    exit 1
}

cp "$TMP/resultats/brume_attaques.json" "$OUTDIR/brume_attaques.json"
cp "$TMP/resultats/brume_attaques_boomerang_raw.csv" "$OUTDIR/brume_attaques_boomerang_raw.csv"

# Métadonnées et empreintes pour rendre la campagne vérifiable.
python3 - "$OUTDIR" "$LQ" "$NC" "$SEED" "$FAMILY" "$THREADS" "$RACINE" "$CANDIDATE" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import platform
import subprocess
import sys

out = Path(sys.argv[1])
lq, nc, seed, family, threads = sys.argv[2:7]
root = Path(sys.argv[7])
candidate = sys.argv[8]
header_name = f"brume512_tables_{candidate}.h"

tables = {
    "BRUME":   [8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5],
    "SBOX6":   [15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1],
    "SBOX_V3": [14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2],
}

files = [
    "sbox_v3.py", "tester_sbox_compare.sh", header_name,
    "brume_attaques.json", "brume_attaques_boomerang_raw.csv",
    "build.log", "run.stdout.log", "run.stderr.log",
    "sbox_v3_validation.log", "brume_attaques.c",
    "tests_c_Makefile", "brume_ref.h", "resultat.h", "compiler_version.txt",
]
checksums = {
    name: hashlib.sha256((out / name).read_bytes()).hexdigest()
    for name in files if (out / name).is_file()
}
try:
    git_commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        stderr=subprocess.DEVNULL, text=True
    ).strip()
except Exception:
    git_commit = None

metadata = {
    "protocol": "BRUME-SBOX-COMPARE v1",
    "git_commit": git_commit,
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "candidate": candidate,
    "sbox_table": tables[candidate],
    "log2_quartets_per_combination": int(lq),
    "combinations_per_round": int(nc),
    "seed_base": seed,
    "family_size_for_bonferroni": int(family),
    "omp_num_threads": int(threads),
    "platform": platform.platform(),
    "python_version": platform.python_version(),
    "artifacts_sha256": checksums,
    "interpretation": (
        "Reduced-round empirical campaign only; not a proof for the 32-round permutation."
    ),
}
(out / "campaign_metadata.json").write_text(
    json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY

printf '%s\n' "Campagne terminée : $CANDIDATE"
printf '%s\n' "Dossier : $OUTDIR"
printf '%s\n' "JSON : $OUTDIR/brume_attaques.json"
printf '%s\n' "CSV : $OUTDIR/brume_attaques_boomerang_raw.csv"
printf '%s\n' "Métadonnées : $OUTDIR/campaign_metadata.json"
printf '\n%s\n' "Résumé du binaire :"
cat "$OUTDIR/run.stdout.log"
