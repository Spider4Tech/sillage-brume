#!/bin/sh
# Campagne boomerang réduite pour SBOX_V3.
#
# Usage :
#   tester_sbox_v3_attaques.sh [log2_quartets] [combinaisons] [seed] [taille_famille] [dossier_sortie]
#
# Exemple :
#   OMP_NUM_THREADS=8 ./tester_sbox_v3_attaques.sh 20 16 0xB00 3
#
# Le dépôt source n'est pas modifié : les sources nécessaires sont copiées dans
# un répertoire temporaire. Les journaux, le JSON C et le CSV brut sont copiés
# dans le dossier de sortie pour rendre la campagne auditable.
set -eu

RACINE=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PROTO=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LQ=${1:-20}
NC=${2:-16}
SEED=${3:-0xB00}
FAMILY=${4:-3}
OUTDIR=${5:-"$PROTO/resultats/sbox_v3_lq${LQ}_nc${NC}_seed${SEED}_family${FAMILY}"}
THREADS=${OMP_NUM_THREADS:-8}

usage() {
    echo "Usage: $0 [log2_quartets] [combinaisons] [seed] [taille_famille] [dossier_sortie]" >&2
    exit 2
}

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

command -v python3 >/dev/null 2>&1 || { echo "python3 introuvable" >&2; exit 1; }
command -v make >/dev/null 2>&1 || { echo "make introuvable" >&2; exit 1; }

umask 077
mkdir -p "$(dirname -- "$OUTDIR")"
if [ -e "$OUTDIR" ]; then
    echo "Le dossier de sortie existe déjà : $OUTDIR" >&2
    echo "Choisis un autre chemin pour ne pas écraser une campagne antérieure." >&2
    exit 1
fi
mkdir -p "$OUTDIR"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/brume_sbox_v3.XXXXXX")
cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

# Archive les sources utilisées avant compilation.
cp "$PROTO/sbox_v3.py" "$OUTDIR/sbox_v3.py"
cp "$PROTO/tester_sbox_v3_attaques.sh" "$OUTDIR/tester_sbox_v3_attaques.sh"
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

# Vérification Python de la candidate.
python3 "$PROTO/sbox_v3.py" > "$OUTDIR/sbox_v3_validation.log"

# Copie isolée des seuls sous-arbres nécessaires au build.
mkdir -p "$TMP/tests" "$TMP/sillage" "$TMP/resultats"
cp -R "$RACINE/tests/c" "$TMP/tests/c"
cp -R "$RACINE/sillage/c" "$TMP/sillage/c"
rm -rf "$TMP/tests/c/build"

# Remplacement exact et contrôlé de la ligne de BR_SBOX dans la copie.
python3 - "$TMP/sillage/c/brume512_tables.h" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = "    8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5"
new = "    14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2"
count = text.count(old)
if count != 1:
    raise SystemExit(
        f"Remplacement refusé : la ligne BR_SBOX attendue apparaît {count} fois dans {path}"
    )
path.write_text(text.replace(old, new, 1), encoding="utf-8")
if new not in path.read_text(encoding="utf-8"):
    raise SystemExit("Échec de vérification de la table SBOX_V3 dans le header temporaire")
PY

cp "$TMP/sillage/c/brume512_tables.h" "$OUTDIR/brume512_tables_sbox_v3.h"

# Build reproductible : conserver la sortie de compilation et le code retour.
if ! make -C "$TMP/tests/c" build/brume_attaques > "$OUTDIR/build.log" 2>&1; then
    echo "Échec de compilation. Voir $OUTDIR/build.log" >&2
    exit 1
fi

# Exécution : les arguments sont transmis au binaire C.
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

# Métadonnées et empreintes des artefacts.
python3 - "$OUTDIR" "$LQ" "$NC" "$SEED" "$FAMILY" "$THREADS" "$RACINE" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import platform
import sys

out = Path(sys.argv[1])
lq, nc, seed, family, threads = sys.argv[2:7]
files = [
    "sbox_v3.py",
    "brume512_tables_sbox_v3.h",
    "brume_attaques.json",
    "brume_attaques_boomerang_raw.csv",
    "build.log",
    "run.stdout.log",
    "run.stderr.log",
    "sbox_v3_validation.log",
    "brume_attaques.c",
    "tests_c_Makefile",
    "brume_ref.h",
    "resultat.h",
    "compiler_version.txt",
]
checksums = {}
for name in files:
    path = out / name
    if path.is_file():
        checksums[name] = hashlib.sha256(path.read_bytes()).hexdigest()

try:
    import subprocess
    root = Path(sys.argv[7])
    git_commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        stderr=subprocess.DEVNULL, text=True
    ).strip()
except Exception:
    git_commit = None

metadata = {
    "protocol": "BRUME-SBOX-SEARCH v3-corrige",
    "git_commit": git_commit,
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "candidate": "SBOX_V3",
    "log2_quartets_per_combination": int(lq),
    "combinations_per_round": int(nc),
    "seed_base": seed,
    "family_size_for_bonferroni": int(family),
    "omp_num_threads": int(threads),
    "platform": platform.platform(),
    "python_version": platform.python_version(),
    "artifacts_sha256": checksums,
    "interpretation": (
        "Reduced-round empirical distinguisher campaign only; not a proof "
        "for the 32-round permutation."
    ),
}
(out / "campaign_metadata.json").write_text(
    json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY

printf '%s\n' "Campagne terminée : $OUTDIR"
printf '%s\n' "JSON C : $OUTDIR/brume_attaques.json"
printf '%s\n' "CSV brut : $OUTDIR/brume_attaques_boomerang_raw.csv"
printf '%s\n' "Métadonnées : $OUTDIR/campaign_metadata.json"
printf '\n%s\n' "Résumé du binaire :"
cat "$OUTDIR/run.stdout.log"
