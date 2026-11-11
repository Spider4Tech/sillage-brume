#!/bin/sh
# Lance cinq campagnes ChaCha20 reproductibles. Chaque quartet est partagé
# entre BRUME, SBOX6 et SBOX_V3 pour permettre des comparaisons appariées.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

LQ=${1:-18}
NC=${2:-32}
ROUNDS=${3:-8}
THREADS=${4:-8}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUTDIR=${5:-"$HERE/resultats/paired_$STAMP"}

is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

is_uint "$LQ" && [ "$LQ" -ge 1 ] && [ "$LQ" -le 32 ] || {
    echo "LQ doit être un entier entre 1 et 32" >&2; exit 2;
}
is_uint "$NC" && [ "$NC" -ge 1 ] && [ "$NC" -le 1000000 ] || {
    echo "NC doit être un entier entre 1 et 1000000" >&2; exit 2;
}
is_uint "$ROUNDS" && [ "$ROUNDS" -ge 1 ] && [ "$ROUNDS" -le 32 ] || {
    echo "ROUNDS doit être un entier entre 1 et 32" >&2; exit 2;
}
is_uint "$THREADS" && [ "$THREADS" -ge 1 ] && [ "$THREADS" -le 256 ] || {
    echo "THREADS doit être un entier entre 1 et 256" >&2; exit 2;
}

command -v python3 >/dev/null 2>&1 || { echo "python3 introuvable" >&2; exit 1; }
command -v cc >/dev/null 2>&1 || { echo "cc introuvable" >&2; exit 1; }

# Cherche la racine Git par la présence de la table générée. Le paquet peut
# être placé directement dans prototypes/brume_sbox6 ou dans un sous-dossier.
ROOT=""
for candidate in \
    "$HERE/../.." \
    "$HERE/../../.." \
    "$HERE/../../../.." \
    "$HERE/../../../../.."; do
    candidate=$(CDPATH= cd -- "$candidate" 2>/dev/null && pwd || true)
    if [ -n "$candidate" ] && [ -f "$candidate/sillage/c/brume512_tables.h" ]; then
        ROOT=$candidate
        break
    fi
done

HEADER=${BRUME_TABLES_HEADER:-"$ROOT/sillage/c/brume512_tables.h"}
if [ ! -f "$HEADER" ]; then
    echo "Impossible de trouver sillage/c/brume512_tables.h." >&2
    echo "Lance le script depuis le dépôt BRUME ou définis BRUME_TABLES_HEADER=/chemin/brume512_tables.h." >&2
    exit 1
fi

if [ -e "$OUTDIR" ]; then
    echo "Le dossier de sortie existe déjà : $OUTDIR" >&2
    echo "Choisis un autre dossier pour ne pas écraser les résultats." >&2
    exit 1
fi
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"
cp "$HEADER" "$OUTDIR/brume512_tables.h"
cp "$HERE/brume_attaques_paired.c" "$OUTDIR/brume_attaques_paired.c"
cp "$HERE/analyse_pairee.py" "$OUTDIR/analyse_pairee.py"

# Cinq clés de campagne fixes, dérivées par SHA-256 d'étiquettes versionnées.
python3 - "$OUTDIR/seeds.txt" <<'PY'
import hashlib
import sys
from pathlib import Path
p = Path(sys.argv[1])
with p.open("w", encoding="ascii") as f:
    for i in range(1, 6):
        label = f"BRUME512-PAIRED-CHACHA20-v1-seed-{i}".encode("ascii")
        f.write(hashlib.sha256(label).hexdigest() + "\n")
PY

# Compilation sur la machine qui exécutera la campagne.
CC=${CC:-cc}
CFLAGS=${CFLAGS:--O3 -march=native -std=c11 -Wall -Wextra -fopenmp}
# shellcheck disable=SC2086
$CC $CFLAGS -I "$OUTDIR" "$HERE/brume_attaques_paired.c" \
    -o "$OUTDIR/brume_attaques_paired" -lm
$CC --version 2>/dev/null | sed -n '1p' > "$OUTDIR/compiler_version.txt" || true

printf 'BRUME-512 paired bench\n' > "$OUTDIR/run.log"
printf 'LQ=%s NC=%s ROUNDS=%s THREADS=%s\n' "$LQ" "$NC" "$ROUNDS" "$THREADS" >> "$OUTDIR/run.log"

while IFS= read -r seed; do
    [ -n "$seed" ] || continue
    echo "Démarrage graine ${seed}" | tee -a "$OUTDIR/run.log"
    "$OUTDIR/brume_attaques_paired" "$LQ" "$NC" "$ROUNDS" \
        "$THREADS" "$seed" "$OUTDIR" >> "$OUTDIR/run.log" 2>&1
done < "$OUTDIR/seeds.txt"

# Métadonnées présentes avant l'analyse ; l'analyse les lit pour contrôler
# l'exhaustivité des CSV. Les empreintes sont finalisées après l'analyse.
python3 - "$OUTDIR" "$LQ" "$NC" "$ROUNDS" "$THREADS" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import platform
import sys

out = Path(sys.argv[1])
lq, nc, rounds, threads = map(int, sys.argv[2:6])
seeds = [x.strip() for x in (out / "seeds.txt").read_text(encoding="ascii").splitlines() if x.strip()]
meta = {
    "protocol": "BRUME-512-PAIRED-CHACHA20-v1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "candidates": ["BRUME", "SBOX6", "SBOX_V3"],
    "log2_quartets_per_combination": lq,
    "quartets_per_combination": 1 << lq,
    "combinations": nc,
    "rounds": rounds,
    "threads": threads,
    "total_paired_quartets": (1 << lq) * nc * rounds * len(seeds),
    "total_candidate_evaluations": 3 * (1 << lq) * nc * rounds * len(seeds),
    "seed_count": len(seeds),
    "seeds_hex": seeds,
    "random_generator": "ChaCha20 RFC 8439, 256-bit key, 96-bit nonce, counter indexed by quartet",
    "paired_design": "same input state, input difference and injected intermediate difference for all three S-boxes",
    "events": {
        "zero_nibble": "final output difference at a nibble equals zero",
        "exact_return": "complete 128-nibble difference equals the original one-nibble input difference"
    },
    "familywise_alpha": 1.0 / 1024.0,
    "bonferroni_family_sizes": {
        "paired_zero_mcnemar": 3 * len(seeds) * rounds * 128,
        "candidate_zero_vs_1_16": 3 * len(seeds) * rounds * 128,
        "paired_exact_mcnemar": 3 * len(seeds) * rounds
    },
    "platform": platform.platform(),
    "python_version": platform.python_version(),
    "limitations": [
        "reduced-round empirical test only; no proof for the full 32-round permutation",
        "McNemar tests compare paired event rates, not cryptographic security in general",
        "the p=1/16 marginal reference remains an exploratory ideal-permutation model"
    ]
}
(out / "campaign_metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY

python3 "$HERE/analyse_pairee.py" "$OUTDIR" | tee -a "$OUTDIR/run.log"

# Empreintes des sources, paramètres, binaires et résultats ; metadata exclu
# de sa propre liste de hash pour éviter une empreinte circulaire.
python3 - "$OUTDIR" <<'PY'
from pathlib import Path
import hashlib, json, sys
out = Path(sys.argv[1])
meta_path = out / "campaign_metadata.json"
meta = json.loads(meta_path.read_text(encoding="utf-8"))
checksums = {}
for p in sorted(out.iterdir()):
    if p.is_file() and p.name != "campaign_metadata.json":
        checksums[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
meta["artifacts_sha256"] = checksums
meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY

printf '\nCampagne appariée terminée. Résultats : %s\n' "$OUTDIR"
printf 'Rapport : %s/synthese_appariee.md\n' "$OUTDIR"
