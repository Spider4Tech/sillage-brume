#!/bin/sh
# Campagne lourde BRUME / SBOX6 / SBOX_V3.
# À installer dans prototypes/brume_sbox6/ avec les deux scripts Python
# et tester_sbox_compare.sh de ce dossier.
set -eu

PROTO=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RACINE=$(CDPATH= cd -- "$PROTO/../.." && pwd)

# Paramètres par défaut : 10 fois plus de quartets cumulés que la précédente
# comparaison 3 candidates x 1 graine x 16 combinaisons x 2^20 quartets.
LQ=${LQ:-20}
NC=${NC:-32}
THREADS=${OMP_NUM_THREADS:-8}
ROUNDS=${ROUNDS:-14}
W2=${W2:-8}
SEEDS=${SEEDS:-"0xB00 0xB01 0xB02 0xB03 0xB04"}

# Nombre de tests candidats x graines. Le paramètre C multiplie le nombre
# de tests par family_size pour Bonferroni.
set -- $SEEDS
SEED_COUNT=$#
[ "$SEED_COUNT" -gt 0 ] || { echo "Aucune graine fournie" >&2; exit 2; }
FAMILY=${FAMILY:-$((3 * SEED_COUNT))}

case "$LQ" in ''|*[!0-9]*) echo "LQ doit être entier" >&2; exit 2 ;; esac
case "$NC" in ''|*[!0-9]*) echo "NC doit être entier" >&2; exit 2 ;; esac
case "$THREADS" in ''|*[!0-9]*) echo "OMP_NUM_THREADS doit être entier" >&2; exit 2 ;; esac
case "$ROUNDS" in ''|*[!0-9]*) echo "ROUNDS doit être entier" >&2; exit 2 ;; esac
case "$W2" in ''|*[!0-9]*) echo "W2 doit être entier" >&2; exit 2 ;; esac
case "$FAMILY" in ''|*[!0-9]*) echo "FAMILY doit être entier" >&2; exit 2 ;; esac
[ "$LQ" -ge 1 ] && [ "$LQ" -le 60 ] || { echo "LQ hors limites (1..60)" >&2; exit 2; }
[ "$NC" -ge 1 ] && [ "$NC" -le 1000000 ] || { echo "NC hors limites" >&2; exit 2; }
[ "$FAMILY" -ge 1 ] && [ "$FAMILY" -le 1000000 ] || { echo "FAMILY hors limites" >&2; exit 2; }
[ "$ROUNDS" -ge 1 ] && [ "$ROUNDS" -le 32 ] || { echo "ROUNDS hors limites (1..32)" >&2; exit 2; }
[ "$W2" -ge 0 ] && [ "$W2" -le "$ROUNDS" ] || { echo "W2 doit être entre 0 et ROUNDS" >&2; exit 2; }

for f in tester_sbox_compare.sh analyse_sbox_v3.py sbox_v3.py; do
    [ -f "$PROTO/$f" ] || { echo "Fichier requis introuvable : $PROTO/$f" >&2; exit 1; }
done
[ -f "$RACINE/tests/c/brume_attaques.c" ] || { echo "tests/c/brume_attaques.c introuvable" >&2; exit 1; }
[ -f "$RACINE/tests/banc_trails.py" ] || { echo "tests/banc_trails.py introuvable" >&2; exit 1; }
[ -f "$RACINE/sillage/brume512.py" ] || { echo "sillage/brume512.py introuvable" >&2; exit 1; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUTROOT=${OUTROOT:-"$PROTO/resultats/campagne_lourde_${STAMP}"}
if [ -e "$OUTROOT" ]; then
    echo "Le dossier existe déjà : $OUTROOT" >&2
    echo "Définis OUTROOT vers un nouveau chemin." >&2
    exit 1
fi
mkdir -p "$OUTROOT"

# Archive le code exact de cette campagne dans son dossier de sortie.
cp "$PROTO/analyse_sbox_v3.py" "$OUTROOT/analyse_sbox_v3.py"
cp "$PROTO/sbox_v3.py" "$OUTROOT/sbox_v3.py"
cp "$PROTO/tester_sbox_compare.sh" "$OUTROOT/tester_sbox_compare.sh"
cp "$PROTO/run_comparaison_lourde.sh" "$OUTROOT/run_comparaison_lourde.sh"
cp "$PROTO/aggregate_comparaison_lourde.py" "$OUTROOT/aggregate_comparaison_lourde.py"

cat > "$OUTROOT/configuration.txt" <<EOF
BRUME-SBOX-COMPARE-HEAVY
LQ=$LQ
NC=$NC
THREADS=$THREADS
ROUNDS=$ROUNDS
W2=$W2
SEEDS=$SEEDS
SEED_COUNT=$SEED_COUNT
FAMILY=$FAMILY
Candidates=BRUME SBOX6 SBOX_V3
Family interpretation=3 S-boxes x $SEED_COUNT seeds
EOF

printf '%s\n' "[1/2] Analyse exacte des S-boxes et recherche des pistes 1..$ROUNDS tours (poids 2 jusqu'à $W2)."
python3 "$PROTO/analyse_sbox_v3.py" \
    --rounds "$ROUNDS" \
    --w2 "$W2" \
    --output "$OUTROOT/analyse_trails.json" \
    > "$OUTROOT/analyse_trails.log" 2>&1

printf '%s\n' "[2/2] Campagnes C : $SEED_COUNT graines x 3 candidates."
for SEED in $SEEDS; do
    for CANDIDATE in BRUME SBOX6 SBOX_V3; do
        DEST="$OUTROOT/$CANDIDATE/seed_$SEED"
        mkdir -p "$(dirname -- "$DEST")"
        printf '\n%s\n' "=== $CANDIDATE / $SEED ==="
        OMP_NUM_THREADS="$THREADS" "$PROTO/tester_sbox_compare.sh" \
            "$CANDIDATE" "$LQ" "$NC" "$SEED" "$FAMILY" "$DEST"
    done
done

printf '\n%s\n' "Agrégation et contrôle des géométries appariées."
python3 "$PROTO/aggregate_comparaison_lourde.py" "$OUTROOT"

printf '\n%s\n' "Campagne terminée : $OUTROOT"
printf '%s\n' "Synthèse : $OUTROOT/synthese.md"
printf '%s\n' "CSV : $OUTROOT/synthese_boomerang.csv"
printf '%s\n' "JSON : $OUTROOT/synthese.json"
