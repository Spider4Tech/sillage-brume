#!/usr/bin/env bash
# Banc de départage complet (PROTOCOLE.md). Usage :
#   ./run_departage.sh [DOSSIER] [SBOX...]
# Par défaut : resultats/<horodatage>, S-box BRUME SBOX6 SBOX_V3 SBOX_V4 (+ celles passées en argument,
# forme NOM=0123456789ABCDEF). Variables : B3_LG (2^lg quartets, défaut 26), B3_K (défaut 6),
# INT_K (nibbles actifs max, défaut 6), THREADS (défaut nproc).
set -euo pipefail
ICI="$(cd "$(dirname "$0")" && pwd)"
RACINE="$(cd "$ICI/../../.." && pwd)"
OUT="${1:-$ICI/resultats/$(date -u +%Y%m%dT%H%M%SZ)}"
shift || true
SBOXES=(BRUME SBOX6 SBOX_V3 SBOX_V4 "$@")
export OMP_NUM_THREADS="${THREADS:-$(nproc)}"
B3_LG="${B3_LG:-26}"
B3_K="${B3_K:-6}"
INT_K="${INT_K:-6}"
mkdir -p "$OUT"
LIB="$RACINE/sillage/c/build/libsillage.so"
CFLAGS="-O3 -march=native -std=c11 -Wall -Wextra -Werror -fopenmp"
cc $CFLAGS -I"$RACINE/sillage/c" "$ICI/departage.c" -o "$OUT/departage" -lm -ldl 2> "$OUT/build.log"
B="$OUT/departage"

{
  echo "{"
  echo "  \"date_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"commit\": \"$(git -C "$RACINE" rev-parse HEAD 2>/dev/null || echo inconnu)\","
  echo "  \"arbre_propre\": $(git -C "$RACINE" diff --quiet 2>/dev/null && echo true || echo false),"
  echo "  \"compilateur\": \"$(cc --version | head -1)\","
  echo "  \"options\": \"$CFLAGS\","
  echo "  \"threads\": $OMP_NUM_THREADS,"
  echo "  \"sha256_departage_c\": \"$(sha256sum "$ICI/departage.c" | cut -d' ' -f1)\","
  echo "  \"sha256_tables\": \"$(sha256sum "$RACINE/sillage/c/brume512_tables.h" | cut -d' ' -f1)\","
  echo "  \"sha256_libsillage\": \"$(sha256sum "$LIB" | cut -d' ' -f1)\","
  echo "  \"sbox\": \"${SBOXES[*]}\","
  echo "  \"b3\": {\"lg\": $B3_LG, \"K\": $B3_K}, \"integral_k_max\": $INT_K"
  echo "}"
} > "$OUT/metadonnees.json"

journal() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }

journal "contrôle du modèle"
"$B" -o "$OUT" controle "$LIB" | tee -a "$OUT/run.log"
"$B" -o "$OUT" local "${SBOXES[@]}" | tee -a "$OUT/run.log"

for s in "${SBOXES[@]}"; do
  journal "exact 2 et 3 tours : $s"
  "$B" -o "$OUT" d2 "$s" 24 3 | tee -a "$OUT/run.log"
  "$B" -o "$OUT" b2 "$s" 22 3 | tee -a "$OUT/run.log"
  "$B" -o "$OUT" l2 "$s" 0 24 3 | tee -a "$OUT/run.log"
  for r in $(seq 1 30); do "$B" -o "$OUT" l2 "$s" "$r" 20 1 >> "$OUT/l2_fenetres.log"; done
  "$B" -o "$OUT" d3 "$s" | tee -a "$OUT/run.log"
  "$B" -o "$OUT" l3 "$s" | tee -a "$OUT/run.log"
done

journal "boomerang 3 tours apparié (2^$B3_LG quartets, K=$B3_K)"
"$B" -o "$OUT" b3 "$B3_LG" "$B3_K" 16 "${SBOXES[@]}" | tee -a "$OUT/run.log"

for k in $(seq 1 "$INT_K"); do
  journal "intégrales directes, cube de $((4 * k)) bits"
  "$B" -o "$OUT" integral "$k" 3 5 0 "${SBOXES[@]}" | tee -a "$OUT/run.log"
done
for k in $(seq 1 $((INT_K < 4 ? INT_K : 4))); do
  journal "intégrales inverses, cube de $((4 * k)) bits"
  "$B" -o "$OUT" integral "$k" 3 4 1 "${SBOXES[@]}" | tee -a "$OUT/run.log"
done

journal "fin ; certificats tronqués : distrobox enter tgh -- python3 $ICI/certificat_tronque.py 900 $OUT"
