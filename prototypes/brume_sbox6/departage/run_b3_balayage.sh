#!/usr/bin/env bash
# B3 EXHAUSTIF (toutes les combinaisons (i, a, j′, δ′), b3_gpu balayage) sur GPU : construction dans tgh, puis balayage.
# Usage : ./run_b3_balayage.sh DOSSIER lg_bal top lg_conf [SBOX...]   (S-box par défaut : BRUME SBOX6 SBOX_V3 SBOX_V4)
# Variables : LG_CTRL (contrôle exact C == GPU, défaut 16), LG_ID (identité rapide == inversion, défaut 12).
# Chaque mesure est précédée d'un contrôle exact C/GPU ; le moindre écart arrête tout (code 1).
set -euo pipefail
ICI="$(cd "$(dirname "$0")" && pwd)"
RACINE="$(cd "$ICI/../../.." && pwd)"
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"; LG="$2"; TOP="$3"; LGC="$4"; shift 4
SBOXES=(BRUME SBOX6 SBOX_V3 SBOX_V4 "$@")
LG_CTRL="${LG_CTRL:-14}"; LG_ID="${LG_ID:-10}"
NVCC=/usr/local/cuda/bin/nvcc
CFLAGS="-O3 -march=native -std=c11 -Wall -Wextra -Werror -fopenmp"
mkdir -p "$ICI/build_bal"
distrobox enter tgh -- sh -c "cd '$ICI' && gcc $CFLAGS -I'$RACINE/sillage/c' -c b3_gpu_hote.c -o build_bal/hote.o \
  && $NVCC -O3 -gencode arch=compute_89,code=sm_89 -c b3_gpu.cu -o build_bal/b3_gpu.o \
  && $NVCC -o build_bal/b3_gpu build_bal/hote.o build_bal/b3_gpu.o -lgomp -lm -ldl" > "$OUT/build_gpu_balayage_lg$LG.log" 2>&1
{
  echo "{"
  echo "  \"date_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"commit\": \"$(git -C "$RACINE" rev-parse HEAD 2>/dev/null || echo inconnu)\","
  echo "  \"gpu\": \"$(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader 2>/dev/null || echo inconnu)\","
  echo "  \"nvcc\": \"$(distrobox enter tgh -- $NVCC --version | tail -1)\","
  echo "  \"sha256_departage_c\": \"$(sha256sum "$ICI/departage.c" | cut -d' ' -f1)\","
  echo "  \"sha256_b3_gpu_cu\": \"$(sha256sum "$ICI/b3_gpu.cu" | cut -d' ' -f1)\","
  echo "  \"sha256_b3_gpu_hote_c\": \"$(sha256sum "$ICI/b3_gpu_hote.c" | cut -d' ' -f1)\","
  echo "  \"sha256_tables\": \"$(sha256sum "$RACINE/sillage/c/brume512_tables.h" | cut -d' ' -f1)\","
  echo "  \"mode\": \"balayage\", \"lg_bal\": $LG, \"top\": $TOP, \"lg_conf\": $LGC, \"lg_ctrl\": $LG_CTRL, \"lg_id\": $LG_ID,"
  echo "  \"sbox\": \"${SBOXES[*]}\""
  echo "}"
} > "$OUT/metadonnees_b3_gpu_balayage_lg$LG.json"
distrobox enter tgh -- sh -c "cd '$ICI' && build_bal/b3_gpu -o '$OUT' balayage $LG $TOP $LGC $LG_CTRL $LG_ID ${SBOXES[*]}" | tee "$OUT/b3_gpu_balayage_lg$LG.log"
