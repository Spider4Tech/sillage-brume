#!/bin/bash
# Reproduces every number of the paper. Usage: bash run_all.sh [quick]     (quick: 100 times fewer trials)
# Needs: gcc with OpenMP, python3 (numpy only for f3_kd_check.py). The Monte Carlo outputs depend on the seeds and, for
# thm1_distinguisher, on the number of threads (one stream per thread): the reference results used OMP_NUM_THREADS=12.
set -eu
cd "$(dirname "$0")"; mkdir -p results build
Q=${1:-}; div() { if [ "$Q" = quick ]; then echo $(($1 / 100)); else echo "$1"; fi; }
export OMP_NUM_THREADS=${OMP_NUM_THREADS:-12}
{ gcc --version | head -1; python3 --version; uname -srm; echo "threads: $OMP_NUM_THREADS"; date -u +%Y-%m-%dT%H:%MZ; } > results/environment.txt
gcc -O3 -march=native -fopenmp -Wall -Wextra -o build/thm1_distinguisher thm1_distinguisher.c -lm
gcc -O2 -Wall -Wextra -o build/f3_kd f3_kd.c -lm
gcc -O2 -Wall -Wextra -o build/f3_rd f3_rd.c -lm
{ python3 f2_exact.py; python3 f2_exact.py small; } > results/f2_exact.txt
{ for a in "16 20 16 640 64 2" "16 20 16 768 48 2" "24 40 24 12288 64 3" "32 64 32 196608 64 3" "64 256 128 12884901888 64 5"; do
    python3 thm1_bounds.py $a; done; } > results/thm1_bounds.txt
{ python3 f3_bound.py 16 20 3; python3 f3_bound.py 32 64 3; python3 f3_bound.py 64 256 5; } > results/f3_bound.txt
{ echo "nu^{22}_{4,12} = $(python3 nu_exact.py 22 4 12)"; echo "nu^{20}_{4,10} = $(python3 nu_exact.py 20 4 10)"; echo "nu^{74}_{8,12} = $(python3 nu_exact.py 74 8 12)"
  build/f3_kd $(div 200000); build/f3_kd $(div 200000) control
  build/f3_rd 8 12 30 6 3 35 $(div 4000000) 1; build/f3_rd 8 12 30 6 3 35 $(div 4000000) 2 control; } > results/f3.txt
if python3 -c 'import numpy' 2>/dev/null; then
  { python3 f3_kd_check.py 10 $(div 20000) 101; python3 f3_kd_check.py 12 $(div 20000) 102; } > results/f3_kd_check.txt
fi
python3 thm1_distinguisher_check.py 8 10 8 40 12 3 $(div 300000) 77 real > results/thm1_distinguisher_check.txt
python3 f3_rd_check.py 8 12 30 6 3 35 $(div 300000) 9 > results/f3_rd_check.txt
T=$(div 400000000)
{ build/thm1_distinguisher 8 10 8 40 12 3 $(div 2000000) 5 real max      # same model as the Python cross-check
  build/thm1_distinguisher 16 20 16 640 64 2 $T 1 real max
  build/thm1_distinguisher 16 20 16 640 64 2 $T 2 real max
  build/thm1_distinguisher 16 20 16 640 64 2 $T 3 real first
  build/thm1_distinguisher 16 20 16 640 64 2 $T 4 ideal max
  build/thm1_distinguisher 16 20 16 640 64 2 $T 7 rd max
  build/thm1_distinguisher 16 20 16 768 48 2 $T 5 real max
  build/thm1_distinguisher 16 20 16 768 48 2 $T 6 real first; } > results/thm1_distinguisher.txt
python3 table3.py > results/table3.txt
echo done
