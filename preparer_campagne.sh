#!/usr/bin/env bash
# Prépare et vérifie une machine pour ./rundenuit.sh (guide : docs/CAMPAGNE_24H.md).
#
#   ./preparer_campagne.sh              vérifie, sans rien installer ni modifier
#   ./preparer_campagne.sh --installer  crée .venv et y installe les paquets Python
#
# Code de retour non nul : il manque quelque chose d'indispensable. rundenuit.sh l'appelle au démarrage.
set -u
cd "$(dirname "$(readlink -f "$0")")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BLOQUANT=0
ok() { echo "  ok        $*"; }
attention() { echo "  ATTENTION $*"; }
manque() { echo "  MANQUE    $*"; BLOQUANT=1; }
PAQUETS_PY="numpy networkx ortools python-sat matplotlib"

if [ "${1:-}" = --installer ]; then
    python3 -m venv .venv || { echo "création de .venv impossible : installer python3-venv" >&2; exit 1; }
    .venv/bin/python3 -m pip install --quiet --upgrade pip && .venv/bin/python3 -m pip install --quiet $PAQUETS_PY \
        || { echo "installation des paquets Python impossible" >&2; exit 1; }
fi
[ -x .venv/bin/python3 ] && export PATH="$PWD/.venv/bin:$PATH"

echo "Outils :"
for c in gcc make python3 awk sed sha256sum tar; do
    if command -v "$c" >/dev/null 2>&1; then ok "$c"; else manque "$c"; fi
done
command -v valgrind >/dev/null 2>&1 && ok valgrind || manque "valgrind (contrôles de temps constant)"
command -v taskset >/dev/null 2>&1 && ok taskset || attention "taskset absent : dudect ne sera pas épinglé sur un cœur, mesures plus bruitées"
command -v pgrep >/dev/null 2>&1 && ok pgrep || manque "pgrep (paquet procps)"

echo "Compilation :"
essai() {   # essai <libellé> <options> <programme C>
    if printf '%s\n' "$3" | gcc -x c - $2 -o "$TMP/a.out" 2>/dev/null && "$TMP/a.out"; then ok "$1"; else manque "$1"; fi
}
essai "OpenMP" "-fopenmp" '#include <omp.h>
int main(void) { return omp_get_max_threads() < 1; }'
essai "libquadmath" "-lquadmath" '#include <quadmath.h>
int main(void) { __float128 x = 2; return log2q(x) != 1; }'
essai "ASan et UBSan" "-fsanitize=address,undefined" 'int main(void) { return 0; }'
if printf 'int main(void) { return 0; }\n' | gcc -x c - -march=native -mavx2 -mpclmul -o "$TMP/a.out" 2>/dev/null && grep -qw avx2 /proc/cpuinfo; then ok "AVX2"
else attention "pas d'AVX2 : noyaux de référence, nettement plus lents et non constant-time"; fi
if printf '#include <valgrind/memcheck.h>\nint main(void) { return 0; }\n' | gcc -x c - -o "$TMP/a.out" 2>/dev/null; then ok "valgrind/memcheck.h"
else manque "valgrind/memcheck.h (paquet de développement de valgrind)"; fi

echo "Python ($(command -v python3 2>/dev/null)) :"
for m in numpy networkx ortools pysat; do
    python3 -c "import $m" 2>/dev/null && ok "$m" || manque "$m"
done
python3 -c "import matplotlib" 2>/dev/null && ok matplotlib || attention "matplotlib absent : pas de figures, sans autre effet"

echo "Machine :"
echo "  $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //'), $(nproc) threads"
ram=$(awk '/MemAvailable/ { printf "%d", $2 / 1048576 }' /proc/meminfo)
[ "$ram" -ge 16 ] && ok "mémoire disponible : $ram Gio" || attention "mémoire disponible : $ram Gio (16 Gio conseillés)"
disque=$(df -BG --output=avail . | tail -1 | tr -dc 0-9)
if [ "$disque" -ge 5 ]; then ok "disque libre : $disque Gio"; else manque "disque libre : $disque Gio (5 Gio nécessaires)"; fi
if grep -qi microsoft /proc/version; then
    attention "WSL : ni température ni blocage de la veille ; désactiver la veille de Windows, et les mesures dudect seront bruitées"
fi
for b in /sys/class/power_supply/BAT*; do
    [ -e "$b" ] && [ "$(cat "$b/status" 2>/dev/null)" = Discharging ] && attention "sur batterie : brancher le secteur"
done
temp=""
for h in /sys/class/hwmon/hwmon*; do
    case $(cat "$h/name" 2>/dev/null) in k10temp|zenpower|coretemp) temp=$(( $(cat "$h/temp1_input" 2>/dev/null || echo 0) / 1000 )); break ;; esac
done
if [ -n "$temp" ]; then ok "température lue : $temp °C"; else attention "température illisible : pas d'arrêt de sécurité (paquet ou module du capteur manquant ?)"; fi
charge=$(cut -d' ' -f1 /proc/loadavg)
awk -v c="$charge" -v n="$(nproc)" 'BEGIN { exit !(c > n / 4) }' && attention "machine déjà chargée ($charge) : fermer les autres programmes"

if [ "$BLOQUANT" != 0 ]; then
    echo
    echo "Il manque des éléments indispensables. Paquets système, selon la distribution :"
    echo "  Debian, Ubuntu : sudo apt install build-essential python3-venv valgrind libc6-dbg procps"
    echo "  Fedora :         sudo dnf install gcc make python3 valgrind valgrind-devel libasan libubsan libquadmath-devel procps-ng"
    echo "  Arch :           sudo pacman -S base-devel python valgrind procps-ng"
    echo "Paquets Python :   ./preparer_campagne.sh --installer"
    exit 1
fi
echo
echo "Prêt."
