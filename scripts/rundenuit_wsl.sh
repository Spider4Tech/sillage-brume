#!/usr/bin/env bash
# Partie Linux de scripts/rundenuit.ps1 (Windows) : ne pas lancer à la main.
#
#   scripts/rundenuit_wsl.sh lancer <heures> <neuf : 0 ou 1> | statut | arreter
#
# Le calcul se fait dans un clone propre au système de fichiers de WSL (~/sillage-brume), jamais dans /mnt/c :
# les accès y sont bien plus rapides, et les droits, les fins de ligne et le verrou de campagne y sont ceux de Linux.
# La campagne reste au premier plan : c'est le wsl.exe ouvert qui maintient WSL en vie.
set -u
DEPOT_URL="${SILLAGE_DEPOT_URL:-https://github.com/Spider4Tech/sillage-brume.git}"
DEPOT="${SILLAGE_DEPOT:-$HOME/sillage-brume}"
LOG=resultats/nuit/journal.log

# Sans les dossiers Windows du PATH : ni python3 ou gcc de Windows, ni nom d'utilisateur Windows dans les journaux
PATH=$(printf '%s' "$PATH" | tr ':' '\n' | grep -v '^/mnt/' | paste -sd: -)
export PATH

case "${1:-}" in
    statut|arreter)
        [ -x "$DEPOT/scripts/runlong" ] || { echo "aucune campagne : $DEPOT n'existe pas"; exit 0; }
        cd "$DEPOT" || exit 1
        [ "$1" = statut ] && exec ./scripts/runlong --statut
        exec ./scripts/runlong --arreter ;;
    lancer) ;;
    *) sed -n '2,3p' "$0" | cut -c3-; exit 2 ;;
esac
H="${2:-8}"; NEUF="${3:-0}"
awk -v h="$H" 'BEGIN { exit !(h > 0) }' || { echo "durée invalide : $H" >&2; exit 2; }

outils_manquants() {
    local c
    for c in git gcc make python3 valgrind pgrep taskset; do command -v "$c" >/dev/null 2>&1 || return 0; done
    printf '#include <valgrind/memcheck.h>\nint main(void) { return 0; }\n' | gcc -x c - -fsyntax-only 2>/dev/null || return 0
    python3 -c 'import ensurepip' >/dev/null 2>&1 || return 0      # absent sans python3-venv sous Debian et Ubuntu
    return 1
}
if outils_manquants; then
    command -v apt-get >/dev/null 2>&1 || { echo "Paquets manquants, et cette distribution n'a pas apt : installer Ubuntu dans WSL (wsl --install -d Ubuntu)." >&2; exit 1; }
    echo "Installation des paquets système (mot de passe Linux demandé) :"
    sudo apt-get update -qq && sudo apt-get install -y -qq git build-essential python3-venv valgrind libc6-dbg procps util-linux \
        || { echo "installation des paquets impossible" >&2; exit 1; }
fi

campagne_inachevee() { [ "$NEUF" = 0 ] && [ -f "$LOG" ] && ! grep -q '\] terminé$' "$LOG" && grep -q 'campagne de nuit :' "$LOG"; }

if [ -d "$DEPOT/.git" ]; then
    cd "$DEPOT" || exit 1
    if ./scripts/runlong --statut 2>/dev/null | grep -q 'en cours'; then ./scripts/runlong --statut; exit 1; fi
    # Une reprise garde ses sources, sauf si l'utilisateur met le clone à jour lui-même
    if ! campagne_inachevee; then
        git pull --ff-only || { echo "mise à jour de $DEPOT impossible : modifications locales ? (git -C $DEPOT status)" >&2; exit 1; }
    fi
elif [ -e "$DEPOT" ]; then
    echo "$DEPOT existe mais n'est pas un dépôt git : le déplacer, ou choisir un autre SILLAGE_DEPOT." >&2
    exit 1
else
    git clone "$DEPOT_URL" "$DEPOT" && cd "$DEPOT" || { echo "clonage de $DEPOT_URL impossible" >&2; exit 1; }
fi

./scripts/preparer_campagne.sh >/dev/null 2>&1 || ./scripts/preparer_campagne.sh --installer >/dev/null
./scripts/preparer_campagne.sh || exit 1      # c'est ce contrôle qui tranche, et il dit ce qui manque
echo

# Une fois l'archive écrite, copie du résultat côté Windows
copier_archive() {
    local f
    [ -n "${SILLAGE_WIN_DIR:-}" ] && [ -d "$SILLAGE_WIN_DIR" ] || return 0
    f=$(ls -t resultats/campagne_*.tar.gz 2>/dev/null | head -1)
    [ -n "$f" ] || return 0
    mkdir -p "$SILLAGE_WIN_DIR/resultats" && cp "$f" "$SILLAGE_WIN_DIR/resultats/" \
        && echo "Archive à transmettre, côté Windows : resultats\\${f##*/}"
}

# Au premier plan : lancée avec &, la campagne ignorerait Ctrl-C. Elle reçoit le signal, écrit sa synthèse et son archive ;
# ce script attend sa fin grâce au trap, puis copie l'archive.
trap ':' INT TERM
if campagne_inachevee; then
    echo "Campagne inachevée trouvée : reprise, avec le temps qu'il lui restait (-Neuf pour repartir de zéro)."
    SILLAGE_REPRISE=1 ./scripts/rundenuit.sh
else
    ./scripts/rundenuit.sh "$H"
fi
RC=$?
copier_archive
exit "$RC"
