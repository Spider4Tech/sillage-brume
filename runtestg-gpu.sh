#!/bin/sh
# Version GPU du test « sig_kz » : attaque de Kales–Zaverucha sur l'instance réduite (N = 2^8, τ = 4, K = GF(2^12)),
# broyage de h1 et de h2 sur GPU, chaque falsification rejouée en C et soumise au vrai vérifieur sl_sig_verify.
#
#   ./runtestg-gpu.sh                      300 essais par stratégie, 100 000 essais quantitatifs (≈ 10 s sur RTX 4070 Ti)
#   ./runtestg-gpu.sh 1000 1000000         campagne plus grande (≈ 1 min) ; 10^7 essais quantitatifs ≈ 10 min
#   SIG_KZ_GRAINE=42 ./runtestg-gpu.sh     aléa reproductible, graine imposée
#
# CUDA : nvcc de l'hôte s'il existe, sinon le conteneur distrobox « tgh » (CUDA 12.9), où le script se relance.
# Refuse de partir pendant une mesure de temps (dudect) ou une campagne GPU (scripts/rungpu).
#
# Contrôles (18) : les 4 de préparation de runtestg.sh, puis
#   - taux_exact_de_faux_positifs_sous_la_borne_du_lemme_6     (racines de T sur tout K)
#   - gpu_disponible_et_dimensions_conformes
#   - conformite_gpu_c_h1_et_faux_positifs                     (256 sels : h1 et faux positifs du GPU = C)
#   - faux_positifs_de_la_campagne_conformes_au_taux_exact
#   - campagne_gpu_sans_erreur
#   - conformite_gpu_c_h2                                      (défis de h2 du GPU = C sur 256 cibles)
#   - h1_retenus_par_le_gpu_confirmes_par_le_c
#   - succes_gpu_rejoues_par_le_c
#   - vue_composee_par_axes_identique_a_vue_verifieur
#   - les 5 du bilan de runtestg.sh (vrai vérifieur, borne du Théorème 8, IC95, prédiction exacte, grand budget)
#
# Sortie : code 0 si tous les contrôles passent, 1 sinon. Résultat JSON : resultats/sig_kz_gpu.json ;
# synthèse lisible : resultats/sig_kz_gpu.md ; températures du GPU : resultats/sig_kz_gpu_capteurs.log.
# Chaque run est aussi archivé dans resultats/sig_kz_gpu_runs/<date>_graine<g>_<essais>_<quantitatifs>/ (rien n'est écrasé).
set -u
cd "$(dirname "$(readlink -f "$0")")" || exit 1

NVCC=$(command -v nvcc 2>/dev/null || { [ -x /usr/local/cuda/bin/nvcc ] && echo /usr/local/cuda/bin/nvcc; })
if [ -z "$NVCC" ]; then
    if [ -z "${SIG_KZ_DANS_TGH:-}" ] && command -v distrobox >/dev/null 2>&1; then
        # garde-fous vérifiés sur l'hôte, puis relance dans le conteneur
        if [ -s resultats/special/run.pid ] && kill -0 "$(cat resultats/special/run.pid)" 2>/dev/null; then
            echo "runtestg-gpu : scripts/runspecial mesure le temps : pas de GPU pendant dudect" >&2; exit 1
        fi
        if pgrep -f 'rundenuit\.sh' >/dev/null; then
            echo "runtestg-gpu : scripts/rundenuit.sh tourne : relancer après" >&2; exit 1
        fi
        if [ -s resultats/gpu/run.pid ] && kill -0 "$(cat resultats/gpu/run.pid)" 2>/dev/null; then
            echo "runtestg-gpu : une campagne GPU tourne (./scripts/rungpu --statut)" >&2; exit 1
        fi
        exec distrobox enter tgh -- env SIG_KZ_DANS_TGH=1 ${SIG_KZ_GRAINE:+SIG_KZ_GRAINE=$SIG_KZ_GRAINE} sh ./runtestg-gpu.sh "$@"
    fi
    echo "runtestg-gpu : nvcc introuvable (ni sur l'hôte ni dans le conteneur tgh)" >&2
    exit 1
fi
command -v nvidia-smi >/dev/null 2>&1 || { echo "runtestg-gpu : nvidia-smi introuvable" >&2; exit 1; }

BIN=tests/gpu/build/sig_kz_gpu
JSON=resultats/sig_kz_gpu.json
CAPT=resultats/sig_kz_gpu_capteurs.log
mkdir -p resultats

ARCH=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 | tr -d '. ')
echo "== Construction de $BIN (sm_${ARCH:-?}) =="
if ! make -C tests/gpu NVCC="$NVCC" ${ARCH:+ARCHS=$ARCH} build/sig_kz_gpu; then
    echo "runtestg-gpu : construction impossible" >&2
    exit 1
fi

capteurs() { nvidia-smi --query-gpu=timestamp,temperature.gpu,power.draw,utilization.gpu,clocks.sm --format=csv,noheader >>"$CAPT" 2>/dev/null; }
: >"$CAPT"
capteurs

echo
echo "== Contrôles sig_kz_gpu${*:+ (arguments : $*)} =="
rm -f "$JSON"
"$BIN" "$@" &
pid=$!
( while kill -0 "$pid" 2>/dev/null; do capteurs; sleep 5; done ) &
surv=$!
wait "$pid"
statut=$?
kill "$surv" 2>/dev/null
capteurs
if [ -f "$JSON" ]; then
    ARCH_DIR=resultats/sig_kz_gpu_runs/$(date +%Y%m%d_%H%M%S)_graine${SIG_KZ_GRAINE:-defaut}_${1:-300}_${2:-100000}
    mkdir -p "$ARCH_DIR" && cp "$JSON" resultats/sig_kz_gpu.md "$CAPT" "$ARCH_DIR"/ 2>/dev/null
fi

echo
if [ ! -f "$JSON" ]; then
    echo "runtestg-gpu : $JSON absent, contrôles non vérifiables" >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    python3 - "$JSON" "$CAPT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
controles = d.get("controles", {})
reussis = sum(1 for ok in controles.values() if ok)
print(f"Résumé : {reussis}/{len(controles)} contrôles réussis")
for nom, ok in controles.items():
    print(f"  {'OK   ' if ok else 'ÉCHEC'}  {nom}")

mes = d.get("mesures", {})
attaques = mes.get("attaques", {})
if isinstance(attaques, dict):
    for nom, m in attaques.items():
        if not isinstance(m, dict):
            continue
        ic = m.get("ic95")
        ic_txt = f", IC95 [{ic[0]:.4f}, {ic[1]:.4f}]" if isinstance(ic, list) and len(ic) == 2 else ""
        print(
            f"  {nom} : {m.get('succes')}/{m.get('essais')} falsifications"
            f" (fréquence {m.get('frequence')}, prédiction {m.get('prediction')},"
            f" borne {m.get('borne_theoreme_8')}{ic_txt})"
        )
fx, fc = mes.get("faux_positifs_exacts"), mes.get("faux_positifs_campagne")
if isinstance(fx, dict) and isinstance(fc, dict):
    print(f"  faux positifs par répétition : exact {fx.get('taux')} ({fx.get('racines_de_T')} racines de T sur {fx.get('corps')}),"
          f" mesuré {fc.get('mesure')} sur {fc.get('repetitions')} (borne du lemme 6 {fx.get('borne_lemme_6')})")
g = mes.get("gpu")
if isinstance(g, dict):
    print(f"  GPU : {g.get('nom')} ; {g.get('tentatives_h1')} tentatives de h1, {g.get('tentatives_par_s')}/s"
          f" ({float(g.get('permutations_par_s') or 0):.3g} permutations Keccak/s) ; total {g.get('temps_total_s')} s")
try:
    temp = [int(l.split(",")[1]) for l in open(sys.argv[2], encoding="utf-8") if l.count(",") >= 4]
    if temp:
        print(f"  température du GPU : {temp[0]} → max {max(temp)} °C")
except (OSError, ValueError):
    pass
PY
fi

if [ "$statut" -ne 0 ]; then
    echo "runtestg-gpu : au moins un contrôle a échoué (code $statut)" >&2
    exit "$statut"
fi
exit 0
