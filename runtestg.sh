#!/bin/sh
# Lance les contrôles du test C « sig_kz » (attaque de Kales–Zaverucha à
# échelle intermédiaire, vrai vérifieur sl_sig_verify).
#
#   ./runtestg.sh                      contrôles par défaut (12 essais, 1000 essais quantitatifs)
#   ./runtestg.sh 1                    un essai par stratégie non quantitative
#   ./runtestg.sh 1 100                idem, campagne quantitative à 100 essais
#   SIG_KZ_GRAINE=42 ./runtestg.sh     aléa reproductible, graine imposée
#
# Les contrôles exécutés sont :
#   - parametres_reduits_valides
#   - vrai_temoin_vue_verifieur_identique_et_signature_acceptee
#   - cle_publique_sans_temoin_de_poids_au_plus_w
#   - faux_positifs_sous_la_borne_du_lemme_6
#   - faux_positifs_de_la_campagne_sous_la_borne_du_lemme_6
#   - chaque_falsification_acceptee_par_le_vrai_verifieur
#   - frequence_de_succes_sous_la_borne_du_theoreme_8     (IC à 99,9 % non au-dessus de la borne)
#   - borne_du_theoreme_8_au_dessus_de_l_ic95_quantitatif
#   - frequence_de_succes_conforme_a_la_prediction_exacte (probabilité exacte de la stratégie dans l'IC à 99,9 %)
#   - falsification_obtenue_au_grand_budget
#
# Sortie : code 0 si les 10 contrôles passent, 1 sinon. Résultat JSON :
# resultats/sig_kz.json ; synthèse lisible : resultats/sig_kz.md.
set -u
cd "$(dirname "$(readlink -f "$0")")" || exit 1

BIN=tests/c/build/sig_kz
JSON=resultats/sig_kz.json

mkdir -p resultats

echo "== Construction de $BIN =="
if ! make -C tests/c build/sig_kz; then
    echo "runtestg : construction impossible" >&2
    exit 1
fi

echo
echo "== Contrôles sig_kz${*:+ (arguments : $*)} =="
"$BIN" "$@"
statut=$?

echo
if [ ! -f "$JSON" ]; then
    echo "runtestg : $JSON absent, contrôles non vérifiables" >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    python3 - "$JSON" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
controles = d.get("controles", {})
reussis = sum(1 for ok in controles.values() if ok)
print(f"Résumé : {reussis}/{len(controles)} contrôles réussis")
for nom, ok in controles.items():
    print(f"  {'OK   ' if ok else 'ÉCHEC'}  {nom}")

attaques = d.get("mesures", {}).get("attaques", {})
if isinstance(attaques, dict):
    for nom, m in attaques.items():
        if not isinstance(m, dict):
            continue
        ic = m.get("ic95")
        ic_txt = f", IC95 [{ic[0]:.3f}, {ic[1]:.3f}]" if isinstance(ic, list) and len(ic) == 2 else ""
        print(
            f"  {nom} : {m.get('succes')}/{m.get('essais')} falsifications"
            f" (fréquence {m.get('frequence')}, prédiction {m.get('prediction')},"
            f" borne {m.get('borne_theoreme_8')}{ic_txt})"
        )
fp = d.get("mesures", {}).get("faux_positifs_campagne")
if isinstance(fp, dict):
    print(f"  faux positifs par répétition : {fp.get('mesure')} sur {fp.get('repetitions')} (borne du lemme 6 {fp.get('borne_lemme_6')})")
PY
fi

if [ "$statut" -ne 0 ]; then
    echo "runtestg : au moins un contrôle a échoué (code $statut)" >&2
    exit "$statut"
fi
exit 0
