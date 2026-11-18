# -*- coding: utf-8 -*-
"""Bibliothèque C sans gadget « Speculative Store Bypass » d'allocation de pile (détecteur tests/gadget_ssb.py).

Origine : enquête du 18 novembre 2026 (docs/AUDIT_REPORT.md). Inlinée dans le banc dudect, la permutation portable était
compilée avec un emplacement de pile partagé entre le pointeur des constantes de tour et un intermédiaire secret ; la
relecture spéculative du pointeur recevait la donnée et s'en servait comme adresse (signal dudect sur Zen 3, supprimé
par SSBD). ctgrind ne voit pas ce motif : il ne regarde que l'exécution architecturale.

1. Témoins (tests/c/temoin_ssb.S) : le motif est signalé dans temoin_ssb_gadget, rien dans temoin_ssb_sain.
2. La bibliothèque (sillage/c : commun, brume1024, kem, sig, vole, isd) compilée par le compilateur de la batterie dans
   quatre réglages (celui de la batterie, la version portable sans AVX2, -O2, x86-64-v3) : aucune fonction signalée.
3. Le banc dudect de BRUME-1024q (tests/c/temps1024.c, réglage de la batterie) : aucune fonction signalée, sinon dudect
   mesurerait un gadget du banc et non la bibliothèque.
Heuristique : un résultat négatif ne prouve pas l'absence de toute fuite spéculative."""
import os
import subprocess

from tests.commun import sauver, RACINE
from tests.gadget_ssb import analyser_fichier

LIB = os.path.join(RACINE, "sillage", "c")
TC = os.path.join(RACINE, "tests", "c")
BUILD = os.path.join(TC, "build", "gadget_ssb")
SOURCES = ["commun.c", "brume1024.c", "kem.c", "sig.c", "vole.c", "isd.c"]
REGLAGES = {
    "batterie": ["-O3", "-march=native"],
    "portable": ["-O3", "-march=native", "-mno-avx2", "-DB1024_API_PORTABLE"],
    "O2": ["-O2", "-march=native"],
    "x86_64_v3": ["-O3", "-march=x86-64-v3"],
}


def compiler(sortie, args):
    subprocess.run(["gcc", *args, "-o", sortie], check=True, capture_output=True, text=True)
    return sortie


def resume(trouves):
    return {f: {s: {"donnee": d[:4], "pointeur": ["%s->%s" % x for x in p[:4]]} for s, (d, p) in part.items()}
            for f, part in trouves.items()}


def run():
    c, m = {}, {}
    os.makedirs(BUILD, exist_ok=True)
    m["compilateur"] = subprocess.run(["gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]

    # 1. témoins
    obj = compiler(os.path.join(BUILD, "temoin_ssb.o"), ["-c", os.path.join(TC, "temoin_ssb.S")])
    gadget, _ = analyser_fichier(obj, ["temoin_ssb_gadget"])
    sain, _ = analyser_fichier(obj, ["temoin_ssb_sain"])
    m["temoin_gadget"] = resume(gadget)
    c["temoin_gadget_signale"] = "temoin_ssb_gadget" in gadget
    c["temoin_sain_non_signale"] = not sain

    # 2. la bibliothèque, quatre réglages
    tous_propres = True
    for nom, fl in REGLAGES.items():
        trouves, lues = {}, 0
        for src in SOURCES:
            o = compiler(os.path.join(BUILD, "%s_%s.o" % (src[:-2], nom)),
                         [*fl, "-fopenmp", "-c", "-I", LIB, os.path.join(LIB, src)])
            t, n = analyser_fichier(o)
            trouves.update({"%s:%s" % (src, f): v for f, v in t.items()})
            lues += n
        m["bibliotheque_" + nom] = {"fonctions_lues": lues, "signalees": resume(trouves)}
        c["bibliotheque_%s_lue" % nom] = lues > 50
        c["bibliotheque_%s_sans_emplacement_partage" % nom] = not trouves
        tous_propres &= not trouves
    m["bibliotheque_propre_dans_tous_les_reglages"] = tous_propres

    # 3. le banc dudect de BRUME-1024q
    banc = compiler(os.path.join(BUILD, "temps1024"),
                    [*REGLAGES["batterie"], "-fopenmp", "-DSANS_MAIN", "-I", LIB, os.path.join(TC, "temps1024.c"),
                     os.path.join(LIB, "commun.c"), "-lm"])
    t, n = analyser_fichier(banc, ["mesurer", "pp_perm"])
    m["banc_dudect"] = {"fonctions_lues": n, "signalees": resume(t)}
    c["banc_dudect_sans_emplacement_partage"] = not t

    out = {"controles": c, "mesures": m}
    sauver("c_gadget_ssb", out)
    return out


if __name__ == "__main__":
    import json
    print(json.dumps(run(), ensure_ascii=False, indent=1))
