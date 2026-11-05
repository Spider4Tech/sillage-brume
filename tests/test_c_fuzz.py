# -*- coding: utf-8 -*-
"""Sûreté mémoire de l'implémentation C, par fuzzing (tests/c/fuzz.c).

Le runtime AddressSanitizer n'étant pas disponible, on combine :
  - UBSan en mode « trap » (-fsanitize=undefined,bounds -fsanitize-trap) :
    débordements arithmétiques, décalages, alignement, indices de tableaux ;
  - un allocateur à pages de garde (tests/c/garde.c) : débordement de tas
    au-delà du bloc → faute immédiate, écriture dans le bourrage → canari,
    utilisation après libération → faute ;
  - protection de pile et _FORTIFY_SOURCE=3.
Le détecteur est d'abord validé sur des erreurs volontaires
(tests/c/garde_test.c), puis toutes les API sont exercées : longueurs
aléatoires biaisées vers les bords de blocs, chiffrés et tags altérés,
parités tronquées, multi-messages hétérogènes, KEM et SIG malformés.
"""
import json
import os
import subprocess

from tests.commun import RACINE, sauver

ICI = os.path.join(RACINE, "sillage", "c")
SRC = ["commun.c", "brume512.c", "brume512_avx2.c", "kem.c", "sig.c"]
OPTS = ["-O1", "-g", "-march=native", "-fopenmp", "-fsanitize=undefined,bounds", "-fsanitize-trap=all",
        "-fstack-protector-all", "-D_FORTIFY_SOURCE=3", "-I", ICI]
ITERATIONS = 2000


def construire(nom, sources):
    exe = os.path.join(RACINE, "tests", "c", "build", nom)
    os.makedirs(os.path.dirname(exe), exist_ok=True)
    subprocess.run(["gcc"] + OPTS + ["-o", exe] + sources + ["-lm"], check=True, capture_output=True)
    return exe


def run():
    c, m = {}, {}
    garde = os.path.join(RACINE, "tests", "c", "garde.c")
    temoin = construire("garde_test", [os.path.join(RACINE, "tests", "c", "garde_test.c"), garde])
    codes = [subprocess.run([temoin, str(k)], capture_output=True).returncode for k in range(7)]
    m["detecteur_codes_erreurs_volontaires"] = codes
    c["detecteur_valide_sur_erreurs_volontaires"] = all(x != 0 for x in codes)
    # Chaque mécanisme a son propre témoin. Les cas 0 et 1 étaient attrapés par UBSan (object-size, SIGILL), pas par
    # l'allocateur : rien ne montrait que le canari fonctionnait. Les cas 5 et 6 passent par un pointeur que UBSan ne
    # suit pas : seul l'allocateur peut les voir (canari → SIGABRT, page protégée → SIGSEGV).
    c["temoin_ubsan_trap_actif"] = codes[3] == codes[4] == -4
    c["temoin_allocateur_de_garde_actif"] = codes[2] == -11 and codes[5] == -6 and codes[6] == -11
    fuzz = construire("fuzz", [os.path.join(RACINE, "tests", "c", "fuzz.c"), garde]
                      + [os.path.join(ICI, s) for s in SRC])
    r = subprocess.run([fuzz, str(ITERATIONS)], capture_output=True, text=True,
                       env={**os.environ, "OMP_NUM_THREADS": "4"})
    m["code_retour"] = r.returncode
    m["sortie_erreur"] = r.stderr[-2000:]
    try:
        m["compteurs"] = json.loads(r.stdout)
    except ValueError:
        m["compteurs"] = None
    c["aucune_erreur_memoire_ni_comportement_indefini"] = r.returncode in (0, 1)
    c["allers_retours_et_rejets_conformes"] = r.returncode == 0
    out = {"controles": c, "mesures": m}
    sauver("c_fuzz", out)
    return out


if __name__ == "__main__":
    print(json.dumps(run(), indent=1, ensure_ascii=False))
