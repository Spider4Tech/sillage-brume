# -*- coding: utf-8 -*-
"""Sillage-SIG v0.5 (sillage/c/vole.c) sous Valgrind, par le banc prototypes/vole/vole_proto.c (même source) :
1. ctgrind : positions secrètes marquées non initialisées, keygen et signature complets des profils VOLE-128 et VOLE-256
   (contraintes de paires comprises) : aucun branchement ni accès mémoire dépendant d'un secret ; témoin (branchement sur
   une position) détecté.
2. memcheck : injection d'échecs (chaque allocation et chaque tirage de l'API, tour à tour) et fuzz du vérifieur sur le
   modèle réduit, sans erreur mémoire ni fuite.
Compilé en -O3 sans -march=native (Valgrind ne décode pas AVX-512), un thread."""
import os
import re
import shutil
import subprocess

from tests.commun import sauver, RACINE

LIB = os.path.join(RACINE, "sillage", "c")
VOLE = os.path.join(RACINE, "prototypes", "vole")
OUT = os.path.join(RACINE, "tests", "c", "build", "vole_valgrind")
CFLAGS = ["-O3", "-g", "-mavx2", "-mpclmul", "-fopenmp", "-I", VOLE, "-I", os.path.join(RACINE, "tests", "c"), "-I", LIB]


def construire(ct):
    exe = OUT + ("_ct" if ct else "_mem")
    subprocess.run(["gcc", *CFLAGS, *(["-DSL_VALGRIND"] if ct else []), "-o", exe, os.path.join(VOLE, "vole_proto.c"),
                    os.path.join(LIB, "commun.c"), os.path.join(LIB, "brume512.c"), os.path.join(LIB, "brume512_avx2.c"), "-lm"],
                   check=True)
    return exe


def valgrind(exe, args, fuites=False):
    cmd = ["valgrind", "--quiet", "--error-exitcode=0", "--error-limit=no"]
    if fuites:
        cmd += ["--leak-check=full", "--show-leak-kinds=definite,indirect,possible"]
    r = subprocess.run(cmd + ["--log-fd=2", exe, *args], capture_output=True, text=True, cwd=RACINE,
                       env={**os.environ, "OMP_NUM_THREADS": "1"})
    erreurs = len(re.findall(r"^==\d+== (?:Conditional jump|Use of uninit|Invalid |Syscall param|[\d,]+ (?:\(.*\) )?bytes in .* lost)",
                             r.stderr, re.M))
    return r.returncode, erreurs, r.stdout[-800:], r.stderr[-1500:]


def run():
    c, m = {}, {}
    if not shutil.which("valgrind"):
        out = {"controles": {"valgrind_disponible": False}, "mesures": {}}
        sauver("c_vole_valgrind", out)
        return out
    ct, mem = construire(True), construire(False)
    for nom, args in (("ct_128", ["--ct", "128"]), ("ct_256", ["--ct", "256"])):
        rc, e, so, tr = valgrind(ct, args)
        m[nom] = {"erreurs": e, "sortie": so.strip()}
        c[f"{nom}_aucun_branchement_ni_acces_dependant_d_un_secret"] = rc == 0 and e == 0 and "acceptée" in so
        if e:
            m[nom + "_trace"] = tr
    rc, e, _, _ = valgrind(ct, ["--ct-temoin"])
    m["temoin_erreurs"] = e
    c["temoin_non_constant_time_detecte"] = e > 0
    rc, e, so, tr = valgrind(mem, ["--injection"], fuites=True)
    m["injection"] = {"erreurs": e, "sortie": so.strip()}
    c["injection_d_echecs_sans_erreur_memoire_ni_fuite"] = rc == 0 and e == 0
    rc, e, so, tr = valgrind(mem, ["--fuzz", "300", "5"], fuites=True)
    m["fuzz"] = {"erreurs": e, "sortie": so.strip()}
    c["fuzz_du_verifieur_sans_erreur_memoire_ni_fuite"] = rc == 0 and e == 0 and "0 altérations acceptées" in so
    out = {"controles": c, "mesures": m}
    sauver("c_vole_valgrind", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
