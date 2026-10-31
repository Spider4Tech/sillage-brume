# -*- coding: utf-8 -*-
"""Sillage-SIG C sous Valgrind : erreurs mémoire et fuites (chemins valides et
entrées malformées), absence de branchement ou d'accès mémoire dépendant d'un
secret (méthode ctgrind, tests/c/sig_valgrind.c), avec un témoin qui doit être
détecté. Compilé en -O3 comme la bibliothèque, mais sans -march=native :
Valgrind ne décode pas AVX-512."""
import os
import re
import shutil
import subprocess

from tests.commun import sauver, RACINE

LIB = os.path.join(RACINE, "sillage", "c")
OUT = os.path.join(RACINE, "tests", "c", "build", "sig_valgrind")
CFLAGS = ["-O3", "-g", "-mavx2", "-mpclmul", "-fopenmp", "-DSL_VALGRIND", "-I", LIB]


def construire():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    obj = OUT + "_commun.o"
    subprocess.run(["gcc", *CFLAGS, "-Dsl_alea=sl_alea_systeme", "-c", "-o", obj, os.path.join(LIB, "commun.c")], check=True)
    subprocess.run(["gcc", *CFLAGS, "-o", OUT, os.path.join(RACINE, "tests", "c", "sig_valgrind.c"), obj,
                    os.path.join(LIB, "brume512.c"), os.path.join(LIB, "brume512_avx2.c"), "-lm"], check=True)


def valgrind(mode, fuites=False, exe=OUT):
    cmd = ["valgrind", "--quiet", "--error-exitcode=0", "--error-limit=no"]
    if fuites:
        cmd += ["--leak-check=full", "--show-leak-kinds=definite,indirect,possible"]   # le cache de H reste atteignable
    r = subprocess.run(cmd + ["--log-fd=2", exe, mode], capture_output=True, text=True,
                       env={**os.environ, "OMP_NUM_THREADS": "1"})
    erreurs = len(re.findall(r"^==\d+== (?:Conditional jump|Use of uninit|Invalid |Syscall param|[\d,]+ (?:\(.*\) )?bytes in .* lost)",
                             r.stderr, re.M))
    return r.returncode, erreurs, r.stdout, r.stderr[-1500:]


def run():
    c, m = {}, {}
    if not shutil.which("valgrind"):
        out = {"controles": {"valgrind_disponible": False}, "mesures": {}}
        sauver("c_sig_valgrind", out)
        return out
    construire()
    rc, e_mem, sortie, trace = valgrind("memoire", fuites=True)
    m["memoire"] = {"erreurs": e_mem, "sortie": sortie}
    c["memoire_sans_erreur_ni_fuite"] = rc == 0 and e_mem == 0 and sortie.count("OK") == 2
    rc2, e_sec, sortie2, trace2 = valgrind("secret")
    m["secret"] = {"erreurs": e_sec, "sortie": sortie2}
    c["aucun_branchement_ni_acces_dependant_d_un_secret"] = (rc2 == 0 and e_sec == 0 and sortie2.count("longueur") == 2
                                                             and "INVALIDE" not in sortie2)
    if e_mem or e_sec:
        m["trace"] = (trace if e_mem else trace2)
    rc3, e_tem, _, _ = valgrind("temoin")
    m["temoin_erreurs"] = e_tem
    c["temoin_non_constant_time_detecte"] = rc3 == 0 and e_tem > 0
    out = {"controles": c, "mesures": m}
    sauver("c_sig_valgrind", out)
    return out


if __name__ == "__main__":
    print(run())
