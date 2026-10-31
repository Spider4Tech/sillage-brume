# -*- coding: utf-8 -*-
"""Sillage-KEM C sous Valgrind : erreurs mémoire et fuites, absence de branchement ou
d'accès mémoire dépendant d'un secret (ctgrind, tests/c/kem_valgrind.c), témoin détecté.
Même compilation que tests/test_c_sig_valgrind.py : sans VPCLMULQDQ, que Valgrind ne décode
pas ; le cas de base de Karatsuba à VPCLMULQDQ est couvert par dudect (tests/c/temps.c)."""
import os
import shutil
import subprocess

from tests.commun import sauver, RACINE
from tests.test_c_sig_valgrind import CFLAGS, LIB, valgrind

OUT = os.path.join(RACINE, "tests", "c", "build", "kem_valgrind")


def construire():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    obj = OUT + "_commun.o"
    subprocess.run(["gcc", *CFLAGS, "-Dsl_alea=sl_alea_systeme", "-c", "-o", obj, os.path.join(LIB, "commun.c")], check=True)
    subprocess.run(["gcc", *CFLAGS, "-o", OUT, os.path.join(RACINE, "tests", "c", "kem_valgrind.c"), obj,
                    os.path.join(LIB, "brume512.c"), os.path.join(LIB, "brume512_avx2.c"), "-lm"], check=True)


def run():
    c, m = {}, {}
    if not shutil.which("valgrind"):
        out = {"controles": {"valgrind_disponible": False}, "mesures": {}}
        sauver("c_kem_valgrind", out)
        return out
    construire()
    rc, e_mem, sortie, trace = valgrind("memoire", fuites=True, exe=OUT)
    m["memoire"] = {"erreurs": e_mem, "sortie": sortie}
    c["memoire_sans_erreur_ni_fuite"] = rc == 0 and e_mem == 0 and sortie.count("OK") == 2
    rc2, e_sec, sortie2, trace2 = valgrind("secret", exe=OUT)
    m["secret"] = {"erreurs": e_sec, "sortie": sortie2}
    c["aucun_branchement_ni_acces_dependant_d_un_secret"] = rc2 == 0 and e_sec == 0 and sortie2.count("secret retrouvé") == 2
    if e_mem or e_sec:
        m["trace"] = trace if e_mem else trace2
    rc3, e_tem, _, _ = valgrind("temoin", exe=OUT)
    m["temoin_erreurs"] = e_tem
    c["temoin_non_constant_time_detecte"] = rc3 == 0 and e_tem > 1   # accès indexé, puis branchement sur sk
    out = {"controles": c, "mesures": m}
    sauver("c_kem_valgrind", out)
    return out


if __name__ == "__main__":
    print(run())
