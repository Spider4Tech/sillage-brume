# -*- coding: utf-8 -*-
"""Les noyaux SIMD ne changent aucune sortie : tests/c/simd_conformite.c doit afficher exactement la même chose en AVX2,
sans SIMD et en NEON. NEON tourne sous qemu-aarch64 quand la chaîne croisée est là : cela vérifie les sorties, pas le temps
constant ni le débit, qui demandent une vraie machine ARM."""
import os
import shutil
import subprocess

from tests.commun import RACINE, sauver

LIB = os.path.join(RACINE, "sillage", "c")
SRC = [os.path.join(LIB, f) for f in ("commun.c", "brume512.c", "brume512_avx2.c", "kem.c", "sig.c")]
PROG = os.path.join(RACINE, "tests", "c", "simd_conformite.c")
BUILD = os.path.join(RACINE, "tests", "c", "build")


def sortie(nom, cc, options, lanceur=()):
    exe = os.path.join(BUILD, nom)
    subprocess.run([cc, "-O2", "-fopenmp", *options, "-I", LIB, "-o", exe, PROG, *SRC, "-lm"], check=True,
                   stderr=subprocess.DEVNULL)
    return subprocess.run([*lanceur, exe], capture_output=True, text=True, check=True).stdout


def run():
    os.makedirs(BUILD, exist_ok=True)
    avx2 = sortie("simd_avx2", "gcc", ["-march=native"])
    c = {"sortie_non_vide": avx2.count("\n") > 70,
         "repli_sans_simd_identique": sortie("simd_sans", "gcc", ["-mno-avx2"]) == avx2}
    m = {"lignes_comparees": avx2.count("\n")}
    if shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"):
        c["neon_sous_qemu_identique"] = sortie("simd_neon", "aarch64-linux-gnu-gcc", ["-static", "-march=armv8-a+crypto"],
                                               ["qemu-aarch64"]) == avx2
        m["neon"] = "sous qemu : sorties seulement"
    else:
        m["neon"] = "non testé : aarch64-linux-gnu-gcc ou qemu-aarch64 absent"
    sauver("c_simd", {"controles": c, "mesures": m})
    print(c, m)


if __name__ == "__main__":
    run()
