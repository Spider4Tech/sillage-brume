# -*- coding: utf-8 -*-
"""Tableau comparatif (Markdown) des sorties de bench_hachage : SHAKE256, BRUME-1024q c = 384, c = 512.
    python3 comparer.py build > BENCH.md"""
import json
import os
import platform
import subprocess
import sys

d = sys.argv[1]
J = {k: json.load(open(os.path.join(d, k + ".json"))) for k in ("shake", "c384", "c512", "compter_c384", "compter_c512")}
S, A, B = J["shake"], J["c384"], J["c512"]


def cpu():
    try:
        for ligne in open("/proc/cpuinfo"):
            if ligne.startswith("model name"):
                return ligne.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def cc():
    try:
        return subprocess.run(["gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    except OSError:
        return "?"


def ligne(nom, s, a, b, unite, pa="", pb="", plus_grand_mieux=False):
    def r(x):
        q = (s / x) if plus_grand_mieux else (x / s)
        return "×%.2f" % q
    return "| %s | %s %s | %s %s | %s | %s %s | %s | %s | %s |" % (
        nom, fmt(s), unite, fmt(a), unite, r(a), fmt(b), unite, r(b), pa, pb)


def fmt(x):
    return "%.0f" % x if x >= 100 else "%.2f" % x if x >= 1 else "%.3f" % x


ok = all(j["ok"] for j in J.values())
print("# Bench comparatif : KEM et signatures avec BRUME-1024q à la place de SHAKE256\n")
print("Prototype `prototypes/brume_hachage` (hors suite). Même code du KEM et des signatures, seule la couche de hachage "
      "change (README.md). Mesuré le %s, %s, %s, %d threads pour les colonnes « tous les cœurs » ; "
      "sinon un cœur. Tous les allers-retours vérifiés, une signature et un chiffré altérés refusés : **%s**. "
      "À c = 384, l'éponge du prototype est égale bit à bit à `sl_xof` de la bibliothèque : **%s**.\n"
      % (subprocess.run(["date", "+%d/%m/%Y"], capture_output=True, text=True).stdout.strip(), cpu(), cc(), S["threads"],
         "oui" if ok else "NON", "oui" if A.get("eponge_egale_sl_xof") else "NON"))
print("Le facteur est le temps de la variante BRUME divisé par celui de SHAKE256 (×2 = deux fois plus lent) ; pour les "
      "débits, SHAKE256 divisé par BRUME. « Perm. » : permutations BRUME-1024q par opération.\n")
print("| Opération | SHAKE256 | BRUME c = 384 | facteur | BRUME c = 512 | facteur | Perm. c = 384 | Perm. c = 512 |")
print("|---|---|---|---|---|---|---|---|")
p, pa, pb = S["primitives"], A["primitives"], B["primitives"]
print(ligne("Hachage 64 o → 32 o", p["hash_64o_vers_32o_us"], pa["hash_64o_vers_32o_us"], pb["hash_64o_vers_32o_us"], "µs",
            J["compter_c384"]["primitives"]["permutations_hash_64o"], J["compter_c512"]["primitives"]["permutations_hash_64o"]))
for cle, nom in (("absorption_mo_s", "Absorption (64 Kio)"), ("extraction_mo_s", "Extraction"), ("flux_mo_s", "Flux d'entiers (mode compteur)")):
    print(ligne(nom, p[cle], pa[cle], pb[cle], "Mo/s", plus_grand_mieux=True))
k, ka, kb = (x["kem"]["Sillage-256"] for x in (S, A, B))
kca, kcb = (J[n]["kem"]["Sillage-256"]["permutations"] for n in ("compter_c384", "compter_c512"))
for cle, nom, pc in (("keygen_ms", "KEM-256 keygen", "keygen"), ("encaps_ms", "KEM-256 encaps", "encaps"),
                     ("decaps_ms", "KEM-256 decaps", "decaps"), ("encaps_pk_changeante_ms", "KEM-256 encaps, pk changeante", None)):
    print(ligne(nom, k[cle], ka[cle], kb[cle], "ms", kca[pc] if pc else "", kcb[pc] if pc else ""))
for prof in ("VOLE-256", "VOLE-256f"):
    v, va, vb = (x["vole"][prof] for x in (S, A, B))
    vca, vcb = (J[n]["vole"][prof]["permutations"] for n in ("compter_c384", "compter_c512"))
    for cle, nom, pc in (("keygen_ms", "keygen", None), ("sign_ms", "sign", "sign"), ("verify_ms", "verify", "verify"),
                         ("sign_tous_les_coeurs_ms", "sign, tous les cœurs", None),
                         ("verify_tous_les_coeurs_ms", "verify, tous les cœurs", None)):
        print(ligne("%s %s" % (prof, nom), v[cle], va[cle], vb[cle], "ms", vca[pc] if pc else "", vcb[pc] if pc else ""))
for niv in ("Sillage-SIG-128", "Sillage-SIG-256"):
    g, ga, gb = (x["sig_v04"][niv] for x in (S, A, B))
    for cle, nom in (("keygen_ms", "keygen"), ("sign_ms", "sign"), ("verify_ms", "verify"), ("sign_tous_les_coeurs_ms", "sign, tous les cœurs")):
        print(ligne("%s (v0.4) %s" % (niv, nom), g[cle], ga[cle], gb[cle], "ms"))
print("\nTailles (inchangées par la variante) : VOLE-256 %d o, VOLE-256f %d o, SIG-128 v0.4 %d o, SIG-256 v0.4 %d o."
      % (S["vole"]["VOLE-256"]["sig"], S["vole"]["VOLE-256f"]["sig"], S["sig_v04"]["Sillage-SIG-128"]["sig"],
         S["sig_v04"]["Sillage-SIG-256"]["sig"]))
