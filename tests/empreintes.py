# -*- coding: utf-8 -*-
"""Empreintes SHA-256 des sources, des tables, des KAT et des résultats
(reproductibilité, audit externe point 10) → resultats/EMPREINTES.md.

À lancer après `python3 -m tests.run_all` : les empreintes des résultats
désignent alors cette exécution. Un tiers qui rejoue la batterie compare
d'abord les sources (mêmes empreintes), puis les contrôles de
resultats/synthese.json ; les mesures statistiques et les temps varient
d'une exécution à l'autre, les KAT et les certificats non.
    python3 -m tests.empreintes
"""
import glob
import hashlib
import json
import os
import platform
import subprocess

from tests.commun import RACINE, RESULTATS

GROUPES = [
    ("Sources Python", ["sillage/*.py"]),
    ("Sources C et en-têtes générés", ["sillage/c/*.c", "sillage/c/*.h", "sillage/c/Makefile"]),
    ("Tests", ["tests/*.py", "tests/c/*.c", "tests/c/*.h", "tests/c/Makefile"]),
    ("Outils de recherche BRUME-1024q (hors bibliothèque)", ["prototypes/brume_q/b1024/*.c", "prototypes/brume_q/b1024/*.h",
                                                           "prototypes/brume_q/b1024/*.py", "prototypes/brume_q/sat/*.c",
                                                           "prototypes/brume_q/sat/*.py"]),
    ("Certificats BRUME-1024q (C4 ≥ 28 : découpages et complétude)", ["prototypes/brume_q/sat/c4_K28/*"]),
    ("Certificats v0.5 (BRUME-512, historique : pistes de division property)", ["resultats/pistes_division.json",
                                                                               "resultats/pistes_exactes.json"]),
    ("Résultats de la batterie", ["resultats/*.json", "resultats/SYNTHESE.md"]),
    ("Spécification, preuves et rapports", ["docs/*.md", "docs/brume1024/*.md"]),
]
EXCLUS = {"resultats/pistes_division.json", "resultats/pistes_exactes.json"}


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def kat():
    from sillage import brume1024_hash, brume1024_xof, Brume1024, Brume1024P
    k = bytes(range(64))
    n = bytes(range(24))
    c, t = Brume1024("BRUME-1024q", key=k).encrypt(n, b"SILLAGE", aad=b"kat")
    cp, tp = Brume1024P("BRUME-1024qp", key=k).encrypt(n, b"SILLAGE", aad=b"kat")
    return {
        "brume1024_hash(b'abc', 64)": brume1024_hash(b"abc").hex(),
        "brume1024_xof(b'abc', 64)": brume1024_xof(b"abc", 64).hex(),
        "BRUME-1024q AEAD(cle=00..3f, nonce=00..17, aad='kat', 'SILLAGE')": (c + t).hex(),
        "BRUME-1024qp AEAD(cle=00..3f, nonce=00..17, aad='kat', 'SILLAGE')": (cp + tp).hex(),
    }


def main():
    lignes = ["# Empreintes SHA-256 — SILLAGE v0.6", ""]
    try:
        syn = json.load(open(os.path.join(RESULTATS, "synthese.json")))
        ok = sum(sum(v["controles"].values()) for v in syn.values())
        tot = sum(len(v["controles"]) for v in syn.values())
        lignes.append(f"Batterie : {ok}/{tot} contrôles, {len(syn)} tests.")
    except (OSError, KeyError, ValueError):
        pass
    gcc = subprocess.run(["gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    lignes += [f"Python {platform.python_version()}, {gcc}.", "", "## KAT", "", "| Entrée | Sortie |",
               "|---|---|"]
    lignes += [f"| `{e}` | `{s}` |" for e, s in kat().items()]
    for titre, motifs in GROUPES:
        fichiers = sorted({os.path.relpath(f, RACINE) for m in motifs for f in glob.glob(os.path.join(RACINE, m))
                           if os.path.isfile(f)})
        if titre == "Résultats de la batterie":
            # seulement les fichiers de la synthèse en cours (resultats/ garde aussi des sorties d'anciennes versions)
            try:
                noms = set(json.load(open(os.path.join(RESULTATS, "synthese.json"))))
                fichiers = [f for f in fichiers if f not in EXCLUS
                            and (os.path.basename(f)[:-5] in noms or f.endswith("SYNTHESE.md"))]
            except (OSError, ValueError):
                fichiers = [f for f in fichiers if f not in EXCLUS]
        lignes += ["", f"## {titre}", "", "| Fichier | SHA-256 |", "|---|---|"]
        lignes += [f"| `{f}` | `{sha(os.path.join(RACINE, f))}` |" for f in fichiers]
    with open(os.path.join(RESULTATS, "EMPREINTES.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lignes) + "\n")
    print(f"{sum(1 for l in lignes if l.startswith('| `'))} empreintes → resultats/EMPREINTES.md")


if __name__ == "__main__":
    main()
