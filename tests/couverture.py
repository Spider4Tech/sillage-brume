# -*- coding: utf-8 -*-
"""Mesure de couverture de la batterie : quelles lignes de sillage/ (Python et C) ne sont jamais exécutées.

    python3 -m tests.couverture              # toute la batterie, sauf dudect et Valgrind (≈ 1 h 30)
    python3 -m tests.couverture kem sig      # sous-ensemble de run_all

Le dépôt (fichiers suivis par git et caches de resultats/) est copié dans un répertoire temporaire, car les tests
réécrivent resultats/. La batterie y tourne instrumentée :
  - Python : coverage.py, sous-processus compris (sitecustomize + COVERAGE_PROCESS_START) ;
  - C : gcc --coverage -O1, pour la bibliothèque chargée par ctypes (SILLAGE_CFLAGS) et pour les tests natifs
    (CFLAGS de tests/c/Makefile). gcovr fusionne les compteurs de tous les binaires.
c_temps (dudect) et les tests Valgrind sont exclus : l'instrumentation fausserait les mesures de temps, et Valgrind
n'est pas forcément installé. Le rapport va dans resultats/COUVERTURE.md et resultats/couverture.json. Les lignes
qui restent non couvertes y sont listées une à une, avec leur justification connue (EXCEPTIONS).
Dépendances : pip install coverage gcovr.
"""
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from tests.commun import RACINE, RESULTATS

EXCLUS = {"c_temps", "c_sig_valgrind", "c_kem_valgrind"}
CACHES = ["resultats/pistes_division.json", "resultats/pistes_exactes.json", "resultats/cache_trails.json"]

# Lignes non couvertes connues, par fichier et par motif du code de la ligne, avec la raison.
EXCEPTIONS = {
    "sillage/c/sig.c": [
        ("(p->t * p->ep) & 7", "champs a, b, c alignés sur l'octet pour les deux niveaux (t·ep = 176 et 192 bits) ; "
                               "équivalent Python couvert (test_erreurs_api, masques_exactement_les_bits_utiles)"),
        ("phi[i] == rj", "défi r dans F_poly : probabilité 2^-33 par point ; branche Python couverte (test_sig_modele, "
                         "Lemme 6 exhaustif sur GF(256))"),
    ],
}


def copier(dest):
    fichiers = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=RACINE, capture_output=True, check=True).stdout.split(b"\0")
    for f in [x.decode() for x in fichiers if x] + [c for c in CACHES if os.path.exists(os.path.join(RACINE, c))]:
        src, dst = os.path.join(RACINE, f), os.path.join(dest, f)
        if os.path.isfile(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)


def mesurer(noms):
    from tests.run_all import TESTS
    choix = [t[1] for t in TESTS if t[1] not in EXCLUS and (not noms or t[1] in noms)]
    garder = os.environ.get("SILLAGE_COUVERTURE_DOSSIER")      # débogage : copie conservée à cet endroit
    with (contextlib.nullcontext(garder) if garder else tempfile.TemporaryDirectory(prefix="sillage_couverture_")) as d:
        if garder:
            shutil.rmtree(d, ignore_errors=True)
        copier(d)
        os.makedirs(os.path.join(d, ".cov"))
        with open(os.path.join(d, ".coveragerc"), "w") as f:
            f.write(f"[run]\nsource = sillage\nparallel = true\ndata_file = {d}/.cov/data\n")
        with open(os.path.join(d, "sitecustomize.py"), "w") as f:
            f.write("import coverage\ncoverage.process_startup()\n")
        drapeaux = "-O1 --coverage -fprofile-update=atomic"
        env = dict(os.environ, PYTHONPATH=d, COVERAGE_PROCESS_START=os.path.join(d, ".coveragerc"),
                   SILLAGE_CFLAGS=drapeaux, CFLAGS=f"{drapeaux} -march=native -fopenmp -Wall -Wextra")
        t0 = time.time()
        r = subprocess.run([sys.executable, "-m", "tests.run_all", *choix], cwd=d, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        duree = time.time() - t0
        synthese = r.stdout.split("\n")[2] if r.stdout else ""
        subprocess.run([sys.executable, "-m", "coverage", "combine", "--data-file", f"{d}/.cov/data", f"{d}/.cov"],
                       cwd=d, capture_output=True)
        py = json.loads(subprocess.run([sys.executable, "-m", "coverage", "json", "--data-file", f"{d}/.cov/data", "-o", "-"],
                                       cwd=d, capture_output=True, text=True).stdout)
        cj = os.path.join(d, "gcovr.json")
        subprocess.run(["gcovr", "--root", d, "--filter", "sillage/c/", "--gcov-ignore-parse-errors=suspicious_hits.warn",
                        "--merge-mode-functions=separate", "--json", cj], cwd=d, capture_output=True)
        cc = json.load(open(cj)) if os.path.exists(cj) else {"files": []}
        sources = {}
        for f in cc["files"]:
            sources[f["file"]] = open(os.path.join(d, f["file"]), encoding="utf-8").read().split("\n")
        for f in py["files"]:
            sources[f] = open(os.path.join(d, f), encoding="utf-8").read().split("\n")
    return choix, duree, synthese, py, cc, sources


def justification(fichier, code):
    for motif, raison in EXCEPTIONS.get(fichier, []):
        if motif in code:
            return raison
    return None


def rapport(choix, duree, synthese, py, cc, sources):
    lignes, res = [], {"python": {}, "c": {}}
    tot_py = [0, 0]
    for f, v in sorted(py["files"].items()):
        s = v["summary"]
        tot_py[0] += s["covered_lines"]
        tot_py[1] += s["num_statements"]
        manq = [(l, sources[f][l - 1].strip()) for l in v["missing_lines"]]
        res["python"][f] = dict(couvertes=s["covered_lines"], instructions=s["num_statements"], manquantes=manq)
    tot_c, tot_b = [0, 0], [0, 0]
    for f in sorted(cc["files"], key=lambda x: x["file"]):
        ls = [l for l in f["lines"] if not l.get("gcovr/noncode")]
        vues = {}
        for l in ls:                                   # une ligne peut apparaître plusieurs fois (fonctions inline)
            vues[l["line_number"]] = vues.get(l["line_number"], 0) + l["count"]
        br = [b for l in ls for b in l.get("branches", [])]
        couv = sum(1 for v in vues.values() if v > 0)
        tot_c[0] += couv
        tot_c[1] += len(vues)
        tot_b[0] += sum(1 for b in br if b["count"] > 0)
        tot_b[1] += len(br)
        manq = [(n, sources[f["file"]][n - 1].strip()) for n, v in sorted(vues.items()) if v == 0]
        res["c"][f["file"]] = dict(couvertes=couv, lignes=len(vues), manquantes=manq)
    pc = lambda a: f"{100 * a[0] / max(a[1], 1):.1f} %"
    lignes += ["# Couverture de la batterie SILLAGE", "",
               f"Mesure du {time.strftime('%Y-%m-%d %H:%M')} ({round(duree)} s, {len(choix)} tests de run_all ; "
               f"exclus : {', '.join(sorted(EXCLUS))}). Batterie instrumentée : {synthese}", "",
               f"- Python (sillage/) : {tot_py[0]}/{tot_py[1]} instructions, {pc(tot_py)}",
               f"- C (sillage/c/) : {tot_c[0]}/{tot_c[1]} lignes, {pc(tot_c)} ; branches {tot_b[0]}/{tot_b[1]}, {pc(tot_b)}", "",
               "Commande : `python3 -m tests.couverture`. Chaque ligne non couverte est listée ci-dessous, avec sa justification "
               "quand elle est connue (tests/couverture.py, EXCEPTIONS).", ""]
    non_justifiees = 0
    for lang in ("python", "c"):
        lignes += [f"## {'Python' if lang == 'python' else 'C'}", "", "| Fichier | Couvert | Total |", "|---|---|---|"]
        for f, v in res[lang].items():
            lignes.append(f"| `{f}` | {v['couvertes']} | {v.get('instructions', v.get('lignes'))} |")
        lignes.append("")
        for f, v in res[lang].items():
            if not v["manquantes"]:
                continue
            lignes += [f"### `{f}`", ""]
            for n, code in v["manquantes"]:
                j = justification(f, code)
                non_justifiees += j is None
                lignes.append(f"- l. {n} : `{code[:100]}`" + (f" — {j}" if j else ""))
            lignes.append("")
    res.update(python_pct=round(100 * tot_py[0] / max(tot_py[1], 1), 2), c_pct=round(100 * tot_c[0] / max(tot_c[1], 1), 2),
               c_branches_pct=round(100 * tot_b[0] / max(tot_b[1], 1), 2), non_justifiees=non_justifiees,
               tests=choix, synthese=synthese)
    lignes.insert(6, f"- Lignes non couvertes sans justification : {non_justifiees}")
    with open(os.path.join(RESULTATS, "COUVERTURE.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lignes) + "\n")
    with open(os.path.join(RESULTATS, "couverture.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    return res


if __name__ == "__main__":
    for outil in ("coverage", "gcovr"):
        if shutil.which(outil) is None and outil == "gcovr":
            sys.exit("gcovr absent : pip install gcovr")
    res = rapport(*mesurer(sys.argv[1:]))
    print(f"Python {res['python_pct']} %, C {res['c_pct']} % (branches {res['c_branches_pct']} %), "
          f"{res['non_justifiees']} lignes non couvertes sans justification → resultats/COUVERTURE.md")
