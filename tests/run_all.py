# -*- coding: utf-8 -*-
"""Orchestrateur de la batterie complète.

    python3 -m tests.run_all            # tout (parallèle)
    python3 -m tests.run_all -j 4       # 4 processus
    python3 -m tests.run_all aead kem   # sous-ensemble
    SILLAGE_INTENSITE=8 python3 -m tests.run_all c_integral   # plus loin

Chaque test écrit resultats/<nom>.json (clé « controles » : booléens) et son
journal dans resultats/logs/<nom>.log ; la synthèse va dans
resultats/SYNTHESE.md et resultats/synthese.json. Les tests « Intensif (C) »
(noyau OpenMP, tests/c/noyau.c) occupent tous les cœurs : ils passent après
les tests Python, l'un après l'autre.
"""
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from tests.commun import RACINE, RESULTATS

# (module, fichier de résultats, thème) — ordre = ordre de la synthèse
TESTS = [
    ("test_fonctionnel", "fonctionnel", "Fonctionnel"),
    ("c:brume1024_api", "brume1024_api", "BRUME-1024q : modes"),
    ("c:brume1024_api_portable", "brume1024_api_portable", "BRUME-1024q : modes"),
    ("c:brume1024", "brume1024", "BRUME-1024q : modes"),
    ("test_b1024_seconde_implementation", "b1024_seconde_implementation", "BRUME-1024q : modes"),
    ("test_b1024_preuves", "b1024_preuves", "BRUME-1024q : modes"),
    ("test_b1024_certificats", "b1024_certificats", "BRUME-1024q : permutation"),
    ("test_b1024_structure", "b1024_structure", "BRUME-1024q : permutation"),
    ("test_kem", "kem", "Sillage-KEM"),
    ("test_kem_lemme3", "kem_lemme3", "Sillage-KEM"),
    ("test_sig", "sig", "Sillage-SIG"),
    ("test_sig_modele", "sig_modele", "Sillage-SIG"),
    ("test_sig_hvzk", "sig_hvzk", "Sillage-SIG"),
    ("test_vole", "vole", "Sillage-SIG v0.5 (VOLE)"),
    ("test_vole_kz", "vole_kz", "Sillage-SIG v0.5 (VOLE)"),
    ("test_isd_parametres", "isd_parametres", "Paramètres"),
    ("test_bornes_preuves", "bornes_preuves", "Paramètres"),
    ("test_robustesse", "robustesse", "Robustesse"),
    ("test_erreurs_api", "erreurs_api", "Robustesse"),
    ("test_c_impl", "c_impl", "Implémentation C"),
    ("test_c_fuzz", "c_fuzz", "Implémentation C"),
    ("test_c_sig_valgrind", "c_sig_valgrind", "Implémentation C"),
    ("test_c_kem_valgrind", "c_kem_valgrind", "Implémentation C"),
    ("test_c_vole_valgrind", "c_vole_valgrind", "Implémentation C"),
    ("test_c_brume1024_valgrind", "c_brume1024_valgrind", "Implémentation C"),
    ("test_api_c", "api_c", "Implémentation C"),
    ("test_c_limites", "c_limites", "Implémentation C"),
    ("c:revue_c", "revue_c", "Implémentation C"),
    ("test_b1024_statistiques", "b1024_statistiques", "Intensif (C)"),
    ("test_b1024_etudes", "b1024_etudes", "Intensif (C)"),
    ("c:temps1024", "temps1024", "Intensif (C)"),
    ("test_c_kem_bruit", "c_kem_bruit", "Intensif (C)"),
    ("test_c_temps", "c_temps", "Intensif (C)"),
    ("test_c_vole_temps", "c_vole_temps", "Intensif (C)"),
    ("c:isd_reel", "isd_reel", "Intensif (C)"),
    ("c:isd_comparaison", "isd_comparaison", "Intensif (C)"),
    ("c:kem_distributions", "kem_distributions", "Intensif (C)"),
    ("c:h1p_fourier", "h1p_fourier", "Intensif (C)"),
    ("c:kem_rejet", "kem_rejet", "Intensif (C)"),
    ("test_kem_theta", "kem_theta", "Intensif (C)"),
    ("c:sig_flux", "sig_flux", "Intensif (C)"),
    ("c:sig_kz", "sig_kz", "Intensif (C)"),
    ("c:vole_proto", "vole_proto", "Intensif (C)"),
    ("c:compression_sig", "compression_sig", "Intensif (C)"),
]
INTENSIF = "Intensif (C)"


INTENSITE = float(os.environ.get("SILLAGE_INTENSITE", "1"))
# Les tests du noyau C (tests/noyau_c.py) suffixent leur fichier de résultats quand SILLAGE_INTENSITE ≠ 1.
AVEC_SUFFIXE = {"c_kem_bruit"}


def fichier_resultat(nom):
    suf = "" if INTENSITE == 1 or nom not in AVEC_SUFFIXE else f"_x{INTENSITE:g}"
    return os.path.join(RESULTATS, nom + suf + ".json")


def lancer(mod, res):
    """Test Python (tests/<mod>.py) ou, si mod = « c:<nom> », test C natif
    (tests/c/<nom>.c, compilé par tests/c/Makefile, qui écrit lui-même
    resultats/<nom>.json). Le fichier de résultats d'un run précédent est effacé avant le lancement : un test qui
    se termine sans l'écrire ne peut plus être compté sur des contrôles périmés."""
    logs = os.path.join(RESULTATS, "logs")
    os.makedirs(logs, exist_ok=True)
    try:
        os.remove(fichier_resultat(res))
    except FileNotFoundError:
        pass
    t0 = time.time()
    nom = mod[2:] if mod.startswith("c:") else mod
    with open(os.path.join(logs, nom + ".log"), "w", encoding="utf-8") as f:
        if mod.startswith("c:"):
            r = subprocess.run(["make", "-s", "-C", os.path.join("tests", "c"), f"build/{nom}"], cwd=RACINE,
                               stdout=f, stderr=subprocess.STDOUT)
            if r.returncode == 0:
                r = subprocess.run([os.path.join("tests", "c", "build", nom)], cwd=RACINE,
                                   stdout=f, stderr=subprocess.STDOUT)
        else:
            r = subprocess.run([sys.executable, "-m", f"tests.{mod}"], cwd=RACINE,
                               stdout=f, stderr=subprocess.STDOUT)
    return mod, r.returncode, round(time.time() - t0, 1)


def main():
    args = sys.argv[1:]
    jobs = 6
    if "-j" in args:
        i = args.index("-j")
        jobs = int(args[i + 1])
        del args[i:i + 2]
    choix = [t for t in TESTS if not args or t[1] in args or t[0] in args]
    t0 = time.time()
    with ThreadPoolExecutor(jobs) as ex:
        runs = {mod: (rc, dt) for mod, rc, dt in
                ex.map(lambda t: lancer(t[0], t[1]), [t for t in choix if t[2] != INTENSIF])}
    for mod, nom, _ in (t for t in choix if t[2] == INTENSIF):
        _, rc, dt = lancer(mod, nom)
        runs[mod] = (rc, dt)
    synth, lignes, echecs = {}, [], []
    theme = None
    for mod, nom, th in choix:
        rc, dt = runs[mod]
        try:
            ctrl = json.load(open(fichier_resultat(nom)))["controles"]
        except (OSError, KeyError, ValueError):
            ctrl = {"execution": False}
        if not ctrl:                                   # un test sans contrôle ne réussit pas par défaut
            ctrl = {"au_moins_un_controle": False}
        if rc != 0:
            ctrl = {**ctrl, "execution_sans_erreur": False}
        ko = [k for k, v in ctrl.items() if v is not True]
        echecs += [f"{nom}.{k}" for k in ko]
        synth[nom] = {"theme": th, "duree_s": dt, "code_retour": rc,
                      "controles": ctrl, "echecs": ko}
        if th != theme:
            lignes.append(f"\n## {th}\n\n| Test | Contrôles | Durée | Statut |\n|---|---|---|---|")
            theme = th
        lignes.append(f"| `{nom}` | {len(ctrl) - len(ko)}/{len(ctrl)} | {dt} s | "
                      f"{'OK' if not ko else 'ÉCHEC : ' + ', '.join(ko)} |")
    total = sum(len(s["controles"]) for s in synth.values())
    tete = (f"# Synthèse de la batterie SILLAGE v0.6\n\n"
            f"{total - len(echecs)}/{total} contrôles réussis — "
            f"{len(choix)} tests — {round(time.time() - t0)} s "
            f"({time.strftime('%Y-%m-%d %H:%M')}).\n\n"
            f"Détails : `resultats/<test>.json`, journaux : `resultats/logs/`.\n")
    with open(os.path.join(RESULTATS, "SYNTHESE.md"), "w", encoding="utf-8") as f:
        f.write(tete + "\n".join(lignes) + "\n")
    with open(os.path.join(RESULTATS, "synthese.json"), "w", encoding="utf-8") as f:
        json.dump(synth, f, ensure_ascii=False, indent=1)
    print(tete + "\n".join(lignes))
    sys.exit(1 if echecs else 0)


if __name__ == "__main__":
    main()
