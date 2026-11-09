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
    ("test_aead", "aead", "Modes BRUME"),
    ("test_te", "te", "Modes BRUME"),
    ("test_hachage", "hachage", "Modes BRUME"),
    ("test_mode_aead", "mode_aead", "Modes BRUME"),
    ("test_aead_modele", "aead_modele", "Modes BRUME"),
    ("test_hachage_arbre", "hachage_arbre", "Modes BRUME"),
    ("test_indiff_arbre", "indiff_arbre", "Modes BRUME"),
    ("test_aead_parallele", "aead_parallele", "Modes BRUME"),
    ("test_branch_exact", "branch_exact", "Permutation BRUME"),
    ("test_banc_cryptanalyse", "banc_cryptanalyse", "Permutation BRUME"),
    ("test_diff_lin_empirique", "diff_lin_empirique", "Permutation BRUME"),
    ("test_cycles", "cycles", "Permutation BRUME"),
    ("test_beam_trails", "beam_trails", "Permutation BRUME"),
    ("test_integral_degre", "integral_degre", "Permutation BRUME"),
    ("test_symetries_invariants", "symetries_invariants", "Permutation BRUME"),
    ("test_hull", "hull", "Permutation BRUME"),
    ("test_division_property", "division_property", "Permutation BRUME"),
    ("test_diffusion_stats", "diffusion_stats", "Permutation BRUME"),
    ("test_kem", "kem", "Sillage-KEM"),
    ("test_kem_lemme3", "kem_lemme3", "Sillage-KEM"),
    ("test_sig", "sig", "Sillage-SIG"),
    ("test_sig_modele", "sig_modele", "Sillage-SIG"),
    ("test_sig_hvzk", "sig_hvzk", "Sillage-SIG"),
    ("test_isd_parametres", "isd_parametres", "Paramètres"),
    ("test_bornes_preuves", "bornes_preuves", "Paramètres"),
    ("test_select_params", "select_params", "Paramètres"),
    ("test_robustesse", "robustesse", "Robustesse"),
    ("test_erreurs_api", "erreurs_api", "Robustesse"),
    ("test_c_impl", "c_impl", "Implémentation C"),
    ("test_c_fuzz", "c_fuzz", "Implémentation C"),
    ("test_c_sig_valgrind", "c_sig_valgrind", "Implémentation C"),
    ("test_c_kem_valgrind", "c_kem_valgrind", "Implémentation C"),
    ("test_api_c", "api_c", "Implémentation C"),
    ("test_c_simd", "c_simd", "Implémentation C"),
    ("test_c_limites", "c_limites", "Implémentation C"),
    ("test_c_integral", "c_integral", "Intensif (C)"),
    ("test_c_diff_lin", "c_diff_lin", "Intensif (C)"),
    ("test_c_sac", "c_sac", "Intensif (C)"),
    ("test_c_statistiques", "c_statistiques", "Intensif (C)"),
    ("test_c_kem_bruit", "c_kem_bruit", "Intensif (C)"),
    ("test_c_cube_init", "c_cube_init", "Intensif (C)"),
    ("test_c_degre", "c_degre", "Intensif (C)"),
    ("test_c_temps", "c_temps", "Intensif (C)"),
    ("test_dp_modele", "dp_modele", "Intensif (C)"),
    ("test_dp_tous_cubes", "dp_tous_cubes", "Intensif (C)"),
    ("test_dp_exact", "dp_exact", "Intensif (C)"),
    ("test_dp_validation", "dp_validation", "Intensif (C)"),
    ("c:revue_c", "revue_c", "Implémentation C"),
    ("c:structure_miss", "structure_miss", "Intensif (C)"),
    ("c:isd_reel", "isd_reel", "Intensif (C)"),
    ("c:isd_comparaison", "isd_comparaison", "Intensif (C)"),
    ("c:diffusion_support", "diffusion_support", "Intensif (C)"),
    ("c:kem_distributions", "kem_distributions", "Intensif (C)"),
    ("c:h1p_fourier", "h1p_fourier", "Intensif (C)"),
    ("c:invariants", "invariants", "Intensif (C)"),
    ("c:kem_rejet", "kem_rejet", "Intensif (C)"),
    ("test_kem_theta", "kem_theta", "Intensif (C)"),
    ("c:brume_gd2", "brume_gd2", "Intensif (C)"),
    ("c:sig_flux", "sig_flux", "Intensif (C)"),
    ("c:sig_kz", "sig_kz", "Intensif (C)"),
    ("c:brume_attaques", "brume_attaques", "Intensif (C)"),
    ("c:mini_brume", "mini_brume", "Intensif (C)"),
    ("c:vole_proto", "vole_proto", "Intensif (C)"),
    ("c:compression_sig", "compression_sig", "Intensif (C)"),
    ("test_brume_algebre", "brume_algebre", "Intensif (C)"),
]
INTENSIF = "Intensif (C)"


INTENSITE = float(os.environ.get("SILLAGE_INTENSITE", "1"))
# Les tests du noyau C (tests/noyau_c.py) suffixent leur fichier de résultats quand SILLAGE_INTENSITE ≠ 1.
AVEC_SUFFIXE = {"c_integral", "c_diff_lin", "c_sac", "c_statistiques", "c_kem_bruit", "c_cube_init", "c_degre"}


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
    tete = (f"# Synthèse de la batterie SILLAGE v0.4\n\n"
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
