# -*- coding: utf-8 -*-
"""Campagne de nuit, volet cryptanalyse de BRUME et modèles de preuve (./rundenuit.sh).
    python3 -m tests.nuit_brume <budget_s> [--reprise]   → resultats/nuit_brume.{json,md}, réécrits après chaque étape.
--reprise repart du JSON existant et saute les étapes déjà écrites ; seule l'étape interrompue est recommencée.
Étapes, chacune avec sa part du budget : boomerang et impossibles (C), modèle exact mini-BRUME (C), activité certifiée
(CP-SAT), récupération d'état par SAT, pistes monomiales sur 32 bits (annulations), attaques sur modèles réduits de la
signature et de l'AEAD à plus grande échelle. Un solveur qui n'a pas fini est compté comme indécis, jamais comme un résultat."""
import json
import multiprocessing as mp
import os
import random
import subprocess
import sys
import time

from pysat.solvers import Cadical153

from tests.commun import RACINE, RESULTATS, sauver
from tests import test_brume_algebre as T

NPROC = os.cpu_count() or 4


def _c(nom, *args, temps=None):
    """Test C natif, résultats relus ; None s'il dépasse son temps ou échoue. Le JSON précédent est retiré d'abord :
    un programme qui meurt ne peut pas faire passer un ancien résultat pour le sien."""
    chemin = os.path.join(RESULTATS, nom + ".json")
    if os.path.exists(chemin):
        os.remove(chemin)
    try:
        r = subprocess.run([os.path.join("tests", "c", "build", nom), *map(str, args)], cwd=RACINE, timeout=temps,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0 or not os.path.exists(chemin):
        return None
    return json.load(open(chemin, encoding="utf-8"))


def boomerang(budget):
    t0 = time.time()
    if _c("brume_attaques", 16, 4, temps=budget * 0.5) is None:
        return None, 16
    tb = max(time.time() - t0, 0.5)                       # 2^16 × 4 quartets, partie fixe comprise : estimation prudente
    lq = 16
    while lq < 34 and tb * 2 ** (lq + 1 - 16) * 8 < budget * 0.8:
        lq += 1
    return _c("brume_attaques", lq, 32, temps=budget), lq


def mini(budget):
    t0 = time.time()
    if _c("mini_brume", 1, 1, 0, temps=budget * 0.25) is None:
        return None, 0, 0
    t24 = max(time.time() - t0, 1)
    t0 = time.time()
    if _c("mini_brume", 0, 1, 1, temps=budget * 0.25) is None:
        return None, 0, 0
    t32 = max(time.time() - t0, 1)
    i24 = max(1, min(60, int(budget * 0.4 / (2 * t24))))
    i32 = max(1, min(40, int(budget * 0.4 / t32)))
    return _c("mini_brume", i24, 2, i32, temps=budget * 1.5), i24, i32


def _une_piste(inst, R, a, b, conn):
    cl = T._cnf_piste(inst, R, a, b)
    if cl is None:
        conn.send(False)
        return
    with Cadical153(bootstrap_with=cl) as s:
        conn.send(s.solve())


def pistes(instances, budget, limite=900):
    """Sommes réelles nulles partout, à la portée réelle : une piste y serait une annulation."""
    fin = time.time() + budget
    rng = random.Random(0xA11)
    res = dict(requetes=0, sans_piste=0, avec_piste=0, indecises=0, annulations=[])
    act = []
    cibles = [i for i in instances if i["nibbles"] == 8] or instances
    while (time.time() < fin - limite) or act:
        while len(act) < max(1, NPROC // 2) and time.time() < fin - limite:
            inst = rng.choice(cibles)
            nz = inst["bits_non_nuls_par_tour"]
            R = next(r for r in range(len(nz)) if nz[r])          # R tours : nz[R − 1] = 0, portée réelle
            n = 4 * inst["nibbles"]
            a, b = rng.randrange(n), rng.randrange(n)
            recoit, envoie = mp.Pipe(False)
            p = mp.Process(target=_une_piste, args=(inst, R, a, b, envoie))
            p.start()
            envoie.close()                                        # ainsi, un fils mort ferme le tube : recv lève EOFError
            act.append((p, recoit, n, R, a, b, time.time()))
        for e in list(act):
            p, recoit, n, R, a, b, t = e
            if not recoit.poll() and time.time() - t < limite:
                continue
            try:
                v = recoit.recv() if recoit.poll() else None      # dépassement ou fils mort : indécise, jamais un résultat
            except EOFError:
                v = None
            if p.is_alive():
                p.terminate()
            p.join()
            recoit.close()
            act.remove(e)
            res["requetes"] += 1
            res["sans_piste"] += v is False
            res["avec_piste"] += v is True
            res["indecises"] += v is None
            if v is True:
                res["annulations"].append(dict(bits=n, tours=R, i=a, j=b))
        time.sleep(1)
    return res


def ecrire(c, m):
    sauver("nuit_brume", {"controles": c, "mesures": m})
    with open(os.path.join(RESULTATS, "nuit_brume.md"), "w", encoding="utf-8") as f:
        f.write("## Cryptanalyse de BRUME et modèles de preuve (nuit)\n\n| Contrôle | Résultat |\n|---|---|\n")
        for k, v in c.items():
            f.write(f"| `{k}` | {'OK' if v else '**ÉCHEC**'} |\n")
        for k, v in m.items():
            if isinstance(v, str) and v.startswith("non "):       # non terminé, non lancé : jamais un succès
                f.write(f"| `{k}` | **{v.upper()}** |\n")
        f.write("\n```json\n" + json.dumps(m, ensure_ascii=False, indent=1)[:60000] + "\n```\n\n")


def run(budget, reprise=False):
    c, m = {}, {}
    if reprise and os.path.exists(os.path.join(RESULTATS, "nuit_brume.json")):
        d = json.load(open(os.path.join(RESULTATS, "nuit_brume.json"), encoding="utf-8"))
        c, m = d["controles"], d["mesures"]
    debut = time.time() - m.get("secondes", 0)
    reste = lambda: budget - (time.time() - debut)        # noqa: E731

    def point():
        m["secondes"] = round(time.time() - debut)
        ecrire(c, m)

    if not isinstance(m.get("boomerang"), dict):
        r, lq = boomerang(budget * 0.15)
        m["boomerang"] = {"log2_quartets": lq, **r["mesures"]} if r else "non terminé dans son budget"
        if r:
            c.update({f"attaques_{k}": v for k, v in r["controles"].items()})
        point()
    if not isinstance(m.get("mini_brume"), dict):
        r, i24, i32 = mini(budget * 0.2)
        m["mini_brume"] = {"instances_24_bits": i24, "instances_32_bits": i32, **r["mesures"]} if r else "non terminé dans son budget"
        if r:
            c.update({f"mini_{k}": v for k, v in r["controles"].items()})
        point()
    m.setdefault("activite", [])
    for tours in (3, 4, 6, 8):
        if all(a["tours"] != tours for a in m["activite"]):
            m["activite"].append(T.activite(tours, budget * 0.04))
            point()
    par = {a["tours"]: a["borne_basse"] for a in m["activite"]} | {2: 8}
    m["activite_32_tours_certifiee"] = max((32 // k) * b + par.get(32 % k, 0) for k, b in par.items())
    c["activite_32_tours_au_moins_128"] = m["activite_32_tours_certifiee"] >= 128
    point()
    if "recuperation_sat" not in m:
        par_sat = max(1, NPROC // 2)
        m["recuperation_sat"] = T.recuperation_sat((1, 2, 3, 4, 5), (4, 8, 16, 32, 64), max(20, budget * 0.25 * par_sat / 25), par_sat)
        resolus = [x["tours"] for x in m["recuperation_sat"] if x["resolu"] and x["bits_inconnus"] == 256]
        m["recuperation_sat_256_bits_tours"] = max(resolus, default=0)
        c["recuperation_sat_loin_de_32_tours"] = m["recuperation_sat_256_bits_tours"] <= 8
        point()
    chemin = os.path.join(RESULTATS, "mini_brume_instances.json")
    # part fixe : les attaques réduites à grande échelle prennent quelques minutes
    os.environ["SILLAGE_INTENSITE"] = "8"
    for mod, nom in (("test_sig_modele", "sig_modele"), ("test_aead_modele", "aead_modele"), ("test_aead_parallele", "aead_parallele")):
        if isinstance(m.get(nom), dict):
            continue
        if reste() <= 900:
            m[nom] = "non lancé (budget)"
            continue
        chemin_m = os.path.join(RESULTATS, nom + ".json")
        if os.path.exists(chemin_m):
            os.remove(chemin_m)
        r = subprocess.run([sys.executable, "-m", f"tests.{mod}"], cwd=RACINE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        c[f"{nom}_execution_sans_erreur"] = r.returncode == 0 and os.path.exists(chemin_m)
        if os.path.exists(chemin_m):
            d = json.load(open(chemin_m, encoding="utf-8"))
            m[nom] = d["mesures"]
            c.update({f"{nom}_{k}": v for k, v in d["controles"].items()})
        else:
            m[nom] = "non terminé (pas de résultat)"
        point()
    os.environ.pop("SILLAGE_INTENSITE")
    if not isinstance(m.get("pistes_a_la_portee_reelle"), dict):
        if os.path.exists(chemin) and reste() > 120:
            limite = min(900, max(60, reste() / 4))
            m["pistes_a_la_portee_reelle"] = pistes(json.load(open(chemin, encoding="utf-8")), reste(), limite)
        else:
            m["pistes_a_la_portee_reelle"] = "non lancé (budget ou instances absentes)"
    point()


if __name__ == "__main__":
    mp.set_start_method("fork")
    args = [x for x in sys.argv[1:] if x != "--reprise"]
    run(float(args[0]) if args else 3600, "--reprise" in sys.argv)
