# -*- coding: utf-8 -*-
"""BRUME-1024q (v0.6) : contrôles mécaniques des arguments de sécurité (docs/brume1024/, docs/PROOFS.md § 4).

1. AEAD parallèle, lemme 5′ (encodage injectif, sans préfixe, rôles) : v06_verif/chemins_paralleles.py, 492
   configurations, deux témoins qui échouent comme attendu (V06_MODES.md § 2).
2. Borne quantique du hachage (SPONGE_QROM.md) : lemme de comptage adapté à nos domaines, exhaustif sur de petits
   modèles (cm26_verif/exhaustif.c, et son témoin -DTEMOIN qui doit échouer), éponge à domaines, arithmétique classique
   et constantes (eponge_domaines.py, classique.py, constantes.py).
3. Chaîne de Carolan–Majenz (CM_VERIFICATION.md) : opérateurs construits depuis les définitions, tous les énoncés
   évalués exactement pour N = 4 et 5 (cpo_exact.py ; N = 6 et 7 sont dans les sorties figées du dossier), formules de
   représentations jusqu'à N = 22 (representations.py).
4. Q1 (AEAD_SECURITY.md § 4 quinquies–septies) : identités des hybrides, lemme de couture, lemmes sources
   (q1_verif/*.py), chacun avec son témoin."""
import os

from tests.commun import sauver
from tests.b1024_outils import PROTO, BUILD, lancer

V = "prototypes/brume_q/b1024/"


def _passe(nom, cmd, motif, c, m, timeout=3600):
    rc, out = lancer(cmd, timeout=timeout)
    m[nom] = out.strip().splitlines()[-2:]
    c[nom] = rc == 0 and motif in out
    return rc, out


def run():
    c, m = {}, {}
    _passe("aead_parallele_lemme_5_prime_encodage", ["python3", V + "v06_verif/chemins_paralleles.py"], "contrôles 1–4 réussis", c, m)
    import subprocess
    src = os.path.join(PROTO, "cm26_verif", "exhaustif.c")
    for nom, fl in (("exhaustif", []), ("exhaustif_temoin", ["-DTEMOIN"])):
        subprocess.run(["gcc", "-O2", *fl, "-o", os.path.join(BUILD, nom), src], check=True)
    # les quatre modèles réduits de SPONGE_QROM.md § 4 (N = 16, 32, 128, 512 ; domaines comme dans la vraie éponge) et le
    # témoin (preuve sans D ⊕ D), qui doit échouer
    ok, fins = True, []
    for arg in (["1", "3", "1", "0x5", "0x4", "0x5", "0x6", "3", "0", "3"], ["1", "4", "1", "0x5", "0x8", "0x9", "0xA", "2", "20000", "8"],
                ["1", "6", "1", "0x05", "0x20", "0x24", "0x28", "1", "3000", "12"], ["2", "7", "2", "0x05", "0x40", "0x48", "0x50", "0", "400", "14"]):
        rc, out = lancer([os.path.join(BUILD, "exhaustif"), *arg], timeout=3600)
        ok &= rc == 0 and "TOUT PASSE" in out
        fins.append(out.strip().splitlines()[-3:])
    m["qrom_hachage_lemme_de_comptage_exhaustif"] = fins
    c["qrom_hachage_lemme_de_comptage_exhaustif"] = ok
    rc, out = lancer([os.path.join(BUILD, "exhaustif_temoin"), "1", "4", "1", "0x5", "0x8", "0x9", "0xA", "1", "500", "6"], timeout=3600)
    c["qrom_hachage_temoin_sans_d_plus_d_echoue"] = rc != 0 and "ECHEC" in out
    for s in ("eponge_domaines", "classique", "constantes"):
        _passe(f"qrom_hachage_{s}", ["python3", V + f"cm26_verif/{s}.py"], "TOUT PASSE", c, m)
    for n in ("4", "5"):
        _passe(f"carolan_majenz_exact_N{n}", ["python3", V + "cm26_verif/cpo_exact.py", n, n], "TOUT PASSE", c, m)
    _passe("carolan_majenz_representations_N_22", ["python3", V + "cm26_verif/representations.py"], "TOUT PASSE", c, m)
    for s in ("identites_hybrides", "couture", "lemmes_sources"):
        rc, out = lancer(["python3", V + f"q1_verif/{s}.py"], timeout=3600)
        m[f"q1_{s}"] = out.strip().splitlines()[-2:]
        c[f"q1_{s}"] = rc == 0 and "Traceback" not in out
    out = {"controles": c, "mesures": m}
    sauver("b1024_preuves", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
