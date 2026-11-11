# -*- coding: utf-8 -*-
"""Sillage-SIG v0.5 : temps constant mesuré (dudect, t de Welch, valeur secrète fixe contre aléatoire, un cœur), par
`vole_proto --dudect N` : préparation du témoin et syndrome (keygen), contraintes_poly (signature, hors grinding, qui ne
dépend que de valeurs publiques). Seuil |t| < 4,5 ; le témoin (sortie anticipée sur la position secrète) doit dépasser.
Machine et GPU au repos (la batterie lance les tests l'un après l'autre)."""
import os
import re
import subprocess

from tests.commun import sauver, RACINE

N = int(os.environ.get("SILLAGE_VOLE_DUDECT", "20000"))


def run():
    c, m = {}, {}
    subprocess.run(["make", "-s", "-C", os.path.join(RACINE, "tests", "c"), "build/vole_proto"], check=True)
    exe = os.path.join(RACINE, "tests", "c", "build", "vole_proto")
    cmd = [exe, "--dudect", str(N)]
    if subprocess.run(["which", "taskset"], capture_output=True).returncode == 0:
        cmd = ["taskset", "-c", "2"] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=RACINE)
    lignes = re.findall(r"dudect (.+?)\s+(\d+) mesures : t = +([-+\d.]+), sous le 90e centile t = +([-+\d.]+)", r.stdout)
    m["sortie"] = r.stdout.strip()
    noms = ["temoin_et_syndrome", "contraintes_poly", "temoin_sortie_anticipee"]
    for nom, (_, n, t, tc) in zip(noms, lignes):
        m[nom] = {"mesures": int(n), "t": float(t), "t_90e_centile": float(tc)}
    if len(lignes) == 3:
        for nom in noms[:2]:
            c[f"{nom}_sous_le_seuil"] = abs(m[nom]["t"]) < 4.5 and abs(m[nom]["t_90e_centile"]) < 4.5
        c["temoin_detecte"] = abs(m["temoin_sortie_anticipee"]["t"]) > 4.5 or abs(m["temoin_sortie_anticipee"]["t_90e_centile"]) > 4.5
    else:
        c["dudect_execute"] = False
    out = {"controles": c, "mesures": m}
    sauver("c_vole_temps", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
