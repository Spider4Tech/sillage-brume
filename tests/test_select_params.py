# -*- coding: utf-8 -*-
"""Tables figées de BRUME-512 : reproduites par leur procédure de sélection (sillage/select_params.py).

La S-box, le graphe de Cayley et les coefficients de diffusion sont publiés comme sortie déterministe d'une recherche à
graine fixée, sous des critères énoncés (docstring de select_params.py, docs/SPEC.md). Rien ne le vérifiait. Contrôles :
0. L'empreinte SHA-256 de brume512_tables.py publiée dans docs/SPEC.md est celle du fichier.

1. Reproduction. gen_graph et gen_coef, relancés avec leurs graines, redonnent exactement (GROUP, GENS) et COEF de
   sillage/brume512_tables.py ; gen_sbox redonne la S-box de la v0.4. Depuis la v0.5, SBOX est SBOX_V05, la candidate
   retenue par le départage (prototypes/brume_sbox6/departage/RAPPORT.md), non rejouable dans la batterie (1 h + GPU). Les empreintes CHECK du fichier sont celles de son contenu.
2. Critères. La S-box retenue satisfait les critères annoncés : U = 4, NL = 4 (max |LAT| = 4), aucun point fixe,
   degré 3. Le graphe est connexe et 6-régulier, et max_chev ≤ 2 (borne utilisée par le lemme wide-trail).
   Les coefficients ne violent aucune contrainte (a) à (e).
3. Groupes. group_op et group_inv de brume512.py coïncident avec ceux de select_params pour D128 et Z4Z32 (le second
   n'est pas retenu, mais il est candidat de la recherche). Les axiomes de groupe sont vérifiés.
4. Chaîne vers le C. sillage/c/gen_tables.py, relancé dans un répertoire temporaire, régénère octet pour octet
   brume512_tables.h et brume512_simd.h. Le C n'a donc pas de tables recopiées à la main.
5. Témoins. Une autre graine donne une autre S-box. Un coefficient modifié fait apparaître des violations. Une S-box
   modifiée change l'en-tête généré.
"""
import hashlib
import os
import random
import tempfile

import numpy as np

from tests.commun import RACINE, sauver, tables_sbox
from sillage import brume512 as B
from sillage import brume512_tables as T
from sillage import select_params as S
from sillage.c import gen_tables as G


def degre_algebrique(sbox):
    """Degré maximal des fonctions coordonnées (transformée de Möbius)."""
    deg = 0
    for bit in range(4):
        f = [(sbox[x] >> bit) & 1 for x in range(16)]
        for i in range(4):
            for x in range(16):
                if x >> i & 1:
                    f[x] ^= f[x ^ (1 << i)]
        deg = max([deg] + [bin(x).count("1") for x in range(16) if f[x]])
    return deg


def groupes(c, m):
    ok_eq, ok_ax = True, True
    vrai = B.GROUP
    try:
        for nom in ("D128", "Z4Z32"):
            B.GROUP = nom
            op, inv = S.GROUPS[nom]["op"], S.GROUPS[nom]["inv"]
            ok_eq &= all(B.group_op(a, b) == op(a, b) for a in range(128) for b in range(128))
            ok_eq &= all(B.group_inv(a) == inv(a) for a in range(128))
            ok_ax &= all(B.group_op(a, 0) == a == B.group_op(0, a) and B.group_op(a, B.group_inv(a)) == 0 for a in range(128))
            rng = random.Random(1)
            ok_ax &= all(B.group_op(B.group_op(a, b), d) == B.group_op(a, B.group_op(b, d))
                         for a, b, d in ((rng.randrange(128), rng.randrange(128), rng.randrange(128)) for _ in range(20000)))
        B.GROUP = "inconnu"
        try:
            B.group_op(1, 2)
            refus = False
        except ValueError:
            refus = True
        try:
            B.group_inv(1)
            refus = False
        except ValueError:
            pass
    finally:
        B.GROUP = vrai
    c["groupes_brume512_egaux_a_select_params"] = ok_eq
    c["axiomes_de_groupe_D128_et_Z4Z32"] = ok_ax
    c["groupe_inconnu_refuse"] = refus


def generer(dossier):
    vrai = G.ICI
    try:
        G.ICI = dossier
        G.main()
        G.simd()
    finally:
        G.ICI = vrai
    return {f: open(os.path.join(dossier, f), "rb").read() for f in ("brume512_tables.h", "brume512_simd.h")}


def chaine_c(c):
    with tempfile.TemporaryDirectory() as d:
        gen = generer(d)
    c["en_tetes_c_regeneres_identiques"] = all(gen[f] == open(os.path.join(G.ICI, f), "rb").read() for f in gen)
    vrai = B.SBOX.copy()
    try:
        B.SBOX[[0, 1]] = B.SBOX[[1, 0]]
        with tempfile.TemporaryDirectory() as d:
            gen2 = generer(d)
    finally:
        B.SBOX[:] = vrai
    c["temoin_sbox_modifiee_change_l_en_tete"] = gen2["brume512_tables.h"] != gen["brume512_tables.h"]


def run():
    c, m = {}, {}
    sbox, sst = S.gen_sbox()
    gname, gens, _, gst = S.gen_graph()
    ADJ = S._adjacency(gens, S.GROUPS[gname])
    coef, cst = S.gen_coef(ADJ)
    # v0.5 : la S-box en service est SBOX_V05, issue du départage (règle fixée d'avance, RAPPORT.md) ; gen_sbox doit toujours
    # redonner celle de la v0.4 (procédure reproductible), et SBOX_V05 doit être la candidate retenue par le rapport.
    rapport = open(os.path.join(RACINE, "prototypes", "brume_sbox6", "departage", "RAPPORT.md"), encoding="utf-8").read()
    c["sbox_v04_reproduite_par_gen_sbox"] = sbox == [int(x, 16) for x in "891AC406DF37E2B5"]
    c["sbox_en_service_est_sbox_v05_du_departage"] = (T.SBOX == S.SBOX_V05
                                                      and "Meilleure candidate : CAND_A1 = `AD412650BFEC7893`" in rapport)
    c["graphe_reproduit"] = gname == T.GROUP and gens == T.GENS
    c["coefficients_reproduits"] = coef == T.COEF
    c["empreintes_check_du_fichier"] = T.CHECK == {k: S._sha(getattr(T, k)) for k in ("SBOX", "GROUP", "GENS", "COEF")}
    sha = hashlib.sha256(open(T.__file__, "rb").read()).hexdigest()
    c["empreinte_sha256_egale_a_celle_de_spec"] = sha in open(os.path.join(RACINE, "docs", "SPEC.md"), encoding="utf-8").read()
    m.update(sbox=sst, graphe=gst, coefficients=cst)

    ddt, lat = tables_sbox(T.SBOX)
    c["sbox_criteres_U4_NL4_sans_point_fixe_degre_3"] = (
        int(ddt[1:].max()) == 4 and int(abs(lat[1:, 1:]).max()) == 4
        and all(T.SBOX[x] != x for x in range(16)) and degre_algebrique(T.SBOX) == 3)
    A = S._adjacency(T.GENS, S.GROUPS[T.GROUP])
    c["graphe_connexe_6_regulier_max_chev_2"] = (bool(S._connected(A)) and bool((A.sum(axis=1) == 6).all())
                                                and S._max_chev(A) <= 2)
    LN = [sorted(set(np.nonzero(A[j])[0].tolist()) | {j}) for j in range(S.N)]
    C = S.Constraintes(LN)
    co = np.array(T.COEF, dtype=np.uint8)
    nb, _ = C.collect(co)
    c["coefficients_sans_violation_a_e"] = nb == 0
    M = np.zeros((S.N, S.N), np.uint8)
    for j in range(S.N):
        for i in LN[j]:
            M[j, i] = co[j, i]
    c["coefficients_det_gf16_non_nul"] = bool(S._det_gf16_nonnul(M))

    # témoins
    c["temoin_autre_graine_autre_sbox"] = S.gen_sbox(seed=0xA11CF)[0] != sbox
    co2 = co.copy()
    j0, i0 = 0, LN[0][1]
    co2[j0, i0] = co2[j0, LN[0][2]]                   # deux coefficients égaux sur une ligne : (a) violée
    c["temoin_coefficient_modifie_detecte"] = C.collect(co2)[0] > 0
    groupes(c, m)
    chaine_c(c)
    out = {"controles": c, "mesures": m}
    sauver("select_params", out)
    return out


if __name__ == "__main__":
    out = run()
    for k, v in out["controles"].items():
        print(f"{'OK ' if v else 'ÉCHEC'} {k}")
