# -*- coding: utf-8 -*-
"""Division property bit à bit (monomial prediction, Hu et al. 2020).

Une piste monomiale x^{u0} → … → y^{e_j} est nécessaire pour que le monôme
x^{u0} apparaisse dans le bit de sortie j ; sans piste, le bit est ÉQUILIBRÉ
sur le cube (distingueur intégral). Cube : 511 bits actifs (2^511 entrées).

Encadrement de la portée d'un distingueur, dans chaque sens (permutation
directe et inverse) :
  - BORNE BASSE (prouvée) : tant que le degré de Boura–Canteaut est ≤ 510,
    tous les bits sont équilibrés ;
  - BORNE HAUTE (vérifiée) : des pistes vers des bits isolés sont
    construites (faisceau guidé, tests/pistes_monomiales.py) et REVÉRIFIÉES
    pas à pas avec les tables exactes (constantes de tour comprises), puis
    prolongées bit à bit d'un tour à l'autre (en y ajoutant, à chaque tour,
    les pistes vérifiées trouvées directement à ce tour) ; dès que les 512
    bits ont une piste au tour R*, c'est vrai à tout tour ≥ R* (récurrence) :
    la division property ne fournit aucun distingueur au-delà de R* − 1.
Portée « inside-out » ≤ R*_direct − 1 + R*_inverse − 1.
"""
import json
import os
from concurrent.futures import ProcessPoolExecutor

from tests.commun import sauver, RESULTATS
from tests.pistes_monomiales import (NB, construire_faisceau, verifier,
                                     extension)
from sillage import brume512 as B

CACHE = os.path.join(RESULTATS, "pistes_division.json")
FAISCEAU = {"direct": dict(largeur=32, tirages=6), "inverse": dict(largeur=8, tirages=4)}


def bornes_degre(deg_s=3, n=NB, m=4, R=40):
    d, out = 1, []
    for _ in range(R):
        d = min(deg_s * d, n - -(-(n - d) // (m - 1)) if d < n - 1 else n - 1, n - 1)
        out.append(d)
    return out


def _chercher(arg):
    R, sens, g = arg
    bit, piste = construire_faisceau(R, sens, graine=g, **FAISCEAU[sens])
    return R, sens, g, bit, piste


def graines(sens, r_bc, cache, essais=6, r_max_sup=6):
    """Plus petit tour R0 > r_bc où une piste vers un bit isolé est trouvée
    (et vérifiée) ; renvoie (R0, bits, journal)."""
    journal = {}
    for R in range(r_bc + 1, r_bc + 1 + r_max_sup):
        cles = [k for k in cache if k.startswith(f"{sens}|{R}|")]
        bits = [cache[k]["bit"] for k in cles if verifier(cache[k]["piste"], R, sens)]
        if not bits:
            with ProcessPoolExecutor(min(essais, os.cpu_count() or 2)) as ex:
                for R_, s_, g, bit, piste in ex.map(_chercher, [(R, sens, g) for g in range(essais)]):
                    if bit is not None and verifier(piste, R, sens):
                        bits.append(bit)
                        cache[f"{sens}|{R}|{g}"] = {"bit": bit, "piste": piste}
        journal[R] = sorted(set(bits))
        print(sens, R, journal[R], flush=True)
        if bits:
            return R, sorted(set(bits)), journal
    return None, [], journal


def temoins_verifier(cache):
    """Toutes les conclusions de la division property (ici, dp_tous_cubes, dp_exact) reposent sur `verifier`. Il doit
    donc REJETER des pistes invalides par construction, dérivées d'une piste valide : départ privé de deux bits du
    cube, arête de la couche linéaire hors du support de L, sortie de S-box nulle pour une entrée non nulle (aucun
    monôme non constant ne donne la constante 1 d'une bijection), arrivée sur deux bits."""
    import copy
    from tests.pistes_monomiales import _couches
    for k, v in sorted(cache.items()):
        sens, R, _ = k.split("|")
        R = int(R)
        if not verifier(v["piste"], R, sens):
            continue
        p0 = json.loads(json.dumps(v["piste"]))          # listes : les pistes neuves sont des tuples (hors cache JSON)
        _, L = _couches(sens)
        mut = {}
        q = copy.deepcopy(p0)
        q[0][1] = q[0][1][2:]
        mut["depart_incomplet"] = q
        iL = next(i for i, e in enumerate(p0) if e[0] == "L")
        q = copy.deepcopy(p0)
        a_, k_ = q[iL][2][0]
        hors = next(j for j in range(NB) if not L[j, a_])
        q[iL][2][0] = [a_, hors]
        mut["arete_hors_support"] = q
        iS = next(i for i, e in enumerate(p0) if e[0] == "S")
        q = copy.deepcopy(p0)
        nib = q[iS - 1][1][0] // 4                      # un nibble actif à l'entrée de cette couche S
        q[iS][1] = [b for b in q[iS][1] if b // 4 != nib]
        mut["sbox_entree_active_sortie_nulle"] = q
        q = copy.deepcopy(p0)
        fin = q[-1][1][0]
        q[-1][1] = sorted({fin, (fin + 1) % NB})
        mut["arrivee_sur_deux_bits"] = q
        return {nom: not verifier(x, R, sens) for nom, x in mut.items()}
    return {}


def run():
    cache = {}
    if os.path.exists(CACHE):
        cache = json.load(open(CACHE))
    bc = bornes_degre()
    r_bc = sum(1 for d in bc if d < NB - 1)
    m, c = {"tours_equilibres_prouves_par_degre": r_bc}, {}
    hauts = {}
    for sens in ("direct", "inverse"):
        R0, bits, journal = graines(sens, r_bc, cache)
        m[f"{sens}_graines_par_tour"] = journal
        if R0 is None:
            hauts[sens] = None
            continue
        directes = {}                    # pistes vérifiées du cache, par tour
        for k, v in cache.items():
            s_, r_, _ = k.split("|")
            if s_ == sens and verifier(v["piste"], int(r_), sens):
                directes.setdefault(int(r_), set()).add(v["bit"])
        etape, couverts, R, couv = extension(sens), set(bits), R0, {R0: len(bits)}
        while len(couverts) < NB and R < R0 + 12:
            couverts = etape(couverts, R) | directes.get(R + 1, set())
            R += 1
            couv[R] = len(couverts)
        m[f"{sens}_couverture_par_tour"] = couv
        hauts[sens] = R - 1 if len(couverts) == NB else None
        m[f"{sens}_portee_DP"] = {"min_prouve": r_bc, "max_verifie": hauts[sens]}
    with open(CACHE, "w") as f:
        json.dump(cache, f)
    ok = all(v is not None for v in hauts.values())
    tot = sum(hauts.values()) if ok else None
    m["portee_inside_out"] = {"min": 2 * r_bc, "max": tot}
    m["marge_tours_min"] = None if tot is None else B.N_ROUNDS - tot
    tv = temoins_verifier(cache)
    m["temoins_verifier_pistes_invalides_rejetees"] = tv
    c["verifier_rejette_les_pistes_invalides"] = bool(tv) and all(tv.values())
    c["division_property_bornee_dans_les_deux_sens"] = ok
    c["division_property_inside_out_inferieure_a_32_tours"] = ok and tot < B.N_ROUNDS
    out = {"controles": c, "mesures": m}
    sauver("division_property", out)
    return out


if __name__ == "__main__":
    print(run()["mesures"])
