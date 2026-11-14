# -*- coding: utf-8 -*-
"""Division property de BRUME-1024q (ROADMAP.md § 3, « Exact division property ») : même méthode que
tests/test_division_property.py pour BRUME-512, avec le code de la suite (pistes1024 = tests/pistes_monomiales.py sur
les paramètres de BRUME-1024q).

  - BORNE BASSE (prouvée) : degré de Boura–Canteaut (γ = 3, n = 1 024) ≤ n − 2 pendant r_bc tours : tous les bits
    sont équilibrés sur le cube de dimension 1 023 (cube 0 : tous les bits sauf le bit 0) ;
  - BORNE HAUTE (vérifiée) : pistes monomiales vers des bits isolés, construites par faisceau et REVÉRIFIÉES par
    `verifier` (tables exactes, constantes de tour comprises), puis prolongées bit à bit d'un tour à l'autre ; dès que
    les 1 024 bits ont une piste au tour R*, la division property ne prouve plus aucun bit équilibré au-delà de R* − 1.
Contrôles : module de paramètres ≡ brume1024.c (vecteurs de gpu/vecteurs_b1024.c, 56 cas) ; `verifier` rejette des
pistes invalides dérivées d'une piste valide.
    python3 dp1024.py vecteurs_b1024.bin [travailleurs]      (dans tgh : numpy, networkx)
Cache : resultats/pistes_division_1024q.json ; sortie : resultats/division_property_1024q.json."""
import copy
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.normpath(os.path.join(_ICI, "..", "..", "..", ".."))
sys.path.insert(0, _ICI)
sys.path.insert(0, _RACINE)
import b1024_module as B  # noqa: E402
import pistes1024 as P  # noqa: E402
from tests.test_division_property import bornes_degre  # noqa: E402

RES = os.path.join(_RACINE, "resultats")
CACHE = os.path.join(RES, "pistes_division_1024q.json")
SORTIE = os.path.join(RES, "division_property_1024q.json")
NB = P.NB
FAISCEAU = {"direct": dict(largeur=16, tirages=4), "inverse": dict(largeur=8, tirages=4)}
ESSAIS = int(os.environ.get("DP_ESSAIS", "8"))


def conformite(chemin):
    v = open(chemin, "rb").read()
    ok = tot = 0
    for t, R in enumerate([1, 2, 3, 4, 5, 8, 32]):
        for e in range(8):
            o = 128 * 3 * (8 * t + e)
            w, att = v[o:o + 128], v[o + 128:o + 256]
            x = [(w[i // 2] >> (4 * (i % 2))) & 15 for i in range(256)]
            for r in range(R):
                x = B.tour(x, r)
            ok += bytes(x[2 * i] | x[2 * i + 1] << 4 for i in range(128)) == att
            tot += 1
    return ok, tot


def _chercher(arg):
    R, sens, g = arg
    t0 = time.time()
    bit, piste = P.construire_faisceau(R, sens, graine=g, **FAISCEAU[sens])
    ok = bit is not None and P.verifier(piste, R, sens)
    return R, sens, g, (bit if ok else None), (piste if ok else None), time.time() - t0


def temoins_verifier(cache):
    for k, v in sorted(cache.items()):
        sens, R, _ = k.split("|")
        R = int(R)
        if not P.verifier(v["piste"], R, sens):
            continue
        p0 = json.loads(json.dumps(v["piste"]))
        _, L = P._couches(sens)
        mut = {}
        q = copy.deepcopy(p0)
        q[0][1] = q[0][1][2:]
        mut["depart_incomplet"] = q
        iL = next(i for i, e in enumerate(p0) if e[0] == "L")
        q = copy.deepcopy(p0)
        a_, _k = q[iL][2][0]
        q[iL][2][0] = [a_, next(j for j in range(NB) if not L[j, a_])]
        mut["arete_hors_support"] = q
        iS = next(i for i, e in enumerate(p0) if e[0] == "S")
        q = copy.deepcopy(p0)
        nib = q[iS - 1][1][0] // 4
        q[iS][1] = [b for b in q[iS][1] if b // 4 != nib]
        mut["sbox_entree_active_sortie_nulle"] = q
        q = copy.deepcopy(p0)
        fin = q[-1][1][0]
        q[-1][1] = sorted({fin, (fin + 1) % NB})
        mut["arrivee_sur_deux_bits"] = q
        return {nom: not P.verifier(x, R, sens) for nom, x in mut.items()}
    return {}


def main():
    vect = sys.argv[1]
    w = int(sys.argv[2]) if len(sys.argv) > 2 else os.cpu_count()
    t0 = time.time()
    c, m = {}, {}
    ok, tot = conformite(vect)
    c["parametres_identiques_a_brume1024_c"] = ok == tot
    print(f"conformité du module : {ok}/{tot}", flush=True)
    if ok != tot:
        return 1
    bc = bornes_degre(n=NB, R=20)
    r_bc = sum(1 for d in bc if d < NB - 1)
    m["degre_boura_canteaut"] = bc[:14]
    m["tours_equilibres_prouves_par_degre"] = r_bc
    cache = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
    hauts = {}
    for sens in ("direct", "inverse"):
        journal, R0, bits = {}, None, []
        for R in range(r_bc + 1, r_bc + 6):
            cles = [k for k in cache if k.startswith(f"{sens}|{R}|")]
            bits = sorted({cache[k]["bit"] for k in cles if P.verifier(cache[k]["piste"], R, sens)})
            if not bits:
                with ProcessPoolExecutor(min(ESSAIS, w)) as ex:
                    for R_, s_, g, bit, piste, dt in ex.map(_chercher, [(R, sens, g) for g in range(ESSAIS)]):
                        print(f"  {sens} R={R} graine {g} : {'bit ' + str(bit) if bit is not None else 'rien'} "
                              f"({dt:.0f} s)", flush=True)
                        if bit is not None:
                            cache[f"{sens}|{R}|{g}"] = {"bit": bit, "piste": piste}
                json.dump(cache, open(CACHE, "w"))
                bits = sorted({cache[k]["bit"] for k in cache if k.startswith(f"{sens}|{R}|")})
            journal[R] = bits
            print(f"{sens} R={R} : {len(bits)} bit(s) avec piste vérifiée ({time.time() - t0:.0f} s)", flush=True)
            if bits:
                R0 = R
                break
        m[f"{sens}_graines_par_tour"] = journal
        if R0 is None:
            hauts[sens] = None
            continue
        directes = {}
        for k, v in cache.items():
            s_, r_, _ = k.split("|")
            if s_ == sens and P.verifier(v["piste"], int(r_), sens):
                directes.setdefault(int(r_), set()).add(v["bit"])
        etape, couverts, R, couv = P.extension(sens), set(bits), R0, {R0: len(bits)}
        while len(couverts) < NB and R < R0 + 12:
            couverts = etape(couverts, R) | directes.get(R + 1, set())
            R += 1
            couv[R] = len(couverts)
        m[f"{sens}_couverture_par_tour"] = couv
        hauts[sens] = R - 1 if len(couverts) == NB else None
        m[f"{sens}_portee_DP"] = {"min_prouve": r_bc, "max_verifie": hauts[sens]}
        print(f"{sens} : couverture {couv} → portée DP ≤ {hauts[sens]}", flush=True)
    okh = all(v is not None for v in hauts.values())
    tot_io = sum(hauts.values()) if okh else None
    m["portee_inside_out"] = {"min": 2 * r_bc, "max": tot_io}
    m["marge_tours_min"] = None if tot_io is None else B.N_ROUNDS - tot_io
    tv = temoins_verifier(cache)
    m["temoins_verifier_pistes_invalides_rejetees"] = tv
    c["verifier_rejette_les_pistes_invalides"] = bool(tv) and all(tv.values())
    c["division_property_bornee_dans_les_deux_sens"] = okh
    c["division_property_inside_out_inferieure_a_32_tours"] = okh and tot_io < B.N_ROUNDS
    m["duree_s"] = round(time.time() - t0)
    json.dump({"nom": "division_property_1024q", "controles": c, "mesures": m}, open(SORTIE, "w"), indent=1,
              ensure_ascii=False)
    print(json.dumps({"controles": c, "mesures": m}, ensure_ascii=False))
    return 0 if all(c.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
