# -*- coding: utf-8 -*-
"""Division property de BRUME-1024q, sens INVERSE : construction directe de pistes monomiales, sans CP-SAT.

Pourquoi une autre méthode : M⁻¹ est dense (93,7 % des coefficients non nuls), si bien que les modèles CP-SAT de
dp1024_exact.py dépassent plusieurs Go par processus et que le faisceau (flots sur des graphes de ~500 000 arêtes)
n'avance pas. Mais cette densité rend la couche linéaire presque LIBRE : les bits actifs U peuvent être envoyés sur
presque n'importe quel ensemble V de positions (|V| ≥ |U|), pourvu qu'il existe des arêtes (copie/XOR) : chaque sortie de
V reçoit exactement une arête, chaque entrée de U en émet au moins une. C'est un couplage biparti saturant U, complété.

Construction, tour par tour (plan inverse : L⁻¹ puis S⁻¹ avec la constante du tour) :
  1. on choisit les motifs d'entrée des S-box : avec W = |U|, si W ≤ 768, ⌈W/3⌉ nibbles reçoivent 3 bits (ou le reste)
     et rendent 1 bit ; sinon W − 768 nibbles pleins (F → F) et les autres 3 bits → 1 bit. C'est la descente la plus
     rapide permise par le degré 3 ; les motifs, nibbles et bits sont tirés au hasard parmi ceux que la table des
     monômes (constante comprise) autorise ;
  2. on relie U à V par un couplage (glouton puis chemins augmentants), puis on rattache les sorties restantes ;
  3. au dernier tour, le nibble et le motif sont imposés pour finir sur le bit cible.
Chaque piste est REVÉRIFIÉE par `verifier` de la suite (pistes1024). Une piste est déterminée par (R, bit, graine) :
le certificat stocké est ce triplet, et la piste est reconstruite puis revérifiée à la relecture.

    python3 dp1024_inverse.py R [travailleurs] [bits: tous | a-b] [essais par bit]
Sortie : resultats/pistes_inverse_1024q.json (ou $DP_INV), une piste complète d'exemple et les certificats."""
import json
import os
import random
import sys
import time
from concurrent.futures import ProcessPoolExecutor

import numpy as np

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.normpath(os.path.join(_ICI, "..", "..", "..", ".."))
sys.path.insert(0, _ICI)
sys.path.insert(0, _RACINE)
import pistes1024 as P  # noqa: E402

NB, N = P.NB, P.N
SORTIE = os.environ.get("DP_INV", os.path.join(_RACINE, "resultats", "pistes_inverse_1024q.json"))
S, L = P._couches("inverse")
LB = L.astype(bool)
POIDS = [bin(x).count("1") for x in range(16)]


def options(c):
    """Pour une S-box de constante c : {u: [v de poids minimal non nul avec T[u, v]]}."""
    T = P.table(S, 0, c)
    out = {}
    for u in range(1, 16):
        vs = [v for v in range(1, 16) if T[u, v]]
        if vs:
            m = min(POIDS[v] for v in vs)
            out[u] = [v for v in vs if POIDS[v] == m]
    return out


def lier(U, V, rng):
    """Arêtes (a, k) de U vers V : chaque k de V une fois, chaque a de U au moins une fois ; None sinon."""
    U, V = list(U), list(V)
    if len(V) < len(U):
        return None
    sub = LB[np.ix_(V, U)]                        # sub[i, j] : arête V[i] ← U[j]
    adj = [np.nonzero(sub[:, j])[0] for j in range(len(U))]
    mv = -np.ones(len(V), int)                     # sortie i couplée à l'entrée mv[i]
    mu = -np.ones(len(U), int)
    ordre = list(range(len(U)))
    rng.shuffle(ordre)
    for j in ordre:                                # glouton
        libres = adj[j][mv[adj[j]] < 0]
        if len(libres):
            i = int(libres[rng.randrange(len(libres))])
            mv[i], mu[j] = j, i
    for j in ordre:                                # chemins augmentants (BFS)
        if mu[j] >= 0:
            continue
        pere, file, vus, fin = {}, [j], {j}, None
        while file and fin is None:
            nf = []
            for x in file:
                for i in adj[x]:
                    i = int(i)
                    if i in pere:
                        continue
                    pere[i] = x
                    if mv[i] < 0:
                        fin = i
                        break
                    y = int(mv[i])
                    if y not in vus:
                        vus.add(y)
                        nf.append(y)
                if fin is not None:
                    break
            file = nf
        if fin is None:
            return None
        i = fin
        while True:                                 # inversion du chemin
            x = pere[i]
            prec = int(mu[x])
            mv[i], mu[x] = x, i
            if x == j:
                break
            i = prec
    aretes = [(U[int(mv[i])], V[i]) for i in range(len(V)) if mv[i] >= 0]
    for i in range(len(V)):                         # sorties restantes : une arête depuis n'importe quel voisin
        if mv[i] < 0:
            vs = np.nonzero(sub[i])[0]
            if not len(vs):
                return None
            aretes.append((U[int(vs[rng.randrange(len(vs))])], V[i]))
    return aretes


def construire(R, cible, graine):
    """Piste inverse de R tours de {0..1023} − {0} vers le bit `cible`, ou None."""
    rng = random.Random(f"{R}|{cible}|{graine}")      # graine textuelle : déterministe d'une exécution à l'autre
    U = sorted(set(range(NB)) - {0})
    piste = [["depart", U]]
    for r in range(R):
        c1 = B_RC[B_NR - 1 - r]
        opts = [options(int(c1[q])) for q in range(N)]
        W = len(U)
        dernier = r == R - 1
        motifs = {}
        if dernier:                                 # un seul nibble, celui de la cible, vers le bit cible
            q, b = divmod(cible, 4)
            us = [u for u, vs in opts[q].items() if POIDS[u] >= W and (1 << b) in vs]
            if not us:
                return None
            motifs[q] = (rng.choice(us), 1 << b)
        else:
            nib = list(range(N))
            rng.shuffle(nib)
            if W > 3 * N:
                pleins, reste = W - 3 * N, 0
                n3 = N - pleins
            else:
                pleins, n3, reste = 0, W // 3, W % 3
            k = 0
            for _ in range(pleins):
                q = nib[k]; k += 1
                motifs[q] = (15, 15)
            for w in [3] * n3 + ([reste] if reste else []):
                while True:
                    if k >= N:
                        return None
                    q = nib[k]; k += 1
                    us = [u for u in opts[q] if POIDS[u] == w and POIDS[opts[q][u][0]] == 1]
                    if us:
                        u = rng.choice(us)
                        motifs[q] = (u, rng.choice(opts[q][u]))
                        break
        V = sorted(4 * q + b for q, (u, _) in motifs.items() for b in range(4) if u >> b & 1)
        ar = lier(U, V, rng)
        if ar is None:
            return None
        piste.append(["L", V, [list(e) for e in ar]])
        U = sorted(4 * q + b for q, (_, v) in motifs.items() for b in range(4) if v >> b & 1)
        piste.append(["S", U])
    return piste


import b1024_module as _B  # noqa: E402
B_RC, B_NR = _B.RC, _B.N_ROUNDS


def _tache(arg):
    R, j, essais = arg
    t0 = time.time()
    for g in range(essais):
        p = construire(R, j, g)
        if p is not None and P.verifier(p, R, "inverse") and p[-1][1] == [j]:
            return j, g, [len(e[1]) for e in p], time.time() - t0
    return j, None, None, time.time() - t0


def main():
    R = int(sys.argv[1])
    w = int(sys.argv[2]) if len(sys.argv) > 2 else os.cpu_count()
    sel = sys.argv[3] if len(sys.argv) > 3 else "tous"
    essais = int(sys.argv[4]) if len(sys.argv) > 4 else 20
    bits = list(range(NB)) if sel == "tous" else list(range(*map(int, sel.split("-"))))
    res = json.load(open(SORTIE)) if os.path.exists(SORTIE) else {}
    cert = res.setdefault("certificats", {}).setdefault(str(R), {})
    faits = set()
    for j, g in cert.items():                        # relecture : chaque certificat est reconstruit et revérifié
        p = construire(R, int(j), g)
        if p is not None and P.verifier(p, R, "inverse") and p[-1][1] == [int(j)]:
            faits.add(int(j))
    cert = {j: g for j, g in cert.items() if int(j) in faits}
    res["certificats"][str(R)] = cert
    bits = [j for j in bits if j not in faits]
    print(f"inverse R={R} : {len(faits)} bits déjà certifiés (revérifiés), {len(bits)} à chercher, {essais} essais par bit",
          flush=True)
    t0, n = time.time(), 0
    with ProcessPoolExecutor(w) as ex:
        for j, g, profil, dt in ex.map(_tache, [(R, j, essais) for j in bits], chunksize=4):
            n += 1
            if g is not None:
                cert[str(j)] = g
                if "exemple" not in res:
                    res["exemple"] = {"R": R, "bit": j, "graine": g, "piste": construire(R, j, g)}
            if g is None or n % 64 == 0:
                print(f"  bit {j} : {'graine ' + str(g) + ', poids ' + str(profil[::2]) if g is not None else 'AUCUNE PISTE'}"
                      f" ({dt:.1f} s) ; {len(cert)}/{NB} certifiés, {time.time() - t0:.0f} s", flush=True)
            if n % 64 == 0:
                json.dump(res, open(SORTIE, "w"))
    json.dump(res, open(SORTIE, "w"))
    tous = len(cert) == NB
    print(f"inverse R={R} : {len(cert)}/{NB} bits avec une piste vérifiée"
          + (f" → portée DP inverse ≤ {R - 1}" if tous else ""), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
