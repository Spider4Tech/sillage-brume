# -*- coding: utf-8 -*-
"""Théorème 14 sur duplex réduit (permutation aléatoire de b = r + c bits) : chaque terme de la borne
est confronté à une attaque exécutée, et les falsifications passent par le vrai déchiffrement du modèle.
  - σ²/2^{c+1} : collisions de capacité entre nœuds (Lemme 4) ;
  - 2σN/2^c : clair choisi constant, une requête teste tous les nœuds à la fois ; état retrouvé, falsification ;
  - N/2^k, 2N/2^b, N/2^c : recherche de clé et requêtes inverses (Lemme 3), multi-utilisateur (μN/2^k) ;
  - q_d/2^τ : tags devinés.
Une attaque au-dessus de sa borne, ou très en dessous là où la borne est censée être atteinte, ferait échouer le test."""
import math
import os

import numpy as np

from tests.commun import sauver

DOM_AAD, DOM_TEXTE, DOM_FINAL = 1, 2, 4
INT = float(os.environ.get("SILLAGE_INTENSITE", "1"))


class Duplex:
    """Même chemin que tests/test_mode_aead.py, en blocs de r bits : blocs entiers uniquement."""

    def __init__(self, r, c, m, rng):
        self.r, self.c, self.m = r, c, m
        self.b = r + c
        self.P = rng.permutation(1 << self.b)
        self.S0 = int(self.P[(r << 4) | 3])       # P(IV)
        self.un = 1 << (r - 1)                    # bourrage 10*

    def cle(self, rng):
        return [int(rng.integers(1 << self.r)) for _ in range(self.m)]

    def _appel(self, S, sigma, dom=0, trace=None):
        x = S ^ (sigma << self.c) ^ dom
        y = int(self.P[x])
        if trace is not None:
            trace.append((x, y))
        return y

    def _debut(self, K, N, A, trace=None):
        S = self.S0
        for blk in K + [N, self.un]:
            S = self._appel(S, blk, 0, trace)
        for blk in A:
            S = self._appel(S, blk, 0, trace)
        return self._appel(S, self.un, DOM_AAD, trace)

    def _fin(self, S, n, trace=None):
        S = self._appel(S, self.un, 0, trace)                 # bourrage du chiffré
        S = self._appel(S, 0, DOM_TEXTE, trace)
        S = self._appel(S, n % (1 << self.r), DOM_FINAL, trace)
        return S >> self.c

    def chiffrer(self, K, N, A, M, trace=None):
        S, C = self._debut(K, N, A, trace), []
        for blk in M:
            z = S >> self.c
            C.append(z ^ blk)
            S = self._appel(S, C[-1], 0, trace)
        return C, self._fin(S, len(M), trace)

    def dechiffrer(self, K, N, A, C, T):
        S = self._debut(K, N, A)
        for blk in C:
            S = self._appel(S, blk)
        return self._fin(S, len(C)) == T


def _freq(succes, essais):
    return dict(succes=succes, essais=essais, frequence=round(succes / essais, 4))


def _collisions(r, c, m, L, essais, rng):
    """Lemme 4 : deux nœuds distincts de même capacité de sortie."""
    coll, sig = 0, 0
    for _ in range(essais):
        d = Duplex(r, c, m, rng)
        K, tr = d.cle(rng), []
        d.chiffrer(K, 0, [], [int(x) for x in rng.integers(1 << r, size=L)], tr)
        noeuds = {x: y & ((1 << c) - 1) for x, y in tr}
        sig = len(noeuds)
        coll += len(set(noeuds.values())) < len(noeuds)
    return coll, sig


def _clair_choisi(r, c, m, L, N, essais, rng):
    """Clair constant : le débit d'entrée de chaque nœud de données vaut le même R, connu. Une requête (R ‖ c')
    teste tous ces nœuds. Le flux suivant confirme ; l'état connu donne le tag d'un chiffré nouveau."""
    gagne = dec = 0
    for _ in range(essais):
        d = Duplex(r, c, m, rng)
        K = d.cle(rng)
        R = int(rng.integers(1 << r))
        C, T = d.chiffrer(K, 0, [], [R] * L)
        flux = [a ^ R for a in C]
        for cp in rng.choice(1 << c, size=N, replace=False):
            y = int(d.P[(R << c) | int(cp)])
            trouve = False
            for i in range(L - 2):                     # l'état après le bloc i vaut y ?
                if y >> c != flux[i + 1]:
                    continue
                y2 = int(d.P[y ^ (C[i + 1] << c)])
                if y2 >> c != flux[i + 2]:
                    continue
                nouveau = (C[i + 1] ^ 1) & ((1 << r) - 1)   # falsification : autre bloc i + 1
                S = int(d.P[y ^ (nouveau << c)])
                Cf = C[:i + 1] + [nouveau]
                Tf = d._fin(S, len(Cf))
                dec += 1
                if d.dechiffrer(K, 0, [], Cf, Tf):
                    trouve = True
                    break
            if trouve:
                gagne += 1
                break
    return gagne, dec


def _inverse(r, c, m, L, N, essais, rng):
    """Requêtes inverses : (flux connu ‖ c') ; le débit d'entrée trouvé doit être le clair connu. Même falsification."""
    gagne = 0
    for _ in range(essais):
        d = Duplex(r, c, m, rng)
        Pi = np.argsort(d.P)
        K = d.cle(rng)
        M = [int(x) for x in rng.integers(1 << r, size=L)]
        C, T = d.chiffrer(K, 0, [], M)
        flux = [a ^ b for a, b in zip(C, M)]
        fini = False
        for k, cp in enumerate(rng.choice(1 << c, size=N, replace=False)):
            i = 1 + k % (L - 2)
            y = (flux[i] << c) | int(cp)
            if int(Pi[y]) >> c != M[i - 1]:
                continue
            nouveau = (C[i] ^ 1) & ((1 << r) - 1)
            Cf = C[:i] + [nouveau]
            Tf = d._fin(int(d.P[y ^ (nouveau << c)]), len(Cf))
            if d.dechiffrer(K, 0, [], Cf, Tf):
                fini = True
                break
        gagne += fini
    return gagne


def _cle(r, c, m, mu, N, essais, rng):
    """Lemme 3 : atteindre X_m de l'un des μ utilisateurs par essais de clé en chaîne (m requêtes par essai)."""
    gagne = 0
    for _ in range(essais):
        d = Duplex(r, c, m, rng)
        Xm = set()
        for _ in range(mu):
            S = d.S0
            K = d.cle(rng)
            for blk in K[:-1]:
                S = int(d.P[S ^ (blk << c)])
            Xm.add(S ^ (K[-1] << c))
        hit = False
        for _ in range(N // m):
            S = d.S0
            for j in range(m):
                x = S ^ (int(rng.integers(1 << r)) << c)
                if j == m - 1:
                    hit |= x in Xm
                S = int(d.P[x])
        gagne += hit
    return gagne


def _inv_cle(r, c, m, N, essais, rng):
    """Requêtes inverses aléatoires visant l'état qui suit la clé : aucun débit n'en est connu, 2^-b par requête."""
    gagne = 0
    for _ in range(essais):
        d = Duplex(r, c, m, rng)
        S = d.S0
        for blk in d.cle(rng):
            S = int(d.P[S ^ (blk << c)])
        gagne += S in {int(x) for x in rng.integers(1 << d.b, size=N)}
    return gagne


def _tags(r, c, qd, essais, rng):
    gagne = 0
    for _ in range(essais):
        d = Duplex(r, c, 2, rng)
        K = d.cle(rng)
        C, T = d.chiffrer(K, 0, [], [1, 2, 3])
        Cf = [C[0], C[1], C[2] ^ 1]
        gagne += any(d.dechiffrer(K, 0, [], Cf, int(t)) for t in rng.choice(1 << r, size=qd, replace=False))
    return gagne


def _sous(f, borne, essais):
    return f / essais <= borne + 3 * math.sqrt(max(borne, 1 / essais) / essais)


def run():
    c, m = {}, {}
    rng = np.random.default_rng(0xAEAD)
    # Lemme 4 : c = 8, tiré sans clair choisi
    E = int(1500 * INT)
    coll, sig = _collisions(8, 8, 2, 6, E, rng)
    b = sig * sig / 2 ** 9
    m["lemme_4_collisions"] = {**_freq(coll, E), "sigma": sig, "borne": round(b, 3)}
    c["lemme_4_borne_respectee"] = _sous(coll, b, E)
    c["lemme_4_atteinte_a_un_facteur_3_pres"] = coll / E >= b / 3
    # 2σN/2^c : r = 6, c = 10, chemin de données de L blocs
    E, L, N = int(1000 * INT), 16, 8
    g, dec = _clair_choisi(6, 10, 2, L, N, E, rng)
    sigma = L + 8
    b = 2 * sigma * N / 2 ** 10 + sigma ** 2 / 2 ** 11 + N / 2 ** 10 + dec / E / 2 ** 6
    m["clair_choisi_multicible"] = {**_freq(g, E), "N": N, "sigma": sigma, "dechiffrements_par_essai": round(dec / E, 2),
                                    "attendu_L_N_sur_2c": round((L - 2) * N / 2 ** 10, 4), "borne_theoreme_14": round(b, 4)}
    c["clair_choisi_falsifie_et_sous_la_borne"] = g > 0 and _sous(g, b, E)
    c["clair_choisi_sigma_N_atteint"] = g / E >= (L - 2) * N / 2 ** 10 / 2
    # inverse : pas de multi-cible sans débits égaux (Lemme 15 a montré le risque de négliger ces requêtes)
    E, N = int(1000 * INT), 48
    gi = _inverse(6, 10, 2, L, N, E, rng)
    bi = 2 * sigma * N / 2 ** 10 + sigma ** 2 / 2 ** 11 + N / 2 ** 10
    m["requetes_inverses"] = {**_freq(gi, E), "N": N, "attendu_N_sur_2c": round(N / 2 ** 10, 4), "borne_theoreme_14": round(bi, 4)}
    c["inverse_falsifie_et_sous_la_borne"] = gi > 0 and _sous(gi, bi, E)
    # Lemme 3 : r = 4, c = 12, m = 2 (k = 8). Le terme naïf N/2^r vaudrait 1.
    E, N = int(3000 * INT), 16
    gk = _cle(4, 12, 2, 1, N, E, rng)
    bk = N / 2 ** 8 + 2 * N / 2 ** 16 + N / 2 ** 12
    m["lemme_3_recherche_de_cle"] = {**_freq(gk, E), "N": N, "borne": round(bk, 4), "terme_naif_N_sur_2r": N / 2 ** 4}
    c["lemme_3_borne_respectee"] = _sous(gk, bk, E)
    c["lemme_3_terme_naif_absent"] = gk / E < N / 2 ** 4 / 4
    c["lemme_3_N_sur_2k_atteint"] = gk / E >= N / 2 / 2 ** 8 / 2
    gi2 = _inv_cle(4, 12, 2, 256, 2000, rng)
    bi2 = 256 / 2 ** 8 + 2 * 256 / 2 ** 16 + 256 / 2 ** 12
    m["lemme_3_inverse"] = {**_freq(gi2, 2000), "N": 256, "borne": round(bi2, 4), "attendu_N_sur_2b": round(256 / 2 ** 16, 4)}
    c["lemme_3_inverse_sous_la_borne"] = _sous(gi2, bi2, 2000)
    # 14-mu : μ = 8, r = 8, c = 8, m = 1 (k = 8)
    E, N, mu = int(3000 * INT), 8, 8
    gm = _cle(8, 8, 1, mu, N, E, rng)
    bm = mu * N / 2 ** 8 + mu * N / 2 ** 8 + 2 * mu * N / 2 ** 16 + mu ** 2 / 2 ** 9
    m["theoreme_14_mu_cle"] = {**_freq(gm, E), "mu": mu, "N": N, "borne": round(bm, 4), "attendu_mu_N_sur_2k": round(mu * N / 2 ** 8, 4)}
    c["mu_borne_respectee"] = _sous(gm, bm, E)
    c["mu_N_sur_2k_atteint"] = gm / E >= mu * N / 2 ** 8 / 2
    # q_d/2^τ
    E, qd = int(3000 * INT), 16
    gt = _tags(8, 8, qd, E, rng)
    m["tags_devines"] = {**_freq(gt, E), "qd": qd, "borne": qd / 2 ** 8}
    c["tag_borne_atteinte_sans_depassement"] = _sous(gt, qd / 2 ** 8, E) and gt / E >= qd / 2 ** 8 / 2
    out = {"controles": c, "mesures": m}
    sauver("aead_modele", out)
    return out


if __name__ == "__main__":
    r = run()
    print(r["controles"])
    print(r["mesures"])
