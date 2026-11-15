# -*- coding: utf-8 -*-
"""Vérification, sur de petites permutations, des identités ALGÉBRIQUES utilisées par la preuve Q1
(AEAD_SECURITY.md § 4 quinquies). Ce programme ne teste aucun adversaire quantique : il vérifie seulement les égalités
entre permutations sur lesquelles reposent les pas « H*_j = H'_j hors E1 ∪ E2 » et la description des points reprogrammés.

Notations : P permutation de {0..n-1} ; T = [(x_1, y_1), …, (x_j, y_j)] ;
  S_{T,P} = swap(P(x_1), y_1) ∘ … ∘ swap(P(x_j), y_j) ;   P^T = S_{T,P} ∘ P.
Identités vérifiées, pour s0, s1 quelconques et y = P(s1), P1 = P ∘ swap(s0, s1) :
  (I1) swap(P(s0), P(s1)) ∘ P = P ∘ swap(s0, s1) ;
  (I2) si aucun x_i n'est dans {s0, s1} (non E1) :  (P1)^T = P^{T + (s0, y)}   (égalité de permutations) ;
  (I3) si de plus y n'est dans aucun {P(x_i), y_i} (non E2) :  (P1)^T (s0) = y ;
  (I4) P^T diffère de P au plus aux points x_i et P^-1(y_i), et (P^T)^-1 de P^-1 au plus aux points P(x_i) et y_i ;
  (I5) témoin : sans la condition de (I2), l'égalité (I2) échoue pour au moins un cas (la condition n'est pas vide).
    python3 identites_hybrides.py [essais]"""
import random
import sys


def swap(a, b, n):
    s = list(range(n))
    s[a], s[b] = s[b], s[a]
    return s


def comp(f, g):          # f ∘ g
    return [f[g[z]] for z in range(len(g))]


def S(T, P):
    n = len(P)
    s = list(range(n))
    for x, y in T:       # s = swap_1 ∘ … ∘ swap_j
        s = comp(s, swap(P[x], y, n))
    return s


def PT(T, P):
    return comp(S(T, P), P)


def main():
    essais = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    rng = random.Random(20261114)
    c = {"I1": 0, "I2": 0, "I3": 0, "I4": 0}
    temoin = 0
    for _ in range(essais):
        n = rng.choice([8, 16, 32])
        P = list(range(n)); rng.shuffle(P)
        Pi = [0] * n
        for z in range(n):
            Pi[P[z]] = z
        j = rng.randrange(0, 5)
        T = [(rng.randrange(n), rng.randrange(n)) for _ in range(j)]      # quelconque : collisions permises
        s0, s1 = rng.randrange(n), rng.randrange(n)
        y = P[s1]
        P1 = comp(P, swap(s0, s1, n))
        assert comp(swap(P[s0], P[s1], n), P) == P1; c["I1"] += 1
        e1 = any(x in (s0, s1) for x, _ in T)
        e2 = any(y in (P[x], yy) for x, yy in T)
        gauche, droite = PT(T, P1), PT(T + [(s0, y)], P)
        if not e1:
            assert gauche == droite; c["I2"] += 1
            if not e2:
                assert gauche[s0] == y; c["I3"] += 1
        elif gauche != droite:
            temoin += 1
        Q = PT(T, P)
        Qi = [0] * n
        for z in range(n):
            Qi[Q[z]] = z
        df = {x for x, _ in T} | {Pi[yy] for _, yy in T}
        di = {P[x] for x, _ in T} | {yy for _, yy in T}
        assert all(Q[z] == P[z] for z in range(n) if z not in df)
        assert all(Qi[w] == Pi[w] for w in range(n) if w not in di); c["I4"] += 1
    assert temoin > 0, "le témoin (I5) n'a jamais échoué : la condition de (I2) serait inutile"
    print(f"identités vérifiées : {c} ; témoin (I2 sans sa condition) en défaut {temoin} fois ; aucune exception")
    return 0


if __name__ == "__main__":
    sys.exit(main())
