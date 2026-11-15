# -*- coding: utf-8 -*-
"""Lemme U (AEAD_SECURITY.md § 4 septies) : la « couture » d'une permutation.
Données : φ permutation uniforme de X ; H ⊂ X ; ψ injection uniforme H → X, indépendante ; A = ψ(H), Y = φ(H) ;
π bijection uniforme de A∖Y sur Y∖A. Couture : φ'(x) = ψ(x) sur H ; hors de H, φ'(x) = φ(x) si φ(x) ∉ A, π(φ(x)) sinon.
Vérifié exhaustivement sur de petits ensembles :
  (1) φ' est une permutation, φ'|_H = ψ ;
  (2) φ' est UNIFORME (chaque permutation a exactement le même poids), pour chaque H fixé ;
  (3) φ et φ' ne diffèrent qu'en avant sur H ∪ φ⁻¹(A∖Y), et en arrière sur A ∪ Y.
Témoin : sans π (valeurs de A∖Y laissées en double), φ' n'est pas une permutation.
    python3 couture.py"""
import itertools
import sys
from collections import Counter
from fractions import Fraction


def main():
    for n, H in ((5, (0, 1)), (6, (0, 1)), (6, (2, 4, 5)), (7, (0, 3))):
        X = range(n)
        poids = Counter()
        temoin = 0
        for phi in itertools.permutations(X):
            Y = {phi[x] for x in H}
            for img in itertools.permutations(X, len(H)):          # ψ|_H
                A = set(img)
                AmY, YmA = sorted(A - Y), sorted(Y - A)
                for pi in itertools.permutations(YmA):            # π : A∖Y → Y∖A
                    p = dict(zip(AmY, pi))
                    phi2 = [None] * n
                    for i, x in enumerate(H):
                        phi2[x] = img[i]
                    for x in X:
                        if x not in H:
                            phi2[x] = p.get(phi[x], phi[x])
                    assert sorted(phi2) == list(X)                 # (1) permutation
                    assert all(phi2[x] == img[i] for i, x in enumerate(H))
                    w = Fraction(1, len(list(itertools.permutations(YmA))))
                    poids[tuple(phi2)] += w
                    # (3) points modifiés
                    fwd = {x for x in X if phi2[x] != phi[x]}
                    assert fwd <= set(H) | {x for x in X if phi[x] in A - Y}
                    inv1 = {y: x for x, y in enumerate(phi)}
                    inv2 = {y: x for x, y in enumerate(phi2)}
                    assert {y for y in X if inv1[y] != inv2[y]} <= A | Y
                    # témoin
                    sans = [img[H.index(x)] if x in H else phi[x] for x in X]
                    if sorted(sans) != list(X):
                        temoin += 1
        vals = set(poids.values())
        import math
        assert len(poids) == math.factorial(n) and len(vals) == 1, (n, H, len(poids), vals)
        assert temoin > 0
        print(f"|X| = {n}, H = {H} : {len(poids)} permutations, toutes de même poids {vals.pop()} ; "
              f"points modifiés conformes ; témoin sans π : {temoin} non-permutations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
