# -*- coding: utf-8 -*-
"""Encodage des chemins de l'AEAD parallèle proposé pour la v0.6 (V06_MODES.md § 2), vérifié mécaniquement.
Modèle abstrait : un chemin est une suite d'entrées (bloc de 80 octets, domaine) précédée de ("init", nonce). Seules
comptent les entrées absorbées ; les valeurs de la permutation (et donc les CV) ne sont pas modélisées : la racine
absorbe des CV symboliques ("CV", j, contenu de la feuille), ce qui vérifie l'injectivité du codage de la racine en
(liste des CV, k, ℓ). B est un paramètre (B = 8 192 dans la proposition ; ici aussi de petites valeurs, pour exercer
beaucoup de feuilles).
Contrôles :
  (1) injectivité : deux (A, C) distincts sous le même nonce donnent des chemins finals de racine distincts, et deux
      feuilles distinctes (j, morceau) des chemins finals de feuille distincts ;
  (2) absence de préfixe : aucun chemin final (racine ou feuille) n'est préfixe strict d'un autre chemin final ;
  (3) rôles : un chemin de flux finit par une entrée de domaine 3 (FOURCHE2) ou 0 (bloc plein) ; un chemin de CV par
      le domaine 2 ; un chemin de tag par le domaine 4 ; aucun chemin de tag n'est un chemin de flux ou de CV ;
  (4) décodage : le chemin final de la racine redonne (A, k, ℓ, liste des CV) ;
  (5) témoins : sans le domaine de fourche (5), une racine et une feuille peuvent partager un chemin ; sans l'indice j,
      deux feuilles se confondent.
    python3 chemins_paralleles.py"""
import itertools
import random
import sys

RB = 80
D_AAD, D_TEXTE, D_FOURCHE2, D_RACINE, D_FOURCHE = 1, 2, 3, 4, 5


def blocs(x):
    """x ‖ 0x01 ‖ 0*, découpé en blocs de 80 octets ; au moins un bloc."""
    y = bytes(x) + b"\x01"
    y += b"\x00" * (-len(y) % RB)
    return [y[i:i + RB] for i in range(0, len(y), RB)]


def absorber(prefixe, donnees, dom_fin):
    """Entrées d'une phase : blocs pleins de domaine 0, dernier bloc de domaine dom_fin."""
    b = blocs(donnees)
    return prefixe + [(x, dom_fin if i == len(b) - 1 else 0) for i, x in enumerate(b)]


def tronc(N, A):
    return [("init", N)] + absorber([], A, D_AAD)[0:]


def feuille(tr, j, morceau, sans_fourche=False, sans_indice=False):
    """Retourne (chemins de flux, chemin final) d'une feuille."""
    idx = b"" if sans_indice else j.to_bytes(8, "little")
    p = tr + [(blocs(idx)[0], 0 if sans_fourche else D_FOURCHE), (bytes(RB), D_FOURCHE2)]
    # texte : blocs pleins (domaine 0), puis le dernier, partiel ou vide, avec bourrage et D_TEXTE
    pleins = len(morceau) // RB
    flux = []
    for t in range(pleins):
        flux.append(tuple(p))
        p = p + [(morceau[RB * t:RB * (t + 1)], 0)]
    flux.append(tuple(p))
    dernier = morceau[RB * pleins:]
    p = p + [(blocs(dernier)[0], D_TEXTE)]
    return flux, tuple(p)


def chiffrer(N, A, C, B, **t):
    tr = tronc(N, A)
    k = max(1, -(-len(C) // B))
    flux, cv = [], []
    for j in range(k):
        f, fin = feuille(tr, j, C[B * j:B * (j + 1)], **t)
        flux += f
        cv.append(fin)
    racine_data = [("CV", j, cv[j]) for j in range(k)] + [("k", k), ("l", len(C))]
    racine = tuple(tr + [(tuple(racine_data), D_RACINE)])   # codage de longueur fixe une fois k connu
    return flux, cv, racine


def main():
    rng = random.Random(20261114)
    ok, n = True, 0
    for B in (80, 160, 200, 8192):
        longueurs = sorted({0, 1, 79, 80, 81, B - 1, B, B + 1, 2 * B, 2 * B + 79, 3 * B + 5})
        for la, lc in itertools.product((0, 1, 79, 80, 81, 200), longueurs):
            for _ in range(2):
                N = rng.randbytes(24)
                A, C = rng.randbytes(la), rng.randbytes(lc)
                flux, cv, rac = chiffrer(N, A, C, B)
                n += 1
                # (3) rôles
                ok &= all(f[-1][1] in (D_FOURCHE2, 0) for f in flux)
                ok &= all(c[-1][1] == D_TEXTE for c in cv) and rac[-1][1] == D_RACINE
                ok &= rac not in set(flux) | set(cv)
                # (2) absence de préfixe entre chemins finals
                fin = list(cv) + [rac]
                for a, b in itertools.permutations(fin, 2):
                    ok &= not (len(a) < len(b) and b[:len(a)] == a)
                # (4) décodage de la racine
                data = dict((e[0], e[1:]) for e in rac[-1][0] if e[0] != "CV")
                ok &= data["k"][0] == len(cv) and data["l"][0] == lc
                ok &= [e[2] for e in rac[-1][0] if e[0] == "CV"] == cv
                # (1) injectivité : une variante (A', C') sous le même nonce
                for _ in range(3):
                    A2 = A if rng.random() < 0.5 else rng.randbytes(rng.choice((0, 1, 80, la)))
                    C2 = bytearray(C)
                    if C2 and rng.random() < 0.7:
                        C2[rng.randrange(len(C2))] ^= 1
                    else:
                        C2 = bytearray(rng.randbytes(rng.choice(longueurs)))
                    if (A2, bytes(C2)) == (A, C):
                        continue
                    f2, cv2, rac2 = chiffrer(N, A2, bytes(C2), B)
                    ok &= rac2 != rac
                    # chaque feuille modifiée a un chemin final différent de toutes les feuilles d'origine
                    for i, c in enumerate(cv2):            # même feuille (A, j, morceau) ⟺ même chemin final
                        meme = (A2 == A and i < len(cv) and bytes(C2)[B * i:B * (i + 1)] == C[B * i:B * (i + 1)])
                        ok &= (c in cv) == meme and (not meme or cv.index(c) == i)
    # (5) témoins
    N, A = bytes(24), b""
    _, cvs, _ = chiffrer(N, A, bytes(480), 160, sans_indice=True)   # 3 feuilles pleines identiques
    temoin_indice = len(set(cvs[:-1])) < len(cvs[:-1])       # feuilles pleines identiques confondues
    # sans domaine de fourche : l'entrée d'une feuille vide (indice 0) égale celle d'une racine possible ?
    _, cvf, _ = chiffrer(N, A, b"", 160, sans_fourche=True)
    tr = tronc(N, A)
    racine_courte = tuple(tr + [(blocs(bytes(8))[0], 0)])
    temoin_fourche = cvf[0][:len(racine_courte)] == racine_courte
    print(f"chemins de l'AEAD parallèle : {n} configurations (B ∈ 80, 160, 200, 8 192), contrôles 1–4 "
          f"{'réussis' if ok else 'EN ÉCHEC'} ; témoins : sans indice {temoin_indice}, sans domaine de fourche "
          f"{temoin_fourche}")
    return 0 if ok and temoin_indice and temoin_fourche else 1


if __name__ == "__main__":
    sys.exit(main())
