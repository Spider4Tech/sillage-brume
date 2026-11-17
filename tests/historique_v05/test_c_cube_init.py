# -*- coding: utf-8 -*-
"""Attaque par cubes sur l'initialisation réduite de l'AEAD (noyau C).

Dans l'AEAD, l'état S_K obtenu après absorption de la clé est le même pour
tous les nonces ; le nonce est ensuite XORé dans les nibbles 0..47 du débit,
puis 2 permutations complètes (64 tours) précèdent le premier bloc de flux
(nibbles 0..63). Modèle réduit : R tours entre l'injection du nonce et le
flux. Variables du cube : bits du nonce ; inconnue : S_K (512 bits —
le retrouver suffit à déchiffrer sous cette clé pour tout nonce).

Pour chaque R et chaque dimension :
  - distingueur : bits de flux à somme nulle (au hasard 128 ± 8 sur 256) ;
  - récupération d'état : superpoly p_j(S_K) NON constant mais LINÉAIRE
    (test de Blum–Luby–Rubinfeld : p(a) ⊕ p(b) ⊕ p(a ⊕ b) ⊕ p(0) = 0 sur
    ESSAIS paires aléatoires, puis CONFIRMATION sur ESSAIS nouvelles paires
    pour les candidats ; un bit aléatoire passe avec probabilité 2^-2·ESSAIS,
    soit < 10^-8 faux positif sur tout le test) → équations linéaires en
    S_K, attaque de type Dinur–Shamir.
"""
import math

import numpy as np

from tests import noyau_c as C
from tests.commun import sauver
from sillage import brume512 as B

N = B.N
SEUIL = 128 + 6 * 8
ESSAIS = 20
DIMS_LIN = (8, 12, 16) + ((20,) if C.INTENSITE >= 4 else ())
DIMS_ZS = DIMS_LIN + (24,)


def flux_bits(out):
    """256 bits du premier bloc de flux (nibbles 0..63)."""
    return np.unpackbits(out[:64, None], axis=1)[:, 4:].ravel()


def cubes(k, rng):
    """Variables dans les 192 bits du nonce : nibbles complets, ou bits épars."""
    nib = rng.choice(48, k // 4, replace=False)
    return {"nibbles_nonce": [4 * int(q) + b for q in nib for b in range(4)],
            "bits_nonce": sorted(int(b) for b in rng.choice(192, k, replace=False))}


def superpoly(bits, R, etat):
    return flux_bits(C.cube(etat, bits, R))


def lineaires_non_constants(bits, R, rng):
    """Test de Blum–Luby–Rubinfeld sur les 256 superpolys du cube : nombre de superpolys affines non constants."""
    p0 = superpoly(bits, R, np.zeros(N, np.uint8))
    lin = np.ones(256, bool)
    const = np.ones(256, bool)
    for t in range(2 * ESSAIS):
        if t == ESSAIS and not (lin & ~const).any():
            break               # confirmation seulement s'il y a des candidats
        a = rng.integers(0, 16, N, dtype=np.uint8)
        b = rng.integers(0, 16, N, dtype=np.uint8)
        pa, pb, pab = superpoly(bits, R, a), superpoly(bits, R, b), superpoly(bits, R, a ^ b)
        lin &= (pa ^ pb ^ pab ^ p0) == 0
        const &= (pa == p0) & (pb == p0) & (pab == p0)
    return int((lin & ~const).sum())


def run():
    c, m = {}, {}
    C.charger()
    c["noyau_c_conforme"] = C.conformite()[0]
    rng = np.random.default_rng(2718)
    # Témoin du détecteur : aucun superpoly linéaire n'a jamais été trouvé ci-dessous, à aucun tour ; rien ne montrait
    # donc que le test BLR sait en voir un. À 1 tour, un cube de 2 bits d'un même nibble a des superpolys affines
    # non constants (S-box de degré 3 : affines en les 2 autres bits du nibble) : le détecteur doit les trouver.
    # Témoin négatif : un cube de 3 bits du même nibble a des superpolys constants (degré 3), qu'il ne doit pas compter.
    temoin = lineaires_non_constants([0, 1], 1, np.random.default_rng(1))
    temoin_cst = lineaires_non_constants([0, 1, 2], 1, np.random.default_rng(2))
    m["temoin_1_tour_superpolys_lineaires"] = {"cube_2_bits": temoin, "cube_3_bits_attendu_0": temoin_cst}
    c["temoin_detecteur_lineaire_trouve_les_superpolys_a_1_tour"] = temoin > 0 and temoin_cst == 0
    portee_zs = portee_lin = 0
    for R in range(1, 9):
        ligne, zs_vu, lin_vu = {}, False, False
        for k in DIMS_ZS:
            for nom, bits in cubes(k, rng).items():
                cle = f"2^{k}_{nom}"
                s0 = superpoly(bits, R, rng.integers(0, 16, N, dtype=np.uint8))
                zeros = int(256 - s0.sum())
                e = {"bits_nuls_sur_256": zeros}
                zs_vu |= zeros >= SEUIL
                if k in DIMS_LIN and zeros < 256:
                    nl = lineaires_non_constants(bits, R, rng)
                    e["superpolys_lineaires_non_constants"] = nl
                    lin_vu |= nl > 0
                ligne[cle] = e
        m[R] = ligne
        if zs_vu:
            portee_zs = R
        if lin_vu:
            portee_lin = R
        if not zs_vu and not lin_vu:
            break
    m["portee"] = {"distingueur_somme_nulle_tours": portee_zs,
                   "superpoly_lineaire_tours": portee_lin,
                   "tours_reels_nonce_vers_flux": 2 * B.N_ROUNDS,
                   "marge_sur_une_permutation": B.N_ROUNDS - max(portee_zs, portee_lin),
                   "faux_positif_lineaire_par_bit": 2.0 ** (-2 * ESSAIS)}
    c["aucun_superpoly_lineaire_au_dela_de_4_tours"] = portee_lin <= 4
    c["marge_au_moins_16_tours_sur_une_permutation"] = B.N_ROUNDS - max(portee_zs, portee_lin) >= 16
    out = {"controles": c, "mesures": m}
    sauver("c_cube_init" + C.SUFFIXE, out)
    return out


if __name__ == "__main__":
    import json
    from tests.commun import _conv
    print(json.dumps(run(), indent=1, ensure_ascii=False, default=_conv))
