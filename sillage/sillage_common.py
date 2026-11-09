# -*- coding: utf-8 -*-
"""
SILLAGE — brique commune
========================
Utilitaires partagés par toutes les primitives de la suite SILLAGE.

Représentation canonique : les polynômes de l'anneau R = F2[z]/(z^n - 1)
sont des entiers Python (bit i = coefficient de z^i). Les vecteurs de
F2^m sont également des entiers (bit i = i-ème coordonnée).

Suite expérimentale de recherche — NE PAS UTILISER EN PRODUCTION.
"""

import hashlib
import math
import subprocess
import os

# ------------------------------------------------------------------
# Fonctions de dérivation (SHAKE256, "oracle aléatoire" du prototype)
# ------------------------------------------------------------------

def shake(data: bytes, out_len: int, domain: bytes = b"") -> bytes:
    """SHAKE256 : extension de longueur arbitraire, séparée par domaine."""
    h = hashlib.shake_256(domain + b"|" + data)
    return h.digest(out_len)


def random_bytes(n: int) -> bytes:
    """Entropie cryptographique du système."""
    return os.urandom(n)


# ------------------------------------------------------------------
# Arithmétique dans R = F2[z]/(z^n - 1)  (anneau cyclotomique binaire)
# ------------------------------------------------------------------

def clmul(a: int, b: int) -> int:
    """Produit de convolution SANS retenue (carry-less) de deux entiers.

    Chaque bit positionné de `a` décale `b`. Complexité O(w(a)) opérations
    big-int — toutes les multiplications du KEM impliquent un facteur creux.
    """
    res = 0
    while a:
        low = a & -a          # bit le plus bas
        res ^= b << (low.bit_length() - 1)
        a ^= low
    return res


def ring_mul(a: int, b: int, n: int) -> int:
    """Multiplication dans R = F2[z]/(z^n - 1).

    z^(n+j) ≡ z^j  =>  un seul repli (le produit de deux polynômes de
    degré < n est de degré < 2n).
    """
    mask = (1 << n) - 1
    p = clmul(a, b)
    return (p & mask) ^ (p >> n)


# ------------------------------------------------------------------
# Vecteurs creux
# ------------------------------------------------------------------

def _shake_int_stream(seed: bytes, domain: bytes):
    """Générateur d'entiers 32 bits dérivés de SHAKE (flux déterministe)."""
    counter = 0
    while True:
        chunk = shake(counter.to_bytes(8, "big"), 64, domain + b"|bits|" + seed)
        for off in range(0, 64, 4):
            yield int.from_bytes(chunk[off:off + 4], "big")
        counter += 1


def sparse_from_seed(seed: bytes, weight: int, n: int, domain: bytes = b"") -> int:
    """Vecteur creux de poids EXACT `weight` dans F2^n, déterministe (SHAKE).

    Échantillonnage avec rejet (positions distinctes garanties).
    """
    if weight > n:
        raise ValueError("poids > longueur")
    positions = []
    seen = set()
    gen = _shake_int_stream(seed, domain)
    mask_span = 1
    while mask_span < n:
        mask_span <<= 1
    while len(positions) < weight:
        r = next(gen) & (mask_span - 1)
        if r < n and r not in seen:
            seen.add(r)
            positions.append(r)
    v = 0
    for p in positions:
        v |= 1 << p
    return v


def sparse_random(weight: int, n: int) -> int:
    """Vecteur creux aléatoire (entropie système) — secrets éphémères."""
    return sparse_from_seed(os.urandom(32), weight, n, domain=b"eph")


# ------------------------------------------------------------------
# Permutations d'octets (cascade de bruit, protocole de Stern)
# ------------------------------------------------------------------

def perm_from_seed(seed: bytes, m: int, domain: bytes = b"perm") -> list:
    """Fisher-Yates déterministe (SHAKE) : permutation de {0..m-1}."""
    gen = _shake_int_stream(seed, domain)
    perm = list(range(m))
    for i in range(m - 1, 0, -1):
        span = i + 1
        mask = 1
        while mask < span:
            mask <<= 1
        while True:
            r = next(gen) & (mask - 1)
            if r < span:
                break
        perm[i], perm[r] = perm[r], perm[i]
    return perm


def apply_perm_int(x: int, perm: list, nbytes: int) -> int:
    """Applique une permutation d'indices d'OCTETS à un entier (poids préservé)."""
    src = x.to_bytes(nbytes, "little")
    out = bytearray(nbytes)
    for i, p in enumerate(perm):
        out[i] = src[p]
    return int.from_bytes(bytes(out), "little")


# ------------------------------------------------------------------
# Estimation de sécurité : décodage de syndrome (famille ISD)
# ------------------------------------------------------------------

def _lb(n: float, k: float) -> float:
    """log2 C(n, k) (n, k réels, via lgamma) ; -inf hors domaine."""
    if k < 0 or k > n:
        return float("-inf")
    return (math.lgamma(n + 1) - math.lgamma(k + 1)
            - math.lgamma(n - k + 1)) / math.log(2)


def _log2_add(*xs: float) -> float:
    m = max(xs)
    return m + math.log2(sum(2 ** (x - m) for x in xs))


def _gauss(n: int, k: int) -> float:
    """log2 du coût d'une élimination (amorti, favorable à l'attaquant)."""
    return math.log2(n * (n - k))


def isd_prange(n: int, k: int, w: int) -> float:
    """log2 du coût de Prange : itérations C(n,w)/C(n-k,w) × élimination
    de Gauss ≈ n·(n-k) opérations (amortie)."""
    return _lb(n, w) - _lb(n - k, w) + _gauss(n, k)


def _deux_listes(n: int, k: int, w: int, partage, p_max: int, l_max: int, inner=None):
    """Optimum (coût, p, l, log2 taille de liste) d'un ISD à deux listes de
    taille L = C(partage(l)/2, p/2) et fenêtre l, avec succès
    C(partage/2, p/2)²·C(n-k-l, w-p)/C(n, w). `inner(L)` remplace le coût de
    la fusion (modèle quantique). On arrête p quand l'optimum à p fixé n'a pas
    progressé sur 8 valeurs (la parité de p/2 fait osciller le coût)."""
    best, local, attente = (isd_prange(n, k, w), 0, 0, 0.0), math.inf, 0
    for p in range(2, min(p_max, w) + 1, 2):
        ici = math.inf
        for l in range(0, min(l_max, n - k - (w - p)) + 1, 2):
            L = _lb(partage(l) / 2, p / 2)
            proba = 2 * L + _lb(n - k - l, w - p) - _lb(n, w)
            if inner:
                cout = -proba / 2 + _log2_add(_gauss(n, k), inner(L))
            else:
                cout = _log2_add(_gauss(n, k), L + 1, 2 * L - l) - proba
            ici = min(ici, cout)
            if cout < best[0]:
                best = (cout, p, l, L)
        attente = attente + 1 if ici >= local else 0
        local = min(local, ici)
        if attente >= 8:
            break
    return best


def _c_isd():
    """Le noyau C de l'estimateur, ou None sans compilateur (repli : Python, même résultat)."""
    try:
        from . import sillage_c
        sillage_c.lib()
        return sillage_c
    except (OSError, subprocess.CalledProcessError, AttributeError):
        return None


def _stern(n, k, w, p_max=400, l_max=1000, inner=None):
    """Stern (1989) : listes sur k/2 colonnes, l positions de pivot nulles."""
    C = _c_isd() if inner is None or inner is EXPOSANT_INTERNE else None
    if C:
        return C.isd_deux_listes(n, k, w, False, p_max, l_max, EXPOSANT_WALK_LISTE if inner else -1.0)
    return _deux_listes(n, k, w, lambda l: k, p_max, l_max, inner)


def _dumer(n, k, w, p_max=400, l_max=1000, inner=None):
    """Dumer (1991) : listes sur (k+l)/2 colonnes, élimination partielle."""
    C = _c_isd() if inner is None or inner is EXPOSANT_INTERNE else None
    if C:
        return C.isd_deux_listes(n, k, w, True, p_max, l_max, EXPOSANT_WALK_LISTE if inner else -1.0)
    return _deux_listes(n, k, w, lambda l: k + l, p_max, l_max, inner)


def isd_dumer(n: int, k: int, w: int) -> float:
    return _dumer(n, k, w)[0]


def _bjmm(n: int, k: int, w: int, p_max: int = 400, e_max: int = 100, l_max: int = 1500):
    C = _c_isd()
    return C.isd_bjmm(n, k, w, p_max, e_max, l_max) if C else _bjmm_ref(n, k, w, p_max, e_max, l_max)


def _bjmm_ref(n: int, k: int, w: int, p_max: int = 400, e_max: int = 100, l_max: int = 1500):
    """Référence Python de sillage/c/isd.c. Optimum (coût, p, ε, l, log2 L0, log2 L1) de BJMM (profondeur 2,
    représentations), modèle concret simplifié :
      p1 = p/2 + ε, représentations R = C(p, p/2)·C(k+l-p, ε), l1 = log2 R ;
      listes de base L0 = C((k+l)/2, p1/2), niveau 1 : L1 = C(k+l, p1)/2^l1 ;
      coût/itération = L0 + L0²/2^l1 + L1²/2^(l-l1) ;
      succès = C(k+l, p)·C(n-k-l, w-p)/C(n, w), soit une représentation
      supposée toujours trouvée : favorable à l'attaquant (tests/c/isd_comparaison.c
      mesure l'écart). ε impair ou p1 impair : L0 interpolé, encore favorable
      à l'attaquant. Arrêt de p et de ε comme dans _deux_listes."""
    best, local, attente = (isd_dumer(n, k, w), 0, 0, 0, 0.0, 0.0), math.inf, 0
    g = _gauss(n, k)
    for p in range(2, min(p_max, w) + 1, 2):
        ici, local_e, att_e = math.inf, math.inf, 0
        for eps in range(0, e_max + 1):
            p1, ici_e = p // 2 + eps, math.inf
            for l in range(2, min(l_max, n - k - (w - p)) + 1, 2):
                R = _lb(p, p // 2) + _lb(k + l - p, eps)
                l1 = min(max(R, 0.0), l)
                L0 = _lb((k + l) / 2, p1 / 2)
                L1 = _lb(k + l, p1) - l1
                cout = _log2_add(g, L0 + 2, 2 * L0 - l1 + 1, 2 * L1 - (l - l1))
                cout -= _lb(k + l, p) + _lb(n - k - l, w - p) - _lb(n, w)
                ici_e = min(ici_e, cout)
                if cout < best[0]:
                    best = (cout, p, eps, l, L0, L1)
            att_e = att_e + 1 if ici_e >= local_e else 0
            local_e = min(local_e, ici_e)
            if att_e >= 4:
                break
        attente = attente + 1 if local_e >= local else 0
        local = min(local, local_e)
        if attente >= 8:
            break
    return best


def isd_bjmm(n: int, k: int, w: int) -> float:
    return _bjmm(n, k, w)[0]


def isd_estimate(n: int, k: int, w: int) -> dict:
    """Estimations classiques (Prange, Stern, Dumer, BJMM), avec paramètres
    optimaux, et quantique (Prange + Grover) — log2 des opérations."""
    pr, st, du, bj = isd_prange(n, k, w), _stern(n, k, w), _dumer(n, k, w), _bjmm(n, k, w)
    return dict(prange=round(pr, 1), stern=round(st[0], 1), dumer=round(du[0], 1),
                bjmm=round(bj[0], 1), classique=round(min(pr, st[0], du[0], bj[0]), 1),
                quantique_prange_grover=round((pr - _gauss(n, k)) / 2 + _gauss(n, k), 1),
                parametres=dict(stern=dict(p=st[1], l=st[2], log2_liste=round(st[3], 1)),
                                dumer=dict(p=du[1], l=du[2], log2_liste=round(du[3], 1)),
                                bjmm=dict(p=bj[1], eps=bj[2], l=bj[3], log2_L0=round(bj[4], 1),
                                          log2_L1=round(bj[5], 1))))


# ------------------------------------------------------------------
# Modèles de coût quantiques (log2) — estimations, pas des circuits vérifiés
# ------------------------------------------------------------------
# Exposants de recherche interne, favorables à l'attaquant (QRAM gratuite) :
# distinction d'éléments par marche quantique (Ambainis, 2/3 de log2 L, pour
# Stern et Dumer) et somme de sous-ensembles par marche (Helm–May 2018,
# 0,226·n, pour BJMM).
EXPOSANT_WALK_LISTE = 2 / 3
EXPOSANT_WALK_BJMM = 0.226
EXPOSANT_INTERNE = lambda L: EXPOSANT_WALK_LISTE * L   # fusion par marche : cas servi par le C
# Keccak-f[1600] réversible : 24 tours de 1600 ET, calcul et décalcul ;
# profondeur comptée en couches de Toffoli (θ et ρ sont de Clifford).
KECCAK_TOFFOLI = 2 * 24 * 1600
KECCAK_PROFONDEUR = 2 * 24
# Seuils NIST (appel PQC 2016) : portes classiques, et 2^x/MAXDEPTH portes
# quantiques pour la recherche de clé AES-128 / 192 / 256.
SEUILS_NIST_CLASSIQUE = {1: 143, 3: 207, 5: 272}
SEUILS_NIST_QUANTIQUE = {1: 170, 3: 233, 5: 298}
MAXDEPTHS = (40, 64, 96)


def grover_portes(log_n: float, log_g: float, log_d: float, log_md: float) -> float:
    """log2 des portes de Grover sur N éléments, oracle de g portes et de
    profondeur d, profondeur totale bornée par MD : √N·g tant que √N·d ≤ MD,
    sinon N·g·d/MD (N·d²/MD² machines en parallèle, √(N/P) itérations)."""
    return max(log_n / 2 + log_g, log_n + log_g + log_d - log_md)


def categorie_nist(portes_par_md: dict) -> int:
    """Plus haute catégorie (1, 3, 5) atteinte pour tous les MAXDEPTH, ou 0."""
    cat = 0
    for c, seuil in SEUILS_NIST_QUANTIQUE.items():
        if all(portes_par_md[md] >= seuil - md for md in MAXDEPTHS):
            cat = c
    return cat


def _bjmm_quantique_ref(n: int, k: int, w: int, depart: float) -> float:
    """BJMM quantique : recherche interne sur les C(k+l, p) vecteurs, marche de Helm–May."""
    bj, r = depart, n - k
    for p in range(2, min(120, w) + 1, 2):
        for l in range(0, min(600, r - (w - p)) + 1, 2):
            esp = _lb(k + l, p)
            proba = esp + _lb(r - l, w - p) - _lb(n, w)
            bj = min(bj, -proba / 2 + _log2_add(_gauss(n, k), EXPOSANT_WALK_BJMM * esp))
    return bj


def isd_quantique(n: int, k: int, w: int) -> dict:
    """Prange, Stern, Dumer et BJMM accélérés (√(1/P) itérations, recherche
    interne par marche quantique), en opérations ; puis Prange–Grover en
    portes sous MAXDEPTH, avec une élimination de r²·n Toffoli et de
    profondeur r (lignes traitées en parallèle)."""
    r = n - k
    n_it = _lb(n, w) - _lb(r, w)
    pr = n_it / 2 + _gauss(n, k)
    st = _stern(n, k, w, inner=EXPOSANT_INTERNE)[0]
    du = _dumer(n, k, w, inner=EXPOSANT_INTERNE)[0]
    C = _c_isd()
    bj = C.isd_bjmm_quantique(n, k, w, EXPOSANT_WALK_BJMM, pr) if C else _bjmm_quantique_ref(n, k, w, pr)
    log_g, log_d = math.log2(r * r * n), math.log2(r)
    portes = {md: round(grover_portes(n_it, log_g, log_d, md), 1) for md in MAXDEPTHS}
    return dict(prange=round(pr, 1), stern=round(st, 1), dumer=round(du, 1), bjmm=round(bj, 1),
                minimum=round(min(pr, st, du, bj), 1), prange_portes_maxdepth=portes,
                categorie_nist=categorie_nist(portes))
