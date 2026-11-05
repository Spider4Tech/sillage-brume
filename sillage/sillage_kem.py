# -*- coding: utf-8 -*-
"""
SILLAGE-KEM — Mécanisme d'encapsulation de clés par décodage bruité
====================================================================
Famille : LPN creux quasi-cyclique (régime d'Alekhnovich, structure type
QC-MDPC durcie), code correcteur RM(1,7) dupliqué, CASCADE DE BRUIT (twist
SILLAGE : e = e1 ⊕ π(e2) avec π permutation publique d'octets), rejet
implicite (transformée de Fujisaki-Okamoto simplifiée).

Problème de dureté sous-jacent :
    Récupération x, y creux depuis (h, s = x·h ⊕ y) dans R = F2[z]/(z^n - 1)
    — décodage de syndrome quasi-cyclique (NP-dur en général, 45+ ans de
    cryptanalyse, aucun algorithme quantique connu au-delà d'ISD quantique,
    dont le gain est modeste et absorbé par les paramètres).

Principe « dégradation sûre » : la structure (cascade, mode tensoriel) ne
porte JAMAIS la sécurité — si elle est attaquée, on retombe sur le KEM à
bruit uniforme (h_mode="uniform"), lui-même réductible au décodage de
syndrome ordinaire.

Suite expérimentale de recherche — NE PAS UTILISER EN PRODUCTION.
"""

import math

import numpy as np

from .sillage_common import (
    shake, random_bytes, ring_mul, sparse_from_seed, sparse_random,
    hamming_weight, perm_from_seed, apply_perm_int,
    isd_estimate,
)

# ------------------------------------------------------------------
# Jeux de paramètres
# ------------------------------------------------------------------
# n  : longueur de l'anneau R = F2[z]/(z^n - 1) — PREMIER avec 2 générateur
#      (vérifié : ord2(n) = n-1 → aucun sous-anneau de petit degré)
# k  : bits de message encodés (matière à clé de session), par octets
# D  : répétitions de chaque position du code interne RM(1,7), réparties par une
#      permutation publique ; un bloc de L = 128·D bits porte un octet de μ ;
#      n2 = (k/8)·L
# w  : poids creux des secrets x, y et des aléas r1, r2
# we : poids de CHAQUE bruit de la cascade (e1, e2) — total ≈ 2·we
# theta : paramètre de Chernoff de la validation des clés (fixé, public)
#
# v0.3 : paramètres re-dimensionnés avec un estimateur ISD concret
# (Prange / Stern-Dumer / BJMM, sillage_common.isd_estimate) sur le code
# [2n, n] de poids 2w, moins log2(n) (gain quasi-cyclique) : sécurité ≥ λ+8.
# n (premier d'Artin) est choisi pour que l'échec de décodage CERTIFIÉ
# (borne_echec_log2, Chernoff rigoureux) d'une clé typique soit ≤ 2^-(λ+8) ;
# keygen rejette toute clé au-delà de 2^-λ (contrôle : tests/test_kem.py).
# v0.4 : le code à répétition [k·d, k, d] (taux 1/531) devient RM(1,7) dupliqué
# (taux 1/96 et 1/176) : mêmes w, même preuve, chiffré ÷ 1,8 (PROOFS § 2.3).

PARAMS = {
    "Sillage-128": dict(
        n=50021, k=128, D=14, w=75, we=25, lam=128, ss_len=32, theta=0.7,
        n2=16 * 128 * 14,
    ),
    "Sillage-256": dict(
        n=170003, k=256, D=28, w=140, we=64, lam=256, ss_len=64, theta=0.7,
        n2=32 * 128 * 28,
    ),
}

# Vérification des invariants de paramètres (exécutée à l'import)
for _name, _p in PARAMS.items():
    assert _p["n2"] == (_p["k"] // 8) * 128 * _p["D"], _name
    assert _p["n2"] <= _p["n"], _name


# ------------------------------------------------------------------
# Borne RIGOUREUSE d'échec de décodage (certifiée clé par clé)
# ------------------------------------------------------------------
# Le décodage à maximum de vraisemblance d'un bloc ne peut échouer que si le
# bruit a au moins |S|/2 bits dans le support S de la différence de deux mots de
# code : S = {q : <u, P[q]> = b} pour u ≠ 0 (254 hyperplans, |S| = 64·D ; le
# support « tout le bloc » est couvert, car il contient S_{u,0} ⊔ S_{u,1}).
# Le XOR ne fait qu'annuler : bits du bruit dans S ≤ T1 + T2 + Te, avec
#   T1 = #{(a,b) ∈ r1×y : a+b ∈ S} = Σ_{a∈r1} |(S−a) ∩ y|
# r1 = w positions tirées sans remise (oracle aléatoire) parmi Z_n : par le
# théorème de Hoeffding (1963, th. 4), la fonction génératrice d'un tirage
# sans remise est majorée par celle du tirage avec remise, d'où Chernoff :
#   ln P[T1+T2+Te ≥ |S|/2] ≤ −θ·|S|/2 + w·ln M_y(θ) + w·ln M_x(θ)
#                            + 2·we·ln(1 + (|S|/n2)(e^θ − 1))
# où M_y(θ) = moyenne sur s de e^{θ·c(s)}, c(s) = |(S + s) ∩ y|. Union sur les
# 254 hyperplans et les k/8 blocs. Aucune hypothèse d'indépendance entre positions.
# Le support d'un bloc translaté donne le même multiensemble : un seul bloc suffit.
# Clés avec c(s) > C_MAX : rejetées. Borne d'union exacte (hypergéométrique, 2 secrets × 254 supports × n
# translations) : 2^-16,9 (128) et 2^-12,0 (256) par clé, contre ≈ 6 % de rejets par la borne (tests/test_kem_theta.py) ; la table
# entière T[c] = ⌈2^F·e^{θc}⌉ majore l'exponentielle et le calcul reste identique en C.
C_MAX, F_TABLE = 15, 12


_POS_CACHE = {}


def _positions(D: int) -> list:
    """Position de chaque bit de bloc dans le mot RM : Fisher-Yates public (domaine
    SILLAGE-KEM|rm) sur L = 128·D, modulo 128 ; chaque position du mot a D bits."""
    if D not in _POS_CACHE:
        _POS_CACHE[D] = [q % 128 for q in perm_from_seed(D.to_bytes(4, "big"), 128 * D, b"SILLAGE-KEM|rm")]
    return _POS_CACHE[D]


def _chips(v: int, p: dict) -> np.ndarray:
    """A[i][s] = bits de v, translatés de s, dans les positions du bloc affectées à i."""
    n, D = p["n"], p["D"]
    bits = np.unpackbits(np.frombuffer(v.to_bytes((n + 7) // 8, "little"), np.uint8),
                         bitorder="little")[:n].astype(np.int16)
    A = np.zeros((128, n), np.int16)
    for q, i in enumerate(_positions(D)):
        A[i] += np.roll(bits, -q)
    return A


def _walsh(a: np.ndarray) -> np.ndarray:
    a = a.copy()
    for h in range(7):
        pas = 1 << h
        for i in range(0, 128, 2 * pas):
            g, d = a[i:i + pas].copy(), a[i + pas:i + 2 * pas].copy()
            a[i:i + pas], a[i + pas:i + 2 * pas] = g + d, g - d
    return a


def _comptes(v: int, p: dict):
    """c_{u,b}(s) pour u ≠ 0, b ∈ {0,1} : tableau (254, n)."""
    w = _walsh(_chips(v, p))
    return np.concatenate(((w[0] + w[1:]) // 2, (w[0] - w[1:]) // 2))


def _table(theta: float) -> np.ndarray:
    return np.array([math.ceil(math.ldexp(math.exp(theta * c), F_TABLE)) for c in range(C_MAX + 1)], np.int64)


def histogrammes(x: int, y: int, p: dict):
    """Histogrammes de c par hyperplan, à réutiliser pour plusieurs seuils."""
    return [np.bincount(l) for l in _comptes(x, p)], [np.bincount(l) for l in _comptes(y, p)]


def borne_echec_log2(x: int, y: int, p: dict, seuil: int = None,
                     union: bool = True, hist=None) -> float:
    """log2 d'une borne supérieure PROUVÉE de Pr[échec de décapsulation]
    pour la clé (x, y), sur l'aléa (r1, r2, e1, e2) de l'encapsulation.
    seuil (défaut |S|/2) : borne de Pr[max des bits sur un hyperplan ≥ seuil],
    avec θ optimisé ; union=False : borne pour un seul hyperplan d'un bloc."""
    n, n2, D, w, we = p["n"], p["n2"], p["D"], p["w"], p["we"]
    S = 64 * D
    u = math.log(254 * (p["k"] // 8)) if union else 0.0
    if seuil is None:
        cx, cy = _comptes(x, p), _comptes(y, p)
        if max(cx.max(), cy.max()) > C_MAX:
            return 0.0
        T = _table(p["theta"])
        mx, my = T[cx].sum(axis=1), T[cy].sum(axis=1)
        d = float(n) * (1 << F_TABLE)
        pire = max(float(a) / d * (float(b) / d) for a, b in zip(mx, my))
        th = p["theta"]
        f = -th * S / 2 + w * math.log(pire) + 2 * we * math.log1p(S / n2 * math.expm1(th))
        return min(0.0, (f + u) / math.log(2))
    hx, hy = hist or histogrammes(x, y, p)

    def f(t):
        pire = max(math.log(float((a * np.exp(t * np.arange(len(a)))).sum()) / n)
                   + math.log(float((b * np.exp(t * np.arange(len(b)))).sum()) / n) for a, b in zip(hx, hy))
        return -t * seuil + w * pire + 2 * we * math.log1p(S / n2 * math.expm1(t))

    lo, hi = 1e-4, 12.0                       # max de convexes : recherche ternaire
    for _ in range(60):
        m1, m2 = lo + (hi - lo) / 3, hi - (hi - lo) / 3
        if f(m1) < f(m2):
            hi = m2
        else:
            lo = m1
    return min(0.0, (f((lo + hi) / 2) + u) / math.log(2))


# ------------------------------------------------------------------
# Code interne RM(1,7) dupliqué (encode / décode)
# ------------------------------------------------------------------
# Octet s de μ : u = s & 127, b = s >> 7 ; bit q d'un bloc : b ⊕ <u, P[q]>, P = _positions(D).
# P est public et pseudo-aléatoire : les supports S ne présentent ni fenêtre dense ni
# période, sans quoi la borne certifiée perd jusqu'à 30 bits et varie beaucoup d'une clé à l'autre.
_RM = [[bin(i & u).count("1") & 1 for i in range(128)] for u in range(128)]


def _mot(s: int, D: int) -> int:
    u, b = s & 127, s >> 7
    r = _RM[u]
    return sum((r[i] ^ b) << q for q, i in enumerate(_positions(D)))


def rm_encode(mu: int, p: dict) -> int:
    D, cw = p["D"], 0
    for j in range(p["k"] // 8):
        cw |= _mot((mu >> (8 * j)) & 255, D) << (j * 128 * D)
    return cw


def rm_decode(nv: int, p: dict):
    """Maximum de vraisemblance, bloc par bloc (transformée de Walsh ; à égalité,
    le plus petit u). Retourne (μ, marge) : marge = max sur les blocs et les
    hyperplans des bits de nv ⊕ mot décodé dans S, moins |S|/2 ; le décodage
    est sûr si elle est < 0, le bruit étant alors nv ⊕ mot décodé."""
    D, L = p["D"], 128 * p["D"]
    pos = _positions(D)
    mu, marge = 0, -(1 << 40)
    for j in range(p["k"] // 8):
        g = (nv >> (j * L)) & ((1 << L) - 1)
        c = np.zeros(128, np.int64)
        for q, i in enumerate(pos):
            c[i] += (g >> q) & 1
        t = _walsh((D - 2 * c)[:, None])[:, 0]
        u = int(np.argmax(np.abs(t)))
        b = int(t[u] < 0)
        mu |= (u | b << 7) << (8 * j)
        e = np.array([D - int(c[i]) if _RM[u][i] ^ b else int(c[i]) for i in range(128)], np.int64)
        we_ = _walsh(e[:, None])[:, 0]
        marge = max(marge, int((we_[0] + np.abs(we_[1:]).max()) // 2) - 32 * D)
    return mu, marge


# ------------------------------------------------------------------
# KEM
# ------------------------------------------------------------------

class SillageKEM:
    """KEM SILLAGE (une instance par jeu de paramètres)."""

    def __init__(self, level: str = "Sillage-128", h_mode: str = "uniform",
                 cascade: bool = True):
        if level not in PARAMS:
            raise ValueError(f"niveau inconnu : {level}")
        if h_mode not in ("uniform", "tensor"):
            raise ValueError("h_mode ∈ {'uniform','tensor'}")
        if h_mode == "tensor":
            # Audit v0.3 : h = h1·h2 avec h1, h2 creux est lui-même CREUX
            # (poids ≤ 289) ; s = x·h ⊕ y a alors une densité ≈ 0,25 (z ≈ -180
            # vs uniforme) — la structure porte de l'information, contrairement
            # au principe de dégradation sûre. Mode retiré.
            raise ValueError("h_mode='tensor' retiré (audit v0.3 : clé "
                             "publique distinguable, densité ≈ 0,25)")
        self.level = level
        self.p = PARAMS[level]
        self.h_mode = h_mode
        self.cascade = cascade
        self._pi_cache = {}

    # ---------------- clé publique dérivée ----------------

    def _dense_h(self, sigma_h: bytes) -> int:
        """h dense dans R, déterministe depuis la graine publique."""
        n = self.p["n"]
        nb = (n + 7) // 8
        raw = shake(sigma_h, nb, b"SILLAGE-KEM|h")
        h = int.from_bytes(raw, "little") & ((1 << n) - 1)
        if self.h_mode == "tensor":
            # --- EXPERIMENTAL (dégradation sûre : jamais requis) ---
            # h = h1 ⊙ h2 dans l'anneau : structure de rang produit.
            # Compression de clé supplémentaire ; statut cryptanalytique
            # OUVERT. En cas d'attaque → h_mode="uniform" (sûr).
            w1 = 17 if self.p["lam"] <= 128 else 29
            h1 = sparse_from_seed(sigma_h, w1, n, b"SILLAGE-KEM|h1")
            h2 = sparse_from_seed(sigma_h, w1, n, b"SILLAGE-KEM|h2")
            h = ring_mul(h1, h2, n)
        return h

    def _byte_perm(self, sigma_h: bytes) -> list:
        """Permutation d'octets publique de la cascade (cachée par graine)."""
        key = bytes(sigma_h)
        if key not in self._pi_cache:
            m = self.p["n2"] // 8
            self._pi_cache[key] = perm_from_seed(key, m, b"SILLAGE-KEM|pi")
        return self._pi_cache[key]

    # ---------------- API KEM ----------------

    def keygen(self):
        """(pk, sk) — sk = (x, y, sigma_h, sigma_rej, s) ; s sert à la
        ré-encapsulation FO."""
        p = self.p
        sigma_h = random_bytes(32)
        sigma_rej = random_bytes(32)
        # validation de clé : échec de décodage PROUVÉ ≤ 2^-λ (δ-correction
        # requise par la transformée FO, cf. docs/PROOFS.md)
        while True:
            x = sparse_random(p["w"], p["n"])
            y = sparse_random(p["w"], p["n"])
            if borne_echec_log2(x, y, p) <= -p["lam"]:
                break
        h = self._dense_h(sigma_h)
        s = ring_mul(x, h, p["n"]) ^ y
        pk = (sigma_h, s)
        sk = (x, y, sigma_h, sigma_rej, s)
        return pk, sk

    def _pk_hash(self, pk) -> bytes:
        sigma_h, s = pk
        return shake(sigma_h + s.to_bytes((self.p["n"] + 7) // 8, "little"),
                     32, b"SILLAGE-KEM|pkh")

    def _encrypt(self, pk, mu: int):
        """Chiffrement DÉTERMINISTE : tous les aléas (r1, r2, e1, e2) sont
        dérivés de (μ, H(pk)) — condition de la transformée FO."""
        p = self.p
        sigma_h, s = pk
        h = self._dense_h(sigma_h)
        n, n2, k = p["n"], p["n2"], p["k"]
        coins = shake(mu.to_bytes(k // 8, "little") + self._pk_hash(pk), 32,
                      b"SILLAGE-KEM|coins")
        r1 = sparse_from_seed(coins, p["w"], n, b"SILLAGE-KEM|r1")
        r2 = sparse_from_seed(coins, p["w"], n, b"SILLAGE-KEM|r2")
        u = ring_mul(r1, h, n) ^ r2
        # v = cw(mu) XOR r1.s XOR e — dechiffrement :
        #   v XOR u.x = cw(mu) XOR r1.y XOR e XOR r2.x  (les r1.x.h s'annulent)
        v = rm_encode(mu, p) ^ (ring_mul(r1, s, n) & ((1 << n2) - 1))
        if self.cascade:
            e1 = sparse_from_seed(coins, p["we"], n2, b"SILLAGE-KEM|e1")
            e2 = sparse_from_seed(coins, p["we"], n2, b"SILLAGE-KEM|e2")
            pi = self._byte_perm(sigma_h)
            v ^= e1 ^ apply_perm_int(e2, pi, n2 // 8)
        return u, v

    def _ss(self, mu: int, ct) -> bytes:
        p = self.p
        u, v = ct
        return shake(mu.to_bytes(p["k"] // 8, "little")
                     + u.to_bytes((p["n"] + 7) // 8, "little")
                     + v.to_bytes((p["n2"] + 7) // 8, "little"),
                     p["ss_len"], b"SILLAGE-KEM|ss")

    def encaps(self, pk):
        """(ct, ss) — encapsule une clé de session secrète."""
        mu = int.from_bytes(random_bytes(self.p["k"] // 8), "little")
        ct = self._encrypt(pk, mu)
        return ct, self._ss(mu, ct)

    def decaps(self, sk, ct):
        """ss — transformée FO à rejet implicite : μ décodé, RÉ-ENCAPSULÉ
        et comparé au chiffré reçu ; tout écart (ou échec de décodage)
        donne un secret pseudo-aléatoire lié à sigma_rej.

        Journal v0.3 : la v0.2 ne ré-encapsulait pas — tout chiffré décodable
        était accepté, ce qui expose le schéma aux attaques à chiffrés
        choisis classiques des cryptosystèmes à décodage (IND-CPA seulement).
        """
        p = self.p
        x, y, sigma_h, sigma_rej, s = sk
        u, v = ct
        n, n2 = p["n"], p["n2"]
        if not (0 <= u < (1 << n) and 0 <= v < (1 << n2)):
            u, v = u & ((1 << n) - 1), v & ((1 << n2) - 1)
            ok = False
        else:
            ok = True
        nv = v ^ (ring_mul(x, u, n) & ((1 << n2) - 1))
        mu = rm_decode(nv, p)[0]
        # La ré-encapsulation est TOUJOURS calculée, même si le décodage a
        # échoué : sauter cette étape rendrait l'échec de décodage visible
        # au temps de réponse (oracle des attaques par réaction sur les
        # codes QC). Les deux secrets sont calculés, puis l'un est choisi.
        ok &= self._encrypt((sigma_h, s), mu) == (u, v)
        ss_ok = self._ss(mu, (u, v))
        ss_rej = shake(sigma_rej + u.to_bytes((n + 7) // 8, "little")
                       + v.to_bytes((n2 + 7) // 8, "little"),
                       p["ss_len"], b"SILLAGE-KEM|rej")
        return ss_ok if ok else ss_rej

    # ---------------- tailles ----------------

    def sizes(self):
        p = self.p
        return dict(
            pk_bytes=(p["n"] + 7) // 8 + 32,
            ct_bytes=(p["n"] + 7) // 8 + (p["n2"] + 7) // 8,
            sk_bytes=3 * ((p["n"] + 7) // 8) + 64,
            ss_bytes=p["ss_len"],
        )

    # ---------------- estimation de sécurité ----------------

    def security_estimate(self):
        """log2 des coûts d'attaque (sillage_common.isd_estimate).

        Récupération de clé : (x, y) mot de poids 2w du code QC [2n, n]
        engendré par (1, h) ; gain QC : n rotations → − log2 n.
        Récupération de message : (r1, r2) de poids 2w depuis u = r1·h ⊕ r2
        (gain DOOM − log2(n)/2) ; variante à 3 blocs (u, v) = r1·(h, s) ⊕
        (r2, e ⊕ cw) : Prange à ensemble d'information pondéré par bloc
        (densités inégales), corrigé du même gain BJMM/Prange.
        On retient le minimum."""
        p = self.p
        n, n2, w, we = p["n"], p["n2"], p["w"], p["we"]
        est = isd_estimate(2 * n, n, 2 * w)
        gain = est["prange"] - est["classique"]
        cle = est["classique"] - math.log2(n)
        msg2 = est["classique"] - math.log2(n) / 2
        # 3 blocs : (n, w), (n, w), (n2, 2we) ; on choisit une fraction f_b
        # de chaque bloc dans l'ensemble d'information (Σ f_b·n_b = n) ;
        # coût ≈ − Σ t_b·log2(1 − f_b) itérations (optimum : 1 − f_b ∝ t_b/n_b)
        blocs = [(n, w), (n, w), (n2, 2 * we)]
        lam_lo, lam_hi = 1e-9, 1e9
        for _ in range(200):                # 1 − f_b = min(1, λ·t_b/n_b)
            lm = math.sqrt(lam_lo * lam_hi)
            k_pris = sum(nb * (1 - min(1.0, lm * tb / nb)) for nb, tb in blocs)
            if k_pris > n:
                lam_lo = lm
            else:
                lam_hi = lm
        it3 = -sum(tb * math.log2(min(1.0, lam_hi * tb / nb)) for nb, tb in blocs)
        msg3 = it3 + math.log2(3 * n * n) - gain - math.log2(n) / 2
        msg = min(msg2, msg3)
        return dict(
            isd_code_2n_n=est,
            recuperation_cle_bits=round(cle, 1),
            recuperation_message_bits=round(msg, 1),
            recuperation_message_3_blocs_bits=round(msg3, 1),
            classique_bits=round(min(cle, msg), 1),
            quantique_bits=round(est["quantique_prange_grover"]
                                 - math.log2(n), 1),
        )
