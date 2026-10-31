# -*- coding: utf-8 -*-
"""
SILLAGE-SIG — Signatures par décodage de syndrome (MPC-in-the-Head)
===================================================================
Même problème dur qu'avant, le décodage de syndrome BINAIRE aléatoire (H3) ; le
protocole de Stern (134 Ko à λ = 128) laisse la place à un protocole MPC-in-the-Head
à la SDitH (Feneuil–Joux–Rivain, CRYPTO 2022), avec partage en hypercube
(Aguilar-Melchor et al., EUROCRYPT 2023) : 8,4 Ko à λ = 128, 34,6 Ko à λ = 256.

Relation prouvée : H = [H' | I], x = (x_A ‖ x_B), H·x = y et wt(x) ≤ w.
Points d'évaluation : F_poly = GF(2^e) entier, n = 2^e, f_i = i. F(X) = X^n + X s'annule
sur tous les f_i, et F'(f_i) = 1. S interpole x, Q = Π_{x_i=1} (X + f_i) unitaire de degré w.
S·Q s'annule sur F_poly : S·Q = P·F avec deg P < w, et réciproquement cette égalité
donne wt(x) ≤ w. Témoin partagé : (x_A, Q, P).

Un tour (répétition) : N = 2^D parties virtuelles, partage additif des graines d'un
arbre GGM. Le signataire vérifie S·Q = P·F en t points r_j de GF(2^ep) ⊃ F_poly, avec un
triplet de Beaver (a, b, c = a·b) par point et un défi ε_j :
    α = ε·Q(r) + a,  β = S(r) + b,  v = c + α·b + β·a + ε·F(r)·P(r) + α·β = 0.
Hypercube : pour chaque dimension d, seules deux « parties » sont simulées (somme des
parts dont le bit d de l'indice vaut 1, et le reste). La partie cachée i* fixe le côté non
vérifié de chaque dimension, d'où la même solidité 1/N qu'avec N parties et ≈ N/D fois
moins de calculs.

Fiat–Shamir en 5 passes : h1 (engagements) → (r, ε) ; h2 (diffusions) → i* ; signature
= sel ‖ h1 ‖ h2 ‖ (chemin de l'arbre ‖ engagement caché ‖ aux ‖ α ‖ β) par répétition.
Falsification : Adv ≤ q1·P[Bin(τ, p) ≥ τ1] + q2·N^-(τ-τ1+1) pour tout τ1 (PREUVES § 3).

Suite expérimentale de recherche — NE PAS UTILISER EN PRODUCTION.
"""

import hmac
import math
import os

import numpy as np

from .sillage_common import (
    shake, sparse_from_seed, isd_estimate, isd_quantique, grover_portes, categorie_nist,
    KECCAK_TOFFOLI, KECCAK_PROFONDEUR, MAXDEPTHS,
)

# ------------------------------------------------------------------
# Paramètres
# ------------------------------------------------------------------
# n, k, w : code [n, k] de distance voisine de Gilbert–Varshamov, solution unique attendue ;
#   marges ISD classiques ≥ celles de la v0.3 (159,7 et 314,9 bits).
# e, ep : F_poly = GF(2^e) ⊂ GF(2^ep) ; t points ; D = log2 N ; τ répétitions.
# sb = graines (λ + 8 bits : Grover y coûte moins d'un Keccak par essai, contre un flux entier
#   pour σ_π de la v0.3 ; ces 8 bits gardent le coût en portes de la v0.3), hb = hachés (2λ bits).
# pe, pb : polynômes irréductibles ; g : racine de pe dans GF(2^ep) (plongement).
SIG_PARAMS = {
    "Sillage-SIG-128": dict(n=2048, k=1434, r=614, w=103, e=11, ep=44, t=4, D=12, tau=11, lam=128,
                            sb=17, hb=32, pe=(1 << 11) | 0b101, pb=(1 << 44) | 0b100001, g=0x110004f8689),
    "Sillage-SIG-256": dict(n=4096, k=2867, r=1229, w=206, e=12, ep=48, t=4, D=12, tau=23, lam=256,
                            sb=33, hb=64, pe=(1 << 12) | 0b1001, pb=(1 << 48) | 0b1010010001, g=0x1c48e8c6fad3),
}


def _mul(a: int, b: int, poly: int, deg: int) -> int:
    """Produit dans GF(2)[X]/(poly), degré deg."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a >> deg:
            a ^= poly
    return r


def _mul_v(a, b, poly: int, deg: int):
    """Produit terme à terme de deux tableaux uint64."""
    a, b, r = a.copy(), b.copy(), np.zeros_like(a)
    un, po, d = np.uint64(1), np.uint64(poly), np.uint64(deg)
    for _ in range(deg):
        r ^= a & (0 - (b & un))
        b >>= un
        a <<= un
        a ^= po & (0 - (a >> d))
    return r


def _inv_v(a, poly: int, deg: int):
    """Inverse terme à terme : a^(2^deg − 2), Itoh–Tsujii sur la chaîne de 1."""
    r = None
    c = a
    for i in range(deg - 1):
        c = _mul_v(c, c, poly, deg)
        r = c if r is None else _mul_v(r, c, poly, deg)
    return r


class SillageSIG:
    """Signature MPC-in-the-Head sur le décodage de syndrome binaire."""

    def __init__(self, level: str = "Sillage-SIG-128"):
        if level not in SIG_PARAMS:
            raise ValueError(f"niveau inconnu : {level}")
        self.level = level
        self.p = p = SIG_PARAMS[level]
        self._H_cache = {}
        self.xb, self.qb, self.pts = (p["k"] + 7) // 8, (p["w"] * p["e"] + 7) // 8, (p["t"] * p["ep"] + 7) // 8
        self.rb = (p["r"] + 7) // 8
        self.L_part = self.xb + 2 * self.qb + 3 * self.pts
        self.L_aux = self.xb + 2 * self.qb + self.pts
        self._phi = None

    # ---------------- corps ----------------

    def _m(self, a, b):
        return _mul(a, b, self.p["pb"], self.p["ep"])

    def _plongement(self):
        """φ : GF(2^e) → GF(2^ep), table complète (référence : pas de temps constant)."""
        if self._phi is None:
            p, base, c = self.p, [], 1
            for _ in range(p["e"]):
                base.append(c)
                c = self._m(c, p["g"])
            t = np.zeros(p["n"], np.uint64)
            for i, b in enumerate(base):
                t[1 << i:2 << i] = t[:1 << i] ^ np.uint64(b)
            self._phi = t
        return self._phi

    def _em(self, a, b):
        return _mul(a, b, self.p["pe"], self.p["e"])

    # ---------------- matrice H' (dérivée d'une graine, mise en cache) -----

    def _matrix(self, seed_h: bytes) -> list:
        """H' : k colonnes de r bits."""
        key = bytes(seed_h)
        if key not in self._H_cache:
            p = self.p
            self._H_cache[key] = [int.from_bytes(shake(j.to_bytes(8, "big") + b"|" + key, self.rb, b"SILLAGE-SIG|Hcol"), "little")
                                  & ((1 << p["r"]) - 1) for j in range(p["k"])]
        return self._H_cache[key]

    def _mat_vec(self, cols: list, v: int) -> int:
        """H'·v — XOR des colonnes sélectionnées par les bits de v."""
        acc = 0
        while v:
            low = v & -v
            acc ^= cols[low.bit_length() - 1]
            v ^= low
        return acc

    # ---------------- clés ----------------

    def keygen(self):
        p = self.p
        seed_h = os.urandom(32)
        x = sparse_from_seed(os.urandom(32), p["w"], p["n"], b"SILLAGE-SIG|x")
        return self._cles(seed_h, x)

    def _cles(self, seed_h: bytes, x: int):
        """(pk, sk) : pk = (graine, y), sk = x_A ‖ Q ‖ P (octets)."""
        p = self.p
        k, w, e = p["k"], p["w"], p["e"]
        xa, xbv = x & ((1 << k) - 1), x >> k
        y = self._mat_vec(self._matrix(seed_h), xa) ^ xbv
        pos = [i for i in range(p["n"]) if (x >> i) & 1]
        Q = [1]
        for f in pos:                                  # Q = Π (X + f)
            Q = [(Q[i - 1] if i else 0) ^ (self._em(Q[i], f) if i < len(Q) else 0) for i in range(len(Q) + 1)]
        P = [0] * w
        for f in pos:                                  # P = Σ Q / (X + f) (F'(f) = 1)
            c = 0
            for i in range(w, 0, -1):                  # division synthétique
                c = Q[i] ^ self._em(c, f)
                P[i - 1] ^= c
        return (seed_h, y), self._emb(xa, Q[:w], P)

    def _emb(self, xa, Q, P) -> bytes:
        e = self.p["e"]
        qi = sum(c << (e * i) for i, c in enumerate(Q))
        pi = sum(c << (e * i) for i, c in enumerate(P))
        return xa.to_bytes(self.xb, "little") + qi.to_bytes(self.qb, "little") + pi.to_bytes(self.qb, "little")

    def _h(self, tag: bytes, *parts: bytes, n: int = None) -> bytes:
        return shake(b"".join(parts), self.p["hb"] if n is None else n, b"SILLAGE-SIG|" + tag)

    # ---------------- parts ----------------

    def _masques(self):
        """Bits utiles d'une part (les bits de bourrage restent nuls)."""
        p = self.p
        m = bytearray(b"\xff" * self.L_part)
        for fin, bits in ((self.xb, p["k"]), (self.xb + self.qb, p["w"] * p["e"]), (self.xb + 2 * self.qb, p["w"] * p["e"])):
            if bits & 7:
                m[fin - 1] = (1 << (bits & 7)) - 1
        tb = p["t"] * p["ep"]
        if tb & 7:
            for i in range(1, 4):
                m[self.xb + 2 * self.qb + i * self.pts - 1] = (1 << (tb & 7)) - 1
        return int.from_bytes(m, "little")

    def _feuille(self, salt, rep, i, seed, masque):
        """(part, engagement) de la feuille i (sans aux)."""
        ids = rep.to_bytes(4, "big") + i.to_bytes(4, "big")
        return int.from_bytes(self._h(b"f", salt, ids, seed, n=self.L_part), "little") & masque

    def _champs(self, part: int):
        """Découpe une part entière en (x_A, Q, P, a, b, c), entiers."""
        o, res = 0, []
        for l in (self.xb, self.qb, self.qb, self.pts, self.pts, self.pts):
            res.append((part >> (8 * o)) & ((1 << (8 * l)) - 1))
            o += l
        return res

    def _coefs(self, v, nb, bits):
        return [(v >> (bits * i)) & ((1 << bits) - 1) for i in range(nb)]

    def _aux_int(self, xa, Q, P, c):
        """aux placé aux positions de la part (a et b : aucun)."""
        return (xa | Q << (8 * self.xb) | P << (8 * (self.xb + self.qb))
                | c << (8 * (self.xb + 2 * self.qb + 2 * self.pts)))

    def _aux_oct(self, aux: int) -> bytes:
        xa, Q, P, _, _, c = self._champs(aux)
        return (xa.to_bytes(self.xb, "little") + Q.to_bytes(self.qb, "little") + P.to_bytes(self.qb, "little")
                + c.to_bytes(self.pts, "little"))

    def _aux_lit(self, b: bytes) -> int:
        xb, qb = self.xb, self.qb
        return self._aux_int(int.from_bytes(b[:xb], "little"), int.from_bytes(b[xb:xb + qb], "little"),
                             int.from_bytes(b[xb + qb:xb + 2 * qb], "little"),
                             int.from_bytes(b[xb + 2 * qb:], "little"))

    # ---------------- arbre GGM ----------------

    def _noeuds(self, salt, rep, racine):
        p = self.p
        N, sb = 1 << p["D"], p["sb"]
        t = [None] * (2 * N)
        t[1] = racine
        rb = rep.to_bytes(4, "big")
        for j in range(1, N):
            s = self._h(b"a", salt, rb, j.to_bytes(4, "big"), t[j], n=2 * sb)
            t[2 * j], t[2 * j + 1] = s[:sb], s[sb:]
        return t

    def _noeuds_sauf(self, salt, rep, chemin, cache):
        """Reconstruit toutes les graines sauf celle de la feuille cachée."""
        p = self.p
        N, sb = 1 << p["D"], p["sb"]
        t = [None] * (2 * N)
        j = N + cache
        for l in range(p["D"]):
            t[j ^ 1] = chemin[l * sb:(l + 1) * sb]
            j >>= 1
        rb = rep.to_bytes(4, "big")
        for j in range(2, N):
            if t[j] is not None:
                s = self._h(b"a", salt, rb, j.to_bytes(4, "big"), t[j], n=2 * sb)
                t[2 * j], t[2 * j + 1] = s[:sb], s[sb:]
        return t

    def _replier(self, parts_iter):
        """Hypercube : (cotes[d] = Σ parts de bit d à 1, total), en 2N additions."""
        D = self.p["D"]
        cotes, pile, tot = [0] * D, [0] * D, 0
        for i, x in parts_iter:
            for l in range(D):
                if not (i >> l) & 1:
                    pile[l] = x
                    break
                cotes[l] ^= x
                x ^= pile[l]
            else:
                tot = x
        return cotes, tot

    # ---------------- MPC ----------------

    def _defis1(self, h1: bytes):
        """(r, ε) pour chaque répétition et chaque point."""
        p = self.p
        o = 2 * p["tau"] * p["t"] * 6
        s = self._h(b"ch1", h1, n=o)
        m = (1 << p["ep"]) - 1
        v = [int.from_bytes(s[i:i + 6], "little") & m for i in range(0, o, 6)]
        return [[(v[2 * (r * p["t"] + j)], v[2 * (r * p["t"] + j) + 1]) for j in range(p["t"])] for r in range(p["tau"])]

    def _defis2(self, h2: bytes):
        p = self.p
        s = self._h(b"ch2", h2, n=2 * p["tau"])
        return [int.from_bytes(s[2 * r:2 * r + 2], "little") & ((1 << p["D"]) - 1) for r in range(p["tau"])]

    def _prepa(self, r):
        """Pour un point r : L_i(r) (i < n), F(r), puissances r^i (i ≤ w)."""
        p = self.p
        n, deg, poly = p["n"], p["ep"], p["pb"]
        Fr = r
        for _ in range(p["e"]):
            Fr = self._m(Fr, Fr)
        Fr ^= r
        phi = self._plongement()
        if Fr == 0:                                    # r ∈ F_poly : L_i(r) = 1 si f_i = r, 0 sinon
            L = (phi == np.uint64(r)).astype(np.uint64)
        else:
            d = phi ^ np.uint64(r)
            L = _mul_v(_inv_v(d, poly, deg), np.full(n, Fr, np.uint64), poly, deg)
        pw = [1]
        for _ in range(p["w"]):
            pw.append(self._m(pw[-1], r))
        return L, Fr, np.array(pw[:-1], np.uint64), pw[-1]

    def _simule(self, part, cols, ys, defis, prep, cte, ouv=None):
        """Diffusion d'un côté, pour tous les points : [(α_s, β_s, v_s)]. cte : le côté porte
        les constantes (y, r^w, α·β). ouv : (α, β) ouverts, requis pour v."""
        p = self.p
        k, w, e, ep, deg, poly = p["k"], p["w"], p["e"], p["ep"], p["ep"], p["pb"]
        xa, Qi, Pi, a, b, c = self._champs(part)
        xbv = self._mat_vec(cols, xa) ^ (ys if cte else 0)
        x = xa | xbv << k
        bits = np.unpackbits(np.frombuffer(x.to_bytes(p["n"] // 8, "little"), np.uint8), bitorder="little").astype(bool)
        phi = self._plongement()
        Qe = phi[np.array(self._coefs(Qi, w, e), np.int64)]
        Pe = phi[np.array(self._coefs(Pi, w, e), np.int64)]
        A, B, C = self._coefs(a, p["t"], ep), self._coefs(b, p["t"], ep), self._coefs(c, p["t"], ep)
        res = []
        for j, (r, eps) in enumerate(defis):
            L, Fr, pw, rw = prep[j]
            S = int(np.bitwise_xor.reduce(L[bits])) if bits.any() else 0
            Qr = int(np.bitwise_xor.reduce(_mul_v(Qe, pw, poly, deg))) ^ (rw if cte else 0)
            Pr = int(np.bitwise_xor.reduce(_mul_v(Pe, pw, poly, deg)))
            al, be = self._m(eps, Qr) ^ A[j], S ^ B[j]
            if ouv is None:
                res.append((al, be, 0))
            else:
                oa, ob = ouv[j]
                v = C[j] ^ self._m(oa, B[j]) ^ self._m(ob, A[j]) ^ self._m(self._m(eps, Fr), Pr)
                if cte:
                    v ^= self._m(oa, ob)
                res.append((al, be, v))
        return res

    def _oct_pts(self, vals) -> bytes:
        ep = self.p["ep"]
        return sum(v << (ep * i) for i, v in enumerate(vals)).to_bytes(self.pts, "little")

    def _pkh(self, pk):
        seed_h, y = pk
        return self._h(b"pkh", seed_h + y.to_bytes(self.rb, "little"))

    # ---------------- API ----------------

    def sign(self, sk: bytes, pk, msg: bytes, salt: bytes = None) -> bytes:
        """salt : aléatoire ; fixé uniquement pour les tests de conformité C/Python."""
        p = self.p
        N, D, tau, sb = 1 << p["D"], p["D"], p["tau"], p["sb"]
        cols = self._matrix(pk[0])
        salt = os.urandom(32) if salt is None else salt
        mh, pkh = self._h(b"msg", msg), self._pkh(pk)
        # Graine maîtresse couverte par sk (un aléa défaillant ne répète pas les graines
        # d'un message à l'autre : deux défis sur les mêmes graines livreraient x).
        mseed = self._h(b"mseed", sk, salt, mh)
        wit = self._aux_int(int.from_bytes(sk[:self.xb], "little"), int.from_bytes(sk[self.xb:self.xb + self.qb], "little"),
                            int.from_bytes(sk[self.xb + self.qb:], "little"), 0)
        masque = self._masques()
        arbres, coms, cotes_tous, tots, auxs, h1s = [], [], [], [], [], []
        for rep in range(tau):
            racine = self._h(b"r", mseed, rep.to_bytes(4, "big"), n=sb)
            t = self._noeuds(salt, rep, racine)
            parts = [self._feuille(salt, rep, i, t[N + i], masque) for i in range(N)]
            cotes, tot = self._replier(enumerate(parts))
            *_, a, b, c = self._champs(tot)
            ep = p["ep"]
            ab = sum(self._m(x, y) << (ep * j) for j, (x, y) in enumerate(zip(self._coefs(a, p["t"], ep), self._coefs(b, p["t"], ep))))
            aux = (wit ^ tot) & self._aux_int((1 << (8 * self.xb)) - 1, (1 << (8 * self.qb)) - 1, (1 << (8 * self.qb)) - 1, 0)
            aux |= (ab ^ c) << (8 * (self.xb + 2 * self.qb + 2 * self.pts))
            tot ^= aux
            cotes = [x ^ aux for x in cotes]           # la feuille N−1 a tous ses bits à 1
            auxb = self._aux_oct(aux)
            rb = rep.to_bytes(4, "big")
            cm = [self._h(b"c", salt, rb, i.to_bytes(4, "big"), t[N + i]) for i in range(N - 1)]
            cm.append(self._h(b"c", salt, rb, (N - 1).to_bytes(4, "big"), t[2 * N - 1], auxb))
            arbres.append(t); coms.append(cm); cotes_tous.append(cotes); tots.append(tot); auxs.append(auxb)
            h1s.append(self._h(b"com", salt, rb, b"".join(cm)))
        h1 = self._h(b"h1", salt, pkh, mh, b"".join(h1s))
        ch1 = self._defis1(h1)
        diff, ouverts = bytearray(), []
        for rep in range(tau):
            prep = [self._prepa(r) for r, _ in ch1[rep]]
            ouv = self._simule(tots[rep], cols, pk[1], ch1[rep], prep, True)
            oa = [(a, b) for a, b, _ in ouv]
            ouverts.append(oa)
            diff += self._oct_pts([a for a, _ in oa]) + self._oct_pts([b for _, b in oa])
            for d in range(D):
                sd = self._simule(cotes_tous[rep][d], cols, pk[1], ch1[rep], prep, False, oa)
                diff += b"".join(self._oct_pts([s[q] for s in sd]) for q in range(3))
        h2 = self._h(b"h2", salt, pkh, mh, h1, bytes(diff))
        ch2 = self._defis2(h2)
        out = bytearray(salt + h1 + h2)
        for rep in range(tau):
            i = ch2[rep]
            j, t = N + i, arbres[rep]
            for _ in range(D):
                out += t[j ^ 1]
                j >>= 1
            oa = ouverts[rep]
            # dernière feuille cachée : aux ne sert pas au vérifieur, il vaut 0 (encodage unique)
            out += coms[rep][i] + (auxs[rep] if i != N - 1 else bytes(self.L_aux))
            out += self._oct_pts([a for a, _ in oa]) + self._oct_pts([b for _, b in oa])
        return bytes(out)

    def sig_len(self) -> int:
        p = self.p
        return 32 + 2 * p["hb"] + p["tau"] * (p["D"] * p["sb"] + p["hb"] + self.L_aux + 2 * self.pts)

    def verify(self, pk, msg: bytes, sig: bytes) -> bool:
        p = self.p
        N, D, tau, sb, hb = 1 << p["D"], p["D"], p["tau"], p["sb"], p["hb"]
        if len(sig) != self.sig_len() or not (0 <= pk[1] < 1 << p["r"]):
            return False
        cols = self._matrix(pk[0])
        salt, h1, h2 = sig[:32], sig[32:32 + hb], sig[32 + hb:32 + 2 * hb]
        mh, pkh = self._h(b"msg", msg), self._pkh(pk)
        ch1, ch2 = self._defis1(h1), self._defis2(h2)
        masque = self._masques()
        lr = D * sb + hb + self.L_aux + 2 * self.pts
        ep = p["ep"]
        h1s, diff = [], bytearray()
        for rep in range(tau):
            o = 32 + 2 * hb + rep * lr
            chemin = sig[o:o + D * sb]
            com_c = sig[o + D * sb:o + D * sb + hb]
            o += D * sb + hb
            auxb = sig[o:o + self.L_aux]
            alb = sig[o + self.L_aux:o + self.L_aux + self.pts]
            beb = sig[o + self.L_aux + self.pts:o + self.L_aux + 2 * self.pts]
            al_i, be_i = int.from_bytes(alb, "little"), int.from_bytes(beb, "little")
            aux = self._aux_lit(auxb)
            cache = ch2[rep]
            if (aux & ~masque) or al_i >> (p["t"] * ep) or be_i >> (p["t"] * ep) or (cache == N - 1 and aux):
                return False                            # encodage non canonique (SUF-CMA : PREUVES § 3.3)
            t = self._noeuds_sauf(salt, rep, chemin, cache)
            rb = rep.to_bytes(4, "big")
            cm, parts = [], []
            for i in range(N):
                if i == cache:
                    cm.append(com_c)
                    parts.append((i, 0))
                    continue
                x = self._feuille(salt, rep, i, t[N + i], masque)
                if i == N - 1:
                    x ^= aux
                    cm.append(self._h(b"c", salt, rb, i.to_bytes(4, "big"), t[N + i], auxb))
                else:
                    cm.append(self._h(b"c", salt, rb, i.to_bytes(4, "big"), t[N + i]))
                parts.append((i, x))
            cotes, tot = self._replier(iter(parts))
            h1s.append(self._h(b"com", salt, rb, b"".join(cm)))
            prep = [self._prepa(r) for r, _ in ch1[rep]]
            A, B = self._coefs(al_i, p["t"], ep), self._coefs(be_i, p["t"], ep)
            oa = list(zip(A, B))
            diff += alb + beb
            for d in range(D):
                if (cache >> d) & 1:                    # cachée du côté 1 : on simule le côté 0
                    sd = self._simule(cotes[d] ^ tot, cols, pk[1], ch1[rep], prep, True, oa)
                    sd = [(a ^ sa, b ^ sb_, sv) for (a, b), (sa, sb_, sv) in zip(oa, sd)]
                else:
                    sd = self._simule(cotes[d], cols, pk[1], ch1[rep], prep, False, oa)
                diff += b"".join(self._oct_pts([s[q] for s in sd]) for q in range(3))
        ok1 = self._h(b"h1", salt, pkh, mh, b"".join(h1s))
        ok2 = self._h(b"h2", salt, pkh, mh, h1, bytes(diff))
        return hmac.compare_digest(ok1, h1) and hmac.compare_digest(ok2, h2)

    # ---------------- tailles & sécurité ----------------

    def sizes(self):
        return dict(pk_bytes=32 + self.rb, sk_bytes=self.xb + 2 * self.qb, sig_bytes=self.sig_len())

    def faux_positif_log2(self) -> float:
        """p par répétition : le tricheur passe le MPC sans témoin, ((n + w)/2^ep)^t (PREUVES § 3)."""
        p = self.p
        return p["t"] * (math.log2(p["n"] + p["w"]) - p["ep"])

    def falsification_termes(self):
        """(τ1, log2 P[Bin(τ, p) ≥ τ1], log2 N^-(τ−τ1+1)), pour le meilleur τ1 du Théorème 8."""
        p = self.p
        tau, lp, D = p["tau"], self.faux_positif_log2(), p["D"]
        lb = lambda a, b: (math.lgamma(a + 1) - math.lgamma(b + 1) - math.lgamma(a - b + 1)) / math.log(2)
        res = []
        for t1 in range(1, tau + 2):
            termes = [lb(tau, i) + i * lp for i in range(t1, tau + 1)]         # P[Bin ≥ t1] ≤ Σ C(τ,i)·p^i
            haut = max(termes, default=-math.inf)
            bin_ = haut + math.log2(sum(2 ** (x - haut) for x in termes)) if termes else -math.inf
            res.append((max(bin_, -(tau - t1 + 1) * D), t1, bin_, -(tau - t1 + 1) * D))
        return min(res)[1:]

    def falsification_bits(self) -> float:
        """Coût de falsification : les deux termes du Théorème 8 au meilleur τ1."""
        _, a, b = self.falsification_termes()
        return -max(a, b)

    def security_estimate(self):
        """Classique : ISD sur (n, k, w), falsification 5 passes, graines λ, collisions.
        Quantique : Grover sur la falsification (√N^τ ou √(1/p)) et sur les graines, BHT sur les
        hachés, ISD accélérés ; portes sous MAXDEPTH. Voir PREUVES § 5 bis."""
        p = self.p
        n, k = p["n"], p["k"]
        est = isd_estimate(n, k, p["w"])
        forge, sigma, hb = self.falsification_bits(), 8 * p["sb"], 8 * p["hb"]
        q = isd_quantique(n, k, p["w"])
        log_g_fs = math.log2(4 * KECCAK_TOFFOLI)
        log_d_fs = math.log2(4 * KECCAK_PROFONDEUR)
        # Oracle de graine : un engagement (un Keccak)
        log_g_s, log_d_s = math.log2(KECCAK_TOFFOLI), math.log2(KECCAK_PROFONDEUR)
        portes = {md: round(min(grover_portes(forge, log_g_fs, log_d_fs, md),
                                grover_portes(sigma, log_g_s, log_d_s, md),
                                q["prange_portes_maxdepth"][md]), 1) for md in MAXDEPTHS}
        q_bits = dict(falsification_grover=round(forge / 2, 1), graine_grover=sigma / 2,
                      collision_bht=round(hb / 3, 1), isd_prange_grover=q["prange"],
                      isd_marche_qram_gratuite=q["minimum"])
        return dict(
            isd=est,
            forgery_fs_bits=round(forge, 1),
            graine_bits=sigma,
            collision_bits=hb / 2,
            effective_bits=round(min(est["classique"], forge, sigma, hb / 2), 1),
            quantique_isd_bits=est["quantique_prange_grover"],
            quantique=dict(bits=q_bits, effectif_bits=round(min(q_bits.values()), 1),
                           isd=q, portes_maxdepth=portes, categorie_nist=categorie_nist(portes)),
        )
