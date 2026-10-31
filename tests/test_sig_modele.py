# -*- coding: utf-8 -*-
"""Sillage-SIG sur modèle réduit : ce que les preuves du § 3 affirment, exécuté.
  - corps : polynômes irréductibles, plongement φ (Lemme 6 suppose un corps) ;
  - Lemme A : exhaustif sur GF(8), dans les deux sens ;
  - Proposition 5 et Lemme 6 : v0 + v1 = ε·T(r) + a·b + c calculé par le vrai _simule ; comptage exact sur K² ;
  - Proposition 6 : le vrai vérifieur, défi i* forcé, n'accepte que la feuille prédite ;
  - Théorème 8 : attaque de Kales–Zaverucha exécutée, falsifications acceptées par le vrai vérifieur ;
  - encodage unique (SUF-CMA) : tout bit modifié rejeté, pour chaque feuille cachée, modèle réduit et C."""
import itertools
import math
import os
import random

from tests.commun import sauver
from sillage.rapide import SillageSIG as Rapide
from sillage.sillage_sig import SIG_PARAMS, SillageSIG

PE, PB = 0b10011, 0x11b           # GF(16), GF(256)


def _mini(D=2, tau=1, t=1):
    """n = 16, k = 6, w = 2, GF(16) ⊂ GF(256) : assez petit pour tout énumérer."""
    s = SillageSIG("Sillage-SIG-128")
    g = next(x for x in range(2, 256) if _racine(x))
    s.p = dict(s.p, n=16, k=6, r=10, w=2, e=4, ep=8, t=t, D=D, tau=tau, sb=4, hb=32, pe=PE, pb=PB, g=g)
    s.rb, s.xb, s.qb, s.pts = 2, 1, 1, (t * 8 + 7) // 8
    s.L_part, s.L_aux = s.xb + 2 * s.qb + 3 * s.pts, s.xb + 2 * s.qb + s.pts
    return s


def _mg(a, b, poly, deg):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a >> deg:
            a ^= poly
    return r


def _racine(x):
    """x⁴ + x + 1 = 0 dans GF(256)."""
    x2 = _mg(x, x, PB, 8)
    return _mg(x2, x2, PB, 8) ^ x ^ 1 == 0


# ---------------- corps ----------------

def _irreductible(poly, d):
    """Rabin : X^(2^d) ≡ X et pgcd(X^(2^(d/q)) − X, poly) = 1 pour chaque premier q | d."""
    def puiss(k):
        a = 2
        for _ in range(k):
            a = _mg(a, a, poly, d)
        return a

    def pgcd(a, b):
        while b:
            while a and a.bit_length() >= b.bit_length():
                a ^= b << (a.bit_length() - b.bit_length())
            a, b = b, a
        return a
    if puiss(d) != 2:
        return False
    return all(pgcd(poly, puiss(d // q) ^ 2) == 1 for q in (2, 3, 5, 7, 11, 13) if d % q == 0)


def _corps():
    ok = {}
    for lvl, q in SIG_PARAMS.items():
        s = SillageSIG(lvl)
        phi = s._plongement()
        ech = random.Random(1).sample(range(q["n"]), 40)
        hom = all(int(phi[s._em(a, b)]) == s._m(int(phi[a]), int(phi[b])) and int(phi[a ^ b]) == int(phi[a]) ^ int(phi[b])
                  for a, b in zip(ech, ech[1:]))
        ok[lvl] = (_irreductible(q["pe"], q["e"]), _irreductible(q["pb"], q["ep"]), q["ep"] % q["e"] == 0, hom)
    return ok


# ---------------- Lemme A, exhaustif sur GF(8) ----------------

def _lemme_a(w, poly=0b1011, e=3):
    n = 1 << e
    M = [[_mg(a, b, poly, e) for b in range(n)] for a in range(n)]

    def pmul(A, B):
        R = [0] * (len(A) + len(B) - 1)
        for i, a in enumerate(A):
            for j, b in enumerate(B):
                R[i + j] ^= M[a][b]
        return R
    # L_i = F / (X + f_i) : F'(f_i) = 1, donc L_i(f_j) = δ_ij
    L = []
    for i in range(n):
        P = [1]
        for j in range(n):
            if j != i:
                P = pmul(P, [j, 1])
        L.append(P)
    def eval_(P, x):
        v = 0
        for c in reversed(P):
            v = M[v][x] ^ c
        return v
    delta = all(eval_(L[i], j) == (i == j) for i in range(n) for j in range(n))
    direct_ok, reciproque_ok, couples = True, True, 0
    for x in range(1 << n):
        S = [0] * n
        for i in range(n):
            if x >> i & 1:
                S = [a ^ b for a, b in zip(S, L[i])]
        trouve = False
        for bas in itertools.product(range(n), repeat=w):
            R = pmul(S, list(bas) + [1])
            R = R + [0] * (n + w - len(R))
            Q2 = [0] * w                                # division par F = X^n + X
            for d in range(n + w - 1, n - 1, -1):
                c = R[d]
                if c:
                    Q2[d - n] = c
                    R[d] = 0
                    R[d - n + 1] ^= c
            if not any(R):
                couples += 1
                trouve = True
                reciproque_ok &= bin(x).count("1") <= w
        direct_ok &= trouve == (bin(x).count("1") <= w)
    return delta, direct_ok, reciproque_ok, couples


# ---------------- Proposition 5, Lemme 6 ----------------

def _parts(sig, salt, rep, xa, Qi, Pi, masque):
    """Parts d'un tricheur : aux corrige vers (x_A, Q, P) et un triplet honnête."""
    p = sig.p
    N, ep = 1 << p["D"], p["ep"]
    t = sig._noeuds(salt, rep, os.urandom(p["sb"]))
    parts = [sig._feuille(salt, rep, i, t[N + i], masque) for i in range(N)]
    cotes, tot = sig._replier(enumerate(parts))
    *_, a, b, c = sig._champs(tot)
    ab = sum(sig._m(x, y) << (ep * j) for j, (x, y) in enumerate(zip(sig._coefs(a, p["t"], ep), sig._coefs(b, p["t"], ep))))
    faux = sig._aux_int(xa, Qi, Pi, 0)
    aux = faux ^ (tot & sig._aux_int((1 << (8 * sig.xb)) - 1, (1 << (8 * sig.qb)) - 1, (1 << (8 * sig.qb)) - 1, 0))
    aux |= (ab ^ c) << (8 * (sig.xb + 2 * sig.qb + 2 * sig.pts))
    tot ^= aux
    return t, [x ^ aux for x in cotes], tot, aux


def _pk_sans_temoin(sig, rng):
    """pk dont aucun x de poids ≤ w n'a le syndrome : le tricheur ne peut pas avoir de témoin."""
    p = sig.p
    while True:
        seed, y = rng.randbytes(32), rng.getrandbits(p["r"])
        cols = sig._matrix(seed)
        ok = True
        for wt in range(p["w"] + 1):
            for pos in itertools.combinations(range(p["n"]), wt):
                x = sum(1 << i for i in pos)
                ok &= (sig._mat_vec(cols, x & ((1 << p["k"]) - 1)) ^ (x >> p["k"])) != y
        if ok:
            return seed, y


def _meilleur_faux(sig, pk, rng):
    """(x_A, Q, P) maximisant les racines de T : x de poids minimal, Q annule w bits de son support, P = 0."""
    p = sig.p
    cols = sig._matrix(pk[0])
    meilleur = min(range(1 << p["k"]), key=lambda xa: bin(xa | (sig._mat_vec(cols, xa) ^ pk[1]) << p["k"]).count("1"))
    x = meilleur | (sig._mat_vec(cols, meilleur) ^ pk[1]) << p["k"]
    sup = [i for i in range(p["n"]) if x >> i & 1]
    Q = [1]
    for f in sup[:p["w"]]:
        Q = [(Q[i - 1] if i else 0) ^ (sig._em(Q[i], f) if i < len(Q) else 0) for i in range(len(Q) + 1)]
    Qi = sum(c << (p["e"] * i) for i, c in enumerate(Q[:p["w"]]))
    return meilleur, Qi, 0, x


def _valeur_T(sig, x, Qi, Pi, r, prep=None):
    """T(r) = S(r)·Q(r) + P(r)·F(r), évalué indépendamment de _simule."""
    p = sig.p
    L, Fr, pw, rw = prep or sig._prepa(r)
    phi = sig._plongement()
    S = 0
    for i in range(p["n"]):
        if x >> i & 1:
            S ^= int(L[i])
    Qr, Pr = rw, 0
    for j in range(p["w"]):
        Qr ^= sig._m(int(phi[(Qi >> (p["e"] * j)) & 15]), int(pw[j]))
        Pr ^= sig._m(int(phi[(Pi >> (p["e"] * j)) & 15]), int(pw[j]))
    return sig._m(S, Qr) ^ sig._m(Pr, Fr)


def _lemme_6(sig, rng, essais):
    """Comptage exact des (r, ε) ∈ K² qui laissent passer un tricheur ; v0 + v1 vérifié sur le vrai _simule."""
    p = sig.p
    pk = _pk_sans_temoin(sig, rng)
    cols = sig._matrix(pk[0])
    masque = sig._masques()
    identite_ok, pire, nul = True, 0, 0
    prep = {r: sig._prepa(r) for r in range(256)}
    fauxes = [_meilleur_faux(sig, pk, rng)]
    for _ in range(essais):
        xa = rng.getrandbits(p["k"])
        fauxes.append((xa, rng.getrandbits(p["w"] * p["e"]), rng.getrandbits(p["w"] * p["e"]),
                       xa | (sig._mat_vec(cols, xa) ^ pk[1]) << p["k"]))
    for xa, Qi, Pi, x in fauxes:
        T = [_valeur_T(sig, x, Qi, Pi, r, prep[r]) for r in range(256)]
        nul += not any(T)
        racines = T.count(0)
        # triplet honnête : a·b + c = 0, le cas le plus favorable au tricheur
        compte = sum(256 if v == 0 else 1 for v in T)
        pire = max(pire, compte / ((p["n"] + p["w"]) * 256))
        t, cotes, tot, aux = _parts(sig, os.urandom(32), 0, xa, Qi, Pi, masque)
        for r, eps in ((rng.randrange(256), rng.randrange(256)) for _ in range(6)):
            defis = [(r, eps)]
            oa = [(u, v) for u, v, _ in sig._simule(tot, cols, pk[1], defis, [prep[r]], True)]
            # côtés de l'axe 0 : la somme des deux v vaut ε·T(r) (triplet honnête)
            v1 = sig._simule(cotes[0], cols, pk[1], defis, [prep[r]], False, oa)[0][2]
            v0 = sig._simule(cotes[0] ^ tot, cols, pk[1], defis, [prep[r]], True, oa)[0][2]
            identite_ok &= (v0 ^ v1) == sig._m(eps, T[r])
    return identite_ok, pire, nul, len(fauxes)


# ---------------- signature d'un tricheur ----------------

class Rep:
    """Une répétition d'un tricheur, parts fixées."""

    def __init__(self, sig, pk, salt, rep, faux, masque):
        self.sig, self.pk, self.salt, self.rep = sig, pk, salt, rep
        xa, Qi, Pi, self.x = faux
        self.Qi, self.Pi = Qi, Pi
        self.t, self.cotes, self.tot, self.aux = _parts(sig, salt, rep, xa, Qi, Pi, masque)
        p = sig.p
        N, rb = 1 << p["D"], rep.to_bytes(4, "big")
        self.auxb = sig._aux_oct(self.aux)
        self.cm = [sig._h(b"c", salt, rb, i.to_bytes(4, "big"), self.t[N + i]) for i in range(N - 1)]
        self.cm.append(sig._h(b"c", salt, rb, (N - 1).to_bytes(4, "big"), self.t[2 * N - 1], self.auxb))
        self.hc = sig._h(b"com", salt, rb, b"".join(self.cm))

    def defi(self, defis):
        s, cols = self.sig, self.sig._matrix(self.pk[0])
        self.defis = defis
        self.prep = [s._prepa(r) for r, _ in defis]
        self.oa = [(u, v) for u, v, _ in s._simule(self.tot, cols, self.pk[1], defis, self.prep, True)]

    def faux_positif(self):
        return all(self.sig._m(eps, _valeur_T(self.sig, self.x, self.Qi, self.Pi, r, pr)) == 0
                   for (r, eps), pr in zip(self.defis, self.prep))

    def diffusion(self, cible, fauxcote=None):
        """Honnête du côté sans la cible. fauxcote : axe → valeur aléatoire engagée sur le côté simulé."""
        s, p, cols = self.sig, self.sig.p, self.sig._matrix(self.pk[0])
        d_ = bytearray(s._oct_pts([x for x, _ in self.oa]) + s._oct_pts([y for _, y in self.oa]))
        for d in range(p["D"]):
            if (cible >> d) & 1:
                sd = s._simule(self.cotes[d] ^ self.tot, cols, self.pk[1], self.defis, self.prep, True, self.oa)
                sd = [(x ^ sa, y ^ sb_, sv) for (x, y), (sa, sb_, sv) in zip(self.oa, sd)]
            else:
                sd = s._simule(self.cotes[d], cols, self.pk[1], self.defis, self.prep, False, self.oa)
            d_ += b"".join(s._oct_pts([v[q] for v in sd]) for q in range(3))
        return bytes(d_)

    def reponse(self, i):
        s, p = self.sig, self.sig.p
        N, j, ch = 1 << p["D"], (1 << p["D"]) + i, bytearray()
        for _ in range(p["D"]):
            ch += self.t[j ^ 1]
            j >>= 1
        aux = self.auxb if i != N - 1 else bytes(s.L_aux)
        return bytes(ch) + self.cm[i] + aux + s._oct_pts([x for x, _ in self.oa]) + s._oct_pts([y for _, y in self.oa])


def _proposition_6(rng, essais):
    """Avec le VRAI vérifieur et i* forcé : un tricheur sans faux positif, honnête du côté sans la cible,
    n'est accepté que sur sa cible. Faux positif : accepté partout."""
    sig = _mini(D=2, tau=1)
    N = 4
    pk = _pk_sans_temoin(sig, rng)
    masque = sig._masques()
    mh, pkh = sig._h(b"msg", b"m"), sig._pkh(pk)
    vu, ok_seul, ok_fp, fp = 0, True, True, 0
    vrai_defis2 = sig._defis2
    faux = _meilleur_faux(sig, pk, rng)
    for _ in range(essais):
        salt = rng.randbytes(32)
        r = Rep(sig, pk, salt, 0, faux, masque)
        h1 = sig._h(b"h1", salt, pkh, mh, r.hc)
        r.defi(sig._defis1(h1)[0])
        cible = rng.randrange(N)
        h2 = sig._h(b"h2", salt, pkh, mh, h1, r.diffusion(cible))
        acceptees = []
        for i in range(N):
            sig._defis2 = lambda _h, i=i: [i]
            acceptees.append(sig.verify(pk, b"m", salt + h1 + h2 + r.reponse(i)))
        sig._defis2 = vrai_defis2
        if r.faux_positif():
            fp += 1
            ok_fp &= all(acceptees)
        else:
            ok_seul &= [i for i, a in enumerate(acceptees) if a] == [cible]
        vu += 1
    return vu, fp, ok_seul, ok_fp


# ---------------- Théorème 8 : attaque de Kales–Zaverucha ----------------

def _borne_8(sig, q1, q2, p_rep):
    p = sig.p
    tau, N = p["tau"], 1 << p["D"]
    def queue(t1):
        return sum(math.comb(tau, i) * p_rep ** i * (1 - p_rep) ** (tau - i) for i in range(t1, tau + 1))
    return min(min(1.0, (q1 + 1) * queue(t1) + (q2 + 1) * N ** -(tau - t1 + 1)) for t1 in range(1, tau + 2))


def _kales_zaverucha(sig, pk, msg, rng, q1_max, q2_max, seuil, masque, faux):
    """Grinder h1 jusqu'à `seuil` faux positifs, puis h2 sur les autres. Renvoie (signature | None, q1, q2)."""
    p = sig.p
    N, tau = 1 << p["D"], p["tau"]
    mh, pkh = sig._h(b"msg", msg), sig._pkh(pk)
    q1 = q2 = 0
    while q1 < q1_max:
        q1 += 1
        salt = rng.randbytes(32)
        reps = [Rep(sig, pk, salt, j, faux, masque) for j in range(tau)]
        h1 = sig._h(b"h1", salt, pkh, mh, b"".join(r.hc for r in reps))
        ch1 = sig._defis1(h1)
        for r, d in zip(reps, ch1):
            r.defi(d)
        fp = [r.faux_positif() for r in reps]
        if sum(fp) < seuil:
            continue
        reste = q2_max - q2
        for _ in range(max(0, reste)):
            q2 += 1
            cibles = [rng.randrange(N) for _ in reps]
            h2 = sig._h(b"h2", salt, pkh, mh, h1, b"".join(r.diffusion(c) for r, c in zip(reps, cibles)))
            ch2 = sig._defis2(h2)
            if all(f or c == i for f, c, i in zip(fp, cibles, ch2)):
                s = salt + h1 + h2 + b"".join(r.reponse(i) for r, i in zip(reps, ch2))
                return s, q1, q2
        return None, q1, q2
    return None, q1, q2


def _attaque_theoreme_8(rng, essais):
    sig = _mini(D=2, tau=3)
    pk = _pk_sans_temoin(sig, rng)
    masque = sig._masques()
    faux = _meilleur_faux(sig, pk, rng)
    p_lemme = (sig.p["n"] + sig.p["w"]) / 256
    res = {}
    for nom, q1, q2, seuil in (("h1_seul", 40, 1, 3), ("h1_puis_h2", 10, 4, 1), ("h2_seul", 1, 16, 0)):
        gagne = valide = 0
        for _ in range(essais):
            s, _, _ = _kales_zaverucha(sig, pk, b"falsifie", rng, q1, q2, seuil, masque, faux)
            if s is not None:
                gagne += 1
                valide += sig.verify(pk, b"falsifie", s)
        res[nom] = dict(succes=gagne, essais=essais, verifiees=valide, frequence=round(gagne / essais, 3),
                        borne_theoreme_8=round(_borne_8(sig, q1, q2, p_lemme), 3))
    return res


# ---------------- encodage unique ----------------

def _bits_modele(rng):
    """Tout bit modifié est rejeté, quelle que soit la feuille cachée (dont la dernière)."""
    sig = _mini(D=2, tau=1)
    while True:
        seed, x = rng.randbytes(32), sum(1 << i for i in rng.sample(range(16), 2))
        pk, sk = sig._cles(seed, x)
        break
    vus = {}
    k = 0
    while len(vus) < 4:
        msg = b"m%d" % k
        k += 1
        s = sig.sign(sk, pk, msg)
        vus.setdefault(sig._defis2(s[64:96])[0], (msg, s))
    acceptes = total = 0
    correct = True
    for i, (msg, s) in vus.items():
        correct &= sig.verify(pk, msg, s)
        for o in range(len(s)):
            for b in range(8):
                z = bytearray(s)
                z[o] ^= 1 << b
                total += 1
                acceptes += sig.verify(pk, msg, bytes(z))
    return correct, acceptes, total


def _bits_c(rng):
    """Niveau réel, C : signature dont une répétition cache la dernière feuille (≈ 1 sur 370), aux nul et verrouillé."""
    lvl = "Sillage-SIG-128"
    R, S = Rapide(lvl), SillageSIG(lvl)
    p = S.p
    hb, N = p["hb"], 1 << p["D"]
    lr = (S.sig_len() - 32 - 2 * hb) // p["tau"]
    pk, sk = R.keygen()
    k = 0
    while True:
        k += 1
        sel = rng.randbytes(32)
        s = R.sign(sk, pk, b"m", sel)
        c = S._defis2(s[32 + hb:32 + 2 * hb])
        if N - 1 in c:
            break
    rep = c.index(N - 1)
    o = 32 + 2 * hb + rep * lr + p["D"] * p["sb"] + hb
    nul = not any(s[o:o + S.L_aux])
    z = bytearray(s)
    z[o] ^= 1
    aux_verrouille = not R.verify(pk, b"m", bytes(z))
    alea = True
    for _ in range(400):
        z = bytearray(s)
        z[rng.randrange(len(s))] ^= 1 << rng.randrange(8)
        alea &= not R.verify(pk, b"m", bytes(z))
    return k, R.verify(pk, b"m", s), nul, aux_verrouille, alea, S.sign(sk, pk, b"m", sel) == s


def run():
    c, m = {}, {}
    rng = random.Random(0x51c)
    for lvl, (pe, pb, sous, hom) in _corps().items():
        c[f"{lvl}_corps_irreductibles"] = pe and pb
        c[f"{lvl}_plongement_morphisme"] = sous and hom
    c["detecteur_irreductibilite"] = _irreductible(0b100011011, 8) and not _irreductible(0b100000001, 8)
    for w in (1, 2, 3):
        delta, direct, reciproque, couples = _lemme_a(w)
        m[f"lemme_A_w_{w}_couples"] = couples
        c[f"lemme_A_exhaustif_w_{w}"] = delta and direct and reciproque
    sig = _mini()
    identite, pire, nul, faux = _lemme_6(sig, rng, 60)
    m["lemme_6"] = dict(tricheurs=faux, pire_fraction_de_la_borne=round(pire, 3), T_nul=nul)
    c["proposition_5_identite_v0_v1_sur_simule"] = identite
    c["lemme_6_borne_respectee_et_serree"] = 0.6 <= pire <= 1 and nul == 0
    vus, fp, seul, ok_fp = _proposition_6(rng, 120)
    m["proposition_6"] = dict(essais=vus, faux_positifs=fp)
    c["proposition_6_seule_la_cible_acceptee"] = seul
    c["proposition_6_faux_positif_accepte_partout"] = ok_fp and fp > 0
    att = _attaque_theoreme_8(rng, int(300 * float(os.environ.get("SILLAGE_INTENSITE", "1"))))
    m["attaque_kales_zaverucha"] = att
    c["falsifications_acceptees_par_le_vrai_verifieur"] = all(a["verifiees"] == a["succes"] for a in att.values()) and any(a["succes"] for a in att.values())
    # marge statistique : 3 écarts-types au-dessus de la borne
    c["theoreme_8_majore_chaque_attaque"] = all(a["frequence"] <= a["borne_theoreme_8"] + 3 * math.sqrt(0.25 / a["essais"]) for a in att.values())
    c["attaque_combinee_atteint_la_borne_a_un_facteur_4_pres"] = att["h1_puis_h2"]["frequence"] >= att["h1_puis_h2"]["borne_theoreme_8"] / 4
    correct, acceptes, total = _bits_modele(rng)
    m["bits_modifies_modele"] = dict(acceptes=acceptes, total=total)
    c["signatures_correctes_pour_chaque_feuille_cachee"] = correct
    c["encodage_unique_modele"] = acceptes == 0 and total > 0
    k, valide, nul_, verrou, alea, conforme = _bits_c(rng)
    m["essais_pour_cacher_la_derniere_feuille"] = k
    c["c_derniere_feuille_cachee_valide"] = valide
    c["c_aux_nul_si_derniere_feuille_cachee"] = nul_
    c["c_aux_verrouille"] = verrou
    c["c_bits_modifies_rejetes"] = alea
    c["c_identique_python_sur_ce_cas"] = conforme
    out = {"controles": c, "mesures": m}
    sauver("sig_modele", out)
    return out


if __name__ == "__main__":
    r = run()
    print(r["controles"])
    print(r["mesures"])
