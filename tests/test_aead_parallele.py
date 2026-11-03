# -*- coding: utf-8 -*-
"""Duplex parallèle BRUME-512p (docs/PROOFS.md § 4.5).
  1. Le modèle de la preuve, écrit ici à partir du seul codage, redonne les chiffrés et tags de la référence, et du C.
  2. Lemme 5 : les chemins sont injectifs et aucun n'est préfixe d'un autre (feuilles et racine).
  3. Altérations entre feuilles : échange, troncature, ajout, greffe depuis un autre message, nonce ou AAD changé.
  4. Aucun flux réutilisé entre feuilles ; séparation du mode séquentiel ; sortie indépendante du nombre de threads.
  5. Théorème 14-p sur duplex réduit : le terme σ/2^|CV| et le terme q_d/2^τ, confrontés à des falsifications exécutées."""
import ctypes
import math
import os
import subprocess
import sys

import numpy as np

from tests.commun import RACINE, sauver
from sillage import brume512 as B
from sillage import sillage_c as C
from sillage.brume512 import Brume512, Brume512P as Ref, AEADP_FEUILLE as F, Brume512TagError
from sillage.rapide import Brume512P

INT = float(os.environ.get("SILLAGE_INTENSITE", "1"))
PROFILS = {"BRUME-512p": (32, 16, 128), "BRUME-512-256p": (16, 32, 256)}     # débit (o), tag (o), λ
CLE, NONCE, AAD = bytes(range(64)), bytes(range(24)), b"entete"


def _pad(d, rb):
    d = d + b"\x01" + b"\x00" * ((-len(d) - 1) % rb)
    return [d[i:i + rb] for i in range(0, len(d), rb)]


def prefixe(rb, cle, nonce, aad):
    a = _pad(aad, rb)
    return [(b, 0) for b in _pad(cle + nonce, rb)] + [(b, 0) for b in a[:-1]] + [(a[-1], 1)]


def chemin_feuille(rb, j, c):
    """Entrées du duplex après le préfixe, pour la feuille j de chiffré c (Lemme 5)."""
    p = _pad(c, rb)
    return [(_pad(j.to_bytes(8, "little"), rb)[0], 5), (b"\x00" * rb, 3)] + [(b, 0) for b in p[:-1]] + [(p[-1], 6)]


def chemin_racine(rb, cvs, k, n):
    p = _pad(b"".join(cvs) + k.to_bytes(8, "little") + n.to_bytes(8, "little"), rb)
    return [(b, 0) for b in p[:-1]] + [(p[-1], 4)]


class Modele:
    """S ← P(S ⊕ σ ‖ 0 ⊕ dom·e_127), débit lu avant chaque appel : rien de brume512.py hors de P."""

    def __init__(self, profil):
        self.rb, self.tl, self.lam = PROFILS[profil]
        e = bytearray(64)
        e[58:64] = bytes((12, 1, 2 * self.rb, self.tl, self.lam & 0xFF, 3))
        self.S0 = self.P(bytes(e))

    @staticmethod
    def P(s):
        return B._pack_nibbles(B.brume_v1(B._unpack_bytes(s)))

    def appel(self, S, sigma, dom):
        x = bytearray(S)
        for i, v in enumerate(sigma):
            x[i] ^= v
        x[63] ^= dom << 4
        return self.P(bytes(x))

    def chiffrer(self, cle, nonce, aad, m):
        S = self.S0
        for sigma, dom in prefixe(self.rb, cle, nonce, aad):
            S = self.appel(S, sigma, dom)
        k = max(1, -(-len(m) // F))
        ct, cvs = bytearray(), []
        for j in range(k):
            morceau = m[j * F:(j + 1) * F]
            c_j = bytearray()
            T = S                                                 # le chiffré dépend du flux : calcul pas à pas
            for sigma, dom in chemin_feuille(self.rb, j, b"")[:2]:
                T = self.appel(T, sigma, dom)
            for o in range(0, len(morceau) + 1, self.rb):
                bloc = morceau[o:o + self.rb]
                cb = bytes(a ^ b for a, b in zip(bloc, T))
                c_j += cb
                if len(bloc) == self.rb:
                    T = self.appel(T, cb, 0)
                else:
                    T = self.appel(T, _pad(cb, self.rb)[0], 6)
            ct += c_j
            cvs.append(T[:self.lam // 4])
        T = S
        for sigma, dom in chemin_racine(self.rb, cvs, k, len(m)):
            T = self.appel(T, sigma, dom)
        tag = bytearray()
        while len(tag) < self.tl:
            tag += T[:self.rb]
            if len(tag) < self.tl:
                T = self.P(T)
        return bytes(ct), bytes(tag[:self.tl])


def _rejete(br, n, c, t, a=AAD):
    try:
        br.decrypt(n, c, t, a)
        return False
    except Brume512TagError:
        return True


def alterations(prof):
    """(nombre de cas, tous rejetés) sur un message de 3 feuilles et demie."""
    br = Brume512P(prof, key=CLE)
    m = bytes((i * 13 + 7) & 0xFF for i in range(3 * F + F // 2))
    ct, tag = br.encrypt(NONCE, m, AAD)
    ct2, _ = br.encrypt(bytes(23) + b"\x01", m, AAD)
    fe = [ct[i:i + F] for i in range(0, len(ct), F)]
    cas = {
        "echange_de_feuilles": fe[1] + fe[0] + fe[2] + fe[3],
        "feuilles_identiques": fe[0] + fe[0] + fe[2] + fe[3],
        "troncature_derniere_feuille": ct[:3 * F],
        "troncature_d_un_bloc": ct[:-32],
        "ajout_d_une_feuille": ct + fe[0],
        "ajout_d_un_octet": ct + b"\x00",
        "greffe_d_un_autre_nonce": fe[0] + ct2[F:2 * F] + fe[2] + fe[3],
        "chiffre_vide": b"",
    }
    for o in (0, 1, F - 1, F, F + 31, 2 * F, 3 * F, len(ct) - 1):       # un bit, de part et d'autre des frontières
        x = bytearray(ct)
        x[o] ^= 0x10
        cas[f"bit_{o}"] = bytes(x)
    res = {k: _rejete(br, NONCE, v, tag) for k, v in cas.items()}
    res["nonce_change"] = _rejete(br, bytes(24), ct, tag)
    res["aad_changee"] = _rejete(br, NONCE, ct, tag, AAD + b"x")
    res["cle_changee"] = _rejete(Brume512P(prof, key=bytes(64)), NONCE, ct, tag)
    res["tag_court"] = _rejete(br, NONCE, ct, tag[:-1])
    res["tag_change"] = _rejete(br, NONCE, ct, bytes([tag[0] ^ 1]) + tag[1:])
    return len(res), all(res.values()), [k for k, v in res.items() if not v]


def chemins_sans_prefixe():
    """Lemme 5 : paires de chemins distincts, toutes les formes aux limites des feuilles."""
    ok_inj, ok_pre, n = True, True, 0
    for rb in (32, 16):
        vus = {}
        for nonce in (bytes(24), b"\x01" + bytes(23)):
            pre = prefixe(rb, CLE, nonce, b"")
            pre2 = prefixe(rb, CLE, nonce, b"a")
            for p, a in ((pre, b""), (pre2, b"a")):
                for L in (0, 1, rb - 1, rb, rb + 1, 2 * rb, F - 1, F):
                    for j in (0, 1, 2, 256):
                        vus[(nonce, a, "f", j, L)] = tuple(p + chemin_feuille(rb, j, bytes(L)))
                for k, n_oct in ((1, 0), (1, 5), (2, F + 1), (3, 2 * F + 1)):
                    cvs = [bytes([v]) * (32 if rb == 32 else 64) for v in range(k)]
                    vus[(nonce, a, "r", k, n_oct)] = tuple(p + chemin_racine(rb, cvs, k, n_oct))
        valeurs = list(vus.values())
        ok_inj &= len(set(valeurs)) == len(valeurs)
        for u in valeurs:
            for v in valeurs:
                n += 1
                if u is not v and len(u) < len(v) and v[:len(u)] == u:
                    ok_pre = False
    return ok_inj, ok_pre, n


# ---------------------------------------------------------------- duplex réduit
class Reduit:
    """b = r + c bits, CV de cv bits, tag de r bits. Mêmes appels que le modèle, en blocs entiers."""

    def __init__(self, r, c, cv, rng):
        self.r, self.c, self.cv = r, c, cv
        self.P = rng.permutation(1 << (r + c))
        self.S0 = int(self.P[(r << 4) | 8])

    def ap(self, S, s, dom=0):
        return int(self.P[S ^ (s << self.c) ^ dom])

    def tronc(self, K, N):
        S = self.S0
        for b in K + [N]:
            S = self.ap(S, b)
        return self.ap(S, 1 << (self.r - 1), 1)

    def feuille(self, T0, j, blocs, dech):
        T = self.ap(self.ap(T0, j + 1, 5), 0, 3)
        sortie = []
        for b in blocs:
            z = T >> self.c
            ch = b if dech else z ^ b
            sortie.append(z ^ b)
            T = self.ap(T, ch)
        T = self.ap(T, 1 << (self.r - 1), 6)
        return sortie, T >> (self.r + self.c - self.cv)

    def racine(self, T0, cvs, n):
        T = T0
        for v in cvs:                                        # CV plus long que le débit : en plusieurs blocs
            for d in range(0, self.cv, self.r):
                T = self.ap(T, (v >> d) & ((1 << self.r) - 1))
        return self.ap(T, n % (1 << self.r), 4) >> self.c

    def enc(self, K, N, feuilles):
        T0 = self.tronc(K, N)
        res = [self.feuille(T0, j, f, False) for j, f in enumerate(feuilles)]
        return [x for x, _ in res], self.racine(T0, [v for _, v in res], sum(map(len, feuilles)))

    def dec_ok(self, K, N, feuilles_c, tag):
        T0 = self.tronc(K, N)
        res = [self.feuille(T0, j, f, True) for j, f in enumerate(feuilles_c)]
        return self.racine(T0, [v for _, v in res], sum(map(len, feuilles_c))) == tag


def falsifications(r, c, cv, essais, rng, mode):
    """Un chiffrement connu, une falsification : altération d'une feuille, ou échange de deux feuilles."""
    ok = 0
    M = None
    for e in range(essais):
        if e % 64 == 0:
            M = Reduit(r, c, cv, rng)
        K = [int(rng.integers(1 << r)) for _ in range(2)]
        N = int(rng.integers(1 << r))
        fe = [[int(rng.integers(1 << r)) for _ in range(3)] for _ in range(2)]
        cf, tag = M.enc(K, N, fe)
        if mode == "alteration":
            cf[1][1] ^= 1 + int(rng.integers((1 << r) - 1))
        else:
            cf = [cf[1], cf[0]]
            if cf[0] == cf[1]:
                continue
        ok += M.dec_ok(K, N, cf, tag)
    return ok / essais


def modele_reduit():
    rng = np.random.default_rng(0xB12E)
    r, c, cv = 8, 12, 3
    n = int(20000 * INT)
    sigma = 2 * (2 + 1 + 1 + 2 * (2 + 3 + 1) + 2 * 2 + 1)        # chiffrement et déchiffrement
    borne_col = sigma ** 2 / 2 ** (c + 1)
    f_cv = falsifications(r, c, cv, n, rng, "alteration")
    att_cv = 2 ** -cv + 2 ** -r
    f_tag = falsifications(r, c, 12, n, rng, "alteration")
    att_tag = 2 ** -12 + 2 ** -r
    f_ech = falsifications(r, c, 12, n, rng, "echange")
    z = lambda f, a: abs(f - a) / math.sqrt(a * (1 - a) / n)         # noqa: E731
    return ({"terme_cv_atteint_et_sous_la_borne": z(f_cv, att_cv) < 5,
             "terme_tag_atteint_et_sous_la_borne": f_tag <= att_tag + borne_col + 5 * math.sqrt(att_tag / n)
             and f_tag > 0.5 * att_tag,
             "echange_de_feuilles_sous_la_borne": f_ech <= att_tag + borne_col + 5 * math.sqrt(att_tag / n)},
            {"essais": n, "alteration_cv_3_bits": {"mesure": round(f_cv, 4), "attendu": round(att_cv, 4)},
             "alteration_cv_12_bits": {"mesure": round(f_tag, 5), "attendu": round(att_tag, 5)},
             "echange_cv_12_bits": {"mesure": round(f_ech, 5)}, "sigma": sigma, "sigma2_sur_2c1": round(borne_col, 4)})


def run():
    c, m = {}, {}
    for prof in PROFILS:
        rb = PROFILS[prof][0]
        mod = Modele(prof)
        lg = [0, 1, rb - 1, rb, rb + 1, 3 * rb + 1, F - 1, F, F + 1, 2 * F + 5]
        msgs = [bytes((i * 11 + 5) & 0xFF for i in range(L)) for L in lg]
        ref, rap = Ref(prof, key=CLE), Brume512P(prof, key=CLE)
        c[f"{prof}_modele_de_la_preuve_egal_reference"] = all(mod.chiffrer(CLE, NONCE, AAD, x) == ref.encrypt(NONCE, x, AAD) for x in msgs)
        c[f"{prof}_reference_egale_c"] = all(ref.encrypt(NONCE, x, AAD) == rap.encrypt(NONCE, x, AAD) for x in msgs)
        # autour des seuils de la répartition : voies unitaires, lot partiel, lots pleins (15, 16, 32, 33 feuilles)
        gros = [bytes((i * 3) & 0xFF for i in range(n * F + d)) for n, d in ((15, 0), (16, 1), (32, 0), (33, 7))]
        c[f"{prof}_lots_egaux_reference"] = all(ref.encrypt(NONCE, x) == rap.encrypt(NONCE, x) for x in gros)
        c[f"{prof}_aller_retour"] = all(rap.decrypt(NONCE, *rap.encrypt(NONCE, x, AAD), AAD) == x for x in msgs + gros)
        ct_te, par, t_te, meta = rap.encrypt_te(NONCE, msgs[-1], AAD)     # le mode TE opère sur le chiffré, inchangé
        abime = bytearray(ct_te)
        abime[F + 3] ^= 0x5A
        pt_te, corr = rap.decrypt_te(NONCE, bytes(abime), par, t_te, meta, AAD)
        c[f"{prof}_mode_te"] = pt_te == msgs[-1] and corr == [F + 3]
        n, tous, ko = alterations(prof)
        c[f"{prof}_alterations_rejetees"] = tous
        m[f"{prof}_alterations"] = {"cas": n, "acceptees": ko}
        z = bytes(64 * F)
        ks, _ = rap.encrypt(NONCE, z)
        tetes = {ks[i:i + rb] for i in range(0, len(ks), F)}
        c[f"{prof}_aucun_flux_reutilise_entre_feuilles"] = len(tetes) == 64
        c[f"{prof}_separe_du_mode_sequentiel"] = rap.encrypt(NONCE, b"x" * 64)[0] != Brume512(prof[:-1], key=CLE).encrypt(NONCE, b"x" * 64)[0]
        uns = np.unpackbits(np.frombuffer(ks, dtype=np.uint8)).sum()
        m[f"{prof}_flux_z_bits"] = round(float((uns - 4 * len(ks)) / math.sqrt(2 * len(ks))), 2)
        c[f"{prof}_flux_equilibre"] = abs(m[f"{prof}_flux_z_bits"]) < 5
        # un déchiffrement refusé ne libère rien
        L = C.lib()
        ct, tag = rap.encrypt(NONCE, b"s" * 5000)
        pt = ctypes.create_string_buffer(5000)
        rc = L.sl_aead_p_decrypt(C.PROFILS_P[prof], CLE, NONCE, b"", C._sz(0), ct, C._sz(5000), bytes(32), pt)
        c[f"{prof}_refus_sans_clair"] = rc == -1 and pt.raw[:5000] == bytes(5000)
    c["profil_inconnu_refuse"] = C.lib().sl_aead_p_encrypt(2, CLE, NONCE, b"", C._sz(0), b"", C._sz(0), bytes(1), bytes(32)) == -3
    prog = ("import sys,hashlib;from sillage.rapide import Brume512P as B;"
            "c,t=B('BRUME-512p',key=bytes(64)).encrypt(bytes(24),bytes(100*4096+3));print(hashlib.sha256(c+t).hexdigest())")
    sorties = {subprocess.run([sys.executable, "-c", prog], cwd=RACINE, capture_output=True, text=True, check=True,
                              env={**os.environ, "OMP_NUM_THREADS": str(t)}).stdout for t in (1, 2, 12)}
    c["sortie_independante_des_threads"] = len(sorties) == 1
    inj, pre, npaires = chemins_sans_prefixe()
    c["chemins_injectifs"], c["chemins_sans_prefixe"] = inj, pre
    m["paires_de_chemins"] = npaires
    cr, mr = modele_reduit()
    c.update(cr)
    m["duplex_reduit"] = mr
    sauver("aead_parallele", {"controles": c, "mesures": m})
    print(f"aead_parallele : {sum(c.values())}/{len(c)} contrôles")
    for k, v in c.items():
        if not v:
            print("  ÉCHEC", k)
    print(m["duplex_reduit"])
    return all(c.values())


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
