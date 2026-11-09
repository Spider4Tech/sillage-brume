# -*- coding: utf-8 -*-
"""Chemins d'erreur et replis de l'API : chaque refus documenté est atteint, chaque repli rend le même résultat.

La mesure de couverture (resultats/COUVERTURE.md) a montré que ces lignes n'étaient jamais exécutées par la batterie.

1. Refus. Paramètres inconnus, clé, nonce ou tours hors domaine, poids > longueur, tampons C de mauvaise taille :
   chacun lève l'exception annoncée. Une clé publique de signature mal formée est refusée, sans exception.
2. Mode TE. Deux erreurs de même valeur dans un bloc (dm = 0, syndromes non nuls) donnent un échec bruyant, de même
   que des parités tronquées, et ce dans les deux implémentations (référence et C).
3. Repli sans C (compilateur absent, simulé). disponible() avertit, SILLAGE_C_OBLIGATOIRE refuse. KEM, SIG, AEAD
   séquentiel et parallèle, TE et hachage passent sur la référence et restent interopérables avec le C.
   L'estimateur ISD sans le noyau C rend les mêmes coûts qu'avec.
4. Codes d'erreur du C. Un code ≠ 0 de l'aléa système devient une OSError, et n'est jamais un tampon nul rendu en
   silence. Une recompilation retire l'ancienne bibliothèque.
5. Témoins. Les auto-tests (brume512.selftest, demo) signalent une implémentation sabotée : leurs branches d'échec
   sont atteignables, et leurs contrôles ne sont donc pas vrais par construction.
"""
import contextlib
import io
import os
import tempfile
import warnings

import numpy as np

from tests.commun import sauver
from sillage import brume512 as B
from sillage import rapide as R
from sillage import sillage_c as C
from sillage import sillage_common as SC
from sillage import sillage_kem as K
from sillage import sillage_sig as S


def leve(exc, f, *a, **k):
    try:
        f(*a, **k)
    except exc:
        return True
    except Exception:
        return False
    return False


def refus(c):
    x = np.zeros(B.N, np.uint8)
    c["tours_hors_domaine_refuses"] = leve(ValueError, B.brume_v1, x, 0) and leve(ValueError, B.brume_v1, x, B.N_ROUNDS + 1)
    c["profil_inconnu_refuse"] = leve(ValueError, B.Brume512, "BRUME-0") and leve(ValueError, B.Brume512P, "BRUME-0")
    c["cle_de_mauvaise_taille_refusee"] = leve(ValueError, B.Brume512, "BRUME-512", bytes(63))
    ok = True
    for cls in (B.Brume512, B.Brume512P, R.Brume512, R.Brume512P):
        br = cls("BRUME-512" if cls in (B.Brume512, R.Brume512) else "BRUME-512p", bytes(64))
        ok &= leve(ValueError, br.encrypt, bytes(23), b"m") and leve(ValueError, br.decrypt, bytes(25), b"m", bytes(16))
    c["nonce_de_mauvaise_taille_refuse_partout"] = ok
    c["kem_niveau_ou_mode_inconnu_refuse"] = (leve(ValueError, K.SillageKEM, "Sillage-64")
                                              and leve(ValueError, K.SillageKEM, "Sillage-128", h_mode="autre"))
    c["sig_niveau_inconnu_refuse"] = leve(ValueError, S.SillageSIG, "Sillage-SIG-64")
    c["poids_superieur_a_la_longueur_refuse"] = leve(ValueError, SC.sparse_from_seed, bytes(32), 11, 10)
    c["binomial_hors_domaine_moins_infini"] = SC._lb(10, 11) == SC._lb(10, -1) == float("-inf")
    t = C.kem_tailles("Sillage-128")
    c["tampons_c_de_mauvaise_taille_refuses"] = (leve(ValueError, C.kem_encaps, "Sillage-128", bytes(t["pk"] - 1))
                                                 and leve(ValueError, C.kem_decaps, "Sillage-128", bytes(t["sk"]), bytes(t["ct"] + 1))
                                                 and leve(ValueError, C.kem_borne, "Sillage-128", bytes(3), bytes(3)))
    sig = R.SillageSIG("Sillage-SIG-128")
    pk, sk = sig.keygen()
    s = sig.sign(sk, pk, b"m")
    c["sig_cle_publique_mal_formee_rejetee"] = (sig.verify(pk, b"m", s) and not sig.verify((pk[0][:31], pk[1]), b"m", s)
                                                and not sig.verify((pk[0], 1 << sig.p["r"]), b"m", s)
                                                and not C.sig_verify("Sillage-SIG-128", bytes(5), b"m", s))
    c["isd_prange_c_egal_reference"] = abs(C.isd_prange(4096, 2867, 206) - SC.isd_prange(4096, 2867, 206)) < 1e-9


def te(c):
    msg = bytes(range(200))
    ok = True
    for cls in (B.Brume512, R.Brume512):
        br = cls("BRUME-512", bytes(64))
        ct, pars, tag, meta = br.encrypt_te(bytes(24), msg)
        canal = bytearray(ct)
        canal[3] ^= 0x5A
        canal[17] ^= 0x5A                                 # même valeur : dm = 0, syndromes non nuls
        ok &= leve(B.Brume512TamperError, br.decrypt_te, bytes(24), bytes(canal), pars, tag, meta)
        ok &= leve(B.Brume512TamperError, br.decrypt_te, bytes(24), ct, pars[:-1], tag, meta)
        ok &= leve(B.Brume512TamperError, br.decrypt_te, bytes(24), ct, pars, tag, (len(ct) + 1).to_bytes(8, "big"))
        ok &= leve(B.Brume512TagError, br.decrypt, bytes(24), ct, bytes(16))
        ok &= br.decrypt_te(bytes(24), ct, pars, tag, meta) == (msg, [])
    c["te_dm_nul_parites_tronquees_tag_faux_refuses"] = ok


@contextlib.contextmanager
def sans_c():
    """Compilateur absent : sillage_c.lib() échoue, l'API passe sur la référence."""
    vrai_lib, vrai_dispo = C.lib, R._dispo

    def absent():
        raise OSError("compilateur absent (simulé)")
    C.lib, R._dispo = absent, None
    try:
        yield
    finally:
        C.lib, R._dispo = vrai_lib, vrai_dispo


def repli(c, m):
    with sans_c():
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            dispo = R.disponible()
        c["repli_avertit_sans_c"] = dispo is False and any(issubclass(x.category, RuntimeWarning) for x in w)
        R._dispo = None
        os.environ["SILLAGE_C_OBLIGATOIRE"] = "1"
        try:
            c["c_obligatoire_refuse_le_repli"] = leve(RuntimeError, R.disponible)
        finally:
            del os.environ["SILLAGE_C_OBLIGATOIRE"]
        R._dispo = False
        kem = R.SillageKEM("Sillage-128")
        pk, sk = kem.keygen()
        ct, ss = kem.encaps(pk)
        kem_ref_ok = kem.decaps(sk, ct) == ss
        sig = R.SillageSIG("Sillage-SIG-128")
        spk, ssk = sig.keygen()
        sg = sig.sign(ssk, spk, b"m")
        sig_ref_ok = sig.verify(spk, b"m", sg)
        aead_ref = {}
        for cls, prof in ((R.Brume512, "BRUME-512"), (R.Brume512P, "BRUME-512p")):
            br = cls(prof, bytes(64))
            aead_ref[prof] = br.encrypt(bytes(24), b"message")
            aead_ref[prof + "_dec"] = br.decrypt(bytes(24), *aead_ref[prof]) == b"message"
        bt = R.Brume512("BRUME-512", bytes(64))
        te_ref = bt.encrypt_te(bytes(24), b"t" * 70)
        te_ref_ok = bt.decrypt_te(bytes(24), *te_ref)[0] == b"t" * 70
        h_ref = (R.brume512_hash(b"h"), R.brume512_hash_arbre(b"h"))
        est_ref = SC.isd_estimate(2048, 1434, 103)
        c_absent = SC._c_isd() is None
    # interopérabilité avec le C, une fois le C revenu
    kc = R.SillageKEM("Sillage-128")
    c["repli_kem_aller_retour_et_lu_par_le_c"] = kem_ref_ok and kc.decaps(sk, ct) == ss
    sc_ = R.SillageSIG("Sillage-SIG-128")
    c["repli_sig_aller_retour_et_lu_par_le_c"] = sig_ref_ok and sc_.verify(spk, b"m", sg)
    ok = all(aead_ref[p + "_dec"] for p in ("BRUME-512", "BRUME-512p"))
    for cls, prof in ((R.Brume512, "BRUME-512"), (R.Brume512P, "BRUME-512p")):
        ok &= cls(prof, bytes(64)).encrypt(bytes(24), b"message") == aead_ref[prof]
    c["repli_aead_sequentiel_et_parallele_identiques_au_c"] = ok
    c["repli_te_identique_au_c"] = te_ref_ok and bt.encrypt_te(bytes(24), b"t" * 70) == te_ref
    c["repli_hachages_identiques_au_c"] = h_ref == (R.brume512_hash(b"h"), R.brume512_hash_arbre(b"h"))
    est_c = SC.isd_estimate(2048, 1434, 103)
    c["estimateur_isd_sans_noyau_c_identique"] = c_absent and est_ref == est_c
    m["estimateur"] = dict(reference=est_ref, c=est_c)


class _Proxy:
    """Bibliothèque C dont une fonction rend un code d'erreur imposé."""

    def __init__(self, lib, nom, rc):
        self._lib, self._nom, self._rc = lib, nom, rc

    def __getattr__(self, a):
        if a == self._nom:
            return lambda *x: self._rc
        return getattr(self._lib, a)


def codes_c(c):
    vrai = C._lib
    ok = True
    try:
        for nom, appel in (("sl_aead_p_decrypt", lambda: C.aead_p_decrypt("BRUME-512p", bytes(64), bytes(24), b"x", bytes(16))),
                           ("sl_kem_keygen", lambda: C.kem_keygen("Sillage-128")),
                           ("sl_sig_keygen", lambda: C.sig_keygen("Sillage-SIG-128"))):
            C._lib = _Proxy(C.lib(), nom, -3)
            ok &= leve(OSError, appel)
        C._lib = _Proxy(C.lib(), "sl_aead_p_decrypt", -1)
        ok &= C.aead_p_decrypt("BRUME-512p", bytes(64), bytes(24), b"x", bytes(16)) is None
    finally:
        C._lib = vrai
    c["code_d_erreur_c_leve_oserror"] = ok
    # recompilation : l'ancienne bibliothèque est retirée
    vrai_build = C.BUILD
    with tempfile.TemporaryDirectory() as d:
        try:
            C.BUILD = d
            vieux = os.path.join(d, "libsillage_000000000000.so")
            open(vieux, "wb").close()
            so = C.compiler()
            c["recompilation_retire_l_ancienne_bibliotheque"] = not os.path.exists(vieux) and os.path.exists(so)
        finally:
            C.BUILD = vrai_build


def temoins(c):
    vrai_dec, vrai_chk = B.Brume512.decrypt, B._te_check
    try:
        B.Brume512.decrypt = lambda self, nonce, ct, tag, aad=b"": b""
        B._te_check = lambda buf, off, par: None
        with contextlib.redirect_stdout(io.StringIO()) as sortie:
            res = B.selftest(verbose=True)
    finally:
        B.Brume512.decrypt, B._te_check = vrai_dec, vrai_chk
    c["selftest_detecte_une_implementation_sabotee"] = (not res["aead_rejet_altere"] and not res["aead_rejet_collision_longueur"]
                                                        and not res["te_echec_bruyant"] and "aead_rejet_altere" in sortie.getvalue())
    c["selftest_sain"] = all(v for v in B.selftest(verbose=False).values() if isinstance(v, bool))
    from sillage import demo
    vrai = (demo.Brume512.decrypt, demo.Brume512.decrypt_te)
    try:
        demo.Brume512.decrypt = lambda self, nonce, ct, tag, aad=b"": b""
        demo.Brume512.decrypt_te = lambda self, *a, **k: (b"", [])
        with contextlib.redirect_stdout(io.StringIO()) as sortie:
            try:
                demo.main()
            except Exception:
                pass
    finally:
        demo.Brume512.decrypt, demo.Brume512.decrypt_te = vrai
    c["demo_signale_une_implementation_sabotee"] = sortie.getvalue().count("(bug") >= 3


def masques(c, m):
    """_masques : exactement les bits utiles de chaque champ, y compris quand un champ ne finit pas sur un octet."""
    ok, cas = True, {}
    for nom, over in (("SIG-128", {}), ("SIG-256", {}), ("t_ep_44_bits", dict(t=1)), ("k_et_we_impairs", dict(k=13, w=3, e=5, t=3, ep=11))):
        s = S.SillageSIG("Sillage-SIG-256" if nom == "SIG-256" else "Sillage-SIG-128")
        if over:
            s.p = dict(s.p, **over)
            p = s.p
            s.xb, s.qb, s.pts = (p["k"] + 7) // 8, (p["w"] * p["e"] + 7) // 8, (p["t"] * p["ep"] + 7) // 8
            s.L_part = s.xb + 2 * s.qb + 3 * s.pts
        p = s.p
        msk = s._masques()
        xa, Q, P, a, b, cc = s._champs(msk)
        attendu = [p["k"], p["w"] * p["e"], p["w"] * p["e"], p["t"] * p["ep"], p["t"] * p["ep"], p["t"] * p["ep"]]
        ok &= [v.bit_length() for v in (xa, Q, P, a, b, cc)] == attendu and all(
            v == (1 << n) - 1 for v, n in zip((xa, Q, P, a, b, cc), attendu))
        cas[nom] = attendu
    c["masques_exactement_les_bits_utiles"] = ok
    m["masques"] = cas


def run():
    c, m = {}, {}
    refus(c)
    te(c)
    repli(c, m)
    codes_c(c)
    temoins(c)
    masques(c, m)
    out = {"controles": c, "mesures": m}
    sauver("erreurs_api", out)
    return out


if __name__ == "__main__":
    out = run()
    for k, v in out["controles"].items():
        print(f"{'OK ' if v else 'ÉCHEC'} {k}")
