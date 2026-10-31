# -*- coding: utf-8 -*-
"""Accès Python à l'implémentation C de SILLAGE (sillage/c/).

Compilation à la demande (gcc -O3 -march=native, cache selon l'empreinte
des sources dans sillage/c/build/), chargement ctypes. Mêmes encodages que
le paquet Python (cf. sillage/c/sillage.h) ; conformité vérifiée par
tests/test_c_impl.py.
"""
import ctypes
import glob
import hashlib
import os
import subprocess

ICI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c")
BUILD = os.path.join(ICI, "build")
SOURCES = ["commun.c", "brume512.c", "brume512_avx2.c", "kem.c", "sig.c", "isd.c"]
_lib = None

_p = ctypes.c_char_p
_sz = ctypes.c_size_t


def _empreinte():
    h = hashlib.sha256()
    for f in SOURCES + ["sillage.h", "brume512_tables.h", "brume512_simd.h"]:
        h.update(open(os.path.join(ICI, f), "rb").read())
    with open("/proc/cpuinfo", "rb") as f:          # -march=native : .so propre à ce CPU
        h.update(next((l for l in f if l.startswith(b"flags")), b""))
    return h.hexdigest()[:12]


def compiler():
    so = os.path.join(BUILD, f"libsillage_{_empreinte()}.so")
    if not os.path.exists(so):
        os.makedirs(BUILD, exist_ok=True)
        for vieux in glob.glob(os.path.join(BUILD, "libsillage_*.so")):
            os.remove(vieux)
        tmp = f"{so}.{os.getpid()}.tmp"
        subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-shared", "-fPIC", "-o", tmp]
                       + [os.path.join(ICI, s) for s in SOURCES] + ["-lm"], check=True)
        os.replace(tmp, so)
    return so


def lib():
    global _lib
    if _lib is None:
        L = ctypes.CDLL(compiler())
        L.sl_init()
        L.sl_kem_borne.restype = ctypes.c_double
        L.sl_aead_tag_len.restype = _sz
        L.sl_te_par_len.restype = _sz
        for f in (L.sl_isd_prange, L.sl_isd_deux_listes, L.sl_isd_bjmm, L.sl_isd_bjmm_quantique):
            f.restype = ctypes.c_double
        _lib = L
    return _lib


def _buf(n):
    return ctypes.create_string_buffer(max(n, 1))


def _ok(rc):
    """Échec de l'aléa système (-3) : ne jamais rendre un tampon nul pour une clé."""
    if rc != 0:
        raise OSError(f"SILLAGE C : code {rc} (aléa système indisponible ?)")


# ------------------------------------------------------------- BRUME-512
PROFILS = {"BRUME-512": 0, "BRUME-512-256": 1}


def permute(etat64: bytes) -> bytes:
    b = _buf(64); b.raw = etat64
    lib().sl_brume_permute(b)
    return b.raw[:64]


def permute_ref(etat64: bytes) -> bytes:
    """Permutation de référence (tables, non constant-time)."""
    b = _buf(64); b.raw = etat64
    lib().sl_brume_permute_ref(b)
    return b.raw[:64]


def permute_lot(etats):
    """32 états empaquetés (64 o chacun) → 32 états (noyau vertical AVX2)."""
    b = _buf(32 * 64); b.raw = b"".join(etats)
    lib().sl_brume_permute_lot(b)
    return [b.raw[64 * i:64 * i + 64] for i in range(32)]


def _tableau(blocs):
    arr = (ctypes.c_char_p * len(blocs))(*blocs)
    return arr, (ctypes.c_size_t * len(blocs))(*[len(x) for x in blocs])


def aead_encrypt_multi(profil, cles, nonces, pts, aads=None):
    """Chiffre n messages indépendants (lots de 32, tous les cœurs)."""
    L, pr, n = lib(), PROFILS[profil], len(pts)
    tl = L.sl_aead_tag_len(pr)
    p_arr, p_len = _tableau(pts)
    sorties = [_buf(len(m)) for m in pts]
    c_arr = (ctypes.c_char_p * n)(*[ctypes.cast(x, ctypes.c_char_p) for x in sorties])
    a_arr, a_len = _tableau(aads) if aads else (None, None)
    tags = _buf(tl * n)
    L.sl_aead_encrypt_multi(pr, _sz(n), b"".join(cles), b"".join(nonces), a_arr, a_len, p_arr, p_len, c_arr, tags)
    return [(sorties[i].raw[:len(pts[i])], tags.raw[tl * i:tl * i + tl]) for i in range(n)]


def aead_decrypt_multi(profil, cles, nonces, cts, tags, aads=None):
    """Liste des clairs (None si tag invalide)."""
    L, pr, n = lib(), PROFILS[profil], len(cts)
    c_arr, c_len = _tableau(cts)
    sorties = [_buf(len(m)) for m in cts]
    p_arr = (ctypes.c_char_p * n)(*[ctypes.cast(x, ctypes.c_char_p) for x in sorties])
    a_arr, a_len = _tableau(aads) if aads else (None, None)
    codes = (ctypes.c_int * n)()
    L.sl_aead_decrypt_multi(pr, _sz(n), b"".join(cles), b"".join(nonces), a_arr, a_len, c_arr, c_len,
                            b"".join(tags), p_arr, codes)
    return [sorties[i].raw[:len(cts[i])] if codes[i] == 0 else None for i in range(n)]


class CleAEAD(ctypes.Structure):
    """Contexte de clé (état après absorption de la clé) — sl_aead_cle_t."""
    _fields_ = [("profil", ctypes.c_int), ("etat", ctypes.c_uint8 * 64)]


def aead_cle(profil, cle):
    c = CleAEAD()
    lib().sl_aead_cle(ctypes.byref(c), PROFILS[profil], cle)
    return c


def aead_encrypt_ctx(c, nonce, pt, aad=b""):
    L = lib()
    ct, tag = _buf(len(pt)), _buf(32)
    L.sl_aead_encrypt_ctx(ctypes.byref(c), nonce, aad, _sz(len(aad)), pt, _sz(len(pt)), ct, tag)
    return ct.raw[:len(pt)], tag.raw[:L.sl_aead_tag_len(c.profil)]


def aead_encrypt_multi_ctx(c, nonces, pts, aads=None):
    L, n = lib(), len(pts)
    tl = L.sl_aead_tag_len(c.profil)
    p_arr, p_len = _tableau(pts)
    sorties = [_buf(len(m)) for m in pts]
    c_arr = (ctypes.c_char_p * n)(*[ctypes.cast(x, ctypes.c_char_p) for x in sorties])
    a_arr, a_len = _tableau(aads) if aads else (None, None)
    tags = _buf(tl * n)
    L.sl_aead_encrypt_multi_ctx(ctypes.byref(c), _sz(n), b"".join(nonces), a_arr, a_len, p_arr, p_len, c_arr, tags)
    return [(sorties[i].raw[:len(pts[i])], tags.raw[tl * i:tl * i + tl]) for i in range(n)]


def aead_decrypt_multi_ctx(c, nonces, cts, tags, aads=None):
    L, n = lib(), len(cts)
    c_arr, c_len = _tableau(cts)
    sorties = [_buf(len(m)) for m in cts]
    p_arr = (ctypes.c_char_p * n)(*[ctypes.cast(x, ctypes.c_char_p) for x in sorties])
    a_arr, a_len = _tableau(aads) if aads else (None, None)
    codes = (ctypes.c_int * n)()
    L.sl_aead_decrypt_multi_ctx(ctypes.byref(c), _sz(n), b"".join(nonces), a_arr, a_len, c_arr, c_len,
                                b"".join(tags), p_arr, codes)
    return [sorties[i].raw[:len(cts[i])] if codes[i] == 0 else None for i in range(n)]


def hash_multi(msgs, out_len=32):
    m_arr, m_len = _tableau(msgs)
    out = _buf(out_len * len(msgs))
    lib().sl_hash_multi(_sz(len(msgs)), m_arr, m_len, out, _sz(out_len))
    return [out.raw[out_len * i:out_len * i + out_len] for i in range(len(msgs))]


def hash(msg: bytes, out_len: int = 32) -> bytes:
    out = _buf(out_len)
    lib().sl_hash(msg, _sz(len(msg)), out, _sz(out_len))
    return out.raw[:out_len]


def hash_arbre(msg: bytes, out_len: int = 32) -> bytes:
    out = _buf(out_len)
    lib().sl_hash_arbre(msg, _sz(len(msg)), out, _sz(out_len))
    return out.raw[:out_len]


def aead_encrypt(profil, cle, nonce, pt, aad=b""):
    L, pr = lib(), PROFILS[profil]
    ct, tag = _buf(len(pt)), _buf(32)
    L.sl_aead_encrypt(pr, cle, nonce, aad, _sz(len(aad)), pt, _sz(len(pt)), ct, tag)
    return ct.raw[:len(pt)], tag.raw[:L.sl_aead_tag_len(pr)]


def aead_decrypt(profil, cle, nonce, ct, tag, aad=b""):
    """Texte clair, ou None si le tag est invalide."""
    pt = _buf(len(ct))
    rc = lib().sl_aead_decrypt(PROFILS[profil], cle, nonce, aad, _sz(len(aad)), ct, _sz(len(ct)), tag, pt)
    return pt.raw[:len(ct)] if rc == 0 else None


PROFILS_P = {"BRUME-512p": 0, "BRUME-512-256p": 1}


def aead_p_encrypt(profil, cle, nonce, pt, aad=b""):
    L, pr = lib(), PROFILS_P[profil]
    ct, tag = _buf(len(pt)), _buf(32)
    _ok(L.sl_aead_p_encrypt(pr, cle, nonce, aad, _sz(len(aad)), pt, _sz(len(pt)), ct, tag))
    return ct.raw[:len(pt)], tag.raw[:L.sl_aead_tag_len(pr)]


def aead_p_decrypt(profil, cle, nonce, ct, tag, aad=b""):
    """Texte clair, ou None si le tag est invalide."""
    pt = _buf(len(ct))
    rc = lib().sl_aead_p_decrypt(PROFILS_P[profil], cle, nonce, aad, _sz(len(aad)), ct, _sz(len(ct)), tag, pt)
    if rc not in (0, -1):
        _ok(rc)
    return pt.raw[:len(ct)] if rc == 0 else None


def te_encrypt(profil, cle, nonce, pt, aad=b""):
    L, pr = lib(), PROFILS[profil]
    ct, par, tag, meta = _buf(len(pt)), _buf(L.sl_te_par_len(_sz(len(pt)))), _buf(32), _buf(8)
    L.sl_te_encrypt(pr, cle, nonce, aad, _sz(len(aad)), pt, _sz(len(pt)), ct, par, tag, meta)
    return ct.raw[:len(pt)], par.raw[:L.sl_te_par_len(_sz(len(pt)))], tag.raw[:L.sl_aead_tag_len(pr)], meta.raw[:8]


def te_decrypt(profil, cle, nonce, ct, par, tag, meta, aad=b""):
    """(code, texte clair, corrections) ; code 0, -1 (tag) ou -2 (altération)."""
    L = lib()
    buf, pt = _buf(len(ct)), _buf(len(ct))
    buf.raw = ct
    corr = (ctypes.c_size_t * (len(ct) // 64 + 2))()
    nc = ctypes.c_size_t(0)
    rc = L.sl_te_decrypt(PROFILS[profil], cle, nonce, aad, _sz(len(aad)), buf, _sz(len(ct)), par,
                         _sz(len(par)), tag, meta, pt, corr, ctypes.byref(nc))
    return rc, pt.raw[:len(ct)], list(corr[:nc.value])


# ------------------------------------------------------------------ KEM
NIVEAUX_KEM = {"Sillage-128": 0, "Sillage-256": 1}


def kem_tailles(niveau):
    t = [ctypes.c_size_t() for _ in range(4)]
    lib().sl_kem_tailles(NIVEAUX_KEM[niveau], *[ctypes.byref(x) for x in t])
    return dict(zip(("pk", "sk", "ct", "ss"), (x.value for x in t)))


def kem_keygen(niveau):
    t = kem_tailles(niveau)
    pk, sk = _buf(t["pk"]), _buf(t["sk"])
    _ok(lib().sl_kem_keygen(NIVEAUX_KEM[niveau], pk, sk))
    return pk.raw[:t["pk"]], sk.raw[:t["sk"]]


def kem_encaps(niveau, pk, mu=None):
    t = kem_tailles(niveau)
    ct, ss = _buf(t["ct"]), _buf(t["ss"])
    if mu is None:
        _ok(lib().sl_kem_encaps(NIVEAUX_KEM[niveau], pk, ct, ss))
    else:
        lib().sl_kem_encaps_det(NIVEAUX_KEM[niveau], pk, mu, ct, ss)
    return ct.raw[:t["ct"]], ss.raw[:t["ss"]]


def kem_decaps(niveau, sk, ct):
    t = kem_tailles(niveau)
    ss = _buf(t["ss"])
    lib().sl_kem_decaps(NIVEAUX_KEM[niveau], sk, ct, ss)
    return ss.raw[:t["ss"]]


def kem_borne(niveau, x: bytes, y: bytes) -> float:
    return lib().sl_kem_borne(NIVEAUX_KEM[niveau], x, y)


# ------------------------------------------------------------------ SIG
NIVEAUX_SIG = {"Sillage-SIG-128": 0, "Sillage-SIG-256": 1}


def sig_tailles(niveau):
    t = [ctypes.c_size_t() for _ in range(3)]
    lib().sl_sig_tailles(NIVEAUX_SIG[niveau], *[ctypes.byref(x) for x in t])
    return dict(zip(("pk", "sk", "sig_max"), (x.value for x in t)))


def sig_keygen(niveau):
    t = sig_tailles(niveau)
    pk, sk = _buf(t["pk"]), _buf(t["sk"])
    _ok(lib().sl_sig_keygen(NIVEAUX_SIG[niveau], pk, sk))
    return pk.raw[:t["pk"]], sk.raw[:t["sk"]]


def sig_sign(niveau, sk, pk, msg):
    t = sig_tailles(niveau)
    sig, n = _buf(t["sig_max"]), ctypes.c_size_t(0)
    _ok(lib().sl_sig_sign(NIVEAUX_SIG[niveau], sk, pk, msg, _sz(len(msg)), sig, ctypes.byref(n)))
    return sig.raw[:n.value]


def sig_sign_sel(niveau, sk, pk, msg, sel):
    t = sig_tailles(niveau)
    sig, n = _buf(t["sig_max"]), ctypes.c_size_t(0)
    lib().sl_sig_sign_sel(NIVEAUX_SIG[niveau], sk, pk, msg, _sz(len(msg)), sel, sig, ctypes.byref(n))
    return sig.raw[:n.value]


def sig_verify(niveau, pk, msg, sig) -> bool:
    return lib().sl_sig_verify(NIVEAUX_SIG[niveau], pk, msg, _sz(len(msg)), sig, _sz(len(sig))) == 1


# ------------------------------------------------------------------ ISD
def isd_prange(n, k, w) -> float:
    return lib().sl_isd_prange(n, k, w)


def isd_deux_listes(n, k, w, dumer, p_max, l_max, exposant_interne=-1.0):
    """(coût, p, l, log2 L) ; exposant_interne < 0 : modèle classique."""
    o = (ctypes.c_double * 4)()
    c = lib().sl_isd_deux_listes(n, k, w, int(dumer), p_max, l_max, ctypes.c_double(exposant_interne), o)
    return (c, int(o[1]), int(o[2]), o[3])


def isd_bjmm(n, k, w, p_max, e_max, l_max):
    """(coût, p, ε, l, log2 L0, log2 L1)"""
    o = (ctypes.c_double * 6)()
    c = lib().sl_isd_bjmm(n, k, w, p_max, e_max, l_max, o)
    return (c, int(o[1]), int(o[2]), int(o[3]), o[4], o[5])


def isd_bjmm_quantique(n, k, w, exposant, depart) -> float:
    return lib().sl_isd_bjmm_quantique(n, k, w, ctypes.c_double(exposant), ctypes.c_double(depart))
