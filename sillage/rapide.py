# -*- coding: utf-8 -*-
"""API publique de SILLAGE, servie par l'implémentation C : mêmes objets et mêmes
sorties que les classes de référence Python (sillage_kem, sillage_sig), de 2 à 1000 fois
plus rapide, et constant-time là où le Python ne peut pas l'être (entiers à longueur
variable, branchements). Les classes de référence restent importables depuis leurs
modules : elles servent de contre-épreuve (tests/test_c_impl.py, tests/test_api_c.py).
Sans compilateur C, repli sur la référence, avec un avertissement ; SILLAGE_C_OBLIGATOIRE=1 le refuse (exception).
BRUME-1024q (v0.6) et la signature VOLE n'existent qu'en C (décision D1 : pas de référence Python ; la contre-épreuve de
BRUME-1024q est la seconde implémentation C écrite depuis la spécification, prototypes/brume_q/b1024/spec_ref.c)."""
import hmac
import os
import subprocess
import warnings

from . import sillage_c as C
from .sillage_kem import SillageKEM as _KEM
from .sillage_sig import SillageSIG as _SIG

_dispo = None


def disponible() -> bool:
    global _dispo
    if _dispo is None:
        try:
            C.lib()
            _dispo = True
        except (OSError, subprocess.CalledProcessError) as e:
            if os.environ.get("SILLAGE_C_OBLIGATOIRE"):
                raise RuntimeError(f"SILLAGE : implémentation C constant-time requise, indisponible ({e})") from e
            warnings.warn(f"SILLAGE : implémentation C indisponible ({e}) ; référence Python, "
                          "lente et NON constant-time", RuntimeWarning, stacklevel=2)
            _dispo = False
    return _dispo


def _ent(b: bytes) -> int:
    return int.from_bytes(b, "little")


class SillageKEM(_KEM):
    def _c(self, *entiers_n):
        """C utilisable : mode standard, et entiers publics dans le domaine (sinon la référence)."""
        return (self.cascade and all(0 <= x < 1 << self.p["n"] for x in entiers_n) and disponible())

    def keygen(self):
        if not self._c():
            return super().keygen()
        nb = (self.p["n"] + 7) // 8
        _, sk = C.kem_keygen(self.level)
        sigma_h, sigma_rej, s = sk[2 * nb:2 * nb + 32], sk[2 * nb + 32:2 * nb + 64], _ent(sk[2 * nb + 64:])
        return (sigma_h, s), (_ent(sk[:nb]), _ent(sk[nb:2 * nb]), sigma_h, sigma_rej, s)

    def encaps(self, pk):
        if not self._c(pk[1]):
            return super().encaps(pk)
        nb = (self.p["n"] + 7) // 8
        ct, ss = C.kem_encaps(self.level, pk[0] + pk[1].to_bytes(nb, "little"))
        return (_ent(ct[:nb]), _ent(ct[nb:])), ss

    def decaps(self, sk, ct):
        x, y, sigma_h, sigma_rej, s = sk
        if not self._c(x, y, s):
            return super().decaps(sk, ct)
        n, n2 = self.p["n"], self.p["n2"]
        nb, nb2 = (n + 7) // 8, (n2 + 7) // 8
        u, v = ct
        if not (0 <= u < 1 << n and 0 <= v < 1 << n2):     # rejet, comme la référence : un
            u, v = (u & ((1 << n) - 1)) | 1 << n, v & ((1 << n2) - 1)   # bit hors domaine dans u
        skb = (x.to_bytes(nb, "little") + y.to_bytes(nb, "little") + sigma_h + sigma_rej
               + s.to_bytes(nb, "little"))
        return C.kem_decaps(self.level, skb, u.to_bytes(nb, "little") + v.to_bytes(nb2, "little"))


class SillageSIG(_SIG):
    def _c(self, pk=None, sk=None):
        return (disponible() and (pk is None or (len(pk[0]) == 32 and 0 <= pk[1] < 1 << self.p["r"]))
                and (sk is None or len(sk) == self.sizes()["sk_bytes"]))

    def keygen(self):
        if not self._c():
            return super().keygen()
        pk, sk = C.sig_keygen(self.level)
        return (pk[:32], _ent(pk[32:])), sk

    def sign(self, sk: bytes, pk, msg: bytes, salt: bytes = None) -> bytes:
        if not self._c(pk, sk) or (salt is not None and len(salt) != 32):
            return super().sign(sk, pk, msg, salt)
        pkb = pk[0] + pk[1].to_bytes(self.rb, "little")
        if salt is not None:
            return C.sig_sign_sel(self.level, bytes(sk), pkb, bytes(msg), bytes(salt))
        return C.sig_sign(self.level, bytes(sk), pkb, bytes(msg))

    def verify(self, pk, msg: bytes, sig: bytes) -> bool:
        if not self._c(pk):
            return super().verify(pk, msg, sig)
        return C.sig_verify(self.level, pk[0] + pk[1].to_bytes(self.rb, "little"), bytes(msg), bytes(sig))


class SillageVOLE:
    """Sillage-SIG v0.5 : VOLE-in-the-Head sur SD régulier (sillage/c/vole.c ; C seulement, sans référence Python ;
    sécurité : PROOFS § 3 bis ; format : SPEC § 4 bis). Profils : VOLE-128, VOLE-256 (courts), VOLE-128f, VOLE-256f (rapides).
    pk = graine de H ‖ y ; sk = pk ‖ positions ; signature de longueur fixe."""
    PROFILS = tuple(C.PROFILS_VOLE)

    def __init__(self, profil: str = "VOLE-128"):
        if profil not in C.PROFILS_VOLE:
            raise ValueError(f"profil inconnu : {profil} (attendu : {', '.join(C.PROFILS_VOLE)})")
        if not disponible():
            raise RuntimeError("Sillage-SIG v0.5 n'existe qu'en C : bibliothèque indisponible")
        self.profil = profil

    def sizes(self) -> dict:
        return C.vole_tailles(self.profil)

    def keygen(self):
        return C.vole_keygen(self.profil)

    def sign(self, sk: bytes, msg: bytes, salt: bytes = None) -> bytes:
        return C.vole_sign(self.profil, bytes(sk), bytes(msg), None if salt is None else bytes(salt))

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        return C.vole_verify(self.profil, bytes(pk), bytes(msg), bytes(sig))


class Brume1024TagError(Exception):
    """Tag invalide : chiffré, nonce, données associées ou tag altéré (rien n'est rendu)."""


class Brume1024TamperError(Exception):
    """Mode TE : altération non corrigeable (plus d'un octet dans un bloc de 64, ou parités incohérentes)."""


BRUME1024_PROFILES = {"BRUME-1024q": dict(key_len=64, nonce_len=24, tag_len=32, capacite=384, debit=640, tours=32)}
BRUME1024P_PROFILES = {"BRUME-1024qp": dict(key_len=64, nonce_len=24, tag_len=32, feuille=8192)}


def _exige_c(quoi):
    if not disponible():
        raise RuntimeError(f"{quoi} n'existe qu'en C (v0.6, décision D1) : bibliothèque indisponible")


class Brume1024:
    """AEAD BRUME-1024q (docs/brume1024/SPEC.md § 3.5) : duplex à clé dans tout l'état, c = 384, clé de 64 octets, nonce
    de 24 octets unique par clé, tag de 32 octets ; et le mode TE (§ 3.7 : correction d'un octet par bloc de 64)."""

    def __init__(self, profile: str = "BRUME-1024q", key: bytes = None):
        if profile not in BRUME1024_PROFILES:
            raise ValueError(f"profil inconnu : {profile} (attendu : {', '.join(BRUME1024_PROFILES)})")
        _exige_c("BRUME-1024q")
        self.name, self.p = profile, BRUME1024_PROFILES[profile]
        if key is None:
            key = os.urandom(self.p["key_len"])
        if len(key) != self.p["key_len"]:
            raise ValueError(f"clé de {self.p['key_len']} octets requise")
        self.key = bytes(key)

    def _nonce(self, nonce):
        if len(nonce) != self.p["nonce_len"]:
            raise ValueError(f"nonce de {self.p['nonce_len']} octets requis")

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b""):
        self._nonce(nonce)
        return C.aead_encrypt(self.name, self.key, bytes(nonce), bytes(plaintext), bytes(aad))

    def decrypt(self, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b""):
        self._nonce(nonce)
        pt = None
        if len(tag) == self.p["tag_len"]:                  # le C lit tag_len octets
            pt = C.aead_decrypt(self.name, self.key, bytes(nonce), bytes(ct), bytes(tag), bytes(aad))
        if pt is None:
            raise Brume1024TagError("tag invalide — chiffré, nonce ou AAD altéré")
        return pt

    def encrypt_te(self, nonce: bytes, plaintext: bytes, aad: bytes = b""):
        self._nonce(nonce)
        return C.te_encrypt(self.name, self.key, bytes(nonce), bytes(plaintext), bytes(aad))

    def decrypt_te(self, nonce: bytes, ct: bytes, parities: bytes, tag: bytes, meta: bytes, aad: bytes = b""):
        self._nonce(nonce)
        if (len(parities) != 7 * (-(-len(ct) // 64)) or len(meta) != 8
                or int.from_bytes(meta, "big") != len(ct)):
            raise Brume1024TamperError("parités/métadonnées incohérentes")
        if len(tag) != self.p["tag_len"]:
            raise Brume1024TagError("tag invalide — chiffré, nonce ou AAD altéré")
        rc, pt, corrections = C.te_decrypt(self.name, self.key, bytes(nonce), bytes(ct), bytes(parities), bytes(tag),
                                           bytes(meta), bytes(aad))
        if rc == -2:
            raise Brume1024TamperError("altération multiple détectée")
        if rc != 0:
            raise Brume1024TagError("tag invalide — chiffré, nonce ou AAD altéré")
        return pt, corrections


class Brume1024P:
    """AEAD parallèle BRUME-1024qp (SPEC § 3.5 bis, mode 6) : feuilles de 8 Kio sur tous les cœurs. Autre fonction que
    Brume1024 (autres chiffrés, autres tags)."""

    def __init__(self, profile: str = "BRUME-1024qp", key: bytes = None):
        if profile not in BRUME1024P_PROFILES:
            raise ValueError(f"profil inconnu : {profile} (attendu : {', '.join(BRUME1024P_PROFILES)})")
        _exige_c("BRUME-1024qp")
        self.name, self.p = profile, BRUME1024P_PROFILES[profile]
        if key is None:
            key = os.urandom(self.p["key_len"])
        if len(key) != self.p["key_len"]:
            raise ValueError(f"clé de {self.p['key_len']} octets requise")
        self.key = bytes(key)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b""):
        if len(nonce) != self.p["nonce_len"]:
            raise ValueError(f"nonce de {self.p['nonce_len']} octets requis")
        return C.aead_p_encrypt(self.name, self.key, bytes(nonce), bytes(plaintext), bytes(aad))

    def decrypt(self, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b""):
        if len(nonce) != self.p["nonce_len"]:
            raise ValueError(f"nonce de {self.p['nonce_len']} octets requis")
        pt = None
        if len(tag) == self.p["tag_len"]:
            pt = C.aead_p_decrypt(self.name, self.key, bytes(nonce), bytes(ct), bytes(tag), bytes(aad))
        if pt is None:
            raise Brume1024TagError("tag invalide — chiffré, nonce ou AAD altéré")
        return pt


def brume1024_hash(msg: bytes, out_len: int = 64) -> bytes:
    """Condensé par défaut H (SPEC § 3.4) : 64 octets par défaut."""
    _exige_c("BRUME-1024q")
    return C.hash(bytes(msg), out_len)


def brume1024_xof(msg: bytes, out_len: int) -> bytes:
    """XOF (SPEC § 3.3)."""
    _exige_c("BRUME-1024q")
    return C.xof(bytes(msg), out_len)
