# -*- coding: utf-8 -*-
"""API publique de SILLAGE, servie par l'implémentation C : mêmes objets et mêmes
sorties que les classes de référence Python (sillage_kem, sillage_sig, brume512), de
2 à 1000 fois plus rapide, et constant-time là où le Python ne peut pas l'être (entiers à
longueur variable, branchements). Les classes de référence restent importables depuis
leurs modules : elles servent de contre-épreuve (tests/test_c_impl.py, tests/test_api_c.py).
Sans compilateur C, repli sur la référence, avec un avertissement ; SILLAGE_C_OBLIGATOIRE=1 le refuse (exception)."""
import hmac
import os
import subprocess
import warnings

from . import sillage_c as C
from .brume512 import (Brume512 as _Brume512, Brume512P as _Brume512P, Brume512TagError, Brume512TamperError,
                       N_ROUNDS, brume512_hash as _hash_ref, brume512_hash_arbre as _hash_arbre_ref)
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


class Brume512(_Brume512):
    def _nonce(self, nonce):
        if len(nonce) != self.p["nonce_len"]:
            raise ValueError(f"nonce de {self.p['nonce_len']} octets requis")

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b""):
        if not disponible():
            return super().encrypt(nonce, plaintext, aad)
        self._nonce(nonce)
        return C.aead_encrypt(self.name, self.key, nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b""):
        if not disponible():
            return super().decrypt(nonce, ct, tag, aad)
        self._nonce(nonce)
        pt = None
        if len(tag) == self.p["tag_len"]:                  # le C lit tag_len octets
            pt = C.aead_decrypt(self.name, self.key, nonce, ct, tag, aad)
        if pt is None:
            raise Brume512TagError("tag invalide — chiffré, nonce ou AAD altéré")
        return pt

    def encrypt_te(self, nonce: bytes, plaintext: bytes, aad: bytes = b""):
        if not disponible():
            return super().encrypt_te(nonce, plaintext, aad)
        self._nonce(nonce)
        return C.te_encrypt(self.name, self.key, nonce, plaintext, aad)

    def decrypt_te(self, nonce: bytes, ct: bytes, parities: bytes, tag: bytes, meta: bytes, aad: bytes = b""):
        if not disponible():
            return super().decrypt_te(nonce, ct, parities, tag, meta, aad)
        self._nonce(nonce)
        if (len(parities) != 7 * (-(-len(ct) // 64)) or len(meta) != 8
                or int.from_bytes(meta, "big") != len(ct)):
            raise Brume512TamperError("parités/métadonnées incohérentes")
        if len(tag) != self.p["tag_len"]:
            raise Brume512TagError("tag invalide — chiffré, nonce ou AAD altéré")
        rc, pt, corrections = C.te_decrypt(self.name, self.key, nonce, ct, parities, tag, meta, aad)
        if rc == -2:
            raise Brume512TamperError("altération multiple détectée")
        if rc != 0:
            raise Brume512TagError("tag invalide — chiffré, nonce ou AAD altéré")
        return pt, corrections


class Brume512P(_Brume512P):
    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b""):
        if not disponible():
            return super().encrypt(nonce, plaintext, aad)
        if len(nonce) != self.p["nonce_len"]:
            raise ValueError(f"nonce de {self.p['nonce_len']} octets requis")
        return C.aead_p_encrypt(self.name, self.key, nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b""):
        if not disponible():
            return super().decrypt(nonce, ct, tag, aad)
        if len(nonce) != self.p["nonce_len"]:
            raise ValueError(f"nonce de {self.p['nonce_len']} octets requis")
        pt = None
        if len(tag) == self.p["tag_len"]:                  # le C lit tag_len octets
            pt = C.aead_p_decrypt(self.name, self.key, nonce, ct, tag, aad)
        if pt is None:
            raise Brume512TagError("tag invalide — chiffré, nonce ou AAD altéré")
        return pt


def brume512_hash(msg: bytes, out_len: int = 32, rounds: int = N_ROUNDS) -> bytes:
    if rounds != N_ROUNDS or not disponible():
        return _hash_ref(msg, out_len, rounds)
    return C.hash(bytes(msg), out_len)


def brume512_hash_arbre(msg: bytes, out_len: int = 32) -> bytes:
    return C.hash_arbre(bytes(msg), out_len) if disponible() else _hash_arbre_ref(msg, out_len)
