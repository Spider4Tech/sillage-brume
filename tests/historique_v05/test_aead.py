# -*- coding: utf-8 -*-
"""AEAD BRUME-512 : malléabilité exhaustive, liaison nonce/AAD/clé/longueur,
régression de la collision longueur/bloc final (v0.2), réutilisation de nonce."""
import os

from tests.commun import sauver
from sillage import Brume512, Brume512TagError, BRUME512_PROFILES


def _rejete(br, n, c, t, a=b""):
    try:
        br.decrypt(n, c, t, a)
        return False
    except Brume512TagError:
        return True


def run():
    c, m = {}, {}
    for prof in BRUME512_PROFILES:
        br = Brume512(prof, key=bytes(range(64)))
        rb = br.p["rate"] // 2
        nonce, aad = bytes(range(24)), b"entete"
        tout_rejete = True
        n_cas = 0
        for L in range(0, 3 * rb + 2):
            msg = bytes((i * 11 + 5) & 0xFF for i in range(L))
            ct, tag = br.encrypt(nonce, msg, aad)
            cas = []
            for i in range(L):                         # chaque octet, 1 bit
                x = bytearray(ct); x[i] ^= 1 << (i % 8); cas.append((bytes(x), tag))
            cas += [(ct + b"\x00", tag), (ct + b"\x01", tag), (ct[:-1], tag) if L else (b"\x00", tag)]
            # collision longueur/bloc final (attaque v0.2) pour L' = L ± 1, L + 8
            for L2 in (L + 1, L - 1, L + 8):
                if L2 < 0:
                    continue
                d = (L ^ L2).to_bytes(8, "little")
                base = (ct + b"\x00" * 8)[:max(L, L2)]
                full = (L // rb) * rb
                tail = bytearray(base[full:L2] if L2 > full else b"")
                for j in range(min(8, len(tail))):
                    tail[j] ^= d[j]
                cas.append((ct[:full] + bytes(tail), tag))
            for ti in range(len(tag)):
                t2 = bytearray(tag); t2[ti] ^= 0x80; cas.append((ct, bytes(t2)))
            cas += [(ct, tag[:-1]), (ct, tag + b"\x00")]
            for cc, tt in cas:
                if (cc, tt) == (ct, tag):
                    continue
                n_cas += 1
                tout_rejete &= _rejete(br, nonce, cc, tt, aad)
            tout_rejete &= _rejete(br, nonce, ct, tag, aad + b"x")
            tout_rejete &= _rejete(br, bytes(24), ct, tag, aad)
            tout_rejete &= _rejete(br, nonce, ct, tag, b"")
            n_cas += 3
        c[f"{prof}_toutes_alterations_rejetees"] = tout_rejete
        m[f"{prof}_cas_testes"] = n_cas
        # clé différente
        br2 = Brume512(prof, key=bytes(64))
        ct, tag = br.encrypt(nonce, b"x" * 50, aad)
        c[f"{prof}_rejet_autre_cle"] = _rejete(br2, nonce, ct, tag, aad)
        # séparation AAD / message : (aad="ab", m="") vs (aad="a", m=?) distincts
        _, t1 = br.encrypt(nonce, b"", b"ab")
        _, t2 = br.encrypt(nonce, b"", b"a")
        c[f"{prof}_aad_prefixe_distinct"] = t1 != t2
        # chiffré vide authentifié
        ct0, t0 = br.encrypt(nonce, b"", aad)
        c[f"{prof}_message_vide"] = ct0 == b"" and br.decrypt(nonce, ct0, t0, aad) == b""
        # nonce de mauvaise taille refusé
        try:
            br.encrypt(b"\x00" * 15, b"m")
            c[f"{prof}_nonce_taille_controlee"] = False
        except ValueError:
            c[f"{prof}_nonce_taille_controlee"] = True
        # réutilisation de nonce : comportement documenté (flux identique sur
        # le 1er bloc → XOR des clairs) — information, pas un contrôle
        m1, m2 = os.urandom(rb), os.urandom(rb)
        x1, _ = br.encrypt(nonce, m1, aad)
        x2, _ = br.encrypt(nonce, m2, aad)
        m[f"{prof}_reutilisation_nonce_fuit_xor_1er_bloc"] = \
            bytes(a ^ b for a, b in zip(x1, x2)) == bytes(a ^ b for a, b in zip(m1, m2))
        # nonces distincts : flux indépendants
        y1, _ = br.encrypt(bytes(24), bytes(rb), aad)
        y2, _ = br.encrypt(b"\x00" * 23 + b"\x01", bytes(rb), aad)
        c[f"{prof}_flux_depend_du_nonce"] = y1 != y2
    out = {"controles": c, "mesures": m}
    sauver("aead", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
