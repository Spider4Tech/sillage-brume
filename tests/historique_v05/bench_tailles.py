# -*- coding: utf-8 -*-
"""Benchmark par taille : chiffrement d'éléments de tailles et de natures
différentes (texte, binaire aléatoire, zéros, JSON) avec BRUME-512,
BRUME-512-256, le mode TE, le hachage, et le schéma hybride complet
KEM (Sillage-128) + AEAD. Vérifie chaque aller-retour.

    python3 -m tests.bench_tailles [--max 1048576]
→ resultats/bench_tailles.json et resultats/BENCH_TAILLES.md
"""
import json
import math
import os
import sys
import time

import numpy as np

from tests.commun import sauver, RESULTATS
from sillage.sillage_kem import SillageKEM
from sillage.brume512 import Brume512, brume512_hash
from sillage.sillage_common import shake

TAILLES = [0, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576]


def contenu(nature, n):
    if nature == "texte":
        base = ("Le paradigme SILLAGE : tout secret vit de l'autre côté d'un "
                "canal bruité. ").encode()
        return (base * (n // len(base) + 1))[:n]
    if nature == "aleatoire":
        return os.urandom(n)
    if nature == "zeros":
        return bytes(n)
    if nature == "json":
        lignes, i = [], 0
        while sum(map(len, lignes)) < n:
            lignes.append(json.dumps({"id": i, "mesure": i * 3.14159, "ok": i % 2 == 0}) + "\n")
            i += 1
        return "".join(lignes).encode()[:n]
    raise ValueError(nature)


def entropie(b):
    if not b:
        return 0.0
    c = np.bincount(np.frombuffer(b, np.uint8), minlength=256) / len(b)
    c = c[c > 0]
    return max(0.0, float(-(c * np.log2(c)).sum()))


def chrono(f):
    t0 = time.perf_counter()
    r = f()
    return r, time.perf_counter() - t0


def debit(n, t):
    return round(n / t / 1024, 1) if t > 0 and n else None


def main():
    tmax = int(sys.argv[sys.argv.index("--max") + 1]) if "--max" in sys.argv else TAILLES[-1]
    tailles = [t for t in TAILLES if t <= tmax]
    kem = SillageKEM("Sillage-128")
    pk, sk = kem.keygen()
    kem.decaps(sk, kem.encaps(pk)[0])          # préchauffage (cache de π)
    nonce = bytes(range(24))
    lignes = []
    res = {"tailles": tailles, "mesures": []}
    ok_global = True
    for nature in ("texte", "aleatoire", "zeros", "json"):
        for n in tailles:
            m = contenu(nature, n)
            ligne = {"nature": nature, "taille": n}
            # hybride : encapsulation + dérivation de clé + AEAD
            (ct_kem, ss), t_enc = chrono(lambda: kem.encaps(pk))
            cle = shake(ss, 64, b"SILLAGE|brume-key")
            br = Brume512("BRUME-512", key=cle)
            (c, tag), t_aead = chrono(lambda: br.encrypt(nonce, m, b"hdr"))
            ss2, t_dec = chrono(lambda: kem.decaps(sk, ct_kem))
            br2 = Brume512("BRUME-512", key=shake(ss2, 64, b"SILLAGE|brume-key"))
            p, t_aead_d = chrono(lambda: br2.decrypt(nonce, c, tag, b"hdr"))
            ok = p == m and ss2 == ss
            br256 = Brume512("BRUME-512-256", key=cle)
            (c256, tag256), t_256 = chrono(lambda: br256.encrypt(nonce, m))
            ok &= br256.decrypt(nonce, c256, tag256) == m
            (cte, pars, tte, meta), t_te = chrono(lambda: br.encrypt_te(nonce, m))
            if n:
                abime = bytearray(cte); abime[n // 2] ^= 0x5A
                (pte, corr), t_te_d = chrono(lambda: br.decrypt_te(nonce, bytes(abime), pars, tte, meta))
                ok &= pte == m and corr == [n // 2]
            else:
                t_te_d = 0.0
            _, t_h = chrono(lambda: brume512_hash(m, 32))
            ok_global &= ok
            ligne.update({
                "aller_retour_ok": ok,
                "kem_encaps_ms": round(1e3 * t_enc, 2), "kem_decaps_ms": round(1e3 * t_dec, 2),
                "aead_chiffrement_ms": round(1e3 * t_aead, 2), "aead_dechiffrement_ms": round(1e3 * t_aead_d, 2),
                "aead_kio_s": debit(n, t_aead),
                "aead256_chiffrement_ms": round(1e3 * t_256, 2), "aead256_kio_s": debit(n, t_256),
                "te_chiffrement_ms": round(1e3 * t_te, 2), "te_dechiffrement_correction_ms": round(1e3 * t_te_d, 2),
                "hachage_ms": round(1e3 * t_h, 2), "hachage_kio_s": debit(n, t_h),
                "hybride_total_ms": round(1e3 * (t_enc + t_aead), 2),
                "surcout_octets_hybride": len(ct_kem[0].to_bytes((kem.p["n"] + 7) // 8, "little"))
                + (kem.p["n2"] + 7) // 8 + len(tag),
                "surcout_octets_te": len(pars),
                "entropie_clair_bits_par_octet": round(entropie(m), 2),
                "entropie_chiffre_bits_par_octet": round(entropie(c), 2),
            })
            res["mesures"].append(ligne)
            print(nature, n, "ok" if ok else "ÉCHEC", ligne["aead_chiffrement_ms"], "ms", flush=True)
    res["tous_aller_retours_ok"] = ok_global
    sauver("bench_tailles", res)
    # tableau Markdown
    md = ["# Benchmark par taille — SILLAGE v0.4", "",
          f"Python {sys.version.split()[0]}, numpy {np.__version__} — {time.strftime('%Y-%m-%d %H:%M')}. "
          f"Allers-retours vérifiés : **{'tous OK' if ok_global else 'ÉCHEC'}**.", "",
          "## Débit selon la taille (contenu aléatoire)", "",
          "| Taille | AEAD-128 chiffr. | AEAD-128 déchiffr. | Kio/s | AEAD-256 | Kio/s | TE chiffr. | TE corr. | Hachage | Hybride KEM+AEAD |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for l in res["mesures"]:
        if l["nature"] != "aleatoire":
            continue
        md.append(f"| {_t(l['taille'])} | {l['aead_chiffrement_ms']} ms | {l['aead_dechiffrement_ms']} ms | "
                  f"{l['aead_kio_s'] or '—'} | {l['aead256_chiffrement_ms']} ms | {l['aead256_kio_s'] or '—'} | "
                  f"{l['te_chiffrement_ms']} ms | {l['te_dechiffrement_correction_ms']} ms | "
                  f"{l['hachage_ms']} ms | {l['hybride_total_ms']} ms |")
    md += ["", "## Selon la nature du contenu (1 Kio et la plus grande taille)", "",
           "| Nature | Taille | AEAD-128 | Entropie clair | Entropie chiffré | Aller-retour |", "|---|---|---|---|---|---|"]
    for l in res["mesures"]:
        if l["taille"] in (1024, tailles[-1]):
            md.append(f"| {l['nature']} | {_t(l['taille'])} | {l['aead_chiffrement_ms']} ms | "
                      f"{l['entropie_clair_bits_par_octet']} | {l['entropie_chiffre_bits_par_octet']} | "
                      f"{'OK' if l['aller_retour_ok'] else 'ÉCHEC'} |")
    l0 = res["mesures"][0]
    md += ["", f"Coût fixe du schéma hybride : encapsulation ≈ {l0['kem_encaps_ms']} ms, "
               f"décapsulation (avec ré-encapsulation FO) ≈ {l0['kem_decaps_ms']} ms, "
               f"surcoût de transmission {l0['surcout_octets_hybride']:,} o (chiffré KEM + tag). "
               f"Mode TE : +7 o par bloc de 64 o (10,9 %).",
           "", "Implémentation Python/numpy de référence (non optimisée, non constant-time)."]
    with open(os.path.join(RESULTATS, "BENCH_TAILLES.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


def _t(n):
    return f"{n // 1048576} Mio" if n >= 1048576 else f"{n // 1024} Kio" if n >= 1024 else f"{n} o"


if __name__ == "__main__":
    main()
