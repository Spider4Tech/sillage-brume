# -*- coding: utf-8 -*-
"""Benchmark de l'implémentation C (sillage/c/bench.c, un cœur) comparée à
l'implémentation Python de référence.

    python3 -m tests.bench_c [--max OCTETS]      (défaut : 16 Mio)

Compile sillage/c/bench.c (-O3 -march=native), mesure KEM, SIG et le
chiffrement de 4 natures de contenu × 12 tailles (0 o → 16 Mio), allers-
retours vérifiés ; mesure le Python sur les mêmes opérations (KEM, SIG ;
tailles reprises de resultats/bench_tailles.json) ; écrit
resultats/bench_c.json et resultats/BENCH_C.md.
"""
import json
import os
import platform
import subprocess
import sys
import time

from tests.commun import RACINE, RESULTATS
from sillage.sillage_kem import SillageKEM
from sillage.sillage_sig import SillageSIG

ICI = os.path.join(RACINE, "sillage", "c")
SRC = ["bench.c", "commun.c", "brume512.c", "brume512_avx2.c", "kem.c", "sig.c"]


def construire():
    os.makedirs(os.path.join(ICI, "build"), exist_ok=True)
    exe = os.path.join(ICI, "build", "bench")
    subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-o", exe] + [os.path.join(ICI, s) for s in SRC] + ["-lm"],
                   check=True)
    return exe


def chrono(f, rep):
    best = 1e30
    for _ in range(rep):
        t = time.perf_counter(); f(); best = min(best, time.perf_counter() - t)
    return 1e3 * best


def python_kem_sig():
    out = {}
    for lvl in ("Sillage-128", "Sillage-256"):
        kem = SillageKEM(lvl)
        pk, sk = kem.keygen()
        ct, _ = kem.encaps(pk)
        out[lvl] = {"keygen_ms": chrono(kem.keygen, 5), "encaps_ms": chrono(lambda: kem.encaps(pk), 5),
                    "decaps_ms": chrono(lambda: kem.decaps(sk, ct), 5)}
    for lvl, rep in (("Sillage-SIG-128", 3), ("Sillage-SIG-256", 1)):
        sg = SillageSIG(lvl)
        pk, sk = sg.keygen()
        s = sg.sign(sk, pk, b"message")
        out[lvl] = {"keygen_ms": chrono(sg.keygen, rep), "sign_ms": chrono(lambda: sg.sign(sk, pk, b"message"), rep),
                    "verify_ms": chrono(lambda: sg.verify(pk, b"message", s), rep)}
    return out


def _t(n):
    for u, k in (("Mio", 1 << 20), ("Kio", 1 << 10)):
        if n >= k:
            return f"{n // k} {u}"
    return f"{n} o"


def _ms(x):
    return f"{x:.3g} ms" if x < 1000 else f"{x / 1000:.3g} s"


def _mio_s(n, ms):
    return f"{n / (1 << 20) / (ms / 1e3):.2f}" if n and ms else "—"


def main():
    tmax = int(sys.argv[sys.argv.index("--max") + 1]) if "--max" in sys.argv else 16 << 20
    exe = construire()
    c = json.loads(subprocess.run([exe, str(tmax)], capture_output=True, text=True, check=True).stdout)
    py = python_kem_sig()
    ref = {}
    try:
        for l in json.load(open(os.path.join(RESULTATS, "bench_tailles.json")))["mesures"]:
            if l["nature"] == "aleatoire":
                ref[l["taille"]] = l
    except (OSError, KeyError, ValueError):
        pass
    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
    gcc = subprocess.run(["gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    ok = (all(l["ok"] for l in c["tailles"] + c["multi"] + c["arbre"])
          and all(v["ok"] for d in (c["kem"], c["sig"]) for v in d.values()))
    md = ["# Benchmark de l'implémentation C — SILLAGE v0.4", "",
          f"{cpu}, **un seul cœur** (sauf les lignes « tous les cœurs ») ; {gcc}, `-O3 -march=native` ; Python {platform.python_version()} "
          f"pour la référence — {time.strftime('%Y-%m-%d %H:%M')}.",
          f"Implémentation C conforme octet pour octet au Python (`tests/test_c_impl.py`). "
          f"Allers-retours vérifiés : **{'tous OK' if ok else 'ÉCHEC'}**.", "",
          f"Permutation BRUME-512 (32 tours) : **{c['permutation_us']:.3f} µs** en AVX2 constant-time "
          f"({1e6 / c['permutation_us']:,.0f} permutations/s) ; référence par tables "
          f"{c['permutation_ref_us']:.2f} µs ; par lots de 32 états : {1e3 * c['permutation_lot_us_par_etat']:.0f} ns "
          f"par état.",
          f"Message de 64 o (AEAD-128) : {c['aead64_us']:.2f} µs avec la clé à chaque appel, "
          f"**{c['aead64_ctx_us']:.2f} µs** avec un contexte de clé précalculé.", "",
          "## KEM et signature", "", "| Opération | C | Python | Facteur |", "|---|---|---|---|"]
    for grp in ("kem", "sig"):
        for lvl, v in c[grp].items():
            for op in [k for k in v if k.endswith("_ms")]:
                p = py[lvl].get(op)
                md.append(f"| {lvl} {op[:-3].replace('_', ' ')} | {_ms(v[op])} | {_ms(p) if p else '—'} | "
                          f"{'×%.0f' % (p / v[op]) if p else '—'} |")
    md += ["", "Tailles : " + ", ".join(f"{lvl} pk {v['pk']:,} o / ct {v['ct']:,} o" for lvl, v in c["kem"].items())
           + " ; " + ", ".join(f"{lvl} signature {v['sig']:,} o" for lvl, v in c["sig"].items()) + ".", "",
           "## Chiffrement selon la taille (contenu aléatoire)", "",
           "| Taille | AEAD-128 | Mio/s | Python | Facteur | AEAD-256 | Mio/s | TE chiffr. | TE corr. | Hachage | Hybride KEM+AEAD |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for l in c["tailles"]:
        if l["nature"] != "aleatoire":
            continue
        n, r = l["taille"], ref.get(l["taille"])
        md.append(f"| {_t(n)} | {_ms(l['aead_chiffrement_ms'])} | {_mio_s(n, l['aead_chiffrement_ms'])} | "
                  f"{_ms(r['aead_chiffrement_ms']) if r else '—'} | "
                  f"{'×%.0f' % (r['aead_chiffrement_ms'] / l['aead_chiffrement_ms']) if r else '—'} | "
                  f"{_ms(l['aead256_ms'])} | {_mio_s(n, l['aead256_ms'])} | {_ms(l['te_chiffrement_ms'])} | "
                  f"{_ms(l['te_correction_ms']) if n else '—'} | {_ms(l['hachage_ms'])} | {_ms(l['hybride_total_ms'])} |")
    md += ["", f"## Chiffrement multi-messages (AEAD-128, lots de 32, 32 Mio au total)", "",
           "| Taille d'un message | Messages | 1 cœur | Tous les cœurs | Tous les cœurs, clé commune | Hachage, tous les cœurs |",
           "|---|---|---|---|---|---|"]
    for l in c["multi"]:
        md.append(f"| {_t(l['taille'])} | {l['messages']:,} | {l['mo_s_1_coeur']:.0f} Mo/s | "
                  f"**{l['mo_s_tous']:.0f} Mo/s** ({l['threads']} threads) | **{l['mo_s_tous_cle_commune']:.0f} Mo/s** | "
                  f"{l['hachage_mo_s_tous']:.0f} Mo/s |")
    md += ["", "## Hachage d'un seul gros message : séquentiel et arborescent", "",
           "| Taille | Séquentiel (1 cœur) | Arbre, 1 cœur | Arbre, tous les cœurs |", "|---|---|---|---|"]
    for l in c["arbre"]:
        md.append(f"| {_t(l['taille'])} | {l['sequentiel_mo_s']:.0f} Mo/s | {l['arbre_mo_s_1_coeur']:.0f} Mo/s | "
                  f"**{l['arbre_mo_s_tous']:.0f} Mo/s** ({l['threads']} threads) |")
    md += ["", "Le hachage arborescent (`sl_hash_arbre`, PREUVES § 4.4) est une fonction distincte du "
               "hachage séquentiel (autres KAT)."]
    md += ["", "## AEAD d'un seul message : séquentiel et duplex parallèle (BRUME-512p)", "",
           "| Taille | Séquentiel (1 cœur) | Parallèle, 1 cœur | Parallèle, tous les cœurs |", "|---|---|---|---|"]
    for l in c["aead_p"]:
        md.append(f"| {_t(l['taille'])} | {l['sequentiel_mo_s']:.0f} Mo/s | {l['p_mo_s_1_coeur']:.0f} Mo/s | "
                  f"**{l['p_mo_s_tous']:.0f} Mo/s** ({l['threads']} threads) |")
    grand = max(l["taille"] for l in c["tailles"])
    md += ["", f"## Selon la nature du contenu ({_t(grand)})", "",
           "| Nature | AEAD-128 | Mio/s | Hachage | Aller-retour |", "|---|---|---|---|---|"]
    for l in c["tailles"]:
        if l["taille"] == grand:
            md.append(f"| {l['nature']} | {_ms(l['aead_chiffrement_ms'])} | {_mio_s(grand, l['aead_chiffrement_ms'])} | "
                      f"{_ms(l['hachage_ms'])} | {'OK' if l['ok'] else 'ÉCHEC'} |")
    l0 = next(l for l in c["tailles"] if l["taille"] == 0)
    md += ["", f"Coût fixe du schéma hybride (Sillage-128 + BRUME-512) : encapsulation ≈ {_ms(l0['kem_encaps_ms'])}, "
               f"décapsulation (ré-encapsulation FO comprise) ≈ {_ms(l0['kem_decaps_ms'])}.",
           "", "BRUME-512 (permutation, AEAD, hachage), KEM et SIG (côté signataire) : **constant-time** "
               "(vérifié par dudect, `tests/test_c_temps.py`). Sauf mention contraire, un seul cœur."]
    with open(os.path.join(RESULTATS, "BENCH_C.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    with open(os.path.join(RESULTATS, "bench_c.json"), "w", encoding="utf-8") as f:
        json.dump({"c": c, "python": py, "cpu": cpu, "compilateur": gcc, "tous_ok": ok}, f, ensure_ascii=False, indent=1)
    print("\n".join(md))


if __name__ == "__main__":
    main()
