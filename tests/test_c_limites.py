# -*- coding: utf-8 -*-
"""Implémentation C : chemins d'erreur et chemins de repli que la batterie n'exécutait jamais (mesure de couverture).

1. Aléa système défaillant. Une bibliothèque LD_PRELOAD intercepte getrandom. Armée, elle fait échouer le k-ième appel
   (EIO), ou renvoie EINTR, ou ne donne qu'un octet par appel. Pour chaque appel à sl_alea de KEM keygen, KEM encaps,
   SIG keygen et SIG sign, un échec rend −3, et l'API Python lève OSError au lieu de rendre une clé nulle. EINTR et les
   lectures partielles ne sont pas des échecs : le résultat reste valide.
2. Niveaux invalides. sl_kem_tailles et sl_sig_tailles rendent des tailles nulles, et keygen, encaps, sign rendent −3
   sans écrire.
3. Replis équivalents. Le flux SHAKE au-delà d'un bloc d'absorption (domaine et graine longs) et le tirage creux naïf
   (poids > 1024) donnent exactement les sorties de la référence Python.
4. Erreurs de programmation. Une graine trop longue pour sl_flux_init, un message ≥ 136 octets pour sl_shake4, un
   malloc ou un calloc impossible (débordement de a × b) provoquent abort(), vérifié dans un sous-processus. Le C ne
   déborde jamais et ne déréférence jamais NULL.
"""
import ctypes
import os
import signal
import subprocess
import sys
import tempfile
import textwrap

from tests.commun import sauver, RACINE
from sillage import sillage_c as C
from sillage.sillage_common import _shake_int_stream, sparse_from_seed

SHIM = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/random.h>
static int mode = 0, appel = 0, cible = -1;     /* mode 1 : échec au k-ième appel ; 2 : EINTR une fois ; 3 : 1 octet par appel */
void shim_armer(int m, int k) { mode = m; cible = k; appel = 0; }
int shim_appels(void) { return appel; }
ssize_t getrandom(void *buf, size_t len, unsigned flags)
{
    static ssize_t (*vrai)(void *, size_t, unsigned);
    if (!vrai) vrai = (ssize_t (*)(void *, size_t, unsigned))dlsym(RTLD_NEXT, "getrandom");
    if (mode == 1 && appel++ >= cible) { errno = EIO; return -1; }
    if (mode == 2) { mode = 0; appel++; errno = EINTR; return -1; }
    if (mode == 3) { appel++; return vrai(buf, len ? 1 : 0, flags); }
    return vrai(buf, len, flags);
}
"""

ENFANT = r"""
import ctypes, json, sys
from sillage import sillage_c as C
shim = ctypes.CDLL(sys.argv[1])
res = {}
def essai(nom, f, m, k):
    shim.shim_armer(m, k)
    try:
        r = f()
        ok = True
    except OSError:
        r, ok = None, False
    n = shim.shim_appels()
    shim.shim_armer(0, -1)
    return ok, n, r
ops = {
    "kem_keygen": lambda: C.kem_keygen("Sillage-128"),
    "sig_keygen": lambda: C.sig_keygen("Sillage-SIG-128"),
}
pk, sk = C.kem_keygen("Sillage-128")
spk, ssk = C.sig_keygen("Sillage-SIG-128")
ops["kem_encaps"] = lambda: C.kem_encaps("Sillage-128", pk)
ops["sig_sign"] = lambda: C.sig_sign("Sillage-SIG-128", ssk, spk, b"m")
for nom, f in ops.items():
    ok, n, _ = essai(nom, f, 0, -1)          # nombre d'appels à getrandom d'une exécution saine
    n = max(n, 0)
    shim.shim_armer(3, 0); f(); n = shim.shim_appels(); shim.shim_armer(0, -1)   # au moins un appel par octet : borne
    echecs = []
    k = 0
    while True:
        ok, appels, _ = essai(nom, f, 1, k)
        if ok:
            break
        echecs.append(k)
        k += 1
        if k > 64:
            break
    ok_intr, _, r1 = essai(nom, f, 2, 0)
    ok_part, _, r2 = essai(nom, f, 3, 0)
    res[nom] = dict(echecs_leves=echecs, eintr_ok=ok_intr, partiel_ok=ok_part)
# valeurs rendues sous EINTR et lecture partielle : utilisables
shim.shim_armer(2, 0); pk2, sk2 = C.kem_keygen("Sillage-128"); shim.shim_armer(3, 0)
ct, ss = C.kem_encaps("Sillage-128", pk2); shim.shim_armer(0, -1)
res["kem_valide_sous_eintr_et_partiel"] = C.kem_decaps("Sillage-128", sk2, ct) == ss
shim.shim_armer(3, 0); s = C.sig_sign("Sillage-SIG-128", ssk, spk, b"m"); shim.shim_armer(0, -1)
res["sig_valide_sous_lecture_partielle"] = C.sig_verify("Sillage-SIG-128", spk, b"m", s)
print(json.dumps(res))
"""

MORT = {
    "flux_graine_trop_longue": "f = ctypes.create_string_buffer(4096); L.sl_flux_init(f, b'd', bytes(73), ctypes.c_size_t(73))",
    "shake4_message_trop_long": ("m = (ctypes.c_char_p * 4)(*[bytes(136)] * 4); o = (ctypes.c_char_p * 4)(*[bytes(8)] * 4); "
                                 "L.sl_shake4(m, ctypes.c_size_t(136), o, ctypes.c_size_t(8))"),
    "malloc_impossible": "L.sl_malloc(ctypes.c_size_t(1 << 62))",
    "calloc_debordement": "L.sl_calloc(ctypes.c_size_t(1 << 40), ctypes.c_size_t(1 << 40))",
}


def alea(c, m):
    C.lib()                                        # bibliothèque compilée avant LD_PRELOAD (gcc ne doit pas le voir)
    with tempfile.TemporaryDirectory() as d:
        src, so = os.path.join(d, "shim.c"), os.path.join(d, "shim.so")
        open(src, "w").write(SHIM)
        subprocess.run(["gcc", "-O2", "-shared", "-fPIC", "-o", so, src, "-ldl"], check=True)
        env = dict(os.environ, LD_PRELOAD=so, PYTHONHASHSEED="0", PYTHONPATH=RACINE)
        r = subprocess.run([sys.executable, "-c", ENFANT, so], env=env, cwd=RACINE, capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        m["alea_erreur"] = r.stderr[-2000:]
        c["alea_defaillant_toujours_signale"] = False
        return
    import json
    res = json.loads(r.stdout.strip().splitlines()[-1])
    m["alea"] = res
    ops = ("kem_keygen", "kem_encaps", "sig_keygen", "sig_sign")
    # chaque appel à getrandom, du premier au dernier, peut échouer : l'échec est toujours levé
    c["alea_defaillant_toujours_signale"] = all(len(res[o]["echecs_leves"]) >= 1 for o in ops)
    c["kem_keygen_chaque_appel_a_l_alea_verifie"] = len(res["kem_keygen"]["echecs_leves"]) >= 4
    c["eintr_et_lectures_partielles_ne_sont_pas_des_echecs"] = all(res[o]["eintr_ok"] and res[o]["partiel_ok"] for o in ops)
    c["sorties_valides_sous_eintr_et_lectures_partielles"] = res["kem_valide_sous_eintr_et_partiel"] and res["sig_valide_sous_lecture_partielle"]


def niveaux(c):
    L = C.lib()
    t = [ctypes.c_size_t(7) for _ in range(4)]
    L.sl_kem_tailles(2, *[ctypes.byref(x) for x in t])
    u = [ctypes.c_size_t(7) for _ in range(3)]
    L.sl_sig_tailles(-1, *[ctypes.byref(x) for x in u])
    c["tailles_nulles_pour_un_niveau_invalide"] = all(x.value == 0 for x in t + u)
    buf = ctypes.create_string_buffer(b"\xaa" * 64, 64)
    rc = [L.sl_kem_keygen(5, buf, buf), L.sl_kem_encaps(5, buf, buf, buf), L.sl_sig_keygen(2, buf, buf),
          L.sl_sig_sign(2, buf, buf, b"m", ctypes.c_size_t(1), buf, ctypes.byref(ctypes.c_size_t(0)))]
    c["niveau_invalide_rend_moins_3_sans_ecrire"] = all(x == -3 for x in rc) and buf.raw == b"\xaa" * 64


def replis(c, m):
    L = C.lib()
    L.sl_flux_next.restype = ctypes.c_uint32
    ok = True
    for dom, graine in ((b"court", bytes(range(32))), (b"D" * 63, bytes(range(72))), (b"SILLAGE-KEM|e1", bytes(range(40, 104)))):
        f = ctypes.create_string_buffer(4096)
        L.sl_flux_init(f, dom, graine, ctypes.c_size_t(len(graine)))
        g = _shake_int_stream(graine, dom)
        ok &= all(L.sl_flux_next(f) == next(g) for _ in range(300))
        m.setdefault("flux_longueur_absorbee", []).append(len(dom) + 6 + len(graine) + 1 + 8)
    c["flux_long_identique_a_la_reference"] = ok and max(m["flux_longueur_absorbee"]) > 135
    ok = True
    for poids, n in ((1100, 50021), (2000, 4096), (75, 50021)):
        pos = (ctypes.c_uint32 * poids)()
        L.sl_creux(b"graine", ctypes.c_size_t(6), poids, ctypes.c_uint32(n), b"test", pos)
        ref = sparse_from_seed(b"graine", poids, n, b"test")
        ok &= sum(1 << p for p in pos) == ref and len(set(pos)) == poids
    c["tirage_creux_naif_identique_a_la_reference"] = ok


def morts(c, m):
    C.lib()
    res = {}
    for nom, code in MORT.items():
        prog = textwrap.dedent(f"""
            import ctypes
            from sillage import sillage_c as C
            L = C.lib()
            L.sl_malloc.restype = L.sl_calloc.restype = ctypes.c_void_p
            {code}
            print("PAS D'ARRET")
        """)
        r = subprocess.run([sys.executable, "-c", prog], cwd=RACINE, capture_output=True, text=True, timeout=600,
                           env=dict(os.environ, PYTHONPATH=RACINE))
        res[nom] = r.returncode
    m["abort_codes_retour"] = res
    c["erreurs_de_programmation_arretent_par_abort"] = all(v == -signal.SIGABRT for v in res.values())


def run():
    c, m = {}, {}
    niveaux(c)
    replis(c, m)
    morts(c, m)
    alea(c, m)
    out = {"controles": c, "mesures": m}
    sauver("c_limites", out)
    return out


if __name__ == "__main__":
    out = run()
    for k, v in out["controles"].items():
        print(f"{'OK ' if v else 'ÉCHEC'} {k}")
    print(out["mesures"])
