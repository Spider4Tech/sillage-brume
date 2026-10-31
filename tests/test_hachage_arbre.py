# -*- coding: utf-8 -*-
"""Hachage arborescent BRUME-512 (piste 5) : conformité, conditions de la
preuve, séparation des domaines, altérations structurelles.

La preuve (docs/PREUVES.md § 4.4) repose sur trois conditions du mode,
au sens de Bertoni–Daemen–Peeters–Van Assche (« Sufficient conditions for
sound tree and sequential hashing modes », 2014). Ce test les vérifie
mécaniquement sur un modèle écrit SANS brume512.py (le mode n'y est décrit
que par la liste de ses nœuds), puis vérifie que ce modèle, instancié avec
l'éponge, redonne exactement brume512_hash_arbre et sl_hash_arbre :
  1. décodabilité : depuis la seule entrée de la racine, on retrouve k, B
     et les k valeurs de chaînage, sans ambiguïté ;
  2. complétude : la concaténation des entrées des feuilles est M ;
  3. séparabilité du nœud final : le domaine de la racine (ou du nœud
     seul) n'est jamais celui d'une feuille, et aucun domaine n'est 0
     (celui du hachage séquentiel).
"""
import json
import os
import random
import subprocess
import sys
import time

from tests.commun import sauver, RACINE
from sillage import brume512 as B
from sillage import sillage_c as C

BLOC, CV = 8192, 32
FEUILLE, RACINE_D, SEUL = 8, 9, 10
LONGUEURS = [0, 1, 31, 32, 33, BLOC - 1, BLOC, BLOC + 1, 2 * BLOC, 2 * BLOC + 31, 3 * BLOC - 1,
             33 * BLOC + 5, 40 * BLOC]
# KAT figés (référence Python, 2026-10-29)
KAT = {
    "vide": "b12171bb632d2602a3c49f9bc5a6a27b891da98bb0cf9a65efd3947011a42c41",
    "abc": "5dd1dcb0b955987a48097577392c12507b5c4f5726a5ba73687c45bb4496c115",
    "motif_3B+7": "4741a5dfa79e432aff03829ce01cd5e40ac3e3d859d6d514ad1d3314f9b1991c"
}


def noeuds(m):
    """Le mode, décrit par ses nœuds : liste de (domaine, entrée, longueur de
    sortie), la racine en dernier ; les feuilles produisent des CV."""
    if len(m) <= BLOC:
        return [(SEUL, m, None)]
    f = [(FEUILLE, m[i:i + BLOC], CV) for i in range(0, len(m), BLOC)]
    return f + [(RACINE_D, None, len(f))]


def evaluer(m, out_len, eponge):
    ns = noeuds(m)
    if ns[-1][0] == SEUL:
        return eponge(m, SEUL, out_len)
    cvs = b"".join(eponge(x, d, l) for d, x, l in ns[:-1])
    k = ns[-1][2]
    return eponge(cvs + k.to_bytes(8, "big") + BLOC.to_bytes(4, "big"), RACINE_D, out_len)


def decoder_racine(x):
    """Inverse du codage de la racine : (k, B, CV) ou None si mal formé."""
    if len(x) < 12:
        return None
    k, b = int.from_bytes(x[-12:-4], "big"), int.from_bytes(x[-4:], "big")
    if b != BLOC or len(x) != CV * k + 12 or k < 2:
        return None
    return k, b, [x[CV * i:CV * i + CV] for i in range(k)]


def _det_threads(m):
    code = ("import sys; from sillage import sillage_c as C; "
            "sys.stdout.write(C.hash_arbre(sys.stdin.buffer.read(), 64).hex())")
    env = dict(os.environ, OMP_NUM_THREADS="1")
    r = subprocess.run([sys.executable, "-c", code], input=m, capture_output=True, env=env, cwd=RACINE,
                       check=True)
    return bytes.fromhex(r.stdout.decode())


def run():
    rng = random.Random(2026)
    c, m = {}, {}
    msgs = {L: bytes(rng.getrandbits(8) for _ in range(L)) for L in LONGUEURS}
    # 0. le nœud de domaine 0 est le hachage séquentiel
    c["eponge_domaine_0_egale_hachage_sequentiel"] = all(
        B._eponge(msgs[L], 0, 64) == B.brume512_hash(msgs[L], 64) for L in LONGUEURS if L <= 2 * BLOC)
    # 1. modèle ≡ Python ≡ C
    ok_py = ok_c = 0
    for L in LONGUEURS:
        for ol in (32, 100):
            ref = evaluer(msgs[L], ol, B._eponge)
            ok_py += ref == B.brume512_hash_arbre(msgs[L], ol)
            ok_c += ref == C.hash_arbre(msgs[L], ol)
    n = 2 * len(LONGUEURS)
    m["longueurs"] = LONGUEURS
    c["modele_egale_reference_python"] = ok_py == n
    c["modele_egale_implementation_c"] = ok_c == n
    # 2. conditions de la preuve
    dec = compl = sep = 0
    essais = LONGUEURS + [rng.randrange(0, 50 * BLOC) for _ in range(40)]
    for L in essais:
        x = msgs.get(L) or bytes(L)
        ns = noeuds(x)
        compl += b"".join(e for d, e, _ in ns if d in (FEUILLE, SEUL)) == x
        doms = [d for d, _, _ in ns]
        sep += (doms[-1] in (RACINE_D, SEUL) and all(d == FEUILLE for d in doms[:-1]) and 0 not in doms)
        if doms[-1] == RACINE_D:
            cvs = [bytes([i % 256]) * CV for i in range(len(ns) - 1)]
            enc = b"".join(cvs) + (len(cvs)).to_bytes(8, "big") + BLOC.to_bytes(4, "big")
            d = decoder_racine(enc)
            dec += d is not None and d[0] == len(cvs) and d[2] == cvs
        else:
            dec += 1
    m["messages_modele"] = len(essais)
    c["decodabilite_de_la_racine"] = dec == len(essais)
    c["completude_des_feuilles"] = compl == len(essais)
    c["separabilite_du_noeud_final"] = sep == len(essais)
    c["domaines_distincts_et_non_nuls"] = len({FEUILLE, RACINE_D, SEUL}) == 3 and 0 not in (FEUILLE, RACINE_D, SEUL)
    # 3. séparation des domaines (sorties)
    c["arbre_different_du_sequentiel"] = all(
        C.hash_arbre(msgs[L]) != C.hash(msgs[L]) for L in LONGUEURS)
    big = msgs[3 * BLOC - 1]
    cvs = b"".join(B._eponge(big[i:i + BLOC], FEUILLE, CV) for i in range(0, len(big), BLOC))
    enc = cvs + (3).to_bytes(8, "big") + BLOC.to_bytes(4, "big")    # ≤ BLOC : haché comme nœud SEUL
    c["entree_de_racine_hachee_comme_message_differe"] = C.hash_arbre(enc) != C.hash_arbre(big)
    # 4. altérations structurelles (aucune ne doit préserver la sortie)
    x = msgs[40 * BLOC]
    alt = {
        "echange_de_deux_feuilles": x[BLOC:2 * BLOC] + x[:BLOC] + x[2 * BLOC:],
        "octet_deplace_entre_feuilles": x[:BLOC - 1] + x[BLOC:BLOC + 1] + x[BLOC - 1:BLOC] + x[BLOC + 1:],
        "extension_par_un_zero": x + b"\x00",
        "troncature_d_un_octet": x[:-1],
        "feuille_dupliquee": x[:BLOC] + x,
        "bit_change_derniere_feuille": x[:-1] + bytes([x[-1] ^ 1]),
    }
    h0 = C.hash_arbre(x)
    m["alterations"] = list(alt)
    c["alterations_structurelles_changent_la_sortie"] = all(C.hash_arbre(v) != h0 for v in alt.values())
    c["bloc_exact_contre_bloc_plus_zero"] = C.hash_arbre(msgs[BLOC]) != C.hash_arbre(msgs[BLOC] + b"\x00")
    # 5. avalanche : un bit changé dans chaque feuille → ≈ la moitié des 256 bits
    dist = []
    for f in range(40):
        y = bytearray(x)
        y[f * BLOC + rng.randrange(BLOC)] ^= 1 << rng.randrange(8)
        dist.append(bin(int.from_bytes(C.hash_arbre(bytes(y)), "big") ^ int.from_bytes(h0, "big")).count("1"))
    m["avalanche_bits_changes_sur_256"] = {"min": min(dist), "moyenne": sum(dist) / len(dist), "max": max(dist)}
    c["avalanche_dans_chaque_feuille"] = 96 <= min(dist) and max(dist) <= 160
    # 6. déterminisme : un seul thread ≡ tous les threads
    c["resultat_independant_du_nombre_de_threads"] = all(
        _det_threads(msgs[L]) == C.hash_arbre(msgs[L], 64) for L in (2 * BLOC + 31, 33 * BLOC + 5, 40 * BLOC))
    # 7. KAT
    kat = {"vide": C.hash_arbre(b"").hex(), "abc": C.hash_arbre(b"abc").hex(),
           "motif_3B+7": C.hash_arbre(bytes(i % 251 for i in range(3 * BLOC + 7))).hex()}
    m["kat"] = kat
    c["kat_python_egale_c"] = (B.brume512_hash_arbre(b"abc").hex() == kat["abc"] and
                              B.brume512_hash_arbre(bytes(i % 251 for i in range(3 * BLOC + 7))).hex()
                              == kat["motif_3B+7"])
    if KAT:
        c["kat_figes"] = kat == KAT
    # 8. sortie extensible (preuve : oracle à sortie extensible) : un préfixe de la sortie longue
    c["sortie_courte_prefixe_de_la_longue"] = all(
        C.hash_arbre(msgs[L], 32) == C.hash_arbre(msgs[L], 100)[:32] for L in LONGUEURS)
    # 9. débit (mesure)
    gros = os.urandom(16 << 20)
    t = time.perf_counter(); C.hash(gros); ts = time.perf_counter() - t
    t = time.perf_counter(); C.hash_arbre(gros); ta = time.perf_counter() - t
    m["debit_16_Mio_Mo_s"] = {"sequentiel": round(len(gros) / ts / 1e6), "arbre": round(len(gros) / ta / 1e6)}
    out = {"controles": c, "mesures": m}
    sauver("hachage_arbre", out)
    return out


if __name__ == "__main__":
    print(json.dumps(run(), indent=1, ensure_ascii=False))
