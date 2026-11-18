# -*- coding: utf-8 -*-
"""Modèle en portes des attaques et placement dans les catégories NIST (1 à 5), pour toute la suite v0.6.

Comptes en portes de tout type (Clifford+T) et en profondeur complète, comme les seuils NIST, et non en Toffoli seuls comme
l'estimation de la signature v0.4 (sillage_common.grover_portes, PROOFS § 5 bis). Chaque compte est un MINIMUM favorable à
l'attaquant : les catégories obtenues sont donc des planchers pour ce modèle. docs/NIST_CATEGORIES.md explique chaque choix.

Seuils (log2) :
  classique : 143 / 146 / 207 / 210 / 272 portes (AES-128, SHA-256 collision, AES-192, SHA-384 collision, AES-256) ;
  quantique, catégories 1 / 3 / 5 : 2^170, 2^233, 2^298 / MAXDEPTH (NIST, appel 2016, d'après Grassl et al.) et, révisés
  par Jaques–Naehrig–Roetteler–Virdia (EUROCRYPT 2020), 2^157, 2^221, 2^285 / MAXDEPTH ; MAXDEPTH ∈ {2^40, 2^64, 2^96}.
Grover sous profondeur bornée : N·g·d/MD portes si √N·d > MD, sinon √N·g (machines en parallèle, Zalka).
    python3 -m tests.modele_portes          → tableau ; run() → dict
"""
import math
import os
import re

from tests.commun import RACINE

LOG = math.log2
MDS = (40, 64, 96)
CLASSIQUE = {1: 143, 2: 146, 3: 207, 4: 210, 5: 272}
QUANTIQUE = {"NIST 2016": {1: 170, 3: 233, 5: 298}, "JNRV 2020": {1: 157, 3: 221, 5: 285}}

# --- portes élémentaires -------------------------------------------------------------------------------------------------
# Toffoli en Clifford+T sans ancilla : 7 T, 6 CNOT, 2 H = 15 portes, profondeur 12 (Amy–Maslov–Mosca–Roetteler 2013).
TOF_G, TOF_D = 15, 12


def circuit(toffoli, cnot, autres, prof_couches_tof, prof_lineaire):
    """(log2 portes, log2 profondeur) d'un circuit réversible."""
    return LOG(toffoli * TOF_G + cnot + autres), LOG(prof_couches_tof * TOF_D + prof_lineaire)


def grover(log_n, g, d, md):
    """log2 des portes d'une recherche de Grover sur 2^log_n éléments, oracle (g, d) en log2, profondeur totale ≤ 2^md."""
    return max(log_n / 2 + g, log_n + g + d - md)


# --- Keccak-f[1600] (SHAKE256 : débit de 136 octets) -----------------------------------------------------------------------
# Par tour : θ ≈ 3 200 XOR (parités de colonnes 1 280, D 320, ajout 1 600), profondeur 5 ; ρ, π : recâblage ; χ : 1 600 ET
# (un Toffoli chacun, au minimum), chaque bit est contrôle de deux Toffoli : 2 couches ; ι : ≤ 7 X.
# Oracle de Grover : calcul puis décalcul (× 2). Classique : θ 3 200 + χ 3 × 1 600 opérations par tour.
KECCAK_TOURS = 24
KECCAK_Q = circuit(toffoli=2 * KECCAK_TOURS * 1600, cnot=2 * KECCAK_TOURS * 3200, autres=2 * KECCAK_TOURS * 7,
                   prof_couches_tof=2 * KECCAK_TOURS * 2, prof_lineaire=2 * KECCAK_TOURS * 5)
KECCAK_C = LOG(KECCAK_TOURS * (3200 + 3 * 1600 + 7))
SHAKE_DEBIT = 136
# Contrôle croisé : Amy et al. (SAC 2016), préimage SHA3-256 : 2,71·10^44 T pour (π/4)·2^128 itérations ≈ 2^19,9 T par
# itération ; ce modèle en compte 2·24·1600·7 = 2^19,0 : il reste en dessous, donc favorable à l'attaquant.
AMY_T_PAR_ITERATION = LOG(2.71e44) - LOG(math.pi / 4 * 2 ** 128)


def keccak_n(appels_seq, log_lin=None, prof_lin=0.0):
    """Oracle de `appels_seq` Keccak-f en série, plus éventuellement 2^log_lin portes linéaires de profondeur prof_lin."""
    g = KECCAK_Q[0] + LOG(appels_seq)
    if log_lin is not None:
        g = LOG(2 ** g + 2 ** log_lin)
    d = LOG(2 ** KECCAK_Q[1] * appels_seq + prof_lin)
    return g, d


# --- BRUME-1024q -----------------------------------------------------------------------------------------------------------
def sbox_brume():
    """Lit le circuit de 17 portes (sillage/c/brume1024_portable.h) : (portes non linéaires, XOR, profondeur non linéaire)."""
    src = open(os.path.join(RACINE, "sillage", "c", "brume1024_portable.h"), encoding="utf-8").read()
    corps = re.search(r"static inline void pp_sbox\(.*?\{(.*?)o\[0\]", src, re.S).group(1)
    prof = {f"w{i}": 0 for i in range(4)}
    nl = xr = 0
    for nom, expr in re.findall(r"(w\d+) = ([^,;]+)", corps):
        ops = re.findall(r"w\d+", expr)
        if "&" in expr or "|" in expr:
            nl += 1
            prof[nom] = 1 + max(prof[o] for o in ops)
        else:
            xr += 1
            prof[nom] = max(prof[o] for o in ops)
    return nl, xr, max(prof.values())


B_N, B_TOURS = 256, 32
# couche linéaire : 34,4 XOR par sommet après partage des sous-expressions (Paar ; README de docs/brume1024, noyau
# bitslicé), profondeur 5 (arbre de XOR sur 28 entrées) ; constantes de tour : 1 024 X par tour.
B_LIN_XOR, B_LIN_PROF = 34.4, 5


def brume_q():
    nl, xr, pnl = sbox_brume()
    g, d = circuit(toffoli=2 * B_TOURS * B_N * nl, cnot=2 * B_TOURS * B_N * (xr + B_LIN_XOR), autres=2 * B_TOURS * 1024,
                   prof_couches_tof=2 * B_TOURS * pnl, prof_lineaire=2 * B_TOURS * (B_LIN_PROF + 2))
    return g, d


def brume_c():
    nl, xr, _ = sbox_brume()
    return LOG(B_TOURS * (B_N * (nl + xr + B_LIN_XOR) + 1024))


# --- ISD : Prange accéléré par Grover --------------------------------------------------------------------------------------
def lb(n, k):
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2)


def prange_grover(n, k, w, cibles_log2=0.0):
    """(log2 N de la recherche, oracle g, d) : une itération = une élimination de Gauss réversible sur la matrice r × n
    (additions de lignes contrôlées : r²·n Toffoli, r couches) ; cibles_log2 : solutions multiples (rotations QC)."""
    r = n - k
    log_n = lb(n, w) - lb(r, w) - cibles_log2
    g, d = circuit(toffoli=r * r * n, cnot=0, autres=0, prof_couches_tof=r, prof_lineaire=0)
    return log_n, g, d


# --- VOLE (sillage/c/vole.c) -----------------------------------------------------------------------------------------------
def profils_vole():
    src = open(os.path.join(RACINE, "sillage", "c", "vole.c"), encoding="utf-8").read()
    res = {}
    for m in re.finditer(r'static const vp_t \w+ = \{"([^"]+)", (\d+), (\d+), (\d+), (\d+), (\d+), (\d+), \{([\d, ]+)\}, '
                         r'(\d+), (\d+), (\d+), (\d+), (\d+), (\d+), (\d+)\};', src):
        nom = m.group(1)
        lam, n, cod, w, bloc, d = (int(m.group(i)) for i in range(2, 8))
        mu = [int(x) for x in m.group(8).split(",")]
        tau, kap, wpow, topen, B = (int(m.group(i)) for i in range(9, 14))
        Bl = lam // 8
        pairs = sum((u - 1) * (u - 2) // 2 for u in mu)
        sw = sum(u - 1 for u in mu)
        witB = (w * sw + 7) // 8
        nb = witB + (d - 1) * Bl + (lam + B) // 8
        res[nom] = dict(lam=lam, n=n, k=n - cod, cod=cod, w=w, d=d, tau=tau, kap=kap, wpow=wpow, B=B, Bl=Bl,
                        m=cod + w * pairs, nb=nb)
    return res


def attaques_vole(p):
    lam = p["lam"]
    att = {}
    # γ : chaque essai change h2 (≥ 1 Keccak), extrait les m éléments de γ (m·Bl octets de SHAKE256, en série) et évalue
    # le coefficient dominant, combinaison linéaire des γ_j à coefficients fixes : m produits par des constantes de GF(2^λ)
    # (λ²/2 XOR chacun), profondeur log2(m) + λ. Succès 2^−λ par essai (Théorème 17).
    appels = 1 + math.ceil(p["m"] * p["Bl"] / SHAKE_DEBIT)
    att["Grover sur le défi γ"] = (lam, *keccak_n(appels, LOG(p["m"] * lam * lam / 2), LOG(p["m"]) + lam))
    # Δ : défi final de τκ + wpow bits, succès d·2^−(τκ+wpow) ; un Keccak (entrée et sortie courtes).
    att["Grover sur le défi Δ"] = (p["tau"] * p["kap"] + p["wpow"] - LOG(p["d"]), *keccak_n(1))
    # M : collision de deux répétitions ouvertes parmi C(τ, 2), 2^−(λ+B) chacune ; extraction de (λ+B) lignes.
    lignes = (lam + p["B"]) * ((8 * p["nb"] - lam - p["B"] + 7) // 8)
    att["Grover sur le défi M"] = (lam + p["B"] - LOG(p["tau"] * (p["tau"] - 1) / 2),
                                   *keccak_n(1 + math.ceil(lignes / SHAKE_DEBIT)))
    # graine cachée : λ + 8 bits, un engagement (un Keccak).
    att["Grover sur une graine cachée"] = (lam + 8, *keccak_n(1))
    # ISD sur (H3) : Prange–Grover sur le code (n, k), poids w (la solution régulière est une solution de poids w).
    att["Prange–Grover sur (H3)"] = prange_grover(p["n"], p["k"], p["w"])
    return att


# --- KEM (sillage/sillage_kem.py) ------------------------------------------------------------------------------------------
def attaques_kem(n, w):
    """Récupération de clé : code QC [2n, n], poids 2w, n solutions (rotations) ; message : même code, √n cibles (DOOM)."""
    return {"Prange–Grover, récupération de clé (n rotations)": prange_grover(2 * n, n, 2 * w, LOG(n)),
            "Prange–Grover, récupération de message (DOOM)": prange_grover(2 * n, n, 2 * w, LOG(n) / 2)}


# --- placement -----------------------------------------------------------------------------------------------------------
def portes_quantiques(attaques, borne_classique):
    """Coût quantique par MAXDEPTH : la moins chère des attaques de Grover et de l'attaque classique (qu'un adversaire
    quantique peut aussi mener). attaques : {nom: (log2 N, g, d)}."""
    res = {}
    for md in MDS:
        couts = {nom: grover(n, g, d, md) for nom, (n, g, d) in attaques.items()}
        couts["meilleure attaque classique"] = borne_classique
        nom = min(couts, key=couts.get)
        res[md] = (round(couts[nom], 1), nom)
    return res


def categorie(classique, quant, seuils, impaires_seulement=True):
    """Plus haute catégorie atteinte : coût classique ≥ seuil classique, et pour chaque MAXDEPTH coût quantique ≥ seuil
    quantique (catégories 1, 3, 5)."""
    meilleure = 0
    for c in (1, 3, 5):
        if classique >= CLASSIQUE[c] and all(quant[md][0] >= seuils[c] - md for md in MDS):
            meilleure = c
    return meilleure


def manque(classique, quant, seuils, c):
    """Bits manquants pour la catégorie c (0 si atteinte)."""
    m = max(0.0, CLASSIQUE[c] - classique)
    for md in MDS:
        m = max(m, seuils[c] - md - quant[md][0])
    return round(m, 1)


def run():
    out = {"elements": {}, "composants": {}}
    kq, bq = KECCAK_Q, brume_q()
    nl, xr, pnl = sbox_brume()
    out["elements"] = dict(keccak_portes_log2=round(kq[0], 2), keccak_profondeur_log2=round(kq[1], 2),
                           keccak_classique_log2=round(KECCAK_C, 2),
                           keccak_T_modele_log2=round(LOG(2 * KECCAK_TOURS * 1600 * 7), 2),
                           keccak_T_amy_et_al_log2=round(AMY_T_PAR_ITERATION, 2),
                           brume_sbox=dict(non_lineaires=nl, xor=xr, profondeur_non_lineaire=pnl),
                           brume_portes_log2=round(bq[0], 2), brume_profondeur_log2=round(bq[1], 2),
                           brume_classique_log2=round(brume_c(), 2))
    comp = {}

    # KEM : coût classique de l'estimateur du dépôt (opérations binaires, sans coût mémoire)
    from sillage.sillage_kem import SillageKEM, PARAMS
    for niv in PARAMS:
        k = SillageKEM(niv)
        cl = k.security_estimate()["classique_bits"]
        att = attaques_kem(k.p["n"], k.p["w"])
        comp[niv] = dict(classique=cl, attaques=att)

    # VOLE : classique = falsification au niveau λ (Théorème 17, notion coût/avantage) × un Keccak, collisions de hachés de
    # 2λ bits (2^λ Keccak), ISD direct de l'estimateur du dépôt
    from sillage.sillage_common import isd_estimate
    for nom, p in profils_vole().items():
        isd = isd_estimate(p["n"], p["k"], p["w"])["classique"]
        cl = min(p["lam"] + KECCAK_C, isd)
        comp[nom] = dict(classique=round(cl, 1), attaques=attaques_vole(p))

    # BRUME-1024q, AEAD (modèle Q1, σ ≤ 2^64 appels) : attaques connues
    sig = 64
    comp["AEAD BRUME-1024q (attaques connues)"] = dict(
        classique=round(min(384 - 1 - LOG(2 * 2 ** sig + 5), 512) + brume_c(), 1),
        attaques={"Grover sur la clé (512 bits)": (512, *bq),
                  "Grover sur la partie interne (384 bits, σ cibles)": (384 - sig, *bq)})
    # AEAD, ce que la preuve Q1 garantit : q_Q ≥ 2^157,5 requêtes à P (σ = 2^64), chacune ≥ une permutation
    q_preuve = 192 - 2 - 0.5 * (sig + 1)
    comp["AEAD BRUME-1024q (preuve Q1, non relue)"] = dict(
        classique=round(384 - 1 - LOG(2 * 2 ** sig + 5) + brume_c(), 1),
        attaques={"borne de la preuve (toute stratégie)": (2 * q_preuve, bq[0], -1e9)})
    # Hachage : collisions et préimages génériques sur la capacité (c = 384) ; les attaques quantiques de type collision
    # (BHT, CNS) ne battent pas la recherche classique quand la mémoire a un coût (Jaques–Schanck 2019) : traitement de NIST
    # pour SHA-384 ; la variante « QRAM gratuite » est donnée à part.
    comp["Hachage BRUME-1024q, préimage"] = dict(
        classique=round(192 + brume_c(), 1), attaques={"Grover sur la sortie (512 bits)": (512, *bq)})
    comp["Hachage BRUME-1024q, préimage (QRAM gratuite, BHT 2^128)"] = dict(
        classique=round(192 + brume_c(), 1), attaques={"BHT sur la capacité, sans contrainte de profondeur": (256, bq[0], -1e9)})
    comp["Hachage BRUME-1024q, preuve quantique (non relue)"] = dict(
        classique=round(192 + brume_c(), 1), attaques={"borne prouvée, 2^124,1 requêtes": (2 * 124.1, bq[0], -1e9)})

    for nom, c in comp.items():
        q = portes_quantiques(c["attaques"], c["classique"])
        cat = {s: categorie(c["classique"], q, seuils) for s, seuils in QUANTIQUE.items()}
        man = {s: {c_: manque(c["classique"], q, seuils, c_) for c_ in (1, 3, 5)} for s, seuils in QUANTIQUE.items()}
        detail = {a: {f"2^{md}": round(grover(n, g, d, md), 1) for md in MDS} for a, (n, g, d) in c["attaques"].items()}
        out["composants"][nom] = dict(classique_log2=c["classique"], quantique_par_maxdepth={f"2^{md}": v for md, v in q.items()},
                                      categorie=cat, bits_manquants=man, attaques=detail)
    # Hachage, collisions : catégorie 4 (SHA-384) si les exposants génériques sont ceux de SHA-384 (c/2 = 192 classique,
    # 2c/5 et c/3 quantiques) et si un appel coûte au moins une compression de SHA-384 (2^210 / 2^192 = 2^18 portes)
    out["composants"]["Hachage BRUME-1024q, collisions"] = dict(
        classique_log2=round(192 + brume_c(), 1), cout_appel_log2=round(brume_c(), 1), cout_appel_sha384_log2=18.0,
        categorie={s: 4 if brume_c() >= 18.0 else 2 for s in QUANTIQUE}, bits_manquants="sans objet (catégorie de collision)")
    return out


def afficher(out):
    e = out["elements"]
    print("Keccak-f[1600] : 2^%.1f portes, profondeur 2^%.1f ; T : 2^%.1f (Amy et al. : 2^%.1f par itération)" % (
        e["keccak_portes_log2"], e["keccak_profondeur_log2"], e["keccak_T_modele_log2"], e["keccak_T_amy_et_al_log2"]))
    print("BRUME-1024q : S-box %(non_lineaires)d non linéaires, %(xor)d XOR, profondeur %(profondeur_non_lineaire)d ; " % e["brume_sbox"]
          + "2^%.1f portes, profondeur 2^%.1f, classique 2^%.1f" % (e["brume_portes_log2"], e["brume_profondeur_log2"],
                                                                   e["brume_classique_log2"]))
    for nom, c in out["composants"].items():
        q = c.get("quantique_par_maxdepth", {})
        print("\n%s : classique 2^%s ; catégorie %s ; bits manquants (cat. 1, 3, 5) : %s" % (
            nom, c["classique_log2"], c["categorie"], c["bits_manquants"]))
        for md, (v, att) in q.items():
            print("    MAXDEPTH %s : 2^%s (%s)" % (md, v, att))
        for a, v in c.get("attaques", {}).items():
            print("      - %s : %s" % (a, ", ".join("%s → 2^%s" % x for x in v.items())))


if __name__ == "__main__":
    afficher(run())
