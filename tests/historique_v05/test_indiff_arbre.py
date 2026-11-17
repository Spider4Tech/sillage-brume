# -*- coding: utf-8 -*-
"""Validation mécanique du Lemme 15 et du Théorème 16 (PROOFS § 4.4).

1. Conditions de Bertoni–Daemen–Peeters–Van Assche (IJIS 2014), définitions 5 à
   7 : un décodeur Adecode classe des instances d'arbre (compliante, sous-arbre
   final compliant, incompliante) et l'on énumère aussi des instances mal formées.
2. Simulateur du Lemme 15, composé avec celui du mode, sur une éponge réduite :
   un distingueur mêle requêtes directes, inverses et calculs complets par le
   simulateur. Hors événement mauvais, le simulateur doit redonner exactement
   l'oracle du mode. La fréquence de l'événement mauvais doit rester sous la
   borne 7q(q+1)/2^(c+1) du lemme.
3. Requêtes inverses : un distingueur concret réussit bien au-delà de q²/2^(b+1),
   le terme par lequel l'ancienne preuve les couvrait.
"""
import itertools
import random

from tests.commun import sauver

# Éponge réduite : les domaines occupent les 4 bits de poids faible de la capacité
FEUILLE, RACINE_D, SEUL = 8, 9, 10
D = (0, FEUILLE, RACINE_D, SEUL)
DELTA = {a ^ b for a in D for b in D}
assert len(DELTA) == 7


# ---------------- 1. Conditions du mode (arbre : racine "*", feuilles 0…k−1)

def adecode(arbre, B, CV=32):
    """Définition 5 : renvoie ("compliante", None), ("final", β) avec β l'indice
    à développer, ou ("incompliante", None). Ne lit que l'instance."""
    d, x = arbre["*"]
    if d == SEUL:
        return ("compliante", None) if len(arbre) == 1 and len(x) <= B else ("incompliante", None)
    if d != RACINE_D or len(x) < 12:
        return ("incompliante", None)
    k, b = int.from_bytes(x[-12:-4], "big"), int.from_bytes(x[-4:], "big")
    if b != B or k < 2 or len(x) != CV * k + 12:
        return ("incompliante", None)
    for i in range(k):
        if i not in arbre:
            return ("final", i)
        dd, y = arbre[i]
        taille_ok = len(y) == B if i < k - 1 else 1 <= len(y) <= B
        if dd != FEUILLE or not taille_ok:
            return ("incompliante", None)
    return ("compliante", None) if len(arbre) == k + 1 else ("incompliante", None)


def message(arbre):
    """Définition 6 : Amessage, sur une instance compliante."""
    if arbre["*"][0] == SEUL:
        return arbre["*"][1]
    return b"".join(arbre[i][1] for i in range(len(arbre) - 1))


def construire(m, B, CV=32):
    """L'arbre du mode pour M (CV symboliques, propres au contenu de chaque feuille)."""
    if len(m) <= B:
        return {"*": (SEUL, m)}
    f = [m[i:i + B] for i in range(0, len(m), B)]
    arbre = {i: (FEUILLE, y) for i, y in enumerate(f)}
    cvs = b"".join(y.ljust(CV, b"\xfe")[:CV] for y in f)
    arbre["*"] = (RACINE_D, cvs + len(f).to_bytes(8, "big") + B.to_bytes(4, "big"))
    return arbre


def conditions():
    B, c, m = 4, {}, {}
    msgs = [bytes(t) for L in range(0, 3 * B + 2) for t in
            ((i % 251 for i in range(L)), (((i * 7 + 1) % 251) for i in range(L)))]
    # compliance, reconstruction, unicité de la racine
    arbres = {mm: construire(mm, B) for mm in msgs}
    c["arbres_du_mode_compliants"] = all(adecode(a, B)[0] == "compliante" for a in arbres.values())
    c["message_reconstruit_depuis_l_arbre"] = all(message(a) == mm for mm, a in arbres.items())
    # Déf. 5 : sous-arbres finaux stricts → « final » et jamais compliants, descente jusqu'au bout
    ok_final, descentes = True, 0
    for mm, a in arbres.items():
        if a["*"][0] != RACINE_D:
            continue
        for r in range(len(a) - 1):
            partiel = {"*": a["*"], **{i: a[i] for i in range(r)}}
            etat, beta = adecode(partiel, B)
            ok_final &= etat == "final" and beta == r
            descentes += 1
    c["sous_arbres_finaux_jamais_compliants"] = ok_final
    m["sous_arbres_finaux_testes"] = descentes
    # Déf. 7 : une feuille, seule, n'est ni compliante ni sous-arbre final
    feuilles = {a[i] for a in arbres.values() for i in a if i != "*"}
    c["noeud_interne_seul_incompliant"] = all(adecode({"*": f}, B)[0] == "incompliante" for f in feuilles)
    m["feuilles_testees"] = len(feuilles)
    # Instances mal formées : énumération de racines et de feuilles invalides
    cv = b"\xaa" * 32
    mal = []
    for k_annonce, k_reel, b_annonce in itertools.product((0, 1, 2, 3), (0, 1, 2, 3), (B, B + 1, 0)):
        x = cv * k_reel + k_annonce.to_bytes(8, "big") + b_annonce.to_bytes(4, "big")
        valide = k_annonce == k_reel and k_annonce >= 2 and b_annonce == B
        mal.append((x, k_annonce, valide))
    ok_racines = True
    for x, k, valide in mal:
        etat, _ = adecode({"*": (RACINE_D, x)}, B)
        ok_racines &= (etat == "final") == valide and (etat == "compliante") is False
    c["racines_mal_formees_rejetees"] = ok_racines
    r2 = cv * 2 + (2).to_bytes(8, "big") + B.to_bytes(4, "big")
    feuilles_mal = [(B - 1, 1), (B + 1, 1), (0, 1), (B, 0), (B, B + 1)]
    c["tailles_de_feuilles_invalides_rejetees"] = all(
        adecode({"*": (RACINE_D, r2), 0: (FEUILLE, b"x" * a), 1: (FEUILLE, b"y" * b)}, B)[0] == "incompliante"
        for a, b in feuilles_mal)
    c["feuille_de_mauvais_domaine_rejetee"] = adecode(
        {"*": (RACINE_D, r2), 0: (SEUL, b"x" * B), 1: (FEUILLE, b"y")}, B)[0] == "incompliante"
    c["seul_trop_long_rejete"] = adecode({"*": (SEUL, b"x" * (B + 1))}, B)[0] == "incompliante"
    # injectivité : un message ↦ un nœud final (les CV symboliques étant injectifs)
    finaux = {tuple(sorted((str(k), v) for k, v in a.items())): mm for mm, a in arbres.items()}
    c["message_vers_arbre_injectif"] = len(finaux) == len(arbres)
    m["messages_enumeres"] = len(arbres)
    return c, m


# ---------------- 2. Simulateur (Lemme 15 composé avec le mode, Théorème 16)

class Monde:
    """Oracles idéaux : mode H(M), F_0 et feuilles (domaine FEUILLE). Sorties
    indexées par j : les oracles sont à sortie extensible."""

    def __init__(self, r, c, rng):
        self.r, self.c, self.rng = r, c, rng
        self.ro = {}

    def tire(self, cle):
        if cle not in self.ro:
            self.ro[cle] = self.rng.getrandbits(self.r)
        return self.ro[cle]


class Simulateur:
    """S : répond à P et P⁻¹ et programme le débit des appels finaux. Blocs de
    r bits. Lemme 15 : mauvais. Théorème 16 : mauvais_cv (collision de CV ou CV
    utilisée par une racine avant d'être produite). Le bourrage du toy est un
    dernier bloc 1 dans les messages, écrit par les appelants."""

    def __init__(self, monde):
        self.w, self.r, self.c = monde, monde.r, monde.c
        self.mc = (1 << self.c) - 1
        self.av, self.ar = {}, {}
        self.rac = {0: ()}                 # capacité enracinée (absorption) → blocs
        self.debit = {0: 0}                # capacité enracinée → débit de l'état
        self.ext = {}                      # capacité post-finale → (clé d'oracle, j, débit)
        self.cv = {}                       # CV → blocs de la feuille
        self.cv_en_racine = set()          # CV lues par une racine avant d'être connues
        self.O = set()                     # capacités des entrées hors chemin enraciné
        self.mauvais = self.mauvais_cv = False
        self.q = 0

    def _depart(self, cap):
        for d in D:
            if cap ^ d in self.rac:
                return cap ^ d, d
        return None, None

    def _cle(self, d, blocs):
        """Clé d'oracle de l'appel final de F_d, ou None si non compliant."""
        if d == 0:                         # décodage de l'éponge : F_0(base), bloc j
            j = 0
            while j < len(blocs) and blocs[-1 - j] == 0:
                j += 1
            base = blocs[:len(blocs) - j]
            return ("S", base, j) if base and base[-1] == 1 else None
        if d == FEUILLE:
            return ("F", blocs)
        if d == SEUL:
            return ("H", blocs)
        *cvs, k = blocs
        if k == len(cvs) and k >= 2 and all(v in self.cv for v in cvs):
            return ("H", tuple(b for v in cvs for b in self.cv[v]))
        self.cv_en_racine.update(cvs)
        return None

    def _controle(self, cap):
        """Capacité d'un nœud enraciné : liée à un nœud existant (Δ) ou à une
        entrée déjà posée (D) ? L'événement mauvais du Lemme 15."""
        if any(cap ^ d in self.rac or cap ^ d in self.ext for d in DELTA) or any(cap ^ d in self.O for d in D):
            self.mauvais = True

    def directe(self, x):
        if x in self.av:
            return self.av[x]
        self.q += 1
        xr, xc = x >> self.c, x & self.mc
        t, d = self._depart(xc)
        rate, cap = self.w.rng.getrandbits(self.r), self.w.rng.getrandbits(self.c)
        info = self.ext.get(xc)
        if t is not None:
            blocs = self.rac[t] + (xr ^ self.debit[t],)
            cle = self._cle(d, blocs)
            if cle is not None:
                rate = self.w.tire(cle if d == 0 else (cle, 0))
                if d == FEUILLE:
                    if (rate in self.cv and self.cv[rate] != blocs) or rate in self.cv_en_racine:
                        self.mauvais_cv = True
                    self.cv[rate] = blocs
            self._controle(cap)
            if d == 0:                     # l'extraction de F_0 est une absorption de 0
                self.rac[cap], self.debit[cap] = blocs, rate
            else:
                self.ext[cap] = (cle, 1, rate)
        elif info is not None and xr == info[2]:   # extraction du bloc de sortie suivant
            cle, j, _ = info
            if cle is not None:
                rate = self.w.tire((cle, j))
            self._controle(cap)
            self.ext[cap] = (cle, j + 1, rate)
        else:
            self.O.add(xc)
        y = rate << self.c | cap
        self.av[x], self.ar[y] = y, x
        return y

    def inverse(self, y):
        if y in self.ar:
            return self.ar[y]
        self.q += 1
        x = self.w.rng.getrandbits(self.r + self.c)
        xc = x & self.mc
        if any(xc ^ d in self.rac or xc ^ d in self.ext for d in D):
            self.mauvais = True
        self.O.add(xc)
        self.av[x], self.ar[y] = y, x
        return x


def eponge_par_s(S, blocs, d, n_sorties=1):
    """F_d(blocs) calculée avec les seules requêtes à S ; sorties de r bits."""
    etat, sorties = 0, []
    for i, b in enumerate(blocs):
        etat = S.directe(etat ^ (b << S.c) ^ (d if i == len(blocs) - 1 else 0))
    for j in range(n_sorties):
        sorties.append(etat >> S.c)
        if j + 1 < n_sorties:
            etat = S.directe(etat)
    return sorties


def partie(r, c, q_cible, graine):
    """Un distingueur : calculs complets du mode et de F_0 par S, comparés aux
    oracles, plus des requêtes directes et inverses. Renvoie (q, mauvais,
    mauvais_cv, incohérences hors événements mauvais, comparaisons)."""
    rng = random.Random(graine)
    w = Monde(r, c, rng)
    S = Simulateur(w)
    incoh = comp = 0
    connus = [0]
    while S.q < q_cible:
        t = rng.random()
        sorties = rng.randrange(1, 3)
        if t < 0.25:                       # message d'un seul nœud
            m = tuple(rng.getrandbits(r) for _ in range(rng.randrange(1, 4))) + (1,)
            vu = eponge_par_s(S, m, SEUL, sorties)
            cle = ("H", m)
        elif t < 0.40:                     # hachage séquentiel : même éponge, domaine 0
            m = tuple(rng.getrandbits(r) for _ in range(rng.randrange(1, 4))) + (1,)
            vu = eponge_par_s(S, m, 0, sorties)
            cle = ("S", m)
        elif t < 0.65:                     # arbre : k feuilles, puis racine
            k = rng.randrange(2, 4)
            f = [tuple(rng.getrandbits(r) for _ in range(2)) + (1,) for _ in range(k)]
            cvs = [eponge_par_s(S, x, FEUILLE)[0] for x in f]
            vu = eponge_par_s(S, tuple(cvs) + (k,), RACINE_D, sorties)
            cle = ("H", tuple(b for x in f for b in x))
        elif t < 0.75:                     # racine sur des CV arbitraires
            eponge_par_s(S, (rng.getrandbits(r), rng.getrandbits(r), 2), RACINE_D)
            continue
        elif t < 0.90:                     # requête directe libre, parfois sur un état connu
            base = rng.choice(connus) if rng.random() < 0.5 else rng.getrandbits(r + c)
            connus.append(S.directe(base ^ (rng.getrandbits(r) << c)))
            continue
        else:
            S.inverse(rng.getrandbits(r + c))
            continue
        comp += 1
        attendu = [w.tire(cle + (j,) if cle[0] == "S" else (cle, j)) for j in range(sorties)]
        if vu != attendu and not (S.mauvais or S.mauvais_cv):
            incoh += 1
    return S.q, S.mauvais, S.mauvais_cv, incoh, comp


def attaque_inverse(r, c, q, graine):
    """Distingueur par requêtes inverses seules : si P⁻¹(y) = x a la capacité
    d'un état enraciné T ⊕ SEUL, alors y impose la sortie de F_SEUL(chemin(T) ‖
    bloc), que le monde réel respecte et que l'oracle du mode ignore. Renvoie
    (l'événement s'est produit, la sortie imposée diffère de l'oracle)."""
    rng = random.Random(graine)
    w = Monde(r, c, rng)
    S = Simulateur(w)
    for _ in range(q // 2):
        S.directe(rng.getrandbits(r) << c)
    for _ in range(q // 2):
        y = rng.getrandbits(r + c)
        x = S.inverse(y)
        t = (x & S.mc) ^ SEUL
        if t in S.rac:
            m = S.rac[t] + ((x >> c) ^ S.debit[t],)
            return True, (y >> c) != w.tire((("H", m), 0))
    return False, False


def simulation():
    c, m = {}, {}
    # (a) capacité large : aucun événement mauvais, simulation parfaite
    incoh = comp = mauv = 0
    for g in range(60):
        _, bad, bad_cv, i, n = partie(32, 48, 300, 1000 + g)
        incoh += i; comp += n; mauv += bad or bad_cv
    m["simulation_parfaite"] = {"parties": 60, "comparaisons": comp, "incoherences": incoh, "mauvais": mauv}
    c["simulateur_coherent_avec_les_oracles"] = incoh == 0 and comp > 1000 and mauv == 0
    # (b) borne du lemme, capacité réduite : fréquence ≤ 7q(q+1)/2^(c+1)
    lignes, ok = [], True
    for (cap, q_c) in ((14, 30), (14, 60), (16, 60), (16, 120), (18, 120)):
        n, bad, q_tot, inc, cp = 3000, 0, 0, 0, 0
        for g in range(n):
            q, b, _, i, k = partie(16, cap, q_c, 10_000 * cap + q_c * 7 + g)
            bad += b; q_tot += q; inc += i; cp += k
        q_moy = q_tot / n
        borne = 7 * q_moy * (q_moy + 1) / 2 ** (cap + 1)
        freq = bad / n
        ok &= freq <= borne + 3 * (freq * (1 - freq) / n) ** 0.5 and inc == 0
        lignes.append(dict(c=cap, q=round(q_moy, 1), frequence=round(freq, 4), borne=round(borne, 4),
                           comparaisons=cp, incoherences_hors_evenement=inc))
    m["evenement_mauvais"] = lignes
    c["evenement_mauvais_sous_la_borne_du_lemme_15"] = ok
    # (b bis) CV : avec n petit, les collisions apparaissent, à l'ordre q²/2^(n+1)
    n, cv, q_tot = 3000, 0, 0
    for g in range(n):
        q, _, b, _, _ = partie(12, 40, 40, 50_000 + g)
        cv += b; q_tot += q
    borne = (q_tot / n) ** 2 / 2 ** 13
    m["collisions_de_cv"] = {"n": 12, "frequence": round(cv / n, 4), "borne_q2_2n1": round(borne, 4)}
    c["collisions_de_cv_sous_la_borne_du_theoreme_16"] = 0 < cv / n <= borne
    # (c) requêtes inverses : distingueur réel, très au-dessus de l'ancien terme q²/2^(b+1)
    n, r, cap, q_c = 4000, 8, 16, 80
    res = [attaque_inverse(r, cap, q_c, 777_000 + g) for g in range(n)]
    freq, diff = sum(a for a, _ in res) / n, sum(b for _, b in res) / n
    ancien = q_c ** 2 / 2 ** (r + cap + 1)
    m["requetes_inverses"] = {"c": cap, "b": r + cap, "q": q_c, "frequence_evenement": freq, "frequence_incoherence": diff,
                              "ancien_terme_q2_2b1": round(ancien, 5), "terme_corrige_7q_q1_2c1": round(7 * q_c * (q_c + 1) / 2 ** (cap + 1), 3)}
    c["distingueur_inverse_au_dessus_de_l_ancien_terme"] = diff > 5 * ancien
    c["distingueur_inverse_sous_le_terme_corrige"] = diff <= 7 * q_c * (q_c + 1) / 2 ** (cap + 1)
    return c, m


def run():
    c1, m1 = conditions()
    c2, m2 = simulation()
    # Instanciation : 128 bits, somme des termes du Théorème 16
    bits = 2 ** 126
    total = 7 * bits * (bits + 1) / 2 ** 257 + bits ** 2 / 2 ** 513 + bits ** 2 / 2 ** 257
    c1["theoreme_16_128_bits_pour_q_2_126"] = total <= bits / 2 ** 128
    out = {"controles": {**c1, **c2}, "mesures": {**m1, **m2}}
    sauver("indiff_arbre", out)
    return out


if __name__ == "__main__":
    print(run())
