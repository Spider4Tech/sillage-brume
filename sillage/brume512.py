# -*- coding: utf-8 -*-
"""
BRUME-512 v1 — permutation sponge 512 bits + AEAD duplex + mode TE + hachage
=============================================================================
Le chiffrement symétrique de la suite SILLAGE, version 1 : c'est la
permutation dont la cryptanalyse complète (recherche différentielle /
linéaire automatisée, bornes wide-trail) est embarquée dans
`sillage.cryptanalyse`. Voir README.md §BRUME-512.

Spécification figée (tables dans brume512_tables.py, empreintes SHA-256) :

  État       : 512 bits = 128 nibbles vus comme éléments de GF(16)
               = GF(2)[x]/(x^4 + x + 1) ;
  Round      : 1) XOR des constantes RC[r] (SHAKE256, anti-slide ; sans
                  effet sur les trails, invariants par translation XOR) ;
               2) S-box 4 bits en parallèle sur les 128 nibbles
                  (U = 4, NL = 4 : optima théoriques des bijections 4×4) ;
               3) diffusion linéaire v' = M v sur GF(16)^128 :
                  v'_j = XOR_{i∈N(j)∪{j}} c(j,i)·v_i, support = adjacence
                  A ⊕ I d'un graphe de Cayley 6-régulier non abélien
                  (D₁₂₈) sur 128 sommets, coefficients c(j,i) ∈ GF(16)*
                  pondérés arête par arête ;
  Rounds     : 32 — garanties PROUVÉES (théorème wide-trail par paires,
               B = 8 certifié exactement, tests/test_branch_exact.py) :
               caractéristique différentielle ≤ 2^-256, corrélation de
               trail linéaire ≤ 2^-128 ;
  Hachage    : sponge débit 256 / capacité 256 (collisions 2^128) ;
  AEAD       : duplex à clé sur la permutation (clé, nonce, AAD absorbés
               avec séparation de domaine), débit 256 bits (BRUME-512,
               λ = 128) ou 128 bits / capacité 384 (BRUME-512-256, λ = 256) ;
  Mode TE    : parités SEC-DED par bit-plan sur blocs de 64 octets de
               chiffré : corrige 1 octet/bloc (tout masque) et détecte les
               altérations multiples ACCIDENTELLES. Les parités ne sont pas
               authentifiées : face à un adversaire, seule la vérification
               du tag garantit l'intégrité.

Le pendant pédagogique `brume_v0` (diffusion NON pondérée, M = A ⊕ I) est
conservé : le banc de cryptanalyse y démontre une caractéristique
itérative fatale 1 → 7 → 1 (théorème d'exposant 2) — c'est ce qui motive
les coefficients pondérés de v1.

Suite expérimentale de recherche — non constant-time, non audité.
NE PAS UTILISER EN PRODUCTION.
"""
import hashlib
import hmac

import numpy as np

from . import brume512_tables as TF

# ---------------------------------------------------------------------------
# GF(16) = GF(2)[x] / (x^4 + x + 1)   (représentation : nibble 0..15)
# ---------------------------------------------------------------------------
POLY = 0x13  # x^4 + x + 1


def _gmul(a: int, b: int) -> int:
    """Multiplication dans GF(16) (boucle de référence)."""
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi = a & 0x8
        a = (a << 1) & 0xF
        if hi:
            a ^= (POLY & 0xF)
        b >>= 1
    return p


GMUL = np.array([[_gmul(a, b) for b in range(16)] for a in range(16)],
                dtype=np.uint8)          # GMUL[c, v] = c · v
GINV = np.zeros(16, dtype=np.uint8)       # GINV[v] = v^{-1} (0 -> 0)
for _a in range(1, 16):
    for _b in range(1, 16):
        if GMUL[_a, _b] == 1:
            GINV[_a] = _b
            break

# ---------------------------------------------------------------------------
# Tables figées (S-box, graphe, coefficients) — voir select_params.py
# ---------------------------------------------------------------------------
SBOX = np.array(TF.SBOX, dtype=np.uint8)
assert sorted(SBOX.tolist()) == list(range(16)), "S-box non bijective"
TF = TF  # alias public (le banc de cryptanalyse importe les tables via TF)

N = 128            # nibbles / sommets
DEG = 6            # degré du graphe
N_ROUNDS = 32      # rounds de la permutation BRUME-512 v1

GENS = list(TF.GENS)
GROUP = TF.GROUP   # 'D128' (dihédral, non abélien)


def group_op(a: int, b: int) -> int:
    """Produit dans le groupe figé (D_128 : Z/64 ⋊ Z/2)."""
    if GROUP == "D128":
        aa, ab = a & 63, (a >> 6) & 1
        ba, bb = b & 63, (b >> 6) & 1
        ra = (aa + (ba if ab == 0 else (-ba % 64))) % 64
        return ra | ((ab ^ bb) << 6)
    if GROUP == "Z4Z32":
        x, y = a & 3, (a >> 2) & 31
        u, v = b & 3, (b >> 2) & 31
        return ((x + u) % 4) | ((((y + v) % 32) << 2))
    raise ValueError("groupe non supporté")


def group_inv(a: int) -> int:
    if GROUP == "D128":
        aa, ab = a & 63, (a >> 6) & 1
        if ab == 0:
            return ((-aa) % 64) | 0
        return aa | (1 << 6)   # (r^aa s)^{-1} = r^aa s
    if GROUP == "Z4Z32":
        x, y = a & 3, (a >> 2) & 31
        return ((4 - x) % 4) | (((32 - y) % 32) << 2)
    raise ValueError("groupe non supporté")


def build_adjacency(gens):
    """Matrice d'adjacence binaire (symétrique) du graphe de Cayley.

    Voisinage de x : { x·g, x·g^{-1} : g dans gens } — 6-régulier que les
    générateurs soient des involutions (D_128) ou des paires inverses.
    """
    A = np.zeros((N, N), dtype=np.uint8)
    for x in range(N):
        for g in gens:
            y1 = group_op(x, g)
            y2 = group_op(x, group_inv(g))
            A[x, y1] = 1
            A[y1, x] = 1
            A[x, y2] = 1
            A[y2, x] = 1
    return A


ADJ = build_adjacency(GENS)          # support de la diffusion (sans self)
ADJ_I = ADJ.copy()
np.fill_diagonal(ADJ_I, 1)           # support de M = A ⊕ I


def _build_edges():
    """Arêtes orientées de M triées par destination j :
    v'_j = XOR_{(i,c) in edges_of[j]} c · v_i."""
    ej, ei, ec = [], [], []
    for j in range(N):
        for i in range(N):
            if ADJ_I[j, i]:
                ej.append(j)
                ei.append(i)
                ec.append(int(TF.COEF[j][i]))
    order = np.argsort(np.array(ej), kind="stable")
    ej = np.array(ej, dtype=np.int32)[order]
    ei = np.array(ei, dtype=np.int32)[order]
    ec = np.array(ec, dtype=np.uint8)[order]
    seg = np.searchsorted(ej, np.arange(N + 1))   # débuts de segments par j
    return ej, ei, ec, seg


E_J, E_I, E_C, E_SEG = _build_edges()
assert len(E_J) == N * (DEG + 1), "support de M incorrect"


def _build_edges_T():
    """Arêtes de M^T (propagation des masques linéaires) : M^T[i,j] = M[j,i]."""
    et_j, et_i, et_c = [], [], []
    for j in range(N):
        for i in range(N):
            if ADJ_I[j, i]:
                et_j.append(i)
                et_i.append(j)
                et_c.append(int(TF.COEF[j][i]))
    order = np.argsort(np.array(et_j), kind="stable")
    ej = np.array(et_j, dtype=np.int32)[order]
    ei = np.array(et_i, dtype=np.int32)[order]
    ec = np.array(et_c, dtype=np.uint8)[order]
    seg = np.searchsorted(ej, np.arange(N + 1))
    return ej, ei, ec, seg


E_J_T, E_I_T, E_C_T, E_SEG_T = _build_edges_T()

# Constantes de round : dérivées de SHAKE256 (sans effet sur diff/lin)
_RC = hashlib.shake_256(b"BRUME-v1-RC").digest(N * N_ROUNDS)
RC = [np.frombuffer(_RC[r * N:(r + 1) * N], dtype=np.uint8) & 0xF
      for r in range(N_ROUNDS)]


# ---------------------------------------------------------------------------
# Diffusion — versions vectorisées (une permutation = batch de 1)
# ---------------------------------------------------------------------------

def diffuse_batch(state: np.ndarray) -> np.ndarray:
    """v' = M v : state (B,128) uint8 -> (B,128) uint8."""
    contrib = GMUL[E_C, state[:, E_I]]            # (B, n_edges)
    return np.bitwise_xor.reduceat(contrib, E_SEG[:-1], axis=1)


def _gmul_T():
    """GMUL_T[c, mu] = L_c^T mu : transposée BINAIRE de la multiplication par
    c (bit k = <mu, c·x^k>). C'est l'adjoint correct pour le pairing binaire
    <a, b> = parité(a & b) du LAT. On a L_c^T = G·L_c·G^{-1} (G = Gram de la
    trace) : mêmes motifs d'activité que M^T sur GF(16), donc mêmes branch
    numbers — mais seules ces valeurs de masques sont cohérentes avec le LAT."""
    t = np.zeros((16, 16), dtype=np.uint8)
    for c in range(16):
        for mu in range(16):
            t[c, mu] = sum((bin(mu & int(GMUL[c, 1 << k])).count("1") & 1) << k
                           for k in range(4))
    return t


GMUL_T = _gmul_T()


def diffuse_T_batch(state: np.ndarray) -> np.ndarray:
    """Masques linéaires : mu -> M^T_bin mu (adjoint binaire), version batch."""
    contrib = GMUL_T[E_C_T, state[:, E_I_T]]
    return np.bitwise_xor.reduceat(contrib, E_SEG_T[:-1], axis=1)


def diffuse(state: np.ndarray) -> np.ndarray:
    """v' = M v d'un état (128,) uint8 (nibbles GF(16))."""
    return diffuse_batch(state[None, :])[0]


def diffuse_T(state: np.ndarray) -> np.ndarray:
    """v' = M^T v d'un état (128,) uint8."""
    return diffuse_T_batch(state[None, :])[0]


# ---------------------------------------------------------------------------
# Permutation BRUME v1 (pondérée) et v0 (naïve, coefficients = 1)
# ---------------------------------------------------------------------------

# Tables fusionnées par tour : T_r[arête, x] = c_arête · S(x ⊕ RC[r][i_arête])
# (constante + S-box + multiplication GF(16) en un seul accès mémoire).
_EDGES = np.arange(len(E_I))
_T_TOUR = [GMUL[E_C[:, None], SBOX[np.arange(16)[None, :] ^ RC[r][E_I][:, None]]]
           for r in range(N_ROUNDS)]


def _permute_batch(state: np.ndarray, rounds: int = N_ROUNDS) -> np.ndarray:
    """Noyau vectorisé : state (B,128) uint8 -> (B,128) uint8.

    Tour r : s ← M·S(s ⊕ RC[r]), calculé par la table fusionnée _T_TOUR[r]."""
    if not 1 <= rounds <= N_ROUNDS:
        raise ValueError(f"rounds ∈ [1,{N_ROUNDS}]")
    s = (state & 0xF).astype(np.uint8)
    for r in range(rounds):
        s = np.bitwise_xor.reduceat(_T_TOUR[r][_EDGES, s[:, E_I]], E_SEG[:-1],
                                    axis=1)
    return s


def brume_v1(state: np.ndarray, rounds: int = N_ROUNDS) -> np.ndarray:
    """Permutation BRUME-512 v1 : (128,) uint8 -> (128,) uint8."""
    return _permute_batch(state[None, :], rounds)[0]


def _diffuse_v0_batch(state: np.ndarray) -> np.ndarray:
    return np.bitwise_xor.reduceat(state[:, E_I], E_SEG[:-1], axis=1)


def brume_v0(state: np.ndarray, rounds: int = N_ROUNDS) -> np.ndarray:
    """Variante pédagogique NON pondérée (M = A ⊕ I) — cassée (voir banc) :
    caractéristique itérative démontrée sur Cayley d'exposant 2."""
    s = (state & 0xF).astype(np.uint8)[None, :]
    for r in range(rounds):
        s = s ^ RC[r]
        s = SBOX[s]
        s = _diffuse_v0_batch(s)
    return s[0]


# ---------------------------------------------------------------------------
# Sponge : hachage BRUME-512
# ---------------------------------------------------------------------------

RATE = 64                 # nibbles d'absorption = 256 bits (débit)
RATE_BYTES = RATE // 2    # 32 octets par bloc
CAPACITY_BITS = (N - RATE) * 4   # 256 bits


def _pack_nibbles(nib: np.ndarray) -> bytes:
    """(2k,) nibbles -> k octets (little-endian par paire)."""
    return (nib[0::2] | (nib[1::2] << 4)).astype(np.uint8).tobytes()


def _unpack_bytes(buf: bytes) -> np.ndarray:
    """k octets -> (2k,) nibbles."""
    a = np.frombuffer(buf, dtype=np.uint8)
    out = np.empty(len(a) * 2, dtype=np.uint8)
    out[0::2] = a & 0xF
    out[1::2] = a >> 4
    return out


def brume512_hash(msg: bytes, out_len: int = 32,
                  rounds: int = N_ROUNDS) -> bytes:
    """Fonction de hachage BRUME-512 (sponge absorb/squeeze).

    Padding prototype : octet 0x01 puis zéros jusqu'au multiple du débit
    (le banc de cryptanalyse n'analyse pas le mode sponge — voir README).
    Sécurité générique ≈ 2^128 (capacité 256 bits).
    """
    state = np.zeros(N, dtype=np.uint8)
    data = msg + b"\x01"
    data += b"\x00" * ((RATE_BYTES - len(data) % RATE_BYTES) % RATE_BYTES)
    for blk in range(0, len(data), RATE_BYTES):
        state[:RATE] ^= _unpack_bytes(data[blk:blk + RATE_BYTES])
        state = brume_v1(state, rounds)
    out = bytearray()
    while len(out) < out_len:
        out += _pack_nibbles(state[:RATE])
        state = brume_v1(state, rounds)
    return bytes(out[:out_len])


# Hachage arborescent (parallélisable) : nœuds = éponge à domaine dans la
# capacité (dernier nibble, avant la permutation finale d'absorption, comme
# l'AEAD) ; domaine 0 = brume512_hash. Codage à la Sakura : nœuds simples,
# feuilles et racine séparés par domaine, racine = CV_0 ‖ … ‖ CV_{k−1} ‖ k ‖ B.
_DOM_FEUILLE, _DOM_RACINE, _DOM_SEUL = 8, 9, 10
ARBRE_BLOC = 8192          # octets par feuille (256 blocs de débit)
ARBRE_CV = 32              # valeur de chaînage (256 bits)


def _eponge(data: bytes, dom: int, out_len: int,
            rounds: int = N_ROUNDS) -> bytes:
    """Éponge BRUME-512 (débit 256 bits, bourrage 10*) avec le domaine `dom`
    XORé dans le dernier nibble de la capacité avant la permutation finale
    d'absorption. _eponge(m, 0, ℓ) = brume512_hash(m, ℓ)."""
    state = np.zeros(N, dtype=np.uint8)
    data = data + b"\x01" + b"\x00" * ((-len(data) - 1) % RATE_BYTES)
    for blk in range(0, len(data), RATE_BYTES):
        state[:RATE] ^= _unpack_bytes(data[blk:blk + RATE_BYTES])
        if blk + RATE_BYTES == len(data):
            state[N - 1] ^= dom
        state = brume_v1(state, rounds)
    out = bytearray()
    while len(out) < out_len:
        out += _pack_nibbles(state[:RATE])
        state = brume_v1(state, rounds)
    return bytes(out[:out_len])


def brume512_hash_arbre(msg: bytes, out_len: int = 32) -> bytes:
    """Hachage arborescent BRUME-512 (un niveau de feuilles, à la
    KangarooTwelve) : les feuilles de ARBRE_BLOC octets se hachent en
    parallèle. Message ≤ ARBRE_BLOC : un seul nœud (domaine SEUL).
    Preuve : docs/PREUVES.md § 4.4."""
    if len(msg) <= ARBRE_BLOC:
        return _eponge(msg, _DOM_SEUL, out_len)
    cvs = b"".join(_eponge(msg[i:i + ARBRE_BLOC], _DOM_FEUILLE, ARBRE_CV)
                   for i in range(0, len(msg), ARBRE_BLOC))
    k = len(cvs) // ARBRE_CV
    return _eponge(cvs + k.to_bytes(8, "big") + ARBRE_BLOC.to_bytes(4, "big"),
                   _DOM_RACINE, out_len)


# ---------------------------------------------------------------------------
# AEAD duplex + mode auto-correcteur (TE)
# ---------------------------------------------------------------------------

class Brume512TagError(Exception):
    """Tag invalide — chiffré, nonce ou AAD altéré."""


class Brume512TamperError(Exception):
    """Altération multiple détectée par les parités TE (échec bruyant)."""


# Débit/capacité par profil. Duplex à clé : avantage générique ≈ M·N/2^c
# (M blocs de données, N appels hors ligne) + N/2^k. BRUME-512 : c = 256
# (λ = 128, M ≤ 2^64) ; BRUME-512-256 : c = 384, débit 128 bits (λ = 256 pour
# M ≤ 2^128 ; clé 512 bits → 2^256 après Grover).
BRUME512_PROFILES = {
    "BRUME-512":     dict(key_len=64, nonce_len=24, tag_len=16, lam=128,
                          rate=64),
    "BRUME-512-256": dict(key_len=64, nonce_len=24, tag_len=32, lam=256,
                          rate=32),
}

# Bits de séparation de domaine (dernier nibble de la capacité)
_DOM_AAD, _DOM_TEXTE, _DOM_FINAL = 1, 2, 4

BLOCK = 64  # taille des blocs TE (octets de chiffré)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")
            ).to_bytes(len(a), "little")


def _plane_syndromes(block) -> list:
    """8 syndromes de Hamming 6 bits (un par bit-plan, positions 1..63)."""
    syns = [0] * 8
    for j in range(1, 64):
        byte = block[j]
        if byte == 0:
            continue
        while byte:
            low = byte & -byte
            k = low.bit_length() - 1
            syns[k] ^= j          # XOR des positions dans chaque plan
            byte ^= low
    return syns


def _te_parity(block: bytes) -> bytes:
    """Parité TE d'un bloc de 64 octets : C0 + 8 syndromes (6 bits chacun)."""
    acc = 0
    for byte in block:
        acc ^= byte
    syns = _plane_syndromes(block)
    bits = 0
    for k in range(7, -1, -1):
        bits = (bits << 6) | syns[k]
    return bytes((acc,)) + bits.to_bytes(6, "big")


def _te_check(buf: bytearray, off: int, par: bytes):
    """Vérifie/corrige le bloc buf[off:off+64] EN PLACE.

    Retourne la position corrigée (offset global) ou None.
    Lève Brume512TamperError si l'altération n'est pas corrigeable."""
    block = buf[off:off + 64]
    acc = 0
    for byte in block:
        acc ^= byte
    syns = _plane_syndromes(block)
    stored = [0] * 8
    packed = int.from_bytes(par[1:7], "big")
    for k in range(8):
        stored[k] = (packed >> (6 * k)) & 0x3F

    deltas = [syns[k] ^ stored[k] for k in range(8)]
    dm = acc ^ par[0]

    if dm == 0 and all(d == 0 for d in deltas):
        return None
    if dm == 0:
        raise Brume512TamperError("altération multiple détectée (dm=0)")
    m = dm  # valeur de l'erreur
    nonzero = sorted({d for d in deltas if d != 0})
    if len(nonzero) == 0:
        pos = 0                      # position 0 : hors groupes Hamming
    elif len(nonzero) == 1:
        pos = nonzero[0]             # tous les plans touchés concordent
        if pos >= 64:
            raise Brume512TamperError("syndrome hors bornes")
    else:
        raise Brume512TamperError(
            f"altération multiple détectée (plans en désaccord: {nonzero})")
    buf[off + pos] ^= m
    return off + pos


class Brume512:
    """AEAD BRUME-512 v1 : sponge duplex (chiffré absorbé) + mode TE.

    Usage :
        br = Brume512("BRUME-512", key=cle_64_octets)
        ct, tag = br.encrypt(nonce24, message, aad)
        pt = br.decrypt(nonce24, ct, tag, aad)          # lève Brume512TagError
        ct, pars, tag, meta = br.encrypt_te(nonce24, message)
        pt, corrections = br.decrypt_te(nonce24, ct, pars, tag, meta)
    """

    PROFILS = BRUME512_PROFILES

    def __init__(self, profile: str = "BRUME-512", key: bytes = None):
        if profile not in self.PROFILS:
            raise ValueError(f"profil inconnu : {profile}")
        self.name = profile
        self.p = self.PROFILS[profile]
        if key is None:
            from .sillage_common import random_bytes
            key = random_bytes(self.p["key_len"])
        if len(key) != self.p["key_len"]:
            raise ValueError(f"clé de {self.p['key_len']} octets requise")
        self.key = key

    # ---------------- duplex à clé (tout par la permutation BRUME) --------

    def _absorb(self, state, data: bytes, dom: int):
        """Absorbe data par blocs de débit, bourrage 10* systématique (un
        bloc au moins), puis bit de domaine dans la capacité et permutation."""
        rb = self.p["rate"] // 2
        data = data + b"\x01" + b"\x00" * ((-len(data) - 1) % rb)
        for i in range(0, len(data), rb):
            state[:self.p["rate"]] ^= _unpack_bytes(data[i:i + rb])
            if i + rb < len(data):
                state = brume_v1(state)
        state[N - 1] ^= dom
        return brume_v1(state)

    def _init_state(self, nonce: bytes, aad: bytes) -> np.ndarray:
        """IV(profil) ‖ 0 → absorbe clé ‖ nonce (une phase), puis AAD.

        v0.3 : l'état initial était entièrement tiré de SHAKE256(clé, nonce,
        AAD) — la clé ne passait jamais par BRUME. Désormais la suite est
        auto-suffisante : duplex à clé « outer-keyed » sur la permutation."""
        state = brume_v1(self._iv())
        state = self._absorb(state, self.key + nonce, 0)
        return self._absorb(state, aad, _DOM_AAD)

    def _iv(self) -> np.ndarray:
        p = self.p
        state = np.zeros(N, dtype=np.uint8)
        state[N - 8:N - 1] = _unpack_bytes(
            bytes((p["rate"], p["tag_len"], p["lam"] & 0xFF, 3)))[:7]
        return state

    def _duplex(self, nonce: bytes, data: bytes, aad: bytes, decrypt: bool):
        """Cœur duplex commun à encrypt/decrypt -> (sortie, tag).

        Le dernier bloc est TOUJOURS partiel et bourré 10* (padding
        injectif) ; finalisation séparée par domaine puis bloc de longueur
        absorbé APRÈS une permutation ; tag extrait par blocs de débit. En
        v0.2, le dernier bloc de chiffré et le bloc de longueur partageaient
        le même débit : (c_last ⊕ Δ(L,L'), L') gardait le tag (falsification
        de probabilité 1 — régression testée par tests/test_aead.py).
        """
        p = self.p
        if len(nonce) != p["nonce_len"]:
            raise ValueError(f"nonce de {p['nonce_len']} octets requis")
        rate, rb = p["rate"], p["rate"] // 2
        state = self._init_state(nonce, aad)
        out = bytearray()
        for i in range(0, len(data) + 1, rb):
            ks = _pack_nibbles(state[:rate])
            chunk = data[i:i + rb]
            o = _xor_bytes(chunk, ks[:len(chunk)])
            c = chunk if decrypt else o
            if len(c) < rb:                               # bloc final, 10*
                c = c + b"\x01" + b"\x00" * (rb - len(c) - 1)
            state[:rate] ^= _unpack_bytes(c)
            out += o
            state = brume_v1(state)
        state[N - 1] ^= _DOM_TEXTE
        state = brume_v1(state)
        state = self._absorb(state, len(data).to_bytes(8, "little"),
                             _DOM_FINAL)
        tag = bytearray()
        while len(tag) < p["tag_len"]:
            tag += _pack_nibbles(state[:rate])
            if len(tag) < p["tag_len"]:
                state = brume_v1(state)
        return bytes(out), bytes(tag[:p["tag_len"]])

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b""):
        """(ct, tag) — duplex : keystream + absorbation du chiffré."""
        return self._duplex(nonce, plaintext, aad, decrypt=False)

    def decrypt(self, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b""):
        """plaintext — lève Brume512TagError si le tag ne correspond pas."""
        pt, expected = self._duplex(nonce, ct, aad, decrypt=True)
        if not hmac.compare_digest(expected, tag):
            raise Brume512TagError("tag invalide — chiffré, nonce ou AAD "
                                   "altéré")
        return pt

    # ---------------- mode auto-correcteur (TE) ----------------
    # Codage : blocs de 64 octets de CHIFFRÉ + 7 octets de parité (10,9 %) :
    #   C0      : XOR de tous les octets → VALEUR de l'erreur (tout masque) ;
    #   s_0..s_7: syndromes de Hamming 6 bits, UN PAR BIT-PLAN → une erreur
    #             d'octet à la position j bascule le bit k du plan k ssi
    #             m_k = 1, et tous les plans touchés indiquent la MÊME
    #             position j.
    # Correction : 1 octet altéré par bloc (tout masque) ; altérations
    # multiples détectées par incohérence inter-plans → échec bruyant.
    # Le tag final reste LA garantie cryptographique d'intégrité.

    def encrypt_te(self, nonce: bytes, plaintext: bytes, aad: bytes = b""):
        """(ct, parities, tag, meta) — mode auto-correcteur."""
        ct, tag = self.encrypt(nonce, plaintext, aad)
        pad_len = (-len(ct)) % BLOCK
        ct_p = ct + b"\x00" * pad_len
        pars = bytearray()
        for i in range(0, len(ct_p), BLOCK):
            pars += _te_parity(ct_p[i:i + BLOCK])
        meta = len(ct).to_bytes(8, "big")
        return ct, bytes(pars), tag, meta

    def decrypt_te(self, nonce: bytes, ct: bytes, parities: bytes,
                   tag: bytes, meta: bytes, aad: bytes = b""):
        """(plaintext, corrections) — corrige EN PLACE puis vérifie le tag.
        Lève Brume512TamperError (altération multiple) ou Brume512TagError."""
        n_blocks = -(-len(ct) // BLOCK)
        if len(parities) != 7 * n_blocks or len(meta) != 8 \
                or int.from_bytes(meta, "big") != len(ct):
            raise Brume512TamperError("parités/métadonnées incohérentes")
        buf = bytearray(ct)
        buf += b"\x00" * (n_blocks * BLOCK - len(buf))
        corrections = []
        for bi in range(n_blocks):
            pos = _te_check(buf, bi * BLOCK,
                            parities[bi * 7:(bi + 1) * 7])
            if pos is not None:
                corrections.append(pos)
        orig_len = int.from_bytes(meta, "big")
        if orig_len > len(buf):
            raise Brume512TamperError("métadonnées incohérentes")
        pt = self.decrypt(nonce, bytes(buf[:orig_len]), tag, aad)
        return pt, corrections


# ---------------------------------------------------------------------------
# AEAD parallèle (docs/PREUVES.md § 4.5)
# ---------------------------------------------------------------------------

BRUME512P_PROFILES = {"BRUME-512p": BRUME512_PROFILES["BRUME-512"],
                      "BRUME-512-256p": BRUME512_PROFILES["BRUME-512-256"]}
AEADP_LOG_FEUILLE = 12
AEADP_FEUILLE = 1 << AEADP_LOG_FEUILLE
_DOM_DEPART, _DOM_FOURCHE, _DOM_FIN_FEUILLE = 3, 5, 6


class Brume512P(Brume512):
    """Duplex parallèle : le message est coupé en feuilles de 4 Kio, chacune suivie par son
    duplex à clé, dérivé d'un tronc (clé, nonce, AAD) ; les états finaux sont absorbés par le
    tronc, qui produit le tag. Même interface que Brume512, autre fonction (IV distinct)."""
    PROFILS = BRUME512P_PROFILES

    def _iv(self) -> np.ndarray:
        state = super()._iv()
        state[N - 12:N - 8] = _unpack_bytes(bytes((AEADP_LOG_FEUILLE, 1)))
        return state

    def _feuille(self, tronc, j: int, data: bytes, decrypt: bool):
        """(sortie, CV) de la feuille j : les 2λ premiers bits de l'état final."""
        rate, rb = self.p["rate"], self.p["rate"] // 2
        state = tronc.copy()
        state[:rate] ^= _unpack_bytes((j.to_bytes(8, "little") + b"\x01").ljust(rb, b"\x00"))
        state[N - 1] ^= _DOM_FOURCHE
        state = brume_v1(state)
        state[N - 1] ^= _DOM_DEPART
        state = brume_v1(state)
        out = bytearray()
        for i in range(0, len(data) + 1, rb):
            ks = _pack_nibbles(state[:rate])
            chunk = data[i:i + rb]
            o = _xor_bytes(chunk, ks[:len(chunk)])
            c = chunk if decrypt else o
            dernier = len(c) < rb
            if dernier:                                   # bloc final, 10*
                c = c + b"\x01" + b"\x00" * (rb - len(c) - 1)
                state[N - 1] ^= _DOM_FIN_FEUILLE
            state[:rate] ^= _unpack_bytes(c)
            out += o
            state = brume_v1(state)
        return bytes(out), _pack_nibbles(state)[:self.p["lam"] // 4]

    def _duplex(self, nonce: bytes, data: bytes, aad: bytes, decrypt: bool):
        p = self.p
        if len(nonce) != p["nonce_len"]:
            raise ValueError(f"nonce de {p['nonce_len']} octets requis")
        rate = p["rate"]
        tronc = self._init_state(nonce, aad)
        k = max(1, -(-len(data) // AEADP_FEUILLE))
        res = [self._feuille(tronc, j, data[j * AEADP_FEUILLE:(j + 1) * AEADP_FEUILLE], decrypt) for j in range(k)]
        state = self._absorb(tronc.copy(), b"".join(cv for _, cv in res) + k.to_bytes(8, "little")
                             + len(data).to_bytes(8, "little"), _DOM_FINAL)
        tag = bytearray()
        while len(tag) < p["tag_len"]:
            tag += _pack_nibbles(state[:rate])
            if len(tag) < p["tag_len"]:
                state = brume_v1(state)
        return b"".join(o for o, _ in res), bytes(tag[:p["tag_len"]])


# ---------------------------------------------------------------------------
# Auto-tests
# ---------------------------------------------------------------------------

def _gauss_gf16_inverse(mat: np.ndarray) -> np.ndarray:
    """Inverse d'une matrice n×n à coefficients GF(16) (Gauss-Jordan)."""
    n = mat.shape[0]
    a = np.concatenate([mat.astype(np.uint8) % 16,
                        np.eye(n, dtype=np.uint8)], axis=1)
    row = 0

    def _row_mul(row_, c):
        return GMUL[c][row_]

    for col in range(n):
        piv = None
        for r in range(row, n):
            if a[r, col] & 0xF:
                piv = r
                break
        assert piv is not None, "matrice singulière sur GF(16)"
        a[[row, piv]] = a[[piv, row]]
        a[row] = _row_mul(a[row], int(GINV[a[row, col]]))
        for r in range(n):
            if r != row and (a[r, col] & 0xF):
                a[r] ^= _row_mul(a[row], int(a[r, col]))
        row += 1
    return a[:, n:] % 16


def selftest(verbose: bool = True) -> dict:
    """Tests de sanité de la permutation, de la diffusion et de l'AEAD."""
    res = {}
    # 0) degré du graphe et connexité
    degs = ADJ_I.sum(axis=1)
    res["degre_6"] = bool((degs == DEG + 1).all())
    seen = np.zeros(N, dtype=bool)
    stack = [0]
    seen[0] = True
    while stack:
        x = stack.pop()
        for y in np.nonzero(ADJ[x])[0]:
            if not seen[y]:
                seen[y] = True
                stack.append(int(y))
    res["graphe_connexe"] = bool(seen.all())
    # 1) diffusion : coefficients non nuls, M inversible sur GF(16)
    assert all(c != 0 for c in E_C), "coefficient nul dans M"
    full = np.zeros((N, N), dtype=np.uint8)
    for j in range(N):
        for k in range(E_SEG[j], E_SEG[j + 1]):
            full[j, E_I[k]] = E_C[k]
    _gauss_gf16_inverse(full)               # lève si singulière
    res["det_M_non_nul_gf16"] = True
    # 2) bijectivité de la permutation sur échantillon
    rng = np.random.default_rng(1)
    seen_out = set()
    for _ in range(200):
        x = rng.integers(0, 16, size=N).astype(np.uint8)
        y = brume_v1(x)
        seen_out.add(y.tobytes())
    res["injectivite_echantillon"] = (len(seen_out) == 200)
    # 3) v0 vs v1 : le cycle itératif v0 1→7→1 (exposant 2, Cf. banc) ne
    #    concerne pas v1 — sonde : poids du support après diffusion v1
    x = np.zeros(N, dtype=np.uint8)
    x[0] = 3
    res["propagation_1_nibble_v1"] = int((diffuse(x) != 0).sum())  # = 7
    # 4) hachage : déterminisme + longueur
    h1 = brume512_hash(b"BRUME-512 KAT", 32)
    h2 = brume512_hash(b"BRUME-512 KAT", 32)
    res["hash_deterministe"] = (h1 == h2)
    res["kat_hash_32o"] = h1.hex()
    # 5) AEAD roundtrip + rejet d'un tag falsifié
    br = Brume512("BRUME-512", key=bytes(range(64)))
    nonce = bytes(range(24))
    msg = b"ordre de mission BRUME-512 - test AEAD duplex"
    ct, tag = br.encrypt(nonce, msg, aad=b"test")
    res["aead_roundtrip"] = (br.decrypt(nonce, ct, tag, aad=b"test") == msg)
    try:
        br.decrypt(nonce, ct + b"\x00", tag, aad=b"test")
        res["aead_rejet_altere"] = False
    except Brume512TagError:
        res["aead_rejet_altere"] = True
    # 5b) régression v0.2 : (c_last ⊕ Δ(L, L+1), L+1) ne doit PAS valider
    ct33, tag33 = br.encrypt(nonce, b"A" * 33)
    d = (33 ^ 34).to_bytes(8, "little")
    forged = ct33[:32] + bytes(a ^ b for a, b in zip(ct33[32:] + b"\x00", d))
    try:
        br.decrypt(nonce, forged, tag33)
        res["aead_rejet_collision_longueur"] = False
    except Brume512TagError:
        res["aead_rejet_collision_longueur"] = True
    # 5c) KAT AEAD (régression de la spécification v0.3)
    kat = {"BRUME-512": "73fd10eb9c0253746ee08c4659573e0b",
           "BRUME-512-256": "94efc56087f4c85d0cd16e954935d1af"
                            "0913c29c36ff0b2a227b0707930e4bd1"}
    res["kat_aead"] = all(
        Brume512(pr, key=bytes(range(64))).encrypt(
            bytes(24), b"BRUME-512 KAT")[1].hex() == v for pr, v in kat.items())
    # 6) mode TE : correction d'1 octet, échec bruyant sur 2
    ct2, pars, tag2, meta = br.encrypt_te(nonce, msg)
    canal = bytearray(ct2)
    canal[10] ^= 0xFF
    pt2, corr = br.decrypt_te(nonce, bytes(canal), pars, tag2, meta)
    res["te_corrections"] = corr
    res["te_repare"] = (pt2 == msg)
    canal2 = bytearray(ct2)
    canal2[10] ^= 0xFF
    canal2[12] ^= 0x01      # 2 erreurs dans le même bloc
    try:
        br.decrypt_te(nonce, bytes(canal2), pars, tag2, meta)
        res["te_echec_bruyant"] = False
    except Brume512TamperError:
        res["te_echec_bruyant"] = True
    if verbose:
        for k, v in res.items():
            print(f"  [brume512] {k}: {v}")
    return res


if __name__ == "__main__":
    print("=== BRUME-512 v1 : auto-tests ===", flush=True)
    selftest()
    rng = np.random.default_rng(0)
    x = rng.integers(0, 16, size=N).astype(np.uint8)
    print("  permutation v1(x)[:8] =", brume_v1(x)[:8].tolist())
    print("  permutation v0(x)[:8] =", brume_v0(x)[:8].tolist())
