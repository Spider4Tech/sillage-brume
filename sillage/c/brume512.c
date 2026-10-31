/* SILLAGE C — BRUME-512 : permutation, hachage, AEAD duplex, mode TE.
 *
 * L'état est EMPAQUETÉ : 64 octets, le nibble i est le demi-octet bas
 * (i pair) ou haut (i impair) de l'octet i/2 — exactement _pack_nibbles du
 * Python. Le débit se lit et s'écrit donc directement en octets.
 *
 * Un tour : y_j = S(x_j ⊕ RC[r][j]) puis M·y = XOR des 128 colonnes
 *   L[j][y] = M · (y placé en position j)   (512 bits, empaquetés),
 * table de 128 Kio indépendante du tour (tient dans le cache L2 ; une
 * table fusionnant S et RC par tour pèserait 4 Mio). Construite par
 * sl_init() à partir de brume512_tables.h.
 */
#include <string.h>

#include "brume512_tables.h"
#include "sillage.h"

static uint64_t L[BR_N][16][8] __attribute__((aligned(64)));
static int pret;
static void init_iv(void);

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 4; i++) {
        if (b & 1)
            r ^= a;
        b >>= 1;
        a <<= 1;
        if (a & 0x10)
            a ^= BR_POLY;
    }
    return r & 15;
}

void sl_init(void)
{
    if (pret)
        return;
    memset(L, 0, sizeof L);
    for (int e = 0; e < BR_ARETES; e++) {
        int v = e / BR_DEG, j = BR_EI[e];
        for (int y = 0; y < 16; y++)
            L[j][y][v >> 4] ^= (uint64_t)gmul(BR_EC[e], (uint8_t)y) << (4 * (v & 15));
    }
    br_init_avx2();
    init_iv();
    pret = 1;
}

/* permutation de référence (tables) — repli sans AVX2, et témoin des tests */
static void permuter_ref(uint64_t w[8])
{
    for (int r = 0; r < BR_TOURS; r++) {
        uint64_t a[8] = {0};
        const uint8_t *rc = BR_RC[r];
        for (int j = 0; j < BR_N; j++) {
            uint8_t y = BR_SBOX[((w[j >> 4] >> (4 * (j & 15))) & 15) ^ rc[j]];
            const uint64_t *u = L[j][y];
            for (int k = 0; k < 8; k++)
                a[k] ^= u[k];
        }
        memcpy(w, a, 64);
    }
}

/* Avec AVX2 ou NEON : version constant-time (brume512_avx2.c), mêmes sorties. */
static inline void permuter(uint64_t w[8])
{
#ifdef __AVX2__
    br_permuter_avx2(w);
#elif defined(__ARM_NEON)
    br_permuter_neon(w);
#else
    permuter_ref(w);
#endif
}

void sl_brume_permute_ref(uint8_t etat[64])
{
    uint64_t w[8];
    memcpy(w, etat, 64);
    permuter_ref(w);
    memcpy(etat, w, 64);
}

void sl_brume_permute(uint8_t etat[64])
{
    uint64_t w[8];
    memcpy(w, etat, 64);
    permuter(w);
    memcpy(etat, w, 64);
}

#define OCT(w) ((uint8_t *)(w))

/* ------------------------------------------------------------- hachage */
/* Éponge à domaine (dernier nibble de la capacité, octet 63 haut, XORé avant
 * la permutation finale d'absorption) ; dom = 0 : hachage séquentiel. */
void br_eponge(const uint8_t *m, size_t len, int dom, uint8_t *out, size_t outlen)
{
    uint64_t w[8] = {0};
    size_t i = 0;
    for (; i + 32 <= len; i += 32) {
        for (int k = 0; k < 32; k++)
            OCT(w)[k] ^= m[i + k];
        permuter(w);
    }
    uint8_t der[32] = {0};                 /* reste ‖ 0x01 ‖ 0* (un bloc) */
    memcpy(der, m + i, len - i);
    der[len - i] = 0x01;
    for (int k = 0; k < 32; k++)
        OCT(w)[k] ^= der[k];
    OCT(w)[63] ^= (uint8_t)(dom << 4);
    permuter(w);
    for (size_t o = 0; o < outlen; o += 32) {
        size_t k = outlen - o < 32 ? outlen - o : 32;
        memcpy(out + o, w, k);
        permuter(w);
    }
}

void sl_hash(const uint8_t *m, size_t len, uint8_t *out, size_t outlen)
{
    br_eponge(m, len, 0, out, outlen);
}

/* ---------------------------------------------------------------- AEAD */
static const struct { int debit, tag, lam; } PROFIL[2] = {{32, 16, 128}, {16, 32, 256}};
enum { DOM_AAD = 1, DOM_TEXTE = 2, DOM_FINAL = 4 };

size_t sl_aead_tag_len(int profil) { return profil < 0 || profil > 1 ? 0 : (size_t)PROFIL[profil].tag; }

/* _absorb : blocs de débit, bourrage 10* (au moins un bloc), domaine, P ;
 * reprise possible au bloc b0 (les blocs < b0 déjà absorbés). */
static void absorber_depuis(uint64_t w[8], int rb, const uint8_t *d1, size_t l1,
                            const uint8_t *d2, size_t l2, size_t b0, int dom)
{
    size_t tot = l1 + l2, nb = tot / (size_t)rb + 1;
    for (size_t b = b0; b < nb; b++) {
        for (int k = 0; k < rb; k++) {
            size_t i = b * (size_t)rb + (size_t)k;
            uint8_t x = i < l1 ? d1[i] : i < tot ? d2[i - l1] : (i == tot ? 0x01 : 0);
            OCT(w)[k] ^= x;
        }
        if (b + 1 < nb)
            permuter(w);
    }
    OCT(w)[63] ^= (uint8_t)(dom << 4);     /* nibble 127 */
    permuter(w);
}

static void absorber(uint64_t w[8], int rb, const uint8_t *d1, size_t l1,
                     const uint8_t *d2, size_t l2, int dom)
{
    absorber_depuis(w, rb, d1, l1, d2, l2, 0, dom);
}

void br_absorber(uint64_t w[8], int rb, const uint8_t *d1, size_t l1, const uint8_t *d2, size_t l2, int dom)
{
    absorber(w, rb, d1, l1, d2, l2, dom);
}

/* État après P(IV) : constante du profil, calculée une fois (sl_init).
 * Indices 2 et 3 : profils parallèles (mêmes paramètres, IV distinct). */
static uint64_t S0[4][8];

const uint8_t *br_etat_iv(int profil) { return (const uint8_t *)S0[profil]; }

static void init_iv(void)
{
    for (int p = 0; p < 4; p++) {
        uint64_t *w = S0[p];
        memset(w, 0, 64);
        if (p >= 2) {                                  /* parallèle : log2 feuille, mode */
            OCT(w)[58] = SL_AEADP_LOG_FEUILLE;
            OCT(w)[59] = 1;
        }
        OCT(w)[60] = (uint8_t)(2 * PROFIL[p & 1].debit);   /* débit en nibbles */
        OCT(w)[61] = (uint8_t)PROFIL[p & 1].tag;
        OCT(w)[62] = (uint8_t)(PROFIL[p & 1].lam & 0xFF);
        OCT(w)[63] = 3;
        permuter(w);
    }
}

/* Contexte de clé : état après absorption des blocs de débit qui ne
 * contiennent QUE la clé (2 blocs en BRUME-512, 4 en BRUME-512-256).
 * Matériel équivalent à la clé : à effacer après usage. */
int sl_aead_cle(sl_aead_cle_t *c, int profil, const uint8_t cle[64])
{
    if (profil < 0 || profil > 1)
        return -3;
    int rb = PROFIL[profil].debit;
    uint64_t w[8];
    memcpy(w, S0[profil], 64);
    for (int b = 0; b < 64 / rb; b++) {
        for (int k = 0; k < rb; k++)
            OCT(w)[k] ^= cle[b * rb + k];
        permuter(w);
    }
    c->profil = profil;
    memcpy(c->etat, w, 64);
    sl_effacer(w, 64);
    return 0;
}

void sl_effacer(void *p, size_t n) { explicit_bzero(p, n); }

static void duplex(const sl_aead_cle_t *c, const uint8_t nonce[SL_NONCE],
                   const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t len,
                   int dechiffre, uint8_t *out, uint8_t *tag)
{
    int profil = c->profil, rb = PROFIL[profil].debit, tl = PROFIL[profil].tag;
    uint64_t w[8];
    static const uint8_t zero[64] = {0};
    memcpy(w, c->etat, 64);                 /* suite de l'absorption clé ‖ nonce */
    absorber_depuis(w, rb, zero, 64, nonce, SL_NONCE, (size_t)(64 / rb), 0);
    absorber(w, rb, aad, aadlen, NULL, 0, DOM_AAD);
    size_t i = 0;
    /* L'état absorbe le CHIFFRÉ c par XOR : débit = flux ⊕ c = CLAIR
     * (duplex « overwrite », comme le Python). */
    for (; i + (size_t)rb <= len; i += (size_t)rb) {   /* blocs pleins */
        for (int k = 0; k < rb; k++) {
            uint8_t o = in[i + k] ^ OCT(w)[k];
            out[i + k] = o;
            OCT(w)[k] = dechiffre ? o : in[i + k];
        }
        permuter(w);
    }
    size_t r = len - i;                                 /* bloc final, 10* */
    for (size_t k = 0; k < r; k++) {      /* l'état absorbe le CHIFFRÉ */
        uint8_t o = in[i + k] ^ OCT(w)[k];
        out[i + k] = o;
        OCT(w)[k] ^= dechiffre ? in[i + k] : o;
    }
    OCT(w)[r] ^= 0x01;
    permuter(w);
    OCT(w)[63] ^= DOM_TEXTE << 4;
    permuter(w);
    uint8_t l8[8];
    for (int k = 0; k < 8; k++)
        l8[k] = (uint8_t)((uint64_t)len >> (8 * k));
    absorber(w, rb, l8, 8, NULL, 0, DOM_FINAL);
    for (int o = 0; o < tl; o += rb) {
        int k = tl - o < rb ? tl - o : rb;
        memcpy(tag + o, w, (size_t)k);
        if (o + rb < tl)
            permuter(w);
    }
    sl_effacer(w, 64);
}

int sl_aead_encrypt_ctx(const sl_aead_cle_t *c, const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                        size_t aadlen, const uint8_t *pt, size_t len, uint8_t *ct, uint8_t *tag)
{
    if (c->profil < 0 || c->profil > 1)
        return -3;
    duplex(c, nonce, aad, aadlen, pt, len, 0, ct, tag);
    return 0;
}

int sl_aead_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                    const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t len,
                    uint8_t *ct, uint8_t *tag)
{
    sl_aead_cle_t c;
    if (sl_aead_cle(&c, profil, cle))
        return -3;
    duplex(&c, nonce, aad, aadlen, pt, len, 0, ct, tag);
    sl_effacer(&c, sizeof c);
    return 0;
}

static int egal_ct(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= a[i] ^ b[i];
    return d == 0;
}

int sl_aead_decrypt_ctx(const sl_aead_cle_t *c, const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                        size_t aadlen, const uint8_t *ct, size_t len, const uint8_t *tag, uint8_t *pt)
{
    if (c->profil < 0 || c->profil > 1)
        return -3;
    uint8_t t[32];
    duplex(c, nonce, aad, aadlen, ct, len, 1, pt, t);
    if (!egal_ct(t, tag, (size_t)PROFIL[c->profil].tag)) {
        memset(pt, 0, len);
        return -1;
    }
    return 0;
}

int sl_aead_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                    const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t len,
                    const uint8_t *tag, uint8_t *pt)
{
    sl_aead_cle_t c;
    if (sl_aead_cle(&c, profil, cle))
        return -3;
    int rc = sl_aead_decrypt_ctx(&c, nonce, aad, aadlen, ct, len, tag, pt);
    sl_effacer(&c, sizeof c);
    return rc;
}

/* ------------------------------------------------------------ mode TE */
size_t sl_te_par_len(size_t len) { return 7 * ((len + 63) / 64); }

static void syndromes(const uint8_t *b, uint8_t *acc, uint8_t syn[8])
{
    uint8_t a = 0;
    memset(syn, 0, 8);
    for (int j = 0; j < 64; j++) {
        a ^= b[j];
        if (j)
            for (int k = 0; k < 8; k++)
                if (b[j] >> k & 1)
                    syn[k] ^= (uint8_t)j;
    }
    *acc = a;
}

static void bloc(const uint8_t *ct, size_t len, size_t i, uint8_t b[64])
{
    size_t k = len - 64 * i < 64 ? len - 64 * i : 64;
    memset(b, 0, 64);
    memcpy(b, ct + 64 * i, k);
}

int sl_te_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                  const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t len,
                  uint8_t *ct, uint8_t *par, uint8_t *tag, uint8_t meta[8])
{
    int rc = sl_aead_encrypt(profil, cle, nonce, aad, aadlen, pt, len, ct, tag);
    if (rc)
        return rc;
    for (size_t i = 0; i < (len + 63) / 64; i++) {
        uint8_t b[64], acc, syn[8];
        bloc(ct, len, i, b);
        syndromes(b, &acc, syn);
        uint64_t bits = 0;
        for (int k = 7; k >= 0; k--)
            bits = (bits << 6) | syn[k];
        par[7 * i] = acc;
        for (int k = 0; k < 6; k++)
            par[7 * i + 1 + k] = (uint8_t)(bits >> (8 * (5 - k)));
    }
    for (int k = 0; k < 8; k++)
        meta[k] = (uint8_t)((uint64_t)len >> (8 * (7 - k)));
    return 0;
}

int sl_te_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                  const uint8_t *aad, size_t aadlen, uint8_t *ct, size_t len,
                  const uint8_t *par, size_t parlen, const uint8_t *tag,
                  const uint8_t meta[8], uint8_t *pt, size_t *corrections, size_t *ncorr)
{
    size_t nb = (len + 63) / 64;
    uint64_t lm = 0;
    for (int k = 0; k < 8; k++)
        lm = (lm << 8) | meta[k];
    *ncorr = 0;
    if (parlen != 7 * nb || lm != len)
        return -2;
    for (size_t i = 0; i < nb; i++) {
        uint8_t b[64], acc, syn[8], d[8];
        bloc(ct, len, i, b);
        syndromes(b, &acc, syn);
        uint64_t bits = 0;
        for (int k = 0; k < 6; k++)
            bits = (bits << 8) | par[7 * i + 1 + k];
        int nul = 1;
        for (int k = 0; k < 8; k++) {
            d[k] = syn[k] ^ (uint8_t)((bits >> (6 * k)) & 0x3F);
            nul &= d[k] == 0;
        }
        uint8_t dm = acc ^ par[7 * i];
        if (dm == 0 && nul)
            continue;
        if (dm == 0)
            return -2;
        int pos = -1;                  /* tous les plans touchés concordent ? */
        for (int k = 0; k < 8; k++)
            if (d[k]) {
                if (pos >= 0 && d[k] != pos)
                    return -2;
                pos = d[k];
            }
        if (pos < 0)
            pos = 0;
        size_t g = 64 * i + (size_t)pos;
        if (g < len)                   /* (une correction du bourrage est sans effet) */
            ct[g] ^= dm;
        corrections[(*ncorr)++] = g;
    }
    return sl_aead_decrypt(profil, cle, nonce, aad, aadlen, ct, len, tag, pt);
}
