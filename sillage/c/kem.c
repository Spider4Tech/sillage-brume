/* SILLAGE C — Sillage-KEM (miroir exact de sillage/sillage_kem.py).
 *
 * Polynômes de F2[z]/(z^n − 1) en mots de 64 bits (bit i = coefficient de
 * z^i, petit-boutiste : la mémoire coïncide avec int.to_bytes(…, "little")).
 * Produit creux × dense : XOR de rotations, lues dans une copie doublée du
 * facteur dense (D = d ‖ d : rot_a(d) = D[n − a, 2n − a)).
 * h, π, le code et H(pk) sont mis en cache (une entrée par niveau et par thread).
 */
#include <math.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>
#if defined(__PCLMUL__) || defined(__AVX2__) || defined(__SSE2__)
#include <immintrin.h>
#endif
#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

#include "sillage.h"

typedef struct { uint32_t n, k, D, w, we, lam, ss, n2; double theta; } params_t;
static const params_t P[2] = {
    {50021, 128, 14, 75, 25, 128, 32, 16 * 128 * 14, 0.7},
    {170003, 256, 28, 140, 64, 256, 64, 32 * 128 * 28, 0.7},
};

#define NB(x) (((x) + 7) / 8)
#define NW(x) (((x) + 63) / 64)

static uint64_t *nouveau(size_t nbits) { return calloc(NW(nbits) + 4, 8); }

static inline uint64_t lire64(const uint64_t *v, size_t p)
{
    size_t q = p >> 6;
    int r = p & 63;
    return r ? (v[q] >> r) | (v[q + 1] << (64 - r)) : v[q];
}

static inline void masquer(uint64_t *v, size_t nbits)
{
    if (nbits & 63)
        v[nbits >> 6] &= (1ULL << (nbits & 63)) - 1;
    memset(v + NW(nbits), 0, 32);
}

static void charger(uint64_t *v, const uint8_t *b, size_t nbits)
{
    memset(v, 0, (NW(nbits) + 4) * 8);
    memcpy(v, b, NB(nbits));
}

static void ranger(uint8_t *b, const uint64_t *v, size_t nbits) { memcpy(b, v, NB(nbits)); }

/* ---------------------------------------------- produits constant-time
 * Les vecteurs secrets (x, y, r1, r2, e1, e2) sont manipulés en représentation
 * DENSE : écriture des bits par balayage masqué, produit dense par Karatsuba
 * et PCLMULQDQ. Aucun accès mémoire ni branchement ne dépend d'une position
 * secrète (une multiplication « creuse » lit la mémoire à des décalages
 * secrets, fuite exploitable par le cache). */
#ifdef __AVX2__
/* v : alloué par nouveau(), les 3 mots après nw existent et restent inchangés */
static void poser_ct(uint64_t *v, size_t nw, const uint32_t *pos, int w)
{
    for (int k = 0; k < w; k++) {
        const __m256i cible = _mm256_set1_epi64x(pos[k] >> 6), quatre = _mm256_set1_epi64x(4);
        const __m256i bit = _mm256_sllv_epi64(_mm256_set1_epi64x(1), _mm256_set1_epi64x(pos[k] & 63));
        __m256i idx = _mm256_set_epi64x(3, 2, 1, 0);
        for (size_t i = 0; i < nw; i += 4) {
            __m256i *q = (__m256i *)(v + i);
            _mm256_storeu_si256(q, _mm256_xor_si256(_mm256_loadu_si256(q),
                                                    _mm256_and_si256(_mm256_cmpeq_epi64(idx, cible), bit)));
            idx = _mm256_add_epi64(idx, quatre);
        }
    }
}
#else
static void poser_ct(uint64_t *v, size_t nw, const uint32_t *pos, int w)
{
    for (size_t i = 0; i < nw; i++) {
        uint64_t acc = 0;
        for (int k = 0; k < w; k++) {
            uint64_t d = (uint64_t)(pos[k] >> 6) ^ i;
            uint64_t m = 0 - (((d | (0 - d)) >> 63) ^ 1);     /* tout à 1 ssi mot i */
            acc |= m & (1ULL << (pos[k] & 63));
        }
        v[i] ^= acc;
    }
}
#endif

/* r (2n mots) = a · b dans F2[z], a et b de n mots */
#ifndef KARA_SEUIL                    /* en mots : produit scolaire en dessous */
#if defined(__VPCLMULQDQ__) && defined(__AVX2__)
#define KARA_SEUIL 40                 /* optimum mesuré avec VPCLMULQDQ (feuilles de 34 et 30 mots) */
#else
#define KARA_SEUIL 16
#endif
#endif
static void kara(const uint64_t *a, const uint64_t *b, size_t n, uint64_t *r, uint64_t *tmp)
{
    if (n <= KARA_SEUIL) {
#if defined(__VPCLMULQDQ__) && defined(__AVX2__)
        /* par colonnes : a_i·b_j, i + j = k, accumulés en registre ; b à l'envers
         * pour charger (a_i…a_{i+3}) et (b_j…b_{j-3}) d'un coup : 4 produits
         * par chargement, sans aller-retour mémoire (tailles publiques). */
        uint64_t rb[KARA_SEUIL + 3];
        for (size_t i = 0; i < n; i++)
            rb[n - 1 - i] = b[i];
        memset(r, 0, 16 * n);
        for (size_t k = 0; k < 2 * n - 1; k++) {
            size_t i = k < n ? 0 : k - n + 1, fin = k < n ? k : n - 1;
            __m256i acc = _mm256_setzero_si256();
            for (; i + 3 <= fin; i += 4) {
                __m256i A = _mm256_loadu_si256((const __m256i *)(a + i));
                __m256i B = _mm256_loadu_si256((const __m256i *)(rb + n - 1 - (k - i)));
                acc = _mm256_xor_si256(acc, _mm256_clmulepi64_epi128(A, B, 0x00));
                acc = _mm256_xor_si256(acc, _mm256_clmulepi64_epi128(A, B, 0x11));
            }
            __m128i s = _mm_xor_si128(_mm256_castsi256_si128(acc), _mm256_extracti128_si256(acc, 1));
            for (; i <= fin; i++)
                s = _mm_xor_si128(s, _mm_clmulepi64_si128(_mm_cvtsi64_si128((long long)a[i]),
                                                          _mm_cvtsi64_si128((long long)b[k - i]), 0));
            r[k] ^= (uint64_t)_mm_cvtsi128_si64(s);
            r[k + 1] ^= (uint64_t)_mm_extract_epi64(s, 1);
        }
#else
        memset(r, 0, 16 * n);
        for (size_t i = 0; i < n; i++)
            for (size_t j = 0; j < n; j++) {
                uint64_t lo, hi;
                sl_clmul64(a[i], b[j], &lo, &hi);
                r[i + j] ^= lo;
                r[i + j + 1] ^= hi;
            }
#endif
        return;
    }
    size_t m = (n + 1) / 2, h = n - m;
    uint64_t *sa = tmp, *sb = tmp + m, *z1 = tmp + 2 * m;
    kara(a, b, m, r, tmp + 4 * m);                       /* z0 → r[0, 2m) */
    kara(a + m, b + m, h, r + 2 * m, tmp + 4 * m);       /* z2 → r[2m, 2n) */
    for (size_t i = 0; i < h; i++) {
        sa[i] = a[i] ^ a[m + i];
        sb[i] = b[i] ^ b[m + i];
    }
    if (h < m) {                                         /* m = h + 1 : tailles publiques */
        sa[h] = a[h];
        sb[h] = b[h];
    }
    kara(sa, sb, m, z1, tmp + 4 * m);
    for (size_t i = 0; i < 2 * h; i++)
        z1[i] ^= r[i] ^ r[2 * m + i];
    for (size_t i = 2 * h; i < 2 * m; i++)
        z1[i] ^= r[i];
    for (size_t i = 0; i < 2 * m; i++)
        r[m + i] ^= z1[i];
}

/* out ^= (a · b mod z^n − 1) restreint aux `lim` premiers bits (a, b réduits) */
static void mul_ct(const uint64_t *a, const uint64_t *b, uint32_t n, uint64_t *out, size_t lim)
{
    size_t W = NW(n);
    uint64_t *F = malloc((2 * W + 4) * 8), *tmp = malloc((8 * W + 256) * 8);
    kara(a, b, W, F, tmp);
    memset(F + 2 * W, 0, 32);
    for (size_t i = 0; i < NW(lim); i++)                 /* repli z^n = 1 */
        out[i] ^= F[i] ^ lire64(F, (size_t)n + 64 * i);
    masquer(out, lim);
    sl_effacer(F, (2 * W + 4) * 8);                      /* dérivés de x ou de r1 */
    sl_effacer(tmp, (8 * W + 256) * 8);
    free(F); free(tmp);
}

/* --------------------------------------- code interne RM(1,7) (public) */
/* Bit q d'un bloc de L = 128·D bits : b ⊕ <u, Q[q]>, octet de μ = u | b << 7. Q : Fisher–Yates
 * public modulo 128. lignes[t] : le bit q vaut le bit t de Q[q] ; lignes[7] : tout à 1. */
static _Thread_local struct { uint8_t *Q; uint64_t *lignes[8]; } code_rm[2];

static void construire_code(int niveau)
{
    const params_t *p = &P[niveau];
    uint32_t L = 128 * p->D;
    if (code_rm[niveau].Q)
        return;
    uint8_t g[4] = {(uint8_t)(p->D >> 24), (uint8_t)(p->D >> 16), (uint8_t)(p->D >> 8), (uint8_t)p->D};
    uint32_t *pm = malloc(4 * (size_t)L);
    uint8_t *Q = malloc(L);
    sl_perm(g, 4, L, "SILLAGE-KEM|rm", pm);
    for (int t = 0; t < 8; t++)
        code_rm[niveau].lignes[t] = calloc(L / 64, 8);
    for (uint32_t q = 0; q < L; q++) {
        Q[q] = (uint8_t)(pm[q] % 128);
        for (int t = 0; t < 8; t++)
            code_rm[niveau].lignes[t][q >> 6] |= (uint64_t)((t < 7 ? Q[q] >> t : 1) & 1) << (q & 63);
    }
    free(pm);
    code_rm[niveau].Q = Q;
}

/* v ^= cw(μ), sans branchement sur μ */
static void poser_mot(int niveau, const uint8_t *mu, uint64_t *v)
{
    const params_t *p = &P[niveau];
    size_t Lw = 128 * p->D / 64;
    for (uint32_t j = 0; j < p->k / 8; j++)
        for (int t = 0; t < 8; t++) {
            uint64_t m = 0 - (uint64_t)(mu[j] >> t & 1);
            const uint64_t *l = code_rm[niveau].lignes[t];
            for (size_t i = 0; i < Lw; i++)
                v[j * Lw + i] ^= l[i] & m;
        }
}

/* Maximum de vraisemblance par blocs (transformée de Walsh), sans branchement ni
 * accès dépendant de nv ; à égalité, le plus petit u (comme np.argmax). */
static void decoder_mot(int niveau, const uint64_t *nv, uint8_t *mu)
{
    const params_t *p = &P[niveau];
    uint32_t L = 128 * p->D;
    const uint8_t *Q = code_rm[niveau].Q;
    for (uint32_t j = 0; j < p->k / 8; j++) {
        const uint64_t *g = nv + j * (L / 64);
        int32_t T[128] = {0};
        for (uint32_t q = 0; q < L; q++)                  /* Q public, le bit n'indexe rien */
            T[Q[q]] += (int32_t)(g[q >> 6] >> (q & 63) & 1);
        for (int i = 0; i < 128; i++)
            T[i] = (int32_t)p->D - 2 * T[i];
        for (int h = 1; h < 128; h <<= 1)
            for (int i = 0; i < 128; i += 2 * h)
                for (int k = i; k < i + h; k++) {
                    int32_t a = T[k], b = T[k + h];
                    T[k] = a + b;
                    T[k + h] = a - b;
                }
        int32_t pire = -1;
        uint32_t s = 0;
        for (uint32_t u = 0; u < 128; u++) {
            int32_t sg = T[u] >> 31, a = (T[u] ^ sg) - sg;
            uint32_t m = (uint32_t)((pire - a) >> 31);    /* tout à 1 ssi a > pire */
            pire = (pire & (int32_t)~m) | (a & (int32_t)m);
            s = (s & ~m) | ((u | (((uint32_t)sg & 1) << 7)) & m);
        }
        mu[j] = (uint8_t)s;
        sl_effacer(T, sizeof T);
    }
}

/* ------------------------------------------------------- borne δ prouvée */
/* Pour chaque hyperplan S_{u,b} et chaque translation s : c(s) = bits de v dans S + s.
 * M[u,b] = Σ_s T[c(s)], T[c] = ⌈2^F·e^{θc}⌉ (table publique, indexée par registre : vpshufb).
 * Sans branchement ni accès mémoire dépendant de v ; drapeau de sortie si c > C_MAX. */
enum { C_MAX = 15, F_TABLE = 12, NB_S = 254 };

static int comptes(const params_t *p, const uint8_t *Q, const uint64_t *v, uint64_t *M, const uint32_t *T)
{
    uint32_t n = p->n, L = 128 * p->D;
    uint8_t *V = malloc((size_t)n + L + 64);
    for (uint32_t i = 0; i < n; i++)
        V[i] = (uint8_t)(v[i >> 6] >> (i & 63) & 1);
    memcpy(V + n, V, L + 64 < n ? L + 64 : n);
    memset(M, 0, NB_S * 8);
    int plein = 0;
#ifdef __AVX2__
    alignas(32) uint8_t tb[4][32];
    for (int o = 0; o < 4; o++)
        for (int i = 0; i < 32; i++)
            tb[o][i] = (uint8_t)(T[i & 15] >> (8 * o));
    __m256i ta[4], acc[NB_S], W[128];
    for (int o = 0; o < 4; o++)
        ta[o] = _mm256_load_si256((const __m256i *)tb[o]);
    for (int i = 0; i < NB_S; i++)
        acc[i] = _mm256_setzero_si256();
    const __m256i zero = _mm256_setzero_si256(), m7f = _mm256_set1_epi8(0x7f), quinze = _mm256_set1_epi8(C_MAX);
    const __m256i trente = _mm256_set1_epi8(2 * C_MAX + 1);
    __m256i mauvais = zero;
    for (uint32_t s = 0; s < n; s += 32) {
        for (int i = 0; i < 128; i++)
            W[i] = zero;
        for (uint32_t q = 0; q < L; q++)
            W[Q[q]] = _mm256_add_epi8(W[Q[q]], _mm256_loadu_si256((const __m256i *)(V + s + q)));
        for (int h = 1; h < 128; h <<= 1)
            for (int i = 0; i < 128; i += 2 * h)
                for (int k = i; k < i + h; k++) {
                    __m256i a = W[k], b = W[k + h];
                    W[k] = _mm256_add_epi8(a, b);
                    W[k + h] = _mm256_sub_epi8(a, b);
                }
        __m256i masque = _mm256_set1_epi8((char)0xFF);     /* translations s ≥ n : hors moyenne */
        if (n - s < 32) {
            alignas(32) uint8_t mq[32] = {0};
            memset(mq, 0xFF, n - s);
            masque = _mm256_load_si256((const __m256i *)mq);
        }
        __m256i C = W[0];
        /* C ≥ 31 : une des deux moitiés dépasse C_MAX pour tout u, et W resterait sur 8 bits signés */
        mauvais = _mm256_or_si256(mauvais, _mm256_and_si256(masque, _mm256_cmpeq_epi8(_mm256_max_epu8(C, trente), C)));
        for (int u = 1; u < 128; u++)
            for (int sg = 0; sg < 2; sg++) {
                __m256i x = sg ? _mm256_sub_epi8(C, W[u]) : _mm256_add_epi8(C, W[u]);
                __m256i c = _mm256_and_si256(_mm256_srli_epi16(x, 1), m7f);
                mauvais = _mm256_or_si256(mauvais, _mm256_and_si256(masque, _mm256_cmpgt_epi8(c, quinze)));
                c = _mm256_and_si256(c, _mm256_set1_epi8(15));
                __m256i r = zero;
                /* T[c] sur 32 bits : 4 octets par somme d'écarts absolus, sous le masque */
                for (int o = 0; o < 4; o++) {
                    __m256i sad = _mm256_sad_epu8(_mm256_and_si256(_mm256_shuffle_epi8(ta[o], c), masque), zero);
                    r = _mm256_add_epi64(r, _mm256_slli_epi64(sad, 8 * o));
                }
                __m256i *a = &acc[(u - 1) + sg * 127];
                *a = _mm256_add_epi64(*a, r);
            }
    }
    for (int i = 0; i < NB_S; i++) {
        alignas(32) uint64_t x[4];
        _mm256_store_si256((__m256i *)x, acc[i]);
        M[i] = x[0] + x[1] + x[2] + x[3];
    }
    plein = _mm256_movemask_epi8(mauvais);
    sl_effacer(acc, sizeof acc); sl_effacer(W, sizeof W);
#elif defined(__ARM_NEON)
    /* même calcul que la version AVX2, 16 translations à la fois */
    uint8_t tb[4][16];
    for (int o = 0; o < 4; o++)
        for (int i = 0; i < 16; i++)
            tb[o][i] = (uint8_t)(T[i] >> (8 * o));
    uint8x16_t ta[4], W[128];
    for (int o = 0; o < 4; o++)
        ta[o] = vld1q_u8(tb[o]);
    const uint8x16_t quinze = vdupq_n_u8(C_MAX), trente = vdupq_n_u8(2 * C_MAX + 1), m15 = vdupq_n_u8(15);
    uint8x16_t mauvais = vdupq_n_u8(0);
    for (uint32_t s = 0; s < n; s += 16) {
        for (int i = 0; i < 128; i++)
            W[i] = vdupq_n_u8(0);
        for (uint32_t q = 0; q < L; q++)
            W[Q[q]] = vaddq_u8(W[Q[q]], vld1q_u8(V + s + q));
        for (int h = 1; h < 128; h <<= 1)
            for (int i = 0; i < 128; i += 2 * h)
                for (int k = i; k < i + h; k++) {
                    uint8x16_t a = W[k], b = W[k + h];
                    W[k] = vaddq_u8(a, b);
                    W[k + h] = vsubq_u8(a, b);
                }
        uint8_t mq[16] = {0};                              /* translations s ≥ n : hors moyenne */
        memset(mq, 0xFF, n - s < 16 ? n - s : 16);
        const uint8x16_t masque = vld1q_u8(mq), C = W[0];
        mauvais = vorrq_u8(mauvais, vandq_u8(masque, vcgeq_u8(C, trente)));
        for (int u = 1; u < 128; u++)
            for (int sg = 0; sg < 2; sg++) {
                uint8x16_t c = vshrq_n_u8(sg ? vsubq_u8(C, W[u]) : vaddq_u8(C, W[u]), 1);
                mauvais = vorrq_u8(mauvais, vandq_u8(masque, vcgtq_u8(c, quinze)));
                c = vandq_u8(c, m15);
                uint64_t r = 0;
                for (int o = 0; o < 4; o++)
                    r += (uint64_t)vaddlvq_u8(vandq_u8(vqtbl1q_u8(ta[o], c), masque)) << (8 * o);
                M[(u - 1) + sg * 127] += r;
            }
    }
    plein = vmaxvq_u8(mauvais);
    sl_effacer(W, sizeof W);
#else
    int32_t W[128];
    uint32_t mauvais = 0;
    for (uint32_t s = 0; s < n; s++) {
        memset(W, 0, sizeof W);
        for (uint32_t q = 0; q < L; q++)
            W[Q[q]] += V[s + q];
        for (int h = 1; h < 128; h <<= 1)
            for (int i = 0; i < 128; i += 2 * h)
                for (int k = i; k < i + h; k++) {
                    int32_t a = W[k], b = W[k + h];
                    W[k] = a + b;
                    W[k + h] = a - b;
                }
        for (int u = 1; u < 128; u++)
            for (int sg = 0; sg < 2; sg++) {
                uint32_t c = (uint32_t)(sg ? W[0] - W[u] : W[0] + W[u]) / 2;
                mauvais |= (uint32_t)((int32_t)(C_MAX - c) >> 31);
                uint64_t r = 0;
                for (uint32_t x = 0; x <= C_MAX; x++) {
                    uint32_t d = x ^ c;
                    r |= T[x] & (0 - (uint64_t)(((d | (0 - d)) >> 31) ^ 1));
                }
                M[(u - 1) + sg * 127] += r;
            }
    }
    plein = (int)mauvais;
    sl_effacer(W, sizeof W);
#endif
    sl_effacer(V, (size_t)n + L + 64);
    free(V);
    SL_PUBLIC(&plein, sizeof plein);
    return plein != 0;
}

/* log2 de la borne, 0 si c dépasse C_MAX. Seul le pire produit M_x·M_y est rendu public ; le
 * parcours reste sans branchement (maxsd), libm ne voit que ce résultat. */
static double borne(int niveau, const uint64_t *x, const uint64_t *y)
{
    const params_t *p = &P[niveau];
    construire_code(niveau);
    uint32_t T[C_MAX + 1];
    for (int c = 0; c <= C_MAX; c++)
        T[c] = (uint32_t)ceil(ldexp(exp(p->theta * c), F_TABLE));
    uint64_t Mx[NB_S], My[NB_S];
    int bx = comptes(p, code_rm[niveau].Q, x, Mx, T), by = comptes(p, code_rm[niveau].Q, y, My, T);
    if (bx || by)
        return 0;
    double d = (double)p->n * (1 << F_TABLE), pire = 0;
    for (int i = 0; i < NB_S; i++)
#ifdef __SSE2__
        pire = _mm_cvtsd_f64(_mm_max_sd(_mm_set_sd(pire), _mm_set_sd((double)(int64_t)Mx[i] / d * ((double)(int64_t)My[i] / d))));
#else
    {
        double m = (double)(int64_t)Mx[i] / d * ((double)(int64_t)My[i] / d);
        pire = m > pire ? m : pire;
    }
#endif
    sl_effacer(Mx, sizeof Mx); sl_effacer(My, sizeof My);
    SL_PUBLIC(&pire, sizeof pire);
    double S = 64.0 * p->D, th = p->theta;
    double f = -th * S / 2 + p->w * log(pire) + 2.0 * p->we * log1p(S / p->n2 * expm1(th));
    double r = (f + log(254.0 * (p->k / 8))) / log(2.0);
    return r < 0 ? r : 0;
}

double sl_kem_borne(int niveau, const uint8_t *xb, const uint8_t *yb)
{
    const params_t *p = &P[niveau];
    uint64_t *x = nouveau(p->n), *y = nouveau(p->n);
    charger(x, xb, p->n);
    charger(y, yb, p->n);
    double b = borne(niveau, x, y);
    free(x); free(y);
    return b;
}

/* --------------------------------------------------- dérivés de σ_h (cache) */
static _Thread_local struct { uint8_t sigma[32], pkh[32], *pk; uint64_t *h; uint32_t *pi; int pk_ok; } cache[2];

static void derives(int niveau, const uint8_t sigma[32], const uint64_t **h, const uint32_t **pi)
{
    const params_t *p = &P[niveau];
    if (!cache[niveau].h || memcmp(cache[niveau].sigma, sigma, 32)) {
        if (!cache[niveau].h) {
            cache[niveau].h = nouveau(p->n);
            cache[niveau].pi = malloc(sizeof(uint32_t) * (p->n2 / 8));
            cache[niveau].pk = malloc(32 + NB(p->n));
        }
        uint8_t *raw = malloc(NB(p->n));
        const uint8_t *parts[1] = {sigma};
        size_t lens[1] = {32};
        sl_shake_dom("SILLAGE-KEM|h", NULL, 0, parts, lens, 1, raw, NB(p->n));
        charger(cache[niveau].h, raw, p->n);
        masquer(cache[niveau].h, p->n);
        free(raw);
        sl_perm(sigma, 32, p->n2 / 8, "SILLAGE-KEM|pi", cache[niveau].pi);
        memcpy(cache[niveau].sigma, sigma, 32);
    }
    *h = cache[niveau].h;
    *pi = cache[niveau].pi;
}

void sl_kem_tailles(int niveau, size_t *pk, size_t *sk, size_t *ct, size_t *ss)
{
    const params_t *p = &P[niveau];
    *pk = NB(p->n) + 32;
    *sk = 3 * NB(p->n) + 64;
    *ct = NB(p->n) + NB(p->n2);
    *ss = p->ss;
}

static void hacher_pk(const params_t *p, const uint8_t *pk, uint8_t *pkh)
{
    const uint8_t *parts[1] = {pk};
    size_t lens[1] = {32 + NB(p->n)};
    sl_shake_dom("SILLAGE-KEM|pkh", NULL, 0, parts, lens, 1, pkh, 32);
}

/* _encrypt déterministe : u, v à partir de (pk, H(pk), μ) */
static void chiffrer(int niveau, const uint8_t *pk, const uint8_t *pkh, const uint8_t *mu, uint64_t *u, uint64_t *v)
{
    const params_t *p = &P[niveau];
    const uint8_t *sigma = pk;
    const uint64_t *h;
    const uint32_t *pi;
    derives(niveau, sigma, &h, &pi);
    uint8_t coins[32];
    {
        const uint8_t *parts[2] = {mu, pkh};
        size_t lens[2] = {p->k / 8, 32};
        sl_shake_dom("SILLAGE-KEM|coins", NULL, 0, parts, lens, 2, coins, 32);
    }
    uint32_t *r1 = malloc(4 * p->w), *r2 = malloc(4 * p->w), *e = malloc(4 * p->we);
    sl_creux(coins, 32, (int)p->w, p->n, "SILLAGE-KEM|r1", r1);
    sl_creux(coins, 32, (int)p->w, p->n, "SILLAGE-KEM|r2", r2);
    uint64_t *s = nouveau(p->n), *r1d = nouveau(p->n), *e2d = nouveau(p->n2);
    charger(s, pk + 32, p->n);
    poser_ct(r1d, NW(p->n), r1, (int)p->w);
    memset(u, 0, (NW(p->n) + 4) * 8);
    mul_ct(r1d, h, p->n, u, p->n);
    poser_ct(u, NW(p->n), r2, (int)p->w);
    memset(v, 0, (NW(p->n2) + 4) * 8);
    mul_ct(r1d, s, p->n, v, p->n2);
    construire_code(niveau);
    poser_mot(niveau, mu, v);
    sl_creux(coins, 32, (int)p->we, p->n2, "SILLAGE-KEM|e1", e);   /* cascade */
    poser_ct(v, NW(p->n2), e, (int)p->we);
    sl_creux(coins, 32, (int)p->we, p->n2, "SILLAGE-KEM|e2", e);
    poser_ct(e2d, NW(p->n2), e, (int)p->we);
    const uint8_t *e2 = (const uint8_t *)e2d;            /* π public : lecture de tous les octets */
    uint8_t *vb = (uint8_t *)v;
    for (uint32_t i = 0; i < p->n2 / 8; i++)            /* octet i ← octet π[i] */
        vb[i] ^= e2[pi[i]];
    sl_effacer(coins, 32);
    sl_effacer(r1, 4 * p->w); sl_effacer(r2, 4 * p->w); sl_effacer(e, 4 * p->we);
    sl_effacer(r1d, NW(p->n) * 8); sl_effacer(e2d, NW(p->n2) * 8);
    free(e2d); free(r1d); free(s); free(r1); free(r2); free(e);
}

static void secret(int niveau, const uint8_t *mu, const uint8_t *ct, uint8_t *ss)
{
    const params_t *p = &P[niveau];
    const uint8_t *parts[2] = {mu, ct};
    size_t lens[2] = {p->k / 8, NB(p->n) + NB(p->n2)};
    sl_shake_dom("SILLAGE-KEM|ss", NULL, 0, parts, lens, 2, ss, p->ss);
}

int sl_kem_encaps_det(int niveau, const uint8_t *pk, const uint8_t *mu, uint8_t *ct, uint8_t *ss)
{
    const params_t *p = &P[niveau];
    uint64_t *u = nouveau(p->n), *v = nouveau(p->n2);
    size_t lpk = 32 + NB(p->n);
    const uint64_t *h;
    const uint32_t *pi;
    derives(niveau, pk, &h, &pi);                        /* alloue le cache */
    /* H(pk) mis en cache côté encapsulation seulement (pk est public) : la décapsulation
     * le recalcule toujours, pour un temps qui ne varie pas d'une clé à l'autre. */
    if (!cache[niveau].pk_ok || memcmp(cache[niveau].pk, pk, lpk)) {
        hacher_pk(p, pk, cache[niveau].pkh);
        memcpy(cache[niveau].pk, pk, lpk);
        cache[niveau].pk_ok = 1;
    }
    chiffrer(niveau, pk, cache[niveau].pkh, mu, u, v);
    ranger(ct, u, p->n);
    ranger(ct + NB(p->n), v, p->n2);
    secret(niveau, mu, ct, ss);
    free(u); free(v);
    return 0;
}

int sl_kem_encaps(int niveau, const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    uint8_t mu[32];
    if (sl_alea(mu, P[niveau].k / 8))
        return -3;
    return sl_kem_encaps_det(niveau, pk, mu, ct, ss);
}

int sl_kem_keygen(int niveau, uint8_t *pk, uint8_t *sk)
{
    const params_t *p = &P[niveau];
    uint8_t sigma_h[32], sigma_rej[32], graine[32];
    if (sl_alea(sigma_h, 32) || sl_alea(sigma_rej, 32))
        return -3;
    uint64_t *x = nouveau(p->n), *y = nouveau(p->n), *s = nouveau(p->n);
    uint32_t *px = malloc(4 * p->w), *py = malloc(4 * p->w);
    do {                         /* validation : δ PROUVÉ ≤ 2^-λ (FO) */
        memset(x, 0, (NW(p->n) + 4) * 8);
        memset(y, 0, (NW(p->n) + 4) * 8);
        if (sl_alea(graine, 32)) {
            free(x); free(y); free(s); free(px); free(py);
            return -3;
        }
        sl_creux(graine, 32, (int)p->w, p->n, "eph", px);
        if (sl_alea(graine, 32)) {
            sl_effacer(px, 4 * p->w);
            free(x); free(y); free(s); free(px); free(py);
            return -3;
        }
        sl_creux(graine, 32, (int)p->w, p->n, "eph", py);
        poser_ct(x, NW(p->n), px, (int)p->w);
        poser_ct(y, NW(p->n), py, (int)p->w);
    } while (borne(niveau, x, y) > -(double)p->lam);
    const uint64_t *h;
    const uint32_t *pi;
    derives(niveau, sigma_h, &h, &pi);
    mul_ct(x, h, p->n, s, p->n);
    poser_ct(s, NW(p->n), py, (int)p->w);
    size_t nb = NB(p->n);
    memcpy(pk, sigma_h, 32);
    ranger(pk + 32, s, p->n);
    ranger(sk, x, p->n);
    ranger(sk + nb, y, p->n);
    memcpy(sk + 2 * nb, sigma_h, 32);
    memcpy(sk + 2 * nb + 32, sigma_rej, 32);
    ranger(sk + 2 * nb + 64, s, p->n);
    sl_effacer(graine, 32); sl_effacer(px, 4 * p->w); sl_effacer(py, 4 * p->w);
    sl_effacer(x, NW(p->n) * 8); sl_effacer(y, NW(p->n) * 8);
    free(x); free(y); free(s); free(px); free(py);
    return 0;
}

int sl_kem_decaps(int niveau, const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    const params_t *p = &P[niveau];
    size_t nb = NB(p->n), nb2 = NB(p->n2), ctlen = nb + nb2;
    uint64_t *x = nouveau(p->n), *u = nouveau(p->n), *v = nouveau(p->n2), *nv = nouveau(p->n2);
    uint8_t *ctc = malloc(ctlen), *ct2 = malloc(ctlen), mu[32] = {0};
    charger(x, sk, p->n);
    charger(u, ct, p->n);
    charger(v, ct + nb, p->n2);
    int ok = 1;
    if ((p->n & 7) && (ct[nb - 1] >> (p->n & 7)))     /* encodage non canonique */
        ok = 0;
    if ((p->n2 & 7) && (ct[ctlen - 1] >> (p->n2 & 7)))
        ok = 0;
    masquer(u, p->n);
    masquer(v, p->n2);
    ranger(ctc, u, p->n);
    ranger(ctc + nb, v, p->n2);
    memcpy(nv, v, (NW(p->n2) + 4) * 8);
    mul_ct(x, u, p->n, nv, p->n2);                      /* x dense : constant-time */
    construire_code(niveau);
    decoder_mot(niveau, nv, mu);
    /* Ré-encapsulation FO TOUJOURS calculée (même après un échec de
     * décodage : sinon l'échec serait visible au temps de réponse, oracle
     * des attaques par réaction) ; les deux secrets sont calculés et l'un
     * est choisi par masque. */
    uint8_t *pkb = malloc(32 + nb), ss_ok[64], ss_rej[64];
    memcpy(pkb, sk + 2 * nb, 32);
    memcpy(pkb + 32, sk + 2 * nb + 64, nb);
    {
        uint64_t *u2 = nouveau(p->n), *v2 = nouveau(p->n2);
        uint8_t pkh[32];
        hacher_pk(p, pkb, pkh);
        chiffrer(niveau, pkb, pkh, mu, u2, v2);
        ranger(ct2, u2, p->n);
        ranger(ct2 + nb, v2, p->n2);
        sl_effacer(u2, NW(p->n) * 8); sl_effacer(v2, NW(p->n2) * 8);
        free(u2); free(v2);
    }
    free(pkb);
    uint8_t d = 0;
    for (size_t i = 0; i < ctlen; i++)
        d |= ct2[i] ^ ctc[i];
    uint32_t dd = d;
    ok &= (int)(1 - ((dd | (0u - dd)) >> 31));
    secret(niveau, mu, ctc, ss_ok);
    {
        const uint8_t *parts[2] = {sk + 2 * nb + 32, ctc};
        size_t lens[2] = {32, ctlen};
        sl_shake_dom("SILLAGE-KEM|rej", NULL, 0, parts, lens, 2, ss_rej, p->ss);
    }
    uint8_t m = (uint8_t)(0 - (uint8_t)ok);
    for (uint32_t i = 0; i < p->ss; i++)
        ss[i] = (uint8_t)((ss_ok[i] & m) | (ss_rej[i] & ~m));
    sl_effacer(x, NW(p->n) * 8); sl_effacer(nv, NW(p->n2) * 8); sl_effacer(ct2, ctlen);
    sl_effacer(mu, sizeof mu); sl_effacer(ss_ok, sizeof ss_ok); sl_effacer(ss_rej, sizeof ss_rej);
    free(x); free(u); free(v); free(nv); free(ctc); free(ct2);
    return 0;
}
