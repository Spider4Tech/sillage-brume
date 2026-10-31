/* SILLAGE C — briques communes : Keccak-f[1600] / SHAKE256, flux
 * d'entiers dérivés de SHAKE, tirages creux et permutations (miroir exact
 * de sillage/sillage_common.py), aléa système. */
#include <math.h>
#include <stdlib.h>
#include <string.h>
#ifdef __AVX2__
#include <immintrin.h>
#endif
#include <sys/random.h>

#include "sillage.h"

static const uint64_t KRC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

#define ROL(x, k) (((x) << (k)) | ((x) >> (64 - (k))))

/* Keccak-f[1600] déroulé (généré : θ, ρ∘π à indices et rotations fixes, χ, ι). */
static void keccakf(uint64_t s[25])
{
    uint64_t C0, C1, C2, C3, C4, D0, D1, D2, D3, D4, B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24;
    for (int r = 0; r < 24; r++) {
        C0 = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
        C1 = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
        C2 = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
        C3 = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
        C4 = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];
        D0 = C4 ^ ROL(C1, 1);
        D1 = C0 ^ ROL(C2, 1);
        D2 = C1 ^ ROL(C3, 1);
        D3 = C2 ^ ROL(C4, 1);
        D4 = C3 ^ ROL(C0, 1);
        B0 = (s[0] ^ D0);
        B16 = ROL(s[5] ^ D0, 36);
        B7 = ROL(s[10] ^ D0, 3);
        B23 = ROL(s[15] ^ D0, 41);
        B14 = ROL(s[20] ^ D0, 18);
        B10 = ROL(s[1] ^ D1, 1);
        B1 = ROL(s[6] ^ D1, 44);
        B17 = ROL(s[11] ^ D1, 10);
        B8 = ROL(s[16] ^ D1, 45);
        B24 = ROL(s[21] ^ D1, 2);
        B20 = ROL(s[2] ^ D2, 62);
        B11 = ROL(s[7] ^ D2, 6);
        B2 = ROL(s[12] ^ D2, 43);
        B18 = ROL(s[17] ^ D2, 15);
        B9 = ROL(s[22] ^ D2, 61);
        B5 = ROL(s[3] ^ D3, 28);
        B21 = ROL(s[8] ^ D3, 55);
        B12 = ROL(s[13] ^ D3, 25);
        B3 = ROL(s[18] ^ D3, 21);
        B19 = ROL(s[23] ^ D3, 56);
        B15 = ROL(s[4] ^ D4, 27);
        B6 = ROL(s[9] ^ D4, 20);
        B22 = ROL(s[14] ^ D4, 39);
        B13 = ROL(s[19] ^ D4, 8);
        B4 = ROL(s[24] ^ D4, 14);
        s[0] = B0 ^ (~B1 & B2);
        s[1] = B1 ^ (~B2 & B3);
        s[2] = B2 ^ (~B3 & B4);
        s[3] = B3 ^ (~B4 & B0);
        s[4] = B4 ^ (~B0 & B1);
        s[5] = B5 ^ (~B6 & B7);
        s[6] = B6 ^ (~B7 & B8);
        s[7] = B7 ^ (~B8 & B9);
        s[8] = B8 ^ (~B9 & B5);
        s[9] = B9 ^ (~B5 & B6);
        s[10] = B10 ^ (~B11 & B12);
        s[11] = B11 ^ (~B12 & B13);
        s[12] = B12 ^ (~B13 & B14);
        s[13] = B13 ^ (~B14 & B10);
        s[14] = B14 ^ (~B10 & B11);
        s[15] = B15 ^ (~B16 & B17);
        s[16] = B16 ^ (~B17 & B18);
        s[17] = B17 ^ (~B18 & B19);
        s[18] = B18 ^ (~B19 & B15);
        s[19] = B19 ^ (~B15 & B16);
        s[20] = B20 ^ (~B21 & B22);
        s[21] = B21 ^ (~B22 & B23);
        s[22] = B22 ^ (~B23 & B24);
        s[23] = B23 ^ (~B24 & B20);
        s[24] = B24 ^ (~B20 & B21);
        s[0] ^= KRC[r];
    }
}

/* Keccak-f[1600] sur 4 états à la fois (vecteurs gcc de 4 × 64 bits, AVX2) :
 * même corps que keccakf, mêmes résultats état par état. Sert au flux
 * d'entiers (sl_flux_next), dont les blocs successifs sont indépendants. */
typedef uint64_t v4 __attribute__((vector_size(32)));
static void keccakf4(v4 s[25])
{
    v4 C0, C1, C2, C3, C4, D0, D1, D2, D3, D4, B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24;
    for (int r = 0; r < 24; r++) {
        C0 = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
        C1 = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
        C2 = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
        C3 = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
        C4 = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];
        D0 = C4 ^ ROL(C1, 1);
        D1 = C0 ^ ROL(C2, 1);
        D2 = C1 ^ ROL(C3, 1);
        D3 = C2 ^ ROL(C4, 1);
        D4 = C3 ^ ROL(C0, 1);
        B0 = (s[0] ^ D0);
        B16 = ROL(s[5] ^ D0, 36);
        B7 = ROL(s[10] ^ D0, 3);
        B23 = ROL(s[15] ^ D0, 41);
        B14 = ROL(s[20] ^ D0, 18);
        B10 = ROL(s[1] ^ D1, 1);
        B1 = ROL(s[6] ^ D1, 44);
        B17 = ROL(s[11] ^ D1, 10);
        B8 = ROL(s[16] ^ D1, 45);
        B24 = ROL(s[21] ^ D1, 2);
        B20 = ROL(s[2] ^ D2, 62);
        B11 = ROL(s[7] ^ D2, 6);
        B2 = ROL(s[12] ^ D2, 43);
        B18 = ROL(s[17] ^ D2, 15);
        B9 = ROL(s[22] ^ D2, 61);
        B5 = ROL(s[3] ^ D3, 28);
        B21 = ROL(s[8] ^ D3, 55);
        B12 = ROL(s[13] ^ D3, 25);
        B3 = ROL(s[18] ^ D3, 21);
        B19 = ROL(s[23] ^ D3, 56);
        B15 = ROL(s[4] ^ D4, 27);
        B6 = ROL(s[9] ^ D4, 20);
        B22 = ROL(s[14] ^ D4, 39);
        B13 = ROL(s[19] ^ D4, 8);
        B4 = ROL(s[24] ^ D4, 14);
        s[0] = B0 ^ (~B1 & B2);
        s[1] = B1 ^ (~B2 & B3);
        s[2] = B2 ^ (~B3 & B4);
        s[3] = B3 ^ (~B4 & B0);
        s[4] = B4 ^ (~B0 & B1);
        s[5] = B5 ^ (~B6 & B7);
        s[6] = B6 ^ (~B7 & B8);
        s[7] = B7 ^ (~B8 & B9);
        s[8] = B8 ^ (~B9 & B5);
        s[9] = B9 ^ (~B5 & B6);
        s[10] = B10 ^ (~B11 & B12);
        s[11] = B11 ^ (~B12 & B13);
        s[12] = B12 ^ (~B13 & B14);
        s[13] = B13 ^ (~B14 & B10);
        s[14] = B14 ^ (~B10 & B11);
        s[15] = B15 ^ (~B16 & B17);
        s[16] = B16 ^ (~B17 & B18);
        s[17] = B17 ^ (~B18 & B19);
        s[18] = B18 ^ (~B19 & B15);
        s[19] = B19 ^ (~B15 & B16);
        s[20] = B20 ^ (~B21 & B22);
        s[21] = B21 ^ (~B22 & B23);
        s[22] = B22 ^ (~B23 & B24);
        s[23] = B23 ^ (~B24 & B20);
        s[24] = B24 ^ (~B20 & B21);
        s[0] ^= (v4){KRC[r], KRC[r], KRC[r], KRC[r]};
    }
}

#define TAUX 136   /* SHAKE256 */

void sl_shake_init(sl_shake_t *h) { memset(h, 0, sizeof *h); }

void sl_shake_absorb(sl_shake_t *h, const void *d, size_t len)
{
    const uint8_t *p = d;
    uint8_t *st = (uint8_t *)h->s;
    while (len) {
        size_t k = TAUX - h->pos < len ? TAUX - h->pos : len;
        for (size_t i = 0; i < k; i++)
            st[h->pos + i] ^= p[i];
        h->pos += k; p += k; len -= k;
        if (h->pos == TAUX) {
            keccakf(h->s);
            h->pos = 0;
        }
    }
}

void sl_shake_final(sl_shake_t *h)
{
    uint8_t *st = (uint8_t *)h->s;
    st[h->pos] ^= 0x1F;
    st[TAUX - 1] ^= 0x80;
    keccakf(h->s);
    h->pos = 0;
}

void sl_shake_squeeze(sl_shake_t *h, void *out, size_t len)
{
    uint8_t *o = out, *st = (uint8_t *)h->s;
    while (len) {
        if (h->pos == TAUX) {
            keccakf(h->s);
            h->pos = 0;
        }
        size_t k = TAUX - h->pos < len ? TAUX - h->pos : len;
        memcpy(o, st + h->pos, k);
        h->pos += k; o += k; len -= k;
    }
}

void sl_shake_dom(const char *dom, const uint8_t *dom2, size_t dom2len,
                  const uint8_t *const *parts, const size_t *lens, int nparts,
                  uint8_t *out, size_t outlen)
{
    sl_shake_t h;
    sl_shake_init(&h);
    sl_shake_absorb(&h, dom, strlen(dom));
    if (dom2len)
        sl_shake_absorb(&h, dom2, dom2len);
    sl_shake_absorb(&h, "|", 1);
    for (int i = 0; i < nparts; i++)
        sl_shake_absorb(&h, parts[i], lens[i]);
    sl_shake_final(&h);
    sl_shake_squeeze(&h, out, outlen);
}

/* _shake_int_stream : bloc c = SHAKE256(dom ‖ "|bits|" ‖ seed ‖ "|" ‖ c_be64), 64 o */
void sl_flux_init(sl_flux_t *f, const char *dom, const uint8_t *seed, size_t seedlen)
{
    strncpy(f->dom, dom, sizeof f->dom - 1);
    f->dom[sizeof f->dom - 1] = 0;
    memcpy(f->seed, seed, seedlen);
    f->seedlen = seedlen;
    f->ctr = 0;
    f->pos = (int)sizeof f->buf;
}

/* Blocs ctr … ctr+3 calculés ensemble quand le message tient dans un seul bloc
 * d'absorption (toujours le cas ici : domaine ≤ 63, graine ≤ 64 octets ne
 * dépassent 135 octets que dans des cas que l'on traite bloc par bloc). */
static void flux_blocs(sl_flux_t *f)
{
    size_t ld = strlen(f->dom), L = ld + 6 + f->seedlen + 1 + 8;
    if (L > TAUX - 1) {
        for (int j = 0; j < 4; j++) {
            uint8_t c[8];
            for (int i = 0; i < 8; i++)
                c[i] = (uint8_t)((f->ctr + j) >> (56 - 8 * i));
            sl_shake_t h;
            sl_shake_init(&h);
            sl_shake_absorb(&h, f->dom, ld);
            sl_shake_absorb(&h, "|bits|", 6);
            sl_shake_absorb(&h, f->seed, f->seedlen);
            sl_shake_absorb(&h, "|", 1);
            sl_shake_absorb(&h, c, 8);
            sl_shake_final(&h);
            sl_shake_squeeze(&h, f->buf + 64 * j, 64);
        }
    } else {
        uint8_t m[TAUX] = {0};
        memcpy(m, f->dom, ld);
        memcpy(m + ld, "|bits|", 6);
        memcpy(m + ld + 6, f->seed, f->seedlen);
        m[ld + 6 + f->seedlen] = '|';
        m[L] ^= 0x1F;
        m[TAUX - 1] ^= 0x80;
        v4 st[25] = {0};
        for (int j = 0; j < 4; j++) {
            uint8_t mj[TAUX];
            memcpy(mj, m, TAUX);
            for (int i = 0; i < 8; i++)
                mj[L - 8 + i] = (uint8_t)((f->ctr + j) >> (56 - 8 * i));
            for (int w = 0; w < TAUX / 8; w++) {
                uint64_t x;
                memcpy(&x, mj + 8 * w, 8);
                st[w][j] = x;
            }
        }
        keccakf4(st);
        for (int j = 0; j < 4; j++)
            for (int w = 0; w < 8; w++) {
                uint64_t x = st[w][j];
                memcpy(f->buf + 64 * j + 8 * w, &x, 8);
            }
    }
    f->ctr += 4;
    f->pos = 0;
}

static inline uint32_t flux_suivant(sl_flux_t *f)
{
    if (f->pos == (int)sizeof f->buf)
        flux_blocs(f);
    uint32_t x;
    memcpy(&x, f->buf + f->pos, 4);
    f->pos += 4;
    return __builtin_bswap32(x);
}

uint32_t sl_flux_next(sl_flux_t *f) { return flux_suivant(f); }

/* sparse_from_seed : positions distinctes, dans l'ordre de tirage.
 *
 * Temps INDÉPENDANT de la graine : la version naïve (rejet jusqu'à `poids`
 * acceptations) a un temps qui dépend du nombre de rejets, donc de la graine
 * — en décapsulation, la graine dérive du μ déchiffré : c'est la fuite
 * exploitée par « Don't Reject This » (Guo et al., CHES 2022) contre HQC et
 * BIKE. Ici on consomme TOUJOURS M mots, avec P[Bin(M, p) < poids] < 2^-128
 * (borne de Chernoff, p = (n − poids)/span minore le taux d'acceptation),
 * et l'acceptation, le test de doublon et l'écriture sont sans branchement, ni
 * accès mémoire dépendant du nombre de rejets (contrôle : Valgrind).
 * Même ordre d'acceptation que la version naïve → mêmes positions. Le
 * complément (probabilité < 2^-128) reprend la version naïve. */
void sl_creux(const uint8_t *seed, size_t seedlen, int poids, uint32_t n, const char *dom, uint32_t *pos)
{
    sl_flux_t f;
    sl_flux_init(&f, dom, seed, seedlen);
    uint32_t span = 1;
    while (span < n)
        span <<= 1;
    double p = (double)(n - (uint32_t)poids) / span, l = 128 * 0.6931471805599453;
    double mu = poids + l + sqrt((poids + l) * (poids + l) - (double)poids * poids);
    long M = (long)ceil(mu / p);
    uint32_t tmp[1024 + 1];
    int k = 0;
    memset(tmp, 0, sizeof tmp);
    if (poids > 1024)
        M = 0;                                  /* (hors des paramètres SILLAGE) */
    for (long t = 0; t < M; t++) {
        uint32_t r = flux_suivant(&f) & (span - 1);
        uint32_t ok = (uint32_t)((int32_t)(r - n) >> 31) & 1;        /* r < n */
        uint32_t vu = 0;
        __asm__ volatile("" : "+r"(k));           /* gcc découperait sinon la boucle sur j < k */
        for (int j = 0; j < poids; j++) {                             /* parcours complet */
            uint32_t ici = -(((uint32_t)(j ^ k) - 1) >> 31);          /* j = k : k dépend des rejets */
            vu |= (uint32_t)(tmp[j] == r) & (uint32_t)((j - k) >> 31 & 1);   /* j < k */
            tmp[j] = (tmp[j] & ~ici) | (r & ici);                     /* écrit toujours en k, avance si accepté */
        }
        ok &= (vu ^ 1) & (uint32_t)((k - poids) >> 31 & 1);          /* non vu, k < poids */
        k += (int)ok;
    }
    SL_PUBLIC(&k, sizeof k);                      /* k = poids, sauf avec probabilité < 2^-128 */
    memcpy(pos, tmp, (size_t)(k < poids ? k : poids) * sizeof *pos);
    while (k < poids) {
        uint32_t r = sl_flux_next(&f) & (span - 1);
        uint32_t vu = 0;
        for (int j = 0; j < k; j++)
            vu |= pos[j] == r;
        if (r < n && !vu)
            pos[k++] = r;
    }
}

/* Tirage des échanges de Fisher–Yates : r[i] ∈ [0, i] pour i = m−1 … 1, masque
 * = plus petite puissance de 2 ≥ i + 1. Rejet sans branchement : on écrit
 * toujours, on ne recule que si la valeur est acceptée. Le temps ne dépend que
 * du nombre de rejets, qui ne porte que sur les valeurs rejetées. */
void sl_echanges(const uint8_t *seed, size_t seedlen, uint32_t m, const char *dom, uint32_t *r)
{
    sl_flux_t f;
    sl_flux_init(&f, dom, seed, seedlen);
    for (uint32_t i = m - 1; i > 0;) {
        uint32_t x = flux_suivant(&f) & ((2u << (31 - __builtin_clz(i))) - 1);
        r[i] = x;
        i -= x <= i;
    }
    sl_effacer(&f, sizeof f);
}

/* perm_from_seed : Fisher–Yates déterministe (π est public ici) */
void sl_perm(const uint8_t *seed, size_t seedlen, uint32_t m, const char *dom, uint32_t *perm)
{
    uint32_t *r = malloc(4 * (size_t)m);
    sl_echanges(seed, seedlen, m, dom, r);
    for (uint32_t i = 0; i < m; i++)
        perm[i] = i;
    for (uint32_t i = m - 1; i > 0; i--) {
        uint32_t t = perm[i]; perm[i] = perm[r[i]]; perm[r[i]] = t;
    }
    free(r);
}

/* 4 SHAKE256 parallèles, entrées de même longueur tenant dans un bloc d'absorption
 * (len < TAUX) : mêmes sorties que 4 appels successifs. */
void sl_shake4(const uint8_t *const m[4], size_t len, uint8_t *const out[4], size_t outlen)
{
    v4 st[25] = {0};
    size_t nw = len / 8 + 1;                     /* seuls ces mots du bloc portent le message et son 0x1F */
    for (int j = 0; j < 4; j++) {
        uint8_t b[TAUX] = {0};
        memcpy(b, m[j], len);
        b[len] ^= 0x1F;
        for (size_t w = 0; w < nw; w++) {
            uint64_t x;
            memcpy(&x, b + 8 * w, 8);
            st[w][j] = x;
        }
        st[TAUX / 8 - 1][j] ^= 0x8000000000000000ULL;
    }
    for (size_t fait = 0; fait < outlen; fait += TAUX) {
        keccakf4(st);
        size_t k = outlen - fait < TAUX ? outlen - fait : TAUX, w = 0;
#ifdef __AVX2__
        for (; 8 * w + 32 <= k; w += 4) {        /* transposition 4 × 4 des mots */
            __m256i a0 = _mm256_unpacklo_epi64((__m256i)st[w], (__m256i)st[w + 1]);
            __m256i a1 = _mm256_unpackhi_epi64((__m256i)st[w], (__m256i)st[w + 1]);
            __m256i a2 = _mm256_unpacklo_epi64((__m256i)st[w + 2], (__m256i)st[w + 3]);
            __m256i a3 = _mm256_unpackhi_epi64((__m256i)st[w + 2], (__m256i)st[w + 3]);
            _mm256_storeu_si256((__m256i *)(out[0] + fait + 8 * w), _mm256_permute2x128_si256(a0, a2, 0x20));
            _mm256_storeu_si256((__m256i *)(out[1] + fait + 8 * w), _mm256_permute2x128_si256(a1, a3, 0x20));
            _mm256_storeu_si256((__m256i *)(out[2] + fait + 8 * w), _mm256_permute2x128_si256(a0, a2, 0x31));
            _mm256_storeu_si256((__m256i *)(out[3] + fait + 8 * w), _mm256_permute2x128_si256(a1, a3, 0x31));
        }
#endif
        for (int j = 0; j < 4; j++)
            for (size_t q = w; q * 8 < k; q++) {
                uint64_t x = st[q][j];
                memcpy(out[j] + fait + 8 * q, &x, k - 8 * q < 8 ? k - 8 * q : 8);
            }
    }
}

void sl_shake256(const uint8_t *m, size_t len, uint8_t *out, size_t outlen)
{
    sl_shake_t h;
    sl_shake_init(&h);
    sl_shake_absorb(&h, m, len);
    sl_shake_final(&h);
    sl_shake_squeeze(&h, out, outlen);
}

int sl_alea(void *out, size_t len)
{
    uint8_t *p = out;
    while (len) {
        ssize_t k = getrandom(p, len, 0);
        if (k < 0)
            return -1;
        p += k; len -= (size_t)k;
    }
    return 0;
}
