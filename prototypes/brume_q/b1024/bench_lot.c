/* Priorité 2 de ROADMAP.md : variantes du noyau à 32 états de BRUME-1024q, contrôlées contre perm1 puis chronométrées
 * (un cœur, médiane de 9 séries d'au moins ~50 ms, ns par état). Variantes :
 *   lot          noyau actuel (b1024_lot.h : un corps de tour généré, S-box dans une boucle à part) ;
 *   fus          généré, S-box et constante du tour suivant fusionnées dans la diffusion, coefficient 1 sans table ;
 *   boucle_uN    boucle compacte sur les sommets (code minuscule), voisins par pointeurs affines (v + K mod 128, anneaux
 *                dédoublés), coefficients lus par sommet, S-box fusionnée ; déroulée N fois (1, 2, 4, 8) ;
 *   fus64        comme fus sur 64 états (deux registres par nibble, une lecture de table pour deux) ;
 *   bs256        bitslicé (b1024_bs.h, code de brume1024.c) : 256 états, un registre par bit de nibble, diffusion en XOR, S-box en circuit ;
 *                transposition 256 états ↔ plans de bits comprise à chaque appel ;
 *   bs256_noyau  le même sans la transposition (l'état resterait bitslicé d'un bloc à l'autre) : chronométrage seul.
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/bench_lot.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm \
 *      -o tests/c/build/bench_lot && tests/c/build/bench_lot      (tailles du code : nm -S --size-sort) */
#include "brume1024.c"
#include "b1024_lot_var.h"

#if B1_M != 128
#error "anneaux de 128 attendus"
#endif

/* ------------------------------------------------------------ entrée / sortie : 32 états ↔ 256 registres (de lot()) */
static void charger32(uint8_t (*e)[128], __m256i *s)
{
    uint8_t T[128][32] __attribute__((aligned(32)));
    __m128i r[16];
    const __m256i m4 = _mm256_set1_epi8(15);
    for (int Q = 0; Q < 2; Q++)
        for (int K = 0; K < 8; K++) {
            for (int i = 0; i < 16; i++)
                r[i] = _mm_loadu_si128((const __m128i *)(e[16 * Q + i] + 16 * K));
            tr16(r);
            for (int j = 0; j < 16; j++)
                _mm_store_si128((__m128i *)(T[16 * K + j] + 16 * Q), r[j]);
        }
    for (int b = 0; b < 128; b++) {
        __m256i x = _mm256_load_si256((const __m256i *)T[b]);
        s[2 * b] = _mm256_and_si256(x, m4);
        s[2 * b + 1] = _mm256_and_si256(_mm256_srli_epi16(x, 4), m4);
    }
}

static void ranger32(const __m256i *s, uint8_t (*e)[128])
{
    uint8_t T[128][32] __attribute__((aligned(32)));
    __m128i r[16];
    for (int b = 0; b < 128; b++)
        _mm256_store_si256((__m256i *)T[b], _mm256_or_si256(s[2 * b], _mm256_slli_epi16(s[2 * b + 1], 4)));
    for (int Q = 0; Q < 2; Q++)
        for (int K = 0; K < 8; K++) {
            for (int j = 0; j < 16; j++)
                r[j] = _mm_load_si128((const __m128i *)(T[16 * K + j] + 16 * Q));
            tr16(r);
            for (int i = 0; i < 16; i++)
                _mm_storeu_si128((__m128i *)(e[16 * Q + i] + 16 * K), r[i]);
        }
}

#define SB1(x, rc) _mm256_shuffle_epi8(TSB, _mm256_xor_si256((x), _mm256_set1_epi8((char)(rc))))

/* ------------------------------------------------------------ fus : généré, S-box fusionnée */
__attribute__((noinline)) static void lot_fus(uint8_t (*e)[128], int R)
{
    __m256i s[N1], ya[N1], yb[N1], *y = ya, *z = yb;
    charger32(e, s);
    for (int v = 0; v < N1; v++)
        y[v] = SB1(s[v], B1_RC[0][v]);
    for (int rr = 0; rr + 1 < R; rr++) {
        const uint8_t *rc = B1_RC[rr + 1];
        B1_DIFF_FUS(y, z, TG, TSB, rc);
        __m256i *t = y; y = z; z = t;
    }
    B1_DIFF_ID(y, s, TG);
    ranger32(s, e);
}

/* ------------------------------------------------------------ fus64 : 64 états */
__attribute__((noinline)) static void lot_fus64(uint8_t (*e)[128], int R)
{
    static __thread __m256i s0[N1], s1[N1], b[4][N1];
    __m256i *y0 = b[0], *y1 = b[1], *z0 = b[2], *z1 = b[3];
    charger32(e, s0);
    charger32(e + 32, s1);
    for (int v = 0; v < N1; v++) {
        y0[v] = SB1(s0[v], B1_RC[0][v]);
        y1[v] = SB1(s1[v], B1_RC[0][v]);
    }
    for (int rr = 0; rr + 1 < R; rr++) {
        const uint8_t *rc = B1_RC[rr + 1];
        B1_DIFF64_FUS(y0, y1, z0, z1, TG, TSB, rc);
        __m256i *t = y0; y0 = z0; z0 = t;
        t = y1; y1 = z1; z1 = t;
    }
    B1_DIFF64_ID(y0, y1, s0, s1, TG);
    ranger32(s0, e);
    ranger32(s1, e + 32);
}

/* ------------------------------------------------------------ boucle : code compact */
/* anneaux dédoublés : ROT[i] = y[i mod 128] (rotations), REF[i] = y[128 + i mod 128] (réflexions), i < 256.
 * Rotation i : soi ROT[i], générateur g : REF[i + K_g]. Réflexion i : soi REF[i], générateur g : ROT[i + 128 − K_g]. */
static uint8_t COV[N1][8];   /* COV[v][0] = coefficient propre, COV[v][1 + g] = coefficient du générateur g */

static void init_boucle(void)
{
    for (int v = 0; v < N1; v++)
        for (int k = 0; k < 7; k++)
            COV[v][k] = CO[k][v];
}

#define TERME(c, p) _mm256_shuffle_epi8(TG[(c)], *(p))
#define DEMI_TOUR(SOI, AUTRE, D0, D1, D2, D3, D4, D5, OFF, DEST_A, DEST_B, FIN, UNROLL)                              \
    _Pragma(UNROLL) for (int i = 0; i < 128; i++) {                                                                   \
        const uint8_t *c = COV[OFF + i];                                                                              \
        __m256i a = TERME(c[0], SOI + i);                                                                             \
        a = _mm256_xor_si256(a, TERME(c[1], AUTRE + i + (D0)));                                                      \
        a = _mm256_xor_si256(a, TERME(c[2], AUTRE + i + (D1)));                                                      \
        a = _mm256_xor_si256(a, TERME(c[3], AUTRE + i + (D2)));                                                      \
        a = _mm256_xor_si256(a, TERME(c[4], AUTRE + i + (D3)));                                                      \
        a = _mm256_xor_si256(a, TERME(c[5], AUTRE + i + (D4)));                                                      \
        a = _mm256_xor_si256(a, TERME(c[6], AUTRE + i + (D5)));                                                      \
        if (FIN)                                                                                                      \
            DEST_A[i] = a;                                                                                            \
        else {                                                                                                        \
            __m256i zz = SB1(a, rc[OFF + i]);                                                                         \
            DEST_A[i] = zz;                                                                                           \
            DEST_B[i] = zz;                                                                                           \
        }                                                                                                             \
    }

#define LOT_BOUCLE(NOM, UNROLL)                                                                                       \
    __attribute__((noinline)) static void NOM(uint8_t (*e)[128], int R)                                               \
    {                                                                                                                 \
        __m256i s[N1], b[2][2][256];   /* b[tampon][0 = ROT, 1 = REF][i] */                                           \
        charger32(e, s);                                                                                              \
        for (int i = 0; i < 256; i++) {                                                                               \
            b[0][0][i] = SB1(s[i & 127], B1_RC[0][i & 127]);                                                          \
            b[0][1][i] = SB1(s[128 + (i & 127)], B1_RC[0][128 + (i & 127)]);                                          \
        }                                                                                                             \
        int p = 0;                                                                                                    \
        for (int rr = 0; rr + 1 < R; rr++, p ^= 1) {                                                                  \
            const uint8_t *rc = B1_RC[rr + 1];                                                                        \
            const __m256i *ROT = b[p][0], *REF = b[p][1];                                                             \
            __m256i *nR = b[p ^ 1][0], *nF = b[p ^ 1][1];                                                             \
            DEMI_TOUR(ROT, REF, K0, K1, K2, K3, K4, K5, 0, nR, (nR + 128), 0, UNROLL)                                 \
            DEMI_TOUR(REF, ROT, 128 - K0, 128 - K1, 128 - K2, 128 - K3, 128 - K4, 128 - K5, 128, nF, (nF + 128), 0, UNROLL) \
        }                                                                                                             \
        {                                                                                                             \
            const uint8_t *rc = B1_RC[0];                                                                             \
            (void)rc;                                                                                                 \
            const __m256i *ROT = b[p][0], *REF = b[p][1];                                                             \
            __m256i *sR = s, *sF = s + 128;                                                                           \
            DEMI_TOUR(ROT, REF, K0, K1, K2, K3, K4, K5, 0, sR, sR, 1, UNROLL)                                         \
            DEMI_TOUR(REF, ROT, 128 - K0, 128 - K1, 128 - K2, 128 - K3, 128 - K4, 128 - K5, 128, sF, sF, 1, UNROLL)   \
        }                                                                                                             \
        ranger32(s, e);                                                                                               \
    }

LOT_BOUCLE(lot_boucle_u1, "GCC unroll 1")
LOT_BOUCLE(lot_boucle_u2, "GCC unroll 2")
LOT_BOUCLE(lot_boucle_u4, "GCC unroll 4")
LOT_BOUCLE(lot_boucle_u8, "GCC unroll 8")

/* ------------------------------------------------------------ bs256 : bitslicé (code de brume1024.c) */
__attribute__((noinline)) static void lot_bs256(uint8_t (*e)[128], int R)
{
    memset(BS_P, 0, sizeof BS_P);
    bs_absorber(BS_P, e[0], 128, 8);
    bs_perm(BS_P, R);
    bs_extraire((const __m256i (*)[4])BS_P, e[0], 128, 8);
}

__attribute__((noinline)) static void lot_bs256_noyau(uint8_t (*e)[128], int R)
{
    (void)e;
    bs_perm(BS_P, R);
}

/* ------------------------------------------------------------ banc */
typedef void (*lot_f)(uint8_t (*)[128], int);
static const struct { const char *nom; lot_f f; int etats; } V[] = {
    {"lot", lot, 32}, {"fus", lot_fus, 32}, {"boucle_u1", lot_boucle_u1, 32}, {"boucle_u2", lot_boucle_u2, 32},
    {"boucle_u4", lot_boucle_u4, 32}, {"boucle_u8", lot_boucle_u8, 32}, {"fus64", lot_fus64, 64}, {"bs256", lot_bs256, 256}, {"bs256_noyau", lot_bs256_noyau, 256},
};
#define NV ((int)(sizeof V / sizeof *V))

int main(int argc, char **argv)
{
    if (!bref_init() || !ref_init() || !init_noyaux())
        return 2;
    init_boucle();
    prepare_iv();
    const char *seul = argc > 1 ? argv[1] : NULL;
    uint8_t (*e)[128] = aligned_alloc(64, 256 * 128), (*f)[128] = aligned_alloc(64, 256 * 128);
    uint64_t g = 0xB0C1E;
    for (int i = 0; i < 256 * 128; i++) {
        g = g * 6364136223846793005ULL + 1442695040888963407ULL;
        e[i / 128][i % 128] = (uint8_t)(g >> 56);
    }
    printf("| Variante | Contrôle (≡ perm1) | ns par état |\n|---|---|---|\n");
    double t1[9];
    for (int s = 0; s < 9; s++) {   /* référence : 1 état */
        uint8_t w[128];
        memcpy(w, e[0], 128);
        long n = 20000;
        double t0 = maintenant();
        for (long i = 0; i < n; i++)
            perm1(w, R1);
        t1[s] = (maintenant() - t0) / n * 1e9 + 0 * w[0];
    }
    printf("| perm1 (1 état) | — | %.0f |\n", mediane(t1, 9));
    for (int k = 0; k < NV; k++) {
        if (seul && strcmp(seul, V[k].nom))
            continue;
        int n = V[k].etats, ok = 1, temps_seul = !strcmp(V[k].nom, "bs256_noyau");
        memcpy(f, e, (size_t)n * 128);
        V[k].f(f, R1);
        for (int i = 0; i < n && !temps_seul; i++) {
            uint8_t w[128];
            memcpy(w, e[i], 128);
            perm1(w, R1);
            ok &= !memcmp(w, f[i], 128);
        }
        long it = 1;
        for (;;) {
            double t0 = maintenant();
            for (long i = 0; i < it; i++)
                V[k].f(f, R1);
            if (maintenant() - t0 > 0.05)
                break;
            it *= 2;
        }
        double t[9];
        for (int s = 0; s < 9; s++) {
            double t0 = maintenant();
            for (long i = 0; i < it; i++)
                V[k].f(f, R1);
            t[s] = (maintenant() - t0) / it / n * 1e9;
        }
        printf("| %s | %s | %.0f |\n", V[k].nom, temps_seul ? "(chronométrage seul)" : ok ? "OK" : "ÉCHEC", mediane(t, 9));
    }
    free(e);
    free(f);
    return 0;
}
