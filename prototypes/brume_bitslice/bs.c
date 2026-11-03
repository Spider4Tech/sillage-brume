/* Prototype hors suite (docs/PISTES.md, piste 10) : BRUME-512 bitslicé sur 256 états. Les 31 premiers tours et le
 * dernier viennent de l'assembleur généré (gen_asm.c → bs_tour.S) ; la S-box du tour 0 est ici, en intrinsèques.
 * P : 512 plans (plan p = 4·nibble + bit, bit s = état s), état x en entrée et en sortie ; T : tampon de 512 plans.
 * Constant-time par construction : opérations booléennes et accès mémoire à adresses fixes. */
#include <immintrin.h>
#include <stdint.h>
#include <string.h>

#include "brume512_tables.h"
#include "sbox_bs.h"
#include "bs.h"

void bs_tour_s(const __m256i *Y, __m256i *Z, const int32_t *rcm);
void bs_tour_x(const __m256i *Y, __m256i *Z, const int32_t *rcm);

static int gmul(int a, int b)
{
    int r = 0;
    for (int i = 0; i < 4; i++) {
        if (b & 1) r ^= a;
        b >>= 1; a <<= 1;
        if (a & 16) a ^= BR_POLY;
    }
    return r & 15;
}

/* RCM[r][p] : bit p de rc[r] ⊕ c*, avec c* = M·(8, …, 8), qui compense le bit 3 complété par la S-box (M est linéaire).
 * RCM[0] = rc[0] (aucune S-box avant) ; RCM[32] = c* (sortie du dernier tour). */
static int32_t RCM[BR_TOURS + 1][4 * BR_N] __attribute__((aligned(64)));

void bs_init(void)
{
    uint8_t cs[BR_N] = {0};
    for (int e = 0; e < BR_ARETES; e++)
        cs[e / BR_DEG] ^= (uint8_t)gmul(BR_EC[e], 8);
    for (int r = 0; r <= BR_TOURS; r++)
        for (int p = 0; p < 4 * BR_N; p++) {
            int v = (r < BR_TOURS ? BR_RC[r][p >> 2] : 0) ^ (r ? cs[p >> 2] : 0);
            RCM[r][p] = -((v >> (p & 3)) & 1);
        }
}

#define RCB(r, p) _mm256_set1_epi32(RCM[r][p])

void bs_permuter(__m256i P[512], __m256i T[512])
{
    for (int u = 0; u < BR_N; u++) {
        __m256i b0, b1, b2, b3;
        SBOX2(XOR_(P[4 * u], RCB(0, 4 * u)), XOR_(P[4 * u + 1], RCB(0, 4 * u + 1)),
              XOR_(P[4 * u + 2], RCB(0, 4 * u + 2)), XOR_(P[4 * u + 3], RCB(0, 4 * u + 3)), b0, b1, b2, b3);
        T[4 * u] = b0; T[4 * u + 1] = b1; T[4 * u + 2] = b2; T[4 * u + 3] = b3;
    }
    for (int q = 0; q < BR_TOURS - 1; q++) {       /* tours pairs : T → P, impairs : P → T ; y du tour 31 dans P */
        if (q & 1) bs_tour_s(P, T, RCM[q + 1]);
        else bs_tour_s(T, P, RCM[q + 1]);
    }
    bs_tour_x(P, T, RCM[BR_TOURS]);
    memcpy(P, T, 512 * sizeof(__m256i));
}
