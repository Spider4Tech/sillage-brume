/* Prototype hors suite (docs/LEADS.md, piste 10) : contrôles et mesures du noyau bitslicé.
 *   1. S-box bitslicée contre BR_SBOX, sur les 16 entrées ;
 *   2. 256 états aléatoires : bs_permuter contre sl_brume_permute, octet pour octet ;
 *   3. cycles cœur réels (perf_event_open) : br_tours_avx2 (un état), br_permuter_lot (32 états), bs_permuter (256 états).
 * La transposition vers et depuis les plans est ici naïve et n'est pas chronométrée. Code de retour : 0 si tout est conforme. */
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "brume512_tables.h"
#include "sillage.h"
#include "sbox_bs.h"
#include "bs.h"
#include "compteurs.h"

void br_tours_avx2(uint64_t w[8], int R);
void br_permuter_lot(uint8_t (*e)[64]);

static uint8_t E[256][64], R[256][64], LOT[32][64];
static __m256i P[512], T[512];

static int bit(const __m256i *pl, int p, int s) { return (int)((((const uint64_t *)&pl[p])[s >> 6] >> (s & 63)) & 1); }

static double cycles(void (*f)(void), int n)
{
    double best = 1e30;
    for (int rep = 0; rep < 7; rep++) {
        uint64_t c0 = cpt_lire(CPT_FD[0]);
        for (int k = 0; k < n; k++) f();
        double c = (double)(cpt_lire(CPT_FD[0]) - c0) / n;
        if (c < best) best = c;
    }
    return best;
}
static uint64_t W[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static void f_mono(void) { br_tours_avx2(W, BR_TOURS); }
static void f_lot(void) { br_permuter_lot(LOT); }
static void f_bs(void) { bs_permuter(P, T); }

int main(void)
{
    sl_init();
    bs_init();
    cpt_init();
    int ok_s = 1, ok_p = 1;
    for (int x = 0; x < 16; x++) {
        __m256i v[4], y[4];
        for (int b = 0; b < 4; b++) v[b] = _mm256_set1_epi32(-((x >> b) & 1));
        SBOX2(v[0], v[1], v[2], v[3], y[0], y[1], y[2], y[3]);
        int s = 0;
        for (int b = 0; b < 4; b++) s |= (_mm256_extract_epi32(y[b], 0) & 1) << b;
        ok_s &= s == (BR_SBOX[x] ^ 8);
    }
    printf("S-box bitslicée (16 entrées)       : %s\n", ok_s ? "conforme" : "FAUSSE");

    sl_alea((uint8_t *)E, sizeof E);
    memcpy(R, E, sizeof E);
    for (int s = 0; s < 256; s++) sl_brume_permute(R[s]);
    memset(P, 0, sizeof P);
    for (int s = 0; s < 256; s++)
        for (int p = 0; p < 512; p++)
            ((uint64_t *)&P[p])[s >> 6] |= (uint64_t)((E[s][p >> 3] >> (p & 7)) & 1) << (s & 63);
    bs_permuter(P, T);
    for (int s = 0; s < 256; s++)
        for (int p = 0; p < 512; p++)
            ok_p &= bit(P, p, s) == ((R[s][p >> 3] >> (p & 7)) & 1);
    printf("256 états contre sl_brume_permute  : %s\n", ok_p ? "conforme" : "DIFFÉRENT");

    if (CPT_FD[0] < 0) { printf("compteur de cycles indisponible (perf_event_paranoid ?)\n"); return !(ok_s && ok_p); }
    double m = cycles(f_mono, 100000), l = cycles(f_lot, 10000) / 32, b = cycles(f_bs, 300) / 256;
    printf("cycles par état (32 tours) : un état %.0f | lot de 32 %.0f | bitslicé 256 %.0f (%+.0f %% contre le lot)\n",
           m, l, b, 100 * (b / l - 1));
    return !(ok_s && ok_p);
}
