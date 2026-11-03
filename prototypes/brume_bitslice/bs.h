/* Prototype hors suite (docs/LEADS.md, piste 10) : BRUME-512 bitslicé sur 256 états. */
#ifndef BS_H
#define BS_H
#include <immintrin.h>
void bs_init(void);
void bs_permuter(__m256i P[512], __m256i T[512]);
#endif
