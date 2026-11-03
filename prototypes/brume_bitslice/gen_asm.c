/* Prototype hors suite (docs/PISTES.md, piste 10). Génère bs_tour.S : un tour de BRUME-512 bitslicé sur 256 états,
 * en assembleur AVX2, avec une allocation de registres explicite (gcc, sur le même code déroulé en C, débordait vers la pile).
 *     gen_asm [G [NACC]] > bs_tour.S
 * G : chaque bloc rejoué sur G groupes de 256 états (expérience sur le frontal, défaut 1) ;
 * NACC : accumulateurs par plan de sortie (expérience sur la latence, défaut 1). Les deux valeurs par défaut sont les plus rapides.
 *   bs_tour_s(Y = rdi, Z = rsi, rcm = rdx) : Z = S(M·Y ⊕ rcm) (S-box à bit 3 complété)
 *   bs_tour_x(Y = rdi, Z = rsi, rcm = rdx) : Z = M·Y ⊕ rcm
 * rcm : 512 masques int32 (0 ou -1), un par plan. Registres : a_k = ymm0-3, plans sources ymm4-7, S-box ymm4-13.
 * Plan p = 4·nibble + bit ; un plan = 256 bits, le bit s appartient à l'état s. Un plan source n'est chargé qu'une fois
 * par arête : opérande mémoire s'il ne sert qu'une fois, registre sinon. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "brume512_tables.h"
static int gmul(int a, int b) { int r = 0; for (int i = 0; i < 4; i++) { if (b & 1) r ^= a; b >>= 1; a <<= 1; if (a & 16) a ^= BR_POLY; } return r & 15; }
static int NACC = 1;   /* accumulateurs par plan de sortie : ymm k, puis ymm 8 + k, 12 + k */
static void lin(int u)
{
    int n[4] = {0}, init[4][4] = {{0}};
    static const int base[4] = {0, 8, 12, 14};
    for (int k = 0; k < 4; k++) { printf("\tvpbroadcastd %d(%%rdx), %%ymm%d\n", 4 * (4 * u + k), k); init[k][0] = 1; }
    for (int e = 7 * u; e < 7 * u + 7; e++) {
        int j = BR_EI[e], c = BR_EC[e], col[4];
        for (int b = 0; b < 4; b++) col[b] = gmul(c, 1 << b);
        for (int b = 0; b < 4; b++) if (__builtin_popcount(col[b]) > 1) printf("\tvmovdqa %d(%%rdi), %%ymm%d\n", 32 * (4 * j + b), 4 + b);
        for (int k = 0; k < 4; k++)
            for (int b = 0; b < 4; b++)
                if ((col[b] >> k) & 1) {
                    int q = n[k]++ % NACC, a = base[q] + k;
                    char src[32];
                    if (__builtin_popcount(col[b]) > 1) sprintf(src, "%%ymm%d", 4 + b); else sprintf(src, "%d(%%rdi)", 32 * (4 * j + b));
                    if (init[k][q]) printf("\tvpxor %s, %%ymm%d, %%ymm%d\n", src, a, a);
                    else if (src[0] == '%') printf("\tvmovdqa %s, %%ymm%d\n", src, a);
                    else printf("\tvmovdqa %s, %%ymm%d\n", src, a);
                    init[k][q] = 1;
                }
    }
    for (int q = 1; q < NACC; q++) for (int k = 0; k < 4; k++) if (init[k][q]) printf("\tvpxor %%ymm%d, %%ymm%d, %%ymm%d\n", base[q] + k, k, k);
}
static void op(const char *o, int a, int b, int d) { printf("\t%s %%ymm%d, %%ymm%d, %%ymm%d\n", o, a, b, d); } /* AT&T : d = b op a ; vpandn a,b,d : d = ¬b ∧ a */
static void sbox_store(int u)
{   /* X0..X3 = ymm0..3. ANDN(p, q) = ¬p ∧ q  →  vpandn q, p, d */
#define ANDN(p, q, d) op("vpandn", q, p, d)
    op("vpxor", 1, 2, 4);              /* x12 */
    op("vpor", 0, 2, 5);               /* o   */
    op("vpxor", 0, 1, 6); ANDN(2, 6, 6);           /* B0 = ¬X2 ∧ (X0⊕X1) */
    op("vpand", 0, 1, 7);                          /* B1 */
    ANDN(0, 1, 8); ANDN(8, 2, 8);                  /* B2 = ¬(¬X0∧X1) ∧ X2 */
    op("vpand", 0, 4, 9); op("vpxor", 1, 9, 9);    /* B3 = X1 ⊕ X0∧x12 */
    op("vpxor", 1, 5, 10);                         /* D0n */
    ANDN(2, 1, 11); op("vpxor", 5, 11, 11);        /* D1 */
    ANDN(0, 4, 12); op("vpand", 1, 2, 13); op("vpxor", 13, 12, 12);   /* D2n */
    op("vpxor", 0, 2, 13); op("vpand", 1, 13, 13); /* D3 */
    ANDN(10, 3, 10); op("vpxor", 10, 6, 6);
    op("vpand", 3, 11, 11); op("vpxor", 11, 7, 7);
    ANDN(12, 3, 12); op("vpxor", 12, 8, 8);
    op("vpand", 3, 13, 13); op("vpxor", 13, 9, 9);
    for (int k = 0; k < 4; k++) printf("\tvmovdqa %%ymm%d, %d(%%rsi)\n", 6 + k, 32 * (4 * u + k));
}
static int G = 1;
int main(int argc, char **argv)
{
    if (argc > 1) G = atoi(argv[1]);
    if (argc > 2) NACC = atoi(argv[2]);
    printf("/* généré par gen_asm.c — ne pas éditer */\n\t.text\n");
    for (int f = 0; f < 2; f++) {
        printf("\t.globl bs_tour_%c\n\t.type bs_tour_%c, @function\n\t.p2align 6\nbs_tour_%c:\n", "sx"[f], "sx"[f], "sx"[f]);
        for (int u = 0; u < BR_N; u++) {
            if (G > 1) printf("\tmov $%d, %%ecx\n\tmov %%rdi, %%r8\n\tmov %%rsi, %%r9\n1:\n", G);
            lin(u);
            if (f == 0) sbox_store(u);
            else for (int k = 0; k < 4; k++) printf("\tvmovdqa %%ymm%d, %d(%%rsi)\n", k, 32 * (4 * u + k));
            if (G > 1) printf("\tadd $16384, %%rdi\n\tadd $16384, %%rsi\n\tdec %%ecx\n\tjnz 1b\n\tmov %%r8, %%rdi\n\tmov %%r9, %%rsi\n");
        }
        printf("\tvzeroupper\n\tret\n\t.size bs_tour_%c, .-bs_tour_%c\n", "sx"[f], "sx"[f]);
    }
    printf("\t.section .note.GNU-stack,\"\",@progbits\n");
    return 0;
}
