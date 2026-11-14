/* Noyau « bitslicé » de BRUME-1024q (priorité 2 de ROADMAP.md) : 256 états à la fois, un registre de 256 bits par bit de
 * nibble (plan P[v][i] : bit k = bit i du nibble v de l'état k). La multiplication par une constante c de GF(16) devient une
 * matrice 4×4 sur GF(2) (des XOR, sans pshufb) ; la S-box devient un circuit booléen tiré de sa forme algébrique normale.
 * Écrit b1024_bs.h à partir de la matrice dense M (ref_init de brume1024.c) et de BR_SBOX :
 *   bs_tour(y, z, rc) : z[v] = S(Σ_u M[v][u]·y[u] ⊕ rc[v]) ;   bs_lin(y, s) : s[v] = Σ_u M[v][u]·y[u] (dernier tour) ;
 *   bs_sbox(x0..x3, o) : la S-box seule (couche initiale).
 * Diffusion : les XOR communs aux 4 plans de sortie d'un sommet sont partagés (Paar glouton) ; « sans_paar » les écrit en chaînes.
 *   cc -O2 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/gen_bitslice.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm \
 *      -o tests/c/build/gen_bitslice && tests/c/build/gen_bitslice > prototypes/brume_q/b1024/b1024_bs.h */
#include "brume1024.c"

static int nxor_lin, nop_sbox;

/* bit i de c·x^j : la matrice de la multiplication par c */
static int mbit(int c, int i, int j)
{
    return gf_mul((uint8_t)c, (uint8_t)(1 << j)) >> i & 1;
}

/* Circuit de la S-box v0.5 (AD412650BFEC7893) : 17 portes, sorties égales à S(x ⊕ TA) ⊕ KS avec TA = 3, KS = S(3) = 1.
 * Trouvé par SAT (circuit_sbox.c, CaDiCaL, 13 novembre 2026) parmi les 16 translations d'entrée ; 16 portes : délai dépassé
 * partout (non prouvé impossible). TA est reporté dans les constantes de tour, KS par linéarité de M (BS_RCK, bs_lin).
 * L'ancien circuit, factorisé à la main (22 portes, TA = 0), est gardé en commentaire dans l'historique.
 * Vérifié sur les 16 entrées avant toute écriture ; à défaut, le circuit ANF (32 opérations, NON compris) est émis. */
enum { ET, OU, OUX, ETN };   /* ETN(a, b) = ~a & b */
static const int CIRC[][4] = {
    {OU, 4, 1, 3},    {OUX, 5, 0, 1},   {ET, 6, 3, 5},    {ETN, 7, 6, 2},   {ETN, 8, 7, 4},   {OUX, 9, 2, 3},
    {OU, 10, 0, 6},   {OUX, 11, 1, 8},  {ETN, 12, 11, 10}, {OUX, 13, 9, 12}, {OUX, 14, 2, 6},  {OUX, 15, 9, 10},
    {ET, 16, 4, 14},  {ET, 17, 3, 15},  {ETN, 18, 5, 1},  {OUX, 19, 5, 17}, {OU, 20, 16, 18},
};
#define NCIRC ((int)(sizeof CIRC / sizeof *CIRC))
static const int SORT[4] = {13, 20, 19, 8};

static const int TA = 3;   /* translation d'entrée a : le circuit calcule S(x ⊕ TA) ⊕ KS */

static int circuit_conforme(int ks)
{
    for (int x = 0; x < 16; x++) {
        int w[32];
        for (int i = 0; i < 4; i++)
            w[i] = x >> i & 1;
        for (int k = 0; k < NCIRC; k++) {
            int a = w[CIRC[k][2]], b = w[CIRC[k][3]];
            w[CIRC[k][1]] = CIRC[k][0] == ET ? a & b : CIRC[k][0] == OU ? a | b : CIRC[k][0] == OUX ? a ^ b : (!a) & b;
        }
        int o = 0;
        for (int i = 0; i < 4; i++)
            o |= w[SORT[i]] << i;
        if (o != (BR_SBOX[x ^ TA] ^ ks))
            return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    int paar = !(argc > 1 && !strcmp(argv[1], "sans_paar"));   /* « sans_paar » : chaînes de XOR directes */
    if (!bref_init() || !ref_init())
        return 2;
    /* forme algébrique normale de la S-box : ANF[i][m] = coefficient du monôme m dans le bit de sortie i */
    int anf[4][16];
    for (int i = 0; i < 4; i++) {
        for (int x = 0; x < 16; x++)
            anf[i][x] = BR_SBOX[x] >> i & 1;
        for (int b = 0; b < 4; b++)
            for (int x = 0; x < 16; x++)
                if (x >> b & 1)
                    anf[i][x] ^= anf[i][x ^ (1 << b)];
    }
    int besoin[16] = {0};
    for (int i = 0; i < 4; i++)
        for (int m = 1; m < 16; m++)
            if (anf[i][m])
                for (int p = m; p; p &= p - 1)   /* le monôme et ses préfixes (bits retirés du bas) */
                    besoin[p] = 1;
    printf("/* Généré par prototypes/brume_q/b1024/gen_bitslice.c — ne pas éditer. Noyau bitslicé, 256 états. */\n");
    printf("static __m256i BS_MSK[16][4];   /* BS_MSK[c][i] = bit i de c répété sur 256 bits */\n");
    printf("static void bs_init(void)\n{\n    for (int c = 0; c < 16; c++)\n        for (int i = 0; i < 4; i++)\n"
           "            BS_MSK[c][i] = _mm256_set1_epi32(-(c >> i & 1));\n}\n\n");
    const int KS = BR_SBOX[TA];
    int fact = circuit_conforme(KS);
    int ks = fact ? KS : 0, ta = fact ? TA : 0;   /* constantes de sortie et d'entrée du circuit */
    if (fact) {
        printf("static inline __attribute__((always_inline)) void bs_sbox(__m256i x0, __m256i x1, __m256i x2, __m256i x3, __m256i *o)\n{\n");
        printf("    /* circuit, %d portes : o = S(x ⊕ 0x%X) ⊕ 0x%X */\n", NCIRC, TA, KS);
        const char *fn[4] = {"_mm256_and_si256", "_mm256_or_si256", "_mm256_xor_si256", "_mm256_andnot_si256"};
        for (int k = 0; k < NCIRC; k++)
            printf("    const __m256i x%d = %s(x%d, x%d);\n", CIRC[k][1], fn[CIRC[k][0]], CIRC[k][2], CIRC[k][3]);
        for (int i = 0; i < 4; i++)
            printf("    o[%d] = x%d;\n", i, SORT[i]);
        printf("}\n\n");
        nop_sbox = NCIRC;
    } else {
    printf("static inline __attribute__((always_inline)) void bs_sbox(__m256i x0, __m256i x1, __m256i x2, __m256i x3, __m256i *o)\n{\n");
    /* produits : P_m = P_{m sans son bit le plus haut} & x_haut */
    for (int m = 1; m < 16; m++) {
        if (!besoin[m] || !(m & (m - 1)))
            continue;
        int h = 31 - __builtin_clz((unsigned)m), r = m ^ (1 << h);
        if (r & (r - 1))
            printf("    const __m256i p%d = _mm256_and_si256(p%d, x%d);\n", m, r, h);
        else
            printf("    const __m256i p%d = _mm256_and_si256(x%d, x%d);\n", m, __builtin_ctz((unsigned)r), h);
        nop_sbox++;
    }
    for (int i = 0; i < 4; i++) {
        printf("    o[%d] = ", i);
        int k = 0;
        char t[16][8];
        for (int m = 1; m < 16; m++)
            if (anf[i][m]) {
                if (m & (m - 1))
                    snprintf(t[k++], 8, "p%d", m);
                else
                    snprintf(t[k++], 8, "x%d", __builtin_ctz((unsigned)m));
            }
        for (int q = 0; q + 1 < k; q++)
            printf("_mm256_xor_si256(");
        printf("%s", t[0]);
        for (int q = 1; q < k; q++)
            printf(", %s)", t[q]);
        nop_sbox += k - 1;
        if (anf[i][0]) {
            printf(";\n    o[%d] = _mm256_xor_si256(o[%d], _mm256_set1_epi32(-1))", i, i);
            nop_sbox++;
        }
        printf(";\n");
    }
    printf("}\n\n");
    }
    /* XN : chaîne de XOR de chargements */
    printf("#define BS_X2(a, b) _mm256_xor_si256((a), (b))\n\n");
    /* constante KS retirée de chaque sortie de S-box : M·KS s'ajoute à la diffusion ; on la retire avec la constante du tour
     * suivant (BS_RCK) et, après le dernier tour, par un XOR final (bs_lin) */
    uint8_t mk[N1];
    for (int v = 0; v < N1; v++) {
        mk[v] = 0;
        for (int u = 0; u < N1; u++)
            mk[v] ^= gf_mul(DM[v][u], (uint8_t)ks);
    }
    printf("/* BS_RCK[r][v] = RC[r][v] ⊕ 0x%X (entrée du circuit) ⊕ (M·0x%X)[v] pour r ≥ 1 (sortie du circuit, tour précédent) */\n", ta, ks);
    printf("static const uint8_t BS_RCK[%d][%d] = {\n", B1_RT, N1);
    for (int r = 0; r < B1_RT; r++) {
        printf("    {");
        for (int v = 0; v < N1; v++)
            printf("%d%s", B1_RC[r][v] ^ ta ^ (r ? mk[v] : 0), v + 1 < N1 ? "," : "");
        printf("},\n");
    }
    printf("};\n\n");
    for (int fus = 1; fus >= 0; fus--) {
        if (fus)
            printf("__attribute__((noinline)) static void bs_tour(const __m256i (*y)[4], __m256i (*z)[4], const uint8_t *rc)\n{\n");
        else
            printf("__attribute__((noinline)) static void bs_lin(const __m256i (*y)[4], __m256i (*z)[4])\n{\n");
        for (int v = 0; v < N1; v++) {
            printf("  {\n");
            /* variables : 0..27 = (terme, plan) ; 28.. = temporaires. Lignes : bit q de row[i] = variable q dans a_i. */
            char nom[64][24];
            uint64_t row[4] = {0};
            int nv = 0;
            for (int u = 0; u < N1; u++) {
                int c = DM[v][u];
                if (!c)
                    continue;
                for (int j = 0; j < 4; j++) {
                    snprintf(nom[nv], 24, "y[%d][%d]", u, j);
                    for (int i = 0; i < 4; i++)
                        if (mbit(c, i, j))
                            row[i] |= 1ULL << nv;
                    nv++;
                }
            }
            /* Paar glouton : la paire présente dans le plus de lignes (au moins 2) devient un temporaire. Les égalités sont
             * départagées au hasard (graine fixe : sortie déterministe) sur ESSAIS essais ; on garde le moins de XOR. */
            enum { ESSAIS = 256 };
            uint64_t meil[4];
            int mpa[64], mpb[64], mnp = 0, mcout = 1 << 30;
            for (int essai = 0; essai < (paar ? ESSAIS : 1); essai++) {
                uint64_t r[4] = {row[0], row[1], row[2], row[3]};
                int n = nv, np = 0, pa[64], pb[64];
                uint32_t h = 2166136261u ^ (uint32_t)(v * 7919 + essai * 104729);
                while (paar && n < 64) {
                    int bn = 1, nc = 0, ca[1024], cb[1024];
                    for (int x = 0; x < n; x++)
                        for (int w = x + 1; w < n; w++) {
                            int c = 0;
                            for (int i = 0; i < 4; i++)
                                c += (r[i] >> x & 1) && (r[i] >> w & 1);
                            if (c > bn) { bn = c; nc = 0; }
                            if (c == bn && bn > 1 && nc < 1024) { ca[nc] = x; cb[nc] = w; nc++; }
                        }
                    if (!nc)
                        break;
                    h = h * 1664525u + 1013904223u;
                    int q = essai ? (int)((h >> 8) % (uint32_t)nc) : 0;
                    pa[np] = ca[q]; pb[np] = cb[q]; np++;
                    for (int i = 0; i < 4; i++)
                        if ((r[i] >> ca[q] & 1) && (r[i] >> cb[q] & 1))
                            r[i] = (r[i] & ~(1ULL << ca[q]) & ~(1ULL << cb[q])) | 1ULL << n;
                    n++;
                }
                int cout = np;
                for (int i = 0; i < 4; i++)
                    cout += __builtin_popcountll(r[i]) - 1;
                if (cout < mcout) {
                    mcout = cout; mnp = np;
                    memcpy(meil, r, sizeof r); memcpy(mpa, pa, sizeof pa); memcpy(mpb, pb, sizeof pb);
                }
            }
            for (int p = 0; p < mnp; p++) {
                snprintf(nom[nv], 24, "t%d", nv);
                printf("    const __m256i t%d = BS_X2(%s, %s);\n", nv, nom[mpa[p]], nom[mpb[p]]);
                nv++;
                if (fus)
                    nxor_lin++;
            }
            memcpy(row, meil, sizeof meil);
            for (int i = 0; i < 4; i++) {
                int k = 0;
                const char *t[64];
                for (int q = 0; q < nv; q++)
                    if (row[i] >> q & 1)
                        t[k++] = nom[q];
                printf("    __m256i a%d = ", i);
                for (int q = 0; q + 1 < k; q++)
                    printf("BS_X2(");
                printf("%s", t[0]);
                for (int q = 1; q < k; q++)
                    printf(", %s)", t[q]);
                printf(";\n");
                if (fus)
                    nxor_lin += k - 1;
            }
            if (fus)
                printf("    bs_sbox(BS_X2(a0, BS_MSK[rc[%d]][0]), BS_X2(a1, BS_MSK[rc[%d]][1]), BS_X2(a2, BS_MSK[rc[%d]][2]), "
                       "BS_X2(a3, BS_MSK[rc[%d]][3]), z[%d]);\n", v, v, v, v, v);
            else
                for (int i = 0; i < 4; i++)
                    printf("    z[%d][%d] = %sa%d%s;\n", v, i, mk[v] >> i & 1 ? "_mm256_xor_si256(" : "", i,
                           mk[v] >> i & 1 ? ", _mm256_set1_epi32(-1))" : "");
            printf("  }\n");
        }
        printf("}\n\n");
    }
    printf("/* par tour et pour 256 états : %d XOR pour la diffusion (%.1f par sommet), %d opérations par S-box, 4 XOR de "
           "constante par sommet */\n", nxor_lin, nxor_lin / 256.0, nop_sbox);
    fprintf(stderr, "diffusion : %d XOR par tour (%.1f par sommet) ; S-box : %d opérations\n", nxor_lin, nxor_lin / 256.0, nop_sbox);
    return 0;
}
