/* Bord de la diffusion : la mesure DL à r tours (dl_verif.c) sur la vraie permutation, comparée à la même mesure sous
 * l'hypothèse de Markov réalisée exactement (constantes de tour aléatoires et indépendantes, tirées à chaque paire et
 * à chaque tour : la suite des différences est alors une chaîne de Markov, et la moyenne sur les constantes de la
 * corrélation est la prédiction de Markov). DIFF_LIN.md, § « Edge of diffusion ».
 *
 *   dl_bord r log2_paires v delta mode [graine] [masque]   mode 0 : constantes fixes (la permutation) ; 1 : Markov
 *     masque : fichier de 256 caractères hexadécimaux (l'état emballé, 128 octets) ; la sortie est alors la seule
 *     corrélation de ce masque sur toute la différence de sortie, « eps n ».
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/dl_bord.c sillage/c/commun.c -lm -o dl_bord
 * Sortie : 256 lignes « nibble h[0] … h[15] » (histogramme de la différence de sortie). */
#include <omp.h>

#include "brume1024.c"

static inline uint64_t xs(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }

int main(int argc, char **argv)
{
    if (argc < 6) { fprintf(stderr, "usage : dl_bord r log2_paires v delta mode [graine]\n"); return 2; }
    int r = atoi(argv[1]), lp = atoi(argv[2]), v = atoi(argv[3]), delta = atoi(argv[4]), mode = atoi(argv[5]);
    uint64_t graine = argc > 6 ? strtoull(argv[6], 0, 0) : 0xB0BDULL;
    uint8_t gm[128] = {0};
    int avec_masque = argc > 7;
    if (avec_masque) {
        FILE *f = fopen(argv[7], "r");
        if (!f) { perror(argv[7]); return 2; }
        for (int i = 0; i < 128; i++) { unsigned o; if (fscanf(f, "%2x", &o) != 1) { fprintf(stderr, "masque\n"); return 2; } gm[i] = (uint8_t)o; }
        fclose(f);
    }

    if (r < 1 || r > 16 || lp < 8 || lp > 40 || v < 0 || v >= N1 || delta < 1 || delta > 15) return 2;
    if (!ref_init() || !init_noyaux()) { fprintf(stderr, "init\n"); return 2; }
    {   /* perm1(·, 1) répété avec une constante XORée avant chaque appel = r tours de constantes RC[0] ⊕ k_t */
        uint8_t a[128], x[N1];
        uint64_t s = graine ^ 7;
        for (int i = 0; i < 128; i++) a[i] = (uint8_t)xs(&s);
        for (int i = 0; i < 128; i++) { x[2 * i] = a[i] & 15; x[2 * i + 1] = a[i] >> 4; }
        perm1(a, 1);
        ref_tour(x, 0);
        for (int i = 0; i < 128; i++)
            if (a[i] != (uint8_t)(x[2 * i] | x[2 * i + 1] << 4)) { fprintf(stderr, "perm1 ≠ ref_tour\n"); return 3; }
    }
    long n = 1L << lp;
    static long h[N1][16];
#pragma omp parallel
    {
        static __thread long hl[N1][16];
        memset(hl, 0, sizeof hl);
        uint64_t s = graine ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(v * 16 + delta + 1)) ^ (uint64_t)omp_get_thread_num() << 40;
        for (int i = 0; i < 4; i++) xs(&s);
#pragma omp for schedule(static)
        for (long i = 0; i < n; i++) {
            uint8_t a[128], b[128];
            for (int k = 0; k < 16; k++) { uint64_t u = xs(&s); memcpy(a + 8 * k, &u, 8); }
            memcpy(b, a, 128);
            b[v / 2] ^= (uint8_t)(v & 1 ? delta << 4 : delta);
            if (mode == 0) { perm1(a, r); perm1(b, r); }
            else
                for (int t = 0; t < r; t++) {
                    if (t) for (int k = 0; k < 16; k++) { uint64_t u = xs(&s), p, q; memcpy(&p, a + 8 * k, 8); memcpy(&q, b + 8 * k, 8);
                                                           p ^= u; q ^= u; memcpy(a + 8 * k, &p, 8); memcpy(b + 8 * k, &q, 8); }
                    perm1(a, 1);
                    perm1(b, 1);
                }
            if (avec_masque) {
                int p = 0;
                for (int k = 0; k < 128; k++) p ^= __builtin_popcount((unsigned)((a[k] ^ b[k]) & gm[k]));
                hl[0][p & 1]++;
                continue;
            }
            for (int k = 0; k < 128; k++) {
                uint8_t d = a[k] ^ b[k];
                hl[2 * k][d & 15]++;
                hl[2 * k + 1][d >> 4]++;
            }
        }
#pragma omp critical
        for (int q = 0; q < N1; q++)
            for (int d = 0; d < 16; d++) h[q][d] += hl[q][d];
    }
    if (avec_masque) { printf("%.6e %ld\n", (double)(h[0][0] - h[0][1]) / n, n); return 0; }

    for (int q = 0; q < N1; q++) {
        printf("%d", q);
        for (int d = 0; d < 16; d++) printf(" %ld", h[q][d]);
        printf("\n");
    }
    return 0;
}
