/* Mesure, sur la vraie permutation BRUME-1024q réduite à r tours, des annulations que suppose le modèle des chemins de
 * collision (REBOND.md, point 3) : pour un nibble d'entrée v du débit (différence δ uniforme non nulle), la fréquence
 * avec laquelle les g premiers nibbles de capacité q1 … qg (que le chemin doit annuler au dernier tour) ont TOUS une
 * différence nulle, à comparer à 2^−4g (modèle de Markov tronqué). Témoin w : un nibble de capacité hors de la boule de
 * rayon r de v, nul avec probabilité 1.
 *
 *   rebond_verif r v log2_paires w q1 q2 … qn       (la liste vient de « rebond1024.py groupes r v »)
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/rebond_verif.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm
 * Sortie : une ligne JSON. */
#include <math.h>
#include <omp.h>

#include "brume1024.c"

static inline uint64_t xs(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }

#define GMAX 6

int main(int argc, char **argv)
{
    if (argc < 6) { fprintf(stderr, "usage : rebond_verif r v log2_paires w q1 … qn\n"); return 2; }
    int r = atoi(argv[1]), v = atoi(argv[2]), lp = atoi(argv[3]), w = atoi(argv[4]);
    int nq = argc - 5, q[N1];
    for (int i = 0; i < nq; i++) q[i] = atoi(argv[5 + i]);
    if (r < 1 || r > 8 || v < 0 || v >= 160 || lp < 8 || lp > 40 || w < 160 || w >= N1 || nq < 1 || nq > N1) return 2;
    int g = nq < GMAX ? nq : GMAX;
    if (!bref_init() || !ref_init() || !init_noyaux()) { fprintf(stderr, "init\n"); return 2; }
    {   /* contrôle : perm1 à r tours = r applications de ref_tour */
        uint8_t a[128], x[N1];
        uint64_t s = 0xC0FFEEULL;
        for (int i = 0; i < 128; i++) a[i] = (uint8_t)xs(&s);
        for (int i = 0; i < 128; i++) { x[2 * i] = a[i] & 15; x[2 * i + 1] = a[i] >> 4; }
        perm1(a, r);
        for (int t = 0; t < r; t++) ref_tour(x, t);
        for (int i = 0; i < 128; i++)
            if (a[i] != (uint8_t)(x[2 * i] | x[2 * i + 1] << 4)) { fprintf(stderr, "perm1 ≠ ref_tour\n"); return 3; }
    }
    long n = 1L << lp, cg[GMAX + 1] = {0}, c1[N1] = {0}, cw = 0;
#pragma omp parallel
    {
        long lg[GMAX + 1] = {0}, l1[N1] = {0}, lw = 0;
        uint64_t s = 0x5EEDB0ULL ^ (uint64_t)omp_get_thread_num() << 40 ^ (uint64_t)v << 20 ^ (uint64_t)r;
        for (int i = 0; i < 4; i++) xs(&s);
#pragma omp for schedule(static)
        for (long i = 0; i < n; i++) {
            uint8_t a[128], b[128];
            for (int k = 0; k < 16; k++) { uint64_t u = xs(&s); memcpy(a + 8 * k, &u, 8); }
            memcpy(b, a, 128);
            uint8_t d = (uint8_t)(xs(&s) % 15 + 1);
            b[v / 2] ^= (uint8_t)(v & 1 ? d << 4 : d);
            perm1(a, r);
            perm1(b, r);
#define NUL(j) (!(((a[(j) / 2] ^ b[(j) / 2]) >> (4 * ((j) & 1))) & 15))
            lw += NUL(w);
            int tous = 1;
            for (int k = 0; k < nq; k++) {
                int z = NUL(q[k]);
                l1[k] += z;
                if (k < g) { tous &= z; if (tous) lg[k + 1]++; }
            }
        }
#pragma omp critical
        {
            for (int k = 0; k <= GMAX; k++) cg[k] += lg[k];
            for (int k = 0; k < nq; k++) c1[k] += l1[k];
            cw += lw;
        }
    }
    printf("{\"tours\": %d, \"v\": %d, \"log2_paires\": %d, \"temoin\": {\"w\": %d, \"freq\": %.6f}, \"groupes\": [", r, v, lp,
           w, (double)cw / n);
    for (int k = 1; k <= g; k++) {
        double f = (double)cg[k] / n, p = pow(2.0, -4.0 * k);
        printf("%s{\"g\": %d, \"compte\": %ld, \"freq\": %.4e, \"modele\": %.4e, \"rapport\": %.4f, \"err_rel\": %.3f}",
               k > 1 ? ", " : "", k, cg[k], f, p, f / p, cg[k] ? 1.0 / sqrt((double)cg[k]) : 1.0);
    }
    double fmin = 1, fmax = 0;
    for (int k = 0; k < nq; k++) { double f = (double)c1[k] / n; if (f < fmin) fmin = f; if (f > fmax) fmax = f; }
    printf("], \"un_nibble\": {\"n\": %d, \"freq_min\": %.5f, \"freq_max\": %.5f, \"modele\": %.5f}}\n", nq, fmin, fmax,
           1.0 / 16);
    return 0;
}
