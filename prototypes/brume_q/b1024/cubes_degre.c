/* Expériences de cubes sur BRUME-1024q (ROADMAP.md § 3, préalable à la propriété de division exacte) : pour r tours de
 * la permutation (sens direct), somme de la sortie sur un cube de d bits d'entrée (les autres bits fixés au hasard). Si le
 * degré algébrique d'un bit de sortie est < d, sa somme sur tout cube de dimension d est nulle. On mesure, pour chaque
 * (r, d), la fraction des 1 024 bits de sortie dont la somme est nulle sur K cubes : le degré effectivement atteint, à
 * comparer à la borne triviale 3^r et à celle de Boura–Canteaut (README, § 5).
 * Noyau bitslicé (256 états) : les 8 premiers bits du cube varient à l'intérieur d'un lot (plans de bits constants, sans
 * transposition), les d − 8 autres d'un lot à l'autre ; la somme est la parité de chaque plan de sortie.
 * Cubes : « nibbles » (les 4 bits de d/4 nibbles tirés au hasard), « bits » (d bits tirés au hasard) ou « boule » (les bits
 * du centre, puis des voisins dans le graphe : la forme la plus favorable aux sommes nulles).
 * Validé le 13 novembre 2026 : sommes bitslicées identiques aux sommes calculées état par état avec perm1 (12 cas, dont 10
 * non nuls).
 * Reprenable : un fichier par (r, d, forme, cube) dans le dossier donné ; un cube déjà fait est sauté.
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN … cubes_degre.c … -o cubes_degre
 *   ./cubes_degre <dossier> <r> <d> <nibbles|bits|boule> <K> [graine]   (d ≥ 8 ; parallèle sur les lots) */
#include <sys/stat.h>

#include "brume1024.c"

static uint64_t xs(uint64_t *s) { *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; return *s; }

/* somme sur le cube : bits[0..d) = indices de bits d'entrée (4·nibble + bit), base = valeurs des autres bits */
static void somme_cube(int r, int d, const int *bits, const uint8_t base[N1], uint8_t somme[N1])
{
    const long nlots = 1L << (d - 8);
    __m256i acc[N1][4];
    memset(acc, 0, sizeof acc);
    /* plans constants des 8 bits internes : bit k du numéro d'état (0..255) */
    __m256i motif[8];
    for (int k = 0; k < 8; k++) {
        uint8_t t[32];
        for (int e = 0; e < 256; e += 8) {
            uint8_t o = 0;
            for (int q = 0; q < 8; q++) o |= (uint8_t)((((e + q) >> k) & 1) << q);
            t[e / 8] = o;
        }
        motif[k] = _mm256_loadu_si256((const __m256i *)t);
    }
#pragma omp parallel
    {
        __m256i loc[N1][4];
        memset(loc, 0, sizeof loc);
        __m256i (*P)[4] = BS_P;
        const __m256i un = _mm256_set1_epi32(-1);
#pragma omp for schedule(static)
        for (long l = 0; l < nlots; l++) {
            for (int v = 0; v < N1; v++)
                for (int i = 0; i < 4; i++)
                    P[v][i] = (base[v] >> i & 1) ? un : _mm256_setzero_si256();
            for (int k = 0; k < 8; k++) {
                int b = bits[k];
                P[b / 4][b % 4] = _mm256_xor_si256(P[b / 4][b % 4], motif[k]);
            }
            for (int k = 8; k < d; k++)
                if (l >> (k - 8) & 1) {
                    int b = bits[k];
                    P[b / 4][b % 4] = _mm256_xor_si256(P[b / 4][b % 4], un);
                }
            bs_perm(P, r);
            for (int v = 0; v < N1; v++)
                for (int i = 0; i < 4; i++)
                    loc[v][i] = _mm256_xor_si256(loc[v][i], P[v][i]);
        }
#pragma omp critical
        for (int v = 0; v < N1; v++)
            for (int i = 0; i < 4; i++)
                acc[v][i] = _mm256_xor_si256(acc[v][i], loc[v][i]);
    }
    for (int v = 0; v < N1; v++) {
        somme[v] = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t w[4];
            memcpy(w, &acc[v][i], 32);
            int p = __builtin_parityll(w[0]) ^ __builtin_parityll(w[1]) ^ __builtin_parityll(w[2]) ^ __builtin_parityll(w[3]);
            somme[v] |= (uint8_t)(p << i);
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 6) return 2;
    const char *dos = argv[1];
    int r = atoi(argv[2]), d = atoi(argv[3]), K = atoi(argv[5]);
    int nib = !strcmp(argv[4], "nibbles"), boule = !strcmp(argv[4], "boule");
    uint64_t g0 = argc > 6 ? strtoull(argv[6], NULL, 10) : 0xC0BE;
    if (d < 8 || d > 44 || r < 1 || r > 32 || (nib && d % 4) || (!nib && !boule && strcmp(argv[4], "bits"))) return 2;
    if (!bref_init() || !ref_init() || !init_noyaux()) return 2;
    prepare_iv();
    {   /* auto-contrôle : noyau bitslicé à r tours ≡ perm1 à r tours (la batterie ne le contrôle qu'à 32 tours) */
        uint8_t (*e)[128] = aligned_alloc(64, 256 * 128), (*f)[128] = aligned_alloc(64, 256 * 128);
        uint64_t s = 77;
        for (int i = 0; i < 256 * 128; i++) e[i / 128][i % 128] = (uint8_t)xs(&s);
        memset(BS_P, 0, sizeof BS_P);
        bs_absorber(BS_P, e[0], 128, 8);
        bs_perm(BS_P, r);
        bs_extraire((const __m256i (*)[4])BS_P, f[0], 128, 8);
        for (int i = 0; i < 256; i++) {
            perm1(e[i], r);
            if (memcmp(e[i], f[i], 128)) { fprintf(stderr, "noyau bitslicé ≠ perm1 à %d tours : arrêt\n", r); return 3; }
        }
        free(e); free(f);
    }
    mkdir(dos, 0755);
    for (int c = 0; c < K; c++) {
        char f[512];
        snprintf(f, sizeof f, "%s/r%d_d%d_%s_%d.json", dos, r, d, argv[4], c);
        struct stat st;
        if (!stat(f, &st)) continue;   /* déjà fait (reprise) */
        uint64_t g = g0 ^ ((uint64_t)r << 48) ^ ((uint64_t)d << 40) ^ ((uint64_t)nib << 39) ^ ((uint64_t)boule << 38) ^ (uint64_t)c * 0x9E3779B97F4A7C15ULL;
        for (int i = 0; i < 8; i++) xs(&g);
        int bits[64], n = 0;
        uint8_t pris[1024] = {0};
        if (boule) {   /* boule du graphe : les 4 bits du centre, puis des voisins, puis des voisins des voisins… */
            int file[N1], deb = 0, fin = 0, vu[N1] = {0};
            file[fin++] = (int)(xs(&g) % N1);
            vu[file[0]] = 1;
            while (n < d && deb < fin) {
                int v = file[deb++];
                for (int i = 0; i < 4 && n < d; i++) bits[n++] = 4 * v + i;
                for (int k = 0; k < 6; k++) {
                    int w = nbr(v, B1_K[k]);
                    if (!vu[w]) { vu[w] = 1; file[fin++] = w; }
                }
            }
        } else if (nib) {
            while (n < d) {
                int v = (int)(xs(&g) % N1);
                if (pris[4 * v]) continue;
                for (int i = 0; i < 4; i++) { pris[4 * v + i] = 1; bits[n++] = 4 * v + i; }
            }
        } else {
            while (n < d) {
                int b = (int)(xs(&g) % 1024);
                if (pris[b]) continue;
                pris[b] = 1;
                bits[n++] = b;
            }
        }
        uint8_t base[N1], somme[N1];
        for (int v = 0; v < N1; v++) base[v] = (uint8_t)(xs(&g) & 15);
        for (int k = 0; k < d; k++) base[bits[k] / 4] &= (uint8_t)~(1 << (bits[k] % 4));
        double t0 = maintenant();
        somme_cube(r, d, bits, base, somme);
        int nuls = 0;
        for (int v = 0; v < N1; v++) nuls += 4 - __builtin_popcount(somme[v]);
        char tmp[520];
        snprintf(tmp, sizeof tmp, "%s.tmp", f);
        FILE *o = fopen(tmp, "w");
        if (!o) return 2;
        fprintf(o, "{\"tours\": %d, \"dimension\": %d, \"forme\": \"%s\", \"cube\": %d, \"bits_de_sortie_a_somme_nulle\": %d, "
                "\"sur\": 1024, \"secondes\": %.1f}\n", r, d, argv[4], c, nuls, maintenant() - t0);
        fclose(o);
        rename(tmp, f);
        printf("r=%d d=%d %s cube %d : %d/1024 bits de sortie à somme nulle (%.1f s)\n", r, d, argv[4], c, nuls, maintenant() - t0);
        fflush(stdout);
    }
    return 0;
}
