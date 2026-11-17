/* Campagne de nuit : distingueurs empiriques à la frontière connue, avec de
 * bien plus gros échantillons que la batterie (qui s'arrête à 2^28).
 *
 * Portée connue de la batterie (README) : cubes 4 tours en direct, 3 en
 * inverse ; différentielles tronquées alignées 5 en direct, 2 en inverse ;
 * linéaire à un nibble 1 tour. Chaque famille a des témoins à cette portée
 * (ils valident la sensibilité) et des expériences au-delà.
 *
 * 1. Cubes simples, 2^32 à 2^36 entrées, nibbles entiers (voisinage d'un
 *    sommet du graphe, ou au hasard). Bits de somme nulle : Bin(512, 1/2).
 * 2. Séries de K cubes de mêmes nibbles et de bases différentes : nombre total
 *    de bits nuls, et bit le plus déséquilibré (Bonferroni sur 512 bits). Voit
 *    un biais limité à quelques bits, invisible sur un cube unique.
 * 3. Différentielles tronquées ALIGNÉES, même statistique que la batterie :
 *    M⁻¹ appliquée à la différence de sortie en direct, différence d'entrée
 *    pré-diffusée en inverse ; χ² à 15 ddl sur les 16 valeurs de chacun des
 *    128 nibbles (Bonferroni). Une fréquence de Δ = 0 sans alignement ne voit
 *    pas le biais à 5 tours (campagne du 2026-10-30, z = 3,2 à 2^34).
 * 4. Linéaire alignée : loi conjointe (nibble d'entrée, nibble de sortie), χ² à
 *    255 ddl par nibble de sortie, couvre les 225 paires de masques à la fois.
 * Sens direct par le noyau AVX2 de la bibliothèque (br_tours_avx2), contrôlé contre la référence.
 * Ordonnancement : un étalonnage mesure le débit, puis les expériences sont
 * lancées par ordre de priorité tant que le budget le permet ; le JSON est
 * réécrit après chacune (rien n'est perdu en cas d'arrêt).
 *     build/nuit_cryptanalyse <budget_s>  → resultats/nuit_cryptanalyse.{json,md}
 */
#include <immintrin.h>
#include <math.h>
#include <omp.h>
#include <time.h>

#include "brume_ref.h"
#include "resultat.h"

static uint64_t LD[BR_N][16][8] __attribute__((aligned(64)));   /* M·(y en position j) */
static uint64_t LI[BR_N][16][8] __attribute__((aligned(64)));   /* M⁻¹·(y en position j) */

static uint64_t RC_E[BR_TOURS][8];
#define NIB(w, j) ((int)(((w)[(j) >> 4] >> (4 * ((j) & 15))) & 15))

static void tables(void)
{
    memset(LD, 0, sizeof LD);
    memset(LI, 0, sizeof LI);
    for (int j = 0; j < BR_N; j++)
        for (int y = 0; y < 16; y++)
            for (int v = 0; v < BR_N; v++) {
                if (BM[v][j])
                    LD[j][y][v >> 4] |= (uint64_t)gf_mul(BM[v][j], (uint8_t)y) << (4 * (v & 15));
                if (BMI[v][j])
                    LI[j][y][v >> 4] |= (uint64_t)gf_mul(BMI[v][j], (uint8_t)y) << (4 * (v & 15));
            }
    memset(RC_E, 0, sizeof RC_E);
    for (int r = 0; r < BR_TOURS; r++)
        for (int j = 0; j < BR_N; j++)
            RC_E[r][j >> 4] |= (uint64_t)BR_RC[r][j] << (4 * (j & 15));
}

static inline void lineaire(uint64_t L[BR_N][16][8], uint64_t w[8])
{
    uint64_t a[8] = {0};
    for (int j = 0; j < BR_N; j++) {
        const uint64_t *l = L[j][NIB(w, j)];
        for (int k = 0; k < 8; k++)
            a[k] ^= l[k];
    }
    memcpy(w, a, 64);
}

/* sens direct : noyau AVX2 de la bibliothèque (×11 sur les tables, tous les cœurs) ; sens inverse : M⁻¹ est
 * dense, donc tables, mais la S-box inverse et les constantes passent par vpshufb */
static inline void tour_i(uint64_t w[8], int r)
{
    uint64_t a[8] __attribute__((aligned(32))) = {0};
    for (int j = 0; j < BR_N; j++) {
        const __m256i *l = (const __m256i *)LI[j][NIB(w, j)];
        _mm256_store_si256((__m256i *)a, _mm256_xor_si256(_mm256_load_si256((const __m256i *)a), _mm256_load_si256(l)));
        _mm256_store_si256((__m256i *)a + 1, _mm256_xor_si256(_mm256_load_si256((const __m256i *)a + 1), _mm256_load_si256(l + 1)));
    }
    const __m256i t = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)BSI)), m = _mm256_set1_epi8(15);
    for (int h = 0; h < 2; h++) {
        __m256i x = _mm256_load_si256((const __m256i *)a + h);
        __m256i bas = _mm256_shuffle_epi8(t, _mm256_and_si256(x, m));
        __m256i haut = _mm256_shuffle_epi8(t, _mm256_and_si256(_mm256_srli_epi16(x, 4), m));
        x = _mm256_or_si256(bas, _mm256_slli_epi16(haut, 4));
        _mm256_storeu_si256((__m256i *)(w + 4 * h), _mm256_xor_si256(x, _mm256_loadu_si256((const __m256i *)(RC_E[r] + 4 * h))));
    }
}

static inline void perm_r(uint64_t w[8], int R, int sens)
{
    if (sens == 0) {
        br_tours_avx2(w, R);
        return;
    }
    for (int t = 0; t < R; t++)
        tour_i(w, BR_TOURS - 1 - t);
}

static int conforme(void)
{
    alea_t g;
    alea_init(&g, 11);
    for (int e = 0; e < 200; e++) {
        int R = 1 + e % 6, sens = e & 1;
        uint8_t x[BR_N];
        uint64_t w[8] = {0};
        for (int j = 0; j < BR_N; j++) {
            x[j] = (uint8_t)(alea64(&g) & 15);
            w[j >> 4] |= (uint64_t)x[j] << (4 * (j & 15));
        }
        bref_perm(x, R, sens);
        perm_r(w, R, sens);
        for (int j = 0; j < BR_N; j++)
            if (NIB(w, j) != x[j])
                return 0;
    }
    return 1;
}

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

/* p = Q(a, x), fonction gamma incomplète régularisée supérieure */
static double gamma_q(double a, double x)
{
    if (x <= 0) return 1;
    double pre = exp(a * log(x) - x - lgamma(a));
    if (x < a + 1) {                                  /* série */
        double t = 1 / a, s = t;
        for (int n = 1; n < 100000 && t > s * 1e-16; n++) {
            t *= x / (a + n);
            s += t;
        }
        return 1 - s * pre;
    }
    double b = x + 1 - a, c = 1e300, d = 1 / b, h = d;  /* fraction continue (Lentz) */
    for (int i = 1; i < 100000; i++) {
        double an = -i * (i - a);
        b += 2;
        d = an * d + b;
        if (fabs(d) < 1e-300) d = 1e-300;
        c = b + an / c;
        if (fabs(c) < 1e-300) c = 1e-300;
        d = 1 / d;
        double del = d * c;
        h *= del;
        if (fabs(del - 1) < 1e-15) break;
    }
    return pre * h;
}

/* χ² moyen sur les 128 nibbles de la dernière tronquée ou linéaire : ≈ ddl sous H0. Pour la linéaire, on retire le
 * χ² de la marge du nibble d'entrée (15 ddl) : il est le MÊME pour les 128 nibbles de sortie (mêmes échantillons) et ne
 * se moyenne pas. La moyenne avait un écart-type de 2,0, et non les 0,71 supposés (simulation sous H0 exacte, 400 × 8
 * runs) : z = 4,49 de la campagne de 24 h valait ≈ 1,5 σ réel. Sans ce terme, il reste 240 ddl indépendants d'un
 * nibble à l'autre (écart-type mesuré 0,696 contre 0,685 prédit). */
static double chi_moyen;

/* somme du cube : `log2n` bits d'indice sur les nibbles nib[], base aléatoire */
static void cube(const int *nib, int log2n, int R, int sens, uint64_t graine, uint64_t acc[8])
{
    alea_t g;
    alea_init(&g, graine);
    uint64_t base[8];
    for (int k = 0; k < 8; k++) base[k] = alea64(&g);
    uint64_t total = 1ULL << log2n;
    int m = (log2n + 3) / 4;
    memset(acc, 0, 64);
#pragma omp parallel
    {
        uint64_t loc[8] = {0};
#pragma omp for schedule(dynamic, 4096)
        for (uint64_t idx = 0; idx < total; idx++) {
            uint64_t w[8];
            memcpy(w, base, 64);
            for (int k = 0; k < m; k++)
                w[nib[k] >> 4] ^= ((idx >> (4 * k)) & 15) << (4 * (nib[k] & 15));
            perm_r(w, R, sens);
            for (int k = 0; k < 8; k++) loc[k] ^= w[k];
        }
#pragma omp critical
        for (int k = 0; k < 8; k++) acc[k] ^= loc[k];
    }
}

static int bits_nuls(const uint64_t acc[8])
{
    int un = 0;
    for (int k = 0; k < 8; k++) un += __builtin_popcountll(acc[k]);
    return 512 - un;
}

/* différentielle tronquée alignée ; delta = 0 : différence aléatoire non nulle.
 * Renvoie le χ² maximal et *p, sa probabilité avec correction de Bonferroni. */
static double tronquee(int q, int delta, int R, int sens, uint64_t paires, uint64_t graine, int *jmax, double *p)
{
    static uint64_t cnt[BR_N][16];
    memset(cnt, 0, sizeof cnt);
#pragma omp parallel
    {
        alea_t g;
        alea_init(&g, graine * 1000003u + (uint64_t)omp_get_thread_num());
        uint64_t loc[BR_N][16];
        memset(loc, 0, sizeof loc);
#pragma omp for schedule(dynamic, 1 << 14)
        for (uint64_t i = 0; i < paires; i++) {
            uint64_t a[8], b[8], d[8];
            for (int k = 0; k < 8; k++) a[k] = alea64(&g);
            memcpy(b, a, 64);
            int y = delta ? delta : 1 + (int)alea_borne(&g, 15);
            if (sens == 0)
                b[q >> 4] ^= (uint64_t)y << (4 * (q & 15));
            else
                for (int k = 0; k < 8; k++) b[k] ^= LD[q][y][k];
            perm_r(a, R, sens);
            perm_r(b, R, sens);
            for (int k = 0; k < 8; k++) d[k] = a[k] ^ b[k];
            if (sens == 0)
                lineaire(LI, d);
            for (int j = 0; j < BR_N; j++)
                loc[j][NIB(d, j)]++;
        }
#pragma omp critical
        for (int j = 0; j < BR_N; j++)
            for (int v = 0; v < 16; v++) cnt[j][v] += loc[j][v];
    }
    double att = (double)paires / 16, cm = 0;
    *jmax = 0;
    chi_moyen = 0;
    for (int j = 0; j < BR_N; j++) {
        double chi = 0;
        for (int v = 0; v < 16; v++) chi += ((double)cnt[j][v] - att) * ((double)cnt[j][v] - att) / att;
        chi_moyen += chi / BR_N;
        if (chi > cm) { cm = chi; *jmax = j; }
    }
    double pr = 128 * gamma_q(7.5, cm / 2);
    *p = pr < 1 ? pr : 1;
    return cm;
}

/* linéaire alignée : χ² de la loi conjointe (entrée q, sortie j) contre l'uniforme
 * sur 256 cases, marges connues : 255 ddl */
static double lineaire_jointe(int q, int R, int sens, uint64_t n, uint64_t graine, int *jmax, double *p)
{
    static uint64_t cnt[BR_N][256];
    memset(cnt, 0, sizeof cnt);
#pragma omp parallel
    {
        alea_t g;
        alea_init(&g, graine * 1000003u + (uint64_t)omp_get_thread_num());
        uint64_t (*loc)[256] = calloc(BR_N, sizeof *loc);
#pragma omp for schedule(dynamic, 1 << 14)
        for (uint64_t i = 0; i < n; i++) {
            uint64_t a[8];
            for (int k = 0; k < 8; k++) a[k] = alea64(&g);
            int e = NIB(a, q);
            if (sens == 1)
                lineaire(LD, a);                      /* pré-diffusion */
            perm_r(a, R, sens);
            if (sens == 0)
                lineaire(LI, a);                      /* alignement de la sortie */
            for (int j = 0; j < BR_N; j++)
                loc[j][16 * e + NIB(a, j)]++;
        }
#pragma omp critical
        for (int j = 0; j < BR_N; j++)
            for (int v = 0; v < 256; v++) cnt[j][v] += loc[j][v];
        free(loc);
    }
    double att = (double)n / 256, cm = 0, chi_e = 0;
    *jmax = 0;
    chi_moyen = 0;
    for (int e = 0; e < 16; e++) {                    /* marge d'entrée, commune à tous les j */
        double ne = 0;
        for (int v = 0; v < 16; v++) ne += (double)cnt[0][16 * e + v];
        chi_e += (ne - (double)n / 16) * (ne - (double)n / 16) / ((double)n / 16);
    }
    for (int j = 0; j < BR_N; j++) {
        double chi = 0;
        for (int v = 0; v < 256; v++) chi += ((double)cnt[j][v] - att) * ((double)cnt[j][v] - att) / att;
        chi_moyen += (chi - chi_e) / BR_N;
        if (chi > cm) { cm = chi; *jmax = j; }
    }
    double pr = 128 * gamma_q(127.5, cm / 2);
    *p = pr < 1 ? pr : 1;
    return cm;
}

/* type : c cube, k série de K cubes, t tronquée alignée, l linéaire alignée */
typedef struct { char type; int sens, R, voisinage, log2n, temoin, K; } exp_t;

static const char *SENS[2] = {"direct", "inverse"};

/* familles : portée connue, au-delà de laquelle tout distingueur est une nouveauté */
static int portee(char type, int sens)
{
    switch (type) {
    case 't': return sens ? 2 : 5;
    case 'l': return 1;
    default:  return sens ? 3 : 4;
    }
}

static int famille(char type, int sens)
{
    return (type == 't' ? 2 : type == 'l' ? 4 : 0) + sens;
}

int main(int argc, char **argv)
{
    double budget = argc > 1 ? atof(argv[1]) : 600, t0 = maintenant();
    resultat_t res = {.nom = "nuit_cryptanalyse", .titre = "Cryptanalyse empirique à la frontière (nuit)"};
    if (!bref_init()) return 1;
    tables();
    int ok_conf = conforme() && bref_conforme(16);
    res_controle(&res, "permutation_rapide_conforme_a_la_reference", ok_conf);
    if (!ok_conf) return res_ecrire(&res);
    /* étalonnage : coût d'une évaluation d'un tour, tous les cœurs */
    int nib_v[11], nb_v = 0;                           /* voisinage du sommet 0 (+ voisins de voisins) */
    for (int j = 0; j < BR_N && nb_v < 7; j++)
        if (BM[0][j]) nib_v[nb_v++] = j;
    for (int j = 0; j < BR_N && nb_v < 11; j++)
        if (BM[nib_v[1]][j]) {
            int deja = 0;
            for (int k = 0; k < nb_v; k++) deja |= nib_v[k] == j;
            if (!deja) nib_v[nb_v++] = j;
        }
    double te = maintenant(), c_tour[2], c_trq[2], c_lin[2];
    uint64_t acc[8];
    int jz;
    double pz;
    for (int sn = 0; sn < 2; sn++) {                  /* coûts tous cœurs, par sens : un tour, frais fixes hors tours */
        te = maintenant();
        cube(nib_v, 20, 4, sn, 1, acc);
        c_tour[sn] = (maintenant() - te) / ((double)(1 << 20) * 4);
        te = maintenant();
        tronquee(0, 1, 0, sn, 1 << 20, 3, &jz, &pz);
        c_trq[sn] = (maintenant() - te) / (1 << 20);
        te = maintenant();
        lineaire_jointe(0, 0, sn, 1 << 20, 3, &jz, &pz);
        c_lin[sn] = (maintenant() - te) / (1 << 20);
    }
    res_mesure(&res, "etalonnage_ns", "{\"tour_direct\": %.3f, \"tour_inverse\": %.3f}", 1e9 * c_tour[0], 1e9 * c_tour[1]);
    res_mesure(&res, "threads", "%d", omp_get_max_threads());
    fprintf(stderr, "étalonnage : %.2f ns par tour direct, %.2f ns par tour inverse (tous les cœurs)\n", 1e9 * c_tour[0], 1e9 * c_tour[1]);
    /* calibrage sous H0 : à 12 tours, le χ² moyen doit valoir son nombre de ddl */
    double m_t = 0, m_l = 0, pc;
    int jc;
    for (int s = 0; s < 8; s++) {
        tronquee(0, 1, 12, s & 1, 1 << 20, 900 + (uint64_t)s, &jc, &pc);
        m_t += chi_moyen / 8;
        lineaire_jointe(0, 12, s & 1, 1 << 20, 950 + (uint64_t)s, &jc, &pc);
        m_l += chi_moyen / 8;
    }
    double z_t = (m_t - 15) / sqrt(2.0 * 15 / (BR_N * 8)), z_l = (m_l - 240) / sqrt(2.0 * 240 / (BR_N * 8));
    res_mesure(&res, "calibrage_chi2_h0", "{\"tronquee\": {\"moyenne\": %.2f, \"ddl\": 15, \"z\": %.2f}, "
               "\"lineaire_hors_marge_d_entree\": {\"moyenne\": %.2f, \"ddl\": 240, \"z\": %.2f}}", m_t, z_t, m_l, z_l);
    res_controle(&res, "statistiques_chi2_calibrees_sous_h0", fabs(z_t) < 5 && fabs(z_l) < 5);
    fprintf(stderr, "calibrage H0 : tronquée %.2f (ddl 15, z = %.2f), linéaire hors marge d'entrée %.2f (ddl 240, z = %.2f)\n", m_t, z_t, m_l, z_l);
    static const exp_t E[] = {
        /* témoins, à la portée connue de chaque famille (le cube inverse à 3 tours
         * découle du degré : 3^3 = 27 < 28) */
        {'c', 0, 4, 1, 24, 1, 1}, {'c', 1, 2, 1, 16, 1, 1}, {'c', 1, 3, 1, 28, 1, 1},
        {'k', 0, 4, 1, 24, 1, 4}, {'t', 0, 4, 0, 20, 1, 0}, {'t', 0, 5, 0, 26, 1, 0}, {'t', 1, 2, 0, 26, 1, 0},
        {'l', 0, 1, 0, 24, 1, 0}, {'l', 1, 1, 0, 24, 1, 0},
        /* au-delà de la portée, à petite échelle : chaque famille est couverte même
         * par une campagne courte */
        {'t', 0, 6, 0, 26, 0, 0}, {'t', 1, 3, 0, 26, 0, 0}, {'l', 0, 2, 0, 24, 0, 0}, {'l', 1, 2, 0, 24, 0, 0},
        {'k', 0, 5, 1, 24, 0, 32}, {'k', 1, 4, 1, 24, 0, 32},
        /* séries de cubes */
        {'k', 0, 5, 1, 26, 0, 32}, {'k', 0, 5, 0, 26, 0, 32}, {'k', 1, 4, 1, 26, 0, 32}, {'k', 1, 4, 0, 26, 0, 32},
        /* tronquées et linéaires alignées à grande échelle */
        {'t', 0, 6, 0, 31, 0, 0}, {'t', 1, 3, 0, 31, 0, 0},
        {'l', 0, 2, 0, 30, 0, 0}, {'l', 1, 2, 0, 30, 0, 0}, {'l', 0, 3, 0, 30, 0, 0}, {'l', 1, 3, 0, 30, 0, 0},
        /* cube inverse à 4 tours : 227 bits nuls (z = −2,56) le 2026-10-30, à revoir */
        {'c', 1, 4, 1, 32, 0, 1},
        /* cubes simples les plus gros */
        {'c', 0, 5, 1, 36, 0, 1},
        {'c', 0, 5, 0, 34, 0, 1}, {'c', 0, 6, 1, 34, 0, 1},
        {'c', 0, 5, 0, 32, 0, 1}, {'c', 1, 4, 0, 32, 0, 1},
        {'t', 0, 6, 0, 33, 0, 0}, {'t', 1, 3, 0, 33, 0, 0},
        /* facultatives : pour les longues campagnes, sur beaucoup de cœurs ; toutes sont aussi au plan du run spécial
         * GPU (scripts/rungpu_special, tests/gpu/frontiere_gpu.cu), qui les tient en ≈ 3 h. Les cubes inverses de 2^34
         * et 2^36 en tête (repli sur 2^34 si le 2^36 n'a pas tenu) : la nuit du 2026-11-05 n'a pas pu les lancer. */
        {'c', 1, 4, 1, 36, 0, 1}, {'c', 1, 4, 1, 34, 0, 1}, {'c', 1, 5, 1, 34, 0, 1},
        {'c', 0, 5, 1, 38, 0, 1}, {'c', 0, 6, 1, 38, 0, 1}, {'c', 0, 5, 1, 40, 0, 1},
        {'k', 0, 5, 1, 28, 0, 32}, {'k', 1, 4, 1, 28, 0, 32}, {'t', 0, 6, 0, 35, 0, 0}, {'t', 1, 3, 0, 35, 0, 0},
        {'l', 0, 2, 0, 32, 0, 0}, {'l', 1, 2, 0, 32, 0, 0}, {'l', 0, 3, 0, 32, 0, 0},
        {'c', 1, 4, 1, 38, 0, 1}, {'c', 0, 6, 1, 40, 0, 1}, {'c', 0, 5, 0, 38, 0, 1}, {'c', 0, 5, 1, 42, 0, 1},
    };
    enum { nb_facultatives = 20 };                     /* faute de temps, elles ne rendent pas la campagne incomplète */
    int ne = (int)(sizeof E / sizeof *E), temoins_ok = 1, faits = 0, nouveaux = 0;
    int couvert[6] = {0}, max_t[6] = {0}, inv36 = 0;
    static char liste[24000] = "[", tmp[24100];
    for (int x = 0; x < ne; x++) {
        const exp_t *e = &E[x];
        double evals = pow(2.0, e->log2n), est = 0;
        switch (e->type) {
        case 'c': est = evals * e->R * c_tour[e->sens]; break;
        case 'k': est = evals * e->R * e->K * c_tour[e->sens]; break;
        case 't': est = evals * (2 * e->R * c_tour[e->sens] + c_trq[e->sens]); break;
        case 'l': est = evals * (e->R * c_tour[e->sens] + c_lin[e->sens]); break;
        }
        double reste = budget - (maintenant() - t0);
        char ligne[800];
        if (e->type == 'c' && e->sens == 1 && e->R == 4 && e->voisinage && e->log2n == 34 && inv36) continue;
        if (est > reste && !e->temoin) {
            snprintf(ligne, sizeof ligne, "%s{\"type\": \"%c\", \"sens\": \"%s\", \"tours\": %d, \"log2\": %d, "
                     "\"nibbles\": \"%s\", \"statut\": \"%s (budget : %.0f s estimés, %.0f s restants)\"}", faits ? ", " : "",
                     e->type, SENS[e->sens], e->R, e->log2n, e->voisinage ? "voisinage" : "hasard",
                     x >= ne - nb_facultatives ? "facultative, pas assez de temps, couverte par scripts/rungpu_special" : "non lancé",
                     est, reste);
            strcat(liste, ligne);
            faits++;
            continue;
        }
        double ts = maintenant();
        int distingue = 0;
        char corps[300];
        if (e->type == 'c' || e->type == 'k') {
            int nib[11], K = e->type == 'k' ? e->K : 1, cpt[512] = {0}, tot = 0;
            alea_t g;
            alea_init(&g, 77 + (uint64_t)x);
            for (int k = 0; k < 11; k++) {
                if (e->voisinage) nib[k] = nib_v[k];
                else {
                    int ok, v;
                    do {
                        v = (int)alea_borne(&g, BR_N);
                        ok = 1;
                        for (int l = 0; l < k; l++) ok &= nib[l] != v;
                    } while (!ok);
                    nib[k] = v;
                }
            }
            for (int c = 0; c < K; c++) {
                cube(nib, e->log2n, e->R, e->sens, 1000 + (uint64_t)x * 1000 + (uint64_t)c, acc);
                tot += bits_nuls(acc);
                for (int b = 0; b < 512; b++)
                    cpt[b] += !((acc[b >> 6] >> (b & 63)) & 1);
            }
            int ext = 0;                              /* bit le plus déséquilibré : écart à K/2 */
            for (int b = 0; b < 512; b++) {
                int dv = 2 * cpt[b] - K;
                if (dv < 0) dv = -dv;
                if (dv > ext) ext = dv;
            }
            double z = (tot - 256.0 * K) / sqrt(128.0 * K);
            /* probabilité binomiale de l'extrême (Bonferroni 512), K ≥ 32 seulement */
            double pb = 1;
            if (K >= 32) {
                double s = 0;
                int k0 = (K + ext) / 2;
                for (int i = k0; i <= K; i++)
                    s += exp(lgamma(K + 1.0) - lgamma(i + 1.0) - lgamma(K - i + 1.0) - K * log(2.0));
                pb = 2 * 512 * s;
                if (pb > 1) pb = 1;
            }
            distingue = tot == 512 * K || fabs(z) > 6 || pb < 1e-6;
            snprintf(corps, sizeof corps, "\"nibbles\": \"%s\", \"cubes\": %d, \"bits_somme_nulle\": %d, \"z\": %.2f, "
                     "\"ecart_bit_max\": %d, \"p_bit\": %.2g", e->voisinage ? "voisinage" : "hasard", K, tot, z, ext, pb);
            fprintf(stderr, "cube %s R=%d 2^%d ×%d %s : %d bits nuls (z = %.2f, écart bit %d)%s\n", SENS[e->sens], e->R,
                    e->log2n, K, e->voisinage ? "voisinage" : "hasard", tot, z, ext, distingue ? " DISTINGUÉ" : "");
        } else {
            int jm;
            double p, chi = e->type == 't'
                ? tronquee(0, 1, e->R, e->sens, 1ULL << e->log2n, 500 + (uint64_t)x, &jm, &p)
                : lineaire_jointe(0, e->R, e->sens, 1ULL << e->log2n, 500 + (uint64_t)x, &jm, &p);
            distingue = p < 1e-6;
            snprintf(corps, sizeof corps, "\"chi2_max\": %.1f, \"nibble\": %d, \"p\": %.2g", chi, jm, p);
            fprintf(stderr, "%s %s R=%d 2^%d : χ²max = %.1f, p = %.2g%s\n", e->type == 't' ? "tronquée" : "linéaire",
                    SENS[e->sens], e->R, e->log2n, chi, p, distingue ? " DISTINGUÉ" : "");
        }
        snprintf(ligne, sizeof ligne, "%s{\"type\": \"%c\", \"sens\": \"%s\", \"tours\": %d, \"log2\": %d, %s, "
                 "\"distingue\": %s, \"temoin\": %s, \"duree_s\": %.0f}", faits ? ", " : "", e->type, SENS[e->sens], e->R,
                 e->log2n, corps, distingue ? "true" : "false", e->temoin ? "true" : "false", maintenant() - ts);
        int f = famille(e->type, e->sens);
        if (e->type == 'c' && e->sens == 1 && e->R == 4 && e->voisinage && e->log2n == 36) inv36 = 1;
        if (e->temoin) temoins_ok &= distingue;
        else {
            if (e->R > portee(e->type, e->sens)) couvert[f] = 1;
            if (distingue) { nouveaux++; if (e->R > max_t[f]) max_t[f] = e->R; }
        }
        strcat(liste, ligne);
        faits++;
        /* point de sauvegarde */
        resultat_t cp = res;
        snprintf(tmp, sizeof tmp, "%s]", liste);
        res_mesure(&cp, "experiences", "%s", tmp);
        res_mesure(&cp, "en_cours", "\"%d/%d\"", x + 1, ne);
        res_ecrire(&cp);
    }
    strcat(liste, "]");
    res_mesure(&res, "experiences", "%s", liste);
    res_mesure(&res, "distingueurs_au_dela_de_la_portee", "{\"cube_direct\": %d, \"cube_inverse\": %d, "
               "\"tronquee_direct\": %d, \"tronquee_inverse\": %d, \"lineaire_direct\": %d, \"lineaire_inverse\": %d}",
               max_t[0], max_t[1], max_t[2], max_t[3], max_t[4], max_t[5]);
    res_mesure(&res, "duree_s", "%.0f", maintenant() - t0);
    res_controle(&res, "temoins_positifs_detectes", temoins_ok);
    int tous = 1;
    for (int f = 0; f < 6; f++) tous &= couvert[f];
    /* une portée non testée n'a rien à dire : les deux contrôles vont ensemble */
    res_controle(&res, "chaque_famille_testee_au_dela_de_sa_portee_connue", tous);
    res_controle(&res, "aucun_distingueur_au_dela_de_la_portee_connue", nouveaux == 0);
    return res_ecrire(&res);
}
