/* Cryptanalyse de BRUME-512 : ce que la batterie ne couvrait pas encore.
 *
 *  1. S-box : DDT, LAT, BCT (boomerang), DLCT (différentiel-linéaire), exhaustifs.
 *  2. Boomerang réel sur R tours : x, x ⊕ α ; y ⊕ δ ; retour P⁻¹ ; on compte, nibble par nibble, les
 *     différences nulles au retour (1/16 pour une permutation aléatoire). α d'un nibble, et δ = M·(un nibble) :
 *     P⁻¹ commence par M⁻¹, dense, et un δ d'un seul nibble activerait d'emblée plus de 100 S-box.
 *     Le seuil tient compte du nombre de tests (Bonferroni).
 *  3. Différentielles impossibles et corrélations nulles par ENSEMBLES de valeurs : par nibble, l'ensemble
 *     des différences (masques) possibles, propagé par la DDT (LAT) et les vrais coefficients de GF(16).
 *     C'est plus fin que l'activité (tests/c/structure_miss.c), qui ignore la valeur des coefficients.
 *     Propagation sûre : les corrélations entre nibbles sont oubliées, chaque ensemble est un sur-ensemble.
 *     Contrôle : des différences réelles restent dans les ensembles prédits.
 *     build/brume_attaques [log2_quartets] [combinaisons] [seed] [taille_famille]
 *     Produit resultats/brume_attaques.json et resultats/brume_attaques_boomerang_raw.csv.
 *
 *     La campagne boomerang est limitée à RB tours. Aucun contrôle ne prétend
 *     en déduire la sécurité de la permutation 32 tours.
 */
#include <errno.h>
#include <immintrin.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <omp.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brume_ref.h"
#include "resultat.h"

#define RB 8                                   /* boomerang : 1 … RB tours */
#define RS 7                                   /* ensembles : au plus RS tours par sens */

static alignas(64) uint64_t LIN_F[BR_N][16][8], LIN_I[BR_N][16][8];

static void tables_rapides(void)
{
    memset(LIN_F, 0, sizeof LIN_F);
    memset(LIN_I, 0, sizeof LIN_I);
    for (int j = 0; j < BR_N; j++)
        for (int x = 0; x < 16; x++)
            for (int v = 0; v < BR_N; v++) {
                LIN_F[j][x][v >> 4] |= (uint64_t)gf_mul(BM[v][j], (uint8_t)x) << (4 * (v & 15));
                LIN_I[j][x][v >> 4] |= (uint64_t)gf_mul(BMI[v][j], (uint8_t)x) << (4 * (v & 15));
            }
}

#ifdef __AVX2__
/* S-box par vpshufb, somme des lignes de table par registres, dépaquetage en nibbles : ×2,5 sur un tour */
static inline void lin(const uint64_t T[BR_N][16][8], uint8_t *s)
{
    __m256i a = _mm256_setzero_si256(), b = a;
    for (int j = 0; j < BR_N; j++) {
        const __m256i *l = (const __m256i *)T[j][s[j]];
        a = _mm256_xor_si256(a, _mm256_load_si256(l));
        b = _mm256_xor_si256(b, _mm256_load_si256(l + 1));
    }
    const __m256i m = _mm256_set1_epi16(0x000f);
    __m128i q[4] = {_mm256_castsi256_si128(a), _mm256_extracti128_si256(a, 1), _mm256_castsi256_si128(b), _mm256_extracti128_si256(b, 1)};
    for (int i = 0; i < 4; i++) {
        __m256i w = _mm256_cvtepu8_epi16(q[i]);
        w = _mm256_or_si256(_mm256_and_si256(w, m), _mm256_slli_epi16(_mm256_and_si256(_mm256_srli_epi16(w, 4), m), 8));
        _mm256_storeu_si256((__m256i *)(s + 32 * i), w);
    }
}

static inline void couche_s(uint8_t *s, const uint8_t *table, const uint8_t *rc, int rc_avant)
{
    const __m256i t = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)table));
    for (int i = 0; i < 4; i++) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(s + 32 * i)), c = _mm256_loadu_si256((const __m256i *)(rc + 32 * i));
        v = rc_avant ? _mm256_shuffle_epi8(t, _mm256_xor_si256(v, c)) : _mm256_xor_si256(_mm256_shuffle_epi8(t, v), c);
        _mm256_storeu_si256((__m256i *)(s + 32 * i), v);
    }
}
#else
static inline void lin(const uint64_t T[BR_N][16][8], uint8_t *s)
{
    uint64_t a[8] = {0};
    for (int j = 0; j < BR_N; j++)
        for (int k = 0; k < 8; k++)
            a[k] ^= T[j][s[j]][k];
    for (int v = 0; v < BR_N; v++)
        s[v] = (a[v >> 4] >> (4 * (v & 15))) & 15;
}

static inline void couche_s(uint8_t *s, const uint8_t *table, const uint8_t *rc, int rc_avant)
{
    for (int j = 0; j < BR_N; j++)
        s[j] = rc_avant ? table[s[j] ^ rc[j]] : table[s[j]] ^ rc[j];
}
#endif

static inline void dir(uint8_t *s, int R)
{
    for (int t = 0; t < R; t++) {
        couche_s(s, BR_SBOX, BR_RC[t], 1);
        lin(LIN_F, s);
    }
}

static inline void inv(uint8_t *s, int R)
{
    for (int t = R - 1; t >= 0; t--) {
        lin(LIN_I, s);
        couche_s(s, BSI, BR_RC[t], 0);
    }
}

static inline uint64_t suiv(uint64_t *g)
{
    uint64_t z = (*g += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static inline void alea(uint8_t *s, uint64_t *g)
{
    /* Un mot SplitMix64 fournit exactement 16 nibbles indépendants en sortie
     * (au sens de la permutation de bits du générateur). Aucun mot généré
     * n'est écrasé ou sauté entre deux blocs.
     */
    for (int base = 0; base < BR_N; base += 16) {
        uint64_t z = suiv(g);
        for (int k = 0; k < 16; k++)
            s[base + k] = (uint8_t)((z >> (4 * k)) & 15u);
    }
}

/* ---------------- S-box ---------------- */

static int DDT[16][16], LAT[16][16];

static void sbox_tables(resultat_t *res)
{
    memset(DDT, 0, sizeof DDT);
    int pire_ddt = 0, pire_lat = 0, pire_bct = 0, pire_dl = 0, bct_tot = 0;
    for (int a = 0; a < 16; a++)
        for (int x = 0; x < 16; x++)
            DDT[a][BR_SBOX[x] ^ BR_SBOX[x ^ a]]++;
    for (int u = 0; u < 16; u++)
        for (int v = 0; v < 16; v++) {
            int s = 0;
            for (int x = 0; x < 16; x++)
                s += (__builtin_parity((unsigned)(u & x)) ^ __builtin_parity((unsigned)(v & BR_SBOX[x]))) ? -1 : 1;
            LAT[u][v] = s;
            if (u && v && abs(s) > pire_lat)
                pire_lat = abs(s);
        }
    for (int a = 1; a < 16; a++)
        for (int b = 1; b < 16; b++) {
            int n = 0, d = 0;
            for (int x = 0; x < 16; x++)
                n += (BSI[BR_SBOX[x] ^ b] ^ BSI[BR_SBOX[x ^ a] ^ b]) == a;
            if (DDT[a][b] > pire_ddt)
                pire_ddt = DDT[a][b];
            if (n > pire_bct)
                pire_bct = n;
            bct_tot += n;
            for (int x = 0; x < 16; x++)
                d += __builtin_parity((unsigned)(b & (BR_SBOX[x] ^ BR_SBOX[x ^ a]))) ? -1 : 1;
            if (abs(d) > pire_dl)
                pire_dl = abs(d);
        }
    res_mesure(res, "sbox", "{\"ddt_max\": %d, \"lat_max\": %d, \"bct_max\": %d, \"bct_moyenne\": %.2f, \"dlct_max\": %d}",
               pire_ddt, pire_lat, pire_bct, bct_tot / 225.0, pire_dl);
    res_controle(res, "sbox_ddt_lat_optimales", pire_ddt == 4 && pire_lat == 8);
    /* BCT ≥ DDT ; 16 serait un passage gratuit au milieu du boomerang (DDT² vaudrait au mieux 1/16 ici) */
    res_controle(res, "sbox_bct_ni_triviale_ni_sous_la_ddt", pire_bct >= pire_ddt && pire_bct < 16);
    res_controle(res, "sbox_dlct_au_plus_8", pire_dl <= 8);
}

/* ---------------- boomerang ---------------- */

static double seuil_z(double tests)
{
    /* Seuil bilatéral : P(|Z| > z) = erfc(z/sqrt(2)).
     * La correction de Bonferroni porte sur toutes les combinaisons, tous les
     * nibbles observés, tous les tours testés et toutes les S-boxes comparées.
     * La probabilité familiale visée est <= 1/1024.
     */
    if (!(tests > 0.0))
        return INFINITY;
    const double target = 1.0 / (tests * 1024.0);
    double low = 0.0, high = 12.0;
    for (int k = 0; k < 80; k++) {
        double mid = (low + high) / 2.0;
        if (erfc(mid / sqrt(2.0)) > target)
            low = mid;
        else
            high = mid;
    }
    return high;
}

static void boomerang(resultat_t *res, int lq, int nc,
                      uint64_t seed_base, int family_size)
{
    const int64_t n = INT64_C(1) << lq;
    const int threads = omp_get_max_threads();
    const double tests_family = (double)nc * (double)BR_N * (double)RB
                                * (double)family_size;
    const double seuil = seuil_z(tests_family);
    int significant[RB + 1] = {0};
    int controle_r1 = 0;
    uint64_t exact_total[RB + 1] = {0};
    double zmax_round[RB + 1] = {0};
    int zmax_combination[RB + 1] = {-1};
    int zmax_nibble[RB + 1] = {-1};

    FILE *raw = fopen("resultats/brume_attaques_boomerang_raw.csv", "w");
    int raw_ok = raw != NULL;
    if (raw) {
        fprintf(raw,
                "round,combination,input_nibble,alpha,delta_source_nibble,delta_value,"
                "output_nibble,zero_count,quartets,exact_returns,threads,"
                "combination_seed,seed_base,family_size\n");
    } else {
        fprintf(stderr,
                "AVERTISSEMENT: impossible d'ouvrir resultats/brume_attaques_boomerang_raw.csv\n");
    }

    for (int R = 1; R <= RB; R++) {
        uint64_t retours_exacts = 0;
        double zmax = 0.0;
        int depasse = 0;

        for (int c = 0; c < nc; c++) {
            uint64_t gc = seed_base + (uint64_t)c * UINT64_C(1000) + (uint64_t)R;
            const int i = (int)(suiv(&gc) % BR_N);
            const int j = (int)(suiv(&gc) % BR_N);
            const uint8_t al = (uint8_t)(1 + suiv(&gc) % 15);
            const uint8_t de = (uint8_t)(1 + suiv(&gc) % 15);
            const uint64_t combination_seed = gc;

            uint8_t delta[BR_N];
            for (int v = 0; v < BR_N; v++)
                delta[v] = gf_mul(BM[v][j], de);

            uint64_t cpt[BR_N] = {0};
            uint64_t exacts = 0;

#pragma omp parallel
            {
                const uint64_t thread_id = (uint64_t)omp_get_thread_num();
                uint64_t g[2] = {
                    combination_seed ^ (thread_id * UINT64_C(0x9e3779b97f4a7c15)),
                    0
                };
                uint64_t local[BR_N] = {0};
                uint64_t exact_local = 0;
                uint8_t x[BR_N], y[BR_N];

#pragma omp for schedule(static)
                for (int64_t q = 0; q < n; q++) {
                    alea(x, g);
                    memcpy(y, x, BR_N);
                    y[i] ^= al;

                    dir(x, R);
                    dir(y, R);
                    for (int v = 0; v < BR_N; v++) {
                        x[v] ^= delta[v];
                        y[v] ^= delta[v];
                    }
                    inv(x, R);
                    inv(y, R);

                    int exact = 1;
                    for (int v = 0; v < BR_N; v++) {
                        const uint8_t dv = (uint8_t)(x[v] ^ y[v]);
                        local[v] += (uint64_t)(dv == 0);
                        exact &= (dv == (v == i ? al : 0));
                    }
                    exact_local += (uint64_t)exact;
                }

#pragma omp critical
                {
                    for (int v = 0; v < BR_N; v++)
                        cpt[v] += local[v];
                    exacts += exact_local;
                }
            }

            retours_exacts += exacts;
            for (int v = 0; v < BR_N; v++) {
                /* Sous le modèle permutation aléatoire, la probabilité
                 * marginale d'égalité d'un nibble est approximée par 1/16.
                 */
                const double expected = (double)n / 16.0;
                const double variance = (double)n * 15.0 / 256.0;
                const double z = ((double)cpt[v] - expected) / sqrt(variance);
                const double abs_z = fabs(z);
                if (abs_z > zmax) {
                    zmax = abs_z;
                    zmax_combination[R] = c;
                    zmax_nibble[R] = v;
                }
                if (abs_z > seuil)
                    depasse = 1;

                if (raw) {
                    fprintf(raw,
                            "%d,%d,%d,%u,%d,%u,%d,%" PRIu64 ",%" PRId64 ",%" PRIu64 ",%d,%" PRIu64 ",%" PRIu64 ",%d\n",
                            R, c, i, (unsigned)al, j, (unsigned)de, v,
                            cpt[v], n, exacts, threads, combination_seed,
                            seed_base, family_size);
                }
            }
        }

        exact_total[R] = retours_exacts;
        zmax_round[R] = zmax;
        significant[R] = depasse;
        if (R == 1)
            controle_r1 = depasse;
    }

    if (raw) {
        if (fclose(raw) != 0) {
            raw_ok = 0;
            fprintf(stderr, "AVERTISSEMENT: erreur lors de la fermeture du CSV brut\n");
        }
    }

    /* Résultats par profondeur. Le maximum est corrigé sur la famille entière. */
    char tours_json[4096];
    size_t used = 0;
    used += (size_t)snprintf(tours_json + used, sizeof tours_json - used, "[");
    for (int R = 1; R <= RB; R++) {
        const int written = snprintf(
            tours_json + used, sizeof tours_json - used,
            "%s{\"tours\":%d,\"z_max\":%.6f,\"combinaison_max\":%d,"
            "\"nibble_max\":%d,\"significatif\":%s,\"retours_exacts\":%" PRIu64 "}",
            R == 1 ? "" : ",", R, zmax_round[R],
            zmax_combination[R], zmax_nibble[R],
            significant[R] ? "true" : "false", exact_total[R]);
        if (written < 0 || (size_t)written >= sizeof tours_json - used) {
            if (raw_ok)
                res_controle(res, "boomerang_csv_brut_ecrit", 1);
            fprintf(stderr, "Erreur: buffer JSON boomerang trop petit\n");
            return;
        }
        used += (size_t)written;
    }
    if (used + 2 >= sizeof tours_json) {
        fprintf(stderr, "Erreur: buffer JSON boomerang trop petit\n");
        return;
    }
    tours_json[used++] = ']';
    tours_json[used] = '\0';

    char significant_json[256];
    size_t sig_used = 0;
    sig_used += (size_t)snprintf(significant_json + sig_used,
                                 sizeof significant_json - sig_used, "[");
    int first = 1;
    for (int R = 1; R <= RB; R++) {
        if (significant[R]) {
            const int written = snprintf(significant_json + sig_used,
                                         sizeof significant_json - sig_used,
                                         "%s%d", first ? "" : ",", R);
            if (written > 0 && (size_t)written < sizeof significant_json - sig_used) {
                sig_used += (size_t)written;
                first = 0;
            }
        }
    }
    snprintf(significant_json + sig_used,
             sizeof significant_json - sig_used, "]");

    res_mesure(res, "boomerang_par_tours", "%s", tours_json);
    res_mesure(res, "boomerang",
               "{\"quartets_par_combinaison\":%" PRId64 ","
               "\"combinaisons_par_tour\":%d,\"tours_testes\":%d,"
               "\"tests_famille\":%.0f,\"taille_famille\":%d,"
               "\"seuil_z_bilateral_bonferroni\":%.6f,"
               "\"probabilite_familiale_cible\":%.10f,"
               "\"tours_significatifs\":%s,\"threads_max\":%d,"
               "\"seed_base\":%" PRIu64 ",\"raw_csv\":"
               "\"resultats/brume_attaques_boomerang_raw.csv\"}",
               n, nc, RB, tests_family, family_size, seuil, 1.0 / 1024.0,
               significant_json, threads, seed_base);

    res_controle(res, "boomerang_temoin_detecte_a_1_tour", controle_r1);
    res_controle(res, "boomerang_csv_brut_ecrit", raw_ok);
    /* Aucune conclusion sur 32 tours : seuls les tours 1..RB sont mesurés. */
}

/* ---------------- impossibles par ensembles ---------------- */

typedef struct { uint16_t e[BR_N]; } ens_t;

static uint8_t ADJ[16][16];                     /* ADJ[c][u] : adjoint binaire de x ↦ c·x appliqué au masque u */

static inline uint16_t sumset(uint16_t a, uint16_t b)
{
    uint16_t r = 0;
    for (int x = 0; x < 16; x++)
        if (a >> x & 1)
            for (int y = 0; y < 16; y++)
                if (b >> y & 1)
                    r |= (uint16_t)(1u << (x ^ y));
    return r;
}

static inline uint16_t image(uint16_t a, const uint8_t c_table[16])
{
    uint16_t r = 0;
    for (int x = 0; x < 16; x++)
        if (a >> x & 1)
            r |= (uint16_t)(1u << c_table[x]);
    return r;
}

/* out_v = ⊕_i T[v][i]·in_i, avec T[v][i][x] la valeur transformée */
static ens_t etape_lin(ens_t a, uint8_t T[BR_N][BR_N][16])
{
    ens_t b;
    for (int v = 0; v < BR_N; v++) {
        uint16_t acc = 1;                       /* {0} */
        for (int i = 0; i < BR_N && acc != 0xFFFF; i++)
            if (T[v][i][1] || T[v][i][2] || T[v][i][4] || T[v][i][8]) {
                if (a.e[i] == 1)
                    continue;
                acc = sumset(acc, image(a.e[i], T[v][i]));
            }
        b.e[v] = acc;
    }
    return b;
}

static ens_t etape_s(ens_t a, const uint16_t Rl[16])
{
    ens_t b;
    for (int v = 0; v < BR_N; v++) {
        uint16_t r = 0;
        for (int x = 0; x < 16; x++)
            if (a.e[v] >> x & 1)
                r |= Rl[x];
        b.e[v] = r;
    }
    return b;
}

static uint8_t T_F[BR_N][BR_N][16], T_I[BR_N][BR_N][16], T_FT[BR_N][BR_N][16], T_IT[BR_N][BR_N][16];
static uint16_t R_DDT[16], R_DDT_I[16], R_LAT[16], R_LAT_I[16];

static void preparer_ensembles(void)
{
    for (int c = 0; c < 16; c++)
        for (int u = 0; u < 16; u++) {
            /* u·(c·x) = u'·x pour tout x */
            int up = 0;
            for (int b = 0; b < 4; b++)
                if (__builtin_parity((unsigned)(u & gf_mul((uint8_t)c, (uint8_t)(1 << b)))))
                    up |= 1 << b;
            ADJ[c][u] = (uint8_t)up;
        }
    for (int v = 0; v < BR_N; v++)
        for (int i = 0; i < BR_N; i++)
            for (int x = 0; x < 16; x++) {
                T_F[v][i][x] = gf_mul(BM[v][i], (uint8_t)x);
                T_I[v][i][x] = gf_mul(BMI[v][i], (uint8_t)x);
                /* masques : u_x[i] = ⊕_v (c_vi)ᵀ u_y[v] pour y = Mx (Mᵀ, sens arrière) ;
                 * en avant : u_y = (M⁻¹)ᵀ u_x */
                T_FT[v][i][x] = ADJ[BM[i][v]][x];
                T_IT[v][i][x] = ADJ[BMI[i][v]][x];
            }
    memset(R_DDT, 0, sizeof R_DDT);
    memset(R_DDT_I, 0, sizeof R_DDT_I);
    memset(R_LAT, 0, sizeof R_LAT);
    memset(R_LAT_I, 0, sizeof R_LAT_I);
    for (int a = 0; a < 16; a++)
        for (int b = 0; b < 16; b++) {
            if (DDT[a][b]) {
                R_DDT[a] |= (uint16_t)(1u << b);
                R_DDT_I[b] |= (uint16_t)(1u << a);
            }
            if (LAT[a][b]) {
                R_LAT[a] |= (uint16_t)(1u << b);
                R_LAT_I[b] |= (uint16_t)(1u << a);
            }
        }
}

static inline int disjoints(const ens_t *a, const ens_t *b)
{
    for (int v = 0; v < BR_N; v++)
        if (!(a->e[v] & b->e[v]))
            return 1;
    return 0;
}

static ens_t singleton(int pos, int val)
{
    ens_t e;
    for (int v = 0; v < BR_N; v++)
        e.e[v] = 1;
    e.e[pos] = (uint16_t)(1u << val);
    return e;
}

/* Portée par R = r1 + r2 : avant[r1] (après S puis lin, r1 fois) contre arriere[r2] */
static int recherche(ens_t (*av)[RS + 1], ens_t (*ar)[RS + 1], int ne, int *r1m, int *comptes)
{
    int best = 0;
    *r1m = 0;
    for (int r1 = 0; r1 <= RS; r1++)
        for (int r2 = 0; r2 <= RS; r2++) {
            if (r1 + r2 < 1)
                continue;
            int trouve = 0;
#pragma omp parallel for schedule(dynamic, 8) reduction(+ : trouve)
            for (int a = 0; a < ne; a++)
                for (int b = 0; b < ne; b++)
                    trouve += disjoints(&av[a][r1], &ar[b][r2]);
            if (trouve && r1 + r2 > best) {
                best = r1 + r2;
                *r1m = r1;
            }
            if (r1 + r2 <= RS)
                comptes[r1 + r2] += trouve;
        }
    return best;
}

static void impossibles(resultat_t *res)
{
    preparer_ensembles();
    int ne = BR_N * 15;
    ens_t (*av)[RS + 1] = malloc(sizeof(ens_t) * (RS + 1) * (size_t)ne), (*ar)[RS + 1] = malloc(sizeof(ens_t) * (RS + 1) * (size_t)ne);
    /* différences : avant = S puis M ; arrière = M⁻¹ puis S⁻¹ (DDT) */
#pragma omp parallel for schedule(dynamic, 16)
    for (int k = 0; k < ne; k++) {
        ens_t a = singleton(k / 15, k % 15 + 1), b = a;
        av[k][0] = a;
        ar[k][0] = b;
        for (int r = 1; r <= RS; r++) {
            a = etape_lin(etape_s(a, R_DDT), T_F);
            b = etape_s(etape_lin(b, T_I), R_DDT_I);
            av[k][r] = a;
            ar[k][r] = b;
        }
    }
    /* solidité : des différences réelles restent dans les ensembles */
    uint64_t viol = 0, tests = 0;
#pragma omp parallel for schedule(dynamic, 8) reduction(+ : viol, tests)
    for (int k = 0; k < ne; k += 7) {
        uint64_t g[2] = {(uint64_t)k * 77 + 1, 0};
        uint8_t x[BR_N], y[BR_N];
        for (int e = 0; e < 40; e++) {
            alea(x, g);
            memcpy(y, x, BR_N);
            y[k / 15] ^= (uint8_t)(k % 15 + 1);
            for (int r = 1; r <= RS; r++) {
                for (int j = 0; j < BR_N; j++) {
                    x[j] = BR_SBOX[x[j] ^ BR_RC[r - 1][j]];
                    y[j] = BR_SBOX[y[j] ^ BR_RC[r - 1][j]];
                }
                lin(LIN_F, x);
                lin(LIN_F, y);
                for (int v = 0; v < BR_N; v++) {
                    tests++;
                    viol += !(av[k][r].e[v] >> (x[v] ^ y[v]) & 1);
                }
            }
        }
    }
    int cd[2 * RS + 2] = {0}, r1d, rd = recherche(av, ar, ne, &r1d, cd);
    res_mesure(res, "impossibles_solidite", "{\"tests\": %llu, \"violations\": %llu}", (unsigned long long)tests, (unsigned long long)viol);
    res_controle(res, "ensembles_contiennent_les_differences_reelles", viol == 0 && tests > 0);
    /* corrélations nulles : avant = (LAT) puis (M⁻¹)ᵀ ; arrière = Mᵀ puis LAT⁻¹ */
#pragma omp parallel for schedule(dynamic, 16)
    for (int k = 0; k < ne; k++) {
        ens_t a = singleton(k / 15, k % 15 + 1), b = a;
        av[k][0] = a;
        ar[k][0] = b;
        for (int r = 1; r <= RS; r++) {
            a = etape_lin(etape_s(a, R_LAT), T_IT);
            b = etape_s(etape_lin(b, T_FT), R_LAT_I);
            av[k][r] = a;
            ar[k][r] = b;
        }
    }
    int cl[2 * RS + 2] = {0}, r1l, rl = recherche(av, ar, ne, &r1l, cl);
    res_mesure(res, "ensembles_par_valeurs", "{\"differentielle_impossible_tours\": %d, \"coupure\": %d, \"correlation_nulle_tours\": %d, \"coupure_lineaire\": %d, \"motifs\": \"1 nibble, 15 valeurs\", \"max_tours_par_sens\": %d, \"max_tours_total_testes\": %d, \"paires_par_tour_diff\": [%d, %d, %d, %d, %d, %d, %d]}",
               rd, r1d, rl, r1l, RS, 2 * RS,
               cd[1], cd[2], cd[3], cd[4], cd[5], cd[6], cd[7]);
    /* Les recherches par ensembles sont limitées à RS tours par sens (2*RS au total). */
    free(av);
    free(ar);
}

static int parse_positive_long(const char *text, long min_value, long max_value,
                               long *out)
{
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || end == text || *end != '\0' || value < min_value || value > max_value)
        return 0;
    *out = value;
    return 1;
}

static int parse_u64(const char *text, uint64_t *out)
{
    if (!text || text[0] == '-')
        return 0;
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 0);
    if (errno || end == text || *end != '\0')
        return 0;
    *out = (uint64_t)value;
    return 1;
}

int main(int argc, char **argv)
{
    long lq_long = 20, nc_long = 16, family_long = 3;
    uint64_t seed_base = UINT64_C(0xB00);

    if (argc > 5) {
        fprintf(stderr,
                "Usage: %s [log2_quartets 1..60] [combinaisons >0] [seed] [taille_famille >0]\n",
                argv[0]);
        return 2;
    }

    if (argc > 1 && !parse_positive_long(argv[1], 1, 60, &lq_long)) {
        fprintf(stderr, "log2_quartets doit être compris entre 1 et 60\n");
        return 2;
    }

    if (argc > 2 && !parse_positive_long(argv[2], 1, 1000000, &nc_long)) {
        fprintf(stderr, "combinaisons doit être compris entre 1 et 1000000\n");
        return 2;
    }

    if (argc > 3 && !parse_u64(argv[3], &seed_base)) {
        fprintf(stderr, "seed invalide (utiliser un entier décimal ou 0x...)\n");
        return 2;
    }

    if (argc > 4 && !parse_positive_long(argv[4], 1, 1000000, &family_long)) {
        fprintf(stderr, "taille_famille doit être compris entre 1 et 1000000\n");
        return 2;
    }

    const int lq = (int)lq_long;
    const int nc = (int)nc_long;
    const int family_size = (int)family_long;

    resultat_t res = {
        .nom = "brume_attaques",
        .titre = NULL
    };

    if (!bref_init())
        return 1;

    res_controle(
        &res,
        "reference_nibbles_conforme_a_sl_brume_permute",
        bref_conforme(16)
    );

    tables_rapides();

    {
        uint8_t x[BR_N], y[BR_N];
        uint64_t g[2] = {42, 0};

        alea(x, g);
        memcpy(y, x, BR_N);

        dir(x, 5);
        bref_perm(y, 5, 0);

        const int ok = !memcmp(x, y, BR_N);

        inv(x, 5);

        for (int t = 4; t >= 0; t--)
            bref_tour_inv(y, t);

        res_controle(
            &res,
            "tables_rapides_conformes",
            ok && !memcmp(x, y, BR_N)
        );
    }

    sbox_tables(&res);

    boomerang(&res, lq, nc, seed_base, family_size);

    impossibles(&res);

    return res_ecrire(&res);
}
