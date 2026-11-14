/* Différentielles impossibles et corrélations nulles (miss-in-the-middle) au niveau des nibbles, À LARGEUR
 * PARAMÉTRÉE : même code que tests/c/structure_miss.c (BRUME-512), compilé avec -DB1024 pour BRUME-1024
 * (prototypes/brume_q/b1024), afin de comparer les portées à méthode identique (WIDTH_ANALYSIS.md, critère 3).
 * Propagation tronquée sûre (0 / non nul / inconnu), motifs d'entrée et de sortie de poids 1 et 2, contrôle de
 * solidité sur des différences réelles (1 à 4 tours, deux sens).
 *   cc -O3 -march=native -fopenmp [-DB1024] -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/largeur/miss_largeur.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm
 */
#include <omp.h>

#include "brume_ref.h"
#include "resultat.h"

#ifdef B1024
#include "b1024_tables.h"
#define NL 256
static uint8_t XM[NL][NL], XMI[NL][NL];
static int init_l(void)
{
    memset(XM, 0, sizeof XM);
    for (int v = 0; v < NL; v++) {
        XM[v][v] = B1_CS[v];
        for (int g = 0; g < 6; g++) {
            int i = v % 128, f = v / 128, k = B1_K[g];
            XM[v][f == 0 ? (i + k) % 128 + 128 : ((i - k) % 128 + 128) % 128] = B1_CG[g][v];
        }
    }
    static uint8_t T[NL][2 * NL];
    for (int i = 0; i < NL; i++)
        for (int j = 0; j < 2 * NL; j++)
            T[i][j] = j < NL ? XM[i][j] : (j - NL == i);
    for (int c = 0; c < NL; c++) {
        int p = c;
        while (p < NL && !T[p][c]) p++;
        if (p == NL) return 0;
        if (p != c) for (int j = 0; j < 2 * NL; j++) { uint8_t t = T[p][j]; T[p][j] = T[c][j]; T[c][j] = t; }
        uint8_t iv = gf_inv(T[c][c]);
        for (int j = 0; j < 2 * NL; j++) T[c][j] = gf_mul(T[c][j], iv);
        for (int i = 0; i < NL; i++)
            if (i != c && T[i][c]) { uint8_t f = T[i][c]; for (int j = 0; j < 2 * NL; j++) T[i][j] ^= gf_mul(f, T[c][j]); }
    }
    for (int i = 0; i < NL; i++) memcpy(XMI[i], T[i] + NL, NL);
    return 1;
}
#define RCL(r, j) B1_RC[r][j]
#define TOURS_L 32
#define NOM_L "miss_largeur_1024"
#define CONFORME() 1
#else
#define NL BR_N
#define XM BM
#define XMI BMI
static int init_l(void) { return 1; }
#define RCL(r, j) BR_RC[r][j]
#define TOURS_L BR_TOURS
#define NOM_L "miss_largeur_512"
#define CONFORME() bref_conforme(64)
#endif
#define W (NL / 64)

static void lin_l(const uint8_t Mx[NL][NL], uint8_t *x)
{
    uint8_t y[NL];
    for (int v = 0; v < NL; v++) {
        uint8_t a = 0;
        for (int i = 0; i < NL; i++)
            if (Mx[v][i]) a ^= gf_mul(Mx[v][i], x[i]);
        y[v] = a;
    }
    memcpy(x, y, NL);
}
static uint8_t SIL[16];
static void tour_l(uint8_t *x, int r) { for (int j = 0; j < NL; j++) x[j] = BR_SBOX[x[j] ^ RCL(r, j)]; lin_l(XM, x); }
static void tour_inv_l(uint8_t *x, int r) { lin_l(XMI, x); for (int j = 0; j < NL; j++) x[j] = SIL[x[j]] ^ RCL(r, j); }
#define RMAX 8
typedef struct { uint64_t z[W], n[W]; } motif_t;     /* nul certain / non nul certain */

static uint8_t SUP[4][NL][NL];                   /* M, M⁻¹, Mᵀ, (M⁻¹)ᵀ : supports */

static motif_t etape(motif_t a, const uint8_t S[NL][NL])
{
    motif_t b;
    memset(&b, 0, sizeof b);
    for (int v = 0; v < NL; v++) {
        int nn = 0, inc = 0;
        for (int i = 0; i < NL; i++)
            if (S[v][i]) {
                int z = a.z[i >> 6] >> (i & 63) & 1, n = a.n[i >> 6] >> (i & 63) & 1;
                nn += n;
                inc += !z && !n;
            }
        if (!nn && !inc)
            b.z[v >> 6] |= 1ULL << (v & 63);
        else if (nn == 1 && !inc)
            b.n[v >> 6] |= 1ULL << (v & 63);
    }
    return b;
}

static motif_t motif(int a, int b)                   /* nibbles a (et b ≥ 0) non nuls, autres nuls */
{
    motif_t m;
    memset(m.z, 0xFF, sizeof m.z);
    memset(m.n, 0, sizeof m.n);
    for (int k = 0; k < 2; k++) {
        int i = k ? b : a;
        if (i < 0)
            continue;
        m.z[i >> 6] &= ~(1ULL << (i & 63));
        m.n[i >> 6] |= 1ULL << (i & 63);
    }
    return m;
}

static int contradiction(const motif_t *f, const motif_t *g)
{
    for (int k = 0; k < W; k++)
        if ((f->z[k] & g->n[k]) | (f->n[k] & g->z[k]))
            return 1;
    return 0;
}

/* plus long R = r1 + r2 avec une contradiction, sur tous les couples de motifs */
static int recherche(const uint8_t Fw[NL][NL], const uint8_t Bw[NL][NL], int *ri, int *ro, int *rf)
{
    int nm = NL + NL * (NL - 1) / 2;
    motif_t (*F)[RMAX + 1] = malloc(sizeof(motif_t[RMAX + 1]) * nm), (*G)[RMAX + 1] = malloc(sizeof(motif_t[RMAX + 1]) * nm);
    int (*id)[2] = malloc(sizeof(int[2]) * nm), k = 0;
    for (int a = 0; a < NL; a++)
        for (int b = -1; b < a; b++) {
            id[k][0] = a; id[k][1] = b; k++;
        }
#pragma omp parallel for schedule(dynamic, 64)
    for (int t = 0; t < nm; t++) {
        F[t][0] = G[t][0] = motif(id[t][0], id[t][1]);
        for (int r = 1; r <= RMAX; r++) {
            F[t][r] = etape(F[t][r - 1], Fw);
            G[t][r] = etape(G[t][r - 1], Bw);
        }
    }
    int meilleur = 0;
    for (int R = 2; R <= 2 * RMAX; R++) {
        int trouve = 0;
#pragma omp parallel for schedule(dynamic, 16) reduction(| : trouve)
        for (int x = 0; x < nm; x++) {
            if (trouve)
                continue;
            for (int r1 = R - RMAX < 0 ? 0 : R - RMAX; r1 <= (R < RMAX ? R : RMAX) && !trouve; r1++)
                for (int y = 0; y < nm; y++)
                    if (contradiction(&F[x][r1], &G[y][R - r1])) {
#pragma omp critical
                        { *ri = x; *ro = y; *rf = r1; }
                        trouve = 1;
                        break;
                    }
        }
        if (!trouve)
            break;
        meilleur = R;
    }
    free(F); free(G); free(id);
    return meilleur;
}

/* solidité : prédictions confrontées à des différences réelles */
static long solidite(long essais, long *viol)
{
    alea_t g;
    alea_init(&g, 0xd1ff);
    long tests = 0;
    *viol = 0;
    for (long k = 0; k < essais; k++) {
        int a = (int)alea_borne(&g, NL), b = alea_borne(&g, 2) ? (int)alea_borne(&g, NL) : -1;
        if (b == a) b = -1;
        uint8_t x[NL], y[NL];
        for (int i = 0; i < NL; i++)
            x[i] = (uint8_t)(alea64(&g) & 15);
        memcpy(y, x, NL);
        y[a] ^= (uint8_t)(1 + alea_borne(&g, 15));
        if (b >= 0) y[b] ^= (uint8_t)(1 + alea_borne(&g, 15));
        motif_t m = motif(a, b);
        for (int r = 1; r <= 4; r++) {
            tour_l(x, r - 1); tour_l(y, r - 1);
            m = etape(m, SUP[0]);
            for (int i = 0; i < NL; i++) {
                int d = x[i] != y[i], z = m.z[i >> 6] >> (i & 63) & 1, n = m.n[i >> 6] >> (i & 63) & 1;
                *viol += (z && d) || (n && !d);
                tests += z || n;
            }
        }
    }
    return tests;
}

static long solidite_inverse(long essais, long *viol)
{
    alea_t g;
    alea_init(&g, 0x1d1ff);
    long tests = 0;
    *viol = 0;
    for (long k = 0; k < essais; k++) {
        int a = (int)alea_borne(&g, NL), b = alea_borne(&g, 2) ? (int)alea_borne(&g, NL) : -1;
        if (b == a) b = -1;
        uint8_t x[NL], y[NL];
        for (int i = 0; i < NL; i++)
            x[i] = (uint8_t)(alea64(&g) & 15);
        memcpy(y, x, NL);
        y[a] ^= (uint8_t)(1 + alea_borne(&g, 15));
        if (b >= 0) y[b] ^= (uint8_t)(1 + alea_borne(&g, 15));
        motif_t m = motif(a, b);
        for (int r = 1; r <= 4; r++) {
            tour_inv_l(x, TOURS_L - r); tour_inv_l(y, TOURS_L - r);
            m = etape(m, SUP[1]);
            for (int i = 0; i < NL; i++) {
                int d = x[i] != y[i], z = m.z[i >> 6] >> (i & 63) & 1, n = m.n[i >> 6] >> (i & 63) & 1;
                *viol += (z && d) || (n && !d);
                tests += z || n;
            }
        }
    }
    return tests;
}

int main(void)
{
    resultat_t res = {.nom = NOM_L};
    for (int x = 0; x < 16; x++) SIL[BR_SBOX[x]] = (uint8_t)x;
    if (!bref_init() || !init_l()) {
        fprintf(stderr, "M non inversible\n");
        return 1;
    }
    res_controle(&res, "reference_nibbles_conforme_a_sl_brume_permute", CONFORME());
    for (int v = 0; v < NL; v++)
        for (int i = 0; i < NL; i++) {
            SUP[0][v][i] = XM[v][i] != 0;
            SUP[1][v][i] = XMI[v][i] != 0;
            SUP[2][v][i] = XM[i][v] != 0;
            SUP[3][v][i] = XMI[i][v] != 0;
        }
    int dM = 0, dMI = 0;
    for (int v = 0; v < NL; v++)
        for (int i = 0; i < NL; i++) { dM += SUP[0][v][i]; dMI += SUP[1][v][i]; }
    res_mesure(&res, "densite_support", "{\"M\": %.4f, \"M_inverse\": %.4f}", dM / (double)(NL * NL), dMI / (double)(NL * NL));
    long viol, vi2, nt = solidite(4000, &viol), nt2 = solidite_inverse(4000, &vi2);
    res_mesure(&res, "solidite", "{\"predictions_testees_direct\": %ld, \"violations_direct\": %ld, "
               "\"predictions_testees_inverse\": %ld, \"violations_inverse\": %ld}", nt, viol, nt2, vi2);
    res_controle(&res, "propagation_tronquee_sure_sur_differences_reelles", viol == 0 && vi2 == 0 && nt > 0 && nt2 > 0);
    int a, b, r1;
    int Rid = recherche(SUP[0], SUP[1], &a, &b, &r1);
    res_mesure(&res, "differentielle_impossible", "{\"tours_max\": %d, \"poids_motifs\": \"1 et 2\", \"coupure\": %d}", Rid, r1);
    int Rzc = recherche(SUP[3], SUP[2], &a, &b, &r1);
    res_mesure(&res, "correlation_nulle", "{\"tours_max\": %d, \"poids_motifs\": \"1 et 2\", \"coupure\": %d}", Rzc, r1);
    int marge = TOURS_L - (Rid > Rzc ? Rid : Rzc);
    res_mesure(&res, "marge_tours", "%d", marge);
    res_controle(&res, "differentielle_impossible_bien_en_deca_de_32_tours", Rid > 0 && Rid <= 16);
    res_controle(&res, "correlation_nulle_bien_en_deca_de_32_tours", Rzc > 0 && Rzc <= 16);
    fprintf(stderr, "différentielle impossible : %d tours ; corrélation nulle : %d tours\n", Rid, Rzc);
    return res_ecrire(&res);
}
