/* Différentielles impossibles et corrélations nulles (miss-in-the-middle),
 * au niveau des nibbles — famille d'attaques structurelles non couverte
 * jusqu'ici par la batterie.
 *
 * Propagation tronquée sûre (probabilité 1), états par nibble : 0 (nul
 * certain), N (non nul certain), ? (inconnu) :
 *  - S-box et constante : la différence (ou le masque) reste nulle ou non
 *    nulle, la S-box étant bijective ;
 *  - couche linéaire : sortie nulle si toutes ses entrées le sont ; non
 *    nulle si exactement UNE entrée est non nulle et les autres nulles
 *    (coefficient de GF(16)* inversible) ; inconnue sinon.
 * Différences : en avant par M, en arrière par M⁻¹. Masques : en avant par
 * (M⁻¹)ᵀ, en arrière par Mᵀ (adjoints ; l'adjoint binaire d'une
 * multiplication par c ≠ 0 est inversible, donc la règle « une seule
 * entrée » vaut aussi). Contradiction au milieu (0 d'un côté, N de l'autre)
 * → différentielle impossible / corrélation nulle sur R = r1 + r2 tours.
 * Motifs d'entrée et de sortie : tous ceux de poids 1 et 2 (8 256 chacun).
 *
 * Contrôle de solidité : les prédictions « nul » et « non nul » sont
 * confrontées à des différences réelles (bref_perm), 1 à 4 tours, deux sens.
 *     build/structure_miss   (depuis la racine) → resultats/structure_miss.json
 */
#include <omp.h>

#include "brume_ref.h"
#include "resultat.h"

#define RMAX 8
typedef struct { uint64_t z[2], n[2]; } motif_t;     /* nul certain / non nul certain */

static uint8_t SUP[4][BR_N][BR_N];                   /* M, M⁻¹, Mᵀ, (M⁻¹)ᵀ : supports */

static motif_t etape(motif_t a, const uint8_t S[BR_N][BR_N])
{
    motif_t b = {{0, 0}, {0, 0}};
    for (int v = 0; v < BR_N; v++) {
        int nn = 0, inc = 0;
        for (int i = 0; i < BR_N; i++)
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
    motif_t m = {{~0ULL, ~0ULL}, {0, 0}};
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
    for (int k = 0; k < 2; k++)
        if ((f->z[k] & g->n[k]) | (f->n[k] & g->z[k]))
            return 1;
    return 0;
}

/* plus long R = r1 + r2 avec une contradiction, sur tous les couples de motifs */
static int recherche(const uint8_t Fw[BR_N][BR_N], const uint8_t Bw[BR_N][BR_N], int *ri, int *ro, int *rf)
{
    int nm = 128 + 128 * 127 / 2;
    motif_t (*F)[RMAX + 1] = malloc(sizeof(motif_t[RMAX + 1]) * nm), (*G)[RMAX + 1] = malloc(sizeof(motif_t[RMAX + 1]) * nm);
    int (*id)[2] = malloc(sizeof(int[2]) * nm), k = 0;
    for (int a = 0; a < 128; a++)
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
        int a = (int)alea_borne(&g, 128), b = alea_borne(&g, 2) ? (int)alea_borne(&g, 128) : -1;
        if (b == a) b = -1;
        uint8_t x[BR_N], y[BR_N];
        for (int i = 0; i < BR_N; i++)
            x[i] = (uint8_t)(alea64(&g) & 15);
        memcpy(y, x, BR_N);
        y[a] ^= (uint8_t)(1 + alea_borne(&g, 15));
        if (b >= 0) y[b] ^= (uint8_t)(1 + alea_borne(&g, 15));
        motif_t m = motif(a, b);
        for (int r = 1; r <= 4; r++) {
            bref_tour(x, r - 1); bref_tour(y, r - 1);
            m = etape(m, SUP[0]);
            for (int i = 0; i < BR_N; i++) {
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
        int a = (int)alea_borne(&g, 128), b = alea_borne(&g, 2) ? (int)alea_borne(&g, 128) : -1;
        if (b == a) b = -1;
        uint8_t x[BR_N], y[BR_N];
        for (int i = 0; i < BR_N; i++)
            x[i] = (uint8_t)(alea64(&g) & 15);
        memcpy(y, x, BR_N);
        y[a] ^= (uint8_t)(1 + alea_borne(&g, 15));
        if (b >= 0) y[b] ^= (uint8_t)(1 + alea_borne(&g, 15));
        motif_t m = motif(a, b);
        for (int r = 1; r <= 4; r++) {
            bref_tour_inv(x, BR_TOURS - r); bref_tour_inv(y, BR_TOURS - r);
            m = etape(m, SUP[1]);
            for (int i = 0; i < BR_N; i++) {
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
    resultat_t res = {.nom = "structure_miss"};
    if (!bref_init()) {
        fprintf(stderr, "M non inversible\n");
        return 1;
    }
    res_controle(&res, "reference_nibbles_conforme_a_sl_brume_permute", bref_conforme(64));
    for (int v = 0; v < BR_N; v++)
        for (int i = 0; i < BR_N; i++) {
            SUP[0][v][i] = BM[v][i] != 0;
            SUP[1][v][i] = BMI[v][i] != 0;
            SUP[2][v][i] = BM[i][v] != 0;
            SUP[3][v][i] = BMI[i][v] != 0;
        }
    int dM = 0, dMI = 0;
    for (int v = 0; v < BR_N; v++)
        for (int i = 0; i < BR_N; i++) { dM += SUP[0][v][i]; dMI += SUP[1][v][i]; }
    res_mesure(&res, "densite_support", "{\"M\": %.4f, \"M_inverse\": %.4f}", dM / 16384.0, dMI / 16384.0);
    long viol, vi2, nt = solidite(4000, &viol), nt2 = solidite_inverse(4000, &vi2);
    res_mesure(&res, "solidite", "{\"predictions_testees_direct\": %ld, \"violations_direct\": %ld, "
               "\"predictions_testees_inverse\": %ld, \"violations_inverse\": %ld}", nt, viol, nt2, vi2);
    res_controle(&res, "propagation_tronquee_sure_sur_differences_reelles", viol == 0 && vi2 == 0 && nt > 0 && nt2 > 0);
    int a, b, r1;
    int Rid = recherche(SUP[0], SUP[1], &a, &b, &r1);
    res_mesure(&res, "differentielle_impossible", "{\"tours_max\": %d, \"poids_motifs\": \"1 et 2\", \"coupure\": %d}", Rid, r1);
    int Rzc = recherche(SUP[3], SUP[2], &a, &b, &r1);
    res_mesure(&res, "correlation_nulle", "{\"tours_max\": %d, \"poids_motifs\": \"1 et 2\", \"coupure\": %d}", Rzc, r1);
    int marge = BR_TOURS - (Rid > Rzc ? Rid : Rzc);
    res_mesure(&res, "marge_tours", "%d", marge);
    res_controle(&res, "differentielle_impossible_bien_en_deca_de_32_tours", Rid > 0 && Rid <= 16);
    res_controle(&res, "correlation_nulle_bien_en_deca_de_32_tours", Rzc > 0 && Rzc <= 16);
    fprintf(stderr, "différentielle impossible : %d tours ; corrélation nulle : %d tours\n", Rid, Rzc);
    return res_ecrire(&res);
}
