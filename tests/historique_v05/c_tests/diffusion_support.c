/* Diffusion de BRUME-512 : supports exacts de M^r et (M⁻¹)^r, et spectre du
 * graphe de Cayley (audit externe, seconde passe, point 1).
 *
 *  - support combinatoire de M^r : positions joignables par des chemins de
 *    longueur ≤ r dans le graphe (diagonale comprise) ;
 *  - support réel sur GF(16) : coefficients non nuls de M^r, qui peut être
 *    plus petit si des contributions s'annulent ;
 *  - borne du groupe : les 6 générateurs sont des réflexions de D128
 *    (s_a s_b = r^{a−b}), donc au plus |{a − b}| + 1 rotations en 2
 *    produits et |{a − b + c}| réflexions en 3 : on recalcule ces nombres
 *    à partir des générateurs et on vérifie que le support les respecte ;
 *  - dépendance réelle : un nibble d'entrée modifié, r tours de la vraie
 *    permutation (S-box comprises), union des nibbles de sortie modifiés
 *    sur 256 essais ; c'est la diffusion qui compte pour le chiffrement,
 *    les S-box empêchant les annulations linéaires de M^r de se propager ;
 *  - spectre de l'adjacence (sans diagonale) par la méthode de Jacobi : le
 *    graphe engendré par des réflexions est biparti (rotations ↔
 *    réflexions), d'où les valeurs propres triviales +6 et −6 ; λ* est le
 *    plus grand |λ| parmi les 126 autres, comparé à 2√5.
 *     build/diffusion_support   (depuis la racine) → resultats/diffusion_support.json
 */
#include <math.h>

#include "brume_ref.h"
#include "resultat.h"

#define RM 8

static void puissance_support(const uint8_t S[BR_N][BR_N], int r, uint8_t out[BR_N][BR_N])
{
    uint8_t A[BR_N][BR_N], B[BR_N][BR_N];
    memcpy(A, S, sizeof A);
    for (int k = 1; k < r; k++) {
        for (int i = 0; i < BR_N; i++)
            for (int j = 0; j < BR_N; j++) {
                uint8_t v = 0;
                for (int l = 0; l < BR_N && !v; l++)
                    v = A[i][l] && S[l][j];
                B[i][j] = v;
            }
        memcpy(A, B, sizeof A);
    }
    memcpy(out, A, sizeof A);
}

static void puissance_gf(const uint8_t Mx[BR_N][BR_N], int r, uint8_t out[BR_N][BR_N])
{
    uint8_t A[BR_N][BR_N], B[BR_N][BR_N];
    memcpy(A, Mx, sizeof A);
    for (int k = 1; k < r; k++) {
        for (int i = 0; i < BR_N; i++)
            for (int j = 0; j < BR_N; j++) {
                uint8_t v = 0;
                for (int l = 0; l < BR_N; l++)
                    if (A[i][l] && Mx[l][j])
                        v ^= gf_mul(A[i][l], Mx[l][j]);
                B[i][j] = v;
            }
        memcpy(A, B, sizeof A);
    }
    memcpy(out, A, sizeof A);
}

/* support d'une colonne (image d'un nibble isolé) : min et max sur les colonnes */
static void extremes(const uint8_t A[BR_N][BR_N], int *mn, int *mx)
{
    *mn = BR_N; *mx = 0;
    for (int j = 0; j < BR_N; j++) {
        int c = 0;
        for (int i = 0; i < BR_N; i++)
            c += A[i][j] != 0;
        if (c < *mn) *mn = c;
        if (c > *mx) *mx = c;
    }
}

/* valeurs propres d'une matrice symétrique (Jacobi cyclique) */
static void jacobi(double a[BR_N][BR_N], double *ev)
{
    for (int balayage = 0; balayage < 100; balayage++) {
        double off = 0;
        for (int p = 0; p < BR_N; p++)
            for (int q = p + 1; q < BR_N; q++)
                off += a[p][q] * a[p][q];
        if (off < 1e-22)
            break;
        for (int p = 0; p < BR_N; p++)
            for (int q = p + 1; q < BR_N; q++) {
                if (fabs(a[p][q]) < 1e-300)
                    continue;
                double th = (a[q][q] - a[p][p]) / (2 * a[p][q]);
                double t = (th >= 0 ? 1 : -1) / (fabs(th) + sqrt(th * th + 1));
                double c = 1 / sqrt(t * t + 1), s = t * c;
                for (int k = 0; k < BR_N; k++) {
                    double akp = a[k][p], akq = a[k][q];
                    a[k][p] = c * akp - s * akq;
                    a[k][q] = s * akp + c * akq;
                }
                for (int k = 0; k < BR_N; k++) {
                    double apk = a[p][k], aqk = a[q][k];
                    a[p][k] = c * apk - s * aqk;
                    a[q][k] = s * apk + c * aqk;
                }
            }
    }
    for (int i = 0; i < BR_N; i++)
        ev[i] = a[i][i];
}

/* union des nibbles modifiés après r tours, nibble d'entrée j, sur `essais` */
static int dependance(int j, int r, int sens, int essais, alea_t *g)
{
    uint8_t vu[BR_N] = {0};
    for (int e = 0; e < essais; e++) {
        uint8_t x[BR_N], y[BR_N];
        for (int i = 0; i < BR_N; i++)
            x[i] = (uint8_t)(alea64(g) & 15);
        memcpy(y, x, BR_N);
        y[j] ^= (uint8_t)(1 + alea_borne(g, 15));
        for (int t = 0; t < r; t++) {
            if (sens == 0) { bref_tour(x, t); bref_tour(y, t); }
            else { bref_tour_inv(x, BR_TOURS - 1 - t); bref_tour_inv(y, BR_TOURS - 1 - t); }
        }
        for (int i = 0; i < BR_N; i++)
            vu[i] |= x[i] != y[i];
    }
    int c = 0;
    for (int i = 0; i < BR_N; i++)
        c += vu[i];
    return c;
}

static int cmpd(const void *x, const void *y)
{
    double a = *(const double *)x, b = *(const double *)y;
    return a < b ? -1 : a > b;
}

int main(void)
{
    resultat_t res = {.nom = "diffusion_support"};
    if (!bref_init())
        return 1;
    res_controle(&res, "reference_nibbles_conforme_a_sl_brume_permute", bref_conforme(16));
    static uint8_t S[BR_N][BR_N], SI[BR_N][BR_N], P[BR_N][BR_N], Q[BR_N][BR_N];
    for (int i = 0; i < BR_N; i++)
        for (int j = 0; j < BR_N; j++) {
            S[i][j] = BM[i][j] != 0;
            SI[i][j] = BMI[i][j] != 0;
        }
    /* générateurs : arêtes hors diagonale du sommet 0 (rotation r^0) */
    int gen[8], ng = 0;
    for (int j = 0; j < BR_N; j++)
        if (S[0][j] && j != 0)
            gen[ng++] = j;
    int refl = 1;
    for (int g = 0; g < ng; g++)
        refl &= gen[g] >= 64;                          /* sommets 64…127 = réflexions */
    int k[8];
    for (int g = 0; g < ng; g++)
        k[g] = gen[g] - 64;
    int rot2[64] = {0}, ref3[64] = {0}, nrot2 = 0, nref3 = 0;
    rot2[0] = 1;
    for (int a = 0; a < ng; a++)
        for (int b = 0; b < ng; b++)
            rot2[((k[a] - k[b]) % 64 + 64) % 64] = 1;
    for (int a = 0; a < ng; a++)
        for (int b = 0; b < ng; b++)
            for (int c = 0; c < ng; c++)
                ref3[(((k[a] - k[b] + k[c]) % 64) + 64) % 64] = 1;
    for (int i = 0; i < 64; i++) { nrot2 += rot2[i]; nref3 += ref3[i]; }
    int borne[4] = {1, 1 + ng, nrot2 + ng, nrot2 + nref3};   /* ≤ 3 produits : rotations de ≤ 2, réflexions de ≤ 3 */
    res_mesure(&res, "generateurs", "{\"nombre\": %d, \"tous_des_reflexions\": %s, \"k\": [%d, %d, %d, %d, %d, %d]}",
               ng, refl ? "true" : "false", k[0], k[1], k[2], k[3], k[4], k[5]);
    res_mesure(&res, "borne_du_groupe", "{\"1\": %d, \"2\": %d, \"3\": %d}", borne[1], borne[2], borne[3]);
    char bc[512] = "{", bg[512] = "{", bi[512] = "{", bgi[512] = "{";
    int complet_c = 0, complet_g = 0, complet_ci = 0, complet_gi = 0, ok_borne = 1;
    for (int r = 1; r <= RM; r++) {
        int mn, mx, mng, mxg, mni, mxi, mngi, mxgi;
        puissance_support(S, r, P);
        extremes(P, &mn, &mx);
        puissance_gf(BM, r, Q);
        extremes(Q, &mng, &mxg);
        puissance_support(SI, r, P);
        extremes(P, &mni, &mxi);
        puissance_gf(BMI, r, Q);
        extremes(Q, &mngi, &mxgi);
        if (r <= 3)
            ok_borne &= mx <= borne[r] && mxg <= mx;
        snprintf(bc + strlen(bc), 64, "%s\"%d\": [%d, %d]", r > 1 ? ", " : "", r, mn, mx);
        snprintf(bg + strlen(bg), 64, "%s\"%d\": [%d, %d]", r > 1 ? ", " : "", r, mng, mxg);
        snprintf(bi + strlen(bi), 64, "%s\"%d\": [%d, %d]", r > 1 ? ", " : "", r, mni, mxi);
        snprintf(bgi + strlen(bgi), 64, "%s\"%d\": [%d, %d]", r > 1 ? ", " : "", r, mngi, mxgi);
        if (!complet_c && mn == BR_N) complet_c = r;
        if (!complet_g && mng == BR_N) complet_g = r;
        if (!complet_ci && mni == BR_N) complet_ci = r;
        if (!complet_gi && mngi == BR_N) complet_gi = r;
        fprintf(stderr, "r=%d : M combinatoire [%d, %d], GF(16) [%d, %d] ; M⁻¹ combinatoire [%d, %d], GF(16) [%d, %d]\n",
                r, mn, mx, mng, mxg, mni, mxi, mngi, mxgi);
    }
    strcat(bc, "}"); strcat(bg, "}"); strcat(bi, "}"); strcat(bgi, "}");
    res_mesure(&res, "support_M_combinatoire_min_max_par_tour", "%s", bc);
    res_mesure(&res, "support_M_gf16_min_max_par_tour", "%s", bg);
    res_mesure(&res, "support_M_inverse_combinatoire_min_max_par_tour", "%s", bi);
    res_mesure(&res, "support_M_inverse_gf16_min_max_par_tour", "%s", bgi);
    res_mesure(&res, "tours_jusqu_au_support_complet",
               "{\"M_combinatoire\": %d, \"M_gf16\": %d, \"M_inverse_combinatoire\": %d, \"M_inverse_gf16\": %d}",
               complet_c, complet_g, complet_ci, complet_gi);
    res_controle(&res, "generateurs_tous_des_reflexions", refl && ng == 6);
    res_controle(&res, "support_respecte_la_borne_du_groupe_et_les_annulations", ok_borne);
    res_controle(&res, "support_combinatoire_7_37_94_puis_complet", complet_c == 5);
    /* densité moyenne réelle de M^r (r = 4 … 8) : une matrice aléatoire de GF(16) a 15/16 de non-nuls */
    double dens = 0;
    for (int r = 4; r <= RM; r++) {
        puissance_gf(BM, r, Q);
        int nz = 0;
        for (int i = 0; i < BR_N; i++)
            for (int j = 0; j < BR_N; j++)
                nz += Q[i][j] != 0;
        dens += nz / (double)(BR_N * BR_N);
    }
    dens /= RM - 3;
    res_mesure(&res, "densite_moyenne_de_M_puissance_r_r4_a_r8", "%.4f", dens);
    res_controle(&res, "puissances_lineaires_de_densite_aleatoire_15_sur_16", fabs(dens - 15.0 / 16) < 0.01);
    /* dépendance réelle par la vraie permutation (tous les nibbles d'entrée) */
    alea_t g;
    alea_init(&g, 0xd1f);
    char bd[512] = "{", bdi[512] = "{";
    int ok_dep = 1, rd = 0, rdi = 0;
    for (int r = 1; r <= 6; r++) {
        int mn = BR_N, mni = BR_N, mx = 0;
        for (int j = 0; j < BR_N; j++) {
            int c = dependance(j, r, 0, 64, &g), ci = dependance(j, r, 1, 64, &g);
            if (c < mn) mn = c;
            if (c > mx) mx = c;
            if (ci < mni) mni = ci;
        }
        int attendu = r == 1 ? 7 : r == 2 ? 37 : r == 3 ? 94 : r == 4 ? 127 : 128;
        ok_dep &= mx <= attendu && mn == attendu;
        if (!rd && mn == BR_N) rd = r;
        if (!rdi && mni == BR_N) rdi = r;
        snprintf(bd + strlen(bd), 64, "%s\"%d\": %d", r > 1 ? ", " : "", r, mn);
        snprintf(bdi + strlen(bdi), 64, "%s\"%d\": %d", r > 1 ? ", " : "", r, mni);
        fprintf(stderr, "dépendance réelle r=%d : direct %d, inverse %d\n", r, mn, mni);
    }
    strcat(bd, "}"); strcat(bdi, "}");
    res_mesure(&res, "dependance_reelle_min_par_tour_direct", "%s", bd);
    res_mesure(&res, "dependance_reelle_min_par_tour_inverse", "%s", bdi);
    res_mesure(&res, "tours_jusqu_a_la_dependance_complete", "{\"direct\": %d, \"inverse\": %d}", rd, rdi);
    res_controle(&res, "dependance_reelle_egale_au_support_combinatoire", ok_dep && rd == 5);
    /* spectre */
    static double A[BR_N][BR_N], ev[BR_N];
    int deg_ok = 1;
    for (int i = 0; i < BR_N; i++) {
        int d = 0;
        for (int j = 0; j < BR_N; j++) {
            A[i][j] = (i != j && S[i][j]) ? 1.0 : 0.0;
            d += i != j && S[i][j];
        }
        deg_ok &= d == 6;
    }
    int sym = 1;
    for (int i = 0; i < BR_N; i++)
        for (int j = 0; j < BR_N; j++)
            sym &= A[i][j] == A[j][i];
    jacobi(A, ev);
    qsort(ev, BR_N, sizeof *ev, cmpd);
    double lam = 0;
    for (int i = 1; i < BR_N - 1; i++)
        if (fabs(ev[i]) > lam) lam = fabs(ev[i]);
    int biparti = fabs(ev[0] + 6) < 1e-8;
    res_mesure(&res, "spectre", "{\"valeur_propre_max\": %.6f, \"valeur_propre_min\": %.6f, \"lambda_etoile_hors_plus_moins_6\": %.4f, "
               "\"borne_2_racine_5\": %.4f}", ev[BR_N - 1], ev[0], lam, 2 * sqrt(5.0));
    res_controle(&res, "graphe_6_regulier_symetrique", deg_ok && sym);
    res_controle(&res, "graphe_biparti_valeur_propre_moins_6", biparti && fabs(ev[BR_N - 1] - 6) < 1e-8);
    res_controle(&res, "ramanujan_lambda_etoile_sous_2_racine_5", lam < 2 * sqrt(5.0));
    res_controle(&res, "lambda_etoile_egal_a_la_valeur_publiee_3_5076", fabs(lam - 3.5076) < 5e-4);
    fprintf(stderr, "λ* = %.4f (2√5 = %.4f), biparti : %d\n", lam, 2 * sqrt(5.0), biparti);
    return res_ecrire(&res);
}
