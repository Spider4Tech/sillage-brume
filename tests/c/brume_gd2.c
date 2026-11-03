/* BRUME-512 réduit à 2 tours : récupération de toute la capacité (256 bits) par devinette et détermination
 * (plan GPU, attaque B3 ; PREUVES § 4.2 bis, « Algébrique »).
 *
 * Modèle d'attaque du duplex : débit connu de part et d'autre d'un appel à la permutation (nibbles 0 à 63 = moitié A du
 * graphe de Cayley, débit de BRUME-512 et du hachage), capacité inconnue (moitié B). Tous les générateurs sont des
 * réflexions, qui relient A et B : après 2 tours, le nibble de débit u ne dépend que des 6 nibbles Y_w = S(x0_w ⊕ rc0_w)
 * de B voisins de u (u + K mod 64, K = {0, 7, 8, 21, 45, 62}), par
 *     x2_u = c_uu·S(x1_u ⊕ rc1_u) + Σ_w c_uw·S(d_w·Y_w + k_w ⊕ rc1_w),   x1_u = c·y0_u + Σ_w c'_uw·Y_w.
 * On introduit les 64 inconnues dans un ordre fixé ; chaque équation entièrement couverte filtre d'un facteur 16. Le
 * nombre de nœuds à la profondeur k est 16^(|V_k| − |E_k|) si les équations se comportent comme des fonctions au
 * hasard ; la largeur w = max_k (|V_k| − |E_k|) donne le coût 16^w en énumération en profondeur (mémoire négligeable).
 *
 *   1. largeur de l'ordre fourni (meilleur trouvé : glouton randomisé et recuit simulé, 24 sur toutes les graines) ;
 *   2. attaque réelle sur des états au hasard, avec un oracle qui fournit les m premières inconnues de l'ordre (largeur
 *      résiduelle ≤ 5) : nœuds mesurés contre la prévision 16^(…) + 1 (le vrai chemin survit toujours), profondeur par
 *      profondeur, et état retrouvé exactement. Mesuré : le modèle sous-estime d'un facteur ≈ 2 (1 bit), d'où ≈ 2^97.
 * Le coût complet n'est pas exécuté (2^96) : la mesure valide le modèle qui le donne.
 *     make -C tests/c build/brume_gd2 && tests/c/build/brume_gd2 [états]   (depuis la racine) → resultats/brume_gd2.json */
#include <math.h>
#include <omp.h>

#include "brume512_tables.h"
#include "resultat.h"
#include "sillage.h"

/* ordre trouvé par recuit simulé (graine 1, 1,5 M itérations), largeur 24 */
static const int ORDRE[64] = {31, 59, 10, 29, 11, 62, 58, 2, 45, 41, 42, 53, 60, 55, 25, 3, 4, 17, 12, 49, 63, 36, 8, 18,
                              5, 61, 51, 34, 32, 15, 24, 38, 22, 48, 39, 1, 52, 56, 46, 9, 19, 44, 43, 6, 16, 26, 57, 40,
                              35, 33, 50, 23, 13, 27, 0, 14, 54, 37, 20, 30, 47, 7, 21, 28};

static uint8_t MUL[16][16], SINV[16];
static int gmul(int a, int b)
{
    int r = 0;
    for (int i = 0; i < 4; i++) {
        if (b & 1) r ^= a;
        b >>= 1; a <<= 1;
        if (a & 16) a ^= BR_POLY;
    }
    return r & 15;
}

/* un tour : x ← M·S(x ⊕ rc_r) sur 128 nibbles */
static void tour(uint8_t x[128], int r)
{
    uint8_t y[128], z[128] = {0};
    for (int v = 0; v < 128; v++) y[v] = BR_SBOX[x[v] ^ BR_RC[r][v]];
    for (int e = 0; e < BR_ARETES; e++) z[e / BR_DEG] ^= MUL[BR_EC[e]][y[BR_EI[e]]];
    memcpy(x, z, 128);
}

/* équation u : coefficients et positions, précalculés */
typedef struct {
    int w[6];          /* inconnues (indices 0..63 dans B) */
    uint8_t cy[6];     /* x1_u = base1 + Σ cy·Y_w */
    uint8_t cz[6];     /* x2_u = cs·S(x1_u ⊕ rc1_u) + Σ cz·S(d_w·Y_w + kB_w ⊕ rc1_B) */
    uint8_t cs;
} equation_t;
static equation_t EQ[64];
static uint8_t D_B[64];                 /* coefficient de la boucle sur le nœud B : x1_B,w = D_B·Y_w + kB_w */
static int complete_a[64][64], ncomp[64];   /* équations complétées à la profondeur k */

typedef struct { uint8_t xA0[64], x2A[64], vraiY[64], base1[64], kB[64]; } instance_t;

static void instance(instance_t *I, uint8_t x0[128])
{
    uint8_t x[128];
    memcpy(x, x0, 128);
    uint8_t y0[128];
    for (int v = 0; v < 128; v++) y0[v] = BR_SBOX[x0[v] ^ BR_RC[0][v]];
    for (int w = 0; w < 64; w++) I->vraiY[w] = y0[64 + w];
    memset(I->base1, 0, 64);
    memset(I->kB, 0, 64);
    for (int e = 0; e < BR_ARETES; e++) {          /* parties connues de x1 (sources A) */
        int v = e / BR_DEG, j = BR_EI[e];
        if (j < 64) { if (v < 64) I->base1[v] ^= MUL[BR_EC[e]][y0[j]]; else I->kB[v - 64] ^= MUL[BR_EC[e]][y0[j]]; }
    }
    tour(x, 0);
    tour(x, 1);
    memcpy(I->xA0, x0, 64);
    memcpy(I->x2A, x, 64);
}

static int verifie(const instance_t *I, const uint8_t *Y, int u)
{
    const equation_t *q = &EQ[u];
    uint8_t x1 = I->base1[u], s = 0;
    for (int i = 0; i < 6; i++) x1 ^= MUL[q->cy[i]][Y[q->w[i]]];
    s = MUL[q->cs][BR_SBOX[x1 ^ BR_RC[1][u]]];
    for (int i = 0; i < 6; i++) {
        int w = q->w[i];
        s ^= MUL[q->cz[i]][BR_SBOX[MUL[D_B[w]][Y[w]] ^ I->kB[w] ^ BR_RC[1][64 + w]]];
    }
    return s == I->x2A[u];
}

/* énumération en profondeur à partir de la profondeur m (les m premières inconnues données par l'oracle) */
static void dfs(const instance_t *I, uint8_t *Y, int k, double *noeuds, long *solutions, int *trouve)
{
    noeuds[k] += 1;
    if (k == 64) {
        (*solutions)++;
        if (!memcmp(Y, I->vraiY, 64)) *trouve = 1;
        return;
    }
    int w = ORDRE[k];
    for (int val = 0; val < 16; val++) {
        Y[w] = (uint8_t)val;
        int ok = 1;
        for (int i = 0; i < ncomp[k] && ok; i++) ok = verifie(I, Y, complete_a[k][i]);
        if (ok) dfs(I, Y, k + 1, noeuds, solutions, trouve);
    }
}

int main(int argc, char **argv)
{
    int NE = argc > 1 ? atoi(argv[1]) : 24;
    resultat_t res = {.nom = "brume_gd2", .titre = "BRUME-512 à 2 tours : récupération de la capacité par devinette et détermination"};
    sl_init();
    for (int a = 0; a < 16; a++) for (int b = 0; b < 16; b++) MUL[a][b] = (uint8_t)gmul(a, b);
    for (int x = 0; x < 16; x++) SINV[BR_SBOX[x]] = (uint8_t)x;

    /* équations : sources de chaque nœud A u (self + 6 dans B) ; boucles des nœuds B */
    int ok_struct = 1;
    for (int u = 0; u < 64; u++) {
        int n = 0;
        for (int e = 7 * u; e < 7 * u + 7; e++) {
            int j = BR_EI[e];
            if (j == u) EQ[u].cs = BR_EC[e];
            else if (j >= 64 && n < 6) { EQ[u].w[n] = j - 64; EQ[u].cz[n] = BR_EC[e]; EQ[u].cy[n] = BR_EC[e]; n++; }
            else ok_struct = 0;
        }
        ok_struct &= n == 6;
    }
    for (int e = 64 * 7; e < BR_ARETES; e++) if (BR_EI[e] == e / BR_DEG) D_B[e / BR_DEG - 64] = BR_EC[e];
    res_controle(&res, "structure_debit_A_capacite_B_6_voisins", ok_struct);

    /* largeur de l'ordre, et équations complétées à chaque profondeur */
    uint64_t V = 0, E = 0;
    int larg = 0, prof[65];
    for (int k = 0; k < 64; k++) {
        V |= 1ULL << ORDRE[k];
        ncomp[k] = 0;
        for (int u = 0; u < 64; u++) {
            if (E >> u & 1) continue;
            int tous = 1;
            for (int i = 0; i < 6; i++) tous &= (int)(V >> EQ[u].w[i] & 1);
            if (tous) { E |= 1ULL << u; complete_a[k][ncomp[k]++] = u; }
        }
        prof[k + 1] = __builtin_popcountll(V) - __builtin_popcountll(E);
        if (prof[k + 1] > larg) larg = prof[k + 1];
    }
    prof[0] = 0;
    res_mesure(&res, "largeur", "%d", larg);
    res_mesure(&res, "cout_log2", "%d", 4 * larg);
    res_controle(&res, "largeur_24_soit_2^96", larg == 24);

    /* oracle : m = plus petite profondeur à partir de laquelle la largeur résiduelle ≤ 5 */
    int m = 0;
    for (int k = 0; k <= 64; k++) {
        int resid = 0;
        for (int j = k; j <= 64; j++) if (prof[j] - prof[k] > resid) resid = prof[j] - prof[k];
        if (resid <= 5) { m = k; break; }
    }
    double noeuds[65] = {0}, prev[65] = {0};
    long sol = 0;
    int trouves = 0;
#pragma omp parallel for reduction(+ : sol, trouves) schedule(dynamic, 1)
    for (int t = 0; t < NE; t++) {
        uint8_t x0[128], Y[64];
        uint8_t g[128];
        sl_alea(g, sizeof g);
        for (int v = 0; v < 128; v++) x0[v] = g[v] & 15;
        instance_t I;
        instance(&I, x0);
        int ok = 1;
        for (int k = 0; k < m; k++) Y[ORDRE[k]] = I.vraiY[ORDRE[k]];
        for (int k = 0; k < m && ok; k++)            /* les équations déjà couvertes par l'oracle doivent tenir */
            for (int i = 0; i < ncomp[k]; i++) ok &= verifie(&I, Y, complete_a[k][i]);
        double nl[65] = {0};
        long s = 0;
        int tr = 0;
        if (ok) dfs(&I, Y, m, nl, &s, &tr);
#pragma omp critical
        for (int k = 0; k <= 64; k++) noeuds[k] += nl[k];
        sol += s;
        trouves += tr;
    }
    /* prévision : 16^(prof[k] − prof[m]) faux candidats + le vrai à la profondeur k ; écart maximal en log2 */
    double ecart = 0;
    char det[4096];
    int lg = snprintf(det, sizeof det, "{");
    for (int k = m; k <= 64; k++) {
        prev[k] = pow(16.0, prof[k] - prof[m]) + 1;
        double mes = noeuds[k] / NE, e = fabs(log2(mes / prev[k]));
        if (e > ecart) ecart = e;
        if ((k - m) % 4 == 0 || k == 64)
            lg += snprintf(det + lg, sizeof det - lg, "%s\"%d\": [%.3g, %.3g]", k > m ? ", " : "", k, mes, prev[k]);
    }
    snprintf(det + lg, sizeof det - lg, "}");
    res_mesure(&res, "oracle_inconnues_fournies", "%d", m);
    res_mesure(&res, "etats_attaques", "%d", NE);
    res_mesure(&res, "noeuds_mesures_contre_prevision_par_profondeur", "%s", det);
    res_mesure(&res, "ecart_max_log2", "%.2f", ecart);
    res_mesure(&res, "cout_mesure_log2", "%.1f", 4.0 * larg + ecart);
    res_mesure(&res, "solutions_par_etat", "%.3f", (double)sol / NE);
    res_controle(&res, "etat_retrouve_a_chaque_fois", trouves == NE);
    res_controle(&res, "noeuds_conformes_au_modele_a_2_bits", ecart < 2.0);
    return res_ecrire(&res);
}
