/* Hypothèses H1-P / H2-P / H3 : attaques ISD RÉELLES sur des instances
 * réduites de même structure, confrontées aux formules des estimateurs.
 *
 * 1. KEM (quasi-cyclique) : s = x·h ⊕ y dans F2[z]/(z^n − 1), n premier
 *    d'Artin, wt(x) = wt(y) = w ; décodage par Prange de H = [C(h) | I]
 *    (n × 2n), poids 2w. Nombre moyen d'itérations mesuré contre
 *    1/P, P = C(n, 2w)/C(2n, 2w) (probabilité qu'un ensemble d'information
 *    évite tout le support).
 * 2. Gain quasi-cyclique : les n syndromes décalés z^i·s (solutions
 *    z^i·(x, y)) testés à chaque itération (« decoding one out of many »).
 *    Gain mesuré sur le nombre d'itérations, comparé au crédit de log2 n
 *    que retranche l'estimateur de Sillage-KEM.
 * 3. SIG (code aléatoire r × n, rendement 1/2, poids w) : même confrontation,
 *    P = C(r, w)/C(n, w).
 * 4. Invariants linéaires de s (h fixé) : rang de {s_k ⊕ s_0} sur F2. La
 *    parité (s(1) public) est le seul invariant si le rang vaut n − 1.
 * Prange est l'ISD le plus simple : ces mesures valident la modélisation
 * (formules, gain QC), pas les variantes avancées (Stern, BJMM), dont les
 * estimateurs suivent les mêmes conventions.
 *     build/isd_reel   (depuis la racine) → resultats/isd_reel.json
 */
#include <math.h>
#include <omp.h>

#include "resultat.h"

#define NMAX 256
#define LMAX 13                                    /* mots de 64 bits par ligne (≤ 3·NMAX bits) */

typedef struct { int n, m; uint64_t H[NMAX][LMAX]; } code_t;   /* n lignes, m colonnes */

static int artin(int n)
{
    for (int d = 2; d < n; d++)
        if (n % d == 0)
            return 0;
    int x = 1;
    for (int k = 1; k < n - 1; k++) {
        x = 2 * x % n;
        if (x == 1)
            return 0;
    }
    return 1;
}

static double log2_binom(int a, int b) { return (lgamma(a + 1.0) - lgamma(b + 1.0) - lgamma(a - b + 1.0)) / log(2.0); }

static int bit(const uint64_t *v, int i) { return v[i >> 6] >> (i & 63) & 1; }
static void pose(uint64_t *v, int i) { v[i >> 6] |= 1ULL << (i & 63); }

static void creux(alea_t *g, int n, int w, uint8_t *v)
{
    memset(v, 0, (size_t)n);
    for (int k = 0; k < w;) {
        int p = (int)alea_borne(g, (uint64_t)n);
        if (!v[p]) { v[p] = 1; k++; }
    }
}

/* Prange : nb d'itérations jusqu'à trouver un e de poids ≤ poids tel que
 * H·e = l'un des T syndromes (colonnes synd[t], t < T). */
static long prange(const code_t *c, const uint8_t (*synd)[NMAX], int T, int poids, alea_t *g, int *cible)
{
    int n = c->n, m = c->m, perm[2 * NMAX], pivcol[NMAX];
    uint64_t A[NMAX][LMAX];
    int mots = (m + T + 63) / 64;
    for (long it = 1;; it++) {
        for (int j = 0; j < m; j++)
            perm[j] = j;
        for (int j = m - 1; j > 0; j--) {
            int r = (int)alea_borne(g, (uint64_t)j + 1), t = perm[j];
            perm[j] = perm[r]; perm[r] = t;
        }
        for (int i = 0; i < n; i++) {
            memset(A[i], 0, sizeof A[i]);
            for (int j = 0; j < m; j++)
                if (bit(c->H[i], perm[j]))
                    pose(A[i], j);
            for (int t = 0; t < T; t++)
                if (synd[t][i])
                    pose(A[i], m + t);
        }
        int piv = 0;
        for (int col = 0; col < m && piv < n; col++) {
            int r = piv;
            while (r < n && !bit(A[r], col))
                r++;
            if (r == n)
                continue;
            if (r != piv)
                for (int k = 0; k < mots; k++) { uint64_t t = A[r][k]; A[r][k] = A[piv][k]; A[piv][k] = t; }
            for (int i = 0; i < n; i++)
                if (i != piv && bit(A[i], col))
                    for (int k = 0; k < mots; k++)
                        A[i][k] ^= A[piv][k];
            pivcol[piv++] = col;
        }
        (void)pivcol;
        for (int t = 0; t < T; t++) {
            int wt = 0;
            for (int i = 0; i < piv; i++)
                wt += bit(A[i], m + t);
            if (wt <= poids && wt > 0) {
                *cible = t;
                return it;
            }
        }
    }
}

static void qc(code_t *c, int n, const uint8_t *h)
{
    c->n = n; c->m = 2 * n;
    memset(c->H, 0, sizeof c->H);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++)
            if (h[((i - j) % n + n) % n])
                pose(c->H[i], j);
        pose(c->H[i], n + i);
    }
}

static void syndrome_qc(int n, const uint8_t *h, const uint8_t *x, const uint8_t *y, uint8_t *s)
{
    for (int i = 0; i < n; i++) {
        uint8_t a = y[i];
        for (int j = 0; j < n; j++)
            a ^= x[j] & h[((i - j) % n + n) % n];
        s[i] = a;
    }
}

typedef struct { double moy, pred_log2, ratio; long inst; } stat_t;

static stat_t mesure_qc(int n, int w, int T, long inst, uint64_t graine)
{
    double somme = 0;
#pragma omp parallel for schedule(dynamic) reduction(+ : somme)
    for (long k = 0; k < inst; k++) {
        alea_t g;
        alea_init(&g, graine + (uint64_t)k);
        uint8_t h[NMAX], x[NMAX], y[NMAX], (*S)[NMAX] = malloc(sizeof(uint8_t[NMAX]) * NMAX);
        for (int i = 0; i < n; i++)
            h[i] = (uint8_t)(alea64(&g) & 1);
        creux(&g, n, w, x);
        creux(&g, n, w, y);
        code_t *c = malloc(sizeof *c);
        qc(c, n, h);
        syndrome_qc(n, h, x, y, S[0]);
        for (int t = 1; t < T; t++)                     /* z^t·s : décalage cyclique */
            for (int i = 0; i < n; i++)
                S[t][(i + t) % n] = S[0][i];
        int cible;
        somme += (double)prange(c, (const uint8_t(*)[NMAX])S, T, 2 * w, &g, &cible);
        free(c); free(S);
    }
    stat_t s = {somme / inst, log2_binom(2 * n, 2 * w) - log2_binom(n, 2 * w), 0, inst};
    s.ratio = s.moy / pow(2.0, s.pred_log2);
    return s;
}

static stat_t mesure_aleatoire(int n, int r, int w, long inst, uint64_t graine)
{
    double somme = 0;
#pragma omp parallel for schedule(dynamic) reduction(+ : somme)
    for (long k = 0; k < inst; k++) {
        alea_t g;
        alea_init(&g, graine + (uint64_t)k);
        code_t *c = malloc(sizeof *c);
        c->n = r; c->m = n;
        memset(c->H, 0, sizeof c->H);
        for (int i = 0; i < r; i++)
            for (int j = 0; j < n; j++)
                if (alea64(&g) & 1)
                    pose(c->H[i], j);
        uint8_t e[2 * NMAX], (*S)[NMAX] = malloc(sizeof(uint8_t[NMAX]));
        creux(&g, n, w, e);
        for (int i = 0; i < r; i++) {
            uint8_t a = 0;
            for (int j = 0; j < n; j++)
                a ^= e[j] & (uint8_t)bit(c->H[i], j);
            S[0][i] = a;
        }
        int cible;
        somme += (double)prange(c, (const uint8_t(*)[NMAX])S, 1, w, &g, &cible);
        free(c); free(S);
    }
    stat_t s = {somme / inst, log2_binom(n, w) - log2_binom(r, w), 0, inst};
    s.ratio = s.moy / pow(2.0, s.pred_log2);
    return s;
}

/* rang sur F2 de {s_k ⊕ s_0}, h fixé, K clés */
__attribute__((unused)) static int rang_differences(int n, int w, int K, uint64_t graine, int *parite_constante)
{
    alea_t g;
    alea_init(&g, graine);
    uint8_t h[NMAX], x[NMAX], y[NMAX], s[NMAX], s0[NMAX];
    for (int i = 0; i < n; i++)
        h[i] = (uint8_t)(alea64(&g) & 1);
    uint64_t B[2 * NMAX][LMAX];
    int nl = 0, rang = 0, par0 = -1;
    *parite_constante = 1;
    for (int k = 0; k <= K; k++) {
        creux(&g, n, w, x); creux(&g, n, w, y);
        syndrome_qc(n, h, x, y, s);
        int par = 0;
        for (int i = 0; i < n; i++) par ^= s[i];
        if (par0 < 0) { par0 = par; memcpy(s0, s, (size_t)n); continue; }
        *parite_constante &= par == par0;
        memset(B[nl], 0, sizeof B[nl]);
        for (int i = 0; i < n; i++)
            if (s[i] ^ s0[i])
                pose(B[nl], i);
        nl++;
    }
    for (int col = 0; col < n; col++) {               /* élimination */
        int r = rang;
        while (r < nl && !bit(B[r], col)) r++;
        if (r == nl) continue;
        for (int k = 0; k < LMAX; k++) { uint64_t t = B[r][k]; B[r][k] = B[rang][k]; B[rang][k] = t; }
        for (int i = 0; i < nl; i++)
            if (i != rang && bit(B[i], col))
                for (int k = 0; k < LMAX; k++) B[i][k] ^= B[rang][k];
        rang++;
    }
    return rang;
}

#ifndef ISD_SANS_MAIN
int main(void)
{
    resultat_t res = {.nom = "isd_reel"};
    /* 1. KEM quasi-cyclique, cible unique */
    static const int QC[][3] = {{101, 4, 400}, {131, 5, 300}, {149, 6, 200}};
    char buf[4096] = "[";
    int ok_qc = 1;
    for (int k = 0; k < 3; k++) {
        int n = QC[k][0], w = QC[k][1];
        if (!artin(n)) { fprintf(stderr, "%d n'est pas d'Artin\n", n); return 1; }
        stat_t s = mesure_qc(n, w, 1, QC[k][2], 1000u * (uint64_t)k);
        ok_qc &= s.ratio > 0.75 && s.ratio < 1.33;
        snprintf(buf + strlen(buf), sizeof buf - strlen(buf),
                 "%s{\"n\": %d, \"w\": %d, \"instances\": %ld, \"iterations_log2\": %.2f, \"prevision_log2\": %.2f, \"ratio\": %.3f}",
                 k ? ", " : "", n, w, s.inst, log2(s.moy), s.pred_log2, s.ratio);
        fprintf(stderr, "QC n=%d w=%d : mesuré 2^%.2f, prévu 2^%.2f (ratio %.3f)\n", n, w, log2(s.moy), s.pred_log2, s.ratio);
    }
    strcat(buf, "]");
    res_mesure(&res, "kem_qc_prange", "%s", buf);
    res_controle(&res, "kem_qc_cout_prange_conforme_a_la_formule", ok_qc);
    /* 2. gain quasi-cyclique (n syndromes décalés) */
    int n2 = 149, w2 = 6;
    stat_t un = mesure_qc(n2, w2, 1, 200, 77000), tous = mesure_qc(n2, w2, n2, 200, 77000);
    double gain = un.moy / tous.moy;
    res_mesure(&res, "gain_quasi_cyclique", "{\"n\": %d, \"w\": %d, \"gain_iterations\": %.1f, \"gain_log2\": %.2f, "
               "\"credit_estimateur_log2\": %.2f}", n2, w2, gain, log2(gain), log2((double)n2));
    fprintf(stderr, "gain QC : ×%.1f (2^%.2f) ; l'estimateur crédite 2^%.2f\n", gain, log2(gain), log2((double)n2));
    res_controle(&res, "gain_quasi_cyclique_ne_depasse_pas_le_credit_de_l_estimateur", gain <= 1.3 * n2);
    res_controle(&res, "gain_quasi_cyclique_reel_et_significatif", gain >= 0.2 * n2);
    /* 3. SIG : code aléatoire de rendement 1/2 */
    static const int RA[][4] = {{160, 80, 9, 300}, {200, 100, 11, 200}};
    char buf2[2048] = "[";
    int ok_ra = 1;
    for (int k = 0; k < 2; k++) {
        stat_t s = mesure_aleatoire(RA[k][0], RA[k][1], RA[k][2], RA[k][3], 5000u + 1000u * (uint64_t)k);
        ok_ra &= s.ratio > 0.75 && s.ratio < 1.33;
        snprintf(buf2 + strlen(buf2), sizeof buf2 - strlen(buf2),
                 "%s{\"n\": %d, \"r\": %d, \"w\": %d, \"instances\": %ld, \"iterations_log2\": %.2f, \"prevision_log2\": %.2f, \"ratio\": %.3f}",
                 k ? ", " : "", RA[k][0], RA[k][1], RA[k][2], s.inst, log2(s.moy), s.pred_log2, s.ratio);
        fprintf(stderr, "aléatoire n=%d w=%d : mesuré 2^%.2f, prévu 2^%.2f (ratio %.3f)\n", RA[k][0], RA[k][2], log2(s.moy), s.pred_log2, s.ratio);
    }
    strcat(buf2, "]");
    res_mesure(&res, "sig_aleatoire_prange", "%s", buf2);
    res_controle(&res, "sig_cout_prange_conforme_a_la_formule", ok_ra);
    /* 4. invariants linéaires */
    static const int NA[] = {101, 131, 149, 163, 197, 227};
    char buf3[1024] = "{";
    int ok_inv = 1;
    for (int k = 0; k < 6; k++) {
        int pc, rg = rang_differences(NA[k], 6 + k, NA[k] + 40, 9000u + (uint64_t)k, &pc);
        ok_inv &= artin(NA[k]) && rg == NA[k] - 1 && pc;
        snprintf(buf3 + strlen(buf3), sizeof buf3 - strlen(buf3), "%s\"%d\": %d", k ? ", " : "", NA[k], rg);
    }
    strcat(buf3, "}");
    res_mesure(&res, "rang_differences_de_s_par_n", "%s", buf3);
    res_controle(&res, "parite_seul_invariant_lineaire_de_s", ok_inv);
    return res_ecrire(&res);
}
#endif
