/* Prange, Stern, Dumer et BJMM RÉELS sur les mêmes instances réduites de code
 * aléatoire (rendement 1/2, structure de la SIG), confrontés aux formules de
 * sillage_common (isd_prange, _stern, _dumer, _bjmm).
 *
 * Pour chaque algorithme : nombre moyen d'itérations contre 1/P, et coût total
 * mesuré (itérations × (n·r + opérations de listes), l'unité de l'estimateur)
 * contre le coût du modèle. Chaque solution est revérifiée sur H·e = s, poids w.
 * Prange, Stern et Dumer doivent suivre 1/P. BJMM ne doit jamais faire mieux
 * que le modèle, qui suppose une représentation toujours trouvée : l'écart
 * mesuré est la marge prudente de l'estimateur.
 *     build/isd_comparaison   (depuis la racine) → resultats/isd_comparaison.json
 */
#define ISD_SANS_MAIN
#include "isd_reel.c"

#define RESTE 3                                    /* mots : r − l ≤ 192, k + l ≤ 192 */
typedef struct { uint64_t tag, reste[RESTE], sup[RESTE]; } elt_t;
typedef struct { elt_t *v; long n, cap; } liste_t;
enum { PRANGE, STERN, DUMER, BJMM, NB_ALGOS };
typedef struct { int algo, p, l, eps; } algo_t;

static const char *const NOMS[] = {"prange", "stern", "dumer", "bjmm"};

static void ajoute(liste_t *L, const elt_t *e)
{
    if (L->n == L->cap) {
        L->cap = L->cap ? 2 * L->cap : 1024;
        L->v = realloc(L->v, (size_t)L->cap * sizeof(elt_t));
    }
    L->v[L->n++] = *e;
}

static int cmp_tag(const void *a, const void *b)
{
    uint64_t x = ((const elt_t *)a)->tag, y = ((const elt_t *)b)->tag;
    return x < y ? -1 : x > y;
}

static elt_t somme(const elt_t *a, const elt_t *b)
{
    elt_t c = {.tag = a->tag ^ b->tag};
    for (int k = 0; k < RESTE; k++) {
        c.reste[k] = a->reste[k] ^ b->reste[k];
        c.sup[k] = a->sup[k] ^ b->sup[k];
    }
    return c;
}

static int poids(const uint64_t *v)
{
    int s = 0;
    for (int k = 0; k < RESTE; k++)
        s += __builtin_popcountll(v[k]);
    return s;
}

/* Sommes de q colonnes parmi col[0..m[ (q = 0, 1 ou 2) */
static void combinaisons(const elt_t *col, int m, int q, liste_t *L)
{
    L->n = 0;
    if (q == 0) { elt_t z = {0}; ajoute(L, &z); }
    else if (q == 1) for (int i = 0; i < m; i++) ajoute(L, &col[i]);
    else for (int i = 0; i < m; i++) for (int j = i + 1; j < m; j++) { elt_t c = somme(&col[i], &col[j]); ajoute(L, &c); }
}

/* Tout (a, b) ∈ A × B avec a.tag ⊕ b.tag = cible sur le masque : soit ajouté à
 * sortie, soit, si sortie = NULL, comparé à la cible de poids (trouve *sol). */
static long fusion(liste_t *A, liste_t *B, uint64_t cible, uint64_t masque, liste_t *sortie,
                   const elt_t *synd, int w, elt_t *sol, int *trouve)
{
    long ops = A->n + B->n;
    /* B trié sur (tag & masque), par une copie des indices */
    typedef struct { uint64_t cle; long i; } ci_t;
    ci_t *idx = malloc((size_t)(B->n + 1) * sizeof(ci_t));
    for (long i = 0; i < B->n; i++) idx[i] = (ci_t){B->v[i].tag & masque, i};
    qsort(idx, (size_t)B->n, sizeof(ci_t), cmp_tag);
    for (long i = 0; i < A->n; i++) {
        uint64_t x = (A->v[i].tag ^ cible) & masque;
        long lo = 0, hi = B->n;
        while (lo < hi) { long m = (lo + hi) / 2; if (idx[m].cle < x) lo = m + 1; else hi = m; }
        for (long j = lo; j < B->n && idx[j].cle == x; j++) {
            elt_t c = somme(&A->v[i], &B->v[idx[j].i]);
            ops++;
            if (sortie)
                ajoute(sortie, &c);
            else {
                uint64_t r[RESTE];
                for (int k = 0; k < RESTE; k++) r[k] = c.reste[k] ^ synd->reste[k];
                if (poids(c.sup) + poids(r) == w) { *sol = c; *trouve = 1; }
            }
        }
    }
    free(idx);
    return ops;
}

/* Une itération : permutation, élimination (npiv pivots), lignes de tag r−l…r−1.
 * Renvoie 1 et remplit e (vecteur n bits) si une solution est trouvée. */
static int iteration(const code_t *c, const uint8_t *s, const algo_t *a, int w, alea_t *g, long *ops, uint8_t *e)
{
    int r = c->n, n = c->m, l = a->l, perm[2 * NMAX], est_piv[2 * NMAX], pivcol[NMAX];
    int npiv = a->algo == STERN || a->algo == PRANGE ? r : r - l;
    uint64_t A[NMAX][LMAX];
    int mots = (n + 1 + 63) / 64;
    for (int j = 0; j < n; j++) perm[j] = j;
    for (int j = n - 1; j > 0; j--) { int q = (int)alea_borne(g, (uint64_t)j + 1), t = perm[j]; perm[j] = perm[q]; perm[q] = t; }
    for (int i = 0; i < r; i++) {
        memset(A[i], 0, sizeof A[i]);
        for (int j = 0; j < n; j++) if (bit(c->H[i], perm[j])) pose(A[i], j);
        if (s[i]) pose(A[i], n);
    }
    memset(est_piv, 0, sizeof est_piv);
    int piv = 0;
    for (int col = 0; col < n && piv < npiv; col++) {
        int q = piv;
        while (q < r && !bit(A[q], col)) q++;
        if (q == r) continue;
        if (q != piv) for (int k = 0; k < mots; k++) { uint64_t t = A[q][k]; A[q][k] = A[piv][k]; A[piv][k] = t; }
        for (int i = 0; i < r; i++)
            if (i != piv && bit(A[i], col))
                for (int k = 0; k < mots; k++) A[i][k] ^= A[piv][k];
        est_piv[col] = 1;
        pivcol[piv++] = col;
    }
    if (piv < npiv) return 0;
    *ops += (long)n * r;
    /* colonnes libres et syndrome, vus sur reste (lignes < r−l) et tag (lignes ≥ r−l) */
    elt_t col[NMAX], synd = {0};
    int libres[NMAX], m = 0;
    for (int j = 0; j < n; j++) {
        if (est_piv[j]) continue;
        elt_t x = {0};
        for (int i = 0; i < r - l; i++) if (bit(A[i], j)) x.reste[i >> 6] |= 1ULL << (i & 63);
        for (int i = r - l; i < r; i++) if (bit(A[i], j)) x.tag |= 1ULL << (i - (r - l));
        x.sup[m >> 6] |= 1ULL << (m & 63);
        libres[m] = j;
        col[m++] = x;
    }
    for (int i = 0; i < r - l; i++) if (bit(A[i], n)) synd.reste[i >> 6] |= 1ULL << (i & 63);
    for (int i = r - l; i < r; i++) if (bit(A[i], n)) synd.tag |= 1ULL << (i - (r - l));
    elt_t sol = {0};
    int trouve = 0;
    uint64_t tout = l ? (l == 64 ? ~0ULL : (1ULL << l) - 1) : 0;
    if (a->algo == PRANGE) {
        if (poids(synd.reste) == w) trouve = 1;
    } else if (a->algo == STERN || a->algo == DUMER) {
        liste_t X = {0}, Y = {0};
        combinaisons(col, m / 2, a->p / 2, &X);
        combinaisons(col + m / 2, m - m / 2, a->p / 2, &Y);
        *ops += fusion(&X, &Y, synd.tag, tout, NULL, &synd, w, &sol, &trouve);
        free(X.v); free(Y.v);
    } else {
        int p1 = a->p / 2 + a->eps;
        double R = log2_binom(a->p, a->p / 2) + (a->eps ? log2_binom(m - a->p, a->eps) : 0);
        int l1 = (int)(R + 0.5);
        if (l1 > l) l1 = l;
        uint64_t bas = (1ULL << l1) - 1, t = alea64(g) & bas;
        liste_t B1 = {0}, B2 = {0}, X = {0}, Y = {0};
        combinaisons(col, m / 2, p1 / 2, &B1);
        combinaisons(col + m / 2, m - m / 2, p1 / 2, &B2);
        *ops += fusion(&B1, &B2, t, bas, &X, &synd, w, &sol, &trouve);
        *ops += fusion(&B1, &B2, synd.tag ^ t, bas, &Y, &synd, w, &sol, &trouve);
        *ops += fusion(&X, &Y, synd.tag, tout, NULL, &synd, w, &sol, &trouve);
        free(B1.v); free(B2.v); free(X.v); free(Y.v);
    }
    if (!trouve) return 0;
    /* reconstruction : colonnes libres de sol, pivots des lignes de reste actives */
    memset(e, 0, (size_t)n);
    for (int q = 0; q < m; q++)
        if (sol.sup[q >> 6] >> (q & 63) & 1) e[perm[libres[q]]] = 1;
    for (int i = 0; i < r - l && i < piv; i++)
        if (((sol.reste[i >> 6] ^ synd.reste[i >> 6]) >> (i & 63)) & 1) e[perm[pivcol[i]]] = 1;
    return 1;
}

typedef struct { double iters, ops, modele_iters_log2, modele_cout_log2; long invalides; } mes_t;

/* Modèle de sillage_common pour ces paramètres : itérations, coût par itération */
static void modele(int n, int r, int w, const algo_t *a, double *it, double *cout)
{
    int k = n - r, l = a->l, p = a->p;
    double base = log2_binom(n, w), nr = (double)n * r;
    if (a->algo == PRANGE) {
        *it = base - log2_binom(r, w);
        *cout = *it + log2(nr);
        return;
    }
    if (a->algo == BJMM) {
        int p1 = p / 2 + a->eps;
        double R = log2_binom(p, p / 2) + (a->eps ? log2_binom(k + l - p, a->eps) : 0);
        double l1 = R < l ? R : l;
        double L0 = log2_binom((k + l) / 2, p1 / 2), L1 = log2_binom(k + l, p1) - l1;
        *it = base - log2_binom(k + l, p) - log2_binom(r - l, w - p);
        *cout = *it + log2(nr + 4 * pow(2, L0) + 2 * pow(2, 2 * L0 - l1) + pow(2, 2 * L1 - (l - l1)));
        return;
    }
    double L = log2_binom((a->algo == STERN ? k : k + l) / 2, p / 2);
    *it = base - 2 * L - log2_binom(r - l, w - p);
    *cout = *it + log2(nr + 2 * pow(2, L) + pow(2, 2 * L - l));
}

static mes_t mesure(int n, int r, int w, const algo_t *a, long inst, uint64_t graine)
{
    double s_it = 0, s_ops = 0;
    long inval = 0;
#pragma omp parallel for schedule(dynamic) reduction(+ : s_it, s_ops, inval)
    for (long k = 0; k < inst; k++) {
        alea_t g;
        alea_init(&g, graine + (uint64_t)k);         /* mêmes instances pour tous les algorithmes */
        code_t *c = malloc(sizeof *c);
        c->n = r; c->m = n;
        memset(c->H, 0, sizeof c->H);
        for (int i = 0; i < r; i++)
            for (int j = 0; j < n; j++)
                if (alea64(&g) & 1) pose(c->H[i], j);
        uint8_t e[2 * NMAX], s[NMAX], sol[2 * NMAX];
        creux(&g, n, w, e);
        for (int i = 0; i < r; i++) {
            uint8_t b = 0;
            for (int j = 0; j < n; j++) b ^= e[j] & (uint8_t)bit(c->H[i], j);
            s[i] = b;
        }
        alea_init(&g, graine * 31 + (uint64_t)k + (uint64_t)a->algo * 1000003 + (uint64_t)a->p * 7);
        long it = 0, ops = 0;
        do it++; while (!iteration(c, s, a, w, &g, &ops, sol));
        int wt = 0, ok = 1;
        for (int j = 0; j < n; j++) wt += sol[j];
        for (int i = 0; i < r; i++) {
            uint8_t b = 0;
            for (int j = 0; j < n; j++) b ^= sol[j] & (uint8_t)bit(c->H[i], j);
            ok &= b == s[i];
        }
        inval += !(ok && wt == w);
        s_it += (double)it;
        s_ops += (double)ops;
        free(c);
    }
    mes_t m = {.iters = s_it / inst, .ops = s_ops / inst, .invalides = inval};
    modele(n, r, w, a, &m.modele_iters_log2, &m.modele_cout_log2);
    return m;
}

int main(void)
{
    resultat_t res = {.nom = "isd_comparaison"};
    /* n, r, w, instances ; p et l choisis près de l'optimum de chaque modèle */
    static const int I[][4] = {{200, 100, 11, 240}, {240, 120, 13, 160}, {280, 140, 15, 80}};
    static const algo_t A[] = {{PRANGE, 0, 0, 0}, {STERN, 2, 6, 0}, {STERN, 4, 11, 0}, {DUMER, 2, 6, 0}, {DUMER, 4, 11, 0},
                               {BJMM, 4, 12, 0}, {BJMM, 4, 18, 2}};
    int na = (int)(sizeof A / sizeof *A), ok_suit = 1, ok_bjmm = 1, ok_val = 1, ok_cout = 1, ok_gain = 1;
    char buf[16384] = "[";
    for (int c = 0; c < 3; c++) {
        int n = I[c][0], r = I[c][1], w = I[c][2];
        long inst = I[c][3];
        double prange_ops = 0;
        for (int k = 0; k < na; k++) {
            const algo_t *a = &A[k];
            mes_t m = mesure(n, r, w, a, inst, 424200u + 1000u * (uint64_t)c);
            double ratio = m.iters / pow(2, m.modele_iters_log2), cout = log2(m.ops), tol = 3.5 / sqrt((double)inst);
            if (a->algo == PRANGE) prange_ops = m.ops;
            if (a->algo == BJMM) {
                ok_bjmm &= ratio >= 1 - tol;
            } else {
                ok_suit &= fabs(ratio - 1) <= tol;
                ok_cout &= fabs(cout - m.modele_cout_log2) <= 1.0;
                ok_gain &= a->algo == PRANGE || a->p != 4 || m.ops < prange_ops;
            }
            ok_val &= m.invalides == 0;
            snprintf(buf + strlen(buf), sizeof buf - strlen(buf),
                     "%s{\"n\": %d, \"r\": %d, \"w\": %d, \"algo\": \"%s\", \"p\": %d, \"l\": %d, \"eps\": %d, \"instances\": %ld, "
                     "\"iterations_log2\": %.2f, \"modele_iterations_log2\": %.2f, \"ratio\": %.3f, "
                     "\"cout_log2\": %.2f, \"modele_cout_log2\": %.2f}",
                     strlen(buf) > 1 ? ", " : "", n, r, w, NOMS[a->algo], a->p, a->l, a->eps, inst,
                     log2(m.iters), m.modele_iters_log2, ratio, cout, m.modele_cout_log2);
            fprintf(stderr, "n=%d w=%d %-6s p=%d l=%2d eps=%d : itérations 2^%.2f (modèle 2^%.2f, ratio %.2f), coût 2^%.2f (modèle 2^%.2f)\n",
                    n, w, NOMS[a->algo], a->p, a->l, a->eps, log2(m.iters), m.modele_iters_log2, ratio, cout, m.modele_cout_log2);
        }
    }
    strcat(buf, "]");
    res_mesure(&res, "comparaison", "%s", buf);
    res_controle(&res, "solutions_toutes_valides_H_e_egale_s_poids_w", ok_val);
    res_controle(&res, "prange_stern_dumer_suivent_les_iterations_du_modele", ok_suit);
    res_controle(&res, "prange_stern_dumer_suivent_le_cout_du_modele_a_1_bit", ok_cout);
    res_controle(&res, "stern_dumer_p4_moins_chers_que_prange", ok_gain);
    res_controle(&res, "bjmm_ne_fait_jamais_mieux_que_le_modele", ok_bjmm);
    return res_ecrire(&res);
}
