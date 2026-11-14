/* Borne C_R sur les S-box actives de BRUME-512 : encodage CNF de la relaxation tronquée, et contrôles
 * de l'encodage contre la permutation réelle.
 *
 * Modèle (une variable x[t][v] par tour t et par nibble v, R tours de S-box) :
 *   la couche linéaire entre deux couches de S-box est A, avec A = M (caractéristiques différentielles)
 *   ou A = Mᵀ (caractéristiques linéaires, tours numérotés à l'envers). Pour une sortie v de A et
 *   s = #{k ∈ supp(A[v]) : x[t][k] = 1} :
 *     (T0) s = 0 ⇒ x[t+1][v] = 0 ;   (T1) s = 1 ⇒ x[t+1][v] = 1 ;   s ≥ 2 : libre.
 *   (V)  aucune couche vide (S bijective, A inversible) ;
 *   (F)  faits de branchement exacts, recalculés ici par énumération (poids ≤ 3, A et A⁻¹) :
 *        W_t = w ⇒ W_{t+1} ≥ minA[w] − w ;  W_{t+1} = w ⇒ W_t ≥ minAinv[w] − w ;
 *   (S)  x[0][0] = 1 : le support est invariant par les 128 multiplications à gauche de D₁₂₈
 *        (vérifié ici pour M et Mᵀ), qui envoient tout nibble actif du tour 0 sur le nibble 0 ;
 *   (K)  Σ x ≤ K − 1 (totalisateurs plafonnés à K, dans les deux sens).
 * Insatisfiable ⇒ toute caractéristique réelle de R tours a au moins K S-box actives.
 *
 *   c3_cnf verif                        contrôles (conformité, automorphismes, faits, traînées réelles)
 *   c3_cnf cnf diff|lin R K fichier     écrit la CNF
 *   c3_cnf modele diff|lin R K fichier  relit un modèle (lignes « v » du solveur), le contrôle contre
 *                                       la relaxation, sans passer par la CNF, et imprime le motif
 * Compilation (racine) :
 *   cc -O3 -march=native -fopenmp -I sillage/c -I tests/c prototypes/brume_q/sat/c3_cnf.c \
 *      sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -o tests/c/build/c3_cnf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brume_ref.h"

#ifdef B1024
/* BRUME-1024 (prototypes/brume_q/b1024) : 256 nibbles, D₂₅₆ ; M et M⁻¹ construites depuis b1024_tables.h */
#include "b1024_tables.h"
#define N 256
#define DEMI 128
static uint8_t BM1[N][N], BMI1[N][N];
#define BM BM1
#define BMI BMI1
static int init_largeur(void)
{
    memset(BM1, 0, sizeof BM1);
    for (int v = 0; v < N; v++) {
        BM1[v][v] = B1_CS[v];
        for (int g = 0; g < 6; g++) {
            int i = v % DEMI, f = v / DEMI, k = B1_K[g];
            int w = f == 0 ? (i + k) % DEMI + DEMI : ((i - k) % DEMI + DEMI) % DEMI;
            BM1[v][w] = B1_CG[g][v];
        }
    }
    static uint8_t T[N][2 * N];
    for (int i = 0; i < N; i++)
        for (int j = 0; j < 2 * N; j++)
            T[i][j] = j < N ? BM1[i][j] : (j - N == i);
    for (int c = 0; c < N; c++) {
        int p = c;
        while (p < N && !T[p][c])
            p++;
        if (p == N)
            return 0;
        if (p != c)
            for (int j = 0; j < 2 * N; j++) { uint8_t t = T[p][j]; T[p][j] = T[c][j]; T[c][j] = t; }
        uint8_t iv = gf_inv(T[c][c]);
        for (int j = 0; j < 2 * N; j++)
            T[c][j] = gf_mul(T[c][j], iv);
        for (int i = 0; i < N; i++)
            if (i != c && T[i][c]) {
                uint8_t f = T[i][c];
                for (int j = 0; j < 2 * N; j++)
                    T[i][j] ^= gf_mul(f, T[c][j]);
            }
    }
    for (int i = 0; i < N; i++)
        memcpy(BMI1[i], T[i] + N, N);
    return 1;
}
#define CONFORMITE() 1   /* la conformité des tables à la permutation est contrôlée par brume1024.c */
#else
#define N BR_N
#define DEMI 64
static int init_largeur(void) { return 1; }
#define CONFORMITE() bref_conforme(64)
#endif
#define RMAX 6

static uint8_t SUP[2][N][N];      /* SUP[0] = supp(M), SUP[1] = supp(Mᵀ) */
static uint8_t MT[N][N], MIT[N][N]; /* Mᵀ, (M⁻¹)ᵀ = (Mᵀ)⁻¹ */
static int FAIT[4][4];            /* min_{wt x = w} wt x + wt(A x), A ∈ {M, M⁻¹, Mᵀ, (Mᵀ)⁻¹}, w = 1..3 */
static int LID[RMAX][N + 2], NLID[RMAX]; /* variables unaires par couche : LID[t][k] ⇔ W_t ≥ k (k ≤ K) */

/* ---------- D_N = Z/DEMI ⋊ Z/2, élément a = (a mod DEMI) + DEMI·flip (définition de sillage/brume512.py) ---------- */
static int gop(int a, int b)
{
    int aa = a % DEMI, ab = a / DEMI, ba = b % DEMI, bb = b / DEMI;
    int ra = (aa + (ab == 0 ? ba : (DEMI - ba) % DEMI)) % DEMI;
    return ra + DEMI * (ab ^ bb);
}

/* ---------- faits de branchement ---------- */
static int poids(const uint8_t *x)
{
    int n = 0;
    for (int i = 0; i < N; i++)
        n += x[i] != 0;
    return n;
}

/* min de wt(x) + wt(A x) sur wt(x) = w ; le premier coefficient est fixé à 1 (wt(A·cx) = wt(A x)).
 * COL[k][c][v] = c·A[v][k] : colonnes multipliées, pour que la boucle interne se vectorise. */
static uint8_t COL[N][16][N];

static int min_branche(const uint8_t A[N][N], int w)
{
    for (int k = 0; k < N; k++)
        for (int c = 0; c < 16; c++)
            for (int v = 0; v < N; v++)
                COL[k][c][v] = gf_mul(A[v][k], (uint8_t)c);
    int best = 1 << 30;
#pragma omp parallel for schedule(dynamic) reduction(min : best)
    for (int i = 0; i < N; i++) {
        if (w == 1) {
            int n = 1;
            for (int v = 0; v < N; v++)
                n += COL[i][1][v] != 0;
            if (n < best)
                best = n;
            continue;
        }
        for (int j = i + 1; j < N; j++)
            for (int b = 1; b < 16; b++) {
                if (w == 2) {
                    int n = 2;
                    for (int v = 0; v < N; v++)
                        n += (COL[i][1][v] ^ COL[j][b][v]) != 0;
                    if (n < best)
                        best = n;
                    continue;
                }
                uint8_t y[N];
                for (int v = 0; v < N; v++)
                    y[v] = COL[i][1][v] ^ COL[j][b][v];
                for (int k = j + 1; k < N; k++)
                    for (int c = 1; c < 16; c++) {
                        int n = 3;
                        for (int v = 0; v < N; v++)
                            n += (y[v] ^ COL[k][c][v]) != 0;
                        if (n < best)
                            best = n;
                    }
            }
    }
    return best;
}

/* ---------- CNF ---------- */
typedef struct {
    int nv, nc, cap;
    int *lits;      /* clauses à la suite, terminées par 0 */
    int nl, capl;
    /* sémantique des variables auxiliaires : aux[v] = (masque des tours, seuil k) — x[t][·] du masque ≥ k */
    int *aux_masque, *aux_k, *aux_debut, *aux_fin; /* intervalle de nibbles [debut, fin) dans l'ordre (t, v) */
} cnf_t;

static void ajoute(cnf_t *f, const int *c, int n)
{
    if (f->nl + n + 1 > f->capl) {
        f->capl = 2 * (f->nl + n + 1) + 1024;
        f->lits = realloc(f->lits, sizeof(int) * f->capl);
    }
    memcpy(f->lits + f->nl, c, sizeof(int) * n);
    f->nl += n;
    f->lits[f->nl++] = 0;
    f->nc++;
}

static int var_x(int t, int v) { return 1 + t * N + v; }

static int nouvelle(cnf_t *f, int debut, int fin, int k)
{
    int v = ++f->nv;
    if (v >= f->cap) {
        f->cap = 2 * v + 1024;
        f->aux_k = realloc(f->aux_k, sizeof(int) * f->cap);
        f->aux_debut = realloc(f->aux_debut, sizeof(int) * f->cap);
        f->aux_fin = realloc(f->aux_fin, sizeof(int) * f->cap);
    }
    f->aux_k[v] = k;
    f->aux_debut[v] = debut;
    f->aux_fin[v] = fin;
    return v;
}

/* totalisateur sur les positions linéaires [debut, fin) (position p ↔ x[p / N][p % N]) ; o[1..n] avec
 * o[k] ⇔ (nombre de vrais ≥ k), plafonné à K : o[K] ⇔ (≥ K). Retourne n = min(fin − debut, K). */
static int fusionne(cnf_t *f, const int *a, int na, const int *b, int nb, int debut, int fin, int K, int *o);

static int totalise(cnf_t *f, int debut, int fin, int K, int *o)
{
    if (fin - debut == 1) {
        o[1] = 1 + debut;
        return 1;
    }
    int mil = (debut + fin) / 2;
    int *a = malloc(sizeof(int) * (K + 2)), *b = malloc(sizeof(int) * (K + 2));
    int na = totalise(f, debut, mil, K, a), nb = totalise(f, mil, fin, K, b);
    int n = fusionne(f, a, na, b, nb, debut, fin, K, o);
    free(a);
    free(b);
    return n;
}

/* fusion de deux compteurs unaires a (positions [debut, ·)) et b (positions [·, fin)), contigus */
static int fusionne(cnf_t *f, const int *a, int na, const int *b, int nb, int debut, int fin, int K, int *o)
{
    int n = na + nb < K ? na + nb : K;
    for (int k = 1; k <= n; k++)
        o[k] = nouvelle(f, debut, fin, k);
    for (int i = 0; i <= na; i++)
        for (int j = 0; j <= nb; j++) {
            if (i + j >= 1) {          /* a_i ∧ b_j ⇒ o_{min(i+j, K)} */
                int c[3], m = 0;
                if (i)
                    c[m++] = -a[i];
                if (j)
                    c[m++] = -b[j];
                c[m++] = o[i + j < n ? i + j : n];
                ajoute(f, c, m);
            }
            if (i + j + 1 <= n) {      /* ¬a_{i+1} ∧ ¬b_{j+1} ⇒ ¬o_{i+j+1} */
                int c[3], m = 0;
                if (i + 1 <= na)
                    c[m++] = a[i + 1];
                if (j + 1 <= nb)
                    c[m++] = b[j + 1];
                c[m++] = -o[i + j + 1];
                ajoute(f, c, m);
            }
        }
    return n;
}

/* cnf de la relaxation, matrice s (0 : M, 1 : Mᵀ), faits fa (A) et fi (A⁻¹) */
static void construit(cnf_t *f, int s, int R, int K, int sym)
{
    memset(f, 0, sizeof *f);
    f->nv = R * N;
    f->cap = f->nv + 1024;
    f->aux_k = calloc(f->cap, sizeof(int));
    f->aux_debut = calloc(f->cap, sizeof(int));
    f->aux_fin = calloc(f->cap, sizeof(int));
    const int *fa = FAIT[s == 0 ? 0 : 2], *fi = FAIT[s == 0 ? 1 : 3];
    int c[N + 2];
    for (int t = 0; t + 1 < R; t++)
        for (int v = 0; v < N; v++) {
            int K7[N], nk = 0;
            for (int k = 0; k < N; k++)
                if (SUP[s][v][k])
                    K7[nk++] = k;
            /* (T0) x[t+1][v] ⇒ ∨ x[t][k] */
            int m = 0;
            c[m++] = -var_x(t + 1, v);
            for (int q = 0; q < nk; q++)
                c[m++] = var_x(t, K7[q]);
            ajoute(f, c, m);
            /* (T1) x[t][k] ∧ ∧_{k' ≠ k} ¬x[t][k'] ⇒ x[t+1][v] */
            for (int q = 0; q < nk; q++) {
                m = 0;
                c[m++] = -var_x(t, K7[q]);
                for (int qq = 0; qq < nk; qq++)
                    if (qq != q)
                        c[m++] = var_x(t, K7[qq]);
                c[m++] = var_x(t + 1, v);
                ajoute(f, c, m);
            }
        }
    for (int t = 0; t < R; t++) {     /* (V) */
        for (int v = 0; v < N; v++)
            c[v] = var_x(t, v);
        ajoute(f, c, N);
    }
    int L[RMAX][N + 2];
    for (int t = 0; t < R; t++)
        NLID[t] = totalise(f, t * N, (t + 1) * N, K, L[t]);
    memcpy(LID, L, sizeof L);
    for (int t = 0; t + 1 < R; t++)    /* (F) */
        for (int w = 1; w <= 3 && w + 1 <= K; w++) {
            int seuil = fa[w] - w, cible = seuil < K ? seuil : K;
            int cl[3] = {-L[t][w], L[t][w + 1], L[t + 1][cible]};
            ajoute(f, cl, 3);
            seuil = fi[w] - w;
            cible = seuil < K ? seuil : K;
            int cl2[3] = {-L[t + 1][w], L[t + 1][w + 1], L[t][cible]};
            ajoute(f, cl2, 3);
        }
    /* (K) : compteur global obtenu en fusionnant les compteurs de couche (les cubes sur W_t propagent) */
    int T[N * RMAX + 2], nT = NLID[0];
    memcpy(T, L[0], sizeof(int) * (NLID[0] + 1));
    for (int t = 1; t < R; t++) {
        int U[N * RMAX + 2];
        nT = fusionne(f, T, nT, L[t], NLID[t], 0, (t + 1) * N, K, U);
        memcpy(T, U, sizeof(int) * (nT + 1));
    }
    if (nT >= K) {
        int u = -T[K];
        ajoute(f, &u, 1);
    }
    if (sym) {                          /* (S) */
        int u = var_x(0, 0);
        ajoute(f, &u, 1);
    }
}

/* évalue toutes les clauses sous l'affectation des x, auxiliaires fixés à leur sémantique exacte */
static int evalue(const cnf_t *f, const uint8_t *x /* R·N */)
{
    uint8_t *val = calloc(f->nv + 1, 1);
    for (int v = 1; v <= f->nv; v++) {
        if (f->aux_k[v] == 0) {
            val[v] = x[v - 1];
            continue;
        }
        int n = 0;
        for (int p = f->aux_debut[v]; p < f->aux_fin[v]; p++)
            n += x[p];
        val[v] = n >= f->aux_k[v];
    }
    int fausses = 0, sat = 0;
    for (int i = 0; i < f->nl; i++) {
        int l = f->lits[i];
        if (l == 0) {
            fausses += !sat;
            sat = 0;
            continue;
        }
        sat |= l > 0 ? val[l] : !val[-l];
    }
    free(val);
    return fausses;
}

/* ---------- traînées réelles ---------- */
static uint64_t g_alea = 0x9E3779B97F4A7C15ULL;
static uint32_t alea(void)
{
    g_alea ^= g_alea << 13;
    g_alea ^= g_alea >> 7;
    g_alea ^= g_alea << 17;
    return (uint32_t)(g_alea >> 11);
}

static uint8_t DDT[16][16], LAT_NZ[16][16], GT[16][16];

static void tables_sbox(void)
{
    for (int a = 0; a < 16; a++)
        for (int x = 0; x < 16; x++)
            DDT[a][BR_SBOX[x] ^ BR_SBOX[x ^ a]]++;
    for (int a = 0; a < 16; a++)
        for (int b = 0; b < 16; b++) {
            int s = 0;
            for (int x = 0; x < 16; x++)
                s += (__builtin_popcount((a & x) ^ (b & BR_SBOX[x])) & 1) ? -1 : 1;
            LAT_NZ[a][b] = s != 0;
        }
    /* adjoint binaire de la multiplication par c : bit k de GT[c][μ] = <μ, c·x^k> */
    for (int c = 0; c < 16; c++)
        for (int mu = 0; mu < 16; mu++) {
            int r = 0;
            for (int k = 0; k < 4; k++)
                r |= (__builtin_popcount(mu & gf_mul((uint8_t)c, (uint8_t)(1 << k))) & 1) << k;
            GT[c][mu] = (uint8_t)r;
        }
}

/* traînée différentielle réelle : différences de sortie de S tirées parmi DDT > 0, puis M (GF(16)) ;
 * traînée linéaire réelle (sens inverse) : masque d'entrée tiré parmi LAT ≠ 0, puis l'adjoint binaire
 * de M. Remplit le motif x[t][v] dans l'ordre du modèle. Retourne 0 si la traînée s'éteint (impossible). */
static int trainee(int s, int R, uint8_t *pat)
{
    uint8_t d[N] = {0};
    int w0 = 1 + alea() % 4;
    for (int q = 0; q < w0; q++)
        d[alea() % N] = (uint8_t)(1 + alea() % 15);
    for (int t = 0; t < R; t++) {
        for (int v = 0; v < N; v++)
            pat[t * N + v] = d[v] != 0;
        if (!poids(d))
            return 0;
        uint8_t e[N];
        for (int v = 0; v < N; v++) {   /* transition de S-box */
            if (!d[v]) {
                e[v] = 0;
                continue;
            }
            uint8_t o;
            do
                o = (uint8_t)(1 + alea() % 15);
            while (s == 0 ? !DDT[d[v]][o] : !LAT_NZ[o][d[v]]);
            e[v] = o;   /* diff : sortie de S ; lin : d = masque de sortie de S, e = masque d'entrée */
        }
        for (int v = 0; v < N; v++) {   /* couche linéaire */
            uint8_t a = 0;
            for (int k = 0; k < N; k++)
                if (s == 0 && BM[v][k])
                    a ^= gf_mul(BM[v][k], e[k]);
                else if (s == 1 && BM[k][v])
                    a ^= GT[BM[k][v]][e[k]];  /* b_v = Σ_k L_{M[k][v]}ᵀ a_k */
            d[v] = a;
        }
    }
    return 1;
}

static int verif(void)
{
    int ok = 1;
    int conf = CONFORMITE();
    printf("conformite_tables_vs_sl_brume_permute %s\n", conf ? "OK" : "ECHEC");
    ok &= conf;
    for (int v = 0; v < N; v++)
        for (int k = 0; k < N; k++) {
            MT[v][k] = BM[k][v];
            MIT[v][k] = BMI[k][v];
            SUP[0][v][k] = BM[v][k] != 0;
            SUP[1][v][k] = BM[k][v] != 0;
        }
    int sym = 1, lignes = 1;
    for (int v = 0; v < N; v++) {
        int n = 0;
        for (int k = 0; k < N; k++) {
            n += SUP[0][v][k];
            sym &= SUP[0][v][k] == SUP[1][v][k];
        }
        lignes &= n == 7;
    }
    printf("support_7_par_ligne %s ; support_symetrique (supp M = supp Mt) %s\n", lignes ? "OK" : "ECHEC",
           sym ? "OK" : "NON");
    ok &= lignes;
    int aut = 1;
    for (int h = 0; h < N; h++)
        for (int s = 0; s < 2; s++)
            for (int v = 0; v < N; v++)
                for (int k = 0; k < N; k++)
                    aut &= SUP[s][gop(h, v)][gop(h, k)] == SUP[s][v][k];
    int trans = 1;
    for (int h = 0; h < N; h++)
        trans &= gop(h, 0) == h;
    printf("automorphismes_gauche_D%d (%d, supports M et Mt) %s ; transitifs (h·0 = h) %s\n", N, N, aut ? "OK" : "ECHEC",
           trans ? "OK" : "ECHEC");
    ok &= aut && trans;
    const char *nom[4] = {"M", "M_inv", "Mt", "Mt_inv"};
    const uint8_t(*mat[4])[N] = {BM, BMI, MT, MIT};
    for (int a = 0; a < 4; a++) {
        printf("branchement %-6s :", nom[a]);
        for (int w = 1; w <= 3; w++) {
            FAIT[a][w] = min_branche(mat[a], w);
            printf(" w=%d -> %d", w, FAIT[a][w]);
        }
        printf("\n");
    }
    int b8 = FAIT[0][1] == 8 && FAIT[2][1] == 8;
    for (int a = 0; a < 4; a++)
        for (int w = 1; w <= 3; w++)
            b8 &= FAIT[a][w] >= 8;
    printf("B_differentiel = B_lineaire = 8 (exact : poids <= 3 des deux cotes) %s\n", b8 ? "OK" : "ECHEC");
    ok &= b8;
    return ok;
}

static void lit_faits_rapide(void)
{
    /* les mêmes contrôles que verif, sans les impressions, pour les modes cnf et modele */
    if (!verif()) {
        fprintf(stderr, "controles en echec\n");
        exit(1);
    }
}

static int traines_reelles(int nb)
{
    tables_sbox();
    int ok = 1;
    for (int s = 0; s < 2; s++)
        for (int R = 2; R <= 4; R++) {
            cnf_t f;
            construit(&f, s, R, R * N + 1, 1);
            int fautes = 0, totmin = 1 << 30;
            uint8_t pat[RMAX * N], img[RMAX * N];
            for (int e = 0; e < nb; e++) {
                if (!trainee(s, R, pat)) {
                    fautes++;
                    continue;
                }
                /* (S) : envoie un nibble actif du tour 0 sur 0 par v ↦ h⁻¹·v */
                int a = 0;
                while (!pat[a])
                    a++;
                int hi = 0;
                while (gop(hi, a) != 0)
                    hi++;
                for (int t = 0; t < R; t++)
                    for (int v = 0; v < N; v++)
                        img[t * N + gop(hi, v)] = pat[t * N + v];
                int tot = 0;
                for (int p = 0; p < R * N; p++)
                    tot += img[p];
                if (tot < totmin)
                    totmin = tot;
                fautes += evalue(&f, img) != 0;
            }
            printf("trainees_reelles %s R=%d : %d tirages, %d clause(s) violee(s) ; min actives observe %d ; CNF %d var, %d clauses\n",
                   s ? "lin" : "diff", R, nb, fautes, totmin, f.nv, f.nc);
            ok &= fautes == 0;
            free(f.lits);
            free(f.aux_k);
            free(f.aux_debut);
            free(f.aux_fin);
        }
    return ok;
}

/* contrôle direct d'un motif contre la relaxation (sans la CNF) */
static int relaxation_directe(int s, int R, const uint8_t *x, int *w)
{
    const int *fa = FAIT[s == 0 ? 0 : 2], *fi = FAIT[s == 0 ? 1 : 3];
    int ok = 1;
    for (int t = 0; t < R; t++) {
        w[t] = 0;
        for (int v = 0; v < N; v++)
            w[t] += x[t * N + v];
        ok &= w[t] > 0;
    }
    for (int t = 0; t + 1 < R; t++) {
        for (int v = 0; v < N; v++) {
            int n = 0;
            for (int k = 0; k < N; k++)
                n += SUP[s][v][k] && x[t * N + k];
            if (n == 0)
                ok &= !x[(t + 1) * N + v];
            if (n == 1)
                ok &= x[(t + 1) * N + v];
        }
        if (w[t] <= 3)
            ok &= w[t + 1] >= fa[w[t]] - w[t];
        if (w[t + 1] <= 3)
            ok &= w[t] >= fi[w[t + 1]] - w[t + 1];
    }
    return ok;
}

int main(int argc, char **argv)
{
    if (!bref_init() || !init_largeur())
        return 2;
    printf("largeur : %d nibbles\n", N);
    if (argc >= 2 && !strcmp(argv[1], "verif")) {
        int ok = verif();
        ok &= traines_reelles(argc > 2 ? atoi(argv[2]) : 20000);
        printf("c3_cnf_controles %s\n", ok ? "OK" : "ECHEC");
        return ok ? 0 : 1;
    }
    if (argc == 6 && !strcmp(argv[1], "cnf")) {
        int s = !strcmp(argv[2], "lin"), R = atoi(argv[3]), K = atoi(argv[4]);
        if (R < 2 || R > RMAX || K < 2)
            return 2;
        lit_faits_rapide();
        cnf_t f;
        construit(&f, s, R, K, 1);
        FILE *o = fopen(argv[5], "w");
        if (!o)
            return 2;
        fprintf(o, "c BRUME-%d, relaxation tronquee, %s, R = %d, total <= %d, x[0][0] = 1\n", 4 * N, s ? "lineaire (Mt)" : "differentiel (M)", R, K - 1);
        fprintf(o, "p cnf %d %d\n", f.nv, f.nc);
        for (int i = 0; i < f.nl; i++)
            fprintf(o, f.lits[i] ? "%d " : "0\n", f.lits[i]);
        fclose(o);
        char nom[4096];
        snprintf(nom, sizeof nom, "%s.unaires", argv[5]);
        o = fopen(nom, "w");
        if (!o)
            return 2;
        for (int t = 0; t < R; t++)
            for (int k = 1; k <= NLID[t]; k++)
                fprintf(o, "%d %d %d\n", t, k, LID[t][k]);
        fclose(o);
        printf("cnf %s R=%d K=%d : %d variables, %d clauses -> %s\n", s ? "lin" : "diff", R, K, f.nv, f.nc, argv[5]);
        return 0;
    }
    if (argc == 6 && !strcmp(argv[1], "modele")) {
        int s = !strcmp(argv[2], "lin"), R = atoi(argv[3]), K = atoi(argv[4]);
        lit_faits_rapide();
        FILE *in = fopen(argv[5], "r");
        if (!in)
            return 2;
        uint8_t x[RMAX * N] = {0};
        char ligne[1 << 16];
        while (fgets(ligne, sizeof ligne, in)) {
            if (ligne[0] != 'v')
                continue;
            char *p = ligne + 1, *q;
            for (;;) {
                long l = strtol(p, &q, 10);
                if (q == p)
                    break;
                p = q;
                if (l > 0 && l <= R * N)
                    x[l - 1] = 1;
            }
        }
        fclose(in);
        int w[RMAX], ok = relaxation_directe(s, R, x, w), tot = 0;
        printf("modele %s R=%d : motif [", s ? "lin" : "diff", R);
        for (int t = 0; t < R; t++) {
            printf(t ? ", %d" : "%d", w[t]);
            tot += w[t];
        }
        /* la CNF plafonnée à K, auxiliaires recalculés depuis leur sémantique exacte, doit être satisfaite */
        cnf_t f;
        construit(&f, s, R, K, 1);
        int faux = evalue(&f, x);
        printf("] total %d ; relaxation directe %s ; CNF K=%d, auxiliaires exacts : %d clause(s) fausse(s)\n", tot,
               ok ? "OK" : "VIOLEE", K, faux);
        return ok && !faux ? 0 : 1;
    }
    fprintf(stderr, "usage : %s verif [n] | cnf diff|lin R K fichier | modele diff|lin R K fichier\n", argv[0]);
    return 2;
}
