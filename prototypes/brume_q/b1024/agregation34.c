/* Agrégation à 3 et 4 tours de BRUME-1024q (étude « effet de groupe », ETUDE_GROUPE_STRUCTURE.md § A) : probabilité EXACTE
 * d'une différentielle, ou corrélation EXACTE d'une coque linéaire, entre deux extrémités fixées, en sommant TOUS les
 * chemins (caractéristiques) qui les relient, comparée au meilleur chemin seul (facteur d'agrégation).
 *
 * Forme étudiée : un seul nibble actif à une extrémité (l'extrémité « proche »), comme les meilleures caractéristiques
 * trouvées par trails1024.py ([1, 7, 32] en différentiel à 3 tours, [31, 7, 1] en linéaire). On part de l'extrémité proche
 * et on traverse les couches ℓ = 0, 1, … :
 *   - différentiel : couche ℓ = tour ℓ ; valeur proche = différence d'entrée de la S-box, valeur lointaine = différence de
 *     sortie ; poids DDT[x][y]/16 ; passage à la couche suivante : x' = M·y ;
 *   - linéaire (on remonte) : couche ℓ = tour R−1−ℓ ; valeur proche = masque de sortie de la S-box, lointaine = masque
 *     d'entrée ; poids (−1)^⟨y, RC_t[q]⟩ · LAT[y][x]/8 (S appliquée à x ⊕ RC_t) ; passage : x' = Mᵀ_bin·y (masques).
 * L'extrémité lointaine E est la valeur lointaine de la dernière couche, sur les 256 nibbles (0 hors du support).
 *
 *   DP ou C (a@v → E) = Σ_chemins Π_couches Π_nibbles poids,
 * exact pour le modèle markovien habituel (entrées des S-box indépendantes et uniformes ; c'est l'hypothèse sous laquelle
 * agregation2.c a été confirmé empiriquement à 2 tours, max |z| = 1,65 à 2^31 échantillons). Les constantes ne comptent
 * qu'en linéaire (signes) ; on prend les tours r0 … r0+R−1 (r0 = 0 par défaut).
 *
 * Méthodes :
 *   R = 2 ou 3 : énumération de tous les chemins (b, u₁) depuis (v, a) : ~6 × 6^7 ≈ 1,7·10^6 ; l'extrémité fixe le reste.
 *   R = 4 : pour chaque chemin (b, u₁) on connaît x₂ (≤ 37 nibbles) ; les valeurs lointaines y₂ doivent donner x₃ = L·y₂ NUL
 *     hors du support de x₃ imposé par E : c'est un système LINÉAIRE sur GF(2) en les 4|supp x₂| bits de y₂. On énumère son
 *     noyau (dimension faible pour les bons chemins, qui annulent beaucoup de nibbles), puis on filtre les y₂ dont tous les
 *     nibbles sont non nuls et compatibles. Exact. Contrôle : à R = 3, la même méthode appliquée à la dernière transition
 *     redonne la somme directe (mode « controle »).
 *
 * Modes :
 *   agregation34 controle                      contrôles (2 tours contre agregation2, noyau contre somme directe, ...)
 *   agregation34 balayage diff|lin R T [r0]    R = 2 ou 3 : meilleur chemin pour chaque (v, a), puis DP/C exacte aux T
 *                                              meilleures extrémités, et recherche locale sur l'extrémité
 *   agregation34 extremite diff|lin fichier.json [r0]   R quelconque ≤ 4 : DP/C exacte à l'extrémité d'une
 *                                              caractéristique de trails1024.py (format « caracteristique »), puis
 *                                              recherche locale
 * Sortie : JSON sur la sortie standard.
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/agregation34.c sillage/c/commun.c -lm \
 *      -o agregation34 */
#include <math.h>
#include <omp.h>

#include "brume1024.c"

static int DDT[16][16], LAT[16][16];   /* LAT[masque d'entrée][masque de sortie] − 8, comme agregation2.c */
static int parite(unsigned x) { return __builtin_parity(x); }
static uint8_t tmulT(uint8_t m, uint8_t g)   /* T(m)ᵀ·g : bit k = ⟨m·2^k, g⟩ */
{
    uint8_t r = 0;
    for (int k = 0; k < 4; k++) r |= (uint8_t)(parite(gf_mul(m, (uint8_t)(1 << k)) & g) << k);
    return r;
}

/* ------------------------------------------------------------------ direction */
static int LIN;          /* 0 : différentiel, 1 : linéaire */
static int NR = 3, R0 = 0;
static int VOIS[N1][7];  /* voisins (ligne et colonne de M : le graphe est symétrique) */
static uint8_t COEF_D[N1][7];   /* diff : x'[VOIS[w][k]] ^= gf_mul(COEF_D[w][k], y_w)  (colonne w de M) */
static uint8_t TM[N1][7][16];   /* image d'une valeur y au nibble w vers le k-ième voisin (diff ou lin) */

static int tour_de(int l) { return LIN ? R0 + NR - 1 - l : R0 + l; }
/* poids d'une S-box à la couche l, nibble q, valeur proche x, valeur lointaine y */
static double POIDS[8][N1][16][16];
static void init_poids(void)
{
    for (int l = 0; l < NR; l++)
        for (int q = 0; q < N1; q++)
            for (int x = 0; x < 16; x++)
                for (int y = 0; y < 16; y++) {
                    double p;
                    if (!LIN) p = DDT[x][y] / 16.0;
                    else p = (parite((unsigned)(y & B1_RC[tour_de(l)][q])) ? -1 : 1) * LAT[y][x] / 8.0;
                    POIDS[l][q][x][y] = p;
                }
}
static void init_graphe(void)
{
    for (int w = 0; w < N1; w++) {
        int k = 0;
        for (int q = 0; q < N1; q++)
            if (DM[q][w]) {
                if (k >= 7 || !DM[w][q]) { fprintf(stderr, "graphe non symétrique ou degré > 7\n"); exit(2); }
                VOIS[w][k] = q;
                COEF_D[w][k] = DM[q][w];
                k++;
            }
        if (k != 7) { fprintf(stderr, "degré %d au nibble %d\n", k, w); exit(2); }
    }
    for (int w = 0; w < N1; w++)
        for (int k = 0; k < 7; k++)
            for (int y = 0; y < 16; y++)
                /* diff : (M·y e_w)_q = M[q][w]·y ; lin : (Mᵀ_bin·y e_w)_q = T(M[w][q])ᵀ·y */
                TM[w][k][y] = LIN ? tmulT(DM[w][VOIS[w][k]], (uint8_t)y) : gf_mul(COEF_D[w][k], (uint8_t)y);
}
static void propager(const uint8_t y[N1], uint8_t x[N1])   /* x = L·y */
{
    memset(x, 0, N1);
    for (int w = 0; w < N1; w++)
        if (y[w])
            for (int k = 0; k < 7; k++) x[VOIS[w][k]] ^= TM[w][k][y[w]];
}

/* ------------------------------------------------------------------ chemins (b, u₁) depuis (v, a) */
typedef struct {
    int v, a;
    int nb;                 /* valeurs lointaines b de la couche 0 */
    uint8_t b[16];
    double pb[16];
    uint8_t x1[16][7];      /* x₁ sur les 7 voisins de v, pour chaque b */
    int n1[16][7];          /* choix lointains de la couche 1 par voisin */
    uint8_t y1[16][7][16];
    double p1[16][7][16];
} depart_t;
static void depart(int v, int a, depart_t *d)
{
    d->v = v; d->a = a; d->nb = 0;
    for (int b = 1; b < 16; b++) {
        double p = POIDS[0][v][a][b];
        if (p == 0) continue;
        int i = d->nb++;
        d->b[i] = (uint8_t)b; d->pb[i] = p;
        for (int k = 0; k < 7; k++) {
            int w = VOIS[v][k];
            uint8_t x = TM[v][k][b];
            d->x1[i][k] = x;
            d->n1[i][k] = 0;
            for (int y = 1; y < 16; y++)
                if (POIDS[1][w][x][y] != 0) {
                    d->y1[i][k][d->n1[i][k]] = (uint8_t)y;
                    d->p1[i][k][d->n1[i][k]] = POIDS[1][w][x][y];
                    d->n1[i][k]++;
                }
        }
    }
}
/* itère sur tous les chemins : f(contexte, poids du chemin, x₂) ; x₂ = L·y₁ (≤ 37 nibbles) */
typedef void (*visite_f)(void *ctx, double p, const uint8_t *x2);
static void chemins(const depart_t *d, visite_f f, void *ctx)
{
    for (int i = 0; i < d->nb; i++) {
        int idx[7] = {0};
        for (;;) {
            double p = d->pb[i];
            uint8_t y1[N1];
            memset(y1, 0, N1);
            for (int k = 0; k < 7; k++) {
                p *= d->p1[i][k][idx[k]];
                y1[VOIS[d->v][k]] = d->y1[i][k][idx[k]];
            }
            uint8_t x2[N1];
            propager(y1, x2);
            f(ctx, p, x2);
            int k = 0;
            while (k < 7 && ++idx[k] == d->n1[i][k]) idx[k++] = 0;
            if (k == 7) break;
        }
    }
}

/* ------------------------------------------------------------------ R = 3 : somme directe */
typedef struct { const uint8_t *E; double somme, terme; long nb; } s3_t;
static void visite3(void *c, double p, const uint8_t *x2)
{
    s3_t *s = c;
    double t = p;
    for (int q = 0; q < N1 && t != 0; q++) t *= POIDS[2][q][x2[q]][s->E[q]];
    if (t != 0) { s->somme += t; s->nb++; if (fabs(t) > s->terme) s->terme = fabs(t); }
}
/* R = 2 : x₂ n'existe pas ; l'extrémité est y₁ elle-même (7 nibbles) */
static double somme2(const depart_t *d, const uint8_t *E, double *terme, long *nb)
{
    double s = 0;
    *terme = 0; *nb = 0;
    for (int i = 0; i < d->nb; i++) {
        double t = d->pb[i];
        for (int k = 0; k < 7 && t != 0; k++) t *= POIDS[1][VOIS[d->v][k]][d->x1[i][k]][E[VOIS[d->v][k]]];
        if (t != 0) { s += t; (*nb)++; if (fabs(t) > *terme) *terme = fabs(t); }
    }
    return s;
}

/* ------------------------------------------------------------------ R = 4 (et contrôle à R = 3) : noyau */
/* Pour un chemin de x₂ donné : somme sur y₂ (valeurs lointaines de la couche 2, support = supp x₂) de
 *   Π_q POIDS[2][q][x₂q][y₂q] · Π_q POIDS[3][q][x₃q][Eq],  x₃ = L·y₂, avec x₃ nul hors de supp E.
 * Système : inconnues = 4·|s| bits de y₂ ; équations = bits des nibbles hors de supp E atteints par s. */
#define MAXV 160
typedef struct {
    int ns, s[40];          /* support de x₂ */
    int dim;                /* dimension du noyau, en bits */
    uint8_t base[64][40];   /* vecteurs de base : un nibble par position de s */
    int ok;
} noyau_t;
static int noyau(const int *s, int ns, const uint8_t *E, noyau_t *K)
{
    K->ns = ns; memcpy(K->s, s, ns * sizeof(int));
    int nv = 4 * ns;
    if (nv > MAXV) return K->ok = 0;
    /* lignes : bits des nibbles q ∉ supp E voisins de s ; colonnes : nv inconnues ; GF(2), mots de 64 bits */
    static __thread uint64_t A[4 * 7 * 40][3];
    int nl = 0;
    int vu[N1];
    memset(vu, 0, sizeof vu);
    for (int i = 0; i < ns; i++)
        for (int k = 0; k < 7; k++) {
            int q = VOIS[s[i]][k];
            if (E[q] || vu[q]) continue;
            vu[q] = 1;
            for (int bit = 0; bit < 4; bit++) {
                memset(A[nl], 0, sizeof A[nl]);
                for (int j = 0; j < ns; j++)
                    for (int kk = 0; kk < 7; kk++)
                        if (VOIS[s[j]][kk] == q)
                            for (int c = 0; c < 4; c++)
                                if (TM[s[j]][kk][1 << c] >> bit & 1) {
                                    int col = 4 * j + c;
                                    A[nl][col / 64] |= 1ULL << (col % 64);
                                }
                nl++;
            }
        }
    /* forme échelonnée réduite */
    int piv_col[MAXV], est_piv[MAXV];
    memset(est_piv, 0, sizeof est_piv);
    int r = 0;
    for (int c = 0; c < nv && r < nl; c++) {
        int p = r;
        while (p < nl && !(A[p][c / 64] >> (c % 64) & 1)) p++;
        if (p == nl) continue;
        if (p != r) for (int w = 0; w < 3; w++) { uint64_t t = A[p][w]; A[p][w] = A[r][w]; A[r][w] = t; }
        for (int q = 0; q < nl; q++)
            if (q != r && (A[q][c / 64] >> (c % 64) & 1))
                for (int w = 0; w < 3; w++) A[q][w] ^= A[r][w];
        piv_col[r] = c; est_piv[c] = 1; r++;
    }
    K->dim = nv - r;
    if (K->dim > 30) return K->ok = 0;
    /* base : une colonne libre f à 1, pivots déduits */
    int d = 0;
    for (int f = 0; f < nv; f++) {
        if (est_piv[f]) continue;
        uint8_t vec[40];
        memset(vec, 0, sizeof vec);
        vec[f / 4] |= (uint8_t)(1 << (f % 4));
        for (int i = 0; i < r; i++)
            if (A[i][f / 64] >> (f % 64) & 1) {
                int c = piv_col[i];
                vec[c / 4] ^= (uint8_t)(1 << (c % 4));
            }
        memcpy(K->base[d++], vec, ns);
    }
    return K->ok = 1;
}
/* somme sur le noyau ; derniere = indice de la couche des valeurs y (2 pour R = 4 ; 1 pour le contrôle à R = 3 ...) */
static double somme_noyau(const noyau_t *K, const uint8_t *x, const uint8_t *E, int lc, double *terme, long *nb)
{
    double s = 0;
    uint8_t y[40];
    memset(y, 0, sizeof y);
    uint64_t n = 1ULL << K->dim;
    for (uint64_t g = 0; g < n; g++) {
        if (g) {   /* code de Gray : on change le vecteur de base de rang = bit de poids faible de g */
            int i = __builtin_ctzll(g);
            for (int j = 0; j < K->ns; j++) y[j] ^= K->base[i][j];
        }
        double t = 1;
        for (int j = 0; j < K->ns && t != 0; j++) {
            if (!y[j]) { t = 0; break; }
            t *= POIDS[lc][K->s[j]][x[K->s[j]]][y[j]];
        }
        if (t == 0) continue;
        uint8_t yy[N1], x3[N1];
        memset(yy, 0, N1);
        for (int j = 0; j < K->ns; j++) yy[K->s[j]] = y[j];
        propager(yy, x3);
        for (int q = 0; q < N1 && t != 0; q++) t *= POIDS[lc + 1][q][x3[q]][E[q]];
        if (t != 0) { s += t; (*nb)++; if (fabs(t) > *terme) *terme = fabs(t); }
    }
    return s;
}
/* cache des noyaux par support de x₂ (l'extrémité E est fixe pendant une somme) : beaucoup de chemins partagent le
 * même support (la boule de rayon 2 moins quelques annulations) */
#define NCACHE 4096
typedef struct { uint64_t cle[4]; int plein; noyau_t K; } entree_cache_t;
typedef struct { const uint8_t *E; double somme, terme; long nb, chemins_trop_gros; int dim_max; entree_cache_t *cache; } s4_t;
static const noyau_t *noyau_cache(s4_t *S, const int *s, int ns)
{
    uint64_t cle[4] = {0, 0, 0, 0};
    for (int i = 0; i < ns; i++) cle[s[i] >> 6] |= 1ULL << (s[i] & 63);
    uint64_t h = (cle[0] * 0x9E3779B97F4A7C15ULL) ^ (cle[1] * 0xC2B2AE3D27D4EB4FULL) ^ (cle[2] * 0x165667B19E3779F9ULL) ^ (cle[3] * 0x27D4EB2F165667C5ULL);
    for (int k = 0; k < 8; k++) {
        entree_cache_t *e = &S->cache[(h + k) % NCACHE];
        if (e->plein && !memcmp(e->cle, cle, sizeof cle)) return e->K.ok ? &e->K : NULL;
        if (!e->plein) {
            e->plein = 1; memcpy(e->cle, cle, sizeof cle);
            noyau(s, ns, S->E, &e->K);
            return e->K.ok ? &e->K : NULL;
        }
    }
    static __thread noyau_t K;   /* cache plein à cet endroit : calcul direct */
    noyau(s, ns, S->E, &K);
    return K.ok ? &K : NULL;
}
static void visite4(void *c, double p, const uint8_t *x2)
{
    s4_t *S = c;
    int s[40], ns = 0;
    for (int q = 0; q < N1; q++) if (x2[q]) { if (ns == 40) { S->chemins_trop_gros++; return; } s[ns++] = q; }
    const noyau_t *Kp = noyau_cache(S, s, ns);
    if (!Kp) { S->chemins_trop_gros++; return; }
    const noyau_t K = *Kp;
    if (K.dim > S->dim_max) S->dim_max = K.dim;
    double terme = 0; long nb = 0;
    double v = somme_noyau(&K, x2, S->E, 2, &terme, &nb);
    S->somme += p * v; S->nb += nb;
    if (fabs(p) * terme > S->terme) S->terme = fabs(p) * terme;
}

/* ------------------------------------------------------------------ somme exacte pour une extrémité */
typedef struct { double somme, terme; long nb, trop; int dim; } res_t;
/* R = 3 par la somme directe sur tous les chemins (contrôle seulement : ~10^8 chemins en linéaire) */
static res_t exacte_directe3(int v, int a, const uint8_t *E)
{
    depart_t *d = malloc(sizeof *d);
    depart(v, a, d);
    s3_t s = {E, 0, 0, 0};
    chemins(d, visite3, &s);
    free(d);
    return (res_t){s.somme, s.terme, s.nb, 0, 0};
}
static res_t exacte(int v, int a, const uint8_t *E)
{
    depart_t *d = malloc(sizeof *d);
    depart(v, a, d);
    res_t r = {0, 0, 0, 0, 0};
    if (NR == 2) {
        r.somme = somme2(d, E, &r.terme, &r.nb);
    } else if (NR == 3) {
        /* pour chaque b : y₁ (7 nibbles) dans le noyau de « x₂ = L·y₁ nul hors de supp E » */
        int s[7];
        for (int k = 0; k < 7; k++) s[k] = VOIS[v][k];
        for (int i = 0; i < d->nb; i++) {
            uint8_t x1[N1];
            memset(x1, 0, N1);
            for (int k = 0; k < 7; k++) x1[s[k]] = d->x1[i][k];
            noyau_t K;
            if (!noyau(s, 7, E, &K)) { r.trop++; continue; }
            if (K.dim > r.dim) r.dim = K.dim;
            double terme = 0; long nb = 0;
            r.somme += d->pb[i] * somme_noyau(&K, x1, E, 1, &terme, &nb);
            r.nb += nb;
            if (fabs(d->pb[i]) * terme > r.terme) r.terme = fabs(d->pb[i]) * terme;
        }
    } else {
        /* parallèle sur (b, choix du premier voisin) ; un cache de noyaux par fil */
        int ntaches = 0, tb[16 * 16], tj[16 * 16];
        for (int i = 0; i < d->nb; i++) for (int j = 0; j < d->n1[i][0]; j++) { tb[ntaches] = i; tj[ntaches] = j; ntaches++; }
        double somme = 0, terme = 0; long nb = 0, trop = 0; int dim = 0;
#pragma omp parallel reduction(+:somme, nb, trop) reduction(max:terme, dim)
        {
            s4_t S = {E, 0, 0, 0, 0, 0, calloc(NCACHE, sizeof(entree_cache_t))};
            depart_t *dd = malloc(sizeof *dd);
#pragma omp for schedule(dynamic)
            for (int tk = 0; tk < ntaches; tk++) {
                *dd = *d;            /* sous-départ : un seul b, un seul choix pour le premier voisin */
                int i = tb[tk], j = tj[tk];
                dd->nb = 1;
                dd->b[0] = d->b[i]; dd->pb[0] = d->pb[i];
                memcpy(dd->x1[0], d->x1[i], sizeof d->x1[i]);
                memcpy(dd->n1[0], d->n1[i], sizeof d->n1[i]);
                memcpy(dd->y1[0], d->y1[i], sizeof d->y1[i]);
                memcpy(dd->p1[0], d->p1[i], sizeof d->p1[i]);
                dd->n1[0][0] = 1; dd->y1[0][0][0] = d->y1[i][0][j]; dd->p1[0][0][0] = d->p1[i][0][j];
                chemins(dd, visite4, &S);
            }
            somme += S.somme; nb += S.nb; trop += S.chemins_trop_gros;
            if (S.terme > terme) terme = S.terme;
            if (S.dim_max > dim) dim = S.dim_max;
            free(S.cache); free(dd);
        }
        r.somme = somme; r.terme = terme; r.nb = nb; r.trop = trop; r.dim = dim;
    }
    free(d);
    return r;
}

/* ------------------------------------------------------------------ recherche locale sur l'extrémité */
static res_t locale(int v, int a, uint8_t *E, int passes)
{
    res_t best = exacte(v, a, E);
    for (int p = 0; p < passes; p++) {
        int ameliore = 0;
        for (int q = 0; q < N1; q++) {
            if (!E[q]) continue;
            uint8_t ancien = E[q];
            for (int y = 1; y < 16; y++) {
                if (y == ancien) continue;
                E[q] = (uint8_t)y;
                res_t r = exacte(v, a, E);
                if (fabs(r.somme) > fabs(best.somme) * (1 + 1e-9)) { best = r; ancien = (uint8_t)y; ameliore = 1; }
            }
            E[q] = ancien;
        }
        if (!ameliore) break;
    }
    return best;
}

/* ------------------------------------------------------------------ balayage (R = 2 ou 3) */
typedef struct { double p; int v, a; uint8_t E[N1]; } cand_t;
#define TMAX 4096
typedef struct { cand_t *c; int n, T; } top_t;
static void top_ajouter(top_t *t, const cand_t *x)
{
    if (t->n < t->T) { t->c[t->n++] = *x; }
    else {
        int m = 0;
        for (int i = 1; i < t->n; i++) if (t->c[i].p < t->c[m].p) m = i;
        if (x->p <= t->c[m].p) return;
        t->c[m] = *x;
    }
}
static double MAXP[8][N1][16];   /* max_y |POIDS[l][q][x][y]| et argmax */
static uint8_t ARG[8][N1][16];
static void init_max(void)
{
    for (int l = 0; l < NR; l++)
        for (int q = 0; q < N1; q++)
            for (int x = 0; x < 16; x++) {
                double m = 0; int am = 0;
                for (int y = 0; y < 16; y++) if (fabs(POIDS[l][q][x][y]) > m) { m = fabs(POIDS[l][q][x][y]); am = y; }
                MAXP[l][q][x] = m; ARG[l][q][x] = (uint8_t)am;
            }
}
typedef struct { top_t *t; int v, a; double seuil; } bal_t;
static void visite_bal(void *c, double p, const uint8_t *x2)
{
    bal_t *b = c;
    double t = fabs(p);
    for (int q = 0; q < N1 && t > b->seuil; q++) t *= MAXP[2][q][x2[q]];
    if (t <= b->seuil) return;
    cand_t x = {t, b->v, b->a, {0}};
    for (int q = 0; q < N1; q++) x.E[q] = x2[q] ? ARG[2][q][x2[q]] : 0;
    top_ajouter(b->t, &x);
    if (b->t->n == b->t->T) {
        double m = b->t->c[0].p;
        for (int i = 1; i < b->t->n; i++) if (b->t->c[i].p < m) m = b->t->c[i].p;
        b->seuil = m;
    }
}
/* Séparation-évaluation sur les 7 nibbles de la couche 1 : un nibble de x₂ est compté (facteur MAXP) dès que tous ses
 * antécédents sont fixés ; borne = produit courant × Π des max restants de la couche 1 (les nibbles de x₂ encore ouverts
 * comptent pour 1). Exact pour le meilleur chemin et le top-T. */
typedef struct {
    const depart_t *d;
    int i;
    top_t *t;
    double *seuil;
    double maxk[8];          /* Π_{k' ≥ k} max |p₁| */
    int cnt[N1];
    uint8_t x2[8][N1];
} bb3_t;
static void bb3_rec(bb3_t *B, int k, double p)
{
    if (p * B->maxk[k] <= *B->seuil) return;
    const depart_t *d = B->d;
    if (k == 7) {
        cand_t x = {p, d->v, d->a, {0}};
        for (int q = 0; q < N1; q++) x.E[q] = B->x2[7][q] ? ARG[2][q][B->x2[7][q]] : 0;
        top_ajouter(B->t, &x);
        if (B->t->n == B->t->T) {
            double m = B->t->c[0].p;
            for (int j = 1; j < B->t->n; j++) if (B->t->c[j].p < m) m = B->t->c[j].p;
            *B->seuil = m;
        }
        return;
    }
    int w = VOIS[d->v][k];
    for (int j = 0; j < d->n1[B->i][k]; j++) {
        uint8_t y = d->y1[B->i][k][j];
        double pp = p * fabs(d->p1[B->i][k][j]);
        memcpy(B->x2[k + 1], B->x2[k], N1);
        for (int m = 0; m < 7; m++) {
            int q = VOIS[w][m];
            B->x2[k + 1][q] ^= TM[w][m][y];
            if (--B->cnt[q] == 0) pp *= MAXP[2][q][B->x2[k + 1][q]];
        }
        bb3_rec(B, k + 1, pp);
        for (int m = 0; m < 7; m++) B->cnt[VOIS[w][m]]++;
    }
}
static void bb3(const depart_t *d, int i, top_t *t, double *seuil)
{
    bb3_t *B = malloc(sizeof *B);
    B->d = d; B->i = i; B->t = t; B->seuil = seuil;
    memset(B->cnt, 0, sizeof B->cnt);
    for (int k = 0; k < 7; k++)
        for (int m = 0; m < 7; m++) B->cnt[VOIS[VOIS[d->v][k]][m]]++;
    B->maxk[7] = 1;
    for (int k = 6; k >= 0; k--) {
        double mx = 0;
        for (int j = 0; j < d->n1[i][k]; j++) if (fabs(d->p1[i][k][j]) > mx) mx = fabs(d->p1[i][k][j]);
        B->maxk[k] = mx * B->maxk[k + 1];
    }
    memset(B->x2[0], 0, N1);
    bb3_rec(B, 0, fabs(d->pb[i]));
    free(B);
}

static int cmp_cand(const void *x, const void *y)
{
    double a = ((const cand_t *)x)->p, b = ((const cand_t *)y)->p;
    return a < b ? 1 : a > b ? -1 : 0;
}
static void balayage(int T)
{
    int nth = omp_get_max_threads();
    top_t *tops = calloc(nth, sizeof *tops);
    for (int i = 0; i < nth; i++) { tops[i].c = malloc(T * sizeof(cand_t)); tops[i].T = T; }
    /* BALAYAGE_V = k : seulement les nibbles v = 0, 256/k, … (mesure de durée) ; défaut : les 256 */
    const char *bv = getenv("BALAYAGE_V");
    int nv = bv ? atoi(bv) : N1;
    if (nv < 1 || nv > N1) nv = N1;
#pragma omp parallel for schedule(dynamic)
    for (int va = 0; va < nv * 15; va++) {
        int v = (va / 15) * (N1 / nv), a = va % 15 + 1;
        top_t *t = &tops[omp_get_thread_num()];
        depart_t *d = malloc(sizeof *d);
        depart(v, a, d);
        if (NR == 2) {   /* extrémité = argmax par voisin */
            for (int i = 0; i < d->nb; i++) {
                cand_t x = {fabs(d->pb[i]), v, a, {0}};
                for (int k = 0; k < 7; k++) {
                    int w = VOIS[v][k];
                    x.p *= MAXP[1][w][d->x1[i][k]];
                    x.E[w] = ARG[1][w][d->x1[i][k]];
                }
                top_ajouter(t, &x);
            }
        } else {
            double seuil = 0;
            if (t->n == t->T) { double m = t->c[0].p; for (int i = 1; i < t->n; i++) if (t->c[i].p < m) m = t->c[i].p; seuil = m; }
            for (int i = 0; i < d->nb; i++) bb3(d, i, t, &seuil);
        }
        free(d);
    }
    top_t tout = {malloc((size_t)nth * T * sizeof(cand_t)), 0, nth * T};
    for (int i = 0; i < nth; i++) for (int j = 0; j < tops[i].n; j++) tout.c[tout.n++] = tops[i].c[j];
    qsort(tout.c, tout.n, sizeof(cand_t), cmp_cand);
    /* on retire les doublons d'extrémité (même (v, a, E)) */
    int n = 0;
    for (int i = 0; i < tout.n && n < T; i++) {
        int dbl = 0;
        for (int j = 0; j < n && !dbl; j++)
            dbl = tout.c[j].v == tout.c[i].v && tout.c[j].a == tout.c[i].a && !memcmp(tout.c[j].E, tout.c[i].E, N1);
        if (!dbl) tout.c[n++] = tout.c[i];
    }
    printf("{\"mode\": \"balayage\", \"sens\": \"%s\", \"tours\": %d, \"r0\": %d, \"T\": %d, \"nibbles_v\": %d,\n",
           LIN ? "lin" : "diff", NR, R0, T, nv);
    printf(" \"meilleur_chemin_bits\": %.4f,\n \"extremites\": [\n", -log2(tout.c[0].p));
    double rmax = 0, smax = 0;
    /* sommes exactes en parallèle ; recherche locale (coûteuse : ~550 sommes par passe) sur les NLOC premières */
    enum { NLOC = 8 };
    res_t *rs = calloc(n, sizeof *rs), *rls = calloc(n, sizeof *rls);
#pragma omp parallel for schedule(dynamic)
    for (int i = 0; i < n; i++) {
        rs[i] = exacte(tout.c[i].v, tout.c[i].a, tout.c[i].E);
        if (i < NLOC) {
            uint8_t E2[N1];
            memcpy(E2, tout.c[i].E, N1);
            rls[i] = locale(tout.c[i].v, tout.c[i].a, E2, 3);
        } else rls[i] = rs[i];
    }
    for (int i = 0; i < n; i++) {
        cand_t *c = &tout.c[i];
        res_t r = rs[i], rl = rls[i];
        double ratio = fabs(r.somme) / c->p;
        if (ratio > rmax) rmax = ratio;
        if (fabs(rl.somme) > smax) smax = fabs(rl.somme);
        int act = 0;
        for (int q = 0; q < N1; q++) act += c->E[q] != 0;
        printf("  {\"v\": %d, \"a\": %d, \"actifs_E\": %d, \"chemin_bits\": %.4f, \"exacte_bits\": %.4f, \"chemins\": %ld, "
               "\"facteur\": %.6f, \"apres_locale_bits\": %.4f, \"chemins_locale\": %ld}%s\n",
               c->v, c->a, act, -log2(c->p), -log2(fabs(r.somme)), r.nb, ratio, -log2(fabs(rl.somme)), rl.nb,
               i + 1 < n ? "," : "");
        fflush(stdout);
    }
    printf(" ],\n \"facteur_max\": %.6f, \"meilleure_exacte_bits\": %.4f}\n", rmax, -log2(smax));
}

/* ------------------------------------------------------------------ extrémité d'une caractéristique (JSON) */
/* lecture minimale du champ "caracteristique" de trails1024.py : liste de {tour, entree: {q: val}, sortie: {q: val}} */
static int lire_car(const char *fichier, uint8_t ent[8][N1], uint8_t sor[8][N1], int *nr)
{
    FILE *f = fopen(fichier, "r");
    if (!f) return 0;
    static char buf[1 << 22];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *p = strstr(buf, "\"caracteristique\"");
    if (!p) return 0;
    memset(ent, 0, 8 * N1); memset(sor, 0, 8 * N1);
    int t = -1;
    *nr = 0;
    /* format : [{'tour': 0, 'entree': {'244': 7}, 'sortie': {'244': 8}}, ...] (repr Python dans une chaîne) */
    while ((p = strstr(p, "tour")) != NULL) {
        p += 4;
        while (*p && (*p < '0' || *p > '9')) p++;
        t = (int)strtol(p, &p, 10);
        if (t < 0 || t >= 8) return 0;
        if (t + 1 > *nr) *nr = t + 1;
        for (int part = 0; part < 2; part++) {
            char *q = strstr(p, part ? "sortie" : "entree");
            if (!q) return 0;
            q = strchr(q, '{');
            char *fin = strchr(q, '}');
            q++;
            while (q < fin) {
                while (q < fin && (*q < '0' || *q > '9')) q++;
                if (q >= fin) break;
                int nib = (int)strtol(q, &q, 10);
                while (q < fin && (*q < '0' || *q > '9')) q++;
                int val = (int)strtol(q, &q, 10);
                if (nib < 0 || nib >= N1 || val < 0 || val > 15) return 0;
                (part ? sor : ent)[t][nib] = (uint8_t)val;
            }
            p = fin;
        }
    }
    return *nr > 0;
}
static void extremite(const char *fichier)
{
    uint8_t ent[8][N1], sor[8][N1];
    int nr;
    if (!lire_car(fichier, ent, sor, &nr)) { fprintf(stderr, "lecture impossible : %s\n", fichier); exit(2); }
    NR = nr;
    if (NR < 2 || NR > 4) { fprintf(stderr, "%d tours : seuls 2 à 4 sont traités\n", NR); exit(2); }
    init_poids(); init_max();
    /* extrémité proche : nibble seul (diff : entrée du tour 0 ; lin : sortie du dernier tour) ; lointaine : l'autre bout */
    const uint8_t *proche = LIN ? sor[NR - 1] : ent[0];
    const uint8_t *loin = LIN ? ent[0] : sor[NR - 1];
    int v = -1, nact = 0;
    for (int q = 0; q < N1; q++) if (proche[q]) { v = q; nact++; }
    if (nact != 1) { fprintf(stderr, "l'extrémité proche a %d nibbles actifs (1 attendu)\n", nact); exit(2); }
    int a = proche[v];
    /* poids du chemin donné (contrôle de lecture) */
    double pc = 1;
    for (int t = 0; t < NR; t++)
        for (int q = 0; q < N1; q++) {
            int l = LIN ? NR - 1 - t : t;
            int x = LIN ? sor[t][q] : ent[t][q], y = LIN ? ent[t][q] : sor[t][q];
            pc *= fabs(POIDS[l][q][x][y]);
        }
    uint8_t E[N1];
    memcpy(E, loin, N1);
    double t0 = omp_get_wtime();
    res_t r = exacte(v, a, E);
    double t1 = omp_get_wtime();
    const char *ev = getenv("LOCALE");
    int passes = ev ? atoi(ev) : (NR <= 3 ? 1 : 0);
    res_t rl = passes ? locale(v, a, E, passes) : r;
    int act = 0;
    for (int q = 0; q < N1; q++) act += loin[q] != 0;
    printf("{\"mode\": \"extremite\", \"sens\": \"%s\", \"tours\": %d, \"r0\": %d, \"fichier\": \"%s\", \"v\": %d, \"a\": %d, "
           "\"actifs_E\": %d, \"chemin_donne_bits\": %.4f, \"exacte_bits\": %.4f, \"plus_grand_terme_bits\": %.4f, "
           "\"chemins\": %ld, \"facteur\": %.6f, \"dim_noyau_max\": %d, \"chemins_non_traites\": %ld, \"s\": %.1f, "
           "\"apres_locale_bits\": %.4f}\n",
           LIN ? "lin" : "diff", NR, R0, fichier, v, a, act, -log2(pc), -log2(fabs(r.somme)), -log2(r.terme), r.nb,
           fabs(r.somme) / pc, r.dim, r.trop, t1 - t0, -log2(fabs(rl.somme)));
}

/* ------------------------------------------------------------------ contrôles */
static int controle(void)
{
    int ok = 1;
    /* (1) 2 tours : le meilleur chemin du balayage = 2^−16 (diff) comme agregation2 ; somme exacte ≤ 1,5 × chemin */
    LIN = 0; NR = 2; init_graphe(); init_poids(); init_max();
    double best = 0;
    for (int v = 0; v < N1; v++)
        for (int a = 1; a < 16; a++) {
            depart_t d; depart(v, a, &d);
            for (int i = 0; i < d.nb; i++) {
                double p = fabs(d.pb[i]);
                for (int k = 0; k < 7; k++) p *= MAXP[1][VOIS[v][k]][d.x1[i][k]];
                if (p > best) best = p;
            }
        }
    int c1 = fabs(-log2(best) - 16) < 1e-9;
    printf("  %s 2 tours, différentiel : meilleur chemin 2^-%.2f (agregation2 : 2^-16)\n", c1 ? "ok" : "ÉCHEC", -log2(best));
    ok &= c1;
    /* (2) somme exacte à 2 tours sur une extrémité aléatoire de la forme, contre la formule d'agregation2 recalculée ici */
    {
        int v = 17, a = 5;
        depart_t d; depart(v, a, &d);
        uint8_t E[N1]; memset(E, 0, N1);
        for (int k = 0; k < 7; k++) E[VOIS[v][k]] = ARG[1][VOIS[v][k]][d.x1[0][k]];
        double terme; long nb;
        double s = somme2(&d, E, &terme, &nb);
        double s2 = 0;   /* agregation2 : Σ_b DDT[a][b]/16 Π_u DDT[c_u][d_u]/16 avec c_u = M[u][v]·b */
        for (int b = 1; b < 16; b++) {
            double t = DDT[a][b] / 16.0;
            for (int u = 0; u < N1; u++) if (DM[u][v]) t *= DDT[gf_mul(DM[u][v], (uint8_t)b)][E[u]] / 16.0;
            s2 += t;
        }
        int c2 = fabs(s - s2) <= 1e-15 * fabs(s2) && s > 0;
        printf("  %s 2 tours : somme exacte %.6g = formule d'agregation2 %.6g\n", c2 ? "ok" : "ÉCHEC", s, s2);
        ok &= c2;
    }
    /* (3) 2 tours linéaire : meilleur chemin 2^-8 ; coque maximale ≥ 2^-7,83 trouvée par la recherche locale ? (on
     *     contrôle seulement le meilleur chemin et la valeur de agregation2 : 2^-8) */
    LIN = 1; NR = 2; init_graphe(); init_poids(); init_max();
    best = 0;
    for (int v = 0; v < N1; v++)
        for (int a = 1; a < 16; a++) {
            depart_t d; depart(v, a, &d);
            for (int i = 0; i < d.nb; i++) {
                double p = fabs(d.pb[i]);
                for (int k = 0; k < 7; k++) p *= MAXP[1][VOIS[v][k]][d.x1[i][k]];
                if (p > best) best = p;
            }
        }
    int c3 = fabs(-log2(best) - 8) < 1e-9;
    printf("  %s 2 tours, linéaire : meilleur chemin 2^-%.2f (agregation2 : 2^-8)\n", c3 ? "ok" : "ÉCHEC", -log2(best));
    ok &= c3;
    /* (4) propager() contre la multiplication dense (diff : M ; lin : Mᵀ binaire) sur des vecteurs aléatoires */
    for (int lin = 0; lin < 2; lin++) {
        LIN = lin; init_graphe();
        uint64_t g = 0x9E3779B97F4A7C15ULL;
        int c4 = 1;
        for (int it = 0; it < 50; it++) {
            uint8_t y[N1], x[N1], x2[N1];
            for (int q = 0; q < N1; q++) { g ^= g << 13; g ^= g >> 7; g ^= g << 17; y[q] = (uint8_t)(g & 15); }
            propager(y, x);
            for (int q = 0; q < N1; q++) {
                uint8_t s = 0;
                for (int w = 0; w < N1; w++)
                    if (!lin && DM[q][w]) s ^= gf_mul(DM[q][w], y[w]);
                    else if (lin && DM[w][q]) s ^= tmulT(DM[w][q], y[w]);
                x2[q] = s;
            }
            c4 &= !memcmp(x, x2, N1);
        }
        printf("  %s couche linéaire (%s) : propager = produit dense sur 50 vecteurs\n", c4 ? "ok" : "ÉCHEC", lin ? "Mᵀ binaire" : "M");
        ok &= c4;
    }
    /* (5) noyau : à 3 tours, la somme par le noyau sur la DERNIÈRE transition (couche 1 → 2) = la somme directe.
     *     On l'obtient en traitant les y₁ par noyau : x₁ (7 nibbles), y₁ ∈ noyau de « x₂ = L y₁ nul hors supp E ». */
    for (int lin = 0; lin < 2; lin++) {
        LIN = lin; NR = 3; R0 = 0; init_graphe(); init_poids(); init_max();
        int v = 100, a = 3;
        depart_t d; depart(v, a, &d);
        /* extrémité : le meilleur chemin depuis le premier b */
        uint8_t y1[N1], x2[N1], E[N1];
        memset(y1, 0, N1);
        for (int k = 0; k < 7; k++) {
            int best_j = 0;
            for (int j = 1; j < d.n1[0][k]; j++) if (fabs(d.p1[0][k][j]) > fabs(d.p1[0][k][best_j])) best_j = j;
            y1[VOIS[v][k]] = d.y1[0][k][best_j];
        }
        propager(y1, x2);
        for (int q = 0; q < N1; q++) E[q] = x2[q] ? ARG[2][q][x2[q]] : 0;
        res_t direct;
        double s_noy = 0;
        for (int i = 0; i < d.nb; i++) {
            uint8_t x1[N1]; memset(x1, 0, N1);
            int s[7];
            for (int k = 0; k < 7; k++) { s[k] = VOIS[v][k]; x1[s[k]] = d.x1[i][k]; }
            noyau_t K;
            if (!noyau(s, 7, E, &K)) { s_noy = NAN; break; }
            double terme = 0; long nb = 0;
            s_noy += d.pb[i] * somme_noyau(&K, x1, E, 1, &terme, &nb);
        }
        res_t vianoy = exacte(v, a, E);
        direct = exacte_directe3(v, a, E);
        int c5 = fabs(direct.somme - s_noy) <= 1e-12 * fabs(direct.somme) && direct.somme != 0
                 && fabs(vianoy.somme - direct.somme) <= 1e-12 * fabs(direct.somme);
        printf("  %s 3 tours (%s) : somme par le noyau %.6g = somme directe %.6g (%ld chemins)\n", c5 ? "ok" : "ÉCHEC",
               lin ? "lin" : "diff", s_noy, direct.somme, direct.nb);
        ok &= c5;
    }
    /* (6) témoin d'agrégation : à 2 tours, une extrémité avec plusieurs b contributeurs (diff) donne facteur > 1 */
    {
        LIN = 0; NR = 2; init_graphe(); init_poids(); init_max();
        double fmax = 0;
        for (int v = 0; v < 8; v++)
            for (int a = 1; a < 16; a++) {
                depart_t d; depart(v, a, &d);
                for (int i = 0; i < d.nb; i++) {
                    uint8_t E[N1]; memset(E, 0, N1);
                    double p = fabs(d.pb[i]);
                    for (int k = 0; k < 7; k++) { int w = VOIS[v][k]; E[w] = ARG[1][w][d.x1[i][k]]; p *= MAXP[1][w][d.x1[i][k]]; }
                    double terme; long nb;
                    double s = somme2(&d, E, &terme, &nb);
                    if (s / p > fmax) fmax = s / p;
                }
            }
        int c6 = fmax > 1.0 + 1e-9 && fmax <= 1.5 + 1e-9;
        printf("  %s témoin : à 2 tours le facteur d'agrégation dépasse 1 (max %.4f sur 8 nibbles ; agregation2 : ≤ 1,5)\n",
               c6 ? "ok" : "ÉCHEC", fmax);
        ok &= c6;
    }
    /* (7) séparation-évaluation = énumération exhaustive (meilleur chemin et top 5) à 3 tours, diff et lin */
    for (int lin = 0; lin < 2; lin++) {
        LIN = lin; NR = 3; R0 = 0; init_graphe(); init_poids(); init_max();
        int c7 = 1;
        for (int ess = 0; ess < (lin ? 1 : 3); ess++) {
            int v = 37 * ess + 11, a = 2 + 5 * ess;
            depart_t *d = malloc(sizeof *d);
            depart(v, a, d);
            cand_t c1[5], c2[5];
            top_t t1 = {c1, 0, 5}, t2 = {c2, 0, 5};
            bal_t b = {&t1, v, a, 0};
            chemins(d, visite_bal, &b);
            double seuil = 0;
            for (int i = 0; i < d->nb; i++) bb3(d, i, &t2, &seuil);
            qsort(c1, t1.n, sizeof(cand_t), cmp_cand);
            qsort(c2, t2.n, sizeof(cand_t), cmp_cand);
            c7 &= t1.n == t2.n;
            for (int i = 0; i < t1.n && c7; i++) c7 &= fabs(c1[i].p - c2[i].p) <= 1e-12 * c1[i].p;
            free(d);
        }
        printf("  %s 3 tours (%s) : séparation-évaluation = énumération exhaustive (5 meilleurs chemins)\n",
               c7 ? "ok" : "ÉCHEC", lin ? "lin" : "diff");
        ok &= c7;
    }
    printf("%s\n", ok ? "tous les contrôles passent" : "CONTRÔLE EN ÉCHEC");
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (!ref_init()) { fprintf(stderr, "ref_init\n"); return 2; }
    for (int a = 0; a < 16; a++)
        for (int x = 0; x < 16; x++) {
            DDT[a][BR_SBOX[x] ^ BR_SBOX[x ^ a]]++;
            for (int b = 0; b < 16; b++) LAT[a][b] += (parite((unsigned)(a & x)) == parite((unsigned)(b & BR_SBOX[x]))) ? 1 : 0;
        }
    for (int a = 0; a < 16; a++) for (int b = 0; b < 16; b++) LAT[a][b] -= 8;
    if (argc >= 2 && !strcmp(argv[1], "controle")) return controle();
    if (argc >= 5 && !strcmp(argv[1], "balayage")) {
        LIN = !strcmp(argv[2], "lin");
        NR = atoi(argv[3]);
        int T = atoi(argv[4]);
        R0 = argc >= 6 ? atoi(argv[5]) : 0;
        if ((NR != 2 && NR != 3) || T < 1 || T > TMAX) { fprintf(stderr, "balayage : R = 2 ou 3, 1 ≤ T ≤ %d\n", TMAX); return 2; }
        init_graphe(); init_poids(); init_max();
        balayage(T);
        return 0;
    }
    if (argc >= 4 && !strcmp(argv[1], "extremite")) {
        LIN = !strcmp(argv[2], "lin");
        R0 = argc >= 5 ? atoi(argv[4]) : 0;
        init_graphe();
        extremite(argv[3]);
        return 0;
    }
    fprintf(stderr, "usage : agregation34 controle | balayage diff|lin R T [r0] | extremite diff|lin fichier.json [r0]\n");
    return 2;
}
