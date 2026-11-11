/* departage.c — banc de départage des S-box de BRUME-512 (BRUME / SBOX_V3 / SBOX_V4 / candidates).
 *
 * Chaque mesure porte un STATUT (voir PROTOCOLE.md § 3) :
 *   EXACT            valeur exacte pour la permutation complète réduite à R tours (modèle complet,
 *                    optimum prouvé par énumération exhaustive ou B&B à borne admissible) ;
 *   EXACT_RESTREINT  optimum prouvé d'un SOUS-problème nommé (restriction explicite) : c'est une
 *                    borne côté attaquant (valeur atteinte), pas une borne de sécurité ;
 *   EMPIRIQUE        fréquence mesurée sur la permutation complète, avec intervalle de confiance.
 *
 * Le modèle n'est jamais recopié : M, les coefficients GF(16) et les constantes viennent de
 * sillage/c/brume512_tables.h ; la commande `controle` vérifie que la permutation reconstruite
 * avec la S-box de BRUME coïncide octet pour octet avec sl_brume_permute_ref (libsillage.so).
 *
 * Conventions : état = 128 nibbles x[0..127] ; tour r : y = M · S(x ⊕ RC[r]) ;
 * y_v = ⊕_e EC[e]·S(x_{EI[e]} ⊕ RC[r][EI[e]]) pour e ∈ [7v, 7v+7) ; GF(16) modulo x^4+x+1.
 * LAT[u][w] = Σ_x (-1)^{u·x ⊕ w·S(x)} (u masque d'entrée, w masque de sortie).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <math.h>
#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "brume512_tables.h"

#define N BR_N
#define D BR_DEG
#define INF 1000000

/* ------------------------------------------------------------------------------------------ */
/* GF(16), matrice M, inverse                                                                  */
/* ------------------------------------------------------------------------------------------ */

static uint8_t GM[16][16], GMT[16][16], GINV[16];
static uint8_t MM[N][N], MI[N][N];
static int COLJ[N][D];          /* pour l'entrée i : sorties j avec M[j][i] != 0 */
static uint8_t COLC[N][D];      /*                   coefficient M[j][i]          */
static int ROWK[N][D];          /* pour la sortie j : entrées k avec M[j][k] != 0 */
static uint8_t ROWC[N][D];
static uint8_t MIT[N][N][16];   /* MIT[k][v][x] = MI[k][v]·x */
static const char *g_sortie = ".";

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 4; i++) {
        if (b & 1)
            p ^= a;
        uint8_t hi = a & 8;
        a = (a << 1) & 15;
        if (hi)
            a ^= (BR_POLY & 15);
        b >>= 1;
    }
    return p;
}

static inline int par(unsigned v) { return __builtin_parity(v); }

static int inverse_gf16(uint8_t A[N][N], uint8_t R[N][N])
{
    static uint8_t T[N][2 * N];
    for (int i = 0; i < N; i++)
        for (int j = 0; j < 2 * N; j++)
            T[i][j] = j < N ? A[i][j] : (j - N == i);
    for (int c = 0; c < N; c++) {
        int p = -1;
        for (int r = c; r < N; r++)
            if (T[r][c]) { p = r; break; }
        if (p < 0)
            return 0;
        if (p != c)
            for (int j = 0; j < 2 * N; j++) { uint8_t t = T[p][j]; T[p][j] = T[c][j]; T[c][j] = t; }
        uint8_t iv = GINV[T[c][c]];
        for (int j = 0; j < 2 * N; j++)
            T[c][j] = GM[iv][T[c][j]];
        for (int r = 0; r < N; r++)
            if (r != c && T[r][c]) {
                uint8_t f = T[r][c];
                for (int j = 0; j < 2 * N; j++)
                    T[r][j] ^= GM[f][T[c][j]];
            }
    }
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            R[i][j] = T[i][N + j];
    return 1;
}

/* rang sur GF(16) d'une matrice nr × nc (nr ≤ 64, nc ≤ N) */
static int rang_gf16(uint8_t A[][N], int nr, int nc)
{
    uint8_t T[64][N];
    memcpy(T, A, sizeof(uint8_t) * N * nr);
    int rg = 0;
    for (int c = 0; c < nc && rg < nr; c++) {
        int p = -1;
        for (int r = rg; r < nr; r++)
            if (T[r][c]) { p = r; break; }
        if (p < 0)
            continue;
        for (int j = 0; j < nc; j++) { uint8_t t = T[p][j]; T[p][j] = T[rg][j]; T[rg][j] = t; }
        uint8_t iv = GINV[T[rg][c]];
        for (int j = 0; j < nc; j++)
            T[rg][j] = GM[iv][T[rg][j]];
        for (int r = 0; r < nr; r++)
            if (r != rg && T[r][c]) {
                uint8_t f = T[r][c];
                for (int j = 0; j < nc; j++)
                    T[r][j] ^= GM[f][T[rg][j]];
            }
        rg++;
    }
    return rg;
}

static void init_modele(void)
{
    for (int a = 0; a < 16; a++)
        for (int b = 0; b < 16; b++)
            GM[a][b] = gmul((uint8_t)a, (uint8_t)b);
    for (int a = 1; a < 16; a++)
        for (int b = 1; b < 16; b++)
            if (GM[a][b] == 1)
                GINV[a] = (uint8_t)b;
    for (int c = 0; c < 16; c++)
        for (int mu = 0; mu < 16; mu++) {
            int r = 0;
            for (int q = 0; q < 4; q++)
                r |= par(mu & GM[c][1 << q]) << q;
            GMT[c][mu] = (uint8_t)r;
        }
    memset(MM, 0, sizeof MM);
    for (int e = 0; e < BR_ARETES; e++)
        MM[e / D][BR_EI[e]] = BR_EC[e];
    if (!inverse_gf16(MM, MI)) {
        fprintf(stderr, "M non inversible\n");
        exit(2);
    }
    for (int i = 0; i < N; i++) {
        int n = 0;
        for (int j = 0; j < N; j++)
            if (MM[j][i]) { COLJ[i][n] = j; COLC[i][n] = MM[j][i]; n++; }
        if (n != D) { fprintf(stderr, "colonne %d de poids %d\n", i, n); exit(2); }
        n = 0;
        for (int k = 0; k < N; k++)
            if (MM[i][k]) { ROWK[i][n] = k; ROWC[i][n] = MM[i][k]; n++; }
        if (n != D) { fprintf(stderr, "ligne %d de poids %d\n", i, n); exit(2); }
    }
    for (int k = 0; k < N; k++)
        for (int v = 0; v < N; v++)
            for (int x = 0; x < 16; x++)
                MIT[k][v][x] = GM[MI[k][v]][x];
}

/* ------------------------------------------------------------------------------------------ */
/* S-box                                                                                       */
/* ------------------------------------------------------------------------------------------ */

typedef struct {
    char nom[40];
    uint8_t s[16], si[16];
    int ddt[16][16], lat[16][16], bct[16][16];
    int rowmax[16];      /* max_b DDT[a][b] */
    int latcolmax[16];   /* max_u |LAT[u][w]| (masque de sortie w) */
    uint8_t (*T)[N * D][16];   /* T[r][e][x] = EC[e]·S(x ⊕ RC[r][EI[e]]) */
} sbox_t;

static const struct { const char *nom; uint8_t s[16]; } NOMMEES[] = {
    {"BRUME", {8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5}},
    {"SBOX6", {15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1}},
    {"SBOX_V3", {14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2}},
    {"SBOX_V4", {10, 4, 15, 6, 0, 2, 9, 5, 12, 8, 7, 3, 13, 1, 11, 14}},
};

static void sbox_tables(sbox_t *S)
{
    for (int x = 0; x < 16; x++)
        S->si[S->s[x]] = (uint8_t)x;
    memset(S->ddt, 0, sizeof S->ddt);
    for (int a = 0; a < 16; a++)
        for (int x = 0; x < 16; x++)
            S->ddt[a][S->s[x] ^ S->s[x ^ a]]++;
    for (int u = 0; u < 16; u++)
        for (int w = 0; w < 16; w++) {
            int t = 0;
            for (int x = 0; x < 16; x++)
                t += (par(u & x) ^ par(w & S->s[x])) ? -1 : 1;
            S->lat[u][w] = t;
        }
    for (int a = 0; a < 16; a++)
        for (int b = 0; b < 16; b++) {
            int t = 0;
            for (int x = 0; x < 16; x++)
                t += (S->si[S->s[x] ^ b] ^ S->si[S->s[x ^ a] ^ b]) == a;
            S->bct[a][b] = t;
        }
    for (int a = 0; a < 16; a++) {
        int m = 0;
        for (int b = 0; b < 16; b++)
            if (S->ddt[a][b] > m)
                m = S->ddt[a][b];
        S->rowmax[a] = m;
    }
    for (int w = 0; w < 16; w++) {
        int m = 0;
        for (int u = 0; u < 16; u++)
            if (abs(S->lat[u][w]) > m)
                m = abs(S->lat[u][w]);
        S->latcolmax[w] = m;
    }
    if (!S->T)
        S->T = malloc(sizeof(uint8_t) * BR_TOURS * N * D * 16);
    for (int r = 0; r < BR_TOURS; r++)
        for (int e = 0; e < N * D; e++)
            for (int x = 0; x < 16; x++)
                S->T[r][e][x] = GM[BR_EC[e]][S->s[x ^ BR_RC[r][BR_EI[e]]]];
}

static int sbox_lire(const char *spec, sbox_t *S)
{
    memset(S, 0, sizeof *S);
    for (size_t i = 0; i < sizeof NOMMEES / sizeof NOMMEES[0]; i++)
        if (!strcmp(spec, NOMMEES[i].nom)) {
            snprintf(S->nom, sizeof S->nom, "%s", NOMMEES[i].nom);
            memcpy(S->s, NOMMEES[i].s, 16);
            sbox_tables(S);
            return 1;
        }
    /* forme NOM=0123456789ABCDEF ou 0123456789ABCDEF */
    const char *eq = strchr(spec, '=');
    const char *hex = eq ? eq + 1 : spec;
    if (strlen(hex) != 16)
        return 0;
    int vu = 0;
    for (int i = 0; i < 16; i++) {
        char c = hex[i];
        int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10
              : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (v < 0 || (vu >> v & 1))
            return 0;
        vu |= 1 << v;
        S->s[i] = (uint8_t)v;
    }
    if (eq)
        snprintf(S->nom, sizeof S->nom, "%.*s", (int)(eq - spec), spec);
    else
        snprintf(S->nom, sizeof S->nom, "S_%s", hex);
    sbox_tables(S);
    return 1;
}

static void sbox_hex(const sbox_t *S, char out[17])
{
    for (int i = 0; i < 16; i++)
        out[i] = "0123456789ABCDEF"[S->s[i]];
    out[16] = 0;
}

/* ------------------------------------------------------------------------------------------ */
/* Permutation réduite (avant / arrière) et générateur à compteur                              */
/* ------------------------------------------------------------------------------------------ */

static inline void tour(const sbox_t *S, int r, const uint8_t *x, uint8_t *y)
{
    const uint8_t (*T)[16] = S->T[r];
    for (int v = 0; v < N; v++) {
        uint8_t acc = 0;
        for (int e = v * D; e < v * D + D; e++)
            acc ^= T[e][x[BR_EI[e]]];
        y[v] = acc;
    }
}

static inline void tour_inv(const sbox_t *S, int r, const uint8_t *y, uint8_t *x)
{
    for (int k = 0; k < N; k++) {
        uint8_t acc = 0;
        for (int v = 0; v < N; v++)
            acc ^= MIT[k][v][y[v]];
        x[k] = S->si[acc] ^ BR_RC[r][k];
    }
}

static void perm(const sbox_t *S, int r0, int R, uint8_t *x)
{
    uint8_t t[N];
    for (int r = r0; r < r0 + R; r++) {
        tour(S, r, x, t);
        memcpy(x, t, N);
    }
}

static void perm_inv(const sbox_t *S, int r0, int R, uint8_t *y)
{
    uint8_t t[N];
    for (int r = r0 + R - 1; r >= r0; r--) {
        tour_inv(S, r, y, t);
        memcpy(y, t, N);
    }
}

static inline uint64_t mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* flux indexé (graine, flux, compteur) : indépendant de l'ordonnancement des threads */
static inline uint64_t rng(uint64_t graine, uint64_t flux, uint64_t ctr)
{
    return mix64(mix64(graine ^ mix64(flux + 0x9E3779B97F4A7C15ULL)) + ctr * 0x9E3779B97F4A7C15ULL);
}

static void etat_aleatoire(uint64_t graine, uint64_t flux, uint64_t n, uint8_t x[N])
{
    for (int w = 0; w < 8; w++) {
        uint64_t r = rng(graine, flux, n * 8 + w);
        for (int q = 0; q < 16; q++)
            x[w * 16 + q] = (r >> (4 * q)) & 15;
    }
}

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + 1e-9 * t.tv_nsec;
}

static FILE *ouvrir(const char *prefixe, const char *nom, const char *ext)
{
    char ch[1024];
    mkdir(g_sortie, 0755);
    snprintf(ch, sizeof ch, "%s/%s_%s.%s", g_sortie, prefixe, nom, ext);
    FILE *f = fopen(ch, "w");
    if (!f) { perror(ch); exit(2); }
    return f;
}

/* intervalle de Wilson à z sigma pour k succès sur n */
static void wilson(double k, double n, double z, double *lo, double *hi)
{
    double p = k / n, z2 = z * z, den = 1 + z2 / n;
    double c = (p + z2 / (2 * n)) / den, h = z * sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / den;
    *lo = c - h;
    *hi = c + h;
}

/* ------------------------------------------------------------------------------------------ */
/* controle : modèle == permutation du dépôt                                                   */
/* ------------------------------------------------------------------------------------------ */

static int cmd_controle(const char *lib)
{
    int ok = 1;
    /* (1) S-box BRUME du tableau nommé == BR_SBOX du dépôt */
    sbox_t B;
    sbox_lire("BRUME", &B);
    int sb = !memcmp(B.s, BR_SBOX, 16);
    ok &= sb;
    /* (2) M · M^-1 == I */
    int inv = 1;
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++) {
            uint8_t a = 0;
            for (int k = 0; k < N; k++)
                a ^= GM[MM[i][k]][MI[k][j]];
            inv &= a == (i == j);
        }
    ok &= inv;
    /* (3) permutation 32 tours == sl_brume_permute_ref */
    int conf = -1, ntest = 2000;
    void *h = dlopen(lib, RTLD_NOW);
    if (h) {
        void (*init)(void) = (void (*)(void))dlsym(h, "sl_init");
        void (*ref)(uint8_t *) = (void (*)(uint8_t *))dlsym(h, "sl_brume_permute_ref");
        if (init && ref) {
            init();
            conf = 1;
            for (int n = 0; n < ntest; n++) {
                uint8_t x[N], e[64];
                etat_aleatoire(0xC0177E, 1, n, x);
                for (int j = 0; j < 64; j++)
                    e[j] = x[2 * j] | (x[2 * j + 1] << 4);
                ref(e);
                perm(&B, 0, BR_TOURS, x);
                for (int j = 0; j < N; j++)
                    conf &= x[j] == ((e[j >> 1] >> (4 * (j & 1))) & 15);
            }
        }
    }
    ok &= conf == 1;
    /* (4) aller-retour avant/arrière pour chaque S-box nommée, (5) adjoint binaire M^T */
    int ar = 1;
    for (size_t q = 0; q < sizeof NOMMEES / sizeof NOMMEES[0]; q++) {
        sbox_t S;
        sbox_lire(NOMMEES[q].nom, &S);
        for (int n = 0; n < 200; n++) {
            uint8_t x[N], y[N];
            etat_aleatoire(0xA11E, q, n, x);
            memcpy(y, x, N);
            perm(&S, 0, 5, y);
            perm_inv(&S, 0, 5, y);
            ar &= !memcmp(x, y, N);
        }
        free(S.T);
    }
    ok &= ar;
    int adj = 1;
    for (int n = 0; n < 2000; n++) {
        uint8_t x[N], u[N], y[N], w[N];
        etat_aleatoire(0xAD1, 2, n, x);
        etat_aleatoire(0xAD1, 3, n, u);
        for (int v = 0; v < N; v++) {
            uint8_t a = 0;
            for (int k = 0; k < N; k++)
                a ^= GM[MM[v][k]][x[k]];
            y[v] = a;
        }
        for (int k = 0; k < N; k++) {
            uint8_t a = 0;
            for (int v = 0; v < N; v++)
                a ^= GMT[MM[v][k]][u[v]];
            w[k] = a;
        }
        int p1 = 0, p2 = 0;
        for (int v = 0; v < N; v++) {
            p1 ^= par(u[v] & y[v]);
            p2 ^= par(w[v] & x[v]);
        }
        adj &= p1 == p2;
    }
    ok &= adj;
    /* (6) condition d'indépendance de l'énoncé D2 : rang 7 de M[N[i], ¬i] pour tout i */
    int rmin = 99;
    for (int i = 0; i < N; i++) {
        uint8_t A[64][N];
        memset(A, 0, sizeof A);
        for (int l = 0; l < D; l++) {
            int j = COLJ[i][l], c = 0;
            for (int k = 0; k < N; k++)
                if (k != i)
                    A[l][c++] = MM[j][k];
        }
        int r = rang_gf16(A, D, N - 1);
        if (r < rmin)
            rmin = r;
    }
    ok &= rmin == D;
    /* (7) structure : recouvrement maximal des voisinages fermés, densité de M^-1 */
    int recmax = 0, wmin = N, wmax = 0, triv = 0;
    for (int i = 0; i < N; i++)
        for (int k = 0; k < N; k++) {
            if (i != k) {
                int o = 0;
                for (int j = 0; j < N; j++)
                    o += MM[j][i] && MM[j][k];
                if (o > recmax)
                    recmax = o;
            }
            triv += !MM[k][i] && !MI[i][k];
        }
    for (int j = 0; j < N; j++) {
        int w = 0;
        for (int k = 0; k < N; k++)
            w += MI[k][j] != 0;
        if (w < wmin) wmin = w;
        if (w > wmax) wmax = w;
    }
    FILE *f = ouvrir("controle", "modele", "json");
    fprintf(f, "{\n  \"sbox_brume_egale_BR_SBOX\": %s,\n  \"M_fois_Minv_egal_I\": %s,\n"
               "  \"conformite_32_tours_vs_sl_brume_permute_ref\": %s,\n  \"etats_testes\": %d,\n"
               "  \"aller_retour_5_tours_4_sbox\": %s,\n  \"adjoint_binaire_MT\": %s,\n"
               "  \"rang_min_M_Ni_sans_i\": %d,\n  \"recouvrement_max_voisinages_fermes\": %d,\n"
               "  \"poids_colonnes_Minv\": [%d, %d],\n  \"couples_boomerang_2t_triviaux\": %d,\n"
               "  \"tout_ok\": %s\n}\n",
            sb ? "true" : "false", inv ? "true" : "false",
            conf == 1 ? "true" : conf == 0 ? "false" : "\"bibliotheque introuvable\"", ntest,
            ar ? "true" : "false", adj ? "true" : "false", rmin, recmax, wmin, wmax, triv,
            ok ? "true" : "false");
    fclose(f);
    printf("controle : sbox=%d M·M^-1=%d conformite32=%d aller-retour=%d adjoint=%d rang_min=%d "
           "recouvrement_max=%d poids(M^-1)=[%d,%d] triviaux=%d => %s\n",
           sb, inv, conf, ar, adj, rmin, recmax, wmin, wmax, triv, ok ? "OK" : "ECHEC");
    free(B.T);
    return ok ? 0 : 1;
}

/* ------------------------------------------------------------------------------------------ */
/* local : propriétés locales                                                                  */
/* ------------------------------------------------------------------------------------------ */

static int anf_deg(const int *f)
{
    int a[16];
    memcpy(a, f, sizeof a);
    for (int i = 0; i < 4; i++)
        for (int x = 0; x < 16; x++)
            if (x >> i & 1)
                a[x] ^= a[x ^ (1 << i)];
    int d = 0;
    for (int x = 0; x < 16; x++)
        if (a[x] && __builtin_popcount(x) > d)
            d = __builtin_popcount(x);
    return d;
}

/* table de division (bit) : u -> ensemble des v tels que x^u ait un terme contenant y^v... on
 * calcule, pour chaque masque de sortie v, le degré de y^v = Π_{k∈v} S_k(x), et pour chaque u le
 * nombre de v tels que le monôme x^u apparaisse dans y^v (propagation u -> v de la division
 * property conventionnelle : u -> v possible ssi x^u ⪯ un monôme de y^v). */
static void table_division(const uint8_t *s, int out[16])
{
    for (int u = 0; u < 16; u++) {
        int n = 0;
        for (int v = 0; v < 16; v++) {
            int f[16];
            for (int x = 0; x < 16; x++)
                f[x] = (s[x] & v) == v;
            int a[16];
            memcpy(a, f, sizeof a);
            for (int i = 0; i < 4; i++)
                for (int x = 0; x < 16; x++)
                    if (x >> i & 1)
                        a[x] ^= a[x ^ (1 << i)];
            int ok = 0;
            for (int m = 0; m < 16; m++)
                if (a[m] && (m & u) == u)
                    ok = 1;
            n += ok;
        }
        out[u] = n;
    }
}

static int cmd_local(int nc, char **specs)
{
    FILE *f = ouvrir("local", "sbox", "json");
    fprintf(f, "{\n");
    for (int q = 0; q < nc; q++) {
        sbox_t S;
        if (!sbox_lire(specs[q], &S)) { fprintf(stderr, "S-box invalide : %s\n", specs[q]); return 2; }
        int du = 0, lmax = 0, bmax = 0, rows2 = 0, bcol[17] = {0}, dhist[17] = {0};
        for (int a = 1; a < 16; a++) {
            int bm = 0;
            for (int b = 0; b < 16; b++) {
                if (S.ddt[a][b] > du) du = S.ddt[a][b];
                dhist[S.ddt[a][b]]++;
            }
            for (int b = 1; b < 16; b++) {
                if (S.bct[a][b] > bmax) bmax = S.bct[a][b];
                if (S.bct[a][b] > bm) bm = S.bct[a][b];
                bcol[S.bct[a][b]]++;
            }
            rows2 += S.rowmax[a] == 2;
        }
        int lrows4 = 0;
        for (int w = 1; w < 16; w++) {
            if (S.latcolmax[w] > lmax) lmax = S.latcolmax[w];
            lrows4 += S.latcolmax[w] == 4;
        }
        int deg[4], degi[4], fp = 0;
        for (int k = 0; k < 4; k++) {
            int c[16], ci[16];
            for (int x = 0; x < 16; x++) { c[x] = S.s[x] >> k & 1; ci[x] = S.si[x] >> k & 1; }
            deg[k] = anf_deg(c);
            degi[k] = anf_deg(ci);
        }
        int mindeg = 4; /* degré minimal des 15 combinaisons de composantes */
        for (int v = 1; v < 16; v++) {
            int c[16];
            for (int x = 0; x < 16; x++) c[x] = par(S.s[x] & v);
            int d = anf_deg(c);
            if (d < mindeg) mindeg = d;
        }
        for (int x = 0; x < 16; x++) fp += S.s[x] == x;
        int div[16], divi[16];
        table_division(S.s, div);
        table_division(S.si, divi);
        char hx[17];
        sbox_hex(&S, hx);
        fprintf(f, "  \"%s\": {\"sbox\": \"%s\", \"ddt_max\": %d, \"lat_max\": %d, \"bct_max\": %d,"
                   " \"lignes_ddt_max2\": %d, \"colonnes_lat_max4\": %d, \"points_fixes\": %d,"
                   " \"degres\": [%d,%d,%d,%d], \"degres_inverse\": [%d,%d,%d,%d],"
                   " \"degre_min_composantes\": %d,\n    \"spectre_bct\": {",
                S.nom, hx, du, lmax, bmax, rows2, lrows4, fp, deg[0], deg[1], deg[2], deg[3],
                degi[0], degi[1], degi[2], degi[3], mindeg);
        int first = 1;
        for (int v = 0; v <= 16; v++)
            if (bcol[v]) { fprintf(f, "%s\"%d\": %d", first ? "" : ", ", v, bcol[v]); first = 0; }
        fprintf(f, "},\n    \"division_sorties_par_u\": [");
        for (int u = 0; u < 16; u++) fprintf(f, "%s%d", u ? "," : "", div[u]);
        fprintf(f, "], \"division_inverse_sorties_par_u\": [");
        for (int u = 0; u < 16; u++) fprintf(f, "%s%d", u ? "," : "", divi[u]);
        fprintf(f, "]}%s\n", q + 1 < nc ? "," : "");
        printf("%-10s %s DU=%d |LAT|max=%d BCTmax=%d lignesDDTmax2=%d colLATmax4=%d deg=%d%d%d%d "
               "degmin=%d\n", S.nom, hx, du, lmax, bmax, rows2, lrows4, deg[0], deg[1], deg[2], deg[3],
               mindeg);
        free(S.T);
    }
    fprintf(f, "}\n");
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------------------------------ */
/* D2 : coque différentielle exacte à 2 tours, entrée de poids 1                                */
/* ------------------------------------------------------------------------------------------ */
/* α = a·e_i. S1 : a -> b (DDT[a][b]/16, exact car x_i uniforme). S2 : entrée M[j][i]·b en
 * j ∈ N[i], sortie d_j. β = M·d. Les 7 valeurs d'entrée de S2 sont uniformes et indépendantes de
 * x_i (rang 7 de M[N[i], ¬i], vérifié par `controle`), donc
 *     DP(α, β) = Σ_b DDT[a][b]/16 · Π_j DDT[M[j][i]·b][d_j]/16        (EXACT)
 * et toutes les caractéristiques de (α, β) sont dans cette somme (b est la seule variable libre).
 * Le maximum sur β est obtenu par B&B à borne admissible (Σ_b P_b · Π_restants max ligne).     */

typedef struct {
    int nb;
    int64_t pa[16];
    int inp[D][16];
    int64_t R[D + 1][16];
    const sbox_t *S;
    int64_t best;
    int dcur[D], dbest[D], nclust;
    long noeuds;
} ctx_d2;

static void d2_dfs(ctx_d2 *c, int l, const int64_t *P)
{
    c->noeuds++;
    if (l == D) {
        int64_t s = 0;
        int nz = 0;
        for (int t = 0; t < c->nb; t++) { s += P[t]; nz += P[t] > 0; }
        if (s > c->best) {
            c->best = s;
            memcpy(c->dbest, c->dcur, sizeof c->dcur);
            c->nclust = nz;
        }
        return;
    }
    int64_t bound = 0;
    for (int t = 0; t < c->nb; t++)
        bound += P[t] * c->R[l][t];
    if (bound <= c->best)
        return;
    /* ordre des valeurs : potentiel décroissant */
    int64_t pot[16];
    int ord[15];
    for (int d = 1; d < 16; d++) {
        int64_t p = 0;
        for (int t = 0; t < c->nb; t++)
            p += P[t] * c->S->ddt[c->inp[l][t]][d] * c->R[l + 1][t];
        pot[d] = p;
        ord[d - 1] = d;
    }
    for (int x = 1; x < 15; x++)
        for (int y = x; y > 0 && pot[ord[y]] > pot[ord[y - 1]]; y--) { int t = ord[y]; ord[y] = ord[y - 1]; ord[y - 1] = t; }
    for (int q = 0; q < 15; q++) {
        int d = ord[q];
        if (pot[d] <= c->best)
            break;
        int64_t Q[16];
        for (int t = 0; t < c->nb; t++)
            Q[t] = P[t] * c->S->ddt[c->inp[l][t]][d];
        c->dcur[l] = d;
        d2_dfs(c, l + 1, Q);
    }
}

typedef struct { int64_t hull, trail; int d[D], nclust; long noeuds; } res_d2;

static void d2_un(const sbox_t *S, int i, int a, res_d2 *o)
{
    ctx_d2 c;
    memset(&c, 0, sizeof c);
    c.S = S;
    int bl[16];
    for (int b = 1; b < 16; b++)
        if (S->ddt[a][b]) { bl[c.nb] = b; c.pa[c.nb] = S->ddt[a][b]; c.nb++; }
    for (int l = 0; l < D; l++)
        for (int t = 0; t < c.nb; t++)
            c.inp[l][t] = GM[COLC[i][l]][bl[t]];
    for (int t = 0; t < c.nb; t++) {
        c.R[D][t] = 1;
        for (int l = D - 1; l >= 0; l--)
            c.R[l][t] = c.R[l + 1][t] * S->rowmax[c.inp[l][t]];
    }
    int64_t tr = 0;
    for (int t = 0; t < c.nb; t++)
        if (c.pa[t] * c.R[0][t] > tr)
            tr = c.pa[t] * c.R[0][t];
    c.best = tr - 1;
    d2_dfs(&c, 0, c.pa);
    o->hull = c.best;
    o->trail = tr;
    memcpy(o->d, c.dbest, sizeof o->d);
    o->nclust = c.nclust;
    o->noeuds = c.noeuds;
}

/* β = M·d (d placé en N[i]) */
static void d2_beta(int i, const int *d, uint8_t beta[N])
{
    uint8_t z[N] = {0};
    for (int l = 0; l < D; l++)
        z[COLJ[i][l]] = (uint8_t)d[l];
    for (int v = 0; v < N; v++) {
        uint8_t a = 0;
        for (int e = v * D; e < v * D + D; e++)
            a ^= GM[BR_EC[e]][z[BR_EI[e]]];
        beta[v] = a;
    }
}

static void hexetat(const uint8_t *x, char *out)
{
    for (int j = 0; j < N; j++)
        out[j] = "0123456789abcdef"[x[j]];
    out[N] = 0;
}

/* contrôle empirique : fréquence de P2(x) ⊕ P2(x ⊕ α) = β sur 2^lg paires */
static uint64_t emp_d2(const sbox_t *S, int i, int a, const uint8_t *beta, int lg, uint64_t graine)
{
    uint64_t n = 1ULL << lg, k = 0;
#pragma omp parallel for reduction(+ : k) schedule(static)
    for (uint64_t s = 0; s < n; s++) {
        uint8_t x[N], y[N];
        etat_aleatoire(graine, 0xD2, s, x);
        memcpy(y, x, N);
        y[i] ^= (uint8_t)a;
        perm(S, 0, 2, x);
        perm(S, 0, 2, y);
        int ok = 1;
        for (int j = 0; j < N && ok; j++)
            ok = (x[j] ^ y[j]) == beta[j];
        k += ok;
    }
    return k;
}

static int cmd_d2(const char *spec, int lg_ctrl, int nctrl)
{
    sbox_t S;
    if (!sbox_lire(spec, &S)) return 2;
    static res_d2 res[N][16];
    double t0 = maintenant();
    long noeuds = 0;
#pragma omp parallel for collapse(2) schedule(dynamic) reduction(+ : noeuds)
    for (int i = 0; i < N; i++)
        for (int a = 1; a < 16; a++) {
            d2_un(&S, i, a, &res[i][a]);
            noeuds += res[i][a].noeuds;
        }
    double dt = maintenant() - t0;
    FILE *f = ouvrir("d2", S.nom, "csv");
    fprintf(f, "i,a,hull_num_sur_2p32,hull_log2,trail_num_sur_2p32,trail_log2,gain_coque_bits,"
               "nb_caracteristiques,d_N_i\n");
    int64_t hmax = 0, tmax = 0;
    int bi = 0, ba = 0, nclus = 0;
    int hist[64] = {0};
    for (int i = 0; i < N; i++)
        for (int a = 1; a < 16; a++) {
            res_d2 *r = &res[i][a];
            double hl = log2((double)r->hull) - 32, tl = log2((double)r->trail) - 32;
            fprintf(f, "%d,%d,%lld,%.6f,%lld,%.6f,%.6f,%d,", i, a, (long long)r->hull, hl,
                    (long long)r->trail, tl, hl - tl, r->nclust);
            for (int l = 0; l < D; l++)
                fprintf(f, "%x", r->d[l]);
            fprintf(f, "\n");
            if (r->hull > hmax) { hmax = r->hull; bi = i; ba = a; }
            if (r->trail > tmax) tmax = r->trail;
            nclus += r->nclust > 1;
            int bin = (int)floor(-(hl) * 2);
            if (bin >= 0 && bin < 64) hist[bin]++;
        }
    fclose(f);
    /* contrôles empiriques : les nctrl plus grandes coques */
    int ci[64], ca[64];
    int nc = 0;
    {
        static int pris[N][16];
        memset(pris, 0, sizeof pris);
        for (int q = 0; q < nctrl && q < 64; q++) {
            int64_t m = -1;
            int mi = 0, ma = 0;
            for (int i = 0; i < N; i++)
                for (int a = 1; a < 16; a++)
                    if (!pris[i][a] && res[i][a].hull > m) { m = res[i][a].hull; mi = i; ma = a; }
            pris[mi][ma] = 1;
            ci[nc] = mi;
            ca[nc] = ma;
            nc++;
        }
    }
    FILE *g = ouvrir("d2", S.nom, "json");
    char hx[17], bh[N + 1];
    sbox_hex(&S, hx);
    uint8_t beta[N];
    d2_beta(bi, res[bi][ba].d, beta);
    hexetat(beta, bh);
    fprintf(g, "{\n  \"sbox\": \"%s\", \"nom\": \"%s\",\n  \"mesure\": \"D2 : max_beta DP(a·e_i -> beta) a 2 tours, "
               "coque complete (somme sur toutes les caracteristiques), entree de poids 1\",\n"
               "  \"statut\": \"EXACT_RESTREINT\",\n  \"restriction\": \"entree de poids 1 (1 S-box active au tour 1) ; "
               "la valeur de chaque DP(alpha,beta) est EXACTE pour la permutation 2 tours ; le passage au maximum "
               "global sur tous les alpha releve du certificat C2 (modele tronque, PROTOCOLE.md 4.1)\",\n"
               "  \"preuve\": \"B&B a borne admissible (sum_b P_b * prod max ligne DDT), exploration complete ; "
               "independance des entrees S2 : rang 7 verifie par controle\",\n"
               "  \"hull_max_log2\": %.6f, \"hull_max_num_sur_2p32\": %lld, \"argmax\": {\"i\": %d, \"a\": %d, "
               "\"beta\": \"%s\", \"nb_caracteristiques\": %d},\n  \"trail_max_log2\": %.6f,\n"
               "  \"entrees_avec_coque_multi_caracteristiques\": %d,\n  \"noeuds_bb\": %ld, \"duree_s\": %.2f,\n"
               "  \"histogramme_demi_bits_moins_log2\": {",
            hx, S.nom, log2((double)hmax) - 32, (long long)hmax, bi, ba, bh, res[bi][ba].nclust,
            log2((double)tmax) - 32, nclus, noeuds, dt);
    int first = 1;
    for (int b = 0; b < 64; b++)
        if (hist[b]) { fprintf(g, "%s\"%.1f\": %d", first ? "" : ", ", b / 2.0, hist[b]); first = 0; }
    fprintf(g, "},\n  \"controles_empiriques\": [\n");
    int ctrl_ok = 1;
    for (int q = 0; q < nc; q++) {
        int i = ci[q], a = ca[q];
        d2_beta(i, res[i][a].d, beta);
        uint64_t k = emp_d2(&S, i, a, beta, lg_ctrl, 0xD200 + q);
        double n = ldexp(1, lg_ctrl), p = ldexp((double)res[i][a].hull, -32);
        double lo, hi;
        wilson((double)k, n, 4.0, &lo, &hi);
        int dans = p >= lo && p <= hi;
        ctrl_ok &= dans;
        fprintf(g, "    {\"i\": %d, \"a\": %d, \"dp_exact\": %.9g, \"paires\": %.0f, \"succes\": %llu, "
                   "\"freq\": %.9g, \"wilson4sigma\": [%.9g, %.9g], \"compatible\": %s}%s\n",
                i, a, p, n, (unsigned long long)k, k / n, lo, hi, dans ? "true" : "false",
                q + 1 < nc ? "," : "");
    }
    fprintf(g, "  ],\n  \"controles_ok\": %s\n}\n", ctrl_ok ? "true" : "false");
    fclose(g);
    printf("D2 %-10s hull_max=2^%.4f (i=%d,a=%d, %d car.) trail_max=2^%.4f multi=%d noeuds=%ld %.1fs ctrl=%s\n",
           S.nom, log2((double)hmax) - 32, bi, ba, res[bi][ba].nclust, log2((double)tmax) - 32, nclus,
           noeuds, dt, ctrl_ok ? "OK" : "ECHEC");
    free(S.T);
    return ctrl_ok ? 0 : 1;
}

/* ------------------------------------------------------------------------------------------ */
/* L2 : coque linéaire exacte à 2 tours (constantes comprises), une S-box active au tour 2      */
/* ------------------------------------------------------------------------------------------ */
/* Masques : sortie u2 = (M^-1)^T λe_j, donc masque λ en sortie de S2 au nibble j ; entrée de
 * S2 μ (seule variable libre) ; sortie de S1 w1_k = L^T_{M[j][k]} μ (k ∈ N[j]) ; entrée u0.
 *   C(u0, u2) = Σ_μ (-1)^{μ·rc1_j} LAT[μ][λ]/16 · Π_k (-1)^{u0_k·rc0_k} LAT[u0_k][w1_k(μ)]/16
 * identité exacte (théorème de la coque linéaire, aucune hypothèse d'indépendance).          */

typedef struct {
    int nm;
    int64_t P0[16];
    int w1[D][16];
    int64_t R[D + 1][16];
    const sbox_t *S;
    int64_t best;
    int ucur[D], ubest[D], nclust;
    int64_t sbest;
    long noeuds;
} ctx_l2;

static void l2_dfs(ctx_l2 *c, int l, const int64_t *P)
{
    c->noeuds++;
    if (l == D) {
        int64_t s = 0;
        int nz = 0;
        for (int t = 0; t < c->nm; t++) { s += P[t]; nz += P[t] != 0; }
        if (llabs(s) > c->best) {
            c->best = llabs(s);
            c->sbest = s;
            memcpy(c->ubest, c->ucur, sizeof c->ucur);
            c->nclust = nz;
        }
        return;
    }
    int64_t bound = 0;
    for (int t = 0; t < c->nm; t++)
        bound += llabs(P[t]) * c->R[l][t];
    if (bound <= c->best)
        return;
    int64_t pot[16];
    int ord[15];
    for (int u = 1; u < 16; u++) {
        int64_t p = 0;
        for (int t = 0; t < c->nm; t++)
            p += llabs(P[t] * c->S->lat[u][c->w1[l][t]]) * c->R[l + 1][t];
        pot[u] = p;
        ord[u - 1] = u;
    }
    for (int x = 1; x < 15; x++)
        for (int y = x; y > 0 && pot[ord[y]] > pot[ord[y - 1]]; y--) { int t = ord[y]; ord[y] = ord[y - 1]; ord[y - 1] = t; }
    for (int q = 0; q < 15; q++) {
        int u = ord[q];
        if (pot[u] <= c->best)
            break;
        int64_t Q[16];
        for (int t = 0; t < c->nm; t++)
            Q[t] = P[t] * c->S->lat[u][c->w1[l][t]];
        c->ucur[l] = u;
        l2_dfs(c, l + 1, Q);
    }
}

typedef struct { int64_t hull, signe, trail; int u[D], nclust; long noeuds; } res_l2;

static void l2_un(const sbox_t *S, int r0, int j, int lam, res_l2 *o)
{
    ctx_l2 c;
    memset(&c, 0, sizeof c);
    c.S = S;
    int ml[16];
    for (int mu = 1; mu < 16; mu++)
        if (S->lat[mu][lam]) {
            ml[c.nm] = mu;
            c.P0[c.nm] = (par(mu & BR_RC[r0 + 1][j]) ? -1 : 1) * S->lat[mu][lam];
            c.nm++;
        }
    for (int l = 0; l < D; l++)
        for (int t = 0; t < c.nm; t++)
            c.w1[l][t] = GMT[ROWC[j][l]][ml[t]];
    for (int t = 0; t < c.nm; t++) {
        c.R[D][t] = 1;
        for (int l = D - 1; l >= 0; l--)
            c.R[l][t] = c.R[l + 1][t] * S->latcolmax[c.w1[l][t]];
    }
    int64_t tr = 0;
    for (int t = 0; t < c.nm; t++)
        if (llabs(c.P0[t]) * c.R[0][t] > tr)
            tr = llabs(c.P0[t]) * c.R[0][t];
    c.best = 0;
    l2_dfs(&c, 0, c.P0);
    /* signe global des constantes du tour 1 */
    int sg = 1;
    for (int l = 0; l < D; l++)
        if (par(c.ubest[l] & BR_RC[r0][ROWK[j][l]]))
            sg = -sg;
    o->hull = c.best;
    o->signe = sg * c.sbest;
    o->trail = tr;
    memcpy(o->u, c.ubest, sizeof o->u);
    o->nclust = c.nclust;
    o->noeuds = c.noeuds;
}

/* corrélation empirique E[(-1)^{u0·x ⊕ u2·P2(x)}] sur 2^lg entrées */
static int64_t emp_l2(const sbox_t *S, int r0, const uint8_t *u0, const uint8_t *u2, int lg, uint64_t graine)
{
    uint64_t n = 1ULL << lg;
    int64_t s = 0;
#pragma omp parallel for reduction(+ : s) schedule(static)
    for (uint64_t q = 0; q < n; q++) {
        uint8_t x[N];
        etat_aleatoire(graine, 0x12, q, x);
        int p = 0;
        for (int k = 0; k < N; k++)
            p ^= par(u0[k] & x[k]);
        perm(S, r0, 2, x);
        for (int k = 0; k < N; k++)
            p ^= par(u2[k] & x[k]);
        s += p ? -1 : 1;
    }
    return s;
}

static int cmd_l2(const char *spec, int r0, int lg_ctrl, int nctrl)
{
    sbox_t S;
    if (!sbox_lire(spec, &S)) return 2;
    static res_l2 res[N][16];
    double t0 = maintenant();
    long noeuds = 0;
#pragma omp parallel for collapse(2) schedule(dynamic) reduction(+ : noeuds)
    for (int j = 0; j < N; j++)
        for (int lam = 1; lam < 16; lam++) {
            l2_un(&S, r0, j, lam, &res[j][lam]);
            noeuds += res[j][lam].noeuds;
        }
    double dt = maintenant() - t0;
    char nomf[64];
    snprintf(nomf, sizeof nomf, "%s_r%d", S.nom, r0);
    FILE *f = ouvrir("l2", nomf, "csv");
    fprintf(f, "j,lambda,abs_hull_num_sur_2p32,correlation_signee_num,abs_corr_log2,trail_log2,gain_coque_bits,"
               "nb_caracteristiques,u0_N_j\n");
    int64_t hmax = 0, tmax = 0;
    int bj = 0, bl = 0, nclus = 0, nannul = 0;
    for (int j = 0; j < N; j++)
        for (int lam = 1; lam < 16; lam++) {
            res_l2 *r = &res[j][lam];
            double hl = log2((double)r->hull) - 32, tl = log2((double)r->trail) - 32;
            fprintf(f, "%d,%d,%lld,%lld,%.6f,%.6f,%.6f,%d,", j, lam, (long long)r->hull, (long long)r->signe,
                    hl, tl, hl - tl, r->nclust);
            for (int l = 0; l < D; l++)
                fprintf(f, "%x", r->u[l]);
            fprintf(f, "\n");
            if (r->hull > hmax) { hmax = r->hull; bj = j; bl = lam; }
            if (r->trail > tmax) tmax = r->trail;
            nclus += r->nclust > 1;
            nannul += r->hull < r->trail;
        }
    fclose(f);
    FILE *g = ouvrir("l2", nomf, "json");
    char hx[17];
    sbox_hex(&S, hx);
    fprintf(g, "{\n  \"sbox\": \"%s\", \"nom\": \"%s\", \"tours\": [%d, %d],\n"
               "  \"mesure\": \"L2 : max |C(u0 -> u2)| a 2 tours avec constantes, une S-box active au tour 2\",\n"
               "  \"statut\": \"EXACT_RESTREINT\",\n  \"restriction\": \"masque de sortie de S2 de poids 1 ; chaque "
               "correlation est EXACTE (theoreme de la coque lineaire, constantes comprises)\",\n"
               "  \"preuve\": \"B&B a borne admissible (sum_mu |P_mu| * prod max colonne |LAT|), exploration complete\",\n"
               "  \"abs_corr_max_log2\": %.6f, \"argmax\": {\"j\": %d, \"lambda\": %d, \"correlation_signee_num\": %lld, "
               "\"nb_caracteristiques\": %d},\n  \"trail_max_log2\": %.6f,\n"
               "  \"entrees_multi_caracteristiques\": %d, \"entrees_ou_la_coque_annule_la_meilleure_piste\": %d,\n"
               "  \"noeuds_bb\": %ld, \"duree_s\": %.2f,\n  \"controles_empiriques\": [\n",
            hx, S.nom, r0, r0 + 1, log2((double)hmax) - 32, bj, bl, (long long)res[bj][bl].signe,
            res[bj][bl].nclust, log2((double)tmax) - 32, nclus, nannul, noeuds, dt);
    /* contrôles : les nctrl plus grandes, corrélation signée comparée à 4 sigma */
    static int pris[N][16];
    memset(pris, 0, sizeof pris);
    int ctrl_ok = 1;
    for (int q = 0; q < nctrl; q++) {
        int64_t m = -1;
        int mj = 0, ml = 0;
        for (int j = 0; j < N; j++)
            for (int lam = 1; lam < 16; lam++)
                if (!pris[j][lam] && res[j][lam].hull > m) { m = res[j][lam].hull; mj = j; ml = lam; }
        pris[mj][ml] = 1;
        uint8_t u0[N] = {0}, u2[N];
        for (int l = 0; l < D; l++)
            u0[ROWK[mj][l]] = (uint8_t)res[mj][ml].u[l];
        for (int v = 0; v < N; v++)
            u2[v] = GMT[MI[mj][v]][ml];
        int64_t s = emp_l2(&S, r0, u0, u2, lg_ctrl, 0x1200 + q);
        double n = ldexp(1, lg_ctrl), ce = s / n, cx = ldexp((double)res[mj][ml].signe, -32);
        double sig = sqrt((1 - cx * cx) / n);
        int dans = fabs(ce - cx) <= 4 * sig;
        ctrl_ok &= dans;
        fprintf(g, "    {\"j\": %d, \"lambda\": %d, \"correlation_exacte\": %.9g, \"entrees\": %.0f, "
                   "\"correlation_mesuree\": %.9g, \"ecart_en_sigma\": %.3f, \"compatible\": %s}%s\n",
                mj, ml, cx, n, ce, (ce - cx) / sig, dans ? "true" : "false", q + 1 < nctrl ? "," : "");
    }
    fprintf(g, "  ],\n  \"controles_ok\": %s\n}\n", ctrl_ok ? "true" : "false");
    fclose(g);
    printf("L2 %-10s r0=%d |C|max=2^%.4f (j=%d,l=%d,%d car.) trail=2^%.4f multi=%d annul=%d %.1fs ctrl=%s\n",
           S.nom, r0, log2((double)hmax) - 32, bj, bl, res[bj][bl].nclust, log2((double)tmax) - 32, nclus,
           nannul, dt, ctrl_ok ? "OK" : "ECHEC");
    free(S.T);
    return ctrl_ok ? 0 : 1;
}

/* ------------------------------------------------------------------------------------------ */
/* B2 : boomerang exact à 2 tours, α = a·e_i, δ = M·(δ' e_j')                                   */
/* ------------------------------------------------------------------------------------------ */
/* Avec c1 = M[j'][i] et c2 = M^-1[i][j'] (voir PROTOCOLE.md § 4.3) :
 *  P = 2^-8 Σ_{x,t} [γ(t) = γ(t ⊕ c1·b(x))] · [S^-1(S(x)⊕c2γ(t)) ⊕ S^-1(S(x⊕a)⊕c2γ(t)) = a]
 * avec b(x) = S(x)⊕S(x⊕a), γ(t) = t ⊕ S^-1(S(t)⊕δ'). x et t uniformes indépendants (exact).
 * P ne dépend de (i, j') que par (c1, c2) : la table P[c1][c2][a][δ'] est complète.          */

static int b2_val(const sbox_t *S, int c1, int c2, int a, int dp)
{
    int n = 0;
    for (int x = 0; x < 16; x++) {
        int b = S->s[x] ^ S->s[x ^ a];
        for (int t = 0; t < 16; t++) {
            int g1 = t ^ S->si[S->s[t] ^ dp];
            int t2 = t ^ GM[c1][b];
            int g2 = t2 ^ S->si[S->s[t2] ^ dp];
            if (g1 != g2)
                continue;
            int g = GM[c2][g1];
            n += (S->si[S->s[x] ^ g] ^ S->si[S->s[x ^ a] ^ g]) == a;
        }
    }
    return n;
}

static int emp_b2_un(const sbox_t *S, int i, int a, int jp, int dp, uint64_t q, uint64_t graine)
{
    uint8_t x1[N], x2[N], dl[N];
    etat_aleatoire(graine, 0xB2, q, x1);
    memcpy(x2, x1, N);
    x2[i] ^= (uint8_t)a;
    for (int v = 0; v < N; v++)
        dl[v] = GM[MM[v][jp]][dp];
    perm(S, 0, 2, x1);
    perm(S, 0, 2, x2);
    for (int v = 0; v < N; v++) { x1[v] ^= dl[v]; x2[v] ^= dl[v]; }
    perm_inv(S, 0, 2, x1);
    perm_inv(S, 0, 2, x2);
    for (int k = 0; k < N; k++)
        if ((x1[k] ^ x2[k]) != (k == i ? a : 0))
            return 0;
    return 1;
}

static int cmd_b2(const char *spec, int lg_ctrl, int nctrl)
{
    sbox_t S;
    if (!sbox_lire(spec, &S)) return 2;
    static int P[16][16][16][16];
    for (int c1 = 0; c1 < 16; c1++)
        for (int c2 = 0; c2 < 16; c2++)
            for (int a = 1; a < 16; a++)
                for (int dp = 1; dp < 16; dp++)
                    P[c1][c2][a][dp] = b2_val(&S, c1, c2, a, dp);
    int occ[16][16] = {{0}};
    for (int i = 0; i < N; i++)
        for (int jp = 0; jp < N; jp++)
            occ[MM[jp][i]][MI[i][jp]]++;
    FILE *f = ouvrir("b2", S.nom, "csv");
    fprintf(f, "c1_M_jp_i,c2_Minv_i_jp,occurrences_i_jp,a,delta_p,P_num_sur_256,P_log2\n");
    int mx_tous = 0, mx_deux = 0, mx_c1 = 0, mx_c2 = 0;
    int arg[4] = {0}, argd[4] = {0};
    long hist[257] = {0}, histd[257] = {0};
    for (int c1 = 0; c1 < 16; c1++)
        for (int c2 = 0; c2 < 16; c2++) {
            if (!occ[c1][c2])
                continue;
            for (int a = 1; a < 16; a++)
                for (int dp = 1; dp < 16; dp++) {
                    int v = P[c1][c2][a][dp];
                    fprintf(f, "%d,%d,%d,%d,%d,%d,%.6f\n", c1, c2, occ[c1][c2], a, dp, v,
                            v ? log2(v / 256.0) : -INFINITY);
                    if (c1 == 0 && c2 == 0)
                        continue;
                    hist[v] += occ[c1][c2];
                    if (v > mx_tous) { mx_tous = v; arg[0] = c1; arg[1] = c2; arg[2] = a; arg[3] = dp; }
                    if (c1 && c2) {
                        histd[v] += occ[c1][c2];
                        if (v > mx_deux) { mx_deux = v; argd[0] = c1; argd[1] = c2; argd[2] = a; argd[3] = dp; }
                    }
                    if (c1 && !c2 && v > mx_c1) mx_c1 = v;
                    if (!c1 && c2 && v > mx_c2) mx_c2 = v;
                }
        }
    fclose(f);
    /* moyenne pondérée des probabilités sur les couples non triviaux, deux couches actives */
    double moy = 0, tot = 0;
    for (int v = 0; v <= 256; v++) { moy += histd[v] * (double)v; tot += histd[v]; }
    moy /= tot * 256;
    FILE *g = ouvrir("b2", S.nom, "json");
    char hx[17];
    sbox_hex(&S, hx);
    fprintf(g, "{\n  \"sbox\": \"%s\", \"nom\": \"%s\",\n  \"mesure\": \"B2 : probabilite de retour du boomerang a 2 tours, "
               "alpha = a e_i, delta = M (delta' e_j'), pour tous (i, a, j', delta')\",\n  \"statut\": \"EXACT_RESTREINT\",\n"
               "  \"restriction\": \"alpha de poids 1, delta' de poids 1 ; chaque probabilite est EXACTE pour la permutation 2 tours\",\n"
               "  \"preuve\": \"enumeration exhaustive des 256 valeurs locales (x, t) ; independance de t et x (t contient un "
               "terme uniforme independant)\",\n  \"couples_triviaux_c1_c2_nuls\": %d,\n"
               "  \"P_max_non_trivial_log2\": %.6f, \"argmax\": {\"c1\": %d, \"c2\": %d, \"a\": %d, \"delta_p\": %d},\n"
               "  \"P_max_deux_couches_actives_log2\": %.6f, \"argmax_deux\": {\"c1\": %d, \"c2\": %d, \"a\": %d, \"delta_p\": %d},\n"
               "  \"P_max_c2_nul_log2\": %.6f, \"P_max_c1_nul_log2\": %.6f,\n  \"P_moyenne_deux_couches\": %.9g,\n"
               "  \"histogramme_P_num_sur_256_deux_couches\": {",
            hx, S.nom, occ[0][0], log2(mx_tous / 256.0), arg[0], arg[1], arg[2], arg[3], log2(mx_deux / 256.0),
            argd[0], argd[1], argd[2], argd[3], log2(mx_c1 / 256.0), log2(mx_c2 / 256.0), moy);
    int first = 1;
    for (int v = 0; v <= 256; v++)
        if (histd[v]) { fprintf(g, "%s\"%d\": %ld", first ? "" : ", ", v, histd[v]); first = 0; }
    fprintf(g, "},\n  \"controles_empiriques\": [\n");
    /* contrôles : nctrl couples (i, j') réalisant les plus grandes valeurs à deux couches + 1 trivial */
    int ctrl_ok = 1, fait = 0;
    for (int q = 0; q <= nctrl; q++) {
        int c1, c2, a, dp, ti = -1, tj = -1;
        if (q < nctrl) {
            /* q-ième meilleure valeur à deux couches actives, couples distincts */
            int best = -1;
            c1 = c2 = a = dp = 0;
            for (int u = 1; u < 16; u++)
                for (int w = 1; w < 16; w++)
                    if (occ[u][w])
                        for (int aa = 1; aa < 16; aa++)
                            for (int dd = 1; dd < 16; dd++) {
                                int v = P[u][w][aa][dd]; /* les valeurs déjà prises sont marquées < 0 */
                                if (v > best) { best = v; c1 = u; c2 = w; a = aa; dp = dd; }
                            }
            P[c1][c2][a][dp] = -1 - P[c1][c2][a][dp]; /* marquer comme pris */
        } else {
            c1 = 0; c2 = 0; a = 1; dp = 1;
        }
        for (int i = 0; i < N && ti < 0; i++)
            for (int jp = 0; jp < N; jp++)
                if (MM[jp][i] == c1 && MI[i][jp] == c2) { ti = i; tj = jp; break; }
        if (ti < 0)
            continue;
        int vexact = q < nctrl ? -1 - P[c1][c2][a][dp] : 256;
        uint64_t n = 1ULL << lg_ctrl, k = 0;
#pragma omp parallel for reduction(+ : k) schedule(static)
        for (uint64_t s = 0; s < n; s++)
            k += emp_b2_un(&S, ti, a, tj, dp, s, 0xB200 + q);
        double p = vexact / 256.0, lo, hi;
        wilson((double)k, (double)n, 4.0, &lo, &hi);
        int dans = (p >= lo && p <= hi) || (p == 1.0 && k == n);
        ctrl_ok &= dans;
        fprintf(g, "%s    {\"i\": %d, \"j_p\": %d, \"c1\": %d, \"c2\": %d, \"a\": %d, \"delta_p\": %d, "
                   "\"P_exact\": %.9g, \"quartets\": %llu, \"retours\": %llu, \"wilson4sigma\": [%.9g, %.9g], "
                   "\"compatible\": %s}",
                fait ? ",\n" : "", ti, tj, c1, c2, a, dp, p, (unsigned long long)n, (unsigned long long)k, lo, hi,
                dans ? "true" : "false");
        fait++;
    }
    fprintf(g, "\n  ],\n  \"controles_ok\": %s\n}\n", ctrl_ok ? "true" : "false");
    fclose(g);
    printf("B2 %-10s Pmax(non triv.)=2^%.4f Pmax(2 couches)=2^%.4f moy(2 couches)=2^%.4f triviaux=%d ctrl=%s\n",
           S.nom, log2(mx_tous / 256.0), log2(mx_deux / 256.0), log2(moy), occ[0][0], ctrl_ok ? "OK" : "ECHEC");
    free(S.T);
    return ctrl_ok ? 0 : 1;
}

/* ------------------------------------------------------------------------------------------ */
/* D3 / L3 : meilleure caractéristique à 3 tours, une S-box active au tour 1 (diff.) ou au     */
/* tour 3 (lin.) — B&B exact sur le sous-problème                                               */
/* ------------------------------------------------------------------------------------------ */
/* Instance générique : 7 variables (valeurs 1..15) de coût cost2[l][v], qui contribuent aux
 * positions de la couche externe via tab[coef][v] ; coût d'une position = c3[valeur].        */

#define NPOS 64
typedef struct {
    int cost2[D][16];
    int np;
    int ncontrib[NPOS];
    int cl[NPOS][D];
    uint8_t cc[NPOS][D];
    int dernier[NPOS];            /* indice de la dernière variable contributrice */
    const uint8_t (*tab)[16];
    const int *c3;
    int priv[D][16];              /* cost2 + coût des positions privées de l */
    int lb[D + 1];                /* Σ_{l' ≥ l} min priv */
    int fin[D][NPOS], nfin[D];    /* positions partagées closes au niveau l */
    int best, cur[D], arg[D];
    long noeuds;
} bb3_t;

static void bb3_prep(bb3_t *B)
{
    for (int l = 0; l < D; l++) {
        B->nfin[l] = 0;
        for (int v = 1; v < 16; v++) {
            int c = B->cost2[l][v];
            if (c >= INF) { B->priv[l][v] = INF; continue; }
            for (int p = 0; p < B->np; p++)
                if (B->ncontrib[p] == 1 && B->cl[p][0] == l)
                    c += B->c3[B->tab[B->cc[p][0]][v]];
            B->priv[l][v] = c;
        }
    }
    for (int p = 0; p < B->np; p++) {
        int m = 0;
        for (int q = 0; q < B->ncontrib[p]; q++)
            if (B->cl[p][q] > m) m = B->cl[p][q];
        B->dernier[p] = m;
        if (B->ncontrib[p] > 1)
            B->fin[m][B->nfin[m]++] = p;
    }
    B->lb[D] = 0;
    for (int l = D - 1; l >= 0; l--) {
        int m = INF;
        for (int v = 1; v < 16; v++)
            if (B->priv[l][v] < m) m = B->priv[l][v];
        B->lb[l] = B->lb[l + 1] + m;
    }
}

static void bb3_dfs(bb3_t *B, int l, int cout, uint8_t *acc)
{
    B->noeuds++;
    if (l == D) {
        if (cout < B->best) { B->best = cout; memcpy(B->arg, B->cur, sizeof B->cur); }
        return;
    }
    if (cout + B->lb[l] >= B->best)
        return;
    int ord[15];
    for (int v = 1; v < 16; v++) ord[v - 1] = v;
    for (int x = 1; x < 15; x++)
        for (int y = x; y > 0 && B->priv[l][ord[y]] < B->priv[l][ord[y - 1]]; y--) { int t = ord[y]; ord[y] = ord[y - 1]; ord[y - 1] = t; }
    for (int q = 0; q < 15; q++) {
        int v = ord[q];
        if (B->priv[l][v] >= INF || cout + B->priv[l][v] + B->lb[l + 1] >= B->best)
            break;
        uint8_t a2[NPOS];
        memcpy(a2, acc, B->np);
        int c = cout + B->priv[l][v];
        for (int p = 0; p < B->np; p++)
            if (B->ncontrib[p] > 1)
                for (int k = 0; k < B->ncontrib[p]; k++)
                    if (B->cl[p][k] == l)
                        a2[p] ^= B->tab[B->cc[p][k]][v];
        for (int k = 0; k < B->nfin[l]; k++)
            c += B->c3[a2[B->fin[l][k]]];
        B->cur[l] = v;
        bb3_dfs(B, l + 1, c, a2);
    }
}

static int C3D[16], C3L[16], CD[16][16], CL[16][16];

static void couts(const sbox_t *S)
{
    for (int e = 0; e < 16; e++) {
        C3D[e] = e ? 4 - (int)log2(S->rowmax[e]) : 0;
        C3L[e] = e ? 4 - (int)log2(S->latcolmax[e]) : 0;
        for (int v = 0; v < 16; v++) {
            CD[e][v] = S->ddt[e][v] ? 4 - (int)log2(S->ddt[e][v]) : INF;   /* diff : entrée e, sortie v */
            CL[v][e] = S->lat[v][e] ? 4 - (int)log2(abs(S->lat[v][e])) : INF; /* lin : entrée v, sortie e */
        }
    }
}

/* positions externes : pour D3, sorties k de M issues des j ∈ N[i] ; pour L3, entrées l de M^T
 * des k ∈ N[j]. vars[l] = nibble de la variable l. */
static void bb3_positions(bb3_t *B, const int *vars, int lin)
{
    B->np = 0;
    int idx[N];
    for (int k = 0; k < N; k++) idx[k] = -1;
    for (int l = 0; l < D; l++)
        for (int q = 0; q < D; q++) {
            int k = lin ? ROWK[vars[l]][q] : COLJ[vars[l]][q];
            uint8_t c = lin ? ROWC[vars[l]][q] : COLC[vars[l]][q];
            if (idx[k] < 0) { idx[k] = B->np; B->ncontrib[B->np] = 0; B->np++; }
            int p = idx[k];
            B->cl[p][B->ncontrib[p]] = l;
            B->cc[p][B->ncontrib[p]] = c;
            B->ncontrib[p]++;
        }
}

typedef struct { int cout, b, v[D]; long noeuds; } res3;

/* D3 : α = a e_i ; S1 a->b ; S2 en j_l = COLJ[i][l] : entrée M[j_l][i]·b, sortie d_l (variable) ;
 * S3 en k : entrée Σ M[k][j_l] d_l, sortie optimale (coût C3D). */
static void d3_un(const sbox_t *S, int i, int a, res3 *o)
{
    bb3_t B;
    memset(&B, 0, sizeof B);
    int vars[D];
    for (int l = 0; l < D; l++) vars[l] = COLJ[i][l];
    bb3_positions(&B, vars, 0);
    B.tab = (const uint8_t (*)[16])GM;
    B.c3 = C3D;
    o->cout = INF;
    o->noeuds = 0;
    /* b par coût S1 croissant */
    int bl[16], nb = 0;
    for (int c = 2; c <= 3; c++)
        for (int b = 1; b < 16; b++)
            if (S->ddt[a][b] && CD[a][b] == c) bl[nb++] = b;
    for (int q = 0; q < nb; q++) {
        int b = bl[q], c1 = CD[a][b];
        for (int l = 0; l < D; l++) {
            int e = GM[COLC[i][l]][b];
            for (int v = 0; v < 16; v++) B.cost2[l][v] = v ? CD[e][v] : INF;
        }
        bb3_prep(&B);
        B.best = o->cout - c1;
        B.noeuds = 0;
        uint8_t acc[NPOS] = {0};
        bb3_dfs(&B, 0, 0, acc);
        o->noeuds += B.noeuds;
        if (B.best + c1 < o->cout) {
            o->cout = B.best + c1;
            o->b = b;
            memcpy(o->v, B.arg, sizeof B.arg);
        }
    }
}

/* L3 : S3 unique en j : sortie λ, entrée μ ; S2 en k_l = ROWK[j][l] : sortie L^T_{M[j][k]} μ,
 * entrée v_l (variable) ; S1 en p : sortie Σ L^T_{M[k][p]} v_l, entrée optimale (coût C3L). */
static void l3_un(const sbox_t *S, int j, int lam, res3 *o)
{
    bb3_t B;
    memset(&B, 0, sizeof B);
    int vars[D];
    for (int l = 0; l < D; l++) vars[l] = ROWK[j][l];
    bb3_positions(&B, vars, 1);
    B.tab = (const uint8_t (*)[16])GMT;
    B.c3 = C3L;
    o->cout = INF;
    o->noeuds = 0;
    int ml[16], nm = 0;
    for (int c = 1; c <= 2; c++)
        for (int mu = 1; mu < 16; mu++)
            if (S->lat[mu][lam] && CL[mu][lam] == c) ml[nm++] = mu;
    for (int q = 0; q < nm; q++) {
        int mu = ml[q], c1 = CL[mu][lam];
        for (int l = 0; l < D; l++) {
            int w = GMT[ROWC[j][l]][mu];
            for (int v = 0; v < 16; v++) B.cost2[l][v] = v ? CL[v][w] : INF;
        }
        bb3_prep(&B);
        B.best = o->cout - c1;
        B.noeuds = 0;
        uint8_t acc[NPOS] = {0};
        bb3_dfs(&B, 0, 0, acc);
        o->noeuds += B.noeuds;
        if (B.best + c1 < o->cout) {
            o->cout = B.best + c1;
            o->b = mu;
            memcpy(o->v, B.arg, sizeof B.arg);
        }
    }
}

/* vérificateur indépendant d'une caractéristique D3 : recalcul complet par la matrice M */
static int d3_verifier(const sbox_t *S, int i, int a, const res3 *r)
{
    int cost = CD[a][r->b];
    uint8_t z[N] = {0}, y[N];
    uint8_t u1[N] = {0};
    u1[i] = (uint8_t)r->b;
    for (int v = 0; v < N; v++) { uint8_t s = 0; for (int k = 0; k < N; k++) s ^= GM[MM[v][k]][u1[k]]; y[v] = s; }
    int nact = 0;
    for (int v = 0; v < N; v++)
        if (y[v]) {
            int l = -1;
            for (int q = 0; q < D; q++) if (COLJ[i][q] == v) l = q;
            if (l < 0) return -1;
            if (!S->ddt[y[v]][r->v[l]]) return -1;
            cost += CD[y[v]][r->v[l]];
            z[v] = (uint8_t)r->v[l];
            nact++;
        }
    if (nact != D) return -1;
    for (int v = 0; v < N; v++) { uint8_t s = 0; for (int k = 0; k < N; k++) s ^= GM[MM[v][k]][z[k]]; y[v] = s; }
    for (int v = 0; v < N; v++) cost += C3D[y[v]];
    return cost;
}

static int l3_verifier(const sbox_t *S, int j, int lam, const res3 *r)
{
    int cost = CL[r->b][lam];
    uint8_t v2[N] = {0}, w[N];
    /* masque en sortie de S2 : M^T (μ e_j) */
    uint8_t m[N] = {0};
    m[j] = (uint8_t)r->b;
    for (int k = 0; k < N; k++) { uint8_t s = 0; for (int v = 0; v < N; v++) s ^= GMT[MM[v][k]][m[v]]; w[k] = s; }
    int nact = 0;
    for (int k = 0; k < N; k++)
        if (w[k]) {
            int l = -1;
            for (int q = 0; q < D; q++) if (ROWK[j][q] == k) l = q;
            if (l < 0) return -1;
            if (!S->lat[r->v[l]][w[k]]) return -1;
            cost += CL[r->v[l]][w[k]];
            v2[k] = (uint8_t)r->v[l];
            nact++;
        }
    if (nact != D) return -1;
    for (int k = 0; k < N; k++) { uint8_t s = 0; for (int v = 0; v < N; v++) s ^= GMT[MM[v][k]][v2[v]]; w[k] = s; }
    for (int k = 0; k < N; k++) cost += C3L[w[k]];
    return cost;
}

static int cmd_3t(const char *spec, int lin)
{
    sbox_t S;
    if (!sbox_lire(spec, &S)) return 2;
    couts(&S);
    static res3 res[N][16];
    double t0 = maintenant();
    long noeuds = 0;
#pragma omp parallel for collapse(2) schedule(dynamic) reduction(+ : noeuds)
    for (int i = 0; i < N; i++)
        for (int a = 1; a < 16; a++) {
            if (lin) l3_un(&S, i, a, &res[i][a]);
            else d3_un(&S, i, a, &res[i][a]);
            noeuds += res[i][a].noeuds;
        }
    double dt = maintenant() - t0;
    const char *pre = lin ? "l3" : "d3";
    FILE *f = ouvrir(pre, S.nom, "csv");
    fprintf(f, lin ? "j,lambda,cout_bits_correlation,mu,v_N_j,verif\n" : "i,a,cout_bits,b,d_N_i,verif\n");
    int cmin = INF, cmax = 0, bi = 0, ba = 0, verif = 1, hist[200] = {0};
    for (int i = 0; i < N; i++)
        for (int a = 1; a < 16; a++) {
            res3 *r = &res[i][a];
            int vc = lin ? l3_verifier(&S, i, a, r) : d3_verifier(&S, i, a, r);
            verif &= vc == r->cout;
            fprintf(f, "%d,%d,%d,%d,", i, a, r->cout, r->b);
            for (int l = 0; l < D; l++) fprintf(f, "%x", r->v[l]);
            fprintf(f, ",%d\n", vc == r->cout);
            if (r->cout < cmin) { cmin = r->cout; bi = i; ba = a; }
            if (r->cout > cmax) cmax = r->cout;
            if (r->cout < 200) hist[r->cout]++;
        }
    fclose(f);
    FILE *g = ouvrir(pre, S.nom, "json");
    char hx[17];
    sbox_hex(&S, hx);
    fprintf(g, "{\n  \"sbox\": \"%s\", \"nom\": \"%s\",\n  \"mesure\": \"%s\",\n  \"statut\": \"EXACT_RESTREINT\",\n"
               "  \"restriction\": \"%s\",\n  \"preuve\": \"B&B a borne admissible (couts prives exacts, positions partagees "
               "minorees par 0), exploration complete ; chaque caracteristique optimale revérifiée par recalcul "
               "independant avec la matrice M complete\",\n  \"modele\": \"caracteristique (une seule piste), cout = "
               "somme des -log2 ; ce n'est ni une coque ni une borne de securite\",\n"
               "  \"cout_min_bits\": %d, \"argmin\": {\"%s\": %d, \"%s\": %d, \"%s\": %d},\n  \"cout_max_sur_les_entrees\": %d,\n"
               "  \"verifications_independantes_ok\": %s,\n  \"noeuds_bb\": %ld, \"duree_s\": %.2f,\n  \"histogramme\": {",
            hx, S.nom,
            lin ? "L3 : meilleure caracteristique lineaire a 3 tours (cout en bits de correlation)"
                : "D3 : meilleure caracteristique differentielle a 3 tours (cout en bits de probabilite)",
            lin ? "une seule S-box active au tour 3 (masque de sortie de S3 de poids 1), toutes les autres "
                  "variables libres"
                : "une seule S-box active au tour 1 (entree de poids 1), toutes les autres variables libres",
            cmin, lin ? "j" : "i", bi, lin ? "lambda" : "a", ba, lin ? "mu" : "b", res[bi][ba].b, cmax,
            verif ? "true" : "false", noeuds, dt);
    int first = 1;
    for (int c = 0; c < 200; c++)
        if (hist[c]) { fprintf(g, "%s\"%d\": %d", first ? "" : ", ", c, hist[c]); first = 0; }
    fprintf(g, "}\n}\n");
    fclose(g);
    printf("%s %-10s cout_min=%d (%d,%d) cout_max=%d verif=%s noeuds=%ld %.1fs\n", lin ? "L3" : "D3", S.nom, cmin,
           bi, ba, cmax, verif ? "OK" : "ECHEC", noeuds, dt);
    free(S.T);
    return verif ? 0 : 1;
}

/* ------------------------------------------------------------------------------------------ */
/* B3 : boomerang à 3 tours (EMPIRIQUE, apparié) — PROTOCOLE.md § 4.4                           */
/* ------------------------------------------------------------------------------------------ */
/* α = a e_i, δ = M(δ' e_j'). Après le tour 1 complet, retour réussi ssi
 *   Y3 ⊕ Y4 = ε·M[:, i] (entrées de S2 des paires retour) et S1^-1(U3_i) ⊕ S1^-1(U3_i ⊕ ε) = a,
 * reformulation algébrique exacte vérifiée quartet par quartet contre l'inversion complète
 * (perm_inv) : `identite_rapide_vs_inverse_complete`.
 * Sélection des (i, a, j', δ') par un PRÉDICTEUR (modèle de Markov, pas une mesure) :
 *   pred = Σ_b p(a,b) Σ_γ DDT[γ][δ']/16 Σ_ε DDT[a][ε]/16 Π_{k∈N[i]} G[M[k][i]b][M^-1[k][j']γ][M[k][i]ε]/16
 * G[Δ][g][Δ'] = #{y : S^-1(S(y)⊕g) ⊕ S^-1(S(y⊕Δ)⊕g) = Δ'} (BCT généralisée), restreint aux j'
 * hors de portée de N[i] (aucune S3 commune : condition de S3 automatiquement satisfaite).   */

static int b3_rapide(const sbox_t *S, int i, int a, int jp, int dp, const uint8_t *x0)
{
    uint8_t y1[N], z1[N], z2[N];
    tour(S, 0, x0, y1);
    for (int k = 0; k < N; k++)
        z1[k] = S->s[y1[k] ^ BR_RC[1][k]];
    memcpy(z2, z1, N);
    int xi = x0[i] ^ BR_RC[0][i];
    int b = S->s[xi] ^ S->s[xi ^ a];
    for (int l = 0; l < D; l++) {
        int k = COLJ[i][l];
        z2[k] = S->s[(y1[k] ^ GM[COLC[i][l]][b]) ^ BR_RC[1][k]];
    }
    int t1 = BR_RC[2][jp], t2 = BR_RC[2][jp];
    for (int q = 0; q < D; q++) {
        int l = ROWK[jp][q];
        t1 ^= GM[ROWC[jp][q]][z1[l]];
        t2 ^= GM[ROWC[jp][q]][z2[l]];
    }
    int g1 = t1 ^ S->si[S->s[t1] ^ dp], g2 = t2 ^ S->si[S->s[t2] ^ dp];
    /* Y3', Y4' (entrées de S2 après constante) et D = Y3' ⊕ Y4' */
    uint8_t y3[N];
    int eps = -1;
    for (int k = 0; k < N; k++) {
        int u3 = S->si[z1[k] ^ GM[MI[k][jp]][g1]];
        int u4 = S->si[z2[k] ^ GM[MI[k][jp]][g2]];
        y3[k] = (uint8_t)(u3 ^ BR_RC[1][k]);
        int dk = u3 ^ u4, mk = MM[k][i];
        if (!mk) {
            if (dk) return 0;
        } else {
            int e = GM[dk][GINV[mk]];
            if (eps < 0) eps = e;
            else if (e != eps) return 0;
        }
    }
    uint8_t u3i = 0;
    for (int k = 0; k < N; k++)
        u3i ^= MIT[i][k][y3[k]];
    return (S->si[u3i] ^ S->si[u3i ^ eps]) == a;
}

static int b3_complet(const sbox_t *S, int i, int a, int jp, int dp, const uint8_t *x0)
{
    uint8_t x1[N], x2[N];
    memcpy(x1, x0, N);
    memcpy(x2, x0, N);
    x2[i] ^= (uint8_t)a;
    perm(S, 0, 3, x1);
    perm(S, 0, 3, x2);
    for (int v = 0; v < N; v++) {
        uint8_t d = GM[MM[v][jp]][dp];
        x1[v] ^= d;
        x2[v] ^= d;
    }
    perm_inv(S, 0, 3, x1);
    perm_inv(S, 0, 3, x2);
    for (int k = 0; k < N; k++)
        if ((x1[k] ^ x2[k]) != (k == i ? a : 0))
            return 0;
    return 1;
}

static int G3[16][16][16];

static void table_g(const sbox_t *S)
{
    memset(G3, 0, sizeof G3);
    for (int d = 0; d < 16; d++)
        for (int g = 0; g < 16; g++)
            for (int y = 0; y < 16; y++)
                G3[d][g][S->si[S->s[y] ^ g] ^ S->si[S->s[y ^ d] ^ g]]++;
}

typedef struct { double pred; int i, a, jp, dp; } combo_t;

static int cmp_combo(const void *x, const void *y)
{
    double a = ((const combo_t *)x)->pred, b = ((const combo_t *)y)->pred;
    return a < b ? 1 : a > b ? -1 : 0;
}

/* les K meilleures combinaisons du prédicteur pour une S-box */
static void b3_predire(const sbox_t *S, int K, combo_t *top)
{
    table_g(S);
    combo_t *loc = calloc((size_t)N * 15 * K, sizeof(combo_t));
#pragma omp parallel for schedule(dynamic)
    for (int i = 0; i < N; i++) {
        int portee[N] = {0}; /* j' dont la ligne touche N[i] */
        for (int jp = 0; jp < N; jp++)
            for (int q = 0; q < D; q++)
                for (int l = 0; l < D; l++)
                    if (ROWK[jp][q] == COLJ[i][l]) portee[jp] = 1;
        for (int a = 1; a < 16; a++) {
            combo_t *t = loc + ((size_t)i * 15 + (a - 1)) * K;
            for (int q = 0; q < K; q++) t[q].pred = -1;
            for (int jp = 0; jp < N; jp++) {
                if (portee[jp]) continue;
                for (int dp = 1; dp < 16; dp++) {
                    double s = 0;
                    for (int b = 1; b < 16; b++) {
                        if (!S->ddt[a][b]) continue;
                        for (int g = 1; g < 16; g++) {
                            if (!S->ddt[g][dp]) continue;
                            for (int e = 1; e < 16; e++) {
                                if (!S->ddt[a][e]) continue;
                                double pr = S->ddt[a][b] * S->ddt[g][dp] * S->ddt[a][e] / 4096.0;
                                for (int l = 0; l < D && pr > 0; l++) {
                                    int k = COLJ[i][l], c = COLC[i][l];
                                    pr *= G3[GM[c][b]][GM[MI[k][jp]][g]][GM[c][e]] / 16.0;
                                }
                                s += pr;
                            }
                        }
                    }
                    if (s > t[K - 1].pred) {
                        int q = K - 1;
                        while (q > 0 && t[q - 1].pred < s) { t[q] = t[q - 1]; q--; }
                        t[q] = (combo_t){s, i, a, jp, dp};
                    }
                }
            }
        }
    }
    qsort(loc, (size_t)N * 15 * K, sizeof(combo_t), cmp_combo);
    memcpy(top, loc, sizeof(combo_t) * K);
    free(loc);
}

static int cmd_b3(int lg, int K, int lg_id, int nc, char **specs)
{
    sbox_t *S = calloc(nc, sizeof(sbox_t));
    for (int q = 0; q < nc; q++)
        if (!sbox_lire(specs[q], &S[q])) return 2;
    /* union des sélections */
    combo_t *uni = calloc((size_t)nc * K, sizeof(combo_t));
    int *source = calloc((size_t)nc * K, sizeof(int));
    int nu = 0;
    combo_t *top = calloc(K, sizeof(combo_t));
    for (int q = 0; q < nc; q++) {
        b3_predire(&S[q], K, top);
        for (int t = 0; t < K; t++) {
            int dup = 0;
            for (int u = 0; u < nu; u++)
                if (uni[u].i == top[t].i && uni[u].a == top[t].a && uni[u].jp == top[t].jp && uni[u].dp == top[t].dp)
                    dup = 1;
            if (!dup) { uni[nu] = top[t]; source[nu] = q; nu++; }
        }
    }
    FILE *f = ouvrir("b3", "apparie", "csv");
    fprintf(f, "sbox,i,a,j_p,delta_p,selection_par,prediction_markov,quartets,retours,P_empirique,P_log2,"
               "wilson4sigma_bas,wilson4sigma_haut,identite_rapide_vs_complete\n");
    double *pmax = calloc(nc, sizeof(double)), *pmaxlo = calloc(nc, sizeof(double));
    int id_ok = 1;
    double t0 = maintenant();
    for (int u = 0; u < nu; u++) {
        combo_t c = uni[u];
        for (int q = 0; q < nc; q++) {
            /* contrôle d'identité sur 2^lg_id quartets */
            uint64_t nid = 1ULL << lg_id, diff = 0;
#pragma omp parallel for reduction(+ : diff) schedule(static)
            for (uint64_t s = 0; s < nid; s++) {
                uint8_t x[N];
                etat_aleatoire(0xB3B3, (uint64_t)u, s, x);
                diff += b3_rapide(&S[q], c.i, c.a, c.jp, c.dp, x) != b3_complet(&S[q], c.i, c.a, c.jp, c.dp, x);
            }
            id_ok &= diff == 0;
            /* mesure : mêmes états d'entrée pour toutes les S-box (flux = combinaison) */
            uint64_t n = 1ULL << lg, k = 0;
#pragma omp parallel for reduction(+ : k) schedule(static)
            for (uint64_t s = 0; s < n; s++) {
                uint8_t x[N];
                etat_aleatoire(0xB30000 + (uint64_t)lg, (uint64_t)u, s, x);
                k += b3_rapide(&S[q], c.i, c.a, c.jp, c.dp, x);
            }
            double p = (double)k / n, lo, hi;
            wilson((double)k, (double)n, 4.0, &lo, &hi);
            /* prédiction pour cette S-box */
            table_g(&S[q]);
            double pr = 0;
            for (int b = 1; b < 16; b++)
                for (int g = 1; g < 16; g++)
                    for (int e = 1; e < 16; e++) {
                        double w = S[q].ddt[c.a][b] * S[q].ddt[g][c.dp] * S[q].ddt[c.a][e] / 4096.0;
                        for (int l = 0; l < D && w > 0; l++) {
                            int kk = COLJ[c.i][l], cc = COLC[c.i][l];
                            w *= G3[GM[cc][b]][GM[MI[kk][c.jp]][g]][GM[cc][e]] / 16.0;
                        }
                        pr += w;
                    }
            fprintf(f, "%s,%d,%d,%d,%d,%s,%.9g,%llu,%llu,%.9g,%.4f,%.9g,%.9g,%llu\n", S[q].nom, c.i, c.a, c.jp, c.dp,
                    S[source[u]].nom, pr, (unsigned long long)n, (unsigned long long)k, p, k ? log2(p) : -INFINITY, lo,
                    hi, (unsigned long long)diff);
            fflush(f);
            if (p > pmax[q]) { pmax[q] = p; pmaxlo[q] = lo; }
            printf("B3 %-10s (i=%3d a=%2d j'=%3d d'=%2d) pred=2^%.2f mes=2^%.3f [%llu/%llu] id=%llu (%.0fs)\n",
                   S[q].nom, c.i, c.a, c.jp, c.dp, log2(pr), k ? log2(p) : -99.0, (unsigned long long)k,
                   (unsigned long long)n, (unsigned long long)diff, maintenant() - t0);
            fflush(stdout);
        }
    }
    fclose(f);
    FILE *g = ouvrir("b3", "apparie", "json");
    fprintf(g, "{\n  \"mesure\": \"B3 : probabilite de retour du boomerang a 3 tours (tours 1-3), alpha = a e_i, "
               "delta = M(delta' e_j')\",\n  \"statut\": \"EMPIRIQUE\",\n  \"selection\": \"union des %d meilleures "
               "combinaisons du predicteur de Markov de chaque S-box (j' hors portee de N[i]) ; la selection ne "
               "depend pas des mesures\",\n  \"quartets_par_combinaison\": %.0f,\n  \"apparie\": \"memes etats "
               "d'entree (flux compteur, graine 0xB30000+lg, flux = indice de combinaison) pour toutes les S-box\",\n"
               "  \"identite_rapide_vs_inverse_complete\": {\"quartets_par_combinaison_et_sbox\": %.0f, \"ok\": %s},\n"
               "  \"combinaisons\": %d,\n  \"P_max_mesuree\": {",
            K, ldexp(1, lg), ldexp(1, lg_id), id_ok ? "true" : "false", nu);
    for (int q = 0; q < nc; q++)
        fprintf(g, "%s\"%s\": {\"P\": %.9g, \"log2\": %.4f, \"wilson4sigma_bas_log2\": %.4f}", q ? ", " : "",
                S[q].nom, pmax[q], log2(pmax[q]), log2(pmaxlo[q]));
    fprintf(g, "},\n  \"duree_s\": %.1f\n}\n", maintenant() - t0);
    fclose(g);
    for (int q = 0; q < nc; q++) free(S[q].T);
    return id_ok ? 0 : 1;
}

/* Balayage empirique des j' À PORTÉE de N[i] (exclus du prédicteur) : couples (i, j') dont au
 * moins zmin des 7 coefficients M^-1[N[i], j'] sont nuls, tous a et δ', 2^lg_scan quartets ;
 * les nconf meilleurs sont confirmés sur 2^lg_conf quartets avec une graine indépendante.     */
static int cmd_b3portee(int zmin, int lg_scan, int lg_conf, int nconf, int nc, char **specs)
{
    int paires[N * N][2], np = 0;
    for (int i = 0; i < N; i++)
        for (int jp = 0; jp < N; jp++) {
            int portee = 0, z = 0;
            for (int q = 0; q < D; q++)
                for (int l = 0; l < D; l++)
                    if (ROWK[jp][q] == COLJ[i][l]) portee = 1;
            for (int l = 0; l < D; l++) z += MI[COLJ[i][l]][jp] == 0;
            if (portee && z >= zmin) { paires[np][0] = i; paires[np][1] = jp; np++; }
        }
    FILE *f = ouvrir("b3portee", "balayage", "csv");
    fprintf(f, "sbox,i,a,j_p,delta_p,quartets_balayage,retours_balayage,quartets_confirmation,retours_confirmation,"
               "P_confirmation_log2,wilson4sigma_bas,wilson4sigma_haut\n");
    double t0 = maintenant();
    printf("b3portee : %d couples (i, j') a portee avec >= %d zeros\n", np, zmin);
    for (int q = 0; q < nc; q++) {
        sbox_t S;
        if (!sbox_lire(specs[q], &S)) return 2;
        int nk = np * 225;
        uint32_t *cnt = calloc(nk, sizeof(uint32_t));
        uint64_t n = 1ULL << lg_scan;
#pragma omp parallel for schedule(dynamic)
        for (int c = 0; c < nk; c++) {
            int p = c / 225, a = (c % 225) / 15 + 1, dp = c % 15 + 1;
            uint32_t k = 0;
            for (uint64_t s = 0; s < n; s++) {
                uint8_t x[N];
                etat_aleatoire(0xB3C0, (uint64_t)c, s, x);
                k += b3_rapide(&S, paires[p][0], a, paires[p][1], dp, x);
            }
            cnt[c] = k;
        }
        double pmax = 0, lomax = 0;
        for (int t = 0; t < nconf; t++) {
            int bc = 0;
            for (int c = 1; c < nk; c++) if (cnt[c] > cnt[bc]) bc = c;
            int p = bc / 225, a = (bc % 225) / 15 + 1, dp = bc % 15 + 1;
            uint64_t m = 1ULL << lg_conf, k = 0;
#pragma omp parallel for reduction(+ : k) schedule(static)
            for (uint64_t s = 0; s < m; s++) {
                uint8_t x[N];
                etat_aleatoire(0xB3C1, (uint64_t)bc, s, x);
                k += b3_rapide(&S, paires[p][0], a, paires[p][1], dp, x);
            }
            double pr = (double)k / m, lo, hi;
            wilson((double)k, (double)m, 4.0, &lo, &hi);
            fprintf(f, "%s,%d,%d,%d,%d,%llu,%u,%llu,%llu,%.4f,%.9g,%.9g\n", S.nom, paires[p][0], a, paires[p][1], dp,
                    (unsigned long long)n, cnt[bc], (unsigned long long)m, (unsigned long long)k, k ? log2(pr) : -99.0, lo,
                    hi);
            if (pr > pmax) { pmax = pr; lomax = lo; }
            cnt[bc] = 0;
        }
        fflush(f);
        printf("B3portee %-10s P_max_confirmee=2^%.3f (bas 4s 2^%.3f) (%.0fs)\n", S.nom, log2(pmax), log2(lomax),
               maintenant() - t0);
        fflush(stdout);
        free(cnt);
        free(S.T);
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------------------------------ */
/* INT : intégrales empiriques appariées (sommes de cubes) — PROTOCOLE.md § 4.5                 */
/* ------------------------------------------------------------------------------------------ */
/* Cube de k nibbles actifs (t = 4k bits), le reste fixé par une base aléatoire ; pour chaque
 * tour r = 1..R on accumule ⊕ des états et on compte les bits de somme nulle (sur 512).
 * Sens direct : tours 1..R ; sens inverse : tours 32..33-R inversés. Mêmes positions et mêmes
 * bases pour toutes les S-box. Statut EMPIRIQUE (somme nulle observée sur toutes les bases
 * n'est pas une preuve d'équilibre ; seule la division property le prouve).                 */

static int cmd_integral(int k, int nbases, int R, int inverse, int nc, char **specs)
{
    sbox_t *S = calloc(nc, sizeof(sbox_t));
    for (int q = 0; q < nc; q++)
        if (!sbox_lire(specs[q], &S[q])) return 2;
    /* deux géométries : voisinage fermé N[0] (k premiers) et positions aléatoires */
    int pos[2][8];
    for (int l = 0; l < k; l++) pos[0][l] = COLJ[0][l];
    {
        int pris[N] = {0}, n = 0;
        uint64_t c = 0;
        while (n < k) {
            int p = (int)(rng(0x1A7E, 7, c++) % N);
            if (!pris[p]) { pris[p] = 1; pos[1][n++] = p; }
        }
    }
    char nomf[64];
    snprintf(nomf, sizeof nomf, "%s_t%d_R%d", inverse ? "inverse" : "direct", 4 * k, R);
    FILE *f = ouvrir("integral", nomf, "csv");
    fprintf(f, "sbox,geometrie,base,tour,bits_somme_nulle_sur_512\n");
    double t0 = maintenant();
    int (*robuste)[2][9] = calloc(nc, sizeof *robuste);
    for (int q = 0; q < nc; q++) {
        for (int geo = 0; geo < 2; geo++) {
            uint8_t acc_and[9][N];
            memset(acc_and, 0, sizeof acc_and); /* OR des sommes : un bit est robuste s'il reste nul */
            for (int bs = 0; bs < nbases; bs++) {
                uint8_t base[N];
                etat_aleatoire(0x1B5E + (uint64_t)geo, (uint64_t)bs, 0, base);
                uint64_t n = 1ULL << (4 * k);
                uint8_t somme[9][N];
                memset(somme, 0, sizeof somme);
#pragma omp parallel
                {
                    uint8_t loc[9][N];
                    memset(loc, 0, sizeof loc);
#pragma omp for schedule(static)
                    for (uint64_t c = 0; c < n; c++) {
                        uint8_t x[N], t[N];
                        memcpy(x, base, N);
                        for (int l = 0; l < k; l++) x[pos[geo][l]] = (c >> (4 * l)) & 15;
                        for (int r = 1; r <= R; r++) {
                            if (inverse) tour_inv(&S[q], BR_TOURS - r, x, t);
                            else tour(&S[q], r - 1, x, t);
                            memcpy(x, t, N);
                            for (int j = 0; j < N; j++) loc[r][j] ^= x[j];
                        }
                    }
#pragma omp critical
                    for (int r = 1; r <= R; r++)
                        for (int j = 0; j < N; j++) somme[r][j] ^= loc[r][j];
                }
                for (int r = 1; r <= R; r++) {
                    int z = 0;
                    for (int j = 0; j < N; j++) {
                        z += 4 - __builtin_popcount(somme[r][j]);
                        acc_and[r][j] |= somme[r][j];
                    }
                    fprintf(f, "%s,%s,%d,%d,%d\n", S[q].nom, geo ? "aleatoire" : "voisinage", bs, r, z);
                }
                fflush(f);
            }
            for (int r = 1; r <= R; r++) {
                int z = 0;
                for (int j = 0; j < N; j++) z += 4 - __builtin_popcount(acc_and[r][j]);
                robuste[q][geo][r] = z;
            }
            printf("INT %s %-10s t=%d %s : robustes par tour", inverse ? "inv" : "dir", S[q].nom, 4 * k,
                   geo ? "aleatoire" : "voisinage");
            for (int r = 1; r <= R; r++) printf(" %d", robuste[q][geo][r]);
            printf(" (%.0fs)\n", maintenant() - t0);
            fflush(stdout);
        }
    }
    fclose(f);
    FILE *g = ouvrir("integral", nomf, "json");
    fprintf(g, "{\n  \"mesure\": \"bits de somme nulle sur toutes les bases (sur 512), cube de %d bits, %s\",\n"
               "  \"statut\": \"EMPIRIQUE\",\n  \"bases\": %d,\n  \"positions\": {\"voisinage\": [",
            4 * k, inverse ? "sens inverse (tours 32 a 33-R)" : "sens direct (tours 1 a R)", nbases);
    for (int l = 0; l < k; l++) fprintf(g, "%s%d", l ? "," : "", pos[0][l]);
    fprintf(g, "], \"aleatoire\": [");
    for (int l = 0; l < k; l++) fprintf(g, "%s%d", l ? "," : "", pos[1][l]);
    fprintf(g, "]},\n  \"robustes\": {");
    for (int q = 0; q < nc; q++) {
        fprintf(g, "%s\"%s\": {", q ? ", " : "", S[q].nom);
        for (int geo = 0; geo < 2; geo++) {
            fprintf(g, "%s\"%s\": [", geo ? ", " : "", geo ? "aleatoire" : "voisinage");
            for (int r = 1; r <= R; r++) fprintf(g, "%s%d", r > 1 ? "," : "", robuste[q][geo][r]);
            fprintf(g, "]");
        }
        fprintf(g, "}");
    }
    fprintf(g, "},\n  \"duree_s\": %.1f\n}\n", maintenant() - t0);
    fclose(g);
    for (int q = 0; q < nc; q++) free(S[q].T);
    return 0;
}

/* ------------------------------------------------------------------------------------------ */
/* criblage : recherche de S-box candidates                                                     */
/* ------------------------------------------------------------------------------------------ */
/* Tirage uniforme de permutations 4 bits (Fisher-Yates sur flux compteur), filtres durs :
 * DU = 4, |LAT| max = 8, toutes les composantes non nulles de degré 3. Puis métriques
 * exactes rapides : D3 et L3 (minimum global, B&B à borne commune), B2 (deux couches), D2, L2.
 * Les meilleures seront réévaluées par le protocole complet.                                   */

static int d3_global(const sbox_t *S, int lin, int *arg_i, int *arg_a)
{
    couts(S);
    int best = INF, bi = -1, ba = -1;
#pragma omp parallel for collapse(2) schedule(dynamic)
    for (int i = 0; i < N; i++)
        for (int a = 1; a < 16; a++) {
            int borne;
#pragma omp atomic read
            borne = best;
            /* sous-problème avec borne commune : on ne cherche qu'à faire mieux que `borne` */
            bb3_t B;
            memset(&B, 0, sizeof B);
            int vars[D];
            for (int l = 0; l < D; l++) vars[l] = lin ? ROWK[i][l] : COLJ[i][l];
            bb3_positions(&B, vars, lin);
            B.tab = lin ? (const uint8_t (*)[16])GMT : (const uint8_t (*)[16])GM;
            B.c3 = lin ? C3L : C3D;
            int meil = borne;
            for (int x = 1; x < 16; x++) {
                int c1 = lin ? (S->lat[x][a] ? CL[x][a] : INF) : (S->ddt[a][x] ? CD[a][x] : INF);
                if (c1 >= INF) continue;
                for (int l = 0; l < D; l++) {
                    int e = lin ? GMT[ROWC[i][l]][x] : GM[COLC[i][l]][x];
                    for (int v = 0; v < 16; v++) B.cost2[l][v] = v ? (lin ? CL[v][e] : CD[e][v]) : INF;
                }
                bb3_prep(&B);
                B.best = meil - c1;
                uint8_t acc[NPOS] = {0};
                bb3_dfs(&B, 0, 0, acc);
                if (B.best + c1 < meil) meil = B.best + c1;
            }
#pragma omp critical
            if (meil < best) { best = meil; bi = i; ba = a; }
        }
    *arg_i = bi;
    *arg_a = ba;
    return best;
}

static int d2_max_rapide(const sbox_t *S, double *l2)
{
    int64_t hm = 0, lm = 0;
#pragma omp parallel for collapse(2) schedule(dynamic) reduction(max : hm, lm)
    for (int i = 0; i < N; i++)
        for (int a = 1; a < 16; a++) {
            res_d2 r;
            d2_un(S, i, a, &r);
            if (r.hull > hm) hm = r.hull;
            res_l2 q;
            l2_un(S, 0, i, a, &q);
            if (q.hull > lm) lm = q.hull;
        }
    *l2 = log2((double)lm) - 32;
    return (int)hm;
}

static double b2_deux_max(const sbox_t *S)
{
    static int occ[16][16];
    static int fait = 0;
    if (!fait) {
        for (int i = 0; i < N; i++)
            for (int jp = 0; jp < N; jp++)
                occ[MM[jp][i]][MI[i][jp]]++;
        fait = 1;
    }
    int mx = 0;
    for (int c1 = 1; c1 < 16; c1++)
        for (int c2 = 1; c2 < 16; c2++)
            if (occ[c1][c2])
                for (int a = 1; a < 16; a++)
                    for (int dp = 1; dp < 16; dp++) {
                        int v = b2_val(S, c1, c2, a, dp);
                        if (v > mx) mx = v;
                    }
    return log2(mx / 256.0);
}

static int cmd_criblage(long ntirages, uint64_t graine, int d3min_garde)
{
    FILE *f = ouvrir("criblage", "candidates", "csv");
    fprintf(f, "tirage,sbox,lignes_ddt_max2,bct_max,D3_min_bits,L3_min_bits,D2_hull_max_log2,L2_abs_corr_max_log2,"
               "B2_deux_couches_max_log2,B3_prediction_max_log2\n");
    long admis = 0, gardes = 0;
    double t0 = maintenant();
    int meilleur = 0;
    for (long n = 0; n < ntirages; n++) {
        sbox_t S;
        memset(&S, 0, sizeof S);
        uint8_t p[16];
        for (int x = 0; x < 16; x++) p[x] = (uint8_t)x;
        for (int x = 15; x > 0; x--) {
            int y = (int)(rng(graine, 0x5B0C, (uint64_t)n * 16 + x) % (x + 1));
            uint8_t t = p[x]; p[x] = p[y]; p[y] = t;
        }
        memcpy(S.s, p, 16);
        /* filtres durs, sans construire les tables de tour */
        for (int x = 0; x < 16; x++) S.si[S.s[x]] = (uint8_t)x;
        int du = 0, lm = 0, ok = 1;
        for (int a = 1; a < 16 && ok; a++) {
            int cnt[16] = {0};
            for (int x = 0; x < 16; x++) cnt[S.s[x] ^ S.s[x ^ a]]++;
            for (int b = 0; b < 16; b++) if (cnt[b] > du) du = cnt[b];
            ok = du <= 4;
        }
        if (!ok) continue;
        for (int u = 0; u < 16 && ok; u++)
            for (int w = 1; w < 16 && ok; w++) {
                int t = 0;
                for (int x = 0; x < 16; x++) t += (par(u & x) ^ par(w & S.s[x])) ? -1 : 1;
                if (abs(t) > lm) lm = abs(t);
                ok = lm <= 8;
            }
        if (!ok) continue;
        for (int v = 1; v < 16 && ok; v++) {
            int c[16];
            for (int x = 0; x < 16; x++) c[x] = par(S.s[x] & v);
            ok = anf_deg(c) == 3;
        }
        if (!ok) continue;
        admis++;
        sbox_tables(&S);
        couts(&S);
        int bi, ba;
        int d3 = d3_global(&S, 0, &bi, &ba);
        int rows2 = 0, bmax = 0;
        for (int a = 1; a < 16; a++) {
            rows2 += S.rowmax[a] == 2;
            for (int b = 1; b < 16; b++) if (S.bct[a][b] > bmax) bmax = S.bct[a][b];
        }
        char hx[17];
        sbox_hex(&S, hx);
        if (d3 >= d3min_garde) {
            int l3 = d3_global(&S, 1, &bi, &ba);
            double l2;
            int hm = d2_max_rapide(&S, &l2);
            double b2 = b2_deux_max(&S);
            combo_t top;
            b3_predire(&S, 1, &top);
            double b3 = log2(top.pred);
            fprintf(f, "%ld,%s,%d,%d,%d,%d,%.6f,%.6f,%.6f,%.6f\n", n, hx, rows2, bmax, d3, l3, log2((double)hm) - 32, l2,
                    b2, b3);
            fflush(f);
            gardes++;
            if (d3 > meilleur) meilleur = d3;
            printf("criblage %ld %s rows2=%d bct=%d D3=%d L3=%d D2=2^%.3f L2=2^%.3f B2=2^%.3f B3p=2^%.3f (%.0fs)\n", n, hx,
                   rows2, bmax, d3, l3, log2((double)hm) - 32, l2, b2, b3, maintenant() - t0);
            fflush(stdout);
        }
        free(S.T);
    }
    fclose(f);
    printf("criblage : %ld tirages, %ld admis (filtres durs), %ld gardes (D3 >= %d), meilleur D3 = %d, %.0fs\n", ntirages,
           admis, gardes, d3min_garde, meilleur, maintenant() - t0);
    return 0;
}

/* ------------------------------------------------------------------------------------------ */
/* recuit : recherche dirigée (recuit simulé) dans l'ensemble admissible                       */
/* ------------------------------------------------------------------------------------------ */
/* Voisinages : transposition de deux sorties, transvection sur l'entrée ou la sortie (garde les
 * tables locales à équivalence près, change l'interaction avec M), 3-cycle. Admissible = R1.
 * Contraintes (R2, sur les mesures exactes) : D3 ≥ D3ref, L3 ≥ L3ref, D2 ≤ D2ref, L2(r0=0) ≤ L2ref,
 * B2 (deux couches) ≤ B2ref. Objectif : prédicteur B3 rapide (couples à ≥ zmin zéros) − 0,02·D3.
 * Les candidates finales sont réévaluées par le protocole complet (prédicteur complet, mesures). */

static int g_bctmax = 8;   /* R1 : BCT max ≤ 8 ; variante R1' (BCT ≤ 10 comme BRUME) : option du recuit */

static int R1_admissible(sbox_t *S)
{
    for (int x = 0; x < 16; x++) S->si[S->s[x]] = (uint8_t)x;
    for (int a = 1; a < 16; a++) {
        int cnt[16] = {0};
        for (int x = 0; x < 16; x++) cnt[S->s[x] ^ S->s[x ^ a]]++;
        for (int b = 0; b < 16; b++) if (cnt[b] > 4) return 0;
    }
    for (int u = 0; u < 16; u++)
        for (int w = 1; w < 16; w++) {
            int t = 0;
            for (int x = 0; x < 16; x++) t += (par(u & x) ^ par(w & S->s[x])) ? -1 : 1;
            if (abs(t) > 8) return 0;
        }
    for (int v = 1; v < 16; v++) {
        int c[16];
        for (int x = 0; x < 16; x++) c[x] = par(S->s[x] & v);
        if (anf_deg(c) != 3) return 0;
    }
    int rows2 = 0;
    for (int a = 1; a < 16; a++) {
        int m = 0;
        for (int x = 0; x < 16; x++) {
            int cnt = 0;
            for (int y = 0; y < 16; y++) cnt += (S->s[y] ^ S->s[y ^ a]) == (S->s[x] ^ S->s[x ^ a]);
            if (cnt > m) m = cnt;
        }
        rows2 += m == 2;
        for (int b = 1; b < 16; b++) {
            int t = 0;
            for (int x = 0; x < 16; x++) t += (S->si[S->s[x] ^ b] ^ S->si[S->s[x ^ a] ^ b]) == a;
            if (t > g_bctmax) return 0;
        }
    }
    return rows2 >= 3;
}

static int PAIRES_Z[N * N][2], NPZ = -1;

static double b3_pred_rapide(const sbox_t *S, int zmin)
{
    if (NPZ < 0) {
        NPZ = 0;
        for (int i = 0; i < N; i++)
            for (int jp = 0; jp < N; jp++) {
                int portee = 0, z = 0;
                for (int q = 0; q < D; q++)
                    for (int l = 0; l < D; l++)
                        if (ROWK[jp][q] == COLJ[i][l]) portee = 1;
                for (int l = 0; l < D; l++) z += MI[COLJ[i][l]][jp] == 0;
                if (!portee && z >= zmin) { PAIRES_Z[NPZ][0] = i; PAIRES_Z[NPZ][1] = jp; NPZ++; }
            }
    }
    table_g(S);
    double best = 0;
#pragma omp parallel for collapse(2) schedule(dynamic) reduction(max : best)
    for (int p = 0; p < NPZ; p++)
        for (int a = 1; a < 16; a++) {
            int i = PAIRES_Z[p][0], jp = PAIRES_Z[p][1];
            for (int dp = 1; dp < 16; dp++) {
                double s = 0;
                for (int b = 1; b < 16; b++) {
                    if (!S->ddt[a][b]) continue;
                    for (int g = 1; g < 16; g++) {
                        if (!S->ddt[g][dp]) continue;
                        for (int e = 1; e < 16; e++) {
                            if (!S->ddt[a][e]) continue;
                            double pr = S->ddt[a][b] * S->ddt[g][dp] * S->ddt[a][e] / 4096.0;
                            for (int l = 0; l < D && pr > 0; l++) {
                                int k = COLJ[i][l], c = COLC[i][l];
                                pr *= G3[GM[c][b]][GM[MI[k][jp]][g]][GM[c][e]] / 16.0;
                            }
                            s += pr;
                        }
                    }
                }
                if (s > best) best = s;
            }
        }
    return log2(best);
}

typedef struct { int d3, l3; double d2, l2, b2, b3; int faisable; double obj; } eval_t;

static eval_t evaluer(sbox_t *S, const eval_t *ref, int zmin)
{
    eval_t e;
    memset(&e, 0, sizeof e);
    sbox_tables(S);
    couts(S);
    e.b2 = b2_deux_max(S);
    e.b3 = b3_pred_rapide(S, zmin);
    int hm = d2_max_rapide(S, &e.l2);
    e.d2 = log2((double)hm) - 32;
    int bi, ba;
    e.d3 = d3_global(S, 0, &bi, &ba);
    e.l3 = d3_global(S, 1, &bi, &ba);
    double viol = 0;
    if (ref) {
        if (e.d3 < ref->d3) viol += ref->d3 - e.d3;
        if (e.l3 < ref->l3) viol += ref->l3 - e.l3;
        if (e.d2 > ref->d2 + 1e-9) viol += 10 * (e.d2 - ref->d2);
        if (e.l2 > ref->l2 + 1e-9) viol += 10 * (e.l2 - ref->l2);
        if (e.b2 > ref->b2 + 1e-9) viol += 10 * (e.b2 - ref->b2);
    }
    e.faisable = viol == 0;
    e.obj = e.b3 - 0.02 * e.d3 + viol;
    return e;
}

static void voisin(const uint8_t *s, uint8_t *t, uint64_t graine, uint64_t n)
{
    memcpy(t, s, 16);
    uint64_t r = rng(graine, 0x7EC, n);
    int m = r % 4;
    r >>= 2;
    if (m == 0) {          /* transposition */
        int x = r % 16, y = (r >> 4) % 16;
        if (x == y) y = (y + 1) % 16;
        uint8_t u = t[x]; t[x] = t[y]; t[y] = u;
    } else if (m == 1 || m == 2) { /* transvection x -> x ⊕ bit_i(x)·e_j, en entrée ou en sortie */
        int i = r % 4, j = (r >> 2) % 4;
        if (i == j) j = (j + 1) % 4;
        uint8_t u[16];
        for (int x = 0; x < 16; x++) {
            if (m == 1) { int xx = x ^ (((x >> i) & 1) << j); u[x] = s[xx]; }
            else u[x] = (uint8_t)(s[x] ^ (((s[x] >> i) & 1) << j));
        }
        memcpy(t, u, 16);
    } else {               /* 3-cycle */
        int x = r % 16, y = (r >> 4) % 16, z = (r >> 8) % 16;
        if (x == y || y == z || x == z) { y = (x + 5) % 16; z = (x + 11) % 16; }
        uint8_t u = t[x]; t[x] = t[y]; t[y] = t[z]; t[z] = u;
    }
}

static int cmd_recuit(long iters, uint64_t graine, const char *depart, int zmin, double T0)
{
    sbox_t ref, cur, nv;
    memset(&ref, 0, sizeof ref);
    if (!sbox_lire("BRUME", &ref)) return 2;
    eval_t eref = evaluer(&ref, NULL, zmin);
    memset(&cur, 0, sizeof cur);
    if (!sbox_lire(depart, &cur)) return 2;
    eval_t ec = evaluer(&cur, &eref, zmin), eb = ec;
    uint8_t meilleur[16];
    memcpy(meilleur, cur.s, 16);
    memset(&nv, 0, sizeof nv);
    char nomf[64];
    snprintf(nomf, sizeof nomf, "%s_%llx_bct%d", depart, (unsigned long long)graine, g_bctmax);
    FILE *f = ouvrir("recuit", nomf, "csv");
    fprintf(f, "iteration,sbox,faisable,objectif,D3,L3,D2,L2_r0,B2_deux,B3_pred_rapide,accepte\n");
    printf("reference BRUME : D3=%d L3=%d D2=%.4f L2=%.4f B2=%.4f B3p(z>=%d)=%.4f\n", eref.d3, eref.l3, eref.d2, eref.l2,
           eref.b2, zmin, eref.b3);
    double t0 = maintenant();
    long admis = 0;
    for (long n = 0; n < iters; n++) {
        double T = T0 * (1.0 - (double)n / iters) + 1e-3;
        uint64_t essai = (uint64_t)n << 12;
        int trouve = 0;
        for (int t = 0; t < 4096 && !trouve; t++) {
            voisin(cur.s, nv.s, graine, essai + t);
            trouve = memcmp(nv.s, cur.s, 16) && R1_admissible(&nv);
        }
        if (!trouve) continue;
        admis++;
        eval_t e = evaluer(&nv, &eref, zmin);
        double u = (double)(rng(graine, 0xACC, (uint64_t)n) >> 11) / 9007199254740992.0;
        int acc = e.obj <= ec.obj || u < exp(-(e.obj - ec.obj) / T);
        char hx[17];
        sbox_hex(&nv, hx);
        fprintf(f, "%ld,%s,%d,%.6f,%d,%d,%.6f,%.6f,%.6f,%.6f,%d\n", n, hx, e.faisable, e.obj, e.d3, e.l3, e.d2, e.l2,
                e.b2, e.b3, acc);
        if (acc) {
            memcpy(cur.s, nv.s, 16);
            ec = e;
            if (e.faisable && (!eb.faisable || e.obj < eb.obj)) {
                eb = e;
                memcpy(meilleur, nv.s, 16);
                printf("[%ld, %.0fs] meilleur faisable %s D3=%d L3=%d D2=%.4f L2=%.4f B2=%.4f B3p=%.4f\n", n,
                       maintenant() - t0, hx, e.d3, e.l3, e.d2, e.l2, e.b2, e.b3);
                fflush(stdout);
            }
        }
        if (n % 200 == 0) fflush(f);
    }
    fclose(f);
    char hx[17];
    memcpy(cur.s, meilleur, 16);
    sbox_hex(&cur, hx);
    printf("recuit %s graine=%llx : %ld admis, meilleur %s faisable=%d B3p=%.4f D3=%d (%.0fs)\n", depart,
           (unsigned long long)graine, admis, hx, eb.faisable, eb.b3, eb.d3, maintenant() - t0);
    free(ref.T);
    free(cur.T);
    free(nv.T);
    return 0;
}

/* écran : mêmes métriques rapides que le criblage, pour des S-box nommées */
static int cmd_ecran(int nc, char **specs)
{
    for (int q = 0; q < nc; q++) {
        sbox_t S;
        if (!sbox_lire(specs[q], &S)) return 2;
        couts(&S);
        int bi, ba;
        int d3 = d3_global(&S, 0, &bi, &ba), l3 = d3_global(&S, 1, &bi, &ba);
        double l2;
        int hm = d2_max_rapide(&S, &l2);
        double b2 = b2_deux_max(&S);
        combo_t top;
        b3_predire(&S, 1, &top);
        printf("ecran %-10s D3=%d L3=%d D2=2^%.3f L2=2^%.3f B2=2^%.3f B3p=2^%.3f (i=%d a=%d j'=%d d'=%d)\n", S.nom, d3, l3,
               log2((double)hm) - 32, l2, b2, log2(top.pred), top.i, top.a, top.jp, top.dp);
        free(S.T);
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------ */
/* main                                                                                        */
/* ------------------------------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr,
            "usage : departage [-o DOSSIER] commande ...\n"
            "  controle LIBSILLAGE.so\n"
            "  local SBOX...\n"
            "  d2 SBOX [lg_ctrl=24] [nctrl=3]\n"
            "  l2 SBOX [r0=0] [lg_ctrl=24] [nctrl=3]\n"
            "  b2 SBOX [lg_ctrl=22] [nctrl=3]\n"
            "  d3 SBOX | l3 SBOX\n"
            "  b3 lg K lg_identite SBOX...          (boomerang 3 tours apparie)\n"
            "  b3portee zmin lg_scan lg_conf nconf SBOX...  (j' a portee de N[i], empirique)\n"
            "  integral k_nibbles bases R inverse(0/1) SBOX...\n"
            "  criblage n_tirages graine D3_min_garde\n"
            "  recuit iterations graine SBOX_depart zmin T0 [bct_max=8]\n"
            "SBOX : BRUME, SBOX6, SBOX_V3, SBOX_V4, 16 chiffres hexa, ou NOM=hex\n");
}

int main(int argc, char **argv)
{
    int k = 1;
    if (k + 1 < argc && !strcmp(argv[k], "-o")) { g_sortie = argv[k + 1]; k += 2; }
    if (k >= argc) { usage(); return 2; }
    init_modele();
    const char *c = argv[k];
    int na = argc - k - 1;
    char **av = argv + k + 1;
    if (!strcmp(c, "controle") && na >= 1) return cmd_controle(av[0]);
    if (!strcmp(c, "local") && na >= 1) return cmd_local(na, av);
    if (!strcmp(c, "d2") && na >= 1) return cmd_d2(av[0], na > 1 ? atoi(av[1]) : 24, na > 2 ? atoi(av[2]) : 3);
    if (!strcmp(c, "l2") && na >= 1)
        return cmd_l2(av[0], na > 1 ? atoi(av[1]) : 0, na > 2 ? atoi(av[2]) : 24, na > 3 ? atoi(av[3]) : 3);
    if (!strcmp(c, "b2") && na >= 1) return cmd_b2(av[0], na > 1 ? atoi(av[1]) : 22, na > 2 ? atoi(av[2]) : 3);
    if (!strcmp(c, "d3") && na >= 1) return cmd_3t(av[0], 0);
    if (!strcmp(c, "l3") && na >= 1) return cmd_3t(av[0], 1);
    if (!strcmp(c, "b3") && na >= 4) return cmd_b3(atoi(av[0]), atoi(av[1]), atoi(av[2]), na - 3, av + 3);
    if (!strcmp(c, "integral") && na >= 5)
        return cmd_integral(atoi(av[0]), atoi(av[1]), atoi(av[2]), atoi(av[3]), na - 4, av + 4);
    if (!strcmp(c, "b3portee") && na >= 5)
        return cmd_b3portee(atoi(av[0]), atoi(av[1]), atoi(av[2]), atoi(av[3]), na - 4, av + 4);
    if (!strcmp(c, "recuit") && na >= 5) {
        if (na > 5) g_bctmax = atoi(av[5]);
        return cmd_recuit(atol(av[0]), strtoull(av[1], 0, 0), av[2], atoi(av[3]), atof(av[4]));
    }
    if (!strcmp(c, "ecran") && na >= 1) return cmd_ecran(na, av);
    if (!strcmp(c, "criblage") && na >= 3) return cmd_criblage(atol(av[0]), strtoull(av[1], 0, 0), atoi(av[2]));
    usage();
    return 2;
}
