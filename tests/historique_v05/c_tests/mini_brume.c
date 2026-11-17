/* Mini-BRUME : même S-box, même forme de couche linéaire (Cayley de D_3, réflexions, coefficients de GF(16)*
 * propres à chaque arête), 6 nibbles soit 24 bits. Assez petit pour calculer EXACTEMENT ce qui reste hors de
 * portée à 512 bits, donc pour éclairer deux questions ouvertes. Ce n'est pas une preuve pour BRUME-512 :
 * le graphe est K_{3,3}, et l'échelle change.
 *  1. Portée réelle du distingueur intégral (les pistes monomiales peuvent s'annuler) : toutes les sommes
 *     sur les cubes de codimension 1 et 2, à tous les tours, contre la borne de Boura–Canteaut.
 *     Dualité : somme sur {x_i = 0} du bit j de F = somme sur {y_j = 0} du bit i de F⁻¹.
 *  2. Validité du modèle de Markov et agrégation au-delà de 2 tours : loi exacte des différences en sortie
 *     (nibble d'entrée α) contre la chaîne de Markov (somme de tous les trails) et le meilleur trail ; de même
 *     pour les masques (Walsh exact contre LAT²). Le bruit n'est pas supposé : il est étalonné. La chaîne de
 *     Markov est EXACTEMENT la moyenne de la loi réelle sur des constantes de tour uniformes et indépendantes
 *     (Lai–Massey–Murphy pour les différences, Nyberg pour les LP), puisque chaque tour XORe sa constante avant
 *     les S-box. On tire donc NC jeux de constantes (même M, même α) et l'on mesure le même rapport pour chacun :
 *     sa moyenne doit valoir 1 (contrôle : vérifie l'hypothèse de base et le code de la chaîne) et sa dispersion
 *     est le vrai écart d'une instance à constantes fixes, qui remplace l'hypothèse d'un bruit de Poisson.
 *  3. Boomerang exact, pour tous les quartets.
 * Témoin : une permutation aléatoire traitée de la même façon.
 *     build/mini_brume [instances] [α par instance] [instances à 32 bits] [jeux de constantes NC]
 *     (depuis la racine) → resultats/mini_brume.json
 */
#include <math.h>
#include <omp.h>
#include <stdio.h>

#include "brume_ref.h"
#include "resultat.h"

#define NIB 6
#define BITS 24
#define TAILLE (1u << BITS)
#define RMAX 12

static uint64_t GR;
static inline uint32_t tirer(uint32_t n)
{
    GR += 0x9e3779b97f4a7c15ULL;
    uint64_t z = GR;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return (uint32_t)((z ^ (z >> 31)) % n);
}

static uint8_t MM[NIB][NIB], MI[NIB][NIB], RCM[RMAX][NIB];
static uint32_t LINM[NIB][16];
static int DDT[16][16], LAT[16][16];

static int inverser(void)
{
    uint8_t A[NIB][2 * NIB];
    for (int i = 0; i < NIB; i++)
        for (int j = 0; j < 2 * NIB; j++)
            A[i][j] = j < NIB ? MM[i][j] : j - NIB == i;
    for (int c = 0; c < NIB; c++) {
        int p = c;
        while (p < NIB && !A[p][c])
            p++;
        if (p == NIB)
            return 0;
        for (int j = 0; j < 2 * NIB; j++) { uint8_t t = A[p][j]; A[p][j] = A[c][j]; A[c][j] = t; }
        uint8_t iv = gf_inv(A[c][c]);
        for (int j = 0; j < 2 * NIB; j++)
            A[c][j] = gf_mul(A[c][j], iv);
        for (int i = 0; i < NIB; i++)
            if (i != c && A[i][c]) {
                uint8_t f = A[i][c];
                for (int j = 0; j < 2 * NIB; j++)
                    A[i][j] ^= gf_mul(f, A[c][j]);
            }
    }
    for (int i = 0; i < NIB; i++)
        memcpy(MI[i], A[i] + NIB, NIB);
    return 1;
}

/* branch number exact, par énumération des 16^6 vecteurs */
static int branch(void)
{
    int b = 99;
#pragma omp parallel for schedule(static) reduction(min : b)
    for (uint32_t x = 1; x < TAILLE; x++) {
        uint32_t y = 0;
        int w = 0;
        for (int k = 0; k < NIB; k++) {
            int v = x >> (4 * k) & 15;
            w += v != 0;
            y ^= LINM[k][v];
        }
        for (int k = 0; k < NIB; k++)
            w += (y >> (4 * k) & 15) != 0;
        if (w < b)
            b = w;
    }
    return b;
}

static int construire(void)
{
    /* rotations 0..2, réflexions 3..5 : chaque sommet voit tout l'autre côté et lui-même */
    for (int essai = 0; essai < 4000; essai++) {
        memset(MM, 0, sizeof MM);
        for (int i = 0; i < NIB; i++) {
            MM[i][i] = (uint8_t)(1 + tirer(15));
            for (int j = 0; j < NIB; j++)
                if ((i < 3) != (j < 3))
                    MM[i][j] = (uint8_t)(1 + tirer(15));
        }
        if (!inverser())
            continue;
        for (int k = 0; k < NIB; k++)
            for (int v = 0; v < 16; v++) {
                uint32_t y = 0;
                for (int i = 0; i < NIB; i++)
                    y |= (uint32_t)gf_mul(MM[i][k], (uint8_t)v) << (4 * i);
                LINM[k][v] = y;
            }
        int b = branch();
        if (b == 5) {
            for (int r = 0; r < RMAX; r++)
                for (int k = 0; k < NIB; k++)
                    RCM[r][k] = (uint8_t)tirer(16);
            return b;
        }
    }
    return 0;
}

static inline uint32_t tour(uint32_t x, int r)
{
    uint32_t y = 0;
    for (int k = 0; k < NIB; k++)
        y ^= LINM[k][BR_SBOX[(x >> (4 * k) & 15) ^ RCM[r][k]]];
    return y;
}

/* ---------------- 1. intégrales ---------------- */

/* A[i] = ⊕_{x : x_i = 0} F(x) ; B[i][j] = ⊕_{x : x_i = x_j = 0} F(x).
 * Trois XOR par x, dans les tables des 3 paires d'octets de x ; tous les cubes s'en déduisent ensuite. */
static uint32_t PAIRES[3][65536];

static void sommes(const uint32_t *F, uint32_t *A, uint32_t B[BITS][BITS])
{
    static const int OCTETS[3][2] = {{0, 1}, {0, 2}, {1, 2}};
    memset(A, 0, 4 * BITS);
    memset(B, 0, sizeof(uint32_t) * BITS * BITS);
    memset(PAIRES, 0, sizeof PAIRES);
#pragma omp parallel
    {
        uint32_t *p = calloc(3 * 65536, 4);
#pragma omp for schedule(static)
        for (uint32_t x = 0; x < TAILLE; x++) {
            uint32_t f = F[x];
            p[x & 0xffff] ^= f;
            p[65536 + ((x & 0xff) | (x >> 8 & 0xff00))] ^= f;
            p[131072 + (x >> 8)] ^= f;
        }
#pragma omp critical
        for (int k = 0; k < 3; k++)
            for (int v = 0; v < 65536; v++)
                PAIRES[k][v] ^= p[k * 65536 + v];
        free(p);
    }
    for (int i = 0; i < BITS; i++)
        for (int j = i; j < BITS; j++) {
            /* une paire d'octets qui contient i et j */
            int k = -1, oi = i / 8, oj = j / 8;
            for (int c = 0; c < 3; c++)
                if ((OCTETS[c][0] == oi || OCTETS[c][1] == oi) && (OCTETS[c][0] == oj || OCTETS[c][1] == oj)) {
                    k = c;
                    break;
                }
            int bi = (i % 8) + (OCTETS[k][0] == oi ? 0 : 8), bj = (j % 8) + (OCTETS[k][0] == oj ? 0 : 8);
            uint32_t s = 0;
            for (int v = 0; v < 65536; v++)
                if (!(v >> bi & 1) && !(v >> bj & 1))
                    s ^= PAIRES[k][v];
            if (i == j)
                A[i] = s;
            else
                B[i][j] = s;
        }
}

/* instance au format JSON, reprise par tests/test_brume_algebre.py (pistes monomiales) */
static void ecrire_instance(FILE *f, const char *debut, int n, const uint8_t *M, const uint8_t *rc, int rmax, const int *nz)
{
    fprintf(f, "%s{\"nibbles\": %d, \"M\": [", debut, n);
    for (int i = 0; i < n * n; i++)
        fprintf(f, "%s%d", i ? "," : "", M[i]);
    fprintf(f, "], \"rc\": [");
    for (int i = 0; i < n * rmax; i++)
        fprintf(f, "%s%d", i ? "," : "", rc[i]);
    fprintf(f, "], \"bits_non_nuls_par_tour\": [");
    for (int r = 0; r < rmax; r++)
        fprintf(f, "%s%d", r ? "," : "", nz[r]);
    fprintf(f, "]}");
}

static int borne_bc(int n)
{
    int d = 1, r = 0;
    while (1) {
        int a = 3 * d, b = n - (n - d + 2) / 3;
        d = a < b ? a : b;
        if (d >= n - 1)
            return r;
        r++;
    }
}

/* ---------------- 2. lois exactes contre Markov ---------------- */

static void tenseur(double *p, double *q, const double T[16][16], int somme)
{
    /* q = (T sur chaque nibble) p : somme (Markov) ou maximum (meilleur trail) */
    for (int k = 0; k < NIB; k++) {
        uint32_t pas = 1u << (4 * k);
#pragma omp parallel for schedule(static)
        for (uint32_t b = 0; b < TAILLE; b += 1) {
            if (b >> (4 * k) & 15)
                continue;
            double v[16], w[16];
            for (int a = 0; a < 16; a++)
                v[a] = p[b + (uint32_t)a * pas];
            for (int y = 0; y < 16; y++) {
                double s = 0;
                for (int a = 0; a < 16; a++)
                    if (somme)
                        s += v[a] * T[a][y];
                    else if (v[a] * T[a][y] > s)
                        s = v[a] * T[a][y];
                w[y] = s;
            }
            for (int y = 0; y < 16; y++)
                q[b + (uint32_t)y * pas] = w[y];
        }
        double *t = p; p = q; q = t;
    }
    /* NIB est pair : le résultat est revenu dans p */
}

static void apres_lin(const double *p, double *q, const uint32_t L[NIB][16])
{
#pragma omp parallel for schedule(static)
    for (uint32_t a = 0; a < TAILLE; a++) {
        uint32_t y = 0;
        for (int k = 0; k < NIB; k++)
            y ^= L[k][a >> (4 * k) & 15];
        q[y] = p[a];
    }
}

static void walsh(double *w)
{
    for (int b = 0; b < BITS; b++) {
        uint32_t h = 1u << b;
#pragma omp parallel for schedule(static)
        for (uint32_t i = 0; i < TAILLE; i++)
            if (!(i & h)) {
                double u = w[i], v = w[i | h];
                w[i] = u + v;
                w[i | h] = u - v;
            }
    }
}

/* Σ réel / Σ modèle sur les K points les plus probables SELON LE MODÈLE (choisis sans regarder le réel : prendre le
 * pic réel biaiserait le rapport vers le haut). Les points retenus sont rendus dans top / val (*nbp), pour l'étalonnage.
 * z : écart du réel au modèle SOUS L'HYPOTHÈSE d'un bruit de Poisson, de variance facteur·N·p par point. facteur = 2
 * pour les différences : H compte les paires ordonnées, chaque paire {x, x ⊕ α} deux fois. Cette hypothèse n'est
 * qu'un repère : la dispersion réelle est mesurée par etalonner(). */
#define TOPK 64
static double rapport_top(const double *m, const double *reel, double facteur, double *z, double *et_poisson,
                          uint32_t *top, double *val, int *nbp)
{
    int nb = 0;
    for (uint32_t d = 1; d < TAILLE; d++) {
        if (nb == TOPK && m[d] <= val[TOPK - 1])
            continue;
        int i = nb < TOPK ? nb++ : TOPK - 1;
        while (i > 0 && val[i - 1] < m[d]) {
            val[i] = val[i - 1];
            top[i] = top[i - 1];
            i--;
        }
        val[i] = m[d];
        top[i] = d;
    }
    double sm = 0, sr = 0;
    for (int i = 0; i < nb; i++) {
        sm += val[i];
        sr += reel[top[i]];
    }
    *nbp = nb;
    *z = sm > 0 ? (sr - sm) * TAILLE / sqrt(facteur * sm * TAILLE + 1) : 0;
    *et_poisson = sm > 0 ? sqrt(facteur * sm * TAILLE + 1) / (sm * TAILLE) : 0;
    return sm > 0 ? sr / sm : 0;
}

/* ---------------- 2 bis. étalonnage par les constantes de tour ---------------- */

#define RCAL 5          /* tours étalonnés : 2 à RCAL (au-delà, tout est au niveau du bruit à 24 bits) */
static uint64_t GC;     /* générateur propre : ne perturbe pas GR, donc ni les instances ni les α */
static inline uint32_t tirer_c(uint32_t n)
{
    GC += 0x9e3779b97f4a7c15ULL;
    uint64_t z = GC;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return (uint32_t)((z ^ (z >> 31)) % n);
}

static uint8_t *MARQUE;  /* MARQUE[d] = 1 + rang de d parmi les points retenus (différences), 0 sinon */

/* Pour NC jeux de constantes uniformes : rapport réel / Markov sur les MÊMES points (td, tl) que l'instance.
 * Sortie : moyenne et écart-type empiriques des deux rapports. Fk et wk : tampons de 2^24 cases. */
static void etalonner(int R, int nc, uint32_t alpha, uint32_t u, const uint32_t *td, const double *vd, int nd,
                      const uint32_t *tl, const double *vl, int nl, uint32_t *Fk, double *wk,
                      double *md, double *sd, double *ml, double *sl)
{
    double smd = 0, sml = 0, s1d = 0, s2d = 0, s1l = 0, s2l = 0;
    for (int i = 0; i < nd; i++)
        smd += vd[i];
    for (int i = 0; i < nl; i++)
        sml += vl[i];
    memset(MARQUE, 0, TAILLE);
    for (int i = 0; i < nd; i++)
        MARQUE[td[i]] = 1;
    for (int c = 0; c < nc; c++) {
        uint8_t rc[RMAX][NIB];
        for (int r = 0; r < R; r++)
            for (int k = 0; k < NIB; k++)
                rc[r][k] = (uint8_t)tirer_c(16);
#pragma omp parallel for schedule(static)
        for (uint32_t x = 0; x < TAILLE; x++) {
            uint32_t f = x;
            for (int r = 0; r < R; r++) {
                uint32_t y = 0;
                for (int k = 0; k < NIB; k++)
                    y ^= LINM[k][BR_SBOX[(f >> (4 * k) & 15) ^ rc[r][k]]];
                f = y;
            }
            Fk[x] = f;
        }
        uint64_t cnt = 0;
#pragma omp parallel for schedule(static) reduction(+ : cnt)
        for (uint32_t x = 0; x < TAILLE; x++)
            cnt += MARQUE[Fk[x] ^ Fk[x ^ alpha]];
        double rd = smd > 0 ? cnt / (double)TAILLE / smd : 0;
        /* Fk est une bijection : une seule écriture par case */
#pragma omp parallel for schedule(static)
        for (uint32_t x = 0; x < TAILLE; x++)
            wk[Fk[x]] = __builtin_parity(u & x) ? -1.0 : 1.0;
        walsh(wk);
        double sr = 0;
        for (int i = 0; i < nl; i++) {
            double cc = wk[tl[i]] / TAILLE;
            sr += cc * cc;
        }
        double rl = sml > 0 ? sr / sml : 0;
        s1d += rd; s2d += rd * rd;
        s1l += rl; s2l += rl * rl;
    }
    *md = s1d / nc;
    *ml = s1l / nc;
    *sd = nc > 1 ? sqrt(fmax(0, (s2d - s1d * s1d / nc) / (nc - 1))) : 0;
    *sl = nc > 1 ? sqrt(fmax(0, (s2l - s1l * s1l / nc) / (nc - 1))) : 0;
}

/* (réel − 1) / σ, la moyenne sur les constantes valant 1 exactement ; σ = 0 : 0 si égalité exacte, sinon 99 */
static double z_cles(double reel, double et)
{
    if (et > 1e-12)
        return (reel - 1) / et;
    return fabs(reel - 1) < 1e-9 ? 0 : 99;
}

/* Portée intégrale à 32 bits (D_4, 3 réflexions) : sommes sur tous les cubes de codimension 1, sans table :
 * par thread, un compteur XOR par valeur de chaque octet de x, pour chaque tour. */
#define RM32 8
static uint32_t L32[8][16];
static uint8_t M32[8][8];
static uint8_t RC32[RM32][8];

static void construire32(void)
{
    static const int GENS[3] = {0, 1, 3};
    uint8_t M[8][8];
    for (;;) {
        memset(M, 0, sizeof M);
        for (int i = 0; i < 8; i++) {
            M[i][i] = (uint8_t)(1 + tirer(15));
            for (int g = 0; g < 3; g++) {
                int j = i < 4 ? 4 + (GENS[g] - i + 4) % 4 : (GENS[g] - (i - 4) + 4) % 4;
                M[i][j] = (uint8_t)(1 + tirer(15));
            }
        }
        uint8_t A[8][8];
        memcpy(A, M, sizeof A);
        int rang = 0;
        for (int c = 0; c < 8; c++) {
            int p = rang;
            while (p < 8 && !A[p][c])
                p++;
            if (p == 8)
                continue;
            for (int j = 0; j < 8; j++) { uint8_t t = A[p][j]; A[p][j] = A[rang][j]; A[rang][j] = t; }
            uint8_t iv = gf_inv(A[rang][c]);
            for (int i = rang + 1; i < 8; i++)
                if (A[i][c]) {
                    uint8_t f = gf_mul(A[i][c], iv);
                    for (int j = 0; j < 8; j++)
                        A[i][j] ^= gf_mul(f, A[rang][j]);
                }
            rang++;
        }
        if (rang == 8)
            break;
    }
    memcpy(M32, M, sizeof M);
    for (int k = 0; k < 8; k++)
        for (int v = 0; v < 16; v++) {
            uint32_t y = 0;
            for (int i = 0; i < 8; i++)
                y |= (uint32_t)gf_mul(M[i][k], (uint8_t)v) << (4 * i);
            L32[k][v] = y;
        }
    for (int r = 0; r < RM32; r++)
        for (int k = 0; k < 8; k++)
            RC32[r][k] = (uint8_t)tirer(16);
}

static void integrale32(int *nz)
{
    uint32_t X[RM32][4][256];
    memset(X, 0, sizeof X);
#pragma omp parallel
    {
        uint32_t L[RM32][4][256];
        memset(L, 0, sizeof L);
#pragma omp for schedule(static)
        for (int64_t a = 0; a < (1LL << 32); a++) {
            uint32_t x = (uint32_t)a, f = x;
            for (int r = 0; r < RM32; r++) {
                uint32_t y = 0;
                for (int k = 0; k < 8; k++)
                    y ^= L32[k][BR_SBOX[(f >> (4 * k) & 15) ^ RC32[r][k]]];
                f = y;
                L[r][0][x & 255] ^= f;
                L[r][1][x >> 8 & 255] ^= f;
                L[r][2][x >> 16 & 255] ^= f;
                L[r][3][x >> 24] ^= f;
            }
        }
#pragma omp critical
        for (int r = 0; r < RM32; r++)
            for (int o = 0; o < 4; o++)
                for (int v = 0; v < 256; v++)
                    X[r][o][v] ^= L[r][o][v];
    }
    for (int r = 0; r < RM32; r++) {
        nz[r] = 0;
        for (int i = 0; i < 32; i++) {
            uint32_t s = 0;
            for (int v = 0; v < 256; v++)
                if (!(v >> (i % 8) & 1))
                    s ^= X[r][i / 8][v];
            nz[r] += __builtin_popcount(s);
        }
    }
}

int main(int argc, char **argv)
{
    int inst = argc > 1 ? atoi(argv[1]) : 1, nal = argc > 2 ? atoi(argv[2]) : 1, i32 = argc > 3 ? atoi(argv[3]) : 1;
    int nc = argc > 4 ? atoi(argv[4]) : 32;
    /* agrégats de l'étalonnage, par nombre de tours */
    int cal_ok = 1, cal_n[RCAL + 1] = {0};
    double cal_zd[RCAL + 1] = {0}, cal_zl[RCAL + 1] = {0}, cal_zpd[RCAL + 1] = {0}, cal_zpl[RCAL + 1] = {0};
    double cal_qd_min[RCAL + 1], cal_qd_max[RCAL + 1] = {0}, cal_ql_min[RCAL + 1], cal_ql_max[RCAL + 1] = {0};
    double cal_ed_max[RCAL + 1] = {0}, cal_el_max[RCAL + 1] = {0};
    for (int r = 0; r <= RCAL; r++)
        cal_qd_min[r] = cal_ql_min[r] = 1e300;
    resultat_t res = {.nom = "mini_brume", .titre = NULL};
    if (!bref_init())
        return 1;
    memset(DDT, 0, sizeof DDT);
    for (int a = 0; a < 16; a++)
        for (int x = 0; x < 16; x++)
            DDT[a][BR_SBOX[x] ^ BR_SBOX[x ^ a]]++;
    for (int u = 0; u < 16; u++)
        for (int v = 0; v < 16; v++) {
            int s = 0;
            for (int x = 0; x < 16; x++)
                s += (__builtin_parity((unsigned)(u & x)) ^ __builtin_parity((unsigned)(v & BR_SBOX[x]))) ? -1 : 1;
            LAT[u][v] = s;
        }
    double TD[16][16], TL[16][16];
    for (int a = 0; a < 16; a++)
        for (int b = 0; b < 16; b++) {
            TD[a][b] = DDT[a][b] / 16.0;
            TL[a][b] = (LAT[a][b] / 16.0) * (LAT[a][b] / 16.0);
        }
    uint32_t *F = malloc(4ull * TAILLE), *G = malloc(4ull * TAILLE), *H = malloc(4ull * TAILLE);
    MARQUE = malloc(TAILLE);
    double *pm = malloc(8ull * TAILLE), *pt = malloc(8ull * TAILLE), *q = malloc(8ull * TAILLE), *wa = malloc(8ull * TAILLE);
    int bc = borne_bc(BITS), dual_ok = 1, bc_ok = 1;
    char *rapport = malloc(2000000), *o = rapport;
    FILE *finst = fopen("resultats/mini_brume_instances.tmp", "w");    /* renommé à la fin : jamais de fichier tronqué */
    const char *sep = "[";
    o += sprintf(o, "[");
    int rmax_int = 0, rmax_diff = 0, rmax_lin = 0, rmax_boom = 0, zero_r[64] = {0};
    uint32_t tem_h = 0;
    double tem_lp = 0, tem_boom = 0;
    for (int I = 0; I <= inst; I++) {               /* I = inst : témoin, permutation aléatoire */
        int temoin = I == inst, portee_int = 0, nz_r[RMAX] = {0};
        GR = 0x1234 + (uint64_t)I * 1000;
        int b = temoin ? 0 : construire();
        if (!temoin && !b)
            return 2;
        /* M adjointe pour les masques : u_y = (M⁻¹)ᵀ u_x */
        uint32_t LT[NIB][16];
        for (int k = 0; k < NIB; k++)
            for (int v = 0; v < 16; v++) {
                uint32_t y = 0;
                for (int i = 0; i < NIB; i++) {
                    int up = 0;
                    for (int t = 0; t < 4; t++)
                        if (__builtin_parity((unsigned)(v & gf_mul(MI[k][i], (uint8_t)(1 << t)))))
                            up |= 1 << t;
                    y |= (uint32_t)up << (4 * i);
                }
                LT[k][v] = y;
            }
        for (uint32_t x = 0; x < TAILLE; x++)
            F[x] = x;
        if (temoin)
            for (uint32_t x = TAILLE - 1; x > 0; x--) {
                uint32_t j = tirer(x + 1), t = F[x];
                F[x] = F[j];
                F[j] = t;
            }
        o += sprintf(o, "%s{\"instance\": %d, \"temoin\": %s, \"tours\": [", I ? ", " : "", I, temoin ? "true" : "false");
        for (int R = 1; R <= (temoin ? 1 : RMAX); R++) {
            if (!temoin) {
#pragma omp parallel for schedule(static)
                for (uint32_t x = 0; x < TAILLE; x++)
                    F[x] = tour(F[x], R - 1);
            }
#pragma omp parallel for schedule(static)
            for (uint32_t x = 0; x < TAILLE; x++)
                G[F[x]] = x;
            uint32_t A[BITS], B[BITS][BITS], Ai[BITS], Bi[BITS][BITS];
            sommes(F, A, B);
            sommes(G, Ai, Bi);
            int nz1 = 0, nz2 = 0;
            for (int i = 0; i < BITS; i++) {
                nz1 += __builtin_popcount(A[i]);
                for (int j = 0; j < BITS; j++)
                    if ((A[i] >> j & 1) != (Ai[j] >> i & 1))
                        dual_ok = 0;
                for (int j = i + 1; j < BITS; j++)
                    nz2 += __builtin_popcount(B[i][j]);
            }
            if (!temoin && R <= bc && nz1)
                bc_ok = 0;
            if (!temoin && nz1 == 0 && R > portee_int)
                portee_int = R;
            /* différences et masques exacts, à partir d'un α d'un nibble */
            double fac_t = 0, fac_m = 0, top_d = 0, zd = 0, top_l = 0, zl = 0, zz, epz;
            uint32_t mx = 0, topd[TOPK], topl[TOPK];
            double lpmax = 0, mx_boom = 0, vald[TOPK], vall[TOPK];
            int nd = 0, nl = 0;
            char cal[4000], *pc = cal;
            pc += sprintf(pc, "[");
            for (int al = 0; al < nal && R <= 8; al++) {
                uint64_t gs = GR;
                int pos = (int)tirer(NIB), val = (int)(1 + tirer(15));
                uint32_t alpha = (uint32_t)val << (4 * pos);
                memset(H, 0, 4ull * TAILLE);
                for (uint32_t x = 0; x < TAILLE; x++)
                    H[F[x] ^ F[x ^ alpha]]++;
                uint32_t bm = 0;
                for (uint32_t d = 1; d < TAILLE; d++)
                    if (H[d] > H[bm] || !bm)
                        bm = d;
                if (H[bm] > mx)
                    mx = H[bm];
                if (!temoin) {
                    memset(pm, 0, 8ull * TAILLE);
                    memset(pt, 0, 8ull * TAILLE);
                    pm[alpha] = pt[alpha] = 1;
                    for (int r = 0; r < R; r++) {
                        tenseur(pm, q, TD, 1);
                        apres_lin(pm, q, LINM);
                        { double *t = pm; pm = q; q = t; }
                        tenseur(pt, q, TD, 0);
                        apres_lin(pt, q, LINM);
                        { double *t = pt; pt = q; q = t; }
                    }
                    double e = H[bm] / (double)TAILLE;
                    if (pt[bm] > 0 && e / pt[bm] > fac_t)
                        fac_t = e / pt[bm];
                    if (pm[bm] > 0 && e / pm[bm] > fac_m)
                        fac_m = e / pm[bm];
                    for (uint32_t d = 0; d < TAILLE; d++)
                        q[d] = H[d] / (double)TAILLE;
                    double tr = rapport_top(pm, q, 2.0, &zz, &epz, topd, vald, &nd), trd = tr, zpd = zz, epd = epz;
                    if (fabs(zz) >= fabs(zd)) { top_d = tr; zd = zz; }
                    /* masque u d'un nibble : corrélations exactes vers tous les v */
                    uint32_t u = (uint32_t)val << (4 * pos);
                    memset(wa, 0, 8ull * TAILLE);
                    for (uint32_t x = 0; x < TAILLE; x++)
                        wa[F[x]] += __builtin_parity(u & x) ? -1.0 : 1.0;
                    walsh(wa);
                    double be = -1;
                    for (uint32_t v = 0; v < TAILLE; v++) {
                        double c = wa[v] / TAILLE;
                        wa[v] = c * c;
                        if (v && c * c > be)
                            be = c * c;
                    }
                    if (be > lpmax)
                        lpmax = be;
                    memset(pm, 0, 8ull * TAILLE);
                    memset(pt, 0, 8ull * TAILLE);
                    pm[u] = pt[u] = 1;
                    for (int r = 0; r < R; r++) {
                        tenseur(pm, q, TL, 1);
                        apres_lin(pm, q, LT);
                        { double *t = pm; pm = q; q = t; }
                        tenseur(pt, q, TL, 0);
                        apres_lin(pt, q, LT);
                        { double *t = pt; pt = q; q = t; }
                    }
                    /* hypothèse de l'ancienne version, gardée comme repère : bruit de c² ≈ 1/N par point */
                    tr = rapport_top(pm, wa, 1.0, &zz, &epz, topl, vall, &nl);
                    if (fabs(zz) >= fabs(zl)) { top_l = tr; zl = zz; }
                    if (R >= 2 && R <= RCAL && nc > 1) {
                        double md, sd, ml, sl;
                        GC = 0xC1E5ULL + (uint64_t)I * 100003 + (uint64_t)R * 1009 + (uint64_t)al * 17;
                        etalonner(R, nc, alpha, u, topd, vald, nd, topl, vall, nl, H, wa, &md, &sd, &ml, &sl);
                        double zcd = z_cles(trd, sd), zcl = z_cles(tr, sl);
                        /* la moyenne vaut 1 par théorème : tolérance 4 σ/√NC (et 1e-9 si σ = 0) */
                        int okm = fabs(md - 1) <= 4 * sd / sqrt(nc) + 1e-9 && fabs(ml - 1) <= 4 * sl / sqrt(nc) + 1e-9;
                        cal_ok &= okm;
                        cal_n[R]++;
                        if (fabs(zcd) > cal_zd[R]) cal_zd[R] = fabs(zcd);
                        if (fabs(zcl) > cal_zl[R]) cal_zl[R] = fabs(zcl);
                        if (fabs(zpd) > cal_zpd[R]) cal_zpd[R] = fabs(zpd);
                        if (fabs(zz) > cal_zpl[R]) cal_zpl[R] = fabs(zz);
                        if (sd > cal_ed_max[R]) cal_ed_max[R] = sd;
                        if (sl > cal_el_max[R]) cal_el_max[R] = sl;
                        if (epd > 0) {
                            double qd = sd / epd;
                            if (qd < cal_qd_min[R]) cal_qd_min[R] = qd;
                            if (qd > cal_qd_max[R]) cal_qd_max[R] = qd;
                        }
                        if (epz > 0) {
                            double ql = sl / epz;
                            if (ql < cal_ql_min[R]) cal_ql_min[R] = ql;
                            if (ql > cal_ql_max[R]) cal_ql_max[R] = ql;
                        }
                        pc += sprintf(pc, "%s{\"alpha\": %u, \"reel\": %.4f, \"moyenne_cles\": %.4f, \"ecart_type_cles\": %.4f, \"ecart_type_poisson\": %.4f, \"z_cles\": %.2f, \"z_poisson\": %.2f, \"lin_reel\": %.4f, \"lin_moyenne_cles\": %.4f, \"lin_ecart_type_cles\": %.4f, \"lin_ecart_type_poisson\": %.4f, \"lin_z_cles\": %.2f, \"lin_z_poisson\": %.2f, \"moyenne_egale_1\": %s}",
                                      pc > cal + 1 ? ", " : "", alpha, trd, md, sd, epd, zcd, zpd, tr, ml, sl, epz, zcl, zz, okm ? "true" : "false");
                        fprintf(stderr, "  I=%d R=%d α=%06x : diff %.3f (clés %.3f ± %.3f, Poisson ± %.3f)  lin %.3f (clés %.3f ± %.3f, Poisson ± %.3f)\n",
                                I, R, alpha, trd, md, sd, epd, tr, ml, sl, epz);
                    }
                    /* boomerang exact, δ d'un nibble */
                    for (int c = 0; c < 8; c++) {
                        uint32_t de = LINM[tirer(NIB)][1 + tirer(15)];   /* M·(un nibble) : M⁻¹ ne le disperse pas */
                        uint32_t nb = 0;
#pragma omp parallel for schedule(static) reduction(+ : nb)
                        for (uint32_t x = 0; x < TAILLE; x++)
                            nb += (G[F[x] ^ de] ^ G[F[x ^ alpha] ^ de]) == alpha;
                        double pb = nb / (double)TAILLE;
                        if (pb > mx_boom)
                            mx_boom = pb;
                    }
                } else {
                    /* témoin : les mêmes maxima (LP, boomerang) sur la permutation aléatoire, pour vérifier les seuils
                     * de portée ci-dessous au lieu de les supposer */
                    uint32_t u = (uint32_t)val << (4 * pos);
#pragma omp parallel for schedule(static)
                    for (uint32_t x = 0; x < TAILLE; x++)
                        wa[F[x]] = __builtin_parity(u & x) ? -1.0 : 1.0;
                    walsh(wa);
                    for (uint32_t v = 1; v < TAILLE; v++) {
                        double c = wa[v] / TAILLE;
                        if (c * c > lpmax)
                            lpmax = c * c;
                    }
                    for (int c = 0; c < 8; c++) {
                        uint32_t de = 1 + tirer(TAILLE - 1);   /* permutation aléatoire : tout δ ≠ 0 se vaut */
                        uint32_t nb = 0;
#pragma omp parallel for schedule(static) reduction(+ : nb)
                        for (uint32_t x = 0; x < TAILLE; x++)
                            nb += (G[F[x] ^ de] ^ G[F[x ^ alpha] ^ de]) == alpha;
                        if (nb / (double)TAILLE > mx_boom)
                            mx_boom = nb / (double)TAILLE;
                    }
                }
                GR = gs + 7919;
            }
            /* seuils de portée : H max > 24, LP max > 40/N, boomerang > 24/N. Sous H0 (permutation aléatoire) : H max ≈ 16,
             * LP max ≈ 2 ln(2^24)/N ≈ 33/N, boomerang ≈ 2^-24 ; vérifiés sur le témoin (contrôle en fin de run) */
            if (temoin) {
                tem_h = mx;
                tem_lp = lpmax;
                tem_boom = mx_boom;
            }
            if (!temoin && mx > 24 && R > rmax_diff && R == rmax_diff + 1)
                rmax_diff = R;
            if (!temoin && lpmax > 40.0 / TAILLE && R == rmax_lin + 1)
                rmax_lin = R;
            if (!temoin && mx_boom > 24.0 / TAILLE && R == rmax_boom + 1)
                rmax_boom = R;
            o += sprintf(o, "%s{\"R\": %d, \"bits_non_nuls_codim1\": %d, \"bits_non_nuls_codim2\": %d, \"H_max\": %u, \"pic_sur_trail\": %.3f, \"pic_sur_markov\": %.3f, \"top64_reel_sur_markov\": %.3f, \"z_poisson\": %.1f, \"LP_max_log2\": %.2f, \"top64_c2_sur_elp\": %.3f, \"z_lin_poisson\": %.1f, \"boomerang_max_log2\": %.2f, \"etalonnage\": %s]}",
                         R > 1 ? ", " : "", R, nz1, nz2, mx, fac_t, fac_m, top_d, zd, lpmax > 0 ? log2(lpmax) : 0.0, top_l, zl, mx_boom > 0 ? log2(mx_boom) : 0.0, cal);
            if (!temoin && nz1 == 0)
                zero_r[I < 64 ? I : 63] = R;
            if (!temoin)
                nz_r[R - 1] = nz1;
        }
        o += sprintf(o, "]}");
        if (portee_int > rmax_int)
            rmax_int = portee_int;
        if (!temoin && finst) {
            ecrire_instance(finst, sep, NIB, &MM[0][0], &RCM[0][0], RMAX, nz_r);
            sep = ", ";
        }
    }
    sprintf(o, "]");
    int depasse_bc = 0, partout_bc = 1;
    for (int I = 0; I < inst && I < 64; I++) {
        depasse_bc |= zero_r[I] > bc;
        partout_bc &= zero_r[I] >= bc;
    }
    FILE *fj = fopen("resultats/mini_brume_detail.json", "w");
    if (fj) { fputs(rapport, fj); fclose(fj); }
    res_mesure(&res, "temoin_permutation_aleatoire", "{\"H_max\": %u, \"seuil_H\": 24, \"LP_max_fois_N\": %.1f, \"seuil_LP_fois_N\": 40, \"boomerang_max_fois_N\": %.1f, \"seuil_boomerang_fois_N\": 24}",
               tem_h, tem_lp * TAILLE, tem_boom * TAILLE);
    res_controle(&res, "seuils_de_portee_non_atteints_par_le_temoin", tem_h <= 24 && tem_lp <= 40.0 / TAILLE && tem_boom <= 24.0 / TAILLE);
    res_mesure(&res, "portees", "{\"instances\": %d, \"borne_boura_canteaut\": %d, \"integrale_reelle_tous_les_bits\": %d, \"une_instance_au_dela_de_la_borne\": %s, \"differentielle\": %d, \"lineaire\": %d, \"boomerang\": %d}",
               inst, bc, rmax_int, depasse_bc ? "true" : "false", rmax_diff, rmax_lin, rmax_boom);
    if (i32) {
        char t32[3000], *p = t32;
        int bc32 = borne_bc(32), ok32 = 1, m32 = 0;
        p += sprintf(p, "[");
        for (int I = 0; I < i32; I++) {
            GR = 0x3232 + (uint64_t)I * 77;
            construire32();
            int nz[RM32];
            integrale32(nz);
            int po = 0;
            for (int r = 0; r < RM32 && nz[r] == 0; r++)
                po = r + 1;
            ok32 &= po >= bc32;
            if (po > m32)
                m32 = po;
            p += sprintf(p, "%s{\"portee\": %d, \"bits_non_nuls\": [%d, %d, %d, %d, %d, %d, %d, %d]}", I ? ", " : "", po,
                         nz[0], nz[1], nz[2], nz[3], nz[4], nz[5], nz[6], nz[7]);
            if (finst) {
                ecrire_instance(finst, sep, 8, &M32[0][0], &RC32[0][0], RM32, nz);
                sep = ", ";
            }
        }
        sprintf(p, "]");
        res_mesure(&res, "integrale_32_bits", "{\"borne_boura_canteaut\": %d, \"portee_max\": %d, \"instances\": %s}", bc32, m32, t32);
        res_controle(&res, "borne_respectee_a_32_bits", ok32);
    }
    if (nc > 1) {
        char tc[4000], *p = tc;
        p += sprintf(p, "{\"jeux_de_constantes\": %d, \"tours\": [", nc);
        for (int R = 2; R <= RCAL; R++)
            if (cal_n[R])
                p += sprintf(p, "%s{\"R\": %d, \"cas\": %d, \"ecart_type_cles_max\": %.4f, \"lin_ecart_type_cles_max\": %.4f, \"cles_sur_poisson\": [%.2f, %.2f], \"lin_cles_sur_poisson\": [%.2f, %.2f], \"z_cles_max\": %.2f, \"lin_z_cles_max\": %.2f, \"z_poisson_max\": %.2f, \"lin_z_poisson_max\": %.2f}",
                             R > 2 ? ", " : "", R, cal_n[R], cal_ed_max[R], cal_el_max[R], cal_qd_min[R] < 1e300 ? cal_qd_min[R] : 0, cal_qd_max[R],
                             cal_ql_min[R] < 1e300 ? cal_ql_min[R] : 0, cal_ql_max[R], cal_zd[R], cal_zl[R], cal_zpd[R], cal_zpl[R]);
        sprintf(p, "]}");
        res_mesure(&res, "markov_etalonne_par_les_constantes", "%s", tc);
        res_controle(&res, "markov_egal_a_la_moyenne_sur_les_constantes", cal_ok);
    }
    res_controle(&res, "dualite_F_F_inverse_exacte_sur_les_cubes", dual_ok);
    res_controle(&res, "borne_de_boura_canteaut_respectee", bc_ok);
    res_controle(&res, "portee_integrale_reelle_au_moins_la_borne", partout_bc);
    if (finst) {
        fprintf(finst, "]\n");
        fclose(finst);
        rename("resultats/mini_brume_instances.tmp", "resultats/mini_brume_instances.json");
    }
    free(F); free(G); free(H); free(pm); free(pt); free(q); free(wa); free(rapport); free(MARQUE);
    return res_ecrire(&res);
}
