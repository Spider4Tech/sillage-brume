/* Contre-vérification indépendante de WIDTH_ANALYSIS.md § 2 (diffusion, spectre, degré), par d'autres méthodes que le
 * programme de l'analyse (qui utilisait le BFS depuis le seul sommet 0 et la formule des représentations de D_m) :
 *   1. le graphe de D₁₂₈ construit depuis les générateurs publiés est COMPARÉ au support réel de M (tables générées) ;
 *   2. boules = support booléen de (A + I)^r, calculé depuis CHAQUE sommet (min et max : égaux si sommet-transitif) ;
 *   3. λ* = deuxième plus grande valeur propre en valeur absolue (hors ±6), par Jacobi sur la matrice d'adjacence dense ;
 *   4. fraction d'ensembles de générateurs à diffusion complète en 5 tours, avec un autre générateur aléatoire ;
 *   5. borne de Boura–Canteaut (2011, 2013) : deg(P_{r+1}) ≤ min(deg(S)·deg(P_r), n − ⌈(n − deg(P_r))/γ⌉), avec γ
 *      calculé exactement depuis la S-box (γ = max_{1≤i≤3} (4 − i)/(4 − δ_i), δ_i = degré maximal d'un produit de i
 *      coordonnées de la S-box inverse de la couche), pour chaque sens.
 * Graphe : D_m' = Z/m ⋊ Z/2 (2m sommets), loi de sillage/brume512.py : (a, f)·(b, g) = (a + (−1)^f b, f ⊕ g) ;
 * générateurs = réflexions s_k = (k, 1), k ∈ K ; voisinage de x : {x·s_k}. M a le support A + I (7 termes par ligne).
 *   cc -O2 -march=native -fopenmp -I sillage/c -I tests/c prototypes/brume_q/largeur/verif_largeur.c sillage/c/commun.c \
 *      sillage/c/brume512.c sillage/c/brume512_avx2.c -lm -o tests/c/build/verif_largeur
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brume_ref.h"

#define VMAX 256

static int op(int m, int a, int b)
{
    int aa = a % m, af = a / m, ba = b % m, bf = b / m;    /* sommet v = a + m·f */
    int r = ((aa + (af ? -ba : ba)) % m + m) % m;
    return r + m * (af ^ bf);
}

static void adjacence(int m, const int *K, uint8_t A[VMAX][VMAX])
{
    int n = 2 * m;
    memset(A, 0, VMAX * VMAX);
    for (int x = 0; x < n; x++)
        for (int g = 0; g < 6; g++) {
            int y = op(m, x, K[g] + m);
            A[x][y] = A[y][x] = 1;
        }
}

/* tailles des boules depuis chaque sommet : bmin[r], bmax[r], r = 1..rmax */
static void boules(int n, uint8_t A[VMAX][VMAX], int rmax, int *bmin, int *bmax)
{
    for (int r = 1; r <= rmax; r++) {
        bmin[r] = 1 << 30;
        bmax[r] = 0;
    }
    for (int s = 0; s < n; s++) {
        uint8_t in[VMAX] = {0}, nv[VMAX];
        in[s] = 1;
        for (int r = 1; r <= rmax; r++) {
            memcpy(nv, in, n);
            for (int v = 0; v < n; v++)
                if (in[v])
                    for (int w = 0; w < n; w++)
                        if (A[v][w])
                            nv[w] = 1;
            memcpy(in, nv, n);
            int c = 0;
            for (int v = 0; v < n; v++)
                c += in[v];
            if (c < bmin[r])
                bmin[r] = c;
            if (c > bmax[r])
                bmax[r] = c;
        }
    }
}

/* valeurs propres d'une matrice symétrique (Jacobi cyclique) */
static void jacobi(int n, double a[VMAX][VMAX], double *ev)
{
    for (int balayage = 0; balayage < 100; balayage++) {
        double hors = 0;
        for (int p = 0; p < n; p++)
            for (int q = p + 1; q < n; q++)
                hors += a[p][q] * a[p][q];
        if (hors < 1e-22)
            break;
        for (int p = 0; p < n; p++)
            for (int q = p + 1; q < n; q++) {
                if (fabs(a[p][q]) < 1e-300)
                    continue;
                double th = (a[q][q] - a[p][p]) / (2 * a[p][q]);
                double t = (th >= 0 ? 1 : -1) / (fabs(th) + sqrt(th * th + 1));
                double c = 1 / sqrt(t * t + 1), s = t * c;
                for (int k = 0; k < n; k++) {
                    double akp = a[k][p], akq = a[k][q];
                    a[k][p] = c * akp - s * akq;
                    a[k][q] = s * akp + c * akq;
                }
                for (int k = 0; k < n; k++) {
                    double apk = a[p][k], aqk = a[q][k];
                    a[p][k] = c * apk - s * aqk;
                    a[q][k] = s * apk + c * aqk;
                }
            }
    }
    for (int i = 0; i < n; i++)
        ev[i] = a[i][i];
}

static double lambda_etoile(int n, uint8_t A[VMAX][VMAX], int *n_triv)
{
    static double a[VMAX][VMAX];
    double ev[VMAX];
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            a[i][j] = A[i][j];
    jacobi(n, a, ev);
    double l = 0;
    *n_triv = 0;
    for (int i = 0; i < n; i++) {
        if (fabs(fabs(ev[i]) - 6) < 1e-7) {
            (*n_triv)++;
            continue;
        }
        if (fabs(ev[i]) > l)
            l = fabs(ev[i]);
    }
    return l;
}

/* ---------- degrés ---------- */
static int deg_anf(const uint8_t *f /* 16 valeurs 0/1 */)
{
    uint8_t a[16];
    memcpy(a, f, 16);
    for (int i = 0; i < 4; i++)
        for (int x = 0; x < 16; x++)
            if (x & (1 << i))
                a[x] ^= a[x ^ (1 << i)];
    int d = 0;
    for (int x = 0; x < 16; x++)
        if (a[x] && __builtin_popcount(x) > d)
            d = __builtin_popcount(x);
    return d;
}

/* δ_i : degré maximal d'un produit de i coordonnées de T ; deg(T) = max sur les combinaisons linéaires */
static void degres_sbox(const uint8_t *T, int *deg, int delta[4])
{
    uint8_t f[16];
    *deg = 0;
    for (int b = 1; b < 16; b++) {
        for (int x = 0; x < 16; x++)
            f[x] = __builtin_popcount(b & T[x]) & 1;
        int d = deg_anf(f);
        if (d > *deg)
            *deg = d;
    }
    for (int i = 1; i <= 3; i++) {
        delta[i] = 0;
        for (int msk = 1; msk < 16; msk++) {
            if (__builtin_popcount(msk) != i)
                continue;
            for (int x = 0; x < 16; x++)
                f[x] = (T[x] & msk) == msk;
            int d = deg_anf(f);
            if (d > delta[i])
                delta[i] = d;
        }
    }
}

/* nombre de tours r tels que deg(P_r) ≤ n − 2 (somme nulle sur tout sous-espace de dimension n − 1) */
static int portee(int n, int degS, double gamma)
{
    int d = 1, r = 0;
    for (;;) {
        int a = degS * d, b = n - (int)ceil((n - d) / gamma - 1e-12);
        d = a < b ? a : b;
        if (d > n - 1)
            d = n - 1;
        if (d > n - 2)
            return r;
        r++;
    }
}

static uint64_t g = 0x2545F4914F6CDD1DULL;
static uint64_t alea(void)
{
    g += 0x9E3779B97F4A7C15ULL;
    uint64_t z = g;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

int main(int argc, char **argv)
{
    long tirages = argc > 1 ? atol(argv[1]) : 200000;
    if (!bref_init())
        return 2;
    int ok = 1;
    static uint8_t A[VMAX][VMAX];
    /* 1. D₁₂₈ : générateurs publiés contre le support réel de M */
    int K0[6] = {21, 0, 7, 45, 8, 62};
    adjacence(64, K0, A);
    int egal = 1;
    for (int v = 0; v < BR_N; v++)
        for (int k = 0; k < BR_N; k++) {
            /* sommet v de l'état = élément v de brume512.py : v = (v & 63) | flip << 6, comme ici (v = a + 64·f) */
            egal &= (BM[v][k] != 0) == (A[v][k] || v == k);
        }
    printf("D128 : graphe des generateurs {21,0,7,45,8,62} = support reel de M (hors diagonale) %s\n", egal ? "OK" : "ECHEC");
    ok &= egal;
    struct {
        int m;
        int K[6];
        int b[6];       /* boules annoncées r = 1..5 */
        double l;       /* λ* annoncé */
    } cas[3] = {
        {64, {21, 0, 7, 45, 8, 62}, {7, 37, 94, 127, 128}, 3.5076},
        {96, {0, 76, 13, 10, 15, 34}, {7, 37, 116, 181, 192}, 3.683},
        {128, {0, 83, 56, 51, 17, 42}, {7, 37, 125, 222, 256}, 3.927},
    };
    for (int c = 0; c < 3; c++) {
        int m = cas[c].m, n = 2 * m;
        adjacence(m, cas[c].K, A);
        int reg = 1;
        for (int v = 0; v < n; v++) {
            int d = 0;
            for (int w = 0; w < n; w++)
                d += A[v][w];
            reg &= d == 6;
        }
        int bmin[8], bmax[8];
        boules(n, A, 5, bmin, bmax);
        int nt;
        double l = lambda_etoile(n, A, &nt);
        int bok = 1;
        printf("D%d (%d bits), K = {%d,%d,%d,%d,%d,%d} : 6-regulier %s ; boules (min..max sur les %d sommets)", n, 4 * n,
               cas[c].K[0], cas[c].K[1], cas[c].K[2], cas[c].K[3], cas[c].K[4], cas[c].K[5], reg ? "OK" : "NON", n);
        for (int r = 1; r <= 5; r++) {
            printf(" %d..%d", bmin[r], bmax[r]);
            bok &= bmin[r] == cas[c].b[r - 1] && bmax[r] == cas[c].b[r - 1];
        }
        printf(" ; annonce %s ; lambda* Jacobi = %.4f (annonce %.4f, %s), valeurs propres +-6 : %d\n", bok ? "OK" : "ECART", l,
               cas[c].l, fabs(l - cas[c].l) < 6e-4 ? "OK" : "ECART", nt);
        ok &= reg && bok && fabs(l - cas[c].l) < 6e-4;
    }
    /* 4. fraction à diffusion complète en 5 tours (0 ∈ K sans perte : H(Z_m, K) ≅ H(Z_m, K + t)) */
    for (int c = 1; c < 3; c++) {
        int m = cas[c].m, n = 2 * m;
        long plein = 0;
#pragma omp parallel for reduction(+ : plein) schedule(static)
        for (long t = 0; t < tirages; t++) {
            uint64_t s = 0x9E3779B97F4A7C15ULL * (uint64_t)(t + 1) ^ (uint64_t)m << 40;
            int K[6] = {0};
            for (int q = 1; q < 6; q++) {
            encore:
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                K[q] = (int)(s % (uint64_t)m);
                for (int h = 0; h < q; h++)
                    if (K[h] == K[q])
                        goto encore;
            }
            uint8_t in[VMAX] = {0}, nv[VMAX];
            in[0] = 1;
            int cnt = 0;
            for (int r = 1; r <= 5; r++) {
                memcpy(nv, in, n);
                for (int v = 0; v < n; v++)
                    if (in[v])
                        for (int q = 0; q < 6; q++)
                            nv[op(m, v, K[q] + m)] = 1;
                memcpy(in, nv, n);
            }
            for (int v = 0; v < n; v++)
                cnt += in[v];
            plein += cnt == n;
        }
        printf("D%d : %ld / %ld ensembles aleatoires a diffusion complete en 5 tours = %.1f %%\n", n, plein, tirages,
               100.0 * plein / tirages);
    }
    /* 5. degré */
    uint8_t S[16], Si[16];
    memcpy(S, BR_SBOX, 16);
    for (int x = 0; x < 16; x++)
        Si[S[x]] = (uint8_t)x;
    int dS, dSi, delS[4], delSi[4];
    degres_sbox(S, &dS, delS);
    degres_sbox(Si, &dSi, delSi);
    double gav = 0, gar = 0;   /* sens direct : γ depuis S⁻¹ ; sens inverse (tours de P⁻¹, S-box S⁻¹) : γ depuis S */
    for (int i = 1; i <= 3; i++) {
        double a = (4.0 - i) / (4.0 - delSi[i]), b = (4.0 - i) / (4.0 - delS[i]);
        if (a > gav)
            gav = a;
        if (b > gar)
            gar = b;
    }
    printf("S-box : deg S = %d, deg S^-1 = %d ; delta_i(S^-1) = %d,%d,%d -> gamma direct = %.3f ; delta_i(S) = %d,%d,%d -> gamma inverse = %.3f\n",
           dS, dSi, delSi[1], delSi[2], delSi[3], gav, delS[1], delS[2], delS[3], gar);
    int n3[3] = {512, 768, 1024};
    for (int c = 0; c < 3; c++) {
        int av = portee(n3[c], dS, gav), ar = portee(n3[c], dSi, gar);
        int av3 = portee(n3[c], 3, 3.0);
        printf("n = %4d : deg(P_r) <= n - 2 jusqu'a r = %d (direct), %d (inverse) -> %d tours inside-out ; avec la borne generique gamma = 3 : %d\n",
               n3[c], av, ar, av + ar, av3);
    }
    printf("verif_largeur %s\n", ok ? "OK" : "ECHEC");
    return ok ? 0 : 1;
}
