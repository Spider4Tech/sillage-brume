/* BRUME-1024 (prototype, hors suite) : sélection déterministe des paramètres figés et contrôles, en reprenant la règle de
 * BRUME-512 (sillage/select_params.py) transposée à 256 nibbles, plus les critères fixés d'avance dans
 * prototypes/brume_q/WIDTH_ANALYSIS.md § 6 (critère 1).
 *
 * 1. S-box : celle de BRUME-512 v0.5 (AD412650BFEC7893), inchangée.
 * 2. Graphe : groupe D₂₅₆ = Z/128 ⋊ Z/2 (loi (a, f)·(b, g) = (a + (−1)^f b, f ⊕ g), sommet v = a + 128·f), 6 réflexions
 *    s_k = (k, 1), k ∈ K, 0 ∈ K sans perte de généralité. Tirages à graine fixe ; contraintes de BRUME-512 : 6-régulier,
 *    max_{i<j} |N(i) ∩ N(j)| + 2·[i~j] ≤ 5, det(A ⊕ I) ≠ 0 sur GF(2) ; critère 1 : diffusion complète en 5 tours,
 *    λ* ≤ 4. Classement : plus grande boule à 4 tours, puis plus petit λ*.
 * 3. Coefficients c(j, i) ∈ GF(16)* sur le support de A ⊕ I, contraintes (a) à (e) de BRUME-512 (lignes et colonnes à 7
 *    valeurs distinctes de somme non nulle, mineurs 2 × 2 non nuls sur les chevauchements de colonnes et de lignes,
 *    det M ≠ 0), par min-conflits à graine fixe.
 * 4. Constantes : RC = SHAKE256("BRUME-1024-v1-RC"), octet (256·r + j) mod 16.
 * Contrôles : B différentiel et linéaire exacts (poids ≤ 3 des deux côtés, M, M⁻¹, Mᵀ, (Mᵀ)⁻¹), aucune translation
 * invariante, graphe pondéré asymétrique (Weisfeiler–Lehman), ordre de M > 256, densité de M⁻¹, constantes distinctes.
 *   cc -O3 -march=native -fopenmp -I sillage/c -I tests/c prototypes/brume_q/b1024/gen_b1024.c sillage/c/commun.c \
 *      sillage/c/brume512.c sillage/c/brume512_avx2.c -lm -o tests/c/build/gen_b1024
 *   tests/c/build/gen_b1024 prototypes/brume_q/b1024/b1024_tables.h prototypes/brume_q/b1024/b1024_lot.h
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brume_ref.h"

#define NN 256
#define MM 128
#define RT 48   /* constantes produites pour 48 tours au plus */

static uint8_t GM[16][16], GI[16];

static int op(int a, int b)
{
    int aa = a % MM, af = a / MM, ba = b % MM, bf = b / MM;
    return (((aa + (af ? -ba : ba)) % MM + MM) % MM) + MM * (af ^ bf);
}

static int nbr(int v, int k) { return op(v, k + MM); }

/* ---------- alea déterministe ---------- */
static uint64_t etat_alea;
static uint64_t alea64(void)
{
    uint64_t z = (etat_alea += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static int alea(int n) { return (int)(alea64() % (uint64_t)n); }

/* ---------- graphe ---------- */
static uint8_t A[NN][NN];

static void adjacence(const int *K)
{
    memset(A, 0, sizeof A);
    for (int x = 0; x < NN; x++)
        for (int g = 0; g < 6; g++) {
            int y = nbr(x, K[g]);
            A[x][y] = A[y][x] = 1;
        }
}

static int boule(int r)    /* taille de la boule de rayon r autour de 0 (sommet-transitif) */
{
    uint8_t in[NN] = {0}, nv[NN];
    in[0] = 1;
    for (int t = 0; t < r; t++) {
        memcpy(nv, in, NN);
        for (int v = 0; v < NN; v++)
            if (in[v])
                for (int w = 0; w < NN; w++)
                    if (A[v][w])
                        nv[w] = 1;
        memcpy(in, nv, NN);
    }
    int c = 0;
    for (int v = 0; v < NN; v++)
        c += in[v];
    return c;
}

static int max_chev(void)
{
    int mx = 0;
    for (int i = 0; i < NN; i++)
        for (int j = i + 1; j < NN; j++) {
            int c = 0;
            for (int k = 0; k < NN; k++)
                c += A[i][k] & A[j][k];
            c += 2 * A[i][j];
            if (c > mx)
                mx = c;
        }
    return mx;
}

static int det_gf2_AI(void)
{
    static uint8_t M[NN][NN];
    for (int i = 0; i < NN; i++)
        for (int j = 0; j < NN; j++)
            M[i][j] = A[i][j] | (i == j);
    for (int c = 0, r = 0; c < NN; c++, r++) {
        int p = r;
        while (p < NN && !M[p][c])
            p++;
        if (p == NN)
            return 0;
        if (p != r)
            for (int j = 0; j < NN; j++) { uint8_t t = M[p][j]; M[p][j] = M[r][j]; M[r][j] = t; }
        for (int k = r + 1; k < NN; k++)
            if (M[k][c])
                for (int j = 0; j < NN; j++)
                    M[k][j] ^= M[r][j];
    }
    return 1;
}

/* λ* par la formule des représentations (vérifiée contre Jacobi dans largeur/verif_largeur.c) */
static double lambda_etoile(const int *K)
{
    double mx = 0;
    for (int j = 1; j < MM; j++) {
        double re = 0, im = 0;
        for (int g = 0; g < 6; g++) {
            re += cos(2 * M_PI * j * K[g] / MM);
            im += sin(2 * M_PI * j * K[g] / MM);
        }
        double a = sqrt(re * re + im * im);
        if (a > mx)
            mx = a;
    }
    int s = 0;
    for (int g = 0; g < 6; g++)
        s += (K[g] & 1) ? -1 : 1;
    if (abs(s) < 6 && abs(s) > mx)
        mx = abs(s);
    return mx;
}

/* ---------- coefficients ---------- */
static int LN[NN][7];   /* LN[j] = support de la ligne j (= colonne j, support symétrique), trié */
static uint8_t C[NN][NN];

typedef struct { int t, a, b, p, q; } contr_t;   /* t : 0 ligne, 1 colonne, 2 mineur colonnes, 3 mineur lignes */
static contr_t *CT;
static int nct;
static int *par_cell[NN][7], npar[NN][7];

static int slot(int j, int i)
{
    for (int s = 0; s < 7; s++)
        if (LN[j][s] == i)
            return s;
    return -1;
}

static int viole(const contr_t *c)
{
    if (c->t <= 1) {
        uint8_t v[7], x = 0;
        for (int s = 0; s < 7; s++) {
            v[s] = c->t == 0 ? C[c->a][LN[c->a][s]] : C[LN[c->a][s]][c->a];
            x ^= v[s];
        }
        if (!x)
            return 1;
        for (int s = 0; s < 7; s++)
            for (int u = s + 1; u < 7; u++)
                if (v[s] == v[u])
                    return 1;
        return 0;
    }
    if (c->t == 2)   /* colonnes a, b ; lignes p, q */
        return GM[C[c->p][c->a]][C[c->q][c->b]] == GM[C[c->q][c->a]][C[c->p][c->b]];
    /* lignes a, b ; colonnes p, q */
    return GM[C[c->a][c->p]][C[c->b][c->q]] == GM[C[c->b][c->p]][C[c->a][c->q]];
}

static void ajoute_contr(contr_t c)
{
    CT = realloc(CT, sizeof(contr_t) * (nct + 1));
    CT[nct++] = c;
}

static void lie(int j, int i, int id)
{
    int s = slot(j, i);
    par_cell[j][s] = realloc(par_cell[j][s], sizeof(int) * (npar[j][s] + 1));
    par_cell[j][s][npar[j][s]++] = id;
}

static void construit_contraintes(void)
{
    for (int j = 0; j < NN; j++) {
        ajoute_contr((contr_t){0, j, 0, 0, 0});
        for (int s = 0; s < 7; s++)
            lie(j, LN[j][s], nct - 1);
        ajoute_contr((contr_t){1, j, 0, 0, 0});
        for (int s = 0; s < 7; s++)
            lie(LN[j][s], j, nct - 1);
    }
    for (int a = 0; a < NN; a++)
        for (int b = a + 1; b < NN; b++) {
            int P[7], np = 0;   /* supp(a) ∩ supp(b) (lignes communes des colonnes a et b = colonnes communes des lignes) */
            for (int s = 0; s < 7; s++)
                for (int u = 0; u < 7; u++)
                    if (LN[a][s] == LN[b][u])
                        P[np++] = LN[a][s];
            for (int x = 0; x < np; x++)
                for (int y = x + 1; y < np; y++) {
                    int p = P[x], q = P[y];
                    ajoute_contr((contr_t){2, a, b, p, q});
                    lie(p, a, nct - 1); lie(q, b, nct - 1); lie(q, a, nct - 1); lie(p, b, nct - 1);
                    ajoute_contr((contr_t){3, a, b, p, q});
                    lie(a, p, nct - 1); lie(b, q, nct - 1); lie(b, p, nct - 1); lie(a, q, nct - 1);
                }
        }
}

static int fautes_cell(int j, int s)
{
    int n = 0;
    for (int k = 0; k < npar[j][s]; k++)
        n += viole(&CT[par_cell[j][s][k]]);
    return n;
}

static int det_gf16(const uint8_t Mx[NN][NN], uint8_t inv[NN][NN])
{
    static uint8_t T[NN][2 * NN];
    for (int i = 0; i < NN; i++)
        for (int j = 0; j < 2 * NN; j++)
            T[i][j] = j < NN ? Mx[i][j] : (j - NN == i);
    for (int c = 0; c < NN; c++) {
        int p = c;
        while (p < NN && !T[p][c])
            p++;
        if (p == NN)
            return 0;
        if (p != c)
            for (int j = 0; j < 2 * NN; j++) { uint8_t t = T[p][j]; T[p][j] = T[c][j]; T[c][j] = t; }
        uint8_t iv = GI[T[c][c]];
        for (int j = 0; j < 2 * NN; j++)
            T[c][j] = GM[T[c][j]][iv];
        for (int i = 0; i < NN; i++)
            if (i != c && T[i][c]) {
                uint8_t f = T[i][c];
                for (int j = 0; j < 2 * NN; j++)
                    T[i][j] ^= GM[f][T[c][j]];
            }
    }
    if (inv)
        for (int i = 0; i < NN; i++)
            memcpy(inv[i], T[i] + NN, NN);
    return 1;
}

static int gen_coef(uint64_t graine)
{
    etat_alea = graine;
    for (int essai = 0; essai < 20; essai++) {
        memset(C, 0, sizeof C);
        for (int j = 0; j < NN; j++) {
            /* ligne : 7 valeurs distinctes de somme non nulle */
            for (;;) {
                uint8_t v[7], x = 0;
                int ok = 1;
                for (int s = 0; s < 7 && ok; s++) {
                    v[s] = (uint8_t)(1 + alea(15));
                    for (int u = 0; u < s; u++)
                        ok &= v[u] != v[s];
                    x ^= v[s];
                }
                if (!ok || !x)
                    continue;
                for (int s = 0; s < 7; s++)
                    C[j][LN[j][s]] = v[s];
                break;
            }
        }
        for (long it = 0; it < 4000000; it++) {
            /* une contrainte violée au hasard (balayage depuis un point aléatoire) */
            int d = alea(nct), k = -1;
            for (int u = 0; u < nct; u++)
                if (viole(&CT[(d + u) % nct])) {
                    k = (d + u) % nct;
                    break;
                }
            if (k < 0) {
                uint8_t (*Mi)[NN] = malloc(NN * NN);
                int ok = det_gf16((const uint8_t(*)[NN])C, Mi);
                free(Mi);
                if (ok)
                    return essai;
                break;   /* det nul : nouvel essai */
            }
            /* cellules de la contrainte */
            contr_t *c = &CT[k];
            int cj[7], ci[7], nc = 0;
            if (c->t == 0)
                for (int s = 0; s < 7; s++) { cj[nc] = c->a; ci[nc++] = LN[c->a][s]; }
            else if (c->t == 1)
                for (int s = 0; s < 7; s++) { cj[nc] = LN[c->a][s]; ci[nc++] = c->a; }
            else if (c->t == 2) {
                cj[0] = c->p; ci[0] = c->a; cj[1] = c->q; ci[1] = c->b; cj[2] = c->q; ci[2] = c->a; cj[3] = c->p; ci[3] = c->b; nc = 4;
            } else {
                cj[0] = c->a; ci[0] = c->p; cj[1] = c->b; ci[1] = c->q; cj[2] = c->b; ci[2] = c->p; cj[3] = c->a; ci[3] = c->q; nc = 4;
            }
            int q = alea(nc), j = cj[q], i = ci[q], s = slot(j, i);
            int ancien = C[j][i], meilleur = ancien, fm = fautes_cell(j, s);
            int depart = alea(15);
            for (int t = 0; t < 15; t++) {
                int v = 1 + (depart + t) % 15;
                if (v == ancien)
                    continue;
                C[j][i] = (uint8_t)v;
                int f = fautes_cell(j, s);
                if (f < fm || (f == fm && alea(4) == 0)) {
                    fm = f;
                    meilleur = v;
                }
            }
            C[j][i] = (uint8_t)meilleur;
        }
    }
    return -1;
}

/* ---------- contrôles ---------- */
static uint8_t COL[NN][16][NN];

static int min_branche(const uint8_t Mx[NN][NN], int w)
{
    for (int k = 0; k < NN; k++)
        for (int c = 0; c < 16; c++)
            for (int v = 0; v < NN; v++)
                COL[k][c][v] = GM[Mx[v][k]][c];
    int best = 1 << 30;
#pragma omp parallel for schedule(dynamic) reduction(min : best)
    for (int i = 0; i < NN; i++) {
        if (w == 1) {
            int n = 1;
            for (int v = 0; v < NN; v++)
                n += COL[i][1][v] != 0;
            if (n < best)
                best = n;
            continue;
        }
        for (int j = i + 1; j < NN; j++)
            for (int b = 1; b < 16; b++) {
                uint8_t y[NN];
                for (int v = 0; v < NN; v++)
                    y[v] = COL[i][1][v] ^ COL[j][b][v];
                if (w == 2) {
                    int n = 2;
                    for (int v = 0; v < NN; v++)
                        n += y[v] != 0;
                    if (n < best)
                        best = n;
                    continue;
                }
                for (int k = j + 1; k < NN; k++)
                    for (int c = 1; c < 16; c++) {
                        int n = 3;
                        for (int v = 0; v < NN; v++)
                            n += (y[v] ^ COL[k][c][v]) != 0;
                        if (n < best)
                            best = n;
                    }
            }
    }
    return best;
}

static int wl_couleurs(void)
{
    int col[NN] = {0}, nouv[NN];
    for (int tour = 0; tour < 40; tour++) {
        /* signature : multiensemble (coef sortant, couleur), (coef entrant, couleur), encodé par tri */
        static long sig[NN][16];
        for (int j = 0; j < NN; j++) {
            long a[14];
            int n = 0;
            for (int s = 0; s < 7; s++) {
                int i = LN[j][s];
                a[n++] = ((long)C[j][i] << 20) | col[i];
                a[n++] = (1L << 40) | ((long)C[i][j] << 20) | col[i];
            }
            for (int x = 0; x < n; x++)
                for (int y = x + 1; y < n; y++)
                    if (a[y] < a[x]) { long t = a[x]; a[x] = a[y]; a[y] = t; }
            sig[j][0] = col[j];
            for (int x = 0; x < 14; x++)
                sig[j][x + 1] = a[x];
            sig[j][15] = 0;
        }
        int nc = 0;
        for (int j = 0; j < NN; j++) {
            int trouve = -1;
            for (int k = 0; k < j; k++)
                if (!memcmp(sig[j], sig[k], sizeof sig[j])) {
                    trouve = nouv[k];
                    break;
                }
            nouv[j] = trouve >= 0 ? trouve : nc++;
        }
        int pareil = 1;
        for (int j = 0; j < NN; j++)
            pareil &= nouv[j] == col[j];
        memcpy(col, nouv, sizeof col);
        if (pareil || nc == NN)
            return nc;
    }
    int nc = 0;
    for (int j = 0; j < NN; j++)
        if (col[j] + 1 > nc)
            nc = col[j] + 1;
    return nc;
}

static int translations_invariantes(void)
{
    int n = 0;
    for (int h = 1; h < NN; h++) {
        int g = 1, d = 1;
        for (int j = 0; j < NN; j++)
            for (int s = 0; s < 7; s++) {
                int i = LN[j][s];
                g &= C[op(h, j)][op(h, i)] == C[j][i];
                d &= C[op(j, h)][op(i, h)] == C[j][i];
            }
        n += g + d;
    }
    return n;
}

static int ordre_superieur(int borne)  /* 1 si M^k ≠ I pour tout 1 ≤ k ≤ borne */
{
    static uint8_t P[NN][NN], Q[NN][NN];
    memcpy(P, C, sizeof P);
    for (int k = 1; k <= borne; k++) {
        int id = 1;
        for (int i = 0; i < NN && id; i++)
            for (int j = 0; j < NN && id; j++)
                id &= P[i][j] == (i == j);
        if (id)
            return 0;
        /* P ← M·P, M creuse */
#pragma omp parallel for
        for (int i = 0; i < NN; i++)
            for (int j = 0; j < NN; j++) {
                uint8_t a = 0;
                for (int s = 0; s < 7; s++)
                    a ^= GM[C[i][LN[i][s]]][P[LN[i][s]][j]];
                Q[i][j] = a;
            }
        memcpy(P, Q, sizeof P);
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    if (!bref_init())
        return 2;
    for (int a = 0; a < 16; a++)
        for (int b = 0; b < 16; b++)
            GM[a][b] = gf_mul((uint8_t)a, (uint8_t)b);
    for (int a = 1; a < 16; a++)
        GI[a] = gf_inv((uint8_t)a);
    /* 2. graphe */
    etat_alea = 0xB1024C0FFEEULL;
    int bestK[6] = {0}, best_b4 = -1, tirages = 400000, valides = 0;
    double best_l = 99;
    for (int t = 0; t < tirages; t++) {
        int K[6] = {0};
        for (int q = 1; q < 6; q++) {
        encore:
            K[q] = alea(MM);
            for (int h = 0; h < q; h++)
                if (K[h] == K[q])
                    goto encore;
        }
        adjacence(K);
        int reg = 1;
        for (int v = 0; v < NN && reg; v++) {
            int d = 0;
            for (int w = 0; w < NN; w++)
                d += A[v][w];
            reg = d == 6;
        }
        if (!reg || boule(5) != NN)
            continue;
        double l = lambda_etoile(K);
        if (l > 4.0)
            continue;
        int b4 = boule(4);
        if (b4 < best_b4 || (b4 == best_b4 && l >= best_l))
            continue;
        if (max_chev() > 5 || !det_gf2_AI())
            continue;
        valides++;
        best_b4 = b4;
        best_l = l;
        memcpy(bestK, K, sizeof K);
    }
    adjacence(bestK);
    printf("graphe D256 : K = {%d,%d,%d,%d,%d,%d} ; boules", bestK[0], bestK[1], bestK[2], bestK[3], bestK[4], bestK[5]);
    for (int r = 1; r <= 5; r++)
        printf(" %d", boule(r));
    printf(" ; lambda* = %.4f ; max_chev = %d ; det(A+I) GF(2) %s ; %d ameliorations sur %d tirages\n", best_l, max_chev(),
           det_gf2_AI() ? "non nul" : "NUL", valides, tirages);
    for (int j = 0; j < NN; j++) {
        int t[7], n = 0;
        t[n++] = j;
        for (int g = 0; g < 6; g++)
            t[n++] = nbr(j, bestK[g]);
        for (int x = 0; x < 7; x++)
            for (int y = x + 1; y < 7; y++)
                if (t[y] < t[x]) { int u = t[x]; t[x] = t[y]; t[y] = u; }
        memcpy(LN[j], t, sizeof t);
    }
    /* 3. coefficients */
    construit_contraintes();
    int essais = gen_coef(0xB1024C0EFULL);
    if (essais < 0) {
        printf("ECHEC : pas de coefficients\n");
        return 1;
    }
    int nv = 0;
    for (int k = 0; k < nct; k++)
        nv += viole(&CT[k]);
    static uint8_t MI[NN][NN], MT[NN][NN], MIT[NN][NN];
    int inv = det_gf16((const uint8_t(*)[NN])C, MI);
    for (int i = 0; i < NN; i++)
        for (int j = 0; j < NN; j++) {
            MT[i][j] = C[j][i];
            MIT[i][j] = MI[j][i];
        }
    int dens = 0;
    for (int i = 0; i < NN; i++)
        for (int j = 0; j < NN; j++)
            dens += MI[i][j] != 0;
    printf("coefficients : %d contraintes (a)-(d), %d violees, %d redemarrage(s) ; det M %s ; densite M^-1 %.1f %%\n", nct, nv, essais,
           inv ? "non nul" : "NUL", 100.0 * dens / (NN * NN));
    int ok = nv == 0 && inv && best_b4 > 0;
    /* contrôles */
    const char *nom[4] = {"M", "M_inv", "Mt", "Mt_inv"};
    const uint8_t(*mat[4])[NN] = {(const uint8_t(*)[NN])C, (const uint8_t(*)[NN])MI, (const uint8_t(*)[NN])MT,
                                  (const uint8_t(*)[NN])MIT};
    int F[4][4], b8 = 1;
    for (int a = 0; a < 4; a++) {
        printf("branchement %-6s :", nom[a]);
        for (int w = 1; w <= 3; w++) {
            F[a][w] = min_branche(mat[a], w);
            printf(" w=%d -> %d", w, F[a][w]);
            b8 &= F[a][w] >= 8;
        }
        printf("\n");
        fflush(stdout);
    }
    b8 &= F[0][1] == 8 && F[2][1] == 8;
    printf("B_differentiel = B_lineaire = 8 (exact) %s\n", b8 ? "OK" : "ECHEC");
    int tr = translations_invariantes(), wl = wl_couleurs(), ordre = ordre_superieur(256);
    printf("translations invariantes : %d ; couleurs WL : %d / %d (%s) ; ordre de M > 256 : %s\n", tr, wl, NN,
           wl == NN ? "asymetrique" : "SYMETRIE", ordre ? "oui" : "NON");
    ok &= b8 && tr == 0 && wl == NN && ordre && best_l <= 4.0;
    /* 4. constantes */
    static uint8_t flux[RT * NN], RC[RT][NN];
    sl_shake256((const uint8_t *)"BRUME-1024-v1-RC", 16, flux, sizeof flux);
    for (int r = 0; r < RT; r++)
        for (int j = 0; j < NN; j++)
            RC[r][j] = flux[r * NN + j] & 15;
    int dist = 1;
    for (int r = 0; r < RT; r++)
        for (int s = r + 1; s < RT; s++)
            dist &= memcmp(RC[r], RC[s], NN) != 0;
    printf("constantes distinctes sur %d tours : %s\n", RT, dist ? "oui" : "NON");
    ok &= dist;
    /* en-tête */
    FILE *o = fopen(argv[1], "w");
    if (!o)
        return 2;
    fprintf(o, "/* Généré par prototypes/brume_q/b1024/gen_b1024.c — ne pas éditer. BRUME-1024 (prototype, hors suite). */\n");
    fprintf(o, "#ifndef B1024_TABLES_H\n#define B1024_TABLES_H\n#include <stdint.h>\n#define B1_N 256\n#define B1_M 128\n#define B1_RT %d\n", RT);
    fprintf(o, "static const int B1_K[6] = {%d, %d, %d, %d, %d, %d};\n", bestK[0], bestK[1], bestK[2], bestK[3], bestK[4], bestK[5]);
    fprintf(o, "/* coefficients : B1_CS[v] = M[v][v], B1_CG[g][v] = M[v][v·s_K[g]] */\nstatic const uint8_t B1_CS[256] = {");
    for (int v = 0; v < NN; v++)
        fprintf(o, "%s%d", v ? ", " : "", C[v][v]);
    fprintf(o, "};\nstatic const uint8_t B1_CG[6][256] = {\n");
    for (int g = 0; g < 6; g++) {
        fprintf(o, "    {");
        for (int v = 0; v < NN; v++)
            fprintf(o, "%s%d", v ? ", " : "", C[v][nbr(v, bestK[g])]);
        fprintf(o, "},\n");
    }
    fprintf(o, "};\nstatic const uint8_t B1_RC[%d][256] = {\n", RT);
    for (int r = 0; r < RT; r++) {
        fprintf(o, "    {");
        for (int v = 0; v < NN; v++)
            fprintf(o, "%s%d", v ? ", " : "", RC[r][v]);
        fprintf(o, "},\n");
    }
    fprintf(o, "};\n/* faits de branchement exacts (poids 1..3) : M, M^-1, Mt, Mt^-1 */\nstatic const int B1_FAITS[4][4] = {");
    for (int a = 0; a < 4; a++)
        fprintf(o, "%s{0, %d, %d, %d}", a ? ", " : "", F[a][1], F[a][2], F[a][3]);
    fprintf(o, "};\n#endif\n");
    fclose(o);
    /* diffusion du noyau à 32 états, indices et coefficients littéraux (comme BR_DIFFUSION_LOT de la suite) */
    if (argc > 2) {
        o = fopen(argv[2], "w");
        if (!o)
            return 2;
        fprintf(o, "/* Généré par prototypes/brume_q/b1024/gen_b1024.c — ne pas éditer. s[v] = Σ_i M[v][i]·y[i] (TG[c] : ×c). */\n");
        fprintf(o, "#define B1_DIFFUSION_LOT(y, s, TG) do { \\\n");
        for (int v = 0; v < NN; v++) {
            fprintf(o, "    (s)[%d] = ", v);
            for (int t = 0; t < 6; t++)
                fprintf(o, "_mm256_xor_si256(");
            for (int t = 0; t < 7; t++) {
                int i = LN[v][t];
                fprintf(o, "%s_mm256_shuffle_epi8(TG[%d], (y)[%d])%s", t ? ", " : "", C[v][i], i, t ? ")" : "");
            }
            fprintf(o, "; \\\n");
        }
        fprintf(o, "} while (0)\n");
        fclose(o);
    }
    printf("gen_b1024 %s -> %s\n", ok ? "OK" : "ECHEC", argv[1]);
    return ok ? 0 : 1;
}
