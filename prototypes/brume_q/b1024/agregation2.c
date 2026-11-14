/* Agrégation à 2 tours de BRUME-1024q (ROADMAP.md § 3, premier point) : différentielles et coques linéaires EXACTES à
 * 2 tours, comparées à la meilleure caractéristique seule (facteur d'agrégation), puis confirmées empiriquement sur les
 * 2 premiers tours de la vraie permutation.
 *
 * Tour : x ← M·S(x ⊕ RC_r) (ref_tour). Deux tours, avec RC_0 et RC_1.
 * Différentielles : une différence a ≠ 0 sur le seul nibble v. Après S : b (DDT[a][b]/16) ; après M : c_u = M[u][v]·b sur
 *   les 7 voisins u de v ; après S : d_u (DDT[c_u][d_u]/16) ; après M : Δ₂ = M·d (bijection, d ↔ Δ₂). D'où
 *       DP(a@v → Δ₂) = Σ_b DDT[a][b]/16 · Π_u DDT[c_u][d_u]/16,
 *   exacte pour la permutation (les constantes s'annulent, et les 7 entrées du 2e tour sont des combinaisons linéaires
 *   indépendantes d'octets uniformes : à vérifier empiriquement, c'est le but de la seconde partie).
 * Coques linéaires : un seul nibble actif au 2e tour (masque d'entrée c, de sortie e, au nibble u). Masque sur y₁ :
 *   μ_w = T(M[u][w])ᵀ·c sur les 7 nibbles w de la ligne u (T(m) : matrice binaire de la multiplication par m) ; au 1er
 *   tour, masques d'entrée α_w. Corrélation exacte (matrices de corrélation, sans hypothèse) de ⟨α, x⟩ ⊕ ⟨Γ, P₂(x)⟩, Γ étant
 *   le masque de sortie tel que Mᵀ_bin·Γ = e au nibble u :
 *       C = Σ_c (−1)^⟨c, RC₁[u]⟩ · L(c, e) · Π_w (−1)^⟨α_w, RC₀[w]⟩ · L(α_w, μ_w),   L(a, b) = LAT[a][b]/8.
 * Pour chaque (v, a) ou (u, e), le maximum exact de |somme| sur les extrémités (d ou α) est trouvé par séparation et
 * évaluation (l'énumération complète demanderait des dizaines de milliards de termes), avec le meilleur terme seul.
 * Borne prouvée à 2 tours (Park, Sung, Lee, Lim 2003), pour un nombre de branchement 8 : MEDP₂ ≤ max_u Σ_v DP(u,v)^8,
 * MELP₂ ≤ max_u Σ_v LP(u,v)^8. Au-delà de 2 tours, MEDP_R ≤ MEDP₂.
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/agregation2.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm \
 *      -o agregation2 && ./agregation2 [log2 du nombre d'échantillons, 26 par défaut] > agregation2.json */
#include <math.h>

#include "brume1024.c"

static int DDT[16][16], LAT[16][16];
static int parite(unsigned x) { return __builtin_parity(x); }
static uint8_t tmulT(uint8_t m, uint8_t g)   /* T(m)ᵀ·g : bit k = ⟨m·2^k, g⟩ */
{
    uint8_t r = 0;
    for (int k = 0; k < 4; k++)
        r |= (uint8_t)(parite(gf_mul(m, (uint8_t)(1 << k)) & g) << k);
    return r;
}

typedef struct { double somme, terme; uint32_t cle; int nb_contrib; } meilleur_t;

/* max sur les extrémités x = (x_0..x_6) de |S(x)|, S(x) = Σ_i w_i Π_j F[i][j][x_j] (i : intermédiaire, 1..15), par
 * séparation et évaluation : on fixe x_0, x_1, … ; la borne Σ_i |w_i Π_{j fixés} F| · Π_{j libres} max_x |F[i][j][x]|
 * majore |S| sur le sous-arbre, qu'on élague si elle ne dépasse pas le meilleur trouvé. Exact. */
typedef struct {
    const double (*F)[7][16];
    double maxr[16][8];   /* maxr[i][j] = Π_{k ≥ j} max_x |F[i][k][x]| */
    double best;
    uint32_t cle;
    long noeuds;
} bb_t;
static void bb(bb_t *t, int j, const double part[16], uint32_t cle)
{
    t->noeuds++;
    if (j == 7) {
        double s = 0;
        for (int i = 1; i < 16; i++) s += part[i];
        if (fabs(s) > t->best) { t->best = fabs(s); t->cle = cle; }
        return;
    }
    for (int x = 0; x < 16; x++) {
        double p2[16], borne = 0;
        int actif = 0;
        for (int i = 1; i < 16; i++) {
            p2[i] = part[i] * t->F[i][j][x];
            borne += fabs(p2[i]) * t->maxr[i][j + 1];
            actif |= p2[i] != 0;
        }
        if (actif && borne > t->best * (1 + 1e-12))
            bb(t, j + 1, p2, cle | (uint32_t)x << (4 * j));
    }
}
static meilleur_t agreger(const double w[16], const double F[16][7][16], double *max_terme, long *noeuds)
{
    bb_t t = {.F = F, .best = 0, .cle = 0, .noeuds = 0};
    *max_terme = 0;
    for (int i = 1; i < 16; i++) {
        t.maxr[i][7] = 1;
        for (int j = 6; j >= 0; j--) {
            double m = 0;
            for (int x = 0; x < 16; x++) if (fabs(F[i][j][x]) > m) m = fabs(F[i][j][x]);
            t.maxr[i][j] = m * t.maxr[i][j + 1];
        }
        if (fabs(w[i]) * t.maxr[i][0] > *max_terme) *max_terme = fabs(w[i]) * t.maxr[i][0];
    }
    t.best = *max_terme * (1 - 1e-9);   /* le meilleur terme seul est atteint : point de départ de l'élagage */
    double part[16];
    for (int i = 0; i < 16; i++) part[i] = i ? w[i] : 0;
    bb(&t, 0, part, 0);
    /* détail à la clé trouvée : somme signée, plus grand terme, nombre de contributeurs */
    meilleur_t m = {0, 0, t.cle, 0};
    for (int i = 1; i < 16; i++) {
        double v = w[i];
        for (int j = 0; j < 7; j++) v *= F[i][j][(t.cle >> (4 * j)) & 15];
        if (v != 0) { m.somme += v; m.nb_contrib++; if (fabs(v) > m.terme) m.terme = fabs(v); }
    }
    *noeuds = t.noeuds;
    return m;
}

/* masque de sortie Γ : solution de Mᵀ_bin·Γ = t (t : e au nibble u), par élimination de Gauss sur GF(2), 1 024 bits */
static uint64_t MB[1024][16];   /* MB[ligne][mot] : Mᵀ_bin, augmentée plus bas */
static void bits_M(void)        /* Mᵀ_bin[i][j] = M_bin[j][i] ; M_bin colonne (4i'+k) = bits de M·(2^k au nibble i') */
{
    memset(MB, 0, sizeof MB);
    for (int ip = 0; ip < N1; ip++)
        for (int k = 0; k < 4; k++) {
            int col = 4 * ip + k;
            for (int j = 0; j < N1; j++) {
                uint8_t v = gf_mul(DM[j][ip], (uint8_t)(1 << k));
                for (int b = 0; b < 4; b++)
                    if (v >> b & 1) {   /* M_bin[4j+b][col] = 1 → Mᵀ_bin[col][4j+b] = 1 */
                        int row = col, c2 = 4 * j + b;
                        MB[row][c2 / 64] |= 1ULL << (c2 % 64);
                    }
            }
        }
}
static int resoudre(const uint8_t t_nib[N1], uint8_t g_nib[N1])
{
    static uint64_t A[1024][17];   /* 16 mots de matrice + 1 mot pour le second membre (bit 0) */
    for (int r = 0; r < 1024; r++) {
        memcpy(A[r], MB[r], 16 * 8);
        A[r][16] = t_nib[r / 4] >> (r % 4) & 1;
    }
    int piv[1024];
    for (int c = 0, r = 0; c < 1024; c++) {
        int p = r;
        while (p < 1024 && !(A[p][c / 64] >> (c % 64) & 1)) p++;
        if (p == 1024) return 0;
        if (p != r) for (int w = 0; w < 17; w++) { uint64_t x = A[p][w]; A[p][w] = A[r][w]; A[r][w] = x; }
        for (int q = 0; q < 1024; q++)
            if (q != r && (A[q][c / 64] >> (c % 64) & 1))
                for (int w = 0; w < 17; w++) A[q][w] ^= A[r][w];
        piv[c] = r++;
    }
    memset(g_nib, 0, N1);
    for (int c = 0; c < 1024; c++)
        if (A[piv[c]][16] & 1)
            g_nib[c / 4] |= (uint8_t)(1 << (c % 4));
    return 1;
}

static void emballer_nib(const uint8_t x[N1], uint8_t w[128]) { emballer_ref(x, w); }
static int produit_scal(const uint8_t a[128], const uint8_t b[128])
{
    int p = 0;
    for (int i = 0; i < 128; i++) p ^= __builtin_parity(a[i] & b[i]);
    return p;
}
static uint64_t xs(uint64_t *s) { *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; return *s; }

/* ---- calcul exact pour une entrée (v, a) (différentielle) ou (u, e) (coque) */
static meilleur_t diff_exacte(int v, int a, double *mt, long *nn)
{
    int vois[7], nv = 0;
    for (int u = 0; u < N1; u++) if (DM[u][v]) vois[nv++] = u;
    double F[16][7][16], w[16] = {0};
    for (int b = 1; b < 16; b++) {
        w[b] = DDT[a][b] / 16.0;
        for (int j = 0; j < 7; j++) {
            uint8_t c = gf_mul(DM[vois[j]][v], (uint8_t)b);
            for (int d = 0; d < 16; d++) F[b][j][d] = DDT[c][d] / 16.0;
        }
    }
    return agreger(w, (const double (*)[7][16])F, mt, nn);
}
static meilleur_t lin_exacte(int u, int e, double *mt, long *nn)
{
    int lig[7], nw = 0;
    for (int x = 0; x < N1; x++) if (DM[u][x]) lig[nw++] = x;
    double F[16][7][16], w[16] = {0};
    for (int c = 1; c < 16; c++) {
        w[c] = (parite(c & B1_RC[1][u]) ? -1 : 1) * LAT[c][e] / 8.0;
        for (int j = 0; j < 7; j++) {
            uint8_t mu = tmulT(DM[u][lig[j]], (uint8_t)c);
            for (int al = 0; al < 16; al++)
                F[c][j][al] = (parite(al & B1_RC[0][lig[j]]) ? -1 : 1) * LAT[al][mu] / 8.0;
        }
    }
    return agreger(w, (const double (*)[7][16])F, mt, nn);
}
static void emballer_nib(const uint8_t x[N1], uint8_t w[128]);
static int produit_scal(const uint8_t a[128], const uint8_t b[128]);
static uint64_t xs(uint64_t *s);
static int resoudre(const uint8_t t_nib[N1], uint8_t g_nib[N1]);
/* ---- mesures empiriques sur les 2 premiers tours de la vraie permutation (perm1, R = 2) */
static long emp_diff(int v, int a, uint32_t cle, long N, uint64_t graine)
{
    uint8_t dx[N1] = {0}, d[N1] = {0}, pd[128], pD2[128];
    dx[v] = (uint8_t)a;
    int j = 0;
    for (int u = 0; u < N1; u++) if (DM[u][v]) { d[u] = (cle >> (4 * j)) & 15; j++; }
    ref_lin(DM, d);
    emballer_nib(dx, pd);
    emballer_nib(d, pD2);
    long cpt = 0;
#pragma omp parallel reduction(+ : cpt)
    {
        uint64_t s = graine * 0x9E3779B97F4A7C15ULL + (uint64_t)(omp_get_thread_num() + 1) * 0xD1B54A32D192ED03ULL;
#pragma omp for
        for (long i = 0; i < N; i++) {
            uint8_t x[128], y[128];
            for (int k = 0; k < 16; k++) { uint64_t r = xs(&s); memcpy(x + 8 * k, &r, 8); }
            for (int k = 0; k < 128; k++) y[k] = x[k] ^ pd[k];
            perm1(x, 2);
            perm1(y, 2);
            int ok = 1;
            for (int k = 0; k < 128; k++) ok &= (x[k] ^ y[k]) == pD2[k];
            cpt += ok;
        }
    }
    return cpt;
}
static double emp_lin(int u, int e, uint32_t cle, long N, uint64_t graine, int *resolu)
{
    uint8_t al[N1] = {0}, t[N1] = {0}, g[N1], pa[128], pg[128];
    int j = 0;
    for (int x = 0; x < N1; x++) if (DM[u][x]) { al[x] = (cle >> (4 * j)) & 15; j++; }
    t[u] = (uint8_t)e;
    *resolu = resoudre(t, g);
    emballer_nib(al, pa);
    emballer_nib(g, pg);
    long zeros = 0;
#pragma omp parallel reduction(+ : zeros)
    {
        uint64_t s = graine * 0xBF58476D1CE4E5B9ULL + (uint64_t)(omp_get_thread_num() + 1) * 0x94D049BB133111EBULL;
#pragma omp for
        for (long i = 0; i < N; i++) {
            uint8_t x[128], x0[128];
            for (int k = 0; k < 16; k++) { uint64_t r = xs(&s); memcpy(x + 8 * k, &r, 8); }
            memcpy(x0, x, 128);
            perm1(x, 2);
            zeros += !(produit_scal(pa, x0) ^ produit_scal(pg, x));
        }
    }
    return 2.0 * zeros / N - 1;
}

int main(int argc, char **argv)
{
    int lg = argc > 1 ? atoi(argv[1]) : 26;
    if (!bref_init() || !ref_init() || !init_noyaux())
        return 2;
    prepare_iv();
    for (int a = 0; a < 16; a++)
        for (int x = 0; x < 16; x++) {
            DDT[a][BR_SBOX[x] ^ BR_SBOX[x ^ a]]++;
            for (int b = 0; b < 16; b++)
                LAT[a][b] += (parite(a & x) == parite(b & BR_SBOX[x])) ? 1 : 0;
        }
    for (int a = 0; a < 16; a++) for (int b = 0; b < 16; b++) LAT[a][b] -= 8;
    /* borne de Park et al. (β = 8) */
    double medp = 0, melp = 0;
    for (int u = 1; u < 16; u++) {
        double sd = 0, sl = 0;
        for (int v = 1; v < 16; v++) {
            sd += pow(DDT[u][v] / 16.0, 8);
            sl += pow(pow(LAT[u][v] / 8.0, 2), 8);
        }
        if (sd > medp) medp = sd;
        if (sl > melp) melp = sl;
    }
    /* ---- différentielles exactes */
    meilleur_t gd = {0, 0, 0, 0};
    int gd_v = 0, gd_a = 0, nb_agrege = 0;
    long noeuds_d = 0, noeuds_l = 0;
    double gd_char = 0, ratio_max = 0;
#pragma omp parallel
    {
#pragma omp for schedule(dynamic) reduction(+ : nb_agrege, noeuds_d)
        for (int va = 0; va < N1 * 15; va++) {
            int v = va / 15, a = 1 + va % 15;
            int vois[7], nv = 0;
            for (int u = 0; u < N1; u++) if (DM[u][v]) vois[nv++] = u;
            static __thread double F[16][7][16];
            double w[16] = {0};
            for (int b = 1; b < 16; b++) {
                w[b] = DDT[a][b] / 16.0;
                for (int j = 0; j < 7; j++) {
                    uint8_t c = gf_mul(DM[vois[j]][v], (uint8_t)b);
                    for (int d = 0; d < 16; d++) F[b][j][d] = DDT[c][d] / 16.0;
                }
            }
            double mt;
            long nn;
            meilleur_t m = agreger(w, (const double (*)[7][16])F, &mt, &nn);
            noeuds_d += nn;
            nb_agrege += m.nb_contrib > 1;
#pragma omp critical
            {
                if (m.somme > gd.somme) { gd = m; gd_v = v; gd_a = a; }
                if (mt > gd_char) gd_char = mt;
                if (m.terme > 0 && m.somme / m.terme > ratio_max) ratio_max = m.somme / m.terme;
            }
        }
    }
    /* ---- coques linéaires exactes */
    meilleur_t gl = {0, 0, 0, 0};
    int gl_u = 0, gl_e = 0, nl_agrege = 0;
    double gl_trail = 0, ratio_lmax = 0;
#pragma omp parallel
    {
#pragma omp for schedule(dynamic) reduction(+ : nl_agrege, noeuds_l)
        for (int ue = 0; ue < N1 * 15; ue++) {
            int u = ue / 15, e = 1 + ue % 15;
            int lig[7], nw = 0;
            for (int x = 0; x < N1; x++) if (DM[u][x]) lig[nw++] = x;
            static __thread double F[16][7][16];
            double w[16] = {0};
            for (int c = 1; c < 16; c++) {
                w[c] = (parite(c & B1_RC[1][u]) ? -1 : 1) * LAT[c][e] / 8.0;
                for (int j = 0; j < 7; j++) {
                    uint8_t mu = tmulT(DM[u][lig[j]], (uint8_t)c);
                    for (int al = 0; al < 16; al++)
                        F[c][j][al] = (parite(al & B1_RC[0][lig[j]]) ? -1 : 1) * LAT[al][mu] / 8.0;
                }
            }
            double mt;
            long nn;
            meilleur_t m = agreger(w, (const double (*)[7][16])F, &mt, &nn);
            noeuds_l += nn;
            nl_agrege += m.nb_contrib > 1;
#pragma omp critical
            {
                if (fabs(m.somme) > fabs(gl.somme)) { gl = m; gl_u = u; gl_e = e; }
                if (mt > gl_trail) gl_trail = mt;
                if (m.terme > 0 && fabs(m.somme) / m.terme > ratio_lmax) ratio_lmax = fabs(m.somme) / m.terme;
            }
        }
    }
    /* ---- confirmation empirique : l'entrée maximale et 7 entrées tirées au hasard, pour chaque famille */
    long N = 1L << lg;
    bits_M();
    char js[1 << 15];
    int o = 0, tout_ok = 1;
    uint64_t g = 0x5EED;
    o += snprintf(js + o, sizeof js - (size_t)o, " \"validations\": [");
    for (int q = 0; q < 8; q++) {
        int v = q ? (int)(xs(&g) % N1) : gd_v, a = q ? 1 + (int)(xs(&g) % 15) : gd_a;
        double mt; long nn;
        meilleur_t m = q ? diff_exacte(v, a, &mt, &nn) : gd;
        long cpt = emp_diff(v, a, m.cle, N, 100 + (uint64_t)q);
        double z = (cpt - N * m.somme) / sqrt(N * m.somme * (1 - m.somme));
        tout_ok &= fabs(z) < 5;
        o += snprintf(js + o, sizeof js - (size_t)o, "%s\n  {\"type\": \"differentielle\", \"nibble\": %d, \"difference\": %d, \"exacte\": %.6g, "
                      "\"comptee\": %ld, \"attendue\": %.1f, \"z\": %.2f}", q ? "," : "", v, a, m.somme, cpt, N * m.somme, z);
    }
    for (int q = 0; q < 8; q++) {
        int u = q ? (int)(xs(&g) % N1) : gl_u, e = q ? 1 + (int)(xs(&g) % 15) : gl_e;
        double mt; long nn;
        meilleur_t m = q ? lin_exacte(u, e, &mt, &nn) : gl;
        int resolu;
        double c = emp_lin(u, e, m.cle, N, 200 + (uint64_t)q, &resolu);
        double z = (c - m.somme) / sqrt((1 - m.somme * m.somme) / N);
        tout_ok &= fabs(z) < 5 && resolu;
        o += snprintf(js + o, sizeof js - (size_t)o, ",\n  {\"type\": \"coque\", \"nibble\": %d, \"masque\": %d, \"exacte\": %.6g, "
                      "\"mesuree\": %.6g, \"z\": %.2f, \"gamma_resolu\": %s}", u, e, m.somme, c, z, resolu ? "true" : "false");
    }
    o += snprintf(js + o, sizeof js - (size_t)o, "\n ],\n");
    printf("{\n \"borne_park_medp2\": %.4g, \"borne_park_melp2\": %.4g,\n", medp, melp);
    printf(" \"differentielle\": {\"max_dp2\": %.6g, \"log2\": %.3f, \"meilleure_caracteristique\": %.6g, \"log2_car\": %.3f, "
           "\"nibble\": %d, \"difference\": %d, \"caracteristiques_agregees\": %d, \"rapport_max_dp_sur_car\": %.4f, "
           "\"entrees_avec_agregation\": %d, \"noeuds\": %ld},\n", gd.somme, log2(gd.somme), gd_char, log2(gd_char), gd_v, gd_a,
           gd.nb_contrib, ratio_max, nb_agrege, noeuds_d);
    printf(" \"lineaire\": {\"max_correlation2\": %.6g, \"log2\": %.3f, \"meilleur_trail\": %.6g, \"log2_trail\": %.3f, "
           "\"nibble\": %d, \"masque\": %d, \"trails_agreges\": %d, \"rapport_max\": %.4f, \"entrees_avec_agregation\": %d, \"noeuds\": %ld},\n",
           gl.somme, log2(fabs(gl.somme)), gl_trail, log2(gl_trail), gl_u, gl_e, gl.nb_contrib, ratio_lmax, nl_agrege, noeuds_l);
    printf(" \"echantillons\": %ld,\n%s \"ok\": %s\n}\n", N, js, tout_ok ? "true" : "false");
    return !tout_ok;
}
