/* Variantes générées du noyau à 32 états de BRUME-1024q (priorité 2 de ROADMAP.md : taille du code par tour). Écrit
 * b1024_lot_var.h à partir de la matrice dense M (ref_init de brume1024.c), donc des mêmes tables que b1024_lot.h :
 *   B1_DIFF_FUS(y, z, TG, TSB, RC)    : z[v] = S(Σ_u M[v][u]·y[u] ⊕ RC[v]) — S-box du tour suivant fusionnée dans la
 *                                       diffusion (s n'est ni rangé ni relu) ; le coefficient 1 ne passe pas par une table ;
 *   B1_DIFF_ID(y, s, TG)              : s[v] = Σ_u M[v][u]·y[u], coefficient 1 sans table (dernier tour) ;
 *   B1_DIFF64_FUS(y0, y1, z0, z1, ...) et B1_DIFF64_ID(...) : les mêmes sur 64 états (deux registres par nibble, une seule
 *                                       lecture de la table du coefficient pour les deux).
 *   cc -O2 -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 prototypes/brume_q/b1024/gen_lot_variantes.c \
 *      sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm -o tests/c/build/gen_lot_variantes \
 *      && tests/c/build/gen_lot_variantes > prototypes/brume_q/b1024/b1024_lot_var.h */
#include "brume1024.c"

static void terme(const char *acc, int premier, int c, const char *y, int u)
{
    char t[96];
    if (c == 1)
        snprintf(t, sizeof t, "(%s)[%d]", y, u);
    else
        snprintf(t, sizeof t, "_mm256_shuffle_epi8(t%d_, (%s)[%d])", c, y, u);
    if (premier)
        printf(" %s = %s;", acc, t);
    else
        printf(" %s = _mm256_xor_si256(%s, %s);", acc, acc, t);
}

/* un macro ; n = 1 ou 2 jeux d'états ; fus : S-box et constante du tour suivant */
static void macro(const char *nom, int n, int fus)
{
    if (n == 1)
        printf("#define %s(y0, %s, TG%s) do { __m256i a0_; \\\n", nom, fus ? "z0" : "s0", fus ? ", TSB, RC" : "");
    else
        printf("#define %s(y0, y1, %s, TG%s) do { __m256i a0_, a1_; \\\n", nom, fus ? "z0, z1" : "s0, s1", fus ? ", TSB, RC" : "");
    for (int v = 0; v < N1; v++) {
        printf("   ");
        int k = 0;
        for (int u = 0; u < N1; u++) {
            int c = DM[v][u];
            if (!c)
                continue;
            if (c != 1)
                printf(" { const __m256i t%d_ = (TG)[%d];", c, c);
            for (int j = 0; j < n; j++) {
                char acc[8], y[8];
                snprintf(acc, sizeof acc, "a%d_", j);
                snprintf(y, sizeof y, "y%d", j);
                terme(acc, k == 0, c, y, u);
            }
            if (c != 1)
                printf(" }");
            k++;
        }
        for (int j = 0; j < n; j++) {
            if (fus)
                printf(" (z%d)[%d] = _mm256_shuffle_epi8(TSB, _mm256_xor_si256(a%d_, _mm256_set1_epi8((char)(RC)[%d])));", j, v, j, v);
            else
                printf(" (s%d)[%d] = a%d_;", j, v, j);
        }
        printf(" \\\n");
    }
    printf("} while (0)\n\n");
}

int main(void)
{
    if (!bref_init() || !ref_init())
        return 2;
    printf("/* Généré par prototypes/brume_q/b1024/gen_lot_variantes.c — ne pas éditer. Variantes du noyau à 32 états "
           "(ROADMAP.md, priorité 2). */\n\n");
    macro("B1_DIFF_FUS", 1, 1);
    macro("B1_DIFF_ID", 1, 0);
    macro("B1_DIFF64_FUS", 2, 1);
    macro("B1_DIFF64_ID", 2, 0);
    return 0;
}
