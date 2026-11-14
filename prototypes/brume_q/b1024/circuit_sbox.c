/* Recherche par SAT d'un petit circuit pour la S-box de BRUME (v0.5, AD412650BFEC7893), pour le noyau bitslicé
 * (ROADMAP.md, performance). Portes permises, celles d'AVX2 en une instruction : ET, OU, OUX, ET-NON (~a & b, dans les
 * deux sens). Liberté gratuite : le circuit peut calculer S(x ⊕ a) ⊕ b pour toute constante a (reportée dans les
 * constantes de tour) et toute constante b (reportée par linéarité de M dans les constantes du tour suivant).
 *   circuit_sbox cnf <a> <k> <fichier.cnf>    : « existe-t-il un circuit de k portes pour S(x ⊕ a) ⊕ b, b libre ? »
 *   circuit_sbox lire <a> <k> <sortie_du_solveur> : décode le modèle, vérifie le circuit sur les 16 entrées, l'écrit
 * Encodage : valeurs des fils sur les 16 lignes de la table ; pour chaque porte, deux sélecteurs à un seul vrai (entrée
 * gauche j1 < entrée droite j2) et un type à un seul vrai ; chaque sortie i = un fil, complémenté ou non (c_i libre). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int SB[16] = {0xA, 0xD, 0x4, 0x1, 0x2, 0x6, 0x5, 0x0, 0xB, 0xF, 0xE, 0xC, 0x7, 0x8, 0x9, 0x3};
enum { ET, OU, OUX, ETN_AB, ETN_BA, NT };   /* ETN_AB = ~a & b, ETN_BA = a & ~b */
static int F(int t, int a, int b)
{
    return t == ET ? a & b : t == OU ? a | b : t == OUX ? a ^ b : t == ETN_AB ? (!a) & b : a & (!b);
}

static int K, A, NW, nv;
static int VAL[64][16], S1[64][64], S2[64][64], TY[64][NT], VA[64][16], VB[64][16], OS[4][64], OC[4];
static FILE *f;
static long ncl;
static int nouvelle(void) { return ++nv; }
static int buf[256], nb;
static void lit(int x) { buf[nb++] = x; }
static void fin(void)
{
    for (int i = 0; i < nb; i++)
        fprintf(f, "%d ", buf[i]);
    fprintf(f, "0\n");
    nb = 0;
    ncl++;
}
static void un_seul(const int *v, int n)   /* exactement un vrai */
{
    for (int i = 0; i < n; i++)
        lit(v[i]);
    fin();
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++) {
            lit(-v[i]);
            lit(-v[j]);
            fin();
        }
}

static void variables(void)
{
    NW = 4 + K;
    nv = 0;
    for (int w = 4; w < NW; w++)
        for (int x = 0; x < 16; x++)
            VAL[w][x] = nouvelle();
    for (int g = 0; g < K; g++) {
        int w = 4 + g;
        for (int j = 0; j < w; j++) {
            S1[g][j] = nouvelle();
            S2[g][j] = nouvelle();
        }
        for (int t = 0; t < NT; t++)
            TY[g][t] = nouvelle();
        for (int x = 0; x < 16; x++) {
            VA[g][x] = nouvelle();
            VB[g][x] = nouvelle();
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int w = 0; w < NW; w++)
            OS[i][w] = nouvelle();
        OC[i] = nouvelle();
    }
}

/* littéral « le fil w vaut 1 sur la ligne x » : constant pour les entrées (renvoie 0 avec *cst) */
static int fil(int w, int x, int *cst)
{
    if (w < 4) {
        *cst = x >> w & 1;
        return 0;
    }
    return VAL[w][x];
}

/* clause « ¬s ∨ (lit = val) » où lit est un fil (constant ou variable) */
static void egal_si(int s, int w, int x, int vlit, int sens)   /* s → (fil(w,x) ↔ vlit) si sens, sinon s → (fil ↔ ¬vlit) */
{
    int cst = 0, l = fil(w, x, &cst);
    int v = sens ? vlit : -vlit;
    if (!l) {   /* fil constant : s → (v = cst) */
        lit(-s);
        lit(cst ? v : -v);
        fin();
        return;
    }
    lit(-s); lit(-l); lit(v); fin();
    lit(-s); lit(l); lit(-v); fin();
}

static void ecrire(void)
{
    for (int g = 0; g < K; g++) {
        int w = 4 + g;
        un_seul(S1[g], w);
        un_seul(S2[g], w);
        un_seul(TY[g], NT);
        for (int j1 = 0; j1 < w; j1++)          /* j1 < j2 */
            for (int j2 = 0; j2 <= j1; j2++) {
                lit(-S1[g][j1]);
                lit(-S2[g][j2]);
                fin();
            }
        for (int x = 0; x < 16; x++) {
            for (int j = 0; j < w; j++) {
                egal_si(S1[g][j], j, x, VA[g][x], 1);
                egal_si(S2[g][j], j, x, VB[g][x], 1);
            }
            for (int t = 0; t < NT; t++)
                for (int a = 0; a < 2; a++)
                    for (int b = 0; b < 2; b++) {
                        lit(-TY[g][t]);
                        lit(a ? -VA[g][x] : VA[g][x]);
                        lit(b ? -VB[g][x] : VB[g][x]);
                        lit(F(t, a, b) ? VAL[w][x] : -VAL[w][x]);
                        fin();
                    }
        }
    }
    for (int i = 0; i < 4; i++) {
        un_seul(OS[i], NW);
        for (int w = 0; w < NW; w++)
            for (int x = 0; x < 16; x++) {
                int T = SB[x ^ A] >> i & 1, cst = 0, l = fil(w, x, &cst);
                /* OS → (fil = T ⊕ OC) */
                if (!l) {
                    lit(-OS[i][w]);
                    lit((cst ^ T) ? OC[i] : -OC[i]);
                    fin();
                } else {
                    /* fil = T ⊕ c : T = 0 → fil ↔ c ; T = 1 → fil ↔ ¬c */
                    lit(-OS[i][w]); lit(-l); lit(T ? -OC[i] : OC[i]); fin();
                    lit(-OS[i][w]); lit(l); lit(T ? OC[i] : -OC[i]); fin();
                }
            }
    }
}

int main(int argc, char **argv)
{
    if (argc < 5)
        return 2;
    A = atoi(argv[2]);
    K = atoi(argv[3]);
    variables();
    if (!strcmp(argv[1], "cnf")) {
        /* deux passes : compter puis écrire */
        f = fopen("/dev/null", "w");
        ncl = 0;
        ecrire();
        fclose(f);
        f = fopen(argv[4], "w");
        fprintf(f, "p cnf %d %ld\n", nv, ncl);
        ecrire();
        fclose(f);
        return 0;
    }
    /* lire : modèle « v ... » de CaDiCaL */
    static int vrai[1 << 20];
    FILE *m = fopen(argv[4], "r");
    char ligne[1 << 16];
    int sat = 0;
    while (fgets(ligne, sizeof ligne, m)) {
        if (!strncmp(ligne, "s SATISFIABLE", 13))
            sat = 1;
        if (ligne[0] != 'v')
            continue;
        char *p = ligne + 1;
        for (;;) {
            char *q;
            long x = strtol(p, &q, 10);
            if (q == p)
                break;
            p = q;
            if (x > 0 && x < (1 << 20))
                vrai[x] = 1;
        }
    }
    fclose(m);
    if (!sat) {
        printf("insatisfiable ou inconnu\n");
        return 1;
    }
    int G[64][3], O[4], C[4];
    for (int g = 0; g < K; g++) {
        int w = 4 + g;
        for (int j = 0; j < w; j++) {
            if (vrai[S1[g][j]]) G[g][1] = j;
            if (vrai[S2[g][j]]) G[g][2] = j;
        }
        for (int t = 0; t < NT; t++)
            if (vrai[TY[g][t]]) G[g][0] = t;
    }
    for (int i = 0; i < 4; i++) {
        for (int w = 0; w < NW; w++)
            if (vrai[OS[i][w]]) O[i] = w;
        C[i] = vrai[OC[i]];
    }
    /* vérification sur les 16 entrées : sortie i = fil O[i] ⊕ C[i] = bit i de S(x ⊕ A) */
    int b = 0, ok = 1;
    for (int i = 0; i < 4; i++)
        b |= C[i] << i;
    for (int x = 0; x < 16; x++) {
        int v[64];
        for (int j = 0; j < 4; j++)
            v[j] = x >> j & 1;
        for (int g = 0; g < K; g++)
            v[4 + g] = F(G[g][0], v[G[g][1]], v[G[g][2]]);
        int o = 0;
        for (int i = 0; i < 4; i++)
            o |= v[O[i]] << i;
        ok &= o == (SB[x ^ A] ^ b);
    }
    const char *nom[NT] = {"ET", "OU", "OUX", "ETN_AB", "ETN_BA"};
    printf("a = 0x%X, b = 0x%X, %d portes, vérifié : %s\n", A, b, K, ok ? "oui" : "NON");
    for (int g = 0; g < K; g++)
        printf("  x%d = %s(x%d, x%d)\n", 4 + g, nom[G[g][0]], G[g][1], G[g][2]);
    printf("  sorties : x%d x%d x%d x%d\n", O[0], O[1], O[2], O[3]);
    return ok ? 0 : 1;
}
