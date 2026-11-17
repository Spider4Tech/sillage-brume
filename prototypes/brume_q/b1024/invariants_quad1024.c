/* Invariants non linéaires QUADRATIQUES LOCAUX de BRUME-1024q (étude « structure », ETUDE_GROUPE_STRUCTURE.md § B2) :
 * extension de structure1024.py, qui excluait les sommes de fonctions d'un seul nibble (g = ⊕ f_q(x_q)).
 *
 * Famille G : fonctions booléennes de degré ≤ 2 sur les 1 024 bits de l'état dont chaque monôme vit dans un nibble ou sur
 * une ARÊTE du graphe de M (deux nibbles voisins) :
 *   1 024 monômes linéaires + 256 × 6 produits dans un nibble + 768 arêtes × 16 produits croisés = 14 848 inconnues.
 * C'est la famille naturelle pour une couche linéaire locale (invariants quadratiques de Todo–Leander–Sasaki et
 * Beierle–Canteaut–Leander, attaques sur Midori, Scream, iSCREAM).
 * Équation : g(R_t(x)) ⊕ g(x) = ε_t pour tout x, R_t(x) = M·S(x ⊕ RC_t). Chaque x tiré au hasard donne une équation
 * LINÉAIRE en (coefficients de g, ε_t) ; avec (inconnues + 64) tirages, la dimension du noyau est exacte sauf probabilité
 * ≤ 2^−64. Noyau nul ⇔ aucun invariant de la famille. Traité tour par tour (t = 0 … 31) et pour les 32 tours à la fois.
 * Témoins (le détecteur doit trouver ce qu'ils contiennent) :
 *   « identite » : R = id → toute fonction est invariante : noyau = 14 848 (ε = 0) ;
 *   « constantes » : R(x) = x ⊕ RC_t (S = id, M = I) → au moins les 1 024 fonctions linéaires (ε = g(RC_t)) ;
 *   « sbox » : M = I, RC = 0 → les invariants quadratiques de la S-box par nibble, s'il y en a (valeur rapportée).
 *
 *   invariants_quad1024 controle | reel [tours] | tous
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/invariants_quad1024.c sillage/c/commun.c -lm
 * Sortie : JSON. */
#include <omp.h>

#include "brume1024.c"

static inline uint64_t xs(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }

/* ------------------------------------------------------------------ monômes */
typedef struct { short i, j; } mono_t;   /* bits i ≤ j (i == j : linéaire) */
static mono_t MONO[16384];
static int NMONO;
static void init_monomes(void)
{
    NMONO = 0;
    for (int b = 0; b < 1024; b++) MONO[NMONO++] = (mono_t){(short)b, (short)b};
    for (int q = 0; q < N1; q++)
        for (int b1 = 0; b1 < 4; b1++)
            for (int b2 = b1 + 1; b2 < 4; b2++) MONO[NMONO++] = (mono_t){(short)(4 * q + b1), (short)(4 * q + b2)};
    for (int q = 0; q < N1; q++)
        for (int p = q + 1; p < N1; p++)
            if (DM[q][p] || DM[p][q])
                for (int b1 = 0; b1 < 4; b1++)
                    for (int b2 = 0; b2 < 4; b2++) MONO[NMONO++] = (mono_t){(short)(4 * q + b1), (short)(4 * p + b2)};
}

/* ------------------------------------------------------------------ tours (réel et témoins) */
enum { REEL, IDENTITE, CONSTANTES, SBOX };
static void tour(uint8_t *x, int t, int var)
{
    switch (var) {
    case REEL: ref_tour(x, t); break;
    case IDENTITE: break;
    case CONSTANTES: for (int q = 0; q < N1; q++) x[q] ^= B1_RC[t][q]; break;
    case SBOX: for (int q = 0; q < N1; q++) x[q] = BR_SBOX[x[q]]; break;
    }
}
static inline int bit(const uint8_t *x, int b) { return x[b >> 2] >> (b & 3) & 1; }

/* ------------------------------------------------------------------ élimination de Gauss en ligne sur GF(2) */
typedef struct {
    int ncol, nmots, rang;
    uint64_t *piv;     /* rang lignes réduites, chacune nmots mots */
    int *col;          /* colonne pivot de chaque ligne */
    int *ligne_de;     /* ligne_de[c] = indice de la ligne de pivot c, ou −1 */
} gauss_t;
static void g_init(gauss_t *g, int ncol)
{
    g->ncol = ncol; g->nmots = (ncol + 63) / 64; g->rang = 0;
    g->piv = calloc((size_t)(ncol + 1) * g->nmots, 8);
    g->col = malloc((ncol + 1) * sizeof(int));
    g->ligne_de = malloc(ncol * sizeof(int));
    for (int c = 0; c < ncol; c++) g->ligne_de[c] = -1;
}
static void g_libre(gauss_t *g) { free(g->piv); free(g->col); free(g->ligne_de); }
/* ajoute une ligne (modifiée sur place) ; rend 1 si elle augmente le rang */
static int g_ajouter(gauss_t *g, uint64_t *v)
{
    for (int w = 0; w < g->nmots; w++)
        while (v[w]) {
            int c = 64 * w + __builtin_ctzll(v[w]);
            int l = g->ligne_de[c];
            if (l < 0) {
                memcpy(g->piv + (size_t)g->rang * g->nmots, v, 8 * g->nmots);
                g->col[g->rang] = c; g->ligne_de[c] = g->rang; g->rang++;
                return 1;
            }
            const uint64_t *p = g->piv + (size_t)l * g->nmots;
            for (int k = w; k < g->nmots; k++) v[k] ^= p[k];
        }
    return 0;
}

/* ------------------------------------------------------------------ une analyse : tours t0..t1−1, variante var */
/* colonnes : NMONO coefficients, puis un ε par tour ; rend la dimension du noyau */
static int analyser(int t0, int t1, int var, uint64_t graine, int *rang_out)
{
    int nt = t1 - t0, ncol = NMONO + nt;
    gauss_t g;
    g_init(&g, ncol);
    long tirages = 0;
    int stables = 0;
    /* on tire par lots parallèles ; on s'arrête quand 64 lignes de suite (par tour) n'augmentent plus le rang et que
     * l'on a au moins ncol + 64 tirages */
    const int LOT = 256;
    uint64_t *lot = malloc((size_t)LOT * g.nmots * 8);
    while (g.rang < ncol && (tirages < ncol + 64 || stables < 64 * nt)) {
#pragma omp parallel for schedule(static)
        for (int i = 0; i < LOT; i++) {
            uint64_t s = graine ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(tirages + i + 1));
            for (int k = 0; k < 3; k++) xs(&s);
            int t = t0 + (int)((tirages + i) % nt);
            uint8_t x[N1], y[N1];
            for (int q = 0; q < N1; q++) x[q] = (uint8_t)(xs(&s) & 15);
            memcpy(y, x, N1);
            tour(y, t, var);
            uint64_t *v = lot + (size_t)i * g.nmots;
            memset(v, 0, 8 * g.nmots);
            for (int m = 0; m < NMONO; m++) {
                int a = MONO[m].i, b = MONO[m].j;
                int e = (bit(x, a) & bit(x, b)) ^ (bit(y, a) & bit(y, b));
                if (e) v[m >> 6] |= 1ULL << (m & 63);
            }
            int c = NMONO + (t - t0);
            v[c >> 6] |= 1ULL << (c & 63);
        }
        for (int i = 0; i < LOT; i++) {
            if (g_ajouter(&g, lot + (size_t)i * g.nmots)) stables = 0; else stables++;
        }
        tirages += LOT;
    }
    free(lot);
    int rang = g.rang;
    g_libre(&g);
    *rang_out = rang;
    return ncol - rang;
}

int main(int argc, char **argv)
{
    if (!ref_init()) return 2;
    init_monomes();
    if (NMONO != 14848) { fprintf(stderr, "monômes : %d (14 848 attendus)\n", NMONO); return 3; }
    const char *mode = argc > 1 ? argv[1] : "controle";
    uint64_t graine = 0xB1A5ED1024ULL;
    if (!strcmp(mode, "controle")) {
        int ok = 1, rg;
        int k1 = analyser(0, 1, IDENTITE, graine, &rg);
        int c1 = k1 == NMONO + 1 - 1;   /* toutes les fonctions, ε = 0 forcé : noyau = NMONO (+ ε libre ? non : ε = 0) */
        printf("  %s témoin identité : noyau %d (attendu %d : toute fonction de la famille, ε = 0)\n", c1 ? "ok" : "ÉCHEC", k1, NMONO);
        ok &= c1;
        int k2 = analyser(0, 1, CONSTANTES, graine, &rg);
        int c2 = k2 >= 1024;
        printf("  %s témoin constantes (x ⊕ RC₀) : noyau %d (attendu ≥ 1 024 : les fonctions linéaires)\n", c2 ? "ok" : "ÉCHEC", k2);
        ok &= c2;
        int k3 = analyser(0, 1, SBOX, graine, &rg);
        printf("  -- témoin S-box seule (M = I, RC = 0) : noyau %d (invariants quadratiques par nibble de la S-box)\n", k3);
        int k4 = analyser(0, 1, REEL, graine, &rg);
        printf("  -- tour 0 réel : noyau %d (rang %d sur %d colonnes)\n", k4, rg, NMONO + 1);
        printf("%s\n", ok ? "tous les contrôles passent" : "CONTRÔLE EN ÉCHEC");
        return ok ? 0 : 1;
    }
    if (!strcmp(mode, "reel") || !strcmp(mode, "tous")) {
        int nt = argc > 2 ? atoi(argv[2]) : B1_RT;
        if (nt < 1 || nt > B1_RT) nt = B1_RT;
        printf("{\"famille\": \"quadratique locale (nibble + arêtes du graphe)\", \"inconnues\": %d, \"tours\": [", NMONO);
        int total = 0;
        for (int t = 0; t < nt; t++) {
            int rg;
            int k = analyser(t, t + 1, REEL, graine ^ (uint64_t)t, &rg);
            total += k;
            printf("%s{\"t\": %d, \"noyau\": %d, \"rang\": %d}", t ? ", " : "", t, k, rg);
            fflush(stdout);
        }
        int rg;
        int kall = !strcmp(mode, "tous") ? analyser(0, nt, REEL, graine ^ 0xA11, &rg) : -1;
        printf("], \"somme_noyaux\": %d, \"noyau_tous_les_tours\": %d, \"aucun_invariant\": %s}\n", total, kall,
               total == 0 && kall <= 0 ? "true" : "false");
        return 0;
    }
    fprintf(stderr, "usage : invariants_quad1024 controle | reel [tours] | tous [tours]\n");
    return 2;
}
