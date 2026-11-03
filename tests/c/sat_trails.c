/* BRUME-512 : nombre minimal de S-box actives d'une caractéristique différentielle ou d'un trail linéaire sur R tours,
 * avec la VRAIE couche linéaire (bit à bit) et la vraie DDT / LAT de la S-box (PREUVES § 4.2, Proposition 10).
 *
 * Le modèle tronqué (CP-SAT, Proposition 10) admet toute annulation et ne dépasse pas 4 S-box par tour. Ici, méthode de
 * Sun, Wang et Wang (ToSC 2021, « Accelerating the search of differential and linear characteristics with the SAT
 * method ») : variables = différences (ou masques) bit à bit en entrée et en sortie de chaque S-box ; transitions
 * impossibles de la DDT (ou de la LAT) interdites clause par clause ; couche linéaire exacte en XOR (M pour les
 * différences, Mᵀ pour les masques) ; cardinalité « au plus K S-box actives » par compteur séquentiel (Sinz 2005) ;
 * entrée non nulle. UNSAT : aucune caractéristique (aucun trail) de R tours n'a ≤ K S-box actives, résultat EXACT
 * (aucune hypothèse de Markov : seule la faisabilité compte). SAT : la solution est relue et revérifiée ici,
 * indépendamment du solveur (DDT/LAT et couche linéaire recalculées).
 *
 * Contraintes ajoutées, valides et seulement destinées à élaguer (à la Matsui) : toute fenêtre de 2 tours consécutifs a
 * ≥ B = 8 S-box actives (Proposition 10) ; si --fenetres est donné, les bornes déjà prouvées pour des fenêtres plus
 * courtes (b2 b3 …) le remplacent.
 *
 *     sat_trails diff|lin R K [délai_s] [--cnf] [--fenetres b2 b3 …]
 *   → code 10 (SAT, trail vérifié écrit sur stdout), 20 (UNSAT), 0 (indécis au délai), autre : erreur.
 * Le solveur est CryptoMiniSat 5 (XOR natifs) ; --cnf écrit les XOR en clauses (pour CaDiCaL et une preuve DRAT).
 * Outil hors batterie (il demande cryptominisat5 ou cadical) : make -C tests/c build/sat_trails.
 * Résultats (2026-11-03) : 2 tours, minimum exact 8 en différentiel et en linéaire, atteint (1 puis 7, 7 puis 1) ;
 * 3 tours, différentiel : K = 13, 16 et 20 indécis à 600 s. La méthode ne passe pas l'échelle de 128 S-box par tour, comme le
 * notent les auteurs pour les états non légers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "brume512_tables.h"

static int gmul(int a, int b)
{
    int r = 0;
    for (int i = 0; i < 4; i++) {
        if (b & 1) r ^= a;
        b >>= 1; a <<= 1;
        if (a & 16) a ^= BR_POLY;
    }
    return r & 15;
}

/* matrice binaire de M : Mb[o][i] = 1 si le bit i de y entre dans le bit o de x = M·y (bit 4v + k) */
static unsigned char Mb[512][512];
static void construire_M(void)
{
    for (int e = 0; e < BR_ARETES; e++) {
        int v = e / BR_DEG, j = BR_EI[e], c = BR_EC[e];
        for (int b = 0; b < 4; b++) {
            int col = gmul(c, 1 << b);
            for (int k = 0; k < 4; k++)
                if ((col >> k) & 1) Mb[4 * v + k][4 * j + b] ^= 1;
        }
    }
}

static int faisable[16][16];            /* DDT (diff) ou LAT (lin) non nulle */
static void construire_table(int lin)
{
    for (int a = 0; a < 16; a++)
        for (int b = 0; b < 16; b++) {
            int n = 0;
            for (int x = 0; x < 16; x++)
                if (lin) n += __builtin_parity((a & x) ^ (b & BR_SBOX[x])) ? -1 : 1;
                else n += (BR_SBOX[x] ^ BR_SBOX[x ^ a]) == b;
            faisable[a][b] = lin ? n != 0 : n != 0;
        }
}

/* ---------------------------------------------------------------- CNF */
static FILE *F;
static long nv, nc;
static int CNF_PUR;
static void clause(const int *l, int n) { for (int i = 0; i < n; i++) fprintf(F, "%d ", l[i]); fputs("0\n", F); nc++; }
static void c2(int a, int b) { int l[2] = {a, b}; clause(l, 2); }
static void c3(int a, int b, int c) { int l[3] = {a, b, c}; clause(l, 3); }

/* XOR des variables v[0..n-1] = 0 */
static void xor0(const int *v, int n)
{
    if (!CNF_PUR) {
        fputs("x", F);
        for (int i = 0; i < n; i++) fprintf(F, "%d ", i ? v[i] : -v[i]);   /* « x » de CryptoMiniSat : XOR = 1 ; nier un littéral donne XOR = 0 */
        fputs("0\n", F); nc++;
        return;
    }
    /* chaîne : t1 = v0 ⊕ v1, t2 = t1 ⊕ v2, …, t_{n-1} = 0 */
    int acc = v[0];
    for (int i = 1; i < n; i++) {
        int t = (i == n - 1) ? 0 : (int)++nv;
        int b = v[i];
        if (t == 0) {                     /* acc ⊕ b = 0 */
            c2(-acc, b); c2(acc, -b);
        } else {                          /* t = acc ⊕ b */
            c3(-t, acc, b); c3(-t, -acc, -b); c3(t, -acc, b); c3(t, acc, -b);
            acc = t;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage : sat_trails diff|lin R K [délai_s] [--cnf] [--fenetres b2 b3 …]\n"); return 2; }
    if (strcmp(argv[1], "diff") && strcmp(argv[1], "lin")) { fprintf(stderr, "mode : diff ou lin\n"); return 2; }
    int lin = !strcmp(argv[1], "lin"), R = atoi(argv[2]), K = atoi(argv[3]);
    if (R < 1 || R > 64 || K < 1 || K > 128 * R) { fprintf(stderr, "R dans [1, 64], K dans [1, 128·R]\n"); return 2; }
    int delai = argc > 4 && argv[4][0] != '-' ? atoi(argv[4]) : 600;
    int fen[64] = {0};                    /* fen[t] : borne prouvée pour t tours consécutifs */
    fen[2] = 8;
    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "--cnf")) CNF_PUR = 1;
        if (!strcmp(argv[i], "--fenetres"))
            for (int t = 2; i + 1 < argc && argv[i + 1][0] != '-'; t++) fen[t] = atoi(argv[++i]);
    }
    construire_M();
    construire_table(lin);

    /* variables : entrée in[r][p] et sortie out[r][p] de la couche S du tour r (512 bits), activité a[r][v] */
    int IN = 0, OUT = R * 512, ACT = 2 * R * 512;
    nv = ACT + R * 128;
#define VIN(r, p) (IN + (r) * 512 + (p) + 1)
#define VOUT(r, p) (OUT + (r) * 512 + (p) + 1)
#define VA(r, v) (ACT + (r) * 128 + (v) + 1)
    char chemin[256];
    /* fichiers dans un répertoire privé (mkdtemp, mode 0700) : pas de nom prévisible dans un répertoire partagé */
    const char *rep = getenv("TMPDIR") && *getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    char dossier[200];
    snprintf(dossier, sizeof dossier, "%s/sat_trails_XXXXXX", rep);
    if (strchr(dossier, '\'') || !mkdtemp(dossier)) { perror("mkdtemp"); return 2; }
    snprintf(chemin, sizeof chemin, "%s/probleme.cnf", dossier);
    F = fopen(chemin, "w");
    if (!F) { perror(chemin); return 2; }
    fprintf(F, "p cnf 1 1\n");            /* en-tête réécrit à la fin (CryptoMiniSat et CaDiCaL l'acceptent approximatif) */
    for (int r = 0; r < R; r++)
        for (int v = 0; v < 128; v++) {
            int a = VA(r, v), x[4], y[4];
            for (int b = 0; b < 4; b++) x[b] = VIN(r, 4 * v + b), y[b] = VOUT(r, 4 * v + b);
            for (int b = 0; b < 4; b++) c2(-x[b], a);
            { int l[5] = {-a, x[0], x[1], x[2], x[3]}; clause(l, 5); }
            for (int din = 0; din < 16; din++)
                for (int dout = 0; dout < 16; dout++)
                    if (!faisable[din][dout]) {
                        int l[8];
                        for (int b = 0; b < 4; b++) {
                            l[b] = (din >> b & 1) ? -x[b] : x[b];
                            l[4 + b] = (dout >> b & 1) ? -y[b] : y[b];
                        }
                        clause(l, 8);
                    }
        }
    /* couche linéaire entre tours : diff : in[r+1] = M·out[r] ; lin : out[r] = Mᵀ·in[r+1] */
    int tmp[600];
    for (int r = 0; r + 1 < R; r++)
        for (int o = 0; o < 512; o++) {
            int n = 0;
            if (!lin) {
                for (int i = 0; i < 512; i++) if (Mb[o][i]) tmp[n++] = VOUT(r, i);
                tmp[n++] = VIN(r + 1, o);
            } else {
                for (int i = 0; i < 512; i++) if (Mb[i][o]) tmp[n++] = VIN(r + 1, i);
                tmp[n++] = VOUT(r, o);
            }
            xor0(tmp, n);
        }
    /* entrée non nulle */
    { int l[128]; for (int v = 0; v < 128; v++) l[v] = VA(0, v); clause(l, 128); }
    /* cardinalité ≤ K (compteur séquentiel de Sinz) sur les R·128 activités */
    {
        int n = R * 128;
        long base = nv;                   /* s[i][j] = « au moins j+1 parmi les i+1 premières » */
#define S(i, j) ((int)(base + (long)(i) * K + (j) + 1))
        nv += (long)n * K;
        for (int i = 0; i < n; i++) {
            int xi = ACT + i + 1;
            c2(-xi, S(i, 0));
            if (i > 0) for (int j = 0; j < K; j++) c2(-S(i - 1, j), S(i, j));
            if (i > 0) for (int j = 1; j < K; j++) c3(-xi, -S(i - 1, j - 1), S(i, j));
            if (i > 0) c2(-xi, -S(i - 1, K - 1));
        }
#undef S
    }
    /* fenêtres (élagage valide) : ≥ fen[t] actives sur t tours consécutifs, par compteur « au moins » */
    for (int t = 2; t <= R && t < 64; t++) {
        if (!fen[t] || (t == R && fen[t] <= 1)) continue;
        for (int r0 = 0; r0 + t <= R; r0++) {
            /* « au moins m parmi n » ⇔ « au plus n − m parmi les négations » */
            int n = t * 128, m = fen[t], Kc = n - m;
            if (Kc < 0) continue;
            long base = nv;
#define S(i, j) ((int)(base + (long)(i) * Kc + (j) + 1))
            nv += (long)n * (Kc > 0 ? Kc : 1);
            for (int i = 0; i < n; i++) {
                int xi = -(ACT + r0 * 128 + i + 1);       /* littéral « inactive » */
                if (Kc == 0) { int l[1] = {-xi}; clause(l, 1); continue; }
                c2(-xi, S(i, 0));
                if (i > 0) for (int j = 0; j < Kc; j++) c2(-S(i - 1, j), S(i, j));
                if (i > 0) for (int j = 1; j < Kc; j++) c3(-xi, -S(i - 1, j - 1), S(i, j));
                if (i > 0) c2(-xi, -S(i - 1, Kc - 1));
            }
#undef S
        }
    }
    fclose(F);
    {   /* en-tête exact */
        char cmd[512];
        snprintf(cmd, sizeof cmd, "sed -i '1s/.*/p cnf %ld %ld/' '%s'", nv, nc, chemin);
        if (system(cmd)) { fprintf(stderr, "sed : échec\n"); return 2; }
    }
    fprintf(stderr, "%s R=%d K=%d : %ld variables, %ld clauses%s\n", argv[1], R, K, nv, nc, CNF_PUR ? " (CNF pure)" : " (XOR natifs)");

    char cmd[1024], sortie[300];
    snprintf(sortie, sizeof sortie, "%s.out", chemin);
    if (CNF_PUR) snprintf(cmd, sizeof cmd, "timeout %d cadical -q '%s' > '%s'", delai, chemin, sortie);
    else snprintf(cmd, sizeof cmd, "cryptominisat5 --verb 0 --maxtime %d '%s' > '%s'", delai, chemin, sortie);
    int rc = system(cmd);
    (void)rc;
    FILE *g = fopen(sortie, "r");
    if (!g) { perror(sortie); return 2; }
    static signed char val[4000000];
    char ligne[1 << 16];
    int etat = 0;                         /* 10 SAT, 20 UNSAT, 0 indécis */
    while (fgets(ligne, sizeof ligne, g)) {
        if (!strncmp(ligne, "s SATISFIABLE", 13)) etat = 10;
        else if (!strncmp(ligne, "s UNSATISFIABLE", 15)) etat = 20;
        else if (ligne[0] == 'v') {
            char *p = ligne + 1;
            for (;;) {
                long l = strtol(p, &p, 10);
                if (!l) break;
                long a = l > 0 ? l : -l;
                if (a < (long)sizeof val) val[a] = l > 0;
            }
        }
    }
    fclose(g);
    remove(chemin);
    remove(sortie);
    rmdir(dossier);
    if (etat == 20) { printf("UNSAT %s R=%d K=%d\n", argv[1], R, K); return 20; }
    if (etat != 10) { printf("INDÉCIS %s R=%d K=%d (délai %d s)\n", argv[1], R, K, delai); return 0; }

    /* vérification indépendante de la solution */
    int ok = 1, actives = 0, par_tour[64];
    unsigned char x[64][512], y[64][512];
    for (int r = 0; r < R; r++) {
        par_tour[r] = 0;
        for (int p = 0; p < 512; p++) x[r][p] = (unsigned char)val[VIN(r, p)], y[r][p] = (unsigned char)val[VOUT(r, p)];
        for (int v = 0; v < 128; v++) {
            int din = 0, dout = 0;
            for (int b = 0; b < 4; b++) din |= x[r][4 * v + b] << b, dout |= y[r][4 * v + b] << b;
            ok &= faisable[din][dout];
            if (din) actives++, par_tour[r]++;
        }
    }
    for (int r = 0; r + 1 < R; r++)
        for (int o = 0; o < 512; o++) {
            int s = 0;
            if (!lin) { for (int i = 0; i < 512; i++) s ^= Mb[o][i] & y[r][i]; ok &= s == x[r + 1][o]; }
            else { for (int i = 0; i < 512; i++) s ^= Mb[i][o] & x[r + 1][i]; ok &= s == y[r][o]; }
        }
    ok &= actives >= 1 && actives <= K;
    printf("SAT %s R=%d K=%d : trail de %d S-box actives (", argv[1], R, K, actives);
    for (int r = 0; r < R; r++) printf("%s%d", r ? "-" : "", par_tour[r]);
    printf(") %s\n", ok ? "vérifié" : "INVALIDE");
    return ok ? 10 : 3;
}
