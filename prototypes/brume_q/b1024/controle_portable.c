/* Contrôle du noyau portable à temps constant (b1024_portable.h) :
 *   1. égalité avec une référence dense écrite ici (matrice M explicite, S-box par table, SPEC § 2) sur des états
 *      aléatoires, pour chaque nombre de tours de 1 à 48 (toute la table des constantes), et sur des états limites ;
 *   2. emballage/déballage : aller-retour exact ;
 *   3. vitesse d'une permutation à 32 tours (indicative) ;
 *   4. -DCTGRIND : l'état est marqué non initialisé (Valgrind memcheck) ; tout branchement ou accès mémoire qui en dépend
 *      est signalé. Témoin : la même permutation avec la S-box par table (accès indexé par le secret) DOIT être signalée.
 *      valgrind --error-exitcode=9 ./controle_portable_ct ct      (aucune erreur attendue)
 *      valgrind --error-exitcode=9 ./controle_portable_ct temoin  (erreurs attendues)
 *   cc -O2 -Wall -Wextra -I prototypes/brume_q/b1024 prototypes/brume_q/b1024/controle_portable.c -o controle_portable
 * C portable seulement (aucune dépendance à la suite ni à brume1024.c). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "b1024_portable.h"
#ifdef CTGRIND
#include <valgrind/memcheck.h>
#endif

static uint8_t DM[256][256];

static int nbr(int v, int k)   /* SPEC § 2.2 */
{
    int f = v / 128, i = v % 128;
    return f == 0 ? 128 + (i + k) % 128 : ((i - k) % 128 + 128) % 128;
}

static void perm_dense(uint8_t w[128], int R)
{
    uint8_t x[256], y[256];
    for (int i = 0; i < 128; i++) { x[2 * i] = w[i] & 15; x[2 * i + 1] = w[i] >> 4; }
    for (int r = 0; r < R; r++) {
        for (int j = 0; j < 256; j++) x[j] = PP_SBOX[x[j] ^ B1_RC[r][j]];
        for (int v = 0; v < 256; v++) {
            uint8_t a = 0;
            for (int u = 0; u < 256; u++) if (DM[v][u]) a ^= pp_gmul(DM[v][u], x[u]);
            y[v] = a;
        }
        memcpy(x, y, 256);
    }
    for (int i = 0; i < 128; i++) w[i] = (uint8_t)(x[2 * i] | x[2 * i + 1] << 4);
}

static uint64_t gr = 0x9E3779B97F4A7C15ull;
static uint64_t alea(void)   /* splitmix64 */
{
    uint64_t z = (gr += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

#ifdef CTGRIND
/* témoin : la S-box lue dans une table à l'indice secret ; memcheck doit le signaler */
static void perm_temoin(uint8_t w[128], int R)
{
    pp_plans x;
    pp_deballer(w, x);
    for (int r = 0; r < R; r++) {
        uint8_t n[256];
        pp_emballer(x, n);   /* (réutilise les 128 premiers octets) */
        for (int i = 0; i < 128; i++)
            n[i] = (uint8_t)(PP_SBOX[n[i] & 15] | PP_SBOX[n[i] >> 4] << 4);
        pp_deballer(n, x);
        pp_tour(x, r);
    }
    pp_emballer(x, w);
}
#endif

int main(int argc, char **argv)
{
    if (!pp_init()) { printf("ÉCHEC : circuit de la S-box non conforme\n"); return 1; }
#ifdef CTGRIND
    uint8_t s[128];
    for (int i = 0; i < 128; i++) s[i] = (uint8_t)alea();
    VALGRIND_MAKE_MEM_UNDEFINED(s, sizeof s);
    if (argc > 1 && !strcmp(argv[1], "temoin"))
        perm_temoin(s, 2);
    else
        pp_perm(s, 32);
    VALGRIND_MAKE_MEM_DEFINED(s, sizeof s);   /* sortie publique (fin de la zone secrète) */
    printf("ctgrind (%s) : %02x…\n", argc > 1 ? argv[1] : "ct", s[0]);
    return 0;
#else
    (void)argc; (void)argv;
    for (int v = 0; v < 256; v++) {
        DM[v][v] = B1_CS[v];
        for (int g = 0; g < 6; g++) DM[v][nbr(v, B1_K[g])] = B1_CG[g][v];
    }
    int ok = 1, ncas = 0;
    /* 1. états aléatoires et limites, R = 1 … 48 */
    for (int R = 1; R <= B1_RT; R++)
        for (int e = 0; e < 6; e++) {
            uint8_t a[128], b[128];
            for (int i = 0; i < 128; i++)
                a[i] = e == 0 ? 0 : e == 1 ? 0xFF : e == 2 ? (i == 0 ? 1 : 0) : e == 3 ? (i == 127 ? 0x80 : 0) : (uint8_t)alea();
            memcpy(b, a, 128);
            pp_perm(a, R);
            perm_dense(b, R);
            ncas++;
            if (memcmp(a, b, 128)) { printf("ÉCHEC : R = %d, état %d différent de la référence dense\n", R, e); ok = 0; }
        }
    for (int n = 0; n < 200; n++) {   /* 32 tours, états aléatoires */
        uint8_t a[128], b[128];
        for (int i = 0; i < 128; i++) a[i] = b[i] = (uint8_t)alea();
        pp_perm(a, 32);
        perm_dense(b, 32);
        ncas++;
        if (memcmp(a, b, 128)) { printf("ÉCHEC : 32 tours, état aléatoire %d\n", n); ok = 0; }
    }
    /* 2. emballage : aller-retour */
    for (int n = 0; n < 1000; n++) {
        uint8_t a[128], b[128];
        pp_plans x;
        for (int i = 0; i < 128; i++) a[i] = (uint8_t)alea();
        pp_deballer(a, x);
        pp_emballer(x, b);
        if (memcmp(a, b, 128)) { printf("ÉCHEC : emballage\n"); ok = 0; break; }
    }
    /* 3. vitesse indicative */
    uint8_t s[128] = {0};
    int nb = 20000;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int n = 0; n < nb; n++) pp_perm(s, 32);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns = ((t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec)) / nb;
    printf("noyau portable : %d cas comparés à la référence dense (R = 1 … %d), %s ; %.0f ns par permutation à 32 tours "
           "(%02x)\n", ncas, B1_RT, ok ? "tous identiques" : "ÉCHEC", ns, s[0]);
    return ok ? 0 : 1;
#endif
}
