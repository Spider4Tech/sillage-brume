/* Sillage-SIG sous Valgrind (tests/test_c_sig_valgrind.py) :
 *   sig_valgrind memoire  : accès mémoire, sur chemins valides et entrées malformées, deux niveaux ;
 *   sig_valgrind secret   : méthode ctgrind : les secrets sont marqués « non initialisés », et
 *                           Memcheck signale tout branchement ou accès mémoire qui en dépend. h1
 *                           et h2, publics (dans la signature), sont redéclarés définis par sig.c.
 *   sig_valgrind temoin   : le chemin direct (non constant-time) doit être détecté, sinon
 *                           l'instrument ne prouve rien.
 * Couvert par « secret » : la graine de x, x_A, Q, P et toutes les valeurs qui en dérivent
 * (graine maîtresse, arbre, parts, aux, diffusions).
 */
#include <stdio.h>
#include <valgrind/memcheck.h>

#include "sig.c"

static int phase, appels;                         /* 1 : keygen, 0 : aucun marquage */

int sl_alea(void *buf, size_t len)
{
    extern int sl_alea_systeme(void *, size_t);
    int r = sl_alea_systeme(buf, len);
    appels++;
    if (phase == 1 && appels == 2)                /* graine de x (après seed_H) */
        VALGRIND_MAKE_MEM_UNDEFINED(buf, len);
    return r;
}

static void memoire(int niv)
{
    size_t lpk, lsk, lmax, ls = 0;
    sl_sig_tailles(niv, &lpk, &lsk, &lmax);
    uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *sig = malloc(lmax), msg[3] = "abc";
    sl_sig_keygen(niv, pk, sk);
    sl_sig_sign(niv, sk, pk, msg, 3, sig, &ls);
    int ok = sl_sig_verify(niv, pk, msg, 3, sig, ls);
    ok &= !sl_sig_verify(niv, pk, msg, 2, sig, ls);
    for (size_t coupe = 0; coupe < ls; coupe += ls / 7 + 1)      /* tronquées */
        ok &= !sl_sig_verify(niv, pk, msg, 3, sig, coupe);
    ok &= !sl_sig_verify(niv, pk, msg, 3, sig, 0);
    for (size_t pos = 0; pos < ls; pos += ls / 5 + 1) {          /* altérées */
        sig[pos] ^= 1;
        ok &= !sl_sig_verify(niv, pk, msg, 3, sig, ls);
        sig[pos] ^= 1;
    }
    memset(sig, 0xff, ls);                                        /* pleine de 1 */
    ok &= !sl_sig_verify(niv, pk, msg, 3, sig, ls);
    memset(sig, 0, ls);
    ok &= !sl_sig_verify(niv, pk, msg, 3, sig, ls);
    printf("niveau %d : correction et rejets %s\n", niv, ok ? "OK" : "ÉCHEC");
    free(pk); free(sk); free(sig);
    if (!ok) exit(1);
}

static void secret(int niv)
{
    size_t lpk, lsk, lmax, ls = 0;
    sl_sig_tailles(niv, &lpk, &lsk, &lmax);
    uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *sig = malloc(lmax), msg[3] = "abc";
    phase = 1; appels = 0;
    sl_sig_keygen(niv, pk, sk);
    phase = 0;
    VALGRIND_MAKE_MEM_DEFINED(pk, lpk);                           /* y est public */
    VALGRIND_MAKE_MEM_UNDEFINED(sk, lsk);
    sl_sig_sign(niv, sk, pk, msg, 3, sig, &ls);
    VALGRIND_MAKE_MEM_DEFINED(&ls, sizeof ls);
    VALGRIND_MAKE_MEM_DEFINED(sig, ls);
    printf("niveau %d : signature marquée, longueur %zu\n", niv, ls);
    VALGRIND_MAKE_MEM_DEFINED(sk, lsk);
    printf("niveau %d : %s\n", niv, sl_sig_verify(niv, pk, msg, 3, sig, ls) ? "valide" : "INVALIDE");
    free(pk); free(sk); free(sig);
}

static void temoin(void)
{
    const sp_t *p = &SP[0];
    size_t rw = NW(p->r);
    uint8_t seed[32] = {1}, *xa = malloc(XB(p));
    uint64_t acc[NW(1229) + 1] = {0};
    sl_alea(xa, XB(p));
    const uint64_t *H = matrice(0, seed);
    VALGRIND_MAKE_MEM_UNDEFINED(xa, XB(p));
    for (uint32_t j = 0; j < p->k; j++)                           /* saute les colonnes des bits nuls */
        if (xa[j >> 3] >> (j & 7) & 1)
            for (size_t q = 0; q < rw; q++)
                acc[q] ^= H[(size_t)j * rw + q];
    __asm__ volatile("" : : "r"(acc) : "memory");                 /* résultat observé : gcc supprimerait la boucle */
    free(xa);
}

int main(int argc, char **argv)
{
    sl_init();
    const char *m = argc > 1 ? argv[1] : "memoire";
    if (!strcmp(m, "temoin")) { temoin(); return 0; }
    for (int niv = 0; niv < 2; niv++) {
        if (!strcmp(m, "secret")) secret(niv); else memoire(niv);
    }
    return 0;
}
