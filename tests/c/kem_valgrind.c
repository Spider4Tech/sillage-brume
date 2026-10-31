/* Sillage-KEM sous Valgrind (tests/test_c_kem_valgrind.py) :
 *   memoire : accès mémoire, chiffrés valides, altérés et remplis de 1, deux niveaux ;
 *   secret  : méthode ctgrind : x, y, σ_rej, les graines de x et y et μ sont marqués « non
 *             initialisés » ; Memcheck signale tout branchement ou accès qui en dépend ;
 *   temoin  : écriture directe d'une position secrète : doit être détectée.
 * Déclarés publics dans le code (SL_PUBLIC) : le nombre d'acceptations de sl_creux
 * (= poids, sauf probabilité < 2^-128), l'histogramme des fenêtres de la borne δ.
 */
#include <stdio.h>
#include <valgrind/memcheck.h>

#include "kem.c"

static int phase, appels;                           /* 1 : keygen, 2 : encaps, 0 : aucun marquage */

int sl_alea(void *buf, size_t len)
{
    extern int sl_alea_systeme(void *, size_t);
    int r = sl_alea_systeme(buf, len);
    appels++;
    if ((phase == 1 && appels >= 2) || phase == 2)  /* σ_h (1er appel) est public */
        VALGRIND_MAKE_MEM_UNDEFINED(buf, len);
    return r;
}

static void memoire(int niv)
{
    size_t lpk, lsk, lct, lss;
    sl_kem_tailles(niv, &lpk, &lsk, &lct, &lss);
    uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *ct = malloc(lct), s1[64], s2[64], s3[64];
    sl_kem_keygen(niv, pk, sk);
    sl_kem_encaps(niv, pk, ct, s1);
    sl_kem_decaps(niv, sk, ct, s2);
    int ok = !memcmp(s1, s2, lss);
    ct[lct / 2] ^= 1;
    sl_kem_decaps(niv, sk, ct, s3);
    ok &= memcmp(s1, s3, lss) != 0;
    memset(ct, 0xff, lct);
    sl_kem_decaps(niv, sk, ct, s3);
    ok &= memcmp(s1, s3, lss) != 0;
    printf("niveau %d : correction et rejets %s\n", niv, ok ? "OK" : "ÉCHEC");
    free(pk); free(sk); free(ct);
    if (!ok)
        exit(1);
}

static void secret_(int niv)
{
    const params_t *p = &P[niv];
    size_t lpk, lsk, lct, lss, nb = NB(p->n);
    sl_kem_tailles(niv, &lpk, &lsk, &lct, &lss);
    uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *ct = malloc(lct), s1[64], s2[64];
    phase = 1; appels = 0;
    sl_kem_keygen(niv, pk, sk);
    phase = 0;
    VALGRIND_MAKE_MEM_DEFINED(pk, lpk);             /* s est public */
    VALGRIND_MAKE_MEM_DEFINED(sk + 2 * nb, 32);     /* σ_h */
    VALGRIND_MAKE_MEM_DEFINED(sk + 2 * nb + 64, nb);
    phase = 2;
    sl_kem_encaps(niv, pk, ct, s1);
    phase = 0;
    VALGRIND_MAKE_MEM_DEFINED(ct, lct);             /* le chiffré est public */
    sl_kem_decaps(niv, sk, ct, s2);
    VALGRIND_MAKE_MEM_DEFINED(s1, lss);
    VALGRIND_MAKE_MEM_DEFINED(s2, lss);
    printf("niveau %d : %s\n", niv, memcmp(s1, s2, lss) ? "ÉCHEC" : "décapsulation marquée, secret retrouvé");
    free(pk); free(sk); free(ct);
}

static void temoin(void)
{
    uint64_t v[8] = {0};
    uint32_t pos = 123;
    VALGRIND_MAKE_MEM_UNDEFINED(&pos, sizeof pos);
    v[pos >> 6] ^= 1ULL << (pos & 63);              /* accès à un indice secret */
    VALGRIND_MAKE_MEM_DEFINED(&pos, sizeof pos);
    printf("%d\n", (int)(v[1] & 1));
    /* le marquage atteint bien la clé : un branchement sur sk doit être signalé */
    size_t lpk, lsk, lct, lss;
    sl_kem_tailles(0, &lpk, &lsk, &lct, &lss);
    uint8_t *pk = malloc(lpk), *sk = malloc(lsk);
    phase = 1; appels = 0;
    sl_kem_keygen(0, pk, sk);
    phase = 0;
    int bits = 0;
    for (size_t i = 0; i < NB(P[0].n); i++)
        if (sk[i])
            bits++;
    printf("%d\n", bits);
    free(pk); free(sk);
}

int main(int argc, char **argv)
{
    const char *m = argc > 1 ? argv[1] : "memoire";
    if (!strcmp(m, "temoin")) {
        temoin();
        return 0;
    }
    for (int niv = 0; niv < 2; niv++) {
        if (!strcmp(m, "secret"))
            secret_(niv);
        else
            memoire(niv);
    }
    return 0;
}
