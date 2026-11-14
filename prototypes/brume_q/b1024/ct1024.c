/* BRUME-1024q sous Valgrind (méthode ctgrind, comme tests/c/kem_valgrind.c) : les secrets sont marqués « non définis »
 * pour memcheck ; tout branchement ou accès mémoire qui en dépend est alors signalé. Modes :
 *   secret  : permutation à 1 état, noyau à 32 états, AEAD (clé et clair secrets ; chiffrement, déchiffrement, déchiffrement
 *             vérifié accepté et rejeté),
 *             éponge et arbre sur un message secret (longueur publique), lot bitslicé de 256 feuilles secrètes ; les sorties, rendues définies, sont
 *             comparées au même calcul sans marquage (« secret retrouvé ») ;
 *   memoire : le même calcul sans marquage (erreurs mémoire et fuites) ;
 *   temoin  : lecture d'une table à un indice secret : doit être détectée.
 *   gcc -O3 -g -mavx2 -fopenmp -DSANS_MAIN -DSL_VALGRIND -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *       prototypes/brume_q/b1024/ct1024.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm -o ct1024
 *   OMP_NUM_THREADS=1 valgrind --error-exitcode=0 ./ct1024 secret */
#include <valgrind/memcheck.h>

#include "brume1024.c"

static int marquer;

static void secret(void *p, size_t n)
{
    if (marquer)
        VALGRIND_MAKE_MEM_UNDEFINED(p, n);
}

static void public(void *p, size_t n)
{
    VALGRIND_MAKE_MEM_DEFINED(p, n);
}

/* tout le calcul ; out reçoit une empreinte de toutes les sorties */
static void calcul(uint8_t out[64])
{
    uint8_t w[128], cle[64], nonce[24], aad[9], m[3 * FEUILLE + 5], c[200], d[200], tag[32], tag2[32], h[64];
    uint8_t (*e)[128] = aligned_alloc(64, 32 * 128);
    for (size_t i = 0; i < sizeof m; i++)
        m[i] = (uint8_t)(i * 7 + 3);
    for (int i = 0; i < 128; i++)
        w[i] = (uint8_t)(i * 13 + 1);
    for (int i = 0; i < 64; i++)
        cle[i] = (uint8_t)(i ^ 0x5A);
    memset(nonce, 0x11, 24);
    memset(aad, 0x22, 9);
    for (int j = 0; j < 32; j++)
        for (int i = 0; i < 128; i++)
            e[j][i] = (uint8_t)(i + 3 * j);
    secret(w, 128);
    secret(e, 32 * 128);
    secret(cle, 64);
    secret(m, sizeof m);
    perm1(w, R1);
    lot(e, R1);
    aead(perm1, cle, nonce, aad, 9, m, 200, 0, c, tag);
    public(c, 200);                     /* le chiffré est public */
    aead(perm1, cle, nonce, aad, 9, c, 200, 1, d, tag2);
    uint8_t diff = 0;                   /* comparaison des tags sans branchement */
    for (int i = 0; i < 32; i++)
        diff |= tag[i] ^ tag2[i];
    public(&diff, 1);                   /* le verdict est public */
    {                                   /* déchiffrement vérifié : acceptation puis rejet (verdict public, SL_PUBLIC) */
        uint8_t pv[200], tg2[32];
        int r1 = aead_ouvrir(cle, nonce, aad, 9, c, 200, tag, pv);
        memcpy(tg2, tag, 32);
        tg2[5] ^= 1;
        int r2 = aead_ouvrir(cle, nonce, aad, 9, c, 200, tg2, pv);
        diff |= (uint8_t)((r1 != 0) | (r2 != -1));
    }
    arbre(m, sizeof m, h, 64, 1);       /* 4 feuilles, chemin par feuille (sous 32 feuilles par thread) */
    for (int i = 0; i < 64; i++)
        out[i] = (uint8_t)(w[i] ^ e[i % 32][i] ^ e[31 - i % 32][64 + i] ^ tag[i % 32] ^ d[i] ^ h[i] ^ (diff ? 0xFF : 0));
    eponge(m, 1000, DOM_SEQ, h, 64);    /* XOF sur un message secret */
    for (int i = 0; i < 64; i++)
        out[i] ^= h[i];
    feuilles(m, 3, d);                  /* noyau à 32 états dans le chemin de l'arbre (lot partiel) */
    for (int i = 0; i < 64; i++)
        out[i] ^= d[i];
    {                                   /* noyau bitslicé : 256 feuilles secrètes (transpositions et 103 permutations) */
        uint8_t *gm = malloc((size_t)256 * FEUILLE), *cv = malloc((size_t)256 * CVL);
        for (size_t i = 0; i < (size_t)256 * FEUILLE; i++)
            gm[i] = (uint8_t)(i * 11 + 5);
        secret(gm, (size_t)256 * FEUILLE);
        feuilles256(gm, cv);
        for (int i = 0; i < 64; i++)
            out[i] ^= cv[i] ^ cv[255 * CVL + i];
        free(gm);
        free(cv);
    }
    if (marquer) {                      /* le marquage a-t-il atteint les sorties ? (bits de validité, sans erreur) */
        uint8_t vb[64];
        int n = 0;
        if (VALGRIND_GET_VBITS(out, vb, 64) == 1)
            for (int i = 0; i < 64; i++)
                n += vb[i] == 0xFF;
        printf("octets de sortie marqués non définis : %d/64\n", n);
    }
    public(out, 64);
    free(e);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "secret";
    if (!bref_init() || !ref_init() || !init_noyaux())
        return 2;
    prepare_iv();
    if (!strcmp(mode, "temoin")) {
        uint8_t pos = 7, x;
        VALGRIND_MAKE_MEM_UNDEFINED(&pos, 1);
        x = SI[pos & 15];               /* accès à une adresse secrète */
        VALGRIND_MAKE_MEM_DEFINED(&x, 1);
        printf("temoin %u\n", x);
        return 0;
    }
    uint8_t a[64], b[64];
    marquer = 0;
    calcul(a);
    marquer = !strcmp(mode, "secret");
    calcul(b);
    printf("%s : %s\n", mode, memcmp(a, b, 64) ? "ÉCHEC" : "secret retrouvé");
    return 0;
}
