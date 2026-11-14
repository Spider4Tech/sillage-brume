/* Seconde implémentation de BRUME-1024q, écrite d'après SPEC.md seul (MIGRATION_V06.md, étape 1) : C portable, sans
 * intrinsèques, sans rien reprendre de brume1024.c. Elle ne prend que les données normatives K, CS, CG de b1024_tables.h,
 * en vérifie l'empreinte (SPEC § 2.2), recalcule les constantes de tour (SPEC § 2.3) au lieu de lire B1_RC, puis calcule
 * les 18 vecteurs de test (SPEC § 4) et les compare à kat_b1024.txt.
 * Ni constant-time, ni rapide : une référence de conformité. SHAKE256 vient de sillage/c/commun.c (indépendant de BRUME).
 *   cc -O2 -I sillage/c -I prototypes/brume_q/b1024 prototypes/brume_q/b1024/spec_ref.c sillage/c/commun.c \
 *      sillage/c/brume512.c -lm -o spec_ref && ./spec_ref prototypes/brume_q/b1024/kat_b1024.txt */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b1024_tables.h"
#include "sillage.h"

static const uint8_t SB[16] = {10, 13, 4, 1, 2, 6, 5, 0, 11, 15, 14, 12, 7, 8, 9, 3};   /* SPEC § 2.1 */
static uint8_t MU[256][256], RCs[32][256];

static uint8_t gmul(uint8_t a, uint8_t b)   /* GF(2^4) modulo t^4 + t + 1 */
{
    uint8_t r = 0;
    for (int k = 0; k < 4; k++)
        if (b >> k & 1) {
            uint8_t t = a;
            for (int j = 0; j < k; j++) t = (uint8_t)((t << 1) ^ ((t & 8) ? 0x13 : 0));
            r ^= t;
        }
    return r & 15;
}
static int voisin(int v, int k)   /* SPEC § 2.2 */
{
    int f = v / 128, i = v % 128;
    return f == 0 ? 128 + (i + k) % 128 : ((i - k) % 128 + 128) % 128;
}

static void P(uint8_t s[128])   /* SPEC § 2.4, sur l'état emballé */
{
    uint8_t x[256], y[256];
    for (int i = 0; i < 128; i++) { x[2 * i] = s[i] & 15; x[2 * i + 1] = s[i] >> 4; }
    for (int r = 0; r < 32; r++) {
        for (int j = 0; j < 256; j++) x[j] = SB[x[j] ^ RCs[r][j]];
        for (int v = 0; v < 256; v++) {
            uint8_t a = 0;
            for (int u = 0; u < 256; u++) if (MU[v][u]) a ^= gmul(MU[v][u], x[u]);
            y[v] = a;
        }
        memcpy(x, y, 256);
    }
    for (int i = 0; i < 128; i++) s[i] = (uint8_t)(x[2 * i] | x[2 * i + 1] << 4);
}

static void cadre(uint8_t s[128], int mode)   /* SPEC § 3.1 */
{
    s[121] = 32; s[122] = 0; s[123] = 0; s[124] = 160; s[125] = 0x10; s[126] = 0x71; s[127] = (uint8_t)mode;
}

static void sponge(const uint8_t *M, size_t len, int dom, uint8_t *out, size_t l)   /* SPEC § 3.2 */
{
    uint8_t s[128] = {0};
    cadre(s, 5);
    P(s);
    size_t n = len / 80 + 1;
    for (size_t i = 0; i < n; i++) {
        for (size_t k = 0; k < 80; k++) {
            size_t p = 80 * i + k;
            s[k] ^= p < len ? M[p] : (p == len ? 0x01 : 0);
        }
        if (i + 1 == n) s[127] ^= (uint8_t)(dom * 16);
        P(s);
    }
    for (size_t o = 0; o < l; o += 80) {
        size_t q = l - o < 80 ? l - o : 80;
        memcpy(out + o, s, q);
        if (o + 80 < l) P(s);
    }
}

static void H(const uint8_t *M, size_t len, uint8_t *out, size_t l)   /* SPEC § 3.4 */
{
    if (len <= 8192) { sponge(M, len, 10, out, l); return; }
    size_t k = (len + 8191) / 8192, lr = 64 * k + 12;
    uint8_t *R = malloc(lr);
    for (size_t i = 0; i < k; i++) {
        size_t li = len - 8192 * i < 8192 ? len - 8192 * i : 8192;
        sponge(M + 8192 * i, li, 8, R + 64 * i, 64);
    }
    for (int b = 0; b < 8; b++) R[64 * k + b] = (uint8_t)(k >> (56 - 8 * b));
    R[64 * k + 8] = 0; R[64 * k + 9] = 0; R[64 * k + 10] = 0x20; R[64 * k + 11] = 0;
    sponge(R, lr, 9, out, l);
    free(R);
}

static void enc(const uint8_t K[64], const uint8_t N[24], const uint8_t *A, size_t la, const uint8_t *X, size_t lx,
                uint8_t *C, uint8_t T[32])   /* SPEC § 3.5 */
{
    uint8_t s[128] = {0};
    memcpy(s, K, 64);
    memcpy(s + 64, N, 24);
    cadre(s, 3);
    P(s);
    size_t n = la / 80 + 1;
    for (size_t i = 0; i < n; i++) {
        for (size_t k = 0; k < 80; k++) {
            size_t p = 80 * i + k;
            s[k] ^= p < la ? A[p] : (p == la ? 0x01 : 0);
        }
        if (i + 1 == n) s[127] ^= 1 * 16;
        P(s);
    }
    size_t i = 0;
    for (; i + 80 <= lx; i += 80) {
        for (int k = 0; k < 80; k++) { C[i + k] = X[i + k] ^ s[k]; s[k] = C[i + k]; }
        P(s);
    }
    size_t l = lx - i;
    for (size_t k = 0; k < l; k++) { C[i + k] = X[i + k] ^ s[k]; s[k] = C[i + k]; }
    s[l] ^= 0x01;
    s[127] ^= 2 * 16;
    P(s);
    for (int k = 0; k < 8; k++) s[k] ^= (uint8_t)((uint64_t)lx >> (8 * k));
    s[8] ^= 0x01;
    s[127] ^= 4 * 16;
    P(s);
    memcpy(T, s, 32);
}

static void hexa(const uint8_t *x, size_t n, char *o)
{
    for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", x[i]);
}

int main(int argc, char **argv)
{
    /* données normatives et empreinte (SPEC § 2.2) */
    uint8_t d[6 + 256 + 1536], e[32];
    for (int g = 0; g < 6; g++) d[g] = (uint8_t)B1_K[g];
    memcpy(d + 6, B1_CS, 256);
    for (int g = 0; g < 6; g++) memcpy(d + 6 + 256 + 256 * g, B1_CG[g], 256);
    sl_shake256(d, sizeof d, e, 32);
    char eh[65];
    hexa(e, 32, eh);
    int ok_emp = !strcmp(eh, "6439f5c30aa7f23c48068818c9b654a3465a14e78fdab723beff219ecd7a0040");
    for (int v = 0; v < 256; v++) {
        MU[v][v] = B1_CS[v];
        for (int g = 0; g < 6; g++) MU[v][voisin(v, B1_K[g])] = B1_CG[g][v];
    }
    /* constantes de tour recalculées (SPEC § 2.3), puis comparées à la table du prototype */
    static uint8_t F[48 * 256];
    sl_shake256((const uint8_t *)"BRUME-1024-v1-RC", 16, F, sizeof F);
    int ok_rc = 1;
    for (int r = 0; r < 32; r++)
        for (int j = 0; j < 256; j++) { RCs[r][j] = F[256 * r + j] % 16; ok_rc &= RCs[r][j] == B1_RC[r][j]; }
    printf("empreinte des tables : %s ; constantes recalculées = table : %s\n", ok_emp ? "conforme" : "DIFFÉRENTE", ok_rc ? "oui" : "NON");
    /* vecteurs de test (SPEC § 4) */
    const size_t TM = 300 * 8192 + 5;
    uint8_t *m = malloc(TM), K[64], N[24], out[200], *C = malloc(1000), T[32];
    for (size_t i = 0; i < TM; i++) m[i] = (uint8_t)(i % 251);
    for (int i = 0; i < 64; i++) K[i] = (uint8_t)i;
    for (int i = 0; i < 24; i++) N[i] = (uint8_t)(0x80 + i);
    FILE *f = fopen(argc > 1 ? argv[1] : "kat_b1024.txt", "r");
    if (!f) { perror("kat_b1024.txt"); return 2; }
    char ligne[1024], nom[64], attendu[512], calc[512];
    int nok = 0, nko = 0;
    while (fgets(ligne, sizeof ligne, f)) {
        if (ligne[0] == '#' || sscanf(ligne, "%63s %511s", nom, attendu) != 2) continue;
        size_t L;
        if (!strcmp(nom, "hachage_abc")) { H((const uint8_t *)"abc", 3, out, 64); hexa(out, 64, calc); }
        else if (sscanf(nom, "hachage_%zu", &L) == 1) { H(m, L, out, 64); hexa(out, 64, calc); }
        else if (sscanf(nom, "xof_%zu", &L) == 1) { sponge(m, L, 0, out, 200); hexa(out, 200, calc); }
        else if (sscanf(nom, "aead_%zu", &L) == 1) {
            int sans = strstr(nom, "sans_aad") != NULL;
            enc(K, N, m + 1000, sans ? 0 : 9, m, L, C, T);
            memcpy(out, T, 32);
            sl_shake256(C, L, out + 32, 32);
            hexa(out, 64, calc);
        } else { printf("vecteur inconnu : %s\n", nom); nko++; continue; }
        int egal = !strcmp(calc, attendu);
        printf("%-18s %s\n", nom, egal ? "conforme" : "DIFFÉRENT");
        egal ? nok++ : nko++;
    }
    fclose(f);
    printf("seconde implémentation : %d vecteurs conformes, %d différents\n", nok, nko);
    return !(ok_emp && ok_rc && nko == 0 && nok == 18);
}
