/* Sorties de toutes les fonctions à noyau SIMD, condensées : doivent être identiques en AVX2, en NEON et sans SIMD
 * (tests/test_c_simd.py). Entrées déterministes ; KEM et SIG : aller-retours sur des clés tirées au hasard en plus. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sillage.h"

static uint64_t G = 0x1234;
static uint8_t alea8(void)
{
    G = G * 0x9e3779b97f4a7c15ULL + 1;
    return (uint8_t)(G >> 56);
}
static void remplir(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = alea8();
}
static void empreinte(const char *nom, const uint8_t *p, size_t n)
{
    uint8_t h[16];
    sl_shake256(p, n, h, 16);
    printf("%s ", nom);
    for (int i = 0; i < 16; i++)
        printf("%02x", h[i]);
    printf("\n");
}

int main(void)
{
    sl_init();
    enum { GROS = 40 * SL_AEADP_FEUILLE + 5 };
    uint8_t *m = malloc(GROS), *c = malloc(GROS), *d = malloc(GROS), e[32][64], k[64], n[SL_NONCE], t[32];
    remplir(m, GROS); remplir(k, 64); remplir(n, SL_NONCE); remplir(&e[0][0], sizeof e);
    uint8_t u[64];
    memcpy(u, e[0], 64);
    sl_brume_permute(u);
    empreinte("permutation", u, 64);
    sl_brume_permute_lot(e);
    empreinte("lot", &e[0][0], sizeof e);
    uint8_t h[64];
    sl_hash(m, 5000, h, 64);
    empreinte("hachage", h, 64);
    sl_hash_arbre(m, GROS, h, 64);
    empreinte("arbre", h, 64);
    for (int pr = 0; pr < 2; pr++) {
        sl_aead_encrypt(pr, k, n, m, 7, m, 1000, c, t);
        empreinte("aead", c, 1000);
        empreinte("aead_tag", t, sl_aead_tag_len(pr));
        static const size_t LG[] = {0, 1, 15, 16, 17, 31, 32, 33, 4095, 4096, 4097, 8192, 14 * 4096, 15 * 4096 + 1, 32 * 4096, GROS};
        for (size_t i = 0; i < sizeof LG / sizeof *LG; i++) {
            if (sl_aead_p_encrypt(pr, k, n, m, 7, m, LG[i], c, t))
                return 1;
            empreinte("aead_p", c, LG[i]);
            empreinte("aead_p_tag", t, sl_aead_tag_len(pr));
            if (sl_aead_p_decrypt(pr, k, n, m, 7, c, LG[i], t, d) || memcmp(d, m, LG[i]))
                return 2;
            memcpy(d, m, LG[i]);                         /* en place, dans les deux sens */
            uint8_t t2[32];
            if (sl_aead_p_encrypt(pr, k, n, m, 7, d, LG[i], d, t2) || memcmp(d, c, LG[i]) || memcmp(t2, t, sl_aead_tag_len(pr)))
                return 7;
            if (sl_aead_p_decrypt(pr, k, n, m, 7, d, LG[i], t, d) || memcmp(d, m, LG[i]))
                return 8;
            t[0] ^= 1;
            if (sl_aead_p_decrypt(pr, k, n, m, 7, c, LG[i], t, d) != -1)
                return 3;
        }
        size_t pk, sk, ct, ss, sm, sl;
        sl_kem_tailles(pr, &pk, &sk, &ct, &ss);
        uint8_t *P = malloc(pk), *C = malloc(ct), *K = malloc(ss), mu[64];
        remplir(P, 32);
        memset(P + 32, 0, pk - 32);
        remplir(P + 32, pk - 32 - 8);       /* (assez pour exercer le produit) */
        remplir(mu, 64);
        if (sl_kem_encaps_det(pr, P, mu, C, K))
            return 4;
        empreinte("kem_encaps", C, ct);
        empreinte("kem_ss", K, ss);
        uint8_t *x = calloc(1, pk), *y = calloc(1, pk);
        for (int i = 0; i < 90; i++) {
            x[alea8()] |= (uint8_t)(1u << (alea8() & 7));
            y[alea8()] |= (uint8_t)(1u << (alea8() & 7));
        }
        double b = sl_kem_borne(pr, x, y);
        empreinte("kem_borne", (const uint8_t *)&b, sizeof b);
        free(x); free(y); free(P); free(C); free(K);
        /* clés tirées au hasard : aller-retours seulement, leur sortie n'est pas comparée */
        uint8_t *kp = malloc(pk), *ks = malloc(sk), *kc = malloc(ct), *s1 = malloc(ss), *s2 = malloc(ss);
        if (sl_kem_keygen(pr, kp, ks) || sl_kem_encaps(pr, kp, kc, s1) || sl_kem_decaps(pr, ks, kc, s2) || memcmp(s1, s2, ss))
            return 5;
        free(kp); free(ks); free(kc); free(s1); free(s2);
        sl_sig_tailles(pr, &pk, &sk, &sm);
        uint8_t *sp = malloc(pk), *ssk = malloc(sk), *sg = malloc(sm);
        if (sl_sig_keygen(pr, sp, ssk) || sl_sig_sign(pr, ssk, sp, m, 32, sg, &sl) || sl_sig_verify(pr, sp, m, 32, sg, sl) != 1)
            return 6;
        free(sp); free(ssk); free(sg);
    }
    free(m); free(c); free(d);
    return 0;
}
