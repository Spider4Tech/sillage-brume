/* Batterie v0.6 — BRUME-1024q par l'API publique seule (sillage.h), sur la bibliothèque compilée telle quelle.
 *
 * Compilé deux fois par tests/c/Makefile : avec AVX2 (noyaux AVX2, lots de 32 et 256 états) et sans AVX2 (noyau portable
 * à temps constant, -DB1024_API_PORTABLE). Les deux doivent redonner les KAT figés de la SPEC § 4 (tests/c/kat_b1024.h).
 * Contrôle aussi : déchiffrement et rejets (clair effacé), contexte de clé, lots ≡ fonctions unitaires, profils et
 * longueurs refusés, AEAD parallèle, et le mode TE (porté de la v0.5 sur l'AEAD de BRUME-1024q). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kat_b1024.h"
#include "resultat.h"
#include "sillage.h"

#ifdef B1024_API_PORTABLE
#define NOM "brume1024_api_portable"
#define TITRE "BRUME-1024q par l'API publique, noyau portable a temps constant (sans AVX2)"
#else
#define NOM "brume1024_api"
#define TITRE "BRUME-1024q par l'API publique, noyaux AVX2"
#endif

static void hexa(const uint8_t *x, size_t n, char *s)
{
    for (size_t i = 0; i < n; i++)
        sprintf(s + 2 * i, "%02x", x[i]);
}

static const char *kat(const char *nom)
{
    for (int i = 0; i < (int)(sizeof KAT_FIGES / sizeof *KAT_FIGES); i++)
        if (!strcmp(KAT_FIGES[i][0], nom))
            return KAT_FIGES[i][1];
    return NULL;
}

static uint64_t g = 0x5EED1024;
static void alea(uint8_t *x, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        g = g * 6364136223846793005ULL + 1442695040888963407ULL;
        x[i] = (uint8_t)(g >> 56);
    }
}

int main(void)
{
    sl_init();
    resultat_t res = {.nom = NOM, .titre = TITRE};
#ifdef __AVX2__
    int avx2 = 1;
#else
    int avx2 = 0;
#endif
    /* une chaîne et non un booléen : la valeur « false » est normale en version portable (CI du 18 nov. 2026) */
    res_mesure(&res, "noyau", "\"%s\"", avx2 ? "avx2" : "portable");
#ifdef B1024_API_PORTABLE
    res_controle(&res, "compile_sans_avx2", !avx2);
#endif

    /* 1. KAT figés (SPEC § 4), par les fonctions publiques */
    const size_t TM = 300 * 8192 + 5;
    uint8_t *m = malloc(TM), cle[64], nonce[SL_NONCE], out[200], tag[32], *c = malloc(3 * 8192 + 5), *p = malloc(3 * 8192 + 5);
    char hx[401], nom[40];
    for (size_t i = 0; i < TM; i++)
        m[i] = (uint8_t)(i % 251);
    for (int i = 0; i < 64; i++)
        cle[i] = (uint8_t)i;
    for (int i = 0; i < SL_NONCE; i++)
        nonce[i] = (uint8_t)(0x80 + i);
    int nk = 0, okk = 1;
    const size_t LH[] = {0, 1, 79, 80, 81, 8192, 8193, 3 * 8192 + 5, 100 * 8192 + 77, 300 * 8192 + 5};
    for (size_t t = 0; t < sizeof LH / sizeof *LH; t++, nk++) {
        snprintf(nom, sizeof nom, "hachage_%zu", LH[t]);
        sl_hash(m, LH[t], out, 64);
        hexa(out, 64, hx);
        okk &= kat(nom) && !strcmp(kat(nom), hx);
    }
    sl_hash((const uint8_t *)"abc", 3, out, 64);
    hexa(out, 64, hx);
    okk &= !strcmp(kat("hachage_abc"), hx);
    nk++;
    const size_t LX[] = {0, 200};
    for (size_t t = 0; t < 2; t++, nk++) {
        snprintf(nom, sizeof nom, "xof_%zu", LX[t]);
        sl_xof(m, LX[t], out, 200);
        hexa(out, 200, hx);
        okk &= !strcmp(kat(nom), hx);
    }
    int okdec = 1;
    const size_t LA[] = {0, 16, 64, 1000, 64};
    for (size_t t = 0; t < 5; t++, nk++) {
        size_t aadlen = t < 4 ? 9 : 0;
        snprintf(nom, sizeof nom, "aead_%zu%s", LA[t], aadlen ? "" : "_sans_aad");
        okk &= sl_aead_encrypt(0, cle, nonce, m + 1000, aadlen, m, LA[t], c, tag) == 0;
        memcpy(out, tag, 32);
        sl_shake256(c, LA[t], out + 32, 32);
        hexa(out, 64, hx);
        okk &= !strcmp(kat(nom), hx);
        memset(p, 0xEE, LA[t] + 1);
        okdec &= sl_aead_decrypt(0, cle, nonce, m + 1000, aadlen, c, LA[t], tag, p) == 0 && !memcmp(p, m, LA[t]);
    }
    const size_t LP[] = {0, 1000, 8192, 8193, 3 * 8192 + 5};
    for (size_t t = 0; t < 5; t++, nk++) {
        snprintf(nom, sizeof nom, "aeadp_%zu", LP[t]);
        okk &= sl_aead_p_encrypt(0, cle, nonce, m + 1000, 9, m, LP[t], c, tag) == 0;
        memcpy(out, tag, 32);
        sl_shake256(c, LP[t], out + 32, 32);
        hexa(out, 64, hx);
        okk &= !strcmp(kat(nom), hx);
        okdec &= sl_aead_p_decrypt(0, cle, nonce, m + 1000, 9, c, LP[t], tag, p) == 0 && !memcmp(p, m, LP[t]);
    }
    res_mesure(&res, "kat_recalcules", "%d", nk);
    res_controle(&res, "kat_figes_par_l_api_publique", okk && nk == 23);
    res_controle(&res, "dechiffrement_aead_et_aead_parallele_redonne_le_clair", okdec);

    /* 2. rejets : une altération du chiffré, du tag, des AAD ou du nonce est refusée et le clair est effacé */
    int okr = 1, nalt = 0;
    {
        const size_t L = 1000;
        uint8_t ct[1000], pt[1000], t0[32], n2[SL_NONCE];
        sl_aead_encrypt(0, cle, nonce, m + 1000, 9, m, L, ct, t0);
        for (int cas = 0; cas < 4; cas++) {
            uint8_t ct2[1000], t2[32], a2[9];
            memcpy(ct2, ct, L); memcpy(t2, t0, 32); memcpy(a2, m + 1000, 9); memcpy(n2, nonce, SL_NONCE);
            if (cas == 0) ct2[517] ^= 1;
            if (cas == 1) t2[31] ^= 0x80;
            if (cas == 2) a2[4] ^= 2;
            if (cas == 3) n2[23] ^= 4;
            memset(pt, 0xAA, L);
            int rc = sl_aead_decrypt(0, cle, n2, a2, 9, ct2, L, t2, pt);
            int nul = 1;
            for (size_t i = 0; i < L; i++)
                nul &= pt[i] == 0;
            okr &= rc == -1 && nul;
            nalt++;
            memset(pt, 0xAA, L);
            uint8_t cp2[1000], tp[32];
            sl_aead_p_encrypt(0, cle, nonce, m + 1000, 9, m, L, cp2, tp);
            if (cas == 0) cp2[3] ^= 1;
            if (cas == 1) tp[0] ^= 1;
            rc = sl_aead_p_decrypt(0, cle, n2, a2, 9, cp2, L, tp, pt);
            nul = 1;
            for (size_t i = 0; i < L; i++)
                nul &= pt[i] == 0;
            okr &= rc == -1 && nul;
            nalt++;
        }
    }
    res_mesure(&res, "alterations_refusees", "%d", nalt);
    res_controle(&res, "alterations_refusees_et_clair_efface", okr);

    /* 3. profils et longueurs refusés, taille du tag */
    {
        uint8_t ct[16], pt[16], t[32];
        int ok = sl_aead_tag_len(0) == 32 && sl_aead_tag_len(1) == 0 && sl_aead_tag_len(-1) == 0;
        ok &= sl_aead_encrypt(1, cle, nonce, NULL, 0, m, 16, ct, t) == -3;
        ok &= sl_aead_decrypt(1, cle, nonce, NULL, 0, ct, 16, t, pt) == -3;
        ok &= sl_aead_p_encrypt(1, cle, nonce, NULL, 0, m, 16, ct, t) == -3;
        sl_aead_cle_t cx;
        ok &= sl_aead_cle(&cx, 1, cle) == -3;
        /* longueur au-delà de 2^63 − 1 : refusée sans lecture (les pointeurs ne sont pas lus) */
        ok &= sl_aead_encrypt(0, cle, nonce, NULL, 0, m, (size_t)1 << 63, ct, t) == -3;
        ok &= sl_aead_decrypt(0, cle, nonce, NULL, (size_t)1 << 63, ct, 16, t, pt) == -3;
        ok &= sl_aead_p_encrypt(0, cle, nonce, NULL, 0, m, (size_t)1 << 63, ct, t) == -3;
        res_controle(&res, "profils_et_longueurs_hors_limite_refuses_tag_32_octets", ok);
    }

    /* 4. contexte de clé ≡ clé passée à chaque appel */
    {
        sl_aead_cle_t cx;
        uint8_t c1[300], c2[300], t1[32], t2[32], pt[300];
        int ok = sl_aead_cle(&cx, 0, cle) == 0;
        for (size_t L = 0; L < 300; L += 37) {
            sl_aead_encrypt(0, cle, nonce, m + 5, L % 90, m + 50, L, c1, t1);
            ok &= sl_aead_encrypt_ctx(&cx, nonce, m + 5, L % 90, m + 50, L, c2, t2) == 0;
            ok &= !memcmp(c1, c2, L) && !memcmp(t1, t2, 32);
            ok &= sl_aead_decrypt_ctx(&cx, nonce, m + 5, L % 90, c2, L, t2, pt) == 0 && !memcmp(pt, m + 50, L);
        }
        sl_effacer(&cx, sizeof cx);
        res_controle(&res, "contexte_de_cle_identique_a_l_appel_direct", ok);
    }

    /* 5. lots ≡ fonctions unitaires : messages de même longueur et mêmes AAD (noyaux de lot), longueurs variées (une
     *    tâche par message), même clé (contexte), déchiffrement par lot avec un message altéré */
    {
        const size_t n = 600;
        uint8_t *cles = malloc(64 * n), *nonces = malloc(SL_NONCE * n), *dat = malloc(n * 300), *chf = malloc(n * 300),
                *dch = malloc(n * 300), *tags = malloc(32 * n), *hs = malloc(64 * n);
        const uint8_t **pp = malloc(n * sizeof *pp), **aa = malloc(n * sizeof *aa);
        uint8_t **cp = malloc(n * sizeof *cp), **dp = malloc(n * sizeof *dp);
        size_t *ln = malloc(n * sizeof *ln), *la = malloc(n * sizeof *la);
        int *codes = malloc(n * sizeof *codes);
        alea(cles, 64 * n); alea(nonces, SL_NONCE * n); alea(dat, n * 300);
        int ok = 1;
        for (int forme = 0; forme < 3; forme++) {
            for (size_t i = 0; i < n; i++) {
                pp[i] = dat + i * 300; cp[i] = chf + i * 300; dp[i] = dch + i * 300;
                ln[i] = forme == 0 ? 250 : (i * 7) % 300;
                aa[i] = m + 2000; la[i] = forme == 0 ? 11 : i % 50;
            }
            if (forme < 2)
                ok &= sl_aead_encrypt_multi(0, n, cles, nonces, aa, la, pp, ln, cp, tags) == 0;
            else {
                sl_aead_cle_t cx;
                sl_aead_cle(&cx, 0, cles);
                ok &= sl_aead_encrypt_multi_ctx(&cx, n, nonces, aa, la, pp, ln, cp, tags) == 0;
            }
            for (size_t i = 0; i < n; i += 13) {
                uint8_t c1[300], t1[32];
                sl_aead_encrypt(0, cles + (forme < 2 ? 64 * i : 0), nonces + SL_NONCE * i, aa[i], la[i], pp[i], ln[i], c1, t1);
                ok &= !memcmp(c1, cp[i], ln[i]) && !memcmp(t1, tags + 32 * i, 32);
            }
            chf[0 * 300 + 1] ^= ln[0] > 1 ? 1 : 0;                 /* message 0 altéré (s'il a au moins 2 octets) */
            if (ln[0] <= 1) tags[0] ^= 1;
            if (forme < 2)
                ok &= sl_aead_decrypt_multi(0, n, cles, nonces, aa, la, (const uint8_t *const *)cp, ln, tags, dp, codes) == 0;
            else {
                sl_aead_cle_t cx;
                sl_aead_cle(&cx, 0, cles);
                ok &= sl_aead_decrypt_multi_ctx(&cx, n, nonces, aa, la, (const uint8_t *const *)cp, ln, tags, dp, codes) == 0;
            }
            ok &= codes[0] == -1;
            for (size_t i = 1; i < n; i++)
                ok &= codes[i] == 0 && !memcmp(dp[i], pp[i], ln[i]);
        }
        sl_hash_multi(n, pp, ln, hs, 64);
        for (size_t i = 0; i < n; i += 17) {
            uint8_t h[64];
            sl_hash(pp[i], ln[i], h, 64);
            ok &= !memcmp(h, hs + 64 * i, 64);
        }
        res_controle(&res, "lots_uniformes_varies_et_cle_commune_identiques_aux_fonctions_unitaires", ok);
        free(cles); free(nonces); free(dat); free(chf); free(dch); free(tags); free(hs); free(pp); free(aa); free(cp); free(dp);
        free(ln); free(la); free(codes);
    }

    /* 6. hachage : sl_hash_arbre = sl_hash, XOF ≠ hachage, sortie prolongée cohérente (préfixe) */
    {
        uint8_t a[100], b[100], x[64];
        int ok = 1;
        for (size_t L = 0; L < 20000; L += 4999) {
            sl_hash(m, L, a, 100);
            sl_hash_arbre(m, L, b, 100);
            ok &= !memcmp(a, b, 100);
            sl_hash(m, L, b, 37);
            ok &= !memcmp(a, b, 37);
            sl_xof(m, L, x, 64);
            ok &= memcmp(a, x, 64) != 0;
        }
        res_controle(&res, "hachage_arbre_egal_au_hachage_prefixe_coherent_xof_distinct", ok);
    }

    /* 7. permutation : lot ≡ unitaire ≡ référence dense, et P⁻¹ (référence) inverse P */
    {
        static uint8_t lot[32][128];
        uint8_t w[128], r[128];
        alea(&lot[0][0], sizeof lot);
        int ok = 1;
        uint8_t copie[32][128];
        memcpy(copie, lot, sizeof lot);
        sl_brume_permute_lot(lot);
        for (int i = 0; i < 32; i++) {
            memcpy(w, copie[i], 128);
            memcpy(r, copie[i], 128);
            sl_brume_permute(w);
            sl_brume_permute_ref(r);
            ok &= !memcmp(w, lot[i], 128) && !memcmp(r, w, 128);
            sl_brume_permute_inv_ref(r);
            ok &= !memcmp(r, copie[i], 128);
        }
        res_controle(&res, "permutation_lot_unitaire_et_reference_identiques_inverse_correct", ok);
    }

    /* 8. mode TE (SPEC § 3.7, docs/SPEC.md § 2.7) sur l'AEAD de BRUME-1024q */
    {
        int okt = 1, okc = 1, okrej = 1, okform = 1, ncas = 0;
        const size_t TL[] = {0, 1, 63, 64, 65, 200, 1000};
        for (size_t t = 0; t < sizeof TL / sizeof *TL; t++) {
            const size_t L = TL[t], nb = L / 64 + (L % 64 != 0);
            uint8_t ct[1000], c2[1000], pt[1000], par[7 * 16], tg[32], meta[8], ta[32], ca[1000];
            size_t corr[16], nc = 99;
            okt &= sl_te_par_len(L) == 7 * nb;
            okt &= sl_te_encrypt(0, cle, nonce, m + 7, 5, m + 100, L, ct, par, tg, meta) == 0;
            /* le chiffré et le tag sont ceux de l'AEAD */
            sl_aead_encrypt(0, cle, nonce, m + 7, 5, m + 100, L, ca, ta);
            okt &= !memcmp(ca, ct, L) && !memcmp(ta, tg, 32);
            uint64_t lm = 0;
            for (int k = 0; k < 8; k++)
                lm = (lm << 8) | meta[k];
            okt &= lm == L;
            memcpy(c2, ct, L);
            okt &= sl_te_decrypt(0, cle, nonce, m + 7, 5, c2, L, par, sl_te_par_len(L), tg, meta, pt, corr, &nc) == 0 && nc == 0 &&
                   !memcmp(pt, m + 100, L);
            /* un octet abîmé par bloc (chaque position d'un bloc, valeurs variées) : corrigé, clair rendu */
            for (size_t pos = 0; L && pos < L; pos += 1 + L / 9) {
                memcpy(c2, ct, L);
                for (size_t b = 0; b < nb; b++) {
                    size_t gpos = 64 * b + (pos % 64);
                    if (gpos < L)
                        c2[gpos] ^= (uint8_t)(1 + (pos + b) % 255);
                }
                nc = 0;
                int rc = sl_te_decrypt(0, cle, nonce, m + 7, 5, c2, L, par, sl_te_par_len(L), tg, meta, pt, corr, &nc);
                okc &= rc == 0 && !memcmp(pt, m + 100, L) && !memcmp(c2, ct, L);
                ncas++;
            }
            /* deux octets abîmés dans un même bloc : refus (-2, chiffré intact) ou, si les syndromes concordent par hasard,
             * la correction fausse est rattrapée par le tag (-1) ; jamais un clair faux */
            if (L >= 2) {
                memcpy(c2, ct, L);
                c2[0] ^= 0x11;
                c2[1] ^= 0x22;
                uint8_t sauve[1000];
                memcpy(sauve, c2, L);
                memset(pt, 0xAA, L);
                int rc = sl_te_decrypt(0, cle, nonce, m + 7, 5, c2, L, par, sl_te_par_len(L), tg, meta, pt, corr, &nc);
                okrej &= (rc == -2 && !memcmp(c2, sauve, L)) || rc == -1;
                if (rc != 0) {
                    int nul = 1;
                    for (size_t i = 0; i < L && rc == -1; i++)
                        nul &= pt[i] == 0;
                    okrej &= nul;
                }
                /* parité abîmée seule (octet C₀) : vue comme une erreur, refus ou correction d'un octet puis tag */
                memcpy(c2, ct, L);
                uint8_t par2[7 * 16];
                memcpy(par2, par, 7 * nb);
                par2[1] ^= 0x01;
                rc = sl_te_decrypt(0, cle, nonce, m + 7, 5, c2, L, par2, sl_te_par_len(L), tg, meta, pt, corr, &nc);
                okrej &= rc == -2 || rc == -1 || (rc == 0 && !memcmp(pt, m + 100, L));
                /* tag altéré : la correction ne le répare pas */
                uint8_t tg2[32];
                memcpy(tg2, tg, 32);
                tg2[5] ^= 1;
                memcpy(c2, ct, L);
                okrej &= sl_te_decrypt(0, cle, nonce, m + 7, 5, c2, L, par, sl_te_par_len(L), tg2, meta, pt, corr, &nc) == -1;
            }
            /* formes : longueur des parités, méta-donnée de longueur, profil */
            memcpy(c2, ct, L);
            okform &= sl_te_decrypt(0, cle, nonce, m + 7, 5, c2, L, par, sl_te_par_len(L) + 7, tg, meta, pt, corr, &nc) == -2;
            uint8_t meta2[8];
            memcpy(meta2, meta, 8);
            meta2[7] ^= 1;
            okform &= sl_te_decrypt(0, cle, nonce, m + 7, 5, c2, L, par, sl_te_par_len(L), tg, meta2, pt, corr, &nc) == -2;
            okform &= sl_te_decrypt(1, cle, nonce, m + 7, 5, c2, L, par, sl_te_par_len(L), tg, meta, pt, corr, &nc) == -3;
            okform &= sl_te_encrypt(1, cle, nonce, m + 7, 5, m + 100, L, ct, par, tg, meta) == -3;
        }
        res_mesure(&res, "te_cas_de_correction", "%d", ncas);
        res_controle(&res, "te_chiffre_et_tag_de_l_aead_aller_retour", okt);
        res_controle(&res, "te_un_octet_par_bloc_corrige", okc && ncas > 20);
        res_controle(&res, "te_deux_octets_ou_tag_altere_jamais_de_clair_faux", okrej);
        res_controle(&res, "te_formes_invalides_refusees", okform);
    }
    free(m);
    free(c);
    free(p);
    return res_ecrire(&res);
}
