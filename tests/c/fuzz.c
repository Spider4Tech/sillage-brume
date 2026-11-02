/* Fuzzing de l'implémentation C sous AddressSanitizer + UndefinedBehavior-
 * Sanitizer (tests/test_c_fuzz.py) : toutes les API, longueurs aléatoires,
 * entrées altérées ou malformées. Tout accès mémoire invalide ou
 * comportement indéfini arrête le programme (code ≠ 0). Vérifie aussi les
 * allers-retours et les rejets.
 * Le bloc KEM/SIG comprend des entrées extrêmes (tout à 0 ou à 1, encodages non
 * canoniques, signature vide, tronquée ou aléatoire).
 *     ./fuzz <itérations> [graine] [répétitions du bloc KEM/SIG]   → JSON sur stdout
 */
#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sillage.h"

static uint64_t g = 0x9e3779b97f4a7c15ULL;
static uint64_t alea(void)
{
    g ^= g << 13; g ^= g >> 7; g ^= g << 17;
    return g;
}
static size_t longueur(size_t max)
{
    size_t r = alea() % 100;           /* biais vers les bords de blocs */
    if (r < 30) {
        static const size_t B[] = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129};
        size_t v = B[alea() % (sizeof B / sizeof *B)];
        return v <= max ? v : max;
    }
    return (size_t)(alea() % (max + 1));
}
static void remplir(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)alea();
}

/* faute (page de garde) ou piège UBSan : pile d'appels sur stderr */
static void signal_faute(int sig)
{
    void *pile[64];
    int n = backtrace(pile, 64);
    fprintf(stderr, "signal %d\n", sig);
    backtrace_symbols_fd(pile, n, 2);
    _exit(128 + sig);
}

int main(int argc, char **argv)
{
    long it = argc > 1 ? atol(argv[1]) : 2000;
    if (argc > 2)                                    /* graine : campagnes longues (scripts/rundenuit.sh) */
        g ^= strtoull(argv[2], NULL, 0) * 0x2545f4914f6cdd1dULL;
    int rep_ks = argc > 3 ? atoi(argv[3]) : 1;
    signal(SIGILL, signal_faute);
    signal(SIGSEGV, signal_faute);
    signal(SIGBUS, signal_faute);
    sl_init();
    long ok_aead = 0, ok_rej = 0, ok_te = 0, ok_ctx = 0, ok_multi = 0, ok_hash = 0, ok_p = 0;
    for (long i = 0; i < it; i++) {
        int pr = (int)(alea() & 1);
        size_t L = longueur(700), A = longueur(100), tl = sl_aead_tag_len(pr);
        uint8_t *m = malloc(L + 1), *c = malloc(L + 1), *p = malloc(L + 1), *a = malloc(A + 1);
        uint8_t k[64], n[SL_NONCE], t[32], t2[32], meta[8];
        remplir(m, L); remplir(a, A); remplir(k, 64); remplir(n, SL_NONCE);
        sl_aead_encrypt(pr, k, n, a, A, m, L, c, t);
        ok_aead += sl_aead_decrypt(pr, k, n, a, A, c, L, t, p) == 0 && !memcmp(m, p, L);
        memcpy(t2, t, tl);
        t2[alea() % tl] ^= (uint8_t)(1 + alea() % 255);
        ok_rej += sl_aead_decrypt(pr, k, n, a, A, c, L, t2, p) == -1;
        sl_aead_cle_t ctx;                                 /* contexte de clé */
        sl_aead_cle(&ctx, pr, k);
        uint8_t *c2 = malloc(L + 1), t3[32];
        sl_aead_encrypt_ctx(&ctx, n, a, A, m, L, c2, t3);
        ok_ctx += !memcmp(c, c2, L) && !memcmp(t, t3, tl);
        size_t pl = sl_te_par_len(L);                      /* TE, avec altérations */
        uint8_t *par = malloc(pl + 1), *ct = malloc(L + 1);
        size_t corr[64], nc;
        sl_te_encrypt(pr, k, n, a, A, m, L, ct, par, t, meta);
        int nerr = (int)(alea() % 3);
        for (int e = 0; e < nerr && L; e++)
            ct[alea() % L] ^= (uint8_t)(1 + alea() % 255);
        int rc = sl_te_decrypt(pr, k, n, a, A, ct, L, par, pl, t, meta, p, corr, &nc);
        ok_te += (nerr == 0 && rc == 0) || (nerr > 0 && (rc == 0 || rc == -1 || rc == -2));
        if (L && pl)                                       /* parités tronquées : refus */
            ok_te += sl_te_decrypt(pr, k, n, a, A, ct, L, par, pl - 1, t, meta, p, corr, &nc) == -2;
        else
            ok_te++;
        {                                                  /* AEAD parallèle : autour des frontières de feuille */
            size_t Lp = alea() % 4 ? L : (alea() % 40) * SL_AEADP_FEUILLE + alea() % 3;
            if (Lp && alea() % 2)
                Lp--;
            uint8_t *mp = malloc(Lp + 1), *cp = malloc(Lp + 1), *dp = malloc(Lp + 1);
            remplir(mp, Lp);
            sl_aead_p_encrypt(pr, k, n, a, A, mp, Lp, cp, t);
            ok_p += sl_aead_p_decrypt(pr, k, n, a, A, cp, Lp, t, dp) == 0 && !memcmp(mp, dp, Lp);
            memcpy(t2, t, tl);
            if (Lp)
                cp[alea() % Lp] ^= (uint8_t)(1 + alea() % 255);
            else
                t2[0] ^= 1;
            ok_p += sl_aead_p_decrypt(pr, k, n, a, A, cp, Lp, t2, dp) == -1;
            free(mp); free(cp); free(dp);
        }
        uint8_t h1[100], h2[100];                          /* hachage unitaire vs lots */
        size_t ho = longueur(99) + 1;
        sl_hash(m, L, h1, ho);
        const uint8_t *mm[1] = {m};
        size_t ll[1] = {L};
        sl_hash_multi(1, mm, ll, h2, ho);
        ok_hash += !memcmp(h1, h2, ho);
        free(m); free(c); free(p); free(a); free(c2); free(par); free(ct);
    }
    /* multi-messages (par lots et un par cœur), longueurs hétérogènes */
    for (int rep = 0; rep < 4; rep++) {
        size_t nmsg = rep < 2 ? 40 : 900;
        uint8_t *cl = malloc(64 * nmsg), *no = malloc(SL_NONCE * nmsg), *tg = malloc(32 * nmsg);
        const uint8_t **pp = malloc(nmsg * sizeof *pp);
        uint8_t **cp = malloc(nmsg * sizeof *cp), **dp = malloc(nmsg * sizeof *dp);
        size_t *ln = malloc(nmsg * sizeof *ln);
        int *codes = malloc(nmsg * sizeof *codes), pr = rep & 1, bon = 1;
        remplir(cl, 64 * nmsg); remplir(no, SL_NONCE * nmsg);
        for (size_t j = 0; j < nmsg; j++) {
            ln[j] = longueur(300);
            uint8_t *x = malloc(ln[j] + 1);
            remplir(x, ln[j]);
            pp[j] = x; cp[j] = malloc(ln[j] + 1); dp[j] = malloc(ln[j] + 1);
        }
        sl_aead_encrypt_multi(pr, nmsg, cl, no, NULL, NULL, pp, ln, cp, tg);
        sl_aead_decrypt_multi(pr, nmsg, cl, no, NULL, NULL, (const uint8_t *const *)cp, ln, tg, dp, codes);
        for (size_t j = 0; j < nmsg; j++)
            bon &= codes[j] == 0 && !memcmp(pp[j], dp[j], ln[j]);
        ok_multi += bon;
        for (size_t j = 0; j < nmsg; j++) { free((void *)pp[j]); free(cp[j]); free(dp[j]); }
        free(cl); free(no); free(tg); free(pp); free(cp); free(dp); free(ln); free(codes);
    }
    /* hachage arborescent : longueurs jusqu'à 5 feuilles (tampons exacts sous
     * pages de garde), comparé à un recalcul feuille par feuille (noyau d'un
     * état) : le chemin par lots ne lit ni n'écrit hors des feuilles */
    long ok_arbre = 0, n_arbre = 60;
    for (long i = 0; i < n_arbre; i++) {
        size_t L = (size_t)(alea() % (5 * 8192 + 1));
        if (i < 8) L = (size_t[]){0, 1, 8191, 8192, 8193, 16384, 32 * 8192, 33 * 8192 + 1}[i];
        uint8_t *x = malloc(L ? L : 1), h1[64], h2[64];
        remplir(x, L);
        sl_hash_arbre(x, L, h1, 64);
        if (L <= 8192)
            br_eponge(x, L, 10, h2, 64);
        else {
            size_t k = (L + 8191) / 8192, lr = 32 * k + 12;
            uint8_t *r = malloc(lr);
            for (size_t j = 0; j < k; j++)
                br_eponge(x + 8192 * j, L - 8192 * j < 8192 ? L - 8192 * j : 8192, 8, r + 32 * j, 32);
            for (int q = 0; q < 8; q++)
                r[32 * k + q] = (uint8_t)((uint64_t)k >> (56 - 8 * q));
            r[32 * k + 8] = 0; r[32 * k + 9] = 0; r[32 * k + 10] = 0x20; r[32 * k + 11] = 0;
            br_eponge(r, lr, 9, h2, 64);
            free(r);
        }
        ok_arbre += !memcmp(h1, h2, 64);
        free(x);
    }
    /* KEM et SIG : entrées malformées (sans plantage, rejet ou secret de rejet) */
    long ok_kem = 0, ok_sig = 0, ok_ext = 0, n_ext = 0;
    for (int rs = 0; rs < rep_ks; rs++)
    for (int niv = 0; niv < 2; niv++) {
        size_t lpk, lsk, lct, lss;
        sl_kem_tailles(niv, &lpk, &lsk, &lct, &lss);
        uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *ct = malloc(lct), ss[64], ss2[64];
        sl_kem_keygen(niv, pk, sk);
        for (int r = 0; r < 6; r++) {
            sl_kem_encaps(niv, pk, ct, ss);
            sl_kem_decaps(niv, sk, ct, ss2);
            int bon = !memcmp(ss, ss2, lss);
            if (r % 2) {                                   /* chiffré altéré ou aléatoire */
                if (r == 5) remplir(ct, lct); else ct[alea() % lct] ^= 1;
                sl_kem_decaps(niv, sk, ct, ss2);
                bon = memcmp(ss, ss2, lss) != 0;
            }
            ok_kem += bon;
        }
        /* chiffrés extrêmes : jamais le secret honnête */
        sl_kem_encaps(niv, pk, ct, ss);
        for (int e = 0; e < 4; e++) {
            uint8_t *x = malloc(lct);
            if (e == 0) memset(x, 0, lct);
            else if (e == 1) memset(x, 0xFF, lct);
            else { memcpy(x, ct, lct); memset(e == 2 ? x : x + lct / 2, 0, lct / 2); }   /* u ou v nul */
            sl_kem_decaps(niv, sk, x, ss2);
            ok_ext += memcmp(ss, ss2, lss) != 0;
            n_ext++;
            free(x);
        }
        /* clé publique extrême : ne doit ni planter ni lire hors limites */
        {
            uint8_t *x = malloc(lpk);
            memset(x, 0xFF, lpk);
            sl_kem_encaps(niv, x, ct, ss);
            memset(x, 0, lpk);
            sl_kem_encaps(niv, x, ct, ss);
            ok_ext++; n_ext++;
            free(x);
        }
        free(pk); free(sk); free(ct);
        size_t spk, ssk, smax, sl = 0;
        sl_sig_tailles(niv, &spk, &ssk, &smax);
        uint8_t *qk = malloc(spk), *qs = malloc(ssk), *sig = malloc(smax), msg[48];
        remplir(msg, sizeof msg);
        sl_sig_keygen(niv, qk, qs);
        sl_sig_sign(niv, qs, qk, msg, sizeof msg, sig, &sl);
        ok_sig += sl_sig_verify(niv, qk, msg, sizeof msg, sig, sl) == 1;
        for (int r = 0; r < 6; r++) {                      /* signatures altérées / tronquées */
            uint8_t *s2 = malloc(sl);
            memcpy(s2, sig, sl);
            size_t l2 = r < 3 ? sl : (size_t)(alea() % sl);
            if (r < 3) s2[alea() % sl] ^= (uint8_t)(1 + alea() % 255);
            ok_sig += sl_sig_verify(niv, qk, msg, sizeof msg, s2, l2) == 0;
            free(s2);
        }
        /* signatures extrêmes : vide, tout à 0, tout à 1, aléatoire, longueur maximale */
        for (int e = 0; e < 5; e++) {
            size_t l2 = e == 0 ? 0 : e == 4 ? smax : sl;
            uint8_t *s2 = malloc(l2 + 1);
            if (e == 2) memset(s2, 0xFF, l2);
            else if (e == 3 || e == 4) remplir(s2, l2);
            else memset(s2, 0, l2);
            ok_ext += sl_sig_verify(niv, qk, msg, sizeof msg, s2, l2) == 0;
            n_ext++;
            free(s2);
        }
        /* message vide */
        sl_sig_sign(niv, qs, qk, msg, 0, sig, &sl);
        ok_ext += sl_sig_verify(niv, qk, msg, 0, sig, sl) == 1 && sl_sig_verify(niv, qk, msg, 1, sig, sl) == 0;
        n_ext++;
        free(qk); free(qs); free(sig);
    }
    printf("{\"iterations\": %ld, \"aead_aller_retour\": %ld, \"aead_rejets\": %ld, \"te\": %ld, "
           "\"contexte\": %ld, \"hachage_lots\": %ld, \"multi\": %ld, \"kem\": %ld, \"sig\": %ld, "
           "\"hachage_arbre\": %ld, \"extremes\": %ld}\n",
           it, ok_aead, ok_rej, ok_te, ok_ctx, ok_hash, ok_multi, ok_kem, ok_sig, ok_arbre, ok_ext);
    return !(ok_aead == it && ok_rej == it && ok_te == 2 * it && ok_ctx == it && ok_hash == it &&
             ok_multi == 4 && ok_p == 2 * it && ok_kem == 12 * rep_ks && ok_sig == 14 * rep_ks && ok_arbre == n_arbre && ok_ext == n_ext);
}
