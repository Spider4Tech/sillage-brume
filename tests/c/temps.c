/* Test de temps constant de type « dudect » (Reparaz, Balasch, Verbauwhede
 * 2017) : temps (rdtscp) d'une opération sur une entrée FIXE (classe 0) ou
 * ALÉATOIRE (classe 1). Les classes sont tirées au hasard et entrelacées ;
 * toutes les entrées d'un paquet sont préparées AVANT les mesures (aucun
 * appel système ni copie différente entre classes pendant la mesure) ; la
 * classe fixe utilise autant de copies en mémoire que la classe aléatoire
 * (même empreinte de cache). Test t de Welch après rognage au 90e centile.
 * |t| > 4,5 : fuite probable (seuil de dudect).
 * KEM (préfixe kem256_ : niveau Sillage-256). Répéter un même chiffré est un
 * peu plus rapide que varier les chiffrés (≈ 170 cycles sur 2,5 M, campagne du
 * 2026-10-30) ; le chiffré étant public, ce n'est pas une fuite, mais il ne
 * doit pas être confondu avec un secret. Les plans suivants le neutralisent :
 * les deux classes puisent dans des réserves de même nature et l'entrée est
 * recopiée dans un tampon commun juste avant la mesure (mêmes adresses, même
 * état du cache). On inclut kem.c pour construire les clés (aucune entrée de
 * test dans la bibliothèque).
 * kem_oracle : même clé ; 256 chiffrés honnêtes (acceptés) contre 256 aléatoires
 * (décodage en échec, rejet) — l'oracle des attaques par réaction.
 * kem_oracle_fo : mêmes chiffrés honnêtes, intacts ou avec un bit de v inversé
 * (décodage réussi, rejet à la comparaison FO seulement).
 * kem_decaps : clé fixe contre 64 clés de même σ_h (mêmes h et π), chiffrés tirés
 * dans la même réserve de 16 pour les deux classes : seuls x, y, σ_rej varient. La clé fixe se
 * recopie depuis 64 copies distinctes, comme la classe aléatoire : avec une source unique
 * (kem_decaps_asym, plan d'origine, témoin), la recopie avant mesure charge le cache différemment
 * selon la classe et |t| dépasse 4,5 sans rapport avec la clé (run 20261102_035910 contre 20261101_222349).
 * kem_encaps : encapsulation déterministe, μ (secret) fixe contre aléatoire.
 * kem_aa : mêmes données dans les deux classes : t mesure le biais du banc.
 * kem_temoin : kem_aa + 300 cycles d'attente en classe 1 : sensibilité du banc.
 * kem_ct_public : chiffré honnête fixe contre 256 honnêtes — l'effet ci-dessus,
 * indicatif, sans contrôle.
 * sig_tour : simulation d'un côté de l'hypercube (x_B, S(r), Q(r), P(r), diffusion), part
 * fixe contre part aléatoire, défis publics communs. sig_tour_ref : même calcul direct (colonnes
 * de H' et points sautés selon les bits) — témoin.
 * sig_sign : signature complète, clé secrète fixe contre clés aléatoires de même H'.
 *     ./temps <permutation|permutation_ref|aead|aead_p|kem_oracle|kem_oracle_fo|kem_decaps|
 *              kem_encaps|kem_aa|kem_temoin|kem_ct_public|kem256_oracle|kem256_decaps|…|
 *              sig_tour|sig_tour_ref|sig_sign> <mesures>
 * SILLAGE_TEMPS_GRAINE=<texte> (aead, aead_sym, aead_aa_fixe, kem_decaps, kem_decaps_aa et
 * variantes kem256_) : les valeurs de mise en place (clés, entrées, réserves) sont dérivées de ce
 * texte, et la sortie porte leur empreinte. D'un processus à l'autre, seule la disposition mémoire
 * change. Les tirages faits pendant la mesure (classes, entrées de la classe aléatoire) restent
 * aléatoires. Voir ./scripts/runspecial.
 * Contrôles du banc AEAD, préparés sans appel système entre les entrées (les deux classes passent
 * par le même memcpy, depuis une réserve tirée d'un bloc) :
 * aead_sym : fixe contre aléatoire ; aead_aa_fixe : même valeur fixe dans les deux classes ;
 * aead_aa_alea : valeurs aléatoires dans les deux classes. kem_decaps_aa : mêmes réserves de 64 clés
 * et de 16 chiffrés dans les deux classes. Dans un A/A, la classe ne porte aucune information.
 * aead_cle : clé fixe contre aléatoire, clair aléatoire partout ; aead_clair : clair fixe contre
 * aléatoire, clé aléatoire partout. kem_decaps_sym : clé fixe recopiée depuis 64 copies distinctes,
 * contre 64 clés : les deux classes lisent autant de mémoire avant la mesure.
 * Avec une graine, la sortie donne aussi les adresses des tampons (champ "adresses").
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include "sillage.h"
#include "kem.c"
#include "sig.c"

/* Aléa de ce fichier seulement (kem.c et sig.c, inclus plus haut, gardent le vrai) :
 * dérivé de SILLAGE_TEMPS_GRAINE pendant la mise en place, s'il est défini. */
static const char *graine_mise_en_place;

static int temps_alea(void *out, size_t len)
{
    static uint64_t compteur;
    if (!graine_mise_en_place)
        return sl_alea(out, len);
    char m[256];
    int k = snprintf(m, sizeof m, "temps/%s/%llu", graine_mise_en_place, (unsigned long long)compteur++);
    sl_shake256((const uint8_t *)m, (size_t)k, out, len);
    return 0;
}
#define sl_alea temps_alea

/* clé de σ_h imposé : x, y creux aléatoires validés (δ ≤ 2^-λ) */
static void cle_sigma(int niv, const uint8_t sigma[32], uint8_t *pk, uint8_t *sk)
{
    const params_t *p = &P[niv];
    uint8_t g[32], rej[32];
    uint64_t *x = nouveau(p->n), *y = nouveau(p->n), *s = nouveau(p->n);
    uint32_t *px = malloc(4 * p->w), *py = malloc(4 * p->w);
    sl_alea(rej, 32);
    do {
        memset(x, 0, (NW(p->n) + 4) * 8); memset(y, 0, (NW(p->n) + 4) * 8);
        sl_alea(g, 32); sl_creux(g, 32, (int)p->w, p->n, "eph", px);
        sl_alea(g, 32); sl_creux(g, 32, (int)p->w, p->n, "eph", py);
        poser_ct(x, NW(p->n), px, (int)p->w);
        poser_ct(y, NW(p->n), py, (int)p->w);
    } while (borne(niv, x, y) > -(double)p->lam);
    const uint64_t *h;
    const uint32_t *pi;
    derives(niv, sigma, &h, &pi);
    mul_ct(x, h, p->n, s, p->n);
    poser_ct(s, NW(p->n), py, (int)p->w);
    size_t nb = NB(p->n);
    memcpy(pk, sigma, 32); ranger(pk + 32, s, p->n);
    ranger(sk, x, p->n); ranger(sk + nb, y, p->n);
    memcpy(sk + 2 * nb, sigma, 32); memcpy(sk + 2 * nb + 32, rej, 32);
    ranger(sk + 2 * nb + 64, s, p->n);
    free(x); free(y); free(s); free(px); free(py);
}

#define PAQ 1024
#define NK 8
#define KV 256                                         /* réserve d'entrées du KEM (puissance de 2) */

/* chiffré aléatoire canonique (décodage en échec) */
static uint8_t *ct_alea(int niv, size_t lct)
{
    uint8_t *c = malloc(lct);
    sl_alea(c, lct);
    if (P[niv].n & 7)
        c[NB(P[niv].n) - 1] &= (uint8_t)((1u << (P[niv].n & 7)) - 1);
    return c;
}

static double t_coupe(double *const t[2], const long nc[2], double seuil, double m[2])
{
    double v[2];
    long k[2];
    for (int c = 0; c < 2; c++) {
        double s = 0, s2 = 0;
        k[c] = 0;
        for (long i = 0; i < nc[c]; i++)
            if (t[c][i] <= seuil) { s += t[c][i]; s2 += t[c][i] * t[c][i]; k[c]++; }
        m[c] = k[c] ? s / k[c] : 0;
        v[c] = k[c] ? s2 / k[c] - m[c] * m[c] : 0;
    }
    if (!k[0] || !k[1])                                 /* classes disjointes (témoin) : séparation totale */
        return k[0] ? -1e6 : 1e6;
    return (m[0] - m[1]) / sqrt(v[0] / k[0] + v[1] / k[1]);
}

static int cmpd(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv)
{
    const char *op = argc > 1 ? argv[1] : "permutation";
    long n = argc > 2 ? atol(argv[2]) : 200000;
    int niv = !strncmp(op, "kem256_", 7), kem = niv || !strncmp(op, "kem_", 4);
    const char *kop = kem ? op + (niv ? 7 : 4) : "";
    int encaps = !strcmp(kop, "encaps"), temoin = !strcmp(kop, "temoin");
    int sig = !strncmp(op, "sig_", 4), sigsign = !strcmp(op, "sig_sign"), sigref = !strcmp(op, "sig_tour_ref");
    int aead_sym = !strcmp(op, "aead_sym"), aa_fixe = !strcmp(op, "aead_aa_fixe"), aa_alea = !strcmp(op, "aead_aa_alea");
    int aead_cle = !strcmp(op, "aead_cle"), aead_clair = !strcmp(op, "aead_clair");
    int prep_sym = aead_sym || aa_fixe || aa_alea || aead_cle || aead_clair, aead_simple = prep_sym || !strcmp(op, "aead");
    int decaps_aa = !strcmp(kop, "decaps_aa"), decaps_asym = !strcmp(kop, "decaps_asym");
    int decaps_sym = !strcmp(kop, "decaps") || !strcmp(kop, "decaps_sym");
    graine_mise_en_place = getenv("SILLAGE_TEMPS_GRAINE");
    if (graine_mise_en_place && (aa_alea || !(aead_simple || decaps_aa || decaps_sym || decaps_asym))) {
        fprintf(stderr, "SILLAGE_TEMPS_GRAINE : plans aead et kem_decaps seulement, pas %s\n", op);
        return 2;
    }
    const sp_t *sp = &SP[0];
    size_t Lp = L_PART(sp), spk, ssk, smax, slen;
    sl_sig_tailles(0, &spk, &ssk, &smax);
    uint8_t seedH[32], *spkf = malloc(spk), *ssig = malloc(smax), smsg[32] = "message";
    uint8_t *su = malloc(PAQ * Lp), *ssk_t[2][NK], *su_f = malloc(Lp), yp[NB(1229)];
    const uint64_t *sH = NULL;
    prep_t sP;
    uint64_t sr[T_MAX], se[T_MAX], soa[T_MAX], sob[T_MAX], sx1[T_MAX], sx2[T_MAX], sx3[T_MAX];
    if (sig) {
        sl_alea(seedH, 32);
        sH = matrice(0, seedH);
        tables(0);
        sP.L = malloc(8 * (size_t)sp->t * sp->n);
        sP.pw = malloc(8 * (size_t)sp->t * sp->w);
        sl_alea(sr, sizeof sr); sl_alea(se, sizeof se); sl_alea(soa, sizeof soa); sl_alea(sob, sizeof sob);
        sl_alea(yp, sizeof yp);
        yp[NB(sp->r) - 1] &= (uint8_t)((1 << (sp->r & 7)) - 1);
        uint64_t mp = (1ULL << sp->ep) - 1;
        for (uint32_t j = 0; j < sp->t; j++) {
            sr[j] &= mp; se[j] &= mp; soa[j] &= mp; sob[j] &= mp;
        }
        preparer(0, sr, &sP);
        sl_alea(su_f, Lp);
        masquer_part(sp, su_f);
        for (int c = 0; c < 2; c++)
            for (int i = 0; i < NK; i++) {               /* clés de même graine publique de H */
                ssk_t[c][i] = malloc(ssk);
                if (c == 0 && i > 0) { memcpy(ssk_t[0][i], ssk_t[0][0], ssk); continue; }
                uint8_t *pk2 = malloc(spk);
                sl_sig_keygen(0, pk2, ssk_t[c][i]);
                free(pk2);
            }
        memset(spkf, 0, spk);
        memcpy(spkf, seedH, 32);
        matrice(0, seedH);                               /* recharge H (keygen l'a changée) */
    }
    sl_init();
    size_t lpk, lsk, lct, lss;
    sl_kem_tailles(niv, &lpk, &lsk, &lct, &lss);
    uint8_t *pk = malloc(lpk), ss[64], sigma[32];
    sl_alea(sigma, 32);
    /* réserves : vs[c][j] clés, vc[c][j] chiffrés (ns, nv : puissances de 2) ;
     * pour kem_decaps le chiffré est tiré indépendamment de la classe */
    uint8_t *vs[2][KV], *vc[2][KV], *ts[NK], *tc[NK];
    int ns[2] = {1, 1}, nv[2] = {1, 1};
    if (kem) {
        uint8_t *sk0 = malloc(lsk), *ct0 = malloc(lct);
        cle_sigma(niv, sigma, pk, sk0);
        sl_kem_encaps(niv, pk, ct0, ss);
        vs[0][0] = vs[1][0] = sk0;
        vc[0][0] = vc[1][0] = ct0;
        if (!strcmp(kop, "oracle") || !strcmp(kop, "oracle_fo") || !strcmp(kop, "ct_public")) {
            int fo = !strcmp(kop, "oracle_fo"), ora = !strcmp(kop, "oracle"), pub = !strcmp(kop, "ct_public");
            nv[1] = KV; nv[0] = pub ? 1 : KV;
            for (int j = 0; j < KV; j++) {
                if (!pub) {
                    vc[0][j] = malloc(lct);
                    sl_kem_encaps(niv, pk, vc[0][j], ss);
                }
                vc[1][j] = ora ? ct_alea(niv, lct) : malloc(lct);
                if (fo) {                                 /* un bit de v inversé */
                    uint8_t r[4];
                    sl_alea(r, 4);
                    memcpy(vc[1][j], vc[0][j], lct);
                    vc[1][j][NB(P[niv].n) + (*(uint32_t *)r % NB(P[niv].n2))] ^= (uint8_t)(1u << (r[0] & 7));
                } else if (pub)
                    sl_kem_encaps(niv, pk, vc[1][j], ss);
            }
        } else if (decaps_asym || decaps_aa || decaps_sym) {
            ns[1] = 64; nv[0] = nv[1] = 16;
            if (decaps_aa || decaps_sym) ns[0] = 64;
            for (int j = 0; j < 64; j++) {
                vs[1][j] = malloc(lsk);
                cle_sigma(niv, sigma, pk, vs[1][j]);
                if (decaps_aa) vs[0][j] = vs[1][j];
                if (decaps_sym) {                      /* mêmes données, 64 zones de mémoire */
                    vs[0][j] = malloc(lsk);
                    memcpy(vs[0][j], sk0, lsk);
                }
            }
            for (int j = 0; j < 16; j++)
                vc[0][j] = vc[1][j] = ct_alea(niv, lct);
        } else if (!encaps && !temoin && strcmp(kop, "aa")) {
            fprintf(stderr, "opération inconnue : %s\n", op);
            return 2;
        }
        for (int i = 0; i < NK; i++) { ts[i] = malloc(lsk); tc[i] = malloc(lct); }
    }
    int aead_p = !strcmp(op, "aead_p");
    static uint8_t gros[32 * SL_AEADP_FEUILLE], gros_c[32 * SL_AEADP_FEUILLE];
    static uint8_t ent[PAQ][64], cle[PAQ][64], cls[PAQ], idx[PAQ], idc[PAQ], fixe[64], cle_f[64];
    uint8_t sortie[64], tag[32], nonce[SL_NONCE] = {0}, acc = 0;
    sl_alea(fixe, 64);
    sl_alea(cle_f, 64);
    char champ_empreinte[48] = "", champ_adresses[256] = "";
    if (graine_mise_en_place) {                        /* preuve que les valeurs sont les mêmes d'un processus à l'autre */
        uint8_t e[8];
        sl_shake_t h;
        sl_shake_init(&h);
        sl_shake_absorb(&h, fixe, 64);
        sl_shake_absorb(&h, cle_f, 64);
        if (kem) {
            sl_shake_absorb(&h, vs[0][0], lsk);
            for (int j = 0; j < ns[1]; j++) sl_shake_absorb(&h, vs[1][j], lsk);
            for (int j = 0; j < nv[0]; j++) sl_shake_absorb(&h, vc[0][j], lct);
        }
        sl_shake_final(&h);
        sl_shake_squeeze(&h, e, 8);
        int k = snprintf(champ_empreinte, sizeof champ_empreinte, ", \"empreinte\": \"");
        for (int j = 0; j < 8; j++) k += snprintf(champ_empreinte + k, sizeof champ_empreinte - (size_t)k, "%02x", e[j]);
        snprintf(champ_empreinte + k, sizeof champ_empreinte - (size_t)k, "\"");
        snprintf(champ_adresses, sizeof champ_adresses,
                 ", \"adresses\": {\"ent\": \"%p\", \"cle\": \"%p\", \"sortie\": \"%p\", \"tag\": \"%p\", \"fixe\": \"%p\", "
                 "\"ts\": \"%p\", \"tc\": \"%p\", \"code\": \"%p\"}", (void *)ent, (void *)cle, (void *)sortie, (void *)tag,
                 (void *)fixe, kem ? (void *)ts[0] : NULL, kem ? (void *)tc[0] : NULL, (void *)(uintptr_t)sl_aead_encrypt);
        graine_mise_en_place = NULL;                   /* la mesure reprend le vrai aléa */
    }
    double *t[2] = {malloc(n * sizeof(double)), malloc(n * sizeof(double))};
    long nc[2] = {0, 0};
    static uint8_t res_ent[PAQ][64], res_cle[PAQ][64];
    for (long base = 0; base < n; base += PAQ) {
        sl_alea(cls, PAQ); sl_alea(idx, PAQ); sl_alea(idc, PAQ);
        if (prep_sym) { sl_alea(res_ent, sizeof res_ent); sl_alea(res_cle, sizeof res_cle); }
        for (int i = 0; i < PAQ; i++) {
            cls[i] &= 1;
            if (prep_sym) {
                int al_ent = aa_alea || aead_cle || (cls[i] && !aa_fixe);
                int al_cle = aa_alea || aead_clair || (cls[i] && !aa_fixe);
                memcpy(ent[i], al_ent ? res_ent[i] : fixe, 64);
                memcpy(cle[i], al_cle ? res_cle[i] : cle_f, 64);
            } else if (cls[i]) { sl_alea(ent[i], 64); sl_alea(cle[i], 64); }
            else { memcpy(ent[i], fixe, 64); memcpy(cle[i], cle_f, 64); }
            if (sig && !sigsign) {
                if (cls[i]) {
                    sl_alea(su + i * Lp, Lp);
                    masquer_part(sp, su + i * Lp);
                } else
                    memcpy(su + i * Lp, su_f, Lp);
            }
        }
        for (int i = 0; i < PAQ && base + i < n; i++) {
            int c = cls[i];
            unsigned aux;
            const uint8_t *ks = NULL, *kc = NULL;
            if (kem && !encaps) {                          /* entrée recopiée : mêmes adresses */
                int o = i & (NK - 1);
                memcpy(ts[o], vs[c][idx[i] & (ns[c] - 1)], lsk);
                memcpy(tc[o], vc[c][idc[i] & (nv[c] - 1)], lct);
                ks = ts[o]; kc = tc[o];
            }
            if (aead_p)                                    /* le secret dans chaque feuille du lot */
                for (int q = 0; q < 32; q++)
                    memcpy(gros + q * SL_AEADP_FEUILLE, ent[i], 64);
            uint64_t t0 = __rdtscp(&aux);
            if (aead_p)
                sl_aead_p_encrypt(0, cle[i], nonce, NULL, 0, gros, 32 * SL_AEADP_FEUILLE, gros_c, tag);
            else if (!strcmp(op, "permutation"))
                sl_brume_permute(ent[i]);
            else if (!strcmp(op, "permutation_ref"))
                sl_brume_permute_ref(ent[i]);
            else if (aead_simple)
                sl_aead_encrypt(0, cle[i], nonce, NULL, 0, ent[i], 64, sortie, tag);
            else if (sigsign) {
                /* pk : graine de H commune ; le syndrome n'influe que sur un hachage public */
                memcpy(spkf, seedH, 32);
                sl_sig_sign(0, ssk_t[c][idx[i] & (NK - 1)], spkf, smsg, 32, ssig, &slen);
                sortie[0] = ssig[40];
            } else if (sigref) {
                /* chemin direct : on saute les colonnes et les points des bits nuls */
                const uint8_t *xa = su + i * Lp;
                uint64_t xB[NW(1229) + 1] = {0}, S = 0;
                size_t rw = NW(sp->r);
                for (uint32_t j = 0; j < sp->k; j++)
                    if (xa[j >> 3] >> (j & 7) & 1)
                        for (size_t q = 0; q < rw; q++)
                            xB[q] ^= sH[(size_t)j * rw + q];
                for (uint32_t j = 0; j < sp->k; j++)
                    if (xa[j >> 3] >> (j & 7) & 1)
                        S ^= sP.L[j];
                for (uint32_t j = 0; j < sp->r; j++)
                    if (xB[j >> 6] >> (j & 63) & 1)
                        S ^= sP.L[sp->k + j];
                sortie[0] = (uint8_t)S;
            } else if (sig) {
                simuler(0, su + i * Lp, sH, yp, se, &sP, 1, soa, sob, sx1, sx2, sx3);
                sortie[0] = (uint8_t)(sx1[0] ^ sx2[0] ^ sx3[0]);
            }
            else if (encaps)
                sl_kem_encaps_det(niv, pk, ent[i], tc[0], ss);
            else {
                sl_kem_decaps(niv, ks, kc, ss);
                if (temoin && c) {                         /* classe 1 : 300 cycles de plus */
                    uint64_t d = __rdtscp(&aux);
                    while (__rdtscp(&aux) - d < 300) { }
                }
            }
            uint64_t t1 = __rdtscp(&aux);
            t[c][nc[c]++] = (double)(t1 - t0);
            acc ^= ent[i][0] ^ sortie[0] ^ ss[0];
        }
    }
    double *tout = malloc((nc[0] + nc[1]) * sizeof(double));
    memcpy(tout, t[0], nc[0] * sizeof(double));
    memcpy(tout + nc[0], t[1], nc[1] * sizeof(double));
    qsort(tout, nc[0] + nc[1], sizeof(double), cmpd);
    double m[2], m50[2];
    double t90 = t_coupe(t, nc, tout[(long)(0.9 * (nc[0] + nc[1]))], m);
    double t50 = t_coupe(t, nc, tout[(long)(0.5 * (nc[0] + nc[1]))], m50);
    printf("{\"operation\": \"%s\", \"mesures\": %ld, \"cycles_fixe\": %.1f, \"cycles_aleatoire\": %.1f, "
           "\"t_welch\": %.2f, \"t_p50\": %.2f, \"x\": %d%s%s}\n", op, n, m[0], m[1], t90, t50, acc, champ_empreinte, champ_adresses);
    return 0;
}
