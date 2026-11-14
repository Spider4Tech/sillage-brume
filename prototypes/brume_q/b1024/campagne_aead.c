/* Campagne longue sur l'AEAD de BRUME-1024q (orientation SpongeWrap, 13 novembre 2026). Chaque processus exécute un mode
 * jusqu'à une échéance, écrit un point d'étape toutes les 10 minutes et un bilan JSON final, avec son propre verdict
 * (seuils fixés d'avance, ci-dessous). Les entrées sont tirées par xoshiro256** (graine donnée) : ce sont des données de
 * test, pas un aléa cryptographique.
 *   equiv : tailles aléatoires (la moitié autour des frontières de 80 octets) ; aead() ≡ référence DMV17 littérale
 *           (aead_kd) au chiffrement et au déchiffrement ; aller-retour par aead_ouvrir ; une partie des petits cas aussi
 *           avec la permutation dense (référence indépendante du noyau AVX2).
 *   forge : 20 types de falsification sur un message valide (et un second message sous la même clé) ; tout doit être
 *           rejeté, sortie effacée. Une acceptation est un échec.
 *   multi : aead_multi (lots bitslicés de 256, lots de 32, unitaire) ≡ aead() message par message.
 *   aval  : avalanche (un bit de clé, nonce, AAD ou clair) sur le tag (256 bits) et sur le chiffré ; propriété structurelle
 *           de SpongeWrap : changer le bit b du clair au bloc j change exactement ce bit du chiffré dans le bloc j, et rien
 *           d'autre dans ce bloc.
 *   biais : flux de chiffrement (clair nul de 640 octets, AAD vide) et tags, nonces en compteur (ou clés en compteur) :
 *           biais par position de bit (5 120 + 256 positions), χ² des octets (256 classes) et des paires d'octets
 *           consécutifs (65 536 classes).
 *   fils  : arbre et AEAD multi calculés avec 1 thread puis 2, 3, 5, 8 et 12 : sorties identiques.
 *   grand : un passage au-delà de 2^32 octets : AEAD de 2^32 + 1 234 octets ≡ référence DMV17, aller-retour, rejet d'une
 *           altération ; arbre de 2^32 + 3·8 192 + 7 octets : lots bitslicés ≡ éponges ≡ un thread (≈ 13 Go de mémoire).
 * Seuils : |z| > 6 sur une position, ou z du χ² > 6, ou toute non-conformité : échec.
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/campagne_aead.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm \
 *      -o campagne_aead && OMP_NUM_THREADS=1 ./campagne_aead <mode> <secondes> <graine> <fichier.json> */
#include <math.h>

#include "brume1024.c"

static uint64_t X[4];
static inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
static uint64_t xo(void)
{
    uint64_t r = rotl(X[1] * 5, 7) * 9, t = X[1] << 17;
    X[2] ^= X[0]; X[3] ^= X[1]; X[1] ^= X[2]; X[0] ^= X[3]; X[2] ^= t; X[3] = rotl(X[3], 45);
    return r;
}
static void remplir(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(xo() >> 56);
}
static size_t taille(size_t max)   /* la moitié du temps près d'une frontière de 80 octets */
{
    if (xo() & 1) {
        size_t b = 80 * (xo() % (max / 80 + 1)), d = xo() % 3;
        size_t t = b + d >= 1 ? b + d - 1 : 0;
        return t > max ? max : t;
    }
    return xo() % (max + 1);
}

static const char *MODE;
static int TEMOIN;   /* CAMPAGNE_TEMOIN=1 : défaut planté exprès, que le mode doit détecter (sensibilité) */
static double DEBUT, ECHEANCE;
static long CAS, ECHECS;
static char JS[1 << 16];
static const char *FICHIER;

static void ecrire(int final, const char *extra)
{
    char nom[512];
    snprintf(nom, sizeof nom, "%s%s", FICHIER, final ? "" : ".partiel");
    FILE *f = fopen(nom, "w");
    if (!f)
        return;
    fprintf(f, "{\"mode\": \"%s%s\", \"duree_s\": %.0f, \"cas\": %ld, \"echecs\": %ld%s, \"ok\": %s}\n", MODE,
            TEMOIN ? "_temoin" : "", maintenant() - DEBUT, CAS, ECHECS, extra, ECHECS == 0 ? "true" : "false");
    fclose(f);
}

static int fini(void)
{
    static double dernier;
    double t = maintenant();
    if (t - dernier > 600) {
        dernier = t;
        ecrire(0, JS);
    }
    return t >= ECHEANCE;
}

/* ---------------------------------------------------------------- equiv */
static void m_equiv(void)
{
    static uint8_t a[400], m[2000], c1[2000], c2[2000], d1[2000], t1[32], t2[32], k[64], n[24];
    long dense = 0;
    while (!fini()) {
        size_t A = taille(400), L = taille(2000);
        remplir(k, 64); remplir(n, 24); remplir(a, A); remplir(m, L);
        aead(perm1, k, n, a, A, m, L, 0, c1, t1);
        aead_kd(perm1, k, n, a, A, m, L, 0, c2, t2);
        int ok = !memcmp(c1, c2, L) && !memcmp(t1, t2, 32);
        ok &= aead_ouvrir(k, n, a, A, c1, L, t1, d1) == 0 && !memcmp(d1, m, L);
        aead(perm1, k, n, a, A, c1, L, 1, d1, t2);
        aead_kd(perm1, k, n, a, A, c1, L, 1, c2, t1);
        ok &= !memcmp(d1, c2, L) && !memcmp(t1, t2, 32) && !memcmp(d1, m, L);
        if (A + L <= 240 && xo() % 64 == 0) {   /* permutation dense : environ 0,7 ms par appel */
            aead_kd(perm_ref, k, n, a, A, m, L, 0, c2, t2);
            aead(perm1, k, n, a, A, m, L, 0, c1, t1);
            ok &= !memcmp(c1, c2, L) && !memcmp(t1, t2, 32);
            dense++;
        }
        CAS++;
        ECHECS += !ok;
        snprintf(JS, sizeof JS, ", \"cas_avec_permutation_dense\": %ld", dense);
    }
}

/* ---------------------------------------------------------------- forge */
#define NT_FORGE 20
static void m_forge(void)
{
    static uint8_t k[64], n1[24], n2[24], a1[400], a2[400], m1[800], m2[800], c1[1000], c2[1000], t1[32], t2[32];
    /* tailles : AAD ≤ 300 + 600 (frontière déplacée du chiffré vers les AAD) + 100 (ajout) ; chiffré ≤ 600 + 300 + 100 */
    static uint8_t K[64], N[24], Aa[1200], C[1200], T[32], P[1200];
    long par_type[NT_FORGE] = {0}, saute = 0, acceptes = 0, non_effaces = 0;
    while (!fini()) {
        size_t A1 = taille(300), L1 = taille(600), A2 = taille(300), L2 = taille(600);
        remplir(k, 64); remplir(n1, 24); remplir(n2, 24); remplir(a1, A1); remplir(a2, A2); remplir(m1, L1); remplir(m2, L2);
        if (!memcmp(n1, n2, 24))
            continue;
        aead(perm1, k, n1, a1, A1, m1, L1, 0, c1, t1);
        aead(perm1, k, n2, a2, A2, m2, L2, 0, c2, t2);
        memcpy(K, k, 64); memcpy(N, n1, 24); memcpy(Aa, a1, A1); memcpy(C, c1, L1); memcpy(T, t1, 32);
        size_t A = A1, L = L1;
        int t = (int)(xo() % NT_FORGE), applicable = 1;
        switch (t) {
        case 0: if (L) C[xo() % L] ^= (uint8_t)(1 << (xo() % 8)); else applicable = 0; break;
        case 1: T[xo() % 32] ^= (uint8_t)(1 << (xo() % 8)); break;
        case 2: if (A) Aa[xo() % A] ^= (uint8_t)(1 << (xo() % 8)); else applicable = 0; break;
        case 3: N[xo() % 24] ^= (uint8_t)(1 << (xo() % 8)); break;
        case 4: K[xo() % 64] ^= (uint8_t)(1 << (xo() % 8)); break;
        case 5: if (L) L -= 1 + xo() % L; else applicable = 0; break;
        case 6: { size_t e = 1 + xo() % 100; remplir(C + L, e); L += e; } break;
        case 7: if (A) A -= 1 + xo() % A; else applicable = 0; break;
        case 8: { size_t e = 1 + xo() % 100; remplir(Aa + A, e); A += e; } break;
        case 9: if (A) { size_t q = 1 + xo() % A; memmove(C + q, C, L); memcpy(C, Aa + A - q, q); A -= q; L += q; } else applicable = 0; break;
        case 10: if (L) { size_t q = 1 + xo() % L; memcpy(Aa + A, C, q); memmove(C, C + q, L - q); A += q; L -= q; } else applicable = 0; break;
        case 11: if (L >= 160) { size_t nb = L / 80, i = xo() % nb, j = xo() % nb; uint8_t tmp[80];
                     if (i == j || !memcmp(C + 80 * i, C + 80 * j, 80)) { applicable = 0; break; }
                     memcpy(tmp, C + 80 * i, 80); memcpy(C + 80 * i, C + 80 * j, 80); memcpy(C + 80 * j, tmp, 80); } else applicable = 0;
                 break;
        case 12: if (L >= 80 && L2 >= 80) { size_t i = xo() % (L / 80), j = xo() % (L2 / 80); memcpy(C + 80 * i, c2 + 80 * j, 80); } else applicable = 0;
                 break;
        case 13: memcpy(T, t2, 32); break;
        case 14: memcpy(N, n2, 24); memcpy(C, c2, L2); L = L2; memcpy(T, t2, 32); break;   /* AAD de 1, reste de 2 */
        case 15: for (int q = 2 + (int)(xo() % 7); q > 0; q--) { int z = (int)(xo() % 4);
                     if (z == 0) T[xo() % 32] ^= 1; else if (z == 1) N[xo() % 24] ^= 2;
                     else if (z == 2 && L) C[xo() % L] ^= 4; else if (A) Aa[xo() % A] ^= 8; } break;
        case 16: memset(T, 0, 32); break;
        case 17: remplir(T, 32); break;
        case 18: memcpy(C, c2, L2); L = L2; memcpy(T, t2, 32); break;   /* nonce et AAD de 1, chiffré et tag de 2 */
        case 19: if (L >= 160) { size_t i = xo() % (L / 80 - 1); memmove(C + 80 * i, C + 80 * (i + 1), L - 80 * (i + 1)); L -= 80; } else applicable = 0;
                 break;
        }
        /* le tuple falsifié ne doit être aucun des deux tuples valides */
        int egal1 = !memcmp(K, k, 64) && !memcmp(N, n1, 24) && A == A1 && !memcmp(Aa, a1, A) && L == L1 && !memcmp(C, c1, L) && !memcmp(T, t1, 32);
        int egal2 = !memcmp(K, k, 64) && !memcmp(N, n2, 24) && A == A2 && !memcmp(Aa, a2, A) && L == L2 && !memcmp(C, c2, L) && !memcmp(T, t2, 32);
        if (!applicable || egal1 || egal2) {
            saute++;
            continue;
        }
        memset(P, 0xEE, L);
        int r, z = 1;
        if (TEMOIN) {   /* déchiffrement fautif : dernier octet du tag non comparé */
            uint8_t tt[32];
            memcpy(tt, T, 32);
            uint8_t vrai[32];
            aead(perm1, K, N, Aa, A, C, L, 1, P, vrai);
            tt[31] = vrai[31];
            r = aead_ouvrir(K, N, Aa, A, C, L, tt, P);
        } else
            r = aead_ouvrir(K, N, Aa, A, C, L, T, P);
        for (size_t q = 0; q < L; q++)
            z &= P[q] == 0;
        par_type[t]++;
        CAS++;
        acceptes += r != -1;
        non_effaces += !z;
        ECHECS += r != -1 || !z;
        int o = snprintf(JS, sizeof JS, ", \"acceptes\": %ld, \"non_effaces\": %ld, \"sautes\": %ld, \"par_type\": [", acceptes,
                         non_effaces, saute);
        for (int q = 0; q < NT_FORGE; q++)
            o += snprintf(JS + o, sizeof JS - (size_t)o, "%s%ld", q ? ", " : "", par_type[q]);
        snprintf(JS + o, sizeof JS - (size_t)o, "]");
    }
}

/* ---------------------------------------------------------------- multi */
static void m_multi(void)
{
    const size_t NMAX = 700, LMAX = 300, AMAX = 200;
    uint8_t *k = malloc(64 * NMAX), *n = malloc(24 * NMAX), *a = malloc(AMAX), *m = malloc(NMAX * LMAX), *c = malloc(NMAX * LMAX),
            *t = malloc(32 * NMAX), c1[LMAX], t1[32];
    long lots256 = 0;
    while (!fini()) {
        size_t N = 1 + xo() % NMAX, L = taille(LMAX), A = taille(AMAX);
        remplir(k, 64 * N); remplir(n, 24 * N); remplir(a, A); remplir(m, N * L);
        aead_multi(N, k, n, a, A, m, L, c, t);
        int ok = 1;
        for (size_t j = 0; j < N; j++) {
            aead(perm1, k + 64 * j, n + 24 * j, a, A, m + j * L, L, 0, c1, t1);
            ok &= !memcmp(c1, c + j * L, L) && !memcmp(t1, t + 32 * j, 32);
        }
        lots256 += N >= 128 ? (long)(N / 256) : 0;
        CAS++;
        ECHECS += !ok;
        snprintf(JS, sizeof JS, ", \"lots_bitslices\": %ld", lots256);
    }
    free(k); free(n); free(a); free(m); free(c); free(t);
}

/* ---------------------------------------------------------------- statistiques */
static double zbin(double compte, double n) { return n > 0 ? (compte - n / 2) / sqrt(n / 4) : 0; }

static void m_aval(void)
{
    static uint8_t k[64], n[24], a[200], m[400], c0[400], c1[400], t0[32], t1[32];
    static double pos[256], champ_n[4], champ_s[4], champ_s2[4], ct_flip = 0, ct_bits = 0, ct_suite_flip = 0, ct_suite_bits = 0;
    long structure = 0, nflips = 0;
    while (!fini()) {
        size_t A = taille(200), L = taille(400);
        remplir(k, 64); remplir(n, 24); remplir(a, A); remplir(m, L);
        aead(perm1, k, n, a, A, m, L, 0, c0, t0);
        int f = (int)(xo() % 4);
        if ((f == 2 && !A) || (f == 3 && !L))
            f = (int)(xo() % 2);
        size_t p = 0;
        int b = (int)(xo() % 8);
        uint8_t *cible = f == 0 ? k : f == 1 ? n : f == 2 ? a : m;
        size_t lc = f == 0 ? 64 : f == 1 ? 24 : f == 2 ? A : L;
        p = xo() % lc;
        cible[p] ^= (uint8_t)(1 << b);
        aead(perm1, k, n, a, A, m, L, 0, c1, t1);
        if (TEMOIN && xo() % 50 == 0)   /* biais planté : le bit 0 du tag ne change pas */
            t1[0] = (uint8_t)((t1[0] & ~1) | (t0[0] & 1));
        int hd = 0;
        for (int i = 0; i < 256; i++) {
            int d = (t0[i / 8] ^ t1[i / 8]) >> (i % 8) & 1;
            hd += d;
            pos[i] += d;
        }
        nflips++;
        champ_n[f]++; champ_s[f] += hd; champ_s2[f] += (double)hd * hd;
        if (f < 3) {   /* clé, nonce ou AAD : tout le chiffré change au hasard */
            for (size_t i = 0; i < L; i++)
                ct_flip += __builtin_popcount(c0[i] ^ c1[i]);
            ct_bits += 8.0 * L;
        } else {       /* clair, bit b de l'octet p, bloc j : exactement ce bit dans le bloc j ; au hasard après */
            size_t j = p / 80;
            for (size_t i = 80 * j; i < L && i < 80 * (j + 1); i++)
                structure += (c0[i] ^ c1[i]) != (i == p ? (1 << b) : 0);
            for (size_t i = 80 * (j + 1); i < L; i++)
                ct_suite_flip += __builtin_popcount(c0[i] ^ c1[i]);
            ct_suite_bits += 8.0 * (L > 80 * (j + 1) ? L - 80 * (j + 1) : 0);
        }
        CAS++;
        ECHECS = structure;
        double zmax = 0, chi = 0;
        for (int i = 0; i < 256; i++) {
            double z = zbin(pos[i], (double)nflips);
            chi += z * z;
            if (fabs(z) > zmax) zmax = fabs(z);
        }
        double zchi = (chi - 256) / sqrt(512), zf[4];
        for (int q = 0; q < 4; q++)   /* distance de Hamming moyenne du tag : 128, écart type 8 */
            zf[q] = champ_n[q] ? (champ_s[q] / champ_n[q] - 128) / (8 / sqrt(champ_n[q])) : 0;
        double zct = zbin(ct_flip, ct_bits), zsuite = zbin(ct_suite_flip, ct_suite_bits);
        int stat_ok = zmax < 6 && fabs(zchi) < 6 && fabs(zct) < 6 && fabs(zsuite) < 6;
        for (int q = 0; q < 4; q++)
            stat_ok &= fabs(zf[q]) < 6;
        if (!stat_ok && CAS > (TEMOIN ? 100000 : 1000000))
            ECHECS = structure + 1;
        snprintf(JS, sizeof JS, ", \"violations_structure\": %ld, \"tag_position_zmax\": %.2f, \"tag_positions_z_chi2\": %.2f, "
                 "\"tag_hd_z\": {\"cle\": %.2f, \"nonce\": %.2f, \"aad\": %.2f, \"clair\": %.2f}, \"chiffre_z\": %.2f, "
                 "\"chiffre_apres_bloc_z\": %.2f, \"bits_chiffre\": %.0f", structure, zmax, zchi, zf[0], zf[1], zf[2], zf[3],
                 zct, zsuite, ct_bits + ct_suite_bits);
    }
}

static void m_biais(void)
{
    enum { LB = 640 };
    static uint8_t k[64], n[24], m[LB], c[LB], t[32];
    static double bits[LB * 8], tbits[256], octets[256], paires[65536];
    double nmsg = 0;
    remplir(k, 64);
    remplir(n, 24);
    uint64_t compteur = 0;
    while (!fini()) {
        for (int rep = 0; rep < 1000; rep++) {
            uint8_t kk[64], nn[24];
            memcpy(kk, k, 64);
            memcpy(nn, n, 24);
            if (compteur & 1)   /* clés en compteur (nonce fixe), sinon nonces en compteur (clé fixe) */
                for (int q = 0; q < 8; q++) kk[q] ^= (uint8_t)((compteur >> 1) >> (8 * q));
            else
                for (int q = 0; q < 8; q++) nn[q] ^= (uint8_t)((compteur >> 1) >> (8 * q));
            compteur++;
            aead(perm1, kk, nn, NULL, 0, m, LB, 0, c, t);
            if (TEMOIN && xo() % 100 == 0)   /* biais planté : le bit 0 du flux vaut 1 un peu plus souvent */
                c[0] |= 1;
            for (int i = 0; i < LB * 8; i++)
                bits[i] += c[i / 8] >> (i % 8) & 1;
            for (int i = 0; i < 256; i++)
                tbits[i] += t[i / 8] >> (i % 8) & 1;
            for (int i = 0; i < LB; i++)
                octets[c[i]]++;
            for (int i = 0; i + 1 < LB; i++)
                paires[c[i] << 8 | c[i + 1]]++;
            nmsg++;
        }
        CAS = (long)nmsg;
        double zmax = 0, ztmax = 0, chio = 0, chip = 0, no = nmsg * LB, np = nmsg * (LB - 1);
        for (int i = 0; i < LB * 8; i++) { double z = fabs(zbin(bits[i], nmsg)); if (z > zmax) zmax = z; }
        for (int i = 0; i < 256; i++) { double z = fabs(zbin(tbits[i], nmsg)); if (z > ztmax) ztmax = z; }
        for (int i = 0; i < 256; i++) { double e = no / 256, d = octets[i] - e; chio += d * d / e; }
        for (int i = 0; i < 65536; i++) { double e = np / 65536, d = paires[i] - e; chip += d * d / e; }
        double zo = (chio - 255) / sqrt(510), zp = (chip - 65535) / sqrt(131070);
        ECHECS = (zmax > 6 || ztmax > 6 || fabs(zo) > 6 || fabs(zp) > 6) && nmsg > 100000;
        snprintf(JS, sizeof JS, ", \"messages\": %.0f, \"flux_position_zmax\": %.2f, \"tag_position_zmax\": %.2f, "
                 "\"octets_z_chi2\": %.2f, \"paires_z_chi2\": %.2f, \"bits_flux\": %.0f", nmsg, zmax, ztmax, zo, zp, nmsg * LB * 8);
    }
}

/* ---------------------------------------------------------------- fils : déterminisme selon le nombre de threads */
static void m_fils(void)
{
    const size_t TMAX = (size_t)40 << 20, NMAX = 4000, LMAX = 200, AMAX = 100;
    uint8_t *m = malloc(TMAX), *k = malloc(64 * NMAX), *n = malloc(24 * NMAX), *a = malloc(AMAX), *c1 = malloc(NMAX * LMAX),
            *c2 = malloc(NMAX * LMAX), *t1 = malloc(32 * NMAX), *t2 = malloc(32 * NMAX), h1[64], h2[64];
    remplir(m, TMAX);
    const int T[] = {2, 3, 5, 8, 12};
    long arbres = 0, lots = 0;
    while (!fini()) {
        int ok = 1;
        if (xo() & 1) {   /* arbre : longueur près d'un multiple de feuilles, parfois au-delà du seuil bitslicé */
            size_t L = 8193 + xo() % (TMAX - 8193);
            if (xo() & 1) L = (L / 8192) * 8192 + xo() % 3;
            if (L > TMAX) L = TMAX;
            omp_set_num_threads(1);
            arbre(m, L, h1, 64, 1);
            for (int i = 0; i < 5; i++) {
                omp_set_num_threads(T[i]);
                arbre(m, L, h2, 64, 1);
                ok &= !memcmp(h1, h2, 64);
            }
            arbres++;
        } else {          /* AEAD multi */
            size_t N = 1 + xo() % NMAX, L = taille(LMAX), A = taille(AMAX);
            remplir(k, 64 * N); remplir(n, 24 * N); remplir(a, A); remplir(m, N * L);
            omp_set_num_threads(1);
            aead_multi(N, k, n, a, A, m, L, c1, t1);
            for (int i = 0; i < 5; i++) {
                omp_set_num_threads(T[i]);
                aead_multi(N, k, n, a, A, m, L, c2, t2);
                ok &= !memcmp(c1, c2, N * L) && !memcmp(t1, t2, 32 * N);
            }
            lots++;
        }
        CAS++;
        ECHECS += !ok;
        snprintf(JS, sizeof JS, ", \"arbres\": %ld, \"aead_multi\": %ld, \"threads\": [1, 2, 3, 5, 8, 12]", arbres, lots);
    }
    omp_set_num_threads(1);
    free(m); free(k); free(n); free(a); free(c1); free(c2); free(t1); free(t2);
}

/* ---------------------------------------------------------------- grand : au-delà de 2^32 octets (un seul passage) */
static void motif(uint8_t *p, size_t n)   /* contenu reproductible, rapide */
{
    uint64_t x = 0x243F6A8885A308D3ULL;
    for (size_t i = 0; i + 8 <= n; i += 8) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        memcpy(p + i, &x, 8);
    }
    for (size_t i = n & ~(size_t)7; i < n; i++)
        p[i] = (uint8_t)i;
}
static void m_grand(void)
{
    const size_t LA = ((size_t)1 << 32) + 1234, LT = ((size_t)1 << 32) + 3 * 8192 + 7;
    uint8_t *m = malloc(LT), *c = malloc(LA), k[64], n[24], a[100], t1[32], t2[32], h1[64], h2[64], h3[64];
    if (!m || !c) { ECHECS = 1; snprintf(JS, sizeof JS, ", \"erreur\": \"mémoire\""); return; }
    remplir(k, 64); remplir(n, 24); remplir(a, 100);
    motif(m, LT);
    double t0 = maintenant();
    aead(perm1, k, n, a, 100, m, LA, 0, c, t1);                 /* chiffré dans c */
    aead_kd(perm1, k, n, a, 100, m, LA, 0, m, t2);              /* référence DMV17 sur place : m devient le chiffré */
    int ok_kd = !memcmp(c, m, LA) && !memcmp(t1, t2, 32);
    int ok_rt = aead_ouvrir(k, n, a, 100, c, LA, t1, m) == 0;   /* m redevient le clair */
    int ok_clair = 0;
    uint8_t *mm = malloc(LT);   /* le motif d'origine, recalculé, pour comparer le clair retrouvé */
    if (mm) { motif(mm, LT); ok_clair = !memcmp(mm, m, LA); free(mm); }
    c[LA / 2] ^= 1;
    int ok_rej = aead_ouvrir(k, n, a, 100, c, LA, t1, m) == -1 && m[0] == 0 && m[LA - 1] == 0;
    double ta = maintenant() - t0;
    motif(m, LT);
    omp_set_num_threads(omp_get_num_procs());
    arbre(m, LT, h1, 64, 1);                                     /* lots bitslicés */
    arbre(m, LT, h2, 64, 0);                                     /* éponges seules */
    omp_set_num_threads(1);
    arbre(m, LT, h3, 64, 1);                                     /* un thread : lots bitslicés */
    int ok_arbre = !memcmp(h1, h2, 64) && !memcmp(h1, h3, 64);
    CAS = 1;
    ECHECS = !(ok_kd && ok_rt && ok_clair && ok_rej && ok_arbre);
    snprintf(JS, sizeof JS, ", \"aead_octets\": %zu, \"arbre_octets\": %zu, \"aead_egal_reference_dmv17\": %s, "
             "\"aller_retour\": %s, \"clair_retrouve\": %s, \"alteration_rejetee_et_effacee\": %s, \"arbre_bitslice_egal_eponges_et_1_thread\": %s, "
             "\"duree_aead_s\": %.0f", LA, LT, ok_kd ? "true" : "false", ok_rt ? "true" : "false", ok_clair ? "true" : "false",
             ok_rej ? "true" : "false", ok_arbre ? "true" : "false", ta);
    free(m); free(c);
}

int main(int argc, char **argv)
{
    if (argc < 5)
        return 2;
    MODE = argv[1];
    TEMOIN = getenv("CAMPAGNE_TEMOIN") != NULL;
    double duree = atof(argv[2]);
    uint64_t g = strtoull(argv[3], NULL, 10);
    FICHIER = argv[4];
    for (int i = 0; i < 4; i++) {
        g += 0x9E3779B97F4A7C15ULL;
        uint64_t z = g;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        X[i] = z ^ (z >> 31);
    }
    if (!bref_init() || !ref_init() || !init_noyaux())
        return 2;
    prepare_iv();
    sl_init();
    omp_set_num_threads(1);
    DEBUT = maintenant();
    ECHEANCE = DEBUT + duree;
    if (!strcmp(MODE, "equiv")) m_equiv();
    else if (!strcmp(MODE, "forge")) m_forge();
    else if (!strcmp(MODE, "multi")) m_multi();
    else if (!strcmp(MODE, "aval")) m_aval();
    else if (!strcmp(MODE, "biais")) m_biais();
    else if (!strcmp(MODE, "fils")) m_fils();
    else if (!strcmp(MODE, "grand")) m_grand();
    else return 2;
    ecrire(1, JS);
    return ECHECS != 0;
}
