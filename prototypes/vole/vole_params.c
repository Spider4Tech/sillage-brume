/* Piste 9 : paramètres d'une signature VOLE-in-the-Head sur SD régulier, avec l'estimateur ISD du projet
 * (mémoire gratuite, favorable à l'attaquant), et non celui de SDitH.
 * Réduction (SDitH v2.0, Théorème 5.1) : résoudre (n, k_rsd, w)-RSD en 2^λ' donne (n, k_sd, w)-SD en
 *     λ' + log2(C(n, w) / (n/w)^w) + 1/(θ ln 2),   k_sd = n − log2 C(n, w),   n − k_rsd ≥ w·log2(n/w) + log2 θ.
 * 1. Contrôles : retrouve les tailles SDitH2 (formule § 4.2) et confronte ses instances à notre estimateur.
 * 2. Réduction EXACTE (Lemme 17.2) : codimension ⌈log2 C(n, w)⌉, aucune ligne retirée, aucune heuristique ; mesurée sur de
 *    petites instances (succès égal à la prédiction exacte).
 * 3. Pour un niveau visé λ', meilleur (μ, w) d'une GRILLE à blocs EXACTS : bloc = n/w = μ_1·μ_2·μ_3·μ_4 (d = 4, 2 ≤ μ_t ≤ 8),
 *    n ≤ 40 000. Avec un produit > bloc, les positions en trop donnent un bloc vide et la preuve ne porte plus sur SD régulier
 *    (constat du 11 nov. 2026) : la règle est désormais imposée. Graines de λ + 8 bits et sel de 32 octets, comme la SIG actuelle.
 *    Ce n'est pas un optimum global ; la dichotomie sur w suppose une monotonie que le contrôle échantillonne seulement.
 *    Le coût « RSD » est celui de la réduction, pas celui d'une attaque directe (rsd_attaques.c).
 *     build/vole_params   (depuis la racine) → resultats/vole_params.json
 */
#include <math.h>

#include "resultat.h"
#include "sillage.h"

static double lb(double n, double k) { return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2.0); }

static double sd_cout(int n, int k, int w)
{
    double o[6], pr = sl_isd_prange(n, k, w), m = pr;
    double t = sl_isd_deux_listes(n, k, w, 1, 400, 1000, -1.0, o);
    m = t < m ? t : m;
    t = sl_isd_bjmm(n, k, w, 400, 100, 1500, o);
    return t < m ? t : m;
}

/* perte de la réduction, θ = 2^10 comme les instances SDitH (terme 1/(θ ln 2) négligeable mais compté) */
static double perte(int n, int w) { return lb(n, w) - w * log2((double)n / w) + 1 / (1024 * log(2.0)); }

static int k_sd(int n, int w) { return n - (int)ceil(lb(n, w)); }

static int ceil8(int x) { return 8 * ((x + 7) / 8); }

/* § 4.2 : salt + h_piop, aux, α' en clair, Δwit, (α_i), ouverture ; graines de sb bits, sel de slb bits (SDitH : λ et λ) */
static long taille_bits(int lam, int sb, int slb, int w, int sum_mu, int d, int tau, int topen, int B)
{
    int wit = ceil8(w * sum_mu);
    return slb + 2L * lam + (tau - 1) * (wit + (d - 1) * lam + lam + B) + (lam + B) + wit + d * lam + sb * (long)topen + tau * (2L * lam) + 32;
}

/* Lemme 17.2 (PROOFS § 3 bis), réduction EXACTE : codimension r = ⌈log2 C(n, w)⌉ arrondie au multiple de 8, aucune ligne
 * retirée. Toute solution régulière de Ĥσ est une solution SD de poids w, sans hypothèse d'unicité. Perte : la probabilité
 * qu'un x de poids w soit régulier après permutation, b^w / C(n, w), et celle que Ĥσ se mette sous forme [H' | I],
 * Π (1 − 2^−i) ≥ 0,288788. */
#define LOG2_INV_SYST 1.7919                             /* log2(1 / 0,288788) */
static int cod_exacte(int n, int w) { return 8 * (((int)ceil(lb(n, w)) + 7) / 8); }
static double marge_rsd(int n, int w)
{
    return sd_cout(n, n - cod_exacte(n, w), w) - (lb(n, w) - w * log2((double)n / w)) - LOG2_INV_SYST;
}

/* La réduction mesurée sur de petites instances : SD (n, n − r, w) aléatoire, permutation, forme systématique, solveur RSD
 * exhaustif. Le lemme minore le succès par b^w/C(n, w) · Π_{i ≤ r} (1 − 2^−i) (x̂ régulier), quelle que soit l'unicité des
 * solutions. B réussit aussi si x̂ n'est pas régulier mais qu'une autre solution régulière existe (b^w/2^r en moyenne) :
 * prédiction affinée Π·[p + (1 − p)(1 − e^(−b^w/2^r))], à laquelle la mesure doit coller. */
static uint64_t xs64(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }
static int reduction_mesuree(int n, int w, int r, long essais, uint64_t graine, double *mes, double *pred, double *z, double *multi, double *fine)
{
    int b = n / w;
    uint64_t s = graine;
    long ok = 0, plusieurs = 0;
    uint32_t col[64], perm[64];
    for (long t = 0; t < essais; t++) {
        for (int j = 0; j < n; j++) col[j] = (uint32_t)xs64(&s) & ((1u << r) - 1);
        int x[64] = {0}, k = 0;
        while (k < w) { int j = (int)(xs64(&s) % (uint64_t)n); if (!x[j]) { x[j] = 1; k++; } }
        uint32_t y = 0;
        for (int j = 0; j < n; j++) if (x[j]) y ^= col[j];
        for (int j = 0; j < n; j++) perm[j] = (uint32_t)j;                 /* σ uniforme */
        for (int j = n - 1; j > 0; j--) { int u = (int)(xs64(&s) % (uint64_t)(j + 1)); uint32_t v = perm[j]; perm[j] = perm[u]; perm[u] = v; }
        uint32_t h[64];
        for (int j = 0; j < n; j++) h[j] = col[perm[j]];
        /* forme systématique : élimination sur les r dernières colonnes (lignes = bits) ; échec si elles sont liées */
        uint64_t L[32];
        for (int i = 0; i < r; i++) { L[i] = 0; for (int j = 0; j < n; j++) L[i] |= (uint64_t)((h[j] >> i) & 1u) << j; }
        uint32_t ys = y;
        int sing = 0;
        for (int c = 0; c < r && !sing; c++) {
            int jc = n - r + c, piv = -1;
            for (int i = c; i < r; i++) if ((L[i] >> jc) & 1) { piv = i; break; }
            if (piv < 0) { sing = 1; break; }
            uint64_t tl = L[piv]; L[piv] = L[c]; L[c] = tl;
            uint32_t bp = (ys >> piv) & 1, bc = (ys >> c) & 1;
            ys = (ys & ~((1u << piv) | (1u << c))) | (bp << c) | (bc << piv);
            for (int i = 0; i < r; i++)
                if (i != c && ((L[i] >> jc) & 1)) { L[i] ^= L[c]; ys ^= ((ys >> c) & 1u) << i; }
        }
        if (sing) continue;
        /* solveur RSD exhaustif sur [H'' | I] : b^w candidats, renvoie la première solution */
        uint32_t hc[64];
        for (int j = 0; j < n; j++) { hc[j] = 0; for (int i = 0; i < r; i++) hc[j] |= (uint32_t)((L[i] >> j) & 1) << i; }
        long nsol = 0, trouve = -1;
        long tot = 1;
        for (int i = 0; i < w; i++) tot *= b;
        for (long code = 0; code < tot; code++) {
            long q = code;
            uint32_t acc = 0;
            for (int i = 0; i < w; i++) { acc ^= hc[i * b + (int)(q % b)]; q /= b; }
            if (acc == ys) { nsol++; if (trouve < 0) trouve = code; }
        }
        if (nsol > 1) plusieurs++;
        if (trouve < 0) continue;
        /* vérification sur l'instance SD d'origine : x = σ(x̂), poids w, H·x = y */
        long q = trouve;
        uint32_t acc = 0;
        for (int i = 0; i < w; i++) { acc ^= col[perm[i * b + (int)(q % b)]]; q /= b; }
        ok += acc == y;
    }
    double p = 1, preg = exp(w * log((double)b) - lb(n, w) * log(2.0));
    for (int i = 1; i <= r; i++) p *= 1 - ldexp(1, -i);
    *pred = preg * p;                                                   /* borne du lemme */
    *fine = p * (preg + (1 - preg) * (1 - exp(-exp(w * log((double)b)) * ldexp(1, -r))));
    *mes = (double)ok / (double)essais;
    double sd = sqrt(*fine * (1 - *fine) / (double)essais);
    *z = (*mes - *fine) / sd;
    *multi = (double)plusieurs / (double)essais;
    return fabs(*z) < 4 && *mes > *pred - 4 * sd;
}

/* Lemme 17.2, forme directe (12 nov. 2026). (H3) est posée sous forme systématique [H' | I] (PROOFS § 1) : B transmet son
 * instance telle quelle au solveur RSD. x de poids w uniforme est régulier avec probabilité b^w/C(n, w), indépendamment de H',
 * et, conditionné à cet événement, (H', x) suit exactement la loi du générateur de clés. Ni permutation, ni élimination :
 * borne b^w/C(n, w), sans le facteur Π (1 − 2^−i). Prédiction affinée p + (1 − p)(1 − e^(−b^w/2^r)). */
static int reduction_directe(int n, int w, int r, long essais, uint64_t graine, double *mes, double *pred, double *z, double *fine)
{
    int b = n / w, k = n - r;
    uint64_t s = graine;
    long ok = 0;
    uint32_t col[64];
    long tot = 1;
    for (int i = 0; i < w; i++) tot *= b;
    for (long t = 0; t < essais; t++) {
        for (int j = 0; j < k; j++) col[j] = (uint32_t)xs64(&s) & ((1u << r) - 1);   /* H' uniforme */
        for (int i = 0; i < r; i++) col[k + i] = 1u << i;                             /* bloc identité */
        int x[64] = {0}, c = 0;
        while (c < w) { int j = (int)(xs64(&s) % (uint64_t)n); if (!x[j]) { x[j] = 1; c++; } }
        uint32_t y = 0;
        for (int j = 0; j < n; j++) if (x[j]) y ^= col[j];
        long trouve = -1;                                     /* solveur RSD exhaustif, sur l'instance elle-même */
        for (long code = 0; code < tot && trouve < 0; code++) {
            long q = code;
            uint32_t acc = 0;
            for (int i = 0; i < w; i++) { acc ^= col[i * b + (int)(q % b)]; q /= b; }
            if (acc == y) trouve = code;
        }
        ok += trouve >= 0;                                    /* solution régulière, donc de poids w : solution de (H3) */
    }
    double preg = exp(w * log((double)b) - lb(n, w) * log(2.0));
    *pred = preg;
    *fine = preg + (1 - preg) * (1 - exp(-exp(w * log((double)b)) * ldexp(1, -r)));
    *mes = (double)ok / (double)essais;
    double sd = sqrt(*fine * (1 - *fine) / (double)essais);
    *z = (*mes - *fine) / sd;
    return fabs(*z) < 4 && *mes > *pred - 4 * sd;
}

int main(void)
{
    resultat_t r = {.nom = "vole_params"};
    static const struct { const char *nom; int lam, n, cod, w, d, sm, tau, topen, sig, cible; } SD[3] = {
        {"SDitH2-L1-short", 128, 10360, 432, 56, 4, 11, 11, 107, 3705, 143},
        {"SDitH2-L3-short", 192, 18396, 592, 73, 4, 12, 16, 157, 7964, 207},
        {"SDitH2-L5-short", 256, 19864, 800, 104, 4, 11, 21, 216, 14121, 272},
    };
    int ok = 1;
    static char json[20000];
    size_t lj = (size_t)snprintf(json, sizeof json, "{\"sdith\":[");
    for (int i = 0; i < 3; i++) {
        long z = taille_bits(SD[i].lam, SD[i].lam, SD[i].lam, SD[i].w, SD[i].sm, SD[i].d, SD[i].tau, SD[i].topen, 16) / 8;
        double p = perte(SD[i].n, SD[i].w), c = sd_cout(SD[i].n, k_sd(SD[i].n, SD[i].w), SD[i].w);
        ok &= z == SD[i].sig;
        double marge = c - p;
        printf("%s : taille %ld o (spéc. %d) ; k_sd=%d, perte %.1f, SD %.1f b → RSD ≥ %.1f b chez nous (visé par SDitH : %d)\n", SD[i].nom, z, SD[i].sig, k_sd(SD[i].n, SD[i].w), p, c, marge, SD[i].cible);
        fflush(stdout);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"nom\":\"%s\",\"taille\":%ld,\"perte\":%.1f,\"sd\":%.1f,\"rsd_garanti\":%.1f}", i ? "," : "", SD[i].nom, z, p, c, marge);
    }
    lj += (size_t)snprintf(json + lj, sizeof json - lj, "]");
    res_controle(&r, "formule_de_taille_retrouve_sdith2", ok);
    {   /* Lemme 17.2 mesuré : (n, w, b) = (48, 3, 16), r = 16 ⩾ log2 C(48, 3) = 14,1, et (60, 4, 15), r = 24 */
        static const int I[2][3] = {{48, 3, 16}, {60, 4, 24}};
        int bon = 1;
        lj += (size_t)snprintf(json + lj, sizeof json - lj, ",\"reduction_exacte\":[");
        for (int i = 0; i < 2; i++) {
            double mes, pred, z, multi, fine;
            bon &= reduction_mesuree(I[i][0], I[i][1], I[i][2], i ? 20000 : 200000, 0x9E3779B97F4A7C15ULL + (uint64_t)i, &mes, &pred, &z, &multi, &fine);
            printf("réduction exacte SD → RSD, n=%d w=%d r=%d : succès %.5f ≥ borne du lemme %.5f ; prédiction affinée %.5f (z = %+.2f) ; instances à plusieurs solutions régulières : %.4f\n",
                   I[i][0], I[i][1], I[i][2], mes, pred, fine, z, multi);
            fflush(stdout);
            lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"n\":%d,\"w\":%d,\"r\":%d,\"succes\":%.5f,\"borne_lemme\":%.5f,\"prediction_affinee\":%.5f,\"z\":%.2f,\"plusieurs_solutions\":%.4f}",
                                   i ? "," : "", I[i][0], I[i][1], I[i][2], mes, pred, fine, z, multi);
        }
        res_controle(&r, "reduction_exacte_sd_vers_rsd_mesuree", bon);
        /* forme directe sur (H3) systématique : mêmes instances, sans permutation ni élimination */
        int bon_d = 1;
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "],\"reduction_directe\":[");
        for (int i = 0; i < 2; i++) {
            double mes, pred, z, fine;
            bon_d &= reduction_directe(I[i][0], I[i][1], I[i][2], i ? 20000 : 200000, 0xD1B54A32D192ED03ULL + (uint64_t)i, &mes, &pred, &z, &fine);
            printf("réduction directe (H3) systématique → RSD, n=%d w=%d r=%d : succès %.5f ≥ borne b^w/C(n,w) %.5f ; prédiction affinée %.5f (z = %+.2f)\n",
                   I[i][0], I[i][1], I[i][2], mes, pred, fine, z);
            fflush(stdout);
            lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"n\":%d,\"w\":%d,\"r\":%d,\"succes\":%.5f,\"borne_lemme\":%.5f,\"prediction_affinee\":%.5f,\"z\":%.2f}",
                                   i ? "," : "", I[i][0], I[i][1], I[i][2], mes, pred, fine, z);
        }
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "],\"grille\":[");
        res_controle(&r, "reduction_directe_sd_systematique_vers_rsd_mesuree", bon_d);
    }
    static const struct { int lam, cible, tau, topen; } V[4] = {{128, 143, 11, 107}, {128, 160, 11, 107}, {256, 272, 21, 216}, {256, 316, 21, 216}};
    int prem = 1, mono = 1;
    for (int v = 0; v < 4; v++) {
        long meilleur = 1L << 60;
        int bw = 0, bs = 0, bloc_b = 0, bmu[4] = {0};
        double bc = 0;
        /* μ croissants de 2 à 8 ; pour chaque μ, plus petit w (dichotomie) tel que la réduction garantisse λ' */
#pragma omp parallel for schedule(dynamic) collapse(2)
        for (int m0 = 2; m0 <= 8; m0++)
            for (int m1 = 2; m1 <= 8; m1++)
                for (int m2 = m1; m2 <= 8; m2++)
                    for (int m3 = m2; m3 <= 8; m3++) {
                        if (m1 < m0) continue;
                        int bloc = m0 * m1 * m2 * m3, sm = m0 + m1 + m2 + m3 - 4, lo = 8, hi = 40000 / bloc;
                        if (hi <= lo || marge_rsd(hi * bloc, hi) < V[v].cible) continue;
                        while (hi - lo > 1) {
                            int m = (lo + hi) / 2;
                            if (marge_rsd(m * bloc, m) >= V[v].cible) hi = m; else lo = m;
                        }
                        long z = taille_bits(V[v].lam, V[v].lam + 8, 256, hi, sm, 4, V[v].tau, V[v].topen, 16) / 8;
#pragma omp critical
                        if (z < meilleur || (z == meilleur && hi * bloc < bw * bloc_b)) {
                            meilleur = z; bw = hi; bs = sm; bloc_b = bloc;
                            bmu[0] = m0; bmu[1] = m1; bmu[2] = m2; bmu[3] = m3;
                            bc = marge_rsd(hi * bloc, hi);
                        }
                    }
        int bn = bw * bloc_b, bk = bn - cod_exacte(bn, bw);
        /* monotonie en w, échantillonnée au μ retenu */
        double prec = -1e9;
        for (int i = 0; i < 6; i++) {
            int w = bw / 2 + i * bw / 5;
            if (w * bloc_b > 60000) break;
            double x_ = marge_rsd(w * bloc_b, w);
            mono &= x_ >= prec;
            prec = x_;
        }
        printf("λ=%d, λ'=%d : μ=(%d,%d,%d,%d) bloc %d, w=%d, n=%d k_rsd=%d (codim %d), témoin %d bits : %ld o, RSD ≥ %.1f b (forme directe du lemme : %.1f b)\n", V[v].lam, V[v].cible, bmu[0], bmu[1], bmu[2], bmu[3], bloc_b, bw, bn, bk, bn - bk, bw * bs, meilleur, bc, bc + LOG2_INV_SYST);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"lam\":%d,\"cible\":%d,\"mu\":[%d,%d,%d,%d],\"bloc\":%d,\"n\":%d,\"k_rsd\":%d,\"w\":%d,\"temoin\":%d,\"taille\":%ld,\"rsd\":%.1f,\"rsd_lemme_direct\":%.1f}", prem ? "" : ",", V[v].lam, V[v].cible, bmu[0], bmu[1], bmu[2], bmu[3], bloc_b, bn, bk, bw, bw * bs, meilleur, bc, bc + LOG2_INV_SYST);
        prem = 0;
        fflush(stdout);
    }
    res_controle(&r, "cout_de_reduction_monotone_en_w_sur_les_echantillons", mono);
    snprintf(json + lj, sizeof json - lj, "]}");
    res_mesure(&r, "resultats", "%s", json);
    return res_ecrire(&r);
}
