/* Piste 9 : paramètres d'une signature VOLE-in-the-Head sur SD régulier, avec l'estimateur ISD du projet
 * (mémoire gratuite, favorable à l'attaquant), et non celui de SDitH.
 * Réduction (SDitH v2.0, Théorème 5.1) : résoudre (n, k_rsd, w)-RSD en 2^λ' donne (n, k_sd, w)-SD en
 *     λ' + log2(C(n, w) / (n/w)^w) + 1/(θ ln 2),   k_sd = n − log2 C(n, w),   n − k_rsd ≥ w·log2(n/w) + log2 θ.
 * 1. Contrôles : retrouve les tailles SDitH2 (formule § 4.2) et confronte ses instances à notre estimateur.
 * 2. Pour un niveau visé λ', meilleur (n, w) d'une GRILLE : d = 4, w pair puis affiné d'une unité autour du minimum, n ≤ 40 000.
 *    Ce n'est pas un optimum global, et la dichotomie sur n suppose une monotonie que le contrôle echantillonne seulement.
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

/* arités μ de produit ≥ n/w, de somme des (μ−1) minimale, degré d fixé (greedy de SDitH § 4.1) */
static int cout_temoin(int bloc, int d)
{
    int s = 0, r = bloc;
    for (int i = d; i > 0; i--) {
        int m = (int)ceil(pow(r, 1.0 / i) - 1e-9);
        s += m - 1;
        r = (r + m - 1) / m;
    }
    return s;
}

static int ceil8(int x) { return 8 * ((x + 7) / 8); }

/* § 4.2 : salt + h_piop, aux, α' en clair, Δwit, (α_i), ouverture */
static long taille_bits(int lam, int w, int sum_mu, int d, int tau, int topen, int B)
{
    int wit = ceil8(w * sum_mu);
    return 3L * lam + (tau - 1) * (wit + (d - 1) * lam + lam + B) + (lam + B) + wit + d * lam + lam * (long)topen + tau * (2L * lam) + 32;
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
        long z = taille_bits(SD[i].lam, SD[i].w, SD[i].sm, SD[i].d, SD[i].tau, SD[i].topen, 16) / 8;
        double p = perte(SD[i].n, SD[i].w), c = sd_cout(SD[i].n, k_sd(SD[i].n, SD[i].w), SD[i].w);
        ok &= z == SD[i].sig;
        double marge = c - p;
        printf("%s : taille %ld o (spéc. %d) ; k_sd=%d, perte %.1f, SD %.1f b → RSD ≥ %.1f b chez nous (visé par SDitH : %d)\n", SD[i].nom, z, SD[i].sig, k_sd(SD[i].n, SD[i].w), p, c, marge, SD[i].cible);
        fflush(stdout);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"nom\":\"%s\",\"taille\":%ld,\"perte\":%.1f,\"sd\":%.1f,\"rsd_garanti\":%.1f}", i ? "," : "", SD[i].nom, z, p, c, marge);
    }
    lj += (size_t)snprintf(json + lj, sizeof json - lj, "],\"grille\":[");
    res_controle(&r, "formule_de_taille_retrouve_sdith2", ok);
    static const struct { int lam, cible, tau, topen; } V[4] = {{128, 143, 11, 107}, {128, 160, 11, 107}, {256, 272, 21, 216}, {256, 316, 21, 216}};
    int prem = 1, mono = 1;
    for (int v = 0; v < 4; v++) {
        long meilleur = 1L << 60;
        int bn = 0, bw = 0, bs = 0, bk = 0;
        double bc = 0;
        for (int passe = 0; passe < 2; passe++) {
        int w0 = passe ? bw - 3 : 36, w1 = passe ? bw + 3 : 240, pas = passe ? 1 : 4;
#pragma omp parallel for schedule(dynamic)
        for (int w = w0; w <= w1; w += pas) {
            int lo = w * 16, hi = 40000;
            hi -= hi % w;
            /* plus petit n multiple de w tel que SD ≥ λ' + perte */
            if (sd_cout(hi, k_sd(hi, w), w) - perte(hi, w) < V[v].cible)
                continue;
            while (hi - lo > 2 * w) {
                int m = lo + (hi - lo) / 2;
                m -= m % w;
                if (m <= lo) break;
                if (sd_cout(m, k_sd(m, w), w) - perte(m, w) >= V[v].cible) hi = m; else lo = m;
            }
            int sm = cout_temoin(hi / w, 4);
            long z = taille_bits(V[v].lam, w, sm, 4, V[v].tau, V[v].topen, 16) / 8;
#pragma omp critical
            if (z < meilleur) {
                meilleur = z; bn = hi; bw = w; bs = sm;
                bk = hi - 8 * (((int)ceil(w * log2((double)hi / w) + 10) + 7) / 8);
                bc = sd_cout(hi, k_sd(hi, w), w) - perte(hi, w);
            }
        }
        }
        /* monotonie en n, échantillonnée au w retenu */
        double prec = -1e9;
        for (int i = 0; i < 6; i++) {
            int m = bn / 2 + i * bn / 5;
            m -= m % bw;
            double x_ = sd_cout(m, k_sd(m, bw), bw) - perte(m, bw);
            mono &= x_ >= prec;
            prec = x_;
        }
        double x = (double)bn / bw;
        printf("λ=%d, λ'=%d : n=%d k_rsd=%d (codim %d) w=%d bloc %.0f témoin %d bits : %ld o, RSD ≥ %.1f b\n", V[v].lam, V[v].cible, bn, bk, bn - bk, bw, x, bw * bs, meilleur, bc);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"lam\":%d,\"cible\":%d,\"n\":%d,\"k_rsd\":%d,\"w\":%d,\"temoin\":%d,\"taille\":%ld,\"rsd\":%.1f}", prem ? "" : ",", V[v].lam, V[v].cible, bn, bk, bw, bw * bs, meilleur, bc);
        prem = 0;
        fflush(stdout);
    }
    res_controle(&r, "cout_de_reduction_monotone_en_n_sur_les_echantillons", mono);
    snprintf(json + lj, sizeof json - lj, "]}");
    res_mesure(&r, "resultats", "%s", json);
    return res_ecrire(&r);
}
