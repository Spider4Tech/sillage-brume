/* Lemme 0 (PREUVES § 1) : spectre de Fourier exact des distributions réelles de (H1-P) et (H2-P).
 *
 *   (H1-P)  E[(-1)^<a,s>]           = κ_w(|a|) · κ_w(|a·h̄|)
 *   (H2-P)  E[(-1)^<a,u> + <b,v'>]  = κ_w(|a|) · κ_w(|a·h̄ ⊕ b̃·s̄|) · κ_we^{n2}(|b|)²
 * avec κ_w(t) = K_w(t) / C(n, w) (Krawtchouk), h̄(z) = h(z^-1), b̃ = b posé sur les n2 positions tronquées.
 * Corollaire : les seuls tests linéaires de biais ±1 sont la parité de s (resp. de u), à toutes les tailles
 * (pour H2-P, dès que s ∉ {0, 𝟙} et n premier d'Artin).
 *
 * 1. n = 50 021 et 170 003 sont des premiers d'Artin (2 engendre (Z/nZ)*).
 * 2. Vérification exhaustive, en entiers, de chaque coefficient sur des instances réduites.
 * 3. Estimation (heuristique, pas une preuve) du meilleur distingueur linéaire aux tailles réelles :
 *    trouver a par Prange (coût) contre le biais du test (avantage), rotations comprises.
 *     tests/c/build/h1p_fourier   (depuis la racine) → resultats/h1p_fourier.json */
#include <math.h>
#include "resultat.h"

/* ---- 1. premiers d'Artin */
static uint64_t puiss(uint64_t b, uint64_t e, uint64_t m)
{
    uint64_t r = 1;
    for (b %= m; e; e >>= 1, b = b * b % m)
        if (e & 1)
            r = r * b % m;
    return r;
}
static int artin(uint64_t n)
{
    for (uint64_t d = 2; d * d <= n; d++)
        if (n % d == 0)
            return 0;
    uint64_t m = n - 1;
    for (uint64_t q = 2; q <= m; q++)               /* facteurs premiers de n − 1 */
        if (m % q == 0) {
            if (puiss(2, (n - 1) / q, n) == 1)
                return 0;
            while (m % q == 0)
                m /= q;
        }
    return 1;
}

/* ---- 2. instances réduites (vecteurs sur ≤ 32 bits) */
static int N;                                       /* longueur de l'anneau courant */
static uint32_t rot(uint32_t v, int i) { return i ? ((v << i) | (v >> (N - i))) & ((1u << N) - 1) : v; }
static uint32_t mul(uint32_t a, uint32_t b)
{
    uint32_t r = 0;
    for (int i = 0; i < N; i++)
        if (a >> i & 1)
            r ^= rot(b, i);
    return r;
}
static uint32_t barre(uint32_t h)                   /* h̄_j = h_{−j mod N} */
{
    uint32_t r = 0;
    for (int j = 0; j < N; j++)
        r |= (h >> ((N - j) % N) & 1u) << j;
    return r;
}
static int64_t binom(int n, int k)
{
    if (k < 0 || k > n)
        return 0;
    int64_t r = 1;
    for (int i = 1; i <= k; i++)
        r = r * (n - k + i) / i;
    return r;
}
static int64_t kraw(int n, int w, int t)            /* K_w(t) sur F2^n */
{
    int64_t s = 0;
    for (int j = 0; j <= w; j++)
        s += (j & 1 ? -1 : 1) * binom(t, j) * binom(n - t, w - j);
    return s;
}
static void wht(int64_t *f, int bits)
{
    for (size_t l = 1; l < (size_t)1 << bits; l <<= 1)
        for (size_t i = 0; i < (size_t)1 << bits; i += 2 * l)
            for (size_t j = i; j < i + l; j++) {
                int64_t a = f[j], b = f[j + l];
                f[j] = a + b, f[j + l] = a - b;
            }
}
static uint64_t g = 0x9E3779B97F4A7C15ull;
static uint32_t alea(void) { g ^= g << 13, g ^= g >> 7, g ^= g << 17; return (uint32_t)(g >> 11); }

/* H1-P : chaque coefficient égale la formule ; seuls a ∈ {0, 𝟙} sont de biais ±1, avec le signe de β(h) */
static int verifie_h1p(int n, int w, uint32_t h)
{
    N = n;
    uint32_t M = (1u << n) - 1, hb = barre(h);
    int64_t *f = calloc((size_t)1 << n, 8), tot = binom(n, w) * binom(n, w);
    for (uint32_t x = 0; x <= M; x++)
        if (__builtin_popcount(x) == w)
            for (uint32_t y = 0; y <= M; y++)
                if (__builtin_popcount(y) == w)
                    f[mul(x, h) ^ y]++;
    wht(f, n);
    int ok = 1, pleins = 0, beta = (w & 1) & ((__builtin_popcount(h) & 1) ^ 1);
    for (uint32_t a = 0; a <= M; a++) {
        ok &= f[a] == kraw(n, w, __builtin_popcount(a)) * kraw(n, w, __builtin_popcount(mul(a, hb)));
        pleins += llabs(f[a]) == tot;
    }
    ok &= pleins == 2 && f[M] == (beta ? -tot : tot);
    free(f);
    return ok;
}

/* H2-P : (u ‖ v') sur n + n2 bits ; renvoie le nombre de tests de biais ±1, ou −1 si une formule diffère */
static int verifie_h2p(int n, int w, int n2, int we, uint32_t h, uint32_t s, const int *pi)
{
    N = n;
    uint32_t M = (1u << n) - 1, M2 = (1u << n2) - 1, hb = barre(h), sb = barre(s);
    int bits = n + n2;
    int64_t *f = calloc((size_t)1 << bits, 8);
    int64_t *he = calloc((size_t)1 << n2, 8);        /* loi de e1 ⊕ π(e2) */
    for (uint32_t e1 = 0; e1 <= M2; e1++)
        if (__builtin_popcount(e1) == we)
            for (uint32_t e2 = 0; e2 <= M2; e2++)
                if (__builtin_popcount(e2) == we) {
                    uint32_t p = 0;
                    for (int i = 0; i < n2; i++)
                        p |= (e2 >> i & 1u) << pi[i];
                    he[e1 ^ p]++;
                }
    for (uint32_t r1 = 0; r1 <= M; r1++)
        if (__builtin_popcount(r1) == w) {
            uint32_t t = mul(r1, s) & M2, ru = mul(r1, h);
            for (uint32_t r2 = 0; r2 <= M; r2++)
                if (__builtin_popcount(r2) == w)
                    for (uint32_t e = 0; e <= M2; e++)
                        if (he[e])
                            f[(ru ^ r2) | (uint64_t)(t ^ e) << n] += he[e];
        }
    wht(f, bits);
    int64_t tot = binom(n, w) * binom(n, w) * binom(n2, we) * binom(n2, we);
    int pleins = 0;
    for (uint64_t c = 0; c < (uint64_t)1 << bits; c++) {
        uint32_t a = (uint32_t)(c & M), b = (uint32_t)(c >> n);
        int64_t kb = kraw(n2, we, __builtin_popcount(b));
        int64_t att = kraw(n, w, __builtin_popcount(a)) * kraw(n, w, __builtin_popcount(mul(a, hb) ^ mul(b, sb))) * kb * kb;
        if (f[c] != att) { pleins = -1; break; }
        pleins += llabs(f[c]) == tot;
    }
    free(f); free(he);
    return pleins;
}

/* ---- 3. estimation aux tailles réelles (log2) */
static double lbin(double n, double k) { return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2); }
static double l1m(double x) { return x < 1 ? log2(1 - x) : -INFINITY; }

/* Prange à p = 1 pour un mot de code de densité θ sur les n positions de redondance : coût ≈ 2^n / (K · C(n, θn)).
 * H1-P : redondance partagée entre les deux blocs, biais (1 − θ)^{2w} ; les n rotations de a donnent n tests
 * de même biais, soit un avantage ≈ √n · biais. On renvoie min_θ (log2 coût − log2 avantage). */
static double marge_h1p(double n, double w)
{
    double best = INFINITY;
    for (double th = 1e-4; th <= 0.5; th += 1e-4) {
        double cout = fmax(0, n - log2(n) - lbin(n, th * n)), adv = 2 * w * l1m(th) + 0.5 * log2(n);
        best = fmin(best, cout - fmin(adv, 0));
    }
    return best;
}
/* H2-P, test à trois blocs (a, b, c = a·h̄ ⊕ b̃·s̄) : redondance m_A + m_B + m_C = n répartie au mieux ;
 * biais (1 − 2θm_A/n)^w (1 − 2θm_C/n)^w (1 − 2θm_B/n2)^{2we}, sans gain de rotation (la troncature le casse). */
static double marge_h2p(double n, double w, double n2, double we)
{
    double best = INFINITY;
    for (double th = 1e-3; th <= 0.5; th += 1e-3) {
        double cout = fmax(0, n - log2(2 * n) - lbin(n, th * n));
        for (double fb = 0; fb <= 1.0001; fb += 0.01) {   /* part de B dans la redondance */
            double mB = fmin(fb * n, n2), mA = (n - mB) / 2;
            double adv = 2 * w * l1m(2 * th * mA / n) + 2 * we * l1m(2 * th * mB / n2);
            best = fmin(best, cout - fmin(adv, 0));
        }
    }
    return best;
}

int main(void)
{
    resultat_t res = {.nom = "h1p_fourier", .titre = "Spectre de Fourier exact de H1-P et H2-P"};
    res_controle(&res, "n_50021_et_170003_premiers_d_artin", artin(50021) && artin(170003));
    res_controle(&res, "temoin_n_50023_non_artin", !artin(50023) && !artin(50017));

    int ok1 = 1;
    for (int k = 0; k < 4; k++) {                    /* h(1) = 0 et h(1) = 1, w impair et pair */
        N = 13;
        uint32_t h = alea() & 0x1FFF;
        if ((__builtin_popcount(h) & 1) != (k & 1))
            h ^= 1;
        ok1 &= verifie_h1p(13, k < 2 ? 3 : 2, h);
    }
    res_controle(&res, "h1p_chaque_coefficient_egale_la_formule_et_seule_la_parite_est_invariante", ok1);

    int pi[7] = {0, 1, 2, 3, 4, 5, 6};
    for (int i = 6; i > 0; i--) {
        int j = (int)(alea() % (unsigned)(i + 1)), t = pi[i];
        pi[i] = pi[j], pi[j] = t;
    }
    int ok2 = 1, temoin = 1;
    for (int k = 0; k < 3; k++) {
        N = 11;
        uint32_t h = alea() & 0x7FF, s = alea() & 0x7FF;
        int beta = (2 & 1) & ((__builtin_popcount(h) & 1) ^ 1);          /* w = 2 : β = 0 */
        if ((__builtin_popcount(s) & 1) != beta)
            s ^= 1;
        if (s == 0 || s == 0x7FF)
            s ^= 3;
        ok2 &= verifie_h2p(11, 2, 7, 2, h, s, pi) == 2;
    }
    /* s = 0 (parité 0 = β) : b = 𝟙_T devient lui aussi invariant, comme l'énonce le corollaire */
    temoin = verifie_h2p(11, 2, 7, 2, alea() & 0x7FF, 0, pi) == 4;
    res_controle(&res, "h2p_chaque_coefficient_egale_la_formule_et_seule_la_parite_de_u_est_invariante", ok2);
    res_controle(&res, "h2p_temoin_s_nul_un_second_invariant", temoin);

    double m1[2] = {marge_h1p(50021, 75), marge_h1p(170003, 140)};
    double m2[2] = {marge_h2p(50021, 75, 28672, 25), marge_h2p(170003, 140, 114688, 64)};
    res_mesure(&res, "distingueur_lineaire_log2_cout_sur_avantage",
               "{\"Sillage-128\": {\"H1P\": %.1f, \"H2P_trois_blocs\": %.1f}, \"Sillage-256\": {\"H1P\": %.1f, \"H2P_trois_blocs\": %.1f}}",
               m1[0], m2[0], m1[1], m2[1]);
    fprintf(stderr, "distingueur linéaire (heuristique) : Sillage-128 H1P %.1f, H2P %.1f ; Sillage-256 H1P %.1f, H2P %.1f bits\n",
            m1[0], m2[0], m1[1], m2[1]);
    res_controle(&res, "distingueur_lineaire_estime_au_dessus_du_niveau", fmin(m1[0], m2[0]) >= 128 && fmin(m1[1], m2[1]) >= 256);
    return res_ecrire(&res);
}
