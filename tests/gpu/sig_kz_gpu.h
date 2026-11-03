/* Interface entre l'hôte C (tests/gpu/sig_kz_gpu.c) et les noyaux CUDA (tests/gpu/sig_kz_gpu.cu) de l'attaque de
 * Kales–Zaverucha sur l'instance réduite de tests/c/sig_kz_commun.h. Le GPU ne fait que hacher : mise en gage complète d'une
 * tentative (arbre GGM, 4 × 256 feuilles, aux, engagements, h1, défis) et énumération des cibles de h2. Tout ce qui décide
 * d'une falsification (recalcul de h1, vues du vérifieur, signature, sl_sig_verify) reste sur l'hôte, dans le code C réel. */
#ifndef SIG_KZ_GPU_H
#define SIG_KZ_GPU_H
#include <stdint.h>

#ifdef __CUDACC__
#define KZ_HD __host__ __device__
#else
#define KZ_HD
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* dimensions de l'instance, comparées à celles compilées dans le noyau (kz_gpu_init échoue sinon) */
typedef struct { uint32_t N, D, tau, t, sb, hb, Lp, lsk, pts, La, ep, lrep; uint64_t pb; } kz_dims_t;

/* aléa des sels : sel(graine, stratégie, essai, tentative), identique sur l'hôte et le GPU (splitmix64 enchaîné) */
KZ_HD static inline uint64_t kz_mix(uint64_t z)
{
    z += 0x9e3779b97f4a7c15ULL;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

KZ_HD static inline void kz_sel(uint64_t graine, uint32_t si, uint32_t essai, uint32_t tentative, uint8_t sel[32])
{
    uint64_t z = kz_mix(kz_mix(kz_mix(graine ^ ((uint64_t)(si + 1) << 56)) ^ essai) ^ tentative);
    for (int k = 0; k < 4; k++) {
        uint64_t w = kz_mix(z + (uint64_t)k);
        for (int b = 0; b < 8; b++) sel[8 * k + b] = (uint8_t)(w >> (8 * b));
    }
}

/* sk = x_A ‖ Q ‖ P (lsk octets), pkh, mh (hb octets), masque des parts (Lp octets), tz : bit r à 1 si T(r) = 0 (2^ep bits).
 * nom : nom du GPU. Renvoie 0, ou −1 (pas de GPU, dimensions différentes, erreur CUDA ; message sur stderr). */
int kz_gpu_init(const kz_dims_t *d, const uint8_t *sk, const uint8_t *pkh, const uint8_t *mh, const uint8_t *masque,
                const uint8_t *tz, char *nom, int lnom);

/* étape 1, une tentative par fil : fil f → essai essais[f / C], tentative a0 + f mod C ; nf[f] = nombre de répétitions à
 * faux positif. ms : durée du noyau. */
int kz_gpu_h1(uint64_t graine, uint32_t si, const uint32_t *essais, uint32_t nessais, uint32_t a0, uint32_t C,
              uint8_t *nf, float *ms);

/* conformité : sels explicites (32 octets chacun) → h1 (hb octets chacun) et nf */
int kz_gpu_h1_sels(const uint8_t *sels, uint32_t nb, uint8_t *h1, uint8_t *nf);

/* étape 2 : énumère u ∈ [0, lim), cibles = u en base N sur les répétitions libres (masque, bit rep), diffusion de la
 * répétition rep = préfixe de lignes[rep][0] puis, axe par axe, le bloc de lignes[rep][bit d de la cible].
 * premier : plus petit u dont les défis de h2 tombent sur les cibles, −1 sinon. ci : si non NULL, défis des ndbg premiers u
 * (τ valeurs par u), pour la conformité. */
int kz_gpu_h2(const uint8_t *sel, const uint8_t *h1, const uint8_t *lignes, uint32_t libres, uint64_t lim,
              int64_t *premier, uint32_t *ci, uint32_t ndbg);

void kz_gpu_fin(void);

#ifdef __cplusplus
}
#endif
#endif
