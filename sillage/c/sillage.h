/* SILLAGE — implémentation C de référence (v0.4.0).
 *
 * Conforme bit à bit à l'implémentation Python du paquet `sillage`
 * (vérifié par tests/test_c_impl.py) : mêmes KAT, mêmes encodages.
 * Prototype de recherche. BRUME-512 (AVX2 ; NEON : constant-time par construction, non mesuré), le KEM et la SIG (signataire) sont
 * constant-time vis-à-vis des secrets, par construction et par mesure
 * (tests/c/temps.c) ; sl_brume_permute_ref et le vérifieur ne le sont pas.
 *
 * Encodages (octets, petit-boutiste comme le Python) :
 *   KEM  pk = σ_h(32) ‖ s(⌈n/8⌉)          ct = u(⌈n/8⌉) ‖ v(n2/8)
 *        sk = x ‖ y ‖ σ_h(32) ‖ σ_rej(32) ‖ s
 *   SIG  pk = seed_H(32) ‖ y(⌈r/8⌉)       sk = x_A ‖ Q ‖ P
 *   AEAD profil 0 = BRUME-512, 1 = BRUME-512-256 ; clé 64 o, nonce 24 o.
 * Codes de retour : 0 succès, -1 tag invalide, -2 altération TE, -3 entrée.
 */
#ifndef SILLAGE_H
#define SILLAGE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __PCLMUL__
#include <immintrin.h>
#endif
#if defined(__ARM_FEATURE_AES) && !defined(__PCLMUL__)
#include <arm_neon.h>
#endif
#define SL_NONCE 24                /* comme XChaCha20 : tirable au hasard (PREUVES § 4.3) */
#ifdef SL_VALGRIND                 /* tests/test_c_*_valgrind.py : valeur déclarée publique */
#include <valgrind/memcheck.h>
#define SL_PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#else
#define SL_PUBLIC(p, n) ((void)0)
#endif

/* À appeler une fois avant tout usage (construit les tables). */
void sl_init(void);

/* ---- BRUME-512 ---- */
void sl_brume_permute(uint8_t etat[64]);      /* état empaqueté (128 nibbles) ;
                                                 constant-time si AVX2 */
void sl_brume_permute_ref(uint8_t etat[64]);  /* référence par tables (non constant-time) */
void sl_brume_permute_lot(uint8_t etats[32][64]);   /* 32 états, constant-time (AVX2) */
void sl_hash(const uint8_t *m, size_t len, uint8_t *out, size_t outlen);
/* Hachage arborescent (docs/PREUVES.md § 4.4) : feuilles de 8 Kio hachées en
 * parallèle (lots de 32 états, tous les cœurs), racine sur les CV. Sortie
 * différente de sl_hash (autre fonction, domaines séparés). */
void sl_hash_arbre(const uint8_t *m, size_t len, uint8_t *out, size_t outlen);
void br_eponge(const uint8_t *m, size_t len, int dom, uint8_t *out, size_t outlen);
int sl_aead_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                    const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t len,
                    uint8_t *ct, uint8_t *tag);
int sl_aead_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                    const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t len,
                    const uint8_t *tag, uint8_t *pt);
size_t sl_aead_tag_len(int profil);
/* Contexte de clé (état après absorption de la clé, précalculé) : évite 2
 * permutations par message (4 en BRUME-512-256). Matériel équivalent à la
 * clé : effacer avec sl_effacer(&c, sizeof c). Mêmes sorties. */
typedef struct { int profil; uint8_t etat[64]; } sl_aead_cle_t;
int sl_aead_cle(sl_aead_cle_t *c, int profil, const uint8_t cle[64]);
int sl_aead_encrypt_ctx(const sl_aead_cle_t *c, const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                        size_t aadlen, const uint8_t *pt, size_t len, uint8_t *ct, uint8_t *tag);
int sl_aead_decrypt_ctx(const sl_aead_cle_t *c, const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                        size_t aadlen, const uint8_t *ct, size_t len, const uint8_t *tag, uint8_t *pt);
void sl_effacer(void *p, size_t n);
/* AEAD parallèle (docs/PREUVES.md § 4.5) : profil 0 = BRUME-512p, 1 = BRUME-512-256p. Le message est coupé en
 * feuilles de SL_AEADP_FEUILLE octets, chacune suivie par son duplex à clé, sur tous les cœurs et par lots de
 * 32 états. Autre fonction que sl_aead_encrypt : autres chiffrés, autres tags. ct peut valoir pt. */
#define SL_AEADP_LOG_FEUILLE 12
#define SL_AEADP_FEUILLE (1u << SL_AEADP_LOG_FEUILLE)
int sl_aead_p_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                      const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t len,
                      uint8_t *ct, uint8_t *tag);
int sl_aead_p_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                      const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t len,
                      const uint8_t *tag, uint8_t *pt);
size_t sl_te_par_len(size_t len);             /* 7 octets par bloc de 64 */
int sl_te_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                  const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t len,
                  uint8_t *ct, uint8_t *par, uint8_t *tag, uint8_t meta[8]);
/* ct est corrigé EN PLACE ; corrections[] (≤ un par bloc) reçoit les positions. */
int sl_te_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                  const uint8_t *aad, size_t aadlen, uint8_t *ct, size_t len,
                  const uint8_t *par, size_t parlen, const uint8_t *tag,
                  const uint8_t meta[8], uint8_t *pt, size_t *corrections, size_t *ncorr);

/* ---- BRUME-512 par lots : n messages indépendants, traités 32 par 32
 * (AVX2, constant-time) et répartis sur les cœurs (OpenMP). Mêmes sorties
 * que les fonctions unitaires. aads/aadlens peuvent être NULL. tags : n ×
 * longueur de tag ; codes[i] : 0 ou -1 (tag invalide, clair mis à zéro). */
int sl_aead_encrypt_multi(int profil, size_t n, const uint8_t *cles, const uint8_t *nonces,
                          const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *pts,
                          const size_t *lens, uint8_t *const *cts, uint8_t *tags);
int sl_aead_decrypt_multi(int profil, size_t n, const uint8_t *cles, const uint8_t *nonces,
                          const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *cts,
                          const size_t *lens, const uint8_t *tags, uint8_t *const *pts, int *codes);
void sl_hash_multi(size_t n, const uint8_t *const *msgs, const size_t *lens, uint8_t *outs, size_t outlen);
/* même clé pour les n messages (cas d'un serveur) : contexte précalculé */
int sl_aead_encrypt_multi_ctx(const sl_aead_cle_t *c, size_t n, const uint8_t *nonces,
                              const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *pts,
                              const size_t *lens, uint8_t *const *cts, uint8_t *tags);
int sl_aead_decrypt_multi_ctx(const sl_aead_cle_t *c, size_t n, const uint8_t *nonces,
                              const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *cts,
                              const size_t *lens, const uint8_t *tags, uint8_t *const *pts, int *codes);

/* ---- Sillage-KEM (niveau 0 = Sillage-128, 1 = Sillage-256) ---- */
void sl_kem_tailles(int niveau, size_t *pk, size_t *sk, size_t *ct, size_t *ss);
int sl_kem_keygen(int niveau, uint8_t *pk, uint8_t *sk);
int sl_kem_encaps(int niveau, const uint8_t *pk, uint8_t *ct, uint8_t *ss);
int sl_kem_encaps_det(int niveau, const uint8_t *pk, const uint8_t *mu, uint8_t *ct, uint8_t *ss);
int sl_kem_decaps(int niveau, const uint8_t *sk, const uint8_t *ct, uint8_t *ss);
double sl_kem_borne(int niveau, const uint8_t *x, const uint8_t *y);   /* log2 δ prouvé */

/* ---- Sillage-SIG (niveau 0 = SIG-128, 1 = SIG-256) ---- */
void sl_sig_tailles(int niveau, size_t *pk, size_t *sk, size_t *sig_max);
int sl_sig_keygen(int niveau, uint8_t *pk, uint8_t *sk);
int sl_sig_sign(int niveau, const uint8_t *sk, const uint8_t *pk, const uint8_t *msg,
                size_t len, uint8_t *sig, size_t *siglen);
/* sel imposé (déterminisme, tests de conformité) ; sl_sig_sign le tire au hasard */
int sl_sig_sign_sel(int niveau, const uint8_t *sk, const uint8_t *pk, const uint8_t *msg, size_t len,
                    const uint8_t sel[32], uint8_t *sig, size_t *siglen);
int sl_sig_verify(int niveau, const uint8_t *pk, const uint8_t *msg, size_t len,
                  const uint8_t *sig, size_t siglen);           /* 1 valide, 0 sinon */

/* ---- Estimateur ISD (log2 du coût, miroir de sillage_common.py) ---- */
double sl_isd_prange(int n, int k, int w);
double sl_isd_deux_listes(int n, int k, int w, int dumer, int p_max, int l_max, double exposant_interne, double *o);
double sl_isd_bjmm(int n, int k, int w, int p_max, int e_max, int l_max, double *o);
double sl_isd_bjmm_quantique(int n, int k, int w, double exposant, double depart);

/* ---- interne (partagé entre fichiers) ---- */
typedef struct { uint64_t s[25]; size_t pos; } sl_shake_t;
void sl_shake_init(sl_shake_t *h);
void sl_shake_absorb(sl_shake_t *h, const void *d, size_t len);
void sl_shake_final(sl_shake_t *h);
void sl_shake_squeeze(sl_shake_t *h, void *out, size_t len);
void sl_shake256(const uint8_t *m, size_t len, uint8_t *out, size_t outlen);   /* SHAKE256 brut (tests) */
/* shake(data, outlen, domaine) du Python : SHAKE256(domaine ‖ "|" ‖ parties…) */
void sl_shake_dom(const char *dom, const uint8_t *dom2, size_t dom2len,
                  const uint8_t *const *parts, const size_t *lens, int nparts,
                  uint8_t *out, size_t outlen);

typedef struct {            /* _shake_int_stream(seed, domaine) */
    char dom[64];
    uint8_t seed[72];
    size_t seedlen;
    uint64_t ctr;
    uint8_t buf[256];        /* 4 blocs de 64 octets (Keccak à 4 voies) */
    int pos;
} sl_flux_t;
void sl_flux_init(sl_flux_t *f, const char *dom, const uint8_t *seed, size_t seedlen);
uint32_t sl_flux_next(sl_flux_t *f);
void sl_creux(const uint8_t *seed, size_t seedlen, int poids, uint32_t n, const char *dom, uint32_t *pos);
void sl_echanges(const uint8_t *seed, size_t seedlen, uint32_t m, const char *dom, uint32_t *r);
void sl_perm(const uint8_t *seed, size_t seedlen, uint32_t m, const char *dom, uint32_t *perm);
void sl_shake4(const uint8_t *const m[4], size_t len, uint8_t *const out[4], size_t outlen);
int sl_alea(void *out, size_t len);
static inline void sl_clmul64(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi)
{
#ifdef __PCLMUL__
    __m128i p = _mm_clmulepi64_si128(_mm_cvtsi64_si128((long long)a), _mm_cvtsi64_si128((long long)b), 0);
    *lo = (uint64_t)_mm_cvtsi128_si64(p);
    *hi = (uint64_t)_mm_extract_epi64(p, 1);
#elif defined(__ARM_FEATURE_AES)
    poly128_t p = vmull_p64((poly64_t)a, (poly64_t)b);       /* PMULL */
    *lo = vgetq_lane_u64(vreinterpretq_u64_p128(p), 0);
    *hi = vgetq_lane_u64(vreinterpretq_u64_p128(p), 1);
#else
    uint64_t l = 0, h = 0;                      /* repli logiciel, sans branchement */
    for (int i = 0; i < 64; i++) {
        uint64_t m = 0 - ((b >> i) & 1);
        l ^= (a << i) & m;
        h ^= (i ? a >> (64 - i) : 0) & m;
    }
    *lo = l; *hi = h;
#endif
}
void br_init_avx2(void);
const uint8_t *br_etat_iv(int profil);
void br_permuter_lot(uint8_t (*e)[64]);
void br_absorber(uint64_t w[8], int rb, const uint8_t *d1, size_t l1, const uint8_t *d2, size_t l2, int dom);
#ifdef __AVX2__
void br_permuter_avx2(uint64_t w[8]);
void br_tours_avx2(uint64_t w[8], int R);     /* les R premiers tours (cryptanalyse) */
#elif defined(__ARM_NEON)
void br_permuter_neon(uint64_t w[8]);
#endif

#endif
