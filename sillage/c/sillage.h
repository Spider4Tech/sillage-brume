/* SILLAGE — implémentation C de référence (v0.6.0).
 *
 * v0.6 : BRUME-1024q remplace BRUME-512 (docs/MIGRATION_V06.md ; spécification docs/brume1024/SPEC.md). Le KEM et la
 * signature ne changent pas (ils n'utilisent que SHAKE256) et restent conformes bit à bit au Python de référence
 * (tests/test_c_impl.py). BRUME-1024q n'a pas de référence Python (décision D1) : sa référence est la seconde
 * implémentation C écrite depuis la spécification seule (prototypes/brume_q/b1024/spec_ref.c, KAT de la SPEC § 4).
 * Prototype de recherche. Constant-time vis-à-vis des secrets, par construction et par mesure (dudect, ctgrind) : noyaux
 * BRUME-1024q AVX2 et portable, KEM, SIG (signataire) ; sl_brume_permute_ref, sl_brume_permute_inv_ref et le vérifieur
 * ne le sont pas.
 *
 * Encodages (octets, petit-boutiste comme le Python) :
 *   KEM  pk = σ_h(32) ‖ s(⌈n/8⌉)          ct = u(⌈n/8⌉) ‖ v(n2/8)
 *        sk = x ‖ y ‖ σ_h(32) ‖ σ_rej(32) ‖ s
 *   SIG  pk = seed_H(32) ‖ y(⌈r/8⌉)       sk = x_A ‖ Q ‖ P
 *   AEAD profil 0 = BRUME-1024q (c = 384, seul profil depuis la v0.6) ; clé 64 o, nonce 24 o, tag 32 o.
 * Codes de retour : 0 succès, -1 tag invalide, -2 altération TE, -3 entrée (profil, longueur > 2^63 − 1 octets).
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
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "formats et états sérialisés depuis la mémoire : petit-boutiste uniquement");
#define SL_NONCE 24                /* 24 octets ; unique par clé (docs/brume1024/SPEC.md § 3.5) */
#ifdef SL_VALGRIND                 /* tests/test_c_*_valgrind.py : valeur déclarée publique */
#include <valgrind/memcheck.h>
#define SL_PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#else
#define SL_PUBLIC(p, n) ((void)0)
#endif

/* À appeler une fois avant tout usage (construit les tables), hors de toute région parallèle. */
void sl_init(void);

/* ---- BRUME-1024q (docs/brume1024/SPEC.md) ----
 * État empaqueté de 128 octets (256 nibbles ; nibble 2i = demi-octet bas de l'octet i). Débit : octets 0..79 (r = 640
 * bits), capacité : 80..127 (c = 384 bits), 32 tours. */
void sl_brume_permute(uint8_t etat[128]);         /* constant-time (AVX2 ou noyau portable) */
void sl_brume_permute_ref(uint8_t etat[128]);     /* référence dense (contrôles ; non constant-time) */
void sl_brume_permute_inv_ref(uint8_t etat[128]); /* P⁻¹, référence dense (contrôles ; non constant-time) */
void sl_brume_permute_lot(uint8_t etats[32][128]);   /* 32 états, constant-time */
/* Condensé par défaut H (SPEC § 3.4) : éponge seule jusqu'à 8 Kio, arbre au-delà (feuilles de 8 Kio hachées en parallèle,
 * CV de 64 octets, racine). Longueur de sortie libre ; 64 octets par défaut (décision D5 : 2^128 quantique en
 * collision). sl_hash_arbre est la même fonction (nom gardé de la v0.5). */
void sl_hash(const uint8_t *m, size_t len, uint8_t *out, size_t outlen);
void sl_hash_arbre(const uint8_t *m, size_t len, uint8_t *out, size_t outlen);
/* XOF (SPEC § 3.3) : éponge à domaine 0, sortie de longueur libre. Autre fonction que sl_hash. */
void sl_xof(const uint8_t *m, size_t len, uint8_t *out, size_t outlen);
void br_eponge(const uint8_t *m, size_t len, int dom, uint8_t *out, size_t outlen);   /* éponge à domaine (0..15) */
/* AEAD (SPEC § 3.5) : duplex à clé dans tout l'état, orientation SpongeWrap ; nonce unique par clé ; rien n'est rendu
 * avant la vérification du tag (clair effacé en cas d'échec). */
int sl_aead_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                    const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t len,
                    uint8_t *ct, uint8_t *tag);
int sl_aead_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                    const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t len,
                    const uint8_t *tag, uint8_t *pt);
size_t sl_aead_tag_len(int profil);                 /* 32 (profil 0), 0 sinon */
/* Contexte de clé : la clé est dans tout l'état initial, il n'y a rien à précalculer ; le contexte garde la clé (API de
 * la v0.5 conservée). Matériel secret : effacer avec sl_effacer(&c, sizeof c). Mêmes sorties. */
typedef struct { int profil; uint8_t etat[64]; } sl_aead_cle_t;
int sl_aead_cle(sl_aead_cle_t *c, int profil, const uint8_t cle[64]);
int sl_aead_encrypt_ctx(const sl_aead_cle_t *c, const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                        size_t aadlen, const uint8_t *pt, size_t len, uint8_t *ct, uint8_t *tag);
int sl_aead_decrypt_ctx(const sl_aead_cle_t *c, const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                        size_t aadlen, const uint8_t *ct, size_t len, const uint8_t *tag, uint8_t *pt);
void sl_effacer(void *p, size_t n);
/* AEAD parallèle (SPEC § 3.5 bis, mode 6) : feuilles de SL_AEADP_FEUILLE octets, chacune après deux appels de fourche,
 * CV de 64 octets, racine ; feuilles calculées sur tous les cœurs. Autre fonction que sl_aead_encrypt. ct peut valoir pt. */
#define SL_AEADP_LOG_FEUILLE 13
#define SL_AEADP_FEUILLE (1u << SL_AEADP_LOG_FEUILLE)
int sl_aead_p_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                      const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t len,
                      uint8_t *ct, uint8_t *tag);
int sl_aead_p_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                      const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t len,
                      const uint8_t *tag, uint8_t *pt);
/* Mode TE (SPEC § 3.7, docs/SPEC.md § 2.7) : 7 octets de parité par bloc de 64 octets du chiffré, correction d'un octet
 * par bloc avant la vérification du tag. */
size_t sl_te_par_len(size_t len);             /* 7 octets par bloc de 64 */
int sl_te_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                  const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t len,
                  uint8_t *ct, uint8_t *par, uint8_t *tag, uint8_t meta[8]);
/* ct est corrigé EN PLACE, seulement si tous les blocs sont corrigeables (sinon -2, ct intact) ;
 * corrections[] doit offrir sl_te_par_len(len) / 7 entrées (une par bloc de 64 octets). */
int sl_te_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE],
                  const uint8_t *aad, size_t aadlen, uint8_t *ct, size_t len,
                  const uint8_t *par, size_t parlen, const uint8_t *tag,
                  const uint8_t meta[8], uint8_t *pt, size_t *corrections, size_t *ncorr);

/* ---- lots : n messages indépendants, répartis sur les cœurs (OpenMP) ; mêmes sorties que les fonctions unitaires.
 * Chiffrement : au moins 32 messages de même longueur et mêmes données associées passent par les noyaux à 32 et 256
 * états. aads/aadlens peuvent être NULL. tags : 32·n octets ; codes[i] : 0 ou -1 (tag invalide, clair effacé). */
int sl_aead_encrypt_multi(int profil, size_t n, const uint8_t *cles, const uint8_t *nonces,
                          const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *pts,
                          const size_t *lens, uint8_t *const *cts, uint8_t *tags);
int sl_aead_decrypt_multi(int profil, size_t n, const uint8_t *cles, const uint8_t *nonces,
                          const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *cts,
                          const size_t *lens, const uint8_t *tags, uint8_t *const *pts, int *codes);
void sl_hash_multi(size_t n, const uint8_t *const *msgs, const size_t *lens, uint8_t *outs, size_t outlen);
/* même clé pour les n messages (cas d'un serveur) */
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
                  const uint8_t *sig, size_t siglen);

/* Sillage-SIG v0.5 : VOLE-in-the-Head sur SD régulier (vole.c, PROOFS § 3 bis, SPEC § 4 bis). Profils : 0 VOLE-128,
 * 1 VOLE-256, 2 VOLE-128f, 3 VOLE-256f. pk = graine de H (λ bits) ‖ y ; sk = pk ‖ positions (un octet par bloc) ;
 * signature de longueur fixe. Retour 0 (succès) ou −1 (profil invalide, mémoire ou aléa indisponibles : signature remise
 * à zéro). sl_vole_verify : 1 acceptée, 0 rejetée, −1 mémoire indisponible. sl_vole_kat : aléa déterministe (tests, KAT). */
void sl_vole_tailles(int profil, size_t *pk, size_t *sk, size_t *sig);
int sl_vole_keygen(int profil, uint8_t *pk, uint8_t *sk);
int sl_vole_sign(int profil, const uint8_t *sk, const uint8_t *msg, size_t len, uint8_t *sig);
int sl_vole_sign_sel(int profil, const uint8_t *sk, const uint8_t *msg, size_t len, const uint8_t *sel, uint8_t *sig);
int sl_vole_verify(int profil, const uint8_t *pk, const uint8_t *msg, size_t len, const uint8_t *sig, size_t siglen);
void sl_vole_kat(int actif, uint32_t ctr);           /* 1 valide, 0 sinon */

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
/* allocations internes : abort() si la mémoire manque (jamais de NULL déréférencé) ;
 * sl_calloc refuse aussi le débordement de a × b */
void *sl_malloc(size_t n);
void *sl_calloc(size_t a, size_t b);
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
#endif
