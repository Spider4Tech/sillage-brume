/* Contrôles des corrections de la revue C (suivi : docs/RAPPORT_AUDIT.md, errata du 2026-11-02) :
 *   C-07 : sl_te_decrypt ne modifie pas ct quand un bloc est incorrigible ;
 *   C-15 : sl_kem_encaps_det refuse une clé publique non canonique (bits de bourrage de s) ;
 *   C-14 : sl_kem_borne ne certifie rien hors du domaine (poids ≠ w).
 *     make -C tests/c build/revue_c && tests/c/build/revue_c   (depuis la racine) */
#include "sillage.h"
#include "resultat.h"

int main(void)
{
    resultat_t res = {.nom = "revue_c"};
    (void)res_mesure;

    /* C-07 */
    uint8_t cle[64] = {1}, nonce[SL_NONCE] = {2}, pt[200], ct[200], par[28], tag[32], meta[8], sortie[200], av[200];
    size_t corr[4], nc;
    for (int i = 0; i < 200; i++)
        pt[i] = (uint8_t)(7 * i);
    sl_te_encrypt(0, cle, nonce, NULL, 0, pt, 200, ct, par, tag, meta);
    ct[10] ^= 0x40;                                  /* bloc 0 : corrigible */
    memcpy(av, ct, 200);
    int rc1 = sl_te_decrypt(0, cle, nonce, NULL, 0, ct, 200, par, sizeof par, tag, meta, sortie, corr, &nc);
    res_controle(&res, "te_un_octet_corrige", rc1 == 0 && nc == 1 && corr[0] == 10 && !memcmp(sortie, pt, 200));
    memcpy(ct, av, 200);
    ct[130] ^= 1, ct[131] ^= 2;                      /* bloc 2 : deux octets, incorrigible */
    memcpy(av, ct, 200);
    int rc2 = sl_te_decrypt(0, cle, nonce, NULL, 0, ct, 200, par, sizeof par, tag, meta, sortie, corr, &nc);
    res_controle(&res, "te_incorrigible_ct_intact", rc2 == -2 && nc == 0 && !memcmp(ct, av, 200));

    /* C-15 et C-14 */
    size_t lpk, lsk, lct, lss;
    sl_kem_tailles(0, &lpk, &lsk, &lct, &lss);
    uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *c = malloc(lct), ss[64], mu[16] = {3};
    size_t nb = (lsk - 64) / 3;
    int ok = !sl_kem_keygen(0, pk, sk);
    res_controle(&res, "kem_pk_canonique_acceptee", ok && sl_kem_encaps_det(0, pk, mu, c, ss) == 0);
    pk[lpk - 1] |= 0x80;                             /* n = 50 021 : 5 bits utiles dans le dernier octet */
    res_controle(&res, "kem_pk_non_canonique_refusee", sl_kem_encaps_det(0, pk, mu, c, ss) == -3);
    res_controle(&res, "kem_borne_cle_acceptee", sl_kem_borne(0, sk, sk + nb) <= -128);
    memset(sk, 0xFF, nb);
    res_controle(&res, "kem_borne_hors_domaine_nulle", sl_kem_borne(0, sk, sk + nb) == 0);
    free(pk); free(sk); free(c);
    return res_ecrire(&res);
}
