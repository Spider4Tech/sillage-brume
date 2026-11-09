/* S-box 4 bits prototype V3 (candidate non dominée, classe G11 de Leander-Poschmann).
 *
 * SBOX_V3 = [14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2]
 * SBOX_V3(x) = M2 * S_G11(M1 * x ^ 9) ^ 5
 *
 * Résout le dilemme mis en évidence par l'analyse Codex du 8 novembre 2026 :
 *   - Réduit la BCT maximale de 10 à 8 (0 entrée à 10, contre 1 à 10 dans BRUME).
 *   - Réduit la DBCT maximale de 52 à 32 (identique à SBOX6).
 *   - Conserve 5 lignes DDT sans transition à 4 (max DDT = 2), contre 3 pour BRUME
 *     et 0 pour SBOX6 (qui avait 15 lignes uniformes à 4).
 *   - Conserve 5 lignes BCT à maximum 2 (évite le profil plat à 6 de SBOX6).
 *   - Piste différentielle à 14 tours : 2^-3021 (plus résistante que BRUME à 2^-2830
 *     et que SBOX6 à 2^-2600).
 *   - Piste boomerang à 14 tours : 2^-2941 (plus résistante que BRUME à 2^-2776
 *     et que SBOX6 à 2^-2486).
 *   - Piste linéaire à 14 tours : 2^-1417 (égale à BRUME).
 *   - MEDP2 = 2^-14.99 (maintient la borne de BRUME).
 *   - Aucun point fixe, degré algébrique 3, immunité algébrique 2.
 *
 * Propriétés vérifiées exhaustivement (voir sbox_v3.py).
 */
#ifndef BRUME_SBOX_V3_H
#define BRUME_SBOX_V3_H

#include <stdint.h>

/* Ligne à substituer à BR_SBOX dans sillage/c/brume512_tables.h :
 *     14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2
 */
static const uint8_t BR_SBOX_V3[16] = {
    14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2
};

static const uint8_t BR_SBOX_V3_INV[16] = {
    10, 13, 15, 2, 9, 11, 3, 12, 7, 1, 6, 5, 8, 14, 0, 4
};

#endif /* BRUME_SBOX_V3_H */
