/* S-box 4 bits prototype, uniformité boomerang 6 (cible optimale pour DU = 4).
 *
 * SBOX6(x) = RECTANGLE(x) XOR 6. La translation de sortie est affine : elle
 * conserve DDT, LAT, degré et immunité algébrique, et retire le point fixe
 * x = 12 de RECTANGLE. Pour une translation pure, la BCT est inchangée ;
 * son maximum passe de 10/16 (S-box actuelle de BRUME) à 6/16.
 *
 * Propriétés vérifiées exhaustivement (voir sbox6.py) :
 *   DU = 4, max |LAT| = 8 (NL = 4), BCT max = 6, degré = 3,
 *   aucun point fixe, AI = 2, DDT max atteint 15 fois, |LAT| max 30 fois.
 *
 * Pour tester cette table dans le test C réduit sans modifier le dépôt :
 *   1. copier tests/c et sillage/c dans un répertoire temporaire ;
 *   2. remplacer la ligne BR_SBOX de sillage/c/brume512_tables.h par la
 *      ligne ci-dessous (même format) ;
 *   3. compiler tests/c/build/brume_attaques et lancer le binaire.
 * Le script tester_brume_attaques.sh automatise ces étapes.
 */
#ifndef BRUME_SBOX6_H
#define BRUME_SBOX6_H

#include <stdint.h>

/* Ligne à substituer à BR_SBOX dans sillage/c/brume512_tables.h :
 *     15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1
 */
static const uint8_t BR_SBOX6[16] = {
    15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1
};

static const uint8_t BR_SBOX6_INV[16] = {
    8, 15, 1, 7, 9, 11, 10, 5, 13, 14, 12, 4, 2, 3, 6, 0
};

#endif /* BRUME_SBOX6_H */
