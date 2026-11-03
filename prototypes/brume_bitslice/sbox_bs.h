/* S-box de BRUME bitslicée (prototype, piste 10), décomposition de Shannon sur x3 : y_k = B_k ⊕ (x3 ∧ D_k). Sortie S(x) ⊕ 8 (bit 3 complété,
 * replié dans les constantes du tour suivant : M·(y ⊕ e) = M·y ⊕ M·e). 25 opérations. ANDN(a, b) = ¬a ∧ b. */
#define XOR_ _mm256_xor_si256
#define AND_ _mm256_and_si256
#define OR_ _mm256_or_si256
#define ANDN_ _mm256_andnot_si256
#define SBOX2(x0, x1, x2, x3, y0, y1, y2, y3) do { \
    __m256i X0 = (x0), X1 = (x1), X2 = (x2), X3 = (x3); \
    __m256i x12 = XOR_(X1, X2), o = OR_(X0, X2); \
    __m256i B0 = ANDN_(X2, XOR_(X0, X1)), B1 = AND_(X0, X1), B2 = ANDN_(ANDN_(X0, X1), X2), B3 = XOR_(X1, AND_(X0, x12)); \
    __m256i D0n = XOR_(X1, o), D1 = XOR_(ANDN_(X2, X1), o), D2n = XOR_(ANDN_(X0, x12), AND_(X1, X2)), D3 = AND_(X1, XOR_(X0, X2)); \
    y0 = XOR_(B0, ANDN_(D0n, X3)); y1 = XOR_(B1, AND_(X3, D1)); y2 = XOR_(B2, ANDN_(D2n, X3)); y3 = XOR_(B3, AND_(X3, D3)); \
} while (0)
