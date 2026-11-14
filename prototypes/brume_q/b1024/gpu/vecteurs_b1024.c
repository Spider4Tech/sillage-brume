/* Vecteurs de la permutation BRUME-1024q pour le banc GPU (gpu/boomerang1024.cu) : produits par la référence dense de
 * brume1024.c (ref_tour, ref_tour_inv), elle-même contrôlée contre le noyau AVX2 et les KAT figés.
 *   vecteurs_b1024 <fichier>  : pour R ∈ {1, 2, 3, 4, 5, 8, 32} et 8 états e (dérivés de R et e), écrit
 *                               x (128 o), P_R(x) (tours 0 … R − 1), P_R⁻¹(x) (inverses des tours R − 1 … 0). */
#define SANS_MAIN
#include "../brume1024.c"

int main(int argc, char **argv)
{
    if (argc != 2 || !bref_init() || !ref_init())
        return 2;
    FILE *f = fopen(argv[1], "wb");
    if (!f)
        return 2;
    static const int RS[] = {1, 2, 3, 4, 5, 8, 32};
    uint64_t g = 0xB00E1024;
    for (int t = 0; t < 7; t++)
        for (int e = 0; e < 8; e++) {
            uint8_t w[128], x[N1], y[N1], z[N1], o[128];
            for (int i = 0; i < 128; i++) {
                g = g * 6364136223846793005ULL + 1442695040888963407ULL;
                w[i] = (uint8_t)(g >> 56);
            }
            fwrite(w, 1, 128, f);
            deballer_ref(w, x);
            memcpy(z, x, N1);
            memcpy(y, x, N1);
            for (int r = 0; r < RS[t]; r++)
                ref_tour(y, r);
            emballer_ref(y, o);
            fwrite(o, 1, 128, f);
            for (int r = RS[t] - 1; r >= 0; r--)
                ref_tour_inv(z, r);
            emballer_ref(z, o);
            fwrite(o, 1, 128, f);
        }
    return fclose(f) ? 2 : 0;
}
