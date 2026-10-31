/* Conformité des chemins constant-time de la SIG C (tests/test_c_temps.py) : corps contre
 * multiplication naïve, plongement (φ(a)·φ(b) = φ(a·b)), Lagrange (partition de l'unité, point de
 * F_poly : vecteur unité, S(f_i) = x_i), H'·x_A masqué contre le chemin direct.
 *     ./sig_ct <essais>   → JSON sur stdout, code 0 si tout est conforme
 */
#include <stdio.h>
#include <stdlib.h>

#include "sig.c"

static uint64_t naif(uint64_t a, uint64_t b, uint64_t poly, uint32_t deg)
{
    uint64_t r = 0;
    while (b) {
        if (b & 1)
            r ^= a;
        b >>= 1;
        a <<= 1;
        if (a >> deg)
            a ^= poly;
    }
    return r;
}

int main(int argc, char **argv)
{
    long essais = argc > 1 ? atol(argv[1]) : 200;
    sl_init();
    long ok_corps = 0, ok_lagrange = 0, ok_mat = 0, total = 0;
    for (int niv = 0; niv < 2; niv++) {
        const sp_t *p = &SP[niv];
        size_t rw = NW(p->r);
        uint8_t seedH[32], *xa = malloc(XB(p));
        sl_alea(seedH, 32);
        const uint64_t *H = matrice(niv, seedH);
        tables(niv);
        prep_t Pr;
        Pr.L = malloc(8 * (size_t)p->t * p->n);
        Pr.pw = malloc(8 * (size_t)p->t * p->w);
        uint64_t m = (1ULL << p->ep) - 1, me = (1ULL << p->e) - 1;
        for (long k = 0; k < essais; k++) {
            uint64_t a, b, r[T_MAX];
            sl_alea(&a, 8); sl_alea(&b, 8);
            a &= m; b &= m;
            int bon = gfm(a, b, p->pb, p->ep) == naif(a, b, p->pb, p->ep);
            uint64_t ae = a & me, be = b & me;
            bon &= gfm(ae, be, p->pe, p->e) == naif(ae, be, p->pe, p->e);
            bon &= tab_sig[niv].phi[gfm(ae, be, p->pe, p->e)] == GF(tab_sig[niv].phi[ae], tab_sig[niv].phi[be]);
            ok_corps += bon;
            /* points génériques, puis un point de F_poly (r public : chemin spécial) */
            sl_alea(r, sizeof r);
            for (uint32_t j = 0; j < p->t; j++)
                r[j] &= m;
            r[0] = tab_sig[niv].phi[ae];
            preparer(niv, r, &Pr);
            int lg = 1;
            for (uint32_t j = 0; j < p->t; j++) {
                uint64_t s = 0;
                for (uint32_t i = 0; i < p->n; i++)
                    s ^= Pr.L[(size_t)j * p->n + i];
                lg &= s == 1;
            }
            for (uint32_t i = 0; i < p->n; i++)
                lg &= Pr.L[i] == (i == ae);
            ok_lagrange += lg;
            sl_alea(xa, XB(p));
            if (p->k & 7)
                xa[XB(p) - 1] &= (uint8_t)((1 << (p->k & 7)) - 1);
            uint64_t c1[NW(1229) + 1], c2[NW(1229) + 1] = {0};
            mat_vec_ct(p, H, xa, c1);
            for (uint32_t j = 0; j < p->k; j++)
                if (xa[j >> 3] >> (j & 7) & 1)
                    for (size_t q = 0; q < rw; q++)
                        c2[q] ^= H[(size_t)j * rw + q];
            ok_mat += !memcmp(c1, c2, rw * 8);
            total++;
        }
        free(xa); free(Pr.L); free(Pr.pw);
    }
    printf("{\"essais\": %ld, \"corps_conforme\": %ld, \"lagrange_conforme\": %ld, \"produit_conforme\": %ld}\n",
           total, ok_corps, ok_lagrange, ok_mat);
    return !(ok_corps == total && ok_lagrange == total && ok_mat == total);
}
