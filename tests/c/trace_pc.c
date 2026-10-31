/* Support du contrôle de flot (tests/c/sig_flux.c), compilé SANS
 * instrumentation : rappel de -fsanitize-coverage=trace-pc (empreinte de la
 * suite des blocs de base exécutés) et sl_alea déterministe, pour rejouer
 * une signature avec le même aléa et des clés différentes. */
#include <stddef.h>
#include <stdint.h>

int trace_actif;
uint64_t trace_h, trace_n;
static uint64_t etat_alea = 0x243f6a8885a308d3ULL;

void __sanitizer_cov_trace_pc(void)
{
    if (!trace_actif)
        return;
    trace_h = (trace_h ^ (uint64_t)(uintptr_t)__builtin_return_address(0)) * 0x100000001b3ULL;
    trace_n++;
}

void trace_debut(void) { trace_h = 0xcbf29ce484222325ULL; trace_n = 0; trace_actif = 1; }
void trace_fin(void) { trace_actif = 0; }
void alea_rejouer(uint64_t graine) { etat_alea = graine; }

int sl_alea(void *out, size_t len)
{
    uint8_t *p = out;
    for (size_t i = 0; i < len; i++) {
        etat_alea = etat_alea * 6364136223846793005ULL + 1442695040888963407ULL;
        p[i] = (uint8_t)(etat_alea >> 56);
    }
    return 0;
}
