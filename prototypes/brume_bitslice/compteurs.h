/* Compteurs matériels génériques par perf_event_open, sans l'outil perf (prototype, piste 10). */
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
static int cpt_ouvrir(uint32_t type, uint64_t cfg) { struct perf_event_attr a; memset(&a, 0, sizeof a); a.type = type; a.size = sizeof a; a.config = cfg; a.exclude_kernel = 1;
    return (int)syscall(SYS_perf_event_open, &a, 0, -1, -1, 0); }
static uint64_t cpt_lire(int fd) { uint64_t v = 0; if (fd < 0 || read(fd, &v, 8) != 8) return 0; return v; }
#define CACHE(c, op, res) ((c) | ((op) << 8) | ((res) << 16))
#define CPT_N 6
static const char *CPT_NOM[CPT_N] = {"cycles", "instr", "L1i miss", "L1d miss", "stall front", "stall back"};
static int CPT_FD[CPT_N];
static void cpt_init(void) {
    CPT_FD[0] = cpt_ouvrir(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
    CPT_FD[1] = cpt_ouvrir(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
    CPT_FD[2] = cpt_ouvrir(PERF_TYPE_HW_CACHE, CACHE(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_MISS));
    CPT_FD[3] = cpt_ouvrir(PERF_TYPE_HW_CACHE, CACHE(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_MISS));
    CPT_FD[4] = cpt_ouvrir(PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND);
    CPT_FD[5] = cpt_ouvrir(PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND);
}
__attribute__((unused)) static void cpt_lire_tout(uint64_t v[CPT_N]) { for (int i = 0; i < CPT_N; i++) v[i] = cpt_lire(CPT_FD[i]); }
__attribute__((unused)) static void cpt_afficher(const uint64_t a[CPT_N], const uint64_t b[CPT_N], double par) {
    for (int i = 0; i < CPT_N; i++) printf("  %-12s %12.0f%s\n", CPT_NOM[i], (b[i] - a[i]) / par, CPT_FD[i] < 0 ? " (indisponible)" : ""); }
