/* Allocateur à pages de garde (à la Electric Fence) pour le fuzzing, en
 * l'absence de runtime AddressSanitizer :
 *  - chaque bloc (aligné sur 16 octets, comme l'exige malloc) se termine à
 *    moins de 16 octets d'une page PROT_NONE : tout débordement au-delà
 *    fait une faute immédiate ;
 *  - les octets de bourrage entre la fin du bloc et la page de garde
 *    portent un canari vérifié à la libération (écriture hors limites de
 *    moins de 16 octets → arrêt) ;
 *  - un bloc libéré devient inaccessible (utilisation après libération →
 *    faute).
 * Remplace malloc/free/calloc/realloc et les allocations alignées. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct { void *base; size_t total, taille; } meta_t;
#define CANARI 0xA5

static void *alloue(size_t taille, size_t align)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (align < 16)
        align = 16;
    if ((align & (align - 1)) || taille > SIZE_MAX / 2 - align * 2 - page * 2)
        return NULL;
    size_t total = ((taille + sizeof(meta_t) + 2 * align + page - 1) / page + 1) * page;
    uint8_t *base = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return NULL;
    uint8_t *garde = base + total - page;
    if (mprotect(garde, page, PROT_NONE)) {
        munmap(base, total);
        return NULL;
    }
    uintptr_t p = ((uintptr_t)(garde - taille)) & ~(uintptr_t)(align - 1);
    memset((uint8_t *)p + taille, CANARI, (size_t)(garde - ((uint8_t *)p + taille)));
    meta_t m = {base, total, taille};
    memcpy((uint8_t *)p - sizeof m, &m, sizeof m);
    return (void *)p;
}

void *malloc(size_t n) { return alloue(n, 16); }

void free(void *p)
{
    if (!p)
        return;
    meta_t m;
    memcpy(&m, (uint8_t *)p - sizeof m, sizeof m);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *fin = (uint8_t *)p + m.taille, *garde = (uint8_t *)m.base + m.total - page;
    for (uint8_t *q = fin; q < garde; q++)
        if (*q != CANARI) {
            static const char msg[] = "garde : écriture hors limites détectée (canari)\n";
            if (write(2, msg, sizeof msg - 1) < 0) { }
            abort();
        }
    madvise(m.base, m.total, MADV_DONTNEED);
    mprotect(m.base, m.total, PROT_NONE);       /* réservé mais inaccessible */
}

void *calloc(size_t a, size_t b)                 /* mmap : déjà à zéro */
{
    size_t t;
    return __builtin_mul_overflow(a, b, &t) ? NULL : alloue(t, 16);
}

void *realloc(void *p, size_t n)
{
    void *q = alloue(n, 16);
    if (p && q) {
        meta_t m;
        memcpy(&m, (uint8_t *)p - sizeof m, sizeof m);
        memcpy(q, p, m.taille < n ? m.taille : n);
        free(p);
    }
    return q;
}

int posix_memalign(void **r, size_t a, size_t n) { *r = alloue(n, a); return *r ? 0 : 12; }
void *aligned_alloc(size_t a, size_t n) { return alloue(n, a); }
void *memalign(size_t a, size_t n) { return alloue(n, a); }
