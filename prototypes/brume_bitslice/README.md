# Bitsliced BRUME-512 (prototype, not part of the suite)

A 256-state bitsliced implementation of the BRUME-512 permutation for AVX2, measured in
[`docs/LEADS.md`](../../docs/LEADS.md), lead 10.
Its outputs are identical to `sl_brume_permute`; it is not used by the library.

```bash
make -C prototypes/brume_bitslice
taskset -c 2 prototypes/brume_bitslice/build/banc   # checks, then cycles per state on an idle core
```

| File | Content |
|---|---|
| `gen_asm.c` | Generator of the unrolled round in assembly (`build/bs_tour.S`, ≈ 95 KB of code per round) |
| `bs.c`, `bs.h` | Round constants (with the bit-3 complement folded in), round 0, call sequence |
| `sbox_bs.h` | The S-box as a 25-operation circuit (Shannon decomposition on x₃) |
| `banc.c` | Exhaustive S-box check, conformance on 256 random states, cycle counts against the current kernels |
| `compteurs.h` | Hardware cycle counters through `perf_event_open` |

Comments are in French, like the rest of the code.
