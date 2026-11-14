# BRUME-q: the 128-bit quantum profile (prototype, not part of the suite)

Since 13 November 2026, at the author's request, work focuses on **BRUME-1024q** only.

**BRUME-1024q** has its own permutation:
- 1 024 bits, D₂₅₆;
- 32 rounds;
- capacity c = 384;
- rate 640 bits.

Its README is `b1024/README.md`, and what remains to do is in `b1024/ROADMAP.md`.

**BRUME-512q is abandoned.** It was the suite's permutation with c = 384 and a rate of 128 bits. It was slower (37 MB/s on
the sponge against 106) and had a lower proved quantum bound (min(r, c) = 128 against 384).
- Its prototype (`brume_q.c`, its README and `resultats/brume_q.*`) was removed from the repository on 13 November 2026.
- It is kept in `~/dev/orion_archive_brume512q_20261113.tar.gz`, outside the repository.
- Its generic quantum analysis, valid for any c = 384 sponge, was moved to `b1024/README.md` § 5.

| Path | Role |
|---|---|
| `b1024/` | BRUME-1024q: generator, permutation, modes, checks, frozen KATs, domains, benches, constant time |
| `WIDTH_ANALYSIS.md` | Why 1 024 bits: the proved quantum bounds in min(r, c), diffusion, attack families at 32 rounds, and the go/no-go criteria. It is a record of the decision, and BRUME-512q appears there as the alternative that was set aside |
| `sat/` | Certificates of the 3-round bound C3 (CNF of the truncated relaxation, our LRAT checker, cubes), for BRUME-1024q (`-DB1024`) and for the permutation of the suite (BRUME-512) |
| `largeur/` | Tools of the width analysis: independent check of diffusion and λ\*, impossible differentials and zero correlations at both widths, early measured 1024 kernel |
