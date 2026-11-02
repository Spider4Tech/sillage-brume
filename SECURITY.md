# Security policy

SILLAGE / BRUME is an **experimental research prototype**. It is not meant to protect real data, and no version is supported for production use. Reports are still very welcome: finding weaknesses is the point of publishing it.

## What to report, and where

| Finding | Where | Why |
|---|---|---|
| Cryptanalysis: a distinguisher, a key or state recovery, a forgery, an attack cheaper than a stated estimate, a flaw in a proof | A **public issue**, with the *Cryptanalysis result* template | Nobody should be relying on the constructions; public discussion is the fastest way to review the result |
| Implementation: memory-safety bugs, secret-dependent timing or control flow, a C/Python mismatch in a security check | A **private report** via *Security → Report a vulnerability* ([direct link](https://github.com/Spider4Tech/sillage-brume/security/advisories/new)) | The C code may be reused elsewhere; a short private window lets a fix land first |
| Anything else (wrong outputs, build failures, unclear documentation) | A public issue, with the *Bug report* template | — |

If the private reporting form is unavailable, open a public issue that only says you have a private report, without details, and a contact channel will be arranged.

## What helps

- the commit tested (`git rev-parse --short HEAD`) and the exact profile or parameters;
- a reproduction: code, seeds, number of samples, and the measured complexity or advantage;
- for reduced-round or reduced-size results, how they are expected to scale to the full parameters.

## What to expect

This is a personal research project with no bug bounty. Reports are answered on a best-effort basis. Confirmed results are credited (unless you prefer otherwise) and recorded with their fix in [`docs/RAPPORT_AUDIT.md`](docs/RAPPORT_AUDIT.md), the project's issue history, and in the relevant section of [`docs/PROOFS.md`](docs/PROOFS.md).

## Known limitations

Do not report these as new findings. They are already documented:

- the security of every scheme is conditional on stated assumptions (H1-P, H2-P, H3, BRUME as an ideal permutation); see [`docs/PROOFS.md`](docs/PROOFS.md), § 6;
- quantum security levels are below the nominal 128 / 256 labels (§ 5 bis);
- the Python reference implementation is not constant-time;
- the C library is built with `-march=native` and is only constant-time on AVX2 or NEON (the table-based fallback is refused at compile time).
