# Contributing

Contributions are welcome, and **cryptanalysis is the most useful one**: attacks, distinguishers, reviews of the proofs and of the parameter estimates. For security-relevant findings, read [`SECURITY.md`](SECURITY.md) first.

## Languages

The README and this file are in English. Every document in `docs/` exists in English and in French ([`docs/README.md`](docs/README.md)); code comments, test names and result files are in French. Issues and pull requests may be written in English or French.

## Build and test

Linux with GCC, GNU Make and OpenMP; Python 3.10 or later.

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements-tests.txt   # or requirements.txt for the package alone
make -C sillage/c                                  # C library and benchmark
make -C tests/c all                                # native test and cryptanalysis programs
python -m tests.test_fonctionnel                   # one test (each writes resultats/<name>.json)
python -m tests.run_all                            # the full suite: about one hour on 12 cores
```

`python -m tests.run_all <subset>` rewrites `resultats/SYNTHESE.md` with that subset only: to run a single test, call its module directly as above. Long campaigns (`scripts/rundenuit.sh`, `scripts/runlong`, `scripts/runspecial`, `scripts/rungpu`) take hours; see [`docs/CAMPAIGN_24H.md`](docs/CAMPAIGN_24H.md).

## Rules for changes

1. **Outputs are frozen.** A change that alters an output (ciphertext, signature, hash, key format) changes the KATs. It needs a security argument, updated proofs and new test vectors; a performance gain alone does not justify it.
2. **C and Python agree byte for byte.** `tests.test_c_impl` and `tests.test_api_c` must pass.
3. **Constant time.** No branch or memory index may depend on a secret in the C code. Changes to secret-handling code should pass `tests.test_c_temps` and the Valgrind tests (`tests.test_c_kem_valgrind`, `tests.test_c_sig_valgrind`).
4. **Every claim has a status.** A new statement says whether it is proved (and in which model), certified by an exhaustive computation, measured, or assumed, and which test checks it. Measurements are not presented as proofs.
5. **English and French documents stay in sync.** The French version of each document in `docs/` is the reference text, cited by the code; a change there is mirrored in its English version (listed in [`docs/README.md`](docs/README.md)), with the same section numbers.
6. **Record corrections.** A flaw found and fixed is added to `docs/RAPPORT_AUDIT.md` and its English version [`docs/AUDIT_REPORT.md`](docs/AUDIT_REPORT.md), with how it was found.

## Pull requests

Describe what changes and why, list the tests you ran, and say whether any output or format changes. Keep unrelated changes in separate pull requests. By contributing, you agree that your contribution is licensed under the project licence ([AGPL-3.0-only](LICENSE)).
