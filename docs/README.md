# Documentation index

Most documents are written in French. This index says, in English, what each one contains and how settled it is.

| Document | Language | Content | Status |
|---|---|---|---|
| [`PROOFS.md`](PROOFS.md) | English | Assumptions, theorems and proofs for the KEM, the signature, BRUME-512, the AEAD and hash modes; parameter derivations; quantum analysis; what remains outside the proofs | Translation of `PREUVES.md`, same section numbers |
| [`PREUVES.md`](PREUVES.md) | French | The same document, reference version | Maintained; cited as “PREUVES § n” in the code |
| [`RAPPORT_AUDIT.md`](RAPPORT_AUDIT.md) | French | Development history: every flaw found (by the test suite, by external reviews or by re-reading), how it was found and how it was fixed; dated errata | Maintained |
| [`PISTES.md`](PISTES.md) | French | Measured optimisations and research leads that were **not** adopted, and the security conditions under which they could be | Maintained |
| [`guide.md`](guide.md) | French | The original design note: the “cryptography by decoding” idea behind the suite | Historical |
| [`CAMPAGNE_24H.md`](CAMPAGNE_24H.md) | French | How to run the long test and cryptanalysis campaigns on another machine (Linux or Windows through WSL 2) | Operational guide |
| [`PLAN_CRYPTANALYSE_GPU.md`](PLAN_CRYPTANALYSE_GPU.md) | French | Planned GPU cryptanalysis: reduced-round BRUME distinguishers, cubes, hash collisions, quasi-cyclic ISD, reaction attacks | Plan; the first campaign has started (`tests/gpu/`) |
| [`REVUE_CODE_VOLE.md`](REVUE_CODE_VOLE.md) | French | A code review of the VOLE-in-the-Head signature prototype (`tests/c/vole_proto.c`), which is not part of the suite | Review, findings addressed in later commits |

## Where results live

`resultats/` keeps only summaries and certificates in the repository: [`SYNTHESE.md`](../resultats/SYNTHESE.md) (latest full test run), [`EMPREINTES.md`](../resultats/EMPREINTES.md) (SHA-256 fingerprints of sources, KATs and results), the benchmarks, and the division-property trail certificates (`pistes_*.json`). Per-test JSON files and campaign logs are produced locally.

## A short French glossary

| French | English |
|---|---|
| preuve, énoncé, hypothèse | proof, statement, assumption |
| borne, majoration | bound, upper bound |
| chiffré, clair | ciphertext, plaintext |
| distingueur, piste | distinguisher, trail |
| tour, débit, capacité | round, rate, capacity |
| contrôle, mesure | check (pass/fail), measurement |
| correctif, errata | correction, errata |
| campagne de nuit | long (overnight) test campaign |
