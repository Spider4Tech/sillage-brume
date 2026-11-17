# Documentation index

The documents are in English. Until 2026-11-03 each one also had a French version, which was the reference text; the French versions were removed then (they remain in the git history). Section numbers did not change: the code and the test names cite them (for example “PROOFS § 4.4”, or “piste 8” for lead 8 of `LEADS.md`).

| Document | Content | Status |
|---|---|---|
| [`SPEC.md`](SPEC.md) | Normative specification: encodings, algorithms and known answers for BRUME-1024q and its modes (by reference to `brume1024/SPEC.md`), Sillage-KEM and Sillage-SIG | Draft for review, written from the reference implementation |
| [`PROOFS.md`](PROOFS.md) | Assumptions, theorems and proofs for the KEM, the signature, BRUME-1024q, the AEAD and hash modes; parameter derivations; quantum analysis; what remains outside the proofs | Maintained |
| [`MIGRATION_V06.md`](MIGRATION_V06.md) | The v0.6 change (BRUME-1024q replaces BRUME-512): decisions D1–D7 and what was done | Done (17 November 2026) |
| [`brume1024/`](brume1024/) | BRUME-1024q: normative specification (`SPEC.md`) and test vectors, README (design, certified bounds, measurements), AEAD proof (`AEAD_SECURITY.md`), quantum hash bound (`SPONGE_QROM.md`) and its verification (`CM_VERIFICATION.md`), v0.6 modes (`V06_MODES.md`), domains, width analysis, cryptanalysis studies (`ETUDE_GROUPE_STRUCTURE.md`, `ALGEBRIQUE.md`, `REBOND.md`, `DIFF_LIN.md`), attack model for 32 rounds (`NIVEAU3.md`), roadmap | Ours, not reviewed |
| [`AUDIT_REPORT.md`](AUDIT_REPORT.md) | Development history: every flaw found (by the test suite, by external reviews or by re-reading), how it was found and how it was fixed; dated errata | Maintained |
| [`LEADS.md`](LEADS.md) | Measured optimisations and research leads that were **not** adopted, and the security conditions under which they could be | Maintained |
| [`DESIGN_NOTE.md`](DESIGN_NOTE.md) | The original design note: the “cryptography by decoding” idea behind the suite | Historical; the constructions have since departed from it |
| [`CAMPAIGN_24H.md`](CAMPAIGN_24H.md) | How to run the long test and cryptanalysis campaigns on another machine (Linux or Windows through WSL 2) | Operational guide |
| [`GPU_CRYPTANALYSIS_PLAN.md`](GPU_CRYPTANALYSIS_PLAN.md) | Planned GPU cryptanalysis: reduced-round BRUME distinguishers, cubes, hash collisions, quasi-cyclic ISD, reaction attacks | Plan; the first campaign has started (`tests/gpu/`) |
| [`VOLE_CODE_REVIEW.md`](VOLE_CODE_REVIEW.md) | A code review of the VOLE-in-the-Head signature prototype (`prototypes/vole/vole_proto.c`), which is not part of the suite | Review; how each finding was handled is in `LEADS.md`, lead 9 |

External review reports kept in their original French, with no English version: [`AUDIT_EXTERNE.md`](AUDIT_EXTERNE.md) (external audit and point-by-point answer), [`REVUE_CODE_DEPOT_C.md`](REVUE_CODE_DEPOT_C.md) (review of the C code), [`rapport31codex.md`](rapport31codex.md), [`rapport-piste-compression.md`](rapport-piste-compression.md) and [`historique/`](historique/).

## Where results live

`resultats/` keeps only summaries and certificates in the repository: [`SYNTHESE.md`](../resultats/SYNTHESE.md) (latest full test run), [`EMPREINTES.md`](../resultats/EMPREINTES.md) (SHA-256 fingerprints of sources, KATs and results), the C benchmark, and the division-property trail certificates of BRUME-512 (`pistes_*.json`, v0.5). The certificates of BRUME-1024q (C4 ≥ 28) are in `prototypes/brume_q/sat/c4_K28/`. These files, the code comments and the test names are in French. Per-test JSON files and campaign logs are produced locally.

## A short French glossary

For reading the code, the test names and the result files:

| French | English |
|---|---|
| preuve, énoncé, hypothèse | proof, statement, assumption |
| borne, majoration | bound, upper bound |
| chiffré, clair | ciphertext, plaintext |
| distingueur, piste | distinguisher, trail (or lead, in `LEADS.md`) |
| tour, débit, capacité | round, rate, capacity |
| contrôle, mesure, témoin | check (pass/fail), measurement, control |
| correctif, errata | correction, errata |
| campagne de nuit | long (overnight) test campaign |
