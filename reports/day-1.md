# Day 1 report — benchmark freeze and reproducibility foundation

Date: 2026-07-30

## Completed scope

1. Initialized the project as a Git repository.
2. Added Tencent/VulnGym as a pinned submodule at tag `v0.1.4`, commit `cd69f7e163e08485ab5496115ae03439cda6e27e`.
3. Added `semgrep/semgrep-rules` as a pinned submodule at commit `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`.
4. Implemented a dataset auditor and reproducible snapshot-manifest generator.
5. Implemented a Git mirror/checkout cache harness for exact vulnerable commits.
6. Defined the enriched-finding JSON Schema and annotation taxonomy.
7. Implemented a range-aware VulnGym matcher and verifier-classification metrics.
8. Added regression tests and scanner smoke fixtures.

## Frozen benchmark audit

- Reports: 184
- Entries: 408
- Human-verified entries: 393
- Unverified entries: 15
- Distinct repositories: 23
- Distinct projects: 38
- Distinct `(repo, commit)` snapshots: 166
- Entries with a line range in source or sink: 44

Checksums:

- `entries.jsonl`: `2158b6bfef0be1812e7a6a77b32ad32b65964c2546c83018ff20a9a6f706c7b1`
- `reports.jsonl`: `5d29ce523441eb1739bddca3e4550514171b1b2b1f9d38bd922933408d25fbb9`

Generated manifest, including all 166 snapshots:

- `artifacts/manifests/vulngym-v0.1.4.json` (generated artifact, intentionally Git-ignored)

## Toolchain freeze

- Python: 3.11.9 (`.python-version`)
- uv: 0.11.18 observed during setup
- Semgrep: 1.171.0, locally verified
- OpenGrep: 1.26.0, locally downloaded and verified
- OpenGrep Windows SHA-256: `4e6c0e201982cd72ca4aff5798a2ff133e17de8af3b00b460238fdda4dd266e3`
- Shared rule corpus: `semgrep/semgrep-rules@40b8c63f75dc7c22c8a77482d73bfb864b146f7e`

Both engines use the same pinned compatible rules so engine differences can be separated from rule differences.

## Verification evidence

### Unit and regression tests

Command:

```bash
uv run pytest
```

Result:

```text
7 passed in 0.07s
```

The tests include an end-to-end self-match of all 408 VulnGym entries at tolerance zero. This verifies that all 44 range-bearing entries are matchable by the new interval matcher. All 184 advisories are covered in the self-test.

### Scanner smoke test

A deterministic `eval(...)` fixture was scanned by both engines using the same rule:

```text
Semgrep findings: 1
OpenGrep findings: 1
```

Raw smoke outputs are under `artifacts/smoke/` and are intentionally Git-ignored.

### Checkout-cache smoke test

The harness mirrored `https://github.com/nltk/nltk` and materialized the VulnGym snapshot:

```text
40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e
checkout-smoke=OK
```

The materialized tree and Git mirrors are under `worktrees/` and `cache/`, both Git-ignored.

### Static checks

- Python bytecode compilation: passed.
- JSON syntax checks for schema and lock/config files: passed.
- `git diff --check`: passed.

## Important design decisions

- An unmatched scanner finding is never automatically labeled false positive.
- Primary metrics only include `TP_KNOWN`, `TP_NOVEL`, and `FP_CONFIRMED`.
- `UNCERTAIN`, `DUPLICATE`, and `OUT_OF_SCOPE` are reported separately.
- The verifier must not receive CVE/GHSA IDs, VulnGym traces/titles, fixed commits, patches, labels, or web access.
- Finding-level classification metrics are separate from advisory/entry-level end-to-end recall.

## Known environment note

Docker CLI 29.6.2 is installed, but Docker Desktop's Linux daemon was not running during Day 1. This did not block work because both scanner executables were run locally. Before Docker-based batch scanning, Docker Desktop must be started; the local executable path remains available as a fallback.

## Day 2 entry criteria

Day 2 can start from the generated 166-snapshot manifest. The next implementation step is the batch runner that iterates snapshots, invokes both scanners with the pinned rule corpus, stores raw JSON/SARIF, normalizes results, and supports resume/retry without losing provenance.
