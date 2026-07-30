# VulnGym enrichment and finding verifier

This repository extends Tencent VulnGym with adjudicated scanner findings, especially confirmed false positives, and provides a reproducible benchmark for finding-verification agents.

## Frozen inputs

- VulnGym: `v0.1.4` at `cd69f7e163e08485ab5496115ae03439cda6e27e`
- Semgrep: `1.171.0`
- OpenGrep: `1.26.0`
- Rules: `semgrep/semgrep-rules` at `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`

The benchmark and rules are Git submodules. Initialize them with:

```bash
git submodule update --init --recursive
```

## Development setup

```bash
uv sync --extra dev
uv run vulngym-audit --benchmark benchmark/VulnGym --output artifacts/manifests/vulngym-v0.1.4.json
uv run pytest
```

## Repository layout

- `benchmark/VulnGym/`: pinned upstream benchmark.
- `rules/semgrep-rules/`: pinned scanner ruleset.
- `config/scanners.lock.json`: reproducibility lock.
- `schemas/`: normalized and adjudicated finding schemas.
- `src/vulngym_enrich/`: audit, checkout, matching, and evaluation tools.
- `tests/`: regression tests.
- `docs/`: annotation and methodology documents.
- `artifacts/`: generated manifests and scan outputs; ignored by Git.

## Label policy

An unmatched Semgrep/OpenGrep finding is not automatically a false positive. Unmatched findings can be novel vulnerabilities or alternate manifestations of known vulnerabilities. See `docs/annotation-guideline.md`.

## Safety and scope

Run scanners only against repositories and commits in the public VulnGym benchmark or other code you are authorized to analyze. Agent verification is read-only by default and must not receive advisory labels or fixed patches during evaluation.
