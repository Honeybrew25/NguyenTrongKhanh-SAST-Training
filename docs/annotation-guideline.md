# Finding annotation guideline

## Unit of annotation

One normalized scanner finding at one exact `(repo_url, commit)` snapshot. Duplicate scanner emissions are clustered but retain all source-tool provenance.

## Labels

- `TP_KNOWN`: exploitable vulnerability linked to a VulnGym advisory.
- `TP_NOVEL`: exploitable vulnerability not represented in VulnGym.
- `FP_CONFIRMED`: the claimed vulnerability is not exploitable under the declared threat model.
- `UNCERTAIN`: evidence is insufficient or reviewers disagree.
- `DUPLICATE`: duplicate of another canonical candidate.
- `OUT_OF_SCOPE`: generated/vendor/test-only code or a non-security finding excluded by policy.

Only `TP_KNOWN`, `TP_NOVEL`, and `FP_CONFIRMED` enter the primary confusion matrix. The other statuses are reported separately.

## Prohibited shortcut

A scanner finding that does not match a VulnGym entry is **not automatically a false positive**. VulnGym does not claim exhaustive vulnerability coverage of each repository.

## Required evidence

Every adjudicated row must include:

1. Exact repository and commit.
2. Scanner, scanner version, ruleset commit, and rule ID.
3. Finding location and relevant source/sink trace when available.
4. A concise rationale with repository-relative file and line references.
5. Annotator identity or stable pseudonym and timestamp.
6. For `FP_CONFIRMED`, at least one reason code.
7. For `TP_KNOWN`, the linked VulnGym entry/report ID in label-only metadata that is hidden from the verifier.

## False-positive reason codes

- `UNREACHABLE_CODE`
- `NO_ATTACKER_CONTROL`
- `SANITIZED_BEFORE_SINK`
- `CONSTANT_VALUE`
- `AUTHZ_PRECONDITION_BLOCKS_ATTACK`
- `SAFE_API_USAGE`
- `TYPE_OR_SCHEMA_CONSTRAINT`
- `TEST_OR_FIXTURE_ONLY`
- `DEAD_OR_UNUSED_PATH`
- `FRAMEWORK_GUARANTEE`
- `SCANNER_MODELING_ERROR`
- `OTHER_EXPLAINED`

## Review protocol

1. Normalize and deduplicate scanner output.
2. Attempt strict/strong matching to known VulnGym entries.
3. Run agent-assisted pre-triage without labels, advisory text, web access, or fixed patches.
4. Human-review all possible novel vulnerabilities, uncertain cases, and the sealed test set.
5. Resolve disagreement with an independent adjudicator.
6. Keep `UNCERTAIN` out of headline precision/recall/F1.

## Leakage controls

The verifier receives the vulnerable repository snapshot and normalized scanner alert only. It must not receive CVE/GHSA IDs, VulnGym titles/traces, fixed commits, patches, labels, or web access.

## Threat model

A true positive requires a concrete attacker capability, a reachable entry, a security-impacting operation, and no effective blocking control. Merely containing a dangerous API or suspicious syntax is insufficient.
