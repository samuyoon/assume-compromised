# Report contract

`report.schema.json` defines the machine-readable structure. All fields are required unless the schema says otherwise. Unknown facts belong in `open_questions` and the relevant boundary's reasoning and checks. Do not fill them with guesses.

## Scope

Describe one operation, the compromised component, the attacker's capabilities, excluded capabilities, and evidence limits. Exclusions are assumptions, not established security guarantees. List known omitted paths under `limitations`.

## Evidence

Each record identifies a file under either `repository` (the `--repo` root) or `artifacts` (the directory containing the report). `path` is relative to that root. `start_line` and `end_line` are inclusive, one-based ranges. `sha256` hashes the entire file's bytes. Evidence can be `repository`, `deployment_snapshot`, or `operator_attestation`. The last two require `captured_at` (ISO 8601 with timezone) and provenance notes. Keep supplied snapshots sanitized and private. The CLI validates hashes, paths, timestamps, and ranges; it does not authenticate snapshots or attestations.

## Steps

Steps are ordered. Each names the actor, action, authority used, credential references (labels only), inputs, outputs, boundary IDs, and evidence IDs. Include the final recipient, not just transaction submission. Use an empty boundary list when no restriction is identified at that step.

## Boundaries

`enforcement_location` is `inside`, `outside`, or `unknown` relative to the assumed compromise. `change_paths` enumerates relevant ways to change or bypass the restriction and whether each is attacker-controlled. An unknown administrator is an unknown boundary.

`survives` requires outside enforcement, documented change/bypass paths assessed as outside attacker control, and evidence other than operator attestation alone. `defeated` identifies the available bypass; it is not automatically a confirmed exploit or a severity rating. `unverified` is the correct classification when the restriction or authority path remains unresolved.

`evidence_basis` is `source_only` or `deployment_snapshot`. Source-only conclusions require explicit production checks. A deployment-snapshot conclusion requires a referenced snapshot and remains limited to the supplied evidence. Neither basis establishes exhaustive coverage or proves a negative.

## Challenges and questions

One challenge per boundary records what was checked, the outcome (`supported`, `revised`, or `unresolved`), and evidence. Open questions say what is missing, which boundary it affects (or `scope`), and what evidence would answer it. `unverified` boundaries require an open question and an unresolved challenge. A completed investigation may still contain unverified boundaries.

## What validation means

The validator checks schema shape, reference integrity, evidence file hashes/ranges, and explicit consistency rules. An incomplete report template intentionally fails validation. Validation success means the artifact meets this contract. It does not establish factual correctness, a complete authority graph, production security, or compliance.
