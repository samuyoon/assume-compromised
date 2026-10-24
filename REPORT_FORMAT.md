# System report, version 2

The authority graph replaces the old single-operation report. There is no v1 compatibility path. `report.schema.json` defines required fields; unknown fields fail validation. All IDs are unique within their collection. Node, edge, boundary, coverage and scenario IDs should also be distinct across collections so question targets are unambiguous.

## Nodes, grants, and scenarios

A node is a precise authority state, not an undifferentiated machine icon. Separate read from write access, deployment from runtime control, policy use from policy administration, and a public key from the ability to sign with it. Kinds: principal, credential, service, control, resource, action. Use `details` for observed deployment/credential metadata and its unresolved facts; use `owner_ids` for controlling entities and explicit edges for their actual powers.

Each edge names its relation (deployment, credential use, secret retrieval, administration, recovery, replacement, upgrade, execution, impersonation, access or other). An edge grants its target when its source AND every `requires_all` authority is controlled. Alternative edges are OR paths. Model quorums with exact combinations or retain an explicit gap. An edge marked `observed` needs deployment evidence; `source` and `unknown` are possible grants only. Deployment rights, credential use, impersonation, policy changes, upgrades, account recovery and alternative execution paths must all be represented. The analyzer computes a fixed point, so indirect chains and cycles are supported. It does not infer hidden grants from node labels or vendor names.

Each scenario states initial controlled nodes and its assumptions. `review: supported` records review of this assumption, not proof that the compromise occurred. Different scenarios can be independent, nested, or combined.

## Boundaries and analysis

Each boundary identifies a consequential action, its enforcing service/control, ALL modeled incoming action edges in `gate_ids`, coverage dependencies, evidence, challenge notes, and remaining checks. Every action node needs a boundary. Include administrative and recovery bypass edges among the action's alternative paths.

For each scenario the analyzer computes:

- `defeated`: deployment-observed grants reach the action under the stated prerequisites. This is an authority finding, not a demonstrated exploit.
- `unverified`: a possible path reaches the action/enforcer, relevant questions/owners remain unresolved, applicable coverage is incomplete, or review/deployment checks remain outstanding.
- `survives`: the reviewed, deployment-observed model does not grant the action under this scenario and its relevant gaps are resolved. This is conditional on model completeness and the captured state; it never certifies security or proves exhaustive discovery.

System-inventory gaps apply across the environment. Other questions and coverage gaps propagate to boundaries that depend on the affected nodes, scenarios or coverage records. Edges' prerequisites and credential/control owners are part of this dependency closure. Recording an unrelated unknown must not silently turn an established bypass green, nor should it invalidate an unrelated restriction.

## Coverage

Inventory every discovered environment. For each environment record system inventory, source, deployment, credentials, administration, recovery and external providers. Explicitly record excluded/not-applicable categories with rationale. `inspected` requires cited evidence. Snapshot inspections have account/project/environment identifiers, revision or contract implementation where relevant, original capture time, method, effective permissions, and access limitations. File discovery is a candidate index, not evidence that a system inventory is complete.

## Evidence and questions

Repository root IDs map to paths in private `workspace.json`; `artifacts` means the review folder. Evidence references relative files, inclusive line ranges, SHA-256 hashes, original capture timestamps with timezone, and provenance. The CLI checks paths, hashes, ranges and metadata, not snapshot authenticity or reasoning. Never store raw credentials or production reports in this public repository.

Questions identify affected IDs and the evidence needed. The host agent must ASK during the investigation. `answer` saves an operator statement with status `answered`; it does not mark the fact verified or change graph grants. Reconcile the statement against evidence, update the graph, then use `resolved` with evidence references. Operator attestation alone must not establish observed grants or independent deployed enforcement. Questions may remain unresolved in a valid, useful report.

`validate` checks the artifact; `render` produces an offline interactive HTML map by default or Markdown with `--format md`. Re-run both after answers, changed evidence, or changed deployments. There is no continuous monitoring and no automatic cloud authentication in the Python package.
