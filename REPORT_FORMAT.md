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

Questions identify affected node, edge, boundary, coverage or scenario IDs and the evidence needed. The host agent first investigates with its available authorized tools, then must ASK for any missing fact/access only a human can supply. `answer` saves an operator statement with status `answered`; it does not mark the fact verified or change graph grants. Reconcile the statement against evidence, update the graph, then use `resolved` with evidence references. Operator attestation alone must not establish observed grants or independent deployed enforcement.

## Completion and human dependencies

`unverified` remains an internal evidence state. It is not permission to finish with generic uncertainty. `validate` and both renderers reject agent-resolvable gaps. `delivery_state()` returns `investigating` while such work remains, `awaiting_human` when every remaining gap has a qualifying human request, and `complete` when all declared review work is resolved. These describe the investigation, not certification of the target system.

An open question may have `human_blocker` with these required fields:

- `kind`: `information` or `access`.
- `requested_from`: the person or role able to supply it.
- `request`: the exact missing fact or scoped read-only access/export, never secret values.
- `why_agent_cannot_resolve`: why the currently authorized tools and available evidence cannot answer it.
- `attempted_checks`: nonempty list of specific checks already made and their results.
- `asked_at`: original timestamp with timezone of the actual request to the user.
- `gap_ids`: the exact gaps this request resolves, including `question:QUESTION_ID` itself.

Diagnostics expose stable gap IDs: `edge:ID`, `owner:ID`, `coverage:ID`, `question:ID`, `deployment:BOUNDARY_ID`, `check-N:BOUNDARY_ID`, `challenge:BOUNDARY_ID`, `scenario:ID`, and `enforcer:BOUNDARY_ID`. The last three are agent-only work and cannot be covered by human blockers. Complete available review work and enumerate modeled bypasses; keep inaccessible facts as separate evidence dependencies. Other gaps may be blocked only by a request whose `affects` includes their target ID. A single request may cover several facts from the same missing provider export, but cannot waive unrelated gaps. `answered` questions cannot justify waiting: the agent must reconcile them or ask a new specific request.

Python checks required records, timestamps, references, gap coverage and delivery eligibility. It cannot prove the agent truly exhausted its tools or that a recorded human request was actually sent. The host agent is responsible for those claims. Do not fabricate them to get a passing result. The delivered UI labels internal `unverified` outcomes **Waiting for your input** and shows the exact request beside each affected conclusion.

`validate` checks evidence, structure and delivery eligibility; `render` applies the same completion gate and produces an offline interactive HTML map by default or Markdown with `--format md`. Re-run both after answers, changed evidence, or changed deployments. There is no continuous monitoring and no automatic cloud authentication in the Python package.
