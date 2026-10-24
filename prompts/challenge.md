# Challenge the map

Start a fresh review pass. Read the scope, report, and cited evidence. Your job is to try to disprove each `survives` conclusion, not to produce more findings by default. If a separate reviewer is available, it can perform this pass; do not assume one exists or automatically delegate.

For every boundary:

1. Re-read the cited code and configuration. Is the restriction actually enforced on the traced path, or merely described in a comment, test, unused policy, or alternate implementation?
2. Ask whether a different action reaches the same value: approval to pull funds, a generic call, an upgrade, a changed recipient, a retry, a claim, a policy update, role administration, or recovery. Follow transitive authority, not just direct permission.
3. Check the distinction between deploying application code and changing independently enforced policy or contracts. Identify any path by which deployment rights gain runtime secrets or independent administrative power. Do not assume either separation or equivalence without evidence.
4. Challenge the evidence basis. Does the report claim deployment state from source code alone? Are snapshots complete, attributable, and applicable to the same environment, version, address, and time?
5. Record a challenge outcome and evidence for every boundary. A supported correction changes the map and classification. Missing evidence becomes an open question and may require `unverified`.

Reconcile this pass into `report.json`, retaining a concise `challenges` record for each boundary. Do not silently remove an objection without stating how it was resolved. Never invent evidence or run live exploits to make the report look complete.

Finally run the validator and renderer. Fix structural errors, stale evidence references, and contradictions; do not change a conclusion merely to make validation pass. If a required fact remains unknown, report it as unknown.
