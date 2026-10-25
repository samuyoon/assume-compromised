# 1. Discover the entire system

You are the investigator. Python does candidate file discovery and artifact checks; it does not run an LLM or query cloud accounts. Carry out this workflow using the host coding agent's read-only tools. The user starts one investigation, not one selected money route.

Read the workspace repositories, discovery candidates, and report contract. Inspect all application entry points, background workers, scheduled jobs, databases, signing systems, financial providers, contracts, build/deploy pipelines, policy administration, and account recovery. Discover linked repositories and environments; ask for access or add explicit coverage gaps when they are missing. Candidate discovery is a starting index, not a complete inventory. Inspect excluded/ignored source paths as appropriate without reading secret values. Do not execute or import target code.

## Inspect actual deployments

Inventory the connected tools you actually have. Use authenticated read-only provider APIs/connectors/CLIs within the user's authorized accounts to gather metadata. Never install cloud tools or request broad new privileges silently. If a read API returns secrets, request a metadata-only projection or a sanitized export instead; never persist or print credential values. Do not source environment files. Do not alter infrastructure, submit transactions, sign messages, or run live exploits.

For each environment discover deployed workloads, provider/account/project identifiers, deployed revision/image, runtime identities, environment-variable NAMES and secret references, workload access to those references, effective IAM permissions, deploy/configure/read-secret/impersonation rights, shared environment groups, and CI identity federation. Read installed signing policies, root/admin/quorum and recovery configuration; for contracts read actual implementation, roles, upgrade/admin paths, registries, allowances and destination restrictions. Follow external-provider authority as well as onchain authority.

Enumerate indirect paths: deployment rights can execute code that uses runtime credentials; a policy administrator can change policy; recovery or root administration can replace normal approvers. Never assume deploying code grants independent administrative credentials, or that an external provider makes a credential independent.

Save sanitized, attributable snapshots in the private review directory. Include account, environment, subject, collection method, original capture time and limitations. Register them as deployment evidence with file hashes and line references. Distinguish source intent from the deployed observation. A failed or inaccessible query is a coverage gap, not a successful inspection.

## Ask and continue

Record questions in report.json as soon as a material unknown is found. First try to resolve each unknown using available authorized source and metadata tools. Search the relevant configuration, follow ownership and recovery paths, and inspect effective permissions. Do not hand the user research the agent can do. If a specific fact or read-only access can only come from a human, use the host's user-question tool or normal conversation to ask for it; a question in the final report alone is insufficient. Batch related requests and continue independent discovery while awaiting answers. Never ask for a secret value or silently widen permissions.

Example: "I found the API signing identity, but cannot establish who can change its policy. Can API deployers retrieve the policy administrator key, and where can I inspect that permission?"

Save answers as operator statements (`answered`). Seek corroborating deployment evidence and reconcile the graph. Mark `resolved` only when the answer and evidence establish the relevant fact; an assurance alone cannot establish independent enforcement. When the user cannot answer, retain the question and show its consequences. Resume from saved report.json on a later turn. No response is not an answer.

For a genuine human-only dependency, record `human_blocker` on the open question: information/access kind, named person or role, the exact requested fact or scoped read-only access/export, why existing tools cannot obtain it, specific checks already attempted and their results, the time you actually asked, and the exact `gap_ids` it would resolve. Use `validate` diagnostics to obtain gap IDs. A generic request to investigate, review code, finish a challenge, or gather more evidence is not a human blocker. A denied read query may justify a request to its account owner; a query you have not tried does not. Do not label an answered question as blocked: reconcile the answer, or ask a new specific question if further human input is necessary.

For each environment cover system inventory, source, deployment, credentials, administration, recovery and external providers. Mark irrelevant categories explicitly excluded with reasons. Record file scan truncation, unavailable accounts, and discovery uncertainty; do not claim whole-system completeness from a repository scan.
