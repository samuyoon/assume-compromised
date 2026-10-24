# Assume Compromised

**Give an attacker your server. Trace what they can do with the money.**

A small, model-independent investigation kit for mapping security boundaries in software that moves money. Use it with a coding agent that can inspect your repository. It produces a money-movement map, an inventory of authority, and a list of restrictions that survive the stated compromise, fail under it, or remain unverified.

This is a method we think is useful. It is not presented as Ground's internal tooling or as a certification of anyone's architecture.

## Run it

Requires Python 3.10 or newer. No third-party packages, API keys, or model subscription required by this package. Your chosen agent has its own requirements and data-handling terms.

```sh
git clone https://github.com/samuyoon/assume-compromised.git
cd assume-compromised
python3 boundary_map.py init \
  --repo /path/to/your/code \
  --operation "Customer withdrawal from request to final recipient" \
  --compromised "Production payments API, including all credentials available to it" \
  --out /path/to/private/boundary-review
```

Open your target repository in your coding agent and give it this instruction:

> Read `/path/to/private/boundary-review/RUN.md`. Carry out the mapping and independent challenge passes. Write the report and validate the evidence. Do not modify the target system or perform transactions.

`init` creates instructions and an intentionally incomplete `report.json` in the output folder. It does **not** run an LLM, scan your code, or discover the boundaries itself. The agent does the investigation; the CLI checks the report's structure, internal consistency, references, and file-backed evidence.

```sh
python3 boundary_map.py validate /path/to/private/boundary-review/report.json \
  --repo /path/to/your/code
python3 boundary_map.py render /path/to/private/boundary-review/report.json \
  --repo /path/to/your/code \
  --out /path/to/private/boundary-review/report.md
```

Keep the output private. The authority inventory can reveal sensitive information about your system. Use credential names or roles, never secret values. The package performs no network requests or uploads; using a hosted coding agent may still transmit material to that agent's provider.

## What the investigation answers

1. Where does the money move, from request to final receipt?
2. What can the compromised component sign, approve, deploy, retry, recover, or redirect?
3. Where is each restriction enforced?
4. Who can change or bypass that restriction, including through deployment, policy administration, upgrades, approvals, and recovery?
5. Which conclusions are supported by source code, which have deployment evidence, and what is still missing?

A restriction enforced outside the server can still fail if the server holds the credential that changes it. A policy definition in a repository does not establish which policy is installed in production. An unknown is a result, not an invitation to assume safety.

## Outputs

The Markdown report includes an operation path, a boundary table, change/bypass authority, evidence references, challenge notes, and outstanding questions. See the [complete fictional example](examples/fictional-payments/REPORT.md) and the [report format](REPORT_FORMAT.md).

| Classification | Meaning within the stated scope and evidence |
| --- | --- |
| `survives` | The report supports independent enforcement and documents change/bypass authority outside the assumed attacker capabilities. |
| `defeated` | The assumed attacker can bypass the restriction or use authority that changes it. |
| `unverified` | Evidence or an authority path is unresolved. |

Every boundary also has an evidence basis: `source_only` or `deployment_snapshot`. A source-only conclusion is conditional on deployment matching the inspected code and configuration. A snapshot is evidence at a particular time, not a continuous guarantee. Even deployment snapshots need review for authenticity, completeness, and applicability.

**A valid report is not a secure system.** The CLI cannot establish whether the agent found every authority path or whether the report's reasoning is correct. It does not assign a security score or a pass/fail verdict on your architecture.

## What's in the box

- [Mapping instructions](prompts/map.md): trace an operation and its authority paths.
- [Challenge instructions](prompts/challenge.md): attempt to disprove every claimed surviving restriction.
- [Input template](scope.example.json): define the compromise and target operation.
- [JSON Schema](report.schema.json) and [format guide](REPORT_FORMAT.md).
- `boundary_map.py`: initialize a review, hash evidence, validate a report, and render Markdown.
- A fictional repository and report demonstrating all three classifications.

The workflow is sequential by default. The challenger is a fresh pass with the same agent or a separate reviewer if your tooling supports one; the package does not spawn agents.

## Develop

```sh
python3 -m unittest discover -s tests -v
python3 boundary_map.py validate examples/fictional-payments/report.json \
  --repo examples/fictional-payments
```

MIT licensed. Contributions that improve evidence requirements, report clarity, and realistic examples are welcome.
