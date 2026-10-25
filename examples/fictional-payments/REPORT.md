# Security Boundary Mapping

Fictional Payments — illustrative architecture

Snapshot-based investigation, not a security certification. Unreachable in the graph does not prove impossible in the system.

Investigation: Waiting for specific human input

| Compromise | Action | Outcome | Why |
| --- | --- | --- | --- |
| Public internet | Approve external payout | Still protected | The reviewed model requires authority outside this compromise. Limited to this snapshot and declared coverage. |
| Public internet | Change allowed recipients | Still protected | The reviewed model requires authority outside this compromise. Limited to this snapshot and declared coverage. |
| Public internet | Redirect provider refund | Waiting for your input | refund_unknown: inspect the effective deployed grant (Provider may permit destination changes; missing provider policy evidence.). Q_refund: reconcile the clarification and its evidence. C_external_provider: complete the external provider inspection. provider: establish who controls and recovers this authority. Inspect provider destination policy and administrator recovery. |
| Employee deploy account | Approve external payout | Still protected | The reviewed model requires authority outside this compromise. Limited to this snapshot and declared coverage. |
| Employee deploy account | Change allowed recipients | Attacker can reach | A modeled authority path reaches this action. Follow the graph edges for the prerequisites. |
| Employee deploy account | Redirect provider refund | Waiting for your input | refund_unknown: inspect the effective deployed grant (Provider may permit destination changes; missing provider policy evidence.). Q_refund: reconcile the clarification and its evidence. C_external_provider: complete the external provider inspection. provider: establish who controls and recovers this authority. Inspect provider destination policy and administrator recovery. |
| Production API and its credentials | Approve external payout | Still protected | The reviewed model requires authority outside this compromise. Limited to this snapshot and declared coverage. |
| Production API and its credentials | Change allowed recipients | Attacker can reach | A modeled authority path reaches this action. Follow the graph edges for the prerequisites. |
| Production API and its credentials | Redirect provider refund | Waiting for your input | refund_unknown: inspect the effective deployed grant (Provider may permit destination changes; missing provider policy evidence.). Q_refund: reconcile the clarification and its evidence. C_external_provider: complete the external provider inspection. provider: establish who controls and recovers this authority. Inspect provider destination policy and administrator recovery. |
| Customer signing credential | Approve external payout | Still protected | The reviewed model requires authority outside this compromise. Limited to this snapshot and declared coverage. |
| Customer signing credential | Change allowed recipients | Still protected | The reviewed model requires authority outside this compromise. Limited to this snapshot and declared coverage. |
| Customer signing credential | Redirect provider refund | Waiting for your input | refund_unknown: inspect the effective deployed grant (Provider may permit destination changes; missing provider policy evidence.). Q_refund: reconcile the clarification and its evidence. C_external_provider: complete the external provider inspection. provider: establish who controls and recovers this authority. Inspect provider destination policy and administrator recovery. |
| Independent settlement administrator | Approve external payout | Attacker can reach | A modeled authority path reaches this action. Follow the graph edges for the prerequisites. |
| Independent settlement administrator | Change allowed recipients | Still protected | The reviewed model requires authority outside this compromise. Limited to this snapshot and declared coverage. |
| Independent settlement administrator | Redirect provider refund | Waiting for your input | refund_unknown: inspect the effective deployed grant (Provider may permit destination changes; missing provider policy evidence.). Q_refund: reconcile the clarification and its evidence. C_external_provider: complete the external provider inspection. provider: establish who controls and recovers this authority. Inspect provider destination policy and administrator recovery. |

## Exact input needed to finish

### Q_refund: Connect read-only access to the production provider account, or export its effective refund-recipient permissions and administrator recovery settings. Do not supply secret values.

Requested from: The fictional payments provider account owner

Why the agent cannot obtain it: The available provider connector can read transactions but cannot inspect permission or recovery settings. Only the account owner can authorize this access or export.

Already checked: Inspected the supplied repository and deployment snapshot; neither contains the installed provider policy.; Inspected the fictional connected provider tool inventory: transaction-read scope only; no permissions or recovery endpoint is authorized.

Resolves: question:Q_refund, owner:provider, edge:refund_unknown, coverage:C_external_provider, check-1:B_refund


## System coverage

```json
[
  {
    "id": "C_system_inventory",
    "environment": "production",
    "category": "system_inventory",
    "subject": "system inventory",
    "status": "inspected",
    "notes": "Reviewed fictional source and snapshot within stated scope.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "C_source",
    "environment": "production",
    "category": "source",
    "subject": "source",
    "status": "inspected",
    "notes": "Reviewed fictional source and snapshot within stated scope.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "C_deployment",
    "environment": "production",
    "category": "deployment",
    "subject": "deployment",
    "status": "inspected",
    "notes": "Reviewed fictional source and snapshot within stated scope.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "C_credentials",
    "environment": "production",
    "category": "credentials",
    "subject": "credentials",
    "status": "inspected",
    "notes": "Reviewed fictional source and snapshot within stated scope.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "C_administration",
    "environment": "production",
    "category": "administration",
    "subject": "administration",
    "status": "inspected",
    "notes": "Reviewed fictional source and snapshot within stated scope.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "C_recovery",
    "environment": "production",
    "category": "recovery",
    "subject": "recovery",
    "status": "inspected",
    "notes": "Reviewed fictional source and snapshot within stated scope.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "C_external_provider",
    "environment": "production",
    "category": "external_provider",
    "subject": "external provider",
    "status": "partial",
    "notes": "Fictional fixture; refund provider metadata unavailable.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  }
]
```

## Clarifications

```json
[
  {
    "id": "Q_refund",
    "question": "Who can change the refund recipient and recover the provider administrator?",
    "affects": [
      "provider",
      "B_refund",
      "C_external_provider",
      "refund_unknown"
    ],
    "needed_evidence": "Provider effective permissions, destination restrictions and recovery metadata.",
    "answer": "",
    "status": "open",
    "evidence_ids": [],
    "human_blocker": {
      "kind": "access",
      "requested_from": "The fictional payments provider account owner",
      "request": "Connect read-only access to the production provider account, or export its effective refund-recipient permissions and administrator recovery settings. Do not supply secret values.",
      "why_agent_cannot_resolve": "The available provider connector can read transactions but cannot inspect permission or recovery settings. Only the account owner can authorize this access or export.",
      "attempted_checks": [
        "Inspected the supplied repository and deployment snapshot; neither contains the installed provider policy.",
        "Inspected the fictional connected provider tool inventory: transaction-read scope only; no permissions or recovery endpoint is authorized."
      ],
      "asked_at": "2026-10-25T12:00:00Z",
      "gap_ids": [
        "question:Q_refund",
        "owner:provider",
        "edge:refund_unknown",
        "coverage:C_external_provider",
        "check-1:B_refund"
      ]
    }
  }
]
```

## Authority inventory

```json
[
  {
    "id": "internet",
    "kind": "principal",
    "label": "Public internet",
    "environment": "production",
    "owner_ids": [],
    "details": "No internal access assumed.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "employee",
    "kind": "principal",
    "label": "Employee deploy account",
    "environment": "production",
    "owner_ids": [],
    "details": "Can deploy API code; cannot replace independent settlement code.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "company",
    "kind": "principal",
    "label": "Company administrator",
    "environment": "production",
    "owner_ids": [],
    "details": "Controls operational credential administration.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "customer",
    "kind": "principal",
    "label": "Customer",
    "environment": "production",
    "owner_ids": [],
    "details": "Controls customer signing credential and its recovery.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "approver",
    "kind": "principal",
    "label": "Independent approver",
    "environment": "production",
    "owner_ids": [],
    "details": "Can replace settlement code; outside API and employee access.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "api",
    "kind": "service",
    "label": "API runtime control",
    "environment": "production",
    "owner_ids": [
      "company"
    ],
    "details": "Fictional production API. Employee can deploy code. Environment exposes OPERATIONS_SIGNER and DESTINATION_ADMIN references, not customer key.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "ops",
    "kind": "credential",
    "label": "Use operations signer",
    "environment": "production",
    "owner_ids": [
      "company"
    ],
    "details": "Available to API; company administers/replaces it. No independent payout approval authority.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "admin",
    "kind": "credential",
    "label": "Use destination admin",
    "environment": "production",
    "owner_ids": [
      "company"
    ],
    "details": "Available to API. Can change destination policy; this deliberately demonstrates a defeated boundary.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "customer_key",
    "kind": "credential",
    "label": "Use customer signing key",
    "environment": "production",
    "owner_ids": [
      "customer"
    ],
    "details": "Held by customer; replacement requires customer authority. Not available to API or employee.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "settlement",
    "kind": "control",
    "label": "Control settlement enforcement",
    "environment": "production",
    "owner_ids": [
      "approver"
    ],
    "details": "Independent deployment. Replacing settlement code permits payout bypass; represented explicitly.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "provider",
    "kind": "control",
    "label": "Control refund policy",
    "environment": "production",
    "owner_ids": [],
    "details": "External provider ownership and recipient/recovery rules are unresolved.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "payout",
    "kind": "action",
    "label": "Approve external payout",
    "environment": "production",
    "owner_ids": [
      "customer"
    ],
    "details": "Requires customer-bound signature or control of settlement enforcement.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "destination",
    "kind": "action",
    "label": "Change allowed recipients",
    "environment": "production",
    "owner_ids": [
      "company"
    ],
    "details": "Destination administrator can replace allowlist.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  },
  {
    "id": "refund",
    "kind": "action",
    "label": "Redirect provider refund",
    "environment": "production",
    "owner_ids": [
      "company"
    ],
    "details": "Provider route exists; effective destination permissions are unknown.",
    "evidence_ids": [
      "Elive",
      "Esource"
    ]
  }
]
```

## Evidence

```json
[
  {
    "id": "Esource",
    "root": "repo1",
    "path": "src/withdrawal.py",
    "start_line": 1,
    "end_line": 34,
    "sha256": "b52a2edd77bfcddf7515b3973235c49fef4a04116be7ce1a224c38d549a7476c",
    "kind": "source",
    "captured_at": "2026-10-24T23:37:50.033381+00:00",
    "provenance": ""
  },
  {
    "id": "Elive",
    "root": "repo1",
    "path": "snapshots/deployment.json",
    "start_line": 1,
    "end_line": 34,
    "sha256": "a5749c3826dde1151a847b6dec2bef0e660de664c3d5b318bb426f3cca60ff1b",
    "kind": "deployment",
    "captured_at": "2026-10-24T12:00:00+00:00",
    "provenance": "Fictional fixture, never a real provider observation. Account fictional-payments / production."
  }
]
```
