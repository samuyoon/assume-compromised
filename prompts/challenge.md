# 3. Challenge, reconcile, and deliver

Perform a fresh review pass (same host agent by default; no automatic delegation). Attempt to disprove every claimed separation. Follow administrator, deployment, credential-read, impersonation, recovery, policy mutation, contract upgrade, token allowance, alternate recipient, generic execution and external-provider paths. Check every action's alternative entry points and asynchronous recovery paths.

Challenge source-vs-deployment parity, environment/account provenance, capture timestamps, effective permissions rather than nominal roles, and whether several apparently independent approvers share recovery or administrative control. Look for implicit OR versus AND mistakes. Check that controlling an enforcer has the correct outgoing bypass edge, rather than simply leaving it as a box in the picture.

Record challenge notes per boundary; `supported` means the model and evidence withstood this pass, not that the system is certified. Reconcile every question into the map or keep it unresolved. Review coverage omissions and exclusions explicitly. You may finish a useful report with unverified outcomes, but must first actively ask the user about material gaps and state what could not be inspected.

Run `python3 TOOL/boundary_map.py validate REVIEW/report.json` and then `render REVIEW/report.json --out REVIEW/map.html`. Repository paths are loaded from workspace.json. Fix structural/evidence errors; never invent evidence or assert deployment state to pass validation. Open the local standalone HTML for visual QA and deliver the map, the compromise matrix, coverage gaps and outstanding questions. The HTML works offline and contains no external scripts or uploads. Do not commit private reports to this public tool repository.
