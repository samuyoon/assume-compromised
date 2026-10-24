# Security boundary map

> Artifact validation does not establish system security. Source-only conclusions are conditional on deployment matching the inspected material.

**Operation:** Fictional withdrawal and its provider refund recovery path

**Assumed compromise:** The payments API runtime

## Attacker capabilities

- Execute arbitrary code in the API runtime
- Use the API runtime policy-admin credential and provider client

## Excluded capabilities / assumptions

- Independent customer signing keys and settlement-service deployment authority are excluded by this fictional scenario

## Evidence limits

- All evidence is fictional source code; no deployed service or provider configuration was inspected

## Money movement

### 1. Request withdrawal (S1)

- Actor: Payments API
- Authority: API can submit requests and administer the destination allowlist
- Credential references: runtime policy-admin role, provider client
- Inputs: Amount, recipient, nonce, customer signature
- Outputs: Request sent to independent settlement service
- Boundaries: B1
- Evidence: E1, E2

### 2. Authorize and transfer (S2)

- Actor: Independent settlement service
- Authority: Settlement service checks customer authorization and nonce
- Credential references: None identified
- Inputs: Customer-signed amount, recipient, nonce
- Outputs: Transfer to the signed recipient
- Boundaries: B2
- Evidence: E3

### 3. Recover through provider refund (S3)

- Actor: Payments API
- Authority: API can request a provider refund; recipient and administrative rules are unknown
- Credential references: runtime policy-admin role, provider client
- Inputs: Provider order ID
- Outputs: Refund outcome and final destination are unresolved
- Boundaries: B3
- Evidence: E4

## Boundary inventory

| Boundary | Restriction | Enforcement | Status | Basis |
| --- | --- | --- | --- | --- |
| B1 | Destination allowlist | External policy service (outside) | defeated | source_only |
| B2 | Customer authorization of the exact recipient and amount | Independent settlement service (outside) | survives | source_only |
| B3 | Refund destination binding | Third-party provider (unknown) | unverified | source_only |

### B1: Destination allowlist

The policy is checked externally, but the API holds the credential that replaces its allowlist. The assumed attacker inherits that administrative authority.

Change and bypass authority:

- API runtime policy administrator: Replace the allowlist using the runtime credential. Attacker control: **yes**. Evidence: E2.

Production checks:

- Determine whether a deployed runtime actually holds policy administration rights.

Evidence: E1, E2

### B2: Customer authorization of the exact recipient and amount

Conditional source-only conclusion: the fictional service checks the customer signature and consumes a nonce. The scenario excludes the customer key and settlement deployment authority. Signature implementation and completeness of authority separation are assumptions, not proven properties.

Change and bypass authority:

- Customer key holder: Replace the customer key using current-customer authorization. Attacker control: **no**. Evidence: E3.
- Settlement-service deployer: Change service code; this principal is outside the scenario’s assumed compromise. Attacker control: **no**. Evidence: E3.

Production checks:

- Verify the deployed settlement implementation and cryptographic checks.
- Verify customer-key recovery, deployer authority, and all admin paths remain outside API control.

Evidence: E3

### B3: Refund destination binding

The API calls a provider refund method, but no destination or administrative policy was supplied. This recovery path could change the overall exfiltration assessment.

Change and bypass authority:

- Provider administrator: Configure refund destination or account recovery. Attacker control: **unknown**. Evidence: Unresolved.

Production checks:

- Obtain sanitized provider destination, signing, administration, and recovery configuration.

Evidence: E4

## Challenge pass

- **B1 / revised**: Can the runtime change the independently enforced policy? Yes. External enforcement alone was insufficient; classification is defeated. Evidence: E2.
- **B2 / supported**: Can changing the API request replace the signed recipient or customer key? The pseudocode binds both fields and key replacement to customer authorization, conditional on excluded service-deployment authority and assumed verifier behavior. Evidence: E3.
- **B3 / unresolved**: Can the provider refund bypass the normal payout path? Provider rules were not supplied. The report keeps this boundary unverified. Evidence: E4.

## Open questions

- **B3**: Who chooses refund recipients and who can change that rule? Needed: Sanitized provider configuration and administrative/recovery authority inventory.

## Limitations

- This is an illustrative, deliberately incomplete system, not an audit of runnable production software.
- Customer signature verification, nonce enforcement, custody implementation, service isolation, and the completeness of change/recovery paths are assumed in the pseudocode; none has been independently established.
- The conclusions apply only to the stated operation and assumptions. A surviving payout restriction does not establish protection against all forms of loss.

## Evidence

- **E1** (repository): repository/src/withdrawal.py, lines 4-8. SHA-256: b52a2edd77bfcddf7515b3973235c49fef4a04116be7ce1a224c38d549a7476c.
  Captured: Repository file; no deployment observation. 
- **E2** (repository): repository/src/withdrawal.py, lines 11-14. SHA-256: b52a2edd77bfcddf7515b3973235c49fef4a04116be7ce1a224c38d549a7476c.
  Captured: Repository file; no deployment observation. 
- **E3** (repository): repository/src/withdrawal.py, lines 17-28. SHA-256: b52a2edd77bfcddf7515b3973235c49fef4a04116be7ce1a224c38d549a7476c.
  Captured: Repository file; no deployment observation. 
- **E4** (repository): repository/src/withdrawal.py, lines 31-34. SHA-256: b52a2edd77bfcddf7515b3973235c49fef4a04116be7ce1a224c38d549a7476c.
  Captured: Repository file; no deployment observation. 
