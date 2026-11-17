# IROKA External Witness, Key Custody and Restore Exercise v1.0.0

**Status:** Exercise plan prepared; live exercises not performed  
**Scope:** A3.10.3 operational closure and A4 evidence

## 1. Preconditions and safety

All exercises must first run in an isolated staging environment using synthetic keys and non-production data. Production keys, production endpoints and real protected effects are excluded until separately approved by the Owner.

The Owner appoints the witness operators and key custodians. The implementation team cannot declare two operators independent merely because they use different service names or databases.

## 2. Independent witness exercise

### Required participants and evidence
- At least two separately administered witness operators, each with named accountable operator and organization.
- Separate legal/control authority, cloud/account ownership, administrator identities, signing keys, backup administrators and retention controls.
- Public endpoint, TLS chain, mTLS enrollment record, service identity and documented SLA/retention.
- Operator-signed challenge response binding the operator identity, key ID, challenge nonce and current checkpoint digest.

### Exercise sequence
1. Freeze the staging kernel commit and witness protocol version.
2. Enroll two synthetic witness signing keys under distinct operator identities.
3. Submit a genesis checkpoint; verify both signatures and receipt bindings.
4. Submit next checkpoint; verify sequence, event monotonicity and predecessor linkage.
5. Retry the exact envelope; require exact idempotent receipt readback.
6. Submit same sequence with altered digest; require rejection.
7. Submit sequence gap, regression, wrong stream and wrong predecessor; require rejection.
8. Revoke one witness key; prove it cannot sign a later accepted checkpoint.
9. Disable one operator; verify quorum behavior and fail-closed protected-operation response.
10. Restore one witness database from its independent backup and reconcile the complete checkpoint/receipt chain.
11. Re-enable only after Owner/custodian review.

### Pass criteria
- No forged, stale, conflicting, replayed or out-of-order checkpoint is accepted.
- Each accepted receipt verifies under the enrolled operator key and binds the exact checkpoint.
- Exact retry returns the previously committed receipt.
- Loss of quorum blocks operations requiring fresh external evidence.
- Operator independence is evidenced by actual control and custody records.

## 3. Owner trust-root and key-custody ceremony

### Participants
- Owner authority holder.
- Two designated custodians (separate people).
- Independent observer or assessor.
- HSM/KMS administrator with no unilateral approval authority.

### Ceremony
1. Approve root purpose, algorithm, key IDs, validity, threshold and recovery policy.
2. Verify HSM/KMS ownership, attestation and administrator separation.
3. Generate keys inside the approved boundary; prohibit private-key export.
4. Record public-key fingerprints and verify them over a second independent channel.
5. Create and sign the root manifest; verify signature and canonical digest.
6. Enroll the root in staging; test rotation overlap, revocation and anti-rollback.
7. Test dual-control recovery and emergency revocation.
8. Seal custody records and audit the ceremony; no secret material enters GitHub, chat, CI or ordinary application configuration.

### Pass criteria
- Private key remains non-exportable or protected under the approved equivalent.
- No single operator can unilaterally create, approve and deploy a root change.
- Root fingerprint, signer identity, purpose and validity are independently verified.
- Rotation/revocation survives restart and restore.
- Recovery and revocation are rehearsed without exposing production secrets.

## 4. External backup and restore drill

### Required backup boundaries
- Operational database backup.
- Trust-root and revocation state (public material and protected key recovery references, never raw private keys).
- Audit events and verified checkpoint prefix.
- Witness receipts and independently retained evidence.
- Executor idempotency/result ledger.
- Release manifests, SBOMs and provenance references.

### Drill
1. Record source commit, schema versions, backup IDs, audit head and latest external checkpoint.
2. Create encrypted backup under an independently administered account and retention policy.
3. Simulate loss of the primary database and local audit volume in staging.
4. Restore into a clean isolated environment with no production egress.
5. Verify database integrity, schema, trust versions, revocation state and Owner approval records.
6. Recompute the local audit chain; compare its head and anchored prefix with at least two external witness receipts.
7. Reconcile executor nonce/result records and confirm no duplicate effect is issued.
8. Record measured RPO/RTO and every missing/ambiguous record.
9. Obtain independent witness/custodian sign-off and Owner acceptance.

### Pass criteria
- Restored trust/revocation state is not older than the accepted anchor.
- No audit fork or missing anchored event exists.
- Every checkpoint receipt and signature validates.
- Executor idempotency prevents duplicate protected effects after restore.
- Actual RPO/RTO meets Owner-approved targets.
- Protected effects remain disabled until reconciliation is signed.

## 5. Evidence bundle

The closure bundle must contain:
- Participant roster, legal/control independence evidence and conflict disclosures.
- Endpoint/TLS and mTLS enrollment evidence.
- Public-key fingerprints and key-custody/ceremony attestations (no secrets).
- Signed challenge, checkpoint and witness receipts.
- Raw test inputs/results and CI commit/run links.
- Backup IDs, encrypted-storage ownership and retention evidence.
- Restore logs, chain reconciliation report and measured RPO/RTO.
- Findings, remediation, retest and signed Owner acceptance.

**Disposition:** This is an executable test plan, not evidence that external parties, ceremonies, backups or restores have been performed. A3.10.3 operational closure remains blocked until the Owner appoints operators/custodians and the exercises are witnessed and recorded.
