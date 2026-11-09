//! G09 short-lived, single-use execution grants.
//!
//! Grants can only be issued from opaque kernel evidence produced after G01,
//! G02, constitutional-baseline and durable-audit checks. This module issues
//! permission tokens; it does not execute commands.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::getrandom;
use sha2::{Digest, Sha256};

use crate::security_store::{ExecutionGrantStoreError, SqliteSecurityStore};
use crate::{GovernedDecisionEvidence, RiskLevel};

pub const MAX_EXECUTION_GRANT_TTL_SECONDS: u64 = 60;
pub const MAX_DECISION_EVIDENCE_AGE_SECONDS: u64 = 30;

const CAPABILITIES: &[&str] = &[
    "coding.sandbox.execute",
    "coding.debug.execute",
    "coding.workspace.write",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionGrantScope {
    subject: String,
    capability: String,
    repository: String,
    source_revision: String,
    sandbox_id: String,
    action_digest: String,
    risk: RiskLevel,
    policy_version: String,
}

impl ExecutionGrantScope {
    pub fn new(
        subject: impl Into<String>,
        capability: impl Into<String>,
        repository: impl Into<String>,
        source_revision: impl Into<String>,
        sandbox_id: impl Into<String>,
        action_digest: impl Into<String>,
        risk: RiskLevel,
        policy_version: impl Into<String>,
    ) -> Result<Self, ExecutionGrantError> {
        let scope = Self {
            subject: subject.into(),
            capability: capability.into(),
            repository: repository.into(),
            source_revision: source_revision.into(),
            sandbox_id: sandbox_id.into(),
            action_digest: action_digest.into(),
            risk,
            policy_version: policy_version.into(),
        };
        if scope.subject.trim().is_empty()
            || scope.subject.len() > 128
            || scope.subject.bytes().any(|byte| byte.is_ascii_control())
            || !CAPABILITIES.contains(&scope.capability.as_str())
            || !valid_repository(&scope.repository)
            || !valid_revision(&scope.source_revision)
            || !valid_identifier(&scope.sandbox_id)
            || !valid_digest(&scope.action_digest)
            || !matches!(scope.risk, RiskLevel::High | RiskLevel::Critical)
            || scope.policy_version.trim().is_empty()
            || scope.policy_version.len() > 128
            || scope.policy_version.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ExecutionGrantError::InvalidScope);
        }
        Ok(scope)
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    #[must_use]
    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    #[must_use]
    pub fn action_digest(&self) -> &str {
        &self.action_digest
    }

    #[must_use]
    pub fn risk(&self) -> RiskLevel {
        self.risk
    }

    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Exact resource string that must be Owner-approved by G02.
    #[must_use]
    pub fn resource(&self) -> String {
        format!(
            "repo:{}/revision:{}/sandbox:{}/action:{}",
            self.repository, self.source_revision, self.sandbox_id, self.action_digest
        )
    }
}

/// Opaque, non-Clone bearer token. Debug output intentionally omits the secret.
pub struct ExecutionGrant {
    grant_id: String,
    decision_id: String,
    token: [u8; 32],
    scope_digest: [u8; 32],
    genesis_digest: String,
    scope: ExecutionGrantScope,
    issued_at: u64,
    expires_at: u64,
}

impl fmt::Debug for ExecutionGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionGrant")
            .field("grant_id", &self.grant_id)
            .field("decision_id", &self.decision_id)
            .field("scope", &self.scope)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Drop for ExecutionGrant {
    fn drop(&mut self) {
        self.token.fill(0);
    }
}

impl ExecutionGrant {
    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    #[must_use]
    pub fn scope(&self) -> &ExecutionGrantScope {
        &self.scope
    }

    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

pub struct ExecutionGrantIssuer<'a> {
    store: &'a SqliteSecurityStore,
}

impl<'a> ExecutionGrantIssuer<'a> {
    #[must_use]
    pub fn new(store: &'a SqliteSecurityStore) -> Self {
        Self { store }
    }

    /// Consume opaque G01/G02/audit evidence and issue one grant for an exact scope.
    pub fn issue(
        &self,
        evidence: GovernedDecisionEvidence,
        scope: ExecutionGrantScope,
        ttl_seconds: u64,
    ) -> Result<ExecutionGrant, ExecutionGrantError> {
        self.issue_at(evidence, scope, unix_now()?, ttl_seconds)
    }

    fn issue_at(
        &self,
        evidence: GovernedDecisionEvidence,
        scope: ExecutionGrantScope,
        now: u64,
        ttl_seconds: u64,
    ) -> Result<ExecutionGrant, ExecutionGrantError> {
        if evidence.reason() != crate::DecisionReason::ApprovalVerified
            || evidence.subject() != scope.subject
            || evidence.capability() != scope.capability
            || evidence.resource() != scope.resource()
            || evidence.policy_version() != scope.policy_version
            || evidence.risk() != scope.risk
            || !valid_digest(evidence.genesis_digest())
        {
            return Err(ExecutionGrantError::InvalidEvidence);
        }
        if now < evidence.issued_at()
            || now.saturating_sub(evidence.issued_at()) > MAX_DECISION_EVIDENCE_AGE_SECONDS
        {
            return Err(ExecutionGrantError::EvidenceStale);
        }
        if ttl_seconds == 0 || ttl_seconds > MAX_EXECUTION_GRANT_TTL_SECONDS {
            return Err(ExecutionGrantError::InvalidTtl);
        }
        let expires_at = now
            .checked_add(ttl_seconds)
            .ok_or(ExecutionGrantError::InvalidTtl)?;

        let mut grant_id_bytes = [0_u8; 16];
        let mut token = [0_u8; 32];
        getrandom(&mut grant_id_bytes).map_err(|_| ExecutionGrantError::RandomnessUnavailable)?;
        getrandom(&mut token).map_err(|_| ExecutionGrantError::RandomnessUnavailable)?;
        let grant_id = hex(&grant_id_bytes);
        let scope_digest = scope_digest(
            &scope,
            evidence.decision_id(),
            evidence.genesis_digest(),
            now,
            expires_at,
        );
        let token_hash = Sha256::digest(token).to_vec();
        self.store
            .store_execution_grant(
                &grant_id,
                evidence.decision_id(),
                &scope_digest,
                &token_hash,
                now,
                expires_at,
            )
            .map_err(map_store_error)?;

        Ok(ExecutionGrant {
            grant_id,
            decision_id: evidence.decision_id().to_owned(),
            token,
            scope_digest,
            genesis_digest: evidence.genesis_digest().to_owned(),
            scope,
            issued_at: now,
            expires_at,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionGrantError {
    InvalidEvidence,
    EvidenceStale,
    InvalidScope,
    ScopeMismatch,
    InvalidTtl,
    Expired,
    InvalidToken,
    Replay,
    Revoked,
    StoreUnavailable,
    RandomnessUnavailable,
    ClockUnavailable,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConsumedExecutionGrant {
    grant_id: String,
    scope: ExecutionGrantScope,
    issued_at: u64,
    expires_at: u64,
    consumed_at: u64,
}

impl ConsumedExecutionGrant {
    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    #[must_use]
    pub fn scope(&self) -> &ExecutionGrantScope {
        &self.scope
    }

    #[must_use]
    pub fn consumed_at(&self) -> u64 {
        self.consumed_at
    }

    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
}

pub struct ExecutionGrantVerifier<'a> {
    store: &'a SqliteSecurityStore,
}

impl<'a> ExecutionGrantVerifier<'a> {
    #[must_use]
    pub fn new(store: &'a SqliteSecurityStore) -> Self {
        Self { store }
    }

    /// Atomically consume the grant. A second call is rejected by the durable store.
    pub fn consume(
        &self,
        grant: ExecutionGrant,
        expected_scope: &ExecutionGrantScope,
    ) -> Result<ConsumedExecutionGrant, ExecutionGrantError> {
        self.consume_at(grant, expected_scope, unix_now()?)
    }

    fn consume_at(
        &self,
        grant: ExecutionGrant,
        expected_scope: &ExecutionGrantScope,
        now: u64,
    ) -> Result<ConsumedExecutionGrant, ExecutionGrantError> {
        if &grant.scope != expected_scope {
            return Err(ExecutionGrantError::ScopeMismatch);
        }
        if now < grant.issued_at || now > grant.expires_at {
            return Err(ExecutionGrantError::Expired);
        }
        let expected_digest = scope_digest(
            &grant.scope,
            &grant.decision_id,
            &grant.genesis_digest,
            grant.issued_at,
            grant.expires_at,
        );
        if expected_digest != grant.scope_digest {
            return Err(ExecutionGrantError::InvalidToken);
        }
        let token_hash = Sha256::digest(grant.token).to_vec();
        self.store
            .consume_execution_grant(
                &grant.grant_id,
                &grant.scope_digest,
                &token_hash,
                now,
            )
            .map_err(map_store_error)?;
        Ok(ConsumedExecutionGrant {
            grant_id: grant.grant_id.clone(),
            scope: grant.scope.clone(),
            issued_at: grant.issued_at,
            expires_at: grant.expires_at,
            consumed_at: now,
        })
    }

    pub fn revoke(&self, grant: &ExecutionGrant) -> Result<(), ExecutionGrantError> {
        self.revoke_at(grant, unix_now()?)
    }

    fn revoke_at(
        &self,
        grant: &ExecutionGrant,
        now: u64,
    ) -> Result<(), ExecutionGrantError> {
        if now < grant.issued_at || now > grant.expires_at {
            return Err(ExecutionGrantError::Expired);
        }
        self.store
            .revoke_execution_grant(&grant.grant_id, now)
            .map_err(map_store_error)
    }
}

fn unix_now() -> Result<u64, ExecutionGrantError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ExecutionGrantError::ClockUnavailable)?;
    Ok(duration.as_secs())
}

fn map_store_error(error: ExecutionGrantStoreError) -> ExecutionGrantError {
    match error {
        ExecutionGrantStoreError::Unavailable => ExecutionGrantError::StoreUnavailable,
        ExecutionGrantStoreError::Invalid => ExecutionGrantError::InvalidToken,
        ExecutionGrantStoreError::Duplicate => ExecutionGrantError::Replay,
        ExecutionGrantStoreError::Expired => ExecutionGrantError::Expired,
        ExecutionGrantStoreError::Replay => ExecutionGrantError::Replay,
        ExecutionGrantStoreError::Revoked => ExecutionGrantError::Revoked,
    }
}

fn scope_digest(
    scope: &ExecutionGrantScope,
    decision_id: &str,
    genesis_digest: &str,
    issued_at: u64,
    expires_at: u64,
) -> [u8; 32] {
    let resource = scope.resource();
    let risk = format!("{:?}", scope.risk);
    let fields = [
        scope.subject.as_str(),
        scope.capability.as_str(),
        scope.repository.as_str(),
        scope.source_revision.as_str(),
        scope.sandbox_id.as_str(),
        scope.action_digest.as_str(),
        risk.as_str(),
        scope.policy_version.as_str(),
        resource.as_str(),
        decision_id,
        genesis_digest,
    ];
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.update(issued_at.to_be_bytes());
    hasher.update(expires_at.to_be_bytes());
    let digest = hasher.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn valid_repository(repository: &str) -> bool {
    !repository.trim().is_empty()
        && repository.len() <= 256
        && !repository.starts_with('/')
        && !repository.contains('\\')
        && !repository.bytes().any(|byte| byte.is_ascii_control())
        && repository
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains(':'))
}

fn valid_revision(revision: &str) -> bool {
    matches!(revision.len(), 40 | 64) && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use ed25519_dalek::{Signer, SigningKey};

    use crate::{
        authorize_authenticated_with_owner_approval_evidence, sign_genesis,
        validate_embedded_baseline, verify_genesis_with_trust_roots, Attestation, AuditError,
        AuditEvent, AuditSink, AuthorizationRequest, Genesis, OwnerApprovalPayload,
        OwnerApprovalVerifier, Policy, SignedOwnerApproval, SqliteSecurityStore, TrustRoot,
        TrustRootSet, TrustedOwnerKey, VerifiedPrincipal,
    };

    struct TestAudit;
    impl AuditSink for TestAudit {
        fn append(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Ok(())
        }
    }

    fn approved_evidence() -> (
        Arc<SqliteSecurityStore>,
        ExecutionGrantScope,
        GovernedDecisionEvidence,
    ) {
        let now = 1_200;
        let store = Arc::new(SqliteSecurityStore::open_in_memory().expect("security store"));
        let owner_signer = SigningKey::from_bytes(&[71_u8; 32]);
        let owner_verifier = OwnerApprovalVerifier::new(
            vec![TrustedOwnerKey {
                owner_subject: "owner:akefa".to_owned(),
                key_id: "owner-key-g09".to_owned(),
                public_key: owner_signer.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 5_000,
            }],
            store.clone(),
        )
        .expect("Owner verifier");

        let scope = ExecutionGrantScope::new(
            "principal:coding-agent",
            "coding.sandbox.execute",
            "akefadaka-git/iroka",
            "a".repeat(40),
            "sandbox-1",
            "b".repeat(64),
            crate::RiskLevel::High,
            "policy-g09-v1",
        )
        .expect("grant scope");
        let request = AuthorizationRequest::new(
            scope.subject(),
            scope.capability(),
            scope.resource(),
            crate::RiskLevel::High,
        );
        let principal = VerifiedPrincipal::from_verified_credential(
            scope.subject().to_owned(),
            "issuer:test".to_owned(),
            "credential:coding-agent".to_owned(),
        );
        let payload = OwnerApprovalPayload::new(
            "approval:g09-test",
            "owner:akefa",
            "owner-key-g09",
            scope.subject(),
            scope.capability(),
            scope.resource(),
            scope.policy_version(),
            1_100,
            1_500,
        );
        let signature = owner_signer
            .sign(&payload.signing_bytes().expect("approval signing bytes"))
            .to_bytes()
            .to_vec();
        let signed = SignedOwnerApproval::from_signature(payload, signature);

        let fingerprint = validate_embedded_baseline().expect("embedded baseline");
        let genesis_signer = SigningKey::from_bytes(&[72_u8; 32]);
        let root = TrustRoot {
            key_id: "genesis-test-key".to_owned(),
            public_key: genesis_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 5_000,
            provenance_ref: "test-root-record".to_owned(),
        };
        let mut genesis = Genesis {
            dna_id: "iroka.dna".to_owned(),
            dna_version: "1.0.0".to_owned(),
            genome_id: "IROKA_ZERO_GENOME".to_owned(),
            genome_version: "1.0.0".to_owned(),
            digest: fingerprint.digest_hex.clone(),
            canonicalization: "RFC8785-JCS".to_owned(),
            hash_algorithm: "SHA-256".to_owned(),
            epoch: 0,
            parent: None,
            owner_approval_ref: "owner-approval:test-genesis".to_owned(),
            trust_root_key_ids: vec!["genesis-test-key".to_owned()],
            trust_root_provenance_refs: vec!["test-root-record".to_owned()],
            attestation: Attestation {
                envelope_type: "iroka.igacms.attestation".to_owned(),
                version: "1.0.0".to_owned(),
                digest: String::new(),
                epoch: 0,
                key_id: "genesis-test-key".to_owned(),
                signature: Vec::new(),
            },
            audit_refs: vec!["audit:test-genesis".to_owned()],
        };
        genesis.attestation =
            sign_genesis(&genesis, "genesis-test-key", &genesis_signer).expect("sign genesis");
        let roots = TrustRootSet::new(vec![root]).expect("trust roots");
        let verified_genesis =
            verify_genesis_with_trust_roots(&genesis, &fingerprint, &roots, now)
                .expect("verified genesis");
        let policy = Policy::new(
            scope.policy_version(),
            vec![scope.capability().to_owned()],
            vec![scope.capability().to_owned()],
            crate::RiskLevel::Critical,
        );
        let evidence = authorize_authenticated_with_owner_approval_evidence(
            &request,
            &principal,
            &verified_genesis,
            Some(&signed),
            &owner_verifier,
            &TestAudit,
            &policy,
            now,
            false,
            "event:g09-1",
            "trace:g09-1",
        )
        .expect("governed decision evidence");
        (store, scope, evidence)
    }

    #[test]
    fn issues_and_consumes_exact_scope_once() {
        let (store, scope, evidence) = approved_evidence();
        let issuer = ExecutionGrantIssuer::new(&store);
        let grant = issuer.issue_at(evidence, scope.clone(), 1_200, 30).expect("G09 grant");
        assert_eq!(grant.expires_at(), 1_230);
        assert_eq!(grant.scope(), &scope);

        let consumer = ExecutionGrantVerifier::new(&store);
        let grant_id = grant.grant_id.clone();
        let scope_digest = grant.scope_digest;
        let token_hash = Sha256::digest(grant.token).to_vec();
        let consumed = consumer.consume_at(grant, &scope, 1_201).expect("consume grant");
        assert_eq!(consumed.scope(), &scope);
        assert_eq!(consumed.consumed_at(), 1_201);
        assert_eq!(
            store.consume_execution_grant(&grant_id, &scope_digest, &token_hash, 1_202),
            Err(ExecutionGrantStoreError::Replay)
        );
    }

    #[test]
    fn rejects_scope_mismatch_and_expired_grants() {
        let (store, scope, evidence) = approved_evidence();
        let issuer = ExecutionGrantIssuer::new(&store);
        let grant = issuer.issue_at(evidence, scope.clone(), 1_200, 30).expect("G09 grant");
        let wrong_scope = ExecutionGrantScope::new(
            scope.subject(),
            scope.capability(),
            scope.repository(),
            scope.source_revision(),
            "sandbox-other",
            scope.action_digest(),
            scope.risk(),
            scope.policy_version(),
        )
        .expect("alternate scope");
        let verifier = ExecutionGrantVerifier::new(&store);
        assert_eq!(
            verifier.consume_at(grant, &wrong_scope, 1_201),
            Err(ExecutionGrantError::ScopeMismatch)
        );

        let (store, scope, evidence) = approved_evidence();
        let grant = ExecutionGrantIssuer::new(&store)
            .issue_at(evidence, scope.clone(), 1_200, 1)
            .expect("short grant");
        assert_eq!(
            ExecutionGrantVerifier::new(&store).consume_at(grant, &scope, 1_202),
            Err(ExecutionGrantError::Expired)
        );
    }

    #[test]
    fn rejects_stale_evidence_and_ttl_above_sixty_seconds() {
        let (store, scope, evidence) = approved_evidence();
        let issuer = ExecutionGrantIssuer::new(&store);
        assert!(matches!(
            issuer.issue_at(evidence, scope.clone(), 1_231, 10),
            Err(ExecutionGrantError::EvidenceStale)
        ));

        let (store, scope, evidence) = approved_evidence();
        assert!(matches!(
            ExecutionGrantIssuer::new(&store).issue_at(evidence, scope, 1_200, 61),
            Err(ExecutionGrantError::InvalidTtl)
        ));
    }

    #[test]
    fn revocation_blocks_unconsumed_grant() {
        let (store, scope, evidence) = approved_evidence();
        let grant = ExecutionGrantIssuer::new(&store)
            .issue_at(evidence, scope.clone(), 1_200, 30)
            .expect("G09 grant");
        let verifier = ExecutionGrantVerifier::new(&store);
        verifier.revoke_at(&grant, 1_201).expect("revoke grant");
        assert_eq!(
            verifier.consume_at(grant, &scope, 1_202),
            Err(ExecutionGrantError::Revoked)
        );
    }

    #[test]
    fn rejects_unapproved_capability_and_invalid_scope() {
        assert_eq!(
            ExecutionGrantScope::new(
                "principal:1",
                "filesystem.unrestricted",
                "akefadaka-git/iroka",
                "a".repeat(40),
                "sandbox-1",
                "b".repeat(64),
                crate::RiskLevel::High,
                "policy-v1"
            ),
            Err(ExecutionGrantError::InvalidScope)
        );
        assert_eq!(
            ExecutionGrantScope::new(
                "principal:1",
                "coding.sandbox.execute",
                "akefadaka-git/iroka",
                "a".repeat(40),
                "../host",
                "b".repeat(64),
                "policy-v1"
            ),
            Err(ExecutionGrantError::InvalidScope)
        );
    }
}
