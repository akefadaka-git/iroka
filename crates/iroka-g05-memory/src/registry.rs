//! Durable G05 consent and organizational reviewer registries.
//! Consent is granted by a G01-verified subject, scoped to a Kernel-resolved
//! tenant and authorized by G02. Reviewer designation is G02-authorized and
//! the target identity/key binding is verified by G01. Approval proof
//! cryptography remains in G01; this registry enforces current designation
//! and one-time use. SQLite is single-node only.

use crate::{
    AuthorizationRequest, Classification, DesignatedReviewerAuthority, DurableApprovalReceipt,
    EpisodicConsentAuthority, G02AuthorizationAuthority, G05Error, MemoryRecord, Operation, Purpose,
};
use iroka_kernel::{
    ReviewerKeyBindingResolver, ReviewerProofError, ReviewerProofVerifier, SignedReviewerProof,
    SqliteSecurityStore, TenantContext, VerifiedPrincipal, VerifiedReviewerProof,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::Digest;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SqliteG05AuthorityRegistry {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteG05AuthorityRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, G05Error> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::fs::{symlink_metadata, OpenOptions};
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            match symlink_metadata(path) {
                Ok(metadata)
                    if metadata.file_type().is_symlink()
                        || metadata.permissions().mode() & 0o077 != 0 =>
                {
                    return Err(G05Error::AuthorityUnavailable)
                }
                Ok(_) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                        .map_err(|_| G05Error::AuthorityUnavailable)?;
                }
                Err(_) => return Err(G05Error::AuthorityUnavailable),
            }
        }
        let c = Connection::open(path).map_err(|_| G05Error::AuthorityUnavailable)?;
        Self::from_connection(c)
    }
    pub fn open_in_memory() -> Result<Self, G05Error> {
        let c = Connection::open_in_memory().map_err(|_| G05Error::AuthorityUnavailable)?;
        Self::from_connection(c)
    }
    fn from_connection(c: Connection) -> Result<Self, G05Error> {
        c.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS g05_episodic_consents(
            consent_ref TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL, subject_ref TEXT NOT NULL,
            purpose TEXT NOT NULL, grant_issuer TEXT NOT NULL, grant_credential_id TEXT NOT NULL,
            granted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER,
            version INTEGER NOT NULL CHECK(version>0), action_ref TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS g05_consent_scope ON g05_episodic_consents(tenant_ref,subject_ref,purpose);
          CREATE TABLE IF NOT EXISTS g05_reviewer_designations(
            designation_ref TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL, organization_ref TEXT NOT NULL,
            reviewer_ref TEXT NOT NULL, reviewer_key_ref TEXT NOT NULL, designated_by TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version>0), valid_from INTEGER NOT NULL,
            valid_until INTEGER NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER,
            UNIQUE(tenant_ref,organization_ref,reviewer_ref,version));
          CREATE INDEX IF NOT EXISTS g05_reviewer_scope ON g05_reviewer_designations
            (tenant_ref,organization_ref,reviewer_ref,version);
          CREATE TABLE IF NOT EXISTS g05_consumed_reviewer_approvals(
            approval_ref TEXT PRIMARY KEY, receipt_digest BLOB NOT NULL CHECK(length(receipt_digest)=32),
            designation_ref TEXT NOT NULL, designation_version INTEGER NOT NULL, consumed_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS g05_authority_outbox(
            event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, aggregate_ref TEXT NOT NULL,
            tenant_ref TEXT NOT NULL, actor_ref TEXT NOT NULL, purpose TEXT NOT NULL,
            record_version INTEGER NOT NULL, outcome TEXT NOT NULL, correlation_ref TEXT NOT NULL,
            occurred_at INTEGER NOT NULL, content_sha256 TEXT NOT NULL,
            delivered_at INTEGER);")
          .map_err(|_| G05Error::AuthorityUnavailable)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(c)),
        })
    }

    /// Explicit authenticated user action only; do not call from passive signup.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_episodic_consent<G: G02AuthorizationAuthority>(
        &self,
        actor: &VerifiedPrincipal,
        tenant: &TenantContext,
        purpose: Purpose,
        consent_ref: &str,
        action_ref: &str,
        expires_at: u64,
        now: u64,
        max_ttl_secs: u64,
        g02: &G,
    ) -> Result<(), G05Error> {
        if actor.subject() != tenant.subject()
            || consent_ref.trim().is_empty()
            || consent_ref.len() > 512
            || action_ref.trim().is_empty()
            || action_ref.len() > 512
            || expires_at <= now
            || max_ttl_secs == 0
            || expires_at.saturating_sub(now) > max_ttl_secs
        {
            return Err(G05Error::MalformedRecord);
        }
        let req = AuthorizationRequest {
            operation: Operation::GrantEpisodicConsent,
            principal_ref: actor.subject().into(),
            tenant_ref: tenant.tenant_id().into(),
            subject_ref: actor.subject().into(),
            purpose,
            classification: Classification::Internal,
            memory_id: None,
            recipient_refs: Vec::new(),
            correlation_ref: action_ref.into(),
        };
        g02.authorize_g05(&req)?;
        let mut c = self
            .connection
            .lock()
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        tx.execute("INSERT INTO g05_episodic_consents
          (consent_ref,tenant_ref,subject_ref,purpose,grant_issuer,grant_credential_id,granted_at,expires_at,revoked_at,version,action_ref)
          VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,1,?9)",
          params![consent_ref,tenant.tenant_id(),actor.subject(),purpose_key(purpose),actor.issuer(),
            actor.credential_id(),to_i64(now)?,to_i64(expires_at)?,action_ref])
          .map_err(|_|G05Error::DuplicateRecord)?;
        enqueue_authority_event(
            &tx,
            AuthorityOutboxEvent {
                event_type: "memory.consent.granted",
                aggregate_ref: consent_ref,
                tenant_ref: tenant.tenant_id(),
                actor_ref: actor.subject(),
                purpose,
                version: 1,
                outcome: "granted",
                correlation_ref: action_ref,
                now,
            },
        )?;
        tx.commit().map_err(|_| G05Error::AuthorityUnavailable)
    }

    /// Withdrawal is self-only and permanent for this consent reference.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_episodic_consent<G: G02AuthorizationAuthority>(
        &self,
        actor: &VerifiedPrincipal,
        tenant: &TenantContext,
        consent_ref: &str,
        action_ref: &str,
        now: u64,
        g02: &G,
    ) -> Result<(), G05Error> {
        if actor.subject() != tenant.subject()
            || consent_ref.trim().is_empty()
            || consent_ref.len() > 512
            || action_ref.trim().is_empty()
            || action_ref.len() > 512
        {
            return Err(G05Error::MalformedRecord);
        }
        let purpose_text: String = {
            let c = self
                .connection
                .lock()
                .map_err(|_| G05Error::AuthorityUnavailable)?;
            c.query_row(
                "SELECT purpose FROM g05_episodic_consents
              WHERE consent_ref=?1 AND tenant_ref=?2 AND subject_ref=?3 AND revoked_at IS NULL",
                params![consent_ref, tenant.tenant_id(), actor.subject()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| G05Error::AuthorityUnavailable)?
            .ok_or(G05Error::EpisodicOptInRequired)?
        };
        let purpose = purpose_from_key(&purpose_text)?;
        let req = AuthorizationRequest {
            operation: Operation::WithdrawEpisodicConsent,
            principal_ref: actor.subject().into(),
            tenant_ref: tenant.tenant_id().into(),
            subject_ref: actor.subject().into(),
            purpose,
            classification: Classification::Internal,
            memory_id: None,
            recipient_refs: Vec::new(),
            correlation_ref: action_ref.into(),
        };
        g02.authorize_g05(&req)?;
        let mut c = self
            .connection
            .lock()
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let current_purpose: String = tx
            .query_row(
                "SELECT purpose FROM g05_episodic_consents
          WHERE consent_ref=?1 AND tenant_ref=?2 AND subject_ref=?3 AND revoked_at IS NULL",
                params![consent_ref, tenant.tenant_id(), actor.subject()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| G05Error::AuthorityUnavailable)?
            .ok_or(G05Error::EpisodicOptInRequired)?;
        if current_purpose != purpose_text {
            return Err(G05Error::VersionConflict);
        }
        let n = tx
            .execute(
                "UPDATE g05_episodic_consents SET revoked_at=?1,version=version+1
          WHERE consent_ref=?2 AND tenant_ref=?3 AND subject_ref=?4 AND revoked_at IS NULL",
                params![
                    to_i64(now)?,
                    consent_ref,
                    tenant.tenant_id(),
                    actor.subject()
                ],
            )
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        if n != 1 {
            return Err(G05Error::EpisodicOptInRequired);
        }
        enqueue_authority_event(
            &tx,
            AuthorityOutboxEvent {
                event_type: "memory.consent.withdrawn",
                aggregate_ref: consent_ref,
                tenant_ref: tenant.tenant_id(),
                actor_ref: actor.subject(),
                purpose,
                version: 2,
                outcome: "withdrawn",
                correlation_ref: action_ref,
                now,
            },
        )?;
        tx.commit().map_err(|_| G05Error::AuthorityUnavailable)
    }

    /// G02 authorizes the organizational action; G01 verifies that the target
    /// reviewer and key reference are a valid current identity/key binding.
    #[allow(clippy::too_many_arguments)]
    pub fn designate_reviewer<G, I>(
        &self,
        actor: &VerifiedPrincipal,
        tenant: &TenantContext,
        organization_ref: &str,
        reviewer_ref: &str,
        reviewer_key_ref: &str,
        designation_ref: &str,
        version: u64,
        valid_from: u64,
        valid_until: u64,
        now: u64,
        g02: &G,
        g01: &I,
    ) -> Result<(), G05Error>
    where
        G: G02AuthorizationAuthority,
        I: G01ReviewerProofAuthority,
    {
        if actor.subject() != tenant.subject()
            || organization_ref.trim().is_empty()
            || organization_ref.len() > 512
            || reviewer_ref.trim().is_empty()
            || reviewer_ref.len() > 512
            || reviewer.subject() != reviewer_ref
            || reviewer_key_ref.trim().is_empty()
            || reviewer_key_ref.len() > 512
            || designation_ref.trim().is_empty()
            || designation_ref.len() > 512
            || version == 0
            || valid_from > now
            || valid_until <= now
            || valid_until <= valid_from
        {
            return Err(G05Error::MalformedRecord);
        }
        let req = AuthorizationRequest {
            operation: Operation::DesignateReviewer,
            principal_ref: actor.subject().into(),
            tenant_ref: tenant.tenant_id().into(),
            subject_ref: organization_ref.into(),
            purpose: Purpose::OrganizationalContext,
            classification: Classification::Confidential,
            memory_id: None,
            recipient_refs: vec![reviewer_ref.into()],
            correlation_ref: designation_ref.into(),
        };
        // Authorize the actor and organization scope before resolving the target
        // reviewer's identity/key binding; denied callers must not probe G01.
        g02.authorize_g05(&req)?;
        g02.authorize_organization_scope(&req, organization_ref)?;
        g01.validate_reviewer_key_binding(reviewer, reviewer_key_ref, now)?;
        let mut c = self
            .connection
            .lock()
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let high: Option<i64> = tx
            .query_row(
                "SELECT MAX(version) FROM g05_reviewer_designations
          WHERE tenant_ref=?1 AND organization_ref=?2 AND reviewer_ref=?3",
                params![tenant.tenant_id(), organization_ref, reviewer_ref],
                |r| r.get(0),
            )
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        if high.is_some_and(|v| i64::try_from(version).map_or(true, |n| n <= v)) {
            return Err(G05Error::VersionConflict);
        }
        tx.execute("INSERT INTO g05_reviewer_designations
          (designation_ref,tenant_ref,organization_ref,reviewer_ref,reviewer_key_ref,designated_by,version,valid_from,valid_until,created_at,revoked_at)
          VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL)",
          params![designation_ref,tenant.tenant_id(),organization_ref,reviewer_ref,reviewer_key_ref,
            actor.subject(),to_i64(version)?,to_i64(valid_from)?,to_i64(valid_until)?,to_i64(now)?])
          .map_err(|_|G05Error::DuplicateRecord)?;
        enqueue_authority_event(
            &tx,
            AuthorityOutboxEvent {
                event_type: "memory.reviewer.designated",
                aggregate_ref: designation_ref,
                tenant_ref: tenant.tenant_id(),
                actor_ref: actor.subject(),
                purpose: Purpose::OrganizationalContext,
                version,
                outcome: "designated",
                correlation_ref: designation_ref,
                now,
            },
        )?;
        tx.commit().map_err(|_| G05Error::AuthorityUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn revoke_reviewer_designation<G: G02AuthorizationAuthority>(
        &self,
        actor: &VerifiedPrincipal,
        tenant: &TenantContext,
        organization_ref: &str,
        designation_ref: &str,
        action_ref: &str,
        now: u64,
        g02: &G,
    ) -> Result<(), G05Error> {
        if actor.subject() != tenant.subject()
            || organization_ref.trim().is_empty()
            || organization_ref.len() > 512
            || designation_ref.trim().is_empty()
            || designation_ref.len() > 512
            || action_ref.trim().is_empty()
            || action_ref.len() > 512
        {
            return Err(G05Error::MalformedRecord);
        }
        let req = AuthorizationRequest {
            operation: Operation::RevokeReviewerDesignation,
            principal_ref: actor.subject().into(),
            tenant_ref: tenant.tenant_id().into(),
            subject_ref: organization_ref.into(),
            purpose: Purpose::OrganizationalContext,
            classification: Classification::Confidential,
            memory_id: None,
            recipient_refs: Vec::new(),
            correlation_ref: action_ref.into(),
        };
        g02.authorize_g05(&req)?;
        g02.authorize_organization_scope(&req, organization_ref)?;
        let mut c = self
            .connection
            .lock()
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let version:i64=tx.query_row("SELECT version FROM g05_reviewer_designations
          WHERE designation_ref=?1 AND tenant_ref=?2 AND organization_ref=?3 AND revoked_at IS NULL",
          params![designation_ref,tenant.tenant_id(),organization_ref],|r|r.get(0))
          .optional().map_err(|_|G05Error::AuthorityUnavailable)?
          .ok_or(G05Error::ReviewerNotAuthorized)?;
        let n=tx.execute("UPDATE g05_reviewer_designations SET revoked_at=?1
          WHERE designation_ref=?2 AND tenant_ref=?3 AND organization_ref=?4 AND revoked_at IS NULL",
          params![to_i64(now)?,designation_ref,tenant.tenant_id(),organization_ref])
          .map_err(|_|G05Error::AuthorityUnavailable)?;
        if n != 1 {
            return Err(G05Error::ReviewerNotAuthorized);
        }
        enqueue_authority_event(
            &tx,
            AuthorityOutboxEvent {
                event_type: "memory.reviewer.revoked",
                aggregate_ref: designation_ref,
                tenant_ref: tenant.tenant_id(),
                actor_ref: actor.subject(),
                purpose: Purpose::OrganizationalContext,
                version: from_i64(version)?,
                outcome: "revoked",
                correlation_ref: action_ref,
                now,
            },
        )?;
        tx.commit().map_err(|_| G05Error::AuthorityUnavailable)
    }

    fn active_designation(
        &self,
        tenant: &str,
        org: &str,
        reviewer: &str,
        now: u64,
    ) -> Result<ReviewerDesignation, G05Error> {
        let c = self
            .connection
            .lock()
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        c.query_row("SELECT designation_ref,tenant_ref,organization_ref,reviewer_ref,reviewer_key_ref,version,valid_from,valid_until
          FROM g05_reviewer_designations d WHERE tenant_ref=?1 AND organization_ref=?2 AND reviewer_ref=?3
          AND version=(SELECT MAX(version) FROM g05_reviewer_designations
            WHERE tenant_ref=?1 AND organization_ref=?2 AND reviewer_ref=?3)
          AND revoked_at IS NULL AND valid_from<=?4 AND valid_until>?4 LIMIT 1",
          params![tenant,org,reviewer,to_i64(now)?],|r|Ok(ReviewerDesignation{
            designation_ref:r.get(0)?,tenant_ref:r.get(1)?,organization_ref:r.get(2)?,
            reviewer_ref:r.get(3)?,reviewer_key_ref:r.get(4)?,version:r.get::<_,u64>(5)?,
            valid_from:r.get::<_,u64>(6)?,valid_until:r.get::<_,u64>(7)?}))
          .optional().map_err(|_|G05Error::AuthorityUnavailable)?
          .ok_or(G05Error::ReviewerNotAuthorized)
    }

    fn consume_approval(
        &self,
        receipt: &DurableApprovalReceipt,
        record: &MemoryRecord,
        d: &ReviewerDesignation,
        proof: &VerifiedReviewerProof,
        now: u64,
    ) -> Result<(), G05Error> {
        let bytes = serde_json::to_vec(&(receipt, record.candidate.record_version, record.candidate.purpose,
            record.candidate.classification, &record.candidate.contract_version, proof.proof_id()))
            .map_err(|_| G05Error::MalformedRecord)?;
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        let mut c = self
            .connection
            .lock()
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM g05_reviewer_designations
          WHERE designation_ref=?1 AND tenant_ref=?2 AND organization_ref=?3 AND reviewer_ref=?4
          AND reviewer_key_ref=?5 AND version=?6 AND version=(SELECT MAX(version)
            FROM g05_reviewer_designations WHERE tenant_ref=?2 AND organization_ref=?3 AND reviewer_ref=?4)
          AND revoked_at IS NULL AND valid_from<=?7 AND valid_until>?7)",
          params![d.designation_ref,d.tenant_ref,d.organization_ref,d.reviewer_ref,d.reviewer_key_ref,
            to_i64(d.version)?,to_i64(now)?],|r|r.get(0)).map_err(|_|G05Error::AuthorityUnavailable)?;
        if !active {
            return Err(G05Error::ReviewerNotAuthorized);
        }
        let n=tx.execute("INSERT OR IGNORE INTO g05_consumed_reviewer_approvals
          (approval_ref,receipt_digest,designation_ref,designation_version,consumed_at) VALUES(?1,?2,?3,?4,?5)",
          params![receipt.approval_ref,digest.as_slice(),d.designation_ref,to_i64(d.version)?,to_i64(now)?])
          .map_err(|_|G05Error::AuthorityUnavailable)?;
        if n != 1 {
            return Err(G05Error::ApprovalReplay);
        }
        enqueue_authority_event(
            &tx,
            AuthorityOutboxEvent {
                event_type: "memory.reviewer.approval_consumed",
                aggregate_ref: &receipt.approval_ref,
                tenant_ref: &receipt.tenant_ref,
                actor_ref: &receipt.reviewer_ref,
                purpose: Purpose::OrganizationalContext,
                version: d.version,
                outcome: "consumed",
                correlation_ref: &receipt.approval_ref,
                now,
            },
        )?;
        tx.commit().map_err(|_| G05Error::AuthorityUnavailable)
    }

    /// Deliver committed G05 authority events to G11. G11 must deduplicate by
    /// event ID; a crash after append and before marking delivery causes retry.
    pub fn drain_g11_outbox<A: crate::G11MemoryAuditAuthority>(
        &self,
        g11: &A,
        now: u64,
        limit: usize,
    ) -> Result<usize, G05Error> {
        if limit == 0 {
            return Ok(0);
        }
        let rows = {
            let c = self
                .connection
                .lock()
                .map_err(|_| G05Error::AuthorityUnavailable)?;
            let mut stmt = c
                .prepare(
                    "SELECT event_id,event_type,aggregate_ref,tenant_ref,actor_ref,
              purpose,record_version,outcome,correlation_ref,occurred_at,content_sha256
              FROM g05_authority_outbox WHERE delivered_at IS NULL ORDER BY rowid LIMIT ?1",
                )
                .map_err(|_| G05Error::AuthorityUnavailable)?;
            let mapped = stmt
                .query_map([i64::try_from(limit.min(500)).unwrap_or(500)], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, String>(8)?,
                        r.get::<_, i64>(9)?,
                        r.get::<_, String>(10)?,
                    ))
                })
                .map_err(|_| G05Error::AuthorityUnavailable)?;
            mapped
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| G05Error::AuthorityUnavailable)?
        };
        let mut delivered = 0;
        for row in rows {
            let (
                id,
                kind,
                aggregate,
                tenant,
                actor,
                purpose,
                version,
                outcome,
                correlation,
                occurred,
                digest,
            ) = row;
            let event = crate::AuditEvent {
                event_id: id.clone(),
                event_type: kind,
                memory_id: aggregate,
                tenant_ref: tenant,
                actor_ref: actor,
                purpose: purpose_from_key(&purpose)?,
                record_version: from_i64(version)?,
                outcome,
                correlation_ref: correlation,
                occurred_at: from_i64(occurred)?,
                content_sha256: digest,
            };
            g11.append_memory_event(&event)?;
            let c = self
                .connection
                .lock()
                .map_err(|_| G05Error::AuthorityUnavailable)?;
            c.execute("UPDATE g05_authority_outbox SET delivered_at=?1 WHERE event_id=?2 AND delivered_at IS NULL",
                params![to_i64(now)?,id]).map_err(|_|G05Error::AuthorityUnavailable)?;
            delivered += 1;
        }
        Ok(delivered)
    }
}

impl EpisodicConsentAuthority for SqliteG05AuthorityRegistry {
    fn verify_active_opt_in(
        &self,
        reference: &str,
        tenant: &str,
        subject: &str,
        purpose: Purpose,
        now: u64,
    ) -> Result<(), G05Error> {
        let c = self
            .connection
            .lock()
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let row:Option<(String,String,String,i64,i64,Option<i64>)>=c.query_row(
          "SELECT tenant_ref,subject_ref,purpose,granted_at,expires_at,revoked_at FROM g05_episodic_consents WHERE consent_ref=?1",
          [reference],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))
          .optional().map_err(|_|G05Error::AuthorityUnavailable)?;
        let (t, s, p, g, e, rev) = row.ok_or(G05Error::EpisodicOptInRequired)?;
        if t != tenant || s != subject || p != purpose_key(purpose) {
            return Err(G05Error::ConsentScopeMismatch);
        }
        if rev.is_some() || now < from_i64(g)? || now >= from_i64(e)? {
            return Err(G05Error::EpisodicOptInRequired);
        }
        Ok(())
    }
}

/// G01 identity/key boundary. Implementations resolve current key state and
/// revocation; proof_ref is only a selector into the trusted proof service.
pub trait G01ReviewerProofAuthority: Send + Sync {
    fn validate_reviewer_key_binding(
        &self,
        principal: &VerifiedPrincipal,
        key_ref: &str,
        now: u64,
    ) -> Result<(), G05Error>;
    fn verify_approval_proof(
        &self,
        principal: &VerifiedPrincipal,
        record: &MemoryRecord,
        receipt: &DurableApprovalReceipt,
        designation: &ReviewerDesignation,
        now: u64,
    ) -> Result<VerifiedReviewerProof, G05Error>;
}
/// Concrete G01 adapter. The serialized proof envelope is untrusted input;
/// only the kernel can construct VerifiedReviewerProof after current binding,
/// signature, exact-scope, freshness, revocation and replay checks.
pub struct KernelG01ReviewerProofAuthority<R: ReviewerKeyBindingResolver> {
    verifier: ReviewerProofVerifier<R>,
}
impl<R: ReviewerKeyBindingResolver> KernelG01ReviewerProofAuthority<R> {
    pub fn new(verifier: ReviewerProofVerifier<R>) -> Self { Self { verifier } }
}
impl<R: ReviewerKeyBindingResolver> G01ReviewerProofAuthority for KernelG01ReviewerProofAuthority<R> {
    fn validate_reviewer_key_binding(
        &self, principal: &VerifiedPrincipal, key_ref: &str, now: u64,
    ) -> Result<(), G05Error> {
        self.verifier.validate_current_key_binding(principal, key_ref, now)
            .map_err(map_reviewer_proof_error)
    }

    fn verify_approval_proof(
        &self,
        principal: &VerifiedPrincipal,
        record: &MemoryRecord,
        receipt: &DurableApprovalReceipt,
        designation: &ReviewerDesignation,
        now: u64,
    ) -> Result<VerifiedReviewerProof, G05Error> {
        if record.candidate.memory_class != crate::MemoryClass::Durable
            || record.lifecycle_state != crate::LifecycleState::PendingReview
            || receipt.memory_id != record.candidate.memory_id
            || receipt.tenant_ref != record.candidate.tenant_ref
            || receipt.subject_ref != record.candidate.subject_ref
            || receipt.subject_ref != designation.organization_ref
            || receipt.content_sha256 != record.candidate.content_sha256
            || receipt.reviewer_ref != designation.reviewer_ref
            || designation.tenant_ref != record.candidate.tenant_ref
            || designation.organization_ref != receipt.subject_ref
            || principal.subject() != receipt.reviewer_ref
            || receipt.issued_at < designation.valid_from
            || receipt.expires_at > designation.valid_until
            || receipt.expires_at <= now
        {
            return Err(G05Error::ApprovalBindingMismatch);
        }
        if receipt.proof_ref.len() > 32_768 || receipt.proof_ref.trim().is_empty() {
            return Err(G05Error::InvalidReference);
        }
        let signed: SignedReviewerProof = serde_json::from_str(&receipt.proof_ref)
            .map_err(|_| G05Error::ReviewerNotAuthorized)?;
        let purpose = purpose_key(record.candidate.purpose);
        let classification = classification_key(record.candidate.classification);
        let resource = format!(
            "g05:durable.activate:{}:{}:{}:{}:{}",
            record.candidate.tenant_ref,
            designation.organization_ref,
            record.candidate.memory_id,
            record.candidate.record_version,
            record.candidate.content_sha256
        );
        let verified = self.verifier.verify_and_consume(
            &signed,
            principal,
            &designation.reviewer_ref,
            &designation.reviewer_key_ref,
            &receipt.approval_ref,
            &record.candidate.tenant_ref,
            &designation.organization_ref,
            &designation.designation_ref,
            designation.version,
            &record.candidate.memory_id,
            record.candidate.record_version,
            &record.candidate.content_sha256,
            purpose,
            classification,
            "g05.memory.durable.activate",
            &resource,
            &record.candidate.contract_version,
            now,
        ).map_err(map_reviewer_proof_error)?;
        if verified.reviewer_id() != designation.reviewer_ref
            || verified.key_id() != designation.reviewer_key_ref
            || verified.designation_id() != designation.designation_ref
            || verified.designation_version() != designation.version
            || verified.memory_id() != record.candidate.memory_id
            || verified.record_version() != record.candidate.record_version
            || verified.content_sha256() != record.candidate.content_sha256
            || verified.purpose() != purpose
            || verified.classification() != classification
            || verified.approval_id() != receipt.approval_ref
            || verified.tenant_id() != receipt.tenant_ref
            || verified.organization_id() != receipt.subject_ref
            || verified.subject() != principal.subject()
        {
            return Err(G05Error::ApprovalBindingMismatch);
        }
        Ok(verified)
    }
}

fn map_reviewer_proof_error(error: ReviewerProofError) -> G05Error {
    match error {
        ReviewerProofError::Replay => G05Error::ApprovalReplay,
        ReviewerProofError::StoreUnavailable => G05Error::AuthorityUnavailable,
        ReviewerProofError::ScopeMismatch | ReviewerProofError::PrincipalMismatch => G05Error::ApprovalBindingMismatch,
        ReviewerProofError::Expired | ReviewerProofError::NotYetValid | ReviewerProofError::KeyOutsideValidity => G05Error::ApprovalExpired,
        ReviewerProofError::Malformed | ReviewerProofError::BindingMissing | ReviewerProofError::BindingInactive
        | ReviewerProofError::InvalidSignature | ReviewerProofError::Revoked => G05Error::ReviewerNotAuthorized,
    }
}

fn classification_key(value: Classification) -> &'static str {
    match value {
        Classification::Public => "PUBLIC",
        Classification::Internal => "INTERNAL",
        Classification::Confidential => "CONFIDENTIAL",
        Classification::Restricted => "RESTRICTED",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewerDesignation {
    pub designation_ref: String,
    pub tenant_ref: String,
    pub organization_ref: String,
    pub reviewer_ref: String,
    pub reviewer_key_ref: String,
    pub version: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}
pub struct RegistryDesignatedReviewerAuthority<P> {
    registry: SqliteG05AuthorityRegistry,
    g01: P,
}
impl<P> RegistryDesignatedReviewerAuthority<P> {
    pub fn new(registry: SqliteG05AuthorityRegistry, g01: P) -> Self {
        Self { registry, g01 }
    }
}
impl<P: G01ReviewerProofAuthority> DesignatedReviewerAuthority
    for RegistryDesignatedReviewerAuthority<P>
{
    fn verify_designated_reviewer(
        &self,
        principal: &VerifiedPrincipal,
        record: &MemoryRecord,
        receipt: &DurableApprovalReceipt,
        org: &str,
        now: u64,
    ) -> Result<(), G05Error> {
        if receipt.approval_ref.trim().is_empty()
            || receipt.memory_id.trim().is_empty()
            || receipt.reviewer_ref.trim().is_empty()
            || receipt.proof_ref.trim().is_empty()
        {
            return Err(G05Error::InvalidReference);
        }
        if receipt.content_sha256.len() != 64
            || !receipt
                .content_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(G05Error::DigestMismatch);
        }
        crate::validate_approval_binding(record, receipt, now)?;
        if receipt.subject_ref != org || record.candidate.subject_ref != org {
            return Err(G05Error::ApprovalBindingMismatch);
        }
        if receipt.expires_at <= now
            || receipt.issued_at > now
            || receipt.expires_at <= receipt.issued_at
        {
            return Err(G05Error::ApprovalExpired);
        }
        let d = self.registry.active_designation(
            &receipt.tenant_ref,
            org,
            &receipt.reviewer_ref,
            now,
        )?;
        if receipt.issued_at < d.valid_from || receipt.expires_at > d.valid_until {
            return Err(G05Error::ReviewerNotAuthorized);
        }
        let verified = self.g01.verify_approval_proof(principal, record, receipt, &d, now)?;
        self.registry.consume_approval(receipt, record, &d, &verified, now)
    }
}

/// Concrete G02 adapter over the canonical Kernel composition. The credential,
/// tenant selector, genesis, verifier, Owner verifier and audit sink are
/// server-side session dependencies; request fields cannot replace them.
/// A policy requiring a separate Owner approval is denied here rather than
/// silently bypassed. Construct a fresh adapter per request with current time.
pub struct KernelG02AuthorizationAdapter<'a, R: iroka_kernel::RevocationChecker> {
    compact_credential: &'a str,
    expected_audience: &'a str,
    requested_tenant_id: &'a str,
    genesis: &'a iroka_kernel::VerifiedGenesis,
    credential_verifier: &'a iroka_kernel::Ed25519CredentialVerifier<R>,
    owner_verifier: &'a iroka_kernel::OwnerApprovalVerifier,
    audit_sink: &'a iroka_kernel::SqliteAuditSink,
    now: u64,
    max_membership_age_secs: u64,
}
impl<'a, R: iroka_kernel::RevocationChecker> KernelG02AuthorizationAdapter<'a, R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        compact_credential: &'a str,
        expected_audience: &'a str,
        requested_tenant_id: &'a str,
        genesis: &'a iroka_kernel::VerifiedGenesis,
        credential_verifier: &'a iroka_kernel::Ed25519CredentialVerifier<R>,
        owner_verifier: &'a iroka_kernel::OwnerApprovalVerifier,
        audit_sink: &'a iroka_kernel::SqliteAuditSink,
        now: u64,
        max_membership_age_secs: u64,
    ) -> Self {
        Self {
            compact_credential,
            expected_audience,
            requested_tenant_id,
            genesis,
            credential_verifier,
            owner_verifier,
            audit_sink,
            now,
            max_membership_age_secs,
        }
    }
}
impl<R: iroka_kernel::RevocationChecker> G02AuthorizationAuthority
    for KernelG02AuthorizationAdapter<'_, R>
{
    fn authorize_g05(&self, request: &AuthorizationRequest) -> Result<(), G05Error> {
        let capability = g05_capability(request.operation);
        let recipient_digest = crate::sha256_hex(request.recipient_refs.join("\\0").as_bytes());
        let resource = format!(
            "g05:{}:{}:{}:{}:{:?}:{}:{}",
            operation_key(request.operation),
            request.tenant_ref,
            request.subject_ref,
            purpose_key(request.purpose),
            request.classification,
            request.memory_id.as_deref().unwrap_or("registry"),
            recipient_digest
        );
        let risk = match request.operation {
            Operation::DesignateReviewer | Operation::RevokeReviewerDesignation => {
                iroka_kernel::RiskLevel::High
            }
            Operation::GrantEpisodicConsent | Operation::WithdrawEpisodicConsent => {
                iroka_kernel::RiskLevel::Moderate
            }
            _ => iroka_kernel::RiskLevel::Moderate,
        };
        let kernel_request = iroka_kernel::AuthorizationRequest::new(
            request.principal_ref.clone(),
            capability,
            resource,
            risk,
        );
        if request.tenant_ref != self.requested_tenant_id {
            return Err(G05Error::TenantScopeMismatch);
        }
        if request.principal_ref.trim().is_empty()
            || request.principal_ref.len() > 512
            || request.subject_ref.trim().is_empty()
            || request.subject_ref.len() > 512
            || request.tenant_ref.trim().is_empty()
            || request.tenant_ref.len() > 512
            || request.correlation_ref.trim().is_empty()
            || request.correlation_ref.len() > 512
            || request.recipient_refs.len() > crate::MAX_SOURCE_REFS
            || request
                .recipient_refs
                .iter()
                .any(|value| value.trim().is_empty() || value.len() > 512)
        {
            return Err(G05Error::MalformedRecord);
        }
        let correlation_digest = crate::sha256_hex(request.correlation_ref.as_bytes());
        let event_id = format!(
            "g05-authz:{}:{}",
            operation_key(request.operation),
            correlation_digest
        );
        let decision = iroka_kernel::authorize_compact_in_tenant(
            self.compact_credential,
            self.expected_audience,
            self.requested_tenant_id,
            &kernel_request,
            self.genesis,
            None,
            self.credential_verifier,
            self.owner_verifier,
            self.audit_sink,
            self.now,
            self.max_membership_age_secs,
            &event_id,
            &request.correlation_ref,
        );
        if decision.code() == iroka_kernel::DecisionCode::Allow {
            Ok(())
        } else {
            Err(G05Error::AuthorizationDenied)
        }
    }
}
fn operation_key(operation: Operation) -> &'static str {
    match operation {
        Operation::Propose => "propose",
        Operation::CreateWorking => "working.create",
        Operation::CreateEpisodic => "episodic.create",
        Operation::ActivateDurable => "durable.activate",
        Operation::Retrieve => "retrieve",
        Operation::InspectMetadata => "metadata.inspect",
        Operation::Correct => "correct",
        Operation::Restrict => "restrict",
        Operation::RequestDeletion => "deletion.request",
        Operation::VerifyDeletion => "deletion.verify",
        Operation::Share => "share",
        Operation::GrantEpisodicConsent => "consent.grant",
        Operation::WithdrawEpisodicConsent => "consent.withdraw",
        Operation::DesignateReviewer => "reviewer.designate",
        Operation::RevokeReviewerDesignation => "reviewer.revoke",
    }
}
fn g05_capability(operation: Operation) -> &'static str {
    match operation {
        Operation::Propose => "g05.memory.propose",
        Operation::CreateWorking => "g05.memory.working.create",
        Operation::CreateEpisodic => "g05.memory.episodic.create",
        Operation::ActivateDurable => "g05.memory.durable.activate",
        Operation::Retrieve => "g05.memory.retrieve",
        Operation::InspectMetadata => "g05.memory.metadata.inspect",
        Operation::Correct => "g05.memory.correct",
        Operation::Restrict => "g05.memory.restrict",
        Operation::RequestDeletion => "g05.memory.deletion.request",
        Operation::VerifyDeletion => "g05.memory.deletion.verify",
        Operation::Share => "g05.memory.share",
        Operation::GrantEpisodicConsent => "g05.memory.consent.grant",
        Operation::WithdrawEpisodicConsent => "g05.memory.consent.withdraw",
        Operation::DesignateReviewer => "g05.memory.reviewer.designate",
        Operation::RevokeReviewerDesignation => "g05.memory.reviewer.revoke",
    }
}

struct AuthorityOutboxEvent<'a> {
    event_type: &'a str,
    aggregate_ref: &'a str,
    tenant_ref: &'a str,
    actor_ref: &'a str,
    purpose: Purpose,
    version: u64,
    outcome: &'a str,
    correlation_ref: &'a str,
    now: u64,
}

fn enqueue_authority_event(
    tx: &rusqlite::Transaction<'_>,
    event: AuthorityOutboxEvent<'_>,
) -> Result<(), G05Error> {
    let aggregate_digest = crate::sha256_hex(event.aggregate_ref.as_bytes());
    let event_id = format!(
        "g05-authority:{}:{}:v{}",
        event.event_type, aggregate_digest, event.version
    );
    tx.execute(
        "INSERT INTO g05_authority_outbox
         (event_id,event_type,aggregate_ref,tenant_ref,actor_ref,purpose,record_version,
          outcome,correlation_ref,occurred_at,content_sha256,delivered_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL)",
        params![
            event_id,
            event.event_type,
            event.aggregate_ref,
            event.tenant_ref,
            event.actor_ref,
            purpose_key(event.purpose),
            to_i64(event.version)?,
            event.outcome,
            event.correlation_ref,
            to_i64(event.now)?,
            crate::sha256_hex(&[])
        ],
    )
    .map_err(|_| G05Error::AuthorityUnavailable)?;
    Ok(())
}
fn purpose_from_key(value: &str) -> Result<Purpose, G05Error> {
    match value {
        "TASK_CONTINUITY" => Ok(Purpose::TaskContinuity),
        "USER_PREFERENCE" => Ok(Purpose::UserPreference),
        "PROJECT_CONTEXT" => Ok(Purpose::ProjectContext),
        "ORGANIZATIONAL_CONTEXT" => Ok(Purpose::OrganizationalContext),
        "OPERATIONAL_HISTORY" => Ok(Purpose::OperationalHistory),
        "AUTHORIZED_SYSTEM_ASSURANCE" => Ok(Purpose::AuthorizedSystemAssurance),
        _ => Err(G05Error::AuthorityUnavailable),
    }
}

fn purpose_key(p: Purpose) -> &'static str {
    match p {
        Purpose::TaskContinuity => "TASK_CONTINUITY",
        Purpose::UserPreference => "USER_PREFERENCE",
        Purpose::ProjectContext => "PROJECT_CONTEXT",
        Purpose::OrganizationalContext => "ORGANIZATIONAL_CONTEXT",
        Purpose::OperationalHistory => "OPERATIONAL_HISTORY",
        Purpose::AuthorizedSystemAssurance => "AUTHORIZED_SYSTEM_ASSURANCE",
    }
}
fn to_i64(v: u64) -> Result<i64, G05Error> {
    i64::try_from(v).map_err(|_| G05Error::MalformedRecord)
}
fn from_i64(v: i64) -> Result<u64, G05Error> {
    u64::try_from(v).map_err(|_| G05Error::AuthorityUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct G01;
    impl G01ReviewerProofAuthority for G01 {
        fn validate_reviewer_key_binding(&self, r: &VerifiedPrincipal, k: &str, _: u64) -> Result<(), G05Error> {
            if r.subject() == "reviewer:1" && k == "key:1" { Ok(()) }
            else { Err(G05Error::ReviewerNotAuthorized) }
        }
        fn verify_approval_proof(
            &self, _principal: &VerifiedPrincipal, _record: &MemoryRecord,
            _receipt: &DurableApprovalReceipt, _d: &ReviewerDesignation, _now: u64,
        ) -> Result<VerifiedReviewerProof, G05Error> {
            Err(G05Error::ReviewerNotAuthorized)
        }
    }
    #[test]
    fn consent_scope_purpose_expiry_and_revocation_fail_closed() {
        let r = SqliteG05AuthorityRegistry::open_in_memory().unwrap();
        {
            let c = r.connection.lock().unwrap();
            c.execute(
                "INSERT INTO g05_episodic_consents VALUES
   ('c1','t1','s1','TASK_CONTINUITY','iss','cred',100,200,NULL,1,'action')",
                [],
            )
            .unwrap();
        }
        assert_eq!(
            r.verify_active_opt_in("missing", "t1", "s1", Purpose::TaskContinuity, 150),
            Err(G05Error::EpisodicOptInRequired)
        );
        assert_eq!(
            r.verify_active_opt_in("c1", "t1", "s1", Purpose::TaskContinuity, 150),
            Ok(())
        );
        assert_eq!(
            r.verify_active_opt_in("c1", "t2", "s1", Purpose::TaskContinuity, 150),
            Err(G05Error::ConsentScopeMismatch)
        );
        assert_eq!(
            r.verify_active_opt_in("c1", "t1", "other-subject", Purpose::TaskContinuity, 150),
            Err(G05Error::ConsentScopeMismatch)
        );
        assert_eq!(
            r.verify_active_opt_in("c1", "t1", "s1", Purpose::UserPreference, 150),
            Err(G05Error::ConsentScopeMismatch)
        );
        assert_eq!(
            r.verify_active_opt_in("c1", "t1", "s1", Purpose::TaskContinuity, 200),
            Err(G05Error::EpisodicOptInRequired)
        );
        let c = r.connection.lock().unwrap();
        c.execute(
            "UPDATE g05_episodic_consents SET revoked_at=160 WHERE consent_ref='c1'",
            [],
        )
        .unwrap();
        drop(c);
        assert_eq!(
            r.verify_active_opt_in("c1", "t1", "s1", Purpose::TaskContinuity, 170),
            Err(G05Error::EpisodicOptInRequired)
        );
    }
    #[test]
    fn reviewer_scope_expiry_revocation_and_replay_fail_closed() {
        let r = SqliteG05AuthorityRegistry::open_in_memory().unwrap();
        {
            let c = r.connection.lock().unwrap();
            c.execute(
                "INSERT INTO g05_reviewer_designations VALUES
   ('d1','t1','org1','reviewer:1','key:1','admin',1,100,300,100,NULL)",
                [],
            )
            .unwrap();
        }
        let receipt = DurableApprovalReceipt {
            approval_ref: "a1".into(),
            memory_id: "m1".into(),
            tenant_ref: "t1".into(),
            subject_ref: "org1".into(),
            content_sha256: "a".repeat(64),
            reviewer_ref: "reviewer:1".into(),
            issued_at: 120,
            expires_at: 200,
            proof_ref: "proof:valid".into(),
        };
        let a = RegistryDesignatedReviewerAuthority::new(r.clone(), G01);
        assert_eq!(a.verify_designated_reviewer(&receipt, "org1", 150), Ok(()));
        assert_eq!(
            a.verify_designated_reviewer(&receipt, "org1", 151),
            Err(G05Error::ApprovalReplay)
        );
        let mut wrong = receipt.clone();
        wrong.tenant_ref = "t2".into();
        assert_eq!(
            a.verify_designated_reviewer(&wrong, "org1", 152),
            Err(G05Error::ReviewerNotAuthorized)
        );
        let mut wrong_org = receipt.clone();
        wrong_org.approval_ref = "a-org".into();
        assert_eq!(
            a.verify_designated_reviewer(&wrong_org, "other-org", 152),
            Err(G05Error::ApprovalBindingMismatch)
        );
        let mut wrong_reviewer = receipt.clone();
        wrong_reviewer.approval_ref = "a-reviewer".into();
        wrong_reviewer.reviewer_ref = "reviewer:other".into();
        assert_eq!(
            a.verify_designated_reviewer(&wrong_reviewer, "org1", 152),
            Err(G05Error::ReviewerNotAuthorized)
        );
        let mut bad_proof = receipt.clone();
        bad_proof.approval_ref = "a-proof".into();
        bad_proof.proof_ref = "proof:forged".into();
        assert_eq!(
            a.verify_designated_reviewer(&bad_proof, "org1", 152),
            Err(G05Error::ReviewerNotAuthorized)
        );
        let mut corrected_proof = bad_proof.clone();
        corrected_proof.proof_ref = "proof:valid".into();
        assert_eq!(
            a.verify_designated_reviewer(&corrected_proof, "org1", 152),
            Ok(())
        );
        let mut overlong = receipt.clone();
        overlong.approval_ref = "a-window".into();
        overlong.expires_at = 301;
        assert_eq!(
            a.verify_designated_reviewer(&overlong, "org1", 152),
            Err(G05Error::ReviewerNotAuthorized)
        );
        {
            let c = r.connection.lock().unwrap();
            c.execute(
                "INSERT INTO g05_reviewer_designations VALUES
    ('d2','t1','org1','reviewer:1','key:2','admin',2,140,300,140,145)",
                [],
            )
            .unwrap();
        }
        let prior = DurableApprovalReceipt {
            approval_ref: "a-prior".into(),
            ..receipt.clone()
        };
        assert_eq!(
            a.verify_designated_reviewer(&prior, "org1", 150),
            Err(G05Error::ReviewerNotAuthorized)
        );
        let c = r.connection.lock().unwrap();
        c.execute(
            "UPDATE g05_reviewer_designations SET revoked_at=153 WHERE designation_ref='d1'",
            [],
        )
        .unwrap();
        drop(c);
        let next = DurableApprovalReceipt {
            approval_ref: "a2".into(),
            ..receipt
        };
        assert_eq!(
            a.verify_designated_reviewer(&next, "org1", 154),
            Err(G05Error::ReviewerNotAuthorized)
        );
    }
    #[test]
    fn trusted_governance_adapter_composes_sqlite_consent_and_reviewer_registries() {
        struct AllowG02;
        impl G02AuthorizationAuthority for AllowG02 {
            fn authorize_g05(&self, _: &AuthorizationRequest) -> Result<(), G05Error> {
                Ok(())
            }
        }
        struct Audit;
        impl crate::G11MemoryAuditAuthority for Audit {
            fn append_memory_event(&self, _: &crate::AuditEvent) -> Result<(), G05Error> {
                Ok(())
            }
        }
        let registry = SqliteG05AuthorityRegistry::open_in_memory().unwrap();
        {
            let c = registry.connection.lock().unwrap();
            c.execute("INSERT INTO g05_episodic_consents VALUES
    ('consent:one','tenant:one','subject:one','TASK_CONTINUITY','issuer','credential',100,300,NULL,1,'action:one')",[]).unwrap();
            c.execute("INSERT INTO g05_reviewer_designations VALUES
    ('designation:one','tenant:one','org:one','reviewer:1','key:1','governor:1',1,100,300,100,NULL)",[]).unwrap();
        }
        let reviewers = RegistryDesignatedReviewerAuthority::new(registry.clone(), G01);
        let adapter = crate::TrustedGovernanceAdapter::new(AllowG02, registry, reviewers, Audit);
        assert_eq!(
            crate::GovernancePort::verify_episodic_opt_in(
                &adapter,
                "consent:one",
                "tenant:one",
                "subject:one",
                Purpose::TaskContinuity,
                150
            ),
            Ok(())
        );
        let receipt = DurableApprovalReceipt {
            approval_ref: "approval:one".into(),
            memory_id: "memory:one".into(),
            tenant_ref: "tenant:one".into(),
            subject_ref: "org:one".into(),
            content_sha256: "b".repeat(64),
            reviewer_ref: "reviewer:1".into(),
            issued_at: 120,
            expires_at: 200,
            proof_ref: "proof:valid".into(),
        };
        assert_eq!(
            crate::GovernancePort::verify_durable_approval(&adapter, &receipt, 150),
            Ok(())
        );
    }
    #[test]
    fn reviewer_registry_rejects_expired_designation_and_untrusted_proof() {
        let r = SqliteG05AuthorityRegistry::open_in_memory().unwrap();
        {
            let c = r.connection.lock().unwrap();
            c.execute(
                "INSERT INTO g05_reviewer_designations VALUES
   ('d-expired','t','org','reviewer:1','key:1','admin',1,100,140,100,NULL)",
                [],
            )
            .unwrap();
        }
        let a = RegistryDesignatedReviewerAuthority::new(r, G01);
        let receipt = DurableApprovalReceipt {
            approval_ref: "a-expired".into(),
            memory_id: "m".into(),
            tenant_ref: "t".into(),
            subject_ref: "org".into(),
            content_sha256: "c".repeat(64),
            reviewer_ref: "reviewer:1".into(),
            issued_at: 110,
            expires_at: 200,
            proof_ref: "proof:valid".into(),
        };
        assert_eq!(
            a.verify_designated_reviewer(&receipt, "org", 150),
            Err(G05Error::ReviewerNotAuthorized)
        );
    }

    #[test]
    fn g11_outbox_retries_after_sink_failure_and_marks_delivery() {
        struct Fail;
        impl crate::G11MemoryAuditAuthority for Fail {
            fn append_memory_event(&self, _: &crate::AuditEvent) -> Result<(), G05Error> {
                Err(G05Error::AuditUnavailable)
            }
        }
        struct Accept;
        impl crate::G11MemoryAuditAuthority for Accept {
            fn append_memory_event(&self, e: &crate::AuditEvent) -> Result<(), G05Error> {
                assert_eq!(e.event_id, "evt1");
                assert_eq!(e.event_type, "memory.consent.granted");
                Ok(())
            }
        }
        let r = SqliteG05AuthorityRegistry::open_in_memory().unwrap();
        {
            let c = r.connection.lock().unwrap();
            c.execute(
                "INSERT INTO g05_authority_outbox
                 (event_id,event_type,aggregate_ref,tenant_ref,actor_ref,purpose,record_version,outcome,
                  correlation_ref,occurred_at,content_sha256,delivered_at)
                 VALUES('evt1','memory.consent.granted','consent:1','tenant:1','subject:1',
                  'TASK_CONTINUITY',1,'granted','trace:1',100,?1,NULL)",
                ["0".repeat(64)],
            )
            .unwrap();
        }
        assert_eq!(
            r.drain_g11_outbox(&Fail, 110, 10),
            Err(G05Error::AuditUnavailable)
        );
        assert_eq!(r.drain_g11_outbox(&Accept, 111, 10), Ok(1));
        assert_eq!(r.drain_g11_outbox(&Accept, 112, 10), Ok(0));
    }

    #[test]
    fn g05_operations_map_to_distinct_g02_capabilities() {
        assert_eq!(
            g05_capability(Operation::GrantEpisodicConsent),
            "g05.memory.consent.grant"
        );
        assert_eq!(
            g05_capability(Operation::WithdrawEpisodicConsent),
            "g05.memory.consent.withdraw"
        );
        assert_eq!(
            g05_capability(Operation::DesignateReviewer),
            "g05.memory.reviewer.designate"
        );
        assert_eq!(
            g05_capability(Operation::RevokeReviewerDesignation),
            "g05.memory.reviewer.revoke"
        );
    }
}
