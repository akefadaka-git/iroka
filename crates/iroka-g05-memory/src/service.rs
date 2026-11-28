//! Mandatory G05 protected-operation facade.
//!
//! Applications receive no repository handle and cannot invoke raw persistence
//! methods. Every read, write and consent mutation is authenticated and executed
//! inside the current G01/G02/G09 authority guard with G11 intent/outcome receipts.
use std::sync::Mutex;

use iroka_kernel::{RevocationChecker, TenantContext};

use crate::{
    AuthenticatedG05Request, AuditEvent, AuthorizationRequest, G02AuthorizationAuthority,
    G05Error, G11MemoryAuditAuthority, G05IngressService,
    MemoryMetadata, MemoryRecord, MemoryRepository, Operation, SqliteMemoryRepository,
    PostgresMemoryRepository,
    SqliteG05AuthorityRegistry, TrustedClock, G09ExecutionRevalidator,
};

/// The only application-facing entry point for protected G05 persistence and
/// consent operations. Repository adapters are deliberately held privately.
enum RepositoryBackend {
    Sqlite(SqliteMemoryRepository),
    Postgres(PostgresMemoryRepository),
}

impl MemoryRepository for RepositoryBackend {
    fn insert_with_audit(&mut self, record: MemoryRecord, event: AuditEvent) -> Result<(), G05Error> {
        match self { Self::Sqlite(r) => r.insert_with_audit(record, event), Self::Postgres(r) => r.insert_with_audit(record, event) }
    }
    fn get_metadata(&self, memory_id: &str) -> Result<Option<MemoryMetadata>, G05Error> {
        match self { Self::Sqlite(r) => r.get_metadata(memory_id), Self::Postgres(r) => r.get_metadata(memory_id) }
    }
    fn get_content(&self, memory_id: &str) -> Result<Option<MemoryRecord>, G05Error> {
        match self { Self::Sqlite(r) => r.get_content(memory_id), Self::Postgres(r) => r.get_content(memory_id) }
    }
    fn replace_with_audit(&mut self, record: MemoryRecord, expected_version: u64, event: AuditEvent) -> Result<(), G05Error> {
        match self { Self::Sqlite(r) => r.replace_with_audit(record, expected_version, event), Self::Postgres(r) => r.replace_with_audit(record, expected_version, event) }
    }
    fn finalize_pending_activation(&mut self, record: MemoryRecord, expected_version: u64, event: AuditEvent) -> Result<(), G05Error> {
        match self { Self::Sqlite(r) => r.finalize_pending_activation(record, expected_version, event), Self::Postgres(r) => r.finalize_pending_activation(record, expected_version, event) }
    }
}

pub struct G05ExecutionService<V, G, C, E, A> {
    ingress: G05IngressService<V, G, C, E>,
    repository: Mutex<RepositoryBackend>,
    g11: A,
    consent_registry: SqliteG05AuthorityRegistry,
}

impl<V, G, C, E, A> G05ExecutionService<V, G, C, E, A>
where
    V: RevocationChecker,
    G: G02AuthorizationAuthority,
    C: TrustedClock,
    E: G09ExecutionRevalidator,
    A: G11MemoryAuditAuthority,
{
    /// Construct the service over the SQLite repository adapter.
    pub fn new_sqlite(
        ingress: G05IngressService<V, G, C, E>,
        repository: SqliteMemoryRepository,
        g11: A,
        consent_registry: SqliteG05AuthorityRegistry,
    ) -> Self {
        Self::new(ingress, RepositoryBackend::Sqlite(repository), g11, consent_registry)
    }

    /// Construct the service over the shared PostgreSQL repository adapter.
    pub fn new_postgres(
        ingress: G05IngressService<V, G, C, E>,
        repository: PostgresMemoryRepository,
        g11: A,
        consent_registry: SqliteG05AuthorityRegistry,
    ) -> Self {
        Self::new(ingress, RepositoryBackend::Postgres(repository), g11, consent_registry)
    }

    fn new(
        ingress: G05IngressService<V, G, C, E>,
        repository: RepositoryBackend,
        g11: A,
        consent_registry: SqliteG05AuthorityRegistry,
    ) -> Self {
        Self {
            ingress,
            repository: Mutex::new(repository),
            g11,
            consent_registry,
        }
    }

    /// Persist a new record. The request and audit event must bind every
    /// security-relevant field to the supplied record before repository access.
    pub fn insert_record(
        &self,
        compact_credential: &str,
        tenant: &TenantContext,
        request: AuthorizationRequest,
        record: MemoryRecord,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        validate_record_binding(&request, &record)?;
        if record.candidate.actor_ref != request.principal_ref {
            return Err(G05Error::AuthorizationDenied);
        }
        let expected_operation = match record.candidate.memory_class {
            crate::MemoryClass::Working => Operation::CreateWorking,
            crate::MemoryClass::Episodic => Operation::CreateEpisodic,
            crate::MemoryClass::Durable => Operation::Propose,
        };
        if request.operation != expected_operation {
            return Err(G05Error::AuthorizationDenied);
        }
        validate_event_binding(&request, &record, &event)?;
        self.execute(compact_credential, tenant, request.clone(), || {
            if record.candidate.memory_class == crate::MemoryClass::Episodic {
                let consent_ref = record.candidate.episodic_opt_in_ref.as_deref()
                    .ok_or(G05Error::EpisodicOptInRequired)?;
                let record_to_write = record.clone();
                let event_to_write = event.clone();
                self.consent_registry.with_active_opt_in(
                    consent_ref,
                    &record.candidate.tenant_ref,
                    &record.candidate.subject_ref,
                    record.candidate.purpose,
                    self.ingress.current_time()?,
                    move || self.repository
                        .lock()
                        .map_err(|_| G05Error::RepositoryUnavailable)?
                        .insert_with_audit(record_to_write, event_to_write),
                )
            } else {
                self.repository
                    .lock()
                    .map_err(|_| G05Error::RepositoryUnavailable)?
                    .insert_with_audit(record, event)
            }
        })
    }

    /// Return metadata only. Content is never deserialized by this method.
    pub fn read_metadata(
        &self,
        compact_credential: &str,
        tenant: &TenantContext,
        request: AuthorizationRequest,
    ) -> Result<Option<MemoryMetadata>, G05Error> {
        if request.operation != Operation::InspectMetadata {
            return Err(G05Error::AuthorizationDenied);
        }
        let memory_id = required_memory_id(&request)?;
        self.execute(compact_credential, tenant, request.clone(), || {
            let repository = self.repository
                .lock()
                .map_err(|_| G05Error::RepositoryUnavailable)?;
            let metadata = repository.get_metadata(&memory_id)?;
            metadata.map(|m| validate_metadata_binding(&request, &m)).transpose()?;
            Ok(metadata)
        })
    }

    /// Return content only after a metadata-first scope, classification,
    /// lifecycle and version check under the same G09 authority transaction.
    pub fn read_content(
        &self,
        compact_credential: &str,
        tenant: &TenantContext,
        request: AuthorizationRequest,
    ) -> Result<Option<MemoryRecord>, G05Error> {
        if request.operation != Operation::Retrieve {
            return Err(G05Error::AuthorizationDenied);
        }
        let memory_id = required_memory_id(&request)?;
        self.execute(compact_credential, tenant, request.clone(), || {
            let repository = self.repository
                .lock()
                .map_err(|_| G05Error::RepositoryUnavailable)?;
            let Some(metadata) = repository.get_metadata(&memory_id)? else {
                return Ok(None);
            };
            validate_metadata_binding(&request, &metadata)?;
            if matches!(
                metadata.lifecycle_state,
                crate::LifecycleState::Deleted
                    | crate::LifecycleState::DeletionPending
                    | crate::LifecycleState::Restricted
                    | crate::LifecycleState::Expired
            ) {
                return Err(G05Error::RecordNotActive);
            }
            let record = repository
                .get_content(&memory_id)?
                .ok_or(G05Error::RecordNotFound)?;
            validate_record_metadata_pair(&request, &metadata, &record)?;
            Ok(Some(record))
        })
    }

    /// Compare-and-swap an existing record. Only correction and restriction
    /// are exposed here; activation/deletion/sharing have dedicated workflows.
    pub fn replace_record(
        &self,
        compact_credential: &str,
        tenant: &TenantContext,
        request: AuthorizationRequest,
        record: MemoryRecord,
        expected_version: u64,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        if !matches!(request.operation, Operation::Correct | Operation::Restrict)
            || expected_version == 0
            || record.candidate.record_version != expected_version.saturating_add(1)
        {
            return Err(G05Error::AuthorizationDenied);
        }
        validate_record_binding(&request, &record)?;
        validate_event_binding(&request, &record, &event)?;
        let memory_id = required_memory_id(&request)?;
        self.execute(compact_credential, tenant, request.clone(), || {
            let mut repository = self.repository
                .lock()
                .map_err(|_| G05Error::RepositoryUnavailable)?;
            let current = repository
                .get_metadata(&memory_id)?
                .ok_or(G05Error::RecordNotFound)?;
            validate_metadata_binding(&request, &current)?;
            if current.record_version != expected_version {
                return Err(G05Error::VersionConflict);
            }
            repository.replace_with_audit(record, expected_version, event)
        })
    }

    /// Finalize an already approved durable record after G11 accepts the
    /// matching activation receipt. The record is re-read under the authority
    /// guard and activated with an atomic repository version compare-and-swap.
    pub fn activate_durable(
        &self,
        compact_credential: &str,
        tenant: &TenantContext,
        request: AuthorizationRequest,
        pending: MemoryRecord,
        expected_version: u64,
    ) -> Result<(), G05Error> {
        if request.operation != Operation::ActivateDurable
            || pending.candidate.memory_class != crate::MemoryClass::Durable
            || pending.lifecycle_state != crate::LifecycleState::PendingAudit
            || pending.candidate.record_version != expected_version
            || pending.approval_ref.as_deref().map_or(true, str::is_empty)
            || pending.approved_by_ref.as_deref().map_or(true, str::is_empty)
            || pending.approved_at.is_none()
        {
            return Err(G05Error::ApprovalBindingMismatch);
        }
        validate_record_binding(&request, &pending)?;
        if pending.approved_by_ref.as_deref() != Some(request.principal_ref.as_str()) {
            return Err(G05Error::ReviewerNotAuthorized);
        }
        let memory_id = required_memory_id(&request)?;
        self.execute(compact_credential, tenant, request.clone(), || {
            let mut repository = self.repository
                .lock()
                .map_err(|_| G05Error::RepositoryUnavailable)?;
            let stored = repository.get_content(&memory_id)?
                .ok_or(G05Error::RecordNotFound)?;
            if stored != pending {
                return Err(G05Error::VersionConflict);
            }
            let activation_event = crate::durable_activation_audit_event(&pending)?;
            let acknowledgment = self.g11.append_memory_event(&activation_event)?;
            let now = self.ingress.current_time()?;
            crate::commit_durable_activation(
                &mut *repository,
                &pending,
                &acknowledgment,
                expected_version,
                now,
            )
        })
    }

    /// Grant episodic opt-in only through the G09/G11 guarded execution path.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_episodic_consent(
        &self,
        compact_credential: &str,
        tenant: &TenantContext,
        request: AuthorizationRequest,
        consent_ref: &str,
        expires_at: u64,
    ) -> Result<(), G05Error> {
        if request.operation != Operation::GrantEpisodicConsent || request.memory_id.is_some() {
            return Err(G05Error::AuthorizationDenied);
        }
        let context = self.authorize(compact_credential, request.clone())?;
        let now = self.ingress.current_time()?;
        let issuer = context.principal().subject().to_owned();
        let credential_id = context.principal().credential_id().to_owned();
        self.ingress.execute_external_with_context(
            &context,
            tenant,
            compact_credential,
            &self.g11,
            || {
                self.consent_registry.grant_episodic_consent(
                    consent_ref,
                    &request.tenant_ref,
                    &request.subject_ref,
                    request.purpose,
                    &issuer,
                    &credential_id,
                    now,
                    expires_at,
                    &request.correlation_ref,
                )
            },
        )
    }

    /// Withdraw episodic opt-in only through the G09/G11 guarded execution path.
    pub fn revoke_episodic_consent(
        &self,
        compact_credential: &str,
        tenant: &TenantContext,
        request: AuthorizationRequest,
        consent_ref: &str,
    ) -> Result<(), G05Error> {
        if request.operation != Operation::WithdrawEpisodicConsent || request.memory_id.is_some() {
            return Err(G05Error::AuthorizationDenied);
        }
        let context = self.authorize(compact_credential, request.clone())?;
        let now = self.ingress.current_time()?;
        self.ingress.execute_external_with_context(
            &context,
            tenant,
            compact_credential,
            &self.g11,
            || {
                self.consent_registry.revoke_episodic_consent(
                    consent_ref,
                    &request.tenant_ref,
                    &request.subject_ref,
                    now,
                )
            },
        )
    }

    fn authorize(
        &self,
        compact_credential: &str,
        request: AuthorizationRequest,
    ) -> Result<AuthenticatedG05Request, G05Error> {
        self.ingress.authorize(compact_credential, request)
    }

    fn execute<T>(
        &self,
        compact_credential: &str,
        tenant: &TenantContext,
        request: AuthorizationRequest,
        effect: impl FnOnce() -> Result<T, G05Error>,
    ) -> Result<T, G05Error> {
        let context = self.authorize(compact_credential, request)?;
        self.ingress.execute_external_with_context(
            &context,
            tenant,
            compact_credential,
            &self.g11,
            effect,
        )
    }
}

fn required_memory_id(request: &AuthorizationRequest) -> Result<String, G05Error> {
    request
        .memory_id
        .as_ref()
        .filter(|id| !id.trim().is_empty())
        .cloned()
        .ok_or(G05Error::MalformedRecord)
}

fn validate_record_binding(
    request: &AuthorizationRequest,
    record: &MemoryRecord,
) -> Result<(), G05Error> {
    let candidate = &record.candidate;
    if request.memory_id.as_deref() != Some(candidate.memory_id.as_str())
        || request.tenant_ref != candidate.tenant_ref
        || request.subject_ref != candidate.subject_ref
        || request.purpose != candidate.purpose
        || request.classification != candidate.classification
        || candidate.record_version == 0
    {
        return Err(G05Error::ApprovalBindingMismatch);
    }
    Ok(())
}

fn validate_metadata_binding(
    request: &AuthorizationRequest,
    metadata: &MemoryMetadata,
) -> Result<(), G05Error> {
    if request.memory_id.as_deref() != Some(metadata.memory_id.as_str())
        || request.tenant_ref != metadata.tenant_ref
        || request.subject_ref != metadata.subject_ref
        || request.purpose != metadata.purpose
        || request.classification != metadata.classification
        || metadata.record_version == 0
    {
        return Err(G05Error::AuthorizationDenied);
    }
    Ok(())
}

fn validate_record_metadata_pair(
    request: &AuthorizationRequest,
    metadata: &MemoryMetadata,
    record: &MemoryRecord,
) -> Result<(), G05Error> {
    validate_metadata_binding(request, metadata)?;
    let candidate = &record.candidate;
    if candidate.memory_id != metadata.memory_id
        || candidate.tenant_ref != metadata.tenant_ref
        || candidate.subject_ref != metadata.subject_ref
        || candidate.purpose != metadata.purpose
        || candidate.classification != metadata.classification
        || candidate.record_version != metadata.record_version
        || record.candidate.content_sha256 != metadata.content_sha256
        || record.lifecycle_state != metadata.lifecycle_state
        || record.candidate.memory_class != metadata.memory_class
    {
        return Err(G05Error::VersionConflict);
    }
    Ok(())
}

fn validate_event_binding(
    request: &AuthorizationRequest,
    record: &MemoryRecord,
    event: &AuditEvent,
) -> Result<(), G05Error> {
    if event.memory_id != record.candidate.memory_id
        || event.tenant_ref != record.candidate.tenant_ref
        || event.actor_ref != request.principal_ref
        || event.purpose != record.candidate.purpose
        || event.record_version != record.candidate.record_version
        || event.correlation_ref != request.correlation_ref
        || event.content_sha256 != record.candidate.content_sha256
    {
        return Err(G05Error::ApprovalBindingMismatch);
    }
    Ok(())
}

