//! IROKA CIW conversation-domain foundation.
//!
//! This crate deliberately owns conversation data only. Identity, tenant
//! membership, session validity, policy and authorization are supplied by
//! trusted adapters. No handler or model can manufacture those authorities.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

use iroka_kernel::VerifiedPrincipal;
use rusqlite::{params, Connection, OptionalExtension};

mod budget;
mod kernel_adapter;
mod policy;
mod tenant_session;
pub use budget::BudgetGuard;
pub use kernel_adapter::KernelConversationAuthorizer;
pub use policy::{
    BudgetLimits, PolicyError, PolicyPayload, PolicyTrustRoot, PolicyVersionStore,
    SignedPolicyBundle, VerifiedPolicy,
};
pub use tenant_session::{
    CredentialStatus, KernelCredentialStatus, SqliteSessionRegistry, SqliteTenantDirectory,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationError {
    StorageUnavailable,
    InvalidInput,
    TenantUnavailable,
    MembershipDenied,
    SessionInvalid,
    AuthorizationDenied,
    NotFound,
    Conflict,
    GenerationFailed,
    BudgetExceeded,
    Cancelled,
}

pub trait TenantMembership: Send + Sync {
    /// Resolve current membership from an authoritative server-side source.
    /// The implementation must fail closed for stale, ambiguous or unavailable state.
    fn resolve_active_tenant(
        &self,
        verified_subject: &str,
        now: u64,
    ) -> Result<String, ConversationError>;
}

pub trait SessionGuard: Send + Sync {
    /// Validate the bounded application session bound to the verified subject
    /// and resolved tenant. This is not an identity verifier.
    fn validate(
        &self,
        verified_subject: &str,
        issuer: &str,
        credential_id: &str,
        tenant_id: &str,
        session_id: &str,
        now: u64,
    ) -> Result<(), ConversationError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Create,
    List,
    Read,
    SubmitTurn,
    CancelTurn,
    Delete,
}

/// Adapter must construct the Kernel AuthorizationRequest itself using the
/// verified subject, constant capability, canonical resource and trusted policy.
/// Only a positive, audited Kernel decision may return Ok.
pub trait KernelAuthorization {
    fn authorize(
        &self,
        principal: &VerifiedPrincipal,
        operation: Operation,
        canonical_resource: &str,
        correlation_id: &str,
        now: u64,
    ) -> Result<(), ConversationError>;
}

pub trait AnswerGenerator: Send + Sync {
    /// Generate an answer from synthetic/non-production input only in A3.
    fn answer(
        &self,
        prompt: &str,
        locale: Locale,
        cancel: &Cancellation,
    ) -> Result<String, ConversationError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    Amharic,
    English,
}

impl Locale {
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("en") | Some("en-us") | Some("english") => Self::English,
            _ => Self::Amharic,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Amharic => "am",
            Self::English => "en",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub id: String,
    pub tenant_id: String,
    pub owner_subject: String,
    pub locale: Locale,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    pub id: String,
    pub conversation_id: String,
    pub sequence: u64,
    pub role: String,
    pub content: String,
    pub state: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Accepted {
        turn_id: String,
        sequence: u64,
    },
    Delta {
        turn_id: String,
        sequence: u64,
        text: String,
    },
    Completed {
        turn_id: String,
        sequence: u64,
    },
    Cancelled {
        turn_id: String,
        sequence: u64,
    },
    Failed {
        turn_id: String,
        sequence: u64,
    },
}

pub struct Cancellation(AtomicBool);
impl Cancellation {
    pub fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ConversationStore {
    db: Mutex<Connection>,
}

impl ConversationStore {
    pub fn open(path: &str) -> Result<Self, ConversationError> {
        let db = Connection::open(path).map_err(|_| ConversationError::StorageUnavailable)?;
        Self::from_connection(db)
    }

    pub fn open_in_memory() -> Result<Self, ConversationError> {
        let db = Connection::open_in_memory().map_err(|_| ConversationError::StorageUnavailable)?;
        Self::from_connection(db)
    }

    fn from_connection(db: Connection) -> Result<Self, ConversationError> {
        db.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS conversations (
               id TEXT PRIMARY KEY NOT NULL,
               tenant_id TEXT NOT NULL,
               owner_subject TEXT NOT NULL,
               locale TEXT NOT NULL CHECK(locale IN ('am','en')),
               created_at INTEGER NOT NULL,
               deleted_at INTEGER,
               purge_after INTEGER,
               UNIQUE(tenant_id,id)
             );
             CREATE INDEX IF NOT EXISTS idx_conversations_owner
               ON conversations(tenant_id,owner_subject,created_at DESC);
             CREATE TABLE IF NOT EXISTS turns (
               id TEXT PRIMARY KEY NOT NULL,
               conversation_id TEXT NOT NULL REFERENCES conversations(id),
               sequence INTEGER NOT NULL,
               role TEXT NOT NULL CHECK(role IN ('user','assistant')),
               content TEXT NOT NULL,
               state TEXT NOT NULL CHECK(state IN ('accepted','generating','completed','cancelled','failed')),
               idempotency_key TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               UNIQUE(conversation_id,sequence),
               UNIQUE(conversation_id,idempotency_key)
             );
             CREATE INDEX IF NOT EXISTS idx_turns_conversation
               ON turns(conversation_id,sequence);
             CREATE TABLE IF NOT EXISTS conversation_events (
               event_id TEXT PRIMARY KEY NOT NULL,
               tenant_id TEXT NOT NULL,
               conversation_id TEXT NOT NULL,
               turn_id TEXT,
               event_type TEXT NOT NULL,
               correlation_id TEXT NOT NULL,
               occurred_at INTEGER NOT NULL
             );"
        ).map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(Self { db: Mutex::new(db) })
    }

    fn insert_conversation(&self, c: &Conversation) -> Result<(), ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute(
            "INSERT INTO conversations(id,tenant_id,owner_subject,locale,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![c.id,c.tenant_id,c.owner_subject,c.locale.as_str(),c.created_at as i64],
        ).map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(())
    }

    fn owned_conversation(
        &self,
        id: &str,
        tenant: &str,
        owner: &str,
    ) -> Result<Conversation, ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        db.query_row(
            "SELECT id,tenant_id,owner_subject,locale,created_at FROM conversations
             WHERE id=?1 AND tenant_id=?2 AND owner_subject=?3 AND deleted_at IS NULL",
            params![id, tenant, owner],
            |r| {
                Ok(Conversation {
                    id: r.get(0)?,
                    tenant_id: r.get(1)?,
                    owner_subject: r.get(2)?,
                    locale: if r.get::<_, String>(3)? == "en" {
                        Locale::English
                    } else {
                        Locale::Amharic
                    },
                    created_at: r.get::<_, i64>(4)? as u64,
                })
            },
        )
        .optional()
        .map_err(|_| ConversationError::StorageUnavailable)?
        .ok_or(ConversationError::NotFound)
    }

    fn list_owned(
        &self,
        tenant: &str,
        owner: &str,
    ) -> Result<Vec<Conversation>, ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let mut stmt = db
            .prepare(
                "SELECT id,tenant_id,owner_subject,locale,created_at FROM conversations
             WHERE tenant_id=?1 AND owner_subject=?2 AND deleted_at IS NULL
             ORDER BY created_at DESC LIMIT 50",
            )
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let rows = stmt
            .query_map(params![tenant, owner], |r| {
                Ok(Conversation {
                    id: r.get(0)?,
                    tenant_id: r.get(1)?,
                    owner_subject: r.get(2)?,
                    locale: if r.get::<_, String>(3)? == "en" {
                        Locale::English
                    } else {
                        Locale::Amharic
                    },
                    created_at: r.get::<_, i64>(4)? as u64,
                })
            })
            .map_err(|_| ConversationError::StorageUnavailable)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConversationError::StorageUnavailable)
    }

    #[allow(clippy::too_many_arguments)] // Lifecycle audit fields are explicit at the persistence boundary.
    fn record_event(
        &self,
        event_id: &str,
        tenant: &str,
        conversation: &str,
        turn: Option<&str>,
        event_type: &str,
        correlation: &str,
        now: u64,
    ) -> Result<(), ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute(
            "INSERT OR IGNORE INTO conversation_events
          (event_id,tenant_id,conversation_id,turn_id,event_type,correlation_id,occurred_at)
          VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                event_id,
                tenant,
                conversation,
                turn,
                event_type,
                correlation,
                now as i64
            ],
        )
        .map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // Turn identity, content, idempotency and timestamp are explicit.
    fn append_turn(
        &self,
        conversation_id: &str,
        id: &str,
        role: &str,
        content: &str,
        state: &str,
        idempotency: &str,
        now: u64,
    ) -> Result<u64, ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let tx = db
            .unchecked_transaction()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let existing: Option<(String, u64)> = tx
            .query_row(
                "SELECT id,sequence FROM turns WHERE conversation_id=?1 AND idempotency_key=?2",
                params![conversation_id, idempotency],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
            )
            .optional()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        if let Some((existing_id, seq)) = existing {
            if existing_id == id {
                tx.commit()
                    .map_err(|_| ConversationError::StorageUnavailable)?;
                return Ok(seq);
            }
            return Err(ConversationError::Conflict);
        }
        let next: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM turns WHERE conversation_id=?1",
                params![conversation_id],
                |r| r.get(0),
            )
            .map_err(|_| ConversationError::StorageUnavailable)?;
        tx.execute(
            "INSERT INTO turns(id,conversation_id,sequence,role,content,state,idempotency_key,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id,conversation_id,next,role,content,state,idempotency,now as i64]
        ).map_err(|_| ConversationError::StorageUnavailable)?;
        tx.commit()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(next as u64)
    }

    fn mark_deleted(
        &self,
        id: &str,
        tenant: &str,
        owner: &str,
        now: u64,
        purge_after: u64,
    ) -> Result<(), ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let changed = db
            .execute(
                "UPDATE conversations SET deleted_at=?4,purge_after=?5
             WHERE id=?1 AND tenant_id=?2 AND owner_subject=?3 AND deleted_at IS NULL",
                params![id, tenant, owner, now as i64, purge_after as i64],
            )
            .map_err(|_| ConversationError::StorageUnavailable)?;
        if changed == 0 {
            return Err(ConversationError::NotFound);
        }
        Ok(())
    }

    /// Mark content whose configured retention period elapsed as inaccessible.
    pub fn expire_old(
        &self,
        now: u64,
        content_retention_seconds: u64,
        deletion_grace_seconds: u64,
    ) -> Result<usize, ConversationError> {
        if content_retention_seconds == 0 || deletion_grace_seconds == 0 {
            return Err(ConversationError::InvalidInput);
        }
        let cutoff = now.saturating_sub(content_retention_seconds);
        let purge_after = now.saturating_add(deletion_grace_seconds);
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute(
            "UPDATE conversations SET deleted_at=?1,purge_after=?2
             WHERE deleted_at IS NULL AND created_at<=?3",
            params![now as i64, purge_after as i64, cutoff as i64],
        )
        .map_err(|_| ConversationError::StorageUnavailable)
    }

    /// Apply the configured age threshold and purge content whose grace period elapsed.
    /// This is a trusted maintenance operation, not an HTTP/API handler.
    pub fn maintain_retention(
        &self,
        now: u64,
        policy: RetentionPolicy,
    ) -> Result<usize, ConversationError> {
        let expired = self.expire_old(
            now,
            policy.content_retention_seconds,
            policy.deletion_grace_seconds,
        )?;
        let purged = self.purge_due(now)?;
        Ok(expired + purged)
    }

    /// Purge due conversation content. Lifecycle events remain for audit review.
    pub fn purge_due(&self, now: u64) -> Result<usize, ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let tx = db
            .unchecked_transaction()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let due = {
            let mut stmt = tx.prepare(
                "SELECT id,tenant_id FROM conversations WHERE deleted_at IS NOT NULL AND purge_after<=?1"
            ).map_err(|_| ConversationError::StorageUnavailable)?;
            let rows = stmt
                .query_map(params![now as i64], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(|_| ConversationError::StorageUnavailable)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| ConversationError::StorageUnavailable)?
        };
        for (id, tenant) in &due {
            tx.execute(
                "INSERT OR IGNORE INTO conversation_events
                 (event_id,tenant_id,conversation_id,turn_id,event_type,correlation_id,occurred_at)
                 VALUES(?1,?2,?3,NULL,'conversation.content_purged','retention-job',?4)",
                params![
                    format!("retention:purge:{id}:{now}"),
                    tenant,
                    id,
                    now as i64
                ],
            )
            .map_err(|_| ConversationError::StorageUnavailable)?;
            tx.execute("DELETE FROM turns WHERE conversation_id=?1", params![id])
                .map_err(|_| ConversationError::StorageUnavailable)?;
            tx.execute("DELETE FROM conversations WHERE id=?1", params![id])
                .map_err(|_| ConversationError::StorageUnavailable)?;
        }
        tx.commit()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(due.len())
    }

    fn finish_turn(
        &self,
        id: &str,
        state: &str,
        content: Option<&str>,
    ) -> Result<(), ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let changed = db.execute(
            "UPDATE turns SET state=?2,content=COALESCE(?3,content) WHERE id=?1 AND state IN ('accepted','generating')",
            params![id,state,content]
        ).map_err(|_| ConversationError::StorageUnavailable)?;
        if changed == 0 {
            return Err(ConversationError::Conflict);
        }
        Ok(())
    }

    pub fn turns(&self, conversation_id: &str) -> Result<Vec<Turn>, ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let mut stmt = db
            .prepare(
                "SELECT id,conversation_id,sequence,role,content,state,created_at FROM turns
             WHERE conversation_id=?1 ORDER BY sequence",
            )
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let rows = stmt
            .query_map(params![conversation_id], |r| {
                Ok(Turn {
                    id: r.get(0)?,
                    conversation_id: r.get(1)?,
                    sequence: r.get::<_, i64>(2)? as u64,
                    role: r.get(3)?,
                    content: r.get(4)?,
                    state: r.get(5)?,
                    created_at: r.get::<_, i64>(6)? as u64,
                })
            })
            .map_err(|_| ConversationError::StorageUnavailable)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConversationError::StorageUnavailable)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    pub content_retention_seconds: u64,
    pub deletion_grace_seconds: u64,
}
impl RetentionPolicy {
    pub fn new(
        content_retention_seconds: u64,
        deletion_grace_seconds: u64,
    ) -> Result<Self, ConversationError> {
        if content_retention_seconds == 0 || deletion_grace_seconds == 0 {
            return Err(ConversationError::InvalidInput);
        }
        Ok(Self {
            content_retention_seconds,
            deletion_grace_seconds,
        })
    }
}

pub struct ConversationService<T, S, A, G> {
    store: ConversationStore,
    tenants: T,
    sessions: S,
    authorization: A,
    generator: G,
    budget: BudgetGuard,
    retention: RetentionPolicy,
}

impl<T: TenantMembership, S: SessionGuard, A: KernelAuthorization, G: AnswerGenerator>
    ConversationService<T, S, A, G>
{
    pub fn new(
        store: ConversationStore,
        tenants: T,
        sessions: S,
        authorization: A,
        generator: G,
        budget: BudgetGuard,
        retention: RetentionPolicy,
    ) -> Self {
        Self {
            store,
            tenants,
            sessions,
            authorization,
            generator,
            budget,
            retention,
        }
    }

    fn context(
        &self,
        principal: &VerifiedPrincipal,
        session: &str,
        now: u64,
    ) -> Result<String, ConversationError> {
        let subject = principal.subject();
        let tenant = self.tenants.resolve_active_tenant(subject, now)?;
        self.sessions.validate(
            subject,
            principal.issuer(),
            principal.credential_id(),
            &tenant,
            session,
            now,
        )?;
        Ok(tenant)
    }

    pub fn create(
        &self,
        principal: &VerifiedPrincipal,
        session: &str,
        id: &str,
        locale: Option<&str>,
        correlation: &str,
        now: u64,
    ) -> Result<Conversation, ConversationError> {
        if id.trim().is_empty() || correlation.trim().is_empty() {
            return Err(ConversationError::InvalidInput);
        }
        let tenant = self.context(principal, session, now)?;
        let resource = format!(
            "tenant/{tenant}/subject/{}/conversation/new",
            principal.subject()
        );
        self.authorization
            .authorize(principal, Operation::Create, &resource, correlation, now)?;
        let c = Conversation {
            id: id.into(),
            tenant_id: tenant,
            owner_subject: principal.subject().into(),
            locale: Locale::parse(locale),
            created_at: now,
        };
        self.store.insert_conversation(&c)?;
        self.store.record_event(
            &format!("ciw:{correlation}:created"),
            &c.tenant_id,
            id,
            None,
            "conversation.created",
            correlation,
            now,
        )?;
        Ok(c)
    }

    pub fn list(
        &self,
        principal: &VerifiedPrincipal,
        session: &str,
        correlation: &str,
        now: u64,
    ) -> Result<Vec<Conversation>, ConversationError> {
        let tenant = self.context(principal, session, now)?;
        self.authorization.authorize(
            principal,
            Operation::List,
            &format!("tenant/{tenant}/conversations"),
            correlation,
            now,
        )?;
        self.store.list_owned(&tenant, principal.subject())
    }

    pub fn read(
        &self,
        principal: &VerifiedPrincipal,
        session: &str,
        id: &str,
        correlation: &str,
        now: u64,
    ) -> Result<Vec<Turn>, ConversationError> {
        let tenant = self.context(principal, session, now)?;
        let c = self
            .store
            .owned_conversation(id, &tenant, principal.subject())?;
        let resource = format!("tenant/{tenant}/conversation/{}", c.id);
        self.authorization
            .authorize(principal, Operation::Read, &resource, correlation, now)?;
        self.store.turns(id)
    }

    #[allow(clippy::too_many_arguments)] // Request, session, idempotency, correlation and cancellation are explicit.
    pub fn submit(
        &self,
        principal: &VerifiedPrincipal,
        session: &str,
        conversation_id: &str,
        turn_id: &str,
        idempotency: &str,
        prompt: &str,
        locale: Option<&str>,
        correlation: &str,
        now: u64,
        cancel: &Cancellation,
    ) -> Result<Vec<StreamEvent>, ConversationError> {
        if prompt.trim().is_empty()
            || turn_id.trim().is_empty()
            || idempotency.trim().is_empty()
            || correlation.trim().is_empty()
        {
            return Err(ConversationError::InvalidInput);
        }
        let tenant = self.context(principal, session, now)?;
        let c = self
            .store
            .owned_conversation(conversation_id, &tenant, principal.subject())?;
        let turn_resource = format!("tenant/{tenant}/conversation/{}/turn/new", c.id);
        self.authorization.authorize(
            principal,
            Operation::SubmitTurn,
            &turn_resource,
            correlation,
            now,
        )?;
        let budget = self
            .budget
            .reserve(principal.subject(), &tenant, prompt.len() as u64, now)?;
        let user_seq = self.store.append_turn(
            conversation_id,
            turn_id,
            "user",
            prompt,
            "completed",
            idempotency,
            now,
        )?;
        self.store.record_event(
            &format!("ciw:{correlation}:user-turn"),
            &tenant,
            conversation_id,
            Some(turn_id),
            "turn.user.accepted",
            correlation,
            now,
        )?;
        if cancel.is_cancelled() {
            return Err(ConversationError::Cancelled);
        }
        let assistant_id = format!("{turn_id}:assistant");
        let assistant_seq = self.store.append_turn(
            conversation_id,
            &assistant_id,
            "assistant",
            "",
            "generating",
            &format!("{idempotency}:assistant"),
            now,
        )?;
        let mut events = vec![StreamEvent::Accepted {
            turn_id: turn_id.into(),
            sequence: user_seq,
        }];
        let answer = match self.generator.answer(
            prompt,
            Locale::parse(locale.or(Some(c.locale.as_str()))),
            cancel,
        ) {
            Ok(answer) if !cancel.is_cancelled() => answer,
            Ok(_) | Err(ConversationError::Cancelled) => {
                self.store.finish_turn(&assistant_id, "cancelled", None)?;
                self.store.record_event(
                    &format!("ciw:{correlation}:cancelled"),
                    &tenant,
                    conversation_id,
                    Some(&assistant_id),
                    "turn.cancelled",
                    correlation,
                    now,
                )?;
                events.push(StreamEvent::Cancelled {
                    turn_id: assistant_id,
                    sequence: assistant_seq,
                });
                return Ok(events);
            }
            Err(_) => {
                self.store.finish_turn(&assistant_id, "failed", None)?;
                self.store.record_event(
                    &format!("ciw:{correlation}:failed"),
                    &tenant,
                    conversation_id,
                    Some(&assistant_id),
                    "turn.failed",
                    correlation,
                    now,
                )?;
                events.push(StreamEvent::Failed {
                    turn_id: assistant_id,
                    sequence: assistant_seq,
                });
                return Ok(events);
            }
        };
        // Revalidate all mutable authorization context immediately before commit.
        let tenant_again = self.context(principal, session, now)?;
        if tenant_again != tenant || cancel.is_cancelled() {
            self.store.finish_turn(&assistant_id, "cancelled", None)?;
            events.push(StreamEvent::Cancelled {
                turn_id: assistant_id,
                sequence: assistant_seq,
            });
            return Ok(events);
        }
        self.authorization.authorize(
            principal,
            Operation::SubmitTurn,
            &turn_resource,
            correlation,
            now,
        )?;
        let output_tokens = answer.chars().count().div_ceil(4) as u32;
        if budget.finish(output_tokens, 0).is_err() {
            self.store.finish_turn(&assistant_id, "failed", None)?;
            self.store.record_event(
                &format!("ciw:{correlation}:budget-failed"),
                &tenant,
                conversation_id,
                Some(&assistant_id),
                "turn.failed",
                correlation,
                now,
            )?;
            events.push(StreamEvent::Failed {
                turn_id: assistant_id,
                sequence: assistant_seq,
            });
            return Ok(events);
        }
        self.store
            .finish_turn(&assistant_id, "completed", Some(&answer))?;
        self.store.record_event(
            &format!("ciw:{correlation}:completed"),
            &tenant,
            conversation_id,
            Some(&assistant_id),
            "turn.completed",
            correlation,
            now,
        )?;
        events.push(StreamEvent::Delta {
            turn_id: assistant_id.clone(),
            sequence: assistant_seq,
            text: answer,
        });
        events.push(StreamEvent::Completed {
            turn_id: assistant_id,
            sequence: assistant_seq,
        });
        Ok(events)
    }
    pub fn delete_conversation(
        &self,
        principal: &VerifiedPrincipal,
        session: &str,
        conversation_id: &str,
        correlation: &str,
        now: u64,
    ) -> Result<(), ConversationError> {
        let tenant = self.context(principal, session, now)?;
        let conversation =
            self.store
                .owned_conversation(conversation_id, &tenant, principal.subject())?;
        let resource = format!("tenant/{tenant}/conversation/{}", conversation.id);
        self.authorization
            .authorize(principal, Operation::Delete, &resource, correlation, now)?;
        let purge_after = now.saturating_add(self.retention.deletion_grace_seconds);
        self.store.mark_deleted(
            conversation_id,
            &tenant,
            principal.subject(),
            now,
            purge_after,
        )?;
        self.store.record_event(
            &format!("ciw:{correlation}:deleted"),
            &tenant,
            conversation_id,
            None,
            "conversation.access_revoked",
            correlation,
            now,
        )
    }

    pub fn cancel_turn(
        &self,
        principal: &VerifiedPrincipal,
        session: &str,
        conversation_id: &str,
        assistant_turn_id: &str,
        correlation: &str,
        now: u64,
    ) -> Result<(), ConversationError> {
        let tenant = self.context(principal, session, now)?;
        self.store
            .owned_conversation(conversation_id, &tenant, principal.subject())?;
        let resource = format!("tenant/{tenant}/generation/{assistant_turn_id}");
        self.authorization.authorize(
            principal,
            Operation::CancelTurn,
            &resource,
            correlation,
            now,
        )?;
        self.store
            .finish_turn(assistant_turn_id, "cancelled", None)?;
        self.store.record_event(
            &format!("ciw:{correlation}:cancelled"),
            &tenant,
            conversation_id,
            Some(assistant_turn_id),
            "turn.cancelled",
            correlation,
            now,
        )
    }
}

/// Deterministic test/development adapter. It never calls an external model.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyntheticAnswerGenerator;
impl AnswerGenerator for SyntheticAnswerGenerator {
    fn answer(
        &self,
        prompt: &str,
        locale: Locale,
        cancel: &Cancellation,
    ) -> Result<String, ConversationError> {
        if cancel.is_cancelled() {
            return Err(ConversationError::Cancelled);
        }
        let normalized = prompt.trim();
        Ok(match locale {
            Locale::Amharic => format!("ይህ የሙከራ መልስ ነው። የተቀበልኩት ጽሑፍ፦ {normalized}"),
            Locale::English => {
                format!("This is a synthetic test response. Received text: {normalized}")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_schema_is_created_and_turns_are_ordered() {
        let store = ConversationStore::open_in_memory().unwrap();
        let c = Conversation {
            id: "c1".into(),
            tenant_id: "t1".into(),
            owner_subject: "s1".into(),
            locale: Locale::Amharic,
            created_at: 1,
        };
        store.insert_conversation(&c).unwrap();
        assert_eq!(
            store.append_turn("c1", "u1", "user", "ሰላም", "completed", "idem1", 2),
            Ok(1)
        );
        assert_eq!(
            store.append_turn("c1", "a1", "assistant", "ሰላም", "completed", "idem2", 3),
            Ok(2)
        );
        let turns = store.turns("c1").unwrap();
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role, "user");
        assert_eq!(turns[1].sequence, 2);
    }

    #[test]
    fn duplicate_idempotency_key_cannot_create_a_second_turn() {
        let store = ConversationStore::open_in_memory().unwrap();
        let c = Conversation {
            id: "c1".into(),
            tenant_id: "t1".into(),
            owner_subject: "s1".into(),
            locale: Locale::English,
            created_at: 1,
        };
        store.insert_conversation(&c).unwrap();
        assert_eq!(
            store.append_turn("c1", "u1", "user", "hello", "completed", "same", 2),
            Ok(1)
        );
        assert_eq!(
            store.append_turn("c1", "u2", "user", "hello", "completed", "same", 3),
            Err(ConversationError::Conflict)
        );
    }

    #[test]
    fn deletion_revokes_access_before_delayed_purge_and_preserves_lifecycle_event() {
        let store = ConversationStore::open_in_memory().unwrap();
        let conversation = Conversation {
            id: "delete-me".into(),
            tenant_id: "tenant-a".into(),
            owner_subject: "subject-a".into(),
            locale: Locale::Amharic,
            created_at: 1,
        };
        store.insert_conversation(&conversation).unwrap();
        store
            .record_event(
                "evt-delete",
                "tenant-a",
                "delete-me",
                None,
                "conversation.access_revoked",
                "corr-1",
                10,
            )
            .unwrap();
        store
            .mark_deleted("delete-me", "tenant-a", "subject-a", 10, 100)
            .unwrap();
        assert_eq!(
            store.owned_conversation("delete-me", "tenant-a", "subject-a"),
            Err(ConversationError::NotFound)
        );
        assert_eq!(store.purge_due(99), Ok(0));
        assert_eq!(store.purge_due(100), Ok(1));
        let db = store.db.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM conversation_events WHERE event_id='evt-delete'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn locale_defaults_to_amharic_and_accepts_english() {
        assert_eq!(Locale::parse(None), Locale::Amharic);
        assert_eq!(Locale::parse(Some("en")), Locale::English);
    }

    #[test]
    fn synthetic_generator_has_no_provider_dependency() {
        let cancel = Cancellation::new();
        let answer = SyntheticAnswerGenerator
            .answer("ሰላም", Locale::Amharic, &cancel)
            .unwrap();
        assert!(answer.starts_with("ይህ የሙከራ መልስ"));
    }
}
