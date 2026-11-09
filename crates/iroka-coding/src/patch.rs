//! Governed, in-memory patch review, preview application and rollback.
//!
//! Persistent workspace writes are intentionally absent until G09 supplies an
//! independently verified execution grant.

use std::collections::BTreeSet;

use iroka_kernel::{
    AuthorizationRequest, OwnerApprovalError, OwnerApprovalVerifier, RiskLevel as KernelRiskLevel,
    SignedOwnerApproval,
};
use sha2::{Digest, Sha256};

use crate::codegen::{ChangeOperation, CodeGenerationRequest, ValidatedCodeGeneration};
use crate::index::SnapshotFile;
use crate::planner::{safe_relative_path, valid_revision};

const PATCH_CAPABILITY: &str = "coding.patch.preview";
const MAX_SNAPSHOT_FILES: usize = 20_000;
const MAX_SNAPSHOT_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SNAPSHOT_TOTAL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceSnapshot {
    repository: String,
    revision: String,
    files: Vec<SnapshotFile>,
}

impl WorkspaceSnapshot {
    pub fn new(
        repository: impl Into<String>,
        revision: impl Into<String>,
        mut files: Vec<SnapshotFile>,
    ) -> Result<Self, PatchReviewError> {
        let repository = repository.into();
        let revision = revision.into();
        if !valid_repository_id(&repository) || !valid_revision(&revision) {
            return Err(PatchReviewError::InvalidSnapshot);
        }
        if files.len() > MAX_SNAPSHOT_FILES {
            return Err(PatchReviewError::LimitExceeded);
        }
        let mut paths = BTreeSet::new();
        let mut total_bytes = 0_usize;
        for file in &files {
            if file.content.len() > MAX_SNAPSHOT_FILE_BYTES {
                return Err(PatchReviewError::LimitExceeded);
            }
            total_bytes = total_bytes.saturating_add(file.content.len());
            if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES {
                return Err(PatchReviewError::LimitExceeded);
            }
            if file.is_symlink || !safe_relative_path(&file.path) {
                return Err(PatchReviewError::UnsafePath);
            }
            if !paths.insert(file.path.as_str()) {
                return Err(PatchReviewError::DuplicatePath);
            }
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(Self {
            repository,
            revision,
            files,
        })
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn files(&self) -> &[SnapshotFile] {
        &self.files
    }

    #[must_use]
    pub fn file(&self, path: &str) -> Option<&SnapshotFile> {
        self.files.iter().find(|file| file.path == path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchReviewPolicy {
    protected_paths: Vec<String>,
    max_patch_bytes: usize,
    max_total_bytes: usize,
}

impl Default for PatchReviewPolicy {
    fn default() -> Self {
        Self {
            protected_paths: vec![
                ".git".to_owned(),
                ".github/workflows".to_owned(),
                ".github/actions".to_owned(),
                ".env".to_owned(),
                ".ssh".to_owned(),
                "secrets".to_owned(),
                "keys".to_owned(),
                "certs".to_owned(),
                "Cargo.lock".to_owned(),
                "package-lock.json".to_owned(),
                "npm-shrinkwrap.json".to_owned(),
                "pnpm-lock.yaml".to_owned(),
                "yarn.lock".to_owned(),
                "poetry.lock".to_owned(),
                "Pipfile.lock".to_owned(),
                "composer.lock".to_owned(),
                "Gemfile.lock".to_owned(),
                "go.sum".to_owned(),
                "crates/iroka-kernel/src/owner_approval.rs".to_owned(),
                "crates/iroka-kernel/src/identity_crypto.rs".to_owned(),
                "crates/iroka-kernel/src/identity.rs".to_owned(),
                "crates/iroka-kernel/src/security_store.rs".to_owned(),
                "crates/iroka-kernel/src/trust_lifecycle.rs".to_owned(),
                "crates/iroka-kernel/src/igacms.rs".to_owned(),
                "crates/iroka-kernel/src/governance.rs".to_owned(),
                "crates/iroka-kernel/src/service.rs".to_owned(),
                "crates/iroka-kernel/src/policy.rs".to_owned(),
                "crates/iroka-kernel/src/audit_store.rs".to_owned(),
                "crates/iroka-kernel/src/assurance.rs".to_owned(),
                "crates/iroka-kernel/src/request.rs".to_owned(),
                "crates/iroka-kernel/src/decision.rs".to_owned(),
                "crates/iroka-kernel/src/lib.rs".to_owned(),
            ],
            max_patch_bytes: 128 * 1024,
            max_total_bytes: 256 * 1024,
        }
    }
}

impl PatchReviewPolicy {
    /// Add a protected path. Defaults cannot be removed through this API.
    pub fn with_additional_protected_path(
        mut self,
        path: impl Into<String>,
    ) -> Result<Self, PatchReviewError> {
        let path = path.into();
        if !safe_relative_path(&path) {
            return Err(PatchReviewError::UnsafePath);
        }
        if !self.protected_paths.contains(&path) {
            self.protected_paths.push(path);
        }
        Ok(self)
    }

    fn protects(&self, path: &str) -> bool {
        let lowercase = path.to_ascii_lowercase();
        if [".pem", ".key", ".p12", ".pfx", ".crt", ".cer"]
            .iter()
            .any(|extension| lowercase.ends_with(extension))
        {
            return true;
        }
        self.protected_paths.iter().any(|protected| {
            path == protected
                || path
                    .strip_prefix(protected)
                    .is_some_and(|suffix| suffix.starts_with('/'))
                || (protected == ".env" && path.starts_with(".env"))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchReviewError {
    InvalidSnapshot,
    StaleSourceRevision,
    UnsafePath,
    DuplicatePath,
    ProtectedPath,
    TargetAlreadyExists,
    TargetDoesNotExist,
    MismatchedRequest,
    OperationMismatch,
    InvalidPatchHeader,
    InvalidHunk,
    HunkContextMismatch,
    HunkOutOfOrder,
    UnsupportedPatch,
    LimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedPatch {
    repository: String,
    source_revision: String,
    request_id: String,
    path: String,
    operation: ChangeOperation,
    patch_digest: String,
    approval_resource: String,
    before_content: Option<String>,
    after_content: Option<String>,
    before_hash: Option<String>,
    after_hash: Option<String>,
}

impl ReviewedPatch {
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn operation(&self) -> ChangeOperation {
        self.operation
    }

    #[must_use]
    pub fn patch_digest(&self) -> &str {
        &self.patch_digest
    }

    #[must_use]
    pub fn approval_resource(&self) -> &str {
        &self.approval_resource
    }

    #[must_use]
    pub fn before_hash(&self) -> Option<&str> {
        self.before_hash.as_deref()
    }

    #[must_use]
    pub fn after_hash(&self) -> Option<&str> {
        self.after_hash.as_deref()
    }

    #[must_use]
    pub fn proposed_content(&self) -> Option<&str> {
        self.after_content.as_deref()
    }
}

pub struct PatchReview {
    policy: PatchReviewPolicy,
}

impl PatchReview {
    #[must_use]
    pub fn new(policy: PatchReviewPolicy) -> Self {
        Self { policy }
    }

    pub fn review(
        &self,
        snapshot: &WorkspaceSnapshot,
        request: &CodeGenerationRequest<'_>,
        generated: &ValidatedCodeGeneration,
    ) -> Result<ReviewedPatch, PatchReviewError> {
        if request.source_revision != snapshot.revision {
            return Err(PatchReviewError::StaleSourceRevision);
        }
        if !safe_relative_path(&request.target_path) {
            return Err(PatchReviewError::UnsafePath);
        }
        if self.policy.protects(&request.target_path) {
            return Err(PatchReviewError::ProtectedPath);
        }
        let response = generated.response();
        if response.request_id != request.request_id || response.changes.len() != 1 {
            return Err(PatchReviewError::MismatchedRequest);
        }
        let change = &response.changes[0];
        if change.path != request.target_path || change.operation != request.operation {
            return Err(PatchReviewError::OperationMismatch);
        }
        if change.unified_diff.len() > self.policy.max_patch_bytes {
            return Err(PatchReviewError::LimitExceeded);
        }

        let existing = snapshot.file(&request.target_path);
        match request.operation {
            ChangeOperation::Create if existing.is_some() => {
                return Err(PatchReviewError::TargetAlreadyExists);
            }
            ChangeOperation::Modify | ChangeOperation::Delete if existing.is_none() => {
                return Err(PatchReviewError::TargetDoesNotExist);
            }
            _ => {}
        }

        let before_content = existing.map(|file| file.content.clone());
        let after_content = apply_unified_diff(
            &request.target_path,
            request.operation,
            before_content.as_deref(),
            &change.unified_diff,
        )?;
        let before_hash = before_content.as_deref().map(content_hash);
        let after_hash = after_content.as_deref().map(content_hash);
        let total_bytes = change
            .unified_diff
            .len()
            .saturating_add(before_content.as_ref().map_or(0, String::len))
            .saturating_add(after_content.as_ref().map_or(0, String::len));
        if total_bytes > self.policy.max_total_bytes {
            return Err(PatchReviewError::LimitExceeded);
        }

        let patch_digest = digest_fields(&[
            "iroka-patch-v1",
            &snapshot.repository,
            &snapshot.revision,
            &request.request_id,
            &request.target_path,
            &format!("{:?}", request.operation),
            before_hash.as_deref().unwrap_or("absent"),
            after_hash.as_deref().unwrap_or("absent"),
            &change.unified_diff,
        ]);
        let approval_resource = format!(
            "repo:{}/revision:{}/patch:{}",
            snapshot.repository, snapshot.revision, patch_digest
        );
        Ok(ReviewedPatch {
            repository: snapshot.repository.clone(),
            source_revision: snapshot.revision.clone(),
            request_id: request.request_id.clone(),
            path: request.target_path.clone(),
            operation: request.operation,
            patch_digest,
            approval_resource,
            before_content,
            after_content,
            before_hash,
            after_hash,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatchApprovalError {
    InvalidRequest,
    Owner(OwnerApprovalError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPatchApproval {
    approval_id: String,
    owner_subject: String,
    repository: String,
    source_revision: String,
    patch_digest: String,
    approval_resource: String,
    policy_version: String,
    verified_at: u64,
}

impl VerifiedPatchApproval {
    #[must_use]
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    #[must_use]
    pub fn owner_subject(&self) -> &str {
        &self.owner_subject
    }

    #[must_use]
    pub fn patch_digest(&self) -> &str {
        &self.patch_digest
    }
}

/// Verify and consume a real G02 Owner approval for this exact in-memory preview.
/// This receipt is not a G09 execution grant and cannot authorize disk writes.
pub fn verify_owner_approval(
    verifier: &OwnerApprovalVerifier,
    approval: &SignedOwnerApproval,
    reviewed: &ReviewedPatch,
    request_subject: &str,
    policy_version: &str,
    now: u64,
) -> Result<VerifiedPatchApproval, PatchApprovalError> {
    if request_subject.trim().is_empty() || policy_version.trim().is_empty() {
        return Err(PatchApprovalError::InvalidRequest);
    }
    let authorization_request = AuthorizationRequest::new(
        request_subject,
        PATCH_CAPABILITY,
        reviewed.approval_resource.clone(),
        KernelRiskLevel::High,
    );
    verifier
        .verify_and_consume(approval, &authorization_request, policy_version, now)
        .map_err(PatchApprovalError::Owner)?;

    Ok(VerifiedPatchApproval {
        approval_id: approval.payload.approval_id.clone(),
        owner_subject: approval.payload.owner_subject.clone(),
        repository: reviewed.repository.clone(),
        source_revision: reviewed.source_revision.clone(),
        patch_digest: reviewed.patch_digest.clone(),
        approval_resource: reviewed.approval_resource.clone(),
        policy_version: policy_version.to_owned(),
        verified_at: now,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchApplyError {
    ApprovalMismatch,
    StaleSnapshot,
    TargetConflict,
    InvalidReview,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedPatchSet {
    original: WorkspaceSnapshot,
    preview: WorkspaceSnapshot,
    patch_digest: String,
}

impl AppliedPatchSet {
    #[must_use]
    pub fn preview(&self) -> &WorkspaceSnapshot {
        &self.preview
    }

    #[must_use]
    pub fn patch_digest(&self) -> &str {
        &self.patch_digest
    }

    /// Restore the exact original snapshot. No persistent commit operation exists.
    #[must_use]
    pub fn rollback(self) -> WorkspaceSnapshot {
        self.original
    }
}

pub struct PatchApplier;

impl PatchApplier {
    /// Apply only to a new in-memory snapshot after the exact G02 preview approval.
    pub fn apply_preview(
        snapshot: &WorkspaceSnapshot,
        reviewed: &ReviewedPatch,
        approval: &VerifiedPatchApproval,
    ) -> Result<AppliedPatchSet, PatchApplyError> {
        if approval.repository != reviewed.repository
            || approval.source_revision != reviewed.source_revision
            || approval.patch_digest != reviewed.patch_digest
            || approval.approval_resource != reviewed.approval_resource
            || approval.policy_version.trim().is_empty()
            || approval.verified_at == 0
        {
            return Err(PatchApplyError::ApprovalMismatch);
        }
        if snapshot.repository != reviewed.repository
            || snapshot.revision != reviewed.source_revision
        {
            return Err(PatchApplyError::StaleSnapshot);
        }
        let existing = snapshot.file(&reviewed.path);
        let current_hash = existing.map(|file| content_hash(&file.content));
        if current_hash != reviewed.before_hash {
            return Err(PatchApplyError::StaleSnapshot);
        }

        let mut preview = snapshot.clone();
        match reviewed.operation {
            ChangeOperation::Create => {
                if existing.is_some() {
                    return Err(PatchApplyError::TargetConflict);
                }
                let content = reviewed
                    .after_content
                    .clone()
                    .ok_or(PatchApplyError::InvalidReview)?;
                preview
                    .files
                    .push(SnapshotFile::new(&reviewed.path, content));
            }
            ChangeOperation::Modify => {
                let content = reviewed
                    .after_content
                    .clone()
                    .ok_or(PatchApplyError::InvalidReview)?;
                let Some(file) = preview
                    .files
                    .iter_mut()
                    .find(|file| file.path == reviewed.path)
                else {
                    return Err(PatchApplyError::TargetConflict);
                };
                file.content = content;
            }
            ChangeOperation::Delete => {
                if reviewed.after_content.is_some() {
                    return Err(PatchApplyError::InvalidReview);
                }
                preview.files.retain(|file| file.path != reviewed.path);
            }
        }
        preview
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        let after_hash = preview
            .file(&reviewed.path)
            .map(|file| content_hash(&file.content));
        if after_hash != reviewed.after_hash {
            return Err(PatchApplyError::InvalidReview);
        }
        Ok(AppliedPatchSet {
            original: snapshot.clone(),
            preview,
            patch_digest: reviewed.patch_digest.clone(),
        })
    }
}

fn apply_unified_diff(
    path: &str,
    operation: ChangeOperation,
    original: Option<&str>,
    patch: &str,
) -> Result<Option<String>, PatchReviewError> {
    let lines: Vec<_> = patch.lines().collect();
    let expected_git_header = format!("diff --git a/{0} b/{0}", path);
    let git_headers: Vec<_> = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("diff --git "))
        .collect();
    let old_headers: Vec<_> = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("--- "))
        .collect();
    let new_headers: Vec<_> = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("+++ "))
        .collect();
    if git_headers.len() != 1
        || git_headers[0] != expected_git_header
        || old_headers.len() != 1
        || new_headers.len() != 1
        || patch.contains('\0')
    {
        return Err(PatchReviewError::InvalidPatchHeader);
    }

    let expected_old = match operation {
        ChangeOperation::Create => "--- /dev/null".to_owned(),
        ChangeOperation::Modify | ChangeOperation::Delete => format!("--- a/{path}"),
    };
    let expected_new = match operation {
        ChangeOperation::Delete => "+++ /dev/null".to_owned(),
        ChangeOperation::Create | ChangeOperation::Modify => format!("+++ b/{path}"),
    };
    if old_headers[0] != expected_old || new_headers[0] != expected_new {
        return Err(PatchReviewError::InvalidPatchHeader);
    }

    let source = original.unwrap_or_default();
    let trailing_newline = original.map_or(true, |content| content.ends_with('\n'));
    let source_lines: Vec<String> = if source.is_empty() {
        Vec::new()
    } else {
        source.split_terminator('\n').map(str::to_owned).collect()
    };
    let mut output = Vec::new();
    let mut source_cursor = 0;
    let mut index = 0;
    let mut hunk_count = 0;
    let mut last_hunk_start = None;

    while index < lines.len() {
        if !lines[index].starts_with("@@ ") {
            if hunk_count == 0 {
                index += 1;
                continue;
            }
            return Err(PatchReviewError::UnsupportedPatch);
        }
        let (old_start, old_count, new_start, new_count) =
            parse_hunk_header(lines[index]).ok_or(PatchReviewError::InvalidHunk)?;
        let target_index = if old_count == 0 {
            old_start
        } else {
            old_start
                .checked_sub(1)
                .ok_or(PatchReviewError::InvalidHunk)?
        };
        if target_index < source_cursor
            || target_index > source_lines.len()
            || last_hunk_start == Some(target_index)
        {
            return Err(PatchReviewError::HunkOutOfOrder);
        }
        output.extend_from_slice(&source_lines[source_cursor..target_index]);
        source_cursor = target_index;
        let expected_new_start = if new_count == 0 {
            output.len()
        } else {
            output.len() + 1
        };
        if new_start != expected_new_start {
            return Err(PatchReviewError::InvalidHunk);
        }

        index += 1;
        let mut old_seen = 0;
        let mut new_seen = 0;
        while index < lines.len() && !lines[index].starts_with("@@ ") {
            let line = lines[index];
            if line.starts_with("\\ No newline at end of file") || line.is_empty() {
                return Err(PatchReviewError::UnsupportedPatch);
            }
            let marker = line.as_bytes()[0];
            let text = &line[1..];
            match marker {
                b' ' => {
                    if source_lines.get(source_cursor).map(String::as_str) != Some(text) {
                        return Err(PatchReviewError::HunkContextMismatch);
                    }
                    output.push(text.to_owned());
                    source_cursor += 1;
                    old_seen += 1;
                    new_seen += 1;
                }
                b'-' => {
                    if source_lines.get(source_cursor).map(String::as_str) != Some(text) {
                        return Err(PatchReviewError::HunkContextMismatch);
                    }
                    source_cursor += 1;
                    old_seen += 1;
                }
                b'+' => {
                    output.push(text.to_owned());
                    new_seen += 1;
                }
                _ => return Err(PatchReviewError::UnsupportedPatch),
            }
            index += 1;
        }
        if old_seen != old_count || new_seen != new_count {
            return Err(PatchReviewError::InvalidHunk);
        }
        last_hunk_start = Some(target_index);
        hunk_count += 1;
    }

    if hunk_count == 0 {
        return Err(PatchReviewError::InvalidHunk);
    }
    output.extend_from_slice(&source_lines[source_cursor..]);
    if operation == ChangeOperation::Delete {
        if !output.is_empty() {
            return Err(PatchReviewError::InvalidHunk);
        }
        return Ok(None);
    }
    let mut content = output.join("\n");
    if trailing_newline && !output.is_empty() {
        content.push('\n');
    }
    Ok(Some(content))
}

fn parse_hunk_header(line: &str) -> Option<(usize, usize, usize, usize)> {
    let body = line.strip_prefix("@@ ")?.split_once(" @@")?.0;
    let mut ranges = body.split_whitespace();
    let (old_start, old_count) = parse_range(ranges.next()?, '-')?;
    let (new_start, new_count) = parse_range(ranges.next()?, '+')?;
    if ranges.next().is_some() {
        return None;
    }
    Some((old_start, old_count, new_start, new_count))
}

fn parse_range(value: &str, prefix: char) -> Option<(usize, usize)> {
    let value = value.strip_prefix(prefix)?;
    let (start, count) = value.split_once(',').unwrap_or((value, "1"));
    Some((start.parse().ok()?, count.parse().ok()?))
}

fn valid_repository_id(repository: &str) -> bool {
    !repository.trim().is_empty()
        && repository.len() <= 256
        && !repository.starts_with('/')
        && !repository.contains('\\')
        && !repository.bytes().any(|byte| byte.is_ascii_control())
        && repository
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains(':'))
}

fn content_hash(content: &str) -> String {
    hex_digest(Sha256::digest(content.as_bytes()).as_slice())
}

fn digest_fields(fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hex_digest(hasher.finalize().as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
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
    use iroka_kernel::{OwnerApprovalPayload, SqliteSecurityStore, TrustedOwnerKey};

    use crate::codegen::{
        CodeGenerationLimits, CodeGenerationProvider, CodeGenerationResponse, CodeGenerator,
        GeneratedChange,
    };
    use crate::index::{FileRecord, FileRole, RepositoryIndex};
    use crate::planner::{EvidenceSnippet, ProviderFailure};
    use crate::{
        ExtensionAdapter, LanguageCapabilities, LanguageDescriptor, LanguageId, LanguageRegistry,
    };

    struct FixtureProvider {
        response: CodeGenerationResponse,
    }

    impl CodeGenerationProvider for FixtureProvider {
        fn generate_patch(
            &self,
            _request: &CodeGenerationRequest<'_>,
        ) -> Result<CodeGenerationResponse, ProviderFailure> {
            Ok(self.response.clone())
        }
    }

    fn registry() -> LanguageRegistry {
        let mut registry = LanguageRegistry::new();
        registry
            .register(Box::new(ExtensionAdapter::new(LanguageDescriptor {
                id: LanguageId::new("rust").expect("language id"),
                display_name: "Rust".to_owned(),
                file_extensions: vec!["rs".to_owned()],
                capabilities: LanguageCapabilities::default(),
            })))
            .expect("register Rust");
        registry
    }

    fn repository_index(path: &str) -> RepositoryIndex {
        RepositoryIndex {
            files: vec![FileRecord {
                path: path.to_owned(),
                size_bytes: 20,
                role: FileRole::Source,
                languages: Vec::new(),
            }],
            ..RepositoryIndex::default()
        }
    }

    fn request<'a>(
        index: &'a RepositoryIndex,
        path: &str,
        operation: ChangeOperation,
    ) -> CodeGenerationRequest<'a> {
        CodeGenerationRequest {
            request_id: "request-1".to_owned(),
            task_id: "task-1".to_owned(),
            step_id: "edit-1".to_owned(),
            source_revision: "a".repeat(40),
            language: LanguageId::new("rust").expect("language"),
            target_path: path.to_owned(),
            operation,
            instructions: "Apply the reviewed source change".to_owned(),
            repository: index,
            evidence: vec![EvidenceSnippet {
                path: path.to_owned(),
                start_line: 1,
                end_line: 2,
                excerpt: "pub fn existing() {}".to_owned(),
            }],
            constraints: vec!["No filesystem writes".to_owned()],
        }
    }

    fn response(path: &str, operation: ChangeOperation, patch: &str) -> CodeGenerationResponse {
        CodeGenerationResponse {
            request_id: "request-1".to_owned(),
            summary: "Propose the requested change".to_owned(),
            changes: vec![GeneratedChange {
                path: path.to_owned(),
                operation,
                unified_diff: patch.to_owned(),
                rationale: "The patch is limited to the requested file".to_owned(),
            }],
            diagnostics: Vec::new(),
        }
    }

    fn reviewed(
        snapshot: &WorkspaceSnapshot,
        path: &str,
        operation: ChangeOperation,
        patch: &str,
    ) -> (RepositoryIndex, ReviewedPatch) {
        let index = repository_index(path);
        let request = request(&index, path, operation);
        let provider = FixtureProvider {
            response: response(path, operation, patch),
        };
        let generated = CodeGenerator::new(CodeGenerationLimits::default())
            .generate(&provider, &request, &registry())
            .expect("validated codegen response");
        let review = PatchReview::new(PatchReviewPolicy::default())
            .review(snapshot, &request, &generated)
            .expect("reviewed patch");
        (index, review)
    }

    fn owner_verifier() -> (OwnerApprovalVerifier, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().expect("security store"));
        let verifier = OwnerApprovalVerifier::new(
            vec![TrustedOwnerKey {
                owner_subject: "owner-1".to_owned(),
                key_id: "owner-key-1".to_owned(),
                public_key: signing_key.verifying_key().to_bytes(),
                not_before: 0,
                not_after: 10_000,
            }],
            store,
        )
        .expect("owner verifier");
        (verifier, signing_key)
    }

    fn approve(
        review: &ReviewedPatch,
        verifier: &OwnerApprovalVerifier,
        key: &SigningKey,
    ) -> VerifiedPatchApproval {
        let payload = OwnerApprovalPayload::new(
            "approval-1",
            "owner-1",
            "owner-key-1",
            "agent-1",
            PATCH_CAPABILITY,
            review.approval_resource(),
            "policy-v1",
            1_000,
            1_600,
        );
        let signature = key.sign(&payload.signing_bytes().expect("signing bytes"));
        let approval = SignedOwnerApproval::from_signature(payload, signature.to_bytes().to_vec());
        verify_owner_approval(verifier, &approval, review, "agent-1", "policy-v1", 1_000)
            .expect("verified Owner approval")
    }

    #[test]
    fn applies_approved_patch_in_memory_and_rolls_back_exactly() {
        let original = WorkspaceSnapshot::new(
            "akefadaka-git/iroka",
            "a".repeat(40),
            vec![SnapshotFile::new("src/lib.rs", "pub fn existing() {}\n")],
        )
        .expect("workspace snapshot");
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,2 @@\n pub fn existing() {}\n+pub fn added() {}\n";
        let (_, review) = reviewed(&original, "src/lib.rs", ChangeOperation::Modify, patch);
        let (verifier, key) = owner_verifier();
        let approval = approve(&review, &verifier, &key);
        let applied =
            PatchApplier::apply_preview(&original, &review, &approval).expect("approved preview");
        assert_eq!(
            applied
                .preview()
                .file("src/lib.rs")
                .expect("preview file")
                .content,
            "pub fn existing() {}\npub fn added() {}\n"
        );
        assert_eq!(applied.rollback(), original);
    }

    #[test]
    fn rejects_replay_of_the_same_owner_approval() {
        let original = WorkspaceSnapshot::new(
            "akefadaka-git/iroka",
            "a".repeat(40),
            vec![SnapshotFile::new("src/lib.rs", "pub fn existing() {}\n")],
        )
        .expect("workspace snapshot");
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,2 @@\n pub fn existing() {}\n+pub fn added() {}\n";
        let (_, review) = reviewed(&original, "src/lib.rs", ChangeOperation::Modify, patch);
        let (verifier, key) = owner_verifier();
        let payload = OwnerApprovalPayload::new(
            "approval-replay",
            "owner-1",
            "owner-key-1",
            "agent-1",
            PATCH_CAPABILITY,
            review.approval_resource(),
            "policy-v1",
            1_000,
            1_600,
        );
        let signature = key.sign(&payload.signing_bytes().expect("signing bytes"));
        let approval = SignedOwnerApproval::from_signature(payload, signature.to_bytes().to_vec());
        assert!(verify_owner_approval(
            &verifier,
            &approval,
            &review,
            "agent-1",
            "policy-v1",
            1_000
        )
        .is_ok());
        assert_eq!(
            verify_owner_approval(&verifier, &approval, &review, "agent-1", "policy-v1", 1_000),
            Err(PatchApprovalError::Owner(OwnerApprovalError::Replay))
        );
    }

    #[test]
    fn rejects_protected_kernel_paths() {
        let path = "crates/iroka-kernel/src/owner_approval.rs";
        let snapshot = WorkspaceSnapshot::new(
            "akefadaka-git/iroka",
            "a".repeat(40),
            vec![SnapshotFile::new(path, "pub struct Existing;\n")],
        )
        .expect("workspace snapshot");
        let index = repository_index(path);
        let request = request(&index, path, ChangeOperation::Modify);
        let patch = format!(
            "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-pub struct Existing;\n+pub struct Changed;\n"
        );
        let provider = FixtureProvider {
            response: response(path, ChangeOperation::Modify, &patch),
        };
        let generated = CodeGenerator::new(CodeGenerationLimits::default())
            .generate(&provider, &request, &registry())
            .expect("validated codegen");
        assert_eq!(
            PatchReview::new(PatchReviewPolicy::default()).review(&snapshot, &request, &generated),
            Err(PatchReviewError::ProtectedPath)
        );
    }

    #[test]
    fn rejects_stale_hunk_context_and_stale_snapshot() {
        let original = WorkspaceSnapshot::new(
            "akefadaka-git/iroka",
            "a".repeat(40),
            vec![SnapshotFile::new("src/lib.rs", "pub fn existing() {}\n")],
        )
        .expect("workspace snapshot");
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,2 @@\n-pub fn stale() {}\n+pub fn added() {}\n";
        let index = repository_index("src/lib.rs");
        let request = request(&index, "src/lib.rs", ChangeOperation::Modify);
        let provider = FixtureProvider {
            response: response("src/lib.rs", ChangeOperation::Modify, patch),
        };
        let generated = CodeGenerator::new(CodeGenerationLimits::default())
            .generate(&provider, &request, &registry())
            .expect("validated codegen");
        assert_eq!(
            PatchReview::new(PatchReviewPolicy::default()).review(&original, &request, &generated),
            Err(PatchReviewError::HunkContextMismatch)
        );
    }

    #[test]
    fn rejects_drive_paths_and_duplicate_snapshot_paths() {
        assert_eq!(
            WorkspaceSnapshot::new(
                "akefadaka-git/iroka",
                "a".repeat(40),
                vec![SnapshotFile::new("C:/outside.rs", "bad")],
            ),
            Err(PatchReviewError::UnsafePath)
        );
        assert_eq!(
            WorkspaceSnapshot::new(
                "akefadaka-git/iroka",
                "a".repeat(40),
                vec![
                    SnapshotFile::new("src/lib.rs", "one"),
                    SnapshotFile::new("src/lib.rs", "two"),
                ],
            ),
            Err(PatchReviewError::DuplicatePath)
        );
    }

    #[test]
    fn applies_create_and_delete_hunks_without_touching_a_filesystem() {
        let create = "diff --git a/src/new.rs b/src/new.rs\n--- /dev/null\n+++ b/src/new.rs\n@@ -0,0 +1 @@\n+pub fn created() {}\n";
        assert_eq!(
            apply_unified_diff("src/new.rs", ChangeOperation::Create, None, create),
            Ok(Some("pub fn created() {}\n".to_owned()))
        );

        let delete = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-pub fn existing() {}\n";
        assert_eq!(
            apply_unified_diff(
                "src/lib.rs",
                ChangeOperation::Delete,
                Some("pub fn existing() {}\n"),
                delete
            ),
            Ok(None)
        );
    }

    #[test]
    fn rejects_repeated_or_out_of_order_hunks() {
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n@@ -1 +1 @@\n-old\n+again\n";
        assert_eq!(
            apply_unified_diff("src/lib.rs", ChangeOperation::Modify, Some("old\n"), patch),
            Err(PatchReviewError::HunkOutOfOrder)
        );
    }

    #[test]
    fn rejects_stale_snapshot_after_owner_approval() {
        let original = WorkspaceSnapshot::new(
            "akefadaka-git/iroka",
            "a".repeat(40),
            vec![SnapshotFile::new("src/lib.rs", "pub fn existing() {}\n")],
        )
        .expect("workspace snapshot");
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,2 @@\n pub fn existing() {}\n+pub fn added() {}\n";
        let (_, review) = reviewed(&original, "src/lib.rs", ChangeOperation::Modify, patch);
        let (verifier, key) = owner_verifier();
        let approval = approve(&review, &verifier, &key);
        let stale = WorkspaceSnapshot::new(
            "akefadaka-git/iroka",
            "a".repeat(40),
            vec![SnapshotFile::new("src/lib.rs", "pub fn changed() {}\n")],
        )
        .expect("stale snapshot");
        assert_eq!(
            PatchApplier::apply_preview(&stale, &review, &approval),
            Err(PatchApplyError::StaleSnapshot)
        );
    }

    #[test]
    fn protects_sensitive_key_material_and_additional_paths() {
        let policy = PatchReviewPolicy::default()
            .with_additional_protected_path("docs/owner-policy.md")
            .expect("additional protected path");
        assert!(policy.protects("id_ed25519.pem"));
        assert!(policy.protects("docs/owner-policy.md"));
        assert!(policy.protects(".env.production"));
    }

    #[test]
    fn rejects_unapproved_preview_application() {
        let original = WorkspaceSnapshot::new(
            "akefadaka-git/iroka",
            "a".repeat(40),
            vec![SnapshotFile::new("src/lib.rs", "pub fn existing() {}\n")],
        )
        .expect("workspace snapshot");
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,2 @@\n pub fn existing() {}\n+pub fn added() {}\n";
        let (_, review) = reviewed(&original, "src/lib.rs", ChangeOperation::Modify, patch);
        let forged = VerifiedPatchApproval {
            approval_id: "fake".to_owned(),
            owner_subject: "owner-1".to_owned(),
            repository: review.repository.clone(),
            source_revision: review.source_revision.clone(),
            patch_digest: review.patch_digest.clone(),
            approval_resource: review.approval_resource.clone(),
            policy_version: "policy-v1".to_owned(),
            verified_at: 1_000,
        };
        assert_eq!(
            PatchApplier::apply_preview(&original, &review, &forged),
            Err(PatchApplyError::ApprovalMismatch)
        );
    }
}
