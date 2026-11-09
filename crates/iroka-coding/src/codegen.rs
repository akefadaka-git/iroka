//! Structured, provider-neutral code-generation proposals.
//!
//! Generated patches are validated but never applied by this module.

use crate::index::RepositoryIndex;
use crate::planner::{
    safe_relative_path, valid_identifier, valid_revision, EvidenceSnippet, ProviderFailure,
};
use crate::{LanguageId, LanguageRegistry};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodeGenerationLimits {
    pub max_changes: usize,
    pub max_context_items: usize,
    pub max_patch_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for CodeGenerationLimits {
    fn default() -> Self {
        Self {
            max_changes: 1,
            max_context_items: 128,
            max_patch_bytes: 128 * 1024,
            max_total_bytes: 256 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeOperation {
    Create,
    Modify,
    Delete,
}

#[derive(Clone, Debug)]
pub struct CodeGenerationRequest<'a> {
    pub request_id: String,
    pub task_id: String,
    pub step_id: String,
    pub source_revision: String,
    pub language: LanguageId,
    pub target_path: String,
    pub operation: ChangeOperation,
    pub instructions: String,
    pub repository: &'a RepositoryIndex,
    pub evidence: Vec<EvidenceSnippet>,
    pub constraints: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedChange {
    pub path: String,
    pub operation: ChangeOperation,
    pub unified_diff: String,
    pub rationale: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeGenerationResponse {
    pub request_id: String,
    pub summary: String,
    pub changes: Vec<GeneratedChange>,
    pub diagnostics: Vec<String>,
}

pub trait CodeGenerationProvider: Send + Sync {
    fn generate_patch(
        &self,
        request: &CodeGenerationRequest<'_>,
    ) -> Result<CodeGenerationResponse, ProviderFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeGenerationValidationError {
    InvalidIdentifier,
    InvalidSourceRevision,
    UnsupportedLanguage,
    EmptyInstructions,
    UnsafePath,
    TargetAlreadyExists,
    TargetDoesNotExist,
    InvalidEvidenceRange,
    EvidenceNotInRepository,
    MissingEvidence,
    LimitExceeded,
    MismatchedRequest,
    EmptyResponse,
    InvalidPatchHeader,
    DuplicateTarget,
    OperationMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodeGenerationError {
    InvalidRequest(CodeGenerationValidationError),
    Provider(ProviderFailure),
    InvalidResponse(CodeGenerationValidationError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCodeGeneration {
    response: CodeGenerationResponse,
}

impl ValidatedCodeGeneration {
    #[must_use]
    pub fn response(&self) -> &CodeGenerationResponse {
        &self.response
    }
}

pub struct CodeGenerator {
    limits: CodeGenerationLimits,
}

impl CodeGenerator {
    #[must_use]
    pub fn new(limits: CodeGenerationLimits) -> Self {
        Self { limits }
    }

    pub fn generate(
        &self,
        provider: &dyn CodeGenerationProvider,
        request: &CodeGenerationRequest<'_>,
        registry: &LanguageRegistry,
    ) -> Result<ValidatedCodeGeneration, CodeGenerationError> {
        validate_request(request, registry, self.limits)
            .map_err(CodeGenerationError::InvalidRequest)?;
        let response = provider
            .generate_patch(request)
            .map_err(CodeGenerationError::Provider)?;
        validate_response(&response, request, self.limits)
            .map_err(CodeGenerationError::InvalidResponse)?;
        Ok(ValidatedCodeGeneration { response })
    }
}

fn validate_request(
    request: &CodeGenerationRequest<'_>,
    registry: &LanguageRegistry,
    limits: CodeGenerationLimits,
) -> Result<(), CodeGenerationValidationError> {
    if !valid_identifier(&request.request_id)
        || !valid_identifier(&request.task_id)
        || !valid_identifier(&request.step_id)
    {
        return Err(CodeGenerationValidationError::InvalidIdentifier);
    }
    if !valid_revision(&request.source_revision) {
        return Err(CodeGenerationValidationError::InvalidSourceRevision);
    }
    if !registry
        .detect_path(&request.target_path)
        .iter()
        .any(|adapter| adapter.descriptor().id == request.language)
    {
        return Err(CodeGenerationValidationError::UnsupportedLanguage);
    }
    if request.instructions.trim().is_empty() {
        return Err(CodeGenerationValidationError::EmptyInstructions);
    }
    if !safe_relative_path(&request.target_path) {
        return Err(CodeGenerationValidationError::UnsafePath);
    }

    let target_exists = request
        .repository
        .files
        .iter()
        .any(|file| file.path == request.target_path);
    match request.operation {
        ChangeOperation::Create if target_exists => {
            return Err(CodeGenerationValidationError::TargetAlreadyExists);
        }
        ChangeOperation::Modify | ChangeOperation::Delete if !target_exists => {
            return Err(CodeGenerationValidationError::TargetDoesNotExist);
        }
        _ => {}
    }

    if request.evidence.is_empty() {
        return Err(CodeGenerationValidationError::MissingEvidence);
    }
    if request.evidence.len() > limits.max_context_items
        || request.instructions.len() > limits.max_patch_bytes
    {
        return Err(CodeGenerationValidationError::LimitExceeded);
    }
    let known_paths: Vec<_> = request
        .repository
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let mut total_bytes = request.instructions.len();
    for evidence in &request.evidence {
        if !safe_relative_path(&evidence.path) {
            return Err(CodeGenerationValidationError::UnsafePath);
        }
        if evidence.start_line == 0 || evidence.end_line < evidence.start_line {
            return Err(CodeGenerationValidationError::InvalidEvidenceRange);
        }
        if !known_paths.contains(&evidence.path.as_str()) {
            return Err(CodeGenerationValidationError::EvidenceNotInRepository);
        }
        if evidence.excerpt.trim().is_empty() || evidence.excerpt.len() > limits.max_patch_bytes {
            return Err(CodeGenerationValidationError::LimitExceeded);
        }
        total_bytes = total_bytes.saturating_add(evidence.excerpt.len());
    }
    for constraint in &request.constraints {
        if constraint.trim().is_empty() || constraint.len() > limits.max_patch_bytes {
            return Err(CodeGenerationValidationError::LimitExceeded);
        }
        total_bytes = total_bytes.saturating_add(constraint.len());
    }
    if total_bytes > limits.max_total_bytes {
        return Err(CodeGenerationValidationError::LimitExceeded);
    }
    Ok(())
}

fn validate_response(
    response: &CodeGenerationResponse,
    request: &CodeGenerationRequest<'_>,
    limits: CodeGenerationLimits,
) -> Result<(), CodeGenerationValidationError> {
    if response.request_id != request.request_id {
        return Err(CodeGenerationValidationError::MismatchedRequest);
    }
    if response.summary.trim().is_empty() || response.changes.is_empty() {
        return Err(CodeGenerationValidationError::EmptyResponse);
    }
    if response.changes.len() > limits.max_changes {
        return Err(CodeGenerationValidationError::LimitExceeded);
    }

    let mut targets = std::collections::BTreeSet::new();
    let mut total_bytes = response.summary.len();
    for change in &response.changes {
        if !safe_relative_path(&change.path) {
            return Err(CodeGenerationValidationError::UnsafePath);
        }
        if !targets.insert(change.path.as_str()) {
            return Err(CodeGenerationValidationError::DuplicateTarget);
        }
        if change.path != request.target_path || change.operation != request.operation {
            return Err(CodeGenerationValidationError::OperationMismatch);
        }
        if change.rationale.trim().is_empty() || change.unified_diff.trim().is_empty() {
            return Err(CodeGenerationValidationError::EmptyResponse);
        }
        if change.unified_diff.len() > limits.max_patch_bytes {
            return Err(CodeGenerationValidationError::LimitExceeded);
        }
        if !valid_unified_diff(change) {
            return Err(CodeGenerationValidationError::InvalidPatchHeader);
        }
        total_bytes = total_bytes
            .saturating_add(change.rationale.len())
            .saturating_add(change.unified_diff.len());
    }
    for diagnostic in &response.diagnostics {
        total_bytes = total_bytes.saturating_add(diagnostic.len());
    }
    if total_bytes > limits.max_total_bytes {
        return Err(CodeGenerationValidationError::LimitExceeded);
    }
    Ok(())
}

fn valid_unified_diff(change: &GeneratedChange) -> bool {
    let lines: Vec<_> = change.unified_diff.lines().collect();
    let expected_git_header = format!("diff --git a/{0} b/{0}", change.path);
    let git_headers: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("diff --git "))
        .collect();
    let old_headers: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("--- "))
        .collect();
    let new_headers: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("+++ "))
        .collect();
    if git_headers.len() != 1
        || git_headers[0].as_str() != expected_git_header
        || old_headers.len() != 1
        || new_headers.len() != 1
        || change.unified_diff.contains('\0')
    {
        return false;
    }

    let old_header = old_headers[0].as_str();
    let new_header = new_headers[0].as_str();
    let expected_old = match change.operation {
        ChangeOperation::Create => "--- /dev/null",
        ChangeOperation::Modify | ChangeOperation::Delete => {
            return old_header == format!("--- a/{}", change.path)
                && valid_new_header(new_header, change);
        }
    };
    old_header == expected_old && valid_new_header(new_header, change)
}

fn valid_new_header(header: &str, change: &GeneratedChange) -> bool {
    let expected = match change.operation {
        ChangeOperation::Delete => "+++ /dev/null".to_owned(),
        ChangeOperation::Create | ChangeOperation::Modify => {
            format!("+++ b/{}", change.path)
        }
    };
    header == expected
        && change
            .unified_diff
            .lines()
            .any(|line| line.starts_with("@@"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{FileRecord, FileRole};
    use crate::{ExtensionAdapter, LanguageCapabilities, LanguageDescriptor};

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

    fn repository() -> RepositoryIndex {
        RepositoryIndex {
            files: vec![FileRecord {
                path: "src/lib.rs".to_owned(),
                size_bytes: 20,
                role: FileRole::Source,
                languages: Vec::new(),
            }],
            ..RepositoryIndex::default()
        }
    }

    fn request<'a>(repository: &'a RepositoryIndex) -> CodeGenerationRequest<'a> {
        CodeGenerationRequest {
            request_id: "request-1".to_owned(),
            task_id: "task-1".to_owned(),
            step_id: "edit-1".to_owned(),
            source_revision: "a".repeat(40),
            language: LanguageId::new("rust").expect("language id"),
            target_path: "src/lib.rs".to_owned(),
            operation: ChangeOperation::Modify,
            instructions: "Add a helper function".to_owned(),
            repository,
            evidence: vec![EvidenceSnippet {
                path: "src/lib.rs".to_owned(),
                start_line: 1,
                end_line: 2,
                excerpt: "pub fn existing() {}".to_owned(),
            }],
            constraints: vec!["Do not change public APIs".to_owned()],
        }
    }

    fn response() -> CodeGenerationResponse {
        CodeGenerationResponse {
            request_id: "request-1".to_owned(),
            summary: "Add a helper function".to_owned(),
            changes: vec![GeneratedChange {
                path: "src/lib.rs".to_owned(),
                operation: ChangeOperation::Modify,
                unified_diff: "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,2 @@\n pub fn existing() {}\n+pub fn added() {}\n".to_owned(),
                rationale: "The helper is additive".to_owned(),
            }],
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn accepts_bounded_structured_patch_proposal() {
        let repository = repository();
        let request = request(&repository);
        let provider = FixtureProvider {
            response: response(),
        };
        let result = CodeGenerator::new(CodeGenerationLimits::default())
            .generate(&provider, &request, &registry())
            .expect("valid patch proposal");
        assert_eq!(result.response().changes.len(), 1);
    }

    #[test]
    fn rejects_mismatched_request_identifier() {
        let repository = repository();
        let request = request(&repository);
        let mut invalid = response();
        invalid.request_id = "another-request".to_owned();
        let provider = FixtureProvider { response: invalid };
        assert_eq!(
            CodeGenerator::new(CodeGenerationLimits::default()).generate(
                &provider,
                &request,
                &registry()
            ),
            Err(CodeGenerationError::InvalidResponse(
                CodeGenerationValidationError::MismatchedRequest
            ))
        );
    }

    #[test]
    fn rejects_create_for_existing_path_and_unsupported_language() {
        let repository = repository();
        let mut request = request(&repository);
        request.operation = ChangeOperation::Create;
        let provider = FixtureProvider {
            response: response(),
        };
        assert_eq!(
            CodeGenerator::new(CodeGenerationLimits::default()).generate(
                &provider,
                &request,
                &registry()
            ),
            Err(CodeGenerationError::InvalidRequest(
                CodeGenerationValidationError::TargetAlreadyExists
            ))
        );

        request.operation = ChangeOperation::Modify;
        request.language = LanguageId::new("future-language").expect("language id");
        assert_eq!(
            CodeGenerator::new(CodeGenerationLimits::default()).generate(
                &provider,
                &request,
                &registry()
            ),
            Err(CodeGenerationError::InvalidRequest(
                CodeGenerationValidationError::UnsupportedLanguage
            ))
        );
    }

    #[test]
    fn rejects_multi_file_patch_payloads() {
        let repository = repository();
        let request = request(&repository);
        let mut invalid = response();
        invalid.changes[0].unified_diff.push_str(
            "diff --git a/other.rs b/other.rs\n--- a/other.rs\n+++ b/other.rs\n@@ -1 +1 @@\n-old\n+new\n",
        );
        let provider = FixtureProvider { response: invalid };
        assert_eq!(
            CodeGenerator::new(CodeGenerationLimits::default()).generate(
                &provider,
                &request,
                &registry()
            ),
            Err(CodeGenerationError::InvalidResponse(
                CodeGenerationValidationError::InvalidPatchHeader
            ))
        );
    }

    #[test]
    fn rejects_unsafe_generated_paths_and_malformed_diff_headers() {
        let repository = repository();
        let request = request(&repository);
        let mut invalid = response();
        invalid.changes[0].path = "../outside.rs".to_owned();
        let provider = FixtureProvider { response: invalid };
        assert_eq!(
            CodeGenerator::new(CodeGenerationLimits::default()).generate(
                &provider,
                &request,
                &registry()
            ),
            Err(CodeGenerationError::InvalidResponse(
                CodeGenerationValidationError::UnsafePath
            ))
        );

        let mut invalid = response();
        invalid.changes[0].unified_diff = "not a diff".to_owned();
        let provider = FixtureProvider { response: invalid };
        assert_eq!(
            CodeGenerator::new(CodeGenerationLimits::default()).generate(
                &provider,
                &request,
                &registry()
            ),
            Err(CodeGenerationError::InvalidResponse(
                CodeGenerationValidationError::InvalidPatchHeader
            ))
        );
    }
}
