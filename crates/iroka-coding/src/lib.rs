//! Language-neutral foundation for IROKA coding intelligence.
//!
//! New and future languages are integrated through adapters. Repository
//! analysis is bounded and static; it does not execute project content.

pub mod codegen;
pub mod index;
pub mod lockfile;
pub mod planner;
pub mod snapshot;

use std::collections::BTreeMap;
use std::fmt;

/// Stable, provider-neutral identifier for a programming language.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct LanguageId(String);

impl LanguageId {
    pub fn new(value: impl Into<String>) -> Result<Self, RegistryError> {
        let value = value.into().to_ascii_lowercase();
        let valid = !value.is_empty()
            && value.len() <= 64
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(RegistryError::InvalidLanguageId)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LanguageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Capabilities an adapter actually implements. Recognition alone grants none.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LanguageCapabilities {
    pub syntax_analysis: bool,
    pub semantic_analysis: bool,
    pub formatting: bool,
    pub compilation: bool,
    pub execution: bool,
    pub debugging: bool,
    pub testing: bool,
}

/// Immutable metadata exposed by a registered language adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanguageDescriptor {
    pub id: LanguageId,
    pub display_name: String,
    pub file_extensions: Vec<String>,
    pub capabilities: LanguageCapabilities,
}

/// Adapter boundary for existing and future programming languages.
pub trait LanguageAdapter: Send + Sync {
    fn descriptor(&self) -> LanguageDescriptor;

    /// Deterministic, side-effect-free path recognition.
    fn recognizes_path(&self, path: &str) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    InvalidLanguageId,
    DuplicateLanguage(LanguageId),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLanguageId => formatter.write_str("invalid language identifier"),
            Self::DuplicateLanguage(id) => {
                write!(formatter, "language adapter already registered: {id}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// Runtime-extensible registry. It has no closed list of supported languages.
#[derive(Default)]
pub struct LanguageRegistry {
    adapters: BTreeMap<LanguageId, Box<dyn LanguageAdapter>>,
}

impl LanguageRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, adapter: Box<dyn LanguageAdapter>) -> Result<(), RegistryError> {
        let id = adapter.descriptor().id;
        if self.adapters.contains_key(&id) {
            return Err(RegistryError::DuplicateLanguage(id));
        }
        self.adapters.insert(id, adapter);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: &LanguageId) -> Option<&dyn LanguageAdapter> {
        self.adapters.get(id).map(Box::as_ref)
    }

    #[must_use]
    pub fn detect_path(&self, path: &str) -> Vec<&dyn LanguageAdapter> {
        self.adapters
            .values()
            .filter(|adapter| adapter.recognizes_path(path))
            .map(Box::as_ref)
            .collect()
    }

    #[must_use]
    pub fn language_ids(&self) -> Vec<LanguageId> {
        self.adapters.keys().cloned().collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }
}

/// Bootstrap adapter for file-type recognition only. It makes no claim to
/// parse, compile, execute or debug the language.
pub struct ExtensionAdapter {
    descriptor: LanguageDescriptor,
}

impl ExtensionAdapter {
    #[must_use]
    pub fn new(descriptor: LanguageDescriptor) -> Self {
        Self { descriptor }
    }
}

impl LanguageAdapter for ExtensionAdapter {
    fn descriptor(&self) -> LanguageDescriptor {
        self.descriptor.clone()
    }

    fn recognizes_path(&self, path: &str) -> bool {
        let Some((_, extension)) = path.rsplit_once('.') else {
            return false;
        };
        self.descriptor.file_extensions.iter().any(|candidate| {
            candidate
                .trim_start_matches('.')
                .eq_ignore_ascii_case(extension)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str, extension: &str) -> LanguageDescriptor {
        LanguageDescriptor {
            id: LanguageId::new(id).expect("valid test language id"),
            display_name: id.to_owned(),
            file_extensions: vec![extension.to_owned()],
            capabilities: LanguageCapabilities::default(),
        }
    }

    #[test]
    fn language_ids_are_normalized_and_future_friendly() {
        let id = LanguageId::new("Future.Lang_2").expect("valid identifier");
        assert_eq!(id.as_str(), "future.lang_2");
        assert!(LanguageId::new("../escape").is_err());
        assert!(LanguageId::new("").is_err());
    }

    #[test]
    fn registry_accepts_new_languages_without_enum_changes() {
        let mut registry = LanguageRegistry::new();
        let future = ExtensionAdapter::new(descriptor("future-lang", "flg"));
        registry
            .register(Box::new(future))
            .expect("registration succeeds");
        let id = LanguageId::new("future-lang").expect("valid identifier");
        assert!(registry.get(&id).is_some());
        assert_eq!(registry.detect_path("src/module.flg").len(), 1);
    }

    #[test]
    fn registry_rejects_duplicate_language_ids() {
        let mut registry = LanguageRegistry::new();
        registry
            .register(Box::new(ExtensionAdapter::new(descriptor("rust", "rs"))))
            .expect("first registration succeeds");
        let result = registry.register(Box::new(ExtensionAdapter::new(descriptor("RUST", "rs"))));
        assert!(matches!(result, Err(RegistryError::DuplicateLanguage(_))));
    }

    #[test]
    fn extension_detection_is_case_insensitive_and_path_safe() {
        let mut registry = LanguageRegistry::new();
        registry
            .register(Box::new(ExtensionAdapter::new(descriptor("python", "py"))))
            .expect("registration succeeds");
        assert_eq!(registry.detect_path("src/MAIN.PY").len(), 1);
        assert!(registry.detect_path("src/no_extension").is_empty());
        assert!(registry.detect_path("src/file.py/child").is_empty());
    }

    #[test]
    fn recognition_does_not_claim_unimplemented_capabilities() {
        let adapter = ExtensionAdapter::new(descriptor("rust", "rs"));
        let capabilities = adapter.descriptor().capabilities;
        assert!(!capabilities.compilation);
        assert!(!capabilities.execution);
        assert!(!capabilities.debugging);
        assert!(!capabilities.testing);
    }
}
