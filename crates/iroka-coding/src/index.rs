//! Bounded, deterministic repository indexing and static project analysis.
//!
//! This module analyzes caller-provided or filesystem-collected snapshots.
//! It does not execute manifests, invoke package managers, install packages,
//! resolve versions through a registry, or access the network. Unsupported
//! manifest and lockfile formats are reported as partial analysis.

use std::collections::BTreeSet;
use std::fmt;

use crate::lockfile::{analyze_lockfile, ResolvedDependency};
use crate::{LanguageId, LanguageRegistry};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexLimits {
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_files: 20_000,
            max_file_bytes: 2 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
}

/// A file supplied by a trusted snapshot collector. Symlinks are rejected,
/// rather than followed, to keep the index within the repository boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotFile {
    pub path: String,
    pub content: String,
    pub is_symlink: bool,
}

impl SnapshotFile {
    #[must_use]
    pub fn new(path: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            content: content.into(),
            is_symlink: false,
        }
    }

    #[must_use]
    pub fn symlink(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            content: String::new(),
            is_symlink: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRole {
    Source,
    Manifest,
    Lockfile,
    Documentation,
    Configuration,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProjectKind {
    Cargo,
    NodePackage,
    PythonProject,
    PythonRequirements,
    GoModule,
    Maven,
    Gradle,
    Composer,
    CMake,
    RubyBundle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceConfidence {
    ExactPattern,
    Heuristic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileRecord {
    pub path: String,
    pub size_bytes: usize,
    pub role: FileRole,
    pub languages: Vec<LanguageId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyDeclaration {
    pub name: String,
    pub requirement: Option<String>,
    pub manifest_path: String,
    pub section: String,
    pub confidence: EvidenceConfidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectManifest {
    pub path: String,
    pub kind: ProjectKind,
    pub package_name: Option<String>,
    pub declared_dependencies: Vec<DependencyDeclaration>,
    /// True when the manifest parser intentionally skipped unsupported syntax.
    pub analysis_partial: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexIssueKind {
    UnsafePath,
    SymlinkSkipped,
    DuplicatePath,
    FileLimitExceeded,
    FileTooLarge,
    TotalSizeLimitExceeded,
    UnsupportedManifestSyntax,
    UnsupportedLockfileSyntax,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexIssue {
    pub path: Option<String>,
    pub kind: IndexIssueKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexError {
    InvalidLimits,
}

impl fmt::Display for IndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("repository index limits must be non-zero"),
        }
    }
}

impl std::error::Error for IndexError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepositoryIndex {
    pub files: Vec<FileRecord>,
    pub projects: Vec<ProjectManifest>,
    pub issues: Vec<IndexIssue>,
    pub resolved_dependencies: Vec<ResolvedDependency>,
    pub dependency_analysis_partial: bool,
    pub total_bytes: usize,
}

impl RepositoryIndex {
    pub fn build(
        snapshot: impl IntoIterator<Item = SnapshotFile>,
        registry: &LanguageRegistry,
        limits: IndexLimits,
    ) -> Result<Self, IndexError> {
        if limits.max_files == 0 || limits.max_file_bytes == 0 || limits.max_total_bytes == 0 {
            return Err(IndexError::InvalidLimits);
        }

        let mut index = Self::default();
        let mut seen = BTreeSet::new();

        for file in snapshot {
            if file.is_symlink {
                index.issues.push(IndexIssue {
                    path: Some(file.path),
                    kind: IndexIssueKind::SymlinkSkipped,
                });
                continue;
            }

            if !is_safe_relative_path(&file.path) {
                index.issues.push(IndexIssue {
                    path: Some(file.path),
                    kind: IndexIssueKind::UnsafePath,
                });
                continue;
            }

            if !seen.insert(file.path.clone()) {
                index.issues.push(IndexIssue {
                    path: Some(file.path),
                    kind: IndexIssueKind::DuplicatePath,
                });
                continue;
            }

            if index.files.len() >= limits.max_files {
                index.issues.push(IndexIssue {
                    path: Some(file.path),
                    kind: IndexIssueKind::FileLimitExceeded,
                });
                break;
            }

            let size_bytes = file.content.len();
            if size_bytes > limits.max_file_bytes {
                index.issues.push(IndexIssue {
                    path: Some(file.path),
                    kind: IndexIssueKind::FileTooLarge,
                });
                continue;
            }

            if index.total_bytes.saturating_add(size_bytes) > limits.max_total_bytes {
                index.issues.push(IndexIssue {
                    path: Some(file.path),
                    kind: IndexIssueKind::TotalSizeLimitExceeded,
                });
                break;
            }

            index.total_bytes += size_bytes;
            let role = classify_role(&file.path);
            if role == FileRole::Lockfile {
                let analysis = analyze_lockfile(&file.path, &file.content);
                if analysis.analysis_partial {
                    index.dependency_analysis_partial = true;
                    index.issues.push(IndexIssue {
                        path: Some(file.path.clone()),
                        kind: IndexIssueKind::UnsupportedLockfileSyntax,
                    });
                }
                index.resolved_dependencies.extend(analysis.packages);
            }
            let languages = registry
                .detect_path(&file.path)
                .into_iter()
                .map(|adapter| adapter.descriptor().id)
                .collect();

            if let Some(kind) = manifest_kind(&file.path) {
                let manifest = analyze_manifest(
                    &file.path,
                    kind,
                    &file.content,
                    &mut index.issues,
                );
                index.dependency_analysis_partial |= manifest.analysis_partial;
                index.projects.push(manifest);
            }

            index.files.push(FileRecord {
                path: file.path,
                size_bytes,
                role,
                languages,
            });
        }

        index
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        index.resolved_dependencies.sort_by(|left, right| {
            left.package_id.cmp(&right.package_id)
        });
        index
            .projects
            .sort_by(|left, right| left.path.cmp(&right.path));
        index
            .issues
            .sort_by(|left, right| left.path.cmp(&right.path));
        Ok(index)
    }

    #[must_use]
    pub fn dependency_count(&self) -> usize {
        self.projects
            .iter()
            .map(|project| project.declared_dependencies.len())
            .sum()
    }

    #[must_use]
    pub fn resolved_dependency_count(&self) -> usize {
        self.resolved_dependencies.len()
    }

    #[must_use]
    pub fn project_kinds(&self) -> Vec<ProjectKind> {
        let mut kinds = self
            .projects
            .iter()
            .map(|project| project.kind)
            .collect::<Vec<_>>();
        kinds.sort();
        kinds.dedup();
        kinds
    }
}

fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }

    path.split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn classify_role(path: &str) -> FileRole {
    let name = path.rsplit('/').next().unwrap_or(path);
    if manifest_kind(path).is_some() {
        FileRole::Manifest
    } else if matches!(
        name,
        "Cargo.lock"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "poetry.lock"
            | "Pipfile.lock"
            | "go.sum"
            | "composer.lock"
            | "Gemfile.lock"
    ) {
        FileRole::Lockfile
    } else if name.ends_with(".md") || name.ends_with(".rst") || name.ends_with(".adoc") {
        FileRole::Documentation
    } else if name.ends_with(".toml")
        || name.ends_with(".yaml")
        || name.ends_with(".yml")
        || name.ends_with(".json")
        || name.ends_with(".xml")
        || name.ends_with(".ini")
    {
        FileRole::Configuration
    } else {
        FileRole::Source
    }
}

fn manifest_kind(path: &str) -> Option<ProjectKind> {
    let name = path.rsplit('/').next()?;
    match name {
        "Cargo.toml" => Some(ProjectKind::Cargo),
        "package.json" => Some(ProjectKind::NodePackage),
        "pyproject.toml" => Some(ProjectKind::PythonProject),
        "requirements.txt" => Some(ProjectKind::PythonRequirements),
        "go.mod" => Some(ProjectKind::GoModule),
        "pom.xml" => Some(ProjectKind::Maven),
        "build.gradle" | "build.gradle.kts" => Some(ProjectKind::Gradle),
        "composer.json" => Some(ProjectKind::Composer),
        "CMakeLists.txt" => Some(ProjectKind::CMake),
        "Gemfile" => Some(ProjectKind::RubyBundle),
        _ => None,
    }
}

fn analyze_manifest(
    path: &str,
    kind: ProjectKind,
    content: &str,
    issues: &mut Vec<IndexIssue>,
) -> ProjectManifest {
    let mut manifest = ProjectManifest {
        path: path.to_owned(),
        kind,
        package_name: None,
        declared_dependencies: Vec::new(),
        analysis_partial: false,
    };

    match kind {
        ProjectKind::Cargo => parse_cargo(path, content, &mut manifest),
        ProjectKind::NodePackage => parse_json_dependency_lines(
            path,
            content,
            &mut manifest,
            &[
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ],
        ),
        ProjectKind::PythonProject => parse_pyproject(path, content, &mut manifest),
        ProjectKind::PythonRequirements => parse_requirements(path, content, &mut manifest),
        ProjectKind::GoModule => parse_go_mod(path, content, &mut manifest),
        ProjectKind::RubyBundle => parse_gemfile(path, content, &mut manifest),
        ProjectKind::Maven | ProjectKind::Gradle | ProjectKind::Composer | ProjectKind::CMake => {
            manifest.analysis_partial = true;
        }
    }

    if manifest.analysis_partial {
        issues.push(IndexIssue {
            path: Some(path.to_owned()),
            kind: IndexIssueKind::UnsupportedManifestSyntax,
        });
    }
    manifest
}

fn parse_cargo(path: &str, content: &str, manifest: &mut ProjectManifest) {
    let mut section = String::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_owned();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = unquote(key.trim());
            let value = value.trim();
            if section == "package" && key == "name" {
                manifest.package_name = Some(unquote(value).to_owned());
            } else if is_cargo_dependency_section(&section) && !key.is_empty() {
                let requirement = if value.starts_with('"') {
                    Some(unquote(value).to_owned())
                } else {
                    extract_inline_version(value)
                };
                manifest.declared_dependencies.push(DependencyDeclaration {
                    name: key.to_owned(),
                    requirement,
                    manifest_path: path.to_owned(),
                    section: section.clone(),
                    confidence: EvidenceConfidence::ExactPattern,
                });
            }
        }
    }
}

fn is_cargo_dependency_section(section: &str) -> bool {
    matches!(
        section,
        "dependencies" | "dev-dependencies" | "build-dependencies" | "workspace.dependencies"
    ) || (section.starts_with("target.") && section.ends_with(".dependencies"))
}

fn extract_inline_version(value: &str) -> Option<String> {
    let marker = "version";
    let (_, rest) = value.split_once(marker)?;
    let (_, value) = rest.split_once('=')?;
    let value = value.trim().trim_start_matches('"');
    let end = value.find('"')?;
    Some(value[..end].to_owned())
}

fn parse_json_dependency_lines(
    path: &str,
    content: &str,
    manifest: &mut ProjectManifest,
    sections: &[&str],
) {
    let mut active_section: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if active_section.is_none() {
            for section in sections {
                if trimmed.starts_with(&format!("\"{section}\"")) && trimmed.contains('{') {
                    active_section = Some((*section).to_owned());
                    break;
                }
            }
            if trimmed.starts_with("\"name\"") {
                manifest.package_name = json_string_value(trimmed);
            }
            continue;
        }

        if trimmed.starts_with('}') {
            active_section = None;
            continue;
        }

        if let Some(section) = &active_section {
            if let Some((key, value)) = trimmed.split_once(':') {
                let name = unquote(key.trim()).to_owned();
                let requirement = json_string_value(value.trim());
                if !name.is_empty() && requirement.is_some() {
                    manifest.declared_dependencies.push(DependencyDeclaration {
                        name,
                        requirement,
                        manifest_path: path.to_owned(),
                        section: section.clone(),
                        confidence: EvidenceConfidence::Heuristic,
                    });
                } else {
                    manifest.analysis_partial = true;
                }
            }
        }
    }
}

fn json_string_value(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches(',').trim();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        Some(unquote(value).to_owned())
    } else {
        None
    }
}

fn parse_pyproject(path: &str, content: &str, manifest: &mut ProjectManifest) {
    let mut section = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed[1..trimmed.len() - 1].to_owned();
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if section == "project" && key == "name" {
                manifest.package_name = Some(unquote(value).to_owned());
            } else if section == "tool.poetry.dependencies" && key != "python" {
                manifest.declared_dependencies.push(DependencyDeclaration {
                    name: key.to_owned(),
                    requirement: Some(unquote(value).to_owned()),
                    manifest_path: path.to_owned(),
                    section: section.clone(),
                    confidence: EvidenceConfidence::Heuristic,
                });
            } else if section == "project" && key == "dependencies" && value.starts_with('[') {
                let entries = value.trim_start_matches('[').trim_end_matches(']');
                for entry in entries
                    .split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                {
                    manifest.declared_dependencies.push(DependencyDeclaration {
                        name: distribution_name(entry),
                        requirement: Some(unquote(entry).to_owned()),
                        manifest_path: path.to_owned(),
                        section: section.clone(),
                        confidence: EvidenceConfidence::Heuristic,
                    });
                }
            }
        }
    }
}

fn distribution_name(requirement: &str) -> String {
    let requirement = unquote(requirement);
    requirement
        .split(['<', '>', '=', '!', '~', '[', ';'])
        .next()
        .unwrap_or(requirement)
        .trim()
        .to_owned()
}

fn parse_requirements(path: &str, content: &str, manifest: &mut ProjectManifest) {
    for line in content.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty()
            || trimmed.starts_with('-')
            || trimmed.starts_with("http:")
            || trimmed.starts_with("https:")
        {
            manifest.analysis_partial = true;
            continue;
        }
        let name = distribution_name(trimmed);
        if !name.is_empty() {
            manifest.declared_dependencies.push(DependencyDeclaration {
                name,
                requirement: Some(trimmed.to_owned()),
                manifest_path: path.to_owned(),
                section: "requirements".to_owned(),
                confidence: EvidenceConfidence::Heuristic,
            });
        }
    }
}

fn parse_go_mod(path: &str, content: &str, manifest: &mut ProjectManifest) {
    let mut in_require = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("module ") {
            manifest.package_name = Some(trimmed.trim_start_matches("module ").trim().to_owned());
        } else if trimmed == "require (" {
            in_require = true;
        } else if in_require && trimmed == ")" {
            in_require = false;
        } else if trimmed.starts_with("require ") || in_require {
            let entry = trimmed.trim_start_matches("require ").trim();
            let mut parts = entry.split_whitespace();
            if let (Some(name), Some(version)) = (parts.next(), parts.next()) {
                manifest.declared_dependencies.push(DependencyDeclaration {
                    name: name.to_owned(),
                    requirement: Some(version.to_owned()),
                    manifest_path: path.to_owned(),
                    section: "require".to_owned(),
                    confidence: EvidenceConfidence::ExactPattern,
                });
            }
        }
    }
}

fn parse_gemfile(path: &str, content: &str, manifest: &mut ProjectManifest) {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("gem ") {
            let name = rest.trim_start_matches(['\'', '"']);
            let name = name.split(['\'', '"', ',']).next().unwrap_or("").trim();
            if !name.is_empty() {
                manifest.declared_dependencies.push(DependencyDeclaration {
                    name: name.to_owned(),
                    requirement: None,
                    manifest_path: path.to_owned(),
                    section: "gem".to_owned(),
                    confidence: EvidenceConfidence::Heuristic,
                });
            }
        }
    }
}

fn unquote(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExtensionAdapter, LanguageCapabilities, LanguageDescriptor};

    fn registry() -> LanguageRegistry {
        let mut registry = LanguageRegistry::new();
        registry
            .register(Box::new(ExtensionAdapter::new(LanguageDescriptor {
                id: LanguageId::new("rust").expect("valid language id"),
                display_name: "Rust".to_owned(),
                file_extensions: vec!["rs".to_owned()],
                capabilities: LanguageCapabilities::default(),
            })))
            .expect("adapter registration");
        registry
    }

    fn build(files: Vec<SnapshotFile>) -> RepositoryIndex {
        RepositoryIndex::build(files, &registry(), IndexLimits::default()).expect("valid limits")
    }

    #[test]
    fn indexes_files_in_stable_order_and_detects_language() {
        let index = build(vec![
            SnapshotFile::new("src/main.rs", "fn main() {}"),
            SnapshotFile::new("README.md", "# project"),
        ]);
        assert_eq!(index.files[0].path, "README.md");
        assert_eq!(index.files[1].languages[0].as_str(), "rust");
        assert_eq!(index.files[0].role, FileRole::Documentation);
    }

    #[test]
    fn identifies_cargo_project_and_declared_dependencies() {
        let index = build(vec![SnapshotFile::new(
            "Cargo.toml",
            r#"[package]
name = "sample"
[dependencies]
serde = "1"
"#,
        )]);
        assert_eq!(index.projects[0].package_name.as_deref(), Some("sample"));
        assert_eq!(index.projects[0].declared_dependencies[0].name, "serde");
        assert_eq!(
            index.projects[0].declared_dependencies[0]
                .requirement
                .as_deref(),
            Some("1")
        );
    }

    #[test]
    fn detects_node_and_python_manifests() {
        let index = build(vec![
            SnapshotFile::new(
                "package.json",
                r#"{
  "name": "web",
  "dependencies": {
    "react": "^19"
  }
}"#,
            ),
            SnapshotFile::new("requirements.txt", "requests>=2\n"),
        ]);
        assert_eq!(index.projects.len(), 2);
        assert!(index
            .projects
            .iter()
            .any(|project| project.kind == ProjectKind::NodePackage));
        assert!(index
            .projects
            .iter()
            .any(|project| project.kind == ProjectKind::PythonRequirements));
        assert!(index.projects.iter().any(|project| project
            .declared_dependencies
            .iter()
            .any(|dep| dep.name == "react")));
        assert!(index.projects.iter().any(|project| project
            .declared_dependencies
            .iter()
            .any(|dep| dep.name == "requests")));
    }

    #[test]
    fn parses_go_module_requirements() {
        let index = build(vec![SnapshotFile::new(
            "go.mod",
            r#"module example.org/app
require (
 example.org/lib v1.2.3
)
"#,
        )]);
        assert_eq!(
            index.projects[0].package_name.as_deref(),
            Some("example.org/app")
        );
        assert_eq!(
            index.projects[0].declared_dependencies[0]
                .requirement
                .as_deref(),
            Some("v1.2.3")
        );
    }

    #[test]
    fn rejects_unsafe_paths_and_skips_symlinks() {
        let index = build(vec![
            SnapshotFile::new("../outside", "secret"),
            SnapshotFile::new("/absolute", "secret"),
            SnapshotFile::symlink("linked.rs"),
            SnapshotFile::new("safe.rs", "fn main() {}"),
        ]);
        assert_eq!(index.files.len(), 1);
        assert!(index
            .issues
            .iter()
            .any(|issue| issue.kind == IndexIssueKind::UnsafePath));
        assert!(index
            .issues
            .iter()
            .any(|issue| issue.kind == IndexIssueKind::SymlinkSkipped));
    }

    #[test]
    fn enforces_file_and_total_size_limits() {
        let limits = IndexLimits {
            max_files: 2,
            max_file_bytes: 4,
            max_total_bytes: 6,
        };
        let index = RepositoryIndex::build(
            vec![
                SnapshotFile::new("a.rs", "1234"),
                SnapshotFile::new("b.rs", "12345"),
                SnapshotFile::new("c.rs", "123"),
            ],
            &registry(),
            limits,
        )
        .expect("valid limits");
        assert!(index
            .issues
            .iter()
            .any(|issue| issue.kind == IndexIssueKind::FileTooLarge));
        assert!(index
            .issues
            .iter()
            .any(|issue| issue.kind == IndexIssueKind::TotalSizeLimitExceeded));
    }

    #[test]
    fn duplicate_paths_are_not_double_counted() {
        let index = build(vec![
            SnapshotFile::new("src/lib.rs", "one"),
            SnapshotFile::new("src/lib.rs", "two"),
        ]);
        assert_eq!(index.files.len(), 1);
        assert!(index
            .issues
            .iter()
            .any(|issue| issue.kind == IndexIssueKind::DuplicatePath));
    }

    #[test]
    fn integrates_resolved_cargo_lockfile_dependencies() {
        let index = build(vec![
            SnapshotFile::new(
                "Cargo.lock",
                r#"[[package]]
name = "serde"
version = "1.0.200"
dependencies = ["serde_core 1.0.200"]
"#,
            ),
        ]);
        assert_eq!(index.resolved_dependency_count(), 1);
        assert_eq!(index.resolved_dependencies[0].name, "serde");
        assert!(!index.dependency_analysis_partial);
    }

    #[test]
    fn unsupported_lockfiles_mark_dependency_analysis_partial() {
        let index = build(vec![SnapshotFile::new("yarn.lock", "# yarn lockfile")]);
        assert!(index.dependency_analysis_partial);
        assert!(index
            .issues
            .iter()
            .any(|issue| issue.kind == IndexIssueKind::UnsupportedLockfileSyntax));
    }

    #[test]
    fn unsupported_manifest_formats_are_reported_as_partial() {
        let index = build(vec![SnapshotFile::new("pom.xml", "<project/>")]);
        assert!(index.projects[0].analysis_partial);
        assert!(index
            .issues
            .iter()
            .any(|issue| issue.kind == IndexIssueKind::UnsupportedManifestSyntax));
    }
}
