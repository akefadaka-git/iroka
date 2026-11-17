//! Confined, read-only repository snapshot collection.
//!
//! Collection is deterministic and bounded. Symlinks and non-regular files are
//! never followed. The collector does not execute project code or invoke tools.

use std::fs;
use std::path::Path;

use crate::index::{IndexLimits, RepositoryIndex, SnapshotFile};
use crate::{index::IndexError, LanguageRegistry};

const MAX_DEPTH: usize = 128;
const IGNORED_DIRECTORIES: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".turbo",
    ".gradle",
    ".idea",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotIssueKind {
    SymlinkSkipped,
    NonRegularFileSkipped,
    IgnoredDirectory,
    FileTooLarge,
    TotalSizeLimitExceeded,
    FileLimitExceeded,
    NonUtf8FileSkipped,
    ReadError,
    UnsupportedIgnorePattern,
    DepthLimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotIssue {
    pub path: Option<String>,
    pub kind: SnapshotIssueKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotCollection {
    pub files: Vec<SnapshotFile>,
    pub issues: Vec<SnapshotIssue>,
    pub total_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    RootUnavailable,
    RootNotDirectory,
    InvalidLimits,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootUnavailable => formatter.write_str("repository root is unavailable"),
            Self::RootNotDirectory => formatter.write_str("repository root is not a directory"),
            Self::InvalidLimits => {
                formatter.write_str("repository snapshot limits must be non-zero")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Collect a bounded snapshot beneath a repository root without following symlinks.
///
/// Root .gitignore literal path rules are honored. Glob, negation, and nested-ignore
/// syntax is reported as unsupported rather than guessed.
pub fn collect_snapshot(
    root: impl AsRef<Path>,
    limits: IndexLimits,
) -> Result<SnapshotCollection, SnapshotError> {
    if limits.max_files == 0 || limits.max_file_bytes == 0 || limits.max_total_bytes == 0 {
        return Err(SnapshotError::InvalidLimits);
    }
    let root = fs::canonicalize(root).map_err(|_| SnapshotError::RootUnavailable)?;
    if !root.is_dir() {
        return Err(SnapshotError::RootNotDirectory);
    }

    let (ignore_rules, mut issues) = load_root_ignore_rules(&root);
    let mut collection = SnapshotCollection {
        files: Vec::new(),
        issues: Vec::new(),
        total_bytes: 0,
    };
    collection.issues.append(&mut issues);
    walk_directory(&root, &root, 0, &ignore_rules, limits, &mut collection);
    collection
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    collection.issues.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| format!("{:?}", left.kind).cmp(&format!("{:?}", right.kind)))
    });
    Ok(collection)
}

/// Collect and statically analyze a workspace in one operation.
pub fn analyze_workspace(
    root: impl AsRef<Path>,
    registry: &LanguageRegistry,
    limits: IndexLimits,
) -> Result<WorkspaceAnalysis, WorkspaceAnalysisError> {
    let snapshot = collect_snapshot(root, limits).map_err(WorkspaceAnalysisError::Snapshot)?;
    let index = RepositoryIndex::build(snapshot.files, registry, limits)
        .map_err(WorkspaceAnalysisError::Index)?;
    Ok(WorkspaceAnalysis {
        index,
        collection_issues: snapshot.issues,
        collected_bytes: snapshot.total_bytes,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceAnalysis {
    pub index: RepositoryIndex,
    pub collection_issues: Vec<SnapshotIssue>,
    pub collected_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceAnalysisError {
    Snapshot(SnapshotError),
    Index(IndexError),
}

impl std::fmt::Display for WorkspaceAnalysisError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Snapshot(error) => write!(formatter, "snapshot collection failed: {error}"),
            Self::Index(error) => write!(formatter, "repository indexing failed: {error}"),
        }
    }
}

impl std::error::Error for WorkspaceAnalysisError {}

fn walk_directory(
    root: &Path,
    directory: &Path,
    depth: usize,
    ignore_rules: &[String],
    limits: IndexLimits,
    collection: &mut SnapshotCollection,
) {
    if depth > MAX_DEPTH {
        collection.issues.push(SnapshotIssue {
            path: relative_path(root, directory),
            kind: SnapshotIssueKind::DepthLimitExceeded,
        });
        return;
    }
    let directory_entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => {
            collection.issues.push(SnapshotIssue {
                path: relative_path(root, directory),
                kind: SnapshotIssueKind::ReadError,
            });
            return;
        }
    };
    let mut entries: Vec<std::fs::DirEntry> = Vec::new();
    for entry in directory_entries {
        match entry {
            Ok(entry) => entries.push(entry),
            Err(_) => collection.issues.push(SnapshotIssue {
                path: relative_path(root, directory),
                kind: SnapshotIssueKind::ReadError,
            }),
        }
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let Some(relative) = relative_path(root, &path) else {
            collection.issues.push(SnapshotIssue {
                path: None,
                kind: SnapshotIssueKind::ReadError,
            });
            continue;
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                collection.issues.push(SnapshotIssue {
                    path: Some(relative),
                    kind: SnapshotIssueKind::ReadError,
                });
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            collection.issues.push(SnapshotIssue {
                path: Some(relative),
                kind: SnapshotIssueKind::SymlinkSkipped,
            });
            continue;
        }
        if metadata.is_dir() {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if IGNORED_DIRECTORIES.contains(&name) || is_ignored(&relative, ignore_rules) {
                collection.issues.push(SnapshotIssue {
                    path: Some(relative),
                    kind: SnapshotIssueKind::IgnoredDirectory,
                });
                continue;
            }
            walk_directory(root, &path, depth + 1, ignore_rules, limits, collection);
            if collection
                .issues
                .iter()
                .any(|issue| issue.kind == SnapshotIssueKind::TotalSizeLimitExceeded)
            {
                return;
            }
            continue;
        }
        if !metadata.is_file() {
            collection.issues.push(SnapshotIssue {
                path: Some(relative),
                kind: SnapshotIssueKind::NonRegularFileSkipped,
            });
            continue;
        }
        if is_ignored(&relative, ignore_rules) {
            continue;
        }
        if collection.files.len() >= limits.max_files {
            collection.issues.push(SnapshotIssue {
                path: Some(relative),
                kind: SnapshotIssueKind::FileLimitExceeded,
            });
            return;
        }
        if metadata.len() > limits.max_file_bytes as u64 {
            collection.issues.push(SnapshotIssue {
                path: Some(relative),
                kind: SnapshotIssueKind::FileTooLarge,
            });
            continue;
        }
        let canonical = match fs::canonicalize(&path) {
            Ok(canonical) if canonical.starts_with(root) => canonical,
            _ => {
                collection.issues.push(SnapshotIssue {
                    path: Some(relative),
                    kind: SnapshotIssueKind::SymlinkSkipped,
                });
                continue;
            }
        };
        let content = match fs::read_to_string(&canonical) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                collection.issues.push(SnapshotIssue {
                    path: Some(relative),
                    kind: SnapshotIssueKind::NonUtf8FileSkipped,
                });
                continue;
            }
            Err(_) => {
                collection.issues.push(SnapshotIssue {
                    path: Some(relative),
                    kind: SnapshotIssueKind::ReadError,
                });
                continue;
            }
        };
        let size = content.len();
        if size > limits.max_file_bytes {
            collection.issues.push(SnapshotIssue {
                path: Some(relative),
                kind: SnapshotIssueKind::FileTooLarge,
            });
            continue;
        }
        if collection.total_bytes.saturating_add(size) > limits.max_total_bytes {
            collection.issues.push(SnapshotIssue {
                path: Some(relative),
                kind: SnapshotIssueKind::TotalSizeLimitExceeded,
            });
            return;
        }
        collection.total_bytes += size;
        collection.files.push(SnapshotFile::new(relative, content));
    }
}

fn relative_path(root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .map(|value| value.replace('\\', "/"))
}

fn load_root_ignore_rules(root: &Path) -> (Vec<String>, Vec<SnapshotIssue>) {
    let content = match fs::read_to_string(root.join(".gitignore")) {
        Ok(content) => content,
        Err(_) => return (Vec::new(), Vec::new()),
    };
    let mut rules = Vec::new();
    let mut issues = Vec::new();
    for (line_number, line) in content.lines().enumerate() {
        let rule = line.trim();
        if rule.is_empty() || rule.starts_with('#') {
            continue;
        }
        if rule.starts_with('!') || rule.contains('*') || rule.contains('?') || rule.contains('[') {
            issues.push(SnapshotIssue {
                path: Some(format!(".gitignore:{}", line_number + 1)),
                kind: SnapshotIssueKind::UnsupportedIgnorePattern,
            });
            continue;
        }
        rules.push(
            rule.trim_start_matches('/')
                .trim_end_matches('/')
                .to_owned(),
        );
    }
    (rules, issues)
}

fn is_ignored(path: &str, rules: &[String]) -> bool {
    rules.iter().any(|rule| {
        path == rule
            || path
                .strip_prefix(rule)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("iroka-snapshot-{nonce}"));
        fs::create_dir_all(&root).expect("create test root");
        root
    }

    #[test]
    fn collects_in_stable_order_and_skips_build_outputs() {
        let root = temp_root();
        fs::create_dir_all(root.join("src")).expect("create source dir");
        fs::create_dir_all(root.join("target")).expect("create target dir");
        fs::write(root.join("src/z.rs"), "z").expect("write z");
        fs::write(root.join("src/a.rs"), "a").expect("write a");
        fs::write(root.join("target/ignored.rs"), "ignored").expect("write ignored");
        let result = collect_snapshot(&root, IndexLimits::default()).expect("collect");
        assert_eq!(
            result
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            vec!["src/a.rs", "src/z.rs"]
        );
        assert!(result
            .issues
            .iter()
            .any(|issue| issue.kind == SnapshotIssueKind::IgnoredDirectory));
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn honors_literal_ignore_rules_and_reports_unsupported_globs() {
        let root = temp_root();
        fs::write(root.join(".gitignore"), "secrets\n*.tmp\n").expect("write ignore");
        fs::write(root.join("secrets"), "hidden").expect("write ignored");
        fs::write(root.join("visible.rs"), "visible").expect("write visible");
        let result = collect_snapshot(&root, IndexLimits::default()).expect("collect");
        assert!(!result.files.iter().any(|file| file.path == "secrets"));
        assert!(result.files.iter().any(|file| file.path == "visible.rs"));
        assert!(result
            .issues
            .iter()
            .any(|issue| issue.kind == SnapshotIssueKind::UnsupportedIgnorePattern));
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn enforces_per_file_size_limit() {
        let root = temp_root();
        fs::write(root.join("large.rs"), "12345").expect("write large");
        let limits = IndexLimits {
            max_files: 5,
            max_file_bytes: 4,
            max_total_bytes: 4,
        };
        let result = collect_snapshot(&root, limits).expect("collect");
        assert!(result.files.is_empty());
        assert!(result
            .issues
            .iter()
            .any(|issue| issue.kind == SnapshotIssueKind::FileTooLarge));
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn enforces_file_count_and_aggregate_byte_limits() {
        let root = temp_root();
        fs::write(root.join("a.rs"), "123").expect("write first");
        fs::write(root.join("b.rs"), "456").expect("write second");

        let byte_limited = IndexLimits {
            max_files: 5,
            max_file_bytes: 4,
            max_total_bytes: 4,
        };
        let byte_result = collect_snapshot(&root, byte_limited).expect("collect");
        assert_eq!(byte_result.files.len(), 1);
        assert!(byte_result
            .issues
            .iter()
            .any(|issue| issue.kind == SnapshotIssueKind::TotalSizeLimitExceeded));

        let file_limited = IndexLimits {
            max_files: 1,
            max_file_bytes: 4,
            max_total_bytes: 10,
        };
        let file_result = collect_snapshot(&root, file_limited).expect("collect");
        assert_eq!(file_result.files.len(), 1);
        assert!(file_result
            .issues
            .iter()
            .any(|issue| issue.kind == SnapshotIssueKind::FileLimitExceeded));

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn never_follows_file_symlinks() {
        use std::os::unix::fs::symlink;
        let root = temp_root();
        let outside = root
            .parent()
            .expect("temp parent")
            .join("iroka-outside-secret");
        fs::write(&outside, "secret").expect("write outside");
        symlink(&outside, root.join("linked.rs")).expect("create symlink");
        let result = collect_snapshot(&root, IndexLimits::default()).expect("collect");
        assert!(result.files.is_empty());
        assert!(result
            .issues
            .iter()
            .any(|issue| issue.kind == SnapshotIssueKind::SymlinkSkipped));
        fs::remove_file(root.join("linked.rs")).expect("remove symlink");
        fs::remove_dir_all(root).expect("remove test root");
        fs::remove_file(outside).expect("remove outside");
    }

    #[test]
    fn rejects_file_roots_and_zero_limits() {
        let root = temp_root();
        let file = root.join("file");
        fs::write(&file, "x").expect("write file");
        assert_eq!(
            collect_snapshot(&file, IndexLimits::default()),
            Err(SnapshotError::RootNotDirectory)
        );
        let invalid = IndexLimits {
            max_files: 0,
            ..IndexLimits::default()
        };
        assert_eq!(
            collect_snapshot(&root, invalid),
            Err(SnapshotError::InvalidLimits)
        );
        fs::remove_dir_all(root).expect("remove test root");
    }
}
