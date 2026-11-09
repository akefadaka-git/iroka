//! Static dependency resolution extracted from supported lockfiles.
//!
//! Lockfile parsing is local-only: it never invokes package managers or the network.
//! Unsupported lockfile formats are reported as partial rather than guessed.

use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedDependency {
    /// Stable within the source lockfile (Cargo package identity or npm package path).
    pub package_id: String,
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<String>,
    /// Dependency references as represented by the lockfile.
    pub dependencies: Vec<String>,
    pub lockfile_path: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LockfileAnalysis {
    pub packages: Vec<ResolvedDependency>,
    pub analysis_partial: bool,
}

/// Parse supported lockfiles; unknown formats are explicitly marked partial.
pub fn analyze_lockfile(path: &str, content: &str) -> LockfileAnalysis {
    match path.rsplit('/').next().unwrap_or(path) {
        "Cargo.lock" => parse_cargo_lock(path, content),
        "package-lock.json" | "npm-shrinkwrap.json" => parse_npm_lock(path, content),
        "composer.lock" => parse_composer_lock(path, content),
        _ => LockfileAnalysis {
            analysis_partial: true,
            ..LockfileAnalysis::default()
        },
    }
}

#[derive(Default)]
struct CargoPackage {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
    dependencies: Vec<String>,
}

fn parse_cargo_lock(path: &str, content: &str) -> LockfileAnalysis {
    let mut result = LockfileAnalysis::default();
    let mut current: Option<CargoPackage> = None;
    let mut in_dependencies = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let Some(package) = current.take() {
                push_cargo_package(path, package, &mut result);
            }
            current = Some(CargoPackage::default());
            in_dependencies = false;
            continue;
        }

        let Some(package) = current.as_mut() else {
            continue;
        };

        if in_dependencies {
            if trimmed.starts_with(']') {
                in_dependencies = false;
            } else {
                package.dependencies.extend(parse_quoted_values(trimmed));
            }
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "name" => package.name = parse_string_literal(value),
            "version" => package.version = parse_string_literal(value),
            "source" => package.source = parse_string_literal(value),
            "checksum" => package.checksum = parse_string_literal(value),
            "dependencies" if value.starts_with('[') => {
                package.dependencies.extend(parse_quoted_values(value));
                in_dependencies = !value.contains(']');
            }
            _ => {}
        }
    }

    if let Some(package) = current {
        push_cargo_package(path, package, &mut result);
    }
    if result.packages.is_empty() {
        result.analysis_partial = true;
    }
    result
        .packages
        .sort_by(|left, right| left.package_id.cmp(&right.package_id));
    result
}

fn push_cargo_package(path: &str, package: CargoPackage, result: &mut LockfileAnalysis) {
    let (Some(name), Some(version)) = (package.name, package.version) else {
        result.analysis_partial = true;
        return;
    };
    let package_id = match &package.source {
        Some(source) => format!("{name}@{version}#{source}"),
        None => format!("{name}@{version}"),
    };
    result.packages.push(ResolvedDependency {
        package_id,
        name,
        version,
        source: package.source,
        checksum: package.checksum,
        dependencies: package.dependencies,
        lockfile_path: path.to_owned(),
    });
}

fn parse_npm_lock(path: &str, content: &str) -> LockfileAnalysis {
    let mut result = LockfileAnalysis::default();
    let document: Value = match serde_json::from_str(content) {
        Ok(document) => document,
        Err(_) => {
            result.analysis_partial = true;
            return result;
        }
    };
    let Some(packages) = document.get("packages").and_then(Value::as_object) else {
        result.analysis_partial = true;
        return result;
    };

    for (package_path, metadata) in packages {
        if package_path.is_empty() {
            continue;
        }
        let Some(metadata) = metadata.as_object() else {
            result.analysis_partial = true;
            continue;
        };
        let name = metadata
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| package_name_from_node_path(package_path));
        let version = metadata
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let (Some(name), Some(version)) = (name, version) else {
            result.analysis_partial = true;
            continue;
        };

        let mut dependencies = Vec::new();
        if let Some(declared) = metadata.get("dependencies").and_then(Value::as_object) {
            for (dependency_name, dependency) in declared {
                let dependency_version = dependency
                    .as_str()
                    .or_else(|| dependency.get("version").and_then(Value::as_str));
                if let Some(dependency_version) = dependency_version {
                    dependencies.push(format!("{dependency_name}@{dependency_version}"));
                } else {
                    result.analysis_partial = true;
                }
            }
        }
        dependencies.sort();

        result.packages.push(ResolvedDependency {
            package_id: package_path.clone(),
            name,
            version,
            source: metadata
                .get("resolved")
                .and_then(Value::as_str)
                .map(str::to_owned),
            checksum: metadata
                .get("integrity")
                .and_then(Value::as_str)
                .map(str::to_owned),
            dependencies,
            lockfile_path: path.to_owned(),
        });
    }

    result
        .packages
        .sort_by(|left, right| left.package_id.cmp(&right.package_id));
    result
}

fn package_name_from_node_path(package_path: &str) -> Option<String> {
    package_path
        .rsplit("node_modules/")
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn parse_composer_lock(path: &str, content: &str) -> LockfileAnalysis {
    let mut result = LockfileAnalysis::default();
    let document: Value = match serde_json::from_str(content) {
        Ok(document) => document,
        Err(_) => {
            result.analysis_partial = true;
            return result;
        }
    };

    let mut found_package_array = false;
    for key in ["packages", "packages-dev"] {
        let Some(packages) = document.get(key).and_then(Value::as_array) else {
            continue;
        };
        found_package_array = true;
        for package in packages {
            let Some(name) = package.get("name").and_then(Value::as_str) else {
                result.analysis_partial = true;
                continue;
            };
            let Some(version) = package.get("version").and_then(Value::as_str) else {
                result.analysis_partial = true;
                continue;
            };
            let mut dependencies = Vec::new();
            if let Some(requirements) = package.get("require").and_then(Value::as_object) {
                for (dependency_name, requirement) in requirements {
                    if let Some(requirement) = requirement.as_str() {
                        dependencies.push(format!("{dependency_name}@{requirement}"));
                    }
                }
            }
            dependencies.sort();
            let source = package
                .get("source")
                .and_then(|source| source.get("url"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let checksum = package
                .get("dist")
                .and_then(|dist| dist.get("shasum"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            result.packages.push(ResolvedDependency {
                package_id: format!("{name}@{version}"),
                name: name.to_owned(),
                version: version.to_owned(),
                source,
                checksum,
                dependencies,
                lockfile_path: path.to_owned(),
            });
        }
    }

    if !found_package_array {
        result.analysis_partial = true;
    }
    result
        .packages
        .sort_by(|left, right| left.package_id.cmp(&right.package_id));
    result
}

fn parse_string_literal(value: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        Some(value[1..value.len() - 1].to_owned())
    } else {
        None
    }
}

fn parse_quoted_values(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    for character in value.chars() {
        match character {
            '"' if in_string => {
                values.push(std::mem::take(&mut current));
                in_string = false;
            }
            '"' => in_string = true,
            _ if in_string => current.push(character),
            _ => {}
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_lock_packages_and_dependency_references() {
        let lock = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
dependencies = [
 "serde_core 1.0.200",
]

[[package]]
name = "serde_core"
version = "1.0.200"
"#;
        let result = analyze_lockfile("Cargo.lock", lock);
        assert!(!result.analysis_partial);
        assert_eq!(result.packages.len(), 2);
        assert_eq!(result.packages[0].name, "serde");
        assert_eq!(result.packages[0].dependencies, vec!["serde_core 1.0.200"]);
        assert_eq!(result.packages[0].checksum.as_deref(), Some("abc"));
    }

    #[test]
    fn parses_npm_lockfile_packages_and_scoped_names() {
        let lock = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {},
            "node_modules/@scope/tool": {
              "version": "2.1.0",
              "resolved": "https://registry.example/tool.tgz",
              "integrity": "sha512-test",
              "dependencies": {"left-pad": "1.3.0"}
            },
            "node_modules/left-pad": {"version": "1.3.0"}
          }
        }"#;
        let result = analyze_lockfile("package-lock.json", lock);
        assert!(!result.analysis_partial);
        assert_eq!(result.packages.len(), 2);
        let scoped = result
            .packages
            .iter()
            .find(|package| package.name == "@scope/tool")
            .expect("scoped package");
        assert_eq!(scoped.version, "2.1.0");
        assert_eq!(scoped.dependencies, vec!["left-pad@1.3.0"]);
    }

    #[test]
    fn parses_composer_lock_package_and_requirements() {
        let lock = r#"{
          "packages": [{
            "name": "vendor/library",
            "version": "1.2.3",
            "require": {"php": "^8.2", "vendor/other": "^2.0"},
            "source": {"url": "https://example.test/repo"},
            "dist": {"shasum": "abc123"}
          }],
          "packages-dev": []
        }"#;
        let result = analyze_lockfile("composer.lock", lock);
        assert!(!result.analysis_partial);
        assert_eq!(result.packages.len(), 1);
        assert_eq!(
            result.packages[0].dependencies,
            vec!["php@^8.2", "vendor/other@^2.0"]
        );
    }

    #[test]
    fn unknown_and_invalid_lockfiles_are_marked_partial() {
        assert!(analyze_lockfile("yarn.lock", "not parsed").analysis_partial);
        assert!(analyze_lockfile("package-lock.json", "{invalid").analysis_partial);
    }
}
