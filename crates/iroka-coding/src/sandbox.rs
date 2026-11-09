//! Typed toolchain profiles and a fail-closed Linux sandbox broker.
//!
//! Project code is never launched through a shell. The Linux backend requires
//! bubblewrap plus prlimit, isolates network/process namespaces, mounts toolchain
//! inputs read-only, and exposes only a temporary pinned workspace as writable.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::index::SnapshotFile;
use crate::patch::WorkspaceSnapshot;
use iroka_kernel::{
    ConsumedExecutionGrant, ExecutionGrant, ExecutionGrantError, ExecutionGrantScope,
    ExecutionGrantVerifier,
};
use crate::planner::safe_relative_path;

const ENVIRONMENT_ALLOWLIST: &[&str] = &[
    "CARGO_NET_OFFLINE",
    "CARGO_HOME",
    "CARGO_TERM_COLOR",
    "PIP_NO_INDEX",
    "PYTHONNOUSERSITE",
    "npm_config_offline",
    "NO_COLOR",
    "RUST_BACKTRACE",
    "GOTOOLCHAIN",
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ToolchainAction {
    Compile,
    Test,
    Debug,
}

impl ToolchainAction {
    fn capability(self) -> &'static str {
        match self {
            Self::Compile | Self::Test => "coding.sandbox.execute",
            Self::Debug => "coding.debug.execute",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Test => "test",
            Self::Debug => "debug",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCommand {
    program_id: String,
    args: Vec<String>,
    working_directory: String,
    environment: BTreeMap<String, String>,
}

impl ToolCommand {
    pub fn new(
        program_id: impl Into<String>,
        args: Vec<String>,
        working_directory: impl Into<String>,
        environment: BTreeMap<String, String>,
    ) -> Result<Self, SandboxError> {
        let program_id = program_id.into();
        let working_directory = working_directory.into();
        if !valid_identifier(&program_id)
            || (!working_directory.is_empty()
                && working_directory != "."
                && !safe_relative_path(&working_directory))
            || args.len() > 256
            || args.iter().any(|arg| {
                arg.len() > 4096 || arg.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            return Err(SandboxError::InvalidInvocation);
        }
        for (key, value) in &environment {
            if !ENVIRONMENT_ALLOWLIST.contains(&key.as_str())
                || value.len() > 256
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(SandboxError::InvalidInvocation);
            }
        }
        Ok(Self {
            program_id,
            args,
            working_directory,
            environment,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolchainProfile {
    language_id: String,
    profile_version: String,
    actions: BTreeMap<ToolchainAction, ToolCommand>,
}

impl ToolchainProfile {
    pub fn new(
        language_id: impl Into<String>,
        profile_version: impl Into<String>,
        actions: BTreeMap<ToolchainAction, ToolCommand>,
    ) -> Result<Self, SandboxError> {
        let language_id = language_id.into();
        let profile_version = profile_version.into();
        if !valid_identifier(&language_id)
            || profile_version.trim().is_empty()
            || profile_version.len() > 64
            || profile_version.bytes().any(|byte| byte.is_ascii_control())
            || actions.is_empty()
        {
            return Err(SandboxError::InvalidInvocation);
        }
        Ok(Self {
            language_id,
            profile_version,
            actions,
        })
    }
}

#[derive(Default)]
pub struct ToolchainRegistry {
    profiles: BTreeMap<String, ToolchainProfile>,
}

impl ToolchainRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an explicit profile. Duplicate language IDs fail closed.
    pub fn register(&mut self, profile: ToolchainProfile) -> Result<(), SandboxError> {
        if self.profiles.contains_key(&profile.language_id) {
            return Err(SandboxError::DuplicateToolchain);
        }
        self.profiles.insert(profile.language_id.clone(), profile);
        Ok(())
    }

    /// Initial offline-only profiles. Executables must still be explicitly
    /// mapped by the sandbox runtime configuration.
    pub fn standard() -> Self {
        let mut registry = Self::new();
        let mut rust = BTreeMap::new();
        rust.insert(
            ToolchainAction::Compile,
            ToolCommand::new(
                "cargo",
                strings(&["check", "--workspace", "--all-targets", "--locked", "--offline"]),
                ".",
                env(&[("CARGO_NET_OFFLINE", "true"), ("CARGO_TERM_COLOR", "never")]),
            )
            .expect("static Rust compile profile"),
        );
        rust.insert(
            ToolchainAction::Test,
            ToolCommand::new(
                "cargo",
                strings(&["test", "--workspace", "--all-targets", "--locked", "--offline"]),
                ".",
                env(&[("CARGO_NET_OFFLINE", "true"), ("CARGO_TERM_COLOR", "never")]),
            )
            .expect("static Rust test profile"),
        );
        registry
            .register(ToolchainProfile::new("rust", "1.0.0", rust).expect("Rust profile"))
            .expect("unique Rust profile");

        let mut python = BTreeMap::new();
        python.insert(
            ToolchainAction::Compile,
            ToolCommand::new(
                "python3",
                strings(&["-m", "compileall", "-q", "."]),
                ".",
                env(&[("PIP_NO_INDEX", "1"), ("PYTHONNOUSERSITE", "1")]),
            )
            .expect("static Python compile profile"),
        );
        python.insert(
            ToolchainAction::Test,
            ToolCommand::new(
                "python3",
                strings(&["-m", "pytest", "-q", "--disable-warnings"]),
                ".",
                env(&[("PIP_NO_INDEX", "1"), ("PYTHONNOUSERSITE", "1")]),
            )
            .expect("static Python test profile"),
        );
        python.insert(
            ToolchainAction::Debug,
            ToolCommand::new(
                "python3",
                strings(&["-m", "pdb", "-c", "continue"]),
                ".",
                env(&[("PYTHONNOUSERSITE", "1"), ("NO_COLOR", "1")]),
            )
            .expect("static Python debugger profile"),
        );
        registry
            .register(ToolchainProfile::new("python", "1.0.0", python).expect("Python profile"))
            .expect("unique Python profile");

        let mut typescript = BTreeMap::new();
        typescript.insert(
            ToolchainAction::Compile,
            ToolCommand::new(
                "tsc",
                strings(&["--noEmit"]),
                ".",
                env(&[("npm_config_offline", "true"), ("NO_COLOR", "1")]),
            )
            .expect("static TypeScript compile profile"),
        );
        typescript.insert(
            ToolchainAction::Test,
            ToolCommand::new(
                "npm",
                strings(&["test", "--", "--runInBand"]),
                ".",
                env(&[("npm_config_offline", "true"), ("NO_COLOR", "1")]),
            )
            .expect("static TypeScript test profile"),
        );
        registry
            .register(ToolchainProfile::new("typescript", "1.0.0", typescript).expect("TypeScript profile"))
            .expect("unique TypeScript profile");

        let mut go = BTreeMap::new();
        go.insert(
            ToolchainAction::Compile,
            ToolCommand::new(
                "go",
                strings(&["test", "-run", "^$", "./..."]),
                ".",
                env(&[("GOTOOLCHAIN", "local")]),
            )
            .expect("static Go compile profile"),
        );
        go.insert(
            ToolchainAction::Test,
            ToolCommand::new("go", strings(&["test", "./..."]), ".", env(&[("GOTOOLCHAIN", "local")]))
                .expect("static Go test profile"),
        );
        registry
            .register(ToolchainProfile::new("go", "1.0.0", go).expect("Go profile"))
            .expect("unique Go profile");
        registry
    }

    pub fn prepare(
        &self,
        language_id: &str,
        action: ToolchainAction,
        sandbox_id: &str,
        snapshot: &WorkspaceSnapshot,
        debug_target: Option<&str>,
    ) -> Result<SandboxInvocation, SandboxError> {
        if !valid_identifier(sandbox_id) {
            return Err(SandboxError::InvalidInvocation);
        }
        if !valid_identifier(sandbox_id) {
            return Err(SandboxError::InvalidInvocation);
        }
        let profile = self
            .profiles
            .get(language_id)
            .ok_or(SandboxError::UnsupportedLanguage)?;
        let command = profile
            .actions
            .get(&action)
            .ok_or(SandboxError::UnsupportedAction)?;
        let mut args = command.args.clone();
        match (action, debug_target) {
            (ToolchainAction::Debug, Some(target)) => {
                if !safe_relative_path(target) || snapshot.file(target).is_none() {
                    return Err(SandboxError::InvalidInvocation);
                }
                args.push(target.to_owned());
            }
            (ToolchainAction::Debug, None) => return Err(SandboxError::InvalidInvocation),
            (_, Some(_)) => return Err(SandboxError::InvalidInvocation),
            (_, None) => {}
        }
        let action_digest = digest_invocation(
            snapshot,
            language_id,
            action,
            &command.program_id,
            &args,
            &command.working_directory,
            &command.environment,
            sandbox_id,
            &profile.profile_version,
        );
        Ok(SandboxInvocation {
            language_id: language_id.to_owned(),
            profile_version: profile.profile_version.clone(),
            action,
            sandbox_id: sandbox_id.to_owned(),
            capability: action.capability().to_owned(),
            program_id: command.program_id.clone(),
            args,
            working_directory: command.working_directory.clone(),
            environment: command.environment.clone(),
            action_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxInvocation {
    language_id: String,
    profile_version: String,
    action: ToolchainAction,
    sandbox_id: String,
    capability: String,
    program_id: String,
    args: Vec<String>,
    working_directory: String,
    environment: BTreeMap<String, String>,
    action_digest: String,
}

impl SandboxInvocation {
    #[must_use]
    pub fn language_id(&self) -> &str {
        &self.language_id
    }

    #[must_use]
    pub fn profile_version(&self) -> &str {
        &self.profile_version
    }

    #[must_use]
    pub fn action(&self) -> ToolchainAction {
        self.action
    }

    #[must_use]
    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    #[must_use]
    pub fn action_digest(&self) -> &str {
        &self.action_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxLimits {
    pub wall_time: Duration,
    pub cpu_seconds: u64,
    pub memory_bytes: u64,
    pub process_count: u64,
    pub max_output_bytes: usize,
    pub max_workspace_bytes: usize,
    pub max_file_bytes: usize,
    pub max_files: usize,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            wall_time: Duration::from_secs(120),
            cpu_seconds: 60,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            process_count: 64,
            max_output_bytes: 1024 * 1024,
            max_workspace_bytes: 64 * 1024 * 1024,
            max_file_bytes: 2 * 1024 * 1024,
            max_files: 20_000,
        }
    }
}

impl SandboxLimits {
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.wall_time.is_zero()
            || self.wall_time > Duration::from_secs(300)
            || !(1..=120).contains(&self.cpu_seconds)
            || !(64 * 1024 * 1024..=4 * 1024 * 1024 * 1024).contains(&self.memory_bytes)
            || !(1..=128).contains(&self.process_count)
            || self.max_output_bytes == 0
            || self.max_output_bytes > 4 * 1024 * 1024
            || self.max_workspace_bytes == 0
            || self.max_workspace_bytes > 128 * 1024 * 1024
            || self.max_file_bytes == 0
            || self.max_file_bytes > 64 * 1024 * 1024
            || self.max_files == 0
            || self.max_files > 20_000
        {
            return Err(SandboxError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionStatus {
    Succeeded,
    Failed,
    TimedOut,
    OutputLimitExceeded,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ExecutionResult {
    pub status: ExecutionStatus,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxError {
    InvalidLimits,
    InvalidInvocation,
    DuplicateToolchain,
    UnsupportedLanguage,
    UnsupportedAction,
    ScopeMismatch,
    Grant(ExecutionGrantError),
    SandboxUnavailable,
    IsolationUnavailable,
    WorkspaceRejected,
    ToolUnavailable,
    SpawnFailed,
    WaitFailed,
    UnsupportedPlatform,
}

pub trait SandboxBackend {
    fn execute(
        &self,
        grant: ConsumedExecutionGrant,
        snapshot: &WorkspaceSnapshot,
        invocation: &SandboxInvocation,
        limits: &SandboxLimits,
    ) -> Result<ExecutionResult, SandboxError>;
}

/// Consume G09 before handing the pinned workspace to any backend.
pub struct SandboxExecutor;

impl SandboxExecutor {
    pub fn execute<B: SandboxBackend>(
        verifier: &ExecutionGrantVerifier<'_>,
        backend: &B,
        grant: ExecutionGrant,
        snapshot: &WorkspaceSnapshot,
        invocation: &SandboxInvocation,
        limits: &SandboxLimits,
    ) -> Result<ExecutionResult, SandboxError> {
        limits.validate()?;
        let scope = grant.scope().clone();
        let recomputed_digest = digest_invocation(
            snapshot,
            &invocation.language_id,
            invocation.action,
            &invocation.program_id,
            &invocation.args,
            &invocation.working_directory,
            &invocation.environment,
            &invocation.sandbox_id,
            &invocation.profile_version,
        );
        if recomputed_digest != invocation.action_digest
            || scope.repository() != snapshot.repository()
            || scope.source_revision() != snapshot.revision()
            || scope.sandbox_id() != invocation.sandbox_id
            || scope.action_digest() != invocation.action_digest
            || scope.capability() != invocation.capability
            || scope.risk() != iroka_kernel::RiskLevel::High
        {
            return Err(SandboxError::ScopeMismatch);
        }
        let consumed = verifier
            .consume(grant, &scope)
            .map_err(SandboxError::Grant)?;
        backend.execute(consumed, snapshot, invocation, limits)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyMount {
    host_path: PathBuf,
    sandbox_path: PathBuf,
}

impl ReadOnlyMount {
    pub fn new(host_path: impl Into<PathBuf>, sandbox_path: impl Into<PathBuf>) -> Self {
        Self {
            host_path: host_path.into(),
            sandbox_path: sandbox_path.into(),
        }
    }
}

#[cfg(target_os = "linux")]
pub struct SandboxRuntimeConfig {
    bwrap_path: PathBuf,
    prlimit_path: PathBuf,
    bwrap_digest: String,
    prlimit_digest: String,
    sandbox_root: PathBuf,
    mounts: Vec<ReadOnlyMount>,
    programs: BTreeMap<String, PathBuf>,
    program_digests: BTreeMap<String, String>,
}

#[cfg(target_os = "linux")]
impl SandboxRuntimeConfig {
    pub fn new(
        bwrap_path: impl Into<PathBuf>,
        prlimit_path: impl Into<PathBuf>,
        sandbox_root: impl Into<PathBuf>,
        mounts: Vec<ReadOnlyMount>,
        programs: BTreeMap<String, PathBuf>,
    ) -> Result<Self, SandboxError> {
        let bwrap_path = canonical_executable(&bwrap_path.into())?;
        let prlimit_path = canonical_executable(&prlimit_path.into())?;
        let bwrap_digest = file_digest(&bwrap_path)?;
        let prlimit_digest = file_digest(&prlimit_path)?;
        let sandbox_root = sandbox_root.into();
        if !sandbox_root.is_absolute() {
            return Err(SandboxError::SandboxUnavailable);
        }
        std::fs::create_dir_all(&sandbox_root).map_err(|_| SandboxError::SandboxUnavailable)?;
        let metadata =
            std::fs::symlink_metadata(&sandbox_root).map_err(|_| SandboxError::SandboxUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(SandboxError::SandboxUnavailable);
        }
        let sandbox_root =
            std::fs::canonicalize(&sandbox_root).map_err(|_| SandboxError::SandboxUnavailable)?;
        if sandbox_root == Path::new("/")
            || sandbox_root == Path::new("/tmp")
            || sandbox_root.starts_with("/home")
            || sandbox_root.starts_with("/root")
            || sandbox_root.starts_with("/etc")
            || sandbox_root.starts_with("/proc")
            || sandbox_root.starts_with("/sys")
            || sandbox_root.starts_with("/dev")
            || sandbox_root.starts_with("/run")
        {
            return Err(SandboxError::SandboxUnavailable);
        }

        if mounts.is_empty() || programs.is_empty() {
            return Err(SandboxError::ToolUnavailable);
        }
        let mut canonical_mounts = Vec::new();
        let mut sandbox_targets = BTreeSet::new();
        for mount in mounts {
            let host_path =
                std::fs::canonicalize(&mount.host_path).map_err(|_| SandboxError::ToolUnavailable)?;
            let metadata =
                std::fs::metadata(&host_path).map_err(|_| SandboxError::ToolUnavailable)?;
            if !metadata.is_dir()
                || host_path == Path::new("/")
                || host_path.starts_with("/home")
                || host_path.starts_with("/root")
                || host_path.starts_with("/etc")
                || host_path.starts_with("/var")
                || host_path.starts_with("/run")
                || host_path.starts_with("/tmp")
                || host_path.starts_with("/proc")
                || host_path.starts_with("/sys")
                || host_path.starts_with("/dev")
                || !["/usr", "/opt", "/lib", "/lib64", "/bin", "/sbin"]
                    .iter()
                    .any(|root| {
                        host_path == Path::new(root)
                            || host_path.starts_with(format!("{root}/"))
                    })
                || canonical_mounts.iter().any(|existing: &ReadOnlyMount| {
                    existing.host_path.starts_with(&host_path)
                        || host_path.starts_with(&existing.host_path)
                })
            {
                return Err(SandboxError::ToolUnavailable);
            }
            if !mount.sandbox_path.is_absolute()
                || mount.sandbox_path == Path::new("/")
                || mount.sandbox_path.starts_with("/home")
                || mount.sandbox_path.starts_with("/root")
                || mount.sandbox_path.starts_with("/etc")
                || mount.sandbox_path.starts_with("/proc")
                || mount.sandbox_path.starts_with("/sys")
                || mount.sandbox_path.starts_with("/dev")
                || mount.sandbox_path.starts_with("/run")
                || mount.sandbox_path.starts_with("/workspace")
                || mount.sandbox_path.starts_with("/tmp")
                || !["/usr", "/opt", "/lib", "/lib64", "/bin", "/sbin"]
                    .iter()
                    .any(|root| {
                        mount.sandbox_path == Path::new(root)
                            || mount.sandbox_path.starts_with(format!("{root}/"))
                    })
                || mount
                    .sandbox_path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
                || sandbox_targets.iter().any(|existing: &PathBuf| {
                    existing.starts_with(&mount.sandbox_path)
                        || mount.sandbox_path.starts_with(existing)
                })
                || !sandbox_targets.insert(mount.sandbox_path.clone())
            {
                return Err(SandboxError::ToolUnavailable);
            }
            canonical_mounts.push(ReadOnlyMount {
                host_path,
                sandbox_path: mount.sandbox_path,
            });
        }
        let mut program_digests = BTreeMap::new();
        for (program_id, sandbox_program) in &programs {
            if !valid_identifier(program_id)
                || !sandbox_program.is_absolute()
                || sandbox_program
                    .components()
                    .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            {
                return Err(SandboxError::ToolUnavailable);
            }
            let host_program = resolve_host_program(&canonical_mounts, sandbox_program)?;
            if !is_executable(&host_program) {
                return Err(SandboxError::ToolUnavailable);
            }
            program_digests.insert(program_id.clone(), file_digest(&host_program)?);
        }
        Ok(Self {
            bwrap_path,
            prlimit_path,
            bwrap_digest,
            prlimit_digest,
            sandbox_root,
            mounts: canonical_mounts,
            programs,
            program_digests,
        })
    }
}

#[cfg(target_os = "linux")]
pub struct BubblewrapBackend {
    config: SandboxRuntimeConfig,
}

#[cfg(target_os = "linux")]
impl BubblewrapBackend {
    #[must_use]
    pub fn new(config: SandboxRuntimeConfig) -> Self {
        Self { config }
    }

    fn build_arguments(
        &self,
        workspace: &Path,
        invocation: &SandboxInvocation,
    ) -> Result<Vec<String>, SandboxError> {
        let program = self
            .config
            .programs
            .get(&invocation.program_id)
            .ok_or(SandboxError::ToolUnavailable)?;
        let mut args = vec![
            "--unshare-all".to_owned(),
            "--unshare-net".to_owned(),
            "--die-with-parent".to_owned(),
            "--new-session".to_owned(),
            "--cap-drop".to_owned(),
            "ALL".to_owned(),
            "--uid".to_owned(),
            "0".to_owned(),
            "--gid".to_owned(),
            "0".to_owned(),
        ];
        for mount in &self.config.mounts {
            args.extend([
                "--ro-bind".to_owned(),
                mount.host_path.display().to_string(),
                mount.sandbox_path.display().to_string(),
            ]);
        }
        args.extend([
            "--symlink".to_owned(),
            "usr/bin".to_owned(),
            "/bin".to_owned(),
            "--symlink".to_owned(),
            "usr/lib".to_owned(),
            "/lib".to_owned(),
            "--symlink".to_owned(),
            "usr/lib64".to_owned(),
            "/lib64".to_owned(),
            "--proc".to_owned(),
            "/proc".to_owned(),
            "--dev".to_owned(),
            "/dev".to_owned(),
            "--tmpfs".to_owned(),
            "/tmp".to_owned(),
            "--dir".to_owned(),
            "/home".to_owned(),
            "--dir".to_owned(),
            "/tmp/home".to_owned(),
            "--dir".to_owned(),
            "/workspace".to_owned(),
            "--bind".to_owned(),
            workspace.display().to_string(),
            "/workspace".to_owned(),
            "--chdir".to_owned(),
            if invocation.working_directory.is_empty() || invocation.working_directory == "." {
                "/workspace".to_owned()
            } else {
                format!("/workspace/{}", invocation.working_directory)
            },
            "--clearenv".to_owned(),
            "--setenv".to_owned(),
            "PATH".to_owned(),
            "/usr/bin:/usr/local/bin".to_owned(),
            "--setenv".to_owned(),
            "HOME".to_owned(),
            "/tmp/home".to_owned(),
            "--setenv".to_owned(),
            "TMPDIR".to_owned(),
            "/tmp".to_owned(),
            "--setenv".to_owned(),
            "CARGO_NET_OFFLINE".to_owned(),
            "true".to_owned(),
            "--setenv".to_owned(),
            "CARGO_HOME".to_owned(),
            "/tmp/cargo".to_owned(),
            "--setenv".to_owned(),
            "PIP_NO_INDEX".to_owned(),
            "1".to_owned(),
            "--setenv".to_owned(),
            "npm_config_offline".to_owned(),
            "true".to_owned(),
            "--setenv".to_owned(),
            "PYTHONNOUSERSITE".to_owned(),
            "1".to_owned(),
        ]);
        for (key, value) in &invocation.environment {
            if !ENVIRONMENT_ALLOWLIST.contains(&key.as_str()) {
                return Err(SandboxError::InvalidInvocation);
            }
            args.extend([
                "--setenv".to_owned(),
                key.clone(),
                value.clone(),
            ]);
        }
        args.push("--".to_owned());
        args.push(program.display().to_string());
        args.extend(invocation.args.clone());
        Ok(args)
    }
}

#[cfg(target_os = "linux")]
impl SandboxBackend for BubblewrapBackend {
    fn execute(
        &self,
        grant: ConsumedExecutionGrant,
        snapshot: &WorkspaceSnapshot,
        invocation: &SandboxInvocation,
        limits: &SandboxLimits,
    ) -> Result<ExecutionResult, SandboxError> {
        if grant.scope().repository() != snapshot.repository()
            || grant.scope().source_revision() != snapshot.revision()
            || grant.scope().action_digest() != invocation.action_digest
            || grant.scope().sandbox_id() != invocation.sandbox_id
            || grant.scope().capability() != invocation.capability
            || grant.scope().risk() != iroka_kernel::RiskLevel::High
        {
            return Err(SandboxError::ScopeMismatch);
        }
        verify_program_digests(&self.config)?;
        let workspace = SandboxWorkspace::create(
            &self.config.sandbox_root,
            grant.grant_id(),
            snapshot,
            limits,
        )?;
        let bwrap_args = self.build_arguments(&workspace.path, invocation)?;
        let mut command = std::process::Command::new(&self.config.prlimit_path);
        command
            .arg(format!("--cpu={}", limits.cpu_seconds))
            .arg(format!("--as={}", limits.memory_bytes))
            .arg(format!("--nproc={}", limits.process_count))
            .arg(format!("--fsize={}", limits.max_file_bytes))
            .arg("--nofile=256")
            .arg("--")
            .arg(&self.config.bwrap_path)
            .args(bwrap_args)
            .env_clear()
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        run_bounded(command, limits)
    }
}

#[cfg(target_os = "linux")]
struct SandboxWorkspace {
    path: PathBuf,
}

#[cfg(target_os = "linux")]
impl SandboxWorkspace {
    fn create(
        sandbox_root: &Path,
        grant_id: &str,
        snapshot: &WorkspaceSnapshot,
        limits: &SandboxLimits,
    ) -> Result<Self, SandboxError> {
        if !valid_identifier(grant_id) || snapshot.files().len() > limits.max_files {
            return Err(SandboxError::WorkspaceRejected);
        }
        let total_bytes = snapshot
            .files()
            .iter()
            .try_fold(0_usize, |sum, file| {
                if file.is_symlink
                    || !safe_relative_path(&file.path)
                    || file.content.len() > limits.max_file_bytes
                {
                    return None;
                }
                sum.checked_add(file.content.len())
            })
            .ok_or(SandboxError::WorkspaceRejected)?;
        if total_bytes > limits.max_workspace_bytes {
            return Err(SandboxError::WorkspaceRejected);
        }
        let path = sandbox_root.join(grant_id);
        std::fs::create_dir(&path).map_err(|_| SandboxError::WorkspaceRejected)?;
        let workspace = Self { path };
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&workspace.path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| SandboxError::WorkspaceRejected)?;
        for file in snapshot.files() {
            let destination = workspace.path.join(&file.path);
            let parent = destination.parent().ok_or(SandboxError::WorkspaceRejected)?;
            std::fs::create_dir_all(parent).map_err(|_| SandboxError::WorkspaceRejected)?;
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|_| SandboxError::WorkspaceRejected)?;
            use std::io::Write;
            output
                .write_all(file.content.as_bytes())
                .map_err(|_| SandboxError::WorkspaceRejected)?;
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| SandboxError::WorkspaceRejected)?;
        }
        Ok(workspace)
    }
}

#[cfg(target_os = "linux")]
impl Drop for SandboxWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(target_os = "linux")]
fn resolve_host_program(
    mounts: &[ReadOnlyMount],
    sandbox_program: &Path,
) -> Result<PathBuf, SandboxError> {
    for mount in mounts {
        if let Ok(relative) = sandbox_program.strip_prefix(&mount.sandbox_path) {
            let host_program = std::fs::canonicalize(mount.host_path.join(relative))
                .map_err(|_| SandboxError::ToolUnavailable)?;
            if host_program.starts_with(&mount.host_path) && is_executable(&host_program) {
                return Ok(host_program);
            }
            return Err(SandboxError::ToolUnavailable);
        }
    }
    Err(SandboxError::ToolUnavailable)
}

#[cfg(target_os = "linux")]
fn file_digest(path: &Path) -> Result<String, SandboxError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|_| SandboxError::ToolUnavailable)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| SandboxError::ToolUnavailable)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex(&hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn verify_program_digests(config: &SandboxRuntimeConfig) -> Result<(), SandboxError> {
    if file_digest(&config.bwrap_path)? != config.bwrap_digest
        || file_digest(&config.prlimit_path)? != config.prlimit_digest
    {
        return Err(SandboxError::ToolUnavailable);
    }
    for (program_id, sandbox_path) in &config.programs {
        let host_program = resolve_host_program(&config.mounts, sandbox_path)?;
        let current_digest = file_digest(&host_program)?;
        if config.program_digests.get(program_id) != Some(&current_digest) {
            return Err(SandboxError::ToolUnavailable);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn canonical_executable(path: &Path) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::SandboxUnavailable);
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| SandboxError::SandboxUnavailable)?;
    if !is_executable(&canonical) {
        return Err(SandboxError::SandboxUnavailable);
    }
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn run_bounded(
    mut command: std::process::Command,
    limits: &SandboxLimits,
) -> Result<ExecutionResult, SandboxError> {
    use std::sync::mpsc;
    use std::thread;

    let started = Instant::now();
    let mut child = command.spawn().map_err(|_| SandboxError::SpawnFailed)?;
    let stdout = child.stdout.take().ok_or(SandboxError::SpawnFailed)?;
    let stderr = child.stderr.take().ok_or(SandboxError::SpawnFailed)?;
    let (signal_tx, signal_rx) = mpsc::channel();
    let stdout_limit = limits.max_output_bytes / 2;
    let stderr_limit = limits.max_output_bytes - stdout_limit;
    let stdout_signal = signal_tx.clone();
    let stdout_thread = thread::spawn(move || read_capped(stdout, stdout_limit, stdout_signal));
    let stderr_thread = thread::spawn(move || read_capped(stderr, stderr_limit, signal_tx));

    let mut timed_out = false;
    let mut output_limited = false;
    let status = loop {
        if signal_rx.try_recv().is_ok() {
            output_limited = true;
            child.kill().map_err(|_| SandboxError::WaitFailed)?;
            break child.wait().map_err(|_| SandboxError::WaitFailed)?;
        }
        if let Some(status) = child.try_wait().map_err(|_| SandboxError::WaitFailed)? {
            break status;
        }
        if started.elapsed() >= limits.wall_time {
            timed_out = true;
            child.kill().map_err(|_| SandboxError::WaitFailed)?;
            break child.wait().map_err(|_| SandboxError::WaitFailed)?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let (stdout, stdout_overflow) = stdout_thread.join().map_err(|_| SandboxError::WaitFailed)?;
    let (stderr, stderr_overflow) = stderr_thread.join().map_err(|_| SandboxError::WaitFailed)?;
    output_limited |= stdout_overflow || stderr_overflow;
    let execution_status = if timed_out {
        ExecutionStatus::TimedOut
    } else if output_limited {
        ExecutionStatus::OutputLimitExceeded
    } else if status.success() {
        ExecutionStatus::Succeeded
    } else {
        ExecutionStatus::Failed
    };
    Ok(ExecutionResult {
        status: execution_status,
        exit_code: status.code(),
        stdout,
        stderr,
        duration_ms: started.elapsed().as_millis(),
    })
}

#[cfg(target_os = "linux")]
fn read_capped<R: std::io::Read>(
    mut reader: R,
    limit: usize,
    signal: std::sync::mpsc::Sender<()>,
) -> (Vec<u8>, bool) {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut overflow = false;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(_) => {
                if !overflow {
                    overflow = true;
                    let _ = signal.send(());
                }
                break;
            }
        };
        let remaining = limit.saturating_sub(output.len());
        let retained = count.min(remaining);
        output.extend_from_slice(&buffer[..retained]);
        if retained < count && !overflow {
            overflow = true;
            let _ = signal.send(());
        }
    }
    (output, overflow)
}

fn digest_invocation(
    snapshot: &WorkspaceSnapshot,
    language_id: &str,
    action: ToolchainAction,
    program_id: &str,
    args: &[String],
    working_directory: &str,
    environment: &BTreeMap<String, String>,
    sandbox_id: &str,
    profile_version: &str,
) -> String {
    let mut hasher = Sha256::new();
    let mut add = |value: &[u8]| {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    };
    add(language_id.as_bytes());
    add(profile_version.as_bytes());
    add(sandbox_id.as_bytes());
    add(action.as_str().as_bytes());
    add(program_id.as_bytes());
    add(working_directory.as_bytes());
    for arg in args {
        add(arg.as_bytes());
    }
    for (key, value) in environment {
        add(key.as_bytes());
        add(value.as_bytes());
    }
    for file in snapshot.files() {
        add(file.path.as_bytes());
        add(file.content.as_bytes());
    }
    hex(&hasher.finalize())
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

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn env(values: &[(&str, &str)]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
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

    use crate::index::SnapshotFile;

    fn snapshot(content: &str) -> WorkspaceSnapshot {
        WorkspaceSnapshot::new(
            "akefadaka-git/iroka",
            "a".repeat(40),
            vec![SnapshotFile::new("src/main.rs", content)],
        )
        .expect("snapshot")
    }

    #[test]
    fn standard_profiles_use_offline_typed_commands() {
        let registry = ToolchainRegistry::standard();
        let source = snapshot("fn main() {}\n");
        let invocation = registry
            .prepare("rust", ToolchainAction::Test, "sandbox-1", &source, None)
            .expect("Rust test command");
        assert_eq!(invocation.program_id, "cargo");
        assert!(invocation.args.contains(&"--offline".to_owned()));
        assert_eq!(invocation.capability(), "coding.sandbox.execute");
        assert_eq!(invocation.action_digest().len(), 64);
    }

    #[test]
    fn debugger_requires_a_real_workspace_target() {
        let registry = ToolchainRegistry::standard();
        let source = WorkspaceSnapshot::new(
            "akefadaka-git/iroka",
            "a".repeat(40),
            vec![SnapshotFile::new("src/main.py", "print('sandbox')\n")],
        )
        .expect("Python snapshot");
        assert!(registry
            .prepare("python", ToolchainAction::Debug, "sandbox-1", &source, None)
            .is_err());
        assert!(registry
            .prepare(
                "python",
                ToolchainAction::Debug,
                "sandbox-1",
                &source,
                Some("../outside")
            )
            .is_err());
        assert!(registry
            .prepare(
                "python",
                ToolchainAction::Debug,
                "sandbox-1",
                &source,
                Some("src/main.py")
            )
            .is_ok());
    }

    #[test]
    fn action_digest_changes_when_snapshot_changes() {
        let registry = ToolchainRegistry::standard();
        let first = snapshot("fn main() {}\n");
        let second = snapshot("fn main() { println!(\"changed\"); }\n");
        let a = registry
            .prepare("rust", ToolchainAction::Compile, "sandbox-1", &first, None)
            .expect("first");
        let b = registry
            .prepare("rust", ToolchainAction::Compile, "sandbox-1", &second, None)
            .expect("second");
        assert_ne!(a.action_digest(), b.action_digest());
    }

    #[test]
    fn rejects_unknown_toolchains_and_unbounded_limits() {
        let registry = ToolchainRegistry::standard();
        let source = snapshot("fn main() {}\n");
        assert_eq!(
            registry.prepare("unknown", ToolchainAction::Test, "sandbox-1", &source, None),
            Err(SandboxError::UnsupportedLanguage)
        );
        let mut limits = SandboxLimits::default();
        limits.wall_time = Duration::from_secs(301);
        assert_eq!(limits.validate(), Err(SandboxError::InvalidLimits));
    }

    #[test]
    fn rejects_duplicate_toolchain_profiles() {
        let mut registry = ToolchainRegistry::standard();
        let profile = ToolchainProfile::new(
            "rust",
            "1.0.0",
            BTreeMap::from([(
                ToolchainAction::Test,
                ToolCommand::new("cargo", strings(&["test"]), ".", BTreeMap::new())
                    .expect("tool command"),
            )]),
        )
        .expect("profile");
        assert_eq!(
            registry.register(profile),
            Err(SandboxError::DuplicateToolchain)
        );
    }
}
