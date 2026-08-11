//! Declarative guest-name registry for the pinned Hell API.

use std::sync::OnceLock;

pub mod assurance_catalogs {
    include!(concat!(env!("OUT_DIR"), "/assurance_catalogs.rs"));
}

pub use assurance_catalogs::{NormalizerContract, NormalizerId, ObservationField};

/// Returns the generated, implementation-digest-bound contract for a normalizer.
#[must_use]
pub fn normalizer_contract(id: NormalizerId) -> Option<&'static NormalizerContract> {
    assurance_catalogs::NORMALIZER_CONTRACTS
        .iter()
        .find(|contract| contract.id == id)
}

mod manifest;

pub use manifest::{
    ClassHeadKind, InstanceResolution, InstanceSpec, KindSignature, ManifestKind, TypeClass,
    TypeConstructorSpec, instance, instances, public_type_arity, resolve_instance,
    type_constructor, type_constructors,
};

pub const LANGUAGE_VERSION: &str = assurance_catalogs::CLAIM_BASELINE;
pub const UPSTREAM_COMMIT: &str = "d4d028609ed46a560c62caea8c70e7e91d1afd29";
pub const UPSTREAM_SOURCE_SHA256: &str =
    "6b59dbbdaaa1e31938e8cbdf93ffb2b981fe8064009693f92fbdd134f7dd25f9";
pub const UPSTREAM_EXAMPLE_COUNT: usize = 44;
/// Updated only alongside the strictly parsed committed promotion policy.
pub const PROMOTION_POLICY_SHA256: &str =
    "f757c44ab61bb590ed6a9ac0453a5a218d564d0c04fd3f340ebb248ee0149708";
pub const PUBLIC_NAME_COUNT: usize = 345;
pub const INTERNAL_NAME_COUNT: usize = 10;
pub const UNIQUE_NAME_COUNT: usize = PUBLIC_NAME_COUNT + INTERNAL_NAME_COUNT;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BuiltinId(pub u16);

/// Canonical diagnostic codes emitted by the runtime evidence producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeDiagnosticCode {
    ResourceLimit,
    UserError,
    BlackHole,
    Io,
    Cancelled,
    Exit,
    Http,
    ResourceClosed,
    InternalInvariant,
    PanicContained,
}

impl RuntimeDiagnosticCode {
    /// Parses one exact runtime diagnostic code from retained evidence.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "H0803" => Some(Self::ResourceLimit),
            "H0901" => Some(Self::UserError),
            "H0902" => Some(Self::BlackHole),
            "H0903" => Some(Self::Io),
            "H0906" => Some(Self::Cancelled),
            "H0907" => Some(Self::Exit),
            "H0908" => Some(Self::Http),
            "H0909" => Some(Self::ResourceClosed),
            "H9001" => Some(Self::InternalInvariant),
            "H9004" => Some(Self::PanicContained),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Internal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WiringStatus {
    Executable,
    DeclaredOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompatibilityDimension {
    Parse,
    StaticSemantics,
    PureRuntime,
    Effects,
    Concurrency,
    Presentation,
    Platform,
    ResourceBehavior,
}

impl CompatibilityDimension {
    pub const ALL: [Self; 8] = [
        Self::Parse,
        Self::StaticSemantics,
        Self::PureRuntime,
        Self::Effects,
        Self::Concurrency,
        Self::Presentation,
        Self::Platform,
        Self::ResourceBehavior,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::StaticSemantics => "static-semantics",
            Self::PureRuntime => "pure-runtime",
            Self::Effects => "effects",
            Self::Concurrency => "concurrency",
            Self::Presentation => "presentation",
            Self::Platform => "platform",
            Self::ResourceBehavior => "resource-behavior",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClaimStatus {
    Exact,
    Normalized,
    PlatformDependent,
    DeliberateDivergence,
    Unverified,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionProfile {
    Upstream,
    Sandboxed,
}

impl ExecutionProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Sandboxed => "sandboxed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClaimPlatform {
    All,
    Linux,
    MacOs,
    Windows,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedClaim {
    pub status: ClaimStatus,
    pub profiles: &'static [ExecutionProfile],
    pub platforms: &'static [ClaimPlatform],
    pub evidence: &'static [&'static str],
    pub normalizers: &'static [NormalizerId],
    pub obligations: &'static [&'static str],
    pub applicability_rule: &'static str,
    pub rationale: Option<&'static str>,
    pub issue: Option<&'static str>,
    pub review_group: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DimensionClaim {
    pub dimension: CompatibilityDimension,
    pub scopes: &'static [ScopedClaim],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompatibilityClaim {
    pub builtin: BuiltinId,
    pub baseline: &'static str,
    pub dimensions: [DimensionClaim; CompatibilityDimension::ALL.len()],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimValidationError {
    RegistryLength,
    BuiltinOrder,
    Baseline,
    DimensionOrder,
    MissingEvidence,
    InvalidEvidence,
    MissingScope,
    MissingNormalizer,
    MissingRationale,
    MissingIssue,
    DuplicateProfile,
    DuplicatePlatform,
    DuplicateEvidence,
    DuplicateObligation,
    OverlappingScope,
    MissingApplicabilityRule,
    InvalidNormalizerScope,
    InvalidStatusMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DifferentialReference<'a> {
    pub case_id: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Demand {
    Lazy,
    Whnf,
    Deep,
    OnIoExecution,
    Conditional,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixity {
    Left(u8),
    Right(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinSpec {
    pub id: BuiltinId,
    pub name: &'static str,
    pub visibility: Visibility,
    pub scheme: Option<&'static str>,
    pub arity: u8,
    pub demand: &'static [Demand],
    pub fixity: Option<Fixity>,
    pub wiring: WiringStatus,
    /// The manifest class whose evidence must be attached to this primitive.
    pub type_class: Option<TypeClass>,
    /// `None` means the language name is accounted for but its adapter is not
    /// yet present in this build. Compilation reports H0004 instead of silently
    /// manufacturing a result.
    pub implementation: Option<&'static str>,
}

/// Trusted projection from an instantiated builtin type to the exact type
/// head constrained by its class predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceHeadProjection {
    FunctionArgument(u8),
    FunctionResult,
    ApplyFunction,
    ApplyArgument,
}

/// Returns the exact registry-owned path from a constrained builtin's full
/// instantiated type to its class-instance head.
#[must_use]
pub fn instance_head_projection(name: &str) -> Option<&'static [InstanceHeadProjection]> {
    use InstanceHeadProjection::{ApplyArgument, ApplyFunction, FunctionArgument, FunctionResult};
    Some(match name {
        "Show.show" | "IO.print" | "Eq.eq" | "Ord.lt" | "Ord.gt" | "List.lookup" | "List.elem"
        | "List.notElem" | "List.elemIndex" | "List.elemIndices" | "Map.lookup" | "Map.insert"
        | "Map.delete" | "Map.singleton" | "Set.insert" | "Set.member" | "Set.delete"
        | "Set.singleton" | "CI.mk" | "<>" => &[FunctionArgument(0)],
        "Map.insertWith" | "Map.adjust" => &[FunctionArgument(1)],
        "List.group"
        | "List.isInfixOf"
        | "List.isPrefixOf"
        | "List.isSubsequenceOf"
        | "List.isSuffixOf"
        | "List.sort"
        | "List.nubOrd"
        | "Set.union"
        | "Set.difference"
        | "Set.intersection" => &[FunctionArgument(0), ApplyArgument],
        "List.sortOn" => &[FunctionArgument(0), FunctionResult],
        "Map.fromList" => &[FunctionResult, ApplyFunction, ApplyArgument],
        "Map.unionWith" => &[FunctionArgument(1), ApplyFunction, ApplyArgument],
        "Set.fromList" => &[FunctionResult, ApplyArgument],
        "Functor.fmap" | "<$>" | "Monad.when" => &[FunctionArgument(1), ApplyFunction],
        "Applicative.pure" | "Monad.return" => &[FunctionResult, ApplyFunction],
        "<*>"
        | "<**>"
        | "Alternative.optional"
        | "Alternative.many"
        | "Monad.bind"
        | "Monad.then" => &[FunctionArgument(0), ApplyFunction],
        "Monad.mapM" | "Monad.mapM_" => &[FunctionArgument(0), FunctionResult, ApplyFunction],
        "Monad.forM" | "Monad.forM_" => &[FunctionArgument(1), FunctionResult, ApplyFunction],
        "Monad.sequence" => &[FunctionArgument(0), ApplyArgument, ApplyFunction],
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceReachability {
    Public,
    GeneratedOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectKind {
    Pure,
    Io,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeterminismClass {
    Deterministic,
    FixtureRelative,
    ScheduleSensitive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssuranceCapability {
    Filesystem,
    Process,
    Network,
    Clock,
    Concurrency,
    StandardIo,
    HostHandle,
    Environment,
    ProcessTermination,
    CommandLine,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssuranceResourceRole {
    Filesystem,
    TemporaryResource,
    Process,
    StandardInput,
    StandardOutput,
    StandardError,
    Handle,
    Environment,
    Clock,
    Network,
    Task,
    Timer,
    ProcessTermination,
    CommandLine,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssuranceSensitivity {
    Presentation,
    Concurrency,
    Resource,
    Platform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinAssuranceMetadata {
    pub source_reachability: SourceReachability,
    pub semantic_family: &'static str,
    pub effect_kind: EffectKind,
    pub capabilities: &'static [AssuranceCapability],
    pub determinism: DeterminismClass,
    pub sensitivities: &'static [AssuranceSensitivity],
    pub resource_roles: &'static [AssuranceResourceRole],
    pub host_failure_applicable: bool,
    pub compatibility_quirks: &'static [&'static str],
}

impl BuiltinSpec {
    /// Derives the fail-closed assurance contract for this registry entry.
    ///
    /// # Panics
    ///
    /// Panics when a public wired builtin has an unclassified IO return or
    /// host-domain type, forcing registry changes to extend the authority.
    #[must_use]
    pub fn assurance_metadata(&self) -> BuiltinAssuranceMetadata {
        const NO_SENSITIVITIES: &[AssuranceSensitivity] = &[];
        const PRESENTATION: &[AssuranceSensitivity] = &[AssuranceSensitivity::Presentation];
        const PRESENTATION_RESOURCE_PLATFORM: &[AssuranceSensitivity] = &[
            AssuranceSensitivity::Presentation,
            AssuranceSensitivity::Resource,
            AssuranceSensitivity::Platform,
        ];
        const CONCURRENT: &[AssuranceSensitivity] = &[
            AssuranceSensitivity::Concurrency,
            AssuranceSensitivity::Resource,
            AssuranceSensitivity::Platform,
        ];
        const RESOURCE_PLATFORM: &[AssuranceSensitivity] = &[
            AssuranceSensitivity::Resource,
            AssuranceSensitivity::Platform,
        ];
        const PLATFORM: &[AssuranceSensitivity] = &[AssuranceSensitivity::Platform];
        let semantic_family = self.name.split_once('.').map_or(self.name, |pair| pair.0);
        let capabilities = assurance_capabilities(self.implementation);
        let resource_roles = assurance_resource_roles(self.implementation);
        let compatibility_quirks = assurance_compatibility_quirks(self.name);
        let effect_kind = if self.scheme.is_some_and(scheme_returns_io) {
            EffectKind::Io
        } else {
            EffectKind::Pure
        };
        assert!(
            assurance_contract_is_complete(self, effect_kind, capabilities, resource_roles),
            "public builtin {} has no explicit host/effect/resource assurance contract",
            self.name
        );
        let concurrency_sensitive = capabilities.contains(&AssuranceCapability::Concurrency);
        let determinism = if concurrency_sensitive {
            DeterminismClass::ScheduleSensitive
        } else if effect_kind == EffectKind::Io {
            DeterminismClass::FixtureRelative
        } else {
            DeterminismClass::Deterministic
        };
        let presentation_sensitive = self.name == "IO.print"
            || matches!(
                semantic_family,
                "Show" | "Text" | "Json" | "Options" | "Diagnostic"
            );
        let sensitivities = if presentation_sensitive
            && (effect_kind == EffectKind::Io
                || !capabilities.is_empty()
                || !resource_roles.is_empty())
        {
            PRESENTATION_RESOURCE_PLATFORM
        } else if presentation_sensitive {
            PRESENTATION
        } else if concurrency_sensitive {
            CONCURRENT
        } else if effect_kind == EffectKind::Io
            || !capabilities.is_empty()
            || !resource_roles.is_empty()
            || matches!(semantic_family, "List" | "Map" | "Set")
        {
            RESOURCE_PLATFORM
        } else if matches!(semantic_family, "Int" | "Word" | "Double") {
            PLATFORM
        } else {
            NO_SENSITIVITIES
        };
        BuiltinAssuranceMetadata {
            source_reachability: match self.visibility {
                Visibility::Public => SourceReachability::Public,
                Visibility::Internal => SourceReachability::GeneratedOnly,
            },
            semantic_family,
            effect_kind,
            capabilities,
            determinism,
            sensitivities,
            resource_roles,
            host_failure_applicable: host_failure_applicable(self.implementation),
            compatibility_quirks,
        }
    }
}

fn assurance_capabilities(implementation: Option<&str>) -> &'static [AssuranceCapability] {
    use AssuranceCapability as Capability;
    match implementation {
        Some(
            "text_read_file"
            | "text_write_file"
            | "text_append_file"
            | "bytes_read_file"
            | "bytes_write_file"
            | "io_open_file"
            | "temp_with_directory"
            | "temp_with_file",
        ) => &[Capability::Filesystem],
        Some(value) if value.starts_with("directory_") => &[Capability::Filesystem],
        Some(
            "text_read_process"
            | "text_read_process_checked"
            | "text_read_process_stdout_checked"
            | "bytes_read_process"
            | "bytes_read_process_checked"
            | "bytes_read_process_stdout_checked"
            | "process_run"
            | "process_run_checked",
        ) => &[Capability::Process],
        Some("utc_time_get_current") => &[Capability::Clock],
        Some("thread_delay" | "timeout") => &[Capability::Concurrency],
        Some(value) if value.starts_with("async_") => &[Capability::Concurrency],
        Some("http_get_body_chunk" | "http_consume_body" | "http_run") => &[Capability::Network],
        Some(
            "text_get_line" | "text_get_contents" | "text_put_str" | "text_put_str_ln"
            | "text_interact" | "bytes_get_contents" | "bytes_interact" | "io_print" | "io_stdin"
            | "io_stdout" | "io_stderr",
        ) => &[Capability::StandardIo],
        Some(
            "io_h_close" | "io_h_set_buffering" | "text_h_put_str" | "bytes_h_get"
            | "bytes_h_put_str",
        ) => &[Capability::HostHandle],
        Some("environment_get_args" | "environment_get_env" | "environment_get_environment") => {
            &[Capability::Environment]
        }
        Some("exit_die" | "exit_with") => &[Capability::ProcessTermination],
        Some("options_exec_parser") => &[Capability::CommandLine],
        _ => &[],
    }
}

fn assurance_resource_roles(implementation: Option<&str>) -> &'static [AssuranceResourceRole] {
    use AssuranceResourceRole as Role;
    match implementation {
        Some("temp_with_directory") => &[Role::TemporaryResource],
        Some("temp_with_file") => &[Role::TemporaryResource, Role::Handle],
        Some(
            "text_read_file" | "text_write_file" | "text_append_file" | "bytes_read_file"
            | "bytes_write_file",
        ) => &[Role::Filesystem],
        Some("io_open_file") => &[Role::Filesystem, Role::Handle],
        Some(value) if value.starts_with("directory_") => &[Role::Filesystem],
        Some(
            "io_stdin" | "text_get_line" | "text_get_contents" | "text_interact"
            | "bytes_get_contents" | "bytes_interact",
        ) => &[Role::StandardInput],
        Some("io_stdout" | "io_print" | "text_put_str" | "text_put_str_ln") => {
            &[Role::StandardOutput]
        }
        Some("io_stderr") => &[Role::StandardError],
        Some(
            "io_h_close" | "io_h_set_buffering" | "text_h_put_str" | "bytes_h_get"
            | "bytes_h_put_str",
        ) => &[Role::Handle],
        Some(
            "text_read_process"
            | "text_read_process_checked"
            | "text_read_process_stdout_checked"
            | "text_set_stdin"
            | "bytes_read_process"
            | "bytes_read_process_checked"
            | "bytes_read_process_stdout_checked"
            | "process_run"
            | "process_run_checked"
            | "process_null_stream"
            | "process_proc"
            | "process_set_env"
            | "process_set_stderr"
            | "process_set_stdin"
            | "process_set_stdout"
            | "process_set_working_dir"
            | "process_use_handle_close"
            | "process_use_handle_open",
        ) => &[Role::Process],
        Some("environment_get_args" | "environment_get_env" | "environment_get_environment") => {
            &[Role::Environment]
        }
        Some("utc_time_get_current") => &[Role::Clock],
        Some("thread_delay" | "timeout") => &[Role::Timer],
        Some(value) if value.starts_with("async_") => &[Role::Task],
        Some("http_run") => &[Role::Network, Role::Task],
        Some(value) if value.starts_with("http_") => &[Role::Network],
        Some("exit_die" | "exit_with") => &[Role::ProcessTermination],
        Some("options_exec_parser") => &[Role::CommandLine],
        _ => &[],
    }
}

fn scheme_returns_io(scheme: &str) -> bool {
    let mut depth = 0_u32;
    let mut result_start = 0;
    let bytes = scheme.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'(' | b'[' => depth = depth.saturating_add(1),
            b')' | b']' => depth = depth.saturating_sub(1),
            b'-' if depth == 0 && bytes.get(index + 1) == Some(&b'>') => {
                result_start = index + 2;
                index += 1;
            }
            _ => {}
        }
        index += 1;
    }
    scheme[result_start..].trim_start().starts_with("IO ")
}

fn assurance_contract_is_complete(
    spec: &BuiltinSpec,
    effect_kind: EffectKind,
    capabilities: &[AssuranceCapability],
    resource_roles: &[AssuranceResourceRole],
) -> bool {
    if spec.visibility != Visibility::Public || spec.implementation.is_none() {
        return true;
    }
    if effect_kind == EffectKind::Io {
        return !capabilities.is_empty()
            || !resource_roles.is_empty()
            || matches!(
                spec.implementation,
                Some("io_pure" | "io_map_m_" | "io_for_m_")
            );
    }
    let scheme = spec.scheme.unwrap_or_default();
    let carries_host_domain = [
        "Handle", "Process", "Request", "Response", "Status", "FilePart",
    ]
    .iter()
    .any(|domain| scheme.contains(domain));
    !carries_host_domain || !resource_roles.is_empty()
}

fn host_failure_applicable(implementation: Option<&str>) -> bool {
    matches!(
        implementation,
        Some(
            "text_read_file"
                | "text_write_file"
                | "text_append_file"
                | "bytes_read_file"
                | "bytes_write_file"
                | "io_open_file"
                | "temp_with_directory"
                | "temp_with_file"
                | "text_read_process"
                | "text_read_process_checked"
                | "text_read_process_stdout_checked"
                | "bytes_read_process"
                | "bytes_read_process_checked"
                | "bytes_read_process_stdout_checked"
                | "process_run"
                | "process_run_checked"
                | "http_get_body_chunk"
                | "http_consume_body"
                | "http_run"
                | "text_get_line"
                | "text_get_contents"
                | "text_interact"
                | "environment_get_env"
                | "exit_die"
                | "exit_with"
                | "options_exec_parser"
                | "thread_delay"
                | "timeout"
                | "async_concurrently"
                | "async_race"
                | "async_pooled_map"
                | "async_pooled_for"
                | "async_pooled_map_"
                | "async_pooled_for_"
        )
    ) || implementation.is_some_and(|value| value.starts_with("directory_"))
}

fn assurance_compatibility_quirks(name: &str) -> &'static [&'static str] {
    match name {
        "Int.subtract" | "Integer.subtract" | "Double.subtract" => {
            &["upstream-second-argument-minus-first"]
        }
        "List.mapAccumR" => &["upstream-map-accum-r-uses-left-order"],
        _ => &[],
    }
}

const LAZY: &[Demand] = &[Demand::Lazy];
const TWO_LAZY: &[Demand] = &[Demand::Lazy, Demand::Lazy];
const WHNF: &[Demand] = &[Demand::Whnf];
const TWO_WHNF: &[Demand] = &[Demand::Whnf, Demand::Whnf];
const THREE_WHNF: &[Demand] = &[Demand::Whnf, Demand::Whnf, Demand::Whnf];
const CONDITIONAL3: &[Demand] = &[Demand::Lazy, Demand::Lazy, Demand::Conditional];
const IO_ARG: &[Demand] = &[Demand::OnIoExecution];
const IO_TWO: &[Demand] = &[Demand::OnIoExecution, Demand::OnIoExecution];

/// All 345 public names in the pinned registry. Whitespace is used only as a
/// source-code separator; every guest name itself is whitespace-free.
pub const PUBLIC_NAMES: &str = r"
List.all List.and List.any List.break List.concat List.concatMap List.cons List.cycle
List.deleteBy List.drop List.dropWhile List.dropWhileEnd List.elem List.elemIndex List.elemIndices
List.filter List.find List.findIndex List.findIndices List.foldl' List.foldr List.group List.groupBy
List.inits List.intercalate List.intersperse List.isInfixOf List.isPrefixOf List.isSubsequenceOf
List.isSuffixOf List.iterate' List.length List.lookup List.map List.mapAccumL List.mapAccumR List.nil
List.notElem List.nubOrd List.null List.or List.partition List.permutations List.repeat List.reverse
List.scanl' List.scanr List.sort List.sortOn List.span List.splitAt List.subsequences List.tails
List.take List.takeWhile List.transpose List.uncons List.unfoldr List.zip List.zipWith
Text.all Text.any Text.appendFile Text.breakOn Text.concat Text.decodeUtf8 Text.drop Text.dropEnd
Text.encodeUtf8 Text.eq Text.filter Text.getContents Text.getLine Text.hPutStr Text.interact
Text.intercalate Text.isInfixOf Text.isPrefixOf Text.isSuffixOf Text.length Text.lines Text.pack
Text.putStr Text.putStrLn Text.readFile Text.readProcess Text.readProcessStdout_ Text.readProcess_
Text.replace Text.reverse Text.setStdin Text.splitOn Text.strip Text.stripPrefix Text.stripSuffix
Text.take Text.takeEnd Text.toLower Text.toUpper Text.unlines Text.unpack Text.unwords Text.words
Text.writeFile
IO.AppendMode IO.BlockBuffering IO.LineBuffering IO.NoBuffering IO.ReadMode IO.ReadWriteMode
IO.WriteMode IO.forM_ IO.hClose IO.hSetBuffering IO.mapM_ IO.openFile IO.print IO.pure IO.stderr
IO.stdin IO.stdout
Map.adjust Map.all Map.any Map.delete Map.elems Map.filter Map.filterWithKey Map.fromList Map.insert
Map.insertWith Map.keys Map.lookup Map.map Map.singleton Map.size Map.toList Map.unionWith
Directory.copyFile Directory.createDirectory Directory.createDirectoryIfMissing
Directory.doesDirectoryExist Directory.doesFileExist Directory.getCurrentDirectory
Directory.getFileSize Directory.getHomeDirectory Directory.getSymbolicLinkTarget Directory.listDirectory
Directory.pathIsSymbolicLink Directory.removeDirectory Directory.removeFile Directory.renameFile
Directory.setCurrentDirectory
Options.command Options.execParser Options.flag Options.flag' Options.fullDesc Options.header
Options.helper Options.hsubparser Options.info Options.progDesc Options.strArgument Options.strOption
Options.switch
Http.FilePart Http.consumeRequestBodyStrict Http.getRequestBodyChunk Http.mkStatus Http.pathInfo
Http.queryString Http.requestHeaders Http.responseBuilder Http.responseFile Http.responseStream Http.run
Process.nullStream Process.proc Process.runProcess Process.runProcess_ Process.setEnv Process.setStderr
Process.setStdin Process.setStdout Process.setWorkingDir Process.useHandleClose Process.useHandleOpen
Set.delete Set.difference Set.fromList Set.insert Set.intersection Set.member Set.singleton Set.size
Set.toList Set.union
ByteString.getContents ByteString.hGet ByteString.hPutStr ByteString.interact ByteString.readFile
ByteString.readProcess ByteString.readProcessStdout_ ByteString.readProcess_ ByteString.writeFile
Double.eq Double.fromInt Double.mult Double.plus Double.readMaybe Double.show Double.showEFloat
Double.showFFloat Double.subtract
Json.Array Json.Bool Json.Null Json.Number Json.Object Json.String Json.decode Json.encode Json.value
Monad.bind Monad.forM Monad.forM_ Monad.mapM Monad.mapM_ Monad.return Monad.sequence Monad.then Monad.when
Int.eq Int.fromInteger Int.mult Int.plus Int.readMaybe Int.show Int.subtract Int.toInteger
TimeOfDay.makeTimeOfDayValid TimeOfDay.midday TimeOfDay.midnight TimeOfDay.timeOfDayToTime
TimeOfDay.timeToTimeOfDay TimeOfDay.todHour TimeOfDay.todMin TimeOfDay.todSec
UTCTime.UTCTime UTCTime.addUTCTime UTCTime.diffUTCTime UTCTime.getCurrentTime
UTCTime.iso8601ParseM UTCTime.iso8601Show UTCTime.utctDay UTCTime.utctDayTime
Day.addDays Day.dayOfWeek Day.diffDays Day.fromGregorianValid Day.iso8601ParseM Day.iso8601Show
Day.toGregorian
Async.concurrently Async.pooledForConcurrently Async.pooledForConcurrently_
Async.pooledMapConcurrently Async.pooledMapConcurrently_ Async.race
$ . <$> <**> <*> <>
Tree.Node Tree.flatten Tree.foldTree Tree.levels Tree.map Tree.unfoldTree
Exit.ExitFailure Exit.ExitSuccess Exit.die Exit.exitCode Exit.exitWith
Maybe.Just Maybe.Nothing Maybe.listToMaybe Maybe.mapMaybe Maybe.maybe
Bool.False Bool.True Bool.bool Bool.not
Integer.mult Integer.plus Integer.readMaybe Integer.subtract
These.That These.These These.This These.these
Argument.help Argument.metavar Argument.value
Either.Left Either.Right Either.either
Environment.getArgs Environment.getEnv Environment.getEnvironment
Option.help Option.long Option.value
Record.get Record.modify Record.set
Tuple.(,) Tuple.(,,) Tuple.(,,,)
Alternative.many Alternative.optional
CI.foldedCase CI.mk
Flag.help Flag.long
Function.fix Function.id
Ord.gt Ord.lt
Temp.withSystemTempDirectory Temp.withSystemTempFile
Vector.fromList Vector.toList
Applicative.pure Builder.byteString Concurrent.threadDelay Eq.eq Error.error Functor.fmap Show.show
Timeout.timeout
";

pub const INTERNAL_NAMES: &[&str] = &[
    "hell:Hell.ConsA",
    "hell:Hell.ConsR",
    "hell:Hell.LeftV",
    "hell:Hell.NilA",
    "hell:Hell.NilR",
    "hell:Hell.Nullary",
    "hell:Hell.RightV",
    "hell:Hell.Tagged",
    "hell:Hell.WildA",
    "hell:Hell.runAccessor",
];

pub const KNOWN_SOURCE_DUPLICATES: &[&str] = &["Text.isPrefixOf", "Text.isSuffixOf", "Tuple.(,)"];

#[allow(clippy::too_many_lines)]
fn executable(name: &str) -> Option<(&'static str, u8, &'static [Demand], &'static str)> {
    Some(match name {
        "Bool.False" => ("Bool", 0, &[], "bool_false"),
        "Bool.True" => ("Bool", 0, &[], "bool_true"),
        "Bool.bool" => (
            "forall a. a -> a -> Bool -> a",
            3,
            CONDITIONAL3,
            "bool_choose",
        ),
        "Bool.not" => ("Bool -> Bool", 1, WHNF, "bool_not"),
        "Error.error" => ("forall a. Text -> a", 1, WHNF, "error"),
        "Function.id" => ("forall a. a -> a", 1, LAZY, "identity"),
        "Function.fix" => ("forall a. (a -> a) -> a", 1, LAZY, "fix"),
        "Record.get" => (
            "forall (k :: Symbol) a (t :: Symbol) xs. hell:Hell.Tagged t (hell:Hell.Record xs) -> a",
            1,
            LAZY,
            "record_get_specialized",
        ),
        "Record.set" => (
            "forall (k :: Symbol) a (t :: Symbol) xs. a -> hell:Hell.Tagged t (hell:Hell.Record xs) -> hell:Hell.Tagged t (hell:Hell.Record xs)",
            2,
            TWO_LAZY,
            "record_set_specialized",
        ),
        "Record.modify" => (
            "forall (k :: Symbol) a (t :: Symbol) xs. (a -> a) -> hell:Hell.Tagged t (hell:Hell.Record xs) -> hell:Hell.Tagged t (hell:Hell.Record xs)",
            2,
            TWO_LAZY,
            "record_modify_specialized",
        ),
        "Int.eq" => ("Int -> Int -> Bool", 2, TWO_WHNF, "int_eq"),
        "Eq.eq" => ("forall a. Eq a => a -> a -> Bool", 2, TWO_WHNF, "eq"),
        "Ord.lt" => ("forall a. Ord a => a -> a -> Bool", 2, TWO_WHNF, "ord_lt"),
        "Ord.gt" => ("forall a. Ord a => a -> a -> Bool", 2, TWO_WHNF, "ord_gt"),
        "Int.plus" => ("Int -> Int -> Int", 2, TWO_WHNF, "int_plus"),
        "Int.subtract" => ("Int -> Int -> Int", 2, TWO_WHNF, "int_subtract"),
        "Int.mult" => ("Int -> Int -> Int", 2, TWO_WHNF, "int_mult"),
        "Int.show" => ("Int -> Text", 1, WHNF, "int_show"),
        "Int.readMaybe" => ("Text -> Maybe Int", 1, WHNF, "int_read_maybe"),
        "Int.toInteger" => ("Int -> Integer", 1, WHNF, "int_to_integer"),
        "Int.fromInteger" => ("Integer -> Int", 1, WHNF, "int_from_integer"),
        "Integer.plus" => ("Integer -> Integer -> Integer", 2, TWO_WHNF, "integer_plus"),
        "Integer.subtract" => (
            "Integer -> Integer -> Integer",
            2,
            TWO_WHNF,
            "integer_subtract",
        ),
        "Integer.mult" => ("Integer -> Integer -> Integer", 2, TWO_WHNF, "integer_mult"),
        "Integer.readMaybe" => ("Text -> Maybe Integer", 1, WHNF, "integer_read_maybe"),
        "Double.eq" => ("Double -> Double -> Bool", 2, TWO_WHNF, "double_eq"),
        "Double.fromInt" => ("Int -> Double", 1, WHNF, "double_from_int"),
        "Double.plus" => ("Double -> Double -> Double", 2, TWO_WHNF, "double_plus"),
        "Double.subtract" => ("Double -> Double -> Double", 2, TWO_WHNF, "double_subtract"),
        "Double.mult" => ("Double -> Double -> Double", 2, TWO_WHNF, "double_mult"),
        "Double.readMaybe" => ("Text -> Maybe Double", 1, WHNF, "double_read_maybe"),
        "Double.show" => ("Double -> Text", 1, WHNF, "double_show"),
        "Double.showEFloat" => (
            "Maybe Int -> Double -> Text -> Text",
            3,
            &[Demand::Whnf, Demand::Whnf, Demand::Whnf],
            "double_show_e_float",
        ),
        "Double.showFFloat" => (
            "Maybe Int -> Double -> Text -> Text",
            3,
            &[Demand::Whnf, Demand::Whnf, Demand::Whnf],
            "double_show_f_float",
        ),
        "Show.show" => ("forall a. Show a => a -> Text", 1, WHNF, "show"),
        "Functor.fmap" | "<$>" => (
            "forall f a b. Functor f => (a -> b) -> f a -> f b",
            2,
            TWO_LAZY,
            "functor_map",
        ),
        "IO.pure" => ("forall a. a -> IO a", 1, LAZY, "io_pure"),
        "Applicative.pure" => (
            "forall f a. Applicative f => a -> f a",
            1,
            LAZY,
            "applicative_pure",
        ),
        "Monad.return" => ("forall m a. Monad m => a -> m a", 1, LAZY, "io_pure"),
        "<*>" => (
            "forall f a b. Applicative f => f (a -> b) -> f a -> f b",
            2,
            TWO_LAZY,
            "applicative_apply",
        ),
        "<**>" => (
            "forall f a b. Applicative f => f a -> f (a -> b) -> f b",
            2,
            TWO_LAZY,
            "applicative_apply_flipped",
        ),
        "Alternative.optional" => (
            "forall f a. Alternative f => f a -> f (Maybe a)",
            1,
            LAZY,
            "alternative_optional",
        ),
        "Alternative.many" => (
            "forall f a. Alternative f => f a -> f [a]",
            1,
            LAZY,
            "alternative_many",
        ),
        "IO.print" => ("forall a. Show a => a -> IO ()", 1, IO_ARG, "io_print"),
        "Monad.bind" => (
            "forall m a b. Monad m => m a -> (a -> m b) -> m b",
            2,
            TWO_LAZY,
            "io_bind",
        ),
        "Monad.then" => (
            "forall m a b. Monad m => m a -> m b -> m b",
            2,
            TWO_LAZY,
            "io_then",
        ),
        "Concurrent.threadDelay" => ("Int -> IO ()", 1, IO_ARG, "thread_delay"),
        "Timeout.timeout" => (
            "forall a. Int -> IO a -> IO (Maybe a)",
            2,
            IO_TWO,
            "timeout",
        ),
        "Day.fromGregorianValid" => (
            "Integer -> Int -> Int -> Maybe Day",
            3,
            THREE_WHNF,
            "day_from_gregorian_valid",
        ),
        "Day.toGregorian" => ("Day -> (Integer, Int, Int)", 1, WHNF, "day_to_gregorian"),
        "Day.addDays" => ("Integer -> Day -> Day", 2, TWO_WHNF, "day_add_days"),
        "Day.diffDays" => ("Day -> Day -> Integer", 2, TWO_WHNF, "day_diff_days"),
        "Day.dayOfWeek" => ("Day -> DayOfWeek", 1, WHNF, "day_of_week"),
        "Day.iso8601Show" => ("Day -> Text", 1, WHNF, "day_iso8601_show"),
        "Day.iso8601ParseM" => ("Text -> Maybe Day", 1, WHNF, "day_iso8601_parse"),
        "UTCTime.UTCTime" => ("Day -> Double -> UTCTime", 2, TWO_WHNF, "utc_time_new"),
        "UTCTime.utctDay" => ("UTCTime -> Day", 1, WHNF, "utc_time_day"),
        "UTCTime.utctDayTime" => ("UTCTime -> Double", 1, WHNF, "utc_time_day_time"),
        "UTCTime.addUTCTime" => ("Double -> UTCTime -> UTCTime", 2, TWO_WHNF, "utc_time_add"),
        "UTCTime.diffUTCTime" => ("UTCTime -> UTCTime -> Double", 2, TWO_WHNF, "utc_time_diff"),
        "UTCTime.getCurrentTime" => ("IO UTCTime", 0, &[], "utc_time_get_current"),
        "UTCTime.iso8601Show" => ("UTCTime -> Text", 1, WHNF, "utc_time_iso8601_show"),
        "UTCTime.iso8601ParseM" => ("Text -> Maybe UTCTime", 1, WHNF, "utc_time_iso8601_parse"),
        "TimeOfDay.timeToTimeOfDay" => ("Double -> TimeOfDay", 1, WHNF, "time_of_day_from_time"),
        "TimeOfDay.todHour" => ("TimeOfDay -> Int", 1, WHNF, "time_of_day_hour"),
        "TimeOfDay.todMin" => ("TimeOfDay -> Int", 1, WHNF, "time_of_day_minute"),
        "TimeOfDay.todSec" => ("TimeOfDay -> Double", 1, WHNF, "time_of_day_second"),
        "TimeOfDay.midnight" => ("TimeOfDay", 0, &[], "time_of_day_midnight"),
        "TimeOfDay.midday" => ("TimeOfDay", 0, &[], "time_of_day_midday"),
        "TimeOfDay.makeTimeOfDayValid" => (
            "Int -> Int -> Double -> Maybe TimeOfDay",
            3,
            THREE_WHNF,
            "time_of_day_make_valid",
        ),
        "TimeOfDay.timeOfDayToTime" => ("TimeOfDay -> Double", 1, WHNF, "time_of_day_to_time"),
        "Async.concurrently" => (
            "forall a b. IO a -> IO b -> IO (a, b)",
            2,
            IO_TWO,
            "async_concurrently",
        ),
        "Async.race" => (
            "forall a b. IO a -> IO b -> IO (Either a b)",
            2,
            IO_TWO,
            "async_race",
        ),
        "Async.pooledMapConcurrently" => (
            "forall a b. (a -> IO b) -> [a] -> IO [b]",
            2,
            IO_TWO,
            "async_pooled_map",
        ),
        "Async.pooledForConcurrently" => (
            "forall a b. [a] -> (a -> IO b) -> IO [b]",
            2,
            IO_TWO,
            "async_pooled_for",
        ),
        "Async.pooledMapConcurrently_" => (
            "forall a. (a -> IO ()) -> [a] -> IO ()",
            2,
            IO_TWO,
            "async_pooled_map_",
        ),
        "Async.pooledForConcurrently_" => (
            "forall a. [a] -> (a -> IO ()) -> IO ()",
            2,
            IO_TWO,
            "async_pooled_for_",
        ),
        "Text.eq" => ("Text -> Text -> Bool", 2, TWO_WHNF, "text_eq"),
        "Text.all" => ("(Char -> Bool) -> Text -> Bool", 2, TWO_LAZY, "text_all"),
        "Text.any" => ("(Char -> Bool) -> Text -> Bool", 2, TWO_LAZY, "text_any"),
        "Text.breakOn" => ("Text -> Text -> (Text, Text)", 2, TWO_WHNF, "text_break_on"),
        "Text.concat" => ("[Text] -> Text", 1, WHNF, "text_concat"),
        "Text.getLine" => ("IO Text", 0, &[], "text_get_line"),
        "Text.take" => ("Int -> Text -> Text", 2, TWO_WHNF, "text_take"),
        "Text.drop" => ("Int -> Text -> Text", 2, TWO_WHNF, "text_drop"),
        "Text.dropEnd" => ("Int -> Text -> Text", 2, TWO_WHNF, "text_drop_end"),
        "Text.filter" => (
            "(Char -> Bool) -> Text -> Text",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "text_filter",
        ),
        "Text.strip" => ("Text -> Text", 1, WHNF, "text_strip"),
        "Text.stripPrefix" => (
            "Text -> Text -> Maybe Text",
            2,
            TWO_WHNF,
            "text_strip_prefix",
        ),
        "Text.stripSuffix" => (
            "Text -> Text -> Maybe Text",
            2,
            TWO_WHNF,
            "text_strip_suffix",
        ),
        "Text.isInfixOf" => ("Text -> Text -> Bool", 2, TWO_WHNF, "text_is_infix_of"),
        "Text.isPrefixOf" => ("Text -> Text -> Bool", 2, TWO_WHNF, "text_is_prefix_of"),
        "Text.isSuffixOf" => ("Text -> Text -> Bool", 2, TWO_WHNF, "text_is_suffix_of"),
        "Text.intercalate" => ("Text -> [Text] -> Text", 2, TWO_WHNF, "text_intercalate"),
        "Text.length" => ("Text -> Int", 1, WHNF, "text_length"),
        "Text.lines" => ("Text -> [Text]", 1, WHNF, "text_lines"),
        "Text.pack" => ("[Char] -> Text", 1, WHNF, "text_pack"),
        "Text.replace" => (
            "Text -> Text -> Text -> Text",
            3,
            &[Demand::Whnf, Demand::Whnf, Demand::Whnf],
            "text_replace",
        ),
        "Text.reverse" => ("Text -> Text", 1, WHNF, "text_reverse"),
        "Text.splitOn" => ("Text -> Text -> [Text]", 2, TWO_WHNF, "text_split_on"),
        "Text.takeEnd" => ("Int -> Text -> Text", 2, TWO_WHNF, "text_take_end"),
        "Text.toLower" => ("Text -> Text", 1, WHNF, "text_to_lower"),
        "Text.toUpper" => ("Text -> Text", 1, WHNF, "text_to_upper"),
        "Text.unlines" => ("[Text] -> Text", 1, WHNF, "text_unlines"),
        "Text.unpack" => ("Text -> [Char]", 1, WHNF, "text_unpack"),
        "Text.unwords" => ("[Text] -> Text", 1, WHNF, "text_unwords"),
        "Text.words" => ("Text -> [Text]", 1, WHNF, "text_words"),
        "Text.putStr" => ("Text -> IO ()", 1, IO_ARG, "text_put_str"),
        "Text.putStrLn" => ("Text -> IO ()", 1, IO_ARG, "text_put_str_ln"),
        "Text.getContents" => ("IO Text", 0, &[], "text_get_contents"),
        "Text.interact" => ("(Text -> Text) -> IO ()", 1, LAZY, "text_interact"),
        "Text.readFile" => ("Text -> IO Text", 1, IO_ARG, "text_read_file"),
        "Text.writeFile" => ("Text -> Text -> IO ()", 2, IO_TWO, "text_write_file"),
        "Text.appendFile" => ("Text -> Text -> IO ()", 2, IO_TWO, "text_append_file"),
        "Text.hPutStr" => ("Handle -> Text -> IO ()", 2, IO_TWO, "text_h_put_str"),
        "Text.readProcess" => (
            "Process -> IO (ExitCode, Text, Text)",
            1,
            IO_ARG,
            "text_read_process",
        ),
        "Text.readProcess_" => (
            "Process -> IO (Text, Text)",
            1,
            IO_ARG,
            "text_read_process_checked",
        ),
        "Text.readProcessStdout_" => (
            "Process -> IO Text",
            1,
            IO_ARG,
            "text_read_process_stdout_checked",
        ),
        "Text.setStdin" => ("Text -> Process -> Process", 2, TWO_WHNF, "text_set_stdin"),
        "Text.encodeUtf8" => ("Text -> ByteString", 1, WHNF, "text_encode_utf8"),
        "Text.decodeUtf8" => ("ByteString -> Text", 1, WHNF, "text_decode_utf8"),
        "IO.stdin" => ("Handle", 0, &[], "io_stdin"),
        "IO.stdout" => ("Handle", 0, &[], "io_stdout"),
        "IO.stderr" => ("Handle", 0, &[], "io_stderr"),
        "IO.NoBuffering" => ("BufferMode", 0, &[], "io_no_buffering"),
        "IO.LineBuffering" => ("BufferMode", 0, &[], "io_line_buffering"),
        "IO.BlockBuffering" => ("BufferMode", 0, &[], "io_block_buffering"),
        "IO.ReadMode" => ("FileMode", 0, &[], "io_read_mode"),
        "IO.WriteMode" => ("FileMode", 0, &[], "io_write_mode"),
        "IO.AppendMode" => ("FileMode", 0, &[], "io_append_mode"),
        "IO.ReadWriteMode" => ("FileMode", 0, &[], "io_read_write_mode"),
        "IO.openFile" => ("Text -> FileMode -> IO Handle", 2, IO_TWO, "io_open_file"),
        "IO.hClose" => ("Handle -> IO ()", 1, IO_ARG, "io_h_close"),
        "IO.hSetBuffering" => (
            "Handle -> BufferMode -> IO ()",
            2,
            IO_TWO,
            "io_h_set_buffering",
        ),
        "Temp.withSystemTempDirectory" => (
            "forall a. Text -> (Text -> IO a) -> IO a",
            2,
            IO_TWO,
            "temp_with_directory",
        ),
        "Temp.withSystemTempFile" => (
            "forall a. Text -> (Text -> Handle -> IO a) -> IO a",
            2,
            IO_TWO,
            "temp_with_file",
        ),
        "List.break" | "List.span" => (
            "forall a. (a -> Bool) -> [a] -> ([a], [a])",
            2,
            &[Demand::Lazy, Demand::Whnf],
            if name == "List.break" {
                "list_break"
            } else {
                "list_span"
            },
        ),
        "List.concatMap" => (
            "forall a b. (a -> [b]) -> [a] -> [b]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_concat_map",
        ),
        "List.cycle" => ("forall a. [a] -> [a]", 1, WHNF, "list_cycle"),
        "List.deleteBy" => (
            "forall a. (a -> a -> Bool) -> a -> [a] -> [a]",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "list_delete_by",
        ),
        "List.dropWhileEnd" => (
            "forall a. (a -> Bool) -> [a] -> [a]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_drop_while_end",
        ),
        "List.foldr" => (
            "forall a b. (a -> b -> b) -> b -> [a] -> b",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "list_foldr",
        ),
        "List.group" => ("forall a. Eq a => [a] -> [[a]]", 1, WHNF, "list_group"),
        "List.groupBy" => (
            "forall a. (a -> a -> Bool) -> [a] -> [[a]]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_group_by",
        ),
        "List.inits" => ("forall a. [a] -> [[a]]", 1, WHNF, "list_inits"),
        "List.intercalate" => (
            "forall a. [a] -> [[a]] -> [a]",
            2,
            TWO_WHNF,
            "list_intercalate",
        ),
        "List.intersperse" => (
            "forall a. a -> [a] -> [a]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_intersperse",
        ),
        "List.isInfixOf" | "List.isSuffixOf" => (
            "forall a. Eq a => [a] -> [a] -> Bool",
            2,
            TWO_LAZY,
            if name == "List.isInfixOf" {
                "list_is_infix_of"
            } else {
                "list_is_suffix_of"
            },
        ),
        "List.mapAccumL" | "List.mapAccumR" => (
            "forall acc a b. (acc -> a -> (acc, b)) -> acc -> [a] -> (acc, [b])",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "list_map_accum_l_compat",
        ),
        "List.nubOrd" => ("forall a. Ord a => [a] -> [a]", 1, WHNF, "list_nub_ord"),
        "List.partition" => (
            "forall a. (a -> Bool) -> [a] -> ([a], [a])",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_partition",
        ),
        "List.permutations" => ("forall a. [a] -> [[a]]", 1, LAZY, "list_permutations"),
        "List.scanl'" => (
            "forall a b. (b -> a -> b) -> b -> [a] -> [b]",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "list_scanl_strict",
        ),
        "List.scanr" => (
            "forall a b. (a -> b -> b) -> b -> [a] -> [b]",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "list_scanr",
        ),
        "List.sort" => ("forall a. Ord a => [a] -> [a]", 1, WHNF, "list_sort"),
        "List.splitAt" => (
            "forall a. Int -> [a] -> ([a], [a])",
            2,
            TWO_WHNF,
            "list_split_at",
        ),
        "List.subsequences" => ("forall a. [a] -> [[a]]", 1, LAZY, "list_subsequences"),
        "List.tails" => ("forall a. [a] -> [[a]]", 1, WHNF, "list_tails"),
        "List.transpose" => ("forall a. [[a]] -> [[a]]", 1, WHNF, "list_transpose"),
        "List.unfoldr" => (
            "forall a b. (b -> Maybe (a, b)) -> b -> [a]",
            2,
            &[Demand::Lazy, Demand::Lazy],
            "list_unfoldr",
        ),
        "List.all" => (
            "forall a. (a -> Bool) -> [a] -> Bool",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_all",
        ),
        "List.any" => (
            "forall a. (a -> Bool) -> [a] -> Bool",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_any",
        ),
        "List.concat" => ("forall a. [[a]] -> [a]", 1, WHNF, "list_concat"),
        "List.drop" => ("forall a. Int -> [a] -> [a]", 2, TWO_WHNF, "list_drop"),
        "List.dropWhile" => (
            "forall a. (a -> Bool) -> [a] -> [a]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_drop_while",
        ),
        "List.elem" => (
            "forall a. Eq a => a -> [a] -> Bool",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_elem",
        ),
        "List.notElem" => (
            "forall a. Eq a => a -> [a] -> Bool",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_not_elem",
        ),
        "List.elemIndex" => (
            "forall a. Eq a => a -> [a] -> Maybe Int",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_elem_index",
        ),
        "List.elemIndices" => (
            "forall a. Eq a => a -> [a] -> [Int]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_elem_indices",
        ),
        "List.filter" => (
            "forall a. (a -> Bool) -> [a] -> [a]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_filter",
        ),
        "List.find" => (
            "forall a. (a -> Bool) -> [a] -> Maybe a",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_find",
        ),
        "List.findIndex" => (
            "forall a. (a -> Bool) -> [a] -> Maybe Int",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_find_index",
        ),
        "List.findIndices" => (
            "forall a. (a -> Bool) -> [a] -> [Int]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_find_indices",
        ),
        "List.isPrefixOf" => (
            "forall a. Eq a => [a] -> [a] -> Bool",
            2,
            TWO_LAZY,
            "list_is_prefix_of",
        ),
        "List.isSubsequenceOf" => (
            "forall a. Eq a => [a] -> [a] -> Bool",
            2,
            TWO_LAZY,
            "list_is_subsequence_of",
        ),
        "List.null" => ("forall a. [a] -> Bool", 1, WHNF, "list_null"),
        "List.repeat" => ("forall a. a -> [a]", 1, LAZY, "list_repeat"),
        "List.takeWhile" => (
            "forall a. (a -> Bool) -> [a] -> [a]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_take_while",
        ),
        "List.uncons" => ("forall a. [a] -> Maybe (a, [a])", 1, WHNF, "list_uncons"),
        "List.zipWith" => (
            "forall a b c. (a -> b -> c) -> [a] -> [b] -> [c]",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Lazy],
            "list_zip_with",
        ),
        "List.nil" => ("forall a. [a]", 0, &[], "list_nil"),
        "List.cons" => (
            "forall a. a -> [a] -> [a]",
            2,
            &[Demand::Lazy, Demand::Lazy],
            "list_cons",
        ),
        "List.take" => (
            "forall a. Int -> [a] -> [a]",
            2,
            &[Demand::Whnf, Demand::Lazy],
            "list_take",
        ),
        "List.iterate'" => (
            "forall a. (a -> a) -> a -> [a]",
            2,
            &[Demand::Lazy, Demand::Lazy],
            "list_iterate",
        ),
        "List.map" => (
            "forall a b. (a -> b) -> [a] -> [b]",
            2,
            &[Demand::Lazy, Demand::Lazy],
            "list_map",
        ),
        "List.sortOn" => (
            "forall a b. Ord b => (a -> b) -> [a] -> [a]",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_sort_on",
        ),
        "List.foldl'" => (
            "forall a b. (b -> a -> b) -> b -> [a] -> b",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "list_foldl_strict",
        ),
        "List.zip" => (
            "forall a b. [a] -> [b] -> [(a, b)]",
            2,
            &[Demand::Lazy, Demand::Lazy],
            "list_zip",
        ),
        "List.reverse" => ("forall a. [a] -> [a]", 1, WHNF, "list_reverse"),
        "List.length" => ("forall a. [a] -> Int", 1, WHNF, "list_length"),
        "List.lookup" => (
            "forall a b. Eq a => a -> [(a, b)] -> Maybe b",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "list_lookup",
        ),
        "List.and" => ("[Bool] -> Bool", 1, WHNF, "list_and"),
        "List.or" => ("[Bool] -> Bool", 1, WHNF, "list_or"),
        "Vector.fromList" => ("forall a. [a] -> Vector a", 1, WHNF, "vector_from_list"),
        "Vector.toList" => ("forall a. Vector a -> [a]", 1, WHNF, "vector_to_list"),
        "Map.fromList" => (
            "forall k v. Ord k => [(k, v)] -> Map k v",
            1,
            WHNF,
            "map_from_list",
        ),
        "Map.toList" => ("forall k v. Map k v -> [(k, v)]", 1, WHNF, "map_to_list"),
        "Map.lookup" => (
            "forall k v. Ord k => k -> Map k v -> Maybe v",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "map_lookup",
        ),
        "Map.insert" => (
            "forall k v. Ord k => k -> v -> Map k v -> Map k v",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "map_insert",
        ),
        "Map.delete" => (
            "forall k v. Ord k => k -> Map k v -> Map k v",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "map_delete",
        ),
        "Map.singleton" => (
            "forall k v. Ord k => k -> v -> Map k v",
            2,
            TWO_LAZY,
            "map_singleton",
        ),
        "Map.size" => ("forall k v. Map k v -> Int", 1, WHNF, "map_size"),
        "Map.filter" => (
            "forall k v. (v -> Bool) -> Map k v -> Map k v",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "map_filter",
        ),
        "Map.filterWithKey" => (
            "forall k v. (k -> v -> Bool) -> Map k v -> Map k v",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "map_filter_with_key",
        ),
        "Map.any" | "Map.all" => (
            "forall k v. (v -> Bool) -> Map k v -> Bool",
            2,
            &[Demand::Lazy, Demand::Whnf],
            if name == "Map.any" {
                "map_any"
            } else {
                "map_all"
            },
        ),
        "Map.insertWith" => (
            "forall k v. Ord k => (v -> v -> v) -> k -> v -> Map k v -> Map k v",
            4,
            &[Demand::Lazy, Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "map_insert_with",
        ),
        "Map.adjust" => (
            "forall k v. Ord k => (v -> v) -> k -> Map k v -> Map k v",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "map_adjust",
        ),
        "Map.unionWith" => (
            "forall k v. Ord k => (v -> v -> v) -> Map k v -> Map k v -> Map k v",
            3,
            &[Demand::Lazy, Demand::Whnf, Demand::Whnf],
            "map_union_with",
        ),
        "Map.map" => (
            "forall k a b. (a -> b) -> Map k a -> Map k b",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "map_map",
        ),
        "Map.keys" => ("forall k v. Map k v -> [k]", 1, WHNF, "map_keys"),
        "Map.elems" => ("forall k v. Map k v -> [v]", 1, WHNF, "map_elems"),
        "Set.fromList" => ("forall a. Ord a => [a] -> Set a", 1, WHNF, "set_from_list"),
        "Set.toList" => ("forall a. Set a -> [a]", 1, WHNF, "set_to_list"),
        "Set.insert" => (
            "forall a. Ord a => a -> Set a -> Set a",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "set_insert",
        ),
        "Set.member" => (
            "forall a. Ord a => a -> Set a -> Bool",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "set_member",
        ),
        "Set.delete" => (
            "forall a. Ord a => a -> Set a -> Set a",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "set_delete",
        ),
        "Set.union" | "Set.difference" | "Set.intersection" => (
            "forall a. Ord a => Set a -> Set a -> Set a",
            2,
            TWO_WHNF,
            match name {
                "Set.union" => "set_union",
                "Set.difference" => "set_difference",
                "Set.intersection" => "set_intersection",
                _ => unreachable!("Set merge builtin matched"),
            },
        ),
        "Set.size" => ("forall a. Set a -> Int", 1, WHNF, "set_size"),
        "Set.singleton" => ("forall a. Ord a => a -> Set a", 1, LAZY, "set_singleton"),
        "Maybe.Nothing" => ("forall a. Maybe a", 0, &[], "maybe_nothing"),
        "Maybe.Just" => ("forall a. a -> Maybe a", 1, LAZY, "maybe_just"),
        "Maybe.maybe" => (
            "forall a b. b -> (a -> b) -> Maybe a -> b",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "maybe_eliminate",
        ),
        "Maybe.listToMaybe" => ("forall a. [a] -> Maybe a", 1, WHNF, "maybe_list_to_maybe"),
        "Maybe.mapMaybe" => (
            "forall a b. (a -> Maybe b) -> [a] -> [b]",
            2,
            TWO_LAZY,
            "maybe_map_maybe",
        ),
        "Either.Left" => ("forall a b. a -> Either a b", 1, LAZY, "either_left"),
        "Either.Right" => ("forall a b. b -> Either a b", 1, LAZY, "either_right"),
        "Either.either" => (
            "forall a b x. (a -> x) -> (b -> x) -> Either a b -> x",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "either_eliminate",
        ),
        "Exit.ExitSuccess" => ("ExitCode", 0, &[], "exit_success"),
        "Exit.ExitFailure" => ("Int -> ExitCode", 1, LAZY, "exit_failure"),
        "Exit.exitCode" => (
            "forall a. a -> (Int -> a) -> ExitCode -> a",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "exit_eliminate",
        ),
        "Exit.die" => ("forall a. Text -> IO a", 1, IO_ARG, "exit_die"),
        "Exit.exitWith" => ("forall a. ExitCode -> IO a", 1, IO_ARG, "exit_with"),
        "These.This" => ("forall a b. a -> These a b", 1, LAZY, "these_this"),
        "These.That" => ("forall a b. b -> These a b", 1, LAZY, "these_that"),
        "These.These" => ("forall a b. a -> b -> These a b", 2, TWO_LAZY, "these_both"),
        "These.these" => (
            "forall a b c. (a -> c) -> (b -> c) -> (a -> b -> c) -> These a b -> c",
            4,
            &[Demand::Lazy, Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "these_eliminate",
        ),
        "Json.Null" => ("Value", 0, &[], "json_null"),
        "Json.Bool" => ("Bool -> Value", 1, LAZY, "json_bool"),
        "Json.String" => ("Text -> Value", 1, LAZY, "json_string"),
        "Json.Number" => ("Double -> Value", 1, LAZY, "json_number"),
        "Json.Array" => ("Vector Value -> Value", 1, LAZY, "json_array"),
        "Json.Object" => ("Map Text Value -> Value", 1, LAZY, "json_object"),
        "Json.value" => (
            "forall a. a -> (Bool -> a) -> (Text -> a) -> (Double -> a) -> (Vector Value -> a) -> (Map Text Value -> a) -> Value -> a",
            7,
            &[
                Demand::Lazy,
                Demand::Lazy,
                Demand::Lazy,
                Demand::Lazy,
                Demand::Lazy,
                Demand::Lazy,
                Demand::Whnf,
            ],
            "json_eliminate",
        ),
        "Json.encode" => ("Value -> ByteString", 1, WHNF, "json_encode"),
        "Json.decode" => ("ByteString -> Maybe Value", 1, WHNF, "json_decode"),
        "Builder.byteString" => ("ByteString -> Builder", 1, WHNF, "builder_byte_string"),
        "Http.mkStatus" => ("Int -> Text -> Status", 2, TWO_WHNF, "http_status"),
        "Http.FilePart" => (
            "Integer -> Integer -> Integer -> FilePart",
            3,
            THREE_WHNF,
            "http_file_part",
        ),
        "Http.pathInfo" => ("Request -> [Text]", 1, WHNF, "http_path_info"),
        "Http.requestHeaders" => (
            "Request -> [(CI ByteString, ByteString)]",
            1,
            WHNF,
            "http_request_headers",
        ),
        "Http.queryString" => (
            "Request -> [(ByteString, Maybe ByteString)]",
            1,
            WHNF,
            "http_query_string",
        ),
        "Http.getRequestBodyChunk" => {
            ("Request -> IO ByteString", 1, IO_ARG, "http_get_body_chunk")
        }
        "Http.consumeRequestBodyStrict" => {
            ("Request -> IO ByteString", 1, IO_ARG, "http_consume_body")
        }
        "Http.responseBuilder" => (
            "Status -> [(CI ByteString, ByteString)] -> Builder -> Response",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Lazy],
            "http_response_builder",
        ),
        "Http.responseFile" => (
            "Status -> [(CI ByteString, ByteString)] -> Text -> Maybe FilePart -> Response",
            4,
            &[Demand::Lazy, Demand::Lazy, Demand::Lazy, Demand::Lazy],
            "http_response_file",
        ),
        "Http.responseStream" => (
            "Status -> [(CI ByteString, ByteString)] -> ((Builder -> IO ()) -> IO () -> IO ()) -> Response",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Lazy],
            "http_response_stream",
        ),
        "Http.run" => (
            "Int -> (Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived) -> IO ()",
            2,
            IO_TWO,
            "http_run",
        ),
        "IO.mapM_" => (
            "forall a b. (a -> IO b) -> [a] -> IO ()",
            2,
            IO_TWO,
            "io_map_m_",
        ),
        "IO.forM_" => (
            "forall a b. [a] -> (a -> IO b) -> IO ()",
            2,
            IO_TWO,
            "io_for_m_",
        ),
        "Monad.mapM" | "Monad.mapM_" | "Monad.forM" | "Monad.forM_" | "Monad.sequence" => (
            "manifest-driven monadic list traversal",
            if name == "Monad.sequence" { 1 } else { 2 },
            if name == "Monad.sequence" {
                LAZY
            } else {
                TWO_LAZY
            },
            match name {
                "Monad.mapM" => "monad_map_m",
                "Monad.mapM_" => "monad_map_m_discard",
                "Monad.forM" => "monad_for_m",
                "Monad.forM_" => "monad_for_m_discard",
                "Monad.sequence" => "monad_sequence",
                _ => unreachable!("monadic traversal matched"),
            },
        ),
        "Monad.when" => (
            "forall m. Monad m => Bool -> m () -> m ()",
            2,
            &[Demand::Whnf, Demand::Lazy],
            "monad_when",
        ),
        "CI.mk" => ("forall a. FoldCase a => a -> CI a", 1, WHNF, "ci_mk"),
        "CI.foldedCase" => ("forall a. CI a -> a", 1, WHNF, "ci_folded_case"),
        "Tree.Node" => (
            "forall a. a -> [Tree a] -> Tree a",
            2,
            TWO_LAZY,
            "tree_node",
        ),
        "Tree.map" => (
            "forall a b. (a -> b) -> Tree a -> Tree b",
            2,
            TWO_LAZY,
            "tree_map",
        ),
        "Tree.foldTree" => (
            "forall a b. (a -> [b] -> b) -> Tree a -> b",
            2,
            TWO_LAZY,
            "tree_fold",
        ),
        "Tree.flatten" => ("forall a. Tree a -> [a]", 1, LAZY, "tree_flatten"),
        "Tree.levels" => ("forall a. Tree a -> [[a]]", 1, LAZY, "tree_levels"),
        "Tree.unfoldTree" => (
            "forall a b. (b -> (a, [b])) -> b -> Tree a",
            2,
            TWO_LAZY,
            "tree_unfold",
        ),
        "Options.fullDesc" => ("forall a. Options.InfoMod a", 0, &[], "options_full_desc"),
        "Options.progDesc" | "Options.header" => (
            "forall a. Text -> Options.InfoMod a",
            1,
            WHNF,
            if name == "Options.progDesc" {
                "options_prog_desc"
            } else {
                "options_header"
            },
        ),
        "Flag.long" | "Flag.help" | "Option.long" | "Option.help" | "Argument.metavar"
        | "Argument.help" => (
            "forall a. Text -> Options.Mod fields a",
            1,
            WHNF,
            match name {
                "Flag.long" | "Option.long" => "options_long",
                "Argument.metavar" => "options_metavar",
                "Flag.help" | "Option.help" | "Argument.help" => "options_help",
                _ => unreachable!("Options text modifier matched"),
            },
        ),
        "Option.value" | "Argument.value" => (
            "forall a fields. a -> Options.Mod fields a",
            1,
            LAZY,
            "options_default",
        ),
        "Options.flag" => (
            "forall a. a -> a -> Options.Mod Options.FlagFields a -> Options.Parser a",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Whnf],
            "options_flag",
        ),
        "Options.flag'" => (
            "forall a. a -> Options.Mod Options.FlagFields a -> Options.Parser a",
            2,
            &[Demand::Lazy, Demand::Whnf],
            "options_flag_prime",
        ),
        "Options.switch" => (
            "Options.Mod Options.FlagFields Bool -> Options.Parser Bool",
            1,
            WHNF,
            "options_switch",
        ),
        "Options.strOption" => (
            "Options.Mod Options.OptionFields Text -> Options.Parser Text",
            1,
            WHNF,
            "options_str_option",
        ),
        "Options.strArgument" => (
            "Options.Mod Options.ArgumentFields Text -> Options.Parser Text",
            1,
            WHNF,
            "options_str_argument",
        ),
        "Options.helper" => (
            "forall a. Options.Parser (a -> a)",
            0,
            &[],
            "options_helper",
        ),
        "Options.info" => (
            "forall a. Options.Parser a -> Options.InfoMod a -> Options.ParserInfo a",
            2,
            TWO_WHNF,
            "options_info",
        ),
        "Options.execParser" => (
            "forall a. Options.ParserInfo a -> IO a",
            1,
            IO_ARG,
            "options_exec_parser",
        ),
        "Options.command" => (
            "forall a. Text -> Options.ParserInfo a -> Options.Mod Options.CommandFields a",
            2,
            TWO_WHNF,
            "options_command",
        ),
        "Options.hsubparser" => (
            "forall a. Options.Mod Options.CommandFields a -> Options.Parser a",
            1,
            WHNF,
            "options_hsubparser",
        ),
        "Environment.getArgs" => ("IO [Text]", 0, &[], "environment_get_args"),
        "Environment.getEnv" => ("Text -> IO Text", 1, IO_ARG, "environment_get_env"),
        "Environment.getEnvironment" => {
            ("IO [(Text, Text)]", 0, &[], "environment_get_environment")
        }
        "Directory.copyFile" => ("Text -> Text -> IO ()", 2, IO_TWO, "directory_copy_file"),
        "Directory.createDirectory" => ("Text -> IO ()", 1, IO_ARG, "directory_create"),
        "Directory.createDirectoryIfMissing" => (
            "Bool -> Text -> IO ()",
            2,
            IO_TWO,
            "directory_create_if_missing",
        ),
        "Directory.doesDirectoryExist" => ("Text -> IO Bool", 1, IO_ARG, "directory_is_directory"),
        "Directory.doesFileExist" => ("Text -> IO Bool", 1, IO_ARG, "directory_is_file"),
        "Directory.getCurrentDirectory" => ("IO Text", 0, &[], "directory_get_current"),
        "Directory.getFileSize" => ("Text -> IO Integer", 1, IO_ARG, "directory_file_size"),
        "Directory.getHomeDirectory" => ("IO Text", 0, &[], "directory_get_home"),
        "Directory.getSymbolicLinkTarget" => {
            ("Text -> IO Text", 1, IO_ARG, "directory_symlink_target")
        }
        "Directory.listDirectory" => ("Text -> IO [Text]", 1, IO_ARG, "directory_list"),
        "Directory.pathIsSymbolicLink" => ("Text -> IO Bool", 1, IO_ARG, "directory_is_symlink"),
        "Directory.removeDirectory" => ("Text -> IO ()", 1, IO_ARG, "directory_remove"),
        "Directory.removeFile" => ("Text -> IO ()", 1, IO_ARG, "directory_remove_file"),
        "Directory.renameFile" => ("Text -> Text -> IO ()", 2, IO_TWO, "directory_rename_file"),
        "Directory.setCurrentDirectory" => ("Text -> IO ()", 1, IO_ARG, "directory_set_current"),
        "ByteString.hPutStr" => (
            "Handle -> ByteString -> IO ()",
            2,
            IO_TWO,
            "bytes_h_put_str",
        ),
        "ByteString.getContents" => ("IO ByteString", 0, &[], "bytes_get_contents"),
        "ByteString.interact" => (
            "(ByteString -> ByteString) -> IO ()",
            1,
            LAZY,
            "bytes_interact",
        ),
        "ByteString.hGet" => ("Handle -> Int -> IO ByteString", 2, IO_TWO, "bytes_h_get"),
        "ByteString.readFile" => ("Text -> IO ByteString", 1, IO_ARG, "bytes_read_file"),
        "ByteString.writeFile" => ("Text -> ByteString -> IO ()", 2, IO_TWO, "bytes_write_file"),
        "ByteString.readProcess" => (
            "Process -> IO (ExitCode, ByteString, ByteString)",
            1,
            IO_ARG,
            "bytes_read_process",
        ),
        "ByteString.readProcess_" => (
            "Process -> IO (ByteString, ByteString)",
            1,
            IO_ARG,
            "bytes_read_process_checked",
        ),
        "ByteString.readProcessStdout_" => (
            "Process -> IO ByteString",
            1,
            IO_ARG,
            "bytes_read_process_stdout_checked",
        ),
        "Process.nullStream" => ("Handle", 0, &[], "process_null_stream"),
        "Process.proc" => ("Text -> [Text] -> Process", 2, TWO_WHNF, "process_proc"),
        "Process.runProcess" => ("Process -> IO ExitCode", 1, IO_ARG, "process_run"),
        "Process.runProcess_" => ("Process -> IO ()", 1, IO_ARG, "process_run_checked"),
        "Process.setEnv" => (
            "[(Text, Text)] -> Process -> Process",
            2,
            TWO_WHNF,
            "process_set_env",
        ),
        "Process.setStderr" => (
            "Handle -> Process -> Process",
            2,
            TWO_WHNF,
            "process_set_stderr",
        ),
        "Process.setStdin" => (
            "Handle -> Process -> Process",
            2,
            TWO_WHNF,
            "process_set_stdin",
        ),
        "Process.setStdout" => (
            "Handle -> Process -> Process",
            2,
            TWO_WHNF,
            "process_set_stdout",
        ),
        "Process.setWorkingDir" => (
            "Text -> Process -> Process",
            2,
            TWO_WHNF,
            "process_set_working_dir",
        ),
        "Process.useHandleClose" => ("Handle -> Handle", 1, WHNF, "process_use_handle_close"),
        "Process.useHandleOpen" => ("Handle -> Handle", 1, WHNF, "process_use_handle_open"),
        "Tuple.(,)" => (
            "forall a b. a -> b -> (a, b)",
            2,
            &[Demand::Lazy, Demand::Lazy],
            "tuple2",
        ),
        "Tuple.(,,)" => (
            "forall a b c. a -> b -> c -> (a, b, c)",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Lazy],
            "tuple3",
        ),
        "Tuple.(,,,)" => (
            "forall a b c d. a -> b -> c -> d -> (a, b, c, d)",
            4,
            &[Demand::Lazy, Demand::Lazy, Demand::Lazy, Demand::Lazy],
            "tuple4",
        ),
        "$" => (
            "forall a b. (a -> b) -> a -> b",
            2,
            &[Demand::Lazy, Demand::Lazy],
            "apply",
        ),
        "." => (
            "forall a b c. (b -> c) -> (a -> b) -> a -> c",
            3,
            &[Demand::Lazy, Demand::Lazy, Demand::Lazy],
            "compose",
        ),
        "<>" => (
            "forall a. Semigroup a => a -> a -> a",
            2,
            &[Demand::Lazy, Demand::Lazy],
            "semigroup_append",
        ),
        // The Rust compiler lowers records and variants directly. These
        // compatibility schemes retain the pinned row/tag primitives with
        // their singleton-symbol arguments erased into visible type binders.
        "hell:Hell.NilR" => (
            "hell:Hell.Record hell:Hell.NilL",
            0,
            &[],
            "internal_record_nil",
        ),
        "hell:Hell.ConsR" => (
            "forall (k :: Symbol) a xs. a -> hell:Hell.Record xs -> hell:Hell.Record (hell:Hell.ConsL k a xs)",
            2,
            TWO_LAZY,
            "internal_record_cons",
        ),
        "hell:Hell.LeftV" => (
            "forall (k :: Symbol) a xs. a -> hell:Hell.Variant (hell:Hell.ConsL k a xs)",
            1,
            LAZY,
            "internal_variant_left",
        ),
        "hell:Hell.RightV" => (
            "forall (k :: Symbol) a xs (k' :: Symbol) a'. hell:Hell.Variant (hell:Hell.ConsL k' a' xs) -> hell:Hell.Variant (hell:Hell.ConsL k a (hell:Hell.ConsL k' a' xs))",
            1,
            LAZY,
            "internal_variant_right",
        ),
        "hell:Hell.NilA" => (
            "forall r. hell:Hell.Accessor hell:Hell.NilL r",
            0,
            &[],
            "internal_accessor_nil",
        ),
        "hell:Hell.WildA" => (
            "forall r xs. r -> hell:Hell.Accessor xs r",
            1,
            LAZY,
            "internal_accessor_wild",
        ),
        "hell:Hell.ConsA" => (
            "forall (k :: Symbol) a r xs. (a -> r) -> hell:Hell.Accessor xs r -> hell:Hell.Accessor (hell:Hell.ConsL k a xs) r",
            2,
            TWO_LAZY,
            "internal_accessor_cons",
        ),
        "hell:Hell.runAccessor" => (
            "forall (t :: Symbol) r xs. hell:Hell.Tagged t (hell:Hell.Variant xs) -> hell:Hell.Accessor xs r -> r",
            2,
            TWO_WHNF,
            "internal_run_accessor",
        ),
        "hell:Hell.Tagged" => (
            "forall (t :: Symbol) a. a -> hell:Hell.Tagged t a",
            1,
            LAZY,
            "internal_tagged",
        ),
        "hell:Hell.Nullary" => ("hell:Hell.Nullary", 0, &[], "internal_nullary"),
        _ => return None,
    })
}

fn builtin_type_class(name: &str) -> Option<TypeClass> {
    Some(match name {
        "Show.show" | "IO.print" => TypeClass::Show,
        "Eq.eq"
        | "List.lookup"
        | "List.elem"
        | "List.notElem"
        | "List.elemIndex"
        | "List.elemIndices"
        | "List.group"
        | "List.isInfixOf"
        | "List.isPrefixOf"
        | "List.isSubsequenceOf"
        | "List.isSuffixOf" => TypeClass::Eq,
        "Ord.lt" | "Ord.gt" | "List.sort" | "List.sortOn" | "List.nubOrd" | "Map.fromList"
        | "Map.lookup" | "Map.insert" | "Map.delete" | "Map.singleton" | "Map.insertWith"
        | "Map.adjust" | "Map.unionWith" | "Set.fromList" | "Set.insert" | "Set.member"
        | "Set.delete" | "Set.union" | "Set.difference" | "Set.intersection" | "Set.singleton" => {
            TypeClass::Ord
        }
        "Functor.fmap" | "<$>" => TypeClass::Functor,
        "Applicative.pure" | "<*>" | "<**>" => TypeClass::Applicative,
        "Monad.bind" | "Monad.then" | "Monad.return" | "Monad.mapM" | "Monad.mapM_"
        | "Monad.forM" | "Monad.forM_" | "Monad.sequence" | "Monad.when" => TypeClass::Monad,
        "Alternative.optional" | "Alternative.many" => TypeClass::Alternative,
        "<>" => TypeClass::Semigroup,
        "CI.mk" => TypeClass::FoldCase,
        _ => return None,
    })
}

fn operator_fixity(name: &str) -> Option<Fixity> {
    match name {
        "$" => Some(Fixity::Right(0)),
        "<$>" | "<*>" | "<**>" => Some(Fixity::Left(4)),
        "<>" => Some(Fixity::Right(6)),
        "." => Some(Fixity::Right(9)),
        _ => None,
    }
}

#[must_use]
/// Returns the immutable, normalized builtin registry.
///
/// # Panics
///
/// Panics if the pinned registry ever grows beyond the 16-bit builtin id
/// space. The generator tests keep the current count fixed at 355.
pub fn registry() -> &'static [BuiltinSpec] {
    static REGISTRY: OnceLock<Vec<BuiltinSpec>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let public = PUBLIC_NAMES.split_ascii_whitespace();
        let all = public.map(|name| (name, Visibility::Public)).chain(
            INTERNAL_NAMES
                .iter()
                .copied()
                .map(|name| (name, Visibility::Internal)),
        );
        all.enumerate()
            .map(|(index, (name, visibility))| {
                let executable = executable(name);
                BuiltinSpec {
                    id: BuiltinId(u16::try_from(index).unwrap_or_else(|_| {
                        panic!("builtin registry exceeds the 16-bit id space")
                    })),
                    name,
                    visibility,
                    scheme: executable.map(|entry| entry.0),
                    arity: executable.map_or(0, |entry| entry.1),
                    demand: executable.map_or(&[], |entry| entry.2),
                    fixity: operator_fixity(name),
                    wiring: if executable.is_some() {
                        WiringStatus::Executable
                    } else {
                        WiringStatus::DeclaredOnly
                    },
                    type_class: builtin_type_class(name),
                    implementation: executable.map(|entry| entry.3),
                }
            })
            .collect()
    })
}

/// Returns a source-language type annotation for an executable builtin.
///
/// The monadic traversal primitives use a manifest marker in [`BuiltinSpec::scheme`]
/// because the compiler specializes their result shape from the selected method.
/// Their source annotations remain ordinary polymorphic schemes.
#[must_use]
pub fn source_annotation_scheme(name: &str) -> Option<&'static str> {
    match name {
        "Monad.mapM" => Some("forall m a b. Monad m => (a -> m b) -> [a] -> m [b]"),
        "Monad.mapM_" => Some("forall m a. Monad m => (a -> m ()) -> [a] -> m ()"),
        "Monad.forM" => Some("forall m a b. Monad m => [a] -> (a -> m b) -> m [b]"),
        "Monad.forM_" => Some("forall m a. Monad m => [a] -> (a -> m ()) -> m ()"),
        "Monad.sequence" => Some("forall m a. Monad m => [m a] -> m [a]"),
        _ => executable(name).map(|entry| entry.0),
    }
}

fn catalog_scope(source: &assurance_catalogs::GeneratedClaimScope) -> ScopedClaim {
    let status = match source.status {
        "exact" => ClaimStatus::Exact,
        "normalized" => ClaimStatus::Normalized,
        "platform-dependent" => ClaimStatus::PlatformDependent,
        "deliberate-divergence" => ClaimStatus::DeliberateDivergence,
        "unverified" => ClaimStatus::Unverified,
        "not-applicable" => ClaimStatus::NotApplicable,
        value => panic!("generated claim catalog contains unknown status {value:?}"),
    };
    let profiles = source
        .profiles
        .iter()
        .map(|value| match *value {
            "upstream" => ExecutionProfile::Upstream,
            "sandboxed" => ExecutionProfile::Sandboxed,
            other => panic!("generated claim catalog contains unknown profile {other:?}"),
        })
        .collect::<Vec<_>>()
        .leak();
    let platforms = source
        .platforms
        .iter()
        .map(|value| match *value {
            "all" => ClaimPlatform::All,
            "linux" => ClaimPlatform::Linux,
            "macos" => ClaimPlatform::MacOs,
            "windows" => ClaimPlatform::Windows,
            other => panic!("generated claim catalog contains unknown platform {other:?}"),
        })
        .collect::<Vec<_>>()
        .leak();
    let normalizers = source
        .normalizers
        .iter()
        .map(|name| {
            NormalizerId::ALL
                .iter()
                .copied()
                .find(|normalizer| normalizer.as_str() == *name)
                .unwrap_or_else(|| panic!("generated claim names unknown normalizer {name:?}"))
        })
        .collect::<Vec<_>>()
        .leak();
    ScopedClaim {
        status,
        profiles,
        platforms,
        evidence: source.evidence,
        normalizers,
        obligations: source.obligations,
        applicability_rule: source.applicability_rule,
        rationale: (!source.rationale.is_empty()).then_some(source.rationale),
        issue: (!source.issue.is_empty()).then_some(source.issue),
        review_group: (!source.review_group.is_empty()).then_some(source.review_group),
    }
}

fn catalog_dimension(spec: &BuiltinSpec, dimension: CompatibilityDimension) -> DimensionClaim {
    let generated = assurance_catalogs::CLAIM_OVERRIDES
        .iter()
        .find(|claim| claim.builtin == spec.name && claim.dimension == dimension.as_str());
    let sources = generated.map_or_else(
        || std::slice::from_ref(&assurance_catalogs::DEFAULT_CLAIM_SCOPE),
        |claim| claim.scopes,
    );
    let scopes = sources.iter().map(catalog_scope).collect::<Vec<_>>().leak();
    DimensionClaim { dimension, scopes }
}

/// Returns the conservative, dimensioned compatibility claim for every term.
///
/// Wiring and semantic equivalence are deliberately independent. Until a
/// retained pinned-oracle evidence record is available, executable terms stay
/// `Unverified` in every observable dimension.
///
/// # Panics
///
/// Panics only when generated catalog data names a builtin absent from the
/// canonical registry. The build-time catalog validation and focused drift
/// tests make that a repository-integrity failure rather than runtime input.
#[must_use]
pub fn compatibility_claims() -> &'static [CompatibilityClaim] {
    static CLAIMS: OnceLock<Vec<CompatibilityClaim>> = OnceLock::new();
    CLAIMS.get_or_init(|| {
        for generated in assurance_catalogs::CLAIM_OVERRIDES {
            assert!(
                registry().iter().any(|spec| spec.name == generated.builtin),
                "generated claim catalog names unknown builtin {:?}",
                generated.builtin
            );
        }
        registry()
            .iter()
            .map(|spec| CompatibilityClaim {
                builtin: spec.id,
                baseline: assurance_catalogs::CLAIM_BASELINE,
                dimensions: CompatibilityDimension::ALL
                    .map(|dimension| catalog_dimension(spec, dimension)),
            })
            .collect()
    })
}

#[must_use]
pub fn compatibility_claim(id: BuiltinId) -> Option<&'static CompatibilityClaim> {
    compatibility_claims().get(usize::from(id.0))
}

/// Validates the fail-closed promotion invariants for compatibility claims.
///
/// Development snapshots may contain `Unverified` claims. Evidence-bearing
/// statuses may not omit their evidence or normalization/rationale metadata.
///
/// # Errors
///
/// Returns the first structural or fail-closed promotion violation.
pub fn validate_compatibility_claims(
    claims: &[CompatibilityClaim],
) -> Result<(), ClaimValidationError> {
    if claims.len() != registry().len() {
        return Err(ClaimValidationError::RegistryLength);
    }
    for (index, claim) in claims.iter().enumerate() {
        if usize::from(claim.builtin.0) != index {
            return Err(ClaimValidationError::BuiltinOrder);
        }
        if claim.baseline != LANGUAGE_VERSION {
            return Err(ClaimValidationError::Baseline);
        }
        for (slot, dimension) in claim.dimensions.iter().enumerate() {
            if dimension.dimension != CompatibilityDimension::ALL[slot] {
                return Err(ClaimValidationError::DimensionOrder);
            }
            validate_scopes(dimension.dimension, dimension.scopes)?;
        }
    }
    Ok(())
}

fn validate_scopes(
    dimension: CompatibilityDimension,
    scopes: &[ScopedClaim],
) -> Result<(), ClaimValidationError> {
    if scopes.is_empty() {
        return Err(ClaimValidationError::MissingScope);
    }
    for (index, scope) in scopes.iter().enumerate() {
        validate_scope(dimension, scope)?;
        for other in &scopes[..index] {
            if scope
                .profiles
                .iter()
                .any(|profile| other.profiles.contains(profile))
                && scope
                    .platforms
                    .iter()
                    .any(|platform| platforms_overlap(*platform, other.platforms))
            {
                return Err(ClaimValidationError::OverlappingScope);
            }
        }
    }
    Ok(())
}

fn validate_scope(
    dimension: CompatibilityDimension,
    scope: &ScopedClaim,
) -> Result<(), ClaimValidationError> {
    if scope.profiles.is_empty() || scope.platforms.is_empty() {
        return Err(ClaimValidationError::MissingScope);
    }
    if has_duplicates(scope.profiles) {
        return Err(ClaimValidationError::DuplicateProfile);
    }
    if has_duplicates(scope.platforms)
        || (scope.platforms.contains(&ClaimPlatform::All) && scope.platforms.len() != 1)
    {
        return Err(ClaimValidationError::DuplicatePlatform);
    }
    if has_duplicates(scope.evidence) {
        return Err(ClaimValidationError::DuplicateEvidence);
    }
    if has_duplicates(scope.normalizers) {
        return Err(ClaimValidationError::MissingNormalizer);
    }
    if has_duplicates(scope.obligations) {
        return Err(ClaimValidationError::DuplicateObligation);
    }
    if scope.applicability_rule.is_empty() {
        return Err(ClaimValidationError::MissingApplicabilityRule);
    }
    if scope.normalizers.iter().any(|normalizer| {
        assurance_catalogs::NORMALIZER_CONTRACTS
            .iter()
            .find(|contract| contract.id == *normalizer)
            .is_none_or(|contract| !contract.allowed_dimensions.contains(&dimension))
    }) {
        return Err(ClaimValidationError::InvalidNormalizerScope);
    }
    if scope
        .evidence
        .iter()
        .any(|reference| parse_differential_reference(reference).is_err())
    {
        return Err(ClaimValidationError::InvalidEvidence);
    }
    let rationale_missing = scope.rationale.is_none_or(str::is_empty);
    let issue_missing = scope.issue.is_none_or(str::is_empty);
    let explicit_platforms = !scope.platforms.contains(&ClaimPlatform::All);
    match scope.status {
        ClaimStatus::Exact => {
            if scope.evidence.is_empty() {
                return Err(ClaimValidationError::MissingEvidence);
            }
            if !scope.normalizers.is_empty() || !explicit_platforms {
                return Err(ClaimValidationError::InvalidStatusMetadata);
            }
        }
        ClaimStatus::Normalized => {
            if scope.evidence.is_empty() {
                return Err(ClaimValidationError::MissingEvidence);
            }
            if scope.normalizers.is_empty() {
                return Err(ClaimValidationError::MissingNormalizer);
            }
            if rationale_missing {
                return Err(ClaimValidationError::MissingRationale);
            }
            if !explicit_platforms {
                return Err(ClaimValidationError::InvalidStatusMetadata);
            }
        }
        ClaimStatus::PlatformDependent | ClaimStatus::DeliberateDivergence => {
            if scope.evidence.is_empty() {
                return Err(ClaimValidationError::MissingEvidence);
            }
            if rationale_missing {
                return Err(ClaimValidationError::MissingRationale);
            }
            if issue_missing {
                return Err(ClaimValidationError::MissingIssue);
            }
            if !explicit_platforms {
                return Err(ClaimValidationError::InvalidStatusMetadata);
            }
        }
        ClaimStatus::Unverified => {
            if !scope.evidence.is_empty() || !scope.normalizers.is_empty() {
                return Err(ClaimValidationError::InvalidStatusMetadata);
            }
            if rationale_missing {
                return Err(ClaimValidationError::MissingRationale);
            }
            if issue_missing {
                return Err(ClaimValidationError::MissingIssue);
            }
        }
        ClaimStatus::NotApplicable => {
            if !scope.evidence.is_empty() || !scope.normalizers.is_empty() {
                return Err(ClaimValidationError::InvalidStatusMetadata);
            }
            if rationale_missing {
                return Err(ClaimValidationError::MissingRationale);
            }
        }
    }
    Ok(())
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn platforms_overlap(platform: ClaimPlatform, others: &[ClaimPlatform]) -> bool {
    platform == ClaimPlatform::All
        || others.contains(&ClaimPlatform::All)
        || others.contains(&platform)
}

/// Parses one canonical, path-safe retained differential reference.
///
/// # Errors
///
/// Returns [`ClaimValidationError::InvalidEvidence`] for an unknown prefix or
/// an unsafe/empty case identifier.
pub fn parse_differential_reference(
    reference: &str,
) -> Result<DifferentialReference<'_>, ClaimValidationError> {
    let case_id = reference
        .strip_prefix("differential:")
        .ok_or(ClaimValidationError::InvalidEvidence)?;
    validate_case_id(case_id)
        .then_some(DifferentialReference { case_id })
        .ok_or(ClaimValidationError::InvalidEvidence)
}

/// Whether a differential case identifier is canonical and path-safe.
#[must_use]
pub fn validate_case_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[must_use]
pub fn lookup(name: &str) -> Option<&'static BuiltinSpec> {
    registry().iter().find(|spec| spec.name == name)
}

#[cfg(test)]
mod assurance_metadata_tests {
    use super::{
        AssuranceCapability, AssuranceResourceRole, AssuranceSensitivity, DeterminismClass,
        EffectKind, Visibility, lookup, registry,
    };

    #[test]
    fn every_public_wired_builtin_has_a_complete_generated_assurance_contract() {
        for spec in registry()
            .iter()
            .filter(|spec| spec.visibility == Visibility::Public && spec.implementation.is_some())
        {
            let metadata = spec.assurance_metadata();
            if metadata.effect_kind == EffectKind::Io {
                assert!(
                    !metadata.resource_roles.is_empty()
                        || matches!(
                            spec.implementation,
                            Some("io_pure" | "io_map_m_" | "io_for_m_")
                        ),
                    "{}",
                    spec.name
                );
            }
            if !metadata.resource_roles.is_empty() {
                for sensitivity in [
                    AssuranceSensitivity::Resource,
                    AssuranceSensitivity::Platform,
                ] {
                    assert!(
                        metadata.sensitivities.contains(&sensitivity),
                        "{}",
                        spec.name
                    );
                }
            }
            assert!(
                !metadata.host_failure_applicable || metadata.effect_kind == EffectKind::Io,
                "{}",
                spec.name
            );
        }
        let double = lookup("Double.eq").unwrap().assurance_metadata();
        assert!(
            double
                .sensitivities
                .contains(&AssuranceSensitivity::Platform)
        );
        for name in ["Text.hPutStr", "ByteString.hGet", "ByteString.hPutStr"] {
            assert!(
                lookup(name)
                    .unwrap()
                    .assurance_metadata()
                    .resource_roles
                    .contains(&AssuranceResourceRole::Handle),
                "{name}"
            );
        }
    }

    #[test]
    fn host_adapter_capabilities_come_from_exact_implementations() {
        for (name, capability) in [
            ("Text.readFile", AssuranceCapability::Filesystem),
            ("Text.writeFile", AssuranceCapability::Filesystem),
            ("ByteString.readFile", AssuranceCapability::Filesystem),
            ("Temp.withSystemTempFile", AssuranceCapability::Filesystem),
            ("Text.readProcess", AssuranceCapability::Process),
            (
                "ByteString.readProcessStdout_",
                AssuranceCapability::Process,
            ),
            ("UTCTime.getCurrentTime", AssuranceCapability::Clock),
            ("Concurrent.threadDelay", AssuranceCapability::Concurrency),
            ("Timeout.timeout", AssuranceCapability::Concurrency),
            ("Async.race", AssuranceCapability::Concurrency),
            ("Http.run", AssuranceCapability::Network),
            ("IO.stdin", AssuranceCapability::StandardIo),
            ("Text.getLine", AssuranceCapability::StandardIo),
            ("ByteString.hGet", AssuranceCapability::HostHandle),
            ("Environment.getEnv", AssuranceCapability::Environment),
            ("Exit.exitWith", AssuranceCapability::ProcessTermination),
            ("Options.execParser", AssuranceCapability::CommandLine),
        ] {
            let metadata = lookup(name)
                .expect("named public builtin")
                .assurance_metadata();
            assert_eq!(metadata.capabilities, [capability], "{name}");
        }
        assert!(
            lookup("Text.eq")
                .expect("pure Text builtin")
                .assurance_metadata()
                .capabilities
                .is_empty()
        );
    }

    #[test]
    fn io_presentation_and_concurrency_sensitivities_are_not_shadowed() {
        let text_file = lookup("Text.readFile")
            .expect("Text.readFile")
            .assurance_metadata();
        for sensitivity in [
            AssuranceSensitivity::Presentation,
            AssuranceSensitivity::Resource,
            AssuranceSensitivity::Platform,
        ] {
            assert!(text_file.sensitivities.contains(&sensitivity));
        }
        for name in ["IO.stdin", "Environment.getArgs", "Exit.exitWith"] {
            let metadata = lookup(name).expect("host adapter").assurance_metadata();
            assert!(
                metadata
                    .sensitivities
                    .contains(&AssuranceSensitivity::Resource),
                "{name}"
            );
            assert!(
                metadata
                    .sensitivities
                    .contains(&AssuranceSensitivity::Platform),
                "{name}"
            );
        }
        for name in [
            "Text.getLine",
            "Text.getContents",
            "Text.interact",
            "Environment.getEnv",
            "Options.execParser",
            "Exit.exitWith",
            "Temp.withSystemTempFile",
        ] {
            assert!(
                lookup(name)
                    .expect("fallible host adapter")
                    .assurance_metadata()
                    .host_failure_applicable,
                "{name}"
            );
        }
        for name in [
            "Text.setStdin",
            "Process.proc",
            "Process.setEnv",
            "Http.responseBuilder",
            "Http.responseStream",
        ] {
            let metadata = lookup(name)
                .expect("pure host value builder")
                .assurance_metadata();
            assert!(metadata.capabilities.is_empty(), "{name}");
            assert!(!metadata.host_failure_applicable, "{name}");
            assert_eq!(metadata.effect_kind, super::EffectKind::Pure, "{name}");
        }
        let timeout = lookup("Timeout.timeout")
            .expect("Timeout.timeout")
            .assurance_metadata();
        assert_eq!(timeout.determinism, DeterminismClass::ScheduleSensitive);
        assert!(
            timeout
                .sensitivities
                .contains(&AssuranceSensitivity::Concurrency)
        );
    }
}
