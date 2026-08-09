//! Declarative guest-name registry for the pinned Hell API.

use std::sync::OnceLock;

mod compatibility;
mod manifest;

pub use manifest::{
    ClassHeadKind, InstanceResolution, InstanceSpec, KindSignature, ManifestKind, TypeClass,
    TypeConstructorSpec, instance, instances, public_type_arity, resolve_instance,
    type_constructor, type_constructors,
};

pub const LANGUAGE_VERSION: &str = "2026-05-29";
pub const UPSTREAM_COMMIT: &str = "d4d028609ed46a560c62caea8c70e7e91d1afd29";
pub const UPSTREAM_SOURCE_SHA256: &str =
    "6b59dbbdaaa1e31938e8cbdf93ffb2b981fe8064009693f92fbdd134f7dd25f9";
pub const UPSTREAM_EXAMPLE_COUNT: usize = 44;
/// Updated only alongside the strictly parsed committed promotion policy.
pub const PROMOTION_POLICY_SHA256: &str =
    "34a03fd2db8156c938b441403c7837557fccf046a3cfaa647b645ee08ce30d74";
pub const PUBLIC_NAME_COUNT: usize = 345;
pub const INTERNAL_NAME_COUNT: usize = 10;
pub const UNIQUE_NAME_COUNT: usize = PUBLIC_NAME_COUNT + INTERNAL_NAME_COUNT;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BuiltinId(pub u16);

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
pub enum NormalizerId {
    DiagnosticSandboxPathV1,
    DiagnosticPathSeparatorV1,
    StderrFixtureRootV1,
}

impl NormalizerId {
    pub const ALL: [Self; 3] = [
        Self::DiagnosticSandboxPathV1,
        Self::DiagnosticPathSeparatorV1,
        Self::StderrFixtureRootV1,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiagnosticSandboxPathV1 => "diagnostic-sandbox-path-v1",
            Self::DiagnosticPathSeparatorV1 => "diagnostic-path-separator-v1",
            Self::StderrFixtureRootV1 => "stderr-fixture-root-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedClaim {
    pub status: ClaimStatus,
    pub profiles: &'static [ExecutionProfile],
    pub platforms: &'static [ClaimPlatform],
    pub evidence: &'static [&'static str],
    pub normalizers: &'static [NormalizerId],
    pub rationale: Option<&'static str>,
    pub issue: Option<&'static str>,
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
    OverlappingScope,
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

const SUPPORTED_PROFILES: &[ExecutionProfile] =
    &[ExecutionProfile::Upstream, ExecutionProfile::Sandboxed];
const ALL_PLATFORMS: &[ClaimPlatform] = &[ClaimPlatform::All];
const UNVERIFIED_SCOPES: &[ScopedClaim] = &[ScopedClaim {
    status: ClaimStatus::Unverified,
    profiles: SUPPORTED_PROFILES,
    platforms: ALL_PLATFORMS,
    evidence: &[],
    normalizers: &[],
    rationale: Some("No current pinned-oracle evidence has been published for this dimension."),
    issue: Some("COMPAT-EVIDENCE"),
}];

fn unverified_dimension(dimension: CompatibilityDimension) -> DimensionClaim {
    DimensionClaim {
        dimension,
        scopes: UNVERIFIED_SCOPES,
    }
}

/// Returns the conservative, dimensioned compatibility claim for every term.
///
/// Wiring and semantic equivalence are deliberately independent. Until a
/// retained pinned-oracle evidence record is available, executable terms stay
/// `Unverified` in every observable dimension.
#[must_use]
pub fn compatibility_claims() -> &'static [CompatibilityClaim] {
    static CLAIMS: OnceLock<Vec<CompatibilityClaim>> = OnceLock::new();
    CLAIMS.get_or_init(|| {
        registry()
            .iter()
            .map(|spec| {
                let mut dimensions = CompatibilityDimension::ALL.map(unverified_dimension);
                for replacement in compatibility::OVERRIDES
                    .iter()
                    .filter(|replacement| replacement.builtin == spec.name)
                {
                    if let Some(slot) = CompatibilityDimension::ALL
                        .iter()
                        .position(|dimension| *dimension == replacement.dimension)
                    {
                        dimensions[slot].scopes = replacement.scopes;
                    }
                }
                CompatibilityClaim {
                    builtin: spec.id,
                    baseline: LANGUAGE_VERSION,
                    dimensions,
                }
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
            validate_scopes(dimension.scopes)?;
        }
    }
    Ok(())
}

fn validate_scopes(scopes: &[ScopedClaim]) -> Result<(), ClaimValidationError> {
    if scopes.is_empty() {
        return Err(ClaimValidationError::MissingScope);
    }
    for (index, scope) in scopes.iter().enumerate() {
        validate_scope(scope)?;
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

fn validate_scope(scope: &ScopedClaim) -> Result<(), ClaimValidationError> {
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
