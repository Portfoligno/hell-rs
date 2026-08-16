//! Stable typed source generation for semantic differential observations.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use crate::{
    CallbackContract, CallbackInvocationContract, CaseReviewState, CausalSignal,
    ClaimEvidenceDescriptor, ComparatorTraceContract, DifferentialCase, DifferentialMode, Digest,
    EnvironmentProfile, EvidenceTarget, EvidenceTargetV2, ObligationId,
    PresentationShadowNormalizerId, sha256_bytes,
};
use hell_builtins::{
    ClaimPlatform, CompatibilityDimension, ExecutionProfile, NormalizerId, Visibility,
};

/// The result type carried by a generated expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeneratedType {
    Unit,
    Bool,
    Int,
    Integer,
    Double,
    Text,
    List(Box<Self>),
    Maybe(Box<Self>),
    Either(Box<Self>, Box<Self>),
    Tuple2(Box<Self>, Box<Self>),
    Record,
    Variant,
    Json,
}

/// One canonical, reproducible, well-typed differential program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedCase {
    pub id: Arc<str>,
    pub seed: u64,
    pub result_type: GeneratedType,
    pub source: Arc<str>,
    pub ast_sha256: Digest,
    pub shrink_description: Arc<str>,
}

/// Generates exactly `count` deterministic programs from typed templates.
///
/// The templates deliberately cover data constructors, control-flow laziness,
/// records, variants, productive lists, ordering, text, and JSON in addition
/// to numeric primitives. Every returned source terminates normally.
#[must_use]
pub fn generated_typed_cases(seed: u64, count: usize) -> Vec<GeneratedCase> {
    (0..count)
        .map(|index| generated_case(seed, index))
        .collect()
}

/// Returns the deterministic, behavior-oriented committed smoke corpus.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn committed_differential_cases() -> Vec<DifferentialCase> {
    committed_differential_cases_with_collection(true)
}

#[must_use]
pub fn dormant_committed_differential_cases() -> Vec<DifferentialCase> {
    committed_differential_cases_with_collection(false)
}

#[allow(clippy::too_many_lines)]
fn committed_differential_cases_with_collection(include_collection: bool) -> Vec<DifferentialCase> {
    let mut cases = [
        (
            "laziness-unused-error",
            "main = IO.print $ Bool.bool 1 (Error.error \"unused\" :: Int) Bool.False\n",
        ),
        (
            "bool-ordinary-success",
            "main = IO.print $ Bool.bool 1 2 Bool.True\n",
        ),
        (
            "bool-typed-result",
            "main = IO.print $ Bool.bool 41 42 Bool.False\n",
        ),
        (
            "nested-maybe-either-show",
            "main = IO.print [Either.Left (Maybe.Just 1), Either.Right (Maybe.Just \"x\")]\n",
        ),
        (
            "record-select-field",
            "data Person = Person { name :: Text, age :: Int }\n\nmain = IO.print $ Record.get @\"age\" @Int Main.Person { name = \"Ada\", age = 42 }\n",
        ),
        (
            "variant-wildcard-case",
            "data Choice = A | B | C\n\nmain = IO.print $ case Main.C of\n  A -> 1\n  _ -> 2\n",
        ),
        (
            "list-infinite-bounded-prefix",
            "main = IO.print $ List.take 8 $ List.iterate' (Int.plus 1) 0\n",
        ),
        (
            "list-stable-sort-on",
            "main = IO.print $ List.sortOn (\\(key, value) -> key) [(2, \"a\"), (1, \"b\"), (2, \"c\")]\n",
        ),
        (
            "json-object-encoding",
            "main = ByteString.hPutStr IO.stdout $ Json.encode $ Json.Object $ Map.fromList [(\"name\", Json.String \"Ada\"), (\"age\", Json.Number 42.0)]\n",
        ),
        (
            "text-utf8-roundtrip",
            "main = Text.putStrLn $ Text.decodeUtf8 $ Text.encodeUtf8 \"snowman-☃\"\n",
        ),
    ]
    .into_iter()
    .map(|(id, source)| {
        let mut claim_evidence = match id {
            "laziness-unused-error" => Some(runtime_claim_descriptor(
                &["Bool.bool"],
                &["lazy-boundary", "conditional-unselected"],
                CausalSignal::RuntimeAdapterAndForceTrace,
            )),
            "bool-ordinary-success" => Some(runtime_claim_descriptor(
                &["Bool.bool"],
                &["adapter-success", "conditional-selected", "constructor-eliminator"],
                CausalSignal::RuntimeAdapter,
            )),
            "bool-typed-result" => Some(runtime_claim_descriptor(
                &["Bool.bool"],
                &["typed-result"],
                CausalSignal::RuntimeAdapter,
            )),
            _ => None,
        };
        if let Some(descriptor) = &mut claim_evidence {
            descriptor.source_sha256 = sha256_bytes(source.as_bytes());
        }
        DifferentialCase {
            id: Arc::from(id),
            source: Arc::from(source),
            claim_evidence,
            ..DifferentialCase::default()
        }
    })
    .collect::<Vec<_>>();
    cases.extend([
        DifferentialCase {
            id: Arc::from("map-set-duplicate-ordering"),
            source: Arc::from(concat!(
                "main = do\n",
                "  IO.print $ Map.toList $ Map.fromList [(3, \"c\"), (1, \"old\"), (2, \"b\"), (1, \"a\")]\n",
                "  IO.print $ Set.toList $ Set.union (Set.fromList [3,1,2,1]) (Set.fromList [2,4])\n",
            )),
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("options-composed-defaults"),
            source: Arc::from(concat!(
                "main = do\n",
                "  values <- Options.execParser $ Options.info\n",
                "    ((\\a b c -> (a,b,c))\n",
                "      <$> Options.flag \"off\" \"on\" (Flag.long \"mode\")\n",
                "      <*> Options.strOption (Option.long \"name\" <> Option.value \"default\")\n",
                "      <*> Options.strArgument (Argument.value \"fallback\"))\n",
                "    Options.fullDesc\n",
                "  let (a,b,c) = values\n",
                "  Text.putStrLn a\n",
                "  Text.putStrLn b\n",
                "  Text.putStrLn c\n",
            )),
            arguments: vec!["--mode".into()],
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("utc-parse-format-arithmetic"),
            source: Arc::from(concat!(
                "day = Maybe.maybe (Error.error \"day\") Function.id $ Day.iso8601ParseM \"2025-01-01\"\n",
                "parsed = Maybe.maybe (Error.error \"time\") Function.id $ UTCTime.iso8601ParseM \"2025-05-30T11:18:26.1951470841234Z\"\n",
                "main = do\n",
                "  Text.putStrLn $ UTCTime.iso8601Show Main.parsed\n",
                "  IO.print $ UTCTime.addUTCTime 1.0 $ UTCTime.UTCTime Main.day 86400.0\n",
                "  IO.print $ UTCTime.diffUTCTime (UTCTime.addUTCTime 1.5 $ UTCTime.UTCTime Main.day 0.0) (UTCTime.UTCTime Main.day 0.0)\n",
            )),
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("function-fix-bounded-productivity"),
            source: Arc::from("main = IO.print $ List.take 8 $ Function.fix (List.cons 1)\n"),
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("check-record-variant-static"),
            source: Arc::from(concat!(
                "data Person = Person { name :: Text, age :: Int }\n",
                "data Choice = First Int | Second Text\n",
                "main = IO.print $ case Main.First (Record.get @\"age\" @Int Main.Person { name = \"Ada\", age = 42 }) of\n",
                "  First value -> value\n",
                "  Second text -> 0\n",
            )),
            mode: DifferentialMode::Check,
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("check-negative-parse-phase"),
            source: Arc::from("main = (\n"),
            mode: DifferentialMode::Check,
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("check-negative-static-phase"),
            source: Arc::from("main = IO.print Main.missingName\n"),
            mode: DifferentialMode::Check,
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("list-structural-streaming-surface"),
            source: Arc::from(concat!(
                "main = do\n",
                "  IO.print $ List.break (Int.eq 0) [1,0,2]\n",
                "  IO.print $ List.span (\\x -> Bool.not $ Int.eq x 0) [1,0,2]\n",
                "  IO.print $ List.dropWhileEnd (Int.eq 0) [0,1,0,0]\n",
                "  IO.print $ List.group [1,1,2,1]\n",
                "  IO.print $ List.nubOrd [2,1,2,1,3]\n",
                "  IO.print $ List.partition (\\x -> Bool.not $ Int.eq x 0) [0,1,0,2]\n",
                "  IO.print $ List.permutations [1,2,3]\n",
                "  IO.print $ List.scanr Int.plus 0 [1,2,3]\n",
                "  IO.print $ List.sort [3,1,2,1]\n",
                "  IO.print $ List.subsequences [1,2]\n",
                "  IO.print $ List.transpose [[1,2],[3],[4,5]]\n",
            )),
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("options-order-equals-and-double-dash"),
            source: Arc::from(concat!(
                "parser = (\\names item verbose -> (names,item,verbose))\n",
                "  <$> Alternative.many (Options.strOption (Option.long \"name\"))\n",
                "  <*> Options.strArgument (Argument.metavar \"ITEM\")\n",
                "  <*> Options.switch (Flag.long \"verbose\")\n",
                "main = do\n",
                "  parsed <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  let (names,item,verbose) = parsed\n",
                "  IO.print names\n",
                "  Text.putStrLn item\n",
                "  IO.print verbose\n",
            )),
            arguments: vec![
                "--name".into(),
                "one".into(),
                "--name=two".into(),
                "--verbose".into(),
                "--".into(),
                "--literal".into(),
            ],
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("json-exact-scientific-roundtrip"),
            source: Arc::from(concat!(
                "large = Maybe.maybe (Error.error \"large\") Function.id $ Json.decode $ Text.encodeUtf8 \"9007199254740993\"\n",
                "huge = Maybe.maybe (Error.error \"huge\") Function.id $ Json.decode $ Text.encodeUtf8 \"1e400\"\n",
                "tiny = Maybe.maybe (Error.error \"tiny\") Function.id $ Json.decode $ Text.encodeUtf8 \"1e-10000\"\n",
                "main = do\n",
                "  ByteString.hPutStr IO.stdout $ Json.encode Main.large\n",
                "  Text.putStrLn \"\"\n",
                "  ByteString.hPutStr IO.stdout $ Json.encode Main.huge\n",
                "  Text.putStrLn \"\"\n",
                "  ByteString.hPutStr IO.stdout $ Json.encode Main.tiny\n",
                "  Text.putStrLn \"\"\n",
            )),
            ..DifferentialCase::default()
        },
    ]);
    cases.push(public_builtin_catalog_reachability_case());
    cases.push(runtime_core_data_obligations_case());
    cases.push(runtime_functional_data_obligations_case());
    cases.extend(runtime_core_typed_result_cases());
    cases.extend(runtime_function_identity_cases());
    cases.extend(runtime_record_exact_cases());
    cases.extend(runtime_tuple_exact_cases());
    cases.extend(runtime_json_codec_presentation_cases());
    cases.extend(runtime_json_value_cases());
    cases.extend(runtime_json_boundary_cases());
    cases.extend(runtime_text_output_boundary_cases());
    cases.extend(runtime_text_decode_utf8_boundary_cases());
    cases.extend(runtime_text_stdio_input_boundary_cases());
    cases.extend(runtime_text_file_output_boundary_cases());
    cases.extend(runtime_byte_string_stdio_boundary_cases());
    cases.extend(runtime_byte_string_write_file_boundary_cases());
    cases.extend(runtime_file_reader_boundary_cases());
    cases.extend(runtime_interact_boundary_cases());
    cases.extend(runtime_read_process_boundary_cases());
    cases.extend(runtime_process_builder_cases());
    cases.extend(runtime_process_execution_cases());
    cases.extend(runtime_environment_observation_cases());
    cases.extend(runtime_io_operation_cases());
    cases.extend(runtime_show_instance_cases());
    cases.extend(runtime_eq_instance_cases());
    cases.extend(runtime_ord_instance_cases());
    cases.extend(runtime_singleton_constructor_cases());
    if ORD_LIST_CLAIM_READY {
        cases.extend(runtime_ord_list_boundary_cases());
    }
    cases.extend(runtime_io_buffering_cases());
    cases.extend(runtime_io_traversal_cases());
    cases.extend(runtime_thread_delay_cases());
    cases.extend(runtime_timeout_cases());
    cases.extend(runtime_async_race_cases());
    cases.extend(runtime_async_concurrently_cases());
    cases.extend(runtime_function_operator_cases());
    cases.extend(runtime_exit_action_cases());
    cases.extend(runtime_alternative_cases());
    cases.extend(runtime_monad_return_cases());
    cases.extend(runtime_monad_when_cases());
    cases.extend(runtime_monad_then_cases());
    cases.extend(runtime_monad_bind_cases());
    cases.extend(runtime_monad_sequence_cases());
    cases.extend(runtime_monad_traversal_cases());
    cases.extend(runtime_functor_cases());
    cases.extend(runtime_applicative_cases());
    cases.extend(runtime_semigroup_cases());
    cases.extend(runtime_list_iterate_exact_cases());
    cases.extend(runtime_byte_string_io_operation_cases());
    cases.extend(runtime_directory_operation_cases());
    cases.extend(runtime_directory_observation_cases());
    cases.extend(runtime_temp_operation_cases());
    cases.extend(runtime_text_set_stdin_boundary_cases());
    cases.extend(runtime_tree_result_boundary_cases());
    cases.extend(runtime_tree_callback_boundary_cases());
    cases.push(runtime_tree_unfold_exact_case());
    cases.extend(runtime_exec_parser_boundary_cases());
    cases.extend(runtime_str_option_boundary_cases());
    cases.extend(runtime_str_argument_boundary_cases());
    cases.extend(runtime_switch_boundary_cases());
    cases.extend(runtime_flag_boundary_cases());
    cases.extend(runtime_flag_prime_boundary_cases());
    cases.extend(runtime_flag_long_boundary_cases());
    cases.extend(runtime_flag_help_boundary_cases());
    cases.extend(runtime_option_long_boundary_cases());
    cases.extend(runtime_option_help_boundary_cases());
    cases.push(runtime_flag_help_observable_case());
    cases.push(runtime_option_help_observable_case());
    cases.extend(runtime_argument_metavar_boundary_cases());
    cases.extend(runtime_argument_help_boundary_cases());
    cases.push(runtime_argument_metavar_observable_case());
    cases.push(runtime_argument_help_observable_case());
    cases.extend(runtime_option_value_boundary_cases());
    cases.extend(runtime_argument_value_boundary_cases());
    cases.extend(runtime_options_header_boundary_cases());
    cases.extend(runtime_options_prog_desc_boundary_cases());
    cases.extend(runtime_options_helper_boundary_cases());
    cases.extend(runtime_options_info_boundary_cases());
    cases.extend(runtime_options_full_desc_boundary_cases());
    cases.extend(runtime_options_command_boundary_cases());
    cases.extend(runtime_options_hsubparser_boundary_cases());
    cases.extend(runtime_options_metadata_observable_cases());
    cases.extend(runtime_options_presentation_cases());
    cases.extend(runtime_boolean_false_outcome_cases());
    cases.push(runtime_unfoldr_exact_case());
    cases.extend(runtime_unfoldr_boundary_cases());
    cases.extend(runtime_cycle_boundary_cases());
    cases.extend(runtime_list_boundary_cases());
    cases.extend(runtime_zip_with_boundary_cases());
    cases.extend(runtime_concat_map_boundary_cases());
    cases.extend(runtime_delete_by_boundary_cases());
    cases.extend(runtime_drop_while_end_boundary_cases());
    cases.extend(runtime_sort_on_boundary_cases());
    cases.extend(runtime_group_by_boundary_cases());
    cases.extend(runtime_foldl_boundary_cases());
    cases.extend(runtime_foldr_boundary_cases());
    cases.extend(runtime_scan_boundary_cases());
    cases.extend(runtime_map_accum_boundary_cases());
    cases.extend(runtime_simple_list_boundary_cases());
    cases.extend(runtime_eq_list_boundary_cases());
    let (ord_map_claim_ready, ord_set_claim_ready) = collection_activation_flags();
    if include_collection && ord_map_claim_ready {
        cases.extend(runtime_ord_map_cases());
    }
    if include_collection && ord_set_claim_ready {
        cases.extend(runtime_ord_set_cases());
    }
    cases.extend(runtime_map_set_boundary_cases());
    cases.extend(runtime_int_plus_boundary_cases());
    cases.extend(runtime_additional_int_boundary_cases());
    cases.extend(runtime_int_conversion_boundary_cases());
    cases.extend(runtime_integer_boundary_cases());
    cases.extend(runtime_double_arithmetic_boundary_cases());
    cases.extend(runtime_double_from_int_boundary_cases());
    cases.extend(runtime_double_read_maybe_boundary_cases());
    cases.extend(runtime_double_comparison_and_show_boundary_cases());
    cases.extend(runtime_double_show_f_boundary_cases());
    cases.extend(runtime_text_value_boundary_cases());
    cases.extend(runtime_text_predicate_boundary_cases());
    cases.extend(runtime_text_filter_boundary_cases());
    cases.extend(runtime_map_quantifier_boundary_cases());
    cases.extend(runtime_map_filter_boundary_cases());
    cases.extend(runtime_map_value_callback_boundary_cases());
    cases.extend(runtime_map_collision_boundary_cases());
    cases.extend(runtime_ci_boundary_cases());
    cases.push(runtime_collection_obligations_case());
    cases.push(runtime_numeric_time_obligations_case());
    cases.extend(list_take_boundary_cases());
    cases.extend(runtime_interaction_cases());
    let reviewed_failure_presentations = cases
        .iter()
        .filter(|case| crate::has_runtime_failure_presentation_authority(&case.id))
        .collect::<Vec<_>>();
    assert_eq!(
        reviewed_failure_presentations.len(),
        33,
        "reviewed exception-presentation authority must bind exactly 33 committed cases",
    );
    assert!(
        reviewed_failure_presentations
            .iter()
            .all(|case| !case.expected_runtime_completion),
        "reviewed exception-presentation cases must declare failing runtime completion",
    );
    let reviewed_regressions = committed_reviewed_regressions(&cases);
    cases.extend(reviewed_regressions);
    cases
}

fn committed_reviewed_regressions(committed: &[DifferentialCase]) -> Vec<DifferentialCase> {
    const CATALOG: &str = include_str!("../../../compat/regression-corpus.tsv");
    let mut lines = CATALOG.lines();
    assert_eq!(lines.next(), Some("schema_version\t2"));
    assert_eq!(
        lines.next(),
        Some(
            "columns\tcase_id\ttemplate_case_id\tsource_hex\tsource_sha256\tcandidate_commit\tassurance_epoch_sha256\tpackage_sha256\tproposal_sha256\treview_sha256\tbundle_sha256\ttargets_hex\tproof_path\tproof_manifest_sha256"
        )
    );
    let mut ids = std::collections::BTreeSet::new();
    lines
        .filter(|line| !line.is_empty())
        .map(|line| committed_reviewed_regression(line, committed, &mut ids))
        .collect()
}

fn committed_reviewed_regression(
    line: &str,
    committed: &[DifferentialCase],
    ids: &mut std::collections::BTreeSet<String>,
) -> DifferentialCase {
    let entry = validated_regression_catalog_entry(line, committed, ids);
    let execution_case = DifferentialCase {
        id: Arc::from(entry.case_id),
        source: entry.source.into(),
        ..DifferentialCase::default()
    };
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("hell-testkit has no repository root");
    let bundle_path = repository
        .join(entry.proof_path)
        .parent()
        .expect("regression proof has no parent")
        .join("package")
        .join("evidence")
        .join(entry.case_id);
    let mut case = crate::reviewed_regression_case_from_bundle(
        &bundle_path,
        &execution_case,
        "oracle-derived minimized regression descriptor proposed for protected review v1",
    )
    .expect("committed regression descriptor does not replay from oracle evidence");
    let retained_descriptor = decode_regression_hex(entry.targets_hex, "target descriptor");
    assert_eq!(
        fs::read_to_string(bundle_path.join("case.toml"))
            .expect("committed regression descriptor is unavailable"),
        retained_descriptor,
        "committed regression descriptor differs from the catalog"
    );
    let descriptor = case
        .claim_evidence
        .as_mut()
        .expect("oracle-derived regression descriptor disappeared");
    descriptor.review_statement = format!(
        "reviewed regression {} for candidate {} epoch {} package {} proposal {} bundle {}",
        entry.review, entry.candidate, entry.epoch, entry.package, entry.proposal, entry.bundle,
    )
    .into();
    case
}

struct RegressionCatalogEntry<'a> {
    case_id: &'a str,
    source: String,
    candidate: &'a str,
    epoch: &'a str,
    package: &'a str,
    proposal: &'a str,
    review: &'a str,
    bundle: &'a str,
    targets_hex: &'a str,
    proof_path: &'a str,
}

fn validated_regression_catalog_entry<'a>(
    line: &'a str,
    committed: &[DifferentialCase],
    ids: &mut std::collections::BTreeSet<String>,
) -> RegressionCatalogEntry<'a> {
    let fields = line.split('\t').collect::<Vec<_>>();
    assert_eq!(fields.len(), 13, "regression catalog row is incomplete");
    let [
        case_id,
        template_id,
        source_hex,
        source_sha256,
        candidate,
        epoch,
        package,
        proposal,
        review,
        bundle,
        targets_hex,
        proof_path,
        proof_manifest_sha256,
    ] = fields.as_slice()
    else {
        unreachable!("regression field cardinality was checked")
    };
    assert!(
        case_id.starts_with("regression-")
            && case_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && ids.insert((*case_id).to_owned()),
        "regression case id is unsafe or duplicated"
    );
    assert!(
        candidate.len() == 40
            && candidate
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "regression candidate commit is invalid"
    );
    for digest in [
        source_sha256,
        epoch,
        package,
        proposal,
        review,
        bundle,
        proof_manifest_sha256,
    ] {
        Digest::from_hex(digest).expect("regression catalog digest is invalid");
    }
    let source = decode_regression_source(source_hex);
    assert_eq!(
        sha256_bytes(source.as_bytes()).hex(),
        *source_sha256,
        "regression source digest differs"
    );
    verify_committed_regression_proof(&RegressionProofExpectation {
        case_id,
        proof_path,
        proof_manifest_sha256,
        package_sha256: package,
        proposal_sha256: proposal,
        review_sha256: review,
        bundle_sha256: bundle,
        source_sha256,
        targets_hex,
    });
    assert!(
        committed
            .iter()
            .any(|case| case.id.as_ref() == *template_id),
        "regression provenance template case disappeared"
    );
    RegressionCatalogEntry {
        case_id,
        source,
        candidate,
        epoch,
        package,
        proposal,
        review,
        bundle,
        targets_hex,
        proof_path,
    }
}

struct RegressionProofExpectation<'a> {
    case_id: &'a str,
    proof_path: &'a str,
    proof_manifest_sha256: &'a str,
    package_sha256: &'a str,
    proposal_sha256: &'a str,
    review_sha256: &'a str,
    bundle_sha256: &'a str,
    source_sha256: &'a str,
    targets_hex: &'a str,
}

fn verify_committed_regression_proof(expected: &RegressionProofExpectation<'_>) {
    let RegressionProofExpectation {
        case_id,
        proof_path,
        proof_manifest_sha256,
        package_sha256,
        proposal_sha256,
        review_sha256,
        bundle_sha256,
        source_sha256,
        targets_hex,
    } = *expected;
    let expected_path = format!("compat/regressions/{case_id}/proof.tsv");
    assert_eq!(
        proof_path, expected_path,
        "regression proof path is not canonical"
    );
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("hell-testkit has no repository root");
    let path = repository.join(proof_path);
    let proof = fs::read(&path).expect("committed regression proof is unavailable");
    assert_eq!(
        sha256_bytes(&proof).hex(),
        proof_manifest_sha256,
        "committed regression proof digest differs"
    );
    let proof = std::str::from_utf8(&proof).expect("regression proof is not UTF-8");
    let expected = format!(
        "schema_version\t1\ncase_id\t{case_id}\npackage_sha256\t{package_sha256}\nproposal_sha256\t{proposal_sha256}\nreview_sha256\t{review_sha256}\nbundle_sha256\t{bundle_sha256}\nsource_sha256\t{source_sha256}\ntargets_hex\t{targets_hex}\n"
    );
    assert_eq!(proof, expected, "committed regression proof fields differ");
    let proof_root = path.parent().expect("regression proof has no directory");
    assert_eq!(
        committed_directory_digest(&proof_root.join("package")),
        package_sha256,
        "committed regression package tree digest differs"
    );
    assert_eq!(
        sha256_bytes(
            &fs::read(proof_root.join("package/proposal.json"))
                .expect("committed regression proposal is unavailable")
        )
        .hex(),
        proposal_sha256,
        "committed regression proposal digest differs"
    );
    assert_eq!(
        sha256_bytes(
            &fs::read(proof_root.join("review/review.dsse.json"))
                .expect("committed regression review is unavailable")
        )
        .hex(),
        review_sha256,
        "committed regression review digest differs"
    );
    let bundle_record = fs::read_to_string(
        proof_root
            .join("package/evidence")
            .join(case_id)
            .join("bundle-manifest.sha256"),
    )
    .expect("committed regression bundle digest is unavailable");
    assert_eq!(
        bundle_record,
        format!("{bundle_sha256}  bundle-manifest.json\n"),
        "committed regression bundle digest differs"
    );
}

fn committed_directory_digest(root: &Path) -> String {
    let mut files = Vec::new();
    collect_committed_proof_files(root, root, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut manifest = String::from(
        "{\n  \"schemaVersion\": 1,\n  \"format\": \"merkle-directory-v1\",\n  \"files\": [",
    );
    for (index, (path, digest, size)) in files.iter().enumerate() {
        if index != 0 {
            manifest.push(',');
        }
        assert!(
            path.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
            "committed regression package path is not portable"
        );
        write!(
            manifest,
            "\n    {{\"path\": \"{path}\", \"sha256\": \"{}\", \"size\": {size}}}",
            digest.hex()
        )
        .expect("writing to String cannot fail");
    }
    manifest.push_str("\n  ]\n}\n");
    sha256_bytes(manifest.as_bytes()).hex()
}

fn collect_committed_proof_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, Digest, u64)>,
) {
    let mut entries = fs::read_dir(directory)
        .expect("cannot enumerate committed regression package")
        .collect::<Result<Vec<_>, _>>()
        .expect("cannot read committed regression package entry");
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let kind = entry
            .file_type()
            .expect("cannot inspect committed regression package entry");
        assert!(
            !kind.is_symlink(),
            "committed regression package contains a symlink"
        );
        if kind.is_dir() {
            collect_committed_proof_files(root, &entry.path(), files);
        } else {
            assert!(
                kind.is_file(),
                "committed regression package has a special file"
            );
            let bytes =
                fs::read(entry.path()).expect("cannot read committed regression package file");
            let relative = entry
                .path()
                .strip_prefix(root)
                .expect("committed regression package path escaped")
                .to_string_lossy()
                .replace('\\', "/");
            files.push((relative, sha256_bytes(&bytes), bytes.len() as u64));
        }
    }
}

fn decode_regression_source(encoded: &str) -> String {
    let source = decode_regression_hex(encoded, "source");
    assert!(
        !source.is_empty() && source.ends_with('\n'),
        "regression source is not canonical text"
    );
    source
}

fn decode_regression_hex(encoded: &str, label: &str) -> String {
    assert!(encoded.len().is_multiple_of(2));
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("regression {label} hex is not canonical lowercase"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect::<Vec<_>>();
    String::from_utf8(bytes).unwrap_or_else(|_| panic!("regression {label} is not UTF-8"))
}

const RUNTIME_CORE_DATA_SOURCE: &str = concat!(
    "main = do\n",
    "  IO.print Bool.False\n",
    "  IO.print Bool.True\n",
    "  IO.print $ Bool.bool 41 42 Bool.False\n",
    "  IO.print $ Bool.not Bool.False\n",
    "  IO.print $ Maybe.Just 1\n",
    "  IO.print (Maybe.Nothing :: Maybe Int)\n",
    "  IO.print $ Maybe.listToMaybe [1,2]\n",
    "  IO.print $ Maybe.mapMaybe (\\x -> Bool.bool Maybe.Nothing (Maybe.Just $ Int.plus x 1) $ Int.eq x 0) [0,1]\n",
    "  IO.print $ Maybe.maybe 0 (Int.plus 1) $ Maybe.Just 1\n",
    "  IO.print (Either.Left 1 :: Either Int Text)\n",
    "  IO.print (Either.Right \"right\" :: Either Int Text)\n",
    "  IO.print $ Either.either (Int.plus 1) Text.length (Either.Left 1 :: Either Int Text)\n",
);

fn runtime_core_data_obligations_case() -> DifferentialCase {
    let mut descriptor =
        runtime_family_bulk_descriptor(&["Bool", "Maybe", "Either"], RUNTIME_CORE_DATA_SOURCE);
    descriptor
        .semantic_targets
        .retain(|target| target.builtin.as_ref() != "Bool.bool");
    descriptor
        .targets
        .retain(|target| target.builtin.as_ref() != "Bool.bool");
    DifferentialCase {
        id: Arc::from("runtime-core-data-obligation-closure"),
        source: Arc::from(RUNTIME_CORE_DATA_SOURCE),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

const RUNTIME_FUNCTIONAL_DATA_SOURCE: &str = concat!(
    "data RuntimePerson = RuntimePerson { name :: Text, age :: Int }\n",
    "person = Main.RuntimePerson { name = \"Ada\", age = 41 }\n",
    "thisValue = These.This 1 :: These Int Text\n",
    "thatValue = These.That \"right\" :: These Int Text\n",
    "bothValue = These.These 1 \"right\" :: These Int Text\n",
    "main = do\n",
    "  IO.print $ These.these (Int.plus 1) Text.length (\\left right -> Int.plus left $ Text.length right) Main.thisValue\n",
    "  IO.print $ These.these (Int.plus 1) Text.length (\\left right -> Int.plus left $ Text.length right) Main.thatValue\n",
    "  IO.print $ These.these (Int.plus 1) Text.length (\\left right -> Int.plus left $ Text.length right) Main.bothValue\n",
    "  IO.print $ Function.id 42\n",
    "  IO.print $ List.take 3 $ Function.fix (List.cons 1)\n",
    "  IO.print $ Ord.lt 1 2\n",
    "  IO.print $ Ord.gt 2 1\n",
    "  IO.print $ Eq.eq 42 42\n",
    "  IO.print $ Record.get @\"age\" @Int Main.person\n",
    "  IO.print $ Record.get @\"age\" @Int $ Record.set @\"age\" @Int 42 Main.person\n",
    "  IO.print $ Record.get @\"age\" @Int $ Record.modify @\"age\" @Int (Int.plus 1) Main.person\n",
);

fn runtime_functional_data_obligations_case() -> DifferentialCase {
    let mut descriptor = runtime_family_bulk_descriptor(
        &["These", "Function", "Ord", "Eq"],
        RUNTIME_FUNCTIONAL_DATA_SOURCE,
    );
    descriptor
        .semantic_targets
        .retain(|target| target.builtin.as_ref() != "Function.id");
    descriptor
        .targets
        .retain(|target| target.builtin.as_ref() != "Function.id");
    DifferentialCase {
        id: Arc::from("runtime-functional-data-obligation-closure"),
        source: Arc::from(RUNTIME_FUNCTIONAL_DATA_SOURCE),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

const RUNTIME_TYPED_RESULT_CASES: &[(&str, &str)] = &[
    (
        "Builder.byteString",
        "main = IO.print $ Builder.byteString $ Text.encodeUtf8 \"aβ\"\n",
    ),
    ("Bool.False", "main = IO.print Bool.False\n"),
    ("Bool.True", "main = IO.print Bool.True\n"),
    ("Bool.not", "main = IO.print $ Bool.not Bool.False\n"),
    ("Maybe.Just", "main = IO.print $ Maybe.Just 1\n"),
    (
        "Maybe.Nothing",
        "main = IO.print (Maybe.Nothing :: Maybe Int)\n",
    ),
    (
        "Maybe.listToMaybe",
        "main = IO.print $ Maybe.listToMaybe [1,2]\n",
    ),
    (
        "Maybe.maybe",
        "main = IO.print $ Maybe.maybe 0 (Int.plus 1) $ Maybe.Just 1\n",
    ),
    (
        "Maybe.mapMaybe",
        "main = IO.print $ Maybe.mapMaybe (\\x -> Bool.bool Maybe.Nothing (Maybe.Just $ Int.plus x 1) $ Int.eq x 0) [0,1]\n",
    ),
    (
        "Either.Left",
        "main = IO.print (Either.Left 1 :: Either Int Text)\n",
    ),
    (
        "Either.Right",
        "main = IO.print (Either.Right \"right\" :: Either Int Text)\n",
    ),
    (
        "Either.either",
        "main = IO.print $ Either.either (Int.plus 1) Text.length (Either.Left 1 :: Either Int Text)\n",
    ),
    (
        "These.This",
        "main = IO.print $ These.these (Int.plus 1) Text.length (\\left right -> Int.plus left $ Text.length right) (These.This 1 :: These Int Text)\n",
    ),
    (
        "These.That",
        "main = IO.print $ These.these (Int.plus 1) Text.length (\\left right -> Int.plus left $ Text.length right) (These.That \"right\" :: These Int Text)\n",
    ),
    (
        "These.These",
        "main = IO.print $ These.these (Int.plus 1) Text.length (\\left right -> Int.plus left $ Text.length right) (These.These 1 \"right\" :: These Int Text)\n",
    ),
    (
        "These.these",
        "main = IO.print $ These.these (Int.plus 1) Text.length (\\left right -> Int.plus left $ Text.length right) (These.These 1 \"right\" :: These Int Text)\n",
    ),
    (
        "Function.fix",
        "main = IO.print $ List.take 3 $ Function.fix (List.cons 1)\n",
    ),
    (
        "List.map",
        "main = IO.print $ List.map (Int.plus 1) [1,2]\n",
    ),
    (
        "List.all",
        "main = IO.print $ List.all (\\x -> Bool.not $ Int.eq x 0) [1,2]\n",
    ),
    ("List.any", "main = IO.print $ List.any (Int.eq 2) [0,2]\n"),
    (
        "List.dropWhile",
        "main = IO.print $ List.dropWhile (\\x -> Ord.lt x 2) [1,2,3]\n",
    ),
    (
        "List.find",
        "main = IO.print $ List.find (Int.eq 2) [1,2]\n",
    ),
    (
        "List.findIndex",
        "main = IO.print $ List.findIndex (Int.eq 2) [1,2]\n",
    ),
    (
        "List.findIndices",
        "main = IO.print $ List.findIndices (Int.eq 2) [1,2,2]\n",
    ),
    (
        "List.filter",
        "main = IO.print $ List.filter (\\x -> Ord.lt x 3) [1,2,3]\n",
    ),
    (
        "List.break",
        "main = IO.print $ List.break (Int.eq 0) [1,0,2]\n",
    ),
    (
        "List.span",
        "main = IO.print $ List.span (\\x -> Bool.not $ Int.eq x 0) [1,2,0]\n",
    ),
    (
        "List.takeWhile",
        "main = IO.print $ List.takeWhile (\\x -> Ord.lt x 3) [1,2,3,4]\n",
    ),
    (
        "List.partition",
        "main = IO.print $ List.partition (\\x -> Ord.lt x 3) [1,2,3]\n",
    ),
    ("Ord.lt", "main = IO.print $ Ord.lt 1 2\n"),
    ("Ord.gt", "main = IO.print $ Ord.gt 2 1\n"),
    ("Eq.eq", "main = IO.print $ Eq.eq 42 42\n"),
    ("List.nil", "main = IO.print (List.nil :: [Int])\n"),
    (
        "Map.singleton",
        "main = IO.print $ Map.toList $ Map.singleton 1 \"a\"\n",
    ),
    ("Set.singleton", "main = IO.print $ Set.singleton 1\n"),
    ("Exit.ExitSuccess", "main = IO.print Exit.ExitSuccess\n"),
    (
        "Exit.ExitFailure",
        "main = IO.print $ Exit.ExitFailure 23\n",
    ),
    (
        "Exit.exitCode",
        "main = IO.print $ Exit.exitCode 0 Function.id $ Exit.ExitFailure 23\n",
    ),
    (
        "IO.stdin",
        "main = do\n  bytes <- ByteString.hGet IO.stdin 0\n  ByteString.hPutStr IO.stdout bytes\n",
    ),
    ("IO.stdout", "main = Text.hPutStr IO.stdout \"\"\n"),
    ("IO.stderr", "main = Text.hPutStr IO.stderr \"\"\n"),
    (
        "Process.nullStream",
        concat!(
            "main = do\n",
            "  helpers <- Environment.getArgs\n",
            "  Monad.forM_ helpers \\helper ->\n",
            "    Process.runProcess_ $ Process.setStdout Process.nullStream $\n",
            "      Process.proc helper [\"emit-hex\",\"\"]\n",
        ),
    ),
    (
        "Json.Null",
        "main = ByteString.hPutStr IO.stdout $ Json.encode Json.Null\n",
    ),
    (
        "Json.Bool",
        "main = ByteString.hPutStr IO.stdout $ Json.encode $ Json.Bool Bool.True\n",
    ),
    (
        "Json.String",
        "main = ByteString.hPutStr IO.stdout $ Json.encode $ Json.String \"value\"\n",
    ),
    (
        "Json.Number",
        "main = ByteString.hPutStr IO.stdout $ Json.encode $ Json.Number 1.5\n",
    ),
    (
        "Json.Array",
        "main = ByteString.hPutStr IO.stdout $ Json.encode $ Json.Array $ Vector.fromList [Json.Null]\n",
    ),
    (
        "Json.Object",
        "main = ByteString.hPutStr IO.stdout $ Json.encode $ Json.Object $ Map.fromList [(\"key\",Json.Null)]\n",
    ),
    (
        "Text.breakOn",
        "main = IO.print $ Text.breakOn \"β\" \"aβc\"\n",
    ),
    (
        "Text.concat",
        "main = IO.print $ Text.concat [\"a\",\"β\"]\n",
    ),
    ("Text.drop", "main = IO.print $ Text.drop 1 \"aβ\"\n"),
    ("Text.dropEnd", "main = IO.print $ Text.dropEnd 1 \"aβ\"\n"),
    (
        "Text.encodeUtf8",
        "main = IO.print $ Text.encodeUtf8 \"aβ\"\n",
    ),
    ("Text.eq", "main = IO.print $ Text.eq \"aβ\" \"aβ\"\n"),
    (
        "Text.intercalate",
        "main = IO.print $ Text.intercalate \"-\" [\"a\",\"β\"]\n",
    ),
    (
        "Text.isInfixOf",
        "main = IO.print $ Text.isInfixOf \"β\" \"aβc\"\n",
    ),
    (
        "Text.isPrefixOf",
        "main = IO.print $ Text.isPrefixOf \"a\" \"aβ\"\n",
    ),
    (
        "Text.isSuffixOf",
        "main = IO.print $ Text.isSuffixOf \"β\" \"aβ\"\n",
    ),
    ("Text.length", "main = IO.print $ Text.length \"aβ\"\n"),
    ("Text.lines", "main = IO.print $ Text.lines \"a\\nβ\\n\"\n"),
    (
        "Text.pack",
        "main = IO.print $ Text.pack $ Text.unpack \"aβ\"\n",
    ),
    (
        "Text.replace",
        "main = IO.print $ Text.replace \"β\" \"b\" \"aβc\"\n",
    ),
    ("Text.reverse", "main = IO.print $ Text.reverse \"aβ\"\n"),
    (
        "Text.splitOn",
        "main = IO.print $ Text.splitOn \"::\" \"a::β\"\n",
    ),
    ("Text.strip", "main = IO.print $ Text.strip \"  aβ  \"\n"),
    (
        "Text.stripPrefix",
        "main = IO.print $ Text.stripPrefix \"a\" \"aβ\"\n",
    ),
    (
        "Text.stripSuffix",
        "main = IO.print $ Text.stripSuffix \"β\" \"aβ\"\n",
    ),
    ("Text.take", "main = IO.print $ Text.take 1 \"aβ\"\n"),
    ("Text.takeEnd", "main = IO.print $ Text.takeEnd 1 \"aβ\"\n"),
    ("Text.toLower", "main = IO.print $ Text.toLower \"AΒ\"\n"),
    ("Text.toUpper", "main = IO.print $ Text.toUpper \"aβ\"\n"),
    (
        "Text.unlines",
        "main = IO.print $ Text.unlines [\"a\",\"β\"]\n",
    ),
    ("Text.unpack", "main = IO.print $ Text.unpack \"aβ\"\n"),
    (
        "Text.unwords",
        "main = IO.print $ Text.unwords [\"a\",\"β\"]\n",
    ),
    ("Text.words", "main = IO.print $ Text.words \" a  β \"\n"),
    ("Int.eq", "main = IO.print $ Int.eq 2 2\n"),
    (
        "Int.fromInteger",
        "main = IO.print $ Int.fromInteger $ Int.toInteger 42\n",
    ),
    ("Int.mult", "main = IO.print $ Int.mult 6 7\n"),
    ("Int.plus", "main = IO.print $ Int.plus 40 2\n"),
    ("Int.readMaybe", "main = IO.print $ Int.readMaybe \"42\"\n"),
    ("Int.show", "main = IO.print $ Int.show 42\n"),
    ("Int.subtract", "main = IO.print $ Int.subtract 40 2\n"),
    ("Int.toInteger", "main = IO.print $ Int.toInteger 42\n"),
    (
        "Integer.mult",
        "main = IO.print $ Integer.mult (Int.toInteger 6) (Int.toInteger 7)\n",
    ),
    (
        "Integer.plus",
        "main = IO.print $ Integer.plus (Int.toInteger 40) (Int.toInteger 2)\n",
    ),
    (
        "Integer.readMaybe",
        "main = IO.print $ Integer.readMaybe \"42\"\n",
    ),
    (
        "Integer.subtract",
        "main = IO.print $ Integer.subtract (Int.toInteger 40) (Int.toInteger 2)\n",
    ),
    ("Double.eq", "main = IO.print $ Double.eq 1.5 1.5\n"),
    ("Double.fromInt", "main = IO.print $ Double.fromInt 42\n"),
    ("Double.mult", "main = IO.print $ Double.mult 2.0 3.0\n"),
    ("Double.plus", "main = IO.print $ Double.plus 1.5 2.5\n"),
    (
        "Double.readMaybe",
        "main = IO.print $ Double.readMaybe \"1.25\"\n",
    ),
    ("Double.show", "main = IO.print $ Double.show 1.25\n"),
    (
        "Double.showEFloat",
        "main = IO.print $ Double.showEFloat (Maybe.Just 2) 12.5 \"\"\n",
    ),
    (
        "Double.showFFloat",
        "main = IO.print $ Double.showFFloat (Maybe.Just 2) 12.5 \"\"\n",
    ),
    (
        "Double.subtract",
        "main = IO.print $ Double.subtract 4.0 1.5\n",
    ),
    (
        "Day.fromGregorianValid",
        "main = IO.print (Day.fromGregorianValid (Int.toInteger 2024) 2 29)\n",
    ),
    (
        "Day.iso8601ParseM",
        "main = IO.print (Day.iso8601ParseM \"2025-08-10\")\n",
    ),
    (
        "TimeOfDay.makeTimeOfDayValid",
        "main = IO.print (TimeOfDay.makeTimeOfDayValid 23 59 60.5)\n",
    ),
    (
        "UTCTime.addUTCTime",
        concat!(
            "day = case Day.iso8601ParseM \"2025-08-10\" of { ",
            "Maybe.Just value -> value; Maybe.Nothing -> Error.error \"day\" }\n",
            "utc = UTCTime.UTCTime Main.day 1.0\n",
            "main = IO.print (UTCTime.addUTCTime 1.5 Main.utc)\n",
        ),
    ),
    (
        "UTCTime.iso8601ParseM",
        "main = IO.print (UTCTime.iso8601ParseM \"2025-05-30T23:59:60Z\")\n",
    ),
    ("CI.mk", "main = IO.print $ CI.mk \"AbC\"\n"),
    (
        "CI.foldedCase",
        "main = IO.print $ CI.foldedCase $ CI.mk \"AbC\"\n",
    ),
    ("Show.show", "main = IO.print $ Show.show 42\n"),
    (
        "Text.decodeUtf8",
        "main = IO.print $ Text.decodeUtf8 $ Text.encodeUtf8 \"aβ\"\n",
    ),
    (
        "IO.NoBuffering",
        "main = IO.hSetBuffering IO.stdout IO.NoBuffering\n",
    ),
    (
        "IO.LineBuffering",
        "main = IO.hSetBuffering IO.stdout IO.LineBuffering\n",
    ),
    (
        "IO.BlockBuffering",
        "main = IO.hSetBuffering IO.stdout $ IO.BlockBuffering Maybe.Nothing\n",
    ),
    (
        "IO.ReadMode",
        "main = do\n  Text.writeFile \"mode.txt\" \"x\"\n  handle <- IO.openFile \"mode.txt\" IO.ReadMode\n  IO.hClose handle\n",
    ),
    (
        "IO.WriteMode",
        "main = do\n  handle <- IO.openFile \"mode.txt\" IO.WriteMode\n  IO.hClose handle\n",
    ),
    (
        "IO.AppendMode",
        "main = do\n  handle <- IO.openFile \"mode.txt\" IO.AppendMode\n  IO.hClose handle\n",
    ),
    (
        "IO.ReadWriteMode",
        "main = do\n  handle <- IO.openFile \"mode.txt\" IO.ReadWriteMode\n  IO.hClose handle\n",
    ),
];

fn runtime_core_typed_result_cases() -> Vec<DifferentialCase> {
    RUNTIME_TYPED_RESULT_CASES
        .iter()
        .copied()
        .map(|(builtin, source)| {
            let implementation = hell_builtins::lookup(builtin)
                .and_then(|spec| spec.implementation)
                .expect("typed target has a runtime implementation");
            let mut descriptor = if runtime_handle_kind(builtin).is_some() {
                runtime_handle_obligation_descriptor(builtin, source)
            } else {
                runtime_single_typed_target_descriptor(builtin, source)
            };
            if let Some(stdout) = runtime_typed_raw_presentation(builtin) {
                attach_raw_presentation_target(&mut descriptor, builtin, stdout);
            }
            if matches!(builtin, "Map.singleton" | "Set.singleton") {
                for target in &mut descriptor.semantic_targets {
                    target.obligations.retain(|obligation| {
                        !matches!(
                            obligation.0.as_ref(),
                            "adapter-failure" | "whnf-failure-boundary"
                        )
                    });
                    target.expected_instance_target = Some(Arc::from("Int"));
                    target.expected_comparator_trace_sha256 =
                        Some(crate::comparator_trace_sha256(builtin, 1, "Int", &[], &[]));
                }
            }
            let (arguments, environment_profile) = if builtin == "Process.nullStream" {
                (
                    vec!["hell-test-helper".into()],
                    EnvironmentProfile::ProcessCapable,
                )
            } else {
                (Vec::new(), EnvironmentProfile::Explicit)
            };
            DifferentialCase {
                id: Arc::from(format!(
                    "runtime-typed-{}",
                    implementation.replace('_', "-")
                )),
                source: Arc::from(source),
                arguments,
                environment_profile,
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_function_identity_cases() -> Vec<DifferentialCase> {
    [
        (
            "int",
            "main = IO.print $ Function.id 42\n",
            "{\"type\":\"Int\",\"value\":\"42\"}",
            b"42\n".as_slice(),
        ),
        (
            "text",
            "main = Text.putStrLn $ Function.id \"aβ\"\n",
            "{\"type\":\"Text\",\"utf8Hex\":\"61ceb2\"}",
            "aβ\n".as_bytes(),
        ),
    ]
    .into_iter()
    .map(|(id, source, value, stdout)| {
        let mut descriptor = runtime_single_typed_target_descriptor("Function.id", source);
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{value}}}"
        );
        let target = &mut descriptor.semantic_targets[0];
        target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
        target.expected_raw_presentation_sha256 =
            Some(crate::raw_presentation_sha256(stdout, b""));
        target.expected_lazy_argument_exit_sha256 =
            Some(crate::lazy_argument_exit_sha256([(0, "not-forced")]));
        DifferentialCase {
            id: Arc::from(format!("runtime-function-id-{id}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

type RuntimeRecordCase = (&'static str, &'static str, String, String, &'static [u8]);

const RUNTIME_RECORD_DECLARATION: &str = "data Person = Person { name :: Text, age :: Int }\n";
const RUNTIME_RECORD_PERSON: &str = "person = Main.Person { name = \"Ada\", age = 41 }\n";
const RUNTIME_LAZY_RECORD_PERSON: &str = concat!(
    "person = Main.Person { name = Error.error \"undemanded-record-field\", ",
    "age = 42 }\n",
);

fn runtime_record_exact_cases() -> Vec<DifferentialCase> {
    runtime_record_case_definitions()
        .into_iter()
        .map(|(builtin, id, source, expected, stdout)| {
            let mut descriptor = runtime_single_typed_target_descriptor(builtin, &source);
            if builtin == "Record.modify" {
                descriptor.callback_contracts = runtime_record_modify_callback(id);
                if id == "undemanded-callback" {
                    descriptor.semantic_targets[0]
                        .obligations
                        .retain(|obligation| obligation.0.as_ref() != "callback-order");
                }
            }
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{expected}}}"
            );
            descriptor.semantic_targets[0].expected_typed_result_sha256 =
                Some(sha256_bytes(canonical.as_bytes()));
            descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
            DifferentialCase {
                id: Arc::from(format!(
                    "runtime-record-{}-{id}",
                    builtin.rsplit_once('.').expect("record builtin family").1
                )),
                source: Arc::from(source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_tuple_exact_cases() -> Vec<DifferentialCase> {
    let mut cases = runtime_tuple_lazy_cases();
    cases.extend(runtime_tuple_forced_cases());
    cases
}

fn runtime_tuple_lazy_cases() -> Vec<DifferentialCase> {
    [
        (
            "Tuple.(,)",
            "two",
            concat!(
                "main = do\n",
                "  let (selected,_ignored) = (1, Error.error \"undemanded-tuple-2\" :: Int)\n",
                "  IO.print selected\n",
            ),
            2,
        ),
        (
            "Tuple.(,,)",
            "three",
            concat!(
                "main = do\n",
                "  let (selected,_second,_third) = ",
                "(1, Error.error \"undemanded-tuple-3a\" :: Int, ",
                "Error.error \"undemanded-tuple-3b\" :: Int)\n",
                "  IO.print selected\n",
            ),
            3,
        ),
        (
            "Tuple.(,,,)",
            "four",
            concat!(
                "main = do\n",
                "  let (selected,_second,_third,_fourth) = ",
                "(1, Error.error \"undemanded-tuple-4a\" :: Int, ",
                "Error.error \"undemanded-tuple-4b\" :: Int, ",
                "Error.error \"undemanded-tuple-4c\" :: Int)\n",
                "  IO.print selected\n",
            ),
            4,
        ),
    ]
    .into_iter()
    .map(|(builtin, id, source, arity)| {
        let mut descriptor = runtime_single_typed_target_descriptor(builtin, source);
        let mut elements = vec![runtime_record_int(1)];
        elements.extend(
            std::iter::repeat_n(
                "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}",
                arity - 1,
            )
            .map(str::to_owned),
        );
        let expected = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Tuple\",\"elements\":[{}]}}}}",
            elements.join(",")
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(expected.as_bytes()));
        descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
            Some(crate::raw_presentation_sha256(b"1\n", b""));
        descriptor.semantic_targets[0].expected_lazy_argument_exit_sha256 = Some(
            crate::lazy_argument_exit_sha256(
                (0..arity).map(|argument| {
                    (
                        u16::try_from(argument).expect("tuple arity fits u16"),
                        "not-forced",
                    )
                }),
            ),
        );
        DifferentialCase {
            id: Arc::from(format!("runtime-tuple-{id}-lazy")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_tuple_forced_cases() -> Vec<DifferentialCase> {
    [
            (
                "Tuple.(,)",
                "two",
                concat!(
                    "main = do\n",
                    "  let (first,second) = (1,\"two\")\n",
                    "  IO.print first\n",
                    "  Text.putStrLn second\n",
                ),
                b"1\ntwo\n".as_slice(),
                vec![
                    runtime_record_int(1),
                    "{\"type\":\"Text\",\"utf8Hex\":\"74776f\"}".to_owned(),
                ],
            ),
            (
                "Tuple.(,,)",
                "three",
                concat!(
                    "main = do\n",
                    "  let (first,second,third) = (1,\"two\",Bool.True)\n",
                    "  IO.print first\n",
                    "  Text.putStrLn second\n",
                    "  IO.print third\n",
                ),
                b"1\ntwo\nTrue\n".as_slice(),
                vec![
                    runtime_record_int(1),
                    "{\"type\":\"Text\",\"utf8Hex\":\"74776f\"}".to_owned(),
                    "{\"type\":\"Bool\",\"value\":true}".to_owned(),
                ],
            ),
            (
                "Tuple.(,,,)",
                "four",
                concat!(
                    "main = do\n",
                    "  let (first,second,third,fourth) = (1,\"two\",Bool.True,4)\n",
                    "  IO.print first\n",
                    "  Text.putStrLn second\n",
                    "  IO.print third\n",
                    "  IO.print fourth\n",
                ),
                b"1\ntwo\nTrue\n4\n".as_slice(),
                vec![
                    runtime_record_int(1),
                    "{\"type\":\"Text\",\"utf8Hex\":\"74776f\"}".to_owned(),
                    "{\"type\":\"Bool\",\"value\":true}".to_owned(),
                    runtime_record_int(4),
                ],
            ),
    ]
    .into_iter()
    .map(|(builtin, id, source, stdout, elements)| {
        let mut descriptor = runtime_single_typed_target_descriptor(builtin, source);
        descriptor.semantic_targets[0]
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "lazy-boundary");
        let expected = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Tuple\",\"elements\":[{}]}}}}",
            elements.join(",")
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(expected.as_bytes()));
        descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
            Some(crate::raw_presentation_sha256(stdout, b""));
        DifferentialCase {
            id: Arc::from(format!("runtime-tuple-{id}-forced")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_record_case_definitions() -> Vec<RuntimeRecordCase> {
    let mut cases = runtime_record_get_cases();
    cases.extend(runtime_record_set_cases());
    cases.extend(runtime_record_modify_cases());
    cases
}

fn runtime_record_get_cases() -> Vec<RuntimeRecordCase> {
    vec![
        (
            "Record.get",
            "age",
            format!(
                "{RUNTIME_RECORD_DECLARATION}{RUNTIME_RECORD_PERSON}main = IO.print $ Record.get @\"age\" @Int Main.person\n"
            ),
            runtime_record_int(41),
            b"41\n".as_slice(),
        ),
        (
            "Record.get",
            "name",
            format!(
                "{RUNTIME_RECORD_DECLARATION}{RUNTIME_RECORD_PERSON}main = Text.putStrLn $ Record.get @\"name\" @Text Main.person\n"
            ),
            runtime_record_text("Ada"),
            b"Ada\n".as_slice(),
        ),
        (
            "Record.get",
            "lazy-other-field",
            format!(
                "{RUNTIME_RECORD_DECLARATION}{RUNTIME_LAZY_RECORD_PERSON}main = IO.print $ Record.get @\"age\" @Int Main.person\n"
            ),
            runtime_record_int(42),
            b"42\n".as_slice(),
        ),
    ]
}

fn runtime_record_set_cases() -> Vec<RuntimeRecordCase> {
    vec![
        (
            "Record.set",
            "age",
            [
                RUNTIME_RECORD_DECLARATION,
                RUNTIME_RECORD_PERSON,
                "main = IO.print $ Record.get @\"age\" @Int $ ",
                "Record.set @\"age\" @Int 42 Main.person\n",
            ]
            .concat(),
            runtime_record_set_age_value(42),
            b"42\n".as_slice(),
        ),
        (
            "Record.set",
            "name",
            [
                RUNTIME_RECORD_DECLARATION,
                RUNTIME_RECORD_PERSON,
                "main = Text.putStrLn $ Record.get @\"name\" @Text $ ",
                "Record.set @\"name\" @Text \"Grace\" Main.person\n",
            ]
            .concat(),
            runtime_record_set_name_value("Grace"),
            b"Grace\n".as_slice(),
        ),
        (
            "Record.set",
            "lazy-other-field",
            [
                RUNTIME_RECORD_DECLARATION,
                RUNTIME_LAZY_RECORD_PERSON,
                "updated = Record.set @\"age\" @Int 43 Main.person\n",
                "main = IO.print $ Record.get @\"age\" @Int Main.updated\n",
            ]
            .concat(),
            runtime_record_set_age_value(43),
            b"43\n".as_slice(),
        ),
    ]
}

fn runtime_record_modify_cases() -> Vec<RuntimeRecordCase> {
    vec![
        (
            "Record.modify",
            "age",
            [
                RUNTIME_RECORD_DECLARATION,
                RUNTIME_RECORD_PERSON,
                "main = IO.print $ Record.get @\"age\" @Int $ ",
                "Record.modify @\"age\" @Int (Int.plus 1) Main.person\n",
            ]
            .concat(),
            runtime_record_set_age_value(42),
            b"42\n".as_slice(),
        ),
        (
            "Record.modify",
            "name",
            [
                RUNTIME_RECORD_DECLARATION,
                RUNTIME_RECORD_PERSON,
                "main = Text.putStrLn $ Record.get @\"name\" @Text $ ",
                "Record.modify @\"name\" @Text Text.toUpper Main.person\n",
            ]
            .concat(),
            runtime_record_set_name_value("ADA"),
            b"ADA\n".as_slice(),
        ),
        (
            "Record.modify",
            "lazy-other-field",
            [
                RUNTIME_RECORD_DECLARATION,
                RUNTIME_LAZY_RECORD_PERSON,
                "main = IO.print $ Record.get @\"age\" @Int $ ",
                "Record.modify @\"age\" @Int (Int.plus 1) Main.person\n",
            ]
            .concat(),
            runtime_record_set_age_value(43),
            b"43\n".as_slice(),
        ),
        (
            "Record.modify",
            "undemanded-callback",
            [
                RUNTIME_RECORD_DECLARATION,
                RUNTIME_RECORD_PERSON,
                "main = Text.putStrLn $ Record.get @\"name\" @Text $ ",
                "Record.modify @\"age\" @Int (Error.error \"undemanded-modifier\") Main.person\n",
            ]
            .concat(),
            runtime_record_set_name_value("Ada"),
            b"Ada\n".as_slice(),
        ),
    ]
}

fn runtime_record_modify_callback(id: &str) -> Vec<CallbackContract> {
    let invocation = match id {
        "age" => Some((runtime_record_int(41), runtime_record_int(42))),
        "name" => Some((runtime_record_text("Ada"), runtime_record_text("ADA"))),
        "lazy-other-field" => Some((runtime_record_int(42), runtime_record_int(43))),
        "undemanded-callback" => None,
        _ => unreachable!("reviewed Record.modify case"),
    };
    invocation.map_or_else(Vec::new, |(argument, result)| {
        vec![CallbackContract {
            builtin: Arc::from("Record.modify"),
            invocations: vec![callback_contract_invocation(
                0,
                "field",
                &[&argument],
                &result,
            )],
        }]
    })
}

fn runtime_record_text(value: &str) -> String {
    format!("{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}", utf8_hex(value))
}

fn runtime_record_int(value: i64) -> String {
    format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}")
}

fn runtime_record_set_age_value(age: i64) -> String {
    let mut output = String::from(
        "{\"type\":\"Record\",\"typeNameHex\":\"4d61696e2e506572736f6e\",\"constructorHex\":\"506572736f6e\",\"fields\":[{\"nameHex\":\"616765\",\"value\":",
    );
    output.push_str(&runtime_record_int(age));
    output.push_str(
        "},{\"nameHex\":\"6e616d65\",\"value\":{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}}]}",
    );
    output
}

fn runtime_record_set_name_value(name: &str) -> String {
    let mut output = String::from(
        "{\"type\":\"Record\",\"typeNameHex\":\"4d61696e2e506572736f6e\",\"constructorHex\":\"506572736f6e\",\"fields\":[{\"nameHex\":\"616765\",\"value\":{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}},{\"nameHex\":\"6e616d65\",\"value\":",
    );
    output.push_str(&runtime_record_text(name));
    output.push_str("}]}");
    output
}

fn runtime_handle_obligation_descriptor(builtin: &str, source: &str) -> ClaimEvidenceDescriptor {
    let kind = runtime_handle_kind(builtin).expect("runtime handle builtin");
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Handle\",\"kind\":\"{kind}\"}}}}"
    );
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    let pure_target = descriptor
        .semantic_targets
        .iter_mut()
        .find(|target| target.dimension == CompatibilityDimension::PureRuntime)
        .expect("runtime handle has a PureRuntime target");
    pure_target
        .obligations
        .retain(|obligation| obligation.0.as_ref() != "adapter-failure");
    pure_target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    descriptor
}

fn runtime_handle_kind(builtin: &str) -> Option<&'static str> {
    match builtin {
        "IO.stdin" => Some("stdin"),
        "IO.stdout" => Some("stdout"),
        "IO.stderr" => Some("stderr"),
        "Process.nullStream" => Some("null"),
        _ => None,
    }
}

fn runtime_typed_raw_presentation(builtin: &str) -> Option<&'static [u8]> {
    match builtin {
        "Json.Null" => Some(b"null"),
        "Json.Bool" => Some(b"true"),
        "Json.String" => Some(b"\"value\""),
        "Json.Number" => Some(b"1.5"),
        "Json.Array" => Some(b"[null]"),
        "Json.Object" => Some(b"{\"key\":null}"),
        "Text.decodeUtf8" => Some(b"\"a\\946\"\n"),
        "Text.drop" => Some(b"\"\\946\"\n"),
        _ => None,
    }
}

fn runtime_json_codec_presentation_cases() -> Vec<DifferentialCase> {
    [
        (
            "Json.encode",
            "main = ByteString.hPutStr IO.stdout $ Json.encode $ Json.String \"aβ\"\n",
            "\"aβ\"".as_bytes(),
        ),
        (
            "Json.decode",
            concat!(
                "decoded = Maybe.maybe (Error.error \"decode\") Function.id $ ",
                "Json.decode $ Text.encodeUtf8 \"{\\\"key\\\":\\\"β\\\"}\"\n",
                "main = ByteString.hPutStr IO.stdout $ Json.encode Main.decoded\n",
            ),
            "{\"key\":\"β\"}".as_bytes(),
        ),
    ]
    .into_iter()
    .map(|(builtin, source, stdout)| {
        let mut descriptor = runtime_single_typed_target_descriptor(builtin, source);
        attach_raw_presentation_target(&mut descriptor, builtin, stdout);
        DifferentialCase {
            id: Arc::from(format!(
                "runtime-raw-{}",
                hell_builtins::lookup(builtin)
                    .and_then(|spec| spec.implementation)
                    .expect("JSON codec has a runtime implementation")
                    .replace('_', "-")
            )),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

type RuntimeJsonValueDefinition = (
    &'static str,
    &'static str,
    u16,
    &'static str,
    Vec<&'static str>,
    &'static str,
);

fn runtime_json_value_definitions() -> [RuntimeJsonValueDefinition; 6] {
    [
        (
            "null",
            concat!(
                "main = Text.putStr $ Json.value \"null\" (\\_ -> \"bool\") ",
                "(\\_ -> \"string\") (\\_ -> \"number\") (\\_ -> \"array\") ",
                "(\\_ -> \"object\") Json.Null\n",
            ),
            0,
            "null",
            Vec::new(),
            "null",
        ),
        (
            "bool",
            concat!(
                "main = Text.putStr $ Json.value \"null\" ",
                "(\\flag -> if flag then \"bool-true\" else \"bool-false\") ",
                "(\\_ -> \"string\") (\\_ -> \"number\") (\\_ -> \"array\") ",
                "(\\_ -> \"object\") (Json.Bool Bool.True)\n",
            ),
            1,
            "bool",
            vec!["{\"type\":\"Bool\",\"value\":true}"],
            "bool-true",
        ),
        (
            "string",
            concat!(
                "main = Text.putStr $ Json.value \"null\" (\\_ -> \"bool\") ",
                "(\\text -> Text.concat [\"string:\",text]) (\\_ -> \"number\") ",
                "(\\_ -> \"array\") (\\_ -> \"object\") (Json.String \"aβ\")\n",
            ),
            2,
            "string",
            vec!["{\"type\":\"Text\",\"utf8Hex\":\"61ceb2\"}"],
            "string:aβ",
        ),
        (
            "number",
            concat!(
                "main = Text.putStr $ Json.value \"null\" (\\_ -> \"bool\") ",
                "(\\_ -> \"string\") (\\number -> Double.show number) ",
                "(\\_ -> \"array\") (\\_ -> \"object\") (Json.Number 1.5)\n",
            ),
            3,
            "number",
            vec!["{\"type\":\"Double\",\"ieee754Bits\":\"3ff8000000000000\"}"],
            "1.5",
        ),
        (
            "array",
            concat!(
                "main = Text.putStr $ Json.value \"null\" (\\_ -> \"bool\") ",
                "(\\_ -> \"string\") (\\_ -> \"number\") ",
                "(\\values -> Text.decodeUtf8 $ Json.encode $ Json.Array values) ",
                "(\\_ -> \"object\") (Json.Array $ Vector.fromList [Json.Null])\n",
            ),
            4,
            "array",
            vec![concat!(
                "{\"type\":\"Vector\",\"elements\":[",
                "{\"type\":\"PrimitiveVariant\",\"family\":\"Json\",",
                "\"constructor\":\"Null\",\"payloads\":[]}]}",
            )],
            "[null]",
        ),
        (
            "object",
            concat!(
                "main = Text.putStr $ Json.value \"null\" (\\_ -> \"bool\") ",
                "(\\_ -> \"string\") (\\_ -> \"number\") (\\_ -> \"array\") ",
                "(\\values -> Text.decodeUtf8 $ Json.encode $ Json.Object values) ",
                "(Json.Object $ Map.fromList [(\"key\",Json.Null)])\n",
            ),
            5,
            "object",
            vec![concat!(
                "{\"type\":\"Map\",\"entries\":[{\"key\":",
                "{\"type\":\"Text\",\"utf8Hex\":\"6b6579\"},\"value\":",
                "{\"type\":\"PrimitiveVariant\",\"family\":\"Json\",",
                "\"constructor\":\"Null\",\"payloads\":[]}}]}",
            )],
            "{\"key\":null}",
        ),
    ]
}

fn runtime_json_value_cases() -> Vec<DifferentialCase> {
    runtime_json_value_definitions()
        .into_iter()
        .map(
            |(id, source, callback_argument, branch, arguments, result)| {
                let result_canonical =
                    format!("{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}", utf8_hex(result));
                let mut descriptor = runtime_all_obligation_descriptor("Json.value", source);
                descriptor.callback_contracts = vec![CallbackContract {
                    builtin: Arc::from("Json.value"),
                    invocations: vec![callback_contract_invocation(
                        callback_argument,
                        branch,
                        &arguments,
                        &result_canonical,
                    )],
                }];
                attach_raw_presentation_target(&mut descriptor, "Json.value", result.as_bytes());
                DifferentialCase {
                    id: Arc::from(format!("runtime-json-value-{id}")),
                    source: Arc::from(source),
                    claim_evidence: Some(descriptor),
                    ..DifferentialCase::default()
                }
            },
        )
        .collect()
}

fn runtime_json_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = runtime_json_string_boundary_cases();
    cases.extend(runtime_json_encode_boundary_cases());
    cases.extend(runtime_json_decode_boundary_cases());
    cases
}

fn runtime_json_string_boundary_cases() -> Vec<DifferentialCase> {
    [("empty-input", ""), ("ascii", "abc"), ("unicode", "β")]
        .into_iter()
        .map(|(boundary, input)| {
            let source = format!("main = IO.print $ Json.String \"{input}\"\n");
            let value = format!(
                "{{\"type\":\"PrimitiveVariant\",\"family\":\"Json\",\"constructor\":\"String\",\"payloads\":[{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}]}}",
                utf8_hex(input)
            );
            DifferentialCase {
                id: Arc::from(format!("json-string-boundary-{boundary}")),
                source: Arc::from(source.as_str()),
                claim_evidence: Some(runtime_expected_boundary_descriptor(
                    "Json.String",
                    boundary,
                    &source,
                    &value,
                )),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_json_encode_boundary_cases() -> Vec<DifferentialCase> {
    [
        ("empty-input", "", "2222"),
        ("ascii", "abc", "2261626322"),
        ("unicode", "β", "22ceb222"),
    ]
    .into_iter()
    .map(|(boundary, input, expected_hex)| {
        let source = format!("main = IO.print $ Json.encode $ Json.String \"{input}\"\n");
        let value = format!("{{\"type\":\"ByteString\",\"hex\":\"{expected_hex}\"}}");
        DifferentialCase {
            id: Arc::from(format!("json-encode-boundary-{boundary}")),
            source: Arc::from(source.as_str()),
            claim_evidence: Some(runtime_expected_boundary_descriptor(
                "Json.encode",
                boundary,
                &source,
                &value,
            )),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_json_decode_boundary_cases() -> Vec<DifferentialCase> {
    let source = "main = do\n  bytes <- ByteString.getContents\n  IO.print $ Json.decode bytes\n";
    [
        ("empty-input", Vec::new(), "null".to_owned()),
        (
            "ascii",
            b"true".to_vec(),
            "{\"type\":\"PrimitiveVariant\",\"family\":\"Json\",\"constructor\":\"Bool\",\"payloads\":[{\"type\":\"Bool\",\"value\":true}]}".to_owned(),
        ),
        (
            "unicode",
            "\"β\"".as_bytes().to_vec(),
            "{\"type\":\"PrimitiveVariant\",\"family\":\"Json\",\"constructor\":\"String\",\"payloads\":[{\"type\":\"Text\",\"utf8Hex\":\"ceb2\"}]}".to_owned(),
        ),
        ("invalid-encoding", vec![0xff, b'A'], "null".to_owned()),
    ]
    .into_iter()
    .map(|(boundary, stdin, payload)| {
        let value = format!("{{\"type\":\"Maybe\",\"payload\":{payload}}}");
        DifferentialCase {
            id: Arc::from(format!("json-decode-boundary-{boundary}")),
            source: Arc::from(source),
            stdin,
            claim_evidence: Some(runtime_expected_boundary_descriptor(
                "Json.decode",
                boundary,
                source,
                &value,
            )),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_text_output_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "Text.putStr",
            [
                ("empty-input", "main = Text.putStr \"\"\n", ""),
                ("ascii", "main = Text.putStr \"abc\"\n", "abc"),
                ("unicode", "main = Text.putStr \"aβ\"\n", "aβ"),
            ],
        ),
        (
            "Text.putStrLn",
            [
                ("empty-input", "main = Text.putStrLn \"\"\n", "\n"),
                ("ascii", "main = Text.putStrLn \"abc\"\n", "abc\n"),
                ("unicode", "main = Text.putStrLn \"aβ\"\n", "aβ\n"),
            ],
        ),
        (
            "Text.hPutStr",
            [
                ("empty-input", "main = Text.hPutStr IO.stdout \"\"\n", ""),
                ("ascii", "main = Text.hPutStr IO.stdout \"abc\"\n", "abc"),
                ("unicode", "main = Text.hPutStr IO.stdout \"aβ\"\n", "aβ"),
            ],
        ),
    ]
    .into_iter()
    .flat_map(|(builtin, boundaries)| {
        boundaries
            .into_iter()
            .map(move |(boundary, source, stdout)| {
                let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
                descriptor
                    .semantic_targets
                    .iter_mut()
                    .find(|target| {
                        target.dimension == hell_builtins::CompatibilityDimension::PureRuntime
                    })
                    .expect("Text output has a pure runtime target")
                    .boundary_classes = vec![Arc::from(boundary)];
                attach_raw_presentation_target(&mut descriptor, builtin, stdout.as_bytes());
                DifferentialCase {
                    id: Arc::from(format!(
                        "{}-boundary-{boundary}",
                        builtin.to_ascii_lowercase().replace('.', "-")
                    )),
                    source: Arc::from(source),
                    claim_evidence: Some(descriptor),
                    ..DifferentialCase::default()
                }
            })
    })
    .collect()
}

fn runtime_text_decode_utf8_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print $ Text.decodeUtf8 $ Text.encodeUtf8 \"\"\n",
            Vec::new(),
            Some("\"\"\n".as_bytes()),
        ),
        (
            "ascii",
            "main = IO.print $ Text.decodeUtf8 $ Text.encodeUtf8 \"abc\"\n",
            Vec::new(),
            Some("\"abc\"\n".as_bytes()),
        ),
        (
            "unicode",
            "main = IO.print $ Text.decodeUtf8 $ Text.encodeUtf8 \"aβ\"\n",
            Vec::new(),
            Some(b"\"a\\946\"\n"),
        ),
        (
            "invalid-encoding",
            "main = do\n  bytes <- ByteString.getContents\n  IO.print $ Text.decodeUtf8 bytes\n",
            vec![0xff, b'A'],
            None,
        ),
    ]
    .into_iter()
    .map(|(boundary, source, stdin, stdout)| {
        let mut descriptor = runtime_all_obligation_descriptor("Text.decodeUtf8", source);
        let pure = descriptor
            .semantic_targets
            .iter_mut()
            .find(|target| target.dimension == hell_builtins::CompatibilityDimension::PureRuntime)
            .expect("Text.decodeUtf8 has a pure runtime target");
        pure.boundary_classes = vec![Arc::from(boundary)];
        pure.obligations.retain(|obligation| {
            if boundary == "invalid-encoding" {
                obligation.0.as_ref() != "adapter-success"
            } else {
                obligation.0.as_ref() != "adapter-failure"
            }
        });
        if let Some(stdout) = stdout {
            attach_raw_presentation_target(&mut descriptor, "Text.decodeUtf8", stdout);
        } else {
            descriptor.targets.retain(|target| {
                target.dimension != hell_builtins::CompatibilityDimension::Presentation
            });
            descriptor.semantic_targets.retain(|target| {
                target.dimension != hell_builtins::CompatibilityDimension::Presentation
            });
        }
        DifferentialCase {
            id: Arc::from(format!("text-decodeutf8-boundary-{boundary}")),
            source: Arc::from(source),
            stdin,
            expected_runtime_completion: boundary != "invalid-encoding",
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_text_stdio_input_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = Vec::new();
    for (boundary, stdin, stdout) in [
        ("empty-input", Vec::new(), Some(Vec::new())),
        ("ascii", b"abc".to_vec(), Some(b"abc".to_vec())),
        (
            "unicode",
            "aβ".as_bytes().to_vec(),
            Some("aβ".as_bytes().to_vec()),
        ),
        ("invalid-encoding", vec![0xff, b'A'], None),
    ] {
        cases.push(runtime_text_stdio_input_case(
            "Text.getContents",
            boundary,
            "main = do\n  text <- Text.getContents\n  Text.putStr text\n",
            stdin,
            stdout,
        ));
    }
    for (boundary, stdin, stdout) in [
        ("empty-input", Vec::new(), None),
        ("ascii", b"abc\nrest".to_vec(), Some(b"abc".to_vec())),
        (
            "unicode",
            "aβ\r\nrest".as_bytes().to_vec(),
            Some("aβ\r".as_bytes().to_vec()),
        ),
        ("invalid-encoding", vec![0xff, b'A', b'\n'], None),
    ] {
        cases.push(runtime_text_stdio_input_case(
            "Text.getLine",
            boundary,
            "main = do\n  text <- Text.getLine\n  Text.putStr text\n",
            stdin,
            stdout,
        ));
    }
    cases
}

fn runtime_text_stdio_input_case(
    builtin: &str,
    boundary: &str,
    source: &str,
    stdin: Vec<u8>,
    stdout: Option<Vec<u8>>,
) -> DifferentialCase {
    let success = stdout.is_some();
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    for target in &mut descriptor.semantic_targets {
        match target.dimension {
            hell_builtins::CompatibilityDimension::PureRuntime => {
                target.boundary_classes = vec![Arc::from(boundary)];
                target.obligations.retain(|obligation| {
                    obligation.0.as_ref()
                        != if success {
                            "adapter-failure"
                        } else {
                            "adapter-success"
                        }
                });
            }
            hell_builtins::CompatibilityDimension::Effects => {
                target.obligations.retain(|obligation| {
                    obligation.0.as_ref()
                        != if success {
                            "effect-failure"
                        } else {
                            "effect-success"
                        }
                });
            }
            _ => {}
        }
    }
    if let Some(stdout) = stdout {
        attach_raw_presentation_target(&mut descriptor, builtin, &stdout);
    } else {
        descriptor.targets.retain(|target| {
            target.dimension != hell_builtins::CompatibilityDimension::Presentation
        });
        descriptor.semantic_targets.retain(|target| {
            target.dimension != hell_builtins::CompatibilityDimension::Presentation
        });
    }
    DifferentialCase {
        id: Arc::from(format!(
            "{}-boundary-{boundary}",
            builtin.to_ascii_lowercase().replace('.', "-")
        )),
        source: Arc::from(source),
        stdin,
        expected_runtime_completion: success,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_byte_string_stdio_boundary_cases() -> Vec<DifferentialCase> {
    let definitions = [
        (
            "ByteString.getContents",
            "main = do\n  bytes <- ByteString.getContents\n  ByteString.hPutStr IO.stdout bytes\n",
        ),
        (
            "ByteString.hPutStr",
            "main = do\n  bytes <- ByteString.getContents\n  ByteString.hPutStr IO.stdout bytes\n",
        ),
        (
            "ByteString.hGet",
            "main = do\n  bytes <- ByteString.hGet IO.stdin 4096\n  ByteString.hPutStr IO.stdout bytes\n",
        ),
    ];
    definitions
        .into_iter()
        .flat_map(|(builtin, source)| {
            [
                ("empty-input", Vec::new()),
                ("ascii", b"abc".to_vec()),
                ("unicode", "aβ".as_bytes().to_vec()),
                ("invalid-encoding", vec![0xff, b'A']),
            ]
            .into_iter()
            .map(move |(boundary, stdin)| {
                let descriptor =
                    runtime_expected_raw_boundary_descriptor(builtin, boundary, source, &stdin);
                DifferentialCase {
                    id: Arc::from(format!(
                        "{}-boundary-{boundary}",
                        builtin.to_ascii_lowercase().replace('.', "-")
                    )),
                    source: Arc::from(source),
                    stdin,
                    claim_evidence: Some(descriptor),
                    ..DifferentialCase::default()
                }
            })
        })
        .collect()
}

fn runtime_text_file_output_boundary_cases() -> Vec<DifferentialCase> {
    let definitions = [
        (
            "Text.writeFile",
            "text-writefile",
            concat!(
                "main = do\n",
                "  input <- Text.getContents\n",
                "  Text.writeFile \"boundary.txt\" input\n",
                "  output <- Text.readFile \"boundary.txt\"\n",
                "  Text.putStr output\n",
            ),
            "main = Text.writeFile \"missing-parent/file.txt\" \"x\"\n",
        ),
        (
            "Text.appendFile",
            "text-appendfile",
            concat!(
                "main = do\n",
                "  input <- Text.getContents\n",
                "  Text.writeFile \"boundary.txt\" \"\"\n",
                "  Text.appendFile \"boundary.txt\" input\n",
                "  output <- Text.readFile \"boundary.txt\"\n",
                "  Text.putStr output\n",
            ),
            "main = Text.appendFile \"missing-parent/file.txt\" \"x\"\n",
        ),
    ];
    definitions
        .into_iter()
        .flat_map(|(builtin, prefix, source, failure_source)| {
            runtime_file_writer_boundary_cases(builtin, prefix, source, failure_source)
        })
        .collect()
}

fn runtime_file_writer_boundary_cases(
    builtin: &str,
    prefix: &str,
    source: &str,
    failure_source: &str,
) -> Vec<DifferentialCase> {
    let mut cases = [
        ("empty-input", Vec::new()),
        ("ascii", b"abc".to_vec()),
        ("unicode", "aβ".as_bytes().to_vec()),
    ]
    .into_iter()
    .map(|(boundary, stdin)| {
        let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
        for target in &mut descriptor.semantic_targets {
            match target.dimension {
                hell_builtins::CompatibilityDimension::PureRuntime => {
                    target.boundary_classes = vec![Arc::from(boundary)];
                    target.expected_raw_presentation_sha256 =
                        Some(crate::raw_presentation_sha256(&stdin, b""));
                }
                hell_builtins::CompatibilityDimension::Presentation => {
                    target.expected_raw_presentation_sha256 =
                        Some(crate::raw_presentation_sha256(&stdin, b""));
                }
                hell_builtins::CompatibilityDimension::Effects => target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "effect-failure"),
                _ => {}
            }
        }
        DifferentialCase {
            id: Arc::from(format!("{prefix}-boundary-{boundary}")),
            source: Arc::from(source),
            stdin,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect::<Vec<_>>();
    let mut descriptor = runtime_all_obligation_descriptor(builtin, failure_source);
    descriptor
        .targets
        .retain(|target| target.dimension != hell_builtins::CompatibilityDimension::Presentation);
    descriptor
        .semantic_targets
        .retain(|target| target.dimension != hell_builtins::CompatibilityDimension::Presentation);
    descriptor.semantic_targets.iter_mut().for_each(|target| {
        if target.dimension == hell_builtins::CompatibilityDimension::Effects {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "effect-success");
        } else if target.dimension == hell_builtins::CompatibilityDimension::PureRuntime {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "adapter-success");
        }
    });
    cases.push(DifferentialCase {
        id: Arc::from(format!("runtime-typed-io-{prefix}-failure")),
        source: Arc::from(failure_source),
        expected_runtime_completion: false,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    });
    cases
}

fn runtime_byte_string_write_file_boundary_cases() -> Vec<DifferentialCase> {
    let source = concat!(
        "main = do\n",
        "  input <- ByteString.getContents\n",
        "  ByteString.writeFile \"boundary.bin\" input\n",
        "  output <- ByteString.readFile \"boundary.bin\"\n",
        "  ByteString.hPutStr IO.stdout output\n",
    );
    let mut cases = [
        ("empty-input", Vec::new()),
        ("ascii", b"abc".to_vec()),
        ("unicode", "aβ".as_bytes().to_vec()),
        ("invalid-encoding", vec![0xff, b'A']),
    ]
    .into_iter()
    .map(|(boundary, stdin)| {
        let mut descriptor = runtime_all_obligation_descriptor("ByteString.writeFile", source);
        for target in &mut descriptor.semantic_targets {
            match target.dimension {
                hell_builtins::CompatibilityDimension::PureRuntime => {
                    target.boundary_classes = vec![Arc::from(boundary)];
                    target.expected_raw_presentation_sha256 =
                        Some(crate::raw_presentation_sha256(&stdin, b""));
                }
                hell_builtins::CompatibilityDimension::Effects => {
                    target
                        .obligations
                        .retain(|obligation| obligation.0.as_ref() != "effect-failure");
                }
                _ => {}
            }
        }
        DifferentialCase {
            id: Arc::from(format!("bytestring-writefile-boundary-{boundary}")),
            source: Arc::from(source),
            stdin,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect::<Vec<_>>();
    let failure_source =
        "main = ByteString.writeFile \"missing-parent/file.bin\" $ Text.encodeUtf8 \"x\"\n";
    let mut failure_descriptor =
        runtime_all_obligation_descriptor("ByteString.writeFile", failure_source);
    failure_descriptor
        .semantic_targets
        .iter_mut()
        .for_each(|target| {
            if target.dimension == hell_builtins::CompatibilityDimension::Effects {
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "effect-success");
            }
        });
    cases.push(DifferentialCase {
        id: Arc::from("runtime-typed-io-bytestring-writefile-failure"),
        source: Arc::from(failure_source),
        expected_runtime_completion: false,
        claim_evidence: Some(failure_descriptor),
        ..DifferentialCase::default()
    });
    cases
}

fn runtime_file_reader_boundary_cases() -> Vec<DifferentialCase> {
    let text_source = concat!(
        "main = do\n",
        "  bytes <- ByteString.getContents\n",
        "  ByteString.writeFile \"boundary.bin\" bytes\n",
        "  output <- Text.readFile \"boundary.bin\"\n",
        "  Text.putStr output\n",
    );
    let bytes_source = concat!(
        "main = do\n",
        "  input <- ByteString.getContents\n",
        "  ByteString.writeFile \"boundary.bin\" input\n",
        "  output <- ByteString.readFile \"boundary.bin\"\n",
        "  ByteString.hPutStr IO.stdout output\n",
    );
    let mut cases =
        runtime_reader_boundary_cases("Text.readFile", "text-readfile", text_source, true);
    cases.extend(runtime_reader_boundary_cases(
        "ByteString.readFile",
        "bytestring-readfile",
        bytes_source,
        false,
    ));
    cases
}

fn runtime_interact_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = runtime_interact_cases(
        "Text.interact",
        "text-interact",
        "main = Text.interact Text.toUpper\n",
        true,
    );
    cases.extend(runtime_interact_cases(
        "ByteString.interact",
        "bytestring-interact",
        "main = ByteString.interact Function.id\n",
        false,
    ));
    cases
}

fn runtime_read_process_boundary_cases() -> Vec<DifferentialCase> {
    [
        ("Text.readProcess", "text-readprocess", true),
        ("Text.readProcess_", "text-readprocess-checked", true),
        (
            "Text.readProcessStdout_",
            "text-readprocess-stdout-checked",
            true,
        ),
        ("ByteString.readProcess", "bytestring-readprocess", false),
        (
            "ByteString.readProcess_",
            "bytestring-readprocess-checked",
            false,
        ),
        (
            "ByteString.readProcessStdout_",
            "bytestring-readprocess-stdout-checked",
            false,
        ),
    ]
    .into_iter()
    .flat_map(|(builtin, prefix, text)| runtime_read_process_cases(builtin, prefix, text))
    .collect()
}

fn runtime_read_process_cases(
    builtin: &str,
    prefix: &str,
    text_output: bool,
) -> Vec<DifferentialCase> {
    let mut cases = [
        ("empty-input", Vec::new()),
        ("ascii", b"abc".to_vec()),
        ("unicode", "aβ".as_bytes().to_vec()),
        ("invalid-encoding", vec![0xff, b'A']),
    ]
    .into_iter()
    .map(|(boundary, stdin)| {
        let source = runtime_read_process_source(builtin, text_output, &runtime_bytes_hex(&stdin));
        let fails = text_output && boundary == "invalid-encoding";
        let descriptor =
            runtime_process_boundary_descriptor(builtin, boundary, &source, &stdin, fails);
        DifferentialCase {
            id: Arc::from(format!("{prefix}-boundary-{boundary}")),
            source: Arc::from(source.as_str()),
            arguments: vec!["hell-test-helper".into()],
            stdin,
            environment_profile: EnvironmentProfile::ProcessCapable,
            expected_runtime_completion: !fails,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect::<Vec<_>>();
    if !text_output {
        let source = runtime_missing_process_source(builtin);
        let mut descriptor = runtime_all_obligation_descriptor(builtin, &source);
        descriptor.targets.retain(|target| {
            target.dimension != hell_builtins::CompatibilityDimension::Presentation
        });
        descriptor.semantic_targets.retain(|target| {
            target.dimension != hell_builtins::CompatibilityDimension::Presentation
        });
        descriptor.semantic_targets.iter_mut().for_each(|target| {
            if target.dimension == hell_builtins::CompatibilityDimension::Effects {
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "effect-success");
            } else if target.dimension == hell_builtins::CompatibilityDimension::PureRuntime {
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "adapter-success");
            }
        });
        cases.push(DifferentialCase {
            id: Arc::from(format!("runtime-typed-io-{prefix}-failure")),
            source: Arc::from(source),
            arguments: vec!["hell-test-helper".into()],
            environment_profile: EnvironmentProfile::ProcessCapable,
            expected_runtime_completion: false,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        });
    }
    cases
}

fn runtime_missing_process_source(builtin: &str) -> String {
    let binding = if builtin.ends_with("Stdout_") {
        "_output"
    } else if builtin.ends_with("readProcess") {
        "(_exit, _output, _stderr)"
    } else {
        "(_output, _stderr)"
    };
    format!(
        "main = do\n  {binding} <- {builtin} $ Process.proc \"missing-hell-test-helper\" []\n  IO.pure ()\n"
    )
}

fn runtime_bytes_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn runtime_read_process_source(builtin: &str, text_output: bool, stdout_hex: &str) -> String {
    let binding = if builtin.ends_with("Stdout_") {
        "output"
    } else if builtin.ends_with("readProcess") {
        "(_exit, output, _stderr)"
    } else {
        "(output, _stderr)"
    };
    let consumer = if text_output {
        "Text.putStr output"
    } else {
        "ByteString.hPutStr IO.stdout output"
    };
    format!(
        concat!(
            "main = do\n",
            "  helpers <- Environment.getArgs\n",
            "  Monad.forM_ helpers \\helper -> do\n",
            "    {binding} <- {builtin} $\n",
            "      Process.proc helper [\"emit-hex\",{stdout_hex:?}]\n",
            "    {consumer}\n",
        ),
        binding = binding,
        builtin = builtin,
        stdout_hex = stdout_hex,
        consumer = consumer,
    )
}

fn runtime_process_boundary_descriptor(
    builtin: &str,
    boundary: &str,
    source: &str,
    stdout: &[u8],
    fails: bool,
) -> ClaimEvidenceDescriptor {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    for target in &mut descriptor.semantic_targets {
        if target.dimension == hell_builtins::CompatibilityDimension::PureRuntime {
            target.boundary_classes = vec![Arc::from(boundary)];
            if fails {
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "adapter-success");
            } else {
                target.expected_raw_presentation_sha256 =
                    Some(crate::raw_presentation_sha256(stdout, b""));
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "adapter-failure");
            }
        }
        if target.dimension == hell_builtins::CompatibilityDimension::Presentation && !fails {
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        }
        if target.dimension == hell_builtins::CompatibilityDimension::Effects {
            let omitted = if fails {
                "effect-success"
            } else {
                "effect-failure"
            };
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != omitted);
        }
    }
    if fails {
        descriptor.targets.retain(|target| {
            target.dimension != hell_builtins::CompatibilityDimension::Presentation
        });
        descriptor.semantic_targets.retain(|target| {
            target.dimension != hell_builtins::CompatibilityDimension::Presentation
        });
    }
    descriptor
}

fn runtime_process_builder_cases() -> Vec<DifferentialCase> {
    runtime_process_builder_definitions()
        .into_iter()
        .map(|(builtin, id, source, expected)| {
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{expected}}}"
            );
            let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
            let pure_target = descriptor
                .semantic_targets
                .iter_mut()
                .find(|target| target.dimension == CompatibilityDimension::PureRuntime)
                .expect("Process builder has a PureRuntime target");
            pure_target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "adapter-failure");
            pure_target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
            DifferentialCase {
                id: Arc::from(format!("runtime-typed-process-{id}")),
                source: Arc::from(source),
                arguments: vec!["hell-test-helper".into()],
                environment_profile: EnvironmentProfile::ProcessCapable,
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_process_execution_cases() -> Vec<DifferentialCase> {
    let mut cases = runtime_process_execution_success_cases();
    for (builtin, id) in [
        ("Process.runProcess", "runtime-process-run-failure"),
        ("Process.runProcess_", "runtime-process-run-checked-failure"),
    ] {
        let source = if builtin == "Process.runProcess" {
            concat!(
                "main = do\n",
                "  _exit <- Process.runProcess $ Process.proc \"missing-hell-test-helper\" []\n",
                "  IO.pure ()\n",
            )
            .to_owned()
        } else {
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper ->\n",
                "    Process.runProcess_ $\n",
                "      Process.setStderr Process.nullStream $ Process.proc helper [\"fail\"]\n",
            )
            .to_owned()
        };
        let mut case = runtime_adapter_failure_case(builtin, id, &source);
        if builtin == "Process.runProcess_" {
            case.arguments = vec!["hell-test-helper".into()];
        }
        case.environment_profile = EnvironmentProfile::ProcessCapable;
        cases.push(case);
    }
    cases
}

fn runtime_process_execution_success_cases() -> Vec<DifferentialCase> {
    let run_source = concat!(
        "main = do\n",
        "  helpers <- Environment.getArgs\n",
        "  Monad.forM_ helpers \\helper -> do\n",
        "    handle <- IO.openFile \"child.out\" IO.WriteMode\n",
        "    exit <- Process.runProcess $\n",
        "      Process.setStdout (Process.useHandleClose handle) $\n",
        "        Process.proc helper [\"emit-hex\",\"41\"]\n",
        "    output <- Text.readFile \"child.out\"\n",
        "    Text.putStr output\n",
        "    IO.print exit\n",
    );
    let checked_source = concat!(
        "main = do\n",
        "  helpers <- Environment.getArgs\n",
        "  Monad.forM_ helpers \\helper -> do\n",
        "    handle <- IO.openFile \"child.out\" IO.WriteMode\n",
        "    Process.runProcess_ $\n",
        "      Process.setStdout (Process.useHandleClose handle) $\n",
        "        Process.proc helper [\"emit-hex\",\"41\"]\n",
        "    output <- Text.readFile \"child.out\"\n",
        "    Text.putStr output\n",
    );
    vec![
        runtime_process_execution_success_case(
            "Process.runProcess",
            "runtime-process-run-success",
            run_source,
            b"AExitSuccess\n",
        ),
        runtime_process_execution_success_case(
            "Process.runProcess_",
            "runtime-process-run-checked-success",
            checked_source,
            b"A",
        ),
        runtime_process_execution_success_case(
            "Process.runProcess",
            "runtime-process-run-nonzero",
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper -> do\n",
                "    exit <- Process.runProcess $\n",
                "      Process.setStderr Process.nullStream $ Process.proc helper [\"fail\"]\n",
                "    IO.print exit\n",
            ),
            b"ExitFailure 2\n",
        ),
        runtime_process_execution_success_case(
            "Process.useHandleOpen",
            "runtime-process-use-handle-open",
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper -> do\n",
                "    handle <- IO.openFile \"child.out\" IO.WriteMode\n",
                "    Process.runProcess_ $\n",
                "      Process.setStdout (Process.useHandleOpen handle) $\n",
                "        Process.proc helper [\"emit-hex\",\"41\"]\n",
                "    Text.hPutStr handle \"B\"\n",
                "    IO.hClose handle\n",
                "    output <- Text.readFile \"child.out\"\n",
                "    Text.putStr output\n",
            ),
            b"AB",
        ),
        runtime_process_execution_success_case(
            "Process.useHandleClose",
            "runtime-process-use-handle-close",
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper -> do\n",
                "    handle <- IO.openFile \"child.out\" IO.WriteMode\n",
                "    Process.runProcess_ $\n",
                "      Process.setStdout (Process.useHandleClose handle) $\n",
                "        Process.proc helper [\"emit-hex\",\"41\"]\n",
                "    output <- Text.readFile \"child.out\"\n",
                "    Text.putStr output\n",
            ),
            b"A",
        ),
    ]
}

fn runtime_process_execution_success_case(
    builtin: &str,
    id: &str,
    source: &str,
    stdout: &[u8],
) -> DifferentialCase {
    let mut case = runtime_io_success_case(builtin, id, source, stdout);
    if builtin == "Process.useHandleClose" {
        let canonical = concat!(
            "{\"type\":\"TypedResult\",\"argument\":0,",
            "\"boundary\":\"adapter-result\",\"value\":",
            "{\"type\":\"Handle\",\"kind\":\"file\",\"closeAfterProcess\":true}}",
        );
        let pure = case
            .claim_evidence
            .as_mut()
            .expect("process handle descriptor")
            .semantic_targets
            .iter_mut()
            .find(|target| target.dimension == CompatibilityDimension::PureRuntime)
            .expect("Process.useHandleClose has a PureRuntime target");
        pure.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    }
    case.arguments = vec!["hell-test-helper".into()];
    case.environment_profile = EnvironmentProfile::ProcessCapable;
    case
}

fn runtime_environment_observation_cases() -> Vec<DifferentialCase> {
    let args_source = concat!(
        "main = do\n",
        "  arguments <- Environment.getArgs\n",
        "  Monad.forM_ arguments Text.putStrLn\n",
    );
    let env_source = concat!(
        "main = do\n",
        "  value <- Environment.getEnv \"REVIEWED_ENV\"\n",
        "  Text.putStr value\n",
    );
    let mut cases = vec![
        runtime_environment_success_case(
            "Environment.getArgs",
            "runtime-environment-get-args",
            args_source,
            b"alpha\n\xce\xb2\n",
            vec!["alpha".into(), "β".into()],
            Vec::new(),
        ),
        runtime_environment_success_case(
            "Environment.getEnv",
            "runtime-environment-get-env",
            env_source,
            b"bound",
            Vec::new(),
            vec![("REVIEWED_ENV".into(), "bound".into())],
        ),
        runtime_environment_success_case(
            "Environment.getEnvironment",
            "runtime-environment-get-environment",
            concat!(
                "main = do\n",
                "  values <- Environment.getEnvironment\n",
                "  Monad.forM_ values \\(name, value) ->\n",
                "    Text.putStrLn $ Text.concat [name, \"=\", value]\n",
            ),
            b"FIRST=one\nSECOND=two\n",
            Vec::new(),
            vec![
                ("FIRST".into(), "one".into()),
                ("SECOND".into(), "two".into()),
            ],
        ),
    ];
    let failure_source = concat!(
        "main = do\n",
        "  value <- Environment.getEnv \"MISSING_REVIEWED_ENV\"\n",
        "  IO.pure ()\n",
    );
    let mut failure = runtime_all_obligation_descriptor("Environment.getEnv", failure_source);
    failure.semantic_targets.retain_mut(|target| {
        if target.dimension != CompatibilityDimension::Effects {
            return false;
        }
        target
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "effect-success");
        true
    });
    failure
        .targets
        .retain(|target| target.dimension == CompatibilityDimension::Effects);
    cases.push(DifferentialCase {
        id: Arc::from("runtime-environment-get-env-missing"),
        source: Arc::from(failure_source),
        expected_runtime_completion: false,
        claim_evidence: Some(failure),
        ..DifferentialCase::default()
    });
    cases
}

fn runtime_environment_success_case(
    builtin: &str,
    id: &str,
    source: &str,
    stdout: &[u8],
    arguments: Vec<std::ffi::OsString>,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    for target in &mut descriptor.semantic_targets {
        if target.dimension == CompatibilityDimension::PureRuntime {
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        }
        if target.dimension == CompatibilityDimension::Effects {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "effect-failure");
        }
    }
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        arguments,
        environment,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_io_operation_cases() -> Vec<DifferentialCase> {
    let definitions = [
        (
            "IO.print",
            "print",
            "main = IO.print (42 :: Int)\n",
            b"42\n".as_slice(),
        ),
        (
            "IO.openFile",
            "open-file",
            concat!(
                "main = do\n",
                "  Text.writeFile \"opened.txt\" \"abc\"\n",
                "  handle <- IO.openFile \"opened.txt\" IO.ReadMode\n",
                "  bytes <- ByteString.hGet handle 3\n",
                "  IO.hClose handle\n",
                "  ByteString.hPutStr IO.stdout bytes\n",
            ),
            b"abc".as_slice(),
        ),
        (
            "IO.hClose",
            "close",
            concat!(
                "main = do\n",
                "  Text.writeFile \"closed.txt\" \"abc\"\n",
                "  handle <- IO.openFile \"closed.txt\" IO.ReadMode\n",
                "  IO.hClose handle\n",
                "  Text.putStr \"closed\"\n",
            ),
            b"closed".as_slice(),
        ),
    ];
    let mut cases = definitions
        .into_iter()
        .map(|(builtin, id, source, stdout)| {
            runtime_io_success_case(builtin, &format!("runtime-io-{id}-success"), source, stdout)
        })
        .collect::<Vec<_>>();
    let failure_source = concat!(
        "main = do\n",
        "  handle <- IO.openFile \"missing.txt\" IO.ReadMode\n",
        "  IO.pure ()\n",
    );
    cases.push(runtime_io_failure_case(
        "IO.openFile",
        "runtime-io-open-file-failure",
        failure_source,
    ));
    cases.extend(runtime_io_pure_cases());
    cases
}

#[derive(Clone, Copy)]
struct ShowInstanceDefinition {
    slug: &'static str,
    prelude: &'static str,
    expression: &'static str,
    rendered: &'static str,
    target: &'static str,
    premises: &'static [(&'static str, u8)],
    stdin: &'static [u8],
}

fn runtime_show_instance_cases() -> Vec<DifferentialCase> {
    show_instance_definitions()
        .into_iter()
        .flat_map(|definition| {
            ["Show.show", "IO.print"].map(|builtin| {
                let source = show_instance_source(builtin, definition);
                let descriptor = show_instance_descriptor(builtin, &source, definition);
                DifferentialCase {
                    id: Arc::from(format!(
                        "runtime-show-{}-{}",
                        builtin.replace('.', "-").to_ascii_lowercase(),
                        definition.slug
                    )),
                    source: Arc::from(source),
                    stdin: definition.stdin.to_vec(),
                    claim_evidence: Some(descriptor),
                    ..DifferentialCase::default()
                }
            })
        })
        .collect()
}

fn show_instance_source(builtin: &str, definition: ShowInstanceDefinition) -> String {
    let operation = if builtin == "Show.show" {
        format!("Text.putStrLn $ Show.show $ {}", definition.expression)
    } else {
        format!("IO.print $ {}", definition.expression)
    };
    if definition.stdin.is_empty() {
        format!("{}main = {operation}\n", definition.prelude)
    } else {
        format!(
            "{}main = do\n  value <- ByteString.hGet IO.stdin {}\n  {operation}\n",
            definition.prelude,
            definition.stdin.len(),
        )
    }
}

fn show_instance_descriptor(
    builtin: &str,
    source: &str,
    definition: ShowInstanceDefinition,
) -> ClaimEvidenceDescriptor {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    let stdout = format!("{}\n", definition.rendered);
    let typed_value = if builtin == "Show.show" {
        format!(
            "{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}",
            utf8_hex(definition.rendered)
        )
    } else {
        "{\"type\":\"IoAction\"}".to_owned()
    };
    let typed = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{typed_value}}}"
    );
    for target in &mut descriptor.semantic_targets {
        target.expected_instance_target = Some(Arc::from(definition.target));
        target.expected_instance_premises = definition
            .premises
            .iter()
            .map(|(target, premise_count)| crate::InstancePremiseEvidence {
                target: Arc::from(*target),
                premise_count: *premise_count,
            })
            .collect();
        target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
        if matches!(
            target.dimension,
            CompatibilityDimension::PureRuntime | CompatibilityDimension::Presentation
        ) {
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout.as_bytes(), b""));
        }
        if matches!(
            target.dimension,
            CompatibilityDimension::PureRuntime | CompatibilityDimension::Presentation
        ) {
            target.expected_typed_result_sha256 = Some(sha256_bytes(typed.as_bytes()));
        }
        if target.dimension == CompatibilityDimension::Presentation {
            if !target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == "normalized-shadow-diff")
            {
                target
                    .obligations
                    .push(ObligationId(Arc::from("normalized-shadow-diff")));
            }
            target.expected_presentation_shadow_normalizer =
                Some(PresentationShadowNormalizerId::LineEndingsV1);
            target.expected_normalized_presentation_sha256 = Some(
                crate::normalized_presentation_shadow_sha256(
                    PresentationShadowNormalizerId::LineEndingsV1,
                    stdout.as_bytes(),
                    b"",
                )
                .expect("reviewed Show presentation is UTF-8"),
            );
            if builtin == "IO.print" {
                target.expected_single_effect_lifecycle_sha256 =
                    Some(crate::single_effect_lifecycle_sha256([
                        "started",
                        "completed",
                    ]));
            }
        }
        if target.dimension == CompatibilityDimension::PureRuntime {
            target.obligations.retain(|obligation| {
                !matches!(
                    obligation.0.as_ref(),
                    "adapter-failure" | "whnf-failure-boundary"
                )
            });
        }
        if target.dimension == CompatibilityDimension::Effects {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "effect-failure");
            target.expected_single_effect_lifecycle_sha256 =
                Some(crate::single_effect_lifecycle_sha256([
                    "started",
                    "completed",
                ]));
        }
    }
    descriptor
}

const SHOW_DAY_PRELUDE: &str = concat!(
    "day = Maybe.maybe (Error.error \"day\") Function.id $ ",
    "Day.iso8601ParseM \"2025-08-10\"\n",
);
const SHOW_NO_PREMISES: &[(&str, u8)] = &[];
const SHOW_INT_PREMISE: &[(&str, u8)] = &[("Int", 0)];
const SHOW_TEXT_PREMISE: &[(&str, u8)] = &[("Text", 0)];

macro_rules! show_definition {
    ($slug:expr, $expression:expr, $rendered:expr, $target:expr, $premises:expr) => {
        ShowInstanceDefinition {
            slug: $slug,
            prelude: "",
            expression: $expression,
            rendered: $rendered,
            target: $target,
            premises: $premises,
            stdin: b"",
        }
    };
    ($slug:expr, prelude: $prelude:expr, $expression:expr, $rendered:expr, $target:expr, $premises:expr) => {
        ShowInstanceDefinition {
            slug: $slug,
            prelude: $prelude,
            expression: $expression,
            rendered: $rendered,
            target: $target,
            premises: $premises,
            stdin: b"",
        }
    };
    ($slug:expr, stdin: $stdin:expr, $expression:expr, $rendered:expr, $target:expr, $premises:expr) => {
        ShowInstanceDefinition {
            slug: $slug,
            prelude: "",
            expression: $expression,
            rendered: $rendered,
            target: $target,
            premises: $premises,
            stdin: $stdin,
        }
    };
}

fn show_instance_definitions() -> Vec<ShowInstanceDefinition> {
    let mut definitions = show_basic_instance_definitions();
    definitions.extend(show_double_instance_definitions());
    definitions.extend(show_scalar_instance_definitions());
    definitions.extend(show_json_instance_definitions());
    definitions.extend(show_parameterized_instance_definitions());
    definitions.extend(show_collection_instance_definitions());
    definitions
}

fn show_basic_instance_definitions() -> Vec<ShowInstanceDefinition> {
    vec![
        show_definition!("bool", "Bool.True", "True", "Bool", SHOW_NO_PREMISES),
        show_definition!(
            "bool-false",
            "Bool.False",
            "False",
            "Bool",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "builder",
            "Builder.byteString $ Text.encodeUtf8 \"aβ\"",
            r#""a\206\178""#,
            "Builder",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "builder-arbitrary-bytes",
            stdin: &[0xff, 0x41, 0xfe, 0x42],
            "Builder.byteString value",
            r#""\255A\254B""#,
            "Builder",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "byte-string",
            "Text.encodeUtf8 \"aβ\"",
            r#""a\206\178""#,
            "ByteString",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "byte-string-arbitrary-bytes",
            stdin: &[0xff, 0x41, 0xfe, 0x42],
            "value",
            r#""\255A\254B""#,
            "ByteString",
            SHOW_NO_PREMISES
        ),
        show_definition!("char", "'β'", "'\\946'", "Char", SHOW_NO_PREMISES),
        show_definition!("char-quote", r"'\''", r"'\''", "Char", SHOW_NO_PREMISES),
        show_definition!("char-backslash", r"'\\'", r"'\\'", "Char", SHOW_NO_PREMISES),
        show_definition!("char-control", r"'\n'", r"'\n'", "Char", SHOW_NO_PREMISES),
        show_definition!("day", prelude: SHOW_DAY_PRELUDE, "Main.day", "2025-08-10", "Day", SHOW_NO_PREMISES),
        show_definition!("day-of-week", prelude: SHOW_DAY_PRELUDE, "Day.dayOfWeek Main.day", "Sunday", "DayOfWeek", SHOW_NO_PREMISES),
    ]
}

fn show_double_instance_definitions() -> Vec<ShowInstanceDefinition> {
    vec![
        show_definition!("double-finite", "1.25", "1.25", "Double", SHOW_NO_PREMISES),
        show_definition!("double-zero", "0.0", "0.0", "Double", SHOW_NO_PREMISES),
        show_definition!(
            "double-negative-zero",
            prelude: concat!(
                "negativeZero = Maybe.maybe (Error.error \"negative zero\") Function.id $ ",
                "Double.readMaybe \"-0.0\"\n",
            ),
            "Main.negativeZero", "-0.0", "Double", SHOW_NO_PREMISES
        ),
        show_definition!(
            "double-exponential",
            "1.7976931348623157e308",
            "1.7976931348623157e308",
            "Double",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "double-infinity",
            "Double.plus 1.7976931348623157e308 1.7976931348623157e308",
            "Infinity",
            "Double",
            SHOW_NO_PREMISES
        ),
        show_definition!("double-negative-infinity", prelude: "infinity = Double.plus 1.7976931348623157e308 1.7976931348623157e308\n", "Double.mult (Double.fromInt $ Int.subtract 1 0) Main.infinity", "-Infinity", "Double", SHOW_NO_PREMISES),
        show_definition!("double-nan", prelude: "infinity = Double.plus 1.7976931348623157e308 1.7976931348623157e308\n", "Double.subtract Main.infinity Main.infinity", "NaN", "Double", SHOW_NO_PREMISES),
    ]
}

fn show_scalar_instance_definitions() -> Vec<ShowInstanceDefinition> {
    vec![
        show_definition!(
            "exit-code",
            "Exit.ExitFailure 23",
            "ExitFailure 23",
            "ExitCode",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "exit-code-success",
            "Exit.ExitSuccess",
            "ExitSuccess",
            "ExitCode",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "int",
            "(Int.subtract 42 0 :: Int)",
            "-42",
            "Int",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "integer",
            "(Int.toInteger 42 :: Integer)",
            "42",
            "Integer",
            SHOW_NO_PREMISES
        ),
        show_definition!("text", "\"aβ\"", "\"a\\946\"", "Text", SHOW_NO_PREMISES),
        show_definition!(
            "text-escaping",
            r#""\"\\\n\t""#,
            r#""\"\\\n\t""#,
            "Text",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "time-of-day",
            "TimeOfDay.midday",
            "12:00:00",
            "TimeOfDay",
            SHOW_NO_PREMISES
        ),
        show_definition!("utc-time", prelude: SHOW_DAY_PRELUDE, "UTCTime.UTCTime Main.day 1.5", "2025-08-10 00:00:01.5 UTC", "UTCTime", SHOW_NO_PREMISES),
    ]
}

fn show_json_instance_definitions() -> Vec<ShowInstanceDefinition> {
    vec![
        show_definition!(
            "value-string",
            "Json.String \"aβ\"",
            "String \"a\\946\"",
            "Value",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "value-string-escaping",
            r#"Json.String "\"\\\n\t""#,
            r#"String "\"\\\n\t""#,
            "Value",
            SHOW_NO_PREMISES
        ),
        show_definition!("value-null", "Json.Null", "Null", "Value", SHOW_NO_PREMISES),
        show_definition!(
            "value-bool",
            "Json.Bool Bool.True",
            "Bool True",
            "Value",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "value-number",
            "Json.Number 1.5",
            "Number 1.5",
            "Value",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "value-array",
            "Json.Array $ Vector.fromList [Json.Null]",
            "Array [Null]",
            "Value",
            SHOW_NO_PREMISES
        ),
        show_definition!(
            "value-object",
            "Json.Object $ Map.fromList [(\"a\", Json.Null)]",
            "Object (fromList [(\"a\",Null)])",
            "Value",
            SHOW_NO_PREMISES
        ),
    ]
}

fn show_parameterized_instance_definitions() -> Vec<ShowInstanceDefinition> {
    vec![
        show_definition!(
            "tuple",
            "((1, \"a\") :: (Int, Text))",
            "(1,\"a\")",
            "(,)",
            &[("Int", 0), ("Text", 0)]
        ),
        show_definition!("ci", "CI.mk \"AbC\"", "\"AbC\"", "CI", SHOW_TEXT_PREMISE),
        show_definition!(
            "either-left",
            "(Either.Left 1 :: Either Int Text)",
            "Left 1",
            "Either",
            &[("Int", 0), ("Text", 0)]
        ),
        show_definition!(
            "either-right",
            "(Either.Right \"a\" :: Either Int Text)",
            "Right \"a\"",
            "Either",
            &[("Int", 0), ("Text", 0)]
        ),
        show_definition!(
            "maybe-nothing",
            "(Maybe.Nothing :: Maybe Int)",
            "Nothing",
            "Maybe",
            SHOW_INT_PREMISE
        ),
        show_definition!(
            "maybe-just",
            "(Maybe.Just 1 :: Maybe Int)",
            "Just 1",
            "Maybe",
            SHOW_INT_PREMISE
        ),
    ]
}

fn show_collection_instance_definitions() -> Vec<ShowInstanceDefinition> {
    vec![
        show_definition!(
            "set-empty",
            "Set.fromList ([] :: [Int])",
            "fromList []",
            "Set",
            SHOW_INT_PREMISE
        ),
        show_definition!(
            "set-nonempty",
            "Set.fromList [2,1]",
            "fromList [1,2]",
            "Set",
            SHOW_INT_PREMISE
        ),
        show_definition!(
            "tree-leaf",
            "(Tree.Node 1 [] :: Tree Int)",
            "Node {rootLabel = 1, subForest = []}",
            "Tree",
            SHOW_INT_PREMISE
        ),
        show_definition!(
            "tree-branch",
            "(Tree.Node 1 [Tree.Node 2 []] :: Tree Int)",
            "Node {rootLabel = 1, subForest = [Node {rootLabel = 2, subForest = []}]}",
            "Tree",
            SHOW_INT_PREMISE
        ),
        show_definition!(
            "vector-empty",
            "Vector.fromList ([] :: [Int])",
            "[]",
            "Vector",
            SHOW_INT_PREMISE
        ),
        show_definition!(
            "vector-nonempty",
            "Vector.fromList [1,2]",
            "[1,2]",
            "Vector",
            SHOW_INT_PREMISE
        ),
        show_definition!("list-empty", "([] :: [Int])", "[]", "[]", SHOW_INT_PREMISE),
        show_definition!(
            "list-nonempty",
            "([1,2] :: [Int])",
            "[1,2]",
            "[]",
            SHOW_INT_PREMISE
        ),
    ]
}

#[derive(Clone, Copy)]
struct EqInstanceDefinition {
    slug: &'static str,
    prelude: &'static str,
    target: &'static str,
    premises: &'static [(&'static str, u8)],
    equal: (&'static str, &'static str),
    unequal: (&'static str, &'static str),
}

const EQ_NO_PREMISES: &[(&str, u8)] = &[];
const EQ_INT_PREMISE: &[(&str, u8)] = &[("Int", 0)];
const EQ_TEXT_PREMISE: &[(&str, u8)] = &[("Text", 0)];

macro_rules! eq_definition {
    ($slug:expr, $target:expr, $premises:expr, $equal:expr, $unequal:expr) => {
        EqInstanceDefinition {
            slug: $slug,
            prelude: "",
            target: $target,
            premises: $premises,
            equal: $equal,
            unequal: $unequal,
        }
    };
    ($slug:expr, prelude: $prelude:expr, $target:expr, $premises:expr, $equal:expr, $unequal:expr) => {
        EqInstanceDefinition {
            slug: $slug,
            prelude: $prelude,
            target: $target,
            premises: $premises,
            equal: $equal,
            unequal: $unequal,
        }
    };
}

fn runtime_eq_instance_cases() -> Vec<DifferentialCase> {
    let mut cases = eq_instance_definitions()
        .into_iter()
        .flat_map(|definition| {
            [
                runtime_eq_instance_case(definition, "equal", definition.equal, true),
                runtime_eq_instance_case(definition, "unequal", definition.unequal, false),
            ]
        })
        .collect::<Vec<_>>();
    cases.extend(runtime_eq_breadth_cases());
    cases.extend(runtime_eq_invalid_byte_cases());
    cases
}

fn runtime_eq_instance_case(
    definition: EqInstanceDefinition,
    path: &str,
    (left, right): (&str, &str),
    result: bool,
) -> DifferentialCase {
    let source = format!(
        "{}main = IO.print $ Eq.eq ({left}) ({right})\n",
        definition.prelude
    );
    runtime_eq_case(
        format!("runtime-typed-eq-{}-{path}", definition.slug),
        definition.target,
        definition.premises,
        source,
        Vec::new(),
        result,
    )
}

fn runtime_eq_case(
    id: String,
    instance: &str,
    premises: &[(&str, u8)],
    source: String,
    stdin: Vec<u8>,
    result: bool,
) -> DifferentialCase {
    let mut descriptor = runtime_single_typed_target_descriptor("Eq.eq", &source);
    let target = &mut descriptor.semantic_targets[0];
    target.expected_instance_target = Some(Arc::from(instance));
    target.expected_instance_premises = premises
        .iter()
        .map(|(target, premise_count)| crate::InstancePremiseEvidence {
            target: Arc::from(*target),
            premise_count: *premise_count,
        })
        .collect();
    let rendered: &[u8] = if result { b"True\n" } else { b"False\n" };
    target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(rendered, b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Bool\",\"value\":{result}}}}}"
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        stdin,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn eq_instance_definitions() -> Vec<EqInstanceDefinition> {
    let mut definitions = eq_scalar_definitions();
    definitions.extend(eq_time_definitions());
    definitions.extend(eq_sum_product_definitions());
    definitions.extend(eq_collection_definitions());
    definitions
}

fn eq_scalar_definitions() -> Vec<EqInstanceDefinition> {
    vec![
        eq_definition!(
            "bool",
            "Bool",
            EQ_NO_PREMISES,
            ("Bool.True", "Bool.True"),
            ("Bool.True", "Bool.False")
        ),
        eq_definition!(
            "byte-string",
            "ByteString",
            EQ_NO_PREMISES,
            ("Text.encodeUtf8 \"aβ\"", "Text.encodeUtf8 \"aβ\""),
            ("Text.encodeUtf8 \"aβ\"", "Text.encodeUtf8 \"ab\"")
        ),
        eq_definition!(
            "ci",
            "CI",
            EQ_TEXT_PREMISE,
            ("CI.mk \"AbC\"", "CI.mk \"aBc\""),
            ("CI.mk \"AbC\"", "CI.mk \"abd\"")
        ),
        eq_definition!(
            "char",
            "Char",
            EQ_NO_PREMISES,
            ("'β'", "'β'"),
            ("'β'", "'a'")
        ),
        eq_definition!(
            "double",
            "Double",
            EQ_NO_PREMISES,
            ("1.25", "1.25"),
            ("1.25", "1.5")
        ),
        eq_definition!(
            "exit-code",
            "ExitCode",
            EQ_NO_PREMISES,
            ("Exit.ExitFailure 23", "Exit.ExitFailure 23"),
            ("Exit.ExitSuccess", "Exit.ExitFailure 23")
        ),
        eq_definition!(
            "int",
            "Int",
            EQ_NO_PREMISES,
            ("(42 :: Int)", "(42 :: Int)"),
            ("(42 :: Int)", "(41 :: Int)")
        ),
        eq_definition!(
            "integer",
            "Integer",
            EQ_NO_PREMISES,
            ("Int.toInteger 42", "Int.toInteger 42"),
            ("Int.toInteger 42", "Int.toInteger 41")
        ),
        eq_definition!(
            "text",
            "Text",
            EQ_NO_PREMISES,
            ("\"aβ\"", "\"aβ\""),
            ("\"aβ\"", "\"ab\"")
        ),
    ]
}

fn eq_time_definitions() -> Vec<EqInstanceDefinition> {
    const DAYS: &str = concat!(
        "day1 = Maybe.maybe (Error.error \"day1\") Function.id $ Day.iso8601ParseM \"2025-08-11\"\n",
        "day2 = Maybe.maybe (Error.error \"day2\") Function.id $ Day.iso8601ParseM \"2025-08-12\"\n",
    );
    vec![
        eq_definition!("day", prelude: DAYS, "Day", EQ_NO_PREMISES, ("Main.day1", "Main.day1"), ("Main.day1", "Main.day2")),
        eq_definition!("day-of-week", prelude: DAYS, "DayOfWeek", EQ_NO_PREMISES, ("Day.dayOfWeek Main.day1", "Day.dayOfWeek Main.day1"), ("Day.dayOfWeek Main.day1", "Day.dayOfWeek Main.day2")),
        eq_definition!(
            "time-of-day",
            "TimeOfDay",
            EQ_NO_PREMISES,
            ("TimeOfDay.midday", "TimeOfDay.midday"),
            ("TimeOfDay.midday", "TimeOfDay.midnight")
        ),
        eq_definition!("utc-time", prelude: DAYS, "UTCTime", EQ_NO_PREMISES, ("UTCTime.UTCTime Main.day1 1.5", "UTCTime.UTCTime Main.day1 1.5"), ("UTCTime.UTCTime Main.day1 1.5", "UTCTime.UTCTime Main.day1 2.5")),
    ]
}

fn eq_sum_product_definitions() -> Vec<EqInstanceDefinition> {
    vec![
        eq_definition!(
            "tuple",
            "(,)",
            &[("Int", 0), ("Text", 0)],
            ("((1, \"a\") :: (Int, Text))", "((1, \"a\") :: (Int, Text))"),
            ("((1, \"a\") :: (Int, Text))", "((1, \"b\") :: (Int, Text))")
        ),
        eq_definition!(
            "either",
            "Either",
            &[("Text", 0), ("Int", 0)],
            (
                "(Either.Right 1 :: Either Text Int)",
                "(Either.Right 1 :: Either Text Int)"
            ),
            (
                "(Either.Left \"left\" :: Either Text Int)",
                "(Either.Right 1 :: Either Text Int)"
            )
        ),
        eq_definition!(
            "maybe",
            "Maybe",
            EQ_INT_PREMISE,
            ("(Maybe.Just 1 :: Maybe Int)", "(Maybe.Just 1 :: Maybe Int)"),
            (
                "(Maybe.Nothing :: Maybe Int)",
                "(Maybe.Just 1 :: Maybe Int)"
            )
        ),
    ]
}

fn eq_collection_definitions() -> Vec<EqInstanceDefinition> {
    vec![
        eq_definition!(
            "set",
            "Set",
            EQ_INT_PREMISE,
            ("Set.fromList [2,1]", "Set.fromList [1,2]"),
            ("Set.fromList [1]", "Set.fromList [1,2]")
        ),
        eq_definition!(
            "tree",
            "Tree",
            EQ_INT_PREMISE,
            (
                "(Tree.Node 1 [Tree.Node 2 []] :: Tree Int)",
                "(Tree.Node 1 [Tree.Node 2 []] :: Tree Int)"
            ),
            (
                "(Tree.Node 1 [] :: Tree Int)",
                "(Tree.Node 1 [Tree.Node 2 []] :: Tree Int)"
            )
        ),
        eq_definition!(
            "vector",
            "Vector",
            EQ_INT_PREMISE,
            ("Vector.fromList [1,2]", "Vector.fromList [1,2]"),
            ("Vector.fromList [1]", "Vector.fromList [1,2]")
        ),
        eq_definition!(
            "list",
            "[]",
            EQ_INT_PREMISE,
            ("([1,2] :: [Int])", "([1,2] :: [Int])"),
            ("([1] :: [Int])", "([1,2] :: [Int])")
        ),
    ]
}

fn runtime_eq_breadth_cases() -> Vec<DifferentialCase> {
    let mut cases = runtime_eq_numeric_breadth_cases();
    cases.extend(runtime_eq_sum_product_breadth_cases());
    cases.extend(runtime_eq_collection_breadth_cases());
    cases
}

fn runtime_eq_numeric_breadth_cases() -> Vec<DifferentialCase> {
    const NAN: &str = concat!(
        "infinity = Double.plus 1.7976931348623157e308 1.7976931348623157e308\n",
        "nan = Double.subtract Main.infinity Main.infinity\n",
    );
    const NEGATIVE_ZERO: &str = concat!(
        "negativeZero = Maybe.maybe (Error.error \"negative zero\") Function.id $ ",
        "Double.readMaybe \"-0.0\"\n",
    );
    vec![
        runtime_eq_instance_case(
            EqInstanceDefinition {
                prelude: NEGATIVE_ZERO,
                ..eq_definition_by_slug("double")
            },
            "signed-zero",
            ("0.0", "Main.negativeZero"),
            true,
        ),
        runtime_eq_instance_case(
            EqInstanceDefinition {
                prelude: NAN,
                ..eq_definition_by_slug("double")
            },
            "nan",
            ("Main.nan", "Main.nan"),
            false,
        ),
        runtime_eq_breadth_case(
            "exit-code",
            "failure-code",
            "Exit.ExitFailure 23",
            "Exit.ExitFailure 24",
            false,
        ),
    ]
}

fn runtime_eq_sum_product_breadth_cases() -> Vec<DifferentialCase> {
    vec![
        runtime_eq_breadth_case(
            "tuple",
            "first-field",
            "((1, \"same\") :: (Int, Text))",
            "((2, \"same\") :: (Int, Text))",
            false,
        ),
        runtime_eq_breadth_case(
            "tuple",
            "early-mismatch",
            "((1, Error.error \"tuple left tail\" :: Text) :: (Int, Text))",
            "((2, Error.error \"tuple right tail\" :: Text) :: (Int, Text))",
            false,
        ),
        runtime_eq_breadth_case(
            "either",
            "payload",
            "(Either.Right 1 :: Either Text Int)",
            "(Either.Right 2 :: Either Text Int)",
            false,
        ),
        runtime_eq_breadth_case(
            "either",
            "left-equal",
            "(Either.Left \"left\" :: Either Text Int)",
            "(Either.Left \"left\" :: Either Text Int)",
            true,
        ),
        runtime_eq_breadth_case(
            "either",
            "left-payload",
            "(Either.Left \"left\" :: Either Text Int)",
            "(Either.Left \"other\" :: Either Text Int)",
            false,
        ),
        runtime_eq_breadth_case(
            "either",
            "early-mismatch",
            "(Either.Left (Error.error \"left payload\" :: Text) :: Either Text Int)",
            "(Either.Right (Error.error \"right payload\" :: Int) :: Either Text Int)",
            false,
        ),
        runtime_eq_breadth_case(
            "maybe",
            "payload",
            "(Maybe.Just 1 :: Maybe Int)",
            "(Maybe.Just 2 :: Maybe Int)",
            false,
        ),
        runtime_eq_breadth_case(
            "maybe",
            "early-mismatch",
            "(Maybe.Nothing :: Maybe Int)",
            "(Maybe.Just (Error.error \"maybe payload\" :: Int) :: Maybe Int)",
            false,
        ),
        runtime_eq_breadth_case(
            "maybe",
            "nothing-equal",
            "(Maybe.Nothing :: Maybe Int)",
            "(Maybe.Nothing :: Maybe Int)",
            true,
        ),
    ]
}

fn runtime_eq_collection_breadth_cases() -> Vec<DifferentialCase> {
    vec![
        runtime_eq_breadth_case(
            "set",
            "empty",
            "Set.fromList ([] :: [Int])",
            "Set.fromList ([] :: [Int])",
            true,
        ),
        runtime_eq_breadth_case(
            "set",
            "element",
            "Set.fromList [1,2]",
            "Set.fromList [1,3]",
            false,
        ),
        runtime_eq_breadth_case(
            "vector",
            "empty",
            "Vector.fromList ([] :: [Int])",
            "Vector.fromList ([] :: [Int])",
            true,
        ),
        runtime_eq_breadth_case(
            "tree",
            "child",
            "(Tree.Node 1 [Tree.Node 2 []] :: Tree Int)",
            "(Tree.Node 1 [Tree.Node 3 []] :: Tree Int)",
            false,
        ),
        runtime_eq_breadth_case("list", "empty", "([] :: [Int])", "([] :: [Int])", true),
        runtime_eq_breadth_case(
            "tree",
            "early-mismatch",
            "(Tree.Node 1 [Error.error \"tree left child\" :: Tree Int] :: Tree Int)",
            "(Tree.Node 2 [Error.error \"tree right child\" :: Tree Int] :: Tree Int)",
            false,
        ),
        runtime_eq_breadth_case(
            "vector",
            "element",
            "Vector.fromList [1,2]",
            "Vector.fromList [1,3]",
            false,
        ),
        runtime_eq_breadth_case(
            "vector",
            "early-mismatch",
            "Vector.fromList [1, Error.error \"vector left tail\" :: Int]",
            "Vector.fromList [2, Error.error \"vector right tail\" :: Int]",
            false,
        ),
        runtime_eq_breadth_case(
            "list",
            "element",
            "([1,2] :: [Int])",
            "([1,3] :: [Int])",
            false,
        ),
        runtime_eq_breadth_case(
            "list",
            "early-mismatch",
            "([1, Error.error \"list left tail\" :: Int] :: [Int])",
            "([2, Error.error \"list right tail\" :: Int] :: [Int])",
            false,
        ),
    ]
}

fn runtime_eq_breadth_case(
    slug: &str,
    path: &str,
    left: &'static str,
    right: &'static str,
    result: bool,
) -> DifferentialCase {
    runtime_eq_instance_case(eq_definition_by_slug(slug), path, (left, right), result)
}

fn eq_definition_by_slug(slug: &str) -> EqInstanceDefinition {
    eq_instance_definitions()
        .into_iter()
        .find(|definition| definition.slug == slug)
        .unwrap_or_else(|| panic!("missing Eq instance definition {slug}"))
}

fn runtime_eq_invalid_byte_cases() -> Vec<DifferentialCase> {
    [
        (
            "equal",
            concat!(
                "main = do\n",
                "  left <- ByteString.hGet IO.stdin 2\n",
                "  right <- ByteString.hGet IO.stdin 2\n",
                "  IO.print $ Eq.eq left right\n",
            ),
            vec![0xff, 0x41, 0xff, 0x41],
            true,
        ),
        (
            "unequal",
            concat!(
                "main = do\n",
                "  left <- ByteString.hGet IO.stdin 2\n",
                "  right <- ByteString.hGet IO.stdin 2\n",
                "  IO.print $ Eq.eq left right\n",
            ),
            vec![0xff, 0x41, 0xff, 0x42],
            false,
        ),
    ]
    .into_iter()
    .map(|(path, source, stdin, result)| {
        runtime_eq_case(
            format!("runtime-typed-eq-byte-string-invalid-{path}"),
            "ByteString",
            EQ_NO_PREMISES,
            source.to_owned(),
            stdin,
            result,
        )
    })
    .collect()
}

#[derive(Clone, Copy)]
struct OrdInstanceDefinition {
    slug: &'static str,
    prelude: &'static str,
    target: &'static str,
    premises: &'static [(&'static str, u8)],
    lower: &'static str,
    equal: (&'static str, &'static str),
    upper: &'static str,
}

macro_rules! ord_definition {
    ($slug:expr, $target:expr, $premises:expr, $lower:expr, $equal:expr, $upper:expr) => {
        OrdInstanceDefinition {
            slug: $slug,
            prelude: "",
            target: $target,
            premises: $premises,
            lower: $lower,
            equal: $equal,
            upper: $upper,
        }
    };
    ($slug:expr, prelude: $prelude:expr, $target:expr, $premises:expr, $lower:expr, $equal:expr, $upper:expr) => {
        OrdInstanceDefinition {
            slug: $slug,
            prelude: $prelude,
            target: $target,
            premises: $premises,
            lower: $lower,
            equal: $equal,
            upper: $upper,
        }
    };
}

fn runtime_ord_instance_cases() -> Vec<DifferentialCase> {
    let mut cases = Vec::new();
    for definition in ord_instance_definitions() {
        for (builtin, lower, upper) in [
            ("Ord.lt", definition.lower, definition.upper),
            ("Ord.gt", definition.upper, definition.lower),
        ] {
            cases.push(runtime_ord_case(
                definition,
                builtin,
                "ordered",
                lower,
                upper,
                Vec::new(),
                true,
            ));
            cases.push(runtime_ord_case(
                definition,
                builtin,
                "reverse",
                upper,
                lower,
                Vec::new(),
                false,
            ));
            cases.push(runtime_ord_case(
                definition,
                builtin,
                "equal",
                definition.equal.0,
                definition.equal.1,
                Vec::new(),
                false,
            ));
        }
    }
    cases.extend(runtime_ord_breadth_cases());
    cases.extend(runtime_ord_invalid_byte_cases());
    cases
}

fn runtime_ord_case(
    definition: OrdInstanceDefinition,
    builtin: &str,
    path: &str,
    left: &str,
    right: &str,
    stdin: Vec<u8>,
    result: bool,
) -> DifferentialCase {
    let builtin_slug = if builtin == "Ord.lt" { "lt" } else { "gt" };
    let source = format!(
        "{}main = IO.print $ {builtin} ({left}) ({right})\n",
        definition.prelude
    );
    let mut descriptor = runtime_single_typed_target_descriptor(builtin, &source);
    let target = &mut descriptor.semantic_targets[0];
    target.expected_instance_target = Some(Arc::from(definition.target));
    target.expected_instance_premises = definition
        .premises
        .iter()
        .map(|(target, premise_count)| crate::InstancePremiseEvidence {
            target: Arc::from(*target),
            premise_count: *premise_count,
        })
        .collect();
    let rendered: &[u8] = if result { b"True\n" } else { b"False\n" };
    target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(rendered, b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Bool\",\"value\":{result}}}}}"
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-typed-ord-{builtin_slug}-{}-{path}",
            definition.slug
        )),
        source: Arc::from(source),
        stdin,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn ord_set_boundary_comparator_contracts(
    definition: &OrdListDefinition,
    builtin: &str,
    boundary: OrdSetBoundary,
) -> Vec<ComparatorTraceContract> {
    let lower = definition.lower.canonical.as_str();
    let upper = definition.upper.canonical.as_str();
    let retained_tree_lower = (definition.slug == "tree"
        && matches!(builtin, "Set.member" | "Set.intersection"))
    .then(ord_set_retained_tree_lower);
    let retained_list_lower = (definition.slug == "list"
        && matches!(builtin, "Set.member" | "Set.intersection"))
    .then(ord_set_retained_list_lower);
    let lower = retained_tree_lower
        .as_deref()
        .or(retained_list_lower.as_deref())
        .unwrap_or(lower);
    match (builtin, boundary) {
        ("Set.fromList", OrdSetBoundary::Finite) => vec![
            reviewed_comparator_contract(1, "Ord.gt", upper, lower, true),
            reviewed_comparator_contract(2, "Ord.lt", lower, upper, true),
        ],
        (
            "Set.insert" | "Set.member" | "Set.delete" | "Set.union" | "Set.difference",
            OrdSetBoundary::Finite,
        )
        | ("Set.insert", OrdSetBoundary::Singleton) => vec![
            reviewed_comparator_contract(1, "Ord.lt", upper, lower, false),
            reviewed_comparator_contract(2, "Ord.gt", upper, lower, true),
        ],
        ("Set.intersection", OrdSetBoundary::Finite) => vec![reviewed_comparator_contract(
            1, "Ord.lt", lower, upper, true,
        )],
        _ => Vec::new(),
    }
}

fn ord_set_retained_tree_lower() -> String {
    concat!(
        "{\"type\":\"Tree\",\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},",
        "{\"type\":\"List\",\"elements\":[{\"type\":\"Tree\",\"elements\":[",
        "{\"type\":\"Int\",\"value\":\"2\"},{\"type\":\"ForceBoundary\",",
        "\"outcome\":\"not-forced\"}]}],\"terminationHex\":\"6e6f742d666f72636564\"}]}"
    )
    .to_owned()
}

fn ord_set_retained_list_lower() -> String {
    concat!(
        "{\"type\":\"List\",\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},",
        "{\"type\":\"Int\",\"value\":\"2\"}],",
        "\"terminationHex\":\"6e6f742d666f72636564\"}"
    )
    .to_owned()
}

pub(crate) fn reviewed_comparator_contract(
    ordinal: u64,
    comparator: &str,
    canonical_left: &str,
    canonical_right: &str,
    result: bool,
) -> ComparatorTraceContract {
    ComparatorTraceContract {
        parent_invocation: 1,
        direct_child_ordinal: ordinal,
        comparator_ordinal: ordinal,
        comparator: Arc::from(comparator),
        canonical_left: Arc::from(canonical_left),
        canonical_right: Arc::from(canonical_right),
        result,
        outcome: Arc::from("value"),
    }
}

const ORD_DAYS: &str = concat!(
    "day1 = Maybe.maybe (Error.error \"day1\") Function.id $ Day.iso8601ParseM \"2025-08-11\"\n",
    "day2 = Maybe.maybe (Error.error \"day2\") Function.id $ Day.iso8601ParseM \"2025-08-12\"\n",
);

fn ord_instance_definitions() -> Vec<OrdInstanceDefinition> {
    let mut definitions = ord_primitive_instance_definitions();
    definitions.extend(ord_composite_instance_definitions());
    definitions
}

fn ord_primitive_instance_definitions() -> Vec<OrdInstanceDefinition> {
    vec![
        ord_definition!(
            "bool",
            "Bool",
            EQ_NO_PREMISES,
            "Bool.False",
            ("Bool.True", "Bool.True"),
            "Bool.True"
        ),
        ord_definition!(
            "byte-string",
            "ByteString",
            EQ_NO_PREMISES,
            "Text.encodeUtf8 \"a\"",
            ("Text.encodeUtf8 \"aβ\"", "Text.encodeUtf8 \"aβ\""),
            "Text.encodeUtf8 \"b\""
        ),
        ord_definition!(
            "ci",
            "CI",
            EQ_TEXT_PREMISE,
            "CI.mk \"AbC\"",
            ("CI.mk \"AbC\"", "CI.mk \"aBc\""),
            "CI.mk \"aBd\""
        ),
        ord_definition!("char", "Char", EQ_NO_PREMISES, "'a'", ("'β'", "'β'"), "'β'"),
        ord_definition!("day", prelude: ORD_DAYS, "Day", EQ_NO_PREMISES, "Main.day1", ("Main.day1", "Main.day1"), "Main.day2"),
        ord_definition!("day-of-week", prelude: ORD_DAYS, "DayOfWeek", EQ_NO_PREMISES, "Day.dayOfWeek Main.day1", ("Day.dayOfWeek Main.day1", "Day.dayOfWeek Main.day1"), "Day.dayOfWeek Main.day2"),
        ord_definition!(
            "double",
            "Double",
            EQ_NO_PREMISES,
            "1.25",
            ("1.5", "1.5"),
            "1.75"
        ),
        ord_definition!(
            "either",
            "Either",
            &[("Text", 0), ("Int", 0)],
            "(Either.Left \"a\" :: Either Text Int)",
            (
                "(Either.Right 1 :: Either Text Int)",
                "(Either.Right 1 :: Either Text Int)"
            ),
            "(Either.Left \"b\" :: Either Text Int)"
        ),
        ord_definition!(
            "exit-code",
            "ExitCode",
            EQ_NO_PREMISES,
            "Exit.ExitSuccess",
            ("Exit.ExitFailure 23", "Exit.ExitFailure 23"),
            "Exit.ExitFailure 24"
        ),
        ord_definition!(
            "int",
            "Int",
            EQ_NO_PREMISES,
            "(1 :: Int)",
            ("(2 :: Int)", "(2 :: Int)"),
            "(3 :: Int)"
        ),
        ord_definition!(
            "integer",
            "Integer",
            EQ_NO_PREMISES,
            "Int.toInteger 1",
            ("Int.toInteger 2", "Int.toInteger 2"),
            "Int.toInteger 3"
        ),
    ]
}

fn ord_composite_instance_definitions() -> Vec<OrdInstanceDefinition> {
    vec![
        ord_definition!(
            "maybe",
            "Maybe",
            EQ_INT_PREMISE,
            "(Maybe.Nothing :: Maybe Int)",
            ("(Maybe.Just 1 :: Maybe Int)", "(Maybe.Just 1 :: Maybe Int)"),
            "(Maybe.Just 0 :: Maybe Int)"
        ),
        ord_definition!(
            "set",
            "Set",
            EQ_INT_PREMISE,
            "Set.fromList [1,2]",
            ("Set.fromList [2,1]", "Set.fromList [1,2]"),
            "Set.fromList [1,3]"
        ),
        ord_definition!(
            "text",
            "Text",
            EQ_NO_PREMISES,
            "\"a\"",
            ("\"aβ\"", "\"aβ\""),
            "\"b\""
        ),
        ord_definition!(
            "time-of-day",
            "TimeOfDay",
            EQ_NO_PREMISES,
            "TimeOfDay.midnight",
            ("TimeOfDay.midday", "TimeOfDay.midday"),
            "TimeOfDay.midday"
        ),
        ord_definition!(
            "tree",
            "Tree",
            EQ_INT_PREMISE,
            "(Tree.Node 1 [Tree.Node 2 []] :: Tree Int)",
            (
                "(Tree.Node 1 [Tree.Node 2 []] :: Tree Int)",
                "(Tree.Node 1 [Tree.Node 2 []] :: Tree Int)"
            ),
            "(Tree.Node 1 [Tree.Node 3 []] :: Tree Int)"
        ),
        ord_definition!(
            "tuple",
            "(,)",
            &[("Int", 0), ("Text", 0)],
            "((1, \"a\") :: (Int, Text))",
            ("((1, \"b\") :: (Int, Text))", "((1, \"b\") :: (Int, Text))"),
            "((1, \"c\") :: (Int, Text))"
        ),
        ord_definition!("utc-time", prelude: ORD_DAYS, "UTCTime", EQ_NO_PREMISES, "UTCTime.UTCTime Main.day1 1.5", ("UTCTime.UTCTime Main.day1 2.5", "UTCTime.UTCTime Main.day1 2.5"), "UTCTime.UTCTime Main.day2 1.5"),
        ord_definition!(
            "vector",
            "Vector",
            EQ_INT_PREMISE,
            "Vector.fromList [1,2]",
            ("Vector.fromList [1,2]", "Vector.fromList [1,2]"),
            "Vector.fromList [1,3]"
        ),
        ord_definition!(
            "list",
            "[]",
            EQ_INT_PREMISE,
            "([1,2] :: [Int])",
            ("([1,2] :: [Int])", "([1,2] :: [Int])"),
            "([1,3] :: [Int])"
        ),
    ]
}

fn ord_definition_by_slug(slug: &str) -> OrdInstanceDefinition {
    ord_instance_definitions()
        .into_iter()
        .find(|definition| definition.slug == slug)
        .unwrap_or_else(|| panic!("missing Ord instance definition {slug}"))
}

fn runtime_ord_breadth_cases() -> Vec<DifferentialCase> {
    let mut cases = Vec::new();
    for builtin in ["Ord.lt", "Ord.gt"] {
        cases.extend(runtime_ord_structural_breadth_cases(builtin));
        cases.extend(runtime_ord_double_breadth_cases(builtin));
    }
    cases
}

fn runtime_ord_structural_breadth_cases(builtin: &str) -> [DifferentialCase; 7] {
    [
        runtime_ord_ordered_breadth_case(
            builtin,
            "tuple",
            "first-field-bottom-tail",
            "((1, Error.error \"tuple lower tail\" :: Text) :: (Int, Text))",
            "((2, Error.error \"tuple upper tail\" :: Text) :: (Int, Text))",
        ),
        runtime_ord_ordered_breadth_case(
            builtin,
            "either",
            "constructor-bottom-payload",
            "(Either.Left (Error.error \"left payload\" :: Text) :: Either Text Int)",
            "(Either.Right (Error.error \"right payload\" :: Int) :: Either Text Int)",
        ),
        runtime_ord_ordered_breadth_case(
            builtin,
            "maybe",
            "payload",
            "(Maybe.Just 1 :: Maybe Int)",
            "(Maybe.Just 2 :: Maybe Int)",
        ),
        runtime_ord_ordered_breadth_case(
            builtin,
            "set",
            "prefix-length",
            "Set.fromList [1]",
            "Set.fromList [1,2]",
        ),
        runtime_ord_ordered_breadth_case(
            builtin,
            "tree",
            "root-bottom-children",
            "(Tree.Node 1 [Error.error \"tree lower child\" :: Tree Int] :: Tree Int)",
            "(Tree.Node 2 [Error.error \"tree upper child\" :: Tree Int] :: Tree Int)",
        ),
        runtime_ord_ordered_breadth_case(
            builtin,
            "vector",
            "prefix-bottom-tail",
            "Vector.fromList [1]",
            "Vector.fromList [1, Error.error \"vector upper tail\" :: Int]",
        ),
        runtime_ord_ordered_breadth_case(
            builtin,
            "list",
            "prefix-bottom-tail",
            "([1] :: [Int])",
            "([1, Error.error \"list upper tail\" :: Int] :: [Int])",
        ),
    ]
}

fn runtime_ord_ordered_breadth_case(
    builtin: &str,
    slug: &str,
    path: &str,
    lower: &'static str,
    upper: &'static str,
) -> DifferentialCase {
    let (left, right) = if builtin == "Ord.lt" {
        (lower, upper)
    } else {
        (upper, lower)
    };
    runtime_ord_case(
        ord_definition_by_slug(slug),
        builtin,
        path,
        left,
        right,
        Vec::new(),
        true,
    )
}

fn runtime_ord_double_breadth_cases(builtin: &str) -> [DifferentialCase; 3] {
    const NAN: &str = concat!(
        "infinity = Double.plus 1.7976931348623157e308 1.7976931348623157e308\n",
        "nan = Double.subtract Main.infinity Main.infinity\n",
    );
    const ZERO: &str = concat!(
        "negativeZero = Maybe.maybe (Error.error \"negative zero\") Function.id $ ",
        "Double.readMaybe \"-0.0\"\n",
    );
    let double = ord_definition_by_slug("double");
    let (finite, infinity) = if builtin == "Ord.lt" {
        ("1.7976931348623157e308", "Main.infinity")
    } else {
        ("Main.infinity", "1.7976931348623157e308")
    };
    [
        runtime_ord_case(
            OrdInstanceDefinition {
                prelude: NAN,
                ..double
            },
            builtin,
            "nan",
            "Main.nan",
            "Main.nan",
            Vec::new(),
            false,
        ),
        runtime_ord_case(
            OrdInstanceDefinition {
                prelude: ZERO,
                ..double
            },
            builtin,
            "signed-zero",
            "0.0",
            "Main.negativeZero",
            Vec::new(),
            false,
        ),
        runtime_ord_case(
            OrdInstanceDefinition {
                prelude: NAN,
                ..double
            },
            builtin,
            "infinity",
            finite,
            infinity,
            Vec::new(),
            true,
        ),
    ]
}

fn runtime_ord_invalid_byte_cases() -> Vec<DifferentialCase> {
    let mut cases = Vec::new();
    for builtin in ["Ord.lt", "Ord.gt"] {
        for (path, stdin, result) in [
            ("invalid-bytes", vec![0xff, b'A', 0xff, b'B'], true),
            ("invalid-equal", vec![0xff, b'A', 0xff, b'A'], false),
        ] {
            let source = format!(
                concat!(
                    "main = do\n",
                    "  lower <- ByteString.hGet IO.stdin 2\n",
                    "  upper <- ByteString.hGet IO.stdin 2\n",
                    "  IO.print $ {builtin} {left} {right}\n",
                ),
                builtin = builtin,
                left = if builtin == "Ord.lt" {
                    "lower"
                } else {
                    "upper"
                },
                right = if builtin == "Ord.lt" {
                    "upper"
                } else {
                    "lower"
                }
            );
            cases.push(runtime_ord_case(
                ord_definition_by_slug("byte-string"),
                builtin,
                path,
                "lower",
                "upper",
                stdin,
                result,
            ));
            let case = cases.last_mut().unwrap();
            case.source = Arc::from(source.clone());
            case.claim_evidence.as_mut().unwrap().source_sha256 = sha256_bytes(source.as_bytes());
        }
    }
    cases
}

#[derive(Clone)]
struct SingletonOrdDefinition {
    slug: &'static str,
    value: ShowInstanceDefinition,
    canonical: String,
}

fn runtime_singleton_constructor_cases() -> Vec<DifferentialCase> {
    let mut cases = singleton_ord_definitions()
        .into_iter()
        .flat_map(|definition| {
            [
                runtime_singleton_constructor_case("Map.singleton", &definition),
                runtime_singleton_constructor_case("Set.singleton", &definition),
            ]
        })
        .collect::<Vec<_>>();
    cases.extend(runtime_singleton_strictness_cases());
    cases
}

fn runtime_singleton_constructor_case(
    builtin: &'static str,
    definition: &SingletonOrdDefinition,
) -> DifferentialCase {
    let (source, stdout, typed_value) = if builtin == "Map.singleton" {
        let payload = format!("payload-{}", definition.slug);
        let source = format!(
            "{}main = IO.print $ Map.toList $ Map.singleton ({}) \"{payload}\"\n",
            definition.value.prelude, definition.value.expression
        );
        let stdout = format!("[({},\"{payload}\")]\n", definition.value.rendered);
        let typed_value = format!(
            "{{\"type\":\"Map\",\"entries\":[{{\"key\":{},\"value\":{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}}}]}}",
            definition.canonical,
            utf8_hex(&payload),
        );
        (source, stdout, typed_value)
    } else {
        let source = format!(
            "{}main = IO.print $ Set.singleton ({})\n",
            definition.value.prelude, definition.value.expression
        );
        let stdout = if definition.value.target == "Char" {
            "fromList \"\\946\"\n".to_owned()
        } else {
            format!("fromList [{}]\n", definition.value.rendered)
        };
        let typed_value = format!(
            "{{\"type\":\"Set\",\"elements\":[{}]}}",
            definition.canonical
        );
        (source, stdout, typed_value)
    };
    let mut descriptor = runtime_all_obligation_descriptor(builtin, &source);
    for target in &mut descriptor.semantic_targets {
        target.expected_instance_target = Some(Arc::from(definition.value.target));
        target.expected_instance_premises = definition
            .value
            .premises
            .iter()
            .map(|(target, premise_count)| crate::InstancePremiseEvidence {
                target: Arc::from(*target),
                premise_count: *premise_count,
            })
            .collect();
        target.expected_comparator_trace_sha256 = Some(crate::comparator_trace_sha256(
            builtin,
            1,
            definition.value.target,
            &target.expected_instance_premises,
            &[],
        ));
        target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
        if target.dimension == CompatibilityDimension::PureRuntime {
            target.obligations.retain(|obligation| {
                !matches!(
                    obligation.0.as_ref(),
                    "adapter-failure" | "whnf-failure-boundary"
                )
            });
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout.as_bytes(), b""));
            let exits: &[(u16, &str)] = if builtin == "Map.singleton" {
                &[(1, "not-forced")]
            } else {
                &[]
            };
            if !exits.is_empty() {
                target.expected_lazy_argument_exit_sha256 =
                    Some(crate::lazy_argument_exit_sha256(exits.iter().copied()));
            }
            let typed = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{typed_value}}}"
            );
            target.expected_typed_result_sha256 = Some(sha256_bytes(typed.as_bytes()));
        }
    }
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-typed-{}-{}",
            builtin.replace('.', "-").to_ascii_lowercase(),
            definition.slug
        )),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_singleton_strictness_cases() -> Vec<DifferentialCase> {
    const MAP_KEY_STRICT_SOURCE: &str = concat!(
        "main = IO.print $ Map.size $ Map.singleton ",
        "(Error.error \"singleton key forced\" :: Int) \"value\"\n",
    );
    const MAP_VALUE_LAZY_SOURCE: &str = concat!(
        "main = IO.print $ Map.size $ Map.singleton (1 :: Int) ",
        "(Error.error \"singleton value forced\" :: Text)\n",
    );
    const SET_ELEMENT_STRICT_SOURCE: &str = concat!(
        "main = IO.print $ Set.size $ Set.singleton ",
        "(Error.error \"singleton element forced\" :: Int)\n",
    );
    vec![
        runtime_singleton_strictness_case(
            "Map.singleton",
            "runtime-typed-map-singleton-key-strict",
            MAP_KEY_STRICT_SOURCE,
            &[(1, "not-forced")],
            false,
            b"",
            Some("singleton key forced"),
        ),
        runtime_singleton_strictness_case(
            "Map.singleton",
            "runtime-typed-map-singleton-value-nonforce",
            MAP_VALUE_LAZY_SOURCE,
            &[(1, "not-forced")],
            true,
            b"1\n",
            None,
        ),
        runtime_singleton_strictness_case(
            "Set.singleton",
            "runtime-typed-set-singleton-element-strict",
            SET_ELEMENT_STRICT_SOURCE,
            &[],
            false,
            b"",
            Some("singleton element forced"),
        ),
    ]
}

fn runtime_singleton_strictness_case(
    builtin: &'static str,
    id: &'static str,
    source: &'static str,
    exits: &[(u16, &'static str)],
    expected_completion: bool,
    stdout: &'static [u8],
    error_message: Option<&'static str>,
) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    descriptor
        .targets
        .retain(|target| target.dimension == CompatibilityDimension::PureRuntime);
    descriptor.semantic_targets.retain_mut(|target| {
        if target.dimension != CompatibilityDimension::PureRuntime {
            return false;
        }
        target.obligations.retain(|obligation| {
            matches!(
                obligation.0.as_ref(),
                "adapter-success" | "whnf-boundary" | "whnf-failure-boundary" | "lazy-boundary"
            )
        });
        if expected_completion {
            target.obligations.retain(|obligation| {
                !matches!(
                    obligation.0.as_ref(),
                    "adapter-failure" | "whnf-failure-boundary"
                )
            });
            target.expected_instance_target = Some(Arc::from("Int"));
            target.expected_comparator_trace_sha256 =
                Some(crate::comparator_trace_sha256(builtin, 1, "Int", &[], &[]));
        } else {
            target.obligations.retain(|obligation| {
                matches!(
                    obligation.0.as_ref(),
                    "whnf-failure-boundary" | "lazy-boundary"
                )
            });
            target.causal_signal = crate::CausalSignal::ForceTrace;
            target.expected_instance_target = None;
            target.expected_instance_premises.clear();
            target.expected_comparator_trace_sha256 = None;
            target.expected_typed_result_sha256 = None;
            target.expected_whnf_argument_failure_sha256 =
                Some(crate::whnf_argument_failure_sha256([(0, "error", "H0901")]));
        }
        let stderr = error_message.map_or_else(Vec::new, pinned_user_error_stderr);
        target.expected_raw_presentation_sha256 =
            Some(crate::raw_presentation_sha256(stdout, &stderr));
        target.expected_process_status_sha256 = Some(crate::process_status_sha256(
            expected_completion,
            Some(i32::from(!expected_completion)),
        ));
        if !exits.is_empty() {
            target.expected_lazy_argument_exit_sha256 =
                Some(crate::lazy_argument_exit_sha256(exits.iter().copied()));
        }
        true
    });
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        expected_runtime_completion: expected_completion,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn pinned_user_error_stderr(message: &str) -> Vec<u8> {
    format!(
        "hell: {message}\nCallStack (from HasCallStack):\n  error, called at src/Hell.hs:1953:4 in main:Main\n"
    )
    .into_bytes()
}

fn singleton_ord_definitions() -> Vec<SingletonOrdDefinition> {
    let selected = [
        ("bool", "bool"),
        ("byte-string", "byte-string"),
        ("char", "char"),
        ("day", "day"),
        ("day-of-week", "day-of-week"),
        ("double", "double-finite"),
        ("exit-code", "exit-code"),
        ("int", "int"),
        ("integer", "integer"),
        ("text", "text"),
        ("time-of-day", "time-of-day"),
        ("utc-time", "utc-time"),
        ("tuple", "tuple"),
        ("ci", "ci"),
        ("either", "either-left"),
        ("maybe", "maybe-just"),
        ("set", "set-nonempty"),
        ("tree", "tree-branch"),
        ("vector", "vector-nonempty"),
        ("list", "list-nonempty"),
    ];
    let show = show_instance_definitions();
    selected
        .into_iter()
        .map(|(slug, show_slug)| {
            let value = show
                .iter()
                .copied()
                .find(|definition| definition.slug == show_slug)
                .unwrap_or_else(|| panic!("missing singleton value definition {show_slug}"));
            SingletonOrdDefinition {
                slug,
                value,
                canonical: singleton_ord_canonical(slug),
            }
        })
        .collect()
}

fn singleton_ord_canonical(slug: &str) -> String {
    let int = |value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let text = |value: &str| format!("{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}", utf8_hex(value));
    match slug {
        "bool" => "{\"type\":\"Bool\",\"value\":true}".to_owned(),
        "byte-string" => "{\"type\":\"ByteString\",\"hex\":\"61ceb2\"}".to_owned(),
        "char" => "{\"type\":\"Character\",\"codePoint\":946}".to_owned(),
        "day" => "{\"type\":\"Day\",\"iso8601Hex\":\"323032352d30382d3130\"}".to_owned(),
        "day-of-week" => "{\"type\":\"DayOfWeek\",\"value\":\"Sunday\"}".to_owned(),
        "double" => "{\"type\":\"Double\",\"ieee754Bits\":\"3ff4000000000000\"}".to_owned(),
        "exit-code" => format!(
            "{{\"type\":\"PrimitiveVariant\",\"family\":\"Exit\",\"constructor\":\"ExitFailure\",\"payloads\":[{}]}}",
            int(23)
        ),
        "int" => int(-42),
        "integer" => "{\"type\":\"Integer\",\"value\":\"42\"}".to_owned(),
        "text" => text("aβ"),
        "time-of-day" => "{\"type\":\"TimeOfDay\",\"iso8601Hex\":\"31323a30303a3030\"}".to_owned(),
        "utc-time" => "{\"type\":\"UtcTime\",\"iso8601Hex\":\"323032352d30382d31302030303a30303a30312e3520555443\"}".to_owned(),
        "tuple" => format!(
            "{{\"type\":\"Tuple\",\"elements\":[{},{}]}}",
            int(1),
            text("a")
        ),
        "ci" => format!(
            "{{\"type\":\"CaseInsensitive\",\"original\":{},\"folded\":{}}}",
            text("AbC"),
            text("abc")
        ),
        "either" => format!(
            "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{}]}}",
            int(1)
        ),
        "maybe" => format!("{{\"type\":\"Maybe\",\"payload\":{}}}", int(1)),
        "set" => format!(
            "{{\"type\":\"Set\",\"elements\":[{},{}]}}",
            int(1),
            int(2)
        ),
        "tree" => singleton_tree_canonical(),
        "vector" => format!(
            "{{\"type\":\"Vector\",\"elements\":[{},{}]}}",
            int(1),
            int(2)
        ),
        "list" => format!(
            "{{\"type\":\"List\",\"elements\":[{},{}],\"terminationHex\":\"6e696c\"}}",
            int(1),
            int(2)
        ),
        _ => unreachable!("singleton Ord inventory is closed"),
    }
}

fn singleton_tree_canonical() -> String {
    let int = |value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let empty_children = "{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}";
    let child = format!(
        "{{\"type\":\"Tree\",\"elements\":[{},{}]}}",
        int(2),
        empty_children
    );
    let children =
        format!("{{\"type\":\"List\",\"elements\":[{child}],\"terminationHex\":\"6e696c\"}}");
    format!(
        "{{\"type\":\"Tree\",\"elements\":[{},{}]}}",
        int(1),
        children
    )
}

const ORD_LIST_CLAIM_READY: bool = true;

#[derive(Clone)]
struct OrdListValue {
    expression: String,
    rendered: String,
    canonical: String,
}

#[derive(Clone)]
struct OrdListDefinition {
    slug: &'static str,
    prelude: &'static str,
    target: &'static str,
    type_expression: &'static str,
    premises: &'static [(&'static str, u8)],
    lower: OrdListValue,
    upper: OrdListValue,
}

pub(crate) fn runtime_ord_list_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = ord_list_definitions()
        .into_iter()
        .flat_map(|definition| runtime_ord_list_cases_for_definition(&definition))
        .collect::<Vec<_>>();
    cases.extend(runtime_ord_list_ci_stability_cases());
    cases.extend(runtime_ord_list_double_exception_cases());
    cases.extend(runtime_ord_list_invalid_byte_cases());
    cases
}

fn runtime_ord_list_cases_for_definition(definition: &OrdListDefinition) -> Vec<DifferentialCase> {
    let mut cases = Vec::new();
    for builtin in ["List.sort", "List.nubOrd", "List.sortOn"] {
        cases.push(runtime_ord_list_case(
            definition,
            builtin,
            "empty-input",
            OrdListPath::Empty,
        ));
        cases.push(runtime_ord_list_case(
            definition,
            builtin,
            "singleton-input",
            OrdListPath::Singleton,
        ));
        cases.push(runtime_ord_list_case(
            definition,
            builtin,
            "finite-input",
            OrdListPath::Finite,
        ));
        if builtin == "List.nubOrd" {
            cases.push(runtime_ord_list_case(
                definition,
                builtin,
                "all-unique",
                OrdListPath::Unique,
            ));
        }
    }
    cases
}

#[derive(Clone, Copy)]
enum OrdListPath {
    Empty,
    Singleton,
    Finite,
    Unique,
}

struct OrdListCaseFacts<'a> {
    path: &'a str,
    boundary: Option<&'a str>,
    output_shape: OrdListOutputShape,
    source: String,
    values: Vec<OrdListValue>,
    invocations: Vec<CallbackInvocationContract>,
    stdin: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OrdListOutputShape {
    Elements,
    KeyedTuples,
}

fn runtime_ord_list_case(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    shape: OrdListPath,
) -> DifferentialCase {
    let (expression, values, invocations) = ord_list_case_facts(definition, builtin, shape);
    let source = format!(
        "{}main = IO.print $ {builtin} {expression}\n",
        definition.prelude
    );
    let boundary = match shape {
        OrdListPath::Empty => Some("empty-input"),
        OrdListPath::Singleton => Some("singleton-input"),
        OrdListPath::Finite => Some("finite-input"),
        OrdListPath::Unique => None,
    };
    ord_list_case_from_facts(
        definition,
        builtin,
        OrdListCaseFacts {
            path,
            boundary,
            output_shape: if builtin == "List.sortOn" {
                OrdListOutputShape::KeyedTuples
            } else {
                OrdListOutputShape::Elements
            },
            source,
            values,
            invocations,
            stdin: Vec::new(),
        },
    )
}

fn ord_list_case_facts(
    definition: &OrdListDefinition,
    builtin: &str,
    shape: OrdListPath,
) -> (String, Vec<OrdListValue>, Vec<CallbackInvocationContract>) {
    if builtin == "List.sortOn" {
        return ord_list_sort_on_facts(definition, shape);
    }
    match shape {
        OrdListPath::Empty => (
            format!("([] :: [{}])", definition.type_expression),
            Vec::new(),
            Vec::new(),
        ),
        OrdListPath::Singleton => (
            format!("[{}]", definition.lower.expression),
            vec![definition.lower.clone()],
            Vec::new(),
        ),
        OrdListPath::Finite if builtin == "List.sort" => (
            format!(
                "[{}, {}, {}]",
                definition.upper.expression,
                definition.lower.expression,
                definition.upper.expression,
            ),
            vec![
                definition.lower.clone(),
                definition.upper.clone(),
                definition.upper.clone(),
            ],
            Vec::new(),
        ),
        OrdListPath::Finite => (
            format!(
                "[{}, {}, {}, {}]",
                definition.upper.expression,
                definition.lower.expression,
                definition.upper.expression,
                definition.lower.expression,
            ),
            vec![definition.upper.clone(), definition.lower.clone()],
            Vec::new(),
        ),
        OrdListPath::Unique => (
            format!(
                "[{}, {}]",
                definition.upper.expression, definition.lower.expression,
            ),
            vec![definition.upper.clone(), definition.lower.clone()],
            Vec::new(),
        ),
    }
}

fn ord_list_sort_on_facts(
    definition: &OrdListDefinition,
    shape: OrdListPath,
) -> (String, Vec<OrdListValue>, Vec<CallbackInvocationContract>) {
    let function = "(\\(key, payload) -> key)";
    match shape {
        OrdListPath::Empty => (
            format!(
                "{function} ([] :: [({}, Text)])",
                definition.type_expression
            ),
            Vec::new(),
            Vec::new(),
        ),
        OrdListPath::Singleton => {
            let value = ord_list_keyed_value(&definition.lower, "only");
            (
                format!("{function} [({}, \"only\")]", definition.lower.expression),
                vec![value],
                Vec::new(),
            )
        }
        OrdListPath::Finite => {
            let first = ord_list_keyed_value(&definition.upper, "first");
            let middle = ord_list_keyed_value(&definition.lower, "middle");
            let last = ord_list_keyed_value(&definition.upper, "last");
            let expression = format!(
                "{function} [({}, \"first\"), ({}, \"middle\"), ({}, \"last\")]",
                definition.upper.expression,
                definition.lower.expression,
                definition.upper.expression,
            );
            let invocations = vec![
                ord_list_key_invocation(&first, &definition.upper),
                ord_list_key_invocation(&middle, &definition.lower),
                ord_list_key_invocation(&last, &definition.upper),
            ];
            (expression, vec![middle, first, last], invocations)
        }
        OrdListPath::Unique => unreachable!("sortOn has no all-unique auxiliary"),
    }
}

fn ord_list_keyed_value(key: &OrdListValue, payload: &str) -> OrdListValue {
    OrdListValue {
        expression: String::new(),
        rendered: format!("({},\"{payload}\")", key.rendered.as_str()),
        canonical: format!(
            "{{\"type\":\"Tuple\",\"elements\":[{},{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}]}}",
            key.canonical,
            utf8_hex(payload),
        ),
    }
}

fn ord_list_key_invocation(
    argument: &OrdListValue,
    result: &OrdListValue,
) -> CallbackInvocationContract {
    callback_contract_invocation(
        0,
        "key",
        &[argument.canonical.as_str()],
        result.canonical.as_str(),
    )
}

fn ord_list_case_from_facts(
    definition: &OrdListDefinition,
    builtin: &str,
    facts: OrdListCaseFacts<'_>,
) -> DifferentialCase {
    let OrdListCaseFacts {
        path,
        boundary,
        output_shape,
        source,
        values,
        invocations,
        stdin,
    } = facts;
    let mut descriptor = if let Some(boundary) = boundary {
        if builtin == "List.sortOn" {
            runtime_boundary_descriptor(builtin, boundary, &source, invocations)
        } else {
            runtime_builtin_boundary_descriptor(builtin, boundary, &source)
        }
    } else {
        let mut descriptor = runtime_single_typed_target_descriptor(builtin, &source);
        descriptor.callback_contracts = (builtin == "List.sortOn")
            .then(|| CallbackContract {
                builtin: Arc::from(builtin),
                invocations,
            })
            .into_iter()
            .collect();
        descriptor
    };
    let target = &mut descriptor.semantic_targets[0];
    target.expected_instance_target = Some(Arc::from(definition.target));
    target.expected_instance_premises = definition
        .premises
        .iter()
        .map(|(target, premise_count)| crate::InstancePremiseEvidence {
            target: Arc::from(*target),
            premise_count: *premise_count,
        })
        .collect();
    let canonical = ord_list_canonical(&values);
    let typed = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{canonical}}}"
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(typed.as_bytes()));
    let stdout = ord_list_stdout(definition, output_shape, &values);
    target.expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(stdout.as_bytes(), b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-ord-list-{}-{}-{path}",
            builtin.replace('.', "-").to_ascii_lowercase(),
            definition.slug,
        )),
        source: Arc::from(source),
        stdin,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn ord_list_canonical(values: &[OrdListValue]) -> String {
    format!(
        "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}",
        values
            .iter()
            .map(|value| value.canonical.as_str())
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn ord_list_stdout(
    definition: &OrdListDefinition,
    output_shape: OrdListOutputShape,
    values: &[OrdListValue],
) -> String {
    if output_shape == OrdListOutputShape::Elements
        && definition.target == "Char"
        && values
            .iter()
            .all(|value| reviewed_character_code_point(&value.canonical).is_some())
    {
        return format!("{}\n", reviewed_haskell_character_sequence(values));
    }
    format!(
        "[{}]\n",
        values
            .iter()
            .map(|value| value.rendered.as_str())
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn reviewed_character_code_point(canonical: &str) -> Option<u32> {
    canonical
        .strip_prefix("{\"type\":\"Character\",\"codePoint\":")?
        .strip_suffix('}')?
        .parse()
        .ok()
}

fn reviewed_haskell_character_sequence(values: &[OrdListValue]) -> String {
    let canonicals = values
        .iter()
        .map(|value| value.canonical.as_str())
        .collect::<Vec<_>>();
    reviewed_haskell_character_canonicals(&canonicals)
}

fn reviewed_haskell_character_canonicals(canonicals: &[&str]) -> String {
    let code_points = canonicals
        .iter()
        .map(|canonical| {
            reviewed_character_code_point(canonical)
                .expect("Char sequence authority contains only canonical Character values")
        })
        .collect::<Vec<_>>();
    crate::reviewed_haskell_string_literal(&code_points)
        .expect("canonical Character code points are valid")
}

fn ord_list_definitions() -> Vec<OrdListDefinition> {
    let mut definitions = ord_list_primitive_definitions();
    definitions.extend(ord_list_composite_definitions());
    definitions
}

fn ord_list_value(
    expression: impl Into<String>,
    rendered: impl Into<String>,
    canonical: impl Into<String>,
) -> OrdListValue {
    OrdListValue {
        expression: expression.into(),
        rendered: rendered.into(),
        canonical: canonical.into(),
    }
}

fn ord_list_text(value: &str) -> String {
    format!("{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}", utf8_hex(value))
}

fn ord_list_int(value: i64) -> String {
    format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}")
}

fn ord_list_primitive_definitions() -> Vec<OrdListDefinition> {
    let mut definitions = ord_list_primitive_head_definitions();
    definitions.extend(ord_list_primitive_tail_definitions());
    definitions
}

fn ord_list_primitive_head_definitions() -> Vec<OrdListDefinition> {
    vec![
        ord_list_definition(
            "bool",
            "",
            "Bool",
            "Bool",
            EQ_NO_PREMISES,
            ord_list_value("Bool.False", "False", "{\"type\":\"Bool\",\"value\":false}"),
            ord_list_value("Bool.True", "True", "{\"type\":\"Bool\",\"value\":true}"),
        ),
        ord_list_definition(
            "byte-string",
            "",
            "ByteString",
            "ByteString",
            EQ_NO_PREMISES,
            ord_list_value(
                "Text.encodeUtf8 \"a\"",
                "\"a\"",
                "{\"type\":\"ByteString\",\"hex\":\"61\"}",
            ),
            ord_list_value(
                "Text.encodeUtf8 \"b\"",
                "\"b\"",
                "{\"type\":\"ByteString\",\"hex\":\"62\"}",
            ),
        ),
        ord_list_definition(
            "ci",
            "",
            "CI",
            "CI Text",
            EQ_TEXT_PREMISE,
            ord_list_ci_value("AbC"),
            ord_list_ci_value("aBd"),
        ),
        ord_list_definition(
            "char",
            "",
            "Char",
            "Char",
            EQ_NO_PREMISES,
            ord_list_value("'a'", "'a'", "{\"type\":\"Character\",\"codePoint\":97}"),
            ord_list_value(
                "'β'",
                "'\\946'",
                "{\"type\":\"Character\",\"codePoint\":946}",
            ),
        ),
        ord_list_definition(
            "day",
            ORD_DAYS,
            "Day",
            "Day",
            EQ_NO_PREMISES,
            ord_list_day_value("Main.day1", "2025-08-11"),
            ord_list_day_value("Main.day2", "2025-08-12"),
        ),
        ord_list_definition(
            "day-of-week",
            ORD_DAYS,
            "DayOfWeek",
            "DayOfWeek",
            EQ_NO_PREMISES,
            ord_list_value(
                "Day.dayOfWeek Main.day1",
                "Monday",
                "{\"type\":\"DayOfWeek\",\"value\":\"Monday\"}",
            ),
            ord_list_value(
                "Day.dayOfWeek Main.day2",
                "Tuesday",
                "{\"type\":\"DayOfWeek\",\"value\":\"Tuesday\"}",
            ),
        ),
    ]
}

fn ord_list_primitive_tail_definitions() -> Vec<OrdListDefinition> {
    vec![
        ord_list_definition(
            "double",
            "",
            "Double",
            "Double",
            EQ_NO_PREMISES,
            ord_list_double_value("1.25", "1.25", "3ff4000000000000"),
            ord_list_double_value("1.75", "1.75", "3ffc000000000000"),
        ),
        ord_list_definition(
            "exit-code",
            "",
            "ExitCode",
            "ExitCode",
            EQ_NO_PREMISES,
            ord_list_value(
                "Exit.ExitSuccess",
                "ExitSuccess",
                "{\"type\":\"PrimitiveVariant\",\"family\":\"Exit\",\"constructor\":\"ExitSuccess\",\"payloads\":[]}",
            ),
            ord_list_value(
                "Exit.ExitFailure 24",
                "ExitFailure 24",
                format!(
                    "{{\"type\":\"PrimitiveVariant\",\"family\":\"Exit\",\"constructor\":\"ExitFailure\",\"payloads\":[{}]}}",
                    ord_list_int(24),
                ),
            ),
        ),
        ord_list_definition(
            "int",
            "",
            "Int",
            "Int",
            EQ_NO_PREMISES,
            ord_list_value("(1 :: Int)", "1", ord_list_int(1)),
            ord_list_value("(3 :: Int)", "3", ord_list_int(3)),
        ),
        ord_list_definition(
            "integer",
            "",
            "Integer",
            "Integer",
            EQ_NO_PREMISES,
            ord_list_value(
                "Int.toInteger 1",
                "1",
                "{\"type\":\"Integer\",\"value\":\"1\"}",
            ),
            ord_list_value(
                "Int.toInteger 3",
                "3",
                "{\"type\":\"Integer\",\"value\":\"3\"}",
            ),
        ),
        ord_list_definition(
            "text",
            "",
            "Text",
            "Text",
            EQ_NO_PREMISES,
            ord_list_value("\"a\"", "\"a\"", ord_list_text("a")),
            ord_list_value("\"b\"", "\"b\"", ord_list_text("b")),
        ),
        ord_list_definition(
            "time-of-day",
            "",
            "TimeOfDay",
            "TimeOfDay",
            EQ_NO_PREMISES,
            ord_list_time_value("TimeOfDay.midnight", "00:00:00"),
            ord_list_time_value("TimeOfDay.midday", "12:00:00"),
        ),
        ord_list_definition(
            "utc-time",
            ORD_DAYS,
            "UTCTime",
            "UTCTime",
            EQ_NO_PREMISES,
            ord_list_utc_value("UTCTime.UTCTime Main.day1 1.5", "2025-08-11 00:00:01.5 UTC"),
            ord_list_utc_value("UTCTime.UTCTime Main.day2 1.5", "2025-08-12 00:00:01.5 UTC"),
        ),
    ]
}

fn ord_list_composite_definitions() -> Vec<OrdListDefinition> {
    vec![
        ord_list_definition(
            "either",
            "",
            "Either",
            "Either Text Int",
            &[("Text", 0), ("Int", 0)],
            ord_list_either_left_value("a"),
            ord_list_either_left_value("b"),
        ),
        ord_list_definition(
            "maybe",
            "",
            "Maybe",
            "Maybe Int",
            EQ_INT_PREMISE,
            ord_list_value(
                "(Maybe.Nothing :: Maybe Int)",
                "Nothing",
                "{\"type\":\"Maybe\",\"payload\":null}",
            ),
            ord_list_value(
                "(Maybe.Just 0 :: Maybe Int)",
                "Just 0",
                format!("{{\"type\":\"Maybe\",\"payload\":{}}}", ord_list_int(0)),
            ),
        ),
        ord_list_definition(
            "set",
            "",
            "Set",
            "Set Int",
            EQ_INT_PREMISE,
            ord_list_set_value("Set.fromList [1,2]", &[1, 2]),
            ord_list_set_value("Set.fromList [1,3]", &[1, 3]),
        ),
        ord_list_definition(
            "tree",
            "",
            "Tree",
            "Tree Int",
            EQ_INT_PREMISE,
            ord_list_tree_value(2),
            ord_list_tree_value(3),
        ),
        ord_list_definition(
            "tuple",
            "",
            "(,)",
            "(Int, Text)",
            &[("Int", 0), ("Text", 0)],
            ord_list_tuple_value("a"),
            ord_list_tuple_value("c"),
        ),
        ord_list_definition(
            "vector",
            "",
            "Vector",
            "Vector Int",
            EQ_INT_PREMISE,
            ord_list_vector_value("Vector.fromList [1,2]", &[1, 2]),
            ord_list_vector_value("Vector.fromList [1,3]", &[1, 3]),
        ),
        ord_list_definition(
            "list",
            "",
            "[]",
            "[Int]",
            EQ_INT_PREMISE,
            ord_list_list_value("([1,2] :: [Int])", &[1, 2]),
            ord_list_list_value("([1,3] :: [Int])", &[1, 3]),
        ),
    ]
}

fn ord_list_definition(
    slug: &'static str,
    prelude: &'static str,
    target: &'static str,
    type_expression: &'static str,
    premises: &'static [(&'static str, u8)],
    lower: OrdListValue,
    upper: OrdListValue,
) -> OrdListDefinition {
    OrdListDefinition {
        slug,
        prelude,
        target,
        type_expression,
        premises,
        lower,
        upper,
    }
}

fn ord_list_ci_value(value: &'static str) -> OrdListValue {
    ord_list_value(
        format!("CI.mk \"{value}\""),
        format!("\"{value}\""),
        format!(
            "{{\"type\":\"CaseInsensitive\",\"original\":{},\"folded\":{}}}",
            ord_list_text(value),
            ord_list_text(&value.to_ascii_lowercase()),
        ),
    )
}

fn ord_list_day_value(expression: &'static str, value: &'static str) -> OrdListValue {
    ord_list_value(
        expression,
        value,
        format!(
            "{{\"type\":\"Day\",\"iso8601Hex\":\"{}\"}}",
            utf8_hex(value)
        ),
    )
}

fn ord_list_double_value(
    expression: impl Into<String>,
    rendered: impl Into<String>,
    bits: &str,
) -> OrdListValue {
    ord_list_value(
        expression,
        rendered,
        format!("{{\"type\":\"Double\",\"ieee754Bits\":\"{bits}\"}}"),
    )
}

fn ord_list_time_value(expression: &'static str, value: &'static str) -> OrdListValue {
    ord_list_value(
        expression,
        value,
        format!(
            "{{\"type\":\"TimeOfDay\",\"iso8601Hex\":\"{}\"}}",
            utf8_hex(value)
        ),
    )
}

fn ord_list_utc_value(expression: &'static str, value: &'static str) -> OrdListValue {
    ord_list_value(
        expression,
        value,
        format!(
            "{{\"type\":\"UtcTime\",\"iso8601Hex\":\"{}\"}}",
            utf8_hex(value)
        ),
    )
}

fn ord_list_either_left_value(value: &'static str) -> OrdListValue {
    ord_list_value(
        format!("(Either.Left \"{value}\" :: Either Text Int)"),
        format!("Left \"{value}\""),
        format!(
            "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{}]}}",
            ord_list_text(value),
        ),
    )
}

fn ord_list_set_value(expression: &'static str, values: &[i64]) -> OrdListValue {
    let rendered = values
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let canonical = values
        .iter()
        .map(|value| ord_list_int(*value))
        .collect::<Vec<_>>()
        .join(",");
    ord_list_value(
        expression,
        format!("fromList [{rendered}]"),
        format!("{{\"type\":\"Set\",\"elements\":[{canonical}]}}"),
    )
}

fn ord_list_tree_value(child: i64) -> OrdListValue {
    let expression = format!("(Tree.Node 1 [Tree.Node {child} []] :: Tree Int)");
    let rendered = format!(
        "Node {{rootLabel = 1, subForest = [Node {{rootLabel = {child}, subForest = []}}]}}"
    );
    let empty = "{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}";
    let child = format!(
        "{{\"type\":\"Tree\",\"elements\":[{},{}]}}",
        ord_list_int(child),
        empty,
    );
    let children =
        format!("{{\"type\":\"List\",\"elements\":[{child}],\"terminationHex\":\"6e696c\"}}");
    ord_list_value(
        expression,
        rendered,
        format!(
            "{{\"type\":\"Tree\",\"elements\":[{},{}]}}",
            ord_list_int(1),
            children,
        ),
    )
}

fn ord_list_tuple_value(value: &'static str) -> OrdListValue {
    ord_list_value(
        format!("((1, \"{value}\") :: (Int, Text))"),
        format!("(1,\"{value}\")"),
        format!(
            "{{\"type\":\"Tuple\",\"elements\":[{},{}]}}",
            ord_list_int(1),
            ord_list_text(value),
        ),
    )
}

fn ord_list_vector_value(expression: &'static str, values: &[i64]) -> OrdListValue {
    let rendered = values
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let canonical = values
        .iter()
        .map(|value| ord_list_int(*value))
        .collect::<Vec<_>>()
        .join(",");
    ord_list_value(
        expression,
        format!("[{rendered}]"),
        format!("{{\"type\":\"Vector\",\"elements\":[{canonical}]}}"),
    )
}

fn ord_list_list_value(expression: &'static str, values: &[i64]) -> OrdListValue {
    let rendered = values
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let canonical = values
        .iter()
        .map(|value| ord_list_int(*value))
        .collect::<Vec<_>>()
        .join(",");
    ord_list_value(
        expression,
        format!("[{rendered}]"),
        format!("{{\"type\":\"List\",\"elements\":[{canonical}],\"terminationHex\":\"6e696c\"}}"),
    )
}

fn runtime_ord_list_ci_stability_cases() -> Vec<DifferentialCase> {
    let definition = OrdListDefinition {
        lower: ord_list_ci_value("AbC"),
        upper: ord_list_ci_value("aBc"),
        ..ord_list_definitions()
            .into_iter()
            .find(|definition| definition.slug == "ci")
            .expect("CI is an Ord list scope")
    };
    ["List.sort", "List.nubOrd", "List.sortOn"]
        .into_iter()
        .map(|builtin| {
            let (expression, values, invocations) = if builtin == "List.sortOn" {
                let first = ord_list_keyed_value(&definition.lower, "first");
                let second = ord_list_keyed_value(&definition.upper, "second");
                (
                    format!(
                        "(\\(key, payload) -> key) [({}, \"first\"), ({}, \"second\")]",
                        definition.lower.expression, definition.upper.expression,
                    ),
                    vec![first.clone(), second.clone()],
                    vec![
                        ord_list_key_invocation(&first, &definition.lower),
                        ord_list_key_invocation(&second, &definition.upper),
                    ],
                )
            } else if builtin == "List.sort" {
                (
                    format!(
                        "[{}, {}]",
                        definition.lower.expression, definition.upper.expression,
                    ),
                    vec![definition.lower.clone(), definition.upper.clone()],
                    Vec::new(),
                )
            } else {
                (
                    format!(
                        "[{}, {}]",
                        definition.lower.expression, definition.upper.expression,
                    ),
                    vec![definition.lower.clone()],
                    Vec::new(),
                )
            };
            let source = format!("main = IO.print $ {builtin} {expression}\n");
            ord_list_case_from_facts(
                &definition,
                builtin,
                OrdListCaseFacts {
                    path: "ci-folded-stability",
                    boundary: None,
                    output_shape: if builtin == "List.sortOn" {
                        OrdListOutputShape::KeyedTuples
                    } else {
                        OrdListOutputShape::Elements
                    },
                    source,
                    values,
                    invocations,
                    stdin: Vec::new(),
                },
            )
        })
        .collect()
}

fn runtime_ord_list_double_exception_cases() -> Vec<DifferentialCase> {
    const PRELUDE: &str = concat!(
        "nan = Maybe.maybe (Error.error \"nan\") Function.id $ Double.readMaybe \"NaN\"\n",
        "negativeZero = Maybe.maybe (Error.error \"negative zero\") Function.id $ Double.readMaybe \"-0.0\"\n",
        "infinity = Double.plus 1.7976931348623157e308 1.7976931348623157e308\n",
        "negativeInfinity = Double.mult (Double.fromInt $ Int.subtract 1 0) Main.infinity\n",
    );
    let definition = OrdListDefinition {
        prelude: PRELUDE,
        ..ord_list_definitions()
            .into_iter()
            .find(|definition| definition.slug == "double")
            .expect("Double is an Ord list scope")
    };
    let negative_zero = ord_list_double_value("Main.negativeZero", "-0.0", "8000000000000000");
    let positive_zero = ord_list_double_value("0.0", "0.0", "0000000000000000");
    let negative_infinity =
        ord_list_double_value("Main.negativeInfinity", "-Infinity", "fff0000000000000");
    let finite = ord_list_double_value("1.25", "1.25", "3ff4000000000000");
    let infinity = ord_list_double_value("Main.infinity", "Infinity", "7ff0000000000000");
    let nan = ord_list_double_value("Main.nan", "NaN", "7ff8000000000000");
    let paths = [
        (
            "signed-zero-stability",
            vec![negative_zero.clone(), positive_zero],
        ),
        (
            "infinities",
            vec![infinity, negative_infinity, finite.clone()],
        ),
        ("nan-finite", vec![nan.clone(), finite.clone(), nan.clone()]),
    ];
    let mut cases = Vec::new();
    for builtin in ["List.sort", "List.nubOrd", "List.sortOn"] {
        for (path, source_values) in &paths {
            cases.push(runtime_ord_list_double_case(
                &definition,
                builtin,
                path,
                source_values,
            ));
        }
    }
    cases.extend(runtime_ord_list_double_two_value_cases(
        &definition,
        &nan,
        &finite,
    ));
    cases.extend(runtime_ord_list_double_shape_cases(&definition, &nan));
    let upper_finite = ord_list_double_value("1.75", "1.75", "3ffc000000000000");
    let source = format!(
        "{}main = IO.print $ List.nubOrd [1.25,Main.nan,1.75,1.25]\n",
        definition.prelude,
    );
    cases.push(ord_list_case_from_facts(
        &definition,
        "List.nubOrd",
        OrdListCaseFacts {
            path: "nan-finite-set-routing",
            boundary: None,
            output_shape: OrdListOutputShape::Elements,
            source,
            values: vec![
                ord_list_double_value("1.25", "1.25", "3ff4000000000000"),
                ord_list_double_value("Main.nan", "NaN", "7ff8000000000000"),
                upper_finite,
                ord_list_double_value("1.25", "1.25", "3ff4000000000000"),
            ],
            invocations: Vec::new(),
            stdin: Vec::new(),
        },
    ));
    cases
}

fn runtime_ord_list_invalid_byte_cases() -> Vec<DifferentialCase> {
    let definition = ord_list_definitions()
        .into_iter()
        .find(|definition| definition.slug == "byte-string")
        .expect("ByteString is an Ord list scope");
    let first = ord_list_value(
        "first",
        r#""\255A""#,
        "{\"type\":\"ByteString\",\"hex\":\"ff41\"}",
    );
    let middle = ord_list_value(
        "middle",
        r#""\254B""#,
        "{\"type\":\"ByteString\",\"hex\":\"fe42\"}",
    );
    let last = ord_list_value(
        "last",
        r#""\255A""#,
        "{\"type\":\"ByteString\",\"hex\":\"ff41\"}",
    );
    ["List.sort", "List.nubOrd", "List.sortOn"]
        .into_iter()
        .map(|builtin| {
            let prefix = concat!(
                "main = do\n",
                "  first <- ByteString.hGet IO.stdin 2\n",
                "  middle <- ByteString.hGet IO.stdin 2\n",
                "  last <- ByteString.hGet IO.stdin 2\n",
            );
            let (operation, values, invocations) = match builtin {
                "List.sort" => (
                    "List.sort [first,middle,last]",
                    vec![middle.clone(), first.clone(), last.clone()],
                    Vec::new(),
                ),
                "List.nubOrd" => (
                    "List.nubOrd [first,middle,last]",
                    vec![first.clone(), middle.clone()],
                    Vec::new(),
                ),
                "List.sortOn" => {
                    let first_keyed = ord_list_keyed_value(&first, "first");
                    let middle_keyed = ord_list_keyed_value(&middle, "middle");
                    let last_keyed = ord_list_keyed_value(&last, "last");
                    (
                        "List.sortOn (\\(key, payload) -> key) [(first,\"first\"),(middle,\"middle\"),(last,\"last\")]",
                        vec![middle_keyed.clone(), first_keyed.clone(), last_keyed.clone()],
                        vec![
                            ord_list_key_invocation(&first_keyed, &first),
                            ord_list_key_invocation(&middle_keyed, &middle),
                            ord_list_key_invocation(&last_keyed, &last),
                        ],
                    )
                }
                _ => unreachable!("reviewed Ord list builtin"),
            };
            let source = format!("{prefix}  IO.print $ {operation}\n");
            ord_list_case_from_facts(
                &definition,
                builtin,
                OrdListCaseFacts {
                    path: "invalid-bytes",
                    boundary: None,
                    output_shape: if builtin == "List.sortOn" {
                        OrdListOutputShape::KeyedTuples
                    } else {
                        OrdListOutputShape::Elements
                    },
                    source,
                    values,
                    invocations,
                    stdin: vec![0xff, 0x41, 0xfe, 0x42, 0xff, 0x41],
                },
            )
        })
        .collect()
}

fn runtime_ord_list_double_case(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    source_values: &[OrdListValue],
) -> DifferentialCase {
    let sorted_indices: Vec<usize> = match path {
        "signed-zero-stability" => vec![0, 1],
        "nan-finite"
            if builtin == "List.sort"
                && hell_builtins::native_oracle_list_sort()
                    == hell_builtins::NativeOracleListSort::Ghc912Base421FourWay =>
        {
            vec![0, 1, 2]
        }
        "nan-finite" => vec![2, 1, 0],
        "infinities" => vec![1, 2, 0],
        _ => unreachable!("reviewed Double Ord list path"),
    };
    let result_indices = if builtin == "List.nubOrd" {
        if path == "signed-zero-stability" {
            vec![0]
        } else {
            (0..source_values.len()).collect()
        }
    } else {
        sorted_indices
    };
    let values = result_indices
        .iter()
        .map(|index| source_values[*index].clone())
        .collect::<Vec<_>>();
    let expression = source_values
        .iter()
        .map(|value| value.expression.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let (source, values, invocations) = if builtin == "List.sortOn" {
        let keyed_source = source_values
            .iter()
            .enumerate()
            .map(|(index, value)| format!("({},\"item-{index}\")", value.expression))
            .collect::<Vec<_>>();
        let keyed_values = result_indices
            .iter()
            .map(|index| ord_list_keyed_value(&source_values[*index], &format!("item-{index}")))
            .collect::<Vec<_>>();
        let callback_indices: &[usize] = if source_values.len() == 2 {
            &[0, 1]
        } else {
            &[0, 1, 2]
        };
        let invocations = callback_indices
            .iter()
            .map(|index| {
                let argument =
                    ord_list_keyed_value(&source_values[*index], &format!("item-{index}"));
                ord_list_key_invocation(&argument, &source_values[*index])
            })
            .collect();
        (
            format!(
                "{}main = IO.print $ List.sortOn (\\(key, payload) -> key) [{}]\n",
                definition.prelude,
                keyed_source.join(","),
            ),
            keyed_values,
            invocations,
        )
    } else {
        (
            format!(
                "{}main = IO.print $ {builtin} [{expression}]\n",
                definition.prelude,
            ),
            values,
            Vec::new(),
        )
    };
    ord_list_case_from_facts(
        definition,
        builtin,
        OrdListCaseFacts {
            path,
            boundary: None,
            output_shape: if builtin == "List.sortOn" {
                OrdListOutputShape::KeyedTuples
            } else {
                OrdListOutputShape::Elements
            },
            source,
            values,
            invocations,
            stdin: Vec::new(),
        },
    )
}

fn runtime_ord_list_double_two_value_cases(
    definition: &OrdListDefinition,
    nan: &OrdListValue,
    finite: &OrdListValue,
) -> Vec<DifferentialCase> {
    let mut cases = Vec::new();
    for (path, source_values) in [
        ("nan-before-finite", [nan, finite]),
        ("finite-before-nan", [finite, nan]),
    ] {
        for builtin in ["List.sort", "List.sortOn"] {
            let values = if builtin == "List.sort"
                && hell_builtins::native_oracle_list_sort()
                    == hell_builtins::NativeOracleListSort::Ghc912Base421FourWay
            {
                source_values.iter().map(|value| (*value).clone()).collect()
            } else {
                vec![source_values[1].clone(), source_values[0].clone()]
            };
            let (source, values, invocations) = if builtin == "List.sortOn" {
                let first = ord_list_keyed_value(source_values[0], "first");
                let second = ord_list_keyed_value(source_values[1], "second");
                (
                    format!(
                        concat!(
                            "{}main = IO.print $ List.sortOn (\\(key, payload) -> key) ",
                            "[({},\"first\"),({},\"second\")]\n",
                        ),
                        definition.prelude,
                        source_values[0].expression,
                        source_values[1].expression,
                    ),
                    vec![second.clone(), first.clone()],
                    vec![
                        ord_list_key_invocation(&first, source_values[0]),
                        ord_list_key_invocation(&second, source_values[1]),
                    ],
                )
            } else {
                (
                    format!(
                        "{}main = IO.print $ List.sort [{},{}]\n",
                        definition.prelude,
                        source_values[0].expression,
                        source_values[1].expression,
                    ),
                    values,
                    Vec::new(),
                )
            };
            cases.push(ord_list_case_from_facts(
                definition,
                builtin,
                OrdListCaseFacts {
                    path,
                    boundary: None,
                    output_shape: if builtin == "List.sortOn" {
                        OrdListOutputShape::KeyedTuples
                    } else {
                        OrdListOutputShape::Elements
                    },
                    source,
                    values,
                    invocations,
                    stdin: Vec::new(),
                },
            ));
        }
    }
    cases
}

fn runtime_ord_list_double_shape_cases(
    definition: &OrdListDefinition,
    nan: &OrdListValue,
) -> Vec<DifferentialCase> {
    let finite_one = ord_list_double_value("1.25", "1.25", "3ff4000000000000");
    let finite_two = ord_list_double_value("1.75", "1.75", "3ffc000000000000");
    let source_values = [nan.clone(), finite_one, nan.clone(), finite_two];
    let mut cases = Vec::new();
    for builtin in ["List.sort", "List.sortOn"] {
        let output_indices = ord_list_double_shape_output_indices(builtin);
        let (source, values, invocations) = if builtin == "List.sortOn" {
            let keyed = source_values
                .iter()
                .enumerate()
                .map(|(index, value)| ord_list_keyed_value(value, &format!("item-{index}")))
                .collect::<Vec<_>>();
            (
                format!(
                    concat!(
                        "{}main = IO.print $ List.sortOn (\\(key, payload) -> key) ",
                        "[(Main.nan,\"item-0\"),(1.25,\"item-1\"),",
                        "(Main.nan,\"item-2\"),(1.75,\"item-3\")]\n",
                    ),
                    definition.prelude,
                ),
                output_indices
                    .iter()
                    .map(|index| keyed[*index].clone())
                    .collect(),
                keyed
                    .iter()
                    .zip(&source_values)
                    .map(|(argument, result)| ord_list_key_invocation(argument, result))
                    .collect(),
            )
        } else {
            (
                format!(
                    "{}main = IO.print $ List.sort [Main.nan,1.25,Main.nan,1.75]\n",
                    definition.prelude,
                ),
                output_indices
                    .iter()
                    .map(|index| source_values[*index].clone())
                    .collect(),
                Vec::new(),
            )
        };
        cases.push(ord_list_case_from_facts(
            definition,
            builtin,
            OrdListCaseFacts {
                path: "nan-alternating-runs",
                boundary: None,
                output_shape: if builtin == "List.sortOn" {
                    OrdListOutputShape::KeyedTuples
                } else {
                    OrdListOutputShape::Elements
                },
                source,
                values,
                invocations,
                stdin: Vec::new(),
            },
        ));
    }

    let nub_values = [
        nan.clone(),
        ord_list_double_value("1.0", "1.0", "3ff0000000000000"),
        nan.clone(),
        ord_list_double_value("0.0", "0.0", "0000000000000000"),
        nan.clone(),
        nan.clone(),
        nan.clone(),
        nan.clone(),
        ord_list_double_value("3.0", "3.0", "4008000000000000"),
        ord_list_double_value("2.0", "2.0", "4000000000000000"),
        ord_list_double_value("0.0", "0.0", "0000000000000000"),
    ];
    cases.push(ord_list_case_from_facts(
        definition,
        "List.nubOrd",
        OrdListCaseFacts {
            path: "nan-size-balanced-routing",
            boundary: None,
            output_shape: OrdListOutputShape::Elements,
            source: format!(
                concat!(
                    "{}main = IO.print $ List.nubOrd ",
                    "[Main.nan,1.0,Main.nan,0.0,Main.nan,Main.nan,",
                    "Main.nan,Main.nan,3.0,2.0,0.0]\n",
                ),
                definition.prelude,
            ),
            values: nub_values.to_vec(),
            invocations: Vec::new(),
            stdin: Vec::new(),
        },
    ));
    cases
}

fn ord_list_double_shape_output_indices(builtin: &str) -> [usize; 4] {
    match (hell_builtins::native_oracle_list_sort(), builtin) {
        (hell_builtins::NativeOracleListSort::Ghc912Base421FourWay, "List.sort") => [0, 1, 2, 3],
        (hell_builtins::NativeOracleListSort::Ghc912Base421FourWay, "List.sortOn") => [1, 3, 2, 0],
        _ => [3, 2, 1, 0],
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OrdSetBoundary {
    Empty,
    Singleton,
    Finite,
}

enum OrdSetResult {
    Set(Vec<OrdListValue>),
    Bool(bool),
}

struct OrdSetObservation {
    expression: String,
    result: OrdSetResult,
}

pub(crate) fn runtime_ord_set_boundary_cases() -> Vec<DifferentialCase> {
    const BUILTINS: &[&str] = &[
        "Set.fromList",
        "Set.insert",
        "Set.member",
        "Set.delete",
        "Set.union",
        "Set.difference",
        "Set.intersection",
    ];
    ord_list_definitions()
        .into_iter()
        .flat_map(|definition| {
            BUILTINS.iter().flat_map(move |builtin| {
                [
                    ("empty-input", OrdSetBoundary::Empty),
                    ("singleton-input", OrdSetBoundary::Singleton),
                    ("finite-input", OrdSetBoundary::Finite),
                ]
                .into_iter()
                .map({
                    let definition = definition.clone();
                    move |(path, boundary)| {
                        runtime_ord_set_case(&definition, builtin, path, boundary)
                    }
                })
            })
        })
        .collect()
}

pub(crate) fn runtime_ord_set_cases() -> Vec<DifferentialCase> {
    let mut cases = runtime_ord_set_boundary_cases();
    cases.extend(runtime_ord_set_auxiliary_cases());
    cases
}

fn runtime_ord_set_case(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    boundary: OrdSetBoundary,
) -> DifferentialCase {
    let observation = ord_set_observation(definition, builtin, boundary);
    let (raw_expression, canonical, stdout) = match &observation.result {
        OrdSetResult::Set(values) => (
            format!("Set.toList $ {}", observation.expression),
            ord_set_canonical(values),
            ord_sequence_stdout(definition, values),
        ),
        OrdSetResult::Bool(value) => (
            observation.expression.clone(),
            format!("{{\"type\":\"Bool\",\"value\":{value}}}"),
            format!("{}\n", if *value { "True" } else { "False" }),
        ),
    };
    let source = format!("{}main = IO.print $ {raw_expression}\n", definition.prelude);
    let mut descriptor = runtime_builtin_boundary_descriptor(builtin, path, &source);
    let target = &mut descriptor.semantic_targets[0];
    target.expected_instance_target = Some(Arc::from(definition.target));
    target.expected_instance_premises = definition
        .premises
        .iter()
        .map(|(target, premise_count)| crate::InstancePremiseEvidence {
            target: Arc::from(*target),
            premise_count: *premise_count,
        })
        .collect();
    let comparator_records = ord_set_boundary_comparator_contracts(definition, builtin, boundary);
    target.expected_comparator_trace_sha256 = Some(crate::comparator_trace_sha256(
        builtin,
        1,
        definition.target,
        &target.expected_instance_premises,
        &comparator_records,
    ));
    let typed = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{canonical}}}"
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(typed.as_bytes()));
    target.expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(stdout.as_bytes(), b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-ord-set-{}-{}-{path}",
            builtin.trim_start_matches("Set.").to_ascii_lowercase(),
            definition.slug,
        )),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn ord_set_observation(
    definition: &OrdListDefinition,
    builtin: &str,
    boundary: OrdSetBoundary,
) -> OrdSetObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let (lower_expression, upper_expression) =
        if builtin == "Set.fromList" && definition.slug == "set" {
            (
                "Set.insert (2 :: Int) $ Set.singleton 1",
                "Set.insert (3 :: Int) $ Set.singleton 1",
            )
        } else {
            (lower.expression.as_str(), upper.expression.as_str())
        };
    match builtin {
        "Set.fromList" => {
            ord_set_from_list_observation(definition, boundary, lower_expression, upper_expression)
        }
        "Set.insert" => ord_set_insert_observation(definition, boundary),
        "Set.member" => ord_set_member_observation(definition, boundary),
        "Set.delete" => ord_set_delete_observation(definition, boundary),
        "Set.union" => ord_set_union_observation(definition, boundary),
        "Set.difference" => ord_set_difference_observation(definition, boundary),
        "Set.intersection" => ord_set_intersection_observation(definition, boundary),
        _ => unreachable!("Ord/Set builtin inventory is exact"),
    }
}

fn ord_set_from_list_observation(
    definition: &OrdListDefinition,
    boundary: OrdSetBoundary,
    lower_expression: &str,
    upper_expression: &str,
) -> OrdSetObservation {
    match boundary {
        OrdSetBoundary::Empty => OrdSetObservation {
            expression: format!("Set.fromList ([] :: [{}])", definition.type_expression),
            result: OrdSetResult::Set(Vec::new()),
        },
        OrdSetBoundary::Singleton => OrdSetObservation {
            expression: format!("Set.fromList [{lower_expression}]"),
            result: OrdSetResult::Set(vec![definition.lower.clone()]),
        },
        OrdSetBoundary::Finite => OrdSetObservation {
            expression: format!(
                "Set.fromList [{upper_expression}, {lower_expression}, {upper_expression}]"
            ),
            result: OrdSetResult::Set(vec![definition.lower.clone(), definition.upper.clone()]),
        },
    }
}

fn ord_set_insert_observation(
    definition: &OrdListDefinition,
    boundary: OrdSetBoundary,
) -> OrdSetObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    match boundary {
        OrdSetBoundary::Empty => OrdSetObservation {
            expression: format!(
                "Set.insert ({}) $ Set.fromList ([] :: [{}])",
                lower.expression, definition.type_expression,
            ),
            result: OrdSetResult::Set(vec![lower.clone()]),
        },
        OrdSetBoundary::Singleton => OrdSetObservation {
            expression: format!(
                "Set.insert ({}) $ Set.fromList [{}]",
                upper.expression, lower.expression,
            ),
            result: OrdSetResult::Set(vec![lower.clone(), upper.clone()]),
        },
        OrdSetBoundary::Finite => OrdSetObservation {
            expression: format!(
                "Set.insert ({}) $ Set.fromList [{}, {}]",
                upper.expression, lower.expression, upper.expression,
            ),
            result: OrdSetResult::Set(vec![lower.clone(), upper.clone()]),
        },
    }
}

fn ord_set_member_observation(
    definition: &OrdListDefinition,
    boundary: OrdSetBoundary,
) -> OrdSetObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    match boundary {
        OrdSetBoundary::Empty => OrdSetObservation {
            expression: format!(
                "Set.member ({}) $ Set.fromList ([] :: [{}])",
                lower.expression, definition.type_expression,
            ),
            result: OrdSetResult::Bool(false),
        },
        OrdSetBoundary::Singleton => OrdSetObservation {
            expression: format!(
                "Set.member ({}) $ Set.fromList [{}]",
                lower.expression, lower.expression,
            ),
            result: OrdSetResult::Bool(true),
        },
        OrdSetBoundary::Finite => OrdSetObservation {
            expression: format!(
                "Set.member ({}) $ Set.fromList [{}, {}]",
                upper.expression, lower.expression, upper.expression,
            ),
            result: OrdSetResult::Bool(true),
        },
    }
}

fn ord_set_delete_observation(
    definition: &OrdListDefinition,
    boundary: OrdSetBoundary,
) -> OrdSetObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    match boundary {
        OrdSetBoundary::Empty => OrdSetObservation {
            expression: format!(
                "Set.delete ({}) $ Set.fromList ([] :: [{}])",
                lower.expression, definition.type_expression,
            ),
            result: OrdSetResult::Set(Vec::new()),
        },
        OrdSetBoundary::Singleton => OrdSetObservation {
            expression: format!(
                "Set.delete ({}) $ Set.fromList [{}]",
                lower.expression, lower.expression,
            ),
            result: OrdSetResult::Set(Vec::new()),
        },
        OrdSetBoundary::Finite => OrdSetObservation {
            expression: format!(
                "Set.delete ({}) $ Set.fromList [{}, {}]",
                upper.expression, lower.expression, upper.expression,
            ),
            result: OrdSetResult::Set(vec![lower.clone()]),
        },
    }
}

fn ord_set_union_observation(
    definition: &OrdListDefinition,
    boundary: OrdSetBoundary,
) -> OrdSetObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    match boundary {
        OrdSetBoundary::Empty => OrdSetObservation {
            expression: format!(
                "Set.union (Set.fromList ([] :: [{}])) (Set.fromList [])",
                definition.type_expression,
            ),
            result: OrdSetResult::Set(Vec::new()),
        },
        OrdSetBoundary::Singleton => OrdSetObservation {
            expression: format!(
                "Set.union (Set.fromList [{}]) (Set.fromList [])",
                lower.expression,
            ),
            result: OrdSetResult::Set(vec![lower.clone()]),
        },
        OrdSetBoundary::Finite => OrdSetObservation {
            expression: format!(
                "Set.union (Set.fromList [{}]) (Set.fromList [{}])",
                lower.expression, upper.expression,
            ),
            result: OrdSetResult::Set(vec![lower.clone(), upper.clone()]),
        },
    }
}

fn ord_set_difference_observation(
    definition: &OrdListDefinition,
    boundary: OrdSetBoundary,
) -> OrdSetObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    match boundary {
        OrdSetBoundary::Empty => OrdSetObservation {
            expression: format!(
                "Set.difference (Set.fromList ([] :: [{}])) (Set.fromList [])",
                definition.type_expression,
            ),
            result: OrdSetResult::Set(Vec::new()),
        },
        OrdSetBoundary::Singleton => OrdSetObservation {
            expression: format!(
                "Set.difference (Set.fromList [{}]) (Set.fromList [])",
                lower.expression,
            ),
            result: OrdSetResult::Set(vec![lower.clone()]),
        },
        OrdSetBoundary::Finite => OrdSetObservation {
            expression: format!(
                "Set.difference (Set.fromList [{}, {}]) (Set.fromList [{}])",
                lower.expression, upper.expression, upper.expression,
            ),
            result: OrdSetResult::Set(vec![lower.clone()]),
        },
    }
}

fn ord_set_intersection_observation(
    definition: &OrdListDefinition,
    boundary: OrdSetBoundary,
) -> OrdSetObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    match boundary {
        OrdSetBoundary::Empty => OrdSetObservation {
            expression: format!(
                "Set.intersection (Set.fromList ([] :: [{}])) (Set.fromList [])",
                definition.type_expression,
            ),
            result: OrdSetResult::Set(Vec::new()),
        },
        OrdSetBoundary::Singleton => OrdSetObservation {
            expression: format!(
                "Set.intersection (Set.fromList [{}]) (Set.fromList [{}])",
                lower.expression, lower.expression,
            ),
            result: OrdSetResult::Set(vec![lower.clone()]),
        },
        OrdSetBoundary::Finite => OrdSetObservation {
            expression: format!(
                "Set.intersection (Set.fromList [{}, {}]) (Set.fromList [{}])",
                lower.expression, upper.expression, upper.expression,
            ),
            result: OrdSetResult::Set(vec![upper.clone()]),
        },
    }
}

fn ord_set_canonical(values: &[OrdListValue]) -> String {
    format!(
        "{{\"type\":\"Set\",\"elements\":[{}]}}",
        values
            .iter()
            .map(|value| value.canonical.as_str())
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn ord_sequence_stdout(definition: &OrdListDefinition, values: &[OrdListValue]) -> String {
    if definition.target == "Char" {
        return format!("{}\n", reviewed_haskell_character_sequence(values));
    }
    format!(
        "[{}]\n",
        values
            .iter()
            .map(|value| value.rendered.as_str())
            .collect::<Vec<_>>()
            .join(","),
    )
}

const ORD_SET_DOUBLE_PRELUDE: &str = concat!(
    "negativeZero = Maybe.maybe (Error.error \"negative zero\") Function.id $ Double.readMaybe \"-0.0\"\n",
    "nan = Maybe.maybe (Error.error \"nan\") Function.id $ Double.readMaybe \"NaN\"\n",
);

fn runtime_ord_set_auxiliary_cases() -> Vec<DifferentialCase> {
    let definitions = ord_list_definitions();
    let ci = definitions
        .iter()
        .find(|definition| definition.slug == "ci")
        .expect("Ord CI definition exists");
    let int = definitions
        .iter()
        .find(|definition| definition.slug == "int")
        .expect("Ord Int definition exists");
    let mut double = definitions
        .iter()
        .find(|definition| definition.slug == "double")
        .expect("Ord Double definition exists")
        .clone();
    double.prelude = ORD_SET_DOUBLE_PRELUDE;

    let mut cases = runtime_ord_set_representative_cases(ci, &double);
    cases.extend(runtime_ord_set_unary_path_cases(int));
    cases.extend(runtime_ord_set_create_chunk_cases(&double));
    cases.extend(runtime_ord_set_binary_cases(ci, int, &double));
    cases.extend(runtime_ord_set_nan_mutation_paths(&double));
    cases.extend(runtime_ord_set_identity_preservation_paths(&double));
    cases.extend(runtime_ord_set_source_branch_cases(ci, int, &double));
    cases
}

fn runtime_ord_set_representative_cases(
    ci: &OrdListDefinition,
    double: &OrdListDefinition,
) -> Vec<DifferentialCase> {
    let ci_abc = ord_list_ci_value("AbC");
    let ci_abc_folded = ord_list_ci_value("aBc");
    let positive_zero = ord_set_double_value(0.0);
    let negative_zero = ord_list_double_value("Main.negativeZero", "-0.0", "8000000000000000");
    vec![
        ord_set_auxiliary_case(
            ci,
            "Set.fromList",
            "equal-representative-forward",
            "Set.fromList [CI.mk \"AbC\", CI.mk \"aBc\"]".to_owned(),
            OrdSetResult::Set(vec![ci_abc_folded.clone()]),
        ),
        ord_set_auxiliary_case(
            ci,
            "Set.fromList",
            "equal-representative-reverse",
            "Set.fromList [CI.mk \"aBc\", CI.mk \"AbC\"]".to_owned(),
            OrdSetResult::Set(vec![ci_abc.clone()]),
        ),
        ord_set_auxiliary_case(
            double,
            "Set.fromList",
            "signed-zero-forward",
            "Set.fromList [0.0, Main.negativeZero]".to_owned(),
            OrdSetResult::Set(vec![negative_zero.clone()]),
        ),
        ord_set_auxiliary_case(
            double,
            "Set.fromList",
            "signed-zero-reverse",
            "Set.fromList [Main.negativeZero, 0.0]".to_owned(),
            OrdSetResult::Set(vec![positive_zero.clone()]),
        ),
        ord_set_auxiliary_case(
            ci,
            "Set.insert",
            "equal-representative-replacement",
            "Set.insert (CI.mk \"aBc\") $ Set.fromList [CI.mk \"AbC\"]".to_owned(),
            OrdSetResult::Set(vec![ci_abc_folded]),
        ),
        ord_set_auxiliary_case(
            double,
            "Set.insert",
            "signed-zero-replacement",
            "Set.insert Main.negativeZero $ Set.fromList [0.0]".to_owned(),
            OrdSetResult::Set(vec![negative_zero]),
        ),
    ]
}

fn runtime_ord_set_unary_path_cases(int: &OrdListDefinition) -> Vec<DifferentialCase> {
    vec![
        ord_set_auxiliary_case(
            int,
            "Set.insert",
            "absent-left",
            "Set.insert (0 :: Int) $ Set.fromList [1,3]".to_owned(),
            OrdSetResult::Set(vec![
                ord_set_int_value(0),
                ord_set_int_value(1),
                ord_set_int_value(3),
            ]),
        ),
        ord_set_auxiliary_case(
            int,
            "Set.insert",
            "absent-right",
            "Set.insert (4 :: Int) $ Set.fromList [1,3]".to_owned(),
            OrdSetResult::Set(vec![
                ord_set_int_value(1),
                ord_set_int_value(3),
                ord_set_int_value(4),
            ]),
        ),
        ord_set_auxiliary_case(
            int,
            "Set.member",
            "nonempty-miss",
            "Set.member (2 :: Int) $ Set.fromList [1,3]".to_owned(),
            OrdSetResult::Bool(false),
        ),
        ord_set_auxiliary_case(
            int,
            "Set.delete",
            "nonempty-miss",
            "Set.delete (2 :: Int) $ Set.fromList [1,3]".to_owned(),
            OrdSetResult::Set(vec![ord_set_int_value(1), ord_set_int_value(3)]),
        ),
        ord_set_auxiliary_case(
            int,
            "Set.delete",
            "two-child-interior",
            "Set.delete (4 :: Int) $ Set.fromList [1,2,3,4,5,6,7]".to_owned(),
            OrdSetResult::Set(vec![
                ord_set_int_value(1),
                ord_set_int_value(2),
                ord_set_int_value(3),
                ord_set_int_value(5),
                ord_set_int_value(6),
                ord_set_int_value(7),
            ]),
        ),
    ]
}

fn runtime_ord_set_source_branch_cases(
    ci: &OrdListDefinition,
    int: &OrdListDefinition,
    double: &OrdListDefinition,
) -> Vec<DifferentialCase> {
    let ci_abc = ord_list_ci_value("AbC");
    let ci_next = ord_list_ci_value("aBd");
    let ci_zzz = ord_list_ci_value("zzz");
    let negative_zero = ord_list_double_value("Main.negativeZero", "-0.0", "8000000000000000");
    let mut cases = vec![
        ord_set_auxiliary_case(
            ci,
            "Set.union",
            "right-singleton-equal",
            concat!(
                "Set.union (Set.fromList [CI.mk \"AbC\",CI.mk \"aBd\"]) ",
                "(Set.fromList [CI.mk \"aBc\"])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![ci_abc.clone(), ci_next.clone()]),
        ),
        ord_set_auxiliary_case(
            ci,
            "Set.union",
            "left-singleton-equal",
            concat!(
                "Set.union (Set.fromList [CI.mk \"AbC\"]) ",
                "(Set.fromList [CI.mk \"aBc\",CI.mk \"aBd\"])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![ci_abc.clone(), ci_next.clone()]),
        ),
        ord_set_auxiliary_case(
            ci,
            "Set.union",
            "multi-equal-overlap",
            concat!(
                "Set.union (Set.fromList [CI.mk \"AbC\",CI.mk \"aBd\"]) ",
                "(Set.fromList [CI.mk \"aBc\",CI.mk \"zzz\"])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![ci_abc.clone(), ci_next, ci_zzz]),
        ),
        ord_set_auxiliary_case(
            double,
            "Set.union",
            "right-singleton-signed-zero",
            concat!(
                "Set.union (Set.fromList [Main.negativeZero,1.0]) ",
                "(Set.fromList [0.0])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![negative_zero.clone(), ord_set_double_value(1.0)]),
        ),
        ord_set_auxiliary_case(
            double,
            "Set.union",
            "left-singleton-signed-zero",
            concat!(
                "Set.union (Set.fromList [Main.negativeZero]) ",
                "(Set.fromList [0.0,1.0])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![negative_zero, ord_set_double_value(1.0)]),
        ),
    ];
    cases.extend(runtime_ord_set_source_difference_cases(ci, int));
    cases
}

fn runtime_ord_set_source_difference_cases(
    ci: &OrdListDefinition,
    int: &OrdListDefinition,
) -> Vec<DifferentialCase> {
    let ci_abc = ord_list_ci_value("AbC");
    vec![
        ord_set_int_binary_case(
            int,
            "Set.difference",
            "identical",
            "Set.difference (Set.fromList [1,2,3]) (Set.fromList [1,2,3])",
            &[],
        ),
        ord_set_int_binary_case(
            int,
            "Set.difference",
            "right-superset",
            "Set.difference (Set.fromList [2,3]) (Set.fromList [1,2,3,4])",
            &[],
        ),
        ord_set_int_binary_case(
            int,
            "Set.difference",
            "left-skewed",
            "Set.difference (Set.fromList [1,2,3,4,5,6]) (Set.fromList [2])",
            &[1, 3, 4, 5, 6],
        ),
        ord_set_int_binary_case(
            int,
            "Set.difference",
            "right-skewed",
            "Set.difference (Set.fromList [2,4]) (Set.fromList [1,2,3,4,5,6])",
            &[],
        ),
        ord_set_int_binary_case(
            int,
            "Set.intersection",
            "left-skewed",
            "Set.intersection (Set.fromList [1,2,3,4,5,6]) (Set.fromList [2])",
            &[2],
        ),
        ord_set_int_binary_case(
            int,
            "Set.intersection",
            "right-skewed",
            "Set.intersection (Set.fromList [2]) (Set.fromList [1,2,3,4,5,6])",
            &[2],
        ),
        ord_set_auxiliary_case(
            ci,
            "Set.intersection",
            "multi-equal-overlap",
            concat!(
                "Set.intersection (Set.fromList [CI.mk \"AbC\",CI.mk \"aBd\"]) ",
                "(Set.fromList [CI.mk \"aBc\",CI.mk \"zzz\"])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![ci_abc]),
        ),
    ]
}

fn runtime_ord_set_binary_cases(
    ci: &OrdListDefinition,
    int: &OrdListDefinition,
    double: &OrdListDefinition,
) -> Vec<DifferentialCase> {
    let ci_abc = ord_list_ci_value("AbC");
    let ci_abc_folded = ord_list_ci_value("aBc");
    let positive_zero = ord_set_double_value(0.0);
    let negative_zero = ord_list_double_value("Main.negativeZero", "-0.0", "8000000000000000");
    let mut cases = vec![
        ord_set_auxiliary_case(
            ci,
            "Set.union",
            "left-representative-forward",
            "Set.union (Set.fromList [CI.mk \"AbC\"]) (Set.fromList [CI.mk \"aBc\"])".to_owned(),
            OrdSetResult::Set(vec![ci_abc.clone()]),
        ),
        ord_set_auxiliary_case(
            ci,
            "Set.union",
            "left-representative-reverse",
            "Set.union (Set.fromList [CI.mk \"aBc\"]) (Set.fromList [CI.mk \"AbC\"])".to_owned(),
            OrdSetResult::Set(vec![ci_abc_folded.clone()]),
        ),
        ord_set_auxiliary_case(
            ci,
            "Set.intersection",
            "left-representative-forward",
            "Set.intersection (Set.fromList [CI.mk \"AbC\"]) (Set.fromList [CI.mk \"aBc\"])"
                .to_owned(),
            OrdSetResult::Set(vec![ci_abc]),
        ),
        ord_set_auxiliary_case(
            ci,
            "Set.intersection",
            "left-representative-reverse",
            "Set.intersection (Set.fromList [CI.mk \"aBc\"]) (Set.fromList [CI.mk \"AbC\"])"
                .to_owned(),
            OrdSetResult::Set(vec![ci_abc_folded]),
        ),
        ord_set_auxiliary_case(
            double,
            "Set.union",
            "signed-zero-left-forward",
            "Set.union (Set.fromList [Main.negativeZero]) (Set.fromList [0.0])".to_owned(),
            OrdSetResult::Set(vec![negative_zero.clone()]),
        ),
        ord_set_auxiliary_case(
            double,
            "Set.union",
            "signed-zero-left-reverse",
            "Set.union (Set.fromList [0.0]) (Set.fromList [Main.negativeZero])".to_owned(),
            OrdSetResult::Set(vec![positive_zero.clone()]),
        ),
        ord_set_auxiliary_case(
            double,
            "Set.intersection",
            "signed-zero-left-forward",
            "Set.intersection (Set.fromList [Main.negativeZero]) (Set.fromList [0.0])".to_owned(),
            OrdSetResult::Set(vec![negative_zero]),
        ),
        ord_set_auxiliary_case(
            double,
            "Set.intersection",
            "signed-zero-left-reverse",
            "Set.intersection (Set.fromList [0.0]) (Set.fromList [Main.negativeZero])".to_owned(),
            OrdSetResult::Set(vec![positive_zero]),
        ),
    ];
    cases.extend(runtime_ord_set_integer_binary_cases(int));
    cases
}

fn runtime_ord_set_integer_binary_cases(int: &OrdListDefinition) -> Vec<DifferentialCase> {
    vec![
        ord_set_int_binary_case(
            int,
            "Set.union",
            "empty-left",
            "Set.union (Set.fromList ([] :: [Int])) (Set.fromList [1,3])",
            &[1, 3],
        ),
        ord_set_int_binary_case(
            int,
            "Set.union",
            "empty-right",
            "Set.union (Set.fromList [1,3]) (Set.fromList ([] :: [Int]))",
            &[1, 3],
        ),
        ord_set_int_binary_case(
            int,
            "Set.union",
            "disjoint-left-small",
            "Set.union (Set.fromList [1]) (Set.fromList [2,3,4])",
            &[1, 2, 3, 4],
        ),
        ord_set_int_binary_case(
            int,
            "Set.union",
            "disjoint-right-small",
            "Set.union (Set.fromList [1,2,3]) (Set.fromList [4])",
            &[1, 2, 3, 4],
        ),
        ord_set_int_binary_case(
            int,
            "Set.union",
            "overlap",
            "Set.union (Set.fromList [1,3,5]) (Set.fromList [2,3,4])",
            &[1, 2, 3, 4, 5],
        ),
        ord_set_int_binary_case(
            int,
            "Set.difference",
            "empty-left",
            "Set.difference (Set.fromList ([] :: [Int])) (Set.fromList [1,3])",
            &[],
        ),
        ord_set_int_binary_case(
            int,
            "Set.difference",
            "empty-right",
            "Set.difference (Set.fromList [1,3]) (Set.fromList ([] :: [Int]))",
            &[1, 3],
        ),
        ord_set_int_binary_case(
            int,
            "Set.difference",
            "disjoint",
            "Set.difference (Set.fromList [1,3]) (Set.fromList [2,4])",
            &[1, 3],
        ),
        ord_set_int_binary_case(
            int,
            "Set.difference",
            "overlap",
            "Set.difference (Set.fromList [1,2,3,4]) (Set.fromList [2,4])",
            &[1, 3],
        ),
        ord_set_int_binary_case(
            int,
            "Set.intersection",
            "empty-left",
            "Set.intersection (Set.fromList ([] :: [Int])) (Set.fromList [1,3])",
            &[],
        ),
        ord_set_int_binary_case(
            int,
            "Set.intersection",
            "empty-right",
            "Set.intersection (Set.fromList [1,3]) (Set.fromList ([] :: [Int]))",
            &[],
        ),
        ord_set_int_binary_case(
            int,
            "Set.intersection",
            "disjoint",
            "Set.intersection (Set.fromList [1,3]) (Set.fromList [2,4])",
            &[],
        ),
        ord_set_int_binary_case(
            int,
            "Set.intersection",
            "overlap",
            "Set.intersection (Set.fromList [1,3,5]) (Set.fromList [2,3,4])",
            &[3],
        ),
    ]
}

fn ord_set_int_binary_case(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    expression: &str,
    output: &[i64],
) -> DifferentialCase {
    ord_set_auxiliary_case(
        definition,
        builtin,
        path,
        expression.to_owned(),
        OrdSetResult::Set(output.iter().copied().map(ord_set_int_value).collect()),
    )
}

fn runtime_ord_set_nan_mutation_paths(definition: &OrdListDefinition) -> Vec<DifferentialCase> {
    let nan = || ord_set_named_double_value("nan");
    let number = ord_set_double_value;
    let mut cases = vec![
        ord_set_auxiliary_case(
            definition,
            "Set.delete",
            "nan-routing-miss",
            concat!(
                "Set.delete Main.nan $ Set.fromList ",
                "[Main.nan,1.0,Main.nan,0.0,Main.nan,Main.nan,",
                "Main.nan,Main.nan,3.0,2.0,0.0]",
            )
            .to_owned(),
            OrdSetResult::Set(vec![
                nan(),
                number(1.0),
                nan(),
                number(0.0),
                nan(),
                nan(),
                nan(),
                nan(),
                number(2.0),
                number(3.0),
            ]),
        ),
        ord_set_auxiliary_case(
            definition,
            "Set.union",
            "nan-shape-routing",
            concat!(
                "Set.union (Set.fromList [Main.nan,1.0,0.0,3.0]) ",
                "(Set.fromList [2.0,0.0,Main.nan])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![
                nan(),
                number(0.0),
                number(2.0),
                nan(),
                number(1.0),
                number(3.0),
            ]),
        ),
        ord_set_auxiliary_case(
            definition,
            "Set.union",
            "nan-shape-routing-reverse",
            concat!(
                "Set.union (Set.fromList [2.0,0.0,Main.nan]) ",
                "(Set.fromList [Main.nan,1.0,0.0,3.0])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![
                nan(),
                number(0.0),
                number(1.0),
                number(2.0),
                nan(),
                number(3.0),
            ]),
        ),
    ];
    cases.extend(runtime_ord_set_nan_difference_paths(definition));
    cases
}

fn runtime_ord_set_nan_difference_paths(definition: &OrdListDefinition) -> Vec<DifferentialCase> {
    let nan = || ord_set_named_double_value("nan");
    let number = ord_set_double_value;
    vec![
        ord_set_auxiliary_case(
            definition,
            "Set.difference",
            "nan-shape-routing",
            concat!(
                "Set.difference (Set.fromList [Main.nan,1.0,0.0,3.0,2.0]) ",
                "(Set.fromList [2.0,0.0,Main.nan])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![nan(), number(1.0), number(3.0)]),
        ),
        ord_set_auxiliary_case(
            definition,
            "Set.difference",
            "nan-shape-routing-reverse",
            concat!(
                "Set.difference (Set.fromList [2.0,0.0,Main.nan]) ",
                "(Set.fromList [Main.nan,1.0,0.0,3.0,2.0])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![number(2.0), nan()]),
        ),
        ord_set_auxiliary_case(
            definition,
            "Set.intersection",
            "nan-shape-routing",
            concat!(
                "Set.intersection (Set.fromList [Main.nan,1.0,0.0,3.0,2.0]) ",
                "(Set.fromList [2.0,0.0,Main.nan])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![number(0.0)]),
        ),
        ord_set_auxiliary_case(
            definition,
            "Set.intersection",
            "nan-shape-routing-reverse",
            concat!(
                "Set.intersection (Set.fromList [2.0,0.0,Main.nan]) ",
                "(Set.fromList [Main.nan,1.0,0.0,3.0,2.0])",
            )
            .to_owned(),
            OrdSetResult::Set(vec![number(0.0), number(2.0)]),
        ),
    ]
}

fn runtime_ord_set_identity_preservation_paths(
    definition: &OrdListDefinition,
) -> Vec<DifferentialCase> {
    let nan = || ord_set_named_double_value("nan");
    let number = ord_set_double_value;
    let long_source = concat!(
        "[Main.nan,1.0,Main.nan,0.0,Main.nan,Main.nan,",
        "Main.nan,Main.nan,3.0,2.0,0.0]",
    );
    vec![
        ord_set_auxiliary_case(
            definition,
            "Set.union",
            "shared-tree-delete-routing",
            format!(
                "(\\set -> Set.delete Main.nan $ Set.union set set) $ Set.fromList {long_source}"
            ),
            OrdSetResult::Set(vec![
                nan(),
                nan(),
                number(1.0),
                nan(),
                nan(),
                number(0.0),
                nan(),
                nan(),
                nan(),
                nan(),
                number(2.0),
                number(3.0),
                nan(),
                nan(),
                nan(),
                nan(),
                number(2.0),
                number(3.0),
            ]),
        ),
        ord_set_auxiliary_case(
            definition,
            "Set.intersection",
            "shared-tree-delete-routing",
            format!(
                "(\\set -> Set.delete Main.nan $ Set.intersection set set) $ Set.fromList {long_source}"
            ),
            OrdSetResult::Set(vec![number(1.0), number(0.0)]),
        ),
        ord_set_auxiliary_consumed_bool_case(
            definition,
            "Set.difference",
            "disjoint-size-preserved-member-outcome",
            concat!(
                "(\\set -> Set.member 0.0 $ Set.difference set ",
                "(Set.fromList [8.0,9.0])) $ Set.fromList ",
                "[Main.nan,Main.nan,Main.nan,Main.nan,Main.nan,Main.nan,0.0,Main.nan]",
            )
            .to_owned(),
            &[nan(), nan(), nan(), nan(), nan(), nan(), number(0.0), nan()],
            true,
        ),
    ]
}

struct OrdSetAuxiliaryFacts {
    raw_expression: String,
    target_canonical: String,
    stdout: String,
}

fn ord_set_auxiliary_case(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    expression: String,
    result: OrdSetResult,
) -> DifferentialCase {
    let observation = OrdSetObservation { expression, result };
    let (raw_expression, target_canonical, stdout) = match &observation.result {
        OrdSetResult::Set(values) => (
            format!("Set.toList $ {}", observation.expression),
            ord_set_canonical(values),
            ord_sequence_stdout(definition, values),
        ),
        OrdSetResult::Bool(value) => (
            observation.expression.clone(),
            format!("{{\"type\":\"Bool\",\"value\":{value}}}"),
            format!("{}\n", if *value { "True" } else { "False" }),
        ),
    };
    ord_set_auxiliary_case_from_facts(
        definition,
        builtin,
        path,
        OrdSetAuxiliaryFacts {
            raw_expression,
            target_canonical,
            stdout,
        },
    )
}

fn ord_set_auxiliary_consumed_bool_case(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    expression: String,
    target_values: &[OrdListValue],
    observed: bool,
) -> DifferentialCase {
    ord_set_auxiliary_case_from_facts(
        definition,
        builtin,
        path,
        OrdSetAuxiliaryFacts {
            raw_expression: expression,
            target_canonical: ord_set_canonical(target_values),
            stdout: format!("{}\n", if observed { "True" } else { "False" }),
        },
    )
}

fn ord_set_auxiliary_case_from_facts(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    facts: OrdSetAuxiliaryFacts,
) -> DifferentialCase {
    let OrdSetAuxiliaryFacts {
        raw_expression,
        target_canonical,
        stdout,
    } = facts;
    let id = format!(
        "runtime-ord-set-{}-{}-{path}",
        builtin.trim_start_matches("Set.").to_ascii_lowercase(),
        definition.slug,
    );
    let source = format!("{}main = IO.print $ {raw_expression}\n", definition.prelude);
    let mut descriptor = runtime_single_typed_target_descriptor(builtin, &source);
    let target = &mut descriptor.semantic_targets[0];
    target.expected_instance_target = Some(Arc::from(definition.target));
    target.expected_instance_premises = definition
        .premises
        .iter()
        .map(|(target, premise_count)| crate::InstancePremiseEvidence {
            target: Arc::from(*target),
            premise_count: *premise_count,
        })
        .collect();
    let comparators =
        crate::reviewed_set::auxiliary_contracts(builtin, definition.slug, path, &target_canonical);
    target.expected_comparator_trace_sha256 = Some(crate::comparator_trace_sha256(
        builtin,
        1,
        definition.target,
        &target.expected_instance_premises,
        &comparators,
    ));
    let typed = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{target_canonical}}}"
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(typed.as_bytes()));
    target.expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(stdout.as_bytes(), b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_ord_set_create_chunk_cases(definition: &OrdListDefinition) -> Vec<DifferentialCase> {
    const SOURCES: &[(&str, &str, &[&str])] = &[
        (
            "create-chunk-1",
            "[1.0,1.0,2.0,3.0,Main.nan,4.0,5.0,Main.nan,6.0,0.0]",
            &["1", "2", "3", "nan", "0", "4", "5", "nan", "6"],
        ),
        (
            "create-chunk-2",
            "[1.0,2.0,2.0,3.0,4.0,Main.nan,5.0,6.0,7.0,0.0]",
            &["0", "1", "2", "3", "4", "nan", "5", "6", "7"],
        ),
        (
            "create-chunk-3",
            "[1.0,2.0,3.0,4.0,4.0,5.0,6.0,Main.nan,7.0,8.0,0.0]",
            &["0", "1", "2", "3", "4", "5", "6", "nan", "7", "8"],
        ),
        (
            "create-chunk-4",
            "[1.0,2.0,3.0,4.0,0.0,Main.nan,5.0,6.0]",
            &["0", "1", "2", "3", "4", "nan", "5", "6"],
        ),
        (
            "create-chunk-5",
            "[Main.nan,1.0,1.0,Main.nan,0.0,Main.nan,2.0,2.0,3.0]",
            &["nan", "0", "1", "nan", "nan", "2", "3"],
        ),
    ];
    SOURCES
        .iter()
        .map(|(path, source, output)| {
            ord_set_auxiliary_case(
                definition,
                "Set.fromList",
                path,
                format!("Set.fromList {source}"),
                OrdSetResult::Set(
                    output
                        .iter()
                        .map(|value| ord_set_named_double_value(value))
                        .collect(),
                ),
            )
        })
        .collect()
}

fn ord_set_named_double_value(value: &str) -> OrdListValue {
    if value == "nan" {
        return ord_list_double_value("Main.nan", "NaN", "7ff8000000000000");
    }
    let parsed = value.parse::<f64>().expect("fixed Double fixture parses");
    ord_set_double_value(parsed)
}

fn ord_set_double_value(value: f64) -> OrdListValue {
    ord_list_double_value(
        format!("{value:.1}"),
        format!("{value:.1}"),
        &format!("{:016x}", value.to_bits()),
    )
}

fn ord_set_int_value(value: i64) -> OrdListValue {
    ord_list_value(
        format!("({value} :: Int)"),
        value.to_string(),
        ord_list_int(value),
    )
}

fn runtime_io_pure_cases() -> Vec<DifferentialCase> {
    let mut demanded_int = runtime_io_success_case(
        "IO.pure",
        "runtime-io-pure-success",
        "main = do\n  value <- IO.pure (42 :: Int)\n  IO.print value\n",
        b"42\n",
    );
    for target in demanded_int
        .claim_evidence
        .as_mut()
        .expect("IO.pure descriptor")
        .semantic_targets
        .iter_mut()
        .filter(|target| target.dimension == CompatibilityDimension::PureRuntime)
    {
        target
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "lazy-boundary");
    }
    let demanded_text = runtime_io_pure_auxiliary_case(
        "runtime-io-pure-text",
        "main = do\n  value <- IO.pure \"aβ\"\n  Text.putStrLn value\n",
        "aβ\n".as_bytes(),
        false,
    );
    let ignored_bottom = runtime_io_pure_auxiliary_case(
        "runtime-io-pure-ignored-bottom",
        concat!(
            "main = do\n",
            "  _ <- IO.pure (Error.error \"undemanded pure\" :: Int)\n",
            "  Text.putStr \"after\"\n",
        ),
        b"after",
        true,
    );
    vec![demanded_int, demanded_text, ignored_bottom]
}

fn runtime_io_pure_auxiliary_case(
    id: &str,
    source: &str,
    stdout: &[u8],
    retain_lazy: bool,
) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor("IO.pure", source);
    descriptor
        .targets
        .retain(|target| target.dimension == CompatibilityDimension::PureRuntime);
    descriptor.semantic_targets.retain_mut(|target| {
        if target.dimension != CompatibilityDimension::PureRuntime {
            return false;
        }
        target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(stdout, b""));
        if retain_lazy {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() == "lazy-boundary");
            target.expected_lazy_argument_exit_sha256 =
                Some(crate::lazy_argument_exit_sha256([(0, "not-forced")]));
        } else {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "lazy-boundary");
        }
        true
    });
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_byte_string_io_operation_cases() -> Vec<DifferentialCase> {
    let arbitrary = vec![0xff, b'A'];
    let mut get_contents = runtime_io_success_case(
        "ByteString.getContents",
        "runtime-bytestring-get-contents-io",
        concat!(
            "main = do\n",
            "  bytes <- ByteString.getContents\n",
            "  ByteString.hPutStr IO.stdout bytes\n",
        ),
        &arbitrary,
    );
    get_contents.stdin = arbitrary;
    vec![
        get_contents,
        runtime_io_success_case(
            "ByteString.hGet",
            "runtime-bytestring-hget-io",
            concat!(
                "main = do\n",
                "  Text.writeFile \"input.txt\" \"abc\"\n",
                "  handle <- IO.openFile \"input.txt\" IO.ReadMode\n",
                "  bytes <- ByteString.hGet handle 2\n",
                "  IO.hClose handle\n",
                "  ByteString.hPutStr IO.stdout bytes\n",
            ),
            b"ab",
        ),
        runtime_io_success_case(
            "ByteString.hPutStr",
            "runtime-bytestring-hputstr-io",
            "main = ByteString.hPutStr IO.stdout $ Text.encodeUtf8 \"aβ\"\n",
            "aβ".as_bytes(),
        ),
    ]
}

fn runtime_io_traversal_cases() -> Vec<DifferentialCase> {
    [
        (
            "IO.mapM_",
            "mapm",
            "main = IO.mapM_ (\\value -> IO.print value) [1,2]\n",
            "main = IO.mapM_ (\\value -> if Int.eq value 2 then Error.error \"mapM failure\" else IO.pure ()) [1,2]\n",
            0,
        ),
        (
            "IO.forM_",
            "form",
            "main = IO.forM_ [1,2] (\\value -> IO.print value)\n",
            "main = IO.forM_ [1,2] (\\value -> if Int.eq value 2 then Error.error \"forM failure\" else IO.pure ())\n",
            1,
        ),
    ]
    .into_iter()
    .flat_map(|(builtin, id, success_source, failure_source, callback_argument)| {
        let mut success = runtime_io_success_case(
            builtin,
            &format!("runtime-io-{id}-success"),
            success_source,
            b"1\n2\n",
        );
        success
            .claim_evidence
            .as_mut()
            .expect("IO traversal success descriptor")
            .callback_contracts = vec![CallbackContract {
            builtin: Arc::from(builtin),
            invocations: [1, 2]
                .into_iter()
                .map(|value| {
                    callback_contract_invocation(
                        callback_argument,
                        "element",
                        &[&format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}")],
                        "{\"type\":\"IoAction\"}",
                    )
                })
                .collect(),
        }];
        [
            success,
            runtime_io_failure_case(
                builtin,
                &format!("runtime-io-{id}-failure"),
                failure_source,
            ),
        ]
    })
    .collect()
}

fn runtime_io_success_case(
    builtin: &str,
    id: &str,
    source: &str,
    stdout: &[u8],
) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    for target in &mut descriptor.semantic_targets {
        if matches!(
            target.dimension,
            CompatibilityDimension::PureRuntime | CompatibilityDimension::Presentation
        ) {
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        }
        if target.dimension == CompatibilityDimension::PureRuntime {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "adapter-failure");
        }
        if target.dimension == CompatibilityDimension::Effects {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "effect-failure");
        }
    }
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_thread_delay_cases() -> Vec<DifferentialCase> {
    const DIRECT_SOURCE: &str = concat!(
        "main = do\n",
        "  Concurrent.threadDelay 1000\n",
        "  Text.putStr \"completed\"\n",
    );
    const TIMEOUT_SOURCE: &str = concat!(
        "main = do\n",
        "  result <- Timeout.timeout 100000 $ Concurrent.threadDelay 1000000\n",
        "  IO.print $ Maybe.maybe Bool.False (\\_ -> Bool.True) result\n",
    );
    const FAILURE_SOURCE: &str =
        "main = Concurrent.threadDelay (Error.error \"reviewed delay failure\" :: Int)\n";
    let mut direct = runtime_io_success_case(
        "Concurrent.threadDelay",
        "runtime-typed-thread-delay-completed",
        DIRECT_SOURCE,
        b"completed",
    );
    bind_single_task_lifecycle(&mut direct, &["started", "completed"]);

    let mut timeout_descriptor =
        runtime_all_obligation_descriptor("Concurrent.threadDelay", TIMEOUT_SOURCE);
    timeout_descriptor
        .targets
        .retain(|target| target.dimension == CompatibilityDimension::PureRuntime);
    timeout_descriptor.semantic_targets.retain_mut(|target| {
        if target.dimension != CompatibilityDimension::PureRuntime {
            return false;
        }
        target.expected_raw_presentation_sha256 =
            Some(crate::raw_presentation_sha256(b"False\n", b""));
        target.expected_single_effect_lifecycle_sha256 =
            Some(crate::single_effect_lifecycle_sha256([
                "started",
                "cancelled",
            ]));
        true
    });
    let mut timeout = DifferentialCase {
        id: Arc::from("runtime-typed-thread-delay-timeout"),
        source: Arc::from(TIMEOUT_SOURCE),
        claim_evidence: Some(timeout_descriptor),
        ..DifferentialCase::default()
    };
    bind_single_task_lifecycle(&mut timeout, &["started", "cancelled"]);

    let mut forced_argument_failure = runtime_io_failure_case(
        "Concurrent.threadDelay",
        "runtime-typed-thread-delay-forced-argument-failure",
        FAILURE_SOURCE,
    );
    bind_single_task_lifecycle(&mut forced_argument_failure, &["started", "failed"]);
    vec![direct, timeout, forced_argument_failure]
}

fn bind_single_task_lifecycle(case: &mut DifferentialCase, events: &[&str]) {
    let expected = crate::single_task_lifecycle_sha256(events.iter().copied());
    for target in &mut case
        .claim_evidence
        .as_mut()
        .expect("task lifecycle case descriptor")
        .semantic_targets
    {
        target.expected_single_task_lifecycle_sha256 = Some(expected);
    }
}

fn runtime_timeout_cases() -> Vec<DifferentialCase> {
    let definitions = [
        RuntimeTimeoutDefinition {
            id: "zero-no-force",
            source: concat!(
                "main = do\n",
                "  result <- Timeout.timeout 0 (Error.error \"must not force\" :: IO Int)\n",
                "  IO.print $ Maybe.maybe Bool.False (\\_ -> Bool.True) result\n",
            ),
            stdout: Some(b"False\n"),
            task_lifecycle: None,
            keep_concurrency: false,
            keep_platform_resource: false,
        },
        RuntimeTimeoutDefinition {
            id: "negative-completed",
            source: concat!(
                "main = do\n",
                "  result <- Timeout.timeout (Int.subtract 1 0) (IO.pure 7)\n",
                "  IO.print $ Maybe.maybe 0 (\\value -> value) result\n",
            ),
            stdout: Some(b"7\n"),
            task_lifecycle: None,
            keep_concurrency: false,
            keep_platform_resource: false,
        },
        RuntimeTimeoutDefinition {
            id: "positive-completed",
            source: concat!(
                "main = do\n",
                "  result <- Timeout.timeout 100000 (IO.pure 7)\n",
                "  IO.print $ Maybe.maybe 0 (\\value -> value) result\n",
            ),
            stdout: Some(b"7\n"),
            task_lifecycle: Some(&["started", "completed"]),
            keep_concurrency: false,
            keep_platform_resource: false,
        },
        RuntimeTimeoutDefinition {
            id: "positive-expired",
            source: concat!(
                "main = do\n",
                "  result <- Timeout.timeout 100000 $ Concurrent.threadDelay 1000000\n",
                "  IO.print $ Maybe.maybe Bool.False (\\_ -> Bool.True) result\n",
            ),
            stdout: Some(b"False\n"),
            task_lifecycle: Some(&["started", "cancelled"]),
            keep_concurrency: true,
            keep_platform_resource: true,
        },
        RuntimeTimeoutDefinition {
            id: "positive-action-failure",
            source: concat!(
                "main = do\n",
                "  _result <- Timeout.timeout 100000 (Error.error \"reviewed\" :: IO Int)\n",
                "  IO.pure ()\n",
            ),
            stdout: None,
            task_lifecycle: Some(&["started", "failed"]),
            keep_concurrency: false,
            keep_platform_resource: false,
        },
    ];
    definitions.into_iter().map(runtime_timeout_case).collect()
}

#[derive(Clone, Copy)]
struct RuntimeTimeoutDefinition {
    id: &'static str,
    source: &'static str,
    stdout: Option<&'static [u8]>,
    task_lifecycle: Option<&'static [&'static str]>,
    keep_concurrency: bool,
    keep_platform_resource: bool,
}

fn runtime_timeout_case(definition: RuntimeTimeoutDefinition) -> DifferentialCase {
    let success = definition.stdout.is_some();
    let mut descriptor = runtime_all_obligation_descriptor("Timeout.timeout", definition.source);
    descriptor.targets.retain(|target| {
        target.dimension == CompatibilityDimension::PureRuntime
            || (definition.task_lifecycle.is_some()
                && target.dimension == CompatibilityDimension::Effects)
            || (definition.keep_concurrency
                && target.dimension == CompatibilityDimension::Concurrency)
            || (definition.keep_platform_resource
                && matches!(
                    target.dimension,
                    CompatibilityDimension::Platform | CompatibilityDimension::ResourceBehavior
                ))
    });
    descriptor.semantic_targets.retain_mut(|target| {
        if !descriptor.targets.iter().any(|retained| {
            retained.builtin == target.builtin && retained.dimension == target.dimension
        }) {
            return false;
        }
        target.expected_process_status_sha256 = Some(crate::process_status_sha256(
            success,
            Some(i32::from(!success)),
        ));
        if target.dimension == CompatibilityDimension::PureRuntime
            && let Some(stdout) = definition.stdout
        {
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        }
        if definition.id == "zero-no-force"
            && target.dimension == CompatibilityDimension::PureRuntime
        {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "io-execution-boundary");
        }
        if target.dimension == CompatibilityDimension::Effects {
            let omitted = if success {
                "effect-failure"
            } else {
                "effect-success"
            };
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != omitted);
            target.expected_single_effect_lifecycle_sha256 =
                Some(crate::single_effect_lifecycle_sha256(if success {
                    ["started", "completed"]
                } else {
                    ["started", "failed"]
                }));
        }
        if let Some(events) = definition.task_lifecycle {
            target.expected_single_task_lifecycle_sha256 =
                Some(crate::single_task_lifecycle_sha256(events.iter().copied()));
        }
        true
    });
    DifferentialCase {
        id: Arc::from(format!("runtime-typed-timeout-{}", definition.id)),
        source: Arc::from(definition.source),
        expected_runtime_completion: success,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_async_race_cases() -> Vec<DifferentialCase> {
    [
        RuntimeRaceDefinition {
            id: "left-completes",
            source: concat!(
                "slow = do\n",
                "  Concurrent.threadDelay 100000\n",
                "  IO.pure 8\n",
                "main = do\n",
                "  result <- Async.race (IO.pure 7) Main.slow\n",
                "  IO.print result\n",
            ),
            stdout: Some(b"Left 7\n"),
            task_trace: &[
                (0, "started"),
                (0, "completed"),
                (1, "started"),
                (1, "cancelled"),
            ],
        },
        RuntimeRaceDefinition {
            id: "right-completes",
            source: concat!(
                "slow = do\n",
                "  Concurrent.threadDelay 100000\n",
                "  IO.pure 8\n",
                "main = do\n",
                "  result <- Async.race Main.slow (IO.pure 9)\n",
                "  IO.print result\n",
            ),
            stdout: Some(b"Right 9\n"),
            task_trace: &[
                (0, "started"),
                (0, "cancelled"),
                (1, "started"),
                (1, "completed"),
            ],
        },
        RuntimeRaceDefinition {
            id: "left-fails",
            source: concat!(
                "slow = do\n",
                "  Concurrent.threadDelay 100000\n",
                "  IO.pure 8\n",
                "main = do\n",
                "  _result <- Async.race (Error.error \"left\" :: IO Int) Main.slow\n",
                "  IO.pure ()\n",
            ),
            stdout: None,
            task_trace: &[
                (0, "started"),
                (0, "failed"),
                (1, "started"),
                (1, "cancelled"),
            ],
        },
        RuntimeRaceDefinition {
            id: "right-fails",
            source: concat!(
                "slow = do\n",
                "  Concurrent.threadDelay 100000\n",
                "  IO.pure 8\n",
                "main = do\n",
                "  _result <- Async.race Main.slow (Error.error \"right\" :: IO Int)\n",
                "  IO.pure ()\n",
            ),
            stdout: None,
            task_trace: &[
                (0, "started"),
                (0, "cancelled"),
                (1, "started"),
                (1, "failed"),
            ],
        },
    ]
    .into_iter()
    .map(|definition| runtime_async_pair_case("Async.race", "async-race", definition))
    .collect()
}

fn runtime_async_concurrently_cases() -> Vec<DifferentialCase> {
    [
        RuntimeRaceDefinition {
            id: "right-completes-first",
            source: concat!(
                "left = do\n",
                "  Concurrent.threadDelay 100000\n",
                "  IO.pure 7\n",
                "main = do\n",
                "  result <- Async.concurrently Main.left (IO.pure 9)\n",
                "  IO.print result\n",
            ),
            stdout: Some(b"(7,9)\n"),
            task_trace: &[
                (0, "started"),
                (0, "completed"),
                (1, "started"),
                (1, "completed"),
            ],
        },
        RuntimeRaceDefinition {
            id: "left-completes-first",
            source: concat!(
                "right = do\n",
                "  Concurrent.threadDelay 100000\n",
                "  IO.pure 9\n",
                "main = do\n",
                "  result <- Async.concurrently (IO.pure 7) Main.right\n",
                "  IO.print result\n",
            ),
            stdout: Some(b"(7,9)\n"),
            task_trace: &[
                (0, "started"),
                (0, "completed"),
                (1, "started"),
                (1, "completed"),
            ],
        },
        RuntimeRaceDefinition {
            id: "left-fails",
            source: concat!(
                "right = do\n",
                "  Concurrent.threadDelay 100000\n",
                "  IO.pure 9\n",
                "main = do\n",
                "  _result <- Async.concurrently (Error.error \"left\" :: IO Int) Main.right\n",
                "  IO.pure ()\n",
            ),
            stdout: None,
            task_trace: &[
                (0, "started"),
                (0, "failed"),
                (1, "started"),
                (1, "cancelled"),
            ],
        },
        RuntimeRaceDefinition {
            id: "right-fails",
            source: concat!(
                "left = do\n",
                "  Concurrent.threadDelay 100000\n",
                "  IO.pure 7\n",
                "main = do\n",
                "  _result <- Async.concurrently Main.left (Error.error \"right\" :: IO Int)\n",
                "  IO.pure ()\n",
            ),
            stdout: None,
            task_trace: &[
                (0, "started"),
                (0, "cancelled"),
                (1, "started"),
                (1, "failed"),
            ],
        },
    ]
    .into_iter()
    .map(|definition| {
        runtime_async_pair_case("Async.concurrently", "async-concurrently", definition)
    })
    .collect()
}

#[cfg(all(test, feature = "compat-tracing"))]
#[derive(Clone, Copy)]
struct RuntimePooledDefinition {
    builtin: &'static str,
    slug: &'static str,
    callback_argument: u16,
    discard: bool,
}

#[cfg(all(test, feature = "compat-tracing"))]
pub(crate) fn runtime_async_pooled_cases() -> Vec<DifferentialCase> {
    [
        RuntimePooledDefinition {
            builtin: "Async.pooledMapConcurrently",
            slug: "pooled-map",
            callback_argument: 0,
            discard: false,
        },
        RuntimePooledDefinition {
            builtin: "Async.pooledForConcurrently",
            slug: "pooled-for",
            callback_argument: 1,
            discard: false,
        },
        RuntimePooledDefinition {
            builtin: "Async.pooledMapConcurrently_",
            slug: "pooled-map-discard",
            callback_argument: 0,
            discard: true,
        },
        RuntimePooledDefinition {
            builtin: "Async.pooledForConcurrently_",
            slug: "pooled-for-discard",
            callback_argument: 1,
            discard: true,
        },
    ]
    .into_iter()
    .flat_map(|definition| {
        [
            runtime_async_pooled_case(definition, "success"),
            runtime_async_pooled_case(definition, "empty"),
            runtime_async_pooled_case(definition, "failure"),
        ]
    })
    .collect()
}

#[cfg(all(test, feature = "compat-tracing"))]
fn runtime_async_pooled_case(
    definition: RuntimePooledDefinition,
    path: &'static str,
) -> DifferentialCase {
    let path_definition = runtime_async_pooled_path(definition, path);
    let RuntimePooledPath {
        source,
        stdout,
        completion,
        task_trace,
        callbacks,
    } = path_definition;
    let mut descriptor = runtime_all_obligation_descriptor(definition.builtin, &source);
    if path == "empty" {
        descriptor
            .targets
            .retain(|target| target.dimension == CompatibilityDimension::PureRuntime);
    }
    descriptor.semantic_targets.retain_mut(|target| {
        if path == "empty" && target.dimension != CompatibilityDimension::PureRuntime {
            return false;
        }
        target.expected_process_status_sha256 = Some(crate::process_status_sha256(
            completion,
            Some(i32::from(!completion)),
        ));
        target.expected_task_trace_sha256 =
            Some(crate::task_trace_sha256(task_trace.iter().copied()));
        if target.dimension == CompatibilityDimension::PureRuntime {
            let stderr = if path == "failure" {
                pinned_user_error_stderr("pooled failure")
            } else {
                Vec::new()
            };
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, &stderr));
            if path == "empty" {
                target.obligations.retain(|obligation| {
                    !matches!(
                        obligation.0.as_ref(),
                        "callback-order" | "io-execution-boundary"
                    )
                });
            }
        }
        if target.dimension == CompatibilityDimension::Effects {
            let omitted = if completion {
                "effect-failure"
            } else {
                "effect-success"
            };
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != omitted);
            target.expected_single_effect_lifecycle_sha256 =
                Some(crate::single_effect_lifecycle_sha256(if completion {
                    ["started", "completed"]
                } else {
                    ["started", "failed"]
                }));
        }
        true
    });
    descriptor.callback_contracts = vec![CallbackContract {
        builtin: Arc::from(definition.builtin),
        invocations: callbacks,
    }];
    DifferentialCase {
        id: Arc::from(format!("runtime-typed-async-{}-{path}", definition.slug)),
        source: Arc::from(source),
        expected_runtime_completion: completion,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

#[cfg(all(test, feature = "compat-tracing"))]
struct RuntimePooledPath {
    source: String,
    stdout: &'static [u8],
    completion: bool,
    task_trace: Vec<(usize, &'static str)>,
    callbacks: Vec<CallbackInvocationContract>,
}

#[cfg(all(test, feature = "compat-tracing"))]
fn runtime_async_pooled_path(definition: RuntimePooledDefinition, path: &str) -> RuntimePooledPath {
    match path {
        "success" => runtime_async_pooled_success_path(definition),
        "empty" => runtime_async_pooled_empty_path(definition),
        "failure" => runtime_async_pooled_failure_path(definition),
        _ => unreachable!("pooled async path set is closed"),
    }
}

#[cfg(all(test, feature = "compat-tracing"))]
fn runtime_async_pooled_call(
    definition: RuntimePooledDefinition,
    callback: &str,
    list: &str,
) -> String {
    if definition.callback_argument == 0 {
        format!("{} ({callback}) ({list})", definition.builtin)
    } else {
        format!("{} ({list}) ({callback})", definition.builtin)
    }
}

#[cfg(all(test, feature = "compat-tracing"))]
fn runtime_async_pooled_success_path(definition: RuntimePooledDefinition) -> RuntimePooledPath {
    let callback = if definition.discard {
        "\\value -> do { Concurrent.threadDelay (if Int.eq value 3 then 3000 else if Int.eq value 2 then 2000 else 1000); IO.pure () }"
    } else {
        "\\value -> do { Concurrent.threadDelay (if Int.eq value 3 then 3000 else if Int.eq value 2 then 2000 else 1000); IO.pure (Int.mult value 10) }"
    };
    let operation = runtime_async_pooled_call(definition, callback, "[3,1,2]");
    let source = if definition.discard {
        format!("main = do {{ _ <- {operation}; Text.putStr \"done\" }}\n")
    } else {
        format!("main = Monad.bind ({operation}) IO.print\n")
    };
    RuntimePooledPath {
        source,
        stdout: if definition.discard {
            b"done"
        } else {
            b"[30,10,20]\n"
        },
        completion: true,
        task_trace: vec![
            (0, "started"),
            (0, "completed"),
            (1, "started"),
            (1, "completed"),
            (2, "started"),
            (2, "completed"),
        ],
        callbacks: runtime_async_pooled_callbacks(definition, [3, 1, 2]),
    }
}

#[cfg(all(test, feature = "compat-tracing"))]
fn runtime_async_pooled_empty_path(definition: RuntimePooledDefinition) -> RuntimePooledPath {
    let result = if definition.discard { "()" } else { "Int" };
    let callback = format!("\\_ -> Error.error \"forged pooled callback\" :: IO {result}");
    let operation = runtime_async_pooled_call(definition, &callback, "[] :: [Int]");
    let source = if definition.discard {
        format!("main = do {{ _ <- {operation}; Text.putStr \"empty\" }}\n")
    } else {
        format!("main = Monad.bind ({operation}) IO.print\n")
    };
    RuntimePooledPath {
        source,
        stdout: if definition.discard {
            b"empty"
        } else {
            b"[]\n"
        },
        completion: true,
        task_trace: Vec::new(),
        callbacks: Vec::new(),
    }
}

#[cfg(all(test, feature = "compat-tracing"))]
fn runtime_async_pooled_failure_path(definition: RuntimePooledDefinition) -> RuntimePooledPath {
    let result = if definition.discard { "()" } else { "Int" };
    let first_value = if definition.discard { "()" } else { "10" };
    let callback = format!(
        concat!(
            "\\value -> if Int.eq value 1 then do {{ ",
            "Concurrent.threadDelay 500000; IO.pure {first_value} }} ",
            "else do {{ Concurrent.threadDelay 50000; ",
            "Error.error \"pooled failure\" :: IO {result} }}",
        ),
        first_value = first_value,
        result = result,
    );
    let operation = runtime_async_pooled_call(definition, &callback, "[1,2]");
    RuntimePooledPath {
        source: format!("main = do {{ _ <- {operation}; IO.pure () }}\n"),
        stdout: b"",
        completion: false,
        task_trace: vec![
            (0, "started"),
            (0, "cancelled"),
            (1, "started"),
            (1, "failed"),
        ],
        callbacks: runtime_async_pooled_callbacks(definition, [1, 2]),
    }
}

#[cfg(all(test, feature = "compat-tracing"))]
fn runtime_async_pooled_callbacks<const N: usize>(
    definition: RuntimePooledDefinition,
    values: [i64; N],
) -> Vec<CallbackInvocationContract> {
    values
        .into_iter()
        .map(|value| {
            callback_contract_invocation(
                definition.callback_argument,
                "element",
                &[&runtime_traversal_int(value)],
                "{\"type\":\"IoAction\"}",
            )
        })
        .collect()
}

#[derive(Clone, Copy)]
struct RuntimeRaceDefinition {
    id: &'static str,
    source: &'static str,
    stdout: Option<&'static [u8]>,
    task_trace: &'static [(usize, &'static str)],
}

fn runtime_async_pair_case(
    builtin: &str,
    id_prefix: &str,
    definition: RuntimeRaceDefinition,
) -> DifferentialCase {
    let success = definition.stdout.is_some();
    let mut descriptor = runtime_all_obligation_descriptor(builtin, definition.source);
    descriptor.semantic_targets.retain_mut(|target| {
        target.expected_process_status_sha256 = Some(crate::process_status_sha256(
            success,
            Some(i32::from(!success)),
        ));
        target.expected_task_trace_sha256 = Some(crate::task_trace_sha256(
            definition.task_trace.iter().copied(),
        ));
        if target.dimension == CompatibilityDimension::PureRuntime
            && let Some(stdout) = definition.stdout
        {
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        }
        if target.dimension == CompatibilityDimension::PureRuntime {
            let omitted = if success {
                "adapter-failure"
            } else {
                "adapter-success"
            };
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != omitted);
        }
        if target.dimension == CompatibilityDimension::Effects {
            let omitted = if success {
                "effect-failure"
            } else {
                "effect-success"
            };
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != omitted);
            target.expected_single_effect_lifecycle_sha256 =
                Some(crate::single_effect_lifecycle_sha256(if success {
                    ["started", "completed"]
                } else {
                    ["started", "failed"]
                }));
        }
        true
    });
    DifferentialCase {
        id: Arc::from(format!("runtime-typed-{id_prefix}-{}", definition.id)),
        source: Arc::from(definition.source),
        expected_runtime_completion: success,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_function_operator_cases() -> Vec<DifferentialCase> {
    runtime_function_operator_definitions()
        .into_iter()
        .map(runtime_function_operator_case)
        .collect()
}

type RuntimeFunctionOperatorDefinition = (
    &'static str,
    &'static str,
    &'static str,
    &'static [u8],
    bool,
    Vec<CallbackInvocationContract>,
);

fn runtime_function_operator_definitions() -> Vec<RuntimeFunctionOperatorDefinition> {
    let mut definitions = runtime_function_apply_operator_definitions();
    definitions.extend(runtime_function_compose_operator_definitions());
    definitions
}

fn runtime_function_apply_operator_definitions() -> Vec<RuntimeFunctionOperatorDefinition> {
    vec![
        (
            "$",
            "runtime-typed-function-apply-operator",
            "main = IO.print ((\\value -> Int.plus value 1) $ 2)\n",
            b"3\n".as_slice(),
            true,
            vec![callback_contract_invocation(
                0,
                "function",
                &["{\"type\":\"Int\",\"value\":\"2\"}"],
                "{\"type\":\"Int\",\"value\":\"3\"}",
            )],
        ),
        (
            "$",
            "runtime-typed-function-apply-operator-lazy",
            "main = IO.print ((\\_ -> 7) $ (Error.error \"undemanded\" :: Int))\n",
            b"7\n".as_slice(),
            false,
            vec![callback_contract_invocation(
                0,
                "function",
                &["{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}"],
                "{\"type\":\"Int\",\"value\":\"7\"}",
            )],
        ),
        (
            "$",
            "runtime-typed-function-apply-operator-text",
            "main = Text.putStrLn ((\\text -> Text.toUpper text) $ \"ab\")\n",
            b"AB\n".as_slice(),
            true,
            vec![callback_contract_invocation(
                0,
                "function",
                &["{\"type\":\"Text\",\"utf8Hex\":\"6162\"}"],
                "{\"type\":\"Text\",\"utf8Hex\":\"4142\"}",
            )],
        ),
    ]
}

fn runtime_function_compose_operator_definitions() -> Vec<RuntimeFunctionOperatorDefinition> {
    vec![
        (
            ".",
            "runtime-typed-function-compose-operator",
            concat!(
                "main = IO.print (((\\value -> Int.plus value 1) . ",
                "(\\value -> Int.mult value 2)) 3)\n",
            ),
            b"7\n".as_slice(),
            true,
            vec![
                callback_contract_invocation(
                    1,
                    "inner",
                    &["{\"type\":\"Int\",\"value\":\"3\"}"],
                    "{\"type\":\"Int\",\"value\":\"6\"}",
                ),
                callback_contract_invocation(
                    0,
                    "outer",
                    &["{\"type\":\"Int\",\"value\":\"6\"}"],
                    "{\"type\":\"Int\",\"value\":\"7\"}",
                ),
            ],
        ),
        (
            ".",
            "runtime-typed-function-compose-operator-lazy",
            concat!(
                "main = IO.print (((\\_ -> 7) . ",
                "(\\_ -> Error.error \"undemanded inner\" :: Int)) ",
                "(Error.error \"undemanded input\" :: Int))\n",
            ),
            b"7\n".as_slice(),
            false,
            vec![callback_contract_invocation(
                0,
                "outer",
                &["{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}"],
                "{\"type\":\"Int\",\"value\":\"7\"}",
            )],
        ),
        (
            ".",
            "runtime-typed-function-compose-operator-heterogeneous",
            concat!(
                "main = Text.putStrLn (((\\text -> Text.concat [\"v\",text]) . ",
                "Int.show) 42)\n",
            ),
            b"v42\n".as_slice(),
            true,
            vec![
                callback_contract_invocation(
                    1,
                    "inner",
                    &["{\"type\":\"Int\",\"value\":\"42\"}"],
                    "{\"type\":\"Text\",\"utf8Hex\":\"3432\"}",
                ),
                callback_contract_invocation(
                    0,
                    "outer",
                    &["{\"type\":\"Text\",\"utf8Hex\":\"3432\"}"],
                    "{\"type\":\"Text\",\"utf8Hex\":\"763432\"}",
                ),
            ],
        ),
    ]
}

fn runtime_function_operator_case(
    (builtin, id, source, stdout, demanded, invocations): RuntimeFunctionOperatorDefinition,
) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    for target in &mut descriptor.semantic_targets {
        if demanded {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "lazy-boundary");
        }
        target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(stdout, b""));
    }
    descriptor.callback_contracts = vec![CallbackContract {
        builtin: Arc::from(builtin),
        invocations,
    }];
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_exit_action_cases() -> Vec<DifferentialCase> {
    const SUCCESS_SOURCE: &str = "main = (Exit.exitWith Exit.ExitSuccess :: IO ())\n";
    let mut cases = [
        (
            "Exit.die",
            "runtime-typed-exit-die",
            "main = (Exit.die \"reviewed exit\" :: IO ())\n",
            1,
            b"".as_slice(),
            b"reviewed exit\n".as_slice(),
        ),
        (
            "Exit.exitWith",
            "runtime-typed-exit-with-failure",
            "main = (Exit.exitWith (Exit.ExitFailure 23) :: IO ())\n",
            23,
            b"".as_slice(),
            b"".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(builtin, id, source, code, stdout, stderr)| {
        let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
        let status = crate::process_status_sha256(false, Some(code));
        let raw = crate::raw_presentation_sha256(stdout, stderr);
        let effect = crate::single_effect_lifecycle_sha256(["started", "failed"]);
        for target in &mut descriptor.semantic_targets {
            target.expected_process_status_sha256 = Some(status);
            target.expected_raw_presentation_sha256 = Some(raw);
            target.expected_single_effect_lifecycle_sha256 = Some(effect);
        }
        DifferentialCase {
            id: Arc::from(id),
            source: Arc::from(source),
            expected_runtime_completion: false,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect::<Vec<_>>();

    let mut success = runtime_all_obligation_descriptor("Exit.exitWith", SUCCESS_SOURCE);
    success
        .targets
        .retain(|target| target.dimension == CompatibilityDimension::PureRuntime);
    success.semantic_targets.retain_mut(|target| {
        if target.dimension != CompatibilityDimension::PureRuntime {
            return false;
        }
        target
            .obligations
            .retain(|obligation| obligation.0.as_ref() == "io-execution-boundary");
        target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
        target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(b"", b""));
        target.expected_single_effect_lifecycle_sha256 =
            Some(crate::single_effect_lifecycle_sha256(["started", "failed"]));
        true
    });
    cases.push(DifferentialCase {
        id: Arc::from("runtime-typed-exit-with-success"),
        source: Arc::from(SUCCESS_SOURCE),
        expected_runtime_completion: false,
        claim_evidence: Some(success),
        ..DifferentialCase::default()
    });
    cases
}

fn runtime_alternative_cases() -> Vec<DifferentialCase> {
    let mut cases = runtime_alternative_maybe_cases();
    cases.extend(runtime_alternative_parser_cases());
    cases
}

fn runtime_monad_return_cases() -> Vec<DifferentialCase> {
    let int = "{\"type\":\"Int\",\"value\":\"42\"}";
    let cases = [
        (
            "io",
            "IO",
            "main = do { value <- Monad.return 42; IO.print value }\n",
            b"42\n".as_slice(),
            None,
        ),
        (
            "maybe",
            "Maybe",
            "main = case (Monad.return 42 :: Maybe Int) of { Maybe.Just value -> IO.print value; Maybe.Nothing -> IO.print 0 }\n",
            b"42\n".as_slice(),
            Some(format!("{{\"type\":\"Maybe\",\"payload\":{int}}}")),
        ),
        (
            "list",
            "[]",
            "main = IO.print (Monad.return 42 :: [Int])\n",
            b"[42]\n".as_slice(),
            Some(format!(
                "{{\"type\":\"List\",\"elements\":[{int}],\"terminationHex\":\"6e696c\"}}"
            )),
        ),
        (
            "tree",
            "Tree",
            "main = IO.print $ Tree.flatten (Monad.return 42 :: Tree Int)\n",
            b"[42]\n".as_slice(),
            Some(format!(
                "{{\"type\":\"Tree\",\"elements\":[{int},{{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}}]}}"
            )),
        ),
        (
            "either",
            "Either",
            "main = case (Monad.return 42 :: Either Text Int) of { Either.Right value -> IO.print value; Either.Left ignored -> IO.print 0 }\n",
            b"42\n".as_slice(),
            Some(format!(
                "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{int}]}}"
            )),
        ),
    ];
    cases
        .into_iter()
        .map(|(id, instance, source, stdout, typed)| {
            let mut descriptor = runtime_single_typed_target_descriptor("Monad.return", source);
            let target = &mut descriptor.semantic_targets[0];
            target.expected_instance_target = Some(Arc::from(instance));
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
            target.expected_lazy_argument_exit_sha256 =
                Some(crate::lazy_argument_exit_sha256([(0, "not-forced")]));
            if let Some(typed) = typed {
                let canonical = format!(
                    "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{typed}}}"
                );
                target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
            }
            DifferentialCase {
                id: Arc::from(format!("runtime-typed-monad-return-{id}")),
                source: Arc::from(source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

type RuntimeMonadWhenPair = (
    &'static str,
    &'static str,
    (&'static str, &'static [u8], String),
    (&'static str, &'static [u8], String),
);

fn runtime_monad_when_cases() -> Vec<DifferentialCase> {
    runtime_monad_when_definitions()
        .into_iter()
        .flat_map(|(id, instance, selected, unselected)| {
            [
                runtime_monad_when_case(id, instance, "selected", selected),
                runtime_monad_when_case(id, instance, "unselected", unselected),
            ]
        })
        .collect()
}

fn runtime_monad_when_case(
    id: &str,
    instance: &str,
    branch: &str,
    (source, stdout, value): (&str, &[u8], String),
) -> DifferentialCase {
    let mut descriptor = runtime_single_typed_target_descriptor("Monad.when", source);
    let target = &mut descriptor.semantic_targets[0];
    target.obligations.retain(|obligation| {
        if branch == "selected" {
            obligation.0.as_ref() != "lazy-boundary"
        } else {
            obligation.0.as_ref() == "lazy-boundary"
        }
    });
    target.expected_instance_target = Some(Arc::from(instance));
    target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(stdout, b""));
    target.expected_lazy_argument_exit_sha256 =
        Some(crate::lazy_argument_exit_sha256([(1, "not-forced")]));
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{value}}}"
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    DifferentialCase {
        id: Arc::from(format!("runtime-typed-monad-when-{id}-{branch}")),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_monad_when_definitions() -> [RuntimeMonadWhenPair; 5] {
    const IO: &str = "{\"type\":\"IoAction\"}";
    const UNIT: &str = "{\"type\":\"Unit\",\"value\":null}";
    const NOT_FORCED: &str = "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}";
    const MAYBE_NOTHING: &str = "{\"type\":\"Maybe\",\"payload\":null}";
    const LIST_EMPTY: &str = "{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}";
    const EITHER_LEFT: &str = "{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{\"type\":\"Text\",\"utf8Hex\":\"73656c6563746564\"}]}";
    let maybe_unit = format!("{{\"type\":\"Maybe\",\"payload\":{UNIT}}}");
    let list_unit =
        format!("{{\"type\":\"List\",\"elements\":[{UNIT}],\"terminationHex\":\"6e696c\"}}");
    let either_unit = format!(
        "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{UNIT}]}}"
    );
    let tree_unit = format!(
        "{{\"type\":\"Tree\",\"elements\":[{UNIT},{{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}}]}}"
    );
    let tree_two_units = format!(
        "{{\"type\":\"Tree\",\"elements\":[{NOT_FORCED},{{\"type\":\"List\",\"elements\":[{{\"type\":\"Tree\",\"elements\":[{NOT_FORCED},{{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}}]}}],\"terminationHex\":\"6e696c\"}}]}}"
    );
    [
        (
            "io",
            "IO",
            (
                "main = Monad.when Bool.True (Text.putStr \"selected\")\n",
                b"selected",
                IO.to_owned(),
            ),
            (
                concat!(
                    "main = do\n",
                    "  Monad.when Bool.False (Error.error \"unselected\" :: IO ())\n",
                    "  Text.putStr \"skipped\"\n"
                ),
                b"skipped",
                IO.to_owned(),
            ),
        ),
        (
            "maybe",
            "Maybe",
            (
                "main = case (Monad.when Bool.True (Maybe.Nothing :: Maybe ())) of { Maybe.Nothing -> IO.print 0; Maybe.Just ignored -> IO.print 1 }\n",
                b"0\n",
                MAYBE_NOTHING.to_owned(),
            ),
            (
                "main = case (Monad.when Bool.False (Maybe.Nothing :: Maybe ())) of { Maybe.Nothing -> IO.print 0; Maybe.Just ignored -> IO.print 1 }\n",
                b"1\n",
                maybe_unit,
            ),
        ),
        (
            "list",
            "[]",
            (
                "main = IO.print $ List.length $ Monad.when Bool.True ([] :: [()])\n",
                b"0\n",
                LIST_EMPTY.to_owned(),
            ),
            (
                "main = IO.print $ List.length $ Monad.when Bool.False ([] :: [()])\n",
                b"1\n",
                list_unit,
            ),
        ),
        (
            "tree",
            "Tree",
            (
                "main = IO.print $ List.length $ Tree.flatten $ Monad.when Bool.True (Tree.Node () [Tree.Node () []])\n",
                b"2\n",
                tree_two_units,
            ),
            (
                "main = IO.print $ List.length $ Tree.flatten $ Monad.when Bool.False (Tree.Node () [Tree.Node () []])\n",
                b"1\n",
                tree_unit,
            ),
        ),
        (
            "either",
            "Either",
            (
                "main = case (Monad.when Bool.True (Either.Left \"selected\" :: Either Text ())) of { Either.Left text -> Text.putStrLn text; Either.Right ignored -> Text.putStrLn \"right\" }\n",
                b"selected\n",
                EITHER_LEFT.to_owned(),
            ),
            (
                "main = case (Monad.when Bool.False (Either.Left \"selected\" :: Either Text ())) of { Either.Left text -> Text.putStrLn text; Either.Right ignored -> Text.putStrLn \"right\" }\n",
                b"right\n",
                either_unit,
            ),
        ),
    ]
}

type RuntimeMonadThenDefinition = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static [u8],
    String,
    bool,
    &'static [(u16, &'static str)],
);

fn runtime_monad_then_cases() -> Vec<DifferentialCase> {
    runtime_monad_then_definitions()
        .into_iter()
        .chain(runtime_monad_then_list_definitions())
        .chain(runtime_monad_then_tree_definitions())
        .map(runtime_monad_then_case)
        .collect()
}

fn runtime_monad_then_case(
    (id, instance, branch, source, stdout, value, success, exit_states): RuntimeMonadThenDefinition,
) -> DifferentialCase {
    let mut descriptor = runtime_single_typed_target_descriptor("Monad.then", source);
    let target = &mut descriptor.semantic_targets[0];
    target.obligations.retain(|obligation| {
        if branch == "success" || branch == "simple" {
            obligation.0.as_ref() != "lazy-boundary"
        } else {
            obligation.0.as_ref() == "lazy-boundary"
        }
    });
    target.expected_instance_target = Some(Arc::from(instance));
    target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(stdout, b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(
        success,
        Some(i32::from(!success)),
    ));
    target.expected_lazy_argument_exit_sha256 = Some(crate::lazy_argument_exit_sha256(
        exit_states.iter().copied(),
    ));
    if instance != "[]" {
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{value}}}"
        );
        target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    }
    DifferentialCase {
        id: Arc::from(format!("runtime-typed-monad-then-{id}-{branch}")),
        source: Arc::from(source),
        expected_runtime_completion: success,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_monad_then_definitions() -> Vec<RuntimeMonadThenDefinition> {
    const IO: &str = "{\"type\":\"IoAction\"}";
    const MAYBE_NOTHING: &str = "{\"type\":\"Maybe\",\"payload\":null}";
    const CONTAINER_EXIT: &[(u16, &str)] = &[(0, "value"), (1, "not-forced")];
    const IO_EXIT: &[(u16, &str)] = &[(0, "not-forced"), (1, "not-forced")];
    let int = |value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let maybe_two = format!("{{\"type\":\"Maybe\",\"payload\":{}}}", int(2));
    let either_right = format!(
        "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{}]}}",
        int(2)
    );
    let either_left = "{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{\"type\":\"Text\",\"utf8Hex\":\"6669727374\"}]}".to_owned();
    vec![
        (
            "io",
            "IO",
            "success",
            "main = do { Text.putStr \"first\"; Text.putStr \"second\" }\n",
            b"firstsecond",
            IO.to_owned(),
            true,
            IO_EXIT,
        ),
        (
            "io",
            "IO",
            "short-circuit",
            "main = do { (Exit.exitWith (Exit.ExitFailure 1) :: IO ()); Text.putStr \"forged\" }\n",
            b"",
            IO.to_owned(),
            false,
            IO_EXIT,
        ),
        (
            "maybe",
            "Maybe",
            "success",
            "main = case (do { (Maybe.Just 1 :: Maybe Int); (Maybe.Just 2 :: Maybe Int) } :: Maybe Int) of { Maybe.Just value -> IO.print value; Maybe.Nothing -> IO.print 0 }\n",
            b"2\n",
            maybe_two,
            true,
            CONTAINER_EXIT,
        ),
        (
            "maybe",
            "Maybe",
            "short-circuit",
            "main = case (do { (Maybe.Nothing :: Maybe ()); Error.error \"forged\" } :: Maybe Int) of { Maybe.Just value -> IO.print value; Maybe.Nothing -> IO.print 0 }\n",
            b"0\n",
            MAYBE_NOTHING.to_owned(),
            true,
            CONTAINER_EXIT,
        ),
        (
            "either",
            "Either",
            "success",
            "main = case (do { (Either.Right 1 :: Either Text Int); (Either.Right 2 :: Either Text Int) } :: Either Text Int) of { Either.Left text -> Text.putStrLn text; Either.Right value -> IO.print value }\n",
            b"2\n",
            either_right,
            true,
            CONTAINER_EXIT,
        ),
        (
            "either",
            "Either",
            "short-circuit",
            "main = case (do { (Either.Left \"first\" :: Either Text ()); (Error.error \"forged\" :: Either Text Int) } :: Either Text Int) of { Either.Left text -> Text.putStrLn text; Either.Right value -> IO.print value }\n",
            b"first\n",
            either_left,
            true,
            CONTAINER_EXIT,
        ),
    ]
}

fn runtime_monad_then_list_definitions() -> Vec<RuntimeMonadThenDefinition> {
    const EXIT: &[(u16, &str)] = &[(0, "not-forced"), (1, "not-forced")];
    const EMPTY: &str = "{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}";
    let int = |value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let repeated = format!(
        "{{\"type\":\"List\",\"elements\":[{},{},{},{}],\"terminationHex\":\"6e696c\"}}",
        int(7),
        int(8),
        int(7),
        int(8),
    );
    vec![
        (
            "list",
            "[]",
            "success",
            "main = IO.print (do { ([1,2] :: [Int]); ([7,8] :: [Int]) } :: [Int])\n",
            b"[7,8,7,8]\n",
            repeated,
            true,
            EXIT,
        ),
        (
            "list",
            "[]",
            "short-circuit",
            "main = IO.print (do { ([] :: [()]); (Error.error \"forged\" :: [Int]) } :: [Int])\n",
            b"[]\n",
            EMPTY.to_owned(),
            true,
            EXIT,
        ),
    ]
}

fn runtime_monad_then_tree_definitions() -> Vec<RuntimeMonadThenDefinition> {
    const TREE_EXIT: &[(u16, &str)] = &[(0, "value"), (1, "value")];
    const SIMPLE: &str = "{\"type\":\"Tree\",\"elements\":[{\"type\":\"Int\",\"value\":\"2\"},{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}]}";
    const BRANCHING: &str = "{\"type\":\"Tree\",\"elements\":[{\"type\":\"Int\",\"value\":\"2\"},{\"type\":\"List\",\"elements\":[{\"type\":\"Tree\",\"elements\":[{\"type\":\"Int\",\"value\":\"22\"},{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}]},{\"type\":\"Tree\",\"elements\":[{\"type\":\"Int\",\"value\":\"2\"},{\"type\":\"List\",\"elements\":[{\"type\":\"Tree\",\"elements\":[{\"type\":\"Int\",\"value\":\"22\"},{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}]}],\"terminationHex\":\"6e696c\"}]}],\"terminationHex\":\"6e696c\"}]}";
    vec![
        (
            "tree",
            "Tree",
            "simple",
            "main = IO.print $ Tree.flatten $ (do { Tree.Node 1 []; Tree.Node 2 [] } :: Tree Int)\n",
            b"[2]\n",
            SIMPLE.to_owned(),
            true,
            TREE_EXIT,
        ),
        (
            "tree",
            "Tree",
            "branching",
            "main = IO.print $ Tree.flatten $ (do { Tree.Node 1 [Tree.Node 11 []]; Tree.Node 2 [Tree.Node 22 []] } :: Tree Int)\n",
            b"[2,22,2,22]\n",
            BRANCHING.to_owned(),
            true,
            TREE_EXIT,
        ),
    ]
}

struct RuntimeMonadBindDefinition {
    id: &'static str,
    instance: &'static str,
    branch: &'static str,
    source: &'static str,
    stdout: &'static [u8],
    value: Option<String>,
    success: bool,
    exit_states: &'static [(u16, &'static str)],
    invocations: Vec<CallbackInvocationContract>,
}

fn runtime_monad_bind_cases() -> Vec<DifferentialCase> {
    runtime_monad_bind_base_definitions()
        .into_iter()
        .chain(runtime_monad_bind_list_definitions())
        .chain(runtime_monad_bind_tree_definitions())
        .map(runtime_monad_bind_case)
        .collect()
}

fn runtime_monad_bind_case(definition: RuntimeMonadBindDefinition) -> DifferentialCase {
    let mut descriptor = runtime_single_typed_target_descriptor("Monad.bind", definition.source);
    let target = &mut descriptor.semantic_targets[0];
    target.obligations.retain(|obligation| {
        if definition.branch == "success" || definition.branch == "simple" {
            obligation.0.as_ref() != "lazy-boundary"
        } else {
            matches!(obligation.0.as_ref(), "callback-order" | "lazy-boundary")
        }
    });
    target.expected_instance_target = Some(Arc::from(definition.instance));
    target.expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(definition.stdout, b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(
        definition.success,
        Some(i32::from(!definition.success)),
    ));
    target.expected_lazy_argument_exit_sha256 = Some(crate::lazy_argument_exit_sha256(
        definition.exit_states.iter().copied(),
    ));
    if let Some(value) = definition.value {
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{value}}}"
        );
        target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    }
    descriptor.callback_contracts = vec![CallbackContract {
        builtin: Arc::from("Monad.bind"),
        invocations: definition.invocations,
    }];
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-typed-monad-bind-{}-{}",
            definition.id, definition.branch
        )),
        source: Arc::from(definition.source),
        expected_runtime_completion: definition.success,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_monad_bind_base_definitions() -> Vec<RuntimeMonadBindDefinition> {
    const IO: &str = "{\"type\":\"IoAction\"}";
    const IO_EXIT: &[(u16, &str)] = &[(0, "not-forced"), (1, "not-forced")];
    const CONTAINER_EXIT: &[(u16, &str)] = &[(0, "value"), (1, "not-forced")];
    let int = |value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let maybe = |value| format!("{{\"type\":\"Maybe\",\"payload\":{}}}", int(value));
    let right = |value| {
        format!(
            "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{}]}}",
            int(value)
        )
    };
    let left = "{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{\"type\":\"Text\",\"utf8Hex\":\"6669727374\"}]}".to_owned();
    vec![
        RuntimeMonadBindDefinition {
            id: "io",
            instance: "IO",
            branch: "success",
            source: "main = Monad.bind (IO.pure 41) (\\value -> IO.print (Int.plus value 1))\n",
            stdout: b"42\n",
            value: Some(IO.to_owned()),
            success: true,
            exit_states: IO_EXIT,
            invocations: vec![callback_contract_invocation(
                1,
                "continuation",
                &[&int(41)],
                IO,
            )],
        },
        RuntimeMonadBindDefinition {
            id: "io",
            instance: "IO",
            branch: "short-circuit",
            source: "main = Monad.bind (Exit.exitWith (Exit.ExitFailure 1) :: IO Int) (\\_ -> Text.putStr \"forged\")\n",
            stdout: b"",
            value: Some(IO.to_owned()),
            success: false,
            exit_states: IO_EXIT,
            invocations: Vec::new(),
        },
        RuntimeMonadBindDefinition {
            id: "maybe",
            instance: "Maybe",
            branch: "success",
            source: "main = case (Monad.bind (Maybe.Just 2) (\\value -> Maybe.Just (Int.plus value 1)) :: Maybe Int) of { Maybe.Just value -> IO.print value; Maybe.Nothing -> IO.print 0 }\n",
            stdout: b"3\n",
            value: Some(maybe(3)),
            success: true,
            exit_states: CONTAINER_EXIT,
            invocations: vec![callback_contract_invocation(
                1,
                "continuation",
                &[&int(2)],
                &maybe(3),
            )],
        },
        RuntimeMonadBindDefinition {
            id: "maybe",
            instance: "Maybe",
            branch: "short-circuit",
            source: "main = case (Monad.bind (Maybe.Nothing :: Maybe Int) (\\_ -> Error.error \"forged\") :: Maybe Int) of { Maybe.Just value -> IO.print value; Maybe.Nothing -> IO.print 0 }\n",
            stdout: b"0\n",
            value: Some("{\"type\":\"Maybe\",\"payload\":null}".to_owned()),
            success: true,
            exit_states: CONTAINER_EXIT,
            invocations: Vec::new(),
        },
        RuntimeMonadBindDefinition {
            id: "either",
            instance: "Either",
            branch: "success",
            source: "main = case (Monad.bind (Either.Right 2 :: Either Text Int) (\\value -> Either.Right (Int.plus value 1)) :: Either Text Int) of { Either.Left text -> Text.putStrLn text; Either.Right value -> IO.print value }\n",
            stdout: b"3\n",
            value: Some(right(3)),
            success: true,
            exit_states: CONTAINER_EXIT,
            invocations: vec![callback_contract_invocation(
                1,
                "continuation",
                &[&int(2)],
                &right(3),
            )],
        },
        RuntimeMonadBindDefinition {
            id: "either",
            instance: "Either",
            branch: "short-circuit",
            source: "main = case (Monad.bind (Either.Left \"first\" :: Either Text Int) (\\_ -> Error.error \"forged\") :: Either Text Int) of { Either.Left text -> Text.putStrLn text; Either.Right value -> IO.print value }\n",
            stdout: b"first\n",
            value: Some(left),
            success: true,
            exit_states: CONTAINER_EXIT,
            invocations: Vec::new(),
        },
    ]
}

fn runtime_monad_bind_list_definitions() -> Vec<RuntimeMonadBindDefinition> {
    const EXIT: &[(u16, &str)] = &[(0, "not-forced"), (1, "not-forced")];
    let int = |value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let list = |values: &[i64]| {
        let elements = values
            .iter()
            .map(|value| int(*value))
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"type\":\"List\",\"elements\":[{elements}],\"terminationHex\":\"6e696c\"}}")
    };
    vec![
        RuntimeMonadBindDefinition {
            id: "list",
            instance: "[]",
            branch: "success",
            source: "main = IO.print (Monad.bind ([1,2] :: [Int]) (\\value -> [value, Int.plus value 10]) :: [Int])\n",
            stdout: b"[1,11,2,12]\n",
            value: None,
            success: true,
            exit_states: EXIT,
            invocations: vec![
                callback_contract_invocation(1, "continuation", &[&int(1)], &list(&[1, 11])),
                callback_contract_invocation(1, "continuation", &[&int(2)], &list(&[2, 12])),
            ],
        },
        RuntimeMonadBindDefinition {
            id: "list",
            instance: "[]",
            branch: "short-circuit",
            source: "main = IO.print (Monad.bind ([] :: [Int]) (\\_ -> Error.error \"forged\") :: [Int])\n",
            stdout: b"[]\n",
            value: None,
            success: true,
            exit_states: EXIT,
            invocations: Vec::new(),
        },
    ]
}

fn runtime_monad_bind_tree_definitions() -> Vec<RuntimeMonadBindDefinition> {
    const EXIT: &[(u16, &str)] = &[(0, "value"), (1, "value")];
    let int = |value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let empty_list = "{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}";
    let leaf = |value| {
        format!(
            "{{\"type\":\"Tree\",\"elements\":[{},{empty_list}]}}",
            int(value)
        )
    };
    let tree = |root, children: &[String]| {
        format!(
            "{{\"type\":\"Tree\",\"elements\":[{},{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}]}}",
            int(root),
            children.join(",")
        )
    };
    let simple = leaf(30);
    let root_result = tree(10, &[leaf(11)]);
    let child_result = tree(20, &[leaf(21)]);
    let branching = tree(10, &[leaf(11), child_result.clone()]);
    vec![
        RuntimeMonadBindDefinition {
            id: "tree",
            instance: "Tree",
            branch: "simple",
            source: "main = IO.print $ Tree.flatten $ (Monad.bind (Tree.Node 3 []) (\\value -> Tree.Node (Int.mult value 10) []) :: Tree Int)\n",
            stdout: b"[30]\n",
            value: Some(simple.clone()),
            success: true,
            exit_states: EXIT,
            invocations: vec![callback_contract_invocation(
                1,
                "continuation",
                &[&int(3)],
                &simple,
            )],
        },
        RuntimeMonadBindDefinition {
            id: "tree",
            instance: "Tree",
            branch: "branching",
            source: "main = IO.print $ Tree.flatten $ (Monad.bind (Tree.Node 1 [Tree.Node 2 []]) (\\value -> Tree.Node (Int.mult value 10) [Tree.Node (Int.plus (Int.mult value 10) 1) []]) :: Tree Int)\n",
            stdout: b"[10,11,20,21]\n",
            value: Some(branching),
            success: true,
            exit_states: EXIT,
            invocations: vec![
                callback_contract_invocation(1, "continuation", &[&int(1)], &root_result),
                callback_contract_invocation(1, "continuation", &[&int(2)], &child_result),
            ],
        },
    ]
}

struct RuntimeMonadSequenceDefinition {
    id: &'static str,
    instance: &'static str,
    branch: &'static str,
    source: &'static str,
    stdout: &'static [u8],
    value: Option<String>,
    success: bool,
}

fn runtime_monad_sequence_cases() -> Vec<DifferentialCase> {
    runtime_monad_sequence_definitions()
        .into_iter()
        .chain(runtime_monad_sequence_list_tree_definitions())
        .map(|definition| {
            let mut descriptor =
                runtime_single_typed_target_descriptor("Monad.sequence", definition.source);
            let target = &mut descriptor.semantic_targets[0];
            target.obligations.retain(|obligation| {
                if definition.branch == "finite" {
                    obligation.0.as_ref() != "lazy-boundary"
                } else {
                    obligation.0.as_ref() == "lazy-boundary"
                }
            });
            target.expected_instance_target = Some(Arc::from(definition.instance));
            target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(
                definition.stdout,
                b"",
            ));
            target.expected_process_status_sha256 = Some(crate::process_status_sha256(
                definition.success,
                Some(i32::from(!definition.success)),
            ));
            target.expected_lazy_argument_exit_sha256 =
                Some(crate::lazy_argument_exit_sha256([(0, "value")]));
            if let Some(value) = definition.value {
                let canonical = format!(
                    "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{value}}}"
                );
                target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
            }
            DifferentialCase {
                id: Arc::from(format!(
                    "runtime-typed-monad-sequence-{}-{}",
                    definition.id, definition.branch
                )),
                source: Arc::from(definition.source),
                expected_runtime_completion: definition.success,
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_monad_sequence_definitions() -> Vec<RuntimeMonadSequenceDefinition> {
    const IO: &str = "{\"type\":\"IoAction\"}";
    let int = |value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let values = format!(
        "{{\"type\":\"List\",\"elements\":[{},{}],\"terminationHex\":\"6e696c\"}}",
        int(1),
        int(2)
    );
    let maybe = format!("{{\"type\":\"Maybe\",\"payload\":{values}}}");
    let right = format!(
        "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{values}]}}"
    );
    let left = "{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{\"type\":\"Text\",\"utf8Hex\":\"6669727374\"}]}".to_owned();
    vec![
        runtime_monad_sequence_definition(
            "io",
            "IO",
            "finite",
            "main = do { Monad.sequence [Text.putStr \"a\", Text.putStr \"b\"]; IO.pure () }\n",
            b"ab",
            Some(IO.to_owned()),
            true,
        ),
        runtime_monad_sequence_definition(
            "io",
            "IO",
            "short-circuit",
            "main = do { Monad.sequence [(Exit.exitWith (Exit.ExitFailure 1) :: IO ()), Text.putStr \"forged\"]; IO.pure () }\n",
            b"",
            Some(IO.to_owned()),
            false,
        ),
        runtime_monad_sequence_definition(
            "maybe",
            "Maybe",
            "finite",
            "main = IO.print (Monad.sequence [Maybe.Just 1, Maybe.Just 2] :: Maybe [Int])\n",
            b"Just [1,2]\n",
            Some(maybe),
            true,
        ),
        runtime_monad_sequence_definition(
            "maybe",
            "Maybe",
            "short-circuit",
            "main = IO.print (Monad.sequence [Maybe.Nothing, Error.error \"forged\"] :: Maybe [Int])\n",
            b"Nothing\n",
            Some("{\"type\":\"Maybe\",\"payload\":null}".to_owned()),
            true,
        ),
        runtime_monad_sequence_definition(
            "either",
            "Either",
            "finite",
            "main = IO.print (Monad.sequence [Either.Right 1, Either.Right 2] :: Either Text [Int])\n",
            b"Right [1,2]\n",
            Some(right),
            true,
        ),
        runtime_monad_sequence_definition(
            "either",
            "Either",
            "short-circuit",
            "main = case (Monad.sequence [Either.Left \"first\", Error.error \"forged\"] :: Either Text [Int]) of { Either.Left text -> Text.putStrLn text; Either.Right values -> IO.print values }\n",
            b"first\n",
            Some(left),
            true,
        ),
    ]
}

fn runtime_monad_sequence_definition(
    id: &'static str,
    instance: &'static str,
    branch: &'static str,
    source: &'static str,
    stdout: &'static [u8],
    value: Option<String>,
    success: bool,
) -> RuntimeMonadSequenceDefinition {
    RuntimeMonadSequenceDefinition {
        id,
        instance,
        branch,
        source,
        stdout,
        value,
        success,
    }
}

fn runtime_monad_sequence_list_tree_definitions() -> Vec<RuntimeMonadSequenceDefinition> {
    let int = |value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let empty = "{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}";
    let list = |values: &[i64]| {
        let elements = values
            .iter()
            .map(|value| int(*value))
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"type\":\"List\",\"elements\":[{elements}],\"terminationHex\":\"6e696c\"}}")
    };
    let list_values = |values: &[String]| {
        format!(
            "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}",
            values.join(",")
        )
    };
    let indirect_pair = |left, right| {
        let tail = list(&[right]);
        let termination = runtime_bytes_hex(format!("indirection:{tail}").as_bytes());
        format!(
            "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"{termination}\"}}",
            int(left)
        )
    };
    let tree = |root: String, children: &[String]| {
        format!(
            "{{\"type\":\"Tree\",\"elements\":[{root},{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}]}}",
            children.join(",")
        )
    };
    let cross = tree(indirect_pair(11, 22), &[]);
    let left_branch = tree(indirect_pair(1, 22), &[]);
    let right_branch = tree(indirect_pair(11, 2), &[cross]);
    let tree_values = tree(indirect_pair(1, 2), &[left_branch, right_branch]);
    let list_values_finite =
        list_values(&[list(&[1, 7]), list(&[1, 8]), list(&[2, 7]), list(&[2, 8])]);
    let list_values_empty = list_values(&[empty.to_owned()]);
    let tree_empty = format!(
        "{{\"type\":\"Tree\",\"elements\":[{empty},{{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}}]}}"
    );
    vec![
        runtime_monad_sequence_definition(
            "list",
            "[]",
            "finite",
            "main = IO.print (Monad.sequence [[1,2],[7,8]] :: [[Int]])\n",
            b"[[1,7],[1,8],[2,7],[2,8]]\n",
            Some(list_values_finite),
            true,
        ),
        runtime_monad_sequence_definition(
            "list",
            "[]",
            "empty",
            "main = IO.print (Monad.sequence ([] :: [[Int]]) :: [[Int]])\n",
            b"[[]]\n",
            Some(list_values_empty),
            true,
        ),
        runtime_monad_sequence_definition(
            "tree",
            "Tree",
            "finite",
            "main = IO.print $ Tree.flatten $ (Monad.sequence [Tree.Node 1 [Tree.Node 11 []], Tree.Node 2 [Tree.Node 22 []]] :: Tree [Int])\n",
            b"[[1,2],[1,22],[11,2],[11,22]]\n",
            Some(tree_values),
            true,
        ),
        runtime_monad_sequence_definition(
            "tree",
            "Tree",
            "empty",
            "main = IO.print $ Tree.flatten $ (Monad.sequence ([] :: [Tree Int]) :: Tree [Int])\n",
            b"[[]]\n",
            Some(tree_empty),
            true,
        ),
    ]
}

struct RuntimeMonadTraversalDefinition {
    id: &'static str,
    instance: &'static str,
    branch: &'static str,
    source: String,
    stdout: Vec<u8>,
    value: String,
    success: bool,
    exit_states: Vec<(u16, &'static str)>,
    invocations: Vec<CallbackInvocationContract>,
}

macro_rules! runtime_monad_traversal_definition {
    ($id:expr, $instance:expr, $branch:expr, $source:expr, $stdout:expr, $value:expr,
     $success:expr, $exit_states:expr, $invocations:expr $(,)?) => {
        RuntimeMonadTraversalDefinition {
            id: $id,
            instance: $instance,
            branch: $branch,
            source: $source,
            stdout: $stdout,
            value: $value,
            success: $success,
            exit_states: $exit_states,
            invocations: $invocations,
        }
    };
}

fn runtime_monad_traversal_cases() -> Vec<DifferentialCase> {
    [
        ("Monad.mapM", false),
        ("Monad.forM", false),
        ("Monad.mapM_", true),
        ("Monad.forM_", true),
    ]
    .into_iter()
    .flat_map(|(builtin, discard)| {
        runtime_monad_traversal_definitions(builtin, discard)
            .into_iter()
            .map(move |definition| runtime_monad_traversal_case(builtin, definition))
    })
    .collect()
}

fn runtime_monad_traversal_case(
    builtin: &'static str,
    definition: RuntimeMonadTraversalDefinition,
) -> DifferentialCase {
    let mut descriptor = runtime_single_typed_target_descriptor(builtin, &definition.source);
    let target = &mut descriptor.semantic_targets[0];
    target.obligations.retain(|obligation| {
        if definition.branch == "finite" {
            obligation.0.as_ref() != "lazy-boundary"
        } else {
            matches!(obligation.0.as_ref(), "callback-order" | "lazy-boundary")
        }
    });
    target.expected_instance_target = Some(Arc::from(definition.instance));
    target.expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(&definition.stdout, b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(
        definition.success,
        Some(i32::from(!definition.success)),
    ));
    target.expected_lazy_argument_exit_sha256 = Some(crate::lazy_argument_exit_sha256(
        definition.exit_states.iter().copied(),
    ));
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{}}}",
        definition.value
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    descriptor.callback_contracts = vec![CallbackContract {
        builtin: Arc::from(builtin),
        invocations: definition.invocations,
    }];
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-typed-{}-{}-{}",
            runtime_monad_traversal_slug(builtin),
            definition.id,
            definition.branch,
        )),
        source: Arc::from(definition.source),
        expected_runtime_completion: definition.success,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_monad_traversal_definitions(
    builtin: &'static str,
    discard: bool,
) -> Vec<RuntimeMonadTraversalDefinition> {
    let mut definitions = runtime_monad_traversal_base_definitions(builtin, discard);
    definitions.extend(runtime_monad_traversal_list_tree_definitions(
        builtin, discard,
    ));
    definitions
}

fn runtime_monad_traversal_base_definitions(
    builtin: &'static str,
    discard: bool,
) -> Vec<RuntimeMonadTraversalDefinition> {
    let mut definitions = runtime_monad_traversal_io_definitions(builtin, discard);
    definitions.extend(runtime_monad_traversal_maybe_definitions(builtin, discard));
    definitions.extend(runtime_monad_traversal_either_definitions(builtin, discard));
    definitions
}

fn runtime_monad_traversal_io_definitions(
    builtin: &'static str,
    discard: bool,
) -> Vec<RuntimeMonadTraversalDefinition> {
    let callback_argument = traversal_callback_argument(builtin);
    let int = runtime_traversal_int;
    let io_finite_callback = if discard {
        "\\value -> do { IO.print value; IO.pure () }"
    } else {
        "\\value -> do { IO.print value; IO.pure (Int.plus value 10) }"
    };
    let io_finite_source = if discard {
        format!(
            "main = do {{ {}; Text.putStr \"done\" }}\n",
            traversal_call(builtin, io_finite_callback, "[1,2]")
        )
    } else {
        format!(
            "main = do {{ values <- {}; IO.print values }}\n",
            traversal_call(builtin, io_finite_callback, "[1,2]")
        )
    };
    let io_result = "{\"type\":\"IoAction\"}";
    let io_finite_callbacks = [1, 2]
        .into_iter()
        .map(|value| runtime_traversal_callback(callback_argument, &int(value), io_result))
        .collect();
    let io_short_callback = if discard {
        "\\_ -> (Exit.exitWith (Exit.ExitFailure 1) :: IO ())"
    } else {
        "\\_ -> (Exit.exitWith (Exit.ExitFailure 1) :: IO Int)"
    };
    let io_short_source = format!(
        "main = do {{ _result <- {}; IO.pure () }}\n",
        traversal_call(builtin, io_short_callback, "[1,2]")
    );
    vec![
        runtime_monad_traversal_definition!(
            "io",
            "IO",
            "finite",
            io_finite_source,
            if discard {
                b"1\n2\ndone".as_slice()
            } else {
                b"1\n2\n[11,12]\n".as_slice()
            }
            .to_vec(),
            io_result.to_owned(),
            true,
            traversal_exit_states(builtin, true, true),
            io_finite_callbacks,
        ),
        runtime_monad_traversal_definition!(
            "io",
            "IO",
            "short-circuit",
            io_short_source,
            Vec::new(),
            io_result.to_owned(),
            false,
            traversal_exit_states(builtin, true, true),
            vec![runtime_traversal_callback(
                callback_argument,
                "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}",
                io_result,
            )],
        ),
    ]
}

fn runtime_monad_traversal_maybe_definitions(
    builtin: &'static str,
    discard: bool,
) -> Vec<RuntimeMonadTraversalDefinition> {
    let callback_argument = traversal_callback_argument(builtin);
    let int = runtime_traversal_int;
    let maybe = |value: &str| format!("{{\"type\":\"Maybe\",\"payload\":{value}}}");
    let values = runtime_traversal_list(&[int(11), int(12)]);
    let unit = "{\"type\":\"Unit\",\"value\":null}";
    let maybe_finite_callback = if discard {
        concat!(
            "\\value -> if Int.eq value 1 then ",
            "Maybe.Just () else Maybe.Just ()"
        )
    } else {
        "\\value -> Maybe.Just (Int.plus value 10)"
    };
    let maybe_finite_source = if discard {
        format!(
            concat!(
                "main = case ({} :: Maybe ()) of {{ ",
                "Maybe.Just ignored -> Text.putStrLn \"just\"; ",
                "Maybe.Nothing -> Text.putStrLn \"nothing\" }}\n"
            ),
            traversal_call(builtin, maybe_finite_callback, "[1,2]")
        )
    } else {
        format!(
            "main = IO.print ({} :: Maybe [Int])\n",
            traversal_call(builtin, maybe_finite_callback, "[1,2]")
        )
    };
    let maybe_callback_results = if discard {
        vec![
            maybe("{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}"),
            maybe("{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}"),
        ]
    } else {
        vec![maybe(&int(11)), maybe(&int(12))]
    };
    let maybe_finite_callbacks = [1, 2]
        .into_iter()
        .zip(maybe_callback_results)
        .map(|(argument, result)| {
            let argument = int(argument);
            runtime_traversal_callback(callback_argument, &argument, &result)
        })
        .collect();
    let maybe_short_callback = if discard {
        "\\_ -> (Maybe.Nothing :: Maybe ())"
    } else {
        "\\_ -> (Maybe.Nothing :: Maybe Int)"
    };
    let maybe_short_source = if discard {
        format!(
            concat!(
                "main = case ({} :: Maybe ()) of {{ ",
                "Maybe.Just ignored -> Text.putStrLn \"just\"; ",
                "Maybe.Nothing -> Text.putStrLn \"nothing\" }}\n"
            ),
            traversal_call(builtin, maybe_short_callback, "[1,2]")
        )
    } else {
        format!(
            "main = IO.print ({} :: Maybe [Int])\n",
            traversal_call(builtin, maybe_short_callback, "[1,2]")
        )
    };
    vec![
        runtime_monad_traversal_definition!(
            "maybe",
            "Maybe",
            "finite",
            maybe_finite_source,
            if discard {
                b"just\n".as_slice()
            } else {
                b"Just [11,12]\n".as_slice()
            }
            .to_vec(),
            maybe(if discard { unit } else { &values }),
            true,
            traversal_exit_states(builtin, false, true),
            maybe_finite_callbacks,
        ),
        runtime_monad_traversal_definition!(
            "maybe",
            "Maybe",
            "short-circuit",
            maybe_short_source,
            if discard { b"nothing\n" } else { b"Nothing\n" }.to_vec(),
            "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
            true,
            traversal_exit_states(builtin, false, true),
            vec![runtime_traversal_callback(
                callback_argument,
                "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}",
                "{\"type\":\"Maybe\",\"payload\":null}",
            )],
        ),
    ]
}

fn runtime_monad_traversal_either_definitions(
    builtin: &'static str,
    discard: bool,
) -> Vec<RuntimeMonadTraversalDefinition> {
    let callback_argument = traversal_callback_argument(builtin);
    let int = runtime_traversal_int;
    let right = |value: &str| {
        format!(
            "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{value}]}}"
        )
    };
    let left = "{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{\"type\":\"Text\",\"utf8Hex\":\"6669727374\"}]}";
    let values = runtime_traversal_list(&[int(11), int(12)]);
    let unit = "{\"type\":\"Unit\",\"value\":null}";
    let (either_finite_source, either_short_source) =
        runtime_monad_traversal_either_sources(builtin, discard);
    let either_callback_results = if discard {
        vec![
            right("{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}"),
            right("{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}"),
        ]
    } else {
        vec![right(&int(11)), right(&int(12))]
    };
    let either_finite_callbacks = [1, 2]
        .into_iter()
        .zip(either_callback_results)
        .map(|(argument, result)| {
            runtime_traversal_callback(callback_argument, &int(argument), &result)
        })
        .collect();
    vec![
        runtime_monad_traversal_definition!(
            "either",
            "Either",
            "finite",
            either_finite_source,
            if discard {
                b"right\n".as_slice()
            } else {
                b"Right [11,12]\n".as_slice()
            }
            .to_vec(),
            right(if discard { unit } else { &values }),
            true,
            traversal_exit_states(builtin, false, true),
            either_finite_callbacks,
        ),
        runtime_monad_traversal_definition!(
            "either",
            "Either",
            "short-circuit",
            either_short_source,
            b"first\n".to_vec(),
            left.to_owned(),
            true,
            traversal_exit_states(builtin, false, true),
            vec![runtime_traversal_callback(
                callback_argument,
                "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}",
                left,
            )],
        ),
    ]
}

fn runtime_monad_traversal_either_sources(builtin: &str, discard: bool) -> (String, String) {
    let either_finite_callback = if discard {
        concat!(
            "\\value -> if Int.eq value 1 then ",
            "Either.Right () else Either.Right ()"
        )
    } else {
        "\\value -> Either.Right (Int.plus value 10)"
    };
    let either_finite_source = if discard {
        format!(
            concat!(
                "main = case ({} :: Either Text ()) of {{ ",
                "Either.Left text -> Text.putStrLn text; ",
                "Either.Right ignored -> Text.putStrLn \"right\" }}\n"
            ),
            traversal_call(builtin, either_finite_callback, "[1,2]")
        )
    } else {
        format!(
            "main = IO.print ({} :: Either Text [Int])\n",
            traversal_call(builtin, either_finite_callback, "[1,2]")
        )
    };
    let either_short_callback = if discard {
        "\\_ -> (Either.Left \"first\" :: Either Text ())"
    } else {
        "\\_ -> (Either.Left \"first\" :: Either Text Int)"
    };
    let either_short_source = if discard {
        format!(
            concat!(
                "main = case ({} :: Either Text ()) of {{ ",
                "Either.Left text -> Text.putStrLn text; ",
                "Either.Right ignored -> Text.putStrLn \"right\" }}\n"
            ),
            traversal_call(builtin, either_short_callback, "[1,2]")
        )
    } else {
        format!(
            concat!(
                "main = case ({} :: Either Text [Int]) of {{ ",
                "Either.Left text -> Text.putStrLn text; Either.Right value -> IO.print value }}\n"
            ),
            traversal_call(builtin, either_short_callback, "[1,2]")
        )
    };
    (either_finite_source, either_short_source)
}

fn runtime_monad_traversal_list_tree_definitions(
    builtin: &'static str,
    discard: bool,
) -> Vec<RuntimeMonadTraversalDefinition> {
    let mut definitions = runtime_monad_traversal_list_definitions(builtin, discard);
    definitions.extend(runtime_monad_traversal_tree_definitions(builtin, discard));
    definitions
}

fn runtime_monad_traversal_list_definitions(
    builtin: &'static str,
    discard: bool,
) -> Vec<RuntimeMonadTraversalDefinition> {
    let callback_argument = traversal_callback_argument(builtin);
    let int = runtime_traversal_int;
    let unit = "{\"type\":\"Unit\",\"value\":null}".to_owned();
    let callback = if discard {
        "\\value -> if Int.eq value 1 then [(),()] else [(),()]"
    } else {
        "\\value -> [value, Int.plus value 10]"
    };
    let list_finite = traversal_call(builtin, callback, "[1,2]");
    let list_finite_source = if discard {
        format!("main = IO.print $ List.length $ ({list_finite} :: [()])\n")
    } else {
        format!("main = IO.print ({list_finite} :: [[Int]])\n")
    };
    let list_empty = traversal_call(
        builtin,
        if discard {
            "\\_ -> Error.error \"forged\" :: [()]"
        } else {
            "\\_ -> Error.error \"forged\" :: [Int]"
        },
        "[] :: [Int]",
    );
    let list_empty_source = if discard {
        format!("main = IO.print $ List.length $ ({list_empty} :: [()])\n")
    } else {
        format!("main = IO.print ({list_empty} :: [[Int]])\n")
    };
    let callback_one = if discard {
        runtime_traversal_list(&[
            "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}".to_owned(),
            "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}".to_owned(),
        ])
    } else {
        runtime_traversal_list(&[int(1), int(11)])
    };
    let callback_two = if discard {
        runtime_traversal_list(&[
            "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}".to_owned(),
            "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}".to_owned(),
        ])
    } else {
        runtime_traversal_list(&[int(2), int(12)])
    };
    let first_argument = int(1);
    let second_argument = int(2);
    let combinations = runtime_traversal_list(&[
        runtime_traversal_list(&[int(1), int(2)]),
        runtime_traversal_list(&[int(1), int(12)]),
        runtime_traversal_list(&[int(11), int(2)]),
        runtime_traversal_list(&[int(11), int(12)]),
    ]);
    let list_units =
        runtime_traversal_list(&[unit.clone(), unit.clone(), unit.clone(), unit.clone()]);
    let list_empty_result = runtime_traversal_list(&[if discard {
        unit.clone()
    } else {
        runtime_traversal_list(&[])
    }]);
    vec![
        runtime_monad_traversal_definition!(
            "list",
            "[]",
            "finite",
            list_finite_source,
            if discard {
                b"4\n".as_slice()
            } else {
                b"[[1,2],[1,12],[11,2],[11,12]]\n".as_slice()
            }
            .to_vec(),
            if discard { list_units } else { combinations },
            true,
            traversal_exit_states(builtin, false, true),
            vec![
                runtime_traversal_callback(callback_argument, &first_argument, &callback_one),
                runtime_traversal_callback(callback_argument, &second_argument, &callback_two),
            ],
        ),
        runtime_monad_traversal_definition!(
            "list",
            "[]",
            "empty",
            list_empty_source,
            if discard {
                b"1\n".as_slice()
            } else {
                b"[[]]\n".as_slice()
            }
            .to_vec(),
            list_empty_result,
            true,
            traversal_exit_states(builtin, false, false),
            Vec::new(),
        ),
    ]
}

struct RuntimeTraversalTreeValues {
    first: String,
    second: String,
    result: String,
    empty: String,
}

fn runtime_traversal_tree_values(discard: bool) -> RuntimeTraversalTreeValues {
    let int = runtime_traversal_int;
    let not_forced = "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}".to_owned();
    let callback_tree = |root: String, child: String| {
        runtime_traversal_tree(&root, &[runtime_traversal_tree(&child, &[])])
    };
    let first = if discard {
        callback_tree(not_forced.clone(), not_forced.clone())
    } else {
        callback_tree(int(11), int(21))
    };
    let second = if discard {
        callback_tree(not_forced.clone(), not_forced.clone())
    } else {
        callback_tree(int(12), int(22))
    };
    let result = if discard {
        runtime_traversal_tree(
            &not_forced,
            &[
                runtime_traversal_tree(&not_forced, &[]),
                callback_tree(not_forced.clone(), not_forced.clone()),
            ],
        )
    } else {
        runtime_traversal_tree_combinations()
    };
    let empty_root = if discard {
        not_forced
    } else {
        runtime_traversal_list(&[])
    };
    let empty = runtime_traversal_tree(&empty_root, &[]);
    RuntimeTraversalTreeValues {
        first,
        second,
        result,
        empty,
    }
}

fn runtime_monad_traversal_tree_definitions(
    builtin: &'static str,
    discard: bool,
) -> Vec<RuntimeMonadTraversalDefinition> {
    let callback_argument = traversal_callback_argument(builtin);
    let first_argument = runtime_traversal_int(1);
    let second_argument = runtime_traversal_int(2);
    let tree_callback = if discard {
        concat!(
            "\\value -> if Int.eq value 1 then ",
            "Tree.Node () [Tree.Node () []] else ",
            "Tree.Node () [Tree.Node () []]"
        )
    } else {
        concat!(
            "\\value -> Tree.Node (Int.plus value 10) ",
            "[Tree.Node (Int.plus value 20) []]"
        )
    };
    let tree_finite = traversal_call(builtin, tree_callback, "[1,2]");
    let tree_finite_source = if discard {
        format!("main = IO.print $ List.length $ Tree.flatten $ ({tree_finite} :: Tree ())\n")
    } else {
        format!("main = IO.print $ Tree.flatten $ ({tree_finite} :: Tree [Int])\n")
    };
    let tree_empty = traversal_call(
        builtin,
        if discard {
            "\\_ -> Error.error \"forged\" :: Tree ()"
        } else {
            "\\_ -> Error.error \"forged\" :: Tree Int"
        },
        "[] :: [Int]",
    );
    let tree_empty_source = if discard {
        format!("main = IO.print $ List.length $ Tree.flatten $ ({tree_empty} :: Tree ())\n")
    } else {
        format!("main = IO.print $ Tree.flatten $ ({tree_empty} :: Tree [Int])\n")
    };
    let RuntimeTraversalTreeValues {
        first,
        second,
        result,
        empty,
    } = runtime_traversal_tree_values(discard);
    vec![
        runtime_monad_traversal_definition!(
            "tree",
            "Tree",
            "finite",
            tree_finite_source,
            if discard {
                b"4\n".as_slice()
            } else {
                b"[[11,12],[11,22],[21,12],[21,22]]\n".as_slice()
            }
            .to_vec(),
            result,
            true,
            traversal_exit_states(builtin, false, discard),
            vec![
                runtime_traversal_callback(callback_argument, &first_argument, &first),
                runtime_traversal_callback(callback_argument, &second_argument, &second),
            ],
        ),
        runtime_monad_traversal_definition!(
            "tree",
            "Tree",
            "empty",
            tree_empty_source,
            if discard {
                b"1\n".as_slice()
            } else {
                b"[[]]\n".as_slice()
            }
            .to_vec(),
            empty,
            true,
            traversal_exit_states(builtin, false, false),
            Vec::new(),
        ),
    ]
}

fn traversal_call(builtin: &str, callback: &str, list: &str) -> String {
    if builtin.contains("forM") {
        format!("{builtin} ({list}) ({callback})")
    } else {
        format!("{builtin} ({callback}) ({list})")
    }
}

fn runtime_monad_traversal_slug(builtin: &str) -> &'static str {
    match builtin {
        "Monad.mapM" => "monad-mapm",
        "Monad.forM" => "monad-form",
        "Monad.mapM_" => "monad-mapm-discard",
        "Monad.forM_" => "monad-form-discard",
        _ => unreachable!("monad traversal builtin is closed"),
    }
}

fn traversal_callback_argument(builtin: &str) -> u16 {
    u16::from(builtin.contains("forM"))
}

fn traversal_exit_states(builtin: &str, io: bool, callback_used: bool) -> Vec<(u16, &'static str)> {
    let callback = traversal_callback_argument(builtin);
    let list = 1 - callback;
    let mut states = vec![
        (
            callback,
            if io || !callback_used {
                "not-forced"
            } else {
                "value"
            },
        ),
        (list, "value"),
    ];
    states.sort_unstable_by_key(|(argument, _)| *argument);
    states
}

fn runtime_traversal_callback(
    callback_argument: u16,
    argument: &str,
    result: &str,
) -> CallbackInvocationContract {
    callback_contract_invocation(callback_argument, "element", &[argument], result)
}

fn runtime_traversal_int(value: i64) -> String {
    format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}")
}

fn runtime_traversal_list(values: &[String]) -> String {
    format!(
        "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}",
        values.join(",")
    )
}

fn runtime_traversal_tree(root: &str, children: &[String]) -> String {
    format!(
        "{{\"type\":\"Tree\",\"elements\":[{root},{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}]}}",
        children.join(",")
    )
}

fn runtime_traversal_tree_combinations() -> String {
    let indirect_pair = |left, right| {
        let tail = runtime_traversal_list(&[runtime_traversal_int(right)]);
        let termination = runtime_bytes_hex(format!("indirection:{tail}").as_bytes());
        format!(
            "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"{termination}\"}}",
            runtime_traversal_int(left)
        )
    };
    let cross = runtime_traversal_tree(&indirect_pair(21, 22), &[]);
    let left_branch = runtime_traversal_tree(&indirect_pair(11, 22), &[]);
    let right_branch = runtime_traversal_tree(&indirect_pair(21, 12), &[cross]);
    runtime_traversal_tree(&indirect_pair(11, 12), &[left_branch, right_branch])
}

struct RuntimeFunctorDefinition {
    instance: &'static str,
    path: &'static str,
    source: String,
    arguments: Vec<OsString>,
    stdout: &'static [u8],
    stderr: &'static [u8],
    completion: bool,
    exit_states: &'static [(u16, &'static str)],
    invocations: Vec<CallbackInvocationContract>,
}

fn runtime_functor_cases() -> Vec<DifferentialCase> {
    ["Functor.fmap", "<$>"]
        .into_iter()
        .flat_map(|builtin| {
            runtime_functor_definitions(builtin)
                .into_iter()
                .map(move |definition| runtime_functor_case(builtin, definition))
        })
        .collect()
}

fn runtime_functor_case(
    builtin: &'static str,
    definition: RuntimeFunctorDefinition,
) -> DifferentialCase {
    let mut descriptor = runtime_single_typed_target_descriptor(builtin, &definition.source);
    let target = &mut descriptor.semantic_targets[0];
    target.obligations.retain(|obligation| {
        if definition.path == "mapped" {
            obligation.0.as_ref() != "lazy-boundary"
        } else {
            matches!(obligation.0.as_ref(), "callback-order" | "lazy-boundary")
        }
    });
    target.expected_instance_target = Some(Arc::from(definition.instance));
    target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(
        definition.stdout,
        definition.stderr,
    ));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(
        definition.completion,
        Some(i32::from(!definition.completion)),
    ));
    target.expected_lazy_argument_exit_sha256 = Some(crate::lazy_argument_exit_sha256(
        definition.exit_states.iter().copied(),
    ));
    if let Some(value) = runtime_functor_typed_result(definition.instance, definition.path) {
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{value}}}"
        );
        target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    }
    descriptor.callback_contracts = vec![CallbackContract {
        builtin: Arc::from(builtin),
        invocations: definition.invocations,
    }];
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-typed-functor-{}-{}-{}",
            runtime_functor_slug(builtin),
            runtime_functor_instance_slug(definition.instance),
            definition.path,
        )),
        source: Arc::from(definition.source),
        arguments: definition.arguments,
        expected_runtime_completion: definition.completion,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_functor_definitions(builtin: &'static str) -> Vec<RuntimeFunctorDefinition> {
    let mut definitions = runtime_functor_list_io_definitions(builtin);
    definitions.extend(runtime_functor_parser_tree_definitions(builtin));
    definitions.extend(runtime_functor_sum_product_definitions(builtin));
    definitions
}

fn runtime_functor_list_io_definitions(builtin: &str) -> Vec<RuntimeFunctorDefinition> {
    const DEFERRED: &[(u16, &str)] = &[(0, "not-forced"), (1, "not-forced")];
    let list_finite = runtime_functor_apply(builtin, "\\value -> Int.plus value 10", "[1,2]");
    let list_empty = runtime_functor_apply(
        builtin,
        "\\_ -> Error.error \"forged list callback\" :: Int",
        "([] :: [Int])",
    );
    let io_finite = runtime_functor_apply(builtin, "\\value -> Int.plus value 10", "IO.pure 1");
    let io_failure = runtime_functor_apply(
        builtin,
        "\\_ -> Error.error \"forged IO callback\" :: Int",
        "(Exit.exitWith (Exit.ExitFailure 1) :: IO Int)",
    );
    vec![
        runtime_functor_definition(
            "[]",
            "mapped",
            format!("main = IO.print $ {list_finite}\n"),
            b"[11,12]\n",
            true,
            DEFERRED,
            vec![
                runtime_functor_int_callback("element", 1, 11),
                runtime_functor_int_callback("element", 2, 12),
            ],
        ),
        runtime_functor_definition(
            "[]",
            "short",
            format!("main = IO.print $ {list_empty}\n"),
            b"[]\n",
            true,
            DEFERRED,
            Vec::new(),
        ),
        runtime_functor_definition(
            "IO",
            "mapped",
            format!("main = do\n  value <- {io_finite}\n  IO.print value\n"),
            b"11\n",
            true,
            DEFERRED,
            vec![runtime_functor_int_callback("io-result", 1, 11)],
        ),
        runtime_functor_definition(
            "IO",
            "short",
            format!("main = do\n  _value <- {io_failure}\n  IO.pure ()\n"),
            b"",
            false,
            DEFERRED,
            Vec::new(),
        ),
    ]
}

fn runtime_functor_parser_tree_definitions(builtin: &str) -> Vec<RuntimeFunctorDefinition> {
    const CONTAINER: &[(u16, &str)] = &[(0, "not-forced"), (1, "value")];
    let parser = runtime_functor_apply(
        builtin,
        "\\value -> Text.length value",
        "(Options.strOption $ Option.long \"name\")",
    );
    let tree = runtime_functor_apply(
        builtin,
        "\\value -> Int.plus value 10",
        "(Tree.Node 1 [Tree.Node 2 []])",
    );
    let singleton_tree =
        runtime_functor_apply(builtin, "\\value -> Int.plus value 10", "(Tree.Node 1 [])");
    vec![
        RuntimeFunctorDefinition {
            instance: "Options.Parser",
            path: "mapped",
            source: format!(
                "parser = {parser}\nmain = do\n  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  IO.print value\n"
            ),
            arguments: vec!["--name".into(), "alpha".into()],
            stdout: b"5\n",
            stderr: b"",
            completion: true,
            exit_states: CONTAINER,
            invocations: vec![callback_contract_invocation(
                0,
                "parser-result",
                &["{\"type\":\"Text\",\"utf8Hex\":\"616c706861\"}"],
                "{\"type\":\"Int\",\"value\":\"5\"}",
            )],
        },
        RuntimeFunctorDefinition {
            instance: "Options.Parser",
            path: "short",
            source: format!(
                "parser = {parser}\nmain = do\n  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  IO.print value\n"
            ),
            arguments: Vec::new(),
            stdout: b"",
            stderr: b"Missing: --name ARG\n\nUsage: hell --name ARG\n",
            completion: false,
            exit_states: CONTAINER,
            invocations: Vec::new(),
        },
        runtime_functor_definition(
            "Tree",
            "mapped",
            format!("main = IO.print $ Tree.flatten $ {tree}\n"),
            b"[11,12]\n",
            true,
            CONTAINER,
            vec![
                runtime_functor_int_callback("node", 1, 11),
                runtime_functor_int_callback("node", 2, 12),
            ],
        ),
        runtime_functor_definition(
            "Tree",
            "short",
            format!("main = IO.print $ Tree.flatten $ {singleton_tree}\n"),
            b"[11]\n",
            true,
            CONTAINER,
            vec![runtime_functor_int_callback("node", 1, 11)],
        ),
    ]
}

fn runtime_functor_sum_product_definitions(builtin: &str) -> Vec<RuntimeFunctorDefinition> {
    let mut definitions = runtime_functor_maybe_either_definitions(builtin);
    definitions.extend(runtime_functor_pair_definitions(builtin));
    definitions
}

fn runtime_functor_maybe_either_definitions(builtin: &str) -> Vec<RuntimeFunctorDefinition> {
    const CONTAINER: &[(u16, &str)] = &[(0, "not-forced"), (1, "value")];
    let just = runtime_functor_apply(builtin, "\\value -> Int.plus value 10", "Maybe.Just 1");
    let nothing = runtime_functor_apply(
        builtin,
        "\\_ -> Error.error \"forged Maybe callback\" :: Int",
        "(Maybe.Nothing :: Maybe Int)",
    );
    let right = runtime_functor_apply(
        builtin,
        "\\value -> Int.plus value 10",
        "(Either.Right 1 :: Either Text Int)",
    );
    let left = runtime_functor_apply(
        builtin,
        "\\_ -> Error.error \"forged Either callback\" :: Int",
        "(Either.Left \"left\" :: Either Text Int)",
    );
    vec![
        runtime_functor_definition(
            "Maybe",
            "mapped",
            format!("main = IO.print $ {just}\n"),
            b"Just 11\n",
            true,
            CONTAINER,
            vec![runtime_functor_int_callback("just", 1, 11)],
        ),
        runtime_functor_definition(
            "Maybe",
            "short",
            format!("main = IO.print $ {nothing}\n"),
            b"Nothing\n",
            true,
            CONTAINER,
            Vec::new(),
        ),
        runtime_functor_definition(
            "Either",
            "mapped",
            format!("main = IO.print $ {right}\n"),
            b"Right 11\n",
            true,
            CONTAINER,
            vec![runtime_functor_int_callback("right", 1, 11)],
        ),
        runtime_functor_definition(
            "Either",
            "short",
            format!("main = IO.print $ {left}\n"),
            b"Left \"left\"\n",
            true,
            CONTAINER,
            Vec::new(),
        ),
    ]
}

fn runtime_functor_pair_definitions(builtin: &str) -> Vec<RuntimeFunctorDefinition> {
    const CONTAINER: &[(u16, &str)] = &[(0, "not-forced"), (1, "value")];
    let mapped = runtime_functor_apply(builtin, "\\value -> Int.plus value 10", "(\"keep\", 1)");
    let short = runtime_functor_apply(
        builtin,
        "\\_ -> Error.error \"forged pair callback\" :: Int",
        "(\"keep\", Error.error \"undemanded pair second\" :: Int)",
    );
    vec![
        runtime_functor_definition(
            "(,)",
            "mapped",
            format!("main = IO.print $ {mapped}\n"),
            b"(\"keep\",11)\n",
            true,
            CONTAINER,
            vec![runtime_functor_int_callback("second", 1, 11)],
        ),
        runtime_functor_definition(
            "(,)",
            "short",
            format!("main = (\\(first, ignored) -> Text.putStr first) ({short})\n"),
            b"keep",
            true,
            CONTAINER,
            Vec::new(),
        ),
    ]
}

fn runtime_functor_definition(
    instance: &'static str,
    path: &'static str,
    source: String,
    stdout: &'static [u8],
    completion: bool,
    exit_states: &'static [(u16, &'static str)],
    invocations: Vec<CallbackInvocationContract>,
) -> RuntimeFunctorDefinition {
    RuntimeFunctorDefinition {
        instance,
        path,
        source,
        arguments: Vec::new(),
        stdout,
        stderr: b"",
        completion,
        exit_states,
        invocations,
    }
}

fn runtime_functor_apply(builtin: &str, function: &str, value: &str) -> String {
    if builtin == "Functor.fmap" {
        format!("Functor.fmap ({function}) ({value})")
    } else {
        format!("({function}) <$> ({value})")
    }
}

fn runtime_functor_int_callback(
    branch: &str,
    argument: i64,
    result: i64,
) -> CallbackInvocationContract {
    callback_contract_invocation(
        0,
        branch,
        &[&runtime_traversal_int(argument)],
        &runtime_traversal_int(result),
    )
}

fn runtime_functor_slug(builtin: &str) -> &'static str {
    if builtin == "Functor.fmap" {
        "fmap"
    } else {
        "operator"
    }
}

fn runtime_functor_instance_slug(instance: &str) -> &'static str {
    match instance {
        "[]" => "list",
        "IO" => "io",
        "Options.Parser" => "parser",
        "Tree" => "tree",
        "Maybe" => "maybe",
        "Either" => "either",
        "(,)" => "pair",
        _ => unreachable!("Functor direct instance set is closed"),
    }
}

fn runtime_functor_typed_result(instance: &str, path: &str) -> Option<String> {
    let int = runtime_traversal_int;
    let value = match (instance, path) {
        ("[]", "mapped") => runtime_traversal_list(&[int(11), int(12)]),
        ("[]", "short") => runtime_traversal_list(&[]),
        ("IO", _) => "{\"type\":\"IoAction\"}".to_owned(),
        ("Options.Parser", _) => return None,
        ("Tree", "mapped") => {
            runtime_traversal_tree(&int(11), &[runtime_traversal_tree(&int(12), &[])])
        }
        ("Tree", "short") => runtime_traversal_tree(&int(11), &[]),
        ("Maybe", "mapped") => {
            format!("{{\"type\":\"Maybe\",\"payload\":{}}}", int(11))
        }
        ("Maybe", "short") => "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
        ("Either", "mapped") => format!(
            "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{}]}}",
            int(11)
        ),
        ("Either", "short") => concat!(
            "{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",",
            "\"constructor\":\"Left\",\"payloads\":[",
            "{\"type\":\"Text\",\"utf8Hex\":\"6c656674\"}]}"
        )
        .to_owned(),
        ("(,)", "mapped") => format!(
            "{{\"type\":\"Tuple\",\"elements\":[{{\"type\":\"Text\",\"utf8Hex\":\"6b656570\"}},{}]}}",
            int(11)
        ),
        ("(,)", "short") => concat!(
            "{\"type\":\"Tuple\",\"elements\":[",
            "{\"type\":\"Text\",\"utf8Hex\":\"6b656570\"},",
            "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}]}"
        )
        .to_owned(),
        _ => unreachable!("Functor instance/path matrix is closed"),
    };
    Some(value)
}

struct RuntimeApplicativeDefinition {
    builtin: &'static str,
    instance: &'static str,
    path: &'static str,
    source: String,
    arguments: Vec<OsString>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    success: bool,
    typed_value: Option<String>,
    exit_states: Vec<(u16, &'static str)>,
    callbacks: Vec<CallbackInvocationContract>,
}

fn runtime_applicative_cases() -> Vec<DifferentialCase> {
    let mut definitions = runtime_applicative_pure_definitions();
    for builtin in ["<*>", "<**>"] {
        definitions.extend(runtime_applicative_apply_definitions(builtin));
    }
    definitions
        .into_iter()
        .map(runtime_applicative_case)
        .collect()
}

fn runtime_applicative_case(definition: RuntimeApplicativeDefinition) -> DifferentialCase {
    let mut descriptor =
        runtime_single_typed_target_descriptor(definition.builtin, &definition.source);
    let target = &mut descriptor.semantic_targets[0];
    let has_callbacks = !definition.callbacks.is_empty();
    if definition.builtin == "Applicative.pure" {
        if definition.path == "lazy" {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() == "lazy-boundary");
        } else {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "lazy-boundary");
        }
    } else if !has_callbacks {
        target
            .obligations
            .retain(|obligation| obligation.0.as_ref() == "lazy-boundary");
    } else if definition.instance != "Tree" {
        target
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "lazy-boundary");
    }
    target.expected_instance_target = Some(Arc::from(definition.instance));
    target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(
        &definition.stdout,
        &definition.stderr,
    ));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(
        definition.success,
        Some(i32::from(!definition.success)),
    ));
    target.expected_lazy_argument_exit_sha256 = Some(crate::lazy_argument_exit_sha256(
        definition.exit_states.iter().copied(),
    ));
    if let Some(value) = definition.typed_value {
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{value}}}"
        );
        target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    }
    descriptor.callback_contracts = if definition.builtin == "Applicative.pure" {
        Vec::new()
    } else {
        vec![CallbackContract {
            builtin: Arc::from(definition.builtin),
            invocations: definition.callbacks,
        }]
    };
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-typed-applicative-{}-{}-{}",
            runtime_applicative_builtin_slug(definition.builtin),
            runtime_applicative_instance_slug(definition.instance),
            definition.path,
        )),
        source: Arc::from(definition.source),
        arguments: definition.arguments,
        expected_runtime_completion: definition.success,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_applicative_pure_definitions() -> Vec<RuntimeApplicativeDefinition> {
    let int = runtime_traversal_int(7);
    let deferred = "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}";
    let list = |value: &str| runtime_traversal_list(&[value.to_owned()]);
    let tree = |value: &str| runtime_traversal_tree(value, &[]);
    let maybe = |value: &str| format!("{{\"type\":\"Maybe\",\"payload\":{value}}}");
    let right = |value: &str| {
        format!(
            "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{value}]}}"
        )
    };
    [
        ("IO", "value", "main = do { value <- (Applicative.pure 7 :: IO Int); IO.print value }\n", b"7\n".as_slice(), Some("{\"type\":\"IoAction\"}".to_owned())),
        ("IO", "lazy", "main = do { _value <- (Applicative.pure (Error.error \"forced IO pure\" :: Int) :: IO Int); Text.putStr \"ok\" }\n", b"ok".as_slice(), Some("{\"type\":\"IoAction\"}".to_owned())),
        ("Maybe", "value", "main = IO.print (Applicative.pure 7 :: Maybe Int)\n", b"Just 7\n".as_slice(), Some(maybe(&int))),
        ("Maybe", "lazy", "main = case (Applicative.pure (Error.error \"forced Maybe pure\" :: Int) :: Maybe Int) of { Maybe.Just _value -> Text.putStr \"ok\"; Maybe.Nothing -> Text.putStr \"bad\" }\n", b"ok".as_slice(), Some(maybe(deferred))),
        ("[]", "value", "main = IO.print (Applicative.pure 7 :: [Int])\n", b"[7]\n".as_slice(), Some(list(&int))),
        ("[]", "lazy", "main = IO.print $ List.length (Applicative.pure (Error.error \"forced List pure\" :: Int) :: [Int])\n", b"1\n".as_slice(), Some(list(deferred))),
        ("Tree", "value", "main = IO.print $ Tree.flatten (Applicative.pure 7 :: Tree Int)\n", b"[7]\n".as_slice(), Some(tree(&int))),
        ("Tree", "lazy", "main = IO.print $ List.length $ Tree.flatten (Applicative.pure (Error.error \"forced Tree pure\" :: Int) :: Tree Int)\n", b"1\n".as_slice(), Some(tree(deferred))),
        ("Options.Parser", "value", "main = do { value <- Options.execParser $ Options.info (Applicative.pure 7) Options.fullDesc; IO.print value }\n", b"7\n".as_slice(), None),
        ("Options.Parser", "lazy", "main = do { _value <- Options.execParser $ Options.info (Applicative.pure (Error.error \"forced Parser pure\" :: Int)) Options.fullDesc; Text.putStr \"ok\" }\n", b"ok".as_slice(), None),
        ("Either", "value", "main = IO.print (Applicative.pure 7 :: Either Text Int)\n", b"Right 7\n".as_slice(), Some(right(&int))),
        ("Either", "lazy", "main = case (Applicative.pure (Error.error \"forced Either pure\" :: Int) :: Either Text Int) of { Either.Left _text -> Text.putStr \"bad\"; Either.Right _value -> Text.putStr \"ok\" }\n", b"ok".as_slice(), Some(right(deferred))),
    ]
    .into_iter()
    .map(|(instance, path, source, stdout, typed_value)| RuntimeApplicativeDefinition {
        builtin: "Applicative.pure",
        instance,
        path,
        source: source.to_owned(),
        arguments: Vec::new(),
        stdout: stdout.to_vec(),
        stderr: Vec::new(),
        success: true,
        typed_value,
        exit_states: vec![(0, "not-forced")],
        callbacks: Vec::new(),
    })
    .collect()
}

fn runtime_applicative_apply_definitions(
    builtin: &'static str,
) -> Vec<RuntimeApplicativeDefinition> {
    let mut definitions = runtime_applicative_io_definitions(builtin);
    definitions.extend(runtime_applicative_maybe_either_definitions(builtin));
    definitions.extend(runtime_applicative_list_tree_definitions(builtin));
    definitions.extend(runtime_applicative_parser_definitions(builtin));
    definitions
}

macro_rules! runtime_applicative_definition {
    ($builtin:expr, $instance:expr, $path:expr, $source:expr, $stdout:expr, $success:expr,
     $typed_value:expr, $exit_states:expr, $callbacks:expr $(,)?) => {
        RuntimeApplicativeDefinition {
            builtin: $builtin,
            instance: $instance,
            path: $path,
            source: $source,
            arguments: Vec::new(),
            stdout: $stdout.to_vec(),
            stderr: Vec::new(),
            success: $success,
            typed_value: $typed_value,
            exit_states: $exit_states,
            callbacks: $callbacks,
        }
    };
}

fn runtime_applicative_io_definitions(builtin: &'static str) -> Vec<RuntimeApplicativeDefinition> {
    let flipped = builtin == "<**>";
    let operation = runtime_applicative_apply(builtin, "Main.function", "Main.argument");
    let failing = if flipped {
        runtime_applicative_apply(builtin, "Main.function", "Main.failingArgument")
    } else {
        runtime_applicative_apply(builtin, "Main.failingFunction", "Main.argument")
    };
    let prelude = concat!(
        "function = do { Text.putStr \"f\"; IO.pure (Int.plus 10) }\n",
        "argument = do { Text.putStr \"a\"; IO.pure 1 }\n",
        "failingFunction = (Exit.exitWith (Exit.ExitFailure 1) :: IO (Int -> Int))\n",
        "failingArgument = (Exit.exitWith (Exit.ExitFailure 1) :: IO Int)\n",
    );
    vec![
        runtime_applicative_definition!(
            builtin,
            "IO",
            "ordered",
            format!("{prelude}main = do {{ value <- {operation}; IO.print value }}\n"),
            if flipped { b"af11\n" } else { b"fa11\n" },
            true,
            Some("{\"type\":\"IoAction\"}".to_owned()),
            vec![(0, "not-forced"), (1, "not-forced")],
            vec![runtime_applicative_int_callback(builtin, 1, 11)],
        ),
        runtime_applicative_definition!(
            builtin,
            "IO",
            "short",
            format!("{prelude}main = do {{ _value <- {failing}; IO.pure () }}\n"),
            b"",
            false,
            Some("{\"type\":\"IoAction\"}".to_owned()),
            vec![(0, "not-forced"), (1, "not-forced")],
            Vec::new(),
        ),
    ]
}

fn runtime_applicative_maybe_either_definitions(
    builtin: &'static str,
) -> Vec<RuntimeApplicativeDefinition> {
    let maybe_success =
        runtime_applicative_apply(builtin, "Maybe.Just (Int.plus 10)", "Maybe.Just 1");
    let maybe_short = if builtin == "<**>" {
        "(Maybe.Nothing :: Maybe Int) <**> (Error.error \"forced function\" :: Maybe (Int -> Int))"
            .to_owned()
    } else {
        "(Maybe.Nothing :: Maybe (Int -> Int)) <*> (Error.error \"forced argument\" :: Maybe Int)"
            .to_owned()
    };
    let either_success = runtime_applicative_apply(
        builtin,
        "(Either.Right (Int.plus 10) :: Either Text (Int -> Int))",
        "(Either.Right 1 :: Either Text Int)",
    );
    let either_short = if builtin == "<**>" {
        "(Either.Left \"argument\" :: Either Text Int) <**> (Error.error \"forced function\" :: Either Text (Int -> Int))".to_owned()
    } else {
        "(Either.Left \"function\" :: Either Text (Int -> Int)) <*> (Error.error \"forced argument\" :: Either Text Int)".to_owned()
    };
    let int = runtime_traversal_int(11);
    let maybe = format!("{{\"type\":\"Maybe\",\"payload\":{int}}}");
    let right = format!(
        "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{int}]}}"
    );
    let left_text = if builtin == "<**>" {
        "argument"
    } else {
        "function"
    };
    let left = format!(
        "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}]}}",
        runtime_bytes_hex(left_text.as_bytes())
    );
    vec![
        runtime_applicative_definition!(
            builtin,
            "Maybe",
            "success",
            format!("main = IO.print ({maybe_success} :: Maybe Int)\n"),
            b"Just 11\n",
            true,
            Some(maybe),
            vec![(0, "value"), (1, "value")],
            vec![runtime_applicative_int_callback(builtin, 1, 11)]
        ),
        runtime_applicative_definition!(
            builtin,
            "Maybe",
            "short",
            format!("main = IO.print ({maybe_short} :: Maybe Int)\n"),
            b"Nothing\n",
            true,
            Some("{\"type\":\"Maybe\",\"payload\":null}".to_owned()),
            vec![(0, "value"), (1, "not-forced")],
            Vec::new()
        ),
        runtime_applicative_definition!(
            builtin,
            "Either",
            "success",
            format!("main = IO.print ({either_success} :: Either Text Int)\n"),
            b"Right 11\n",
            true,
            Some(right),
            vec![(0, "value"), (1, "value")],
            vec![runtime_applicative_int_callback(builtin, 1, 11)]
        ),
        RuntimeApplicativeDefinition {
            builtin,
            instance: "Either",
            path: "short",
            source: format!("main = IO.print ({either_short} :: Either Text Int)\n"),
            arguments: Vec::new(),
            stdout: format!("Left \"{left_text}\"\n").into_bytes(),
            stderr: Vec::new(),
            success: true,
            typed_value: Some(left),
            exit_states: vec![(0, "value"), (1, "not-forced")],
            callbacks: Vec::new(),
        },
    ]
}

fn runtime_applicative_list_tree_definitions(
    builtin: &'static str,
) -> Vec<RuntimeApplicativeDefinition> {
    let list_success = runtime_applicative_apply(builtin, "[Int.plus 10, Int.mult 2]", "[1,2]");
    let list_short = if builtin == "<**>" {
        "([] :: [Int]) <**> (Error.error \"forced functions\" :: [Int -> Int])".to_owned()
    } else {
        "([] :: [Int -> Int]) <*> (Error.error \"forced arguments\" :: [Int])".to_owned()
    };
    let tree_success = runtime_applicative_apply(
        builtin,
        "(Tree.Node (Int.plus 10) [Tree.Node (Int.mult 2) []])",
        "(Tree.Node 1 [Tree.Node 2 []])",
    );
    let outputs = if builtin == "<**>" {
        [11, 2, 12, 4]
    } else {
        [11, 12, 2, 4]
    };
    let typed_list = runtime_traversal_list(&outputs.map(runtime_traversal_int));
    let leaf = |value| runtime_traversal_tree(&runtime_traversal_int(value), &[]);
    let typed_tree = if builtin == "<**>" {
        runtime_traversal_tree(
            &runtime_traversal_int(11),
            &[
                leaf(2),
                runtime_traversal_tree(&runtime_traversal_int(12), &[leaf(4)]),
            ],
        )
    } else {
        runtime_traversal_tree(
            &runtime_traversal_int(11),
            &[
                leaf(12),
                runtime_traversal_tree(&runtime_traversal_int(2), &[leaf(4)]),
            ],
        )
    };
    let callbacks = outputs
        .into_iter()
        .zip(if builtin == "<**>" {
            [1, 1, 2, 2]
        } else {
            [1, 2, 1, 2]
        })
        .map(|(result, argument)| runtime_applicative_int_callback(builtin, argument, result))
        .collect::<Vec<_>>();
    vec![
        runtime_applicative_definition!(
            builtin,
            "[]",
            "cartesian",
            format!("main = IO.print ({list_success} :: [Int])\n"),
            if builtin == "<**>" {
                b"[11,2,12,4]\n"
            } else {
                b"[11,12,2,4]\n"
            },
            true,
            Some(typed_list),
            vec![(0, "value"), (1, "value")],
            callbacks.clone()
        ),
        runtime_applicative_definition!(
            builtin,
            "[]",
            "short",
            format!("main = IO.print ({list_short} :: [Int])\n"),
            b"[]\n",
            true,
            Some(runtime_traversal_list(&[])),
            vec![(0, "value"), (1, "not-forced")],
            Vec::new()
        ),
        runtime_applicative_definition!(
            builtin,
            "Tree",
            "branching",
            format!("main = IO.print $ Tree.flatten $ ({tree_success} :: Tree Int)\n"),
            if builtin == "<**>" {
                b"[11,2,12,4]\n"
            } else {
                b"[11,12,2,4]\n"
            },
            true,
            Some(typed_tree),
            vec![(0, "value"), (1, "value")],
            callbacks
        ),
    ]
}

fn runtime_applicative_parser_definitions(
    builtin: &'static str,
) -> Vec<RuntimeApplicativeDefinition> {
    let operation = runtime_applicative_apply(builtin, "Main.function", "Main.value");
    let source = format!(
        concat!(
            "function = (\\delta value -> Int.plus (Text.length delta) (Text.length value)) <$> Options.strOption (Option.long \"function\")\n",
            "value = Options.strOption (Option.long \"value\")\n",
            "parser = {operation}\n",
            "main = do {{ result <- Options.execParser $ Options.info Main.parser Options.fullDesc; IO.print result }}\n",
        ),
        operation = operation
    );
    vec![
        RuntimeApplicativeDefinition {
            builtin,
            instance: "Options.Parser",
            path: "present",
            source: source.clone(),
            arguments: vec![
                "--value".into(),
                "abc".into(),
                "--function".into(),
                "xy".into(),
            ],
            stdout: b"5\n".to_vec(),
            stderr: Vec::new(),
            success: true,
            typed_value: None,
            exit_states: vec![(0, "value"), (1, "value")],
            callbacks: vec![runtime_applicative_int_callback_text(builtin, "abc", 5)],
        },
        RuntimeApplicativeDefinition {
            builtin,
            instance: "Options.Parser",
            path: "absent",
            source: source.clone(),
            arguments: Vec::new(),
            stdout: Vec::new(),
            stderr: runtime_applicative_parser_stderr(builtin, "absent"),
            success: false,
            typed_value: None,
            exit_states: vec![(0, "value"), (1, "value")],
            callbacks: Vec::new(),
        },
        RuntimeApplicativeDefinition {
            builtin,
            instance: "Options.Parser",
            path: "consumed-missing",
            source,
            arguments: if builtin == "<**>" {
                vec!["--value".into(), "abc".into()]
            } else {
                vec!["--function".into(), "xy".into()]
            },
            stdout: Vec::new(),
            stderr: runtime_applicative_parser_stderr(builtin, "consumed-missing"),
            success: false,
            typed_value: None,
            exit_states: vec![(0, "value"), (1, "value")],
            callbacks: Vec::new(),
        },
    ]
}

fn runtime_applicative_parser_stderr(builtin: &str, path: &str) -> Vec<u8> {
    let (usage, missing) = match (builtin, path) {
        ("<*>", "absent") => ("--function ARG --value ARG", "--function ARG --value ARG"),
        ("<*>", "consumed-missing") => ("--function ARG --value ARG", "--value ARG"),
        ("<**>", "absent") => ("--value ARG --function ARG", "--value ARG --function ARG"),
        ("<**>", "consumed-missing") => ("--value ARG --function ARG", "--function ARG"),
        _ => unreachable!("parser diagnostic authority is a closed matrix"),
    };
    format!("Missing: {missing}\n\nUsage: hell {usage}\n").into_bytes()
}

fn runtime_applicative_apply(builtin: &str, function: &str, value: &str) -> String {
    if builtin == "<**>" {
        format!("({value}) <**> ({function})")
    } else {
        format!("({function}) <*> ({value})")
    }
}

fn runtime_applicative_int_callback(
    builtin: &str,
    argument: i64,
    result: i64,
) -> CallbackInvocationContract {
    callback_contract_invocation(
        u16::from(builtin == "<**>"),
        "application",
        &[&runtime_traversal_int(argument)],
        &runtime_traversal_int(result),
    )
}

fn runtime_applicative_int_callback_text(
    builtin: &str,
    argument: &str,
    result: i64,
) -> CallbackInvocationContract {
    callback_contract_invocation(
        u16::from(builtin == "<**>"),
        "application",
        &[&format!(
            "{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}",
            runtime_bytes_hex(argument.as_bytes())
        )],
        &runtime_traversal_int(result),
    )
}

fn runtime_applicative_builtin_slug(builtin: &str) -> &'static str {
    match builtin {
        "Applicative.pure" => "pure",
        "<*>" => "apply",
        "<**>" => "apply-flipped",
        _ => unreachable!("Applicative builtin set is closed"),
    }
}

fn runtime_applicative_instance_slug(instance: &str) -> &'static str {
    match instance {
        "IO" => "io",
        "Maybe" => "maybe",
        "[]" => "list",
        "Tree" => "tree",
        "Options.Parser" => "parser",
        "Either" => "either",
        _ => unreachable!("Applicative direct instance set is closed"),
    }
}

struct RuntimeSemigroupDefinition {
    slug: &'static str,
    target: &'static str,
    path: &'static str,
    source: String,
    arguments: Vec<OsString>,
    stdin: Vec<u8>,
    stdout: Vec<u8>,
    runtime_completion: bool,
    status_success: bool,
    status_code: i32,
    typed_value: String,
    premises: &'static [(&'static str, u8)],
}

fn runtime_semigroup_cases() -> Vec<DifferentialCase> {
    let mut definitions = runtime_semigroup_sequence_definitions();
    definitions.extend(runtime_semigroup_either_definitions());
    definitions.extend(runtime_semigroup_options_definitions());
    definitions.extend(runtime_semigroup_maybe_definitions());
    definitions
        .into_iter()
        .map(runtime_semigroup_case)
        .collect()
}

fn runtime_semigroup_case(definition: RuntimeSemigroupDefinition) -> DifferentialCase {
    let mut descriptor = runtime_single_typed_target_descriptor("<>", &definition.source);
    let target = &mut descriptor.semantic_targets[0];
    target.expected_instance_target = Some(Arc::from(definition.target));
    target.expected_instance_premises = definition
        .premises
        .iter()
        .map(|(target, premise_count)| crate::InstancePremiseEvidence {
            target: Arc::from(*target),
            premise_count: *premise_count,
        })
        .collect();
    target.expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(&definition.stdout, b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(
        definition.status_success,
        Some(definition.status_code),
    ));
    target.expected_lazy_argument_exit_sha256 = Some(crate::lazy_argument_exit_sha256([
        (0, "not-forced"),
        (1, "not-forced"),
    ]));
    let typed = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{}}}",
        definition.typed_value
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(typed.as_bytes()));
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-typed-semigroup-{}-{}",
            definition.slug, definition.path
        )),
        source: Arc::from(definition.source),
        arguments: definition.arguments,
        stdin: definition.stdin,
        expected_runtime_completion: definition.runtime_completion,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

macro_rules! runtime_semigroup_definition {
    ($slug:expr, $target:expr, $path:expr, $source:expr, $stdout:expr, $typed:expr) => {
        RuntimeSemigroupDefinition {
            slug: $slug,
            target: $target,
            path: $path,
            source: $source.to_owned(),
            arguments: Vec::new(),
            stdin: Vec::new(),
            stdout: $stdout.to_vec(),
            runtime_completion: true,
            status_success: true,
            status_code: 0,
            typed_value: $typed,
            premises: &[],
        }
    };
}

fn runtime_semigroup_sequence_definitions() -> Vec<RuntimeSemigroupDefinition> {
    let text = |value: &str| {
        format!(
            "{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}",
            runtime_bytes_hex(value.as_bytes())
        )
    };
    let builder = |value: &str| {
        format!(
            "{{\"type\":\"Builder\",\"hex\":\"{}\"}}",
            runtime_bytes_hex(value.as_bytes())
        )
    };
    let vector = |values: &[i64]| {
        format!(
            "{{\"type\":\"Vector\",\"elements\":[{}]}}",
            values
                .iter()
                .map(|value| runtime_traversal_int(*value))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let list = |values: &[i64]| {
        runtime_traversal_list(
            &values
                .iter()
                .map(|value| runtime_traversal_int(*value))
                .collect::<Vec<_>>(),
        )
    };
    let lazy_list = |values: &[i64]| {
        format!(
            "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e6f742d666f72636564\"}}",
            values
                .iter()
                .map(|value| runtime_traversal_int(*value))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let appended_list = |left: &[i64], right: &[i64]| {
        let right = list(right);
        let termination = runtime_bytes_hex(format!("indirection:{right}").as_bytes());
        format!(
            "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"{termination}\"}}",
            left.iter()
                .map(|value| runtime_traversal_int(*value))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    vec![
        runtime_semigroup_definition!("text", "Text", "ordered", "main = Text.putStrLn $ \"ab\" <> \"cd\"\n", b"abcd\n", text("abcd")),
        runtime_semigroup_definition!("text", "Text", "unicode", "main = Text.putStrLn $ \"aβ\" <> \"🙂\"\n", "aβ🙂\n".as_bytes(), text("aβ🙂")),
        runtime_semigroup_definition!("text", "Text", "left-empty", "main = Text.putStrLn $ \"\" <> \"right\"\n", b"right\n", text("right")),
        runtime_semigroup_definition!("text", "Text", "right-empty", "main = Text.putStrLn $ \"left\" <> \"\"\n", b"left\n", text("left")),
        runtime_semigroup_definition!("builder", "Builder", "ordered", "main = IO.print $ (Builder.byteString (Text.encodeUtf8 \"ab\")) <> (Builder.byteString (Text.encodeUtf8 \"cd\"))\n", b"\"abcd\"\n", builder("abcd")),
        runtime_semigroup_definition!("builder", "Builder", "left-empty", "main = IO.print $ (Builder.byteString (Text.encodeUtf8 \"\")) <> (Builder.byteString (Text.encodeUtf8 \"right\"))\n", b"\"right\"\n", builder("right")),
        runtime_semigroup_definition!("builder", "Builder", "right-empty", "main = IO.print $ (Builder.byteString (Text.encodeUtf8 \"left\")) <> (Builder.byteString (Text.encodeUtf8 \"\"))\n", b"\"left\"\n", builder("left")),
        RuntimeSemigroupDefinition { slug: "builder", target: "Builder", path: "arbitrary-bytes", source: "main = do { left <- ByteString.hGet IO.stdin 2; right <- ByteString.hGet IO.stdin 2; IO.print $ Builder.byteString left <> Builder.byteString right }\n".to_owned(), arguments: Vec::new(), stdin: vec![0xff, 0x41, 0xfe, 0x42], stdout: b"\"\\255A\\254B\"\n".to_vec(), runtime_completion: true, status_success: true, status_code: 0, typed_value: "{\"type\":\"Builder\",\"hex\":\"ff41fe42\"}".to_owned(), premises: &[] },
        runtime_semigroup_definition!("vector", "Vector", "ordered", "main = IO.print $ Vector.toList $ Vector.fromList [1,2] <> Vector.fromList [3,4]\n", b"[1,2,3,4]\n", vector(&[1,2,3,4])),
        runtime_semigroup_definition!("vector", "Vector", "left-empty", "main = IO.print $ Vector.toList $ Vector.fromList ([] :: [Int]) <> Vector.fromList [3,4]\n", b"[3,4]\n", vector(&[3,4])),
        runtime_semigroup_definition!("vector", "Vector", "right-empty", "main = IO.print $ Vector.toList $ Vector.fromList [1,2] <> Vector.fromList ([] :: [Int])\n", b"[1,2]\n", vector(&[1,2])),
        runtime_semigroup_definition!("list", "[]", "ordered", "main = IO.print $ ([1,2] :: [Int]) <> [3,4]\n", b"[1,2,3,4]\n", appended_list(&[1,2], &[3,4])),
        runtime_semigroup_definition!("list", "[]", "left-empty", "main = IO.print $ ([] :: [Int]) <> [3,4]\n", b"[3,4]\n", list(&[3,4])),
        runtime_semigroup_definition!("list", "[]", "right-empty", "main = IO.print $ ([1,2] :: [Int]) <> []\n", b"[1,2]\n", appended_list(&[1,2], &[])),
        runtime_semigroup_definition!("list", "[]", "lazy-tail", "main = IO.print $ List.take 1 $ ([1] :: [Int]) <> (Error.error \"forced tail\" :: [Int])\n", b"[1]\n", lazy_list(&[1])),
    ]
}

fn runtime_semigroup_either_definitions() -> Vec<RuntimeSemigroupDefinition> {
    let left = |value: &str| {
        format!(
            "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}]}}",
            runtime_bytes_hex(value.as_bytes())
        )
    };
    let right = |value| {
        format!(
            "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Right\",\"payloads\":[{}]}}",
            runtime_traversal_int(value)
        )
    };
    vec![
        runtime_semigroup_definition!(
            "either",
            "Either",
            "left-left",
            "main = IO.print $ (Either.Left \"left\" :: Either Text Int) <> Either.Left \"right\"\n",
            b"Left \"right\"\n",
            left("right")
        ),
        runtime_semigroup_definition!(
            "either",
            "Either",
            "left-right",
            "main = IO.print $ (Either.Left \"left\" :: Either Text Int) <> Either.Right 2\n",
            b"Right 2\n",
            right(2)
        ),
        runtime_semigroup_definition!(
            "either",
            "Either",
            "right-left",
            "main = IO.print $ (Either.Right 1 :: Either Text Int) <> Either.Left \"right\"\n",
            b"Right 1\n",
            right(1)
        ),
        runtime_semigroup_definition!(
            "either",
            "Either",
            "right-nonforce",
            "main = IO.print $ (Either.Right 1 :: Either Text Int) <> (Error.error \"forced right\" :: Either Text Int)\n",
            b"Right 1\n",
            right(1)
        ),
    ]
}

fn runtime_semigroup_options_definitions() -> Vec<RuntimeSemigroupDefinition> {
    let option_mod = |left: &str, right: &str| {
        format!(
            "{{\"type\":\"OptionsMod\",\"modifiers\":[{{\"kind\":\"long\",\"textHex\":\"{}\"}},{{\"kind\":\"long\",\"textHex\":\"{}\"}}]}}",
            runtime_bytes_hex(left.as_bytes()),
            runtime_bytes_hex(right.as_bytes())
        )
    };
    let info_mod = |full, header: &str| {
        format!(
            "{{\"type\":\"OptionsInfoMod\",\"fullDescription\":{full},\"programDescriptionHex\":null,\"headerHex\":\"{}\"}}",
            runtime_bytes_hex(header.as_bytes())
        )
    };
    let option_source = |left: &str, right: &str| {
        format!(
            concat!(
                "parser = Options.switch (Flag.long \"{left}\" <> Flag.long \"{right}\") <**> Options.helper\n",
                "main = do {{ _ <- Options.execParser $ Options.info Main.parser Options.fullDesc; IO.pure () }}\n",
            ),
            left = left,
            right = right
        )
    };
    let info_source = |left: &str, right: &str| {
        format!(
            concat!(
                "parser = Options.switch (Flag.long \"flag\")\n",
                "main = do {{ _ <- Options.execParser $ Options.info (Main.parser <**> Options.helper) (Options.header \"{left}\" <> Options.header \"{right}\"); IO.pure () }}\n",
            ),
            left = left,
            right = right
        )
    };
    vec![
        RuntimeSemigroupDefinition { slug: "options-mod", target: "Options.Mod", path: "left-right", source: option_source("one", "two"), arguments: vec!["--help".into()], stdin: Vec::new(), stdout: b"Usage: hell [--one|--two]\n\nAvailable options:\n  -h,--help                Show this help text\n".to_vec(), runtime_completion: false, status_success: true, status_code: 0, typed_value: option_mod("one", "two"), premises: &[] },
        RuntimeSemigroupDefinition { slug: "options-mod", target: "Options.Mod", path: "right-left", source: option_source("two", "one"), arguments: vec!["--help".into()], stdin: Vec::new(), stdout: b"Usage: hell [--one|--two]\n\nAvailable options:\n  -h,--help                Show this help text\n".to_vec(), runtime_completion: false, status_success: true, status_code: 0, typed_value: option_mod("two", "one"), premises: &[] },
        RuntimeSemigroupDefinition { slug: "options-info-mod", target: "Options.InfoMod", path: "right-precedence", source: info_source("left", "right"), arguments: vec!["--help".into()], stdin: Vec::new(), stdout: b"right\n\nUsage: hell [--flag]\n\nAvailable options:\n  -h,--help                Show this help text\n".to_vec(), runtime_completion: false, status_success: true, status_code: 0, typed_value: info_mod(false, "right"), premises: &[] },
        RuntimeSemigroupDefinition { slug: "options-info-mod", target: "Options.InfoMod", path: "reversed-precedence", source: info_source("right", "left"), arguments: vec!["--help".into()], stdin: Vec::new(), stdout: b"left\n\nUsage: hell [--flag]\n\nAvailable options:\n  -h,--help                Show this help text\n".to_vec(), runtime_completion: false, status_success: true, status_code: 0, typed_value: info_mod(false, "left"), premises: &[] },
        RuntimeSemigroupDefinition { slug: "options-info-mod", target: "Options.InfoMod", path: "full-description", source: "parser = Options.switch (Flag.long \"flag\")\nmain = do { _ <- Options.execParser $ Options.info (Main.parser <**> Options.helper) (Options.fullDesc <> Options.header \"head\"); IO.pure () }\n".to_owned(), arguments: vec!["--help".into()], stdin: Vec::new(), stdout: b"head\n\nUsage: hell [--flag]\n\nAvailable options:\n  -h,--help                Show this help text\n".to_vec(), runtime_completion: false, status_success: true, status_code: 0, typed_value: info_mod(true, "head"), premises: &[] },
    ]
}

fn runtime_semigroup_maybe_definitions() -> Vec<RuntimeSemigroupDefinition> {
    let maybe = |payload: Option<&str>| {
        payload.map_or_else(
            || "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
            |value| {
                format!(
                    "{{\"type\":\"Maybe\",\"payload\":{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}}}",
                    runtime_bytes_hex(value.as_bytes())
                )
            },
        )
    };
    [
        (
            "nothing-left",
            "(Maybe.Nothing :: Maybe Text) <> Maybe.Just \"right\"",
            "Just \"right\"\n",
            maybe(Some("right")),
        ),
        (
            "nothing-right",
            "Maybe.Just \"left\" <> (Maybe.Nothing :: Maybe Text)",
            "Just \"left\"\n",
            maybe(Some("left")),
        ),
        (
            "just-combine",
            "Maybe.Just \"left\" <> Maybe.Just \"right\"",
            "Just \"leftright\"\n",
            maybe(Some("leftright")),
        ),
    ]
    .into_iter()
    .map(
        |(path, operation, stdout, typed_value)| RuntimeSemigroupDefinition {
            slug: "maybe-text",
            target: "Maybe",
            path,
            source: format!("main = IO.print $ {operation}\n"),
            arguments: Vec::new(),
            stdin: Vec::new(),
            stdout: stdout.as_bytes().to_vec(),
            runtime_completion: true,
            status_success: true,
            status_code: 0,
            typed_value,
            premises: &[("Text", 0)],
        },
    )
    .collect()
}

fn runtime_alternative_maybe_cases() -> Vec<DifferentialCase> {
    [
        (
            "Alternative.optional",
            "runtime-typed-alternative-optional-maybe-nothing",
            "main = IO.print $ Alternative.optional (Maybe.Nothing :: Maybe Int)\n",
            "{\"type\":\"Maybe\",\"payload\":{\"type\":\"Maybe\",\"payload\":null}}",
            b"Just Nothing\n".as_slice(),
        ),
        (
            "Alternative.optional",
            "runtime-typed-alternative-optional-maybe-just",
            "main = IO.print $ Alternative.optional (Maybe.Just 3 :: Maybe Int)\n",
            "{\"type\":\"Maybe\",\"payload\":{\"type\":\"Maybe\",\"payload\":{\"type\":\"Int\",\"value\":\"3\"}}}",
            b"Just (Just 3)\n".as_slice(),
        ),
        (
            "Alternative.many",
            "runtime-typed-alternative-many-maybe-nothing",
            "main = IO.print $ Alternative.many (Maybe.Nothing :: Maybe Int)\n",
            "{\"type\":\"Maybe\",\"payload\":{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}}",
            b"Just []\n".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(builtin, id, source, value, stdout)| {
        let mut descriptor = runtime_single_typed_target_descriptor(builtin, source);
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{value}}}"
        );
        let target = &mut descriptor.semantic_targets[0];
        target.expected_instance_target = Some(Arc::from("Maybe"));
        target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
        target.expected_raw_presentation_sha256 =
            Some(crate::raw_presentation_sha256(stdout, b""));
        target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
        DifferentialCase {
            id: Arc::from(id),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .chain(std::iter::once(runtime_alternative_many_nonproductive_case()))
    .collect()
}

fn runtime_alternative_many_nonproductive_case() -> DifferentialCase {
    const SOURCE: &str = concat!(
        "main = do\n",
        "  result <- Timeout.timeout 100000 $ ",
        "Maybe.maybe (IO.pure ()) ",
        "(\\values -> Monad.forM_ values (\\_ -> IO.pure ())) $ ",
        "Alternative.many (Maybe.Just 1 :: Maybe Int)\n",
        "  Maybe.maybe (Text.putStr \"timeout\") ",
        "(\\_ -> Text.putStr \"completed\") result\n",
    );
    let mut descriptor = runtime_all_obligation_descriptor("Alternative.many", SOURCE);
    let target = &mut descriptor.semantic_targets[0];
    target.expected_instance_target = Some(Arc::from("Maybe"));
    target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(b"timeout", b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));

    target.expected_nonproductive_trace_sha256 = Some(crate::nonproductive_trace_sha256([
        ("nonproductive-repeat", "value"),
        ("nonproductive-pending", "value"),
        ("nonproductive-cancelled", "value"),
    ]));
    append_expired_timeout_descriptor(&mut descriptor, SOURCE, b"timeout");
    DifferentialCase {
        id: Arc::from("runtime-typed-alternative-many-maybe-nonproductive"),
        source: Arc::from(SOURCE),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_alternative_parser_cases() -> Vec<DifferentialCase> {
    [
        (
            "Alternative.optional",
            "runtime-typed-alternative-optional-parser-absent",
            concat!(
                "parser = Alternative.optional $ Options.strOption $ Option.long \"name\"\n",
                "main = do\n",
                "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Maybe.maybe (Text.putStr \"missing\") Text.putStr value\n",
            ),
            Vec::<OsString>::new(),
            Some(b"missing".as_slice()),
        ),
        (
            "Alternative.optional",
            "runtime-typed-alternative-optional-parser-present",
            concat!(
                "parser = Alternative.optional $ Options.strOption $ Option.long \"name\"\n",
                "main = do\n",
                "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Maybe.maybe (Text.putStr \"missing\") Text.putStr value\n",
            ),
            vec!["--name".into(), "alpha".into()],
            Some(b"alpha".as_slice()),
        ),
        (
            "Alternative.optional",
            "runtime-typed-alternative-optional-parser-partial",
            concat!(
                "parser = Alternative.optional $ Options.strOption $ Option.long \"name\"\n",
                "main = do\n",
                "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Maybe.maybe (Text.putStr \"missing\") Text.putStr value\n",
            ),
            vec!["--name".into()],
            None,
        ),
        (
            "Alternative.many",
            "runtime-typed-alternative-many-parser-absent",
            concat!(
                "parser = Alternative.many $ Options.strOption $ Option.long \"name\"\n",
                "main = do\n",
                "  values <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  IO.print $ List.length values\n",
            ),
            Vec::<OsString>::new(),
            Some(b"0\n".as_slice()),
        ),
        (
            "Alternative.many",
            "runtime-typed-alternative-many-parser-repeated",
            concat!(
                "parser = Alternative.many $ Options.strOption $ Option.long \"name\"\n",
                "main = do\n",
                "  values <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Monad.forM_ values Text.putStrLn\n",
            ),
            vec!["--name".into(), "one".into(), "--name".into(), "two".into()],
            Some(b"one\ntwo\n".as_slice()),
        ),
        (
            "Alternative.many",
            "runtime-typed-alternative-many-parser-partial",
            concat!(
                "parser = Alternative.many $ Options.strOption $ Option.long \"name\"\n",
                "main = do\n",
                "  values <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Monad.forM_ values Text.putStrLn\n",
            ),
            vec!["--name".into(), "one".into(), "--name".into()],
            None,
        ),
        (
            "Alternative.many",
            "runtime-typed-alternative-many-parser-nonproductive",
            concat!(
                "parser = Alternative.many $ Applicative.pure \"value\"\n",
                "main = do\n",
                "  result <- Timeout.timeout 100000 $ ",
                "Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Maybe.maybe (Text.putStr \"timeout\") ",
                "(\\values -> IO.print $ List.length values) result\n",
            ),
            Vec::<OsString>::new(),
            Some(b"timeout".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(builtin, id, source, arguments, stdout)| {
        runtime_alternative_parser_case(builtin, id, source, arguments, stdout)
    })
    .collect()
}

fn runtime_alternative_parser_case(
    builtin: &'static str,
    id: &'static str,
    source: &'static str,
    arguments: Vec<OsString>,
    stdout: Option<&'static [u8]>,
) -> DifferentialCase {
    let mut descriptor = runtime_alternative_parser_descriptor(builtin, source, stdout);
    if id == "runtime-typed-alternative-many-parser-nonproductive" {
        for target in &mut descriptor.semantic_targets {
            if target.builtin.as_ref() == "Options.execParser"
                && target.dimension == CompatibilityDimension::Effects
            {
                target.obligations.retain(|obligation| {
                    !matches!(obligation.0.as_ref(), "effect-success" | "effect-failure")
                });
                target
                    .obligations
                    .push(ObligationId(Arc::from("effect-cancellation")));
                target.expected_single_effect_lifecycle_sha256 =
                    Some(crate::single_effect_lifecycle_sha256([
                        "started",
                        "cancelled",
                    ]));
            }
        }
        append_expired_timeout_descriptor(&mut descriptor, source, b"timeout");
        descriptor.semantic_targets[0].expected_nonproductive_trace_sha256 =
            Some(crate::nonproductive_trace_sha256([
                ("nonproductive-parser-node", "not-forced"),
                ("nonproductive-pending", "value"),
                ("nonproductive-cancelled", "value"),
            ]));
    }
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        arguments,
        expected_runtime_completion: stdout.is_some(),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn append_expired_timeout_descriptor(
    descriptor: &mut ClaimEvidenceDescriptor,
    source: &str,
    stdout: &[u8],
) {
    let mut timeout = runtime_all_obligation_descriptor("Timeout.timeout", source);
    timeout.targets.retain(|target| {
        matches!(
            target.dimension,
            CompatibilityDimension::PureRuntime
                | CompatibilityDimension::Effects
                | CompatibilityDimension::Concurrency
                | CompatibilityDimension::Platform
                | CompatibilityDimension::ResourceBehavior
        )
    });
    timeout.semantic_targets.retain_mut(|target| {
        if !timeout.targets.iter().any(|retained| {
            retained.builtin == target.builtin && retained.dimension == target.dimension
        }) {
            return false;
        }
        target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
        if target.dimension == CompatibilityDimension::PureRuntime {
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        }
        if target.dimension == CompatibilityDimension::Effects {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "effect-failure");
            target.expected_single_effect_lifecycle_sha256 =
                Some(crate::single_effect_lifecycle_sha256([
                    "started",
                    "completed",
                ]));
        }
        target.expected_single_task_lifecycle_sha256 = Some(crate::single_task_lifecycle_sha256([
            "started",
            "cancelled",
        ]));
        true
    });
    descriptor.targets.extend(timeout.targets);
    descriptor.semantic_targets.extend(timeout.semantic_targets);
}

fn runtime_alternative_parser_descriptor(
    builtin: &str,
    source: &str,
    stdout: Option<&[u8]>,
) -> ClaimEvidenceDescriptor {
    let success = stdout.is_some();
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    let target = &mut descriptor.semantic_targets[0];
    target.expected_instance_target = Some(Arc::from("Options.Parser"));
    if let Some(stdout) = stdout {
        target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(stdout, b""));
    } else {
        target
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "parser-composition");
    }
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(
        success,
        Some(i32::from(!success)),
    ));

    let mut exec = runtime_all_obligation_descriptor("Options.execParser", source);
    exec.semantic_targets.retain_mut(|target| {
        if target.dimension != CompatibilityDimension::Effects {
            return false;
        }
        let omitted = if success {
            "effect-failure"
        } else {
            "effect-success"
        };
        target.obligations.retain(|obligation| {
            let value = obligation.0.as_ref();
            value != omitted && value != "effect-cancellation"
        });
        target.expected_single_effect_lifecycle_sha256 =
            Some(crate::single_effect_lifecycle_sha256(if success {
                ["started", "completed"]
            } else {
                ["started", "failed"]
            }));
        true
    });
    exec.targets
        .retain(|target| target.dimension == CompatibilityDimension::Effects);
    descriptor.targets.extend(exec.targets);
    descriptor.semantic_targets.extend(exec.semantic_targets);
    descriptor
}

fn runtime_io_buffering_cases() -> Vec<DifferentialCase> {
    [
        (
            "block",
            "(IO.BlockBuffering Maybe.Nothing)",
            "pending",
            b"0\npending".as_slice(),
        ),
        (
            "line",
            "IO.LineBuffering",
            "line\npending",
            b"12\nline\npending".as_slice(),
        ),
        (
            "none",
            "IO.NoBuffering",
            "pending",
            b"7\npending".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(id, mode, input, stdout)| {
        let source = format!(
            concat!(
                "main = do\n",
                "  handle <- IO.openFile \"buffered.txt\" IO.WriteMode\n",
                "  IO.hSetBuffering handle {mode}\n",
                "  Text.hPutStr handle {input:?}\n",
                "  visible <- Directory.getFileSize \"buffered.txt\"\n",
                "  IO.hClose handle\n",
                "  contents <- Text.readFile \"buffered.txt\"\n",
                "  IO.print visible\n",
                "  Text.putStr contents\n",
            ),
            mode = mode,
            input = input,
        );
        runtime_io_success_case(
            "IO.hSetBuffering",
            &format!("runtime-io-buffering-{id}"),
            &source,
            stdout,
        )
    })
    .collect()
}

fn runtime_list_iterate_exact_cases() -> Vec<DifferentialCase> {
    const FINITE_SOURCE: &str = "main = IO.print $ List.take 4 $ List.iterate' (Int.plus 1) 0\n";
    const LAZY_SOURCE: &str = concat!(
        "step = \\x -> if Int.eq x 7 then 8 else ",
        "Error.error \"undemanded-iterate-deeper-tail\"\n",
        "main = IO.print $ List.take 1 $ ",
        "List.iterate' Main.step 7\n",
    );
    let int = |value: i64| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let mut finite = runtime_single_typed_target_descriptor("List.iterate'", FINITE_SOURCE);
    finite.semantic_targets[0].expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(b"[0,1,2,3]\n", b""));
    finite.callback_contracts = vec![CallbackContract {
        builtin: Arc::from("List.iterate'"),
        invocations: [0, 1, 2, 3]
            .into_iter()
            .map(|value| {
                callback_contract_invocation(0, "element", &[&int(value)], &int(value + 1))
            })
            .collect(),
    }];
    let mut lazy = runtime_single_typed_target_descriptor("List.iterate'", LAZY_SOURCE);
    lazy.semantic_targets[0].expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(b"[7]\n", b""));
    lazy.semantic_targets[0]
        .obligations
        .retain(|obligation| matches!(obligation.0.as_ref(), "callback-order" | "lazy-boundary"));
    lazy.callback_contracts = vec![CallbackContract {
        builtin: Arc::from("List.iterate'"),
        invocations: vec![callback_contract_invocation(
            0,
            "element",
            &[&int(7)],
            &int(8),
        )],
    }];
    vec![
        DifferentialCase {
            id: Arc::from("runtime-list-iterate-finite-prefix"),
            source: Arc::from(FINITE_SOURCE),
            claim_evidence: Some(finite),
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("runtime-list-iterate-undemanded-tail"),
            source: Arc::from(LAZY_SOURCE),
            claim_evidence: Some(lazy),
            ..DifferentialCase::default()
        },
    ]
}

fn runtime_io_failure_case(builtin: &str, id: &str, source: &str) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    descriptor
        .targets
        .retain(|target| target.dimension == CompatibilityDimension::Effects);
    descriptor.semantic_targets.retain_mut(|target| {
        if target.dimension != CompatibilityDimension::Effects {
            return false;
        }
        target
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "effect-success");
        true
    });
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        expected_runtime_completion: false,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_adapter_failure_case(builtin: &str, id: &str, source: &str) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    descriptor.targets.retain(|target| {
        matches!(
            target.dimension,
            CompatibilityDimension::PureRuntime | CompatibilityDimension::Effects
        )
    });
    descriptor
        .semantic_targets
        .retain_mut(|target| match target.dimension {
            CompatibilityDimension::PureRuntime => {
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "adapter-success");
                if !target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "adapter-failure")
                {
                    target
                        .obligations
                        .push(ObligationId(Arc::from("adapter-failure")));
                }
                true
            }
            CompatibilityDimension::Effects => {
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "effect-success");
                true
            }
            _ => false,
        });
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        expected_runtime_completion: false,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_directory_operation_cases() -> Vec<DifferentialCase> {
    runtime_directory_operation_definitions()
        .into_iter()
        .flat_map(|(builtin, id, success_source, stdout, failure_source)| {
            [
                runtime_directory_success_case(
                    builtin,
                    &format!("runtime-directory-{id}-success"),
                    success_source,
                    stdout,
                ),
                runtime_directory_failure_case(
                    builtin,
                    &format!("runtime-directory-{id}-failure"),
                    failure_source,
                ),
            ]
        })
        .collect()
}

fn runtime_directory_observation_cases() -> Vec<DifferentialCase> {
    let mut cases = [
        (
            "Directory.doesDirectoryExist",
            "directory-exists-true",
            concat!(
                "main = do\n",
                "  Directory.createDirectory \"present\"\n",
                "  exists <- Directory.doesDirectoryExist \"present\"\n",
                "  Directory.removeDirectory \"present\"\n",
                "  IO.print exists\n",
            ),
            b"True\n".as_slice(),
        ),
        (
            "Directory.doesDirectoryExist",
            "directory-exists-false",
            "main = do\n  exists <- Directory.doesDirectoryExist \"missing\"\n  IO.print exists\n",
            b"False\n".as_slice(),
        ),
        (
            "Directory.doesFileExist",
            "file-exists-true",
            concat!(
                "main = do\n",
                "  Text.writeFile \"present.txt\" \"present\"\n",
                "  exists <- Directory.doesFileExist \"present.txt\"\n",
                "  Directory.removeFile \"present.txt\"\n",
                "  IO.print exists\n",
            ),
            b"True\n".as_slice(),
        ),
        (
            "Directory.doesFileExist",
            "file-exists-false",
            "main = do\n  exists <- Directory.doesFileExist \"missing.txt\"\n  IO.print exists\n",
            b"False\n".as_slice(),
        ),
        (
            "Directory.getCurrentDirectory",
            "current-directory-roundtrip",
            concat!(
                "main = do\n",
                "  Directory.createDirectory \"current\"\n",
                "  Directory.setCurrentDirectory \"current\"\n",
                "  current <- Directory.getCurrentDirectory\n",
                "  Directory.setCurrentDirectory \"..\"\n",
                "  Directory.setCurrentDirectory current\n",
                "  Text.writeFile \"sentinel\" \"bound\"\n",
                "  output <- Text.readFile \"sentinel\"\n",
                "  Directory.removeFile \"sentinel\"\n",
                "  Directory.setCurrentDirectory \"..\"\n",
                "  Directory.removeDirectory \"current\"\n",
                "  Text.putStr output\n",
            ),
            b"bound".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(builtin, id, source, stdout)| {
        let mut case = runtime_io_success_case(builtin, &format!("runtime-{id}"), source, stdout);
        if builtin == "Directory.getCurrentDirectory" {
            let descriptor = case.claim_evidence.as_mut().expect("directory descriptor");
            let target = descriptor
                .semantic_targets
                .iter_mut()
                .find(|target| target.dimension == CompatibilityDimension::Effects)
                .expect("current-directory Effects target");
            target.expected_process_status_sha256 =
                Some(crate::process_status_sha256(true, Some(0)));
            target.expected_single_effect_lifecycle_sha256 =
                Some(crate::single_effect_lifecycle_sha256([
                    "started",
                    "completed",
                ]));
        }
        case
    })
    .collect::<Vec<_>>();
    cases.push(runtime_current_directory_upstream_success_case());
    cases.extend([
        runtime_io_success_case(
            "Directory.doesDirectoryExist",
            "runtime-directory-exists-invalid-path-false",
            "main = do\n  exists <- Directory.doesDirectoryExist \"\\0\"\n  IO.print exists\n",
            b"False\n",
        ),
        runtime_io_success_case(
            "Directory.doesFileExist",
            "runtime-directory-file-exists-invalid-path-false",
            "main = do\n  exists <- Directory.doesFileExist \"\\0\"\n  IO.print exists\n",
            b"False\n",
        ),
    ]);
    cases.extend(runtime_home_directory_cases());
    cases
}

fn runtime_current_directory_upstream_success_case() -> DifferentialCase {
    const SOURCE: &str = concat!(
        "main = do\n",
        "  _current <- Directory.getCurrentDirectory\n",
        "  Text.putStr \"available\"\n",
    );
    let mut case = runtime_io_success_case(
        "Directory.getCurrentDirectory",
        "runtime-current-directory-upstream-available",
        SOURCE,
        b"available",
    );
    let descriptor = case
        .claim_evidence
        .as_mut()
        .expect("current-directory descriptor");
    descriptor.review_statement =
        Arc::from("runtime-current-directory-upstream-availability-review-v1");
    let target = descriptor
        .semantic_targets
        .iter_mut()
        .find(|target| target.dimension == CompatibilityDimension::Effects)
        .expect("current-directory Effects target");
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
    target.expected_single_effect_lifecycle_sha256 = Some(crate::single_effect_lifecycle_sha256([
        "started",
        "completed",
    ]));
    case
}

fn runtime_home_directory_cases() -> Vec<DifferentialCase> {
    let mut cases = [("reviewed-home-a", "home-a"), ("reviewed-home-b", "home-b")]
        .into_iter()
        .map(|(home, output)| {
            let source = format!(
                concat!(
                    "main = do\n",
                    "  actual <- Directory.getHomeDirectory\n",
                    "  IO.print $ Text.eq actual {home:?}\n",
                ),
                home = home,
            );
            let mut case = runtime_io_success_case(
                "Directory.getHomeDirectory",
                &format!("runtime-directory-get-home-{output}"),
                &source,
                b"",
            );
            case.environment = vec![
                ("HOME".into(), home.into()),
                ("USERPROFILE".into(), home.into()),
            ];
            let descriptor = case
                .claim_evidence
                .as_mut()
                .expect("home-directory descriptor");
            descriptor.review_statement =
                Arc::from("runtime-home-directory-platform-native-oracle-review-v1");
            for target in &mut descriptor.semantic_targets {
                target.expected_raw_presentation_sha256 = None;
            }
            case
        })
        .collect::<Vec<_>>();
    cases.push(runtime_io_success_case(
        "Directory.getHomeDirectory",
        "runtime-directory-get-home-platform-fallback",
        concat!(
            "main = do\n",
            "  _home <- Directory.getHomeDirectory\n",
            "  Text.putStr \"available\"\n",
        ),
        b"available",
    ));
    cases
}

fn runtime_temp_operation_cases() -> Vec<DifferentialCase> {
    let directory_source = concat!(
        "main = Temp.withSystemTempDirectory \"reviewed\" \\directory -> do\n",
        "  Text.writeFile (Text.concat [directory, \"/value.txt\"]) \"abc\"\n",
        "  output <- Text.readFile (Text.concat [directory, \"/value.txt\"])\n",
        "  Text.putStr output\n",
    );
    let file_source = concat!(
        "main = Temp.withSystemTempFile \"reviewed\" \\_path handle -> do\n",
        "  Text.hPutStr handle \"abc\"\n",
        "  Text.putStr \"written\"\n",
    );
    let mut cases = vec![
        runtime_io_success_case(
            "Temp.withSystemTempDirectory",
            "runtime-temp-directory-success",
            directory_source,
            b"abc",
        ),
        runtime_io_success_case(
            "Temp.withSystemTempFile",
            "runtime-temp-file-success",
            file_source,
            b"written",
        ),
    ];
    for (builtin, id, callback) in [
        (
            "Temp.withSystemTempDirectory",
            "runtime-temp-directory-failure",
            "\\_directory -> (Error.error \"reviewed\" :: IO ())",
        ),
        (
            "Temp.withSystemTempFile",
            "runtime-temp-file-failure",
            "\\_path _handle -> (Error.error \"reviewed\" :: IO ())",
        ),
    ] {
        let source = format!("main = {builtin} \"reviewed\" $ {callback}\n");
        cases.push(runtime_io_failure_case(builtin, id, &source));
    }
    cases
}

type RuntimeDirectoryDefinition = (
    &'static str,
    &'static str,
    &'static str,
    &'static [u8],
    &'static str,
);

fn runtime_directory_operation_definitions() -> Vec<RuntimeDirectoryDefinition> {
    let mut definitions: Vec<RuntimeDirectoryDefinition> = vec![
        (
            "Directory.copyFile",
            "copy-file",
            concat!(
                "main = do\n",
                "  Text.writeFile \"source.txt\" \"abc\"\n",
                "  Directory.copyFile \"source.txt\" \"target.txt\"\n",
                "  output <- Text.readFile \"target.txt\"\n",
                "  Text.putStr output\n",
            ),
            b"abc",
            "main = Directory.copyFile \"missing.txt\" \"target.txt\"\n",
        ),
        (
            "Directory.createDirectory",
            "create-directory",
            concat!(
                "main = do\n",
                "  Directory.createDirectory \"created\"\n",
                "  exists <- Directory.doesDirectoryExist \"created\"\n",
                "  IO.print exists\n",
            ),
            b"True\n",
            "main = Directory.createDirectory \".\"\n",
        ),
        (
            "Directory.createDirectoryIfMissing",
            "create-directory-if-missing",
            concat!(
                "main = do\n",
                "  Directory.createDirectoryIfMissing Bool.True \"parent/created\"\n",
                "  exists <- Directory.doesDirectoryExist \"parent/created\"\n",
                "  IO.print exists\n",
            ),
            b"True\n",
            "main = Directory.createDirectoryIfMissing Bool.False \"missing/created\"\n",
        ),
        (
            "Directory.getFileSize",
            "get-file-size",
            concat!(
                "main = do\n",
                "  Text.writeFile \"sized.txt\" \"abc\"\n",
                "  size <- Directory.getFileSize \"sized.txt\"\n",
                "  IO.print size\n",
            ),
            b"3\n",
            "main = do\n  size <- Directory.getFileSize \"missing.txt\"\n  IO.pure ()\n",
        ),
        (
            "Directory.removeFile",
            "remove-file",
            concat!(
                "main = do\n",
                "  Text.writeFile \"removed.txt\" \"abc\"\n",
                "  Directory.removeFile \"removed.txt\"\n",
                "  exists <- Directory.doesFileExist \"removed.txt\"\n",
                "  IO.print exists\n",
            ),
            b"False\n",
            "main = Directory.removeFile \"missing.txt\"\n",
        ),
        (
            "Directory.renameFile",
            "rename-file",
            concat!(
                "main = do\n",
                "  Text.writeFile \"source.txt\" \"abc\"\n",
                "  Directory.renameFile \"source.txt\" \"target.txt\"\n",
                "  output <- Text.readFile \"target.txt\"\n",
                "  Text.putStr output\n",
            ),
            b"abc",
            "main = Directory.renameFile \"missing.txt\" \"target.txt\"\n",
        ),
    ];
    definitions.extend(runtime_directory_state_definitions());
    definitions
}

fn runtime_directory_state_definitions() -> Vec<RuntimeDirectoryDefinition> {
    vec![
        (
            "Directory.listDirectory",
            "list-directory",
            concat!(
                "main = do\n",
                "  Directory.createDirectory \"listed\"\n",
                "  Text.writeFile \"listed/entry.txt\" \"entry\"\n",
                "  entries <- Directory.listDirectory \"listed\"\n",
                "  IO.print entries\n",
            ),
            b"[\"entry.txt\"]\n",
            "main = do\n  entries <- Directory.listDirectory \"missing\"\n  IO.pure ()\n",
        ),
        (
            "Directory.removeDirectory",
            "remove-directory",
            concat!(
                "main = do\n",
                "  Directory.createDirectory \"removed\"\n",
                "  Directory.removeDirectory \"removed\"\n",
                "  exists <- Directory.doesDirectoryExist \"removed\"\n",
                "  IO.print exists\n",
            ),
            b"False\n",
            "main = Directory.removeDirectory \"missing\"\n",
        ),
        (
            "Directory.setCurrentDirectory",
            "set-current-directory",
            concat!(
                "main = do\n",
                "  Directory.createDirectory \"current\"\n",
                "  Text.writeFile \"current/sentinel\" \"present\"\n",
                "  Directory.setCurrentDirectory \"current\"\n",
                "  exists <- Directory.doesFileExist \"sentinel\"\n",
                "  IO.print exists\n",
            ),
            b"True\n",
            "main = Directory.setCurrentDirectory \"missing\"\n",
        ),
    ]
}

fn runtime_directory_success_case(
    builtin: &str,
    id: &str,
    source: &str,
    stdout: &[u8],
) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    for target in &mut descriptor.semantic_targets {
        if matches!(
            target.dimension,
            CompatibilityDimension::PureRuntime | CompatibilityDimension::Presentation
        ) {
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        }
        if target.dimension == CompatibilityDimension::Effects {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "effect-failure");
        }
    }
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_directory_failure_case(builtin: &str, id: &str, source: &str) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    descriptor
        .targets
        .retain(|target| target.dimension == CompatibilityDimension::Effects);
    descriptor.semantic_targets.retain_mut(|target| {
        if target.dimension != CompatibilityDimension::Effects {
            return false;
        }
        target
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "effect-success");
        true
    });
    DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        expected_runtime_completion: false,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_process_builder_definitions() -> Vec<(&'static str, &'static str, &'static str, String)>
{
    let mut definitions = vec![
        (
            "Process.proc",
            "proc",
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper ->\n",
                "    Process.runProcess_ $ Process.proc helper [\"emit-hex\",\"\"]\n",
            ),
            runtime_process_value(&RuntimeProcessValue::new(&["emit-hex", ""])),
        ),
        (
            "Process.setWorkingDir",
            "set-working-dir",
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Directory.createDirectory \"reviewed-cwd\"\n",
                "  Monad.forM_ helpers \\helper ->\n",
                "    Process.runProcess_ $ Process.setWorkingDir \"reviewed-cwd\" $\n",
                "      Process.proc helper [\"assert-current-dir-name\",\"reviewed-cwd\"]\n",
            ),
            runtime_process_value(&RuntimeProcessValue {
                arguments: &["assert-current-dir-name", "reviewed-cwd"],
                working_directory: Some("reviewed-cwd"),
                ..RuntimeProcessValue::new(&[])
            }),
        ),
        (
            "Process.setEnv",
            "set-env",
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper ->\n",
                "    Process.runProcess_ $\n",
                "      Process.setEnv [(\"LC_ALL\",\"C\")] $\n",
                "        Process.proc helper [\"assert-env\",\"LC_ALL\",\"C\"]\n",
            ),
            runtime_process_value(&RuntimeProcessValue {
                arguments: &["assert-env", "LC_ALL", "C"],
                environment: Some(&[("LC_ALL", "C")]),
                ..RuntimeProcessValue::new(&[])
            }),
        ),
    ];
    definitions.extend(runtime_process_stream_builder_definitions());
    definitions
}

fn runtime_process_stream_builder_definitions()
-> Vec<(&'static str, &'static str, &'static str, String)> {
    vec![
        (
            "Process.setStdin",
            "set-stdin",
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper ->\n",
                "    Process.runProcess_ $ Process.setStdin Process.nullStream $\n",
                "      Process.proc helper [\"echo-stdin\"]\n",
            ),
            runtime_process_value(&RuntimeProcessValue {
                arguments: &["echo-stdin"],
                stdin: "null",
                ..RuntimeProcessValue::new(&[])
            }),
        ),
        (
            "Process.setStdout",
            "set-stdout",
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper ->\n",
                "    Process.runProcess_ $ Process.setStdout Process.nullStream $\n",
                "      Process.proc helper [\"emit-hex\",\"41\"]\n",
            ),
            runtime_process_value(&RuntimeProcessValue {
                arguments: &["emit-hex", "41"],
                stdout: "null",
                ..RuntimeProcessValue::new(&[])
            }),
        ),
        (
            "Process.setStderr",
            "set-stderr",
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper ->\n",
                "    Process.runProcess_ $ Process.setStderr Process.nullStream $\n",
                "      Process.proc helper [\"emit\",\"--stdout-bytes\",\"0\",\"--stderr-bytes\",\"1\"]\n",
            ),
            runtime_process_value(&RuntimeProcessValue {
                arguments: &["emit", "--stdout-bytes", "0", "--stderr-bytes", "1"],
                stderr: "null",
                ..RuntimeProcessValue::new(&[])
            }),
        ),
    ]
}

struct RuntimeProcessValue<'a> {
    command: &'a str,
    arguments: &'a [&'a str],
    working_directory: Option<&'a str>,
    environment: Option<&'a [(&'a str, &'a str)]>,
    stdin: &'a str,
    stdin_bytes: Option<&'a [u8]>,
    stdout: &'a str,
    stderr: &'a str,
}

impl<'a> RuntimeProcessValue<'a> {
    fn new(arguments: &'a [&'a str]) -> Self {
        Self {
            command: "hell-test-helper",
            arguments,
            working_directory: None,
            environment: None,
            stdin: "stdin",
            stdin_bytes: None,
            stdout: "stdout",
            stderr: "stderr",
        }
    }
}

fn runtime_process_value(value: &RuntimeProcessValue<'_>) -> String {
    let arguments = value
        .arguments
        .iter()
        .map(|argument| format!("\"{}\"", utf8_hex(argument)))
        .collect::<Vec<_>>()
        .join(",");
    let working_directory = value.working_directory.map_or_else(
        || "null".to_owned(),
        |directory| format!("\"{}\"", utf8_hex(directory)),
    );
    let environment = value.environment.map_or_else(
        || "null".to_owned(),
        |environment| {
            let entries = environment
                .iter()
                .map(|(name, value)| {
                    format!(
                        "{{\"nameHex\":\"{}\",\"valueHex\":\"{}\"}}",
                        utf8_hex(name),
                        utf8_hex(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("[{entries}]")
        },
    );
    let stdin_bytes = value.stdin_bytes.map_or_else(
        || "null".to_owned(),
        |bytes| format!("\"{}\"", runtime_bytes_hex(bytes)),
    );
    format!(
        "{{\"type\":\"Process\",\"commandHex\":\"{}\",\"argumentsHex\":[{arguments}],\"workingDirectoryHex\":{working_directory},\"environment\":{environment},\"stdin\":{{\"type\":\"Handle\",\"kind\":\"{}\"}},\"stdinHex\":{stdin_bytes},\"stdout\":{{\"type\":\"Handle\",\"kind\":\"{}\"}},\"stderr\":{{\"type\":\"Handle\",\"kind\":\"{}\"}}}}",
        utf8_hex(value.command),
        value.stdin,
        value.stdout,
        value.stderr
    )
}

fn runtime_text_set_stdin_boundary_cases() -> Vec<DifferentialCase> {
    [("empty-input", ""), ("ascii", "abc"), ("unicode", "aβ")]
        .into_iter()
        .map(|(boundary, input)| {
            let source = format!(
                concat!(
                    "main = do\n",
                    "  helpers <- Environment.getArgs\n",
                    "  Monad.forM_ helpers \\helper -> do\n",
                    "    output <- ByteString.readProcessStdout_ $ Text.setStdin {input:?} $\n",
                    "      Process.proc helper [\"echo-stdin\"]\n",
                    "    ByteString.hPutStr IO.stdout output\n",
                ),
                input = input,
            );
            let mut descriptor = runtime_all_obligation_descriptor("Text.setStdin", &source);
            let raw = crate::raw_presentation_sha256(input.as_bytes(), b"");
            for target in &mut descriptor.semantic_targets {
                if target.dimension == hell_builtins::CompatibilityDimension::PureRuntime {
                    target.boundary_classes = vec![Arc::from(boundary)];
                    target.expected_raw_presentation_sha256 = Some(raw);
                }
                if target.dimension == hell_builtins::CompatibilityDimension::Presentation {
                    target.expected_raw_presentation_sha256 = Some(raw);
                }
            }
            DifferentialCase {
                id: Arc::from(format!("text-setstdin-boundary-{boundary}")),
                source: Arc::from(source),
                arguments: vec!["hell-test-helper".into()],
                environment_profile: EnvironmentProfile::ProcessCapable,
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_interact_cases(
    builtin: &str,
    prefix: &str,
    source: &str,
    invalid_fails: bool,
) -> Vec<DifferentialCase> {
    [
        ("empty-input", Vec::new(), Vec::new()),
        (
            "ascii",
            b"abc".to_vec(),
            if invalid_fails {
                b"ABC".to_vec()
            } else {
                b"abc".to_vec()
            },
        ),
        (
            "unicode",
            "aβ".as_bytes().to_vec(),
            if invalid_fails {
                "AΒ".as_bytes().to_vec()
            } else {
                "aβ".as_bytes().to_vec()
            },
        ),
        ("invalid-encoding", vec![0xff, b'A'], vec![0xff, b'A']),
    ]
    .into_iter()
    .map(|(boundary, stdin, stdout)| {
        let fails = invalid_fails && boundary == "invalid-encoding";
        let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
        for target in &mut descriptor.semantic_targets {
            if target.dimension == hell_builtins::CompatibilityDimension::PureRuntime {
                target.boundary_classes = vec![Arc::from(boundary)];
                if fails {
                    target
                        .obligations
                        .retain(|obligation| obligation.0.as_ref() != "adapter-success");
                } else {
                    target.expected_raw_presentation_sha256 =
                        Some(crate::raw_presentation_sha256(&stdout, b""));
                    target
                        .obligations
                        .retain(|obligation| obligation.0.as_ref() != "adapter-failure");
                }
            }
            if target.dimension == hell_builtins::CompatibilityDimension::Presentation && !fails {
                target.expected_raw_presentation_sha256 =
                    Some(crate::raw_presentation_sha256(&stdout, b""));
            }
            if target.dimension == hell_builtins::CompatibilityDimension::Effects {
                let omitted = if fails {
                    "effect-success"
                } else {
                    "effect-failure"
                };
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != omitted);
            }
        }
        if fails {
            descriptor.targets.retain(|target| {
                target.dimension != hell_builtins::CompatibilityDimension::Presentation
            });
            descriptor.semantic_targets.retain(|target| {
                target.dimension != hell_builtins::CompatibilityDimension::Presentation
            });
        }
        DifferentialCase {
            id: Arc::from(format!("{prefix}-boundary-{boundary}")),
            source: Arc::from(source),
            stdin,
            expected_runtime_completion: !fails,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_reader_boundary_cases(
    builtin: &str,
    prefix: &str,
    source: &str,
    invalid_fails: bool,
) -> Vec<DifferentialCase> {
    let mut cases = [
        ("empty-input", Vec::new()),
        ("ascii", b"abc".to_vec()),
        ("unicode", "aβ".as_bytes().to_vec()),
        ("invalid-encoding", vec![0xff, b'A']),
    ]
    .into_iter()
    .map(|(boundary, stdin)| {
        runtime_reader_boundary_case(builtin, prefix, source, boundary, stdin, invalid_fails)
    })
    .collect::<Vec<_>>();
    let consumer = if builtin.starts_with("Text.") {
        "Text.putStr output"
    } else {
        "ByteString.hPutStr IO.stdout output"
    };
    let failure_source =
        format!("main = do\n  output <- {builtin} \"missing.bin\"\n  {consumer}\n");
    let mut descriptor = runtime_all_obligation_descriptor(builtin, &failure_source);
    descriptor
        .targets
        .retain(|target| target.dimension != hell_builtins::CompatibilityDimension::Presentation);
    descriptor
        .semantic_targets
        .retain(|target| target.dimension != hell_builtins::CompatibilityDimension::Presentation);
    descriptor.semantic_targets.iter_mut().for_each(|target| {
        if target.dimension == hell_builtins::CompatibilityDimension::Effects {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "effect-success");
        } else if target.dimension == hell_builtins::CompatibilityDimension::PureRuntime {
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "adapter-success");
        }
    });
    cases.push(DifferentialCase {
        id: Arc::from(format!("runtime-typed-io-{prefix}-failure")),
        source: Arc::from(failure_source),
        expected_runtime_completion: false,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    });
    cases
}

fn runtime_reader_boundary_case(
    builtin: &str,
    prefix: &str,
    source: &str,
    boundary: &str,
    stdin: Vec<u8>,
    invalid_fails: bool,
) -> DifferentialCase {
    let fails = invalid_fails && boundary == "invalid-encoding";
    let mut descriptor = runtime_all_obligation_descriptor(builtin, source);
    for target in &mut descriptor.semantic_targets {
        if target.dimension == hell_builtins::CompatibilityDimension::PureRuntime {
            target.boundary_classes = vec![Arc::from(boundary)];
            if fails {
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "adapter-success");
            } else {
                target.expected_raw_presentation_sha256 =
                    Some(crate::raw_presentation_sha256(&stdin, b""));
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "adapter-failure");
            }
        }
        if target.dimension == hell_builtins::CompatibilityDimension::Presentation && !fails {
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(&stdin, b""));
        }
        if target.dimension == hell_builtins::CompatibilityDimension::Effects {
            let omitted = if fails {
                "effect-success"
            } else {
                "effect-failure"
            };
            target
                .obligations
                .retain(|obligation| obligation.0.as_ref() != omitted);
        }
    }
    if fails {
        descriptor.targets.retain(|target| {
            target.dimension != hell_builtins::CompatibilityDimension::Presentation
        });
        descriptor.semantic_targets.retain(|target| {
            target.dimension != hell_builtins::CompatibilityDimension::Presentation
        });
    }
    DifferentialCase {
        id: Arc::from(format!("{prefix}-boundary-{boundary}")),
        source: Arc::from(source),
        stdin,
        expected_runtime_completion: !fails,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_expected_raw_boundary_descriptor(
    builtin: &str,
    boundary: &str,
    source: &str,
    stdout: &[u8],
) -> ClaimEvidenceDescriptor {
    let mut descriptor = runtime_builtin_boundary_descriptor(builtin, boundary, source);
    descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(stdout, b""));
    descriptor
}

fn runtime_tree_result_boundary_cases() -> Vec<DifferentialCase> {
    let int = |value: i64| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let list = |elements: &[String]| {
        format!(
            "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}",
            elements.join(",")
        )
    };
    let tree = |root: i64, children: &[String]| {
        format!(
            "{{\"type\":\"Tree\",\"elements\":[{},{}]}}",
            int(root),
            list(children)
        )
    };
    let singleton = "Tree.Node 1 []";
    let finite = "Tree.Node 1 [Tree.Node 2 [], Tree.Node 3 []]";
    [
        (
            "Tree.Node",
            "empty-input",
            "main = IO.print $ Tree.flatten $ Tree.Node 1 []\n".to_owned(),
            tree(1, &[]),
        ),
        (
            "Tree.Node",
            "singleton-input",
            "main = IO.print $ Tree.flatten $ Tree.Node 1 [Tree.unfoldTree (\\seed -> (seed, [])) 2]\n".to_owned(),
            tree(1, &[tree(2, &[])]),
        ),
        (
            "Tree.Node",
            "finite-input",
            "main = IO.print $ Tree.flatten $ Tree.Node 1 [Tree.unfoldTree (\\seed -> (seed, [])) 2, Tree.unfoldTree (\\seed -> (seed, [])) 3]\n".to_owned(),
            tree(1, &[tree(2, &[]), tree(3, &[])]),
        ),
        (
            "Tree.flatten",
            "singleton-input",
            format!("main = IO.print $ Tree.flatten $ {singleton}\n"),
            list(&[int(1)]),
        ),
        (
            "Tree.flatten",
            "finite-input",
            format!("main = IO.print $ Tree.flatten $ {finite}\n"),
            list(&[int(1), int(2), int(3)]),
        ),
        (
            "Tree.levels",
            "singleton-input",
            format!("main = IO.print $ Tree.levels $ {singleton}\n"),
            list(&[list(&[int(1)])]),
        ),
        (
            "Tree.levels",
            "finite-input",
            format!("main = IO.print $ Tree.levels $ {finite}\n"),
            list(&[list(&[int(1)]), list(&[int(2), int(3)])]),
        ),
    ]
    .into_iter()
    .map(|(builtin, boundary, source, expected)| DifferentialCase {
        id: Arc::from(format!(
            "{}-boundary-{boundary}",
            builtin.to_ascii_lowercase().replace('.', "-")
        )),
        source: Arc::from(source.as_str()),
        claim_evidence: Some(runtime_expected_boundary_descriptor(
            builtin, boundary, &source, &expected,
        )),
        ..DifferentialCase::default()
    })
    .collect()
}

fn runtime_exec_parser_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "absent-option",
            concat!(
                "parser = Options.strOption (Option.long \"name\")\n",
                "main = do\n",
                "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Text.putStrLn value\n",
            ),
            Vec::<OsString>::new(),
            None,
        ),
        (
            "present-option",
            concat!(
                "parser = Options.strOption (Option.long \"name\")\n",
                "main = do\n",
                "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Text.putStrLn value\n",
            ),
            vec!["--name".into(), "alpha".into()],
            Some(b"alpha\n".as_slice()),
        ),
        (
            "repeated-option",
            concat!(
                "parser = Alternative.many (Options.strOption (Option.long \"name\"))\n",
                "main = do\n",
                "  names <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Monad.forM_ names Text.putStrLn\n",
            ),
            vec!["--name".into(), "one".into(), "--name".into(), "two".into()],
            Some(b"one\ntwo\n".as_slice()),
        ),
        (
            "malformed-option",
            concat!(
                "parser = Options.switch (Flag.long \"verbose\")\n",
                "main = do\n",
                "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  IO.print value\n",
            ),
            vec!["--unknown".into()],
            None,
        ),
        (
            "end-of-options",
            concat!(
                "parser = Options.strArgument (Argument.metavar \"ITEM\")\n",
                "main = do\n",
                "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Text.putStrLn value\n",
            ),
            vec!["--".into(), "--literal".into()],
            Some(b"--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, source, arguments, stdout)| {
        let descriptor = runtime_exec_parser_descriptor(boundary, source, stdout);
        DifferentialCase {
            id: Arc::from(format!("options-execparser-boundary-{boundary}")),
            source: Arc::from(source),
            arguments,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_exec_parser_descriptor(
    boundary: &str,
    source: &str,
    stdout: Option<&[u8]>,
) -> ClaimEvidenceDescriptor {
    let mut descriptor =
        runtime_builtin_boundary_descriptor("Options.execParser", boundary, source);
    if let Some(bytes) = stdout {
        descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
            Some(crate::raw_presentation_sha256(bytes, b""));
    } else {
        descriptor.semantic_targets[0]
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "parser-composition");
    }
    let full = runtime_all_obligation_descriptor("Options.execParser", source);
    for mut target in full.semantic_targets {
        let retain = match (stdout, target.dimension) {
            (Some(_), CompatibilityDimension::Effects) => {
                target.obligations.retain(|obligation| {
                    !matches!(
                        obligation.0.as_ref(),
                        "effect-failure" | "effect-cancellation"
                    )
                });
                true
            }
            (
                Some(_),
                CompatibilityDimension::Platform | CompatibilityDimension::ResourceBehavior,
            ) => true,
            (None, CompatibilityDimension::Effects) => {
                target.obligations.retain(|obligation| {
                    !matches!(
                        obligation.0.as_ref(),
                        "effect-success" | "effect-cancellation"
                    )
                });
                true
            }
            _ => false,
        };
        if retain {
            descriptor.targets.push(EvidenceTarget::new(
                Arc::clone(&target.builtin),
                target.dimension,
            ));
            descriptor.semantic_targets.push(target);
        }
    }
    descriptor
}

fn runtime_str_option_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "absent-option",
            Vec::<OsString>::new(),
            None,
            "Options.strOption (Option.long \"name\")",
        ),
        (
            "present-option",
            vec!["--name".into(), "alpha".into()],
            Some(b"alpha\n".as_slice()),
            "Options.strOption (Option.long \"name\")",
        ),
        (
            "repeated-option",
            vec!["--name".into(), "one".into(), "--name".into(), "two".into()],
            Some(b"one\ntwo\n".as_slice()),
            "Alternative.many (Options.strOption (Option.long \"name\"))",
        ),
        (
            "malformed-option",
            vec!["--name".into()],
            None,
            "Options.strOption (Option.long \"name\")",
        ),
        (
            "end-of-options",
            vec![
                "--name".into(),
                "alpha".into(),
                "--".into(),
                "--literal".into(),
            ],
            Some(b"alpha\n--literal\n".as_slice()),
            "Options.strOption (Option.long \"name\")",
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout, parser)| {
        let repeated = boundary == "repeated-option";
        let source = if boundary == "end-of-options" {
            concat!(
                "parser = (\\name item -> (name,item)) <$> Options.strOption (Option.long \"name\") <*> Options.strArgument (Argument.metavar \"ITEM\")\n",
                "main = do\n",
                "  (name,item) <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Text.putStrLn name\n",
                "  Text.putStrLn item\n",
            )
            .to_owned()
        } else if repeated {
            format!(
                "parser = {parser}\nmain = do\n  values <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  Monad.forM_ values Text.putStrLn\n"
            )
        } else {
            format!(
                "parser = {parser}\nmain = do\n  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  Text.putStrLn value\n"
            )
        };
        let mut descriptor =
            runtime_builtin_boundary_descriptor("Options.strOption", boundary, &source);
        if let Some(stdout) = stdout {
            descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        } else {
            descriptor.semantic_targets[0]
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "parser-composition");
        }
        DifferentialCase {
            id: Arc::from(format!("options-stroption-boundary-{boundary}")),
            source: Arc::from(source),
            arguments,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_str_argument_boundary_cases() -> Vec<DifferentialCase> {
    [
        ("absent-option", Vec::<OsString>::new(), None),
        (
            "present-option",
            vec!["alpha".into()],
            Some(b"alpha\n".as_slice()),
        ),
        ("repeated-option", vec!["one".into(), "two".into()], None),
        ("malformed-option", vec!["--unknown".into()], None),
        (
            "end-of-options",
            vec!["--".into(), "--literal".into()],
            Some(b"--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = concat!(
            "parser = Options.strArgument (Argument.metavar \"ITEM\")\n",
            "main = do\n",
            "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
            "  Text.putStrLn value\n",
        );
        let mut descriptor =
            runtime_builtin_boundary_descriptor("Options.strArgument", boundary, source);
        if let Some(stdout) = stdout {
            descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        } else {
            descriptor.semantic_targets[0]
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "parser-composition");
        }
        DifferentialCase {
            id: Arc::from(format!("options-strargument-boundary-{boundary}")),
            source: Arc::from(source),
            arguments,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_switch_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "absent-option",
            Vec::<OsString>::new(),
            Some(b"False\n".as_slice()),
        ),
        (
            "present-option",
            vec!["--verbose".into()],
            Some(b"True\n".as_slice()),
        ),
        (
            "repeated-option",
            vec!["--verbose".into(), "--verbose".into()],
            None,
        ),
        ("malformed-option", vec!["--unknown".into()], None),
        (
            "end-of-options",
            vec!["--verbose".into(), "--".into(), "--literal".into()],
            Some(b"True\n--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = if boundary == "end-of-options" {
            concat!(
                "parser = (\\flag item -> (flag,item)) <$> Options.switch (Flag.long \"verbose\") <*> Options.strArgument (Argument.metavar \"ITEM\")\n",
                "main = do\n",
                "  (flag,item) <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  IO.print flag\n",
                "  Text.putStrLn item\n",
            )
        } else {
            concat!(
                "parser = Options.switch (Flag.long \"verbose\")\n",
                "main = do\n",
                "  flag <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  IO.print flag\n",
            )
        };
        let mut descriptor =
            runtime_builtin_boundary_descriptor("Options.switch", boundary, source);
        if let Some(stdout) = stdout {
            descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        } else {
            descriptor.semantic_targets[0]
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "parser-composition");
        }
        DifferentialCase {
            id: Arc::from(format!("options-switch-boundary-{boundary}")),
            source: Arc::from(source),
            arguments,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_flag_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "absent-option",
            Vec::<OsString>::new(),
            Some(b"False\n".as_slice()),
        ),
        (
            "present-option",
            vec!["--verbose".into()],
            Some(b"True\n".as_slice()),
        ),
        (
            "repeated-option",
            vec!["--verbose".into(), "--verbose".into()],
            None,
        ),
        ("malformed-option", vec!["--unknown".into()], None),
        (
            "end-of-options",
            vec!["--verbose".into(), "--".into(), "--literal".into()],
            Some(b"True\n--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = if boundary == "end-of-options" {
            concat!(
                "parser = (\\flag item -> (flag,item)) <$> Options.flag Bool.False Bool.True (Flag.long \"verbose\") <*> Options.strArgument (Argument.metavar \"ITEM\")\n",
                "main = do\n",
                "  (flag,item) <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  IO.print flag\n",
                "  Text.putStrLn item\n",
            )
        } else {
            concat!(
                "parser = Options.flag Bool.False Bool.True (Flag.long \"verbose\")\n",
                "main = do\n",
                "  flag <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  IO.print flag\n",
            )
        };
        let mut descriptor = runtime_builtin_boundary_descriptor("Options.flag", boundary, source);
        if let Some(stdout) = stdout {
            descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        } else {
            descriptor.semantic_targets[0]
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "parser-composition");
        }
        DifferentialCase {
            id: Arc::from(format!("options-flag-boundary-{boundary}")),
            source: Arc::from(source),
            arguments,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_flag_prime_boundary_cases() -> Vec<DifferentialCase> {
    [
        ("absent-option", Vec::<OsString>::new(), None),
        (
            "present-option",
            vec!["--verbose".into()],
            Some(b"True\n".as_slice()),
        ),
        (
            "repeated-option",
            vec!["--verbose".into(), "--verbose".into()],
            None,
        ),
        ("malformed-option", vec!["--unknown".into()], None),
        (
            "end-of-options",
            vec!["--verbose".into(), "--".into(), "--literal".into()],
            Some(b"True\n--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = if boundary == "end-of-options" {
            concat!(
                "parser = (\\flag item -> (flag,item)) <$> Options.flag' Bool.True (Flag.long \"verbose\") <*> Options.strArgument (Argument.metavar \"ITEM\")\n",
                "main = do\n",
                "  (flag,item) <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  IO.print flag\n",
                "  Text.putStrLn item\n",
            )
        } else {
            concat!(
                "parser = Options.flag' Bool.True (Flag.long \"verbose\")\n",
                "main = do\n",
                "  flag <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  IO.print flag\n",
            )
        };
        let mut descriptor =
            runtime_builtin_boundary_descriptor("Options.flag'", boundary, source);
        if let Some(stdout) = stdout {
            descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        } else {
            descriptor.semantic_targets[0]
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "parser-composition");
        }
        DifferentialCase {
            id: Arc::from(format!("options-flag-prime-boundary-{boundary}")),
            source: Arc::from(source),
            arguments,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_flag_long_boundary_cases() -> Vec<DifferentialCase> {
    runtime_flag_modifier_boundary_cases("Flag.long", "flag-long", "Flag.long \"verbose\"")
}

fn runtime_flag_help_boundary_cases() -> Vec<DifferentialCase> {
    runtime_flag_modifier_boundary_cases(
        "Flag.help",
        "flag-help",
        "Flag.help \"verbosity\" <> Flag.long \"verbose\"",
    )
}

fn runtime_flag_help_observable_case() -> DifferentialCase {
    let source = concat!(
        "parser = Options.switch (Flag.help \"verbosity\" <> Flag.long \"verbose\")\n",
        "main = do\n",
        "  flag <- Options.execParser $ Options.info (Main.parser <**> Options.helper) Options.fullDesc\n",
        "  IO.print flag\n",
    );
    let stdout = concat!(
        "Usage: hell [--verbose]\n\n",
        "Available options:\n",
        "  --verbose                verbosity\n",
        "  -h,--help                Show this help text\n",
    )
    .as_bytes();
    let mut descriptor = runtime_all_obligation_descriptor("Flag.help", source);
    descriptor.semantic_targets[0]
        .obligations
        .retain(|obligation| obligation.0.as_ref() != "parser-composition");
    descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(stdout, b""));
    DifferentialCase {
        id: Arc::from("runtime-parser-observable-flag-help"),
        source: Arc::from(source),
        arguments: vec!["--help".into()],
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_option_help_observable_case() -> DifferentialCase {
    let source = concat!(
        "parser = Options.strOption (Option.help \"chosen name\" <> Option.long \"name\")\n",
        "main = do\n",
        "  value <- Options.execParser $ Options.info (Main.parser <**> Options.helper) Options.fullDesc\n",
        "  Text.putStrLn value\n",
    );
    let stdout = concat!(
        "Usage: hell --name ARG\n\n",
        "Available options:\n",
        "  --name ARG               chosen name\n",
        "  -h,--help                Show this help text\n",
    )
    .as_bytes();
    let mut descriptor = runtime_all_obligation_descriptor("Option.help", source);
    descriptor.semantic_targets[0]
        .obligations
        .retain(|obligation| obligation.0.as_ref() != "parser-composition");
    descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(stdout, b""));
    DifferentialCase {
        id: Arc::from("runtime-parser-observable-option-help"),
        source: Arc::from(source),
        arguments: vec!["--help".into()],
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_flag_modifier_boundary_cases(
    builtin: &str,
    case_prefix: &str,
    modifier: &str,
) -> Vec<DifferentialCase> {
    [
        (
            "absent-option",
            Vec::<OsString>::new(),
            Some(b"False\n".as_slice()),
        ),
        (
            "present-option",
            vec!["--verbose".into()],
            Some(b"True\n".as_slice()),
        ),
        (
            "repeated-option",
            vec!["--verbose".into(), "--verbose".into()],
            None,
        ),
        ("malformed-option", vec!["--unknown".into()], None),
        (
            "end-of-options",
            vec!["--verbose".into(), "--".into(), "--literal".into()],
            Some(b"True\n--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = if boundary == "end-of-options" {
            format!(
                "parser = (\\flag item -> (flag,item)) <$> Options.switch ({modifier}) <*> Options.strArgument (Argument.metavar \"ITEM\")\nmain = do\n  (flag,item) <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  IO.print flag\n  Text.putStrLn item\n",
            )
        } else {
            format!(
                "parser = Options.switch ({modifier})\nmain = do\n  flag <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  IO.print flag\n",
            )
        };
        let mut descriptor = runtime_builtin_boundary_descriptor(builtin, boundary, &source);
        if let Some(stdout) = stdout {
            descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        } else {
            descriptor.semantic_targets[0]
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "parser-composition");
        }
        DifferentialCase {
            id: Arc::from(format!("{case_prefix}-boundary-{boundary}")),
            source: Arc::from(source),
            arguments,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_option_long_boundary_cases() -> Vec<DifferentialCase> {
    runtime_option_modifier_boundary_cases("Option.long", "option-long", "Option.long \"name\"")
}

fn runtime_option_help_boundary_cases() -> Vec<DifferentialCase> {
    runtime_option_modifier_boundary_cases(
        "Option.help",
        "option-help",
        "Option.help \"name\" <> Option.long \"name\"",
    )
}

fn runtime_option_modifier_boundary_cases(
    builtin: &str,
    case_prefix: &str,
    modifier: &str,
) -> Vec<DifferentialCase> {
    [
        ("absent-option", Vec::<OsString>::new(), None),
        (
            "present-option",
            vec!["--name".into(), "alpha".into()],
            Some(b"alpha\n".as_slice()),
        ),
        (
            "repeated-option",
            vec!["--name".into(), "one".into(), "--name".into(), "two".into()],
            Some(b"one\ntwo\n".as_slice()),
        ),
        ("malformed-option", vec!["--name".into()], None),
        (
            "end-of-options",
            vec![
                "--name".into(),
                "alpha".into(),
                "--".into(),
                "--literal".into(),
            ],
            Some(b"alpha\n--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = if boundary == "end-of-options" {
            format!(
                "parser = (\\name item -> (name,item)) <$> Options.strOption ({modifier}) <*> Options.strArgument (Argument.metavar \"ITEM\")\nmain = do\n  (name,item) <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  Text.putStrLn name\n  Text.putStrLn item\n",
            )
        } else if boundary == "repeated-option" {
            format!(
                "parser = Alternative.many (Options.strOption ({modifier}))\nmain = do\n  values <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  Monad.forM_ values Text.putStrLn\n",
            )
        } else {
            format!(
                "parser = Options.strOption ({modifier})\nmain = do\n  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  Text.putStrLn value\n",
            )
        };
        let mut descriptor = runtime_builtin_boundary_descriptor(builtin, boundary, &source);
        if let Some(stdout) = stdout {
            descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        } else {
            descriptor.semantic_targets[0]
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "parser-composition");
        }
        DifferentialCase {
            id: Arc::from(format!("{case_prefix}-boundary-{boundary}")),
            source: Arc::from(source),
            arguments,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_argument_metavar_boundary_cases() -> Vec<DifferentialCase> {
    runtime_argument_modifier_boundary_cases(
        "Argument.metavar",
        "argument-metavar",
        "Argument.metavar \"ITEM\"",
    )
}

fn runtime_argument_help_boundary_cases() -> Vec<DifferentialCase> {
    runtime_argument_modifier_boundary_cases(
        "Argument.help",
        "argument-help",
        "Argument.help \"chosen item\" <> Argument.metavar \"ITEM\"",
    )
}

fn runtime_argument_modifier_boundary_cases(
    builtin: &str,
    case_prefix: &str,
    modifier: &str,
) -> Vec<DifferentialCase> {
    [
        ("absent-option", Vec::<OsString>::new(), None),
        (
            "present-option",
            vec!["alpha".into()],
            Some(b"alpha\n".as_slice()),
        ),
        ("repeated-option", vec!["one".into(), "two".into()], None),
        ("malformed-option", vec!["--unknown".into()], None),
        (
            "end-of-options",
            vec!["--".into(), "--literal".into()],
            Some(b"--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = format!(
            "parser = Options.strArgument ({modifier})\nmain = do\n  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n  Text.putStrLn value\n",
        );
        let mut descriptor = runtime_builtin_boundary_descriptor(builtin, boundary, &source);
        if let Some(stdout) = stdout {
            descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(stdout, b""));
        } else {
            descriptor.semantic_targets[0]
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "parser-composition");
        }
        DifferentialCase {
            id: Arc::from(format!("{case_prefix}-boundary-{boundary}")),
            source: Arc::from(source),
            arguments,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_argument_metavar_observable_case() -> DifferentialCase {
    runtime_argument_observable_case(
        "Argument.metavar",
        "runtime-parser-observable-argument-metavar",
        "Argument.metavar \"ITEM\"",
        "Usage: hell ITEM\n\nAvailable options:\n  -h,--help                Show this help text\n",
    )
}

fn runtime_argument_help_observable_case() -> DifferentialCase {
    runtime_argument_observable_case(
        "Argument.help",
        "runtime-parser-observable-argument-help",
        "Argument.help \"chosen item\" <> Argument.metavar \"ITEM\"",
        "Usage: hell ITEM\n\nAvailable options:\n  ITEM                     chosen item\n  -h,--help                Show this help text\n",
    )
}

fn runtime_argument_observable_case(
    builtin: &str,
    case_id: &str,
    modifier: &str,
    stdout: &str,
) -> DifferentialCase {
    let source = format!(
        "parser = Options.strArgument ({modifier})\nmain = do\n  value <- Options.execParser $ Options.info (Main.parser <**> Options.helper) Options.fullDesc\n  Text.putStrLn value\n",
    );
    let mut descriptor = runtime_all_obligation_descriptor(builtin, &source);
    descriptor.semantic_targets[0]
        .obligations
        .retain(|obligation| obligation.0.as_ref() != "parser-composition");
    descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(stdout.as_bytes(), b""));
    DifferentialCase {
        id: Arc::from(case_id),
        source: Arc::from(source),
        arguments: vec!["--help".into()],
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_option_value_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "absent-option",
            Vec::<OsString>::new(),
            Some(b"fallback\n".as_slice()),
        ),
        (
            "present-option",
            vec!["--name".into(), "alpha".into()],
            Some(b"alpha\n".as_slice()),
        ),
        (
            "repeated-option",
            vec!["--name".into(), "one".into(), "--name".into(), "two".into()],
            None,
        ),
        ("malformed-option", vec!["--name".into()], None),
        (
            "end-of-options",
            vec![
                "--name".into(),
                "alpha".into(),
                "--".into(),
                "--literal".into(),
            ],
            Some(b"alpha\n--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = if boundary == "end-of-options" {
            concat!(
                "parser = (\\name item -> (name,item)) <$> Options.strOption (Option.value \"fallback\" <> Option.long \"name\") <*> Options.strArgument (Argument.metavar \"ITEM\")\n",
                "main = do\n",
                "  (name,item) <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Text.putStrLn name\n",
                "  Text.putStrLn item\n",
            )
        } else {
            concat!(
                "parser = Options.strOption (Option.value \"fallback\" <> Option.long \"name\")\n",
                "main = do\n",
                "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  Text.putStrLn value\n",
            )
        };
        runtime_default_modifier_boundary_case(
            "Option.value",
            "option-value",
            boundary,
            source,
            arguments,
            stdout,
        )
    })
    .collect()
}

fn runtime_argument_value_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "absent-option",
            Vec::<OsString>::new(),
            Some(b"fallback\n".as_slice()),
        ),
        (
            "present-option",
            vec!["alpha".into()],
            Some(b"alpha\n".as_slice()),
        ),
        ("repeated-option", vec!["one".into(), "two".into()], None),
        ("malformed-option", vec!["--unknown".into()], None),
        (
            "end-of-options",
            vec!["--".into(), "--literal".into()],
            Some(b"--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = concat!(
            "parser = Options.strArgument (Argument.value \"fallback\" <> Argument.metavar \"ITEM\")\n",
            "main = do\n",
            "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
            "  Text.putStrLn value\n",
        );
        runtime_default_modifier_boundary_case(
            "Argument.value",
            "argument-value",
            boundary,
            source,
            arguments,
            stdout,
        )
    })
    .collect()
}

fn runtime_default_modifier_boundary_case(
    builtin: &str,
    case_prefix: &str,
    boundary: &str,
    source: &str,
    arguments: Vec<OsString>,
    stdout: Option<&[u8]>,
) -> DifferentialCase {
    let mut descriptor = runtime_builtin_boundary_descriptor(builtin, boundary, source);
    if let Some(stdout) = stdout {
        descriptor.semantic_targets[0].expected_raw_presentation_sha256 =
            Some(crate::raw_presentation_sha256(stdout, b""));
    } else {
        descriptor.semantic_targets[0]
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "parser-composition");
    }
    DifferentialCase {
        id: Arc::from(format!("{case_prefix}-boundary-{boundary}")),
        source: Arc::from(source),
        arguments,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_options_header_boundary_cases() -> Vec<DifferentialCase> {
    runtime_options_metadata_boundary_cases(
        "Options.header",
        "options-header",
        "Options.switch (Flag.long \"verbose\")",
        "Options.header \"reviewed header\"",
    )
}

fn runtime_options_prog_desc_boundary_cases() -> Vec<DifferentialCase> {
    runtime_options_metadata_boundary_cases(
        "Options.progDesc",
        "options-progdesc",
        "Options.switch (Flag.long \"verbose\")",
        "Options.progDesc \"reviewed description\"",
    )
}

fn runtime_options_helper_boundary_cases() -> Vec<DifferentialCase> {
    runtime_options_metadata_boundary_cases(
        "Options.helper",
        "options-helper",
        "Options.switch (Flag.long \"verbose\") <**> Options.helper",
        "Options.fullDesc",
    )
}

fn runtime_options_info_boundary_cases() -> Vec<DifferentialCase> {
    runtime_options_metadata_boundary_cases(
        "Options.info",
        "options-info",
        "Options.switch (Flag.long \"verbose\")",
        "Options.fullDesc",
    )
}

fn runtime_options_full_desc_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = runtime_options_metadata_boundary_cases(
        "Options.fullDesc",
        "options-fulldesc",
        "Options.switch (Flag.long \"verbose\")",
        "Options.fullDesc",
    );
    let canonical = concat!(
        "{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",",
        "\"value\":{\"type\":\"OptionsInfoMod\",\"fullDescription\":true,",
        "\"programDescriptionHex\":null,\"headerHex\":null}}",
    );
    for case in &mut cases {
        case.claim_evidence
            .as_mut()
            .expect("fullDesc boundary descriptor")
            .semantic_targets[0]
            .expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    }
    cases
}

fn runtime_options_command_boundary_cases() -> Vec<DifferentialCase> {
    runtime_command_graph_boundary_cases("Options.command", "options-command")
}

fn runtime_options_hsubparser_boundary_cases() -> Vec<DifferentialCase> {
    runtime_command_graph_boundary_cases("Options.hsubparser", "options-hsubparser")
}

fn runtime_command_graph_boundary_cases(builtin: &str, case_prefix: &str) -> Vec<DifferentialCase> {
    [
        ("absent-option", Vec::<OsString>::new(), None),
        (
            "present-option",
            vec!["run".into()],
            Some(b"ran\n".as_slice()),
        ),
        ("repeated-option", vec!["run".into(), "run".into()], None),
        ("malformed-option", vec!["unknown".into()], None),
        (
            "end-of-options",
            vec!["--".into(), "run".into()],
            Some(b"ran\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = concat!(
            "parser = Options.hsubparser (Options.command \"run\" (Options.info (Applicative.pure \"ran\") Options.fullDesc))\n",
            "main = do\n",
            "  value <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
            "  Text.putStrLn value\n",
        );
        runtime_default_modifier_boundary_case(
            builtin,
            case_prefix,
            boundary,
            source,
            arguments,
            stdout,
        )
    })
    .collect()
}

fn runtime_options_metadata_boundary_cases(
    builtin: &str,
    case_prefix: &str,
    parser: &str,
    info_modifier: &str,
) -> Vec<DifferentialCase> {
    [
        (
            "absent-option",
            Vec::<OsString>::new(),
            Some(b"False\n".as_slice()),
        ),
        (
            "present-option",
            vec!["--verbose".into()],
            Some(b"True\n".as_slice()),
        ),
        (
            "repeated-option",
            vec!["--verbose".into(), "--verbose".into()],
            None,
        ),
        ("malformed-option", vec!["--unknown".into()], None),
        (
            "end-of-options",
            vec!["--verbose".into(), "--".into(), "--literal".into()],
            Some(b"True\n--literal\n".as_slice()),
        ),
    ]
    .into_iter()
    .map(|(boundary, arguments, stdout)| {
        let source = if boundary == "end-of-options" {
            format!(
                "parser = (\\flag item -> (flag,item)) <$> ({parser}) <*> Options.strArgument (Argument.metavar \"ITEM\")\nmain = do\n  (flag,item) <- Options.execParser $ Options.info Main.parser ({info_modifier})\n  IO.print flag\n  Text.putStrLn item\n",
            )
        } else {
            format!(
                "parser = {parser}\nmain = do\n  flag <- Options.execParser $ Options.info Main.parser ({info_modifier})\n  IO.print flag\n",
            )
        };
        runtime_default_modifier_boundary_case(
            builtin,
            case_prefix,
            boundary,
            &source,
            arguments,
            stdout,
        )
    })
    .collect()
}

fn runtime_options_metadata_observable_cases() -> Vec<DifferentialCase> {
    [
        (
            "Options.header",
            "runtime-parser-observable-options-header",
            "Options.header \"reviewed header\"",
            "reviewed header\n\nUsage: hell [--verbose]\n\nAvailable options:\n  -h,--help                Show this help text\n",
        ),
        (
            "Options.progDesc",
            "runtime-parser-observable-options-progdesc",
            "Options.progDesc \"reviewed description\"",
            "Usage: hell [--verbose]\n\n  reviewed description\n\nAvailable options:\n  -h,--help                Show this help text\n",
        ),
        (
            "Options.helper",
            "runtime-parser-observable-options-helper",
            "Options.fullDesc",
            "Usage: hell [--verbose]\n\nAvailable options:\n  -h,--help                Show this help text\n",
        ),
    ]
    .into_iter()
    .map(|(builtin, case_id, info_modifier, stdout)| {
        let source = format!(
            "parser = Options.switch (Flag.long \"verbose\") <**> Options.helper\nmain = do\n  flag <- Options.execParser $ Options.info Main.parser ({info_modifier})\n  IO.print flag\n",
        );
        let mut descriptor = runtime_all_obligation_descriptor(builtin, &source);
        descriptor.targets.retain(|target| {
            target.dimension == hell_builtins::CompatibilityDimension::PureRuntime
        });
        descriptor.semantic_targets.retain(|target| {
            target.dimension == hell_builtins::CompatibilityDimension::PureRuntime
        });
        descriptor.semantic_targets[0]
            .obligations
            .retain(|obligation| obligation.0.as_ref() != "parser-composition");
        descriptor.semantic_targets[0].expected_raw_presentation_sha256 = Some(
            crate::raw_presentation_sha256(stdout.as_bytes(), b""),
        );
        DifferentialCase {
            id: Arc::from(case_id),
            source: Arc::from(source),
            arguments: vec!["--help".into()],
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

#[derive(Clone, Copy)]
struct OptionsPresentationDefinition {
    builtin: &'static str,
    slug: &'static str,
    source: &'static str,
    stdout: &'static [u8],
}

fn runtime_options_presentation_cases() -> Vec<DifferentialCase> {
    options_presentation_definitions()
        .into_iter()
        .map(runtime_options_presentation_case)
        .collect()
}

fn runtime_options_presentation_case(
    definition: OptionsPresentationDefinition,
) -> DifferentialCase {
    let mut descriptor = runtime_all_obligation_descriptor(definition.builtin, definition.source);
    descriptor
        .targets
        .retain(|target| target.dimension == CompatibilityDimension::Presentation);
    descriptor
        .semantic_targets
        .retain(|target| target.dimension == CompatibilityDimension::Presentation);
    let target = &mut descriptor.semantic_targets[0];
    target.expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(definition.stdout, b""));
    target.expected_presentation_shadow_normalizer =
        Some(PresentationShadowNormalizerId::LineEndingsV1);
    target.expected_normalized_presentation_sha256 = Some(
        crate::normalized_presentation_shadow_sha256(
            PresentationShadowNormalizerId::LineEndingsV1,
            definition.stdout,
            b"",
        )
        .expect("reviewed Options presentation is UTF-8"),
    );
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
    if definition.builtin == "Options.fullDesc" {
        let canonical = concat!(
            "{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",",
            "\"value\":{\"type\":\"OptionsInfoMod\",\"fullDescription\":true,",
            "\"programDescriptionHex\":null,\"headerHex\":null}}",
        );
        target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    }
    DifferentialCase {
        id: Arc::from(format!("runtime-options-presentation-{}", definition.slug)),
        source: Arc::from(definition.source),
        arguments: vec!["--help".into()],
        expected_runtime_completion: false,
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

const OPTIONS_BASE_SOURCE: &str = concat!(
    "parser = Options.switch (Flag.long \"verbose\") <**> Options.helper\n",
    "main = do { _ <- Options.execParser $ Options.info Main.parser Options.fullDesc; IO.pure () }\n",
);
const OPTIONS_BASE_HELP: &[u8] = concat!(
    "Usage: hell [--verbose]\n\n",
    "Available options:\n",
    "  -h,--help                Show this help text\n",
)
.as_bytes();
const OPTIONS_FLAG_SOURCE: &str = concat!(
    "parser = Options.flag Bool.False Bool.True (Flag.long \"verbose\") <**> Options.helper\n",
    "main = do { _ <- Options.execParser $ Options.info Main.parser Options.fullDesc; IO.pure () }\n",
);
const OPTIONS_FLAG_PRIME_SOURCE: &str = concat!(
    "parser = Options.flag' Bool.True (Flag.long \"verbose\") <**> Options.helper\n",
    "main = do { _ <- Options.execParser $ Options.info Main.parser Options.fullDesc; IO.pure () }\n",
);
const OPTIONS_FLAG_PRIME_HELP: &[u8] = concat!(
    "Usage: hell --verbose\n\n",
    "Available options:\n",
    "  -h,--help                Show this help text\n",
)
.as_bytes();
const OPTIONS_STR_OPTION_SOURCE: &str = concat!(
    "parser = Options.strOption (Option.long \"name\") <**> Options.helper\n",
    "main = do { _ <- Options.execParser $ Options.info Main.parser Options.fullDesc; IO.pure () }\n",
);
const OPTIONS_STR_OPTION_HELP: &[u8] = concat!(
    "Usage: hell --name ARG\n\n",
    "Available options:\n",
    "  -h,--help                Show this help text\n",
)
.as_bytes();
const OPTIONS_STR_ARGUMENT_SOURCE: &str = concat!(
    "parser = Options.strArgument (Argument.metavar \"ITEM\") <**> Options.helper\n",
    "main = do { _ <- Options.execParser $ Options.info Main.parser Options.fullDesc; IO.pure () }\n",
);
const OPTIONS_STR_ARGUMENT_HELP: &[u8] = concat!(
    "Usage: hell ITEM\n\n",
    "Available options:\n",
    "  -h,--help                Show this help text\n",
)
.as_bytes();
const OPTIONS_HEADER_SOURCE: &str = concat!(
    "parser = Options.switch (Flag.long \"verbose\") <**> Options.helper\n",
    "main = do { _ <- Options.execParser $ Options.info Main.parser (Options.header \"reviewed header\"); IO.pure () }\n",
);
const OPTIONS_HEADER_HELP: &[u8] = concat!(
    "reviewed header\n\nUsage: hell [--verbose]\n\n",
    "Available options:\n",
    "  -h,--help                Show this help text\n",
)
.as_bytes();
const OPTIONS_DESCRIPTION_SOURCE: &str = concat!(
    "parser = Options.switch (Flag.long \"verbose\") <**> Options.helper\n",
    "main = do { _ <- Options.execParser $ Options.info Main.parser (Options.progDesc \"reviewed description\"); IO.pure () }\n",
);
const OPTIONS_DESCRIPTION_HELP: &[u8] = concat!(
    "Usage: hell [--verbose]\n\n  reviewed description\n\n",
    "Available options:\n",
    "  -h,--help                Show this help text\n",
)
.as_bytes();
const OPTIONS_COMMAND_SOURCE: &str = concat!(
    "parser = Options.hsubparser (Options.command \"run\" (Options.info (Applicative.pure \"ran\") (Options.progDesc \"run it\"))) <**> Options.helper\n",
    "main = do { _ <- Options.execParser $ Options.info Main.parser Options.fullDesc; IO.pure () }\n",
);
const OPTIONS_COMMAND_HELP: &[u8] = concat!(
    "Usage: hell COMMAND\n\n",
    "Available options:\n",
    "  -h,--help                Show this help text\n\n",
    "Available commands:\n",
    "  run                      run it\n",
)
.as_bytes();

fn options_presentation_definitions() -> [OptionsPresentationDefinition; 13] {
    [
        options_presentation_definition(
            "Options.command",
            "command",
            OPTIONS_COMMAND_SOURCE,
            OPTIONS_COMMAND_HELP,
        ),
        options_presentation_definition(
            "Options.execParser",
            "exec-parser",
            OPTIONS_BASE_SOURCE,
            OPTIONS_BASE_HELP,
        ),
        options_presentation_definition(
            "Options.flag",
            "flag",
            OPTIONS_FLAG_SOURCE,
            OPTIONS_BASE_HELP,
        ),
        options_presentation_definition(
            "Options.flag'",
            "flag-prime",
            OPTIONS_FLAG_PRIME_SOURCE,
            OPTIONS_FLAG_PRIME_HELP,
        ),
        options_presentation_definition(
            "Options.fullDesc",
            "full-desc",
            OPTIONS_BASE_SOURCE,
            OPTIONS_BASE_HELP,
        ),
        options_presentation_definition(
            "Options.header",
            "header",
            OPTIONS_HEADER_SOURCE,
            OPTIONS_HEADER_HELP,
        ),
        options_presentation_definition(
            "Options.helper",
            "helper",
            OPTIONS_BASE_SOURCE,
            OPTIONS_BASE_HELP,
        ),
        options_presentation_definition(
            "Options.hsubparser",
            "hsubparser",
            OPTIONS_COMMAND_SOURCE,
            OPTIONS_COMMAND_HELP,
        ),
        options_presentation_definition(
            "Options.info",
            "info",
            OPTIONS_BASE_SOURCE,
            OPTIONS_BASE_HELP,
        ),
        options_presentation_definition(
            "Options.progDesc",
            "prog-desc",
            OPTIONS_DESCRIPTION_SOURCE,
            OPTIONS_DESCRIPTION_HELP,
        ),
        options_presentation_definition(
            "Options.strArgument",
            "str-argument",
            OPTIONS_STR_ARGUMENT_SOURCE,
            OPTIONS_STR_ARGUMENT_HELP,
        ),
        options_presentation_definition(
            "Options.strOption",
            "str-option",
            OPTIONS_STR_OPTION_SOURCE,
            OPTIONS_STR_OPTION_HELP,
        ),
        options_presentation_definition(
            "Options.switch",
            "switch",
            OPTIONS_BASE_SOURCE,
            OPTIONS_BASE_HELP,
        ),
    ]
}

const fn options_presentation_definition(
    builtin: &'static str,
    slug: &'static str,
    source: &'static str,
    stdout: &'static [u8],
) -> OptionsPresentationDefinition {
    OptionsPresentationDefinition {
        builtin,
        slug,
        source,
        stdout,
    }
}

fn runtime_tree_callback_boundary_cases() -> Vec<DifferentialCase> {
    let int = |value: i64| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let list = |elements: &[String]| {
        format!(
            "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}",
            elements.join(",")
        )
    };
    let tree = |root: i64, children: &[String]| {
        format!(
            "{{\"type\":\"Tree\",\"elements\":[{},{}]}}",
            int(root),
            list(children)
        )
    };
    let empty = list(&[]);
    let map_singleton = tree(2, &[]);
    let map_finite = tree(2, &[tree(3, &[]), tree(4, &[])]);
    let fold_children = list(&[int(2), int(3)]);
    [
        (
            "Tree.map",
            "singleton-input",
            "main = IO.print $ Tree.flatten $ Tree.map (Int.plus 1) $ Tree.Node 1 []\n",
            vec![callback_contract_invocation(
                0,
                "node",
                &[&int(1)],
                &int(2),
            )],
            map_singleton,
        ),
        (
            "Tree.map",
            "finite-input",
            "main = IO.print $ Tree.flatten $ Tree.map (Int.plus 1) $ Tree.Node 1 [Tree.Node 2 [], Tree.Node 3 []]\n",
            [1, 2, 3]
                .into_iter()
                .map(|value| {
                    callback_contract_invocation(
                        0,
                        "node",
                        &[&int(value)],
                        &int(value + 1),
                    )
                })
                .collect(),
            map_finite,
        ),
        (
            "Tree.foldTree",
            "singleton-input",
            "main = IO.print $ Tree.foldTree (\\value children -> List.foldl' Int.plus value children) $ Tree.Node 1 []\n",
            vec![callback_contract_invocation(
                0,
                "node",
                &[&int(1), &empty],
                &int(1),
            )],
            int(1),
        ),
        (
            "Tree.foldTree",
            "finite-input",
            "main = IO.print $ Tree.foldTree (\\value children -> List.foldl' Int.plus value children) $ Tree.Node 1 [Tree.Node 2 [], Tree.Node 3 []]\n",
            vec![
                callback_contract_invocation(
                    0,
                    "node",
                    &[&int(1), &fold_children],
                    &int(6),
                ),
                callback_contract_invocation(0, "node", &[&int(2), &empty], &int(2)),
                callback_contract_invocation(0, "node", &[&int(3), &empty], &int(3)),
            ],
            int(6),
        ),
    ]
    .into_iter()
    .map(|(builtin, boundary, source, invocations, expected)| {
        let mut descriptor = runtime_boundary_descriptor(builtin, boundary, source, invocations);
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{expected}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!(
                "{}-boundary-{boundary}",
                builtin.to_ascii_lowercase().replace('.', "-")
            )),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_tree_unfold_exact_case() -> DifferentialCase {
    const SOURCE: &str = concat!(
        "main = IO.print $ Tree.flatten $ Tree.unfoldTree (\\seed -> ",
        "(seed, if Int.eq seed 3 then [] else [Int.plus seed 1])) 1\n",
    );
    let int = |value: i64| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let list = |elements: &[String]| {
        format!(
            "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}",
            elements.join(",")
        )
    };
    let tree = |root: i64, children: &[String]| {
        format!(
            "{{\"type\":\"Tree\",\"elements\":[{},{}]}}",
            int(root),
            list(children)
        )
    };
    let callback_result = |root: i64, children: &[i64]| {
        let children = children.iter().map(|child| int(*child)).collect::<Vec<_>>();
        format!(
            "{{\"type\":\"Tuple\",\"elements\":[{},{}]}}",
            int(root),
            list(&children)
        )
    };
    let mut descriptor = runtime_single_typed_target_descriptor("Tree.unfoldTree", SOURCE);
    descriptor.callback_contracts = vec![CallbackContract {
        builtin: Arc::from("Tree.unfoldTree"),
        invocations: vec![
            callback_contract_invocation(0, "seed", &[&int(1)], &callback_result(1, &[2])),
            callback_contract_invocation(0, "seed", &[&int(2)], &callback_result(2, &[3])),
            callback_contract_invocation(0, "seed", &[&int(3)], &callback_result(3, &[])),
        ],
    }];
    let expected = tree(1, &[tree(2, &[tree(3, &[])])]);
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{expected}}}"
    );
    descriptor.semantic_targets[0].expected_typed_result_sha256 =
        Some(sha256_bytes(canonical.as_bytes()));
    DifferentialCase {
        id: Arc::from("runtime-typed-tree-unfold-exact"),
        source: Arc::from(SOURCE),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_all_obligation_descriptor(builtin: &str, source: &str) -> ClaimEvidenceDescriptor {
    let spec = hell_builtins::lookup(builtin).expect("runtime target is registry-backed");
    let cells = crate::runtime_obligation_cells_for_spec(spec);
    ClaimEvidenceDescriptor {
        schema_version: 8,
        profile: ExecutionProfile::Upstream,
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        targets: cells
            .iter()
            .map(|cell| EvidenceTarget::new(Arc::clone(&cell.builtin), cell.dimension))
            .collect(),
        semantic_targets: cells
            .into_iter()
            .map(|cell| {
                let mut target = EvidenceTargetV2::new(
                    cell.builtin,
                    cell.dimension,
                    cell.obligations,
                    cell.causal_signal,
                    cell.platforms,
                );
                if builtin == "IO.print" {
                    target
                        .obligations
                        .retain(|obligation| obligation.0.as_ref() != "normalized-shadow-diff");
                }
                target
            })
            .collect(),
        callback_contracts: Vec::new(),
        review_state: CaseReviewState::Reviewed,
        review_statement: Arc::from("runtime-all-obligation-review-v1"),
        source_sha256: sha256_bytes(source.as_bytes()),
    }
}

fn runtime_boolean_false_outcome_cases() -> Vec<DifferentialCase> {
    [
        ("Int.eq", "main = IO.print $ Int.eq 2 2\n", true),
        ("Double.eq", "main = IO.print $ Double.eq 1.5 1.5\n", true),
        ("Text.eq", "main = IO.print $ Text.eq \"aβ\" \"aβ\"\n", true),
        ("Eq.eq", "main = IO.print $ Eq.eq 42 42\n", true),
        ("Ord.lt", "main = IO.print $ Ord.lt 1 2\n", true),
        ("Ord.gt", "main = IO.print $ Ord.gt 2 1\n", true),
        ("Eq.eq", "main = IO.print $ Eq.eq 1 2\n", false),
        ("Ord.lt", "main = IO.print $ Ord.lt 2 1\n", false),
        ("Ord.gt", "main = IO.print $ Ord.gt 1 2\n", false),
    ]
    .into_iter()
    .map(|(builtin, source, expected)| {
        let mut descriptor = runtime_single_typed_target_descriptor(builtin, source);
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Bool\",\"value\":{expected}}}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!(
                "runtime-typed-{}-{expected}",
                hell_builtins::lookup(builtin)
                    .and_then(|spec| spec.implementation)
                    .expect("Bool comparator has a runtime implementation")
                    .replace('_', "-")
            )),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_unfoldr_exact_case() -> DifferentialCase {
    const SOURCE: &str = concat!(
        "main = IO.print $ List.unfoldr (\\seed -> ",
        "if Int.eq seed 2 then Maybe.Nothing ",
        "else Maybe.Just (seed,Int.plus seed 1)) 0\n",
    );
    let mut descriptor = runtime_single_typed_target_descriptor("List.unfoldr", SOURCE);
    descriptor.semantic_targets[0].expected_typed_result_sha256 = Some(sha256_bytes(
        b"{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{\"type\":\"List\",\"elements\":[{\"type\":\"Int\",\"value\":\"0\"},{\"type\":\"Int\",\"value\":\"1\"}],\"terminationHex\":\"6e696c\"}}",
    ));
    descriptor.callback_contracts = vec![CallbackContract {
        builtin: Arc::from("List.unfoldr"),
        invocations: vec![
            callback_contract_invocation(
                0,
                "seed",
                &["{\"type\":\"Int\",\"value\":\"0\"}"],
                "{\"type\":\"Maybe\",\"payload\":{\"type\":\"Tuple\",\"elements\":[{\"type\":\"Int\",\"value\":\"0\"},{\"type\":\"Int\",\"value\":\"1\"}]}}",
            ),
            callback_contract_invocation(
                0,
                "seed",
                &["{\"type\":\"Int\",\"value\":\"1\"}"],
                "{\"type\":\"Maybe\",\"payload\":{\"type\":\"Tuple\",\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},{\"type\":\"Int\",\"value\":\"2\"}]}}",
            ),
            callback_contract_invocation(
                0,
                "seed",
                &["{\"type\":\"Int\",\"value\":\"2\"}"],
                "{\"type\":\"Maybe\",\"payload\":null}",
            ),
        ],
    }];
    DifferentialCase {
        id: Arc::from("runtime-typed-list-unfoldr-exact"),
        source: Arc::from(SOURCE),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn runtime_unfoldr_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print (List.unfoldr (\\seed -> if Int.eq seed seed then Maybe.Nothing else Maybe.Nothing) 0 :: [Int])\n",
            vec![callback_contract_invocation(
                0,
                "seed",
                &["{\"type\":\"Int\",\"value\":\"0\"}"],
                "{\"type\":\"Maybe\",\"payload\":null}",
            )],
            "{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}",
        ),
        (
            "singleton-input",
            concat!(
                "main = IO.print $ List.unfoldr (\\seed -> ",
                "if Int.eq seed 0 then Maybe.Just (seed,Int.plus seed 1) ",
                "else Maybe.Nothing) 0\n",
            ),
            vec![
                callback_contract_invocation(
                    0,
                    "seed",
                    &["{\"type\":\"Int\",\"value\":\"0\"}"],
                    "{\"type\":\"Maybe\",\"payload\":{\"type\":\"Tuple\",\"elements\":[{\"type\":\"Int\",\"value\":\"0\"},{\"type\":\"Int\",\"value\":\"1\"}]}}",
                ),
                callback_contract_invocation(
                    0,
                    "seed",
                    &["{\"type\":\"Int\",\"value\":\"1\"}"],
                    "{\"type\":\"Maybe\",\"payload\":null}",
                ),
            ],
            "{\"type\":\"List\",\"elements\":[{\"type\":\"Int\",\"value\":\"0\"}],\"terminationHex\":\"6e696c\"}",
        ),
        (
            "finite-input",
            concat!(
                "main = IO.print $ List.unfoldr (\\seed -> ",
                "if Int.eq seed 2 then Maybe.Nothing ",
                "else Maybe.Just (seed,Int.plus seed 1)) 0\n",
            ),
            vec![
                callback_contract_invocation(
                    0,
                    "seed",
                    &["{\"type\":\"Int\",\"value\":\"0\"}"],
                    "{\"type\":\"Maybe\",\"payload\":{\"type\":\"Tuple\",\"elements\":[{\"type\":\"Int\",\"value\":\"0\"},{\"type\":\"Int\",\"value\":\"1\"}]}}",
                ),
                callback_contract_invocation(
                    0,
                    "seed",
                    &["{\"type\":\"Int\",\"value\":\"1\"}"],
                    "{\"type\":\"Maybe\",\"payload\":{\"type\":\"Tuple\",\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},{\"type\":\"Int\",\"value\":\"2\"}]}}",
                ),
                callback_contract_invocation(
                    0,
                    "seed",
                    &["{\"type\":\"Int\",\"value\":\"2\"}"],
                    "{\"type\":\"Maybe\",\"payload\":null}",
                ),
            ],
            "{\"type\":\"List\",\"elements\":[{\"type\":\"Int\",\"value\":\"0\"},{\"type\":\"Int\",\"value\":\"1\"}],\"terminationHex\":\"6e696c\"}",
        ),
    ]
    .into_iter()
    .map(|(boundary, source, invocations, expected)| {
        let mut descriptor =
            runtime_boundary_descriptor("List.unfoldr", boundary, source, invocations);
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{expected}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!("list-unfoldr-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_single_typed_target_descriptor(builtin: &str, source: &str) -> ClaimEvidenceDescriptor {
    let spec = hell_builtins::lookup(builtin).expect("typed target builtin is registry-backed");
    let cells = crate::runtime_obligation_cells_for_spec(spec);
    let cell = cells
        .into_iter()
        .find(|cell| cell.dimension == hell_builtins::CompatibilityDimension::PureRuntime)
        .expect("typed target has a pure runtime cell");
    let mut target = EvidenceTargetV2::new(
        cell.builtin,
        cell.dimension,
        cell.obligations,
        cell.causal_signal,
        cell.platforms,
    );
    target
        .obligations
        .retain(|obligation| obligation.0.as_ref() != "adapter-failure");
    ClaimEvidenceDescriptor {
        schema_version: 8,
        profile: ExecutionProfile::Upstream,
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        targets: vec![EvidenceTarget::new(
            Arc::clone(&target.builtin),
            target.dimension,
        )],
        semantic_targets: vec![target],
        callback_contracts: runtime_callback_contracts(builtin),
        review_state: CaseReviewState::Reviewed,
        review_statement: Arc::from("runtime-typed-target-review-v1"),
        source_sha256: sha256_bytes(source.as_bytes()),
    }
}

fn runtime_callback_contracts(builtin: &str) -> Vec<CallbackContract> {
    let Some(invocations) =
        core_callback_invocations(builtin).or_else(|| list_callback_invocations(builtin))
    else {
        return Vec::new();
    };
    vec![CallbackContract {
        builtin: Arc::from(builtin),
        invocations,
    }]
}

fn core_callback_invocations(builtin: &str) -> Option<Vec<CallbackInvocationContract>> {
    let invocations = match builtin {
        "Maybe.maybe" => vec![callback_contract_invocation(
            1,
            "just",
            &["{\"type\":\"Int\",\"value\":\"1\"}"],
            "{\"type\":\"Int\",\"value\":\"2\"}",
        )],
        "Maybe.mapMaybe" => vec![
            callback_contract_invocation(
                0,
                "element",
                &["{\"type\":\"Int\",\"value\":\"0\"}"],
                "{\"type\":\"Maybe\",\"payload\":{\"type\":\"Int\",\"value\":\"1\"}}",
            ),
            callback_contract_invocation(
                0,
                "element",
                &["{\"type\":\"Int\",\"value\":\"1\"}"],
                "{\"type\":\"Maybe\",\"payload\":null}",
            ),
        ],
        "Either.either" => vec![callback_contract_invocation(
            0,
            "left",
            &["{\"type\":\"Int\",\"value\":\"1\"}"],
            "{\"type\":\"Int\",\"value\":\"2\"}",
        )],
        "These.these" => vec![callback_contract_invocation(
            2,
            "these",
            &[
                "{\"type\":\"Int\",\"value\":\"1\"}",
                "{\"type\":\"Text\",\"utf8Hex\":\"7269676874\"}",
            ],
            "{\"type\":\"Int\",\"value\":\"6\"}",
        )],
        "Function.fix" => vec![CallbackInvocationContract {
            callback_argument: 0,
            branch: Arc::from("recursive"),
            canonical_argument_sha256: vec![callback_digest(
                "205696a9b4f90c1d548d93a20d1a0d4481961f216d84702363a5ff14711b53da",
            )],
            outcome: Arc::from("value"),
            canonical_result_sha256: callback_digest(
                "205696a9b4f90c1d548d93a20d1a0d4481961f216d84702363a5ff14711b53da",
            ),
        }],
        "Exit.exitCode" => vec![callback_contract_invocation(
            1,
            "failure",
            &["{\"type\":\"Int\",\"value\":\"23\"}"],
            "{\"type\":\"Int\",\"value\":\"23\"}",
        )],
        _ => return None,
    };
    Some(invocations)
}

fn list_callback_invocations(builtin: &str) -> Option<Vec<CallbackInvocationContract>> {
    let invocations = match builtin {
        "List.map" => vec![
            callback_contract_invocation(
                0,
                "element",
                &["{\"type\":\"Int\",\"value\":\"1\"}"],
                "{\"type\":\"Int\",\"value\":\"2\"}",
            ),
            callback_contract_invocation(
                0,
                "element",
                &["{\"type\":\"Int\",\"value\":\"2\"}"],
                "{\"type\":\"Int\",\"value\":\"3\"}",
            ),
        ],
        "List.all" => predicate_invocations(&[("1", true), ("2", true)]),
        "List.any" => predicate_invocations(&[("0", false), ("2", true)]),
        "List.dropWhile" => predicate_invocations(&[("1", true), ("2", false)]),
        "List.find" | "List.findIndex" => predicate_invocations(&[("1", false), ("2", true)]),
        "List.findIndices" => predicate_invocations(&[("1", false), ("2", true), ("2", true)]),
        "List.filter" => predicate_invocations(&[("1", true), ("2", true), ("3", false)]),
        "List.break" => predicate_invocations(&[("1", false), ("0", true)]),
        "List.span" => predicate_invocations(&[("1", true), ("2", true), ("0", false)]),
        "List.takeWhile" | "List.partition" => {
            predicate_invocations(&[("1", true), ("2", true), ("3", false)])
        }
        _ => return None,
    };
    Some(invocations)
}

fn predicate_invocations(values: &[(&str, bool)]) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|(value, result)| {
            let argument = format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
            let result = format!("{{\"type\":\"Bool\",\"value\":{result}}}");
            callback_contract_invocation(0, "predicate", &[&argument], &result)
        })
        .collect()
}

fn value_callback_invocations(values: &[(&str, &str)]) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|(value, result)| {
            let argument = format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
            let result = format!("{{\"type\":\"Int\",\"value\":\"{result}\"}}");
            callback_contract_invocation(0, "value", &[&argument], &result)
        })
        .collect()
}

fn map_collision_callback_invocations(
    values: &[(&str, &str, &str)],
) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|(left, right, result)| {
            let left = format!("{{\"type\":\"Int\",\"value\":\"{left}\"}}");
            let right = format!("{{\"type\":\"Int\",\"value\":\"{right}\"}}");
            let result = format!("{{\"type\":\"Int\",\"value\":\"{result}\"}}");
            callback_contract_invocation(0, "collision", &[&left, &right], &result)
        })
        .collect()
}

fn fold_callback_invocations(values: &[(&str, &str, &str)]) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|(accumulator, item, result)| {
            let accumulator = format!("{{\"type\":\"Int\",\"value\":\"{accumulator}\"}}");
            let item = format!("{{\"type\":\"Int\",\"value\":\"{item}\"}}");
            let result = format!("{{\"type\":\"Int\",\"value\":\"{result}\"}}");
            callback_contract_invocation(0, "fold", &[&accumulator, &item], &result)
        })
        .collect()
}

fn scan_callback_invocations(values: &[(&str, &str, &str)]) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|(left, right, result)| {
            let left = format!("{{\"type\":\"Int\",\"value\":\"{left}\"}}");
            let right = format!("{{\"type\":\"Int\",\"value\":\"{right}\"}}");
            let result = format!("{{\"type\":\"Int\",\"value\":\"{result}\"}}");
            callback_contract_invocation(0, "scan", &[&left, &right], &result)
        })
        .collect()
}

fn duplicated_list_callback_invocations(values: &[i64]) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|value| {
            let argument = format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
            let result = format!(
                "{{\"type\":\"List\",\"elements\":[{argument},{argument}],\"terminationHex\":\"6e696c\"}}"
            );
            callback_contract_invocation(0, "element", &[&argument], &result)
        })
        .collect()
}

fn relation_callback_invocations(values: &[(&str, &str, bool)]) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|(needle, item, result)| {
            let needle = format!("{{\"type\":\"Int\",\"value\":\"{needle}\"}}");
            let item = format!("{{\"type\":\"Int\",\"value\":\"{item}\"}}");
            let result = format!("{{\"type\":\"Bool\",\"value\":{result}}}");
            callback_contract_invocation(0, "relation", &[&needle, &item], &result)
        })
        .collect()
}

fn key_callback_invocations(values: &[i64]) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|value| {
            let value = format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
            callback_contract_invocation(0, "key", &[&value], &value)
        })
        .collect()
}

fn map_accum_callback_invocations(
    values: &[(&str, &str, &str, &str)],
) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|(accumulator, item, next, output)| {
            let accumulator =
                format!("{{\"type\":\"Int\",\"value\":\"{accumulator}\"}}");
            let item = format!("{{\"type\":\"Int\",\"value\":\"{item}\"}}");
            let result = format!(
                "{{\"type\":\"Tuple\",\"elements\":[{{\"type\":\"Int\",\"value\":\"{next}\"}},{{\"type\":\"Int\",\"value\":\"{output}\"}}]}}"
            );
            callback_contract_invocation(0, "accumulate", &[&accumulator, &item], &result)
        })
        .collect()
}

fn character_predicate_invocations(values: &[(char, bool)]) -> Vec<CallbackInvocationContract> {
    values
        .iter()
        .map(|(value, result)| {
            let argument = format!(
                "{{\"type\":\"Character\",\"codePoint\":{}}}",
                u32::from(*value)
            );
            let result = format!("{{\"type\":\"Bool\",\"value\":{result}}}");
            callback_contract_invocation(0, "predicate", &[&argument], &result)
        })
        .collect()
}

fn map_key_value_predicate_invocation(
    key: i64,
    value: i64,
    result: bool,
) -> CallbackInvocationContract {
    let key = format!("{{\"type\":\"Int\",\"value\":\"{key}\"}}");
    let value = format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let result = format!("{{\"type\":\"Bool\",\"value\":{result}}}");
    callback_contract_invocation(0, "predicate", &[&key, &value], &result)
}

fn map_key_unused_value_predicate_invocation(key: i64, result: bool) -> CallbackInvocationContract {
    let key = format!("{{\"type\":\"Int\",\"value\":\"{key}\"}}");
    let unforced = "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}";
    let result = format!("{{\"type\":\"Bool\",\"value\":{result}}}");
    callback_contract_invocation(0, "predicate", &[&key, unforced], &result)
}

fn callback_contract_invocation(
    callback_argument: u16,
    branch: &str,
    canonical_arguments: &[&str],
    canonical_result: &str,
) -> CallbackInvocationContract {
    CallbackInvocationContract {
        callback_argument,
        branch: Arc::from(branch),
        canonical_argument_sha256: canonical_arguments
            .iter()
            .map(|argument| sha256_bytes(argument.as_bytes()))
            .collect(),
        outcome: Arc::from("value"),
        canonical_result_sha256: sha256_bytes(canonical_result.as_bytes()),
    }
}

fn callback_digest(value: &str) -> Digest {
    Digest::from_hex(value).expect("callback digest fixture is canonical")
}

fn runtime_interaction_cases() -> Vec<DifferentialCase> {
    runtime_interaction_definitions()
        .into_iter()
        .map(
            |(interaction, builtins, source, arguments, environment_profile)| DifferentialCase {
                id: Arc::from(format!("runtime-interaction-{interaction}")),
                source: Arc::from(source),
                arguments,
                environment_profile,
                expected_runtime_completion: interaction != "list-laziness-error",
                claim_evidence: Some(runtime_interaction_descriptor(
                    interaction,
                    builtins,
                    source,
                )),
                ..DifferentialCase::default()
            },
        )
        .collect()
}

type RuntimeInteractionDefinition = (
    &'static str,
    &'static [&'static str],
    &'static str,
    Vec<OsString>,
    EnvironmentProfile,
);

fn runtime_interaction_definitions() -> Vec<RuntimeInteractionDefinition> {
    let mut definitions = vec![
        (
            "list-laziness-error",
            &["List.take", "Error.error"][..],
            "main = IO.print $ List.take 2 $ List.cons 1 (Error.error \"interaction-bottom\" :: [Int])\n",
            Vec::new(),
            EnvironmentProfile::Explicit,
        ),
        (
            "map-ordering-custom-ord",
            &["Map.fromList", "Ord.lt", "Ord.gt"][..],
            "main = IO.print $ Map.toList $ Map.fromList [(2,\"b\"),(1,\"a\")]\n",
            Vec::new(),
            EnvironmentProfile::Explicit,
        ),
        (
            "options-platform-argv",
            &["Options.execParser", "Environment.getArgs"][..],
            concat!(
                "parser = Options.strArgument (Argument.metavar \"ITEM\")\n",
                "main = do\n",
                "  platformArgs <- Environment.getArgs\n",
                "  parsed <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
                "  IO.print (platformArgs, parsed)\n",
            ),
            vec!["interaction-argument".into()],
            EnvironmentProfile::Explicit,
        ),
        (
            "json-number-presentation",
            &["Json.Number", "Json.encode", "Double.show"][..],
            concat!(
                "main = do\n",
                "  ByteString.hPutStr IO.stdout $ Json.encode $ Json.Number 42.5\n",
                "  Text.putStrLn \"\"\n",
                "  Text.putStrLn $ Double.show 42.5\n",
            ),
            Vec::new(),
            EnvironmentProfile::Explicit,
        ),
        (
            "race-temporary-resource",
            &["Async.race", "Temp.withSystemTempFile"][..],
            concat!(
                "main = Temp.withSystemTempFile \"hell-runtime-interaction\" \\_path handle -> do\n",
                "  Text.hPutStr handle \"retained-before-cancel\"\n",
                "  _result <- Async.race (Concurrent.threadDelay 1000000) (IO.pure ())\n",
                "  IO.pure ()\n",
            ),
            Vec::new(),
            EnvironmentProfile::Explicit,
        ),
    ];
    definitions.extend(runtime_process_interaction_definitions());
    definitions
}

fn runtime_process_interaction_definitions() -> Vec<RuntimeInteractionDefinition> {
    vec![
        (
            "timeout-process",
            &["Timeout.timeout", "Process.runProcess_"][..],
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper -> do\n",
                "    _result <- Timeout.timeout 100000 $ Process.runProcess_ $\n",
                "      Process.proc helper [\"sleep-ms\",\"30000\"]\n",
                "    IO.pure ()\n",
            ),
            vec!["hell-test-helper".into()],
            EnvironmentProfile::ProcessCapable,
        ),
        (
            "text-decode-process-capture",
            &["Text.decodeUtf8", "ByteString.readProcess_"][..],
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper -> do\n",
                "    (stdout, _stderr) <- ByteString.readProcess_ $\n",
                "      Process.proc helper [\"emit\",\"--stdout-bytes\",\"4\",\"--stderr-bytes\",\"0\"]\n",
                "    Text.putStrLn $ Text.decodeUtf8 stdout\n",
            ),
            vec!["hell-test-helper".into()],
            EnvironmentProfile::ProcessCapable,
        ),
        (
            "cwd-child-process",
            &["Process.setWorkingDir", "Process.runProcess_"][..],
            concat!(
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Directory.createDirectory \"interaction-cwd\"\n",
                "  Monad.forM_ helpers \\helper ->\n",
                "    Process.runProcess_ $ Process.setWorkingDir \"interaction-cwd\" $\n",
                "      Process.proc helper [\"assert-current-dir-name\",\"interaction-cwd\"]\n",
            ),
            vec!["hell-test-helper".into()],
            EnvironmentProfile::ProcessCapable,
        ),
        (
            "http-stream-disconnect",
            &["Http.responseStream", "Http.run"][..],
            concat!(
                "server = \\port -> Http.run port \\_request respond ->\n",
                "  respond $ Http.responseStream (Http.mkStatus 200 \"OK\") []\n",
                "    (\\write _flush -> IO.mapM_ write $ List.take 65536 $ List.repeat $\n",
                "      Builder.byteString $ Text.encodeUtf8 $ Text.pack $\n",
                "        List.take 1024 $ List.repeat 'x')\n",
                "client = \\helper -> \\port -> Process.runProcess_ $\n",
                "  Process.proc helper [\"disconnect-http-stream\", Int.show port]\n",
                "main = do\n",
                "  helpers <- Environment.getArgs\n",
                "  Monad.forM_ helpers \\helper -> do\n",
                "    portText <- Text.readProcessStdout_ $\n",
                "      Process.proc helper [\"available-http-port\"]\n",
                "    let port = Maybe.maybe (Error.error \"invalid helper port\") Function.id $\n",
                "          Int.readMaybe $ Text.strip portText\n",
                "    _result <- Async.race (Main.server port) (Main.client helper port)\n",
                "    IO.pure ()\n",
            ),
            vec!["hell-test-helper".into()],
            EnvironmentProfile::ProcessCapable,
        ),
    ]
}

fn runtime_interaction_descriptor(
    interaction: &str,
    builtins: &[&str],
    source: &str,
) -> ClaimEvidenceDescriptor {
    let cells = builtins
        .iter()
        .flat_map(|builtin| {
            crate::runtime_obligation_cells_for_spec(
                hell_builtins::lookup(builtin).expect("interaction builtin is registry-backed"),
            )
        })
        .filter(|cell| cell.dimension == hell_builtins::CompatibilityDimension::PureRuntime)
        .map(|mut cell| {
            if interaction == "list-laziness-error" && cell.builtin.as_ref() == "List.take" {
                cell.obligations
                    .retain(|obligation| obligation.0.as_ref() == "lazy-boundary");
            }
            if interaction == "http-stream-disconnect" {
                cell.obligations.retain(|obligation| {
                    matches!(
                        (cell.builtin.as_ref(), obligation.0.as_ref()),
                        ("Http.run", "adapter-success" | "io-execution-boundary")
                            | ("Http.responseStream", "adapter-success" | "lazy-boundary")
                    )
                });
            }
            cell
        })
        .collect::<Vec<_>>();
    ClaimEvidenceDescriptor {
        schema_version: 8,
        profile: ExecutionProfile::Upstream,
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        targets: cells
            .iter()
            .map(|cell| EvidenceTarget::new(Arc::clone(&cell.builtin), cell.dimension))
            .collect(),
        semantic_targets: cells
            .into_iter()
            .filter_map(|cell| {
                if interaction == "map-ordering-custom-ord"
                    && cell.dimension != hell_builtins::CompatibilityDimension::PureRuntime
                {
                    return None;
                }
                let mut target = EvidenceTargetV2::new(
                    cell.builtin,
                    cell.dimension,
                    cell.obligations,
                    cell.causal_signal,
                    cell.platforms,
                );
                target
                    .obligations
                    .retain(|obligation| obligation.0.as_ref() != "typed-result");
                if interaction == "map-ordering-custom-ord" {
                    configure_map_ordering_interaction_target(&mut target, cell.dimension);
                }
                if target.builtin.as_ref() == "Text.decodeUtf8" {
                    target
                        .obligations
                        .retain(|obligation| obligation.0.as_ref() != "adapter-failure");
                }
                if matches!(
                    target.builtin.as_ref(),
                    "Process.runProcess"
                        | "Process.runProcess_"
                        | "Async.race"
                        | "Async.concurrently"
                ) {
                    target
                        .obligations
                        .retain(|obligation| obligation.0.as_ref() != "adapter-failure");
                }
                if cell.dimension == hell_builtins::CompatibilityDimension::PureRuntime {
                    Some(target.with_runtime_scope(std::iter::empty::<&str>(), [interaction]))
                } else {
                    Some(target)
                }
            })
            .collect(),
        callback_contracts: Vec::new(),
        review_state: CaseReviewState::Reviewed,
        review_statement: Arc::from("runtime-interaction-observation-review-v1"),
        source_sha256: sha256_bytes(source.as_bytes()),
    }
}

fn configure_map_ordering_interaction_target(
    target: &mut EvidenceTargetV2,
    dimension: hell_builtins::CompatibilityDimension,
) {
    target.obligations = vec![ObligationId(Arc::from("adapter-success"))];
    target.causal_signal = CausalSignal::RuntimeAdapter;
    target.expected_instance_target = Some(Arc::from("Int"));
    if target.builtin.as_ref() == "Ord.gt"
        && dimension == hell_builtins::CompatibilityDimension::PureRuntime
    {
        target
            .obligations
            .push(ObligationId(Arc::from("typed-result")));
        let canonical = "{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{\"type\":\"Bool\",\"value\":true}}";
        target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    }
    if target.builtin.as_ref() == "Map.fromList"
        && dimension == hell_builtins::CompatibilityDimension::PureRuntime
    {
        target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(
            b"[(1,\"a\"),(2,\"b\")]\n",
            b"",
        ));
        let records = [
            reviewed_comparator_contract(1, "Ord.gt", &eq_list_int(2), &eq_list_int(1), true),
            reviewed_comparator_contract(2, "Ord.lt", &eq_list_int(1), &eq_list_int(2), true),
        ];
        target.expected_comparator_trace_sha256 = Some(crate::comparator_trace_sha256(
            "Map.fromList",
            1,
            "Int",
            &[],
            &records,
        ));
    }
}

fn list_take_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "negative-count",
            "main = IO.print $ List.take (Int.subtract 0 1) [1,2]\n",
        ),
        ("zero-count", "main = IO.print $ List.take 0 [1,2]\n"),
        (
            "below-finite-length",
            "main = IO.print $ List.take 2 [1,2,3]\n",
        ),
        (
            "equal-finite-length",
            "main = IO.print $ List.take 3 [1,2,3]\n",
        ),
        (
            "above-finite-length",
            "main = IO.print $ List.take 4 [1,2,3]\n",
        ),
        (
            "infinite-source",
            "main = IO.print $ List.take 3 $ List.iterate' (Int.plus 1) 0\n",
        ),
        (
            "bottom-source-zero-count",
            "main = IO.print $ List.take 0 (Error.error \"unused-list-bottom\" :: [Int])\n",
        ),
        (
            "bottom-after-demanded-prefix",
            "main = IO.print $ List.take 2 $ List.cons 1 (Error.error \"demanded-list-bottom\" :: [Int])\n",
        ),
    ]
    .into_iter()
    .map(|(boundary, source)| DifferentialCase {
        id: Arc::from(format!("list-take-boundary-{boundary}")),
        source: Arc::from(source),
        expected_runtime_completion: boundary != "bottom-after-demanded-prefix",
        claim_evidence: Some(runtime_builtin_boundary_descriptor(
            "List.take",
            boundary,
            source,
        )),
        ..DifferentialCase::default()
    })
    .collect()
}

fn runtime_list_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = Vec::new();
    push_runtime_boundary_cases(
        &mut cases,
        "List.map",
        [
            (
                "empty-input",
                "main = IO.print $ List.map (Int.plus 1) []\n",
                Vec::new(),
            ),
            (
                "singleton-input",
                "main = IO.print $ List.map (Int.plus 1) [1]\n",
                vec![callback_contract_invocation(
                    0,
                    "element",
                    &["{\"type\":\"Int\",\"value\":\"1\"}"],
                    "{\"type\":\"Int\",\"value\":\"2\"}",
                )],
            ),
            (
                "finite-input",
                "main = IO.print $ List.map (Int.plus 1) [1,2]\n",
                list_callback_invocations("List.map").expect("List.map callback contract"),
            ),
        ],
    );
    let list_all_start = cases.len();
    push_runtime_boundary_cases(
        &mut cases,
        "List.all",
        [
            (
                "empty-input",
                "main = IO.print $ List.all (Int.eq 1) []\n",
                Vec::new(),
            ),
            (
                "singleton-input",
                "main = IO.print $ List.all (Int.eq 1) [1]\n",
                predicate_invocations(&[("1", true)]),
            ),
            (
                "finite-input",
                "main = IO.print $ List.all (\\x -> Bool.not $ Int.eq x 0) [1,0,2]\n",
                predicate_invocations(&[("1", true), ("0", false)]),
            ),
        ],
    );
    bind_boolean_boundary_expectations(&mut cases[list_all_start..], [true, true, false]);
    push_runtime_boundary_cases(
        &mut cases,
        "List.any",
        [
            (
                "empty-input",
                "main = IO.print $ List.any (Int.eq 2) []\n",
                Vec::new(),
            ),
            (
                "singleton-input",
                "main = IO.print $ List.any (Int.eq 2) [2]\n",
                predicate_invocations(&[("2", true)]),
            ),
            (
                "finite-input",
                "main = IO.print $ List.any (Int.eq 2) [0,2]\n",
                predicate_invocations(&[("0", false), ("2", true)]),
            ),
        ],
    );
    push_runtime_boundary_cases(
        &mut cases,
        "List.find",
        [
            (
                "empty-input",
                "main = IO.print $ List.find (Int.eq 2) []\n",
                Vec::new(),
            ),
            (
                "singleton-input",
                "main = IO.print $ List.find (Int.eq 2) [2]\n",
                predicate_invocations(&[("2", true)]),
            ),
            (
                "finite-input",
                "main = IO.print $ List.find (Int.eq 2) [1,2]\n",
                predicate_invocations(&[("1", false), ("2", true)]),
            ),
        ],
    );
    cases.extend(runtime_remaining_list_boundary_cases());
    cases
}

fn runtime_cycle_boundary_cases() -> Vec<DifferentialCase> {
    const EMPTY_STDERR: &[u8] = concat!(
        "hell: Prelude.cycle: empty list\n",
        "CallStack (from HasCallStack):\n",
        "  error, called at libraries/base/GHC/List.hs:2004:3 in base:GHC.List\n",
        "  errorEmptyList, called at libraries/base/GHC/List.hs:972:27 in base:GHC.List\n",
        "  cycle, called at src/Hell.hs:1953:4 in main:Main\n",
    )
    .as_bytes();
    [
        (
            "empty-input",
            "main = IO.print $ List.take 1 $ List.cycle ([] :: [Int])\n",
            Some("{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"H0901\"}"),
        ),
        (
            "singleton-input",
            "main = IO.print $ List.take 3 $ List.cycle [7]\n",
            Some(
                "{\"type\":\"List\",\"elements\":[{\"type\":\"Int\",\"value\":\"7\"},{\"type\":\"Int\",\"value\":\"7\"},{\"type\":\"Int\",\"value\":\"7\"}],\"terminationHex\":\"6e6f742d666f72636564\"}",
            ),
        ),
        (
            "finite-input",
            "main = IO.print $ List.take 5 $ List.cycle [1,2]\n",
            Some(
                "{\"type\":\"List\",\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},{\"type\":\"Int\",\"value\":\"2\"},{\"type\":\"Int\",\"value\":\"1\"},{\"type\":\"Int\",\"value\":\"2\"},{\"type\":\"Int\",\"value\":\"1\"}],\"terminationHex\":\"6e6f742d666f72636564\"}",
            ),
        ),
    ]
    .into_iter()
    .map(|(boundary, source, expected)| {
        let mut descriptor = expected.map_or_else(
            || runtime_builtin_boundary_descriptor("List.cycle", boundary, source),
            |expected| {
                runtime_expected_boundary_descriptor("List.cycle", boundary, source, expected)
            },
        );
        let empty = boundary == "empty-input";
        if empty {
            let target = descriptor
                .semantic_targets
                .first_mut()
                .expect("List.cycle empty boundary target");
            target.expected_process_status_sha256 =
                Some(crate::process_status_sha256(false, Some(1)));
            target.expected_raw_presentation_sha256 =
                Some(crate::raw_presentation_sha256(b"", EMPTY_STDERR));
        } else {
            descriptor.semantic_targets[0]
                .obligations
                .retain(|obligation| obligation.0.as_ref() != "result-force-failure");
        }
        DifferentialCase {
            id: Arc::from(format!("list-cycle-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            expected_runtime_completion: !empty,
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_zip_with_boundary_cases() -> Vec<DifferentialCase> {
    let definitions = [
        (
            "empty-input",
            "main = IO.print $ List.zipWith Int.plus ([] :: [Int]) ([] :: [Int])\n",
            Vec::new(),
            "{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}",
        ),
        (
            "singleton-input",
            "main = IO.print $ List.zipWith Int.plus [1] [3]\n",
            vec![callback_contract_invocation(
                0,
                "element",
                &[
                    "{\"type\":\"Int\",\"value\":\"1\"}",
                    "{\"type\":\"Int\",\"value\":\"3\"}",
                ],
                "{\"type\":\"Int\",\"value\":\"4\"}",
            )],
            "{\"type\":\"List\",\"elements\":[{\"type\":\"Int\",\"value\":\"4\"}],\"terminationHex\":\"6e696c\"}",
        ),
        (
            "finite-input",
            "main = IO.print $ List.zipWith Int.plus [1,2] [3,4]\n",
            vec![
                callback_contract_invocation(
                    0,
                    "element",
                    &[
                        "{\"type\":\"Int\",\"value\":\"1\"}",
                        "{\"type\":\"Int\",\"value\":\"3\"}",
                    ],
                    "{\"type\":\"Int\",\"value\":\"4\"}",
                ),
                callback_contract_invocation(
                    0,
                    "element",
                    &[
                        "{\"type\":\"Int\",\"value\":\"2\"}",
                        "{\"type\":\"Int\",\"value\":\"4\"}",
                    ],
                    "{\"type\":\"Int\",\"value\":\"6\"}",
                ),
            ],
            "{\"type\":\"List\",\"elements\":[{\"type\":\"Int\",\"value\":\"4\"},{\"type\":\"Int\",\"value\":\"6\"}],\"terminationHex\":\"6e696c\"}",
        ),
    ];
    definitions
        .into_iter()
        .map(|(boundary, source, invocations, expected)| {
            let mut descriptor =
                runtime_boundary_descriptor("List.zipWith", boundary, source, invocations);
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{expected}}}"
            );
            descriptor.semantic_targets[0].expected_typed_result_sha256 =
                Some(sha256_bytes(canonical.as_bytes()));
            DifferentialCase {
                id: Arc::from(format!("list-zipwith-boundary-{boundary}")),
                source: Arc::from(source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_concat_map_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print $ List.concatMap (\\item -> [item,item]) ([] :: [Int])\n",
            Vec::new(),
            Vec::new(),
        ),
        (
            "singleton-input",
            "main = IO.print $ List.concatMap (\\item -> [item,item]) [1]\n",
            duplicated_list_callback_invocations(&[1]),
            vec![1, 1],
        ),
        (
            "finite-input",
            "main = IO.print $ List.concatMap (\\item -> [item,item]) [1,2]\n",
            duplicated_list_callback_invocations(&[1, 2]),
            vec![1, 1, 2, 2],
        ),
    ]
    .into_iter()
    .map(|(boundary, source, invocations, expected)| {
        let mut descriptor =
            runtime_boundary_descriptor("List.concatMap", boundary, source, invocations);
        let elements = expected
            .into_iter()
            .map(|value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"List\",\"elements\":[{elements}],\"terminationHex\":\"6e696c\"}}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!("list-concatmap-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_delete_by_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print $ List.deleteBy (\\needle item -> Ord.lt needle item) 1 ([] :: [Int])\n",
            Vec::new(),
            Vec::new(),
        ),
        (
            "singleton-input",
            "main = IO.print $ List.deleteBy (\\needle item -> Ord.lt needle item) 1 [2]\n",
            relation_callback_invocations(&[("1", "2", true)]),
            Vec::new(),
        ),
        (
            "finite-input",
            "main = IO.print $ List.deleteBy (\\needle item -> Ord.lt needle item) 1 [1,2,3]\n",
            relation_callback_invocations(&[("1", "1", false), ("1", "2", true)]),
            vec![1, 3],
        ),
    ]
    .into_iter()
    .map(|(boundary, source, invocations, expected)| {
        let mut descriptor =
            runtime_boundary_descriptor("List.deleteBy", boundary, source, invocations);
        let elements = expected
            .into_iter()
            .map(|value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"List\",\"elements\":[{elements}],\"terminationHex\":\"6e696c\"}}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!("list-deleteby-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_drop_while_end_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print $ List.dropWhileEnd (\\item -> Ord.lt 1 item) ([] :: [Int])\n",
            Vec::new(),
            Vec::new(),
        ),
        (
            "singleton-input",
            "main = IO.print $ List.dropWhileEnd (\\item -> Ord.lt 1 item) [2]\n",
            predicate_invocations(&[("2", true)]),
            Vec::new(),
        ),
        (
            "finite-input",
            "main = IO.print $ List.dropWhileEnd (\\item -> Ord.lt 1 item) [1,2,3]\n",
            predicate_invocations(&[("1", false), ("2", true), ("3", true)]),
            vec![1],
        ),
    ]
    .into_iter()
    .map(|(boundary, source, invocations, expected)| {
        let mut descriptor =
            runtime_boundary_descriptor("List.dropWhileEnd", boundary, source, invocations);
        let elements = expected
            .into_iter()
            .map(|value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"List\",\"elements\":[{elements}],\"terminationHex\":\"6e696c\"}}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!("list-dropwhileend-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_sort_on_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print $ List.sortOn Function.id ([] :: [Int])\n",
            Vec::new(),
            Vec::new(),
        ),
        (
            "singleton-input",
            "main = IO.print $ List.sortOn Function.id [2]\n",
            Vec::new(),
            vec![2],
        ),
        (
            "finite-input",
            "main = IO.print $ List.sortOn Function.id [2,1,3]\n",
            key_callback_invocations(&[2, 1, 3]),
            vec![1, 2, 3],
        ),
    ]
    .into_iter()
    .map(|(boundary, source, invocations, expected)| {
        let mut descriptor =
            runtime_boundary_descriptor("List.sortOn", boundary, source, invocations);
        let elements = expected
            .into_iter()
            .map(|value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"List\",\"elements\":[{elements}],\"terminationHex\":\"6e696c\"}}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!("list-sorton-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_group_by_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print $ List.groupBy Int.eq ([] :: [Int])\n",
            Vec::new(),
            Vec::<Vec<i64>>::new(),
        ),
        (
            "singleton-input",
            "main = IO.print $ List.groupBy Int.eq [1]\n",
            Vec::new(),
            vec![vec![1]],
        ),
        (
            "finite-input",
            "main = IO.print $ List.groupBy Int.eq [1,1,2,2]\n",
            relation_callback_invocations(&[
                ("1", "1", true),
                ("1", "2", false),
                ("2", "2", true),
            ]),
            vec![vec![1, 1], vec![2, 2]],
        ),
    ]
    .into_iter()
    .map(|(boundary, source, invocations, expected)| {
        let mut descriptor =
            runtime_boundary_descriptor("List.groupBy", boundary, source, invocations);
        let groups = expected
            .into_iter()
            .map(|group| {
                let elements = group
                    .into_iter()
                    .map(|value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}"))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "{{\"type\":\"List\",\"elements\":[{elements}],\"terminationHex\":\"6e696c\"}}"
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"List\",\"elements\":[{groups}],\"terminationHex\":\"6e696c\"}}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!("list-groupby-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_foldl_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print $ List.foldl' Int.plus 0 ([] :: [Int])\n",
            Vec::new(),
            0,
        ),
        (
            "singleton-input",
            "main = IO.print $ List.foldl' Int.plus 0 [1]\n",
            fold_callback_invocations(&[("0", "1", "1")]),
            1,
        ),
        (
            "finite-input",
            "main = IO.print $ List.foldl' Int.plus 0 [1,2]\n",
            fold_callback_invocations(&[("0", "1", "1"), ("1", "2", "3")]),
            3,
        ),
    ]
    .into_iter()
    .map(|(boundary, source, invocations, expected)| {
        let mut descriptor =
            runtime_boundary_descriptor("List.foldl'", boundary, source, invocations);
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Int\",\"value\":\"{expected}\"}}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!("list-foldl-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_foldr_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print $ List.foldr Int.plus 0 ([] :: [Int])\n",
            Vec::new(),
            0,
        ),
        (
            "singleton-input",
            "main = IO.print $ List.foldr Int.plus 0 [1]\n",
            fold_callback_invocations(&[("1", "0", "1")]),
            1,
        ),
        (
            "finite-input",
            "main = IO.print $ List.foldr Int.plus 0 [1,2]\n",
            fold_callback_invocations(&[("1", "2", "3"), ("2", "0", "2")]),
            3,
        ),
    ]
    .into_iter()
    .map(|(boundary, source, invocations, expected)| {
        let mut descriptor =
            runtime_boundary_descriptor("List.foldr", boundary, source, invocations);
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Int\",\"value\":\"{expected}\"}}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        DifferentialCase {
            id: Arc::from(format!("list-foldr-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_scan_boundary_cases() -> Vec<DifferentialCase> {
    struct Definition {
        builtin: &'static str,
        boundary: &'static str,
        source: &'static str,
        invocations: Vec<CallbackInvocationContract>,
        expected: &'static [i64],
    }
    let definitions = [
        Definition {
            builtin: "List.scanl'",
            boundary: "empty-input",
            source: "main = IO.print $ List.scanl' Int.plus 0 ([] :: [Int])\n",
            invocations: Vec::new(),
            expected: &[0],
        },
        Definition {
            builtin: "List.scanl'",
            boundary: "singleton-input",
            source: "main = IO.print $ List.scanl' Int.plus 0 [1]\n",
            invocations: scan_callback_invocations(&[("0", "1", "1")]),
            expected: &[0, 1],
        },
        Definition {
            builtin: "List.scanl'",
            boundary: "finite-input",
            source: "main = IO.print $ List.scanl' Int.plus 0 [1,2]\n",
            invocations: scan_callback_invocations(&[("0", "1", "1"), ("1", "2", "3")]),
            expected: &[0, 1, 3],
        },
        Definition {
            builtin: "List.scanr",
            boundary: "empty-input",
            source: "main = IO.print $ List.scanr Int.plus 0 ([] :: [Int])\n",
            invocations: Vec::new(),
            expected: &[0],
        },
        Definition {
            builtin: "List.scanr",
            boundary: "singleton-input",
            source: "main = IO.print $ List.scanr Int.plus 0 [1]\n",
            invocations: scan_callback_invocations(&[("1", "0", "1")]),
            expected: &[1, 0],
        },
        Definition {
            builtin: "List.scanr",
            boundary: "finite-input",
            source: "main = IO.print $ List.scanr Int.plus 0 [1,2]\n",
            invocations: scan_callback_invocations(&[("1", "2", "3"), ("2", "0", "2")]),
            expected: &[3, 2, 0],
        },
    ];
    definitions
        .into_iter()
        .map(|definition| {
            let mut descriptor = runtime_boundary_descriptor(
                definition.builtin,
                definition.boundary,
                definition.source,
                definition.invocations,
            );
            let elements = definition
                .expected
                .iter()
                .map(|value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}"))
                .collect::<Vec<_>>()
                .join(",");
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"List\",\"elements\":[{elements}],\"terminationHex\":\"6e696c\"}}}}"
            );
            descriptor.semantic_targets[0].expected_typed_result_sha256 =
                Some(sha256_bytes(canonical.as_bytes()));
            let builtin_case = definition
                .builtin
                .to_ascii_lowercase()
                .replace('.', "-")
                .replace('\'', "");
            DifferentialCase {
                id: Arc::from(format!(
                    "{builtin_case}-boundary-{}",
                    definition.boundary
                )),
                source: Arc::from(definition.source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_map_accum_boundary_cases() -> Vec<DifferentialCase> {
    ["List.mapAccumL", "List.mapAccumR"]
        .into_iter()
        .flat_map(runtime_map_accum_builtin_boundary_cases)
        .collect()
}

fn runtime_map_accum_builtin_boundary_cases(builtin: &str) -> Vec<DifferentialCase> {
    let definitions = [
        (
            "empty-input",
            Vec::new(),
            0,
            Vec::new(),
            format!(
                "main = IO.print $ {builtin} (\\acc item -> (Int.plus acc item, acc)) 0 ([] :: [Int])\n"
            ),
        ),
        (
            "singleton-input",
            map_accum_callback_invocations(&[("0", "1", "1", "0")]),
            1,
            vec![0],
            format!("main = IO.print $ {builtin} (\\acc item -> (Int.plus acc item, acc)) 0 [1]\n"),
        ),
        (
            "finite-input",
            map_accum_callback_invocations(&[("0", "1", "1", "0"), ("1", "2", "3", "1")]),
            3,
            vec![0, 1],
            format!(
                "main = IO.print $ {builtin} (\\acc item -> (Int.plus acc item, acc)) 0 [1,2]\n"
            ),
        ),
    ];
    definitions
        .into_iter()
        .map(|(boundary, invocations, accumulator, outputs, source)| {
            let mut descriptor =
                runtime_boundary_descriptor(builtin, boundary, &source, invocations);
            let outputs = outputs
                .into_iter()
                .map(|value| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}"))
                .collect::<Vec<_>>()
                .join(",");
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Tuple\",\"elements\":[{{\"type\":\"Int\",\"value\":\"{accumulator}\"}},{{\"type\":\"List\",\"elements\":[{outputs}],\"terminationHex\":\"6e696c\"}}]}}}}"
            );
            descriptor.semantic_targets[0].expected_typed_result_sha256 =
                Some(sha256_bytes(canonical.as_bytes()));
            let builtin_case = builtin.to_ascii_lowercase().replace('.', "-");
            DifferentialCase {
                id: Arc::from(format!("{builtin_case}-boundary-{boundary}")),
                source: Arc::from(source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_int_plus_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "negative-value",
            "main = IO.print $ Int.plus (Int.subtract 2 0) 1\n",
        ),
        ("zero-value", "main = IO.print $ Int.plus 0 0\n"),
        ("positive-value", "main = IO.print $ Int.plus 1 2\n"),
        (
            "minimum-value",
            "main = IO.print $ Int.plus (Int.subtract 9223372036854775807 (Int.subtract 1 0)) 0\n",
        ),
        (
            "maximum-value",
            "main = IO.print $ Int.plus 9223372036854775807 0\n",
        ),
        (
            "overflow",
            "main = IO.print $ Int.plus 9223372036854775807 1\n",
        ),
    ]
    .into_iter()
    .map(|(boundary, source)| DifferentialCase {
        id: Arc::from(format!("int-plus-boundary-{boundary}")),
        source: Arc::from(source),
        claim_evidence: Some(runtime_builtin_boundary_descriptor(
            "Int.plus", boundary, source,
        )),
        ..DifferentialCase::default()
    })
    .collect()
}

const RUNTIME_ADDITIONAL_INT_BOUNDARIES: &[(&str, [(&str, &str); 6])] = &[
    (
        "Int.subtract",
        [
            ("negative-value", "main = IO.print $ Int.subtract 1 0\n"),
            ("zero-value", "main = IO.print $ Int.subtract 0 0\n"),
            ("positive-value", "main = IO.print $ Int.subtract 0 1\n"),
            (
                "minimum-value",
                "main = IO.print $ Int.subtract 9223372036854775807 (Int.plus (Int.plus 9223372036854775807 9223372036854775807) 1)\n",
            ),
            (
                "maximum-value",
                "main = IO.print $ Int.subtract 0 9223372036854775807\n",
            ),
            (
                "overflow",
                "main = IO.print $ Int.subtract (Int.plus (Int.plus 9223372036854775807 9223372036854775807) 1) 9223372036854775807\n",
            ),
        ],
    ),
    (
        "Int.mult",
        [
            (
                "negative-value",
                "main = IO.print $ Int.mult (Int.subtract 1 0) 2\n",
            ),
            ("zero-value", "main = IO.print $ Int.mult 0 2\n"),
            ("positive-value", "main = IO.print $ Int.mult 2 3\n"),
            (
                "minimum-value",
                "main = IO.print $ Int.mult (Int.plus 9223372036854775807 1) 1\n",
            ),
            (
                "maximum-value",
                "main = IO.print $ Int.mult 9223372036854775807 1\n",
            ),
            (
                "overflow",
                "main = IO.print $ Int.mult 9223372036854775807 2\n",
            ),
        ],
    ),
];

fn runtime_additional_int_boundary_cases() -> Vec<DifferentialCase> {
    RUNTIME_ADDITIONAL_INT_BOUNDARIES
        .iter()
        .flat_map(|(builtin, definitions)| {
            definitions
                .iter()
                .map(move |(boundary, source)| DifferentialCase {
                    id: Arc::from(format!(
                        "{}-boundary-{boundary}",
                        builtin.to_ascii_lowercase().replace('.', "-")
                    )),
                    source: Arc::from(*source),
                    claim_evidence: Some(runtime_builtin_boundary_descriptor(
                        builtin, boundary, source,
                    )),
                    ..DifferentialCase::default()
                })
        })
        .collect()
}

const INT_SHOW_BOUNDARIES: [(&str, &str); 5] = [
    (
        "negative-value",
        "main = IO.print $ Int.show $ Int.subtract 1 0\n",
    ),
    ("zero-value", "main = IO.print $ Int.show 0\n"),
    ("positive-value", "main = IO.print $ Int.show 1\n"),
    (
        "minimum-value",
        "main = IO.print $ Int.show $ Int.plus 9223372036854775807 1\n",
    ),
    (
        "maximum-value",
        "main = IO.print $ Int.show 9223372036854775807\n",
    ),
];

const INT_TO_INTEGER_BOUNDARIES: [(&str, &str); 5] = [
    (
        "negative-value",
        "main = IO.print $ Int.toInteger $ Int.subtract 1 0\n",
    ),
    ("zero-value", "main = IO.print $ Int.toInteger 0\n"),
    ("positive-value", "main = IO.print $ Int.toInteger 1\n"),
    (
        "minimum-value",
        "main = IO.print $ Int.toInteger $ Int.plus 9223372036854775807 1\n",
    ),
    (
        "maximum-value",
        "main = IO.print $ Int.toInteger 9223372036854775807\n",
    ),
];

const RUNTIME_INT_CONVERSION_BOUNDARIES: &[(&str, &[(&str, &str)])] = &[
    (
        "Int.eq",
        &[
            (
                "negative-value",
                "main = IO.print $ Int.eq (Int.subtract 1 0) 0\n",
            ),
            ("zero-value", "main = IO.print $ Int.eq 0 1\n"),
            ("positive-value", "main = IO.print $ Int.eq 1 2\n"),
            (
                "minimum-value",
                "main = IO.print $ Int.eq (Int.plus 9223372036854775807 1) 9223372036854775807\n",
            ),
            (
                "maximum-value",
                "main = IO.print $ Int.eq 9223372036854775807 (Int.plus 9223372036854775807 1)\n",
            ),
        ],
    ),
    ("Int.show", &INT_SHOW_BOUNDARIES),
    ("Int.toInteger", &INT_TO_INTEGER_BOUNDARIES),
    (
        "Int.fromInteger",
        &[
            (
                "negative-value",
                "main = IO.print $ Int.fromInteger $ Int.toInteger $ Int.subtract 1 0\n",
            ),
            (
                "zero-value",
                "main = IO.print $ Int.fromInteger $ Int.toInteger 0\n",
            ),
            (
                "positive-value",
                "main = IO.print $ Int.fromInteger $ Int.toInteger 1\n",
            ),
            (
                "minimum-value",
                "main = IO.print $ Int.fromInteger $ Int.toInteger $ Int.plus 9223372036854775807 1\n",
            ),
            (
                "maximum-value",
                "main = IO.print $ Int.fromInteger $ Int.toInteger 9223372036854775807\n",
            ),
            (
                "overflow",
                "main = IO.print $ Int.fromInteger $ Integer.plus (Int.toInteger 9223372036854775807) (Int.toInteger 1)\n",
            ),
        ],
    ),
    (
        "Int.readMaybe",
        &[
            ("negative-value", "main = IO.print $ Int.readMaybe \"-1\"\n"),
            ("zero-value", "main = IO.print $ Int.readMaybe \"0\"\n"),
            ("positive-value", "main = IO.print $ Int.readMaybe \"1\"\n"),
            (
                "minimum-value",
                "main = IO.print $ Int.readMaybe \"-9223372036854775808\"\n",
            ),
            (
                "maximum-value",
                "main = IO.print $ Int.readMaybe \"9223372036854775807\"\n",
            ),
            (
                "overflow",
                "main = IO.print $ Int.readMaybe \"9223372036854775808\"\n",
            ),
        ],
    ),
];

fn runtime_int_conversion_boundary_cases() -> Vec<DifferentialCase> {
    RUNTIME_INT_CONVERSION_BOUNDARIES
        .iter()
        .flat_map(|(builtin, definitions)| {
            definitions
                .iter()
                .map(move |(boundary, source)| DifferentialCase {
                    id: Arc::from(format!(
                        "{}-boundary-{boundary}",
                        builtin.to_ascii_lowercase().replace('.', "-")
                    )),
                    source: Arc::from(*source),
                    claim_evidence: Some(if *builtin == "Int.eq" {
                        runtime_expected_boundary_descriptor(
                            builtin,
                            boundary,
                            source,
                            "{\"type\":\"Bool\",\"value\":false}",
                        )
                    } else {
                        runtime_builtin_boundary_descriptor(builtin, boundary, source)
                    }),
                    ..DifferentialCase::default()
                })
        })
        .collect()
}

const RUNTIME_INTEGER_BOUNDARIES: &[(&str, [(&str, &str); 3])] = &[
    (
        "Integer.plus",
        [
            (
                "negative-value",
                "main = IO.print $ Integer.plus (Int.toInteger $ Int.subtract 1 0) (Int.toInteger 0)\n",
            ),
            (
                "zero-value",
                "main = IO.print $ Integer.plus (Int.toInteger 0) (Int.toInteger 0)\n",
            ),
            (
                "positive-value",
                "main = IO.print $ Integer.plus (Int.toInteger 1) (Int.toInteger 2)\n",
            ),
        ],
    ),
    (
        "Integer.subtract",
        [
            (
                "negative-value",
                "main = IO.print $ Integer.subtract (Int.toInteger 1) (Int.toInteger 0)\n",
            ),
            (
                "zero-value",
                "main = IO.print $ Integer.subtract (Int.toInteger 0) (Int.toInteger 0)\n",
            ),
            (
                "positive-value",
                "main = IO.print $ Integer.subtract (Int.toInteger 0) (Int.toInteger 1)\n",
            ),
        ],
    ),
    (
        "Integer.mult",
        [
            (
                "negative-value",
                "main = IO.print $ Integer.mult (Int.toInteger $ Int.subtract 1 0) (Int.toInteger 2)\n",
            ),
            (
                "zero-value",
                "main = IO.print $ Integer.mult (Int.toInteger 0) (Int.toInteger 2)\n",
            ),
            (
                "positive-value",
                "main = IO.print $ Integer.mult (Int.toInteger 2) (Int.toInteger 3)\n",
            ),
        ],
    ),
    (
        "Integer.readMaybe",
        [
            (
                "negative-value",
                "main = IO.print $ Integer.readMaybe \"-1\"\n",
            ),
            ("zero-value", "main = IO.print $ Integer.readMaybe \"0\"\n"),
            (
                "positive-value",
                "main = IO.print $ Integer.readMaybe \"9223372036854775808\"\n",
            ),
        ],
    ),
];

fn runtime_integer_boundary_cases() -> Vec<DifferentialCase> {
    RUNTIME_INTEGER_BOUNDARIES
        .iter()
        .flat_map(|(builtin, definitions)| {
            definitions
                .iter()
                .map(move |(boundary, source)| DifferentialCase {
                    id: Arc::from(format!(
                        "{}-boundary-{boundary}",
                        builtin.to_ascii_lowercase().replace('.', "-")
                    )),
                    source: Arc::from(*source),
                    claim_evidence: Some(runtime_builtin_boundary_descriptor(
                        builtin, boundary, source,
                    )),
                    ..DifferentialCase::default()
                })
        })
        .collect()
}

const RUNTIME_DOUBLE_ARITHMETIC_BOUNDARIES: &[(&str, [(&str, &str); 6])] = &[
    (
        "Double.plus",
        [
            (
                "negative-value",
                "main = IO.print $ Double.plus (Double.fromInt $ Int.subtract 2 0) 1.0\n",
            ),
            ("zero-value", "main = IO.print $ Double.plus 0.0 0.0\n"),
            ("positive-value", "main = IO.print $ Double.plus 1.0 2.0\n"),
            (
                "minimum-value",
                "main = IO.print $ Double.plus (Double.mult (Double.fromInt $ Int.subtract 1 0) 1.7976931348623157e308) 0.0\n",
            ),
            (
                "maximum-value",
                "main = IO.print $ Double.plus 1.7976931348623157e308 0.0\n",
            ),
            (
                "overflow",
                "main = IO.print $ Double.plus 1.7976931348623157e308 1.7976931348623157e308\n",
            ),
        ],
    ),
    (
        "Double.subtract",
        [
            (
                "negative-value",
                "main = IO.print $ Double.subtract 1.0 0.0\n",
            ),
            ("zero-value", "main = IO.print $ Double.subtract 0.0 0.0\n"),
            (
                "positive-value",
                "main = IO.print $ Double.subtract 0.0 1.0\n",
            ),
            (
                "minimum-value",
                "main = IO.print $ Double.subtract 1.7976931348623157e308 0.0\n",
            ),
            (
                "maximum-value",
                "main = IO.print $ Double.subtract 0.0 1.7976931348623157e308\n",
            ),
            (
                "overflow",
                "main = IO.print $ Double.subtract 1.7976931348623157e308 (Double.mult (Double.fromInt $ Int.subtract 1 0) 1.7976931348623157e308)\n",
            ),
        ],
    ),
    (
        "Double.mult",
        [
            (
                "negative-value",
                "main = IO.print $ Double.mult (Double.fromInt $ Int.subtract 1 0) 2.0\n",
            ),
            ("zero-value", "main = IO.print $ Double.mult 0.0 2.0\n"),
            ("positive-value", "main = IO.print $ Double.mult 2.0 3.0\n"),
            (
                "minimum-value",
                "main = IO.print $ Double.mult (Double.fromInt $ Int.subtract 1 0) 1.7976931348623157e308\n",
            ),
            (
                "maximum-value",
                "main = IO.print $ Double.mult 1.7976931348623157e308 1.0\n",
            ),
            (
                "overflow",
                "main = IO.print $ Double.mult 1.7976931348623157e308 2.0\n",
            ),
        ],
    ),
];

fn runtime_double_arithmetic_boundary_cases() -> Vec<DifferentialCase> {
    RUNTIME_DOUBLE_ARITHMETIC_BOUNDARIES
        .iter()
        .flat_map(|(builtin, definitions)| {
            definitions
                .iter()
                .map(move |(boundary, source)| DifferentialCase {
                    id: Arc::from(format!(
                        "{}-boundary-{boundary}",
                        builtin.to_ascii_lowercase().replace('.', "-")
                    )),
                    source: Arc::from(*source),
                    claim_evidence: Some(runtime_double_boundary_descriptor(
                        builtin, boundary, source,
                    )),
                    ..DifferentialCase::default()
                })
        })
        .collect()
}

const RUNTIME_DOUBLE_FROM_INT_BOUNDARIES: &[(&str, &str)] = &[
    (
        "negative-value",
        "main = IO.print $ Double.fromInt $ Int.subtract 1 0\n",
    ),
    ("zero-value", "main = IO.print $ Double.fromInt 0\n"),
    ("positive-value", "main = IO.print $ Double.fromInt 1\n"),
    (
        "minimum-value",
        "main = IO.print $ Double.fromInt $ Int.plus 9223372036854775807 1\n",
    ),
    (
        "maximum-value",
        "main = IO.print $ Double.fromInt 9223372036854775807\n",
    ),
];

fn runtime_double_from_int_boundary_cases() -> Vec<DifferentialCase> {
    RUNTIME_DOUBLE_FROM_INT_BOUNDARIES
        .iter()
        .map(|(boundary, source)| DifferentialCase {
            id: Arc::from(format!("double-fromint-boundary-{boundary}")),
            source: Arc::from(*source),
            claim_evidence: Some(runtime_double_boundary_descriptor(
                "Double.fromInt",
                boundary,
                source,
            )),
            ..DifferentialCase::default()
        })
        .collect()
}

const RUNTIME_DOUBLE_READ_MAYBE_BOUNDARIES: &[(&str, &str)] = &[
    (
        "negative-value",
        "main = IO.print $ Double.readMaybe \"-1.0\"\n",
    ),
    ("zero-value", "main = IO.print $ Double.readMaybe \"0.0\"\n"),
    (
        "positive-value",
        "main = IO.print $ Double.readMaybe \"1.0\"\n",
    ),
    (
        "minimum-value",
        "main = IO.print $ Double.readMaybe \"-1.7976931348623157e308\"\n",
    ),
    (
        "maximum-value",
        "main = IO.print $ Double.readMaybe \"1.7976931348623157e308\"\n",
    ),
    ("overflow", "main = IO.print $ Double.readMaybe \"1e309\"\n"),
];

fn runtime_double_read_maybe_boundary_cases() -> Vec<DifferentialCase> {
    RUNTIME_DOUBLE_READ_MAYBE_BOUNDARIES
        .iter()
        .map(|(boundary, source)| DifferentialCase {
            id: Arc::from(format!("double-readmaybe-boundary-{boundary}")),
            source: Arc::from(*source),
            claim_evidence: Some(runtime_double_boundary_descriptor(
                "Double.readMaybe",
                boundary,
                source,
            )),
            ..DifferentialCase::default()
        })
        .collect()
}

const RUNTIME_DOUBLE_EQ_BOUNDARIES: &[(&str, &str, bool)] = &[
    (
        "negative-value",
        "main = IO.print $ Double.eq (Double.fromInt $ Int.subtract 1 0) 1.0\n",
        false,
    ),
    ("zero-value", "main = IO.print $ Double.eq 0.0 1.0\n", false),
    (
        "positive-value",
        "main = IO.print $ Double.eq 1.0 2.0\n",
        false,
    ),
    (
        "minimum-value",
        "main = IO.print $ Double.eq (Double.mult (Double.fromInt $ Int.subtract 1 0) 1.7976931348623157e308) 1.7976931348623157e308\n",
        false,
    ),
    (
        "maximum-value",
        "main = IO.print $ Double.eq 1.7976931348623157e308 (Double.mult (Double.fromInt $ Int.subtract 1 0) 1.7976931348623157e308)\n",
        false,
    ),
    (
        "overflow",
        "main = IO.print $ Double.eq (Double.subtract (Double.plus 1.7976931348623157e308 1.7976931348623157e308) (Double.plus 1.7976931348623157e308 1.7976931348623157e308)) (Double.subtract (Double.plus 1.7976931348623157e308 1.7976931348623157e308) (Double.plus 1.7976931348623157e308 1.7976931348623157e308))\n",
        false,
    ),
];

const RUNTIME_DOUBLE_SHOW_BOUNDARIES: &[(&str, &str, &str)] = &[
    (
        "negative-value",
        "main = IO.print $ Double.show $ Double.fromInt $ Int.subtract 1 0\n",
        "-1.0",
    ),
    ("zero-value", "main = IO.print $ Double.show 0.0\n", "0.0"),
    (
        "positive-value",
        "main = IO.print $ Double.show 1.0\n",
        "1.0",
    ),
    (
        "minimum-value",
        "main = IO.print $ Double.show $ Double.mult (Double.fromInt $ Int.subtract 1 0) 1.7976931348623157e308\n",
        "-1.7976931348623157e308",
    ),
    (
        "maximum-value",
        "main = IO.print $ Double.show 1.7976931348623157e308\n",
        "1.7976931348623157e308",
    ),
    (
        "overflow",
        "main = IO.print $ Double.show $ Double.plus 1.7976931348623157e308 1.7976931348623157e308\n",
        "Infinity",
    ),
];

const RUNTIME_DOUBLE_SHOW_E_BOUNDARIES: &[(&str, &str, &str)] = &[
    (
        "negative-value",
        "main = IO.print $ Double.showEFloat (Maybe.Just 2) (Double.fromInt $ Int.subtract 1 0) \"\"\n",
        "-1.00e0",
    ),
    (
        "zero-value",
        "main = IO.print $ Double.showEFloat (Maybe.Just 2) 0.0 \"\"\n",
        "0.00e0",
    ),
    (
        "positive-value",
        "main = IO.print $ Double.showEFloat (Maybe.Just 2) 1.0 \"\"\n",
        "1.00e0",
    ),
    (
        "minimum-value",
        "main = IO.print $ Double.showEFloat (Maybe.Just 2) (Double.mult (Double.fromInt $ Int.subtract 1 0) 1.7976931348623157e308) \"\"\n",
        "-1.80e308",
    ),
    (
        "maximum-value",
        "main = IO.print $ Double.showEFloat (Maybe.Just 2) 1.7976931348623157e308 \"\"\n",
        "1.80e308",
    ),
    (
        "overflow",
        "main = IO.print $ Double.showEFloat (Maybe.Just 2) (Double.plus 1.7976931348623157e308 1.7976931348623157e308) \"\"\n",
        "Infinity",
    ),
];

fn runtime_double_comparison_and_show_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = RUNTIME_DOUBLE_EQ_BOUNDARIES
        .iter()
        .map(|(boundary, source, expected)| DifferentialCase {
            id: Arc::from(format!("double-eq-boundary-{boundary}")),
            source: Arc::from(*source),
            claim_evidence: Some(runtime_expected_boundary_descriptor(
                "Double.eq",
                boundary,
                source,
                if *expected {
                    "{\"type\":\"Bool\",\"value\":true}"
                } else {
                    "{\"type\":\"Bool\",\"value\":false}"
                },
            )),
            ..DifferentialCase::default()
        })
        .collect::<Vec<_>>();
    cases.extend(runtime_double_text_boundary_cases(
        "Double.show",
        RUNTIME_DOUBLE_SHOW_BOUNDARIES,
    ));
    cases.extend(runtime_double_text_boundary_cases(
        "Double.showEFloat",
        RUNTIME_DOUBLE_SHOW_E_BOUNDARIES,
    ));
    cases
}

fn runtime_double_show_f_boundary_cases() -> Vec<DifferentialCase> {
    const MAX_FIXED_TWO: &str = concat!(
        "1797693134862315700000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000.00",
    );
    const NEGATIVE_MAX_FIXED_TWO: &str = concat!(
        "-1797693134862315700000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000.00",
    );
    [
        (
            "negative-value",
            "main = IO.print $ Double.showFFloat (Maybe.Just 2) (Double.fromInt $ Int.subtract 1 0) \"\"\n",
            "-1.00",
        ),
        (
            "zero-value",
            "main = IO.print $ Double.showFFloat (Maybe.Just 2) 0.0 \"\"\n",
            "0.00",
        ),
        (
            "positive-value",
            "main = IO.print $ Double.showFFloat (Maybe.Just 2) 1.0 \"\"\n",
            "1.00",
        ),
        (
            "minimum-value",
            "main = IO.print $ Double.showFFloat (Maybe.Just 2) (Double.mult (Double.fromInt $ Int.subtract 1 0) 1.7976931348623157e308) \"\"\n",
            NEGATIVE_MAX_FIXED_TWO,
        ),
        (
            "maximum-value",
            "main = IO.print $ Double.showFFloat (Maybe.Just 2) 1.7976931348623157e308 \"\"\n",
            MAX_FIXED_TWO,
        ),
        (
            "overflow",
            "main = IO.print $ Double.showFFloat (Maybe.Just 2) (Double.plus 1.7976931348623157e308 1.7976931348623157e308) \"\"\n",
            "Infinity",
        ),
    ]
    .into_iter()
    .map(|(boundary, source, expected)| {
        let encoded = utf8_hex(expected);
        let typed = format!("{{\"type\":\"Text\",\"utf8Hex\":\"{encoded}\"}}");
        DifferentialCase {
            id: Arc::from(format!("double-showffloat-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(runtime_expected_boundary_descriptor(
                "Double.showFFloat",
                boundary,
                source,
                &typed,
            )),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_double_text_boundary_cases(
    builtin: &str,
    definitions: &[(&str, &str, &str)],
) -> Vec<DifferentialCase> {
    definitions
        .iter()
        .map(|(boundary, source, expected)| {
            let encoded = utf8_hex(expected);
            let value = format!("{{\"type\":\"Text\",\"utf8Hex\":\"{encoded}\"}}");
            DifferentialCase {
                id: Arc::from(format!(
                    "{}-boundary-{boundary}",
                    builtin.to_ascii_lowercase().replace('.', "-")
                )),
                source: Arc::from(*source),
                claim_evidence: Some(runtime_expected_boundary_descriptor(
                    builtin, boundary, source, &value,
                )),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn utf8_hex(value: &str) -> String {
    const HEX_DIGITS: &[u8] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len().saturating_mul(2));
    for byte in value.bytes() {
        encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn runtime_expected_boundary_descriptor(
    builtin: &str,
    boundary: &str,
    source: &str,
    expected: &str,
) -> ClaimEvidenceDescriptor {
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{expected}}}"
    );
    let mut descriptor = runtime_builtin_boundary_descriptor(builtin, boundary, source);
    descriptor.semantic_targets[0].expected_typed_result_sha256 =
        Some(sha256_bytes(canonical.as_bytes()));
    descriptor
}

fn runtime_double_boundary_descriptor(
    builtin: &str,
    boundary: &str,
    source: &str,
) -> ClaimEvidenceDescriptor {
    let bits = match (builtin, boundary) {
        (
            "Double.fromInt" | "Double.plus" | "Double.subtract" | "Double.readMaybe",
            "negative-value",
        ) => "bff0000000000000",
        ("Double.mult", "negative-value") => "c000000000000000",
        (_, "zero-value") => "0000000000000000",
        ("Double.fromInt" | "Double.subtract" | "Double.readMaybe", "positive-value") => {
            "3ff0000000000000"
        }
        ("Double.plus", "positive-value") => "4008000000000000",
        ("Double.mult", "positive-value") => "4018000000000000",
        ("Double.fromInt", "minimum-value") => "c3e0000000000000",
        ("Double.fromInt", "maximum-value") => "43e0000000000000",
        (
            "Double.plus" | "Double.subtract" | "Double.mult" | "Double.readMaybe",
            "minimum-value",
        ) => "ffefffffffffffff",
        (
            "Double.plus" | "Double.subtract" | "Double.mult" | "Double.readMaybe",
            "maximum-value",
        ) => "7fefffffffffffff",
        ("Double.subtract", "overflow") => "fff0000000000000",
        ("Double.plus" | "Double.mult" | "Double.readMaybe", "overflow") => "7ff0000000000000",
        _ => panic!("unsupported Double boundary {builtin}/{boundary}"),
    };
    let value = format!("{{\"type\":\"Double\",\"ieee754Bits\":\"{bits}\"}}");
    let canonical = if builtin == "Double.readMaybe" {
        format!("{{\"type\":\"Maybe\",\"payload\":{value}}}")
    } else {
        value
    };
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{canonical}}}"
    );
    let mut descriptor = runtime_builtin_boundary_descriptor(builtin, boundary, source);
    let target = descriptor
        .semantic_targets
        .iter_mut()
        .find(|target| target.builtin.as_ref() == builtin)
        .expect("Double boundary target");
    target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    descriptor
}

const RUNTIME_TEXT_VALUE_BOUNDARIES: &[(&str, [&str; 3])] = &[
    (
        "Text.length",
        [
            "main = IO.print $ Text.length \"\"\n",
            "main = IO.print $ Text.length \"abc\"\n",
            "main = IO.print $ Text.length \"aβ\"\n",
        ],
    ),
    (
        "Text.reverse",
        [
            "main = IO.print $ Text.reverse \"\"\n",
            "main = IO.print $ Text.reverse \"abc\"\n",
            "main = IO.print $ Text.reverse \"aβ\"\n",
        ],
    ),
    (
        "Text.toLower",
        [
            "main = IO.print $ Text.toLower \"\"\n",
            "main = IO.print $ Text.toLower \"ABC\"\n",
            "main = IO.print $ Text.toLower \"AΒ\"\n",
        ],
    ),
    (
        "Text.toUpper",
        [
            "main = IO.print $ Text.toUpper \"\"\n",
            "main = IO.print $ Text.toUpper \"abc\"\n",
            "main = IO.print $ Text.toUpper \"aβ\"\n",
        ],
    ),
    (
        "Text.strip",
        [
            "main = IO.print $ Text.strip \"\"\n",
            "main = IO.print $ Text.strip \" abc \"\n",
            "main = IO.print $ Text.strip \" β \"\n",
        ],
    ),
    (
        "Text.take",
        [
            "main = IO.print $ Text.take 1 \"\"\n",
            "main = IO.print $ Text.take 1 \"abc\"\n",
            "main = IO.print $ Text.take 1 \"βx\"\n",
        ],
    ),
    (
        "Text.drop",
        [
            "main = IO.print $ Text.drop 1 \"\"\n",
            "main = IO.print $ Text.drop 1 \"abc\"\n",
            "main = IO.print $ Text.drop 1 \"βx\"\n",
        ],
    ),
    (
        "Text.eq",
        [
            "main = IO.print $ Text.eq \"\" \"x\"\n",
            "main = IO.print $ Text.eq \"abc\" \"abd\"\n",
            "main = IO.print $ Text.eq \"aβ\" \"aγ\"\n",
        ],
    ),
    (
        "Text.breakOn",
        [
            "main = IO.print $ Text.breakOn \"x\" \"\"\n",
            "main = IO.print $ Text.breakOn \"b\" \"abc\"\n",
            "main = IO.print $ Text.breakOn \"β\" \"aβc\"\n",
        ],
    ),
    (
        "Text.dropEnd",
        [
            "main = IO.print $ Text.dropEnd 1 \"\"\n",
            "main = IO.print $ Text.dropEnd 1 \"abc\"\n",
            "main = IO.print $ Text.dropEnd 1 \"aβ\"\n",
        ],
    ),
    (
        "Text.isInfixOf",
        [
            "main = IO.print $ Text.isInfixOf \"x\" \"\"\n",
            "main = IO.print $ Text.isInfixOf \"b\" \"abc\"\n",
            "main = IO.print $ Text.isInfixOf \"β\" \"aβc\"\n",
        ],
    ),
    (
        "Text.isPrefixOf",
        [
            "main = IO.print $ Text.isPrefixOf \"x\" \"\"\n",
            "main = IO.print $ Text.isPrefixOf \"a\" \"abc\"\n",
            "main = IO.print $ Text.isPrefixOf \"β\" \"βx\"\n",
        ],
    ),
    (
        "Text.isSuffixOf",
        [
            "main = IO.print $ Text.isSuffixOf \"x\" \"\"\n",
            "main = IO.print $ Text.isSuffixOf \"c\" \"abc\"\n",
            "main = IO.print $ Text.isSuffixOf \"β\" \"aβ\"\n",
        ],
    ),
    (
        "Text.stripPrefix",
        [
            "main = IO.print $ Text.stripPrefix \"x\" \"\"\n",
            "main = IO.print $ Text.stripPrefix \"a\" \"abc\"\n",
            "main = IO.print $ Text.stripPrefix \"β\" \"βx\"\n",
        ],
    ),
    (
        "Text.stripSuffix",
        [
            "main = IO.print $ Text.stripSuffix \"x\" \"\"\n",
            "main = IO.print $ Text.stripSuffix \"c\" \"abc\"\n",
            "main = IO.print $ Text.stripSuffix \"β\" \"aβ\"\n",
        ],
    ),
    (
        "Text.takeEnd",
        [
            "main = IO.print $ Text.takeEnd 1 \"\"\n",
            "main = IO.print $ Text.takeEnd 1 \"abc\"\n",
            "main = IO.print $ Text.takeEnd 1 \"aβ\"\n",
        ],
    ),
    (
        "Text.concat",
        [
            "main = IO.print $ Text.concat []\n",
            "main = IO.print $ Text.concat [\"a\",\"b\"]\n",
            "main = IO.print $ Text.concat [\"a\",\"β\"]\n",
        ],
    ),
    (
        "Text.intercalate",
        [
            "main = IO.print $ Text.intercalate \"-\" []\n",
            "main = IO.print $ Text.intercalate \"-\" [\"a\",\"b\"]\n",
            "main = IO.print $ Text.intercalate \"β\" [\"a\",\"c\"]\n",
        ],
    ),
    (
        "Text.lines",
        [
            "main = IO.print $ Text.lines \"\"\n",
            "main = IO.print $ Text.lines \"a\\nb\"\n",
            "main = IO.print $ Text.lines \"a\\nβ\"\n",
        ],
    ),
    (
        "Text.pack",
        [
            "main = IO.print $ Text.pack []\n",
            "main = IO.print $ Text.pack ['a','b']\n",
            "main = IO.print $ Text.pack ['a','β']\n",
        ],
    ),
    (
        "Text.splitOn",
        [
            "main = IO.print $ Text.splitOn \"::\" \"\"\n",
            "main = IO.print $ Text.splitOn \"::\" \"a::b\"\n",
            "main = IO.print $ Text.splitOn \"β\" \"aβc\"\n",
        ],
    ),
    (
        "Text.unlines",
        [
            "main = IO.print $ Text.unlines []\n",
            "main = IO.print $ Text.unlines [\"a\",\"b\"]\n",
            "main = IO.print $ Text.unlines [\"a\",\"β\"]\n",
        ],
    ),
    (
        "Text.unwords",
        [
            "main = IO.print $ Text.unwords []\n",
            "main = IO.print $ Text.unwords [\"a\",\"b\"]\n",
            "main = IO.print $ Text.unwords [\"a\",\"β\"]\n",
        ],
    ),
    (
        "Text.words",
        [
            "main = IO.print $ Text.words \"\"\n",
            "main = IO.print $ Text.words \"a b\"\n",
            "main = IO.print $ Text.words \"a β\"\n",
        ],
    ),
    (
        "Text.encodeUtf8",
        [
            "main = IO.print $ Text.encodeUtf8 \"\"\n",
            "main = IO.print $ Text.encodeUtf8 \"abc\"\n",
            "main = IO.print $ Text.encodeUtf8 \"aβ\"\n",
        ],
    ),
    (
        "Text.replace",
        [
            "main = IO.print $ Text.replace \"x\" \"y\" \"\"\n",
            "main = IO.print $ Text.replace \"b\" \"x\" \"abc\"\n",
            "main = IO.print $ Text.replace \"β\" \"x\" \"aβc\"\n",
        ],
    ),
    (
        "Text.unpack",
        [
            "main = IO.print $ Text.unpack \"\"\n",
            "main = IO.print $ Text.unpack \"abc\"\n",
            "main = IO.print $ Text.unpack \"aβ\"\n",
        ],
    ),
];

fn runtime_text_value_boundary_cases() -> Vec<DifferentialCase> {
    RUNTIME_TEXT_VALUE_BOUNDARIES
        .iter()
        .flat_map(|(builtin, sources)| {
            ["empty-input", "ascii", "unicode"]
                .into_iter()
                .zip(*sources)
                .enumerate()
                .map(move |(index, (boundary, source))| {
                    let mut descriptor = if *builtin == "Text.eq" {
                        runtime_expected_boundary_descriptor(
                            builtin,
                            boundary,
                            source,
                            "{\"type\":\"Bool\",\"value\":false}",
                        )
                    } else {
                        runtime_builtin_boundary_descriptor(builtin, boundary, source)
                    };
                    attach_raw_presentation_target(
                        &mut descriptor,
                        builtin,
                        runtime_text_value_stdout(builtin, index).as_bytes(),
                    );
                    DifferentialCase {
                        id: Arc::from(format!(
                            "{}-boundary-{boundary}",
                            builtin.to_ascii_lowercase().replace('.', "-")
                        )),
                        source: Arc::from(source),
                        claim_evidence: Some(descriptor),
                        ..DifferentialCase::default()
                    }
                })
        })
        .collect()
}

fn runtime_text_value_stdout(builtin: &str, index: usize) -> &'static str {
    let outputs = match builtin {
        "Text.length" => ["0\n", "3\n", "2\n"],
        "Text.reverse" => ["\"\"\n", "\"cba\"\n", "\"\\946a\"\n"],
        "Text.toLower" | "Text.unpack" => ["\"\"\n", "\"abc\"\n", "\"a\\946\"\n"],
        "Text.toUpper" => ["\"\"\n", "\"ABC\"\n", "\"A\\914\"\n"],
        "Text.strip" => ["\"\"\n", "\"abc\"\n", "\"\\946\"\n"],
        "Text.take" => ["\"\"\n", "\"a\"\n", "\"\\946\"\n"],
        "Text.drop" => ["\"\"\n", "\"bc\"\n", "\"x\"\n"],
        "Text.eq" => ["False\n", "False\n", "False\n"],
        "Text.breakOn" => ["(\"\",\"\")\n", "(\"a\",\"bc\")\n", "(\"a\",\"\\946c\")\n"],
        "Text.dropEnd" => ["\"\"\n", "\"ab\"\n", "\"a\"\n"],
        "Text.isInfixOf" | "Text.isPrefixOf" | "Text.isSuffixOf" => ["False\n", "True\n", "True\n"],
        "Text.stripPrefix" => ["Nothing\n", "Just \"bc\"\n", "Just \"x\"\n"],
        "Text.stripSuffix" => ["Nothing\n", "Just \"ab\"\n", "Just \"a\"\n"],
        "Text.takeEnd" => ["\"\"\n", "\"c\"\n", "\"\\946\"\n"],
        "Text.concat" | "Text.pack" => ["\"\"\n", "\"ab\"\n", "\"a\\946\"\n"],
        "Text.intercalate" => ["\"\"\n", "\"a-b\"\n", "\"a\\946c\"\n"],
        "Text.lines" | "Text.words" => ["[]\n", "[\"a\",\"b\"]\n", "[\"a\",\"\\946\"]\n"],
        "Text.splitOn" => ["[\"\"]\n", "[\"a\",\"b\"]\n", "[\"a\",\"c\"]\n"],
        "Text.unlines" => ["\"\"\n", "\"a\\nb\\n\"\n", "\"a\\n\\946\\n\"\n"],
        "Text.unwords" => ["\"\"\n", "\"a b\"\n", "\"a \\946\"\n"],
        "Text.encodeUtf8" => ["\"\"\n", "\"abc\"\n", "\"a\\206\\178\"\n"],
        "Text.replace" => ["\"\"\n", "\"axc\"\n", "\"axc\"\n"],
        _ => panic!("missing exact Text presentation output for {builtin}"),
    };
    outputs[index]
}

fn runtime_text_predicate_boundary_cases() -> Vec<DifferentialCase> {
    let definitions = [
        (
            "Text.all",
            "empty-input",
            "main = IO.print $ Text.all (Eq.eq 'a') \"\"\n",
            Vec::new(),
            true,
        ),
        (
            "Text.all",
            "ascii",
            "main = IO.print $ Text.all (Eq.eq 'a') \"a\"\n",
            character_predicate_invocations(&[('a', true)]),
            true,
        ),
        (
            "Text.all",
            "unicode",
            "main = IO.print $ Text.all (Eq.eq 'a') \"aβ\"\n",
            character_predicate_invocations(&[('a', true), ('β', false)]),
            false,
        ),
        (
            "Text.any",
            "empty-input",
            "main = IO.print $ Text.any (Eq.eq 'a') \"\"\n",
            Vec::new(),
            false,
        ),
        (
            "Text.any",
            "ascii",
            "main = IO.print $ Text.any (Eq.eq 'a') \"a\"\n",
            character_predicate_invocations(&[('a', true)]),
            true,
        ),
        (
            "Text.any",
            "unicode",
            "main = IO.print $ Text.any (Eq.eq 'β') \"aβ\"\n",
            character_predicate_invocations(&[('a', false), ('β', true)]),
            true,
        ),
    ];
    definitions
        .into_iter()
        .map(|(builtin, boundary, source, invocations, expected)| {
            let mut descriptor =
                runtime_boundary_descriptor(builtin, boundary, source, invocations);
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Bool\",\"value\":{expected}}}}}"
            );
            descriptor.semantic_targets[0].expected_typed_result_sha256 =
                Some(sha256_bytes(canonical.as_bytes()));
            attach_raw_presentation_target(
                &mut descriptor,
                builtin,
                if expected { b"True\n" } else { b"False\n" },
            );
            DifferentialCase {
                id: Arc::from(format!(
                    "{}-boundary-{boundary}",
                    builtin.to_ascii_lowercase().replace('.', "-")
                )),
                source: Arc::from(source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn attach_raw_presentation_target(
    descriptor: &mut ClaimEvidenceDescriptor,
    builtin: &str,
    stdout: &[u8],
) {
    if let Some(target) = descriptor.semantic_targets.iter_mut().find(|target| {
        target.builtin.as_ref() == builtin
            && target.dimension == hell_builtins::CompatibilityDimension::Presentation
    }) {
        target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(stdout, b""));
        return;
    }
    let spec = hell_builtins::lookup(builtin).expect("presentation target is registry-backed");
    let cell = crate::runtime_obligation_cells_for_spec(spec)
        .into_iter()
        .find(|cell| cell.dimension == hell_builtins::CompatibilityDimension::Presentation)
        .expect("presentation target has an applicable cell");
    let target = EvidenceTargetV2::new(
        cell.builtin,
        cell.dimension,
        cell.obligations,
        cell.causal_signal,
        cell.platforms,
    )
    .with_expected_raw_presentation(stdout, b"");
    descriptor.targets.push(EvidenceTarget::new(
        Arc::clone(&target.builtin),
        target.dimension,
    ));
    descriptor.semantic_targets.push(target);
}

fn runtime_text_filter_boundary_cases() -> Vec<DifferentialCase> {
    [
        (
            "empty-input",
            "main = IO.print $ Text.filter (Eq.eq 'a') \"\"\n",
            Vec::new(),
            "",
        ),
        (
            "ascii",
            "main = IO.print $ Text.filter (Eq.eq 'a') \"ab\"\n",
            character_predicate_invocations(&[('a', true), ('b', false)]),
            "61",
        ),
        (
            "unicode",
            "main = IO.print $ Text.filter (\\character -> Bool.not $ Eq.eq character 'x') \"aβ\"\n",
            character_predicate_invocations(&[('a', true), ('β', true)]),
            "61ceb2",
        ),
    ]
    .into_iter()
    .map(|(boundary, source, invocations, expected_hex)| {
        let mut descriptor =
            runtime_boundary_descriptor("Text.filter", boundary, source, invocations);
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Text\",\"utf8Hex\":\"{expected_hex}\"}}}}"
        );
        descriptor.semantic_targets[0].expected_typed_result_sha256 =
            Some(sha256_bytes(canonical.as_bytes()));
        let rendered = match boundary {
            "empty-input" => b"\"\"\n".as_slice(),
            "ascii" => b"\"a\"\n".as_slice(),
            "unicode" => b"\"a\\946\"\n",
            _ => unreachable!("fixed Text.filter boundary"),
        };
        attach_raw_presentation_target(&mut descriptor, "Text.filter", rendered);
        DifferentialCase {
            id: Arc::from(format!("text-filter-boundary-{boundary}")),
            source: Arc::from(source),
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

fn runtime_map_quantifier_boundary_cases() -> Vec<DifferentialCase> {
    let definitions = [
        (
            "Map.all",
            "empty-input",
            "main = IO.print $ Map.all (Int.eq 2) $ Map.fromList ([] :: [(Int,Int)])\n",
            Vec::new(),
            true,
        ),
        (
            "Map.all",
            "singleton-input",
            "main = IO.print $ Map.all (Int.eq 2) $ Map.fromList [(1,2)]\n",
            predicate_invocations(&[("2", true)]),
            true,
        ),
        (
            "Map.all",
            "finite-input",
            "main = IO.print $ Map.all (Int.eq 2) $ Map.fromList [(1,2),(2,1)]\n",
            predicate_invocations(&[("2", true), ("1", false)]),
            false,
        ),
        (
            "Map.any",
            "empty-input",
            "main = IO.print $ Map.any (Int.eq 2) $ Map.fromList ([] :: [(Int,Int)])\n",
            Vec::new(),
            false,
        ),
        (
            "Map.any",
            "singleton-input",
            "main = IO.print $ Map.any (Int.eq 2) $ Map.fromList [(1,2)]\n",
            predicate_invocations(&[("2", true)]),
            true,
        ),
        (
            "Map.any",
            "finite-input",
            "main = IO.print $ Map.any (Int.eq 2) $ Map.fromList [(1,1),(2,2)]\n",
            predicate_invocations(&[("1", false), ("2", true)]),
            true,
        ),
    ];
    definitions
        .into_iter()
        .map(|(builtin, boundary, source, invocations, expected)| {
            let mut descriptor =
                runtime_boundary_descriptor(builtin, boundary, source, invocations);
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Bool\",\"value\":{expected}}}}}"
            );
            descriptor.semantic_targets[0].expected_typed_result_sha256 =
                Some(sha256_bytes(canonical.as_bytes()));
            DifferentialCase {
                id: Arc::from(format!(
                    "{}-boundary-{boundary}",
                    builtin.to_ascii_lowercase().replace('.', "-")
                )),
                source: Arc::from(source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_map_filter_boundary_cases() -> Vec<DifferentialCase> {
    let int = |value: i64| format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}");
    let definitions = [
        (
            "Map.filter",
            "empty-input",
            "main = IO.print $ Map.toList $ Map.filter (Int.eq 2) $ Map.fromList ([] :: [(Int,Int)])\n",
            Vec::new(),
            Vec::new(),
        ),
        (
            "Map.filter",
            "singleton-input",
            "main = IO.print $ Map.toList $ Map.filter (Int.eq 2) $ Map.fromList [(1,2)]\n",
            predicate_invocations(&[("2", true)]),
            vec![(1, 2)],
        ),
        (
            "Map.filter",
            "finite-input",
            "main = IO.print $ Map.toList $ Map.filter (Int.eq 2) $ Map.fromList [(1,1),(2,2)]\n",
            predicate_invocations(&[("1", false), ("2", true)]),
            vec![(2, 2)],
        ),
        (
            "Map.filterWithKey",
            "empty-input",
            "main = IO.print $ Map.toList $ Map.filterWithKey (\\key _ -> Int.eq key 2) $ Map.fromList ([] :: [(Int,Int)])\n",
            Vec::new(),
            Vec::new(),
        ),
        (
            "Map.filterWithKey",
            "singleton-input",
            "main = IO.print $ Map.toList $ Map.filterWithKey (\\key _ -> Int.eq key 2) $ Map.fromList [(2,3)]\n",
            vec![map_key_value_predicate_invocation(2, 3, true)],
            vec![(2, 3)],
        ),
        (
            "Map.filterWithKey",
            "finite-input",
            "main = IO.print $ Map.toList $ Map.filterWithKey (\\key _ -> Int.eq key 2) $ Map.fromList [(1,1),(2,2)]\n",
            vec![
                map_key_unused_value_predicate_invocation(1, false),
                map_key_value_predicate_invocation(2, 2, true),
            ],
            vec![(2, 2)],
        ),
    ];
    definitions
        .into_iter()
        .map(|(builtin, boundary, source, invocations, entries)| {
            let mut descriptor =
                runtime_boundary_descriptor(builtin, boundary, source, invocations);
            if builtin == "Map.adjust" {
                attach_legacy_map_callback_comparator(
                    &mut descriptor,
                    builtin,
                    boundary,
                );
            }
            let entries = entries
                .into_iter()
                .map(|(key, value)| {
                    format!("{{\"key\":{},\"value\":{}}}", int(key), int(value))
                })
                .collect::<Vec<_>>()
                .join(",");
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Map\",\"entries\":[{entries}]}}}}"
            );
            descriptor.semantic_targets[0].expected_typed_result_sha256 =
                Some(sha256_bytes(canonical.as_bytes()));
            DifferentialCase {
                id: Arc::from(format!(
                    "{}-boundary-{boundary}",
                    builtin.to_ascii_lowercase().replace('.', "-")
                )),
                source: Arc::from(source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_map_value_callback_boundary_cases() -> Vec<DifferentialCase> {
    let definitions = [
        (
            "Map.adjust",
            "empty-input",
            "main = IO.print $ Map.toList $ Map.adjust (Int.plus 1) 1 $ Map.fromList ([] :: [(Int,Int)])\n",
            Vec::new(),
            Vec::new(),
        ),
        (
            "Map.adjust",
            "singleton-input",
            "main = IO.print $ Map.toList $ Map.adjust (Int.plus 1) 1 $ Map.fromList [(1,2)]\n",
            value_callback_invocations(&[("2", "3")]),
            vec![(1, 3)],
        ),
        (
            "Map.adjust",
            "finite-input",
            "main = IO.print $ Map.toList $ Map.adjust (Int.plus 1) 2 $ Map.fromList [(1,1),(2,2)]\n",
            value_callback_invocations(&[("2", "3")]),
            vec![(1, 1), (2, 3)],
        ),
        (
            "Map.map",
            "empty-input",
            "main = IO.print $ Map.toList $ Map.map (Int.plus 1) $ Map.fromList ([] :: [(Int,Int)])\n",
            Vec::new(),
            Vec::new(),
        ),
        (
            "Map.map",
            "singleton-input",
            "main = IO.print $ Map.toList $ Map.map (Int.plus 1) $ Map.fromList [(1,2)]\n",
            value_callback_invocations(&[("2", "3")]),
            vec![(1, 3)],
        ),
        (
            "Map.map",
            "finite-input",
            "main = IO.print $ Map.toList $ Map.map (Int.plus 1) $ Map.fromList [(1,1),(2,2)]\n",
            value_callback_invocations(&[("1", "2"), ("2", "3")]),
            vec![(1, 2), (2, 3)],
        ),
    ];
    definitions
        .into_iter()
        .map(|(builtin, boundary, source, invocations, entries)| {
            let mut descriptor =
                runtime_boundary_descriptor(builtin, boundary, source, invocations);
            if crate::runtime_obligations::collection_comparator_sensitive(builtin) {
                attach_legacy_map_callback_comparator(&mut descriptor, builtin, boundary);
            }
            let entries = entries
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{{\"key\":{{\"type\":\"Int\",\"value\":\"{key}\"}},\"value\":{{\"type\":\"Int\",\"value\":\"{value}\"}}}}"
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Map\",\"entries\":[{entries}]}}}}"
            );
            descriptor.semantic_targets[0].expected_typed_result_sha256 =
                Some(sha256_bytes(canonical.as_bytes()));
            DifferentialCase {
                id: Arc::from(format!(
                    "{}-boundary-{boundary}",
                    builtin.to_ascii_lowercase().replace('.', "-")
                )),
                source: Arc::from(source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn runtime_map_collision_boundary_cases() -> Vec<DifferentialCase> {
    let definitions = [
        (
            "Map.insertWith",
            "empty-input",
            "main = IO.print $ Map.toList $ Map.insertWith Int.plus 1 10 $ Map.fromList ([] :: [(Int,Int)])\n",
            Vec::new(),
            vec![(1, 10)],
        ),
        (
            "Map.insertWith",
            "singleton-input",
            "main = IO.print $ Map.toList $ Map.insertWith Int.plus 1 10 $ Map.fromList [(1,2)]\n",
            map_collision_callback_invocations(&[("10", "2", "12")]),
            vec![(1, 12)],
        ),
        (
            "Map.insertWith",
            "finite-input",
            "main = IO.print $ Map.toList $ Map.insertWith Int.plus 2 10 $ Map.fromList [(1,1),(2,2)]\n",
            map_collision_callback_invocations(&[("10", "2", "12")]),
            vec![(1, 1), (2, 12)],
        ),
        (
            "Map.unionWith",
            "empty-input",
            "main = IO.print $ Map.toList $ Map.unionWith Int.plus (Map.fromList ([] :: [(Int,Int)])) (Map.fromList ([] :: [(Int,Int)]))\n",
            Vec::new(),
            Vec::new(),
        ),
        (
            "Map.unionWith",
            "singleton-input",
            "main = IO.print $ Map.toList $ Map.unionWith Int.plus (Map.fromList [(1,2)]) (Map.fromList [(1,10)])\n",
            map_collision_callback_invocations(&[("2", "10", "12")]),
            vec![(1, 12)],
        ),
        (
            "Map.unionWith",
            "finite-input",
            "main = IO.print $ Map.toList $ Map.unionWith Int.plus (Map.fromList [(1,1),(2,2)]) (Map.fromList [(2,10),(3,3)])\n",
            map_collision_callback_invocations(&[("2", "10", "12")]),
            vec![(1, 1), (2, 12), (3, 3)],
        ),
    ];
    definitions
        .into_iter()
        .map(|(builtin, boundary, source, invocations, entries)| {
            let mut descriptor =
                runtime_boundary_descriptor(builtin, boundary, source, invocations);
            attach_legacy_map_callback_comparator(&mut descriptor, builtin, boundary);
            let entries = entries
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{{\"key\":{{\"type\":\"Int\",\"value\":\"{key}\"}},\"value\":{{\"type\":\"Int\",\"value\":\"{value}\"}}}}"
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let canonical = format!(
                "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Map\",\"entries\":[{entries}]}}}}"
            );
            descriptor.semantic_targets[0].expected_typed_result_sha256 =
                Some(sha256_bytes(canonical.as_bytes()));
            DifferentialCase {
                id: Arc::from(format!(
                    "{}-boundary-{boundary}",
                    builtin.to_ascii_lowercase().replace('.', "-")
                )),
                source: Arc::from(source),
                claim_evidence: Some(descriptor),
                ..DifferentialCase::default()
            }
        })
        .collect()
}

fn attach_legacy_map_callback_comparator(
    descriptor: &mut ClaimEvidenceDescriptor,
    builtin: &str,
    boundary: &str,
) {
    let one = ord_list_int(1);
    let two = ord_list_int(2);
    let records = match (builtin, boundary) {
        ("Map.adjust" | "Map.insertWith", "finite-input") => vec![
            reviewed_comparator_contract(1, "Ord.lt", &two, &one, false),
            reviewed_comparator_contract(2, "Ord.gt", &two, &one, true),
        ],
        ("Map.unionWith", "finite-input") => vec![
            reviewed_comparator_contract(1, "Ord.lt", &one, &two, true),
            reviewed_comparator_contract(2, "Ord.lt", &two, &ord_list_int(3), true),
        ],
        _ => Vec::new(),
    };
    for target in &mut descriptor.semantic_targets {
        target.expected_instance_target = Some(Arc::from("Int"));
        target.expected_comparator_trace_sha256 = Some(crate::comparator_trace_sha256(
            builtin,
            1,
            "Int",
            &[],
            &records,
        ));
    }
}

const RUNTIME_CI_BOUNDARIES: &[(&str, [&str; 4])] = &[
    (
        "CI.mk",
        [
            "main = IO.print $ CI.mk \"\"\n",
            "main = IO.print $ CI.mk \"AbC\"\n",
            "main = IO.print $ CI.mk \"AΒ\"\n",
            "main = do\n  bytes <- ByteString.getContents\n  ByteString.hPutStr IO.stdout $ CI.foldedCase $ CI.mk bytes\n",
        ],
    ),
    (
        "CI.foldedCase",
        [
            "main = IO.print $ CI.foldedCase $ CI.mk \"\"\n",
            "main = IO.print $ CI.foldedCase $ CI.mk \"AbC\"\n",
            "main = IO.print $ CI.foldedCase $ CI.mk \"AΒ\"\n",
            "main = do\n  bytes <- ByteString.getContents\n  ByteString.hPutStr IO.stdout $ CI.foldedCase $ CI.mk bytes\n",
        ],
    ),
];

fn runtime_ci_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = RUNTIME_CI_BOUNDARIES
        .iter()
        .flat_map(|(builtin, sources)| {
            ["empty-input", "ascii", "unicode", "invalid-encoding"]
                .into_iter()
                .zip(*sources)
                .map(move |(boundary, source)| {
                    let mut descriptor =
                        runtime_builtin_boundary_descriptor(builtin, boundary, source);
                    if *builtin == "CI.mk" {
                        descriptor.semantic_targets[0].expected_instance_target =
                            Some(Arc::from(if boundary == "invalid-encoding" {
                                "ByteString"
                            } else {
                                "Text"
                            }));
                    }
                    DifferentialCase {
                        id: Arc::from(format!(
                            "{}-boundary-{boundary}",
                            builtin.to_ascii_lowercase().replace('.', "-")
                        )),
                        source: Arc::from(source),
                        stdin: if boundary == "invalid-encoding" {
                            vec![0xff, b'A']
                        } else {
                            Vec::new()
                        },
                        claim_evidence: Some(descriptor),
                        ..DifferentialCase::default()
                    }
                })
        })
        .collect::<Vec<_>>();
    cases.extend(runtime_ci_bytestring_boundary_cases());
    cases
}

fn runtime_ci_bytestring_boundary_cases() -> Vec<DifferentialCase> {
    [
        ("empty-input", Vec::new()),
        ("ascii", b"AbC".to_vec()),
        ("unicode", "AΒ".as_bytes().to_vec()),
    ]
    .into_iter()
    .map(|(boundary, stdin)| {
        const SOURCE: &str = concat!(
            "main = do\n",
            "  bytes <- ByteString.getContents\n",
            "  ByteString.hPutStr IO.stdout $ CI.foldedCase $ CI.mk bytes\n",
        );
        let mut descriptor = runtime_builtin_boundary_descriptor("CI.mk", boundary, SOURCE);
        descriptor.semantic_targets[0].expected_instance_target = Some(Arc::from("ByteString"));
        DifferentialCase {
            id: Arc::from(format!("ci-mk-bytestring-boundary-{boundary}")),
            source: Arc::from(SOURCE),
            stdin,
            claim_evidence: Some(descriptor),
            ..DifferentialCase::default()
        }
    })
    .collect()
}

const RUNTIME_SIMPLE_LIST_BOUNDARIES: &[(&str, [&str; 3])] = &[
    (
        "List.null",
        [
            "main = IO.print $ List.null ([] :: [Int])\n",
            "main = IO.print $ List.null [1]\n",
            "main = IO.print $ List.null [1,2]\n",
        ],
    ),
    (
        "List.reverse",
        [
            "main = IO.print $ List.reverse ([] :: [Int])\n",
            "main = IO.print $ List.reverse [1]\n",
            "main = IO.print $ List.reverse [1,2]\n",
        ],
    ),
    (
        "List.length",
        [
            "main = IO.print $ List.length ([] :: [Int])\n",
            "main = IO.print $ List.length [1]\n",
            "main = IO.print $ List.length [1,2]\n",
        ],
    ),
    (
        "List.concat",
        [
            "main = IO.print $ List.concat ([] :: [[Int]])\n",
            "main = IO.print $ List.concat [[1]]\n",
            "main = IO.print $ List.concat [[1],[2]]\n",
        ],
    ),
    (
        "List.drop",
        [
            "main = IO.print $ List.drop 1 ([] :: [Int])\n",
            "main = IO.print $ List.drop 1 [1]\n",
            "main = IO.print $ List.drop 1 [1,2]\n",
        ],
    ),
    (
        "List.splitAt",
        [
            "main = IO.print $ List.splitAt 1 ([] :: [Int])\n",
            "main = IO.print $ List.splitAt 1 [1]\n",
            "main = IO.print $ List.splitAt 1 [1,2]\n",
        ],
    ),
    (
        "List.uncons",
        [
            "main = IO.print $ List.uncons ([] :: [Int])\n",
            "main = IO.print $ List.uncons [1]\n",
            "main = IO.print $ List.uncons [1,2]\n",
        ],
    ),
    (
        "List.inits",
        [
            "main = IO.print $ List.inits ([] :: [Int])\n",
            "main = IO.print $ List.inits [1]\n",
            "main = IO.print $ List.inits [1,2]\n",
        ],
    ),
    (
        "List.tails",
        [
            "main = IO.print $ List.tails ([] :: [Int])\n",
            "main = IO.print $ List.tails [1]\n",
            "main = IO.print $ List.tails [1,2]\n",
        ],
    ),
    (
        "List.intersperse",
        [
            "main = IO.print $ List.intersperse 0 []\n",
            "main = IO.print $ List.intersperse 0 [1]\n",
            "main = IO.print $ List.intersperse 0 [1,2]\n",
        ],
    ),
    (
        "List.and",
        [
            "main = IO.print $ List.and ([] :: [Bool])\n",
            "main = IO.print $ List.and [Bool.True]\n",
            "main = IO.print $ List.and [Bool.True,Bool.False]\n",
        ],
    ),
    (
        "List.or",
        [
            "main = IO.print $ List.or ([] :: [Bool])\n",
            "main = IO.print $ List.or [Bool.False]\n",
            "main = IO.print $ List.or [Bool.False,Bool.True]\n",
        ],
    ),
    (
        "List.elem",
        [
            "main = IO.print $ List.elem 1 []\n",
            "main = IO.print $ List.elem 1 [1]\n",
            "main = IO.print $ List.elem 2 [1,2]\n",
        ],
    ),
    (
        "List.notElem",
        [
            "main = IO.print $ List.notElem 1 []\n",
            "main = IO.print $ List.notElem 1 [1]\n",
            "main = IO.print $ List.notElem 2 [1,2]\n",
        ],
    ),
    (
        "List.elemIndex",
        [
            "main = IO.print $ List.elemIndex 1 []\n",
            "main = IO.print $ List.elemIndex 1 [1]\n",
            "main = IO.print $ List.elemIndex 2 [1,2]\n",
        ],
    ),
    (
        "List.elemIndices",
        [
            "main = IO.print $ List.elemIndices 1 []\n",
            "main = IO.print $ List.elemIndices 1 [1]\n",
            "main = IO.print $ List.elemIndices 2 [1,2,2]\n",
        ],
    ),
    (
        "List.lookup",
        [
            "main = IO.print $ List.lookup 1 ([] :: [(Int,Text)])\n",
            "main = IO.print $ List.lookup 1 [(1,\"a\")]\n",
            "main = IO.print $ List.lookup 2 [(1,\"a\"),(2,\"b\")]\n",
        ],
    ),
    (
        "List.zip",
        [
            "main = IO.print $ List.zip ([] :: [Int]) ([] :: [Text])\n",
            "main = IO.print $ List.zip [1] [\"a\"]\n",
            "main = IO.print $ List.zip [1,2] [\"a\",\"b\"]\n",
        ],
    ),
    (
        "List.transpose",
        [
            "main = IO.print $ List.transpose ([] :: [[Int]])\n",
            "main = IO.print $ List.transpose [[1]]\n",
            "main = IO.print $ List.transpose [[1,2],[3,4]]\n",
        ],
    ),
    (
        "List.intercalate",
        [
            "main = IO.print $ List.intercalate [0] ([] :: [[Int]])\n",
            "main = IO.print $ List.intercalate [0] [[1]]\n",
            "main = IO.print $ List.intercalate [0] [[1],[2]]\n",
        ],
    ),
    (
        "List.sort",
        [
            "main = IO.print $ List.sort ([] :: [Int])\n",
            "main = IO.print $ List.sort [1]\n",
            "main = IO.print $ List.sort [2,1]\n",
        ],
    ),
    (
        "List.nubOrd",
        [
            "main = IO.print $ List.nubOrd ([] :: [Int])\n",
            "main = IO.print $ List.nubOrd [1]\n",
            "main = IO.print $ List.nubOrd [2,1,2]\n",
        ],
    ),
    (
        "List.group",
        [
            "main = IO.print $ List.group ([] :: [Int])\n",
            "main = IO.print $ List.group [1]\n",
            "main = IO.print $ List.group [1,1,2]\n",
        ],
    ),
    (
        "List.subsequences",
        [
            "main = IO.print $ List.subsequences ([] :: [Int])\n",
            "main = IO.print $ List.subsequences [1]\n",
            "main = IO.print $ List.subsequences [1,2]\n",
        ],
    ),
    (
        "List.permutations",
        [
            "main = IO.print $ List.permutations ([] :: [Int])\n",
            "main = IO.print $ List.permutations [1]\n",
            "main = IO.print $ List.permutations [1,2]\n",
        ],
    ),
    (
        "List.isPrefixOf",
        [
            "main = IO.print $ List.isPrefixOf [1] []\n",
            "main = IO.print $ List.isPrefixOf [1] [1]\n",
            "main = IO.print $ List.isPrefixOf [1] [1,2]\n",
        ],
    ),
    (
        "List.isSuffixOf",
        [
            "main = IO.print $ List.isSuffixOf [1] []\n",
            "main = IO.print $ List.isSuffixOf [1] [1]\n",
            "main = IO.print $ List.isSuffixOf [1] [2,1]\n",
        ],
    ),
    (
        "List.isInfixOf",
        [
            "main = IO.print $ List.isInfixOf [1] []\n",
            "main = IO.print $ List.isInfixOf [1] [1]\n",
            "main = IO.print $ List.isInfixOf [1] [2,1]\n",
        ],
    ),
    (
        "List.isSubsequenceOf",
        [
            "main = IO.print $ List.isSubsequenceOf [1] []\n",
            "main = IO.print $ List.isSubsequenceOf [1] [1]\n",
            "main = IO.print $ List.isSubsequenceOf [1,2] [1,0,2]\n",
        ],
    ),
    (
        "List.cons",
        [
            "main = IO.print $ List.cons 0 []\n",
            "main = IO.print $ List.cons 0 [1]\n",
            "main = IO.print $ List.cons 0 [1,2]\n",
        ],
    ),
];

fn runtime_simple_list_boundary_cases() -> Vec<DifferentialCase> {
    RUNTIME_SIMPLE_LIST_BOUNDARIES
        .iter()
        .flat_map(|(builtin, sources)| {
            ["empty-input", "singleton-input", "finite-input"]
                .into_iter()
                .zip(*sources)
                .map(move |(boundary, source)| DifferentialCase {
                    id: Arc::from(format!(
                        "{}-boundary-{boundary}",
                        builtin.to_ascii_lowercase().replace('.', "-")
                    )),
                    source: Arc::from(source),
                    claim_evidence: Some(runtime_builtin_boundary_descriptor(
                        builtin, boundary, source,
                    )),
                    ..DifferentialCase::default()
                })
        })
        .collect()
}

#[derive(Clone)]
struct EqListBoundaryValue {
    definition: EqInstanceDefinition,
    value_type: &'static str,
    first: &'static str,
    second: &'static str,
    first_canonical: String,
    second_canonical: String,
    first_rendered: &'static str,
    second_rendered: &'static str,
}

fn runtime_eq_list_boundary_cases() -> Vec<DifferentialCase> {
    const BUILTINS: &[&str] = &[
        "List.lookup",
        "List.elem",
        "List.notElem",
        "List.elemIndex",
        "List.elemIndices",
        "List.group",
        "List.isInfixOf",
        "List.isPrefixOf",
        "List.isSubsequenceOf",
        "List.isSuffixOf",
    ];
    let mut cases = eq_list_boundary_values()
        .into_iter()
        .flat_map(|value| {
            BUILTINS.iter().flat_map(move |builtin| {
                ["empty-input", "singleton-input", "finite-input"]
                    .into_iter()
                    .map({
                        let value = value.clone();
                        move |boundary| runtime_eq_list_boundary_case(builtin, boundary, &value)
                    })
            })
        })
        .collect::<Vec<_>>();
    cases.extend(runtime_eq_list_breadth_cases());
    cases
}

fn runtime_eq_list_boundary_case(
    builtin: &str,
    boundary: &str,
    value: &EqListBoundaryValue,
) -> DifferentialCase {
    let (body, expected, stdout) = eq_list_boundary_observation(builtin, boundary, value);
    let source = format!("{}main = IO.print $ {body}\n", value.definition.prelude);
    let mut descriptor = runtime_builtin_boundary_descriptor(builtin, boundary, &source);
    configure_eq_list_target(
        &mut descriptor.semantic_targets[0],
        value,
        &expected,
        &stdout,
    );
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-eq-list-{}-{}-{boundary}",
            builtin.trim_start_matches("List.").to_ascii_lowercase(),
            value.definition.slug,
        )),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn configure_eq_list_target(
    target: &mut EvidenceTargetV2,
    value: &EqListBoundaryValue,
    expected: &str,
    stdout: &str,
) {
    target.expected_instance_target = Some(Arc::from(value.definition.target));
    target.expected_instance_premises = value
        .definition
        .premises
        .iter()
        .map(|(target, premise_count)| crate::InstancePremiseEvidence {
            target: Arc::from(*target),
            premise_count: *premise_count,
        })
        .collect();
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{expected}}}"
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    target.expected_raw_presentation_sha256 =
        Some(crate::raw_presentation_sha256(stdout.as_bytes(), b""));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
}

fn runtime_eq_list_breadth_cases() -> Vec<DifferentialCase> {
    eq_list_boundary_values()
        .into_iter()
        .flat_map(|value| {
            eq_list_breadth_observations(&value).into_iter().map(
                move |(builtin, path, body, expected, stdout)| {
                    let source = format!("{}main = IO.print $ {body}\n", value.definition.prelude);
                    let mut descriptor = runtime_all_obligation_descriptor(builtin, &source);
                    descriptor
                        .targets
                        .retain(|target| target.dimension == CompatibilityDimension::PureRuntime);
                    descriptor
                        .semantic_targets
                        .retain(|target| target.dimension == CompatibilityDimension::PureRuntime);
                    configure_eq_list_target(
                        &mut descriptor.semantic_targets[0],
                        &value,
                        &expected,
                        &stdout,
                    );
                    DifferentialCase {
                        id: Arc::from(format!(
                            "runtime-eq-list-{}-{}-{path}",
                            builtin.trim_start_matches("List.").to_ascii_lowercase(),
                            value.definition.slug,
                        )),
                        source: Arc::from(source),
                        claim_evidence: Some(descriptor),
                        ..DifferentialCase::default()
                    }
                },
            )
        })
        .collect()
}

fn eq_list_breadth_observations(
    value: &EqListBoundaryValue,
) -> Vec<(&'static str, &'static str, String, String, String)> {
    let first = value.first;
    let second = value.second;
    let false_result = "{\"type\":\"Bool\",\"value\":false}".to_owned();
    let true_result = "{\"type\":\"Bool\",\"value\":true}".to_owned();
    let nothing = "{\"type\":\"Maybe\",\"payload\":null}".to_owned();
    let mut observations = vec![
        (
            "List.lookup",
            "finite-miss",
            format!("List.lookup ({second}) [(({first}),\"a\"),(({first}),\"b\")]"),
            nothing.clone(),
            "Nothing\n".to_owned(),
        ),
        (
            "List.elem",
            "finite-miss",
            format!("List.elem ({second}) [({first}),({first})]"),
            false_result.clone(),
            "False\n".to_owned(),
        ),
        (
            "List.notElem",
            "finite-miss",
            format!("List.notElem ({second}) [({first}),({first})]"),
            true_result,
            "True\n".to_owned(),
        ),
        (
            "List.elemIndex",
            "finite-miss",
            format!("List.elemIndex ({second}) [({first}),({first})]"),
            nothing,
            "Nothing\n".to_owned(),
        ),
        (
            "List.elemIndex",
            "duplicate-first-bias",
            format!("List.elemIndex ({second}) [({first}),({second}),({second})]"),
            format!("{{\"type\":\"Maybe\",\"payload\":{}}}", eq_list_int(1)),
            "Just 1\n".to_owned(),
        ),
        (
            "List.elemIndices",
            "finite-miss",
            format!("List.elemIndices ({second}) [({first}),({first})]"),
            eq_list_canonical_list(&[]),
            "[]\n".to_owned(),
        ),
        (
            "List.isPrefixOf",
            "finite-mismatch",
            format!("List.isPrefixOf [({first}),({second})] [({first}),({first})]"),
            false_result.clone(),
            "False\n".to_owned(),
        ),
        (
            "List.isInfixOf",
            "finite-order-mismatch",
            format!("List.isInfixOf [({second}),({first})] [({first}),({second})]"),
            false_result.clone(),
            "False\n".to_owned(),
        ),
        (
            "List.isSubsequenceOf",
            "finite-order-mismatch",
            format!("List.isSubsequenceOf [({second}),({first})] [({first}),({second})]"),
            false_result.clone(),
            "False\n".to_owned(),
        ),
        (
            "List.isSuffixOf",
            "finite-mismatch",
            format!("List.isSuffixOf [({first})] [({first}),({second})]"),
            false_result.clone(),
            "False\n".to_owned(),
        ),
        (
            "List.isSuffixOf",
            "finite-longer-needle",
            format!("List.isSuffixOf [({first}),({second})] [({second})]"),
            false_result,
            "False\n".to_owned(),
        ),
    ];
    observations.push(eq_list_lookup_bias_observation(value));
    observations.extend(eq_list_empty_needle_observations(value));
    observations
}

fn eq_list_lookup_bias_observation(
    value: &EqListBoundaryValue,
) -> (&'static str, &'static str, String, String, String) {
    let first = value.first;
    let second = value.second;
    (
        "List.lookup",
        "duplicate-first-bias",
        format!(
            "List.lookup ({second}) [(({first}),\"before\"),(({second}),\"chosen\"),(({second}),\"later\")]"
        ),
        format!(
            "{{\"type\":\"Maybe\",\"payload\":{}}}",
            eq_list_text("chosen")
        ),
        "Just \"chosen\"\n".to_owned(),
    )
}

fn eq_list_empty_needle_observations(
    value: &EqListBoundaryValue,
) -> Vec<(&'static str, &'static str, String, String, String)> {
    let first = value.first;
    [
        "List.isPrefixOf",
        "List.isInfixOf",
        "List.isSubsequenceOf",
        "List.isSuffixOf",
    ]
    .into_iter()
    .map(|builtin| {
        let haystack = if builtin == "List.isSuffixOf" {
            format!("[({first})]")
        } else {
            format!(
                "(Error.error \"empty needle input\" :: [{}])",
                value.value_type
            )
        };
        (
            builtin,
            "empty-needle",
            format!("{builtin} ([] :: [{}]) {haystack}", value.value_type),
            "{\"type\":\"Bool\",\"value\":true}".to_owned(),
            "True\n".to_owned(),
        )
    })
    .collect()
}

fn eq_list_boundary_observation(
    builtin: &str,
    boundary: &str,
    value: &EqListBoundaryValue,
) -> (String, String, String) {
    if eq_list_binary_builtin(builtin) {
        return eq_list_binary_boundary_observation(builtin, boundary, value);
    }
    if matches!(builtin, "List.elemIndices" | "List.group") {
        return eq_list_aggregate_boundary_observation(builtin, boundary, value);
    }
    if builtin == "List.lookup" {
        return eq_list_lookup_boundary_observation(boundary, value);
    }
    eq_list_search_boundary_observation(builtin, boundary, value)
}

fn eq_list_search_boundary_observation(
    builtin: &str,
    boundary: &str,
    value: &EqListBoundaryValue,
) -> (String, String, String) {
    let first = value.first;
    let second = value.second;
    let empty = format!("([] :: [{}])", value.value_type);
    let bool_result = |result: bool| {
        let rendered = if result { "True\n" } else { "False\n" };
        (
            format!("{{\"type\":\"Bool\",\"value\":{result}}}"),
            rendered.to_owned(),
        )
    };
    match (builtin, boundary) {
        ("List.elem", "empty-input") => {
            let (expected, stdout) = bool_result(false);
            (format!("List.elem ({first}) {empty}"), expected, stdout)
        }
        ("List.elem", "singleton-input") => {
            let (expected, stdout) = bool_result(false);
            (
                format!("List.elem ({first}) [({second})]"),
                expected,
                stdout,
            )
        }
        ("List.elem", "finite-input") => {
            let (expected, stdout) = bool_result(true);
            (
                format!(
                    "List.elem ({second}) $ List.cons ({first}) $ List.cons ({second}) (Error.error \"elem tail\" :: [{}])",
                    value.value_type
                ),
                expected,
                stdout,
            )
        }
        ("List.notElem", "empty-input") => {
            let (expected, stdout) = bool_result(true);
            (format!("List.notElem ({first}) {empty}"), expected, stdout)
        }
        ("List.notElem", "singleton-input") => {
            let (expected, stdout) = bool_result(true);
            (
                format!("List.notElem ({first}) [({second})]"),
                expected,
                stdout,
            )
        }
        ("List.notElem", "finite-input") => {
            let (expected, stdout) = bool_result(false);
            (
                format!(
                    "List.notElem ({second}) $ List.cons ({first}) $ List.cons ({second}) (Error.error \"notElem tail\" :: [{}])",
                    value.value_type
                ),
                expected,
                stdout,
            )
        }
        ("List.elemIndex", "empty-input") => (
            format!("List.elemIndex ({first}) {empty}"),
            "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
            "Nothing\n".to_owned(),
        ),
        ("List.elemIndex", "singleton-input") => (
            format!("List.elemIndex ({first}) [({first})]"),
            format!("{{\"type\":\"Maybe\",\"payload\":{}}}", eq_list_int(0)),
            "Just 0\n".to_owned(),
        ),
        ("List.elemIndex", "finite-input") => (
            format!(
                "List.elemIndex ({second}) $ List.cons ({first}) $ List.cons ({second}) (Error.error \"elemIndex tail\" :: [{}])",
                value.value_type
            ),
            format!("{{\"type\":\"Maybe\",\"payload\":{}}}", eq_list_int(1)),
            "Just 1\n".to_owned(),
        ),
        _ => unreachable!("Eq/List search boundary inventory is closed"),
    }
}

fn eq_list_lookup_boundary_observation(
    boundary: &str,
    value: &EqListBoundaryValue,
) -> (String, String, String) {
    let first = value.first;
    let second = value.second;
    match boundary {
        "empty-input" => (
            format!(
                "List.lookup ({first}) ([] :: [({},Text)])",
                value.value_type
            ),
            "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
            "Nothing\n".to_owned(),
        ),
        "singleton-input" => (
            format!("List.lookup ({first}) [(({first}),\"first\")]"),
            format!(
                "{{\"type\":\"Maybe\",\"payload\":{}}}",
                eq_list_text("first")
            ),
            "Just \"first\"\n".to_owned(),
        ),
        "finite-input" => (
            format!(
                "List.lookup ({second}) $ List.cons (({first}),\"before\") $ List.cons (({second}),\"chosen\") (Error.error \"lookup tail\" :: [({},Text)])",
                value.value_type
            ),
            format!(
                "{{\"type\":\"Maybe\",\"payload\":{}}}",
                eq_list_text("chosen")
            ),
            "Just \"chosen\"\n".to_owned(),
        ),
        _ => unreachable!("Eq/List lookup boundary inventory is closed"),
    }
}

fn eq_list_aggregate_boundary_observation(
    builtin: &str,
    boundary: &str,
    value: &EqListBoundaryValue,
) -> (String, String, String) {
    let first = value.first;
    let second = value.second;
    match (builtin, boundary) {
        ("List.elemIndices", "empty-input") => (
            format!("List.elemIndices ({first}) ([] :: [{}])", value.value_type),
            eq_list_canonical_list(&[]),
            "[]\n".to_owned(),
        ),
        ("List.elemIndices", "singleton-input") => (
            format!("List.elemIndices ({first}) [({first})]"),
            eq_list_canonical_list(&[eq_list_int(0)]),
            "[0]\n".to_owned(),
        ),
        ("List.elemIndices", "finite-input") => (
            format!("List.elemIndices ({second}) [({first}),({second}),({first}),({second})]"),
            eq_list_canonical_list(&[eq_list_int(1), eq_list_int(3)]),
            "[1,3]\n".to_owned(),
        ),
        ("List.group", "empty-input") => (
            format!("List.group ([] :: [{}])", value.value_type),
            eq_list_canonical_list(&[]),
            "[]\n".to_owned(),
        ),
        ("List.group", "singleton-input") => {
            let group = eq_list_canonical_list(std::slice::from_ref(&value.first_canonical));
            let stdout = if value.definition.target == "Char" {
                format!(
                    "[{}]\n",
                    reviewed_haskell_character_canonicals(&[&value.first_canonical])
                )
            } else {
                format!("[[{}]]\n", value.first_rendered)
            };
            (
                format!("List.group [({first})]"),
                eq_list_canonical_list(&[group]),
                stdout,
            )
        }
        ("List.group", "finite-input") => eq_list_group_finite_observation(value),
        _ => unreachable!("Eq/List aggregate boundary inventory is closed"),
    }
}

fn eq_list_group_finite_observation(value: &EqListBoundaryValue) -> (String, String, String) {
    let first_group =
        eq_list_canonical_list(&[value.first_canonical.clone(), value.first_canonical.clone()]);
    let second_group = eq_list_canonical_list(std::slice::from_ref(&value.second_canonical));
    let separated = eq_list_canonical_list(std::slice::from_ref(&value.first_canonical));
    let stdout = if value.definition.target == "Char" {
        let first = reviewed_haskell_character_canonicals(&[
            &value.first_canonical,
            &value.first_canonical,
        ]);
        let second = reviewed_haskell_character_canonicals(&[&value.second_canonical]);
        let separated = reviewed_haskell_character_canonicals(&[&value.first_canonical]);
        format!("[{first},{second},{separated}]\n")
    } else {
        format!(
            "[[{0},{0}],[{1}],[{0}]]\n",
            value.first_rendered, value.second_rendered
        )
    };
    (
        format!(
            "List.group [({0}),({0}),({1}),({0})]",
            value.first, value.second
        ),
        eq_list_canonical_list(&[first_group, second_group, separated]),
        stdout,
    )
}

fn eq_list_binary_boundary_observation(
    builtin: &str,
    boundary: &str,
    value: &EqListBoundaryValue,
) -> (String, String, String) {
    let first = value.first;
    let second = value.second;
    match boundary {
        "empty-input" => eq_list_boolean_observation(
            format!("{builtin} [({first})] ([] :: [{}])", value.value_type),
            false,
        ),
        "singleton-input" => {
            eq_list_boolean_observation(format!("{builtin} [({first})] [({first})]"), true)
        }
        "finite-input" => {
            let body = match builtin {
                "List.isPrefixOf" => format!(
                    "List.isPrefixOf [({first}),({second})] $ List.cons ({first}) $ List.cons ({second}) (Error.error \"prefix tail\" :: [{}])",
                    value.value_type
                ),
                "List.isInfixOf" => format!(
                    "List.isInfixOf [({second})] $ List.cons ({first}) $ List.cons ({second}) (Error.error \"infix tail\" :: [{}])",
                    value.value_type
                ),
                "List.isSubsequenceOf" => format!(
                    "List.isSubsequenceOf [({first}),({second})] $ List.cons ({first}) $ List.cons ({second}) (Error.error \"subsequence tail\" :: [{}])",
                    value.value_type
                ),
                "List.isSuffixOf" => {
                    format!("List.isSuffixOf [({second})] [({first}),({second})]")
                }
                _ => unreachable!("Eq/List binary target inventory is closed"),
            };
            eq_list_boolean_observation(body, true)
        }
        _ => unreachable!("Eq/List binary boundary inventory is closed"),
    }
}

fn eq_list_boolean_observation(body: String, result: bool) -> (String, String, String) {
    let rendered = if result { "True\n" } else { "False\n" };
    (
        body,
        format!("{{\"type\":\"Bool\",\"value\":{result}}}"),
        rendered.to_owned(),
    )
}

fn eq_list_binary_builtin(builtin: &str) -> bool {
    matches!(
        builtin,
        "List.isInfixOf" | "List.isPrefixOf" | "List.isSubsequenceOf" | "List.isSuffixOf"
    )
}

fn eq_list_canonical_list(elements: &[String]) -> String {
    format!(
        "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"6e696c\"}}",
        elements.join(",")
    )
}

fn eq_list_int(value: i64) -> String {
    format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}")
}

fn eq_list_text(value: &str) -> String {
    format!("{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}", utf8_hex(value))
}

fn eq_list_boundary_values() -> Vec<EqListBoundaryValue> {
    eq_instance_definitions()
        .into_iter()
        .map(eq_list_boundary_value)
        .collect()
}

fn eq_list_boundary_value(definition: EqInstanceDefinition) -> EqListBoundaryValue {
    let (value_type, canonical, rendered) = eq_list_boundary_value_data(definition.slug);
    EqListBoundaryValue {
        definition,
        value_type,
        first: definition.unequal.0,
        second: definition.unequal.1,
        first_canonical: canonical.0,
        second_canonical: canonical.1,
        first_rendered: rendered.0,
        second_rendered: rendered.1,
    }
}

type EqListValueData = (&'static str, (String, String), (&'static str, &'static str));

fn eq_list_boundary_value_data(slug: &str) -> EqListValueData {
    eq_list_scalar_value_data(slug)
        .or_else(|| eq_list_compound_value_data(slug))
        .unwrap_or_else(|| unreachable!("Eq boundary instance inventory is closed"))
}

fn eq_list_primitive(kind: &str, constructor: &str, payloads: &[String]) -> String {
    format!(
        "{{\"type\":\"PrimitiveVariant\",\"family\":\"{kind}\",\"constructor\":\"{constructor}\",\"payloads\":[{}]}}",
        payloads.join(",")
    )
}

fn eq_list_pair(left: &str, right: &str) -> String {
    format!("{{\"type\":\"Tuple\",\"elements\":[{left},{right}]}}")
}

fn eq_list_scalar_value_data(slug: &str) -> Option<EqListValueData> {
    match slug {
        "bool" => Some((
            "Bool",
            (
                "{\"type\":\"Bool\",\"value\":true}".to_owned(),
                "{\"type\":\"Bool\",\"value\":false}".to_owned(),
            ),
            ("True", "False"),
        )),
        "byte-string" => Some((
            "ByteString",
            (
                "{\"type\":\"ByteString\",\"hex\":\"61ceb2\"}".to_owned(),
                "{\"type\":\"ByteString\",\"hex\":\"6162\"}".to_owned(),
            ),
            (r#""a\206\178""#, "\"ab\""),
        )),
        "ci" => Some((
            "CI Text",
            (
                format!(
                    "{{\"type\":\"CaseInsensitive\",\"original\":{},\"folded\":{}}}",
                    eq_list_text("AbC"),
                    eq_list_text("abc")
                ),
                format!(
                    "{{\"type\":\"CaseInsensitive\",\"original\":{},\"folded\":{}}}",
                    eq_list_text("abd"),
                    eq_list_text("abd")
                ),
            ),
            ("\"AbC\"", "\"abd\""),
        )),
        "char" => Some((
            "Char",
            (
                "{\"type\":\"Character\",\"codePoint\":946}".to_owned(),
                "{\"type\":\"Character\",\"codePoint\":97}".to_owned(),
            ),
            ("'\\946'", "'a'"),
        )),
        "day" => Some((
            "Day",
            (
                "{\"type\":\"Day\",\"iso8601Hex\":\"323032352d30382d3131\"}".to_owned(),
                "{\"type\":\"Day\",\"iso8601Hex\":\"323032352d30382d3132\"}".to_owned(),
            ),
            ("2025-08-11", "2025-08-12"),
        )),
        "day-of-week" => Some((
            "DayOfWeek",
            (
                "{\"type\":\"DayOfWeek\",\"value\":\"Monday\"}".to_owned(),
                "{\"type\":\"DayOfWeek\",\"value\":\"Tuesday\"}".to_owned(),
            ),
            ("Monday", "Tuesday"),
        )),
        "double" => Some((
            "Double",
            (
                "{\"type\":\"Double\",\"ieee754Bits\":\"3ff4000000000000\"}".to_owned(),
                "{\"type\":\"Double\",\"ieee754Bits\":\"3ff8000000000000\"}".to_owned(),
            ),
            ("1.25", "1.5"),
        )),
        "exit-code" => Some((
            "ExitCode",
            (
                eq_list_primitive("Exit", "ExitSuccess", &[]),
                eq_list_primitive("Exit", "ExitFailure", &[eq_list_int(23)]),
            ),
            ("ExitSuccess", "ExitFailure 23"),
        )),
        "int" => Some(("Int", (eq_list_int(42), eq_list_int(41)), ("42", "41"))),
        "integer" => Some((
            "Integer",
            (
                "{\"type\":\"Integer\",\"value\":\"42\"}".to_owned(),
                "{\"type\":\"Integer\",\"value\":\"41\"}".to_owned(),
            ),
            ("42", "41"),
        )),
        _ => None,
    }
}

fn eq_list_compound_value_data(slug: &str) -> Option<EqListValueData> {
    match slug {
        "either" => Some((
            "Either Text Int",
            (
                eq_list_primitive("Either", "Left", &[eq_list_text("left")]),
                eq_list_primitive("Either", "Right", &[eq_list_int(1)]),
            ),
            ("Left \"left\"", "Right 1"),
        )),
        "maybe" => Some((
            "Maybe Int",
            (
                "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
                format!("{{\"type\":\"Maybe\",\"payload\":{}}}", eq_list_int(1)),
            ),
            ("Nothing", "Just 1"),
        )),
        "set" => Some((
            "Set Int",
            (
                format!("{{\"type\":\"Set\",\"elements\":[{}]}}", eq_list_int(1)),
                format!(
                    "{{\"type\":\"Set\",\"elements\":[{},{}]}}",
                    eq_list_int(1),
                    eq_list_int(2)
                ),
            ),
            ("fromList [1]", "fromList [1,2]"),
        )),
        "text" => Some((
            "Text",
            (eq_list_text("aβ"), eq_list_text("ab")),
            ("\"a\\946\"", "\"ab\""),
        )),
        "time-of-day" => Some((
            "TimeOfDay",
            (
                "{\"type\":\"TimeOfDay\",\"iso8601Hex\":\"31323a30303a3030\"}".to_owned(),
                "{\"type\":\"TimeOfDay\",\"iso8601Hex\":\"30303a30303a3030\"}".to_owned(),
            ),
            ("12:00:00", "00:00:00"),
        )),
        "tree" => Some((
            "Tree Int",
            (
                eq_list_tree(&eq_list_int(1), &[]),
                eq_list_tree(
                    &eq_list_int(1),
                    &[eq_list_tree(&eq_list_int(2), &[])],
                ),
            ),
            (
                "Node {rootLabel = 1, subForest = []}",
                "Node {rootLabel = 1, subForest = [Node {rootLabel = 2, subForest = []}]}",
            ),
        )),
        "tuple" => Some((
            "(Int, Text)",
            (
                eq_list_pair(&eq_list_int(1), &eq_list_text("a")),
                eq_list_pair(&eq_list_int(1), &eq_list_text("b")),
            ),
            ("(1,\"a\")", "(1,\"b\")"),
        )),
        "utc-time" => Some((
            "UTCTime",
            (
                "{\"type\":\"UtcTime\",\"iso8601Hex\":\"323032352d30382d31312030303a30303a30312e3520555443\"}".to_owned(),
                "{\"type\":\"UtcTime\",\"iso8601Hex\":\"323032352d30382d31312030303a30303a30322e3520555443\"}".to_owned(),
            ),
            (
                "2025-08-11 00:00:01.5 UTC",
                "2025-08-11 00:00:02.5 UTC",
            ),
        )),
        "vector" => Some((
            "Vector Int",
            (
                format!("{{\"type\":\"Vector\",\"elements\":[{}]}}", eq_list_int(1)),
                format!(
                    "{{\"type\":\"Vector\",\"elements\":[{},{}]}}",
                    eq_list_int(1),
                    eq_list_int(2)
                ),
            ),
            ("[1]", "[1,2]"),
        )),
        "list" => Some((
            "[Int]",
            (
                eq_list_canonical_list(&[eq_list_int(1)]),
                eq_list_canonical_list(&[eq_list_int(1), eq_list_int(2)]),
            ),
            ("[1]", "[1,2]"),
        )),
        _ => None,
    }
}

fn eq_list_tree(root: &str, children: &[String]) -> String {
    format!(
        "{{\"type\":\"Tree\",\"elements\":[{root},{}]}}",
        eq_list_canonical_list(children)
    )
}

const COLLECTION_ACTIVATION: &str = include_str!("../../../compat/collection-activation.toml");
const COLLECTION_ACTIVATION_PROVENANCE: &str =
    include_str!("../../../compat/collection-activation-provenance.json");
const COLLECTION_ACTIVATION_CLAIMS: &str =
    include_str!("../../../compat/collection-activation-claims.json");
const DORMANT_COLLECTION_PROVENANCE: &str = "{\"activationAuthority\":false,\"domain\":\"hell.collection-activation.provenance.v1\",\"freshCollectionRequired\":true,\"promotionAuthority\":false,\"schemaVersion\":1,\"state\":\"dormant-no-reviewed-activation\"}\n";
const DORMANT_COLLECTION_CLAIMS: &str = "{\"activationAuthority\":false,\"domain\":\"hell.collection-activation.claims.v1\",\"freshEvidenceRequired\":true,\"promotionAuthority\":false,\"schemaVersion\":1,\"scopes\":[],\"state\":\"dormant-no-activated-claims\"}\n";
const DORMANT_COLLECTION_ACTIVATION: &str = concat!(
    "schema_version = 1\n",
    "domain = \"hell.collection-activation.v1\"\n",
    "scopes = [\"Map.adjust|pure-runtime|upstream|linux,macos,windows\", \"Map.delete|pure-runtime|upstream|linux,macos,windows\", \"Map.fromList|pure-runtime|upstream|linux,macos,windows\", \"Map.insert|pure-runtime|upstream|linux,macos,windows\", \"Map.insertWith|pure-runtime|upstream|linux,macos,windows\", \"Map.lookup|pure-runtime|upstream|linux,macos,windows\", \"Map.unionWith|pure-runtime|upstream|linux,macos,windows\", \"Set.delete|pure-runtime|upstream|linux,macos,windows\", \"Set.difference|pure-runtime|upstream|linux,macos,windows\", \"Set.fromList|pure-runtime|upstream|linux,macos,windows\", \"Set.insert|pure-runtime|upstream|linux,macos,windows\", \"Set.intersection|pure-runtime|upstream|linux,macos,windows\", \"Set.member|pure-runtime|upstream|linux,macos,windows\", \"Set.union|pure-runtime|upstream|linux,macos,windows\"]\n",
    "fresh_collection_required = true\n",
    "map712 = false\n",
    "set479 = false\n",
);
const ACTIVE_COLLECTION_ACTIVATION: &str = concat!(
    "schema_version = 1\n",
    "domain = \"hell.collection-activation.v1\"\n",
    "scopes = [\"Map.adjust|pure-runtime|upstream|linux,macos,windows\", \"Map.delete|pure-runtime|upstream|linux,macos,windows\", \"Map.fromList|pure-runtime|upstream|linux,macos,windows\", \"Map.insert|pure-runtime|upstream|linux,macos,windows\", \"Map.insertWith|pure-runtime|upstream|linux,macos,windows\", \"Map.lookup|pure-runtime|upstream|linux,macos,windows\", \"Map.unionWith|pure-runtime|upstream|linux,macos,windows\", \"Set.delete|pure-runtime|upstream|linux,macos,windows\", \"Set.difference|pure-runtime|upstream|linux,macos,windows\", \"Set.fromList|pure-runtime|upstream|linux,macos,windows\", \"Set.insert|pure-runtime|upstream|linux,macos,windows\", \"Set.intersection|pure-runtime|upstream|linux,macos,windows\", \"Set.member|pure-runtime|upstream|linux,macos,windows\", \"Set.union|pure-runtime|upstream|linux,macos,windows\"]\n",
    "fresh_collection_required = true\n",
    "map712 = true\n",
    "set479 = true\n",
);

fn collection_activation_flags() -> (bool, bool) {
    verify_collection_activation_state(
        COLLECTION_ACTIVATION.as_bytes(),
        COLLECTION_ACTIVATION_PROVENANCE.as_bytes(),
        COLLECTION_ACTIVATION_CLAIMS.as_bytes(),
    )
    .map_or((false, false), |active| (active, active))
}

/// Verifies the atomic collection activation manifest and its non-authoritative provenance.
///
/// # Errors
///
/// Returns an error unless the three inputs are the exact canonical dormant state or the exact
/// reviewed active state derived from the committed Map712/Set479 corpus.
pub fn verify_collection_activation_state(
    manifest: &[u8],
    provenance: &[u8],
    claims: &[u8],
) -> Result<bool, String> {
    if manifest == DORMANT_COLLECTION_ACTIVATION.as_bytes() {
        return (provenance == DORMANT_COLLECTION_PROVENANCE.as_bytes()
            && claims == DORMANT_COLLECTION_CLAIMS.as_bytes())
        .then_some(false)
        .ok_or_else(|| "dormant collection activation provenance is not canonical".to_owned());
    }
    if manifest != ACTIVE_COLLECTION_ACTIVATION.as_bytes() {
        return Err("collection activation manifest is not an exact atomic state".to_owned());
    }
    verify_active_collection_provenance(provenance)?;
    if claims != render_active_collection_claims()?.as_slice() {
        return Err("active collection claims differ from exact reviewed case mapping".to_owned());
    }
    Ok(true)
}

/// Renders the exact non-authoritative 14-scope Map712/Set479 activation mapping.
///
/// # Errors
///
/// Returns an error if the reviewed collection corpus no longer has one exact upstream native
/// `PureRuntime` target per case or the exact 14-scope/1,191-case inventory.
pub fn render_active_collection_claims() -> Result<Vec<u8>, String> {
    let cases = crate::reviewed_collection_cases()?;
    let mut scopes =
        std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    for case in cases {
        let descriptor = case
            .claim_evidence
            .ok_or_else(|| "collection activation case lacks claim evidence".to_owned())?;
        let [target] = descriptor.semantic_targets.as_slice() else {
            return Err("collection activation case does not bind one exact scope".to_owned());
        };
        if descriptor.profile != ExecutionProfile::Upstream
            || !descriptor.claim_normalizers.is_empty()
            || target.dimension != CompatibilityDimension::PureRuntime
            || target.expected_instance_target.is_none()
            || target.platforms
                != [
                    ClaimPlatform::Linux,
                    ClaimPlatform::MacOs,
                    ClaimPlatform::Windows,
                ]
        {
            return Err("collection activation case scope metadata is not exact".to_owned());
        }
        scopes
            .entry(target.builtin.to_string())
            .or_default()
            .insert(case.id.to_string());
    }
    if scopes.len() != 14
        || scopes
            .values()
            .map(std::collections::BTreeSet::len)
            .sum::<usize>()
            != 1_191
    {
        return Err("collection activation claims are not exact Map712/Set479".to_owned());
    }
    let mut output = String::from(
        "{\"activationAuthority\":false,\"domain\":\"hell.collection-activation.claims.v1\",\"freshEvidenceRequired\":true,\"promotionAuthority\":false,\"schemaVersion\":1,\"scopes\":[",
    );
    for (index, (builtin, case_ids)) in scopes.into_iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"caseRefs\":[");
        for (case_index, case_id) in case_ids.into_iter().enumerate() {
            if case_index != 0 {
                output.push(',');
            }
            if case_id.is_empty()
                || !case_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err("collection activation case reference is not canonical".to_owned());
            }
            write!(output, "\"{case_id}\"").expect("writing to String cannot fail");
        }
        write!(output, "],\"disposition\":\"requires-fresh-evidence\",\"scope\":\"{builtin}|pure-runtime|upstream|linux,macos,windows\"}}")
            .expect("writing to String cannot fail");
    }
    output.push_str("],\"state\":\"activated-scopes-require-fresh-evidence\"}\n");
    Ok(output.into_bytes())
}

fn verify_active_collection_provenance(bytes: &[u8]) -> Result<(), String> {
    let mut input = std::str::from_utf8(bytes)
        .map_err(|_| "collection activation provenance is not UTF-8".to_owned())?;
    take_activation_literal(&mut input, "{")?;
    let author_authorization =
        take_activation_string(&mut input, "activationAuthorAuthorizationSha256")?;
    let author_packet = take_activation_string(&mut input, "activationAuthorPacketSha256")?;
    let author_sha = take_activation_string(&mut input, "activationAuthorSha256")?;
    let author_fingerprint =
        take_activation_string(&mut input, "activationAuthorSignerFingerprint")?;
    let author_subject = take_activation_string(&mut input, "activationAuthorSubject")?;
    take_activation_literal(&mut input, "\"activationAuthority\":false,")?;
    let claims = take_activation_string(&mut input, "activationClaimsSha256")?;
    let proposal = take_activation_string(&mut input, "activationProposalSha256")?;
    let review_authorization =
        take_activation_string(&mut input, "activationReviewAuthorizationSha256")?;
    let review_packet = take_activation_string(&mut input, "activationReviewPacketSha256")?;
    let review_sha = take_activation_string(&mut input, "activationReviewSha256")?;
    let review_fingerprint =
        take_activation_string(&mut input, "activationReviewSignerFingerprint")?;
    let review_subject = take_activation_string(&mut input, "activationReviewSubject")?;
    let token = take_activation_string(&mut input, "activationTokenSha256")?;
    let base = take_activation_string(&mut input, "baseCandidateCommit")?;
    let mapping = take_activation_string(&mut input, "corpusMappingSha256")?;
    let retained = parse_retained_activation_provenance(&mut input)?;
    let worm = take_activation_final_string(&mut input, "wormCustodyIdentitySha256")?;
    take_activation_literal(&mut input, "}\n")?;
    if !input.is_empty() {
        return Err("collection activation provenance has trailing bytes".to_owned());
    }
    for digest in [
        author_sha,
        author_authorization,
        author_packet,
        author_fingerprint,
        claims,
        proposal,
        review_sha,
        review_authorization,
        review_packet,
        review_fingerprint,
        token,
        mapping,
        worm,
    ]
    .into_iter()
    .chain(retained.digests)
    {
        require_activation_hex(digest, 64, "collection activation digest")?;
    }
    require_activation_hex(base, 40, "collection activation base commit")?;
    for commit in retained.commits {
        require_activation_hex(commit, 40, "retained activation commit")?;
    }
    if author_subject == review_subject || author_fingerprint == review_fingerprint {
        return Err("collection activation author and reviewer are not independent".to_owned());
    }
    Ok(())
}

struct RetainedActivationProvenance<'a> {
    digests: Vec<&'a str>,
    commits: [&'a str; 2],
}

fn parse_retained_activation_provenance<'a>(
    input: &mut &'a str,
) -> Result<RetainedActivationProvenance<'a>, String> {
    require_activation_string(input, "domain", "hell.collection-activation.provenance.v1")?;
    take_activation_literal(input, "\"freshCollectionRequired\":true,")?;
    let historical_candidate =
        take_activation_string(input, "historicalCollectionCandidateCommit")?;
    let integration_proof = take_activation_string(input, "integrationProofSha256")?;
    let integration_review = take_activation_string(input, "integrationReviewSha256")?;
    take_activation_positive_number(input, "mapCaseCount")?;
    let outer_archive = take_activation_string(input, "outerArchiveSha256")?;
    take_activation_positive_number(input, "outerArtifactId")?;
    let outer_candidate = take_activation_string(input, "outerCandidateCommit")?;
    let outer_directory = take_activation_string(input, "outerDirectorySha256")?;
    take_activation_positive_number(input, "outerRunAttempt")?;
    take_activation_positive_number(input, "outerRunId")?;
    let outer_selection = take_activation_string(input, "outerSelectionSha256")?;
    require_activation_string(
        input,
        "outerWorkflowPath",
        ".github/workflows/collection-activation-preparation.yml",
    )?;
    let package = take_activation_string(input, "packageTreeSha256")?;
    let payload = take_activation_string(input, "payloadMerkleRoot")?;
    take_activation_literal(input, "\"promotionAuthority\":false,")?;
    let archive = take_activation_string(input, "providerArchiveSha256")?;
    take_activation_positive_number(input, "providerArtifactId")?;
    let directory = take_activation_string(input, "providerDirectorySha256")?;
    take_activation_positive_number(input, "providerRunAttempt")?;
    take_activation_positive_number(input, "providerRunId")?;
    let selection = take_activation_string(input, "providerSelectionSha256")?;
    require_activation_string(
        input,
        "providerWorkflowPath",
        ".github/workflows/collection-custody-integration.yml",
    )?;
    take_activation_positive_number(input, "replayCaseCount")?;
    let replay = take_activation_string(input, "replayObservationRootSha256")?;
    take_activation_literal(input, "\"schemaVersion\":1,")?;
    take_activation_positive_number(input, "setCaseCount")?;
    let signature = take_activation_string(input, "signatureTreeSha256")?;
    require_activation_string(
        input,
        "state",
        "reviewed-activation-requires-fresh-collection",
    )?;
    Ok(RetainedActivationProvenance {
        digests: vec![
            integration_proof,
            integration_review,
            outer_archive,
            outer_directory,
            outer_selection,
            package,
            payload,
            archive,
            directory,
            selection,
            replay,
            signature,
        ],
        commits: [historical_candidate, outer_candidate],
    })
}

fn take_activation_literal(input: &mut &str, expected: &str) -> Result<(), String> {
    *input = input
        .strip_prefix(expected)
        .ok_or_else(|| "collection activation provenance is not canonical".to_owned())?;
    Ok(())
}

fn take_activation_string<'a>(input: &mut &'a str, key: &str) -> Result<&'a str, String> {
    take_activation_string_with_suffix(input, key, ",")
}

fn take_activation_final_string<'a>(input: &mut &'a str, key: &str) -> Result<&'a str, String> {
    take_activation_string_with_suffix(input, key, "")
}

fn take_activation_string_with_suffix<'a>(
    input: &mut &'a str,
    key: &str,
    suffix: &str,
) -> Result<&'a str, String> {
    let prefix = format!("\"{key}\":\"");
    take_activation_literal(input, &prefix)?;
    let end = input
        .find('"')
        .ok_or_else(|| format!("collection activation provenance {key} is unterminated"))?;
    let value = &input[..end];
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'\\' | b'"'))
    {
        return Err(format!("collection activation provenance {key} is invalid"));
    }
    *input = &input[end + 1..];
    take_activation_literal(input, suffix)?;
    Ok(value)
}

fn require_activation_string(input: &mut &str, key: &str, expected: &str) -> Result<(), String> {
    if take_activation_string(input, key)? != expected {
        return Err(format!("collection activation provenance {key} differs"));
    }
    Ok(())
}

fn take_activation_positive_number(input: &mut &str, key: &str) -> Result<(), String> {
    take_activation_literal(input, &format!("\"{key}\":"))?;
    let end = input
        .find(',')
        .ok_or_else(|| format!("collection activation provenance {key} is unterminated"))?;
    let digits = &input[..end];
    let number = digits
        .parse::<u64>()
        .map_err(|_| format!("collection activation provenance {key} is invalid"))?;
    if number == 0 || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(format!("collection activation provenance {key} is invalid"));
    }
    *input = &input[end + 1..];
    Ok(())
}

fn require_activation_hex(value: &str, length: usize, label: &str) -> Result<(), String> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not canonical lowercase hexadecimal"));
    }
    Ok(())
}

struct OrdMapObservation {
    target_expression: String,
    typed_value: String,
    stdout: String,
    callbacks: Vec<CallbackInvocationContract>,
    comparators: Vec<ComparatorTraceContract>,
}

type OrdMapCreateFixture = (
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str)],
);

pub(crate) fn runtime_ord_map_boundary_cases() -> Vec<DifferentialCase> {
    const BUILTINS: &[&str] = &[
        "Map.fromList",
        "Map.lookup",
        "Map.insert",
        "Map.delete",
        "Map.insertWith",
        "Map.adjust",
        "Map.unionWith",
    ];
    ord_list_definitions()
        .into_iter()
        .flat_map(|definition| {
            BUILTINS.iter().flat_map(move |builtin| {
                ["empty-input", "singleton-input", "finite-input"]
                    .into_iter()
                    .map({
                        let definition = definition.clone();
                        move |boundary| ord_map_boundary_case(&definition, builtin, boundary)
                    })
            })
        })
        .collect()
}

pub(crate) fn runtime_ord_map_cases() -> Vec<DifferentialCase> {
    let mut cases = runtime_ord_map_boundary_cases();
    cases.extend(runtime_ord_map_auxiliary_cases());
    cases
}

fn ord_map_boundary_case(
    definition: &OrdListDefinition,
    builtin: &str,
    boundary: &str,
) -> DifferentialCase {
    let mut observation = ord_map_boundary_observation(definition, builtin, boundary);
    observation.comparators = ord_map_boundary_comparator_contracts(definition, builtin, boundary);
    ord_map_case_from_observation(definition, builtin, boundary, Some(boundary), observation)
}

fn ord_map_case_from_observation(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    boundary: Option<&str>,
    observation: OrdMapObservation,
) -> DifferentialCase {
    let raw_expression = if builtin == "Map.lookup" {
        observation.target_expression.clone()
    } else {
        format!("Map.toList $ {}", observation.target_expression)
    };
    ord_map_case_from_observation_with_raw(
        definition,
        builtin,
        path,
        boundary,
        observation,
        &raw_expression,
    )
}

fn ord_map_case_from_observation_with_raw(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    boundary: Option<&str>,
    mut observation: OrdMapObservation,
    raw_expression: &str,
) -> DifferentialCase {
    if observation.comparators.is_empty() {
        observation.comparators = reviewed_ord_map_path_comparators(definition, builtin, path);
    }
    let comparator_contracts = observation.comparators.clone();
    let source = format!("{}main = IO.print $ {raw_expression}\n", definition.prelude);
    let callback_builtin = matches!(builtin, "Map.insertWith" | "Map.adjust" | "Map.unionWith");
    let mut descriptor = if let Some(boundary) = boundary {
        if callback_builtin {
            runtime_boundary_descriptor(builtin, boundary, &source, observation.callbacks)
        } else {
            runtime_builtin_boundary_descriptor(builtin, boundary, &source)
        }
    } else {
        let mut descriptor = runtime_single_typed_target_descriptor(builtin, &source);
        descriptor.callback_contracts = callback_builtin
            .then(|| CallbackContract {
                builtin: Arc::from(builtin),
                invocations: observation.callbacks,
            })
            .into_iter()
            .collect();
        descriptor
    };
    let target = &mut descriptor.semantic_targets[0];
    target.expected_instance_target = Some(Arc::from(definition.target));
    target.expected_instance_premises = definition
        .premises
        .iter()
        .map(|(target, premise_count)| crate::InstancePremiseEvidence {
            target: Arc::from(*target),
            premise_count: *premise_count,
        })
        .collect();
    target.expected_comparator_trace_sha256 = Some(crate::comparator_trace_sha256(
        builtin,
        1,
        definition.target,
        &target.expected_instance_premises,
        &comparator_contracts,
    ));
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{}}}",
        observation.typed_value
    );
    target.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    target.expected_raw_presentation_sha256 = Some(crate::raw_presentation_sha256(
        observation.stdout.as_bytes(),
        b"",
    ));
    target.expected_process_status_sha256 = Some(crate::process_status_sha256(true, Some(0)));
    DifferentialCase {
        id: Arc::from(format!(
            "runtime-ord-map-{}-{}-{path}",
            builtin.trim_start_matches("Map.").to_ascii_lowercase(),
            definition.slug,
        )),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        ..DifferentialCase::default()
    }
}

fn reviewed_ord_map_path_comparators(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
) -> Vec<ComparatorTraceContract> {
    if let Some(contracts) = reviewed_special_ord_map_comparators(definition, builtin, path) {
        return contracts;
    }
    let query_only = matches!(builtin, "Map.lookup" | "Map.delete" | "Map.adjust");
    let retained_lower = match (query_only, definition.slug) {
        (true, "tree") => Some(ord_set_retained_tree_lower()),
        (true, "list") => Some(ord_set_retained_list_lower()),
        _ => None,
    };
    let query_lower = retained_lower
        .as_deref()
        .unwrap_or(definition.lower.canonical.as_str());
    let retained_root_lower = if builtin == "Map.lookup" {
        query_lower
    } else {
        definition.lower.canonical.as_str()
    };
    let retained_upper = matches!(builtin, "Map.lookup" | "Map.delete" | "Map.adjust")
        .then(|| retained_ord_map_upper(definition.slug))
        .flatten();
    let query_upper = retained_upper
        .as_deref()
        .unwrap_or(definition.upper.canonical.as_str());
    let retained_root_upper = if builtin == "Map.lookup" {
        query_upper
    } else {
        definition.upper.canonical.as_str()
    };
    reviewed_ord_map_path_comparators_for_values(
        builtin,
        path,
        query_lower,
        retained_root_lower,
        query_upper,
        retained_root_upper,
    )
}

fn reviewed_special_ord_map_comparators(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
) -> Option<Vec<ComparatorTraceContract>> {
    if builtin == "Map.fromList" && definition.slug == "double" && path.starts_with("create-chunk-")
    {
        // The reviewed containers 0.6.8 Map/Set sources share the exact
        // create/go key comparison protocol; the byte-identical 0.7 source is
        // equivalence evidence only. Map values do not participate here.
        return Some(crate::reviewed_set::map_from_list_contracts(path));
    }
    if definition.slug == "double"
        && matches!(
            (builtin, path),
            ("Map.lookup" | "Map.delete", "nan-routing-miss")
                | ("Map.insert", "nan-routing")
                | ("Map.unionWith", "nan-shape-routing")
        )
    {
        return Some(crate::reviewed_set::map_auxiliary_contracts(builtin, path));
    }
    None
}

fn retained_ord_map_upper(slug: &str) -> Option<String> {
    match slug {
        "exit-code" => Some(
            concat!(
                "{\"type\":\"PrimitiveVariant\",\"family\":\"Exit\",",
                "\"constructor\":\"ExitFailure\",\"payloads\":[",
                "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}]}"
            )
            .to_owned(),
        ),
        "maybe" => Some(
            concat!(
                "{\"type\":\"Maybe\",\"payload\":",
                "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}}"
            )
            .to_owned(),
        ),
        "tree" => Some(ord_map_retained_tree_upper()),
        "list" => Some(ord_map_retained_list_upper()),
        _ => None,
    }
}

fn reviewed_ord_map_path_comparators_for_values(
    builtin: &str,
    path: &str,
    query_lower: &str,
    retained_root_lower: &str,
    query_upper: &str,
    retained_root_upper: &str,
) -> Vec<ComparatorTraceContract> {
    let forward = || {
        vec![
            reviewed_comparator_contract(1, "Ord.lt", query_upper, retained_root_lower, false),
            reviewed_comparator_contract(2, "Ord.gt", query_upper, retained_root_lower, true),
        ]
    };
    let reverse = || {
        vec![reviewed_comparator_contract(
            1,
            "Ord.lt",
            query_lower,
            retained_root_upper,
            true,
        )]
    };
    match (builtin, path) {
        ("Map.lookup" | "Map.delete" | "Map.adjust", "nonempty-miss")
        | ("Map.insert" | "Map.insertWith", "nonempty-absent")
        | ("Map.unionWith", "nonempty-disjoint") => forward(),
        ("Map.lookup" | "Map.delete" | "Map.adjust", "nonempty-miss-left")
        | ("Map.insert" | "Map.insertWith", "nonempty-absent-left") => reverse(),
        ("Map.insert", "values-nonforce") | ("Map.delete", "retained-value-nonforce") => {
            let one = ord_list_int(1);
            let three = ord_list_int(3);
            vec![
                reviewed_comparator_contract(1, "Ord.lt", &three, &one, false),
                reviewed_comparator_contract(2, "Ord.gt", &three, &one, true),
            ]
        }
        ("Map.unionWith", "multi-disjoint") => {
            let one = ord_list_int(1);
            let two = ord_list_int(2);
            let three = ord_list_int(3);
            let four = ord_list_int(4);
            vec![
                reviewed_comparator_contract(1, "Ord.lt", &one, &two, true),
                reviewed_comparator_contract(2, "Ord.lt", &three, &four, true),
                reviewed_comparator_contract(3, "Ord.lt", &three, &two, false),
                reviewed_comparator_contract(4, "Ord.gt", &three, &two, true),
            ]
        }
        _ => Vec::new(),
    }
}

fn ord_map_retained_tree_upper() -> String {
    concat!(
        "{\"type\":\"Tree\",\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},",
        "{\"type\":\"List\",\"elements\":[{\"type\":\"Tree\",\"elements\":[",
        "{\"type\":\"Int\",\"value\":\"3\"},{\"type\":\"ForceBoundary\",",
        "\"outcome\":\"not-forced\"}]}],\"terminationHex\":\"6e6f742d666f72636564\"}]}"
    )
    .to_owned()
}

fn ord_map_retained_list_upper() -> String {
    concat!(
        "{\"type\":\"List\",\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},",
        "{\"type\":\"Int\",\"value\":\"3\"}],",
        "\"terminationHex\":\"6e6f742d666f72636564\"}"
    )
    .to_owned()
}

fn ord_map_boundary_comparator_contracts(
    definition: &OrdListDefinition,
    builtin: &str,
    boundary: &str,
) -> Vec<ComparatorTraceContract> {
    let retained_tree_lower =
        (builtin == "Map.lookup" && definition.slug == "tree").then(ord_set_retained_tree_lower);
    let retained_list_lower =
        (builtin == "Map.lookup" && definition.slug == "list").then(ord_set_retained_list_lower);
    let lower = retained_tree_lower
        .as_deref()
        .or(retained_list_lower.as_deref())
        .unwrap_or(definition.lower.canonical.as_str());
    let upper = definition.upper.canonical.as_str();
    match (builtin, boundary) {
        ("Map.fromList", "finite-input") => vec![
            reviewed_comparator_contract(1, "Ord.gt", upper, lower, true),
            reviewed_comparator_contract(2, "Ord.lt", lower, upper, true),
        ],
        (
            "Map.lookup" | "Map.insert" | "Map.delete" | "Map.insertWith" | "Map.adjust"
            | "Map.unionWith",
            "finite-input",
        ) => vec![
            reviewed_comparator_contract(1, "Ord.lt", upper, lower, false),
            reviewed_comparator_contract(2, "Ord.gt", upper, lower, true),
        ],
        _ => Vec::new(),
    }
}

fn ord_map_boundary_observation(
    definition: &OrdListDefinition,
    builtin: &str,
    boundary: &str,
) -> OrdMapObservation {
    match builtin {
        "Map.fromList" => ord_map_from_list_observation(definition, boundary),
        "Map.lookup" => ord_map_lookup_observation(definition, boundary),
        "Map.insert" => ord_map_insert_observation(definition, boundary),
        "Map.delete" => ord_map_delete_observation(definition, boundary),
        "Map.insertWith" => ord_map_insert_with_observation(definition, boundary),
        "Map.adjust" => ord_map_adjust_observation(definition, boundary),
        "Map.unionWith" => ord_map_union_with_observation(definition, boundary),
        _ => unreachable!("Ord/Map builtin inventory is closed"),
    }
}

fn ord_map_from_list_observation(
    definition: &OrdListDefinition,
    boundary: &str,
) -> OrdMapObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let entries = match boundary {
        "empty-input" => Vec::new(),
        "singleton-input" => vec![(lower, "one")],
        "finite-input" => vec![(lower, "low"), (upper, "last")],
        _ => unreachable!("Ord/Map fromList boundary inventory is closed"),
    };
    let input = match boundary {
        "empty-input" => format!("([] :: [({},Text)])", definition.type_expression),
        "singleton-input" => format!("[({},\"one\")]", lower.expression),
        "finite-input" => format!(
            "[({},\"old\"),({},\"low\"),({},\"last\")]",
            upper.expression, lower.expression, upper.expression
        ),
        _ => unreachable!("Ord/Map fromList boundary inventory is closed"),
    };
    ord_map_observation(format!("Map.fromList {input}"), &entries, Vec::new())
}

fn ord_map_lookup_observation(definition: &OrdListDefinition, boundary: &str) -> OrdMapObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let (key, map, result) = match boundary {
        "empty-input" => (
            lower,
            format!(
                "Map.fromList ([] :: [({},Text)])",
                definition.type_expression
            ),
            None,
        ),
        "singleton-input" => (
            lower,
            format!("Map.fromList [({},\"one\")]", lower.expression),
            Some("one"),
        ),
        "finite-input" => (
            upper,
            format!(
                "Map.fromList [({},\"low\"),({},\"upper\")]",
                lower.expression, upper.expression
            ),
            Some("upper"),
        ),
        _ => unreachable!("Ord/Map lookup boundary inventory is closed"),
    };
    let typed_value = result.map_or_else(
        || "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
        |value| {
            format!(
                "{{\"type\":\"Maybe\",\"payload\":{}}}",
                ord_list_text(value)
            )
        },
    );
    let stdout = result.map_or_else(
        || "Nothing\n".to_owned(),
        |value| format!("Just \"{value}\"\n"),
    );
    OrdMapObservation {
        target_expression: format!("Map.lookup ({}) $ {map}", key.expression),
        typed_value,
        stdout,
        callbacks: Vec::new(),
        comparators: Vec::new(),
    }
}

fn ord_map_insert_observation(definition: &OrdListDefinition, boundary: &str) -> OrdMapObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let (key, value, map, entries) = match boundary {
        "empty-input" => (
            lower,
            "new",
            format!(
                "Map.fromList ([] :: [({},Text)])",
                definition.type_expression
            ),
            vec![(lower, "new")],
        ),
        "singleton-input" => (
            lower,
            "new",
            format!("Map.fromList [({},\"old\")]", lower.expression),
            vec![(lower, "new")],
        ),
        "finite-input" => (
            upper,
            "new",
            ord_map_two_entry_source(definition, "low", "old"),
            vec![(lower, "low"), (upper, "new")],
        ),
        _ => unreachable!("Ord/Map insert boundary inventory is closed"),
    };
    ord_map_observation(
        format!("Map.insert ({}) \"{value}\" $ {map}", key.expression),
        &entries,
        Vec::new(),
    )
}

fn ord_map_delete_observation(definition: &OrdListDefinition, boundary: &str) -> OrdMapObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let (key, map, entries) = match boundary {
        "empty-input" => (
            lower,
            format!(
                "Map.fromList ([] :: [({},Text)])",
                definition.type_expression
            ),
            Vec::new(),
        ),
        "singleton-input" => (
            lower,
            format!("Map.fromList [({},\"one\")]", lower.expression),
            Vec::new(),
        ),
        "finite-input" => (
            upper,
            ord_map_two_entry_source(definition, "low", "upper"),
            vec![(lower, "low")],
        ),
        _ => unreachable!("Ord/Map delete boundary inventory is closed"),
    };
    ord_map_observation(
        format!("Map.delete ({}) $ {map}", key.expression),
        &entries,
        Vec::new(),
    )
}

fn ord_map_insert_with_observation(
    definition: &OrdListDefinition,
    boundary: &str,
) -> OrdMapObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let (key, map, entries, callback) = match boundary {
        "empty-input" => (
            lower,
            format!(
                "Map.fromList ([] :: [({},Text)])",
                definition.type_expression
            ),
            vec![(lower, "new")],
            None,
        ),
        "singleton-input" => (
            lower,
            format!("Map.fromList [({},\"old\")]", lower.expression),
            vec![(lower, "newold")],
            Some(("new", "old", "newold")),
        ),
        "finite-input" => (
            upper,
            ord_map_two_entry_source(definition, "low", "old"),
            vec![(lower, "low"), (upper, "newold")],
            Some(("new", "old", "newold")),
        ),
        _ => unreachable!("Ord/Map insertWith boundary inventory is closed"),
    };
    let callbacks = callback
        .map(|(left, right, result)| vec![ord_map_collision_callback(left, right, result)])
        .unwrap_or_default();
    ord_map_observation(
        format!(
            "Map.insertWith (\\new old -> new <> old) ({}) \"new\" $ {map}",
            key.expression
        ),
        &entries,
        callbacks,
    )
}

fn ord_map_adjust_observation(definition: &OrdListDefinition, boundary: &str) -> OrdMapObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let (key, map, entries, callback) = match boundary {
        "empty-input" => (
            lower,
            format!(
                "Map.fromList ([] :: [({},Text)])",
                definition.type_expression
            ),
            Vec::new(),
            None,
        ),
        "singleton-input" => (
            lower,
            format!("Map.fromList [({},\"old\")]", lower.expression),
            vec![(lower, "OLD")],
            Some(("old", "OLD")),
        ),
        "finite-input" => (
            upper,
            ord_map_two_entry_source(definition, "low", "old"),
            vec![(lower, "low"), (upper, "OLD")],
            Some(("old", "OLD")),
        ),
        _ => unreachable!("Ord/Map adjust boundary inventory is closed"),
    };
    let callbacks = callback
        .map(|(argument, result)| vec![ord_map_value_callback(argument, result)])
        .unwrap_or_default();
    ord_map_observation(
        format!("Map.adjust Text.toUpper ({}) $ {map}", key.expression),
        &entries,
        callbacks,
    )
}

fn ord_map_union_with_observation(
    definition: &OrdListDefinition,
    boundary: &str,
) -> OrdMapObservation {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let (left, right, entries, callback) = match boundary {
        "empty-input" => (
            format!(
                "Map.fromList ([] :: [({},Text)])",
                definition.type_expression
            ),
            format!(
                "Map.fromList ([] :: [({},Text)])",
                definition.type_expression
            ),
            Vec::new(),
            None,
        ),
        "singleton-input" => (
            format!("Map.fromList [({},\"left\")]", lower.expression),
            format!("Map.fromList [({},\"right\")]", lower.expression),
            vec![(lower, "leftright")],
            Some(("left", "right", "leftright")),
        ),
        "finite-input" => (
            ord_map_two_entry_source(definition, "low", "left"),
            format!("Map.fromList [({},\"right\")]", upper.expression),
            vec![(lower, "low"), (upper, "leftright")],
            Some(("left", "right", "leftright")),
        ),
        _ => unreachable!("Ord/Map unionWith boundary inventory is closed"),
    };
    let callbacks = callback
        .map(|(left, right, result)| vec![ord_map_collision_callback(left, right, result)])
        .unwrap_or_default();
    ord_map_observation(
        format!("Map.unionWith (\\left right -> left <> right) ({left}) ({right})"),
        &entries,
        callbacks,
    )
}

fn runtime_ord_map_auxiliary_cases() -> Vec<DifferentialCase> {
    let definitions = ord_list_definitions();
    let mut cases = definitions
        .iter()
        .flat_map(runtime_ord_map_required_path_cases)
        .collect::<Vec<_>>();
    cases.extend(
        definitions
            .iter()
            .flat_map(runtime_ord_map_reverse_path_cases),
    );
    cases.extend(runtime_ord_map_integer_shape_cases(&definitions));
    cases.extend(runtime_ord_map_representative_cases(&definitions));
    cases.extend(runtime_ord_map_nan_cases(&definitions));
    cases.extend(runtime_ord_map_nonforce_cases(&definitions));
    cases
}

fn runtime_ord_map_reverse_path_cases(definition: &OrdListDefinition) -> Vec<DifferentialCase> {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let upper_map = format!("Map.fromList [({},\"high\")]", upper.expression);
    let mut cases = vec![ord_map_case_from_observation(
        definition,
        "Map.lookup",
        "nonempty-miss-left",
        None,
        OrdMapObservation {
            target_expression: format!("Map.lookup ({}) $ {upper_map}", lower.expression),
            typed_value: "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
            stdout: "Nothing\n".to_owned(),
            callbacks: Vec::new(),
            comparators: Vec::new(),
        },
    )];
    for (builtin, path, expression) in [
        (
            "Map.insert",
            "nonempty-absent-left",
            format!("Map.insert ({}) \"new\" $ {upper_map}", lower.expression),
        ),
        (
            "Map.insertWith",
            "nonempty-absent-left",
            format!(
                "Map.insertWith (\\new old -> new <> old) ({}) \"new\" $ {upper_map}",
                lower.expression
            ),
        ),
    ] {
        cases.push(ord_map_auxiliary_map_case(
            definition,
            builtin,
            path,
            expression,
            vec![(lower.clone(), "new"), (upper.clone(), "high")],
            Vec::new(),
        ));
    }
    for (builtin, path, expression) in [
        (
            "Map.delete",
            "nonempty-miss-left",
            format!("Map.delete ({}) $ {upper_map}", lower.expression),
        ),
        (
            "Map.adjust",
            "nonempty-miss-left",
            format!(
                "Map.adjust Text.toUpper ({}) $ {upper_map}",
                lower.expression
            ),
        ),
    ] {
        cases.push(ord_map_auxiliary_map_case(
            definition,
            builtin,
            path,
            expression,
            vec![(upper.clone(), "high")],
            Vec::new(),
        ));
    }
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.unionWith",
        "left-singleton-multi-right",
        format!(
            "Map.unionWith (\\left right -> left <> right) (Map.fromList [({},\"left\")]) ({})",
            lower.expression,
            ord_map_two_entry_source(definition, "right-low", "right-high")
        ),
        vec![
            (lower.clone(), "leftright-low"),
            (upper.clone(), "right-high"),
        ],
        vec![ord_map_collision_callback(
            "left",
            "right-low",
            "leftright-low",
        )],
    ));
    cases
}

fn runtime_ord_map_integer_shape_cases(definitions: &[OrdListDefinition]) -> Vec<DifferentialCase> {
    let definition = definitions
        .iter()
        .find(|definition| definition.slug == "int")
        .expect("Ord Int definition exists");
    vec![
        ord_map_auxiliary_map_case(
            definition,
            "Map.delete",
            "two-child-interior",
            "Map.delete (4 :: Int) $ Map.fromList [(1,\"1\"),(2,\"2\"),(3,\"3\"),(4,\"4\"),(5,\"5\"),(6,\"6\"),(7,\"7\")]".to_owned(),
            [1, 2, 3, 5, 6, 7]
                .into_iter()
                .map(|key| (ord_set_int_value(key), match key {
                    1 => "1",
                    2 => "2",
                    3 => "3",
                    5 => "5",
                    6 => "6",
                    7 => "7",
                    _ => unreachable!(),
                }))
                .collect(),
            Vec::new(),
        ),
        ord_map_auxiliary_map_case(
            definition,
            "Map.unionWith",
            "multi-disjoint",
            concat!(
                "Map.unionWith (\\left right -> left <> right) ",
                "(Map.fromList [(1,\"1\"),(3,\"3\")]) ",
                "(Map.fromList [(2,\"2\"),(4,\"4\")])",
            )
            .to_owned(),
            [1, 2, 3, 4]
                .into_iter()
                .map(|key| (ord_set_int_value(key), match key {
                    1 => "1",
                    2 => "2",
                    3 => "3",
                    4 => "4",
                    _ => unreachable!(),
                }))
                .collect(),
            Vec::new(),
        ),
    ]
}

fn runtime_ord_map_required_path_cases(definition: &OrdListDefinition) -> Vec<DifferentialCase> {
    let lower = &definition.lower;
    let upper = &definition.upper;
    let lower_map = format!("Map.fromList [({},\"low\")]", lower.expression);
    let two_entry_map = ord_map_two_entry_source(definition, "left-low", "left-high");
    let mut cases = vec![ord_map_case_from_observation(
        definition,
        "Map.lookup",
        "nonempty-miss",
        None,
        OrdMapObservation {
            target_expression: format!("Map.lookup ({}) $ {lower_map}", upper.expression),
            typed_value: "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
            stdout: "Nothing\n".to_owned(),
            callbacks: Vec::new(),
            comparators: Vec::new(),
        },
    )];
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.insert",
        "nonempty-absent",
        format!("Map.insert ({}) \"new\" $ {lower_map}", upper.expression),
        vec![(lower.clone(), "low"), (upper.clone(), "new")],
        Vec::new(),
    ));
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.delete",
        "nonempty-miss",
        format!("Map.delete ({}) $ {lower_map}", upper.expression),
        vec![(lower.clone(), "low")],
        Vec::new(),
    ));
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.insertWith",
        "nonempty-absent",
        format!(
            "Map.insertWith (\\new old -> new <> old) ({}) \"new\" $ {lower_map}",
            upper.expression
        ),
        vec![(lower.clone(), "low"), (upper.clone(), "new")],
        Vec::new(),
    ));
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.adjust",
        "nonempty-miss",
        format!(
            "Map.adjust Text.toUpper ({}) $ {lower_map}",
            upper.expression
        ),
        vec![(lower.clone(), "low")],
        Vec::new(),
    ));
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.unionWith",
        "nonempty-disjoint",
        format!(
            "Map.unionWith (\\left right -> left <> right) ({lower_map}) (Map.fromList [({},\"right\")])",
            upper.expression
        ),
        vec![(lower.clone(), "low"), (upper.clone(), "right")],
        Vec::new(),
    ));
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.unionWith",
        "multi-collision",
        format!(
            "Map.unionWith (\\left right -> left <> right) ({two_entry_map}) ({})",
            ord_map_two_entry_source(definition, "right-low", "right-high")
        ),
        vec![
            (lower.clone(), "left-lowright-low"),
            (upper.clone(), "left-highright-high"),
        ],
        vec![
            ord_map_collision_callback("left-low", "right-low", "left-lowright-low"),
            ord_map_collision_callback("left-high", "right-high", "left-highright-high"),
        ],
    ));
    cases
}

fn ord_map_auxiliary_map_case(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    target_expression: String,
    entries: Vec<(OrdListValue, &'static str)>,
    callbacks: Vec<CallbackInvocationContract>,
) -> DifferentialCase {
    let observation = ord_map_owned_observation(target_expression, entries, callbacks);
    ord_map_case_from_observation(definition, builtin, path, None, observation)
}

fn ord_map_owned_observation(
    target_expression: String,
    entries: Vec<(OrdListValue, &'static str)>,
    callbacks: Vec<CallbackInvocationContract>,
) -> OrdMapObservation {
    let mut canonical_entries = Vec::with_capacity(entries.len());
    let mut rendered_entries = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        canonical_entries.push(format!(
            "{{\"key\":{},\"value\":{}}}",
            key.canonical,
            ord_list_text(value)
        ));
        rendered_entries.push(format!("({},\"{value}\")", key.rendered));
    }
    OrdMapObservation {
        target_expression,
        typed_value: format!(
            "{{\"type\":\"Map\",\"entries\":[{}]}}",
            canonical_entries.join(",")
        ),
        stdout: format!("[{}]\n", rendered_entries.join(",")),
        callbacks,
        comparators: Vec::new(),
    }
}

fn runtime_ord_map_representative_cases(
    definitions: &[OrdListDefinition],
) -> Vec<DifferentialCase> {
    let ci = definitions
        .iter()
        .find(|definition| definition.slug == "ci")
        .expect("Ord CI definition exists");
    let mut double = definitions
        .iter()
        .find(|definition| definition.slug == "double")
        .expect("Ord Double definition exists")
        .clone();
    double.prelude = ORD_SET_DOUBLE_PRELUDE;
    let mut cases = runtime_ord_map_ci_representative_cases(ci);
    cases.extend(runtime_ord_map_double_representative_cases(&double));
    cases.extend([
        ord_map_auxiliary_map_case(
            ci,
            "Map.unionWith",
            "ci-left-representative",
            concat!(
                "Map.unionWith (\\left right -> left <> right) ",
                "(Map.fromList [(CI.mk \"AbC\",\"left\")]) ",
                "(Map.fromList [(CI.mk \"aBc\",\"right\")])",
            )
            .to_owned(),
            vec![(ord_list_ci_value("AbC"), "leftright")],
            vec![ord_map_collision_callback("left", "right", "leftright")],
        ),
        ord_map_auxiliary_map_case(
            &double,
            "Map.unionWith",
            "signed-zero-left-representative",
            concat!(
                "Map.unionWith (\\left right -> left <> right) ",
                "(Map.fromList [(Main.negativeZero,\"left\")]) ",
                "(Map.fromList [(0.0,\"right\")])",
            )
            .to_owned(),
            vec![(
                ord_list_double_value("Main.negativeZero", "-0.0", "8000000000000000"),
                "leftright",
            )],
            vec![ord_map_collision_callback("left", "right", "leftright")],
        ),
    ]);
    cases
}

fn runtime_ord_map_ci_representative_cases(
    definition: &OrdListDefinition,
) -> Vec<DifferentialCase> {
    let old_key = || ord_list_ci_value("AbC");
    let new_key = || ord_list_ci_value("aBc");
    vec![
        ord_map_auxiliary_map_case(
            definition,
            "Map.fromList",
            "equal-representative-later",
            "Map.fromList [(CI.mk \"AbC\",\"old\"),(CI.mk \"aBc\",\"new\")]".to_owned(),
            vec![(new_key(), "new")],
            Vec::new(),
        ),
        ord_map_auxiliary_map_case(
            definition,
            "Map.insert",
            "equal-representative-new-key",
            "Map.insert (CI.mk \"aBc\") \"new\" $ Map.fromList [(CI.mk \"AbC\",\"old\")]"
                .to_owned(),
            vec![(new_key(), "new")],
            Vec::new(),
        ),
        ord_map_auxiliary_map_case(
            definition,
            "Map.insertWith",
            "equal-representative-new-key",
            concat!(
                "Map.insertWith (\\new old -> new <> old) (CI.mk \"aBc\") \"new\" $ ",
                "Map.fromList [(CI.mk \"AbC\",\"old\")]",
            )
            .to_owned(),
            vec![(new_key(), "newold")],
            vec![ord_map_collision_callback("new", "old", "newold")],
        ),
        ord_map_auxiliary_map_case(
            definition,
            "Map.adjust",
            "equivalent-query-preserves-old-key",
            concat!(
                "Map.adjust Text.toUpper (CI.mk \"aBc\") $ ",
                "Map.fromList [(CI.mk \"AbC\",\"old\")]",
            )
            .to_owned(),
            vec![(old_key(), "OLD")],
            vec![ord_map_value_callback("old", "OLD")],
        ),
        ord_map_lookup_representative_case(
            definition,
            "equivalent-query",
            "Map.lookup (CI.mk \"aBc\") $ Map.fromList [(CI.mk \"AbC\",\"old\")]",
            "old",
        ),
        ord_map_auxiliary_map_case(
            definition,
            "Map.delete",
            "equivalent-query",
            "Map.delete (CI.mk \"aBc\") $ Map.fromList [(CI.mk \"AbC\",\"old\")]".to_owned(),
            Vec::new(),
            Vec::new(),
        ),
    ]
}

fn runtime_ord_map_double_representative_cases(
    definition: &OrdListDefinition,
) -> Vec<DifferentialCase> {
    let negative_zero = || ord_list_double_value("Main.negativeZero", "-0.0", "8000000000000000");
    let positive_zero = || ord_list_double_value("0.0", "0.0", "0000000000000000");
    vec![
        ord_map_auxiliary_map_case(
            definition,
            "Map.fromList",
            "signed-zero-representative-later",
            "Map.fromList [(Main.negativeZero,\"old\"),(0.0,\"new\")]".to_owned(),
            vec![(positive_zero(), "new")],
            Vec::new(),
        ),
        ord_map_auxiliary_map_case(
            definition,
            "Map.insert",
            "signed-zero-representative-new-key",
            "Map.insert 0.0 \"new\" $ Map.fromList [(Main.negativeZero,\"old\")]".to_owned(),
            vec![(positive_zero(), "new")],
            Vec::new(),
        ),
        ord_map_auxiliary_map_case(
            definition,
            "Map.insertWith",
            "signed-zero-representative-new-key",
            concat!(
                "Map.insertWith (\\new old -> new <> old) 0.0 \"new\" $ ",
                "Map.fromList [(Main.negativeZero,\"old\")]",
            )
            .to_owned(),
            vec![(positive_zero(), "newold")],
            vec![ord_map_collision_callback("new", "old", "newold")],
        ),
        ord_map_auxiliary_map_case(
            definition,
            "Map.adjust",
            "signed-zero-query-preserves-old-key",
            concat!(
                "Map.adjust Text.toUpper 0.0 $ ",
                "Map.fromList [(Main.negativeZero,\"old\")]",
            )
            .to_owned(),
            vec![(negative_zero(), "OLD")],
            vec![ord_map_value_callback("old", "OLD")],
        ),
        ord_map_lookup_representative_case(
            definition,
            "signed-zero-equivalent-query",
            "Map.lookup 0.0 $ Map.fromList [(Main.negativeZero,\"old\")]",
            "old",
        ),
        ord_map_auxiliary_map_case(
            definition,
            "Map.delete",
            "signed-zero-equivalent-query",
            "Map.delete 0.0 $ Map.fromList [(Main.negativeZero,\"old\")]".to_owned(),
            Vec::new(),
            Vec::new(),
        ),
    ]
}

fn ord_map_lookup_representative_case(
    definition: &OrdListDefinition,
    path: &str,
    expression: &str,
    result: &str,
) -> DifferentialCase {
    ord_map_case_from_observation(
        definition,
        "Map.lookup",
        path,
        None,
        OrdMapObservation {
            target_expression: expression.to_owned(),
            typed_value: format!(
                "{{\"type\":\"Maybe\",\"payload\":{}}}",
                ord_list_text(result)
            ),
            stdout: format!("Just \"{result}\"\n"),
            callbacks: Vec::new(),
            comparators: Vec::new(),
        },
    )
}

fn runtime_ord_map_nonforce_cases(definitions: &[OrdListDefinition]) -> Vec<DifferentialCase> {
    let definition = definitions
        .iter()
        .find(|definition| definition.slug == "int")
        .expect("Ord Int definition exists");
    let bottom = "(Error.error \"value\" :: Text)";
    let one_entry = format!("Map.fromList [((1 :: Int),{bottom})]");
    let two_entries = format!("Map.fromList [((1 :: Int),{bottom}),((3 :: Int),{bottom})]");
    vec![
        ord_map_nonforce_case(
            definition,
            "Map.fromList",
            "value-nonforce",
            one_entry.clone(),
            ord_map_nonforce_typed(&[1]),
            &format!("Map.keys $ {one_entry}"),
            "[1]\n",
        ),
        ord_map_nonforce_case(
            definition,
            "Map.lookup",
            "just-payload-nonforce",
            format!("Map.lookup (1 :: Int) $ {one_entry}"),
            format!(
                "{{\"type\":\"Maybe\",\"payload\":{}}}",
                ord_map_not_forced()
            ),
            &format!(
                "Maybe.maybe Bool.False (\\_ -> Bool.True) $ Map.lookup (1 :: Int) $ {one_entry}"
            ),
            "True\n",
        ),
        ord_map_nonforce_case(
            definition,
            "Map.insert",
            "values-nonforce",
            format!("Map.insert (3 :: Int) {bottom} $ {one_entry}"),
            ord_map_nonforce_typed(&[1, 3]),
            &format!("Map.keys $ Map.insert (3 :: Int) {bottom} $ {one_entry}"),
            "[1,3]\n",
        ),
        ord_map_nonforce_case(
            definition,
            "Map.delete",
            "retained-value-nonforce",
            format!("Map.delete (3 :: Int) $ {two_entries}"),
            ord_map_nonforce_typed(&[1]),
            &format!("Map.keys $ Map.delete (3 :: Int) $ {two_entries}"),
            "[1]\n",
        ),
        ord_map_nonforce_case(
            definition,
            "Map.insertWith",
            "callback-result-nonforce",
            format!("Map.insertWith (\\_ _ -> {bottom}) (1 :: Int) {bottom} $ {one_entry}"),
            ord_map_nonforce_typed(&[1]),
            &format!(
                "Map.keys $ Map.insertWith (\\_ _ -> {bottom}) (1 :: Int) {bottom} $ {one_entry}"
            ),
            "[1]\n",
        ),
        ord_map_nonforce_case(
            definition,
            "Map.adjust",
            "callback-result-nonforce",
            format!("Map.adjust (\\_ -> {bottom}) (1 :: Int) $ {one_entry}"),
            ord_map_nonforce_typed(&[1]),
            &format!("Map.keys $ Map.adjust (\\_ -> {bottom}) (1 :: Int) $ {one_entry}"),
            "[1]\n",
        ),
        ord_map_nonforce_case(
            definition,
            "Map.unionWith",
            "callback-result-nonforce",
            format!("Map.unionWith (\\_ _ -> {bottom}) ({one_entry}) ({one_entry})"),
            ord_map_nonforce_typed(&[1]),
            &format!("Map.keys $ Map.unionWith (\\_ _ -> {bottom}) ({one_entry}) ({one_entry})"),
            "[1]\n",
        ),
    ]
}

fn ord_map_nonforce_case(
    definition: &OrdListDefinition,
    builtin: &str,
    path: &str,
    target_expression: String,
    typed_value: String,
    raw_expression: &str,
    stdout: &str,
) -> DifferentialCase {
    let mut case = ord_map_case_from_observation_with_raw(
        definition,
        builtin,
        path,
        None,
        OrdMapObservation {
            target_expression,
            typed_value,
            stdout: stdout.to_owned(),
            callbacks: Vec::new(),
            comparators: Vec::new(),
        },
        raw_expression,
    );
    let exit_states: &[(u16, &str)] = match builtin {
        "Map.insert" => &[(0, "value"), (1, "not-forced")],
        "Map.insertWith" => &[(0, "not-forced"), (1, "value"), (2, "not-forced")],
        "Map.adjust" => &[(0, "not-forced"), (1, "value")],
        "Map.unionWith" => &[(0, "not-forced")],
        _ => &[],
    };
    if !exit_states.is_empty() {
        case.claim_evidence.as_mut().unwrap().semantic_targets[0]
            .expected_lazy_argument_exit_sha256 = Some(crate::lazy_argument_exit_sha256(
            exit_states.iter().copied(),
        ));
    }
    case
}

fn ord_map_not_forced() -> &'static str {
    "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}"
}

fn ord_map_nonforce_typed(keys: &[i64]) -> String {
    format!(
        "{{\"type\":\"Map\",\"entries\":[{}]}}",
        keys.iter()
            .map(|key| format!(
                "{{\"key\":{},\"value\":{}}}",
                ord_list_int(*key),
                ord_map_not_forced()
            ))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn runtime_ord_map_nan_cases(definitions: &[OrdListDefinition]) -> Vec<DifferentialCase> {
    let mut definition = definitions
        .iter()
        .find(|definition| definition.slug == "double")
        .expect("Ord Double definition exists")
        .clone();
    definition.prelude = ORD_SET_DOUBLE_PRELUDE;
    let mut cases = runtime_ord_map_nan_create_cases(&definition);
    cases.extend(runtime_ord_map_nan_context_cases(&definition));
    cases
}

fn runtime_ord_map_nan_context_cases(definition: &OrdListDefinition) -> Vec<DifferentialCase> {
    const BASE: &str = concat!(
        "Map.fromList [(Main.nan,\"na\"),(1.0,\"1a\"),(1.0,\"1b\"),",
        "(Main.nan,\"nb\"),(0.0,\"0\"),(Main.nan,\"nc\"),",
        "(2.0,\"2a\"),(2.0,\"2b\"),(3.0,\"3\")]",
    );
    let base_entries = || {
        [
            ("nan", "na"),
            ("0", "0"),
            ("1", "1b"),
            ("nan", "nb"),
            ("nan", "nc"),
            ("2", "2b"),
            ("3", "3"),
        ]
        .into_iter()
        .map(|(key, value)| (ord_set_named_double_value(key), value))
        .collect::<Vec<_>>()
    };
    let mut cases = vec![ord_map_case_from_observation(
        definition,
        "Map.lookup",
        "nan-routing-miss",
        None,
        OrdMapObservation {
            target_expression: format!("Map.lookup Main.nan $ {BASE}"),
            typed_value: "{\"type\":\"Maybe\",\"payload\":null}".to_owned(),
            stdout: "Nothing\n".to_owned(),
            callbacks: Vec::new(),
            comparators: Vec::new(),
        },
    )];
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.delete",
        "nan-routing-miss",
        format!("Map.delete Main.nan $ {BASE}"),
        base_entries(),
        Vec::new(),
    ));
    let mut inserted = base_entries();
    inserted.push((ord_set_named_double_value("nan"), "NI"));
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.insert",
        "nan-routing",
        format!("Map.insert Main.nan \"NI\" $ {BASE}"),
        inserted,
        Vec::new(),
    ));
    cases.push(ord_map_auxiliary_map_case(
        definition,
        "Map.unionWith",
        "nan-shape-routing",
        format!(
            "Map.unionWith (\\left right -> left <> right) ({BASE}) (Map.fromList [(2.0,\"R2\"),(Main.nan,\"RN\"),(9.0,\"R9\")])"
        ),
        [
            ("2", "R2"),
            ("nan", "RN"),
            ("nan", "na"),
            ("0", "0"),
            ("1", "1b"),
            ("nan", "nb"),
            ("nan", "nc"),
            ("2", "2b"),
            ("3", "3"),
            ("9", "R9"),
        ]
        .into_iter()
        .map(|(key, value)| (ord_set_named_double_value(key), value))
        .collect(),
        Vec::new(),
    ));
    cases
}

fn runtime_ord_map_nan_create_cases(definition: &OrdListDefinition) -> Vec<DifferentialCase> {
    const CASES: &[OrdMapCreateFixture] = &[
        (
            "create-chunk-1",
            "[(1.0,\"1a\"),(1.0,\"1b\"),(2.0,\"2\"),(3.0,\"3\"),(Main.nan,\"na\"),(4.0,\"4\"),(5.0,\"5\"),(Main.nan,\"nb\"),(6.0,\"6\"),(0.0,\"0\")]",
            &[
                ("1", "1b"),
                ("2", "2"),
                ("3", "3"),
                ("nan", "na"),
                ("0", "0"),
                ("4", "4"),
                ("5", "5"),
                ("nan", "nb"),
                ("6", "6"),
            ],
        ),
        (
            "create-chunk-2",
            "[(1.0,\"1\"),(2.0,\"2a\"),(2.0,\"2b\"),(3.0,\"3\"),(4.0,\"4\"),(Main.nan,\"n\"),(5.0,\"5\"),(6.0,\"6\"),(7.0,\"7\"),(0.0,\"0\")]",
            &[
                ("0", "0"),
                ("1", "1"),
                ("2", "2b"),
                ("3", "3"),
                ("4", "4"),
                ("nan", "n"),
                ("5", "5"),
                ("6", "6"),
                ("7", "7"),
            ],
        ),
        (
            "create-chunk-3",
            "[(1.0,\"1\"),(2.0,\"2\"),(3.0,\"3\"),(4.0,\"4a\"),(4.0,\"4b\"),(5.0,\"5\"),(6.0,\"6\"),(Main.nan,\"n\"),(7.0,\"7\"),(8.0,\"8\"),(0.0,\"0\")]",
            &[
                ("0", "0"),
                ("1", "1"),
                ("2", "2"),
                ("3", "3"),
                ("4", "4b"),
                ("5", "5"),
                ("6", "6"),
                ("nan", "n"),
                ("7", "7"),
                ("8", "8"),
            ],
        ),
        (
            "create-chunk-4",
            "[(1.0,\"1\"),(2.0,\"2\"),(3.0,\"3\"),(4.0,\"4\"),(0.0,\"0\"),(Main.nan,\"n\"),(5.0,\"5\"),(6.0,\"6\")]",
            &[
                ("0", "0"),
                ("1", "1"),
                ("2", "2"),
                ("3", "3"),
                ("4", "4"),
                ("nan", "n"),
                ("5", "5"),
                ("6", "6"),
            ],
        ),
        (
            "create-chunk-5",
            "[(Main.nan,\"na\"),(1.0,\"1a\"),(1.0,\"1b\"),(Main.nan,\"nb\"),(0.0,\"0\"),(Main.nan,\"nc\"),(2.0,\"2a\"),(2.0,\"2b\"),(3.0,\"3\")]",
            &[
                ("nan", "na"),
                ("0", "0"),
                ("1", "1b"),
                ("nan", "nb"),
                ("nan", "nc"),
                ("2", "2b"),
                ("3", "3"),
            ],
        ),
    ];
    CASES
        .iter()
        .map(|(path, input, entries)| {
            ord_map_auxiliary_map_case(
                definition,
                "Map.fromList",
                path,
                format!("Map.fromList {input}"),
                entries
                    .iter()
                    .map(|(key, value)| (ord_set_named_double_value(key), *value))
                    .collect(),
                Vec::new(),
            )
        })
        .collect()
}

fn ord_map_two_entry_source(
    definition: &OrdListDefinition,
    lower_value: &str,
    upper_value: &str,
) -> String {
    format!(
        "Map.fromList [({},\"{lower_value}\"),({},\"{upper_value}\")]",
        definition.lower.expression, definition.upper.expression
    )
}

fn ord_map_observation(
    target_expression: String,
    entries: &[(&OrdListValue, &str)],
    callbacks: Vec<CallbackInvocationContract>,
) -> OrdMapObservation {
    let typed_value = format!(
        "{{\"type\":\"Map\",\"entries\":[{}]}}",
        entries
            .iter()
            .map(|(key, value)| format!(
                "{{\"key\":{},\"value\":{}}}",
                key.canonical,
                ord_list_text(value)
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let stdout = format!(
        "[{}]\n",
        entries
            .iter()
            .map(|(key, value)| format!("({},\"{value}\")", key.rendered))
            .collect::<Vec<_>>()
            .join(",")
    );
    OrdMapObservation {
        target_expression,
        typed_value,
        stdout,
        callbacks,
        comparators: Vec::new(),
    }
}

fn ord_map_collision_callback(left: &str, right: &str, result: &str) -> CallbackInvocationContract {
    let left = ord_list_text(left);
    let right = ord_list_text(right);
    let result = ord_list_text(result);
    callback_contract_invocation(0, "collision", &[&left, &right], &result)
}

fn ord_map_value_callback(argument: &str, result: &str) -> CallbackInvocationContract {
    let argument = ord_list_text(argument);
    let result = ord_list_text(result);
    callback_contract_invocation(0, "value", &[&argument], &result)
}

const RUNTIME_MAP_SET_BOUNDARIES: &[(&str, [&str; 3])] = &[
    (
        "Map.fromList",
        [
            "main = IO.print $ Map.toList $ Map.fromList ([] :: [(Int,Text)])\n",
            "main = IO.print $ Map.toList $ Map.fromList [(1,\"a\")]\n",
            "main = IO.print $ Map.toList $ Map.fromList [(1,\"a\"),(2,\"b\")]\n",
        ],
    ),
    (
        "Map.size",
        [
            "main = IO.print $ Map.size $ Map.fromList ([] :: [(Int,Text)])\n",
            "main = IO.print $ Map.size $ Map.fromList [(1,\"a\")]\n",
            "main = IO.print $ Map.size $ Map.fromList [(1,\"a\"),(2,\"b\")]\n",
        ],
    ),
    (
        "Map.lookup",
        [
            "main = IO.print $ Map.lookup 1 $ Map.fromList ([] :: [(Int,Text)])\n",
            "main = IO.print $ Map.lookup 1 $ Map.fromList [(1,\"a\")]\n",
            "main = IO.print $ Map.lookup 2 $ Map.fromList [(1,\"a\"),(2,\"b\")]\n",
        ],
    ),
    (
        "Map.insert",
        [
            "main = IO.print $ Map.toList $ Map.insert 1 \"a\" $ Map.fromList ([] :: [(Int,Text)])\n",
            "main = IO.print $ Map.toList $ Map.insert 2 \"b\" $ Map.fromList [(1,\"a\")]\n",
            "main = IO.print $ Map.toList $ Map.insert 3 \"c\" $ Map.fromList [(1,\"a\"),(2,\"b\")]\n",
        ],
    ),
    (
        "Map.delete",
        [
            "main = IO.print $ Map.toList $ Map.delete 1 $ Map.fromList ([] :: [(Int,Text)])\n",
            "main = IO.print $ Map.toList $ Map.delete 1 $ Map.fromList [(1,\"a\")]\n",
            "main = IO.print $ Map.toList $ Map.delete 2 $ Map.fromList [(1,\"a\"),(2,\"b\")]\n",
        ],
    ),
    (
        "Map.keys",
        [
            "main = IO.print $ Map.keys $ Map.fromList ([] :: [(Int,Text)])\n",
            "main = IO.print $ Map.keys $ Map.fromList [(1,\"a\")]\n",
            "main = IO.print $ Map.keys $ Map.fromList [(1,\"a\"),(2,\"b\")]\n",
        ],
    ),
    (
        "Map.elems",
        [
            "main = IO.print $ Map.elems $ Map.fromList ([] :: [(Int,Text)])\n",
            "main = IO.print $ Map.elems $ Map.fromList [(1,\"a\")]\n",
            "main = IO.print $ Map.elems $ Map.fromList [(1,\"a\"),(2,\"b\")]\n",
        ],
    ),
    (
        "Map.toList",
        [
            "main = IO.print $ Map.toList $ Map.fromList ([] :: [(Int,Text)])\n",
            "main = IO.print $ Map.toList $ Map.fromList [(1,\"a\")]\n",
            "main = IO.print $ Map.toList $ Map.fromList [(1,\"a\"),(2,\"b\")]\n",
        ],
    ),
    (
        "Set.fromList",
        [
            "main = IO.print $ Set.toList $ Set.fromList ([] :: [Int])\n",
            "main = IO.print $ Set.toList $ Set.fromList [1]\n",
            "main = IO.print $ Set.toList $ Set.fromList [2,1]\n",
        ],
    ),
    (
        "Set.size",
        [
            "main = IO.print $ Set.size $ Set.fromList ([] :: [Int])\n",
            "main = IO.print $ Set.size $ Set.fromList [1]\n",
            "main = IO.print $ Set.size $ Set.fromList [2,1]\n",
        ],
    ),
    (
        "Set.member",
        [
            "main = IO.print $ Set.member 1 $ Set.fromList ([] :: [Int])\n",
            "main = IO.print $ Set.member 1 $ Set.fromList [1]\n",
            "main = IO.print $ Set.member 2 $ Set.fromList [1,2]\n",
        ],
    ),
    (
        "Set.insert",
        [
            "main = IO.print $ Set.toList $ Set.insert 1 $ Set.fromList ([] :: [Int])\n",
            "main = IO.print $ Set.toList $ Set.insert 2 $ Set.fromList [1]\n",
            "main = IO.print $ Set.toList $ Set.insert 3 $ Set.fromList [1,2]\n",
        ],
    ),
    (
        "Set.delete",
        [
            "main = IO.print $ Set.toList $ Set.delete 1 $ Set.fromList ([] :: [Int])\n",
            "main = IO.print $ Set.toList $ Set.delete 1 $ Set.fromList [1]\n",
            "main = IO.print $ Set.toList $ Set.delete 2 $ Set.fromList [1,2]\n",
        ],
    ),
    (
        "Set.toList",
        [
            "main = IO.print $ Set.toList $ Set.fromList ([] :: [Int])\n",
            "main = IO.print $ Set.toList $ Set.fromList [1]\n",
            "main = IO.print $ Set.toList $ Set.fromList [2,1]\n",
        ],
    ),
    (
        "Set.union",
        [
            "main = IO.print $ Set.toList $ Set.union (Set.fromList ([] :: [Int])) (Set.fromList [])\n",
            "main = IO.print $ Set.toList $ Set.union (Set.fromList [1]) (Set.fromList [])\n",
            "main = IO.print $ Set.toList $ Set.union (Set.fromList [1]) (Set.fromList [2])\n",
        ],
    ),
    (
        "Set.difference",
        [
            "main = IO.print $ Set.toList $ Set.difference (Set.fromList ([] :: [Int])) (Set.fromList [])\n",
            "main = IO.print $ Set.toList $ Set.difference (Set.fromList [1]) (Set.fromList [])\n",
            "main = IO.print $ Set.toList $ Set.difference (Set.fromList [1,2]) (Set.fromList [2])\n",
        ],
    ),
    (
        "Set.intersection",
        [
            "main = IO.print $ Set.toList $ Set.intersection (Set.fromList ([] :: [Int])) (Set.fromList [])\n",
            "main = IO.print $ Set.toList $ Set.intersection (Set.fromList [1]) (Set.fromList [1])\n",
            "main = IO.print $ Set.toList $ Set.intersection (Set.fromList [1,2]) (Set.fromList [2,3])\n",
        ],
    ),
    (
        "Vector.fromList",
        [
            "main = IO.print $ Vector.toList $ Vector.fromList ([] :: [Int])\n",
            "main = IO.print $ Vector.toList $ Vector.fromList [1]\n",
            "main = IO.print $ Vector.toList $ Vector.fromList [1,2]\n",
        ],
    ),
    (
        "Vector.toList",
        [
            "main = IO.print $ Vector.toList $ Vector.fromList ([] :: [Int])\n",
            "main = IO.print $ Vector.toList $ Vector.fromList [1]\n",
            "main = IO.print $ Vector.toList $ Vector.fromList [1,2]\n",
        ],
    ),
];

fn runtime_map_set_boundary_cases() -> Vec<DifferentialCase> {
    RUNTIME_MAP_SET_BOUNDARIES
        .iter()
        .flat_map(|(builtin, sources)| {
            ["empty-input", "singleton-input", "finite-input"]
                .into_iter()
                .zip(*sources)
                .map(move |(boundary, source)| {
                    let mut descriptor =
                        runtime_builtin_boundary_descriptor(builtin, boundary, source);
                    if crate::runtime_obligations::collection_comparator_sensitive(builtin) {
                        let records = legacy_collection_boundary_comparators(builtin, boundary);
                        for target in &mut descriptor.semantic_targets {
                            target.expected_instance_target = Some(Arc::from("Int"));
                            target.expected_comparator_trace_sha256 = Some(
                                crate::comparator_trace_sha256(builtin, 1, "Int", &[], &records),
                            );
                        }
                    }
                    DifferentialCase {
                        id: Arc::from(format!(
                            "{}-boundary-{boundary}",
                            builtin.to_ascii_lowercase().replace('.', "-")
                        )),
                        source: Arc::from(source),
                        claim_evidence: Some(descriptor),
                        ..DifferentialCase::default()
                    }
                })
        })
        .collect()
}

fn legacy_collection_boundary_comparators(
    builtin: &str,
    boundary: &str,
) -> Vec<ComparatorTraceContract> {
    let one = ord_list_int(1);
    let two = ord_list_int(2);
    let three = ord_list_int(3);
    let compare = |ordinal, left: &str, right: &str, comparator, result| {
        reviewed_comparator_contract(ordinal, comparator, left, right, result)
    };
    match (builtin, boundary) {
        ("Map.fromList", "finite-input") => {
            vec![compare(1, &one, &two, "Ord.gt", false)]
        }
        ("Set.fromList", "finite-input") => vec![
            compare(1, &two, &one, "Ord.gt", true),
            compare(2, &one, &two, "Ord.lt", true),
        ],
        (
            "Map.lookup" | "Map.delete" | "Set.member" | "Set.delete" | "Set.difference"
            | "Set.union",
            "finite-input",
        )
        | ("Map.insert" | "Set.insert", "singleton-input") => vec![
            compare(1, &two, &one, "Ord.lt", false),
            compare(2, &two, &one, "Ord.gt", true),
        ],
        ("Map.insert" | "Set.insert", "finite-input") => vec![
            compare(1, &three, &one, "Ord.lt", false),
            compare(2, &three, &one, "Ord.gt", true),
            compare(3, &three, &two, "Ord.lt", false),
            compare(4, &three, &two, "Ord.gt", true),
        ],
        ("Set.intersection", "finite-input") => vec![
            compare(1, &one, &two, "Ord.lt", true),
            compare(2, &two, &three, "Ord.lt", true),
        ],
        _ => Vec::new(),
    }
}

fn runtime_remaining_list_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = Vec::new();
    push_predicate_boundary_cases(
        &mut cases,
        "List.dropWhile",
        [
            "main = IO.print $ List.dropWhile (\\x -> Ord.lt x 2) []\n",
            "main = IO.print $ List.dropWhile (\\x -> Ord.lt x 2) [1]\n",
            "main = IO.print $ List.dropWhile (\\x -> Ord.lt x 2) [1,2]\n",
        ],
        &[("1", true)],
        &[("1", true), ("2", false)],
    );
    push_predicate_boundary_cases(
        &mut cases,
        "List.findIndex",
        [
            "main = IO.print $ List.findIndex (Int.eq 2) []\n",
            "main = IO.print $ List.findIndex (Int.eq 2) [2]\n",
            "main = IO.print $ List.findIndex (Int.eq 2) [1,2]\n",
        ],
        &[("2", true)],
        &[("1", false), ("2", true)],
    );
    push_predicate_boundary_cases(
        &mut cases,
        "List.findIndices",
        [
            "main = IO.print $ List.findIndices (Int.eq 2) []\n",
            "main = IO.print $ List.findIndices (Int.eq 2) [2]\n",
            "main = IO.print $ List.findIndices (Int.eq 2) [1,2,2]\n",
        ],
        &[("2", true)],
        &[("1", false), ("2", true), ("2", true)],
    );
    push_predicate_boundary_cases(
        &mut cases,
        "List.filter",
        [
            "main = IO.print $ List.filter (\\x -> Ord.lt x 3) []\n",
            "main = IO.print $ List.filter (\\x -> Ord.lt x 3) [1]\n",
            "main = IO.print $ List.filter (\\x -> Ord.lt x 3) [1,2,3]\n",
        ],
        &[("1", true)],
        &[("1", true), ("2", true), ("3", false)],
    );
    cases.extend(runtime_partition_list_boundary_cases());
    cases
}

fn runtime_partition_list_boundary_cases() -> Vec<DifferentialCase> {
    let mut cases = Vec::new();
    for (builtin, operation) in [
        ("List.break", "List.break (Int.eq 0)"),
        ("List.span", "List.span (\\x -> Bool.not $ Int.eq x 0)"),
    ] {
        let empty = format!("main = IO.print $ {operation} []\n");
        let singleton = format!("main = IO.print $ {operation} [1]\n");
        let finite = format!("main = IO.print $ {operation} [1,0]\n");
        let finite_contract = if builtin == "List.break" {
            predicate_invocations(&[("1", false), ("0", true)])
        } else {
            predicate_invocations(&[("1", true), ("0", false)])
        };
        let singleton_contract = if builtin == "List.break" {
            predicate_invocations(&[("1", false)])
        } else {
            predicate_invocations(&[("1", true)])
        };
        push_runtime_boundary_cases(
            &mut cases,
            builtin,
            [
                ("empty-input", empty.as_str(), Vec::new()),
                ("singleton-input", singleton.as_str(), singleton_contract),
                ("finite-input", finite.as_str(), finite_contract),
            ],
        );
    }
    push_predicate_boundary_cases(
        &mut cases,
        "List.takeWhile",
        [
            "main = IO.print $ List.takeWhile (\\x -> Ord.lt x 3) []\n",
            "main = IO.print $ List.takeWhile (\\x -> Ord.lt x 3) [1]\n",
            "main = IO.print $ List.takeWhile (\\x -> Ord.lt x 3) [1,2,3]\n",
        ],
        &[("1", true)],
        &[("1", true), ("2", true), ("3", false)],
    );
    push_predicate_boundary_cases(
        &mut cases,
        "List.partition",
        [
            "main = IO.print $ List.partition (\\x -> Ord.lt x 3) []\n",
            "main = IO.print $ List.partition (\\x -> Ord.lt x 3) [1]\n",
            "main = IO.print $ List.partition (\\x -> Ord.lt x 3) [1,2,3]\n",
        ],
        &[("1", true)],
        &[("1", true), ("2", true), ("3", false)],
    );
    cases
}

fn push_predicate_boundary_cases(
    cases: &mut Vec<DifferentialCase>,
    builtin: &str,
    sources: [&str; 3],
    singleton: &[(&str, bool)],
    finite: &[(&str, bool)],
) {
    push_runtime_boundary_cases(
        cases,
        builtin,
        [
            ("empty-input", sources[0], Vec::new()),
            (
                "singleton-input",
                sources[1],
                predicate_invocations(singleton),
            ),
            ("finite-input", sources[2], predicate_invocations(finite)),
        ],
    );
}

fn push_runtime_boundary_cases<const N: usize>(
    cases: &mut Vec<DifferentialCase>,
    builtin: &str,
    definitions: [(&str, &str, Vec<CallbackInvocationContract>); N],
) {
    let case_prefix = builtin.to_ascii_lowercase().replace('.', "-");
    cases.extend(
        definitions
            .into_iter()
            .map(|(boundary, source, invocations)| DifferentialCase {
                id: Arc::from(format!("{case_prefix}-boundary-{boundary}")),
                source: Arc::from(source),
                claim_evidence: Some(runtime_boundary_descriptor(
                    builtin,
                    boundary,
                    source,
                    invocations,
                )),
                ..DifferentialCase::default()
            }),
    );
}

fn bind_boolean_boundary_expectations<const N: usize>(
    cases: &mut [DifferentialCase],
    expected: [bool; N],
) {
    assert_eq!(cases.len(), expected.len());
    for (case, expected) in cases.iter_mut().zip(expected) {
        let canonical = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Bool\",\"value\":{expected}}}}}"
        );
        case.claim_evidence
            .as_mut()
            .expect("runtime boundary descriptor")
            .semantic_targets[0]
            .expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
    }
}

fn runtime_boundary_descriptor(
    builtin: &str,
    boundary: &str,
    source: &str,
    invocations: Vec<CallbackInvocationContract>,
) -> ClaimEvidenceDescriptor {
    let spec = hell_builtins::lookup(builtin).expect("boundary target is registry-backed");
    let cell = crate::runtime_obligation_cells_for_spec(spec)
        .into_iter()
        .find(|cell| cell.dimension == hell_builtins::CompatibilityDimension::PureRuntime)
        .expect("boundary target has a pure runtime cell");
    let target = EvidenceTargetV2::new(
        cell.builtin,
        cell.dimension,
        cell.obligations,
        cell.causal_signal,
        cell.platforms,
    )
    .with_runtime_scope([boundary], std::iter::empty::<&str>());
    ClaimEvidenceDescriptor {
        schema_version: 8,
        profile: ExecutionProfile::Upstream,
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        targets: vec![EvidenceTarget::new(
            Arc::clone(&target.builtin),
            target.dimension,
        )],
        semantic_targets: vec![target],
        callback_contracts: vec![CallbackContract {
            builtin: Arc::from(builtin),
            invocations,
        }],
        review_state: CaseReviewState::Reviewed,
        review_statement: Arc::from("runtime-boundary-review-v1"),
        source_sha256: sha256_bytes(source.as_bytes()),
    }
}

fn runtime_builtin_boundary_descriptor(
    builtin: &str,
    boundary: &str,
    source: &str,
) -> ClaimEvidenceDescriptor {
    let spec = hell_builtins::lookup(builtin).expect("boundary builtin is registry-backed");
    let cells = crate::runtime_obligation_cells_for_spec(spec)
        .into_iter()
        .filter(|cell| cell.dimension == hell_builtins::CompatibilityDimension::PureRuntime)
        .map(|mut cell| {
            if builtin == "List.cycle" && boundary == "empty-input" {
                cell.obligations.retain(|obligation| {
                    matches!(
                        obligation.0.as_ref(),
                        "adapter-success" | "result-force-failure" | "whnf-boundary"
                    )
                });
            } else if boundary == "bottom-after-demanded-prefix" {
                cell.obligations
                    .retain(|obligation| obligation.0.as_ref() == "lazy-boundary");
            }
            cell
        })
        .collect::<Vec<_>>();
    let mut descriptor = ClaimEvidenceDescriptor {
        schema_version: 8,
        profile: ExecutionProfile::Upstream,
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        targets: cells
            .iter()
            .map(|cell| EvidenceTarget::new(Arc::clone(&cell.builtin), cell.dimension))
            .collect(),
        semantic_targets: cells
            .into_iter()
            .map(|cell| {
                let target = EvidenceTargetV2::new(
                    cell.builtin,
                    cell.dimension,
                    cell.obligations,
                    cell.causal_signal,
                    cell.platforms,
                );
                if cell.dimension == hell_builtins::CompatibilityDimension::PureRuntime {
                    target.with_runtime_scope([boundary], std::iter::empty::<&str>())
                } else {
                    target
                }
            })
            .collect(),
        callback_contracts: Vec::new(),
        review_state: CaseReviewState::Reviewed,
        review_statement: Arc::from("runtime-boundary-observation-review-v1"),
        source_sha256: sha256_bytes(source.as_bytes()),
    };
    if boundary == "bottom-after-demanded-prefix" {
        for target in &mut descriptor.semantic_targets {
            target.expected_process_status_sha256 =
                Some(crate::process_status_sha256(false, Some(1)));
        }
    }
    descriptor
}

fn runtime_numeric_time_obligations_case() -> DifferentialCase {
    let source = concat!(
        "day = Maybe.maybe (Error.error \"day\") Function.id $ Day.iso8601ParseM \"2025-08-10\"\n",
        "otherDay = Maybe.maybe (Error.error \"day\") Function.id $ Day.fromGregorianValid (Int.toInteger 2025) 8 9\n",
        "utc = Maybe.maybe (Error.error \"utc\") Function.id $ UTCTime.iso8601ParseM \"2025-05-30T11:18:26Z\"\n",
        "tod = Maybe.maybe (Error.error \"tod\") Function.id $ TimeOfDay.makeTimeOfDayValid 23 59 60.5\n",
        "integerTwo = Int.toInteger 2\n",
        "integerSix = Int.toInteger 6\n",
        "integerSeven = Int.toInteger 7\n",
        "integerForty = Int.toInteger 40\n",
        "main = do\n",
        "  IO.print $ Int.eq 1 1\n",
        "  IO.print $ Int.fromInteger $ Int.toInteger 42\n",
        "  IO.print $ Int.mult 6 7\n",
        "  IO.print $ Int.plus 40 2\n",
        "  IO.print $ Int.readMaybe \"42\"\n",
        "  Text.putStrLn $ Int.show 42\n",
        "  IO.print $ Int.subtract 40 2\n",
        "  IO.print $ Int.toInteger 42\n",
        "  IO.print $ Integer.mult Main.integerSix Main.integerSeven\n",
        "  IO.print $ Integer.plus Main.integerForty Main.integerTwo\n",
        "  IO.print $ Integer.readMaybe \"42\"\n",
        "  IO.print $ Integer.subtract Main.integerForty Main.integerTwo\n",
        "  IO.print $ Double.eq 1.5 1.5\n",
        "  IO.print $ Double.fromInt 42\n",
        "  IO.print $ Double.mult 2.0 3.0\n",
        "  IO.print $ Double.plus 1.5 2.5\n",
        "  IO.print $ Double.readMaybe \"1.25\"\n",
        "  Text.putStrLn $ Double.show 1.25\n",
        "  Text.putStrLn $ Double.showEFloat (Maybe.Just 2) 12.5 \"\"\n",
        "  Text.putStrLn $ Double.showFFloat (Maybe.Just 2) 12.5 \"\"\n",
        "  IO.print $ Double.subtract 4.0 1.5\n",
        "  IO.print $ Day.addDays Main.integerTwo Main.day\n",
        "  IO.print $ Day.dayOfWeek Main.day\n",
        "  IO.print $ Day.diffDays Main.day Main.otherDay\n",
        "  IO.print $ Day.fromGregorianValid (Int.toInteger 2024) 2 29\n",
        "  IO.print $ Day.iso8601ParseM \"-0001-01-01\"\n",
        "  Text.putStrLn $ Day.iso8601Show Main.day\n",
        "  (year,month,date) <- IO.pure $ Day.toGregorian Main.day\n",
        "  IO.print year\n",
        "  IO.print month\n",
        "  IO.print date\n",
        "  IO.print $ TimeOfDay.makeTimeOfDayValid 23 59 60.5\n",
        "  IO.print TimeOfDay.midday\n",
        "  IO.print TimeOfDay.midnight\n",
        "  IO.print $ TimeOfDay.timeOfDayToTime Main.tod\n",
        "  IO.print $ TimeOfDay.timeToTimeOfDay 86401.25\n",
        "  IO.print $ TimeOfDay.todHour Main.tod\n",
        "  IO.print $ TimeOfDay.todMin Main.tod\n",
        "  IO.print $ TimeOfDay.todSec Main.tod\n",
        "  IO.print $ UTCTime.UTCTime Main.day 1.0\n",
        "  IO.print $ UTCTime.addUTCTime 1.5 Main.utc\n",
        "  IO.print $ UTCTime.diffUTCTime (UTCTime.addUTCTime 1.5 Main.utc) Main.utc\n",
        "  IO.print $ UTCTime.iso8601ParseM \"2025-05-30T23:59:60Z\"\n",
        "  Text.putStrLn $ UTCTime.iso8601Show Main.utc\n",
        "  IO.print $ UTCTime.utctDay Main.utc\n",
        "  IO.print $ UTCTime.utctDayTime Main.utc\n",
    );
    DifferentialCase {
        id: Arc::from("runtime-numeric-time-obligation-closure"),
        source: Arc::from(source),
        claim_evidence: Some(runtime_numeric_time_bulk_descriptor(source)),
        timeout: std::time::Duration::from_secs(10),
        ..DifferentialCase::default()
    }
}

const RUNTIME_COLLECTION_SOURCE: &str = concat!(
    "baseMap = Map.fromList [(3, \"c\"), (1, \"a\"), (2, \"b\")]\n",
    "otherMap = Map.fromList [(2, \"r\"), (4, \"d\")]\n",
    "baseSet = Set.fromList [3,1,2,1]\n",
    "otherSet = Set.fromList [2,4]\n",
    "main = do\n",
    "  IO.print $ List.all (\\x -> Bool.not $ Int.eq x 0) [1,2,3]\n",
    "  IO.print $ List.and [Bool.True,Bool.False]\n",
    "  IO.print $ List.any (Int.eq 2) [0,2,0]\n",
    "  IO.print $ List.break (Int.eq 0) [1,0,2]\n",
    "  IO.print $ List.concat [[1,2],[],[3]]\n",
    "  IO.print $ List.concatMap (\\x -> [x,x]) [1,2]\n",
    "  IO.print $ List.cons 1 [2,3]\n",
    "  IO.print $ List.take 5 $ List.cycle [1,2]\n",
    "  IO.print $ List.deleteBy Int.eq 2 [1,2,2]\n",
    "  IO.print $ List.drop 1 [1,2,3]\n",
    "  IO.print $ List.dropWhile (Int.eq 0) [0,0,1]\n",
    "  IO.print $ List.dropWhileEnd (Int.eq 0) [0,1,0]\n",
    "  IO.print $ List.elem 2 [1,2,3]\n",
    "  IO.print $ List.elemIndex 2 [1,2,2]\n",
    "  IO.print $ List.elemIndices 2 [2,1,2]\n",
    "  IO.print $ List.filter (\\x -> Bool.not $ Int.eq x 0) [0,1,0,2]\n",
    "  IO.print $ List.find (Int.eq 2) [1,2,3]\n",
    "  IO.print $ List.findIndex (Int.eq 2) [1,2,3]\n",
    "  IO.print $ List.findIndices (Int.eq 2) [2,1,2]\n",
    "  IO.print $ List.foldl' Int.plus 0 [1,2,3]\n",
    "  IO.print $ List.foldr Int.plus 0 [1,2,3]\n",
    "  IO.print $ List.group [1,1,2,1]\n",
    "  IO.print $ List.groupBy Int.eq [1,1,2,1]\n",
    "  IO.print $ List.inits [1,2]\n",
    "  IO.print $ List.intercalate [0] [[1],[2,3]]\n",
    "  IO.print $ List.intersperse 0 [1,2,3]\n",
    "  IO.print $ List.isInfixOf [2,3] [1,2,3]\n",
    "  IO.print $ List.isPrefixOf [1,2] [1,2,3]\n",
    "  IO.print $ List.isSubsequenceOf [1,3] [1,2,3]\n",
    "  IO.print $ List.isSuffixOf [2,3] [1,2,3]\n",
    "  IO.print $ List.take 4 $ List.iterate' (Int.plus 1) 0\n",
    "  IO.print $ List.length [1,2,3]\n",
    "  IO.print $ List.lookup 2 [(1,\"a\"),(2,\"b\")]\n",
    "  IO.print $ List.map (Int.plus 1) [1,2]\n",
    "  IO.print $ List.mapAccumL (\\acc x -> (Int.plus acc x,acc)) 0 [1,2]\n",
    "  IO.print $ List.mapAccumR (\\acc x -> (Int.plus acc x,acc)) 0 [1,2]\n",
    "  IO.print (List.nil :: [Int])\n",
    "  IO.print $ List.notElem 4 [1,2,3]\n",
    "  IO.print $ List.nubOrd [2,1,2,1,3]\n",
    "  IO.print $ List.null ([] :: [Int])\n",
    "  IO.print $ List.or [Bool.False,Bool.True]\n",
    "  IO.print $ List.partition (\\x -> Bool.not $ Int.eq x 0) [0,1,0,2]\n",
    "  IO.print $ List.permutations [1,2,3]\n",
    "  IO.print $ List.take 3 $ List.repeat 7\n",
    "  IO.print $ List.reverse [1,2,3]\n",
    "  IO.print $ List.scanl' Int.plus 0 [1,2,3]\n",
    "  IO.print $ List.scanr Int.plus 0 [1,2,3]\n",
    "  IO.print $ List.sort [3,1,2,1]\n",
    "  IO.print $ List.sortOn (\\(key,value) -> key) [(2,\"a\"),(1,\"b\")]\n",
    "  IO.print $ List.span (\\x -> Bool.not $ Int.eq x 0) [1,0,2]\n",
    "  IO.print $ List.splitAt 2 [1,2,3]\n",
    "  IO.print $ List.subsequences [1,2]\n",
    "  IO.print $ List.tails [1,2]\n",
    "  IO.print $ List.take 2 [1,2,3]\n",
    "  IO.print $ List.takeWhile (\\x -> Bool.not $ Int.eq x 0) [1,2,0]\n",
    "  IO.print $ List.transpose [[1,2],[3],[4,5]]\n",
    "  IO.print $ List.uncons [1,2]\n",
    "  IO.print $ List.unfoldr (\\x -> if Int.eq x 3 then Maybe.Nothing else Maybe.Just (x,Int.plus x 1)) 0\n",
    "  IO.print $ List.zip [1,2] [3,4]\n",
    "  IO.print $ List.zipWith Int.plus [1,2] [3,4]\n",
    "  IO.print $ Map.toList $ Map.adjust Text.toUpper 3 Main.baseMap\n",
    "  IO.print $ Map.all (\\_ -> Bool.True) Main.baseMap\n",
    "  IO.print $ Map.any (Text.eq \"b\") Main.baseMap\n",
    "  IO.print $ Map.toList $ Map.delete 2 Main.baseMap\n",
    "  IO.print $ Map.elems Main.baseMap\n",
    "  IO.print $ Map.toList $ Map.filter (Text.eq \"a\") Main.baseMap\n",
    "  IO.print $ Map.toList $ Map.filterWithKey (\\key _ -> Ord.lt key 3) Main.baseMap\n",
    "  IO.print $ Map.toList $ Map.fromList [(2,\"b\"),(1,\"a\")]\n",
    "  IO.print $ Map.toList $ Map.insert 0 \"z\" Main.baseMap\n",
    "  IO.print $ Map.toList $ Map.insertWith (\\new old -> new <> old) 2 \"N\" Main.baseMap\n",
    "  IO.print $ Map.keys Main.baseMap\n",
    "  IO.print $ Map.lookup 2 Main.baseMap\n",
    "  IO.print $ Map.toList $ Map.map Text.toUpper Main.baseMap\n",
    "  IO.print $ Map.toList $ Map.singleton 4 \"d\"\n",
    "  IO.print $ Map.size Main.baseMap\n",
    "  IO.print $ Map.toList Main.baseMap\n",
    "  IO.print $ Map.toList $ Map.unionWith (\\left right -> left <> right) Main.baseMap Main.otherMap\n",
    "  IO.print $ Set.toList $ Set.delete 2 Main.baseSet\n",
    "  IO.print $ Set.toList $ Set.difference Main.baseSet Main.otherSet\n",
    "  IO.print $ Set.fromList [2,1,2]\n",
    "  IO.print $ Set.toList $ Set.insert 0 Main.baseSet\n",
    "  IO.print $ Set.toList $ Set.intersection Main.baseSet Main.otherSet\n",
    "  IO.print $ Set.member 2 Main.baseSet\n",
    "  IO.print $ Set.singleton 5\n",
    "  IO.print $ Set.size Main.baseSet\n",
    "  IO.print $ Set.toList Main.baseSet\n",
    "  IO.print $ Set.toList $ Set.union Main.baseSet Main.otherSet\n",
);

fn runtime_collection_obligations_case() -> DifferentialCase {
    let source = RUNTIME_COLLECTION_SOURCE;
    let mut descriptor = runtime_family_bulk_descriptor(&["List", "Map", "Set"], source);
    descriptor.semantic_targets.retain(|target| {
        !crate::runtime_obligations::collection_comparator_sensitive(&target.builtin)
    });
    descriptor.targets = descriptor
        .semantic_targets
        .iter()
        .map(|target| EvidenceTarget::new(Arc::clone(&target.builtin), target.dimension))
        .collect();
    DifferentialCase {
        id: Arc::from("runtime-collections-obligation-closure"),
        source: Arc::from(source),
        claim_evidence: Some(descriptor),
        timeout: std::time::Duration::from_secs(20),
        ..DifferentialCase::default()
    }
}

fn runtime_numeric_time_bulk_descriptor(source: &str) -> ClaimEvidenceDescriptor {
    let mut descriptor = runtime_family_descriptor_excluding(
        &["Int", "Integer", "Double", "Day", "TimeOfDay", "UTCTime"],
        &["UTCTime.getCurrentTime"],
        source,
    );
    descriptor.semantic_targets.retain(|target| {
        !target
            .obligations
            .iter()
            .any(|obligation| obligation.0.as_ref() == "callback-order")
    });
    for target in &mut descriptor.semantic_targets {
        let repeated_demand_target = source_builtin_occurrences(source, &target.builtin) != 1;
        target.obligations.retain(|obligation| {
            obligation.0.as_ref() != "typed-result"
                && !(repeated_demand_target && is_demand_obligation(obligation.0.as_ref()))
        });
    }
    descriptor.targets = descriptor
        .semantic_targets
        .iter()
        .map(|target| EvidenceTarget::new(Arc::clone(&target.builtin), target.dimension))
        .collect();
    descriptor
}

fn runtime_family_bulk_descriptor(families: &[&str], source: &str) -> ClaimEvidenceDescriptor {
    let mut descriptor = runtime_family_descriptor_excluding(families, &[], source);
    descriptor.semantic_targets.retain(|target| {
        !target
            .obligations
            .iter()
            .any(|obligation| obligation.0.as_ref() == "callback-order")
    });
    for target in &mut descriptor.semantic_targets {
        let ambiguous_demand_target = source_builtin_occurrences(source, &target.builtin) != 1;
        target.obligations.retain(|obligation| {
            obligation.0.as_ref() != "typed-result"
                && !is_failure_path_obligation(obligation.0.as_ref())
                && !(ambiguous_demand_target && is_demand_obligation(obligation.0.as_ref()))
        });
    }
    descriptor.targets = descriptor
        .semantic_targets
        .iter()
        .map(|target| EvidenceTarget::new(Arc::clone(&target.builtin), target.dimension))
        .collect();
    descriptor
}

fn is_failure_path_obligation(obligation: &str) -> bool {
    matches!(
        obligation,
        "adapter-failure" | "result-force-failure" | "whnf-failure-boundary"
    )
}

fn is_demand_obligation(obligation: &str) -> bool {
    matches!(
        obligation,
        "lazy-boundary"
            | "whnf-boundary"
            | "deep-boundary"
            | "conditional-selected"
            | "conditional-unselected"
            | "io-execution-boundary"
    )
}

fn source_builtin_occurrences(source: &str, builtin: &str) -> usize {
    source
        .match_indices(builtin)
        .filter(|(start, matched)| {
            let identifier =
                |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'\'');
            let before = start
                .checked_sub(1)
                .and_then(|index| source.as_bytes().get(index))
                .is_none_or(|byte| !identifier(*byte));
            let end = start.saturating_add(matched.len());
            let after = source
                .as_bytes()
                .get(end)
                .is_none_or(|byte| !identifier(*byte));
            before && after
        })
        .count()
}

fn runtime_family_descriptor_excluding(
    families: &[&str],
    excluded: &[&str],
    source: &str,
) -> ClaimEvidenceDescriptor {
    let cells = hell_builtins::registry()
        .iter()
        .filter(|spec| {
            families.contains(&spec.assurance_metadata().semantic_family)
                && !excluded.contains(&spec.name)
        })
        .flat_map(crate::runtime_obligation_cells_for_spec)
        .collect::<Vec<_>>();
    ClaimEvidenceDescriptor {
        schema_version: 8,
        profile: ExecutionProfile::Upstream,
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        targets: cells
            .iter()
            .map(|cell| EvidenceTarget::new(Arc::clone(&cell.builtin), cell.dimension))
            .collect(),
        semantic_targets: cells
            .into_iter()
            .map(|cell| {
                EvidenceTargetV2::new(
                    cell.builtin,
                    cell.dimension,
                    cell.obligations,
                    cell.causal_signal,
                    cell.platforms,
                )
            })
            .collect(),
        callback_contracts: Vec::new(),
        review_state: CaseReviewState::Reviewed,
        review_statement: Arc::from("runtime-family-obligation-review-v1"),
        source_sha256: sha256_bytes(source.as_bytes()),
    }
}

fn public_builtin_catalog_reachability_case() -> DifferentialCase {
    let public = hell_builtins::registry()
        .iter()
        .filter(|spec| spec.visibility == Visibility::Public)
        .collect::<Vec<_>>();
    let mut source = String::new();
    for (index, spec) in public.iter().enumerate() {
        let annotation = (!spec.name.starts_with("Process."))
            .then(|| hell_builtins::source_annotation_scheme(spec.name))
            .flatten()
            .map(concrete_builtin_annotation);
        if spec.name != "Monad.then"
            && !spec.name.starts_with("Tuple.(")
            && !spec.name.starts_with("Record.")
            && !is_options_builtin(spec.name)
        {
            let reference = builtin_source_reference(spec.name);
            if annotation
                .as_deref()
                .is_some_and(annotation_is_source_spellable)
            {
                let annotation = annotation.expect("spellable annotations are present");
                writeln!(
                    source,
                    "builtinCatalogProbe{index} :: {annotation} = {reference}"
                )
                .expect("writing to String cannot fail");
            } else {
                writeln!(source, "builtinCatalogProbe{index} = {reference}")
                    .expect("writing to String cannot fail");
            }
        }
    }
    source.push_str(
        "data BuiltinCatalogPerson = BuiltinCatalogPerson { value :: Int }\ndata BuiltinCatalogChoice = BuiltinCatalogFirst Int | BuiltinCatalogMiddle Text | BuiltinCatalogLast\nbuiltinCatalogRecord = Main.BuiltinCatalogPerson { value = 1 }\nbuiltinCatalogRecordGet = Record.get @\"value\" @Int Main.builtinCatalogRecord\nbuiltinCatalogRecordSet = Record.set @\"value\" @Int 2 Main.builtinCatalogRecord\nbuiltinCatalogRecordModify = Record.modify @\"value\" @Int (Int.plus 1) Main.builtinCatalogRecord\nbuiltinCatalogTuple2 = (1,2)\nbuiltinCatalogTuple3 = (1,2,3)\nbuiltinCatalogTuple4 = (1,2,3,4)\n",
    );
    source.push_str("main = do\n");
    for (index, spec) in public.iter().enumerate() {
        if spec.name != "Monad.then"
            && !spec.name.starts_with("Tuple.(")
            && !spec.name.starts_with("Record.")
            && !is_options_builtin(spec.name)
            && spec.scheme.is_some()
        {
            writeln!(
                source,
                "  let builtinCatalogUse{index} = Main.builtinCatalogProbe{index}"
            )
            .expect("writing to String cannot fail");
        }
    }
    source.push_str(
        "  let builtinCatalogRecordUseGet = Main.builtinCatalogRecordGet\n  let builtinCatalogRecordUseSet = Main.builtinCatalogRecordSet\n  let builtinCatalogRecordUseModify = Main.builtinCatalogRecordModify\n  let builtinCatalogTupleUse2 = Main.builtinCatalogTuple2\n  let builtinCatalogTupleUse3 = Main.builtinCatalogTuple3\n  let builtinCatalogTupleUse4 = Main.builtinCatalogTuple4\n  let builtinCatalogVariantFirst = Main.BuiltinCatalogFirst 1\n  let builtinCatalogVariantMiddle = Main.BuiltinCatalogMiddle \"middle\"\n  let builtinCatalogVariantLast = Main.BuiltinCatalogLast\n  let builtinCatalogVariantExact = case builtinCatalogVariantFirst of { BuiltinCatalogFirst value -> value; BuiltinCatalogMiddle text -> Text.length text; BuiltinCatalogLast -> 0 }\n  let builtinCatalogVariantWildcard = case builtinCatalogVariantMiddle of { BuiltinCatalogFirst value -> value; _ -> 0 }\n  let builtinCatalogOptionFlag = Options.flag 0 1 (Flag.help \"flag\" <> Flag.long \"flag\")\n  let builtinCatalogOptionFlagPrime = Options.flag' 1 (Flag.help \"prime\" <> Flag.long \"prime\")\n  let builtinCatalogOptionArgument = Options.strArgument (Argument.help \"argument\" <> Argument.metavar \"ARG\" <> Argument.value \"default\")\n  let builtinCatalogOptionValue = Options.strOption (Option.help \"option\" <> Option.long \"option\" <> Option.value \"default\")\n  let builtinCatalogOptionSwitch = Options.switch (Flag.help \"switch\" <> Flag.long \"switch\")\n  let builtinCatalogOptionParser = (\\flag -> \\prime -> \\argument -> \\option -> \\switch -> flag) <$> builtinCatalogOptionFlag <*> builtinCatalogOptionFlagPrime <*> builtinCatalogOptionArgument <*> builtinCatalogOptionValue <*> builtinCatalogOptionSwitch\n  let builtinCatalogOptionInfo = Options.info (Options.helper <*> builtinCatalogOptionParser) (Options.fullDesc <> Options.header \"catalog\" <> Options.progDesc \"catalog reachability\")\n  let builtinCatalogOptionCommand = Options.command \"catalog\" builtinCatalogOptionInfo\n  let builtinCatalogOptionSubparser = Options.hsubparser builtinCatalogOptionCommand\n  let builtinCatalogOptionExec = Options.execParser $ Options.info builtinCatalogOptionSubparser Options.fullDesc\n  IO.print 0\n  IO.print 1\n",
    );
    DifferentialCase {
        id: Arc::from("public-builtin-catalog-reachability"),
        source: Arc::from(source),
        claim_evidence: None,
        ..DifferentialCase::default()
    }
}

fn is_options_builtin(name: &str) -> bool {
    ["Options.", "Argument.", "Option.", "Flag."]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn concrete_builtin_annotation(scheme: &str) -> String {
    let text_argument = scheme.contains("Semigroup a =>") || scheme.contains("FoldCase a =>");
    let monotype = scheme
        .strip_prefix("forall ")
        .and_then(|quantified| quantified.split_once(". "))
        .map_or(scheme, |(_, body)| body);
    let monotype = monotype
        .split_once(" => ")
        .map_or(monotype, |(_, body)| body);
    let mut annotation = String::with_capacity(monotype.len());
    let mut token = String::new();
    for character in monotype.chars().chain(std::iter::once(' ')) {
        if character.is_ascii_alphanumeric() || character == '_' {
            token.push(character);
            continue;
        }
        if !token.is_empty() {
            match token.as_str() {
                "f" => annotation.push_str("Maybe"),
                "m" => annotation.push_str("IO"),
                "fields" => annotation.push_str("Options.FlagFields"),
                "a" if text_argument => annotation.push_str("Text"),
                token if token.chars().next().is_some_and(char::is_lowercase) => {
                    annotation.push_str("Int");
                }
                _ => annotation.push_str(&token),
            }
            token.clear();
        }
        if character != ' ' || !annotation.ends_with(' ') {
            annotation.push(character);
        }
    }
    annotation.pop();
    annotation
}

fn annotation_is_source_spellable(annotation: &str) -> bool {
    annotation
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | ':'))
        })
        .filter(|token| token.chars().next().is_some_and(char::is_uppercase))
        .all(|token| hell_builtins::public_type_arity(token).is_some())
}

fn builtin_source_reference(name: &str) -> String {
    match name {
        "$" | "." | "<$>" | "<**>" | "<*>" | "<>" => format!("({name})"),
        "Process.nullStream" | "Process.setStdout" => process_catalog_reference(
            "Process.setStdout Process.nullStream $ Process.proc \"catalog\" []",
        ),
        "Process.proc" => process_catalog_reference("Process.proc \"catalog\" []"),
        "Process.runProcess" => {
            process_catalog_reference("Process.runProcess $ Process.proc \"catalog\" []")
        }
        "Process.runProcess_" => {
            process_catalog_reference("Process.runProcess_ $ Process.proc \"catalog\" []")
        }
        "Process.setEnv" => {
            process_catalog_reference("Process.setEnv [] $ Process.proc \"catalog\" []")
        }
        "Process.setStderr" => process_catalog_reference(
            "Process.setStderr Process.nullStream $ Process.proc \"catalog\" []",
        ),
        "Process.setStdin" => process_catalog_reference(
            "Process.setStdin Process.nullStream $ Process.proc \"catalog\" []",
        ),
        "Process.setWorkingDir" => {
            process_catalog_reference("Process.setWorkingDir \".\" $ Process.proc \"catalog\" []")
        }
        "Process.useHandleClose" => process_catalog_reference(
            "Process.setStdout (Process.useHandleClose IO.stdout) $ Process.proc \"catalog\" []",
        ),
        "Process.useHandleOpen" => process_catalog_reference(
            "Process.setStdout (Process.useHandleOpen IO.stdout) $ Process.proc \"catalog\" []",
        ),
        _ => name.to_owned(),
    }
}

fn process_catalog_reference(source: &str) -> String {
    source.to_owned()
}

fn runtime_claim_descriptor(
    targets: &[&str],
    obligations: &[&str],
    causal_signal: CausalSignal,
) -> ClaimEvidenceDescriptor {
    ClaimEvidenceDescriptor {
        schema_version: 8,
        profile: ExecutionProfile::Upstream,
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        targets: targets
            .iter()
            .map(|builtin| EvidenceTarget::new(*builtin, CompatibilityDimension::PureRuntime))
            .collect(),
        semantic_targets: targets
            .iter()
            .map(|builtin| {
                EvidenceTargetV2::new(
                    *builtin,
                    CompatibilityDimension::PureRuntime,
                    obligations
                        .iter()
                        .map(|obligation| ObligationId(Arc::from(*obligation)))
                        .collect(),
                    causal_signal,
                    vec![ClaimPlatform::All],
                )
            })
            .collect(),
        callback_contracts: Vec::new(),
        review_state: CaseReviewState::Reviewed,
        review_statement: Arc::from("committed-corpus-review-v1"),
        source_sha256: Digest::default(),
    }
}

#[allow(clippy::too_many_lines)]
fn generated_case(seed: u64, index: usize) -> GeneratedCase {
    let word = split_mix(seed.wrapping_add(u64::try_from(index).unwrap_or(u64::MAX)));
    let small = i64::try_from(word % 10_000).expect("generated value is bounded");
    let alternative = i64::try_from((word >> 16) % 10_000).expect("generated value is bounded");
    let (family, result_type, source, shrink): (&str, GeneratedType, String, &str) = match index
        % 10
    {
        0 => (
            "int-boundary",
            GeneratedType::Int,
            format!("main = IO.print $ Int.plus {small} {alternative}\n"),
            "replace either integer operand with 0, then 1",
        ),
        1 => (
            "nested-maybe-list",
            GeneratedType::List(Box::new(GeneratedType::Maybe(Box::new(GeneratedType::Int)))),
            format!("main = IO.print [Maybe.Just {small}, Maybe.Nothing]\n"),
            "remove the Nothing element, then shrink the Just payload",
        ),
        2 => (
            "either-tuple",
            GeneratedType::Tuple2(
                Box::new(GeneratedType::Either(
                    Box::new(GeneratedType::Int),
                    Box::new(GeneratedType::Text),
                )),
                Box::new(GeneratedType::Bool),
            ),
            format!("main = IO.print ((Either.Left {small} :: Either Int Text), Bool.True)\n"),
            "replace the Left payload with 0",
        ),
        3 => (
            "short-circuit-unused-error",
            GeneratedType::Int,
            format!(
                "main = IO.print $ Bool.bool {small} (Error.error \"unused\" :: Int) Bool.False\n"
            ),
            "replace the selected integer with 0",
        ),
        4 => (
            "record-field",
            GeneratedType::Record,
            format!(
                "data GeneratedRecord = GeneratedRecord {{ value :: Int, other :: Int }}\n\nmain = IO.print $ Record.get @\"value\" @Int Main.GeneratedRecord {{ value = {small}, other = {alternative} }}\n"
            ),
            "remove the unrelated field, then shrink the selected value",
        ),
        5 => (
            "variant-case",
            GeneratedType::Variant,
            format!(
                "data Choice = First Int | Second Text\n\nmain = case Main.First {small} of\n  First value -> IO.print value\n  Second text -> Text.putStrLn text\n"
            ),
            "shrink the First payload, then remove the unused constructor branch",
        ),
        6 => {
            let take = usize::try_from(word % 8 + 1).expect("generated take is bounded");
            (
                "productive-list",
                GeneratedType::List(Box::new(GeneratedType::Int)),
                format!(
                    "main = IO.print $ List.take {take} $ List.iterate' (Int.plus 1) {small}\n"
                ),
                "reduce the take count, then shrink the initial value",
            )
        }
        7 => (
            "stable-ordering",
            GeneratedType::List(Box::new(GeneratedType::Tuple2(
                Box::new(GeneratedType::Int),
                Box::new(GeneratedType::Text),
            ))),
            format!(
                "main = IO.print $ List.sortOn (\\(key, value) -> key) [(2, \"{small}\"), (1, \"{alternative}\"), (2, \"tail\")]\n"
            ),
            "remove one list element, then shrink keys and text payloads",
        ),
        8 => (
            "text-roundtrip",
            GeneratedType::Text,
            format!(
                "main = Text.putStrLn $ Text.decodeUtf8 $ Text.encodeUtf8 \"generated-{small}-{alternative}\"\n"
            ),
            "remove one text segment, then shrink decimal digits",
        ),
        _ => (
            "json-object",
            GeneratedType::Json,
            format!(
                "main = ByteString.hPutStr IO.stdout $ Json.encode $ Json.Object $ Map.fromList [(\"n\", Json.Number {small}.0), (\"ok\", Json.Bool Bool.True)]\n"
            ),
            "remove one object member, then shrink the numeric payload",
        ),
    };
    let id: Arc<str> = format!("generated-{family}-{index:04}").into();
    let ast = format!("{family}\0{result_type:?}\0{source}");
    GeneratedCase {
        id,
        seed,
        result_type,
        source: source.into(),
        ast_sha256: sha256_bytes(ast.as_bytes()),
        shrink_description: shrink.into(),
    }
}

fn split_mix(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn race_temporary_interaction_acquires_its_resource_before_starting_the_race() {
        let (_, participants, source, _, _) = runtime_interaction_definitions()
            .into_iter()
            .find(|(interaction, _, _, _, _)| *interaction == "race-temporary-resource")
            .expect("race/temporary interaction definition");
        assert_eq!(participants, ["Async.race", "Temp.withSystemTempFile"]);
        let temporary = source
            .find("main = Temp.withSystemTempFile")
            .expect("outer temporary resource acquisition");
        let write = source
            .find("Text.hPutStr handle")
            .expect("temporary resource use");
        let race = source.find("Async.race").expect("nested race execution");
        assert!(temporary < write && write < race);

        let case = runtime_interaction_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "runtime-interaction-race-temporary-resource")
            .expect("committed race/temporary interaction");
        let targets = &case.claim_evidence.as_ref().unwrap().semantic_targets;
        assert!(targets.iter().any(|target| {
            target.builtin.as_ref() == "Temp.withSystemTempFile"
                && target.dimension == CompatibilityDimension::PureRuntime
                && target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "io-execution-boundary")
        }));
    }

    #[test]
    fn reviewed_runtime_failure_presentations_bind_exact_closed_inventory() {
        let cases = committed_differential_cases();
        let authorities = cases
            .iter()
            .filter_map(|case| {
                crate::reviewed_runtime_failure_presentation_authority(case)
                    .map(|authority| (case, authority))
            })
            .collect::<Vec<_>>();
        let rejected = cases
            .iter()
            .filter(|case| crate::has_runtime_failure_presentation_authority(&case.id))
            .filter(|case| crate::reviewed_runtime_failure_presentation_authority(case).is_none())
            .map(|case| case.id.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(authorities.len(), 33, "rejected authorities: {rejected:?}");
        assert!(
            authorities
                .iter()
                .all(|(case, _)| !case.expected_runtime_completion)
        );
        assert_eq!(
            authorities
                .iter()
                .filter(|(_, authority)| {
                    authority.family == crate::RuntimeFailureExceptionFamily::UnicodeException
                })
                .count(),
            3,
        );
        assert_eq!(
            authorities
                .iter()
                .filter(|(_, authority)| {
                    authority.family == crate::RuntimeFailureExceptionFamily::IOException
                })
                .count(),
            19,
        );
        assert_eq!(
            authorities
                .iter()
                .filter(|(_, authority)| {
                    authority.family == crate::RuntimeFailureExceptionFamily::ErrorCall
                })
                .count(),
            11,
        );
        assert!(authorities.iter().all(|(case, _)| {
            crate::artifact::case_descriptor(case).starts_with("schema_version = 9\n")
        }));
        let ordinary = cases
            .iter()
            .find(|case| case.id.as_ref() == "bool-ordinary-success")
            .expect("ordinary committed case");
        assert!(crate::artifact::case_descriptor(ordinary).starts_with("schema_version = 8\n"));
    }

    fn assert_io_print_presentation_is_applicable() {
        let print = hell_builtins::lookup("IO.print").expect("IO.print remains registry-backed");
        let print_dimensions = crate::runtime_obligation_cells_for_spec(print)
            .into_iter()
            .map(|cell| cell.dimension)
            .collect::<Vec<_>>();
        assert_eq!(
            print_dimensions,
            [
                CompatibilityDimension::PureRuntime,
                CompatibilityDimension::Effects,
                CompatibilityDimension::Presentation,
                CompatibilityDimension::Platform,
                CompatibilityDimension::ResourceBehavior,
            ],
            "IO.print must retain its exact Presentation applicability while normalized shadow is open"
        );
    }

    fn assert_show_manifest_scope(definitions: &[ShowInstanceDefinition]) {
        let actual = definitions
            .iter()
            .map(|definition| definition.target)
            .collect::<std::collections::BTreeSet<_>>();
        let expected = hell_builtins::instances()
            .iter()
            .filter(|instance| instance.class == hell_builtins::TypeClass::Show)
            .map(|instance| instance.target)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    fn assert_show_constructor_breadth(definitions: &[ShowInstanceDefinition]) {
        let slugs = definitions
            .iter()
            .map(|definition| definition.slug)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            slugs.len(),
            definitions.len(),
            "Show case slugs must be unique"
        );
        assert!(
            show_constructor_breadth_gaps(definitions).is_empty(),
            "Show constructor breadth is incomplete"
        );
    }

    fn show_constructor_breadth_gaps(
        definitions: &[ShowInstanceDefinition],
    ) -> std::collections::BTreeSet<&'static str> {
        let actual = definitions
            .iter()
            .map(|definition| definition.slug)
            .collect::<std::collections::BTreeSet<_>>();
        REQUIRED_SHOW_CONSTRUCTOR_BREADTH
            .iter()
            .copied()
            .filter(|required| !actual.contains(required))
            .collect()
    }

    const REQUIRED_SHOW_CONSTRUCTOR_BREADTH: &[&str] = &[
        "bool",
        "bool-false",
        "builder-arbitrary-bytes",
        "byte-string-arbitrary-bytes",
        "char-quote",
        "char-backslash",
        "char-control",
        "double-finite",
        "double-zero",
        "double-negative-zero",
        "double-exponential",
        "double-infinity",
        "double-negative-infinity",
        "double-nan",
        "exit-code",
        "exit-code-success",
        "value-null",
        "value-bool",
        "value-number",
        "value-string",
        "value-string-escaping",
        "value-array",
        "value-object",
        "maybe-nothing",
        "maybe-just",
        "either-left",
        "either-right",
        "set-empty",
        "set-nonempty",
        "tree-leaf",
        "tree-branch",
        "vector-empty",
        "vector-nonempty",
        "list-empty",
        "list-nonempty",
        "tuple",
        "text-escaping",
    ];

    fn assert_show_descriptor_scope(
        definitions: &[ShowInstanceDefinition],
        cases: &[DifferentialCase],
    ) {
        for definition in definitions {
            for builtin in ["Show.show", "IO.print"] {
                let id = format!(
                    "runtime-show-{}-{}",
                    builtin.replace('.', "-").to_ascii_lowercase(),
                    definition.slug
                );
                let case = cases.iter().find(|case| case.id.as_ref() == id).unwrap();
                let descriptor = case.claim_evidence.as_ref().unwrap();
                assert!(descriptor.semantic_targets.iter().all(|target| {
                    target.builtin.as_ref() == builtin
                        && target.expected_instance_target.as_deref() == Some(definition.target)
                        && target
                            .expected_instance_premises
                            .iter()
                            .map(|premise| (premise.target.as_ref(), premise.premise_count))
                            .eq(definition.premises.iter().copied())
                }));
                let presentation = descriptor
                    .semantic_targets
                    .iter()
                    .filter(|target| target.dimension == CompatibilityDimension::Presentation)
                    .collect::<Vec<_>>();
                assert_eq!(presentation.len(), 1);
                assert!(presentation[0].expected_typed_result_sha256.is_some());
                assert!(presentation[0].expected_raw_presentation_sha256.is_some());
                assert_eq!(
                    presentation[0].expected_presentation_shadow_normalizer,
                    Some(PresentationShadowNormalizerId::LineEndingsV1)
                );
                assert!(
                    presentation[0]
                        .expected_normalized_presentation_sha256
                        .is_some()
                );
                assert!(presentation[0].expected_process_status_sha256.is_some());
                assert_eq!(
                    presentation[0]
                        .obligations
                        .iter()
                        .map(|obligation| obligation.0.as_ref())
                        .collect::<std::collections::BTreeSet<_>>(),
                    std::collections::BTreeSet::from(
                        ["normalized-shadow-diff", "raw-observation",]
                    )
                );
            }
        }
    }

    #[test]
    fn show_instance_definitions_exactly_cover_manifest_scopes_and_constructor_breadth() {
        let definitions = show_instance_definitions();
        assert_io_print_presentation_is_applicable();
        assert_show_manifest_scope(&definitions);
        assert_eq!(
            definitions
                .iter()
                .map(|definition| definition.target)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            22
        );
        assert_show_constructor_breadth(&definitions);
        let cases = runtime_show_instance_cases();
        assert_eq!(cases.len(), definitions.len() * 2);
        crate::validate_evidence_catalog(&cases).expect("Show tranche descriptors are canonical");
        assert_show_descriptor_scope(&definitions, &cases);
    }

    #[test]
    fn show_presentation_requires_every_builtin_instance_scope() {
        let cases = runtime_show_instance_cases();
        let roots = hell_builtins::instances()
            .iter()
            .filter(|instance| instance.class == hell_builtins::TypeClass::Show)
            .map(|instance| instance.target)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(roots.len(), 22);
        for builtin in ["Show.show", "IO.print"] {
            for root in &roots {
                let reduced = cases
                    .iter()
                    .filter(|case| {
                        !case.claim_evidence.as_ref().is_some_and(|descriptor| {
                            descriptor.semantic_targets.iter().any(|target| {
                                target.builtin.as_ref() == builtin
                                    && target.dimension == CompatibilityDimension::Presentation
                                    && target.expected_instance_target.as_deref() == Some(*root)
                            })
                        })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                assert!(
                    !crate::runtime_obligation_scope_complete(
                        &reduced,
                        builtin,
                        CompatibilityDimension::Presentation,
                        root,
                    )
                    .unwrap(),
                    "removing {builtin}/{root} did not reopen its Presentation scope"
                );
            }
        }
    }

    #[test]
    fn show_presentation_constructor_breadth_rejects_every_required_path_deletion() {
        let definitions = show_instance_definitions();
        for required in REQUIRED_SHOW_CONSTRUCTOR_BREADTH {
            let remaining = definitions
                .iter()
                .copied()
                .filter(|definition| definition.slug != *required)
                .collect::<Vec<_>>();
            assert_eq!(
                show_constructor_breadth_gaps(&remaining),
                std::collections::BTreeSet::from([*required]),
                "deleted Show breadth path {required} was not detected exactly"
            );
        }
    }

    fn expected_singleton_case_ids() -> std::collections::BTreeSet<String> {
        let mut ids = std::collections::BTreeSet::new();
        for definition in singleton_ord_definitions() {
            for builtin in ["map-singleton", "set-singleton"] {
                ids.insert(format!("runtime-typed-{builtin}-{}", definition.slug));
            }
        }
        ids.insert("runtime-typed-map-singleton-key-strict".to_owned());
        ids.insert("runtime-typed-map-singleton-value-nonforce".to_owned());
        ids.insert("runtime-typed-set-singleton-element-strict".to_owned());
        ids
    }

    fn validate_singleton_inventory(cases: &[DifferentialCase]) -> Result<(), String> {
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        if actual.len() != cases.len() || actual != expected_singleton_case_ids() {
            return Err("singleton constructor inventory is incomplete or duplicated".into());
        }
        for case in cases {
            let descriptor = case
                .claim_evidence
                .as_ref()
                .ok_or_else(|| format!("{} lacks singleton evidence", case.id))?;
            let expected: &[CompatibilityDimension] = if case
                .id
                .starts_with("runtime-typed-map-singleton-key-strict")
                || case
                    .id
                    .starts_with("runtime-typed-map-singleton-value-nonforce")
                || case
                    .id
                    .starts_with("runtime-typed-set-singleton-element-strict")
            {
                &[CompatibilityDimension::PureRuntime]
            } else {
                &[
                    CompatibilityDimension::PureRuntime,
                    CompatibilityDimension::Platform,
                    CompatibilityDimension::ResourceBehavior,
                ]
            };
            if !descriptor
                .semantic_targets
                .iter()
                .map(|target| target.dimension)
                .eq(expected.iter().copied())
                || !descriptor
                    .targets
                    .iter()
                    .map(|target| target.dimension)
                    .eq(expected.iter().copied())
            {
                return Err(format!("{} has an incomplete singleton cell set", case.id));
            }
        }
        Ok(())
    }

    #[test]
    fn singleton_constructors_exactly_cover_every_ord_scope_and_nonforce_path() {
        let definitions = singleton_ord_definitions();
        let actual = definitions
            .iter()
            .map(|definition| definition.value.target)
            .collect::<std::collections::BTreeSet<_>>();
        let expected = hell_builtins::instances()
            .iter()
            .filter(|instance| instance.class == hell_builtins::TypeClass::Ord)
            .map(|instance| instance.target)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);

        let cases = runtime_singleton_constructor_cases();
        validate_singleton_inventory(&cases).unwrap();
        crate::validate_evidence_catalog(&cases)
            .expect("singleton constructor descriptors are canonical");
        for definition in &definitions {
            for builtin in ["map-singleton", "set-singleton"] {
                let id = format!("runtime-typed-{builtin}-{}", definition.slug);
                let descriptor = cases
                    .iter()
                    .find(|case| case.id.as_ref() == id)
                    .and_then(|case| case.claim_evidence.as_ref())
                    .expect("singleton scope descriptor");
                assert_eq!(descriptor.semantic_targets.len(), 3, "{id}");
                assert!(descriptor.semantic_targets.iter().all(|target| {
                    target.expected_instance_target.as_deref() == Some(definition.value.target)
                        && target
                            .expected_instance_premises
                            .iter()
                            .map(|premise| (premise.target.as_ref(), premise.premise_count))
                            .eq(definition.value.premises.iter().copied())
                }));
            }
        }
        for omitted in expected_singleton_case_ids() {
            let reduced = cases
                .iter()
                .filter(|case| case.id.as_ref() != omitted)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                validate_singleton_inventory(&reduced).is_err(),
                "omitted singleton path {omitted}"
            );
        }
        for index in 0..cases.len() {
            let target_count = cases[index]
                .claim_evidence
                .as_ref()
                .unwrap()
                .semantic_targets
                .len();
            for target_index in 0..target_count {
                let mut reduced = cases.clone();
                let descriptor = reduced[index].claim_evidence.as_mut().unwrap();
                descriptor.semantic_targets.remove(target_index);
                descriptor.targets.remove(target_index);
                assert!(validate_singleton_inventory(&reduced).is_err());
            }
        }
    }

    fn expected_applicative_case_ids() -> std::collections::BTreeSet<String> {
        let mut ids = std::collections::BTreeSet::new();
        for instance in ["io", "maybe", "list", "tree", "parser", "either"] {
            for path in ["value", "lazy"] {
                ids.insert(format!("runtime-typed-applicative-pure-{instance}-{path}"));
            }
        }
        for builtin in ["apply", "apply-flipped"] {
            for (instance, paths) in [
                ("io", &["ordered", "short"][..]),
                ("maybe", &["success", "short"][..]),
                ("list", &["cartesian", "short"][..]),
                ("tree", &["branching"][..]),
                ("parser", &["present", "absent", "consumed-missing"][..]),
                ("either", &["success", "short"][..]),
            ] {
                for path in paths {
                    ids.insert(format!(
                        "runtime-typed-applicative-{builtin}-{instance}-{path}"
                    ));
                }
            }
        }
        ids
    }

    fn validate_applicative_inventory(cases: &[DifferentialCase]) -> Result<(), String> {
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        if actual.len() != cases.len() || actual != expected_applicative_case_ids() {
            return Err("Applicative case inventory is incomplete or duplicated".into());
        }
        Ok(())
    }

    #[test]
    fn applicative_matrix_has_exact_inventory_and_every_case_is_required() {
        let cases = runtime_applicative_cases();
        let expected = expected_applicative_case_ids();
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        validate_applicative_inventory(&cases).unwrap();
        assert_eq!(actual, expected);
        crate::validate_evidence_catalog(&cases)
            .expect("Applicative tranche descriptors are canonical");
        for omitted in &expected {
            let reduced = cases
                .iter()
                .filter(|case| case.id.as_ref() != omitted)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                validate_applicative_inventory(&reduced).is_err(),
                "omitted Applicative case {omitted}"
            );
        }
    }

    #[test]
    fn applicative_empty_callback_contracts_are_exactly_limited_to_zero_call_paths() {
        let cases = runtime_applicative_cases();
        crate::validate_evidence_catalog(&cases).expect("zero-call Applicative paths are valid");
        for slug in ["apply", "apply-flipped"] {
            for path in [
                "io-short",
                "maybe-short",
                "list-short",
                "parser-absent",
                "parser-consumed-missing",
                "either-short",
            ] {
                let id = format!("runtime-typed-applicative-{slug}-{path}");
                let case = cases.iter().find(|case| case.id.as_ref() == id).unwrap();
                let contracts = &case.claim_evidence.as_ref().unwrap().callback_contracts;
                assert_eq!(contracts.len(), 1, "{id} exact callback contract");
                assert!(contracts[0].invocations.is_empty(), "{id} is zero-call");
            }
        }

        let mut forged = cases;
        let success = forged
            .iter_mut()
            .find(|case| case.id.as_ref() == "runtime-typed-applicative-apply-tree-branching")
            .unwrap();
        success.claim_evidence.as_mut().unwrap().callback_contracts[0]
            .invocations
            .clear();
        assert!(crate::validate_evidence_catalog(&forged).is_err());
    }

    fn expected_semigroup_case_ids() -> std::collections::BTreeSet<String> {
        [
            (
                "text",
                &["ordered", "unicode", "left-empty", "right-empty"][..],
            ),
            (
                "builder",
                &["ordered", "left-empty", "right-empty", "arbitrary-bytes"][..],
            ),
            ("vector", &["ordered", "left-empty", "right-empty"][..]),
            (
                "list",
                &["ordered", "left-empty", "right-empty", "lazy-tail"][..],
            ),
            (
                "either",
                &["left-left", "left-right", "right-left", "right-nonforce"][..],
            ),
            ("options-mod", &["left-right", "right-left"][..]),
            (
                "options-info-mod",
                &[
                    "right-precedence",
                    "reversed-precedence",
                    "full-description",
                ][..],
            ),
            (
                "maybe-text",
                &["nothing-left", "nothing-right", "just-combine"][..],
            ),
        ]
        .into_iter()
        .flat_map(|(scope, paths)| {
            paths
                .iter()
                .map(move |path| format!("runtime-typed-semigroup-{scope}-{path}"))
        })
        .collect()
    }

    fn validate_semigroup_inventory(cases: &[DifferentialCase]) -> Result<(), String> {
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        if actual.len() != cases.len() || actual != expected_semigroup_case_ids() {
            return Err("Semigroup case inventory is incomplete or duplicated".into());
        }
        Ok(())
    }

    #[test]
    fn semigroup_matrix_exactly_covers_manifest_scopes_and_requires_every_path() {
        let cases = runtime_semigroup_cases();
        validate_semigroup_inventory(&cases).unwrap();
        crate::validate_evidence_catalog(&cases).expect("Semigroup descriptors are canonical");
        let manifest = hell_builtins::instances()
            .iter()
            .filter(|instance| instance.class == hell_builtins::TypeClass::Semigroup)
            .map(|instance| (instance.target, instance.resolution.premise_count()))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            manifest,
            [
                ("Maybe", 1),
                ("Either", 0),
                ("Options.Mod", 0),
                ("Options.InfoMod", 0),
                ("Text", 0),
                ("Builder", 0),
                ("Vector", 0),
                ("[]", 0),
            ]
            .into_iter()
            .collect()
        );
        for omitted in expected_semigroup_case_ids() {
            let reduced = cases
                .iter()
                .filter(|case| case.id.as_ref() != omitted)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                validate_semigroup_inventory(&reduced).is_err(),
                "omitted Semigroup case {omitted}"
            );
        }
    }

    #[test]
    fn options_presentation_matrix_exactly_covers_every_public_options_target() {
        let cases = runtime_options_presentation_cases();
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        let expected = [
            "command",
            "exec-parser",
            "flag",
            "flag-prime",
            "full-desc",
            "header",
            "helper",
            "hsubparser",
            "info",
            "prog-desc",
            "str-argument",
            "str-option",
            "switch",
        ]
        .into_iter()
        .map(|slug| format!("runtime-options-presentation-{slug}"))
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual.len(), cases.len());
        assert_eq!(actual, expected);
        crate::validate_evidence_catalog(&cases)
            .expect("Options Presentation descriptors are canonical");

        let manifest = hell_builtins::registry()
            .iter()
            .filter(|spec| {
                spec.name.starts_with("Options.")
                    && spec
                        .assurance_metadata()
                        .sensitivities
                        .contains(&hell_builtins::AssuranceSensitivity::Presentation)
            })
            .map(|spec| spec.name)
            .collect::<std::collections::BTreeSet<_>>();
        let targets = cases
            .iter()
            .map(|case| {
                case.claim_evidence.as_ref().unwrap().semantic_targets[0]
                    .builtin
                    .as_ref()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(targets, manifest);

        let committed = crate::committed_differential_cases();
        for omitted in &expected {
            let target = cases
                .iter()
                .find(|case| case.id.as_ref() == omitted)
                .unwrap()
                .claim_evidence
                .as_ref()
                .unwrap()
                .semantic_targets[0]
                .builtin
                .clone();
            let reduced = committed
                .iter()
                .filter(|case| case.id.as_ref() != omitted)
                .cloned()
                .collect::<Vec<_>>();
            let error = crate::validate_runtime_obligation_coverage(&reduced)
                .expect_err("remaining runtime scope is intentionally incomplete");
            assert!(
                error.contains(&format!("{target}/Presentation")),
                "omitting {omitted} did not reopen {target}/Presentation: {error}"
            );
        }
    }

    #[test]
    fn current_directory_differentials_are_upstream_and_success_bound() {
        let cases = runtime_directory_observation_cases();
        let selected = cases
            .iter()
            .filter(|case| {
                matches!(
                    case.id.as_ref(),
                    "runtime-current-directory-roundtrip"
                        | "runtime-current-directory-upstream-available"
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected[0].claim_evidence.as_ref().unwrap().profile,
            ExecutionProfile::Upstream
        );
        assert_eq!(
            selected[1].claim_evidence.as_ref().unwrap().profile,
            ExecutionProfile::Upstream
        );
        crate::validate_evidence_catalog(&cases)
            .expect("current-directory profile descriptors are canonical");
    }

    const EQ_LIST_EXPECTED_BUILTIN_PATHS: &[(&str, &[&str])] = &[
        (
            "lookup",
            &[
                "empty-input",
                "singleton-input",
                "finite-input",
                "finite-miss",
                "duplicate-first-bias",
            ],
        ),
        (
            "elem",
            &[
                "empty-input",
                "singleton-input",
                "finite-input",
                "finite-miss",
            ],
        ),
        (
            "notelem",
            &[
                "empty-input",
                "singleton-input",
                "finite-input",
                "finite-miss",
            ],
        ),
        (
            "elemindex",
            &[
                "empty-input",
                "singleton-input",
                "finite-input",
                "finite-miss",
                "duplicate-first-bias",
            ],
        ),
        (
            "elemindices",
            &[
                "empty-input",
                "singleton-input",
                "finite-input",
                "finite-miss",
            ],
        ),
        ("group", &["empty-input", "singleton-input", "finite-input"]),
        (
            "isinfixof",
            &[
                "empty-input",
                "singleton-input",
                "finite-input",
                "empty-needle",
                "finite-order-mismatch",
            ],
        ),
        (
            "isprefixof",
            &[
                "empty-input",
                "singleton-input",
                "finite-input",
                "empty-needle",
                "finite-mismatch",
            ],
        ),
        (
            "issubsequenceof",
            &[
                "empty-input",
                "singleton-input",
                "finite-input",
                "empty-needle",
                "finite-order-mismatch",
            ],
        ),
        (
            "issuffixof",
            &[
                "empty-input",
                "singleton-input",
                "finite-input",
                "empty-needle",
                "finite-mismatch",
                "finite-longer-needle",
            ],
        ),
    ];

    fn expected_eq_list_boundary_ids() -> std::collections::BTreeSet<String> {
        let slugs = [
            "bool",
            "byte-string",
            "ci",
            "char",
            "double",
            "exit-code",
            "int",
            "integer",
            "text",
            "day",
            "day-of-week",
            "time-of-day",
            "utc-time",
            "tuple",
            "either",
            "maybe",
            "set",
            "tree",
            "vector",
            "list",
        ];
        EQ_LIST_EXPECTED_BUILTIN_PATHS
            .iter()
            .flat_map(|(builtin, paths)| {
                slugs.into_iter().flat_map(move |slug| {
                    paths
                        .iter()
                        .map(move |path| format!("runtime-eq-list-{builtin}-{slug}-{path}"))
                })
            })
            .collect()
    }

    fn validate_eq_list_boundary_inventory(cases: &[DifferentialCase]) -> Result<(), String> {
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        if actual.len() != cases.len() || actual != expected_eq_list_boundary_ids() {
            return Err("Eq/List boundary inventory is incomplete or duplicated".into());
        }
        Ok(())
    }

    #[test]
    fn eq_list_boundary_matrix_has_exact_instances_paths_and_deletion_authority() {
        let cases = runtime_eq_list_boundary_cases();
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        let expected = expected_eq_list_boundary_ids();
        validate_eq_list_boundary_inventory(&cases).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 920);
        crate::validate_evidence_catalog(&cases)
            .expect("Eq/List boundary descriptors are canonical");

        let roots = cases
            .iter()
            .flat_map(|case| {
                case.claim_evidence
                    .as_ref()
                    .unwrap()
                    .semantic_targets
                    .iter()
            })
            .filter_map(|target| target.expected_instance_target.as_deref())
            .collect::<std::collections::BTreeSet<_>>();
        let manifest = hell_builtins::instances()
            .iter()
            .filter(|instance| instance.class == hell_builtins::TypeClass::Eq)
            .map(|instance| instance.target)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(roots, manifest);

        for omitted in expected {
            let reduced = cases
                .iter()
                .filter(|case| case.id.as_ref() != omitted)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                validate_eq_list_boundary_inventory(&reduced).is_err(),
                "omitted Eq/List path {omitted}"
            );
        }
    }

    fn expected_ord_list_case_ids() -> std::collections::BTreeSet<String> {
        let slugs = ord_list_definitions()
            .into_iter()
            .map(|definition| definition.slug)
            .collect::<Vec<_>>();
        let mut ids = std::collections::BTreeSet::new();
        for slug in slugs {
            for (builtin, paths) in [
                (
                    "list-sort",
                    &["empty-input", "singleton-input", "finite-input"][..],
                ),
                (
                    "list-nubord",
                    &[
                        "empty-input",
                        "singleton-input",
                        "finite-input",
                        "all-unique",
                    ][..],
                ),
                (
                    "list-sorton",
                    &["empty-input", "singleton-input", "finite-input"][..],
                ),
            ] {
                for path in paths {
                    ids.insert(format!("runtime-ord-list-{builtin}-{slug}-{path}"));
                }
            }
        }
        for builtin in ["list-sort", "list-nubord", "list-sorton"] {
            ids.insert(format!("runtime-ord-list-{builtin}-ci-ci-folded-stability"));
            ids.insert(format!(
                "runtime-ord-list-{builtin}-byte-string-invalid-bytes"
            ));
            for path in ["signed-zero-stability", "infinities", "nan-finite"] {
                ids.insert(format!("runtime-ord-list-{builtin}-double-{path}"));
            }
        }
        ids.insert("runtime-ord-list-list-nubord-double-nan-finite-set-routing".to_owned());
        for builtin in ["list-sort", "list-sorton"] {
            for path in ["nan-before-finite", "finite-before-nan"] {
                ids.insert(format!("runtime-ord-list-{builtin}-double-{path}"));
            }
            ids.insert(format!(
                "runtime-ord-list-{builtin}-double-nan-alternating-runs"
            ));
        }
        ids.insert("runtime-ord-list-list-nubord-double-nan-size-balanced-routing".to_owned());
        ids
    }

    fn validate_ord_list_inventory(cases: &[DifferentialCase]) -> Result<(), String> {
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        if actual.len() != cases.len() || actual != expected_ord_list_case_ids() {
            return Err("Ord/List inventory is incomplete or duplicated".into());
        }
        for case in cases {
            let descriptor = case
                .claim_evidence
                .as_ref()
                .ok_or_else(|| format!("{} lacks Ord/List evidence", case.id))?;
            if descriptor.semantic_targets.len() != 1
                || descriptor.targets.len() != 1
                || descriptor.semantic_targets[0].dimension != CompatibilityDimension::PureRuntime
                || descriptor.semantic_targets[0]
                    .expected_instance_target
                    .is_none()
                || descriptor.semantic_targets[0]
                    .expected_typed_result_sha256
                    .is_none()
                || descriptor.semantic_targets[0]
                    .expected_raw_presentation_sha256
                    .is_none()
                || descriptor.semantic_targets[0]
                    .expected_process_status_sha256
                    .is_none()
            {
                return Err(format!("{} has incomplete Ord/List authority", case.id));
            }
            let sort_on = case.id.contains("-list-sorton-");
            if descriptor.callback_contracts.len() != usize::from(sort_on)
                || descriptor
                    .callback_contracts
                    .first()
                    .is_some_and(|contract| contract.builtin.as_ref() != "List.sortOn")
            {
                return Err(format!("{} has the wrong callback inventory", case.id));
            }
        }
        Ok(())
    }

    #[test]
    fn ord_list_matrix_has_exact_inventory_and_every_case_is_required() {
        let cases = runtime_ord_list_boundary_cases();
        let expected = expected_ord_list_case_ids();
        assert_eq!(expected.len(), 223);
        validate_ord_list_inventory(&cases).unwrap();
        crate::validate_evidence_catalog(&cases).expect("Ord/List descriptors are canonical");
        for omitted in expected {
            let reduced = cases
                .iter()
                .filter(|case| case.id.as_ref() != omitted)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                validate_ord_list_inventory(&reduced).is_err(),
                "omitted Ord/List path {omitted}"
            );
        }
        for index in 0..cases.len() {
            let mut reduced = cases.clone();
            let descriptor = reduced[index].claim_evidence.as_mut().unwrap();
            descriptor.semantic_targets.clear();
            descriptor.targets.clear();
            assert!(
                validate_ord_list_inventory(&reduced).is_err(),
                "removed Ord/List target from {}",
                cases[index].id,
            );
        }
    }

    #[test]
    fn ord_list_matrix_has_exact_isolated_cell_and_boundary_delta() {
        let cases = dormant_committed_differential_cases();
        let after = crate::validate_runtime_obligation_coverage(&cases)
            .expect_err("the remaining runtime catalog is intentionally incomplete");
        assert!(
            after.contains("138 incomplete cells, 14 boundary gaps, and 0 interaction gaps"),
            "{after}"
        );
        let before = cases
            .into_iter()
            .filter(|case| !case.id.starts_with("runtime-ord-list-"))
            .collect::<Vec<_>>();
        let before = crate::validate_runtime_obligation_coverage(&before)
            .expect_err("removing Ord/List reopens its exact scope");
        assert!(
            before.contains("141 incomplete cells, 17 boundary gaps, and 0 interaction gaps"),
            "{before}"
        );
    }

    fn expected_ord_map_boundary_ids() -> std::collections::BTreeSet<String> {
        const BUILTINS: &[&str] = &[
            "fromlist",
            "lookup",
            "insert",
            "delete",
            "insertwith",
            "adjust",
            "unionwith",
        ];
        let slugs = ord_list_definitions()
            .into_iter()
            .map(|definition| definition.slug)
            .collect::<Vec<_>>();
        let mut ids = BUILTINS
            .iter()
            .flat_map(|builtin| {
                slugs.iter().flat_map(move |slug| {
                    ["empty-input", "singleton-input", "finite-input"]
                        .map(move |boundary| format!("runtime-ord-map-{builtin}-{slug}-{boundary}"))
                })
            })
            .collect::<std::collections::BTreeSet<_>>();
        for slug in slugs {
            for (builtin, path) in [
                ("lookup", "nonempty-miss"),
                ("lookup", "nonempty-miss-left"),
                ("insert", "nonempty-absent"),
                ("insert", "nonempty-absent-left"),
                ("delete", "nonempty-miss"),
                ("delete", "nonempty-miss-left"),
                ("insertwith", "nonempty-absent"),
                ("insertwith", "nonempty-absent-left"),
                ("adjust", "nonempty-miss"),
                ("adjust", "nonempty-miss-left"),
                ("unionwith", "nonempty-disjoint"),
                ("unionwith", "multi-collision"),
                ("unionwith", "left-singleton-multi-right"),
            ] {
                ids.insert(format!("runtime-ord-map-{builtin}-{slug}-{path}"));
            }
        }
        ids.extend([
            "runtime-ord-map-fromlist-int-value-nonforce".to_owned(),
            "runtime-ord-map-lookup-int-just-payload-nonforce".to_owned(),
            "runtime-ord-map-insert-int-values-nonforce".to_owned(),
            "runtime-ord-map-delete-int-retained-value-nonforce".to_owned(),
            "runtime-ord-map-insertwith-int-callback-result-nonforce".to_owned(),
            "runtime-ord-map-adjust-int-callback-result-nonforce".to_owned(),
            "runtime-ord-map-unionwith-int-callback-result-nonforce".to_owned(),
            "runtime-ord-map-fromlist-ci-equal-representative-later".to_owned(),
            "runtime-ord-map-insert-ci-equal-representative-new-key".to_owned(),
            "runtime-ord-map-insertwith-ci-equal-representative-new-key".to_owned(),
            "runtime-ord-map-adjust-ci-equivalent-query-preserves-old-key".to_owned(),
            "runtime-ord-map-lookup-ci-equivalent-query".to_owned(),
            "runtime-ord-map-delete-ci-equivalent-query".to_owned(),
            "runtime-ord-map-fromlist-double-signed-zero-representative-later".to_owned(),
            "runtime-ord-map-insert-double-signed-zero-representative-new-key".to_owned(),
            "runtime-ord-map-insertwith-double-signed-zero-representative-new-key".to_owned(),
            "runtime-ord-map-adjust-double-signed-zero-query-preserves-old-key".to_owned(),
            "runtime-ord-map-lookup-double-signed-zero-equivalent-query".to_owned(),
            "runtime-ord-map-delete-double-signed-zero-equivalent-query".to_owned(),
            "runtime-ord-map-unionwith-ci-ci-left-representative".to_owned(),
            "runtime-ord-map-unionwith-double-signed-zero-left-representative".to_owned(),
            "runtime-ord-map-delete-int-two-child-interior".to_owned(),
            "runtime-ord-map-unionwith-int-multi-disjoint".to_owned(),
            "runtime-ord-map-lookup-double-nan-routing-miss".to_owned(),
            "runtime-ord-map-delete-double-nan-routing-miss".to_owned(),
            "runtime-ord-map-insert-double-nan-routing".to_owned(),
            "runtime-ord-map-unionwith-double-nan-shape-routing".to_owned(),
        ]);
        ids.extend(
            (1..=5).map(|index| format!("runtime-ord-map-fromlist-double-create-chunk-{index}")),
        );
        ids
    }

    fn validate_ord_map_boundary_inventory(cases: &[DifferentialCase]) -> Result<(), String> {
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        if actual.len() != cases.len() || actual != expected_ord_map_boundary_ids() {
            return Err("Ord/Map boundary inventory is incomplete or duplicated".into());
        }
        for case in cases {
            let descriptor = case
                .claim_evidence
                .as_ref()
                .ok_or_else(|| format!("{} has no retained descriptor", case.id))?;
            let [target] = descriptor.semantic_targets.as_slice() else {
                return Err(format!("{} does not bind one exact target", case.id));
            };
            if target.dimension != hell_builtins::CompatibilityDimension::PureRuntime
                || target.expected_instance_target.is_none()
                || target.expected_comparator_trace_sha256.is_none()
                || target.expected_typed_result_sha256.is_none()
                || target.expected_raw_presentation_sha256.is_none()
                || target.expected_process_status_sha256.is_none()
            {
                return Err(format!("{} lacks exact Ord/Map authority", case.id));
            }
            let definition = ord_list_definitions()
                .into_iter()
                .find(|definition| {
                    target.expected_instance_target.as_deref() == Some(definition.target)
                        && target.expected_instance_premises
                            == definition
                                .premises
                                .iter()
                                .map(|(target, premise_count)| crate::InstancePremiseEvidence {
                                    target: Arc::from(*target),
                                    premise_count: *premise_count,
                                })
                                .collect::<Vec<_>>()
                })
                .ok_or_else(|| format!("{} binds an unknown Ord plan", case.id))?;
            if !case.id.contains(&format!("-{}-", definition.slug)) {
                return Err(format!("{} instance slug disagrees with its plan", case.id));
            }
            let callback_target = matches!(
                target.builtin.as_ref(),
                "Map.insertWith" | "Map.adjust" | "Map.unionWith"
            );
            if descriptor.callback_contracts.len() != usize::from(callback_target)
                || descriptor
                    .callback_contracts
                    .first()
                    .is_some_and(|contract| contract.builtin != target.builtin)
            {
                return Err(format!("{} callback authority is not exact", case.id));
            }
        }
        Ok(())
    }

    #[test]
    fn ord_map_boundary_matrix_has_exact_inventory_and_every_case_is_required() {
        let cases = runtime_ord_map_cases();
        validate_ord_map_boundary_inventory(&cases).unwrap();
        assert_eq!(cases.len(), 712);
        crate::validate_evidence_catalog(&cases)
            .expect("Ord/Map boundary descriptors are canonical");

        let expected = expected_ord_map_boundary_ids();
        for omitted in expected {
            let reduced = cases
                .iter()
                .filter(|case| case.id.as_ref() != omitted)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                validate_ord_map_boundary_inventory(&reduced).is_err(),
                "omitted Ord/Map path {omitted}"
            );
        }
    }

    #[test]
    fn ord_map_matrix_has_exact_isolated_cell_and_boundary_delta() {
        let mut cases = dormant_committed_differential_cases();
        let before = crate::validate_runtime_obligation_coverage(&cases)
            .expect_err("the committed runtime catalog is intentionally incomplete");
        assert!(
            before.contains("138 incomplete cells, 14 boundary gaps, and 0 interaction gaps"),
            "{before}"
        );
        cases.extend(runtime_ord_map_cases());
        let after = crate::validate_runtime_obligation_coverage(&cases)
            .expect_err("the remaining runtime catalog is intentionally incomplete");
        assert!(
            after.contains("131 incomplete cells, 7 boundary gaps, and 0 interaction gaps"),
            "{after}"
        );
    }

    fn expected_ord_set_boundary_ids() -> std::collections::BTreeSet<String> {
        const BUILTINS: &[&str] = &[
            "fromlist",
            "insert",
            "member",
            "delete",
            "union",
            "difference",
            "intersection",
        ];
        let slugs = ord_list_definitions()
            .into_iter()
            .map(|definition| definition.slug)
            .collect::<Vec<_>>();
        BUILTINS
            .iter()
            .flat_map(|builtin| {
                slugs.iter().flat_map(move |slug| {
                    ["empty-input", "singleton-input", "finite-input"]
                        .map(move |boundary| format!("runtime-ord-set-{builtin}-{slug}-{boundary}"))
                })
            })
            .collect()
    }

    fn validate_ord_set_boundary_inventory(cases: &[DifferentialCase]) -> Result<(), String> {
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        if actual.len() != cases.len() || actual != expected_ord_set_boundary_ids() {
            return Err("Ord/Set boundary inventory is incomplete or duplicated".into());
        }
        for case in cases {
            let descriptor = case
                .claim_evidence
                .as_ref()
                .ok_or_else(|| format!("{} lacks Ord/Set evidence", case.id))?;
            if descriptor.semantic_targets.len() != 1
                || descriptor.targets.len() != 1
                || descriptor.semantic_targets[0].dimension != CompatibilityDimension::PureRuntime
                || descriptor.semantic_targets[0]
                    .expected_instance_target
                    .is_none()
                || descriptor.semantic_targets[0]
                    .expected_typed_result_sha256
                    .is_none()
                || descriptor.semantic_targets[0]
                    .expected_raw_presentation_sha256
                    .is_none()
                || descriptor.semantic_targets[0]
                    .expected_process_status_sha256
                    .is_none()
                || !descriptor.callback_contracts.is_empty()
            {
                return Err(format!("{} has incomplete Ord/Set authority", case.id));
            }
        }
        Ok(())
    }

    #[test]
    fn ord_set_boundary_matrix_has_exact_inventory_and_every_case_is_required() {
        let cases = runtime_ord_set_boundary_cases();
        validate_ord_set_boundary_inventory(&cases).unwrap();
        assert_eq!(cases.len(), 420);
        crate::validate_evidence_catalog(&cases)
            .expect("Ord/Set boundary descriptors are canonical");

        let expected = expected_ord_set_boundary_ids();
        for omitted in expected {
            let reduced = cases
                .iter()
                .filter(|case| case.id.as_ref() != omitted)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                validate_ord_set_boundary_inventory(&reduced).is_err(),
                "omitted Ord/Set path {omitted}"
            );
        }
    }

    fn expected_ord_set_auxiliary_ids() -> std::collections::BTreeSet<String> {
        let mut ids = expected_ord_set_primary_auxiliary_ids();
        ids.extend(expected_ord_set_secondary_auxiliary_ids());
        ids
    }

    fn expected_ord_set_primary_auxiliary_ids() -> std::collections::BTreeSet<String> {
        let mut ids = std::collections::BTreeSet::new();
        for (builtin, slug, paths) in [
            (
                "fromlist",
                "ci",
                &[
                    "equal-representative-forward",
                    "equal-representative-reverse",
                ][..],
            ),
            (
                "fromlist",
                "double",
                &[
                    "signed-zero-forward",
                    "signed-zero-reverse",
                    "create-chunk-1",
                    "create-chunk-2",
                    "create-chunk-3",
                    "create-chunk-4",
                    "create-chunk-5",
                ][..],
            ),
            ("insert", "ci", &["equal-representative-replacement"][..]),
            ("insert", "double", &["signed-zero-replacement"][..]),
            ("insert", "int", &["absent-left", "absent-right"][..]),
            ("member", "int", &["nonempty-miss"][..]),
            (
                "delete",
                "int",
                &["nonempty-miss", "two-child-interior"][..],
            ),
            ("delete", "double", &["nan-routing-miss"][..]),
            (
                "union",
                "ci",
                &[
                    "left-representative-forward",
                    "left-representative-reverse",
                    "right-singleton-equal",
                    "left-singleton-equal",
                    "multi-equal-overlap",
                ][..],
            ),
            (
                "union",
                "double",
                &[
                    "signed-zero-left-forward",
                    "signed-zero-left-reverse",
                    "right-singleton-signed-zero",
                    "left-singleton-signed-zero",
                    "nan-shape-routing",
                    "nan-shape-routing-reverse",
                    "shared-tree-delete-routing",
                ][..],
            ),
            (
                "union",
                "int",
                &[
                    "empty-left",
                    "empty-right",
                    "disjoint-left-small",
                    "disjoint-right-small",
                    "overlap",
                ][..],
            ),
        ] {
            ids.extend(
                paths
                    .iter()
                    .map(|path| format!("runtime-ord-set-{builtin}-{slug}-{path}")),
            );
        }
        ids
    }

    fn expected_ord_set_secondary_auxiliary_ids() -> std::collections::BTreeSet<String> {
        let mut ids = std::collections::BTreeSet::new();
        for (builtin, slug, paths) in [
            (
                "difference",
                "double",
                &[
                    "nan-shape-routing",
                    "nan-shape-routing-reverse",
                    "disjoint-size-preserved-member-outcome",
                ][..],
            ),
            (
                "difference",
                "int",
                &[
                    "empty-left",
                    "empty-right",
                    "disjoint",
                    "overlap",
                    "identical",
                    "right-superset",
                    "left-skewed",
                    "right-skewed",
                ][..],
            ),
            (
                "intersection",
                "ci",
                &[
                    "left-representative-forward",
                    "left-representative-reverse",
                    "multi-equal-overlap",
                ][..],
            ),
            (
                "intersection",
                "double",
                &[
                    "signed-zero-left-forward",
                    "signed-zero-left-reverse",
                    "nan-shape-routing",
                    "nan-shape-routing-reverse",
                    "shared-tree-delete-routing",
                ][..],
            ),
            (
                "intersection",
                "int",
                &[
                    "empty-left",
                    "empty-right",
                    "disjoint",
                    "overlap",
                    "left-skewed",
                    "right-skewed",
                ][..],
            ),
        ] {
            ids.extend(
                paths
                    .iter()
                    .map(|path| format!("runtime-ord-set-{builtin}-{slug}-{path}")),
            );
        }
        ids
    }

    fn validate_ord_set_inventory(cases: &[DifferentialCase]) -> Result<(), String> {
        let expected = expected_ord_set_boundary_ids()
            .into_iter()
            .chain(expected_ord_set_auxiliary_ids())
            .collect::<std::collections::BTreeSet<_>>();
        let actual = cases
            .iter()
            .map(|case| case.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        if actual.len() != cases.len() || actual != expected {
            return Err("Ord/Set inventory is incomplete or duplicated".into());
        }
        for case in cases {
            let descriptor = case
                .claim_evidence
                .as_ref()
                .ok_or_else(|| format!("{} lacks Ord/Set evidence", case.id))?;
            if descriptor.semantic_targets.len() != 1
                || descriptor.targets.len() != 1
                || descriptor.semantic_targets[0].dimension != CompatibilityDimension::PureRuntime
                || descriptor.semantic_targets[0]
                    .expected_instance_target
                    .is_none()
                || descriptor.semantic_targets[0]
                    .expected_typed_result_sha256
                    .is_none()
                || descriptor.semantic_targets[0]
                    .expected_raw_presentation_sha256
                    .is_none()
                || descriptor.semantic_targets[0]
                    .expected_process_status_sha256
                    .is_none()
                || !descriptor.callback_contracts.is_empty()
            {
                return Err(format!("{} has incomplete Ord/Set authority", case.id));
            }
        }
        Ok(())
    }

    #[test]
    fn ord_set_matrix_has_exact_inventory_and_every_case_is_required() {
        let cases = runtime_ord_set_cases();
        assert_eq!(cases.len(), 479);
        validate_ord_set_inventory(&cases).unwrap();
        crate::validate_evidence_catalog(&cases).expect("Ord/Set descriptors are canonical");
        for omitted in cases.iter().map(|case| case.id.clone()) {
            let reduced = cases
                .iter()
                .filter(|case| case.id != omitted)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                validate_ord_set_inventory(&reduced).is_err(),
                "omitted Ord/Set path {omitted}"
            );
        }
    }

    #[test]
    fn collection_activation_manifest_is_exact_and_atomic() {
        assert!(matches!(
            COLLECTION_ACTIVATION,
            DORMANT_COLLECTION_ACTIVATION | ACTIVE_COLLECTION_ACTIVATION
        ));
        let (map, set) = collection_activation_flags();
        assert_eq!(map, set, "collection activation must remain atomic");
    }

    #[test]
    fn collection_activation_provenance_is_canonical_and_two_role() {
        let digest = "a".repeat(64);
        let reviewer_fingerprint = "b".repeat(64);
        let commit = "c".repeat(40);
        let active = format!(
            "{{\"activationAuthorAuthorizationSha256\":\"{digest}\",\"activationAuthorPacketSha256\":\"{digest}\",\"activationAuthorSha256\":\"{digest}\",\"activationAuthorSignerFingerprint\":\"{digest}\",\"activationAuthorSubject\":\"author-1\",\"activationAuthority\":false,\"activationClaimsSha256\":\"{digest}\",\"activationProposalSha256\":\"{digest}\",\"activationReviewAuthorizationSha256\":\"{digest}\",\"activationReviewPacketSha256\":\"{digest}\",\"activationReviewSha256\":\"{digest}\",\"activationReviewSignerFingerprint\":\"{reviewer_fingerprint}\",\"activationReviewSubject\":\"reviewer-2\",\"activationTokenSha256\":\"{digest}\",\"baseCandidateCommit\":\"{commit}\",\"corpusMappingSha256\":\"{digest}\",\"domain\":\"hell.collection-activation.provenance.v1\",\"freshCollectionRequired\":true,\"historicalCollectionCandidateCommit\":\"{commit}\",\"integrationProofSha256\":\"{digest}\",\"integrationReviewSha256\":\"{digest}\",\"mapCaseCount\":712,\"outerArchiveSha256\":\"{digest}\",\"outerArtifactId\":6,\"outerCandidateCommit\":\"{commit}\",\"outerDirectorySha256\":\"{digest}\",\"outerRunAttempt\":5,\"outerRunId\":4,\"outerSelectionSha256\":\"{digest}\",\"outerWorkflowPath\":\".github/workflows/collection-activation-preparation.yml\",\"packageTreeSha256\":\"{digest}\",\"payloadMerkleRoot\":\"{digest}\",\"promotionAuthority\":false,\"providerArchiveSha256\":\"{digest}\",\"providerArtifactId\":3,\"providerDirectorySha256\":\"{digest}\",\"providerRunAttempt\":2,\"providerRunId\":1,\"providerSelectionSha256\":\"{digest}\",\"providerWorkflowPath\":\".github/workflows/collection-custody-integration.yml\",\"replayCaseCount\":1191,\"replayObservationRootSha256\":\"{digest}\",\"schemaVersion\":1,\"setCaseCount\":479,\"signatureTreeSha256\":\"{digest}\",\"state\":\"reviewed-activation-requires-fresh-collection\",\"wormCustodyIdentitySha256\":\"{digest}\"}}\n"
        );
        assert!(verify_active_collection_provenance(active.as_bytes()).is_ok());
        assert_eq!(
            verify_collection_activation_state(
                DORMANT_COLLECTION_ACTIVATION.as_bytes(),
                DORMANT_COLLECTION_PROVENANCE.as_bytes(),
                DORMANT_COLLECTION_CLAIMS.as_bytes(),
            ),
            Ok(false)
        );
        for mutant in [
            active.replacen('{', "{\"extra\":true,", 1),
            active.replace("reviewer-2", "author-1"),
            active.replace(
                "\"promotionAuthority\":false",
                "\"promotionAuthority\":true",
            ),
            active.replace(&commit, &"C".repeat(40)),
        ] {
            assert!(verify_active_collection_provenance(mutant.as_bytes()).is_err());
        }
    }

    #[test]
    fn generation_is_stable_and_semantically_varied() {
        let first = generated_typed_cases(0x4845_4c4c_2026, 20);
        let second = generated_typed_cases(0x4845_4c4c_2026, 20);
        assert_eq!(first, second);
        assert_eq!(first.len(), 20);
        assert!(first.iter().any(|case| case.id.contains("json")));
        assert!(first.iter().any(|case| case.id.contains("variant")));
        assert!(first.iter().any(|case| case.id.contains("short-circuit")));
        assert!(first.iter().all(|case| case.source.ends_with('\n')));
    }

    #[test]
    fn cycle_empty_boundary_binds_failure_status_presentation_and_adapter_path() {
        let cases = runtime_cycle_boundary_cases();
        let empty = cases
            .iter()
            .find(|case| case.id.as_ref() == "list-cycle-boundary-empty-input")
            .expect("List.cycle empty boundary");
        assert!(!empty.expected_runtime_completion);
        let target = &empty
            .claim_evidence
            .as_ref()
            .expect("List.cycle empty descriptor")
            .semantic_targets[0];
        assert_eq!(
            target
                .obligations
                .iter()
                .map(|obligation| obligation.0.as_ref())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "adapter-success",
                "result-force-failure",
                "whnf-boundary",
            ])
        );
        assert_eq!(
            target.expected_process_status_sha256,
            Some(crate::process_status_sha256(false, Some(1)))
        );
        assert_eq!(
            target.expected_raw_presentation_sha256,
            Some(crate::raw_presentation_sha256(
                b"",
                concat!(
                    "hell: Prelude.cycle: empty list\n",
                    "CallStack (from HasCallStack):\n",
                    "  error, called at libraries/base/GHC/List.hs:2004:3 in base:GHC.List\n",
                    "  errorEmptyList, called at libraries/base/GHC/List.hs:972:27 in base:GHC.List\n",
                    "  cycle, called at src/Hell.hs:1953:4 in main:Main\n",
                )
                .as_bytes(),
            ))
        );
        crate::validate_semantic_target_obligations(empty, target)
            .expect("List.cycle result-force descriptor is complete");
    }

    #[test]
    fn cycle_empty_boundary_rejects_incomplete_result_force_authority() {
        let cases = runtime_cycle_boundary_cases();
        let empty = cases
            .iter()
            .find(|case| case.id.as_ref() == "list-cycle-boundary-empty-input")
            .expect("List.cycle empty boundary");
        let target = &empty
            .claim_evidence
            .as_ref()
            .expect("List.cycle empty descriptor")
            .semantic_targets[0];
        for (name, mutate) in [
            (
                "missing obligation",
                (|target: &mut crate::EvidenceTargetV2| {
                    target
                        .obligations
                        .retain(|item| item.0.as_ref() != "result-force-failure");
                }) as fn(&mut crate::EvidenceTargetV2),
            ),
            ("missing typed result", |target| {
                target.expected_typed_result_sha256 = None;
            }),
            ("missing status", |target| {
                target.expected_process_status_sha256 = None;
            }),
            ("missing raw presentation", |target| {
                target.expected_raw_presentation_sha256 = None;
            }),
            ("failure-path contamination", |target| {
                target
                    .obligations
                    .push(crate::ObligationId(Arc::from("adapter-failure")));
            }),
        ] {
            let mut mutant = target.clone();
            mutate(&mut mutant);
            assert!(
                crate::validate_semantic_target_obligations(empty, &mutant).is_err(),
                "{name} was accepted"
            );
        }
        let mut completion = empty.clone();
        completion.expected_runtime_completion = true;
        assert!(
            crate::validate_semantic_target_obligations(
                &completion,
                &completion.claim_evidence.as_ref().unwrap().semantic_targets[0],
            )
            .is_err(),
            "successful completion contaminated the result-force failure"
        );
    }

    #[test]
    fn cycle_success_boundaries_and_collection_closure_omit_result_force_failure() {
        let cases = runtime_cycle_boundary_cases();
        let empty_id = "list-cycle-boundary-empty-input";
        for success in cases.iter().filter(|case| case.id.as_ref() != empty_id) {
            assert!(success.expected_runtime_completion);
            let obligations =
                &success.claim_evidence.as_ref().unwrap().semantic_targets[0].obligations;
            assert!(
                obligations
                    .iter()
                    .any(|item| item.0.as_ref() == "adapter-success")
            );
            assert!(
                !obligations
                    .iter()
                    .any(|item| item.0.as_ref() == "result-force-failure")
            );
            let mut contaminated = success.clone();
            contaminated
                .claim_evidence
                .as_mut()
                .unwrap()
                .semantic_targets[0]
                .obligations
                .push(crate::ObligationId(Arc::from("result-force-failure")));
            assert!(
                crate::validate_semantic_target_obligations(
                    &contaminated,
                    &contaminated
                        .claim_evidence
                        .as_ref()
                        .unwrap()
                        .semantic_targets[0],
                )
                .is_err(),
                "a successful List.cycle boundary claimed result-force failure"
            );
        }
        let closure = runtime_collection_obligations_case();
        let closure_target = closure
            .claim_evidence
            .as_ref()
            .unwrap()
            .semantic_targets
            .iter()
            .find(|target| {
                target.builtin.as_ref() == "List.cycle"
                    && target.dimension == CompatibilityDimension::PureRuntime
            })
            .expect("successful collection closure List.cycle target");
        assert!(
            closure_target
                .obligations
                .iter()
                .all(|item| item.0.as_ref() != "result-force-failure"),
            "the successful collection closure claimed result-force failure"
        );
    }
}
