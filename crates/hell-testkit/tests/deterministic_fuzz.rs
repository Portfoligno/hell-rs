use hell_compiler::{CompilerConfig, CompilerSession};
use hell_source::{SourceMap, SourceName};
use hell_testkit::{DeterministicBytes, DeterministicUtf8};

#[cfg(feature = "compat-tracing")]
use hell_compiler::compile_source;

#[test]
fn bounded_arbitrary_bytes_never_escape_source_parser_or_compiler_errors() {
    for (index, bytes) in DeterministicBytes::new(0xc0de_2026, 256, 256).enumerate() {
        let mut sources = SourceMap::new();
        let _ = sources.add_bytes(SourceName::Virtual(format!("bytes-{index}").into()), bytes);
    }

    for (index, text) in DeterministicUtf8::new(0xc0de_2026, 256, 256).enumerate() {
        let mut sources = SourceMap::new();
        let source = sources.add_text(format!("utf8-{index}"), text);
        let _ = hell_syntax::parse(&source);
        let mut config = CompilerConfig::deterministic_test();
        config.limits.max_expansion_depth = Some(32);
        config.limits.max_elaborated_nodes = Some(16_384);
        let mut compiler = CompilerSession {
            config,
            ..CompilerSession::default()
        };
        let _ = hell_compiler::compile_source(
            &mut compiler,
            format!("utf8-{index}"),
            source.text.clone(),
        );
    }
}

#[cfg(feature = "compat-tracing")]
#[test]
fn bounded_list_map_inputs_retain_exact_callback_and_typed_result_evidence() {
    let target = hell_builtins::lookup("List.map").expect("List.map registry entry");
    let directory =
        std::env::temp_dir().join(format!("hell-list-map-properties-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create property trace directory");
    let mut compiler = CompilerSession::upstream();

    for (case_index, bytes) in DeterministicBytes::new(0x29_4c49_5354, 32, 8).enumerate() {
        let values = bytes
            .into_iter()
            .map(|byte| i64::from(byte % 17))
            .collect::<Vec<_>>();
        let list = values
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let source = format!("main = IO.print $ List.map (Int.plus 1) [{list}]\n");
        let program = compile_source(
            &mut compiler,
            format!("bounded-list-map-{case_index}"),
            source,
        )
        .unwrap_or_else(|error| panic!("case {case_index} did not compile: {error:?}"));
        let trace_path = directory.join(format!("case-{case_index}.json"));
        hell_runtime::run_main_with_semantic_trace_target(
            program,
            hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
            &trace_path,
            target.id,
        )
        .unwrap_or_else(|error| panic!("case {case_index} did not run: {error}"));
        let semantic = hell_testkit::parse_semantic_trace(
            &std::fs::read(&trace_path).expect("read property trace"),
        )
        .unwrap_or_else(|error| panic!("case {case_index} trace was invalid: {error}"));

        assert_eq!(semantic.typed_result_builtin, Some(target.id));
        let mapped = canonical_int_list(values.iter().map(|value| value + 1));
        let expected_result = format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{mapped}}}"
        );
        assert_eq!(
            semantic.typed_result_canonical.as_deref(),
            Some(expected_result.as_str())
        );
        let target_events = semantic
            .obligation_trace
            .iter()
            .filter(|event| event.builtin == target.id)
            .collect::<Vec<_>>();
        let [event] = target_events.as_slice() else {
            panic!("case {case_index} did not retain exactly one List.map event");
        };
        assert_eq!(event.callbacks.len(), values.len());
        for (invocation, (callback, value)) in event.callbacks.iter().zip(values.iter()).enumerate()
        {
            assert_eq!(callback.invocation, invocation as u64 + 1);
            assert_eq!(callback.callback_argument, 0);
            assert_eq!(callback.branch.as_ref(), "element");
            assert_eq!(callback.canonical_arguments.len(), 1);
            assert_eq!(
                callback.canonical_arguments[0].as_ref(),
                canonical_int(*value)
            );
            assert_eq!(callback.outcome.as_ref(), "value");
            assert_eq!(callback.canonical_result.as_ref(), canonical_int(value + 1));
        }
    }

    std::fs::remove_dir_all(directory).expect("remove property trace directory");
}

#[cfg(feature = "compat-tracing")]
fn canonical_int(value: i64) -> String {
    format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}")
}

#[cfg(feature = "compat-tracing")]
fn canonical_int_list(values: impl IntoIterator<Item = i64>) -> String {
    let elements = values
        .into_iter()
        .map(canonical_int)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"type\":\"List\",\"elements\":[{elements}],\"terminationHex\":\"6e696c\"}}")
}
