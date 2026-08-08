use hell_compiler::{CompilerConfig, CompilerSession};
use hell_source::{SourceMap, SourceName};
use hell_testkit::{DeterministicBytes, DeterministicUtf8};

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
