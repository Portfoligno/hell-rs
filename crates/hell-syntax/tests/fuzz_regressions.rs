use hell_source::SourceMap;

#[test]
fn invalid_multibyte_escape_reports_an_error_without_splitting_utf8() {
    let mut sources = SourceMap::new();
    let source = sources.add_text("multibyte-escape.hell", "main = Text.putStrLn \"\\é\"\n");
    let errors = hell_syntax::parse(&source).expect_err("the escape is not part of Hell syntax");
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("invalid Haskell literal escape")),
        "unexpected diagnostics: {errors:?}"
    );
}
