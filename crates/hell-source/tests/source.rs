use hell_source::{SourceMap, Span};

#[test]
fn shebang_is_trivia_without_removing_its_newline() {
    let mut map = SourceMap::new();
    let source = map.add_text("script.hell", "#!/usr/bin/env hell\nmain = IO.pure ()\n");
    assert_eq!(source.shebang, Some(Span::new(source.id, 0, 19)));
    assert_eq!(source.line_column(20), Some((2, 1)));
    assert!(source.text.starts_with("#!"));
}

#[test]
fn tabs_use_eight_column_stops() {
    let mut map = SourceMap::new();
    let source = map.add_text("tabs", "\tfoo");
    assert_eq!(source.line_column(1), Some((1, 9)));
}

#[test]
fn invalid_utf8_reports_the_byte() {
    let mut map = SourceMap::new();
    let error = map
        .add_bytes(
            hell_source::SourceName::Virtual("bad".into()),
            vec![b'a', 0xff],
        )
        .unwrap_err();
    assert_eq!(error.valid_up_to, 1);
}
