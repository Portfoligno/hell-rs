use hell_source::SourceMap;
use hell_syntax::parse;

fn parses(source: &str) {
    let source = SourceMap::new().add_text("layout.hell", source);
    parse(&source).unwrap();
}

#[test]
fn parenthesized_inner_do_does_not_close_the_outer_do() {
    parses(
        r"main = do
  Maybe.maybe fallback callback
    (do x <- action
        IO.pure x)
  Either.either left right
    (do y <- action
        IO.pure y)
value = IO.pure ()
",
    );
}

#[test]
fn lambda_body_do_inside_parentheses_preserves_following_arguments() {
    parses(
        r"main = do
  fold (\x children -> do
    emit x
    traverse children
    emit end)
    tree
  IO.pure ()
",
    );
}
