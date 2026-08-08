use hell_source::SourceMap;
use hell_syntax::{CasePattern, Declaration, Expr, TokenKind, lex, parse};

fn source(text: &str) -> std::sync::Arc<hell_source::SourceFile> {
    SourceMap::new().add_text("test.hell", text)
}

#[test]
fn nested_comments_and_shebang_preserve_layout() {
    let source = source("#!/usr/bin/env hell\n{- outer {- inner -} -}\nmain = IO.pure ()\n");
    let tokens = lex(&source).unwrap();
    assert!(matches!(tokens[0].kind, TokenKind::VirtualLBrace));
    let parsed = parse(&source).unwrap();
    assert_eq!(parsed.declarations.len(), 1);
}

#[test]
fn parses_lambda_application_and_annotation() {
    let parsed = parse(&source("main :: IO () = IO.pure ((\\x -> x) 1)\n")).unwrap();
    assert_eq!(parsed.declarations.len(), 1);
    assert!(matches!(
        &parsed.declarations[0],
        Declaration::Value(declaration) if declaration.annotation.is_some()
    ));
    assert!(
        parsed
            .expressions
            .iter()
            .any(|expr| matches!(expr, Expr::Lambda { .. }))
    );
}

#[test]
fn rejects_top_level_function_equations() {
    let errors = parse(&source("f x = x\nmain = IO.pure ()\n")).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("function equations"))
    );
}

#[test]
fn inserts_layout_for_do() {
    let parsed = parse(&source(
        "main = do\n  Text.putStrLn \"hello\"\n  IO.pure ()\n",
    ))
    .unwrap();
    assert!(
        parsed
            .expressions
            .iter()
            .any(|expr| matches!(expr, Expr::Do { statements, .. } if statements.len() == 2))
    );
}

#[test]
fn parenthesized_pattern_is_not_a_one_tuple() {
    parse(&source("main = IO.pure ((\\(x) -> x) ())\n")).unwrap();
}

#[test]
fn rejects_duplicate_tuple_binders_and_malformed_numbers() {
    assert!(parse(&source("main = IO.pure ((\\(x, x) -> x) (1, 2))\n")).is_err());
    for malformed in ["0x", "0o8", "1e"] {
        assert!(
            lex(&source(&format!("main = IO.pure {malformed}\n"))).is_err(),
            "{malformed}"
        );
    }
}

#[test]
fn unicode_columns_count_scalars_not_bytes() {
    let tokens = lex(&source("main = IO.pure \"é\"\n")).unwrap();
    let text = tokens
        .iter()
        .find(|token| matches!(token.kind, TokenKind::Text(_)))
        .unwrap();
    assert_eq!(text.column, 16);
}

#[test]
fn pragmas_are_rejected_explicitly() {
    let errors = lex(&source("{-# LANGUAGE GADTs #-}\nmain = IO.pure ()\n")).unwrap_err();
    assert!(errors.iter().any(|error| error.message.contains("pragmas")));
}

#[test]
fn parses_record_and_sum_declarations_canonically_enough_for_resolution() {
    let parsed = parse(&source(
        "data Person = Person { name :: Text, age, score :: Int }\n\
         data Answer = No | Yes Text\n\
         main = IO.pure ()\n",
    ))
    .unwrap();
    let Declaration::Record(record) = &parsed.declarations[0] else {
        panic!("expected record declaration");
    };
    assert_eq!(record.fields.len(), 3);
    assert_eq!(record.fields[1].name.as_ref(), "age");
    assert_eq!(record.fields[2].name.as_ref(), "score");
    let Declaration::Sum(sum) = &parsed.declarations[1] else {
        panic!("expected sum declaration");
    };
    assert_eq!(sum.constructors.len(), 2);
    assert!(sum.constructors[0].payload.is_none());
    assert!(sum.constructors[1].payload.is_some());
}

#[test]
fn parses_record_assignments_puns_and_case_patterns() {
    let parsed = parse(&source(
        "data Answer = No | Yes Text\n\
         name = \"Chris\"\n\
         value = Main.Person { name, age = 23 }\n\
         main = case Main.Yes \"ok\" of\n\
           No -> IO.pure ()\n\
           Yes answer -> Text.putStrLn answer\n",
    ))
    .unwrap();
    let record = parsed
        .expressions
        .iter()
        .find_map(|expression| match expression {
            Expr::RecordConstruction { fields, .. } => Some(fields),
            _ => None,
        })
        .unwrap();
    assert!(record[0].pun);
    assert!(!record[1].pun);
    let alternatives = parsed
        .expressions
        .iter()
        .find_map(|expression| match expression {
            Expr::Case { alternatives, .. } => Some(alternatives),
            _ => None,
        })
        .unwrap();
    assert!(matches!(
        alternatives[0].pattern,
        CasePattern::UserConstructor { binder: None, .. }
    ));
    assert!(matches!(
        alternatives[1].pattern,
        CasePattern::UserConstructor {
            binder: Some(_),
            ..
        }
    ));
}

#[test]
fn rejects_single_constructor_sum_and_non_atomic_payload_arity() {
    assert!(parse(&source("data Only = Only\nmain = IO.pure ()\n")).is_err());
    assert!(
        parse(&source(
            "data Bad = Empty | Bad Int Text\nmain = IO.pure ()\n"
        ))
        .is_err()
    );
}

#[test]
fn nested_explicit_record_braces_do_not_close_root_layout() {
    let parsed = parse(&source(
        "value = Main.Outer { inner = Main.Inner { text = \"ok\" } }\n\
         main = IO.pure ()\n",
    ))
    .unwrap();
    assert_eq!(parsed.declarations.len(), 2);
}

#[test]
fn case_layout_can_close_before_a_parenthesized_block_argument() {
    parse(&source(
        "main = IO.pure (case Bool.True of\n  Bool.True -> ())\n",
    ))
    .unwrap();
}

#[test]
fn excessive_expression_nesting_returns_a_structured_resource_limit() {
    const DEPTH: usize = 2_048;
    let text = format!(
        "main = IO.pure {}(){}\n",
        "Function.id (".repeat(DEPTH),
        ")".repeat(DEPTH)
    );
    let errors = parse(&source(&text)).expect_err("deep input must reach the parser boundary");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].code, "H0801");
    assert_eq!(
        errors[0].message.as_ref(),
        "parser nesting limit exceeded: operation=parse_nesting profile=sandboxed configured=64 observed=65"
    );
}
