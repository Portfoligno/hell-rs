use hell_compiler::{CompilerSession, compile_source};

fn check(source: &str) {
    compile_source(&mut CompilerSession::default(), "record.hell", source).unwrap();
}

#[test]
fn record_intrinsics_resolve_a_directly_bound_local_record() {
    check(
        r#"data Foo = Foo { bar, mu :: Int }
main = do
  let bar = 123
  let mu = 666
  let record = Main.Foo { bar, mu }
  IO.print $ Record.get @"bar" @Int record
"#,
    );

    check(
        r#"data Foo = Foo { bar, mu :: Int }
main :: IO () = Main.foo
foo = do
  let bar = 123
  let mu = 666
  let record = Main.Foo { bar, mu }
  IO.print $ (Record.get @"bar" record :: Int)
"#,
    );
}
