use std::io::Write;
use std::sync::{Arc, Mutex};

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::{RuntimeContext, run_main};

#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn run(source: &str) -> String {
    let program = compile_source(&mut CompilerSession::default(), "json.hell", source)
        .expect("JSON compatibility source compiles");
    let bytes = Arc::new(Mutex::new(Vec::new()));
    run_main(
        program,
        RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&bytes))),
    )
    .unwrap();
    String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
}

#[test]
fn decoded_scientific_numbers_encode_without_f64_rounding_or_range_loss() {
    assert_eq!(
        run(concat!(
            "large = Maybe.maybe (Error.error \"large\") Function.id $ ",
            "Json.decode $ Text.encodeUtf8 \"9007199254740993\"\n",
            "huge = Maybe.maybe (Error.error \"huge\") Function.id $ ",
            "Json.decode $ Text.encodeUtf8 \"1e400\"\n",
            "tiny = Maybe.maybe (Error.error \"tiny\") Function.id $ ",
            "Json.decode $ Text.encodeUtf8 \"1e-10000\"\n",
            "main = do\n",
            "  ByteString.hPutStr IO.stdout $ Json.encode Main.large\n",
            "  Text.putStrLn \"\"\n",
            "  ByteString.hPutStr IO.stdout $ Json.encode Main.huge\n",
            "  Text.putStrLn \"\"\n",
            "  ByteString.hPutStr IO.stdout $ Json.encode Main.tiny\n",
            "  Text.putStrLn \"\"\n",
        )),
        format!("9007199254740993\n1{}\n1.0e-10000\n", "0".repeat(400))
    );
}

#[test]
fn json_value_converts_exact_number_only_when_selecting_number_branch() {
    assert_eq!(
        run(concat!(
            "decoded = Maybe.maybe (Error.error \"decode\") Function.id $ ",
            "Json.decode $ Text.encodeUtf8 \"1e400\"\n",
            "main = IO.print $ Json.value 0.0 (\\_ -> 0.0) (\\_ -> 0.0) ",
            "Function.id (\\_ -> 0.0) (\\_ -> 0.0) Main.decoded\n",
        )),
        "Infinity\n"
    );
}

#[test]
fn guest_double_numbers_use_aeson_nonfinite_and_zero_rendering() {
    assert_eq!(
        run(concat!(
            "negativeZero = Maybe.maybe 1.0 Function.id $ Double.readMaybe \"-0.0\"\n",
            "infinity = Maybe.maybe 1.0 Function.id $ Double.readMaybe \"Infinity\"\n",
            "negativeInfinity = Maybe.maybe 1.0 Function.id $ Double.readMaybe \"-Infinity\"\n",
            "nan = Maybe.maybe 1.0 Function.id $ Double.readMaybe \"NaN\"\n",
            "main = do\n",
            "  ByteString.hPutStr IO.stdout $ Json.encode $ Json.Number Main.negativeZero\n",
            "  Text.putStrLn \"\"\n",
            "  ByteString.hPutStr IO.stdout $ Json.encode $ Json.Number Main.infinity\n",
            "  Text.putStrLn \"\"\n",
            "  ByteString.hPutStr IO.stdout $ Json.encode $ Json.Number Main.negativeInfinity\n",
            "  Text.putStrLn \"\"\n",
            "  ByteString.hPutStr IO.stdout $ Json.encode $ Json.Number Main.nan\n",
            "  Text.putStrLn \"\"\n",
        )),
        "0\n\"+inf\"\n\"-inf\"\nnull\n"
    );
}

#[test]
fn deeply_nested_decode_uses_flat_document_storage() {
    let depth = 20_000;
    let json = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
    let source = format!(
        concat!(
            "decoded = Json.decode $ Text.encodeUtf8 {:?}\n",
            "main = IO.print $ Maybe.maybe 0 (\\_ -> 1) Main.decoded\n",
        ),
        json
    );
    assert_eq!(run(&source), "1\n");

    let source = format!(
        concat!(
            "decoded = Maybe.maybe (Error.error \"decode\") Function.id $ ",
            "Json.decode $ Text.encodeUtf8 {:?}\n",
            "main = ByteString.hPutStr IO.stdout $ Json.encode Main.decoded\n",
        ),
        json
    );
    assert_eq!(run(&source), json);
}
