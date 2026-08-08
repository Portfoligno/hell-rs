//! Stable typed source generation for semantic differential observations.

use std::sync::Arc;

use crate::{DifferentialCase, DifferentialMode, Digest, sha256_bytes};

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
    let mut cases = [
        (
            "laziness-unused-error",
            "main = IO.print $ Bool.bool 1 (Error.error \"unused\" :: Int) Bool.False\n",
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
    .map(|(id, source)| DifferentialCase {
        id: Arc::from(id),
        source: Arc::from(source),
        ..DifferentialCase::default()
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
    cases
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
}
