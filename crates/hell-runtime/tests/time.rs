use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

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
    run_with_context(source, |bytes| {
        RuntimeContext::new(Vec::new(), SharedWriter(bytes))
    })
}

fn run_with_context(
    source: &str,
    context: impl FnOnce(Arc<Mutex<Vec<u8>>>) -> RuntimeContext,
) -> String {
    let program = compile_source(&mut CompilerSession::default(), "time.hell", source)
        .expect("time source compiles");
    let bytes = Arc::new(Mutex::new(Vec::new()));
    run_main(program, context(Arc::clone(&bytes))).unwrap();
    String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
}

#[test]
fn gregorian_dates_cover_validation_arithmetic_weekdays_and_unbounded_years() {
    assert_eq!(
        run(concat!(
            "day = Maybe.maybe (Error.error \"day\") Function.id ",
            "$ Day.fromGregorianValid (Int.toInteger 2025) 8 9\n",
            "other = Maybe.maybe (Error.error \"day\") Function.id ",
            "$ Day.iso8601ParseM \"2025-08-10\"\n",
            "huge = Maybe.maybe (Error.error \"integer\") Function.id ",
            "$ Integer.readMaybe \"100000000000000000000\"\n",
            "main = do\n",
            "  (year, month, date) <- IO.pure $ Day.toGregorian Main.day\n",
            "  IO.print year\n",
            "  IO.print month\n",
            "  IO.print date\n",
            "  Text.putStrLn $ Day.iso8601Show Main.day\n",
            "  IO.print $ Day.dayOfWeek Main.day\n",
            "  IO.print $ Day.diffDays Main.other Main.day\n",
            "  IO.print $ Day.addDays (Int.toInteger 1) Main.day\n",
            "  IO.print $ Day.fromGregorianValid (Int.toInteger 2023) 2 29\n",
            "  IO.print $ Day.fromGregorianValid (Int.toInteger 2024) 2 29\n",
            "  IO.print $ Day.iso8601ParseM \"-0001-01-01\"\n",
            "  IO.print $ Day.iso8601ParseM \"10000-01-01\"\n",
            "  Text.putStrLn $ Day.iso8601Show $ ",
            "Maybe.maybe (Error.error \"huge day\") Function.id ",
            "$ Day.fromGregorianValid Main.huge 1 1\n",
        )),
        concat!(
            "2025\n",
            "8\n",
            "9\n",
            "2025-08-09\n",
            "Saturday\n",
            "1\n",
            "2025-08-10\n",
            "Nothing\n",
            "Just 2024-02-29\n",
            "Just -0001-01-01\n",
            "Nothing\n",
            "100000000000000000000-01-01\n",
        )
    );
}

#[test]
fn time_of_day_matches_picosecond_flooring_and_leap_second_rules() {
    assert_eq!(
        run(concat!(
            "negative = TimeOfDay.timeToTimeOfDay (Double.subtract 1.0 0.0)\n",
            "main = do\n",
            "  IO.print TimeOfDay.midnight\n",
            "  IO.print TimeOfDay.midday\n",
            "  IO.print $ TimeOfDay.timeToTimeOfDay 86401.25\n",
            "  IO.print Main.negative\n",
            "  IO.print $ TimeOfDay.todHour Main.negative\n",
            "  IO.print $ TimeOfDay.todMin Main.negative\n",
            "  IO.print $ TimeOfDay.todSec Main.negative\n",
            "  IO.print $ TimeOfDay.timeOfDayToTime Main.negative\n",
            "  IO.print $ TimeOfDay.timeToTimeOfDay 0.1234567890129\n",
            "  IO.print $ TimeOfDay.timeToTimeOfDay ",
            "(Double.subtract 0.0000000000009 0.0)\n",
            "  IO.print $ TimeOfDay.makeTimeOfDayValid 23 59 60.5\n",
            "  IO.print $ TimeOfDay.timeOfDayToTime $ ",
            "Maybe.maybe (Error.error \"time\") Function.id ",
            "$ TimeOfDay.makeTimeOfDayValid 23 59 60.5\n",
            "  IO.print $ TimeOfDay.makeTimeOfDayValid 23 59 61.0\n",
        )),
        concat!(
            "00:00:00\n",
            "12:00:00\n",
            "23:59:61.25\n",
            "-01:59:59\n",
            "-1\n",
            "59\n",
            "59.0\n",
            "-1.0\n",
            "00:00:00.123456789012\n",
            "-01:59:59.999999999999\n",
            "Just 23:59:60.5\n",
            "86400.5\n",
            "Nothing\n",
        )
    );
}

#[test]
fn utc_time_parsing_formatting_arithmetic_and_clock_override_are_deterministic() {
    assert_eq!(
        run_with_context(
            concat!(
                "day = Maybe.maybe (Error.error \"day\") Function.id ",
                "$ Day.iso8601ParseM \"2025-01-01\"\n",
                "parsed = Maybe.maybe (Error.error \"time\") Function.id ",
                "$ UTCTime.iso8601ParseM \"2025-05-30T11:18:26.1951470841234Z\"\n",
                "main = do\n",
                "  IO.print Main.parsed\n",
                "  Text.putStrLn $ UTCTime.iso8601Show Main.parsed\n",
                "  IO.print $ UTCTime.utctDay Main.parsed\n",
                "  IO.print $ UTCTime.utctDayTime Main.parsed\n",
                "  IO.print $ UTCTime.addUTCTime 1.0 $ UTCTime.UTCTime Main.day 86400.0\n",
                "  IO.print $ UTCTime.diffUTCTime ",
                "(UTCTime.addUTCTime 1.5 $ UTCTime.UTCTime Main.day 0.0) ",
                "(UTCTime.UTCTime Main.day 0.0)\n",
                "  IO.print $ UTCTime.iso8601ParseM \"2025-02-29T00:00:00Z\"\n",
                "  IO.print $ UTCTime.iso8601ParseM \"2025-05-30T11:18:26+09:00\"\n",
                "  IO.print $ UTCTime.iso8601ParseM \"2025-05-30T24:00:00Z\"\n",
                "  IO.print $ UTCTime.iso8601ParseM \"2025-05-30T23:59:60Z\"\n",
                "  now <- UTCTime.getCurrentTime\n",
                "  Text.putStrLn $ UTCTime.iso8601Show now\n",
            ),
            |bytes| {
                RuntimeContext::new(Vec::new(), SharedWriter(bytes))
                    .with_current_time(UNIX_EPOCH + Duration::new(1, 195_147_084))
            },
        ),
        concat!(
            "2025-05-30 11:18:26.195147084123 UTC\n",
            "2025-05-30T11:18:26.195147084123Z\n",
            "2025-05-30\n",
            "40706.19514708412\n",
            "2025-01-02 00:00:01 UTC\n",
            "1.5\n",
            "Nothing\n",
            "Nothing\n",
            "Just 2025-05-31 00:00:00 UTC\n",
            "Just 2025-05-30 23:59:60 UTC\n",
            "1970-01-01T00:00:01.195147084Z\n",
        )
    );

    assert_eq!(
        run_with_context(
            "main = Monad.bind UTCTime.getCurrentTime \
             (\\time -> Text.putStrLn (UTCTime.iso8601Show time))\n",
            |bytes| {
                RuntimeContext::new(Vec::new(), SharedWriter(bytes))
                    .with_current_time(UNIX_EPOCH - Duration::from_nanos(1))
            },
        ),
        "1969-12-31T23:59:59.999999999Z\n"
    );
}
