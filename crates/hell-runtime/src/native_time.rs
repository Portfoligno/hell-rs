//! Fixed-precision Gregorian and UTC values for the guest time API.

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::native_integer::BigInteger;
use crate::{
    Evaluator, ForceOutcome, IoAction, RuntimeError, RuntimeResult, Thunk, ThunkRef, Value,
};

pub(crate) const PICOSECONDS_PER_SECOND: i128 = 1_000_000_000_000;
const SECONDS_PER_DAY: i128 = 86_400;
const PICOSECONDS_PER_MINUTE: i128 = 60 * PICOSECONDS_PER_SECOND;
const PICOSECONDS_PER_HOUR: i128 = 60 * PICOSECONDS_PER_MINUTE;
const PICOSECONDS_PER_DAY: i128 = SECONDS_PER_DAY * PICOSECONDS_PER_SECOND;
const UNIX_EPOCH_MJD: i64 = 40_587;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Day {
    modified_julian_day: BigInteger,
}

impl Day {
    pub(crate) fn from_gregorian_valid(year: &BigInteger, month: i64, day: i64) -> Option<Self> {
        let month = u32::try_from(month).ok()?;
        let day = u32::try_from(day).ok()?;
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        Some(Self {
            modified_julian_day: gregorian_to_mjd(year, month, day),
        })
    }

    pub(crate) fn parse_iso(input: &str) -> Option<Self> {
        let (negative, input) = input
            .strip_prefix('-')
            .map_or((false, input), |rest| (true, rest));
        if input.len() != 10 || input.as_bytes().get(4) != Some(&b'-') {
            return None;
        }
        let year = input.get(..4)?;
        let month = input.get(5..7)?;
        let day = input.get(8..10)?;
        if input.as_bytes().get(7) != Some(&b'-')
            || !year.bytes().all(|byte| byte.is_ascii_digit())
            || !month.bytes().all(|byte| byte.is_ascii_digit())
            || !day.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let year = if negative {
            format!("-{year}")
        } else {
            year.to_owned()
        };
        let year = BigInteger::parse(&year)?;
        Self::from_gregorian_valid(&year, month.parse().ok()?, day.parse().ok()?)
    }

    pub(crate) fn to_gregorian(&self) -> (BigInteger, u32, u32) {
        mjd_to_gregorian(&self.modified_julian_day)
    }

    pub(crate) fn add_days(&self, days: &BigInteger) -> Self {
        Self {
            modified_julian_day: self.modified_julian_day.add(days),
        }
    }

    pub(crate) fn diff_days(&self, other: &Self) -> BigInteger {
        self.modified_julian_day
            .subtract(&other.modified_julian_day)
    }

    pub(crate) fn day_of_week(&self) -> DayOfWeek {
        let (_, remainder) = self.modified_julian_day.div_rem_euclid_small(7);
        DayOfWeek::from_monday_index((remainder + 2) % 7)
    }

    pub(crate) fn iso8601_show(&self) -> String {
        let (year, month, day) = self.to_gregorian();
        format!("{}-{month:02}-{day:02}", format_year(&year))
    }
}

impl fmt::Display for Day {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.iso8601_show())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DayOfWeek {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl DayOfWeek {
    fn from_monday_index(index: u32) -> Self {
        match index {
            0 => Self::Monday,
            1 => Self::Tuesday,
            2 => Self::Wednesday,
            3 => Self::Thursday,
            4 => Self::Friday,
            5 => Self::Saturday,
            6 => Self::Sunday,
            _ => unreachable!("weekday remainder is in 0..7"),
        }
    }
}

impl fmt::Display for DayOfWeek {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Monday => "Monday",
            Self::Tuesday => "Tuesday",
            Self::Wednesday => "Wednesday",
            Self::Thursday => "Thursday",
            Self::Friday => "Friday",
            Self::Saturday => "Saturday",
            Self::Sunday => "Sunday",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimeOfDay {
    hour: i64,
    minute: i64,
    second_picoseconds: i128,
}

impl TimeOfDay {
    pub(crate) const MIDNIGHT: Self = Self {
        hour: 0,
        minute: 0,
        second_picoseconds: 0,
    };
    pub(crate) const MIDDAY: Self = Self {
        hour: 12,
        minute: 0,
        second_picoseconds: 0,
    };

    pub(crate) fn from_seconds(seconds: f64) -> Option<Self> {
        Some(Self::from_picoseconds(double_to_picoseconds(seconds)?))
    }

    pub(crate) fn make_valid(hour: i64, minute: i64, seconds: f64) -> Option<Self> {
        if !(0..=23).contains(&hour)
            || !(0..=59).contains(&minute)
            || !(0.0..61.0).contains(&seconds)
        {
            return None;
        }
        let seconds = double_to_picoseconds(seconds)?;
        Some(Self {
            hour,
            minute,
            second_picoseconds: seconds,
        })
    }

    pub(crate) fn hour(self) -> i64 {
        self.hour
    }

    pub(crate) fn minute(self) -> i64 {
        self.minute
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn second(self) -> f64 {
        self.second_picoseconds as f64 / PICOSECONDS_PER_SECOND as f64
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn to_seconds(self) -> f64 {
        (self.hour as f64).mul_add(
            3_600.0,
            (self.minute as f64).mul_add(
                60.0,
                self.second_picoseconds as f64 / PICOSECONDS_PER_SECOND as f64,
            ),
        )
    }

    fn from_picoseconds(picoseconds: i128) -> Self {
        let hour = picoseconds.div_euclid(PICOSECONDS_PER_HOUR).min(23);
        let after_hour = picoseconds - hour * PICOSECONDS_PER_HOUR;
        let minute = after_hour.div_euclid(PICOSECONDS_PER_MINUTE).min(59);
        let second_picoseconds = after_hour - minute * PICOSECONDS_PER_MINUTE;
        #[allow(clippy::cast_possible_truncation)]
        Self {
            hour: hour as i64,
            minute: i64::try_from(minute).expect("minute produced by conversion fits Int"),
            second_picoseconds,
        }
    }
}

impl fmt::Display for TimeOfDay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let second = self.second_picoseconds.div_euclid(PICOSECONDS_PER_SECOND);
        let fraction = self.second_picoseconds.rem_euclid(PICOSECONDS_PER_SECOND);
        write!(
            formatter,
            "{}:{:02}:{}",
            format_hour(i128::from(self.hour)),
            self.minute,
            format_second(second, fraction)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcTime {
    day: Day,
    day_time_picoseconds: i128,
}

impl UtcTime {
    pub(crate) fn new(day: Day, seconds: f64) -> Option<Self> {
        Some(Self {
            day,
            day_time_picoseconds: double_to_picoseconds(seconds)?,
        })
    }

    pub(crate) fn from_system_time(system_time: SystemTime) -> Self {
        let total_picoseconds = match system_time.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                i128::from(duration.as_secs()) * PICOSECONDS_PER_SECOND
                    + i128::from(duration.subsec_nanos()) * 1_000
            }
            Err(error) => {
                let duration = error.duration();
                -(i128::from(duration.as_secs()) * PICOSECONDS_PER_SECOND
                    + i128::from(duration.subsec_nanos()) * 1_000)
            }
        };
        let day_offset = total_picoseconds.div_euclid(PICOSECONDS_PER_DAY);
        let day_time_picoseconds = total_picoseconds.rem_euclid(PICOSECONDS_PER_DAY);
        let day = Day {
            modified_julian_day: BigInteger::from_i64(UNIX_EPOCH_MJD)
                .add(&BigInteger::from_i128(day_offset)),
        };
        Self {
            day,
            day_time_picoseconds,
        }
    }

    pub(crate) fn day(&self) -> Day {
        self.day.clone()
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn day_time_seconds(&self) -> f64 {
        self.day_time_picoseconds as f64 / PICOSECONDS_PER_SECOND as f64
    }

    pub(crate) fn add_seconds(&self, seconds: f64) -> Option<Self> {
        let adjustment = double_to_picoseconds(seconds)?;
        let clipped = self.day_time_picoseconds.min(PICOSECONDS_PER_DAY);
        let total = clipped.checked_add(adjustment)?;
        let day_offset = total.div_euclid(PICOSECONDS_PER_DAY);
        Some(Self {
            day: self.day.add_days(&BigInteger::from_i128(day_offset)),
            day_time_picoseconds: total.rem_euclid(PICOSECONDS_PER_DAY),
        })
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn diff_seconds(&self, other: &Self) -> f64 {
        let days = self.day.diff_days(&other.day).to_f64();
        let left = self.day_time_picoseconds.min(PICOSECONDS_PER_DAY) as f64;
        let right = other.day_time_picoseconds.min(PICOSECONDS_PER_DAY) as f64;
        days.mul_add(
            SECONDS_PER_DAY as f64,
            (left - right) / PICOSECONDS_PER_SECOND as f64,
        )
    }

    pub(crate) fn parse_iso(input: &str) -> Option<Self> {
        let (date, time) = input.split_once('T')?;
        let time = time.strip_suffix('Z')?;
        let day = Day::parse_iso(date)?;
        if time.len() < 8
            || time.as_bytes().get(2) != Some(&b':')
            || time.as_bytes().get(5) != Some(&b':')
        {
            return None;
        }
        let hour: u32 = time.get(..2)?.parse().ok()?;
        let minute: u32 = time.get(3..5)?.parse().ok()?;
        let (second, fraction) = time.get(6..)?.split_once('.').map_or_else(
            || (time.get(6..).unwrap_or_default(), None),
            |(second, fraction)| (second, Some(fraction)),
        );
        if second.len() != 2 || minute > 59 {
            return None;
        }
        let second: u32 = second.parse().ok()?;
        if hour == 24 {
            if minute != 0
                || second != 0
                || fraction.is_some_and(|value| value.bytes().any(|b| b != b'0'))
            {
                return None;
            }
            return Some(Self {
                day: day.add_days(&BigInteger::from_i64(1)),
                day_time_picoseconds: 0,
            });
        }
        if hour > 23 || second > 60 {
            return None;
        }
        let fraction = fraction.map_or(Some(0), parse_fraction_picoseconds)?;
        let day_time_picoseconds = i128::from(hour) * PICOSECONDS_PER_HOUR
            + i128::from(minute) * PICOSECONDS_PER_MINUTE
            + i128::from(second) * PICOSECONDS_PER_SECOND
            + fraction;
        Some(Self {
            day,
            day_time_picoseconds,
        })
    }

    pub(crate) fn iso8601_show(&self) -> String {
        format!(
            "{}T{}Z",
            self.day,
            TimeOfDay::from_picoseconds(self.day_time_picoseconds)
        )
    }
}

impl fmt::Display for UtcTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} UTC",
            self.day,
            TimeOfDay::from_picoseconds(self.day_time_picoseconds)
        )
    }
}

fn double_to_picoseconds(seconds: f64) -> Option<i128> {
    let bits = seconds.to_bits();
    let negative = bits >> 63 != 0;
    let exponent_bits = u16::try_from((bits >> 52) & 0x7ff).expect("double exponent fits u16");
    let fraction = bits & ((1_u64 << 52) - 1);
    if exponent_bits == 0x7ff {
        return None;
    }
    if exponent_bits == 0 && fraction == 0 {
        return Some(0);
    }
    let (mantissa, exponent) = if exponent_bits == 0 {
        (u128::from(fraction), -1_074_i32)
    } else {
        (
            u128::from((1_u64 << 52) | fraction),
            i32::from(exponent_bits) - 1_023 - 52,
        )
    };
    let scaled = mantissa.checked_mul(PICOSECONDS_PER_SECOND as u128)?;
    let (quotient, has_remainder) = if exponent >= 0 {
        let shift = u32::try_from(exponent).ok()?;
        if shift >= 128 || scaled > (u128::MAX >> shift) {
            return None;
        }
        (scaled << shift, false)
    } else {
        let shift = exponent.unsigned_abs();
        if shift >= 128 {
            (0, scaled != 0)
        } else {
            let quotient = scaled >> shift;
            let mask = (1_u128 << shift) - 1;
            (quotient, scaled & mask != 0)
        }
    };
    let magnitude = if negative && has_remainder {
        quotient.checked_add(1)?
    } else {
        quotient
    };
    let sign_boundary = 1_u128 << 127;
    if negative {
        if magnitude > sign_boundary {
            return None;
        }
        if magnitude == sign_boundary {
            return Some(i128::MIN);
        }
        return i128::try_from(magnitude).ok().map(|value| -value);
    }
    if magnitude >= sign_boundary {
        return None;
    }
    i128::try_from(magnitude).ok()
}

fn is_leap_year(year: &BigInteger) -> bool {
    let (_, remainder) = year.div_rem_euclid_small(400);
    remainder == 0 || (remainder % 4 == 0 && remainder % 100 != 0)
}

fn days_in_month(year: &BigInteger, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn gregorian_to_mjd(year: &BigInteger, month: u32, day: u32) -> BigInteger {
    let adjusted_year = if month <= 2 {
        year.subtract(&BigInteger::from_i64(1))
    } else {
        year.clone()
    };
    let (era, year_of_era) = adjusted_year.div_rem_euclid_small(400);
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let days_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.multiply(&BigInteger::from_i64(146_097))
        .add(&BigInteger::from_i64(i64::from(days_of_era) - 678_881))
}

fn mjd_to_gregorian(modified_julian_day: &BigInteger) -> (BigInteger, u32, u32) {
    let days = modified_julian_day.add(&BigInteger::from_i64(678_881));
    let (era, day_of_era) = days.div_rem_euclid_small(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = era
        .multiply(&BigInteger::from_i64(400))
        .add(&BigInteger::from_i64(i64::from(year_of_era)));
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 {
        year.add(&BigInteger::from_i64(1))
    } else {
        year
    };
    (year, month, day)
}

fn format_year(year: &BigInteger) -> String {
    let rendered = year.to_string();
    if let Some(magnitude) = rendered.strip_prefix('-') {
        format!("-{magnitude:0>4}")
    } else {
        format!("{rendered:0>4}")
    }
}

fn format_hour(hour: i128) -> String {
    if hour < 0 {
        format!("-{:02}", hour.unsigned_abs())
    } else {
        format!("{hour:02}")
    }
}

fn format_second(second: i128, fraction: i128) -> String {
    if fraction == 0 {
        return format!("{second:02}");
    }
    let mut fraction = format!("{fraction:012}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("{second:02}.{fraction}")
}

fn parse_fraction_picoseconds(fraction: &str) -> Option<i128> {
    if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let retained = fraction.get(..fraction.len().min(12))?;
    let mut value: i128 = retained.parse().ok()?;
    for _ in retained.len()..12 {
        value *= 10;
    }
    Some(value)
}

#[allow(clippy::too_many_lines)]
pub(super) fn apply_native(
    implementation: &str,
    arguments: &[ThunkRef],
    evaluator: &mut Evaluator,
) -> Option<RuntimeResult<ForceOutcome>> {
    let value = |value| Ok(ForceOutcome::Value(Arc::new(value)));
    Some(match implementation {
        "day_from_gregorian_valid" => {
            let year = evaluator.force_integer(&arguments[0]);
            let month = evaluator.force_int(&arguments[1]);
            let day = evaluator.force_int(&arguments[2]);
            match (year, month, day) {
                (Ok(year), Ok(month), Ok(day)) => value(Value::Maybe(
                    Day::from_gregorian_valid(year.as_ref(), month, day)
                        .map(|day| Thunk::evaluated(Value::Day(day))),
                )),
                (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
            }
        }
        "day_to_gregorian" => evaluator.force_day(&arguments[0]).map(|day| {
            let (year, month, day) = day.to_gregorian();
            ForceOutcome::Value(Arc::new(Value::Tuple(
                [
                    Thunk::evaluated(Value::Integer(Arc::new(year))),
                    Thunk::evaluated(Value::Int(i64::from(month))),
                    Thunk::evaluated(Value::Int(i64::from(day))),
                ]
                .into(),
            )))
        }),
        "day_add_days" => {
            let days = evaluator.force_integer(&arguments[0]);
            let day = evaluator.force_day(&arguments[1]);
            match (days, day) {
                (Ok(days), Ok(day)) => value(Value::Day(day.add_days(&days))),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
        "day_diff_days" => {
            let left = evaluator.force_day(&arguments[0]);
            let right = evaluator.force_day(&arguments[1]);
            match (left, right) {
                (Ok(left), Ok(right)) => value(Value::Integer(Arc::new(left.diff_days(&right)))),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
        "day_of_week" => evaluator
            .force_day(&arguments[0])
            .and_then(|day| value(Value::DayOfWeek(day.day_of_week()))),
        "day_iso8601_show" => evaluator
            .force_day(&arguments[0])
            .and_then(|day| value(Value::Text(Arc::<str>::from(day.iso8601_show())))),
        "day_iso8601_parse" => evaluator.force_text(&arguments[0]).and_then(|text| {
            value(Value::Maybe(
                Day::parse_iso(&text).map(|day| Thunk::evaluated(Value::Day(day))),
            ))
        }),
        "utc_time_new" => {
            let day = evaluator.force_day(&arguments[0]);
            let seconds = evaluator.force_double(&arguments[1]);
            match (day, seconds) {
                (Ok(day), Ok(seconds)) => UtcTime::new(day, seconds).map_or_else(
                    || Err(fixed_precision_error("UTCTime.UTCTime")),
                    |time| value(Value::UtcTime(time)),
                ),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
        "utc_time_day" => evaluator
            .force_utc_time(&arguments[0])
            .and_then(|time| value(Value::Day(time.day()))),
        "utc_time_day_time" => evaluator
            .force_utc_time(&arguments[0])
            .and_then(|time| value(Value::Double(time.day_time_seconds()))),
        "utc_time_add" => {
            let seconds = evaluator.force_double(&arguments[0]);
            let time = evaluator.force_utc_time(&arguments[1]);
            match (seconds, time) {
                (Ok(seconds), Ok(time)) => time.add_seconds(seconds).map_or_else(
                    || Err(fixed_precision_error("UTCTime.addUTCTime")),
                    |time| value(Value::UtcTime(time)),
                ),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
        "utc_time_diff" => {
            let left = evaluator.force_utc_time(&arguments[0]);
            let right = evaluator.force_utc_time(&arguments[1]);
            match (left, right) {
                (Ok(left), Ok(right)) => value(Value::Double(left.diff_seconds(&right))),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
        "utc_time_get_current" => value(Value::Io(IoAction::new(|_, context| {
            Ok(Thunk::evaluated(Value::UtcTime(UtcTime::from_system_time(
                context.current_time()?,
            ))))
        }))),
        "utc_time_iso8601_show" => evaluator
            .force_utc_time(&arguments[0])
            .and_then(|time| value(Value::Text(Arc::<str>::from(time.iso8601_show())))),
        "utc_time_iso8601_parse" => evaluator.force_text(&arguments[0]).and_then(|text| {
            value(Value::Maybe(
                UtcTime::parse_iso(&text).map(|time| Thunk::evaluated(Value::UtcTime(time))),
            ))
        }),
        "time_of_day_from_time" => evaluator.force_double(&arguments[0]).and_then(|seconds| {
            let seconds = if crate::semantic_mutant_active("datetime-rounding-boundary") {
                seconds.ceil()
            } else {
                seconds
            };
            TimeOfDay::from_seconds(seconds).map_or_else(
                || Err(fixed_precision_error("TimeOfDay.timeToTimeOfDay")),
                |time| value(Value::TimeOfDay(time)),
            )
        }),
        "time_of_day_hour" => evaluator
            .force_time_of_day(&arguments[0])
            .and_then(|time| value(Value::Int(time.hour()))),
        "time_of_day_minute" => evaluator
            .force_time_of_day(&arguments[0])
            .and_then(|time| value(Value::Int(time.minute()))),
        "time_of_day_second" => evaluator
            .force_time_of_day(&arguments[0])
            .and_then(|time| value(Value::Double(time.second()))),
        "time_of_day_midnight" => value(Value::TimeOfDay(TimeOfDay::MIDNIGHT)),
        "time_of_day_midday" => value(Value::TimeOfDay(TimeOfDay::MIDDAY)),
        "time_of_day_make_valid" => {
            let hour = evaluator.force_int(&arguments[0]);
            let minute = evaluator.force_int(&arguments[1]);
            let seconds = evaluator.force_double(&arguments[2]);
            match (hour, minute, seconds) {
                (Ok(hour), Ok(minute), Ok(seconds)) => value(Value::Maybe(
                    TimeOfDay::make_valid(hour, minute, seconds)
                        .map(|time| Thunk::evaluated(Value::TimeOfDay(time))),
                )),
                (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
            }
        }
        "time_of_day_to_time" => evaluator
            .force_time_of_day(&arguments[0])
            .and_then(|time| value(Value::Double(time.to_seconds()))),
        _ => return None,
    })
}

fn fixed_precision_error(operation: &'static str) -> Arc<RuntimeError> {
    RuntimeError::resource_limit(format!(
        "{operation}: value is outside the supported picosecond range"
    ))
}
