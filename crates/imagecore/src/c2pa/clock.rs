//! Time, reduced to the one representation everything else can compare.
//!
//! Certificate validity, time-stamp `genTime` and the validation time the
//! Conformance Program supplies all arrive as text in three different formats.
//! Path validation has to answer "is this instant inside that window", so all
//! three become seconds since the Unix epoch and stay that way.
//!
//! Written by hand rather than taken from `chrono` or `time` for two reasons
//! that both matter here: `wasm32-unknown-unknown` has no clock, so the crates'
//! main draw is unavailable anyway, and every dependency in a WebAssembly
//! bundle is one more entry in the Software Bill of Materials that the
//! conformance programme's O.3 and O.4 requirements make the applicant
//! responsible for tracking. Sixty lines of civil-calendar arithmetic is a
//! better trade than either.

/// Seconds since 1970-01-01T00:00:00Z. Negative for earlier instants.
pub type Instant = i64;

/// Days from the Unix epoch to a proleptic-Gregorian civil date.
///
/// Howard Hinnant's `days_from_civil`, which is exact for every year this will
/// ever see and has no branches worth worrying about.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400; // [0, 399]
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn compose(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<Instant> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // A leap second lands on :60 and is folded onto the following instant,
    // which is what every other consumer of these timestamps does too.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(
        days_from_civil(year, month, day) * 86_400
            + i64::from(hour) * 3600
            + i64::from(minute) * 60
            + i64::from(second.min(59)),
    )
}

/// Parse an RFC 3339 date-time.
///
/// Accepts the offsets RFC 3339 allows, not just `Z`, because the validation
/// time supplied to the conformance harness is whatever the Program chooses to
/// write. Fractional seconds are read and discarded: nothing here is decided at
/// sub-second resolution.
pub fn parse_rfc3339(text: &str) -> Option<Instant> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let num =
        |range: std::ops::Range<usize>| -> Option<i64> { text.get(range)?.parse::<i64>().ok() };

    let year = num(0..4)?;
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let month = num(5..7)? as u32;
    let day = num(8..10)? as u32;
    if !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let hour = num(11..13)? as u32;
    let minute = num(14..16)? as u32;
    let second = num(17..19)? as u32;

    let mut at = 19;
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
    }

    let offset = match bytes.get(at) {
        Some(b'Z') | Some(b'z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let hours = num(at + 1..at + 3)?;
            if bytes.get(at + 3) != Some(&b':') {
                return None;
            }
            let minutes = num(at + 4..at + 6)?;
            let magnitude = hours * 3600 + minutes * 60;
            if *sign == b'-' {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return None,
    };

    Some(compose(year, month, day, hour, minute, second)? - offset)
}

/// Render an instant as an RFC 3339 date-time in UTC.
pub fn to_rfc3339(at: Instant) -> String {
    let days = at.div_euclid(86_400);
    let rest = at.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// Parse a DER `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime`
/// (`YYYYMMDDHHMMSS[.fff]Z`).
///
/// `two_digit_year` selects between them: RFC 5280 pins UTCTime's window so
/// that 00-49 means 20xx and 50-99 means 19xx.
pub fn parse_asn1_time(text: &str, two_digit_year: bool) -> Option<Instant> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_digit).collect();
    let digits = String::from_utf8(digits).ok()?;
    let field =
        |range: std::ops::Range<usize>| -> Option<u32> { digits.get(range)?.parse::<u32>().ok() };

    let (year, rest) = if two_digit_year {
        if digits.len() < 10 {
            return None;
        }
        let two = field(0..2)?;
        (
            if two < 50 {
                2000 + i64::from(two)
            } else {
                1900 + i64::from(two)
            },
            &digits[2..],
        )
    } else {
        if digits.len() < 12 {
            return None;
        }
        (i64::from(field(0..4)?), &digits[4..])
    };

    let at = |range: std::ops::Range<usize>| -> Option<u32> { rest.get(range)?.parse().ok() };
    compose(
        year,
        at(0..2)?,
        at(2..4)?,
        at(4..6)?,
        at(6..8)?,
        at(8..10).unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_zero() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn round_trips_a_range_of_instants() {
        for instant in [
            0,
            1_000_000_000,
            1_770_000_000,
            -1_000_000,
            951_782_400,   // 2000-02-29, a leap day in a century leap year
            4_102_444_800, // 2100-01-01, a century that is not a leap year
        ] {
            assert_eq!(
                parse_rfc3339(&to_rfc3339(instant)),
                Some(instant),
                "{instant}"
            );
        }
    }

    #[test]
    fn honours_the_offset_rather_than_ignoring_it() {
        let utc = parse_rfc3339("2026-08-26T12:00:00Z").unwrap();
        assert_eq!(parse_rfc3339("2026-08-26T14:00:00+02:00"), Some(utc));
        assert_eq!(parse_rfc3339("2026-08-26T07:00:00-05:00"), Some(utc));
    }

    #[test]
    fn accepts_fractional_seconds_and_drops_them() {
        assert_eq!(
            parse_rfc3339("2026-03-16T18:35:24.012Z"),
            parse_rfc3339("2026-03-16T18:35:24Z")
        );
    }

    #[test]
    fn reads_both_asn1_time_forms() {
        let expected = parse_rfc3339("2026-08-26T12:34:56Z");
        assert_eq!(parse_asn1_time("260826123456Z", true), expected);
        assert_eq!(parse_asn1_time("20260826123456Z", false), expected);
    }

    #[test]
    fn applies_rfc_5280_two_digit_year_windowing() {
        // 49 is 2049; 50 is 1950. Getting this backwards would make every
        // certificate issued before 2050 look expired.
        assert_eq!(
            parse_asn1_time("490101000000Z", true),
            parse_rfc3339("2049-01-01T00:00:00Z")
        );
        assert_eq!(
            parse_asn1_time("500101000000Z", true),
            parse_rfc3339("1950-01-01T00:00:00Z")
        );
    }

    #[test]
    fn rejects_text_that_is_not_a_timestamp() {
        for junk in [
            "",
            "yesterday",
            "2026-13-01T00:00:00Z",
            "2026-08-26",
            "2026-08-26T25:00:00Z",
        ] {
            assert_eq!(parse_rfc3339(junk), None, "{junk} should not parse");
        }
    }
}
