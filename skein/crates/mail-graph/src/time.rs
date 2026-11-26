use skein_core::Timestamp;

/// Reads an RFC 3339 date such as `2025-03-01T09:30:00Z`, with an offset or fractional seconds.
/// Years outside 0000–9999 and offsets beyond 23:59 are not dates.
pub(crate) fn parse_utc(raw: &str) -> Option<Timestamp> {
    let raw = raw.trim();
    let (date, rest) = raw.split_once(['T', 't'])?;
    let mut parts = date.splitn(3, '-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    let zone_at = rest.find(['Z', 'z', '+', '-'])?;
    let (clock, zone) = rest.split_at(zone_at);
    let mut clock_parts = clock.splitn(3, ':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let seconds = clock_parts.next()?;
    let (whole, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
    let second: i64 = whole.parse().ok()?;
    let millis: i64 = format!("{fraction:0<3}")
        .get(..3)
        .and_then(|m| m.parse().ok())
        .unwrap_or(0);
    let offset = match zone {
        "Z" | "z" => 0,
        _ => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let (h, m) = zone[1..].split_once(':')?;
            let (h, m) = (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?);
            if !(0..=23).contains(&h) || !(0..=59).contains(&m) {
                return None;
            }
            sign * (h * 60 + m) * 60
        }
    };
    if !(0..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let secs =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    Some(Timestamp(secs * 1000 + millis))
}

/// Whole seconds since the epoch as an RFC 3339 date in UTC.
pub(crate) fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let clock = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        clock / 3600,
        clock % 3600 / 60,
        clock % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_years_and_offsets_are_not_dates() {
        assert_eq!(parse_utc("9223372036854775807-01-01T00:00:00Z"), None);
        assert_eq!(parse_utc("10000-01-01T00:00:00Z"), None);
        assert_eq!(
            parse_utc("2026-01-01T00:00:00+9223372036854775807:00"),
            None
        );
        assert_eq!(parse_utc("2026-01-01T00:00:00+24:00"), None);
        assert!(parse_utc("9999-12-31T23:59:59-23:59").is_some());
    }

    #[test]
    fn reads_and_writes_utc_dates() {
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(Timestamp(0)));
        assert_eq!(
            parse_utc("2025-03-01T10:30:05.25+01:00"),
            Some(Timestamp(1_740_821_405_250))
        );
        assert_eq!(parse_utc("yesterday"), None);
        assert_eq!(parse_utc("2025-13-01T00:00:00Z"), None);
        for secs in [0, 951_782_400, 1_740_821_405, 4_102_444_799] {
            assert_eq!(parse_utc(&format_utc(secs)), Some(Timestamp(secs * 1000)));
        }
    }
}
