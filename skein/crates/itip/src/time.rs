use skein_core::Timestamp;

struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    weekday: usize,
}

fn civil(at: Timestamp) -> Civil {
    let secs = at.0.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    Civil {
        year,
        month,
        day,
        hour: (rem / 3600) as u32,
        minute: (rem % 3600 / 60) as u32,
        second: (rem % 60) as u32,
        weekday: (days + 4).rem_euclid(7) as usize,
    }
}

/// An iCalendar UTC DATE-TIME, such as `20261121T120000Z`.
pub(crate) fn ical(at: Timestamp) -> String {
    let c = civil(at);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// An RFC 5322 date, such as `Sat, 21 Nov 2026 12:00:00 +0000`.
pub(crate) fn rfc5322(at: Timestamp) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let c = civil(at);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        DAYS[c.weekday],
        c.day,
        MONTHS[(c.month - 1) as usize],
        c.year,
        c.hour,
        c.minute,
        c.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(ical(Timestamp(0)), "19700101T000000Z");
        assert_eq!(rfc5322(Timestamp(0)), "Thu, 01 Jan 1970 00:00:00 +0000");
        let at = Timestamp(1_795_262_400_000);
        assert_eq!(ical(at), "20261121T120000Z");
        assert_eq!(rfc5322(at), "Sat, 21 Nov 2026 12:00:00 +0000");
        assert_eq!(ical(Timestamp(951_782_400_000)), "20000229T000000Z");
    }
}
