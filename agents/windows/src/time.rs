//! Timestamp formatting with no external crate dependency.
//!
//! CONTRACTS requires ISO 8601 UTC with second precision, sub-second digits
//! dropped, so semantic diffs line up across platforms. We convert from both
//! Windows FILETIME (100 ns ticks since 1601) and Unix seconds.

use crate::offreg::Filetime;

const FILETIME_TICKS_PER_SEC: i64 = 10_000_000;
// Seconds between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF_SECS: i64 = 11_644_473_600;

/// Convert a FILETIME to an ISO 8601 UTC string truncated to seconds.
pub fn filetime_to_iso8601(ft: Filetime) -> String {
    let ticks = ((ft.high as i64) << 32) | (ft.low as i64 & 0xffff_ffff);
    let unix = ticks / FILETIME_TICKS_PER_SEC - EPOCH_DIFF_SECS;
    unix_to_iso8601(unix)
}

/// Convert Unix seconds (UTC) to an ISO 8601 string truncated to seconds.
pub fn unix_to_iso8601(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Current wall-clock time as ISO 8601, used only for the audit log.
pub fn now_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    unix_to_iso8601(now)
}

/// Howard Hinnant's days-from-civil inverse: a day number relative to the Unix
/// epoch becomes (year, month, day) in the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamp() {
        // 1700000000 == 2023-11-14T22:13:20Z
        assert_eq!(unix_to_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn filetime_epoch() {
        // FILETIME ticks for the Unix epoch: 11644473600 * 10_000_000.
        let ticks: i64 = 11_644_473_600 * 10_000_000;
        let ft = Filetime {
            low: (ticks & 0xffff_ffff) as u32,
            high: (ticks >> 32) as u32,
        };
        assert_eq!(filetime_to_iso8601(ft), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn leap_day() {
        // 2024-02-29T00:00:00Z == 1709164800
        assert_eq!(unix_to_iso8601(1_709_164_800), "2024-02-29T00:00:00Z");
    }
}
