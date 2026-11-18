use jiff::{Timestamp, tz::Offset};

pub(crate) fn rfc3339(timestamp: Timestamp) -> String {
    // Keep the existing wire representation, including grouped fractional
    // precision and an explicit UTC offset.
    let precision = match timestamp.subsec_nanosecond() {
        0 => 0,
        nanos if nanos % 1_000_000 == 0 => 3,
        nanos if nanos % 1_000 == 0 => 6,
        _ => 9,
    };
    let timestamp = timestamp.display_with_offset(Offset::UTC);
    format!("{timestamp:.precision$}")
}

#[cfg(feature = "request-state")]
pub(crate) fn unix_milliseconds(timestamp: Timestamp) -> i64 {
    // Jiff truncates toward zero, while request-state timestamps round down.
    let partial_negative = timestamp.subsec_nanosecond() % 1_000_000 < 0;
    timestamp.as_millisecond() - i64::from(partial_negative)
}

#[cfg(all(test, feature = "request-state"))]
mod tests {
    use super::*;

    #[test]
    fn unix_milliseconds_round_down_on_both_sides_of_the_epoch() {
        for (nanos, millis) in [(-1_000_001, -2), (-1_000_000, -1), (-1, -1), (0, 0), (1, 0)] {
            assert_eq!(unix_milliseconds(Timestamp::new(0, nanos).unwrap()), millis);
        }
    }
}
