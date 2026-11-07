//! Typed temporal values preserve date-only, local civil time and absolute instants as
//! distinct semantic variants. Calendar conversion requires a separately approved oracle.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemporalValue {
    DateOnly {
        calendar: String,
        year: i32,
        month: u8,
        day: u8,
    },
    LocalDateTime {
        calendar: String,
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
        time_zone: String,
        fold: Option<u8>,
    },
    Instant {
        unix_seconds: i64,
        nanosecond: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalValueError {
    MissingCalendar,
    InvalidDateComponents,
    InvalidClockComponents,
    InvalidTimeZone,
    InvalidFold,
    InvalidNanosecond,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalKind {
    DateOnly,
    LocalDateTime,
    Instant,
}

impl TemporalValue {
    pub fn kind(&self) -> TemporalKind {
        match self {
            Self::DateOnly { .. } => TemporalKind::DateOnly,
            Self::LocalDateTime { .. } => TemporalKind::LocalDateTime,
            Self::Instant { .. } => TemporalKind::Instant,
        }
    }

    /// Structural validation only. Calendar-specific date validity/conversion must use
    /// a separately reviewed calendar implementation and independent reference oracle.
    pub fn validate(&self) -> Result<(), TemporalValueError> {
        match self {
            Self::DateOnly {
                calendar,
                year,
                month,
                day,
            } => {
                if calendar.trim().is_empty() {
                    return Err(TemporalValueError::MissingCalendar);
                }
                if *year <= 0 || *month == 0 || *day == 0 {
                    return Err(TemporalValueError::InvalidDateComponents);
                }
            }
            Self::LocalDateTime {
                calendar,
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
                time_zone,
                fold,
            } => {
                if calendar.trim().is_empty() {
                    return Err(TemporalValueError::MissingCalendar);
                }
                if *year <= 0 || *month == 0 || *day == 0 {
                    return Err(TemporalValueError::InvalidDateComponents);
                }
                if *hour > 23 || *minute > 59 || *second > 59 {
                    return Err(TemporalValueError::InvalidClockComponents);
                }
                if time_zone.trim().is_empty() {
                    return Err(TemporalValueError::InvalidTimeZone);
                }
                if fold.is_some_and(|value| value > 1) {
                    return Err(TemporalValueError::InvalidFold);
                }
                if *nanosecond >= 1_000_000_000 {
                    return Err(TemporalValueError::InvalidNanosecond);
                }
            }
            Self::Instant { nanosecond, .. } => {
                if *nanosecond >= 1_000_000_000 {
                    return Err(TemporalValueError::InvalidNanosecond);
                }
            }
        }
        Ok(())
    }

    /// Only an already-absolute instant can be read as Unix time without calendar/zone
    /// conversion. Date-only and local civil values cannot be silently coerced.
    pub fn as_unix_instant(&self) -> Option<(i64, u32)> {
        match self {
            Self::Instant {
                unix_seconds,
                nanosecond,
            } => Some((*unix_seconds, *nanosecond)),
            Self::DateOnly { .. } | Self::LocalDateTime { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_only_remains_distinct_from_an_absolute_instant() {
        let date = TemporalValue::DateOnly {
            calendar: "ethiopic".into(),
            year: 2019,
            month: 1,
            day: 1,
        };
        assert_eq!(date.kind(), TemporalKind::DateOnly);
        assert!(date.validate().is_ok());
        assert_eq!(date.as_unix_instant(), None);

        let instant = TemporalValue::Instant {
            unix_seconds: 1_799_000_000,
            nanosecond: 0,
        };
        assert_eq!(instant.kind(), TemporalKind::Instant);
        assert_eq!(instant.as_unix_instant(), Some((1_799_000_000, 0)));
    }

    #[test]
    fn invalid_clock_and_fractional_components_are_rejected() {
        let local = TemporalValue::LocalDateTime {
            calendar: "gregorian".into(),
            year: 2026,
            month: 11,
            day: 7,
            hour: 24,
            minute: 0,
            second: 0,
            nanosecond: 0,
            time_zone: "Africa/Addis_Ababa".into(),
            fold: None,
        };
        assert_eq!(local.validate(), Err(TemporalValueError::InvalidClockComponents));
        let instant = TemporalValue::Instant {
            unix_seconds: 0,
            nanosecond: 1_000_000_000,
        };
        assert_eq!(instant.validate(), Err(TemporalValueError::InvalidNanosecond));
    }
}
