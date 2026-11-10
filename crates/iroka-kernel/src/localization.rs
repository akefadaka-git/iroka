//! Bounded localization adapters and deterministic calendar conversion.
//!
//! This module provides language-neutral technical infrastructure. It does not
//! supply translations, transliteration tables, authoritative orthography or
//! cultural interpretations. Unsupported script conversion fails closed while
//! preserving the original input. Review evidence is descriptive and is not an
//! authenticated reviewer credential or an authorization grant.

use crate::{EvidenceKind, EvidenceReference, ScriptSystem};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptTransformStatus {
    ExactPassThrough,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptTransformResult {
    original_text: String,
    output_text: Option<String>,
    status: ScriptTransformStatus,
}

impl ScriptTransformResult {
    pub fn original_text(&self) -> &str {
        &self.original_text
    }

    pub fn output_text(&self) -> Option<&str> {
        self.output_text.as_deref()
    }

    pub fn status(&self) -> ScriptTransformStatus {
        self.status
    }
}

/// Conservative adapter: only same-script pass-through is supported.
/// Cross-script conversion is deliberately not guessed.
pub fn transform_script(
    text: &str,
    source: ScriptSystem,
    target: ScriptSystem,
) -> ScriptTransformResult {
    if source == target && source != ScriptSystem::Unspecified {
        ScriptTransformResult {
            original_text: text.to_owned(),
            output_text: Some(text.to_owned()),
            status: ScriptTransformStatus::ExactPassThrough,
        }
    } else {
        ScriptTransformResult {
            original_text: text.to_owned(),
            output_text: None,
            status: ScriptTransformStatus::Unsupported,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationState {
    NotTranslated,
    Draft,
    Unverified,
    ReviewEvidenceRecorded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizationEntry {
    id: String,
    source: EvidenceReference,
    source_language_tag: String,
    target_language_tag: String,
    source_text: String,
    translated_text: Option<String>,
    state: TranslationState,
    review_evidence: Option<EvidenceReference>,
}

impl LocalizationEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        source: EvidenceReference,
        source_language_tag: impl Into<String>,
        target_language_tag: impl Into<String>,
        source_text: impl Into<String>,
        translated_text: Option<String>,
        state: TranslationState,
        review_evidence: Option<EvidenceReference>,
    ) -> Result<Self, LocalizationError> {
        let entry = Self {
            id: id.into(),
            source,
            source_language_tag: source_language_tag.into(),
            target_language_tag: target_language_tag.into(),
            source_text: source_text.into(),
            translated_text,
            state,
            review_evidence,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> Result<(), LocalizationError> {
        if self.id.trim().is_empty() {
            return Err(LocalizationError::EmptyId);
        }
        self.source
            .validate()
            .map_err(LocalizationError::InvalidEvidence)?;
        if !valid_language_tag(&self.source_language_tag)
            || !valid_language_tag(&self.target_language_tag)
        {
            return Err(LocalizationError::InvalidLanguageTag);
        }
        if self.source_language_tag == self.target_language_tag {
            return Err(LocalizationError::SourceAndTargetLanguageMatch);
        }
        if self.source_text.trim().is_empty() {
            return Err(LocalizationError::EmptySourceText);
        }

        match (self.state, self.translated_text.as_deref()) {
            (TranslationState::NotTranslated, None) => {}
            (TranslationState::NotTranslated, Some(_)) => {
                return Err(LocalizationError::UnexpectedTranslation);
            }
            (_, None) => return Err(LocalizationError::TranslationTextRequired),
            (_, Some(text)) if text.trim().is_empty() => {
                return Err(LocalizationError::EmptyTranslationText);
            }
            _ => {}
        }

        match (self.state, &self.review_evidence) {
            (TranslationState::ReviewEvidenceRecorded, None) => {
                return Err(LocalizationError::ReviewEvidenceRequired);
            }
            (TranslationState::ReviewEvidenceRecorded, Some(evidence)) => {
                evidence
                    .validate()
                    .map_err(LocalizationError::InvalidEvidence)?;
                if evidence.kind() == EvidenceKind::GeneratedSynthesis {
                    return Err(LocalizationError::GeneratedSynthesisCannotEvidenceReview);
                }
            }
            (_, Some(_)) => return Err(LocalizationError::UnexpectedReviewEvidence),
            _ => {}
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn source(&self) -> &EvidenceReference {
        &self.source
    }

    pub fn source_language_tag(&self) -> &str {
        &self.source_language_tag
    }

    pub fn target_language_tag(&self) -> &str {
        &self.target_language_tag
    }

    pub fn source_text(&self) -> &str {
        &self.source_text
    }

    pub fn translated_text(&self) -> Option<&str> {
        self.translated_text.as_deref()
    }

    pub fn state(&self) -> TranslationState {
        self.state
    }

    /// Evidence reference only; it does not authenticate a reviewer or confer authority.
    pub fn review_evidence(&self) -> Option<&EvidenceReference> {
        self.review_evidence.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalizationError {
    EmptyId,
    InvalidEvidence(crate::EvidenceValidationError),
    InvalidLanguageTag,
    SourceAndTargetLanguageMatch,
    EmptySourceText,
    UnexpectedTranslation,
    TranslationTextRequired,
    EmptyTranslationText,
    ReviewEvidenceRequired,
    UnexpectedReviewEvidence,
    GeneratedSynthesisCannotEvidenceReview,
}

fn valid_language_tag(tag: &str) -> bool {
    let mut subtags = tag.split('-');
    let Some(language) = subtags.next() else {
        return false;
    };
    if !(2..=8).contains(&language.len())
        || !language.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return false;
    }
    subtags.all(|subtag| {
        (1..=8).contains(&subtag.len()) && subtag.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthiopianDate {
    year: u32,
    month: u8,
    day: u8,
}

impl EthiopianDate {
    pub fn new(year: u32, month: u8, day: u8) -> Result<Self, CalendarError> {
        let date = Self { year, month, day };
        date.validate()?;
        Ok(date)
    }

    pub fn year(&self) -> u32 {
        self.year
    }
    pub fn month(&self) -> u8 {
        self.month
    }
    pub fn day(&self) -> u8 {
        self.day
    }

    fn validate(&self) -> Result<(), CalendarError> {
        if self.year == 0 || !(1..=13).contains(&self.month) {
            return Err(CalendarError::InvalidDate);
        }
        let max_day = if self.month == 13 {
            if self.year % 4 == 3 {
                6
            } else {
                5
            }
        } else {
            30
        };
        if self.day == 0 || self.day > max_day {
            return Err(CalendarError::InvalidDate);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GregorianDate {
    year: u32,
    month: u8,
    day: u8,
}

impl GregorianDate {
    pub fn new(year: u32, month: u8, day: u8) -> Result<Self, CalendarError> {
        let date = Self { year, month, day };
        date.validate()?;
        Ok(date)
    }

    pub fn year(&self) -> u32 { self.year }
    pub fn month(&self) -> u8 { self.month }
    pub fn day(&self) -> u8 { self.day }

    fn validate(&self) -> Result<(), CalendarError> {
        if self.year == 0 || !(1..=12).contains(&self.month) {
            return Err(CalendarError::InvalidDate);
        }
        let max_day = match self.month {
            4 | 6 | 9 | 11 => 30,
            2 if is_gregorian_leap_year(self.year) => 29,
            2 => 28,
            _ => 31,
        };
        if self.day == 0 || self.day > max_day {
            return Err(CalendarError::InvalidDate);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarError {
    InvalidDate,
    OutOfSupportedRange,
}

fn is_gregorian_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Converts an Ethiopian calendar date to the proleptic Gregorian calendar.
pub fn ethiopian_to_gregorian(date: EthiopianDate) -> Result<GregorianDate, CalendarError> {
    date.validate()?;
    let year = i64::from(date.year);
    let jdn = 1_724_220_i64
        + 365 * (year - 1)
        + year / 4
        + 30 * (i64::from(date.month) - 1)
        + i64::from(date.day);
    gregorian_from_jdn(jdn)
}

/// Converts a proleptic Gregorian date to the Ethiopian calendar.
pub fn gregorian_to_ethiopian(date: GregorianDate) -> Result<EthiopianDate, CalendarError> {
    date.validate()?;
    let jdn = gregorian_jdn(date);
    let elapsed = jdn - 1_724_220_i64;
    let year = (4 * elapsed + 1_459) / 1_461;
    if year <= 0 || year > i64::from(u32::MAX) {
        return Err(CalendarError::OutOfSupportedRange);
    }
    let year_start = 1_724_220_i64 + 365 * (year - 1) + year / 4;
    let day_of_year = jdn - year_start;
    if !(1..=366).contains(&day_of_year) {
        return Err(CalendarError::OutOfSupportedRange);
    }
    let month = ((day_of_year - 1) / 30) + 1;
    let day = ((day_of_year - 1) % 30) + 1;
    EthiopianDate::new(year as u32, month as u8, day as u8)
}

fn gregorian_jdn(date: GregorianDate) -> i64 {
    let mut year = i64::from(date.year);
    let month = i64::from(date.month);
    let day = i64::from(date.day);
    let a = (14 - month) / 12;
    year += 4_800 - a;
    let month = month + 12 * a - 3;
    day + (153 * month + 2) / 5 + 365 * year + year / 4 - year / 100 + year / 400 - 32_045
}

fn gregorian_from_jdn(jdn: i64) -> Result<GregorianDate, CalendarError> {
    let a = jdn + 32_044;
    let b = (4 * a + 3) / 146_097;
    let c = a - (146_097 * b) / 4;
    let d = (4 * c + 3) / 1_461;
    let e = c - (1_461 * d) / 4;
    let m = (5 * e + 2) / 153;
    let day = e - (153 * m + 2) / 5 + 1;
    let month = m + 3 - 12 * (m / 10);
    let year = 100 * b + d - 4_800 + m / 10;
    if year <= 0 || year > i64::from(u32::MAX) {
        return Err(CalendarError::OutOfSupportedRange);
    }
    GregorianDate::new(year as u32, month as u8, day as u8)
}
