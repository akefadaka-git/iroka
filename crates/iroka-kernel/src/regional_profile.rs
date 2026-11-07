//! Typed, deterministic regional profile resolution.
//! The included Ethiopia and Kenya records are technical conformance fixtures, not
//! legal/compliance approvals or production deployment profiles.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Reviewed,
    Unreviewed,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanguageProfile {
    pub primary: String,
    pub supported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarProfile {
    pub default: String,
    pub supported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrencyProfile {
    pub default: String,
    pub supported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalReference {
    pub reference_id: String,
    pub jurisdiction: String,
    pub effective_from: String,
    pub review_status: ReviewStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataGovernanceProfile {
    pub residency_policy_ref: Option<String>,
    pub cross_border_policy_ref: Option<String>,
    pub review_status: ReviewStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileProvenance {
    pub source: String,
    pub maintainer: String,
    pub reviewer: Option<String>,
    pub review_status: ReviewStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionalProfile {
    pub profile_id: String,
    pub profile_version: String,
    pub jurisdiction: String,
    pub effective_from: String,
    pub effective_until: Option<String>,
    pub languages: LanguageProfile,
    pub scripts: Vec<String>,
    pub calendar: CalendarProfile,
    pub time_zone: String,
    pub currencies: CurrencyProfile,
    pub numeral_systems: Vec<String>,
    pub legal_references: Vec<LegalReference>,
    pub data_governance: DataGovernanceProfile,
    pub provenance: ProfileProvenance,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfilePreferences {
    pub language: Option<String>,
    pub calendar: Option<String>,
    pub numeral_system: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileResolutionContext {
    pub organization: ProfilePreferences,
    pub user: ProfilePreferences,
    pub request: ProfilePreferences,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileRequirement {
    Presentation,
    Identity,
    LegalOperation,
    CrossBorderTransfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferenceSource {
    Deployment,
    Organization,
    User,
    Request,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRegionalProfile {
    pub profile_id: String,
    pub profile_version: String,
    pub jurisdiction: String,
    pub language: String,
    pub calendar: String,
    pub time_zone: String,
    pub currency: String,
    pub numeral_system: Option<String>,
    pub scripts: Vec<String>,
    pub language_source: PreferenceSource,
    pub calendar_source: PreferenceSource,
    pub numeral_source: Option<PreferenceSource>,
    pub provenance: ProfileProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionalProfileError {
    Malformed,
    Inactive,
    UnsupportedLanguage,
    UnsupportedCalendar,
    UnsupportedNumeralSystem,
    LegalReferencesUnreviewed,
    DataGovernanceUnreviewed,
}

fn valid_iso_date(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn contains_unique_non_empty(values: &[String]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    !values.is_empty()
        && values
            .iter()
            .all(|value| !value.trim().is_empty() && seen.insert(value))
}

impl RegionalProfile {
    pub fn validate(&self) -> Result<(), RegionalProfileError> {
        if self.profile_id.trim().is_empty()
            || self.profile_version.trim().is_empty()
            || self.jurisdiction.trim().is_empty()
            || !valid_iso_date(&self.effective_from)
            || self
                .effective_until
                .as_deref()
                .is_some_and(|until| !valid_iso_date(until) || until < self.effective_from.as_str())
            || self.languages.primary.trim().is_empty()
            || !self.languages.supported.contains(&self.languages.primary)
            || !contains_unique_non_empty(&self.languages.supported)
            || !contains_unique_non_empty(&self.scripts)
            || self.calendar.default.trim().is_empty()
            || !self.calendar.supported.contains(&self.calendar.default)
            || !contains_unique_non_empty(&self.calendar.supported)
            || self.time_zone.trim().is_empty()
            || self.currencies.default.len() != 3
            || !self.currencies.default.bytes().all(|byte| byte.is_ascii_uppercase())
            || !self.currencies.supported.contains(&self.currencies.default)
            || !contains_unique_non_empty(&self.currencies.supported)
            || !contains_unique_non_empty(&self.numeral_systems)
            || self.provenance.source.trim().is_empty()
            || self.provenance.maintainer.trim().is_empty()
        {
            return Err(RegionalProfileError::Malformed);
        }
        for reference in &self.legal_references {
            if reference.reference_id.trim().is_empty()
                || reference.jurisdiction != self.jurisdiction
                || !valid_iso_date(&reference.effective_from)
            {
                return Err(RegionalProfileError::Malformed);
            }
        }
        Ok(())
    }

    pub fn active_on(&self, effective_date: &str) -> bool {
        valid_iso_date(effective_date)
            && effective_date >= self.effective_from.as_str()
            && self
                .effective_until
                .as_deref()
                .is_none_or(|until| effective_date <= until)
    }

    /// Technical Ethiopia fixture: Amharic/Ethiopic, Ethiopian calendar, Addis Ababa and ETB.
    /// Legal/data-governance fields intentionally remain unreviewed.
    pub fn ethiopia_technical_fixture() -> Self {
        Self {
            profile_id: "et-ET".into(),
            profile_version: "1.0.0-fixture".into(),
            jurisdiction: "ET".into(),
            effective_from: "2026-01-01".into(),
            effective_until: None,
            languages: LanguageProfile {
                primary: "am-ET".into(),
                supported: vec!["am-ET".into(), "en".into()],
            },
            scripts: vec!["Ethiopic".into(), "Latin".into()],
            calendar: CalendarProfile {
                default: "ethiopic".into(),
                supported: vec!["ethiopic".into(), "gregorian".into()],
            },
            time_zone: "Africa/Addis_Ababa".into(),
            currencies: CurrencyProfile {
                default: "ETB".into(),
                supported: vec!["ETB".into()],
            },
            numeral_systems: vec!["ethiopic".into(), "latn".into()],
            legal_references: Vec::new(),
            data_governance: DataGovernanceProfile {
                residency_policy_ref: None,
                cross_border_policy_ref: None,
                review_status: ReviewStatus::Pending,
            },
            provenance: ProfileProvenance {
                source: "IROKA A2 technical fixture".into(),
                maintainer: "IROKA".into(),
                reviewer: None,
                review_status: ReviewStatus::Unreviewed,
            },
        }
    }

    /// Synthetic non-Ethiopian profile used only to prove configuration isolation.
    /// It is not a statement of Kenyan law or production support.
    pub fn kenya_technical_fixture() -> Self {
        Self {
            profile_id: "ke-KE".into(),
            profile_version: "1.0.0-fixture".into(),
            jurisdiction: "KE".into(),
            effective_from: "2026-01-01".into(),
            effective_until: None,
            languages: LanguageProfile {
                primary: "en-KE".into(),
                supported: vec!["en-KE".into(), "sw-KE".into()],
            },
            scripts: vec!["Latin".into()],
            calendar: CalendarProfile {
                default: "gregorian".into(),
                supported: vec!["gregorian".into()],
            },
            time_zone: "Africa/Nairobi".into(),
            currencies: CurrencyProfile {
                default: "KES".into(),
                supported: vec!["KES".into()],
            },
            numeral_systems: vec!["latn".into()],
            legal_references: Vec::new(),
            data_governance: DataGovernanceProfile {
                residency_policy_ref: None,
                cross_border_policy_ref: None,
                review_status: ReviewStatus::Pending,
            },
            provenance: ProfileProvenance {
                source: "IROKA A2 synthetic regional isolation fixture".into(),
                maintainer: "IROKA".into(),
                reviewer: None,
                review_status: ReviewStatus::Unreviewed,
            },
        }
    }
}

fn resolve_choice<'a>(
    default: &'a str,
    allowed: &[String],
    preferences: [&'a Option<String>; 3],
    error: RegionalProfileError,
) -> Result<(String, PreferenceSource), RegionalProfileError> {
    let sources = [
        (preferences[2], PreferenceSource::Request),
        (preferences[1], PreferenceSource::User),
        (preferences[0], PreferenceSource::Organization),
    ];
    for (preference, source) in sources {
        if let Some(value) = preference {
            if !allowed.contains(value) {
                return Err(error);
            }
            return Ok((value.clone(), source));
        }
    }
    Ok((default.to_owned(), PreferenceSource::Deployment))
}

pub fn resolve_regional_profile(
    profile: &RegionalProfile,
    effective_date: &str,
    context: &ProfileResolutionContext,
    requirement: ProfileRequirement,
) -> Result<ResolvedRegionalProfile, RegionalProfileError> {
    profile.validate()?;
    if !profile.active_on(effective_date) {
        return Err(RegionalProfileError::Inactive);
    }
    if requirement == ProfileRequirement::LegalOperation
        && (profile.legal_references.is_empty()
            || profile
                .legal_references
                .iter()
                .any(|reference| reference.review_status != ReviewStatus::Reviewed))
    {
        return Err(RegionalProfileError::LegalReferencesUnreviewed);
    }
    if requirement == ProfileRequirement::CrossBorderTransfer
        && (profile.data_governance.residency_policy_ref.is_none()
            || profile.data_governance.cross_border_policy_ref.is_none()
            || profile.data_governance.review_status != ReviewStatus::Reviewed)
    {
        return Err(RegionalProfileError::DataGovernanceUnreviewed);
    }

    let (language, language_source) = resolve_choice(
        &profile.languages.primary,
        &profile.languages.supported,
        [
            &context.organization.language,
            &context.user.language,
            &context.request.language,
        ],
        RegionalProfileError::UnsupportedLanguage,
    )?;
    let (calendar, calendar_source) = resolve_choice(
        &profile.calendar.default,
        &profile.calendar.supported,
        [
            &context.organization.calendar,
            &context.user.calendar,
            &context.request.calendar,
        ],
        RegionalProfileError::UnsupportedCalendar,
    )?;
    let (numeral_system, numeral_source) = match (
        context.organization.numeral_system.as_ref(),
        context.user.numeral_system.as_ref(),
        context.request.numeral_system.as_ref(),
    ) {
        (None, None, None) => (None, None),
        _ => {
            let (value, source) = resolve_choice(
                "",
                &profile.numeral_systems,
                [
                    &context.organization.numeral_system,
                    &context.user.numeral_system,
                    &context.request.numeral_system,
                ],
                RegionalProfileError::UnsupportedNumeralSystem,
            )?;
            (Some(value), Some(source))
        }
    };

    Ok(ResolvedRegionalProfile {
        profile_id: profile.profile_id.clone(),
        profile_version: profile.profile_version.clone(),
        jurisdiction: profile.jurisdiction.clone(),
        language,
        calendar,
        time_zone: profile.time_zone.clone(),
        currency: profile.currencies.default.clone(),
        numeral_system,
        scripts: profile.scripts.clone(),
        language_source,
        calendar_source,
        numeral_source,
        provenance: profile.provenance.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethiopia_fixture_resolves_amharic_ethiopic_calendar_addis_and_etb() {
        let profile = RegionalProfile::ethiopia_technical_fixture();
        let resolved = resolve_regional_profile(
            &profile,
            "2026-11-07",
            &ProfileResolutionContext::default(),
            ProfileRequirement::Presentation,
        )
        .unwrap();
        assert_eq!(resolved.language, "am-ET");
        assert_eq!(resolved.calendar, "ethiopic");
        assert_eq!(resolved.time_zone, "Africa/Addis_Ababa");
        assert_eq!(resolved.currency, "ETB");
    }

    #[test]
    fn user_and_request_preferences_follow_deterministic_precedence() {
        let profile = RegionalProfile::ethiopia_technical_fixture();
        let context = ProfileResolutionContext {
            organization: ProfilePreferences {
                language: Some("en".into()),
                ..ProfilePreferences::default()
            },
            user: ProfilePreferences {
                language: Some("am-ET".into()),
                calendar: Some("gregorian".into()),
                numeral_system: Some("ethiopic".into()),
            },
            request: ProfilePreferences {
                language: Some("en".into()),
                ..ProfilePreferences::default()
            },
        };
        let resolved = resolve_regional_profile(
            &profile,
            "2026-11-07",
            &context,
            ProfileRequirement::Presentation,
        )
        .unwrap();
        assert_eq!(resolved.language, "en");
        assert_eq!(resolved.language_source, PreferenceSource::Request);
        assert_eq!(resolved.calendar, "gregorian");
        assert_eq!(resolved.calendar_source, PreferenceSource::User);
        assert_eq!(resolved.numeral_system.as_deref(), Some("ethiopic"));
    }

    #[test]
    fn kenya_fixture_does_not_inherit_ethiopia_defaults() {
        let profile = RegionalProfile::kenya_technical_fixture();
        let resolved = resolve_regional_profile(
            &profile,
            "2026-11-07",
            &ProfileResolutionContext::default(),
            ProfileRequirement::Presentation,
        )
        .unwrap();
        assert_eq!(resolved.language, "en-KE");
        assert_eq!(resolved.calendar, "gregorian");
        assert_eq!(resolved.time_zone, "Africa/Nairobi");
        assert_eq!(resolved.currency, "KES");
        assert!(!resolved.scripts.contains(&"Ethiopic".into()));
    }

    #[test]
    fn unresolved_legal_and_cross_border_references_fail_closed() {
        let profile = RegionalProfile::ethiopia_technical_fixture();
        assert_eq!(
            resolve_regional_profile(
                &profile,
                "2026-11-07",
                &ProfileResolutionContext::default(),
                ProfileRequirement::LegalOperation
            ),
            Err(RegionalProfileError::LegalReferencesUnreviewed)
        );
        assert_eq!(
            resolve_regional_profile(
                &profile,
                "2026-11-07",
                &ProfileResolutionContext::default(),
                ProfileRequirement::CrossBorderTransfer
            ),
            Err(RegionalProfileError::DataGovernanceUnreviewed)
        );
    }

    #[test]
    fn unsupported_preference_and_expired_profile_are_rejected() {
        let profile = RegionalProfile::ethiopia_technical_fixture();
        let context = ProfileResolutionContext {
            user: ProfilePreferences {
                language: Some("fr-FR".into()),
                ..ProfilePreferences::default()
            },
            ..ProfileResolutionContext::default()
        };
        assert_eq!(
            resolve_regional_profile(
                &profile,
                "2026-11-07",
                &context,
                ProfileRequirement::Presentation
            ),
            Err(RegionalProfileError::UnsupportedLanguage)
        );
        let mut expired = profile;
        expired.effective_until = Some("2026-01-31".into());
        assert_eq!(
            resolve_regional_profile(
                &expired,
                "2026-11-07",
                &ProfileResolutionContext::default(),
                ProfileRequirement::Presentation
            ),
            Err(RegionalProfileError::Inactive)
        );
    }
}
