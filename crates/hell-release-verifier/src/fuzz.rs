use crate::json::{self, Value};
use crate::model::{ConformancePlan, ReleasePlan};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    StrictJson,
    ReleasePlan,
    ConformancePlan,
    Evidence,
    Ledger,
    Exemption,
    Gzip,
    GnuTar,
    Subjects,
    PublicationEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuzzFailure {
    pub code: &'static str,
    pub message: String,
}

impl FuzzFailure {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "fuzz.independent-input.invalid",
            message: message.into(),
        }
    }
}

/// Exercises one independent-verifier parser surface.
///
/// # Errors
///
/// Returns a bounded, typed parser failure when the supplied bytes are not a
/// valid input for the selected surface.
pub fn exercise(target: Target, bytes: &[u8]) -> Result<(), FuzzFailure> {
    const MAX_INPUT: usize = 64 * 1024 * 1024;
    if bytes.len() > MAX_INPUT {
        return Err(FuzzFailure {
            code: "fuzz.independent-input.limit",
            message: "independent fuzz input exceeds the parser bound".to_owned(),
        });
    }
    match target {
        Target::Gzip => crate::archive::fuzz_gzip(bytes),
        Target::GnuTar => crate::archive::fuzz_tar(bytes),
        Target::Subjects => crate::verifier::fuzz_parse_subjects(bytes),
        Target::StrictJson => json::parse_canonical(bytes).map(|_| ()),
        Target::ReleasePlan => {
            parse_json(bytes).and_then(|value| ReleasePlan::parse(&value).map(|_| ()))
        }
        Target::ConformancePlan | Target::Exemption => {
            parse_json(bytes).and_then(|value| ConformancePlan::parse(&value).map(|_| ()))
        }
        Target::Evidence => {
            parse_json(bytes).and_then(|value| crate::verifier::fuzz_validate_evidence(&value))
        }
        Target::Ledger => {
            parse_json(bytes).and_then(|value| crate::verifier::fuzz_validate_ledger(&value))
        }
        Target::PublicationEnvelope => parse_json(bytes)
            .and_then(|value| crate::verifier::fuzz_validate_publication_envelope(&value)),
    }
    .map_err(FuzzFailure::invalid)
}

fn parse_json(bytes: &[u8]) -> Result<Value, String> {
    json::parse_canonical(bytes)
}
