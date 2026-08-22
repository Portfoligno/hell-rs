#[derive(Clone, Copy)]
pub(crate) enum Mutant {
    AcceptUnknownPublisherDraft,
    SkipShallowEnvelopeVerification,
}

#[cfg(feature = "mutation-testing")]
impl Mutant {
    const fn id(self) -> &'static str {
        match self {
            Self::AcceptUnknownPublisherDraft => "accept-unknown-publisher-draft",
            Self::SkipShallowEnvelopeVerification => "skip-shallow-envelope-verification",
        }
    }
}

#[cfg(feature = "mutation-testing")]
pub(crate) fn active(mutant: Mutant) -> bool {
    selected(std::env::args_os()).as_deref() == Some(mutant.id())
}

#[cfg(not(feature = "mutation-testing"))]
pub(crate) const fn active(_mutant: Mutant) -> bool {
    false
}

#[cfg(feature = "mutation-testing")]
fn selected(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Option<String> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let marker_count = arguments
        .iter()
        .filter(|argument| *argument == "__hell_mutant")
        .count();
    if marker_count == 0 {
        return None;
    }
    let selections = arguments
        .windows(4)
        .filter(|window| {
            window[0] == "--skip" && window[1] == "__hell_mutant" && window[2] == "--skip"
        })
        .collect::<Vec<_>>();
    assert_eq!(marker_count, 1, "mutation argv marker must be unique");
    assert_eq!(selections.len(), 1, "mutation argv is malformed");
    Some(
        selections[0][3]
            .to_str()
            .expect("mutation id must be UTF-8")
            .to_owned(),
    )
}
