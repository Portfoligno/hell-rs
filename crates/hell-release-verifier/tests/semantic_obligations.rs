use std::fmt::Write as _;

use hell_release_verifier::validate_semantic_obligation_observation;

const TARGET: u64 = 7;
const RAW_PRESENTATION_SHA256: &str =
    "8c3d1f9e2ebe688d099b39befd3cff8ff07d6a99e561fb34e8edcb1b55440d36";
const FORCE_RESULT_SHA256: &str =
    "7fc90c85a7493cba372cffbd3b8521692573f75247a1605b77fd7fc83681ccba";
const FORCE_RESULT_HEX: &str = "7b2274797065223a225479706564526573756c74222c22617267756d656e74223a302c22626f756e64617279223a22616461707465722d726573756c74222c2276616c7565223a7b2274797065223a22466f726365426f756e64617279222c226f7574636f6d65223a226572726f72222c22636f6465223a2245227d7d";

#[derive(Clone)]
struct SemanticFixture {
    status: SemanticStatus,
    target_entered: EvidencePresence,
    event_outcome: Option<&'static str>,
    materialized_before: u64,
    materialized_after: u64,
    boundaries: Vec<&'static str>,
    effect: Option<&'static str>,
    callback: EvidencePresence,
    typed_force_error: EvidencePresence,
}

#[derive(Clone, Copy)]
enum SemanticStatus {
    Success,
    Failure,
}

#[derive(Clone, Copy)]
enum EvidencePresence {
    Absent,
    Present,
}

impl SemanticFixture {
    const fn success(&self) -> bool {
        matches!(self.status, SemanticStatus::Success)
    }
}

impl EvidencePresence {
    const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

impl Default for SemanticFixture {
    fn default() -> Self {
        Self {
            status: SemanticStatus::Success,
            target_entered: EvidencePresence::Present,
            event_outcome: Some("value"),
            materialized_before: 0,
            materialized_after: 0,
            boundaries: Vec::new(),
            effect: None,
            callback: EvidencePresence::Absent,
            typed_force_error: EvidencePresence::Absent,
        }
    }
}

#[test]
fn every_closed_semantic_class_rejects_plausible_but_wrong_evidence() {
    let cases = semantic_cases();
    assert_eq!(cases.len(), 18);
    for (obligation, builtin, valid, invalid) in cases {
        let valid = observation(&valid);
        validate_semantic_obligation_observation(&valid, builtin, TARGET, obligation)
            .unwrap_or_else(|error| panic!("valid {obligation} evidence was rejected: {error}"));
        let invalid = observation(&invalid);
        assert!(
            validate_semantic_obligation_observation(&invalid, builtin, TARGET, obligation)
                .is_err(),
            "wrong-but-plausible {obligation} evidence was admitted"
        );
    }
}

fn semantic_cases() -> Vec<(&'static str, &'static str, SemanticFixture, SemanticFixture)> {
    let mut cases = first_semantic_cases();
    cases.extend(second_semantic_cases());
    cases
}

fn first_semantic_cases() -> Vec<(&'static str, &'static str, SemanticFixture, SemanticFixture)> {
    let base = SemanticFixture::default();
    let failed = SemanticFixture {
        status: SemanticStatus::Failure,
        event_outcome: Some("error"),
        ..base.clone()
    };
    vec![
        (
            "adapter-success",
            "List.map",
            base.clone(),
            SemanticFixture {
                event_outcome: Some("error"),
                ..base.clone()
            },
        ),
        ("adapter-failure", "List.map", failed, base.clone()),
        (
            "result-force-failure",
            "List.map",
            SemanticFixture {
                status: SemanticStatus::Failure,
                event_outcome: Some("alias"),
                typed_force_error: EvidencePresence::Present,
                ..base.clone()
            },
            SemanticFixture {
                status: SemanticStatus::Failure,
                event_outcome: Some("value"),
                typed_force_error: EvidencePresence::Present,
                ..base.clone()
            },
        ),
        boundary_case("lazy-boundary", "lazy-adapter-entry", "whnf-force-complete"),
        boundary_case(
            "whnf-boundary",
            "whnf-force-complete",
            "deep-force-complete",
        ),
        (
            "whnf-failure-boundary",
            "List.map",
            SemanticFixture {
                status: SemanticStatus::Failure,
                target_entered: EvidencePresence::Absent,
                event_outcome: None,
                boundaries: vec!["whnf-force-failed"],
                ..base.clone()
            },
            SemanticFixture {
                status: SemanticStatus::Success,
                target_entered: EvidencePresence::Absent,
                event_outcome: None,
                boundaries: vec!["whnf-force-failed"],
                ..base.clone()
            },
        ),
        boundary_case(
            "deep-boundary",
            "deep-force-complete",
            "whnf-force-complete",
        ),
        conditional_case("conditional-selected"),
        conditional_case("conditional-unselected"),
    ]
}

fn second_semantic_cases() -> Vec<(&'static str, &'static str, SemanticFixture, SemanticFixture)> {
    let base = SemanticFixture::default();
    let no_event = SemanticFixture {
        event_outcome: None,
        ..base.clone()
    };
    vec![
        (
            "io-execution-boundary",
            "IO.print",
            SemanticFixture {
                boundaries: vec!["io-execution-complete"],
                effect: Some("started"),
                ..base.clone()
            },
            SemanticFixture {
                boundaries: vec!["io-execution-complete"],
                ..base.clone()
            },
        ),
        success_event_case("collection-interaction"),
        success_event_case("constructor-eliminator"),
        success_event_case("numeric-boundary"),
        (
            "encoding-boundary",
            "Text.decodeUtf8",
            base.clone(),
            no_event,
        ),
        success_event_case("parser-composition"),
        (
            "typed-result",
            "List.map",
            SemanticFixture {
                typed_force_error: EvidencePresence::Present,
                ..base.clone()
            },
            base.clone(),
        ),
        (
            "callback-order",
            "List.map",
            SemanticFixture {
                callback: EvidencePresence::Present,
                ..base.clone()
            },
            base.clone(),
        ),
        (
            "bounded-materialization",
            "Map.singleton",
            base.clone(),
            SemanticFixture {
                materialized_before: 1,
                materialized_after: 1,
                ..base
            },
        ),
    ]
}

fn boundary_case(
    obligation: &'static str,
    valid_boundary: &'static str,
    invalid_boundary: &'static str,
) -> (&'static str, &'static str, SemanticFixture, SemanticFixture) {
    let base = SemanticFixture::default();
    (
        obligation,
        "List.map",
        SemanticFixture {
            boundaries: vec![valid_boundary],
            ..base.clone()
        },
        SemanticFixture {
            boundaries: vec![invalid_boundary],
            ..base
        },
    )
}

fn conditional_case(
    obligation: &'static str,
) -> (&'static str, &'static str, SemanticFixture, SemanticFixture) {
    let base = SemanticFixture::default();
    (
        obligation,
        "Bool.bool",
        SemanticFixture {
            boundaries: vec!["conditional-value", "conditional-not-forced"],
            ..base.clone()
        },
        SemanticFixture {
            boundaries: vec!["conditional-value"],
            ..base
        },
    )
}

fn success_event_case(
    obligation: &'static str,
) -> (&'static str, &'static str, SemanticFixture, SemanticFixture) {
    let base = SemanticFixture::default();
    (
        obligation,
        "List.map",
        base.clone(),
        SemanticFixture {
            status: SemanticStatus::Failure,
            ..base
        },
    )
}

fn observation(fixture: &SemanticFixture) -> Vec<u8> {
    let document = semantic_document(fixture);
    let status = if fixture.success() { "true" } else { "false" };
    let code = i32::from(!fixture.success());
    format!(
        concat!(
            "{{\"diagnostic\":\"\",\"exit\":{{\"kind\":\"code\",\"value\":{code}}},",
            "\"filesystem\":\"\",\"mode\":\"release\",",
            "\"normalizerContext\":{{\"executable\":\"hell\",\"sandbox\":\"/sandbox\",\"script\":\"/sandbox/main.hell\"}},",
            "\"rawStderr\":{{\"encoding\":\"base64\",\"value\":\"\"}},",
            "\"resourceAudit\":\"\",\"schemaVersion\":4,\"semanticTrace\":[\"{document}\"],",
            "\"statusSuccess\":{status},\"stderr\":{{\"encoding\":\"base64\",\"value\":\"\"}},",
            "\"stdout\":{{\"encoding\":\"base64\",\"value\":\"\"}},\"termination\":\"exited\"}}\n"
        ),
        code = code,
        status = status,
        document = escape_json_string(&document),
    )
    .into_bytes()
}

fn semantic_document(fixture: &SemanticFixture) -> String {
    let coverage_target = if fixture.target_entered.is_present() {
        TARGET
    } else {
        TARGET + 1
    };
    let mut coverage = format!(
        concat!(
            "[{{\"builtinId\":{TARGET},\"kind\":\"parsed-builtin\"}},",
            "{{\"builtinId\":{coverage_target},\"kind\":\"resolved-builtin\"}},",
            "{{\"builtinId\":{coverage_target},\"kind\":\"specialized-builtin\"}},",
            "{{\"builtinId\":{coverage_target},\"kind\":\"entered-adapter\"}}"
        ),
        TARGET = TARGET,
        coverage_target = coverage_target
    );
    let mut event_kinds = vec![
        "parsed-builtin",
        "resolved-builtin",
        "specialized-builtin",
        "entered-adapter",
    ];
    let boundaries = boundary_json(&fixture.boundaries);
    event_kinds.extend(std::iter::repeat_n(
        "forced-argument",
        fixture.boundaries.len(),
    ));
    let effect = fixture.effect.map_or_else(String::new, |effect| {
        write!(
            coverage,
            ",{{\"builtinId\":{TARGET},\"detail\":\"{effect}\",\"kind\":\"executed-effect\"}}"
        )
        .expect("writing semantic coverage to String cannot fail");
        event_kinds.push("effect-event");
        format!(
            "[{{\"builtinId\":{TARGET},\"effect\":\"{effect}\",\"ownerTaskId\":null,\"parentSequence\":null,\"sequence\":1}}]"
        )
    });
    let effect = if effect.is_empty() {
        "[]".to_owned()
    } else {
        effect
    };
    let obligation = fixture.event_outcome.map_or_else(String::new, |outcome| {
        event_kinds.push("obligation-event");
        obligation_event(fixture, outcome)
    });
    let obligation = if obligation.is_empty() {
        "[]".to_owned()
    } else {
        format!("[{obligation}]")
    };
    let (typed_sha, typed_id, typed_hex) = if fixture.typed_force_error.is_present() {
        event_kinds.push("typed-result");
        (
            format!("\"{FORCE_RESULT_SHA256}\""),
            TARGET.to_string(),
            format!("\"{FORCE_RESULT_HEX}\""),
        )
    } else {
        ("null".to_owned(), "null".to_owned(), "null".to_owned())
    };
    coverage.push(']');
    let order = event_kinds
        .iter()
        .enumerate()
        .map(|(index, kind)| format!("{{\"eventId\":{},\"kind\":\"{kind}\"}}", index + 1))
        .collect::<Vec<_>>()
        .join(",");
    let status = if fixture.success() { "true" } else { "false" };
    let code = i32::from(!fixture.success());
    format!(
        concat!(
            "{{\"diagnostic\":null,\"normalizedPresentationLineEndingsSha256\":null,",
            "\"rawPresentationSha256\":\"{RAW_PRESENTATION_SHA256}\",\"resourceAuditFailures\":0,",
            "\"schemaVersion\":1,\"semanticBoundaries\":{boundaries},\"semanticCoverage\":{coverage},",
            "\"semanticEffectTrace\":{effect},\"semanticEventOrder\":[{order}],",
            "\"semanticObligationTrace\":{obligation},\"semanticResourceTrace\":[],\"semanticTaskTrace\":[],",
            "\"semanticTypedResultBuiltinId\":{typed_id},\"semanticTypedResultHex\":{typed_hex},",
            "\"semanticTypedResultSha256\":{typed_sha},\"status\":{{\"code\":{code},\"success\":{status}}},",
            "\"timedOut\":false}}\n"
        ),
        RAW_PRESENTATION_SHA256 = RAW_PRESENTATION_SHA256,
        boundaries = boundaries,
        coverage = coverage,
        effect = effect,
        order = order,
        obligation = obligation,
        typed_id = typed_id,
        typed_hex = typed_hex,
        typed_sha = typed_sha,
        code = code,
        status = status,
    )
}

fn boundary_json(classes: &[&str]) -> String {
    let entries = classes
        .iter()
        .enumerate()
        .map(|(index, class)| {
            let (class, outcome, error) = match *class {
                "conditional-value" => ("conditional-branch", "value", ""),
                "conditional-not-forced" => ("conditional-branch", "not-forced", ""),
                "lazy-adapter-entry" => (*class, "not-forced", ""),
                "whnf-force-failed" => (*class, "error", ",\"errorCode\":\"E\""),
                _ => (*class, "value", ""),
            };
            format!(
                "{{\"argument\":{index},\"builtinId\":{TARGET},\"class\":\"{class}\"{error},\"outcome\":\"{outcome}\"}}"
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{entries}]")
}

fn obligation_event(fixture: &SemanticFixture, outcome: &str) -> String {
    let callback = if fixture.callback.is_present() {
        concat!(
            "{\"branch\":\"function\",\"callbackArgument\":0,\"canonicalArgumentHex\":[],",
            "\"canonicalResultHex\":\"7b2274797065223a22556e6974222c2276616c7565223a6e756c6c7d\",",
            "\"invocation\":1,\"outcome\":\"value\"}"
        )
    } else {
        ""
    };
    format!(
        concat!(
            "{{\"builtinId\":{TARGET},\"callbackInvocations\":[{callback}],\"comparatorInvocations\":[],",
            "\"instancePremises\":[],\"instanceTarget\":null,\"materializedAfter\":{},",
            "\"materializedBefore\":{},\"nestedAdapters\":0,\"outcome\":\"{outcome}\",",
            "\"ownerTaskId\":null,\"parentSequence\":null,\"sequence\":1}}"
        ),
        fixture.materialized_after,
        fixture.materialized_before,
        TARGET = TARGET,
        callback = callback,
        outcome = outcome,
    )
}

fn escape_json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character => escaped.push(character),
        }
    }
    escaped
}
