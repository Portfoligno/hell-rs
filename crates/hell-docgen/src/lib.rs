//! Deterministic API, compatibility, and release-environment documentation.

use std::fmt::Write as _;

use hell_builtins::{
    ClaimPlatform, ClaimStatus, ClassHeadKind, CompatibilityDimension, ExecutionProfile, Fixity,
    TypeClass, Visibility, WiringStatus,
};

#[must_use]
pub fn render_api_markdown() -> String {
    let mut output = format!("# Hell {} API\n\n", hell_builtins::LANGUAGE_VERSION);
    output.push_str("## Type constructors\n\n");
    let mut constructors = hell_builtins::type_constructors()
        .iter()
        .filter(|constructor| constructor.visibility == Visibility::Public)
        .collect::<Vec<_>>();
    constructors.sort_by_key(|constructor| constructor.name);
    for constructor in constructors {
        writeln!(
            output,
            "- `{}` :: `{}`",
            constructor.name, constructor.kind_text
        )
        .expect("writing to String");
    }

    output.push_str("\n## Type classes\n\n");
    let mut classes = TypeClass::ALL.to_vec();
    classes.sort_by_key(|class| class.as_str());
    for class in classes {
        writeln!(
            output,
            "- `{}` :: `{}`",
            class.as_str(),
            class_head_markdown(class.head_kind())
        )
        .expect("writing to String");
    }

    output.push_str("\n## Primitive terms\n\n");
    let mut primitives = hell_builtins::registry()
        .iter()
        .filter(|primitive| primitive.visibility == Visibility::Public)
        .collect::<Vec<_>>();
    primitives.sort_by_key(|primitive| primitive.name);
    for primitive in primitives {
        output.push_str("- `");
        output.push_str(primitive.name);
        output.push('`');
        if let Some(scheme) = primitive.scheme {
            output.push_str(" :: `");
            output.push_str(scheme);
            output.push('`');
        } else {
            output.push_str(" *(adapter pending)*");
        }
        writeln!(output, " — wiring: `{}`", wiring_name(primitive.wiring))
            .expect("writing to String");
    }

    output.push_str("\n## Closed class instances\n\n");
    let mut instances = hell_builtins::instances().iter().collect::<Vec<_>>();
    instances.sort_by_key(|instance| (instance.class.as_str(), instance.target));
    for instance in instances {
        writeln!(
            output,
            "- `{} {}` — `{}`",
            instance.class.as_str(),
            instance.target,
            instance.resolution.as_str()
        )
        .expect("writing to String");
    }
    output
}

/// Renders the stable, sorted source-of-truth snapshot used by compatibility
/// review and release gates.
///
/// # Panics
///
/// Panics only if the registry and compatibility-claim inventory diverge;
/// repository policy validates that invariant before release generation.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_compatibility_json() -> String {
    let mut output = String::new();
    writeln!(output, "{{").expect("writing to String");
    writeln!(
        output,
        "  \"languageVersion\": \"{}\",",
        json_escape(hell_builtins::LANGUAGE_VERSION)
    )
    .expect("writing to String");
    writeln!(
        output,
        "  \"upstreamCommit\": \"{}\",",
        json_escape(hell_builtins::UPSTREAM_COMMIT)
    )
    .expect("writing to String");
    writeln!(
        output,
        "  \"upstreamSourceSha256\": \"{}\",",
        hell_builtins::UPSTREAM_SOURCE_SHA256
    )
    .expect("writing to String");
    writeln!(
        output,
        "  \"promotionPolicySha256\": \"{}\",",
        hell_builtins::PROMOTION_POLICY_SHA256
    )
    .expect("writing to String");
    writeln!(
        output,
        "  \"counts\": {{ \"publicTerms\": {}, \"internalTerms\": {}, \"typeConstructors\": {}, \"classes\": {}, \"instances\": {}, \"upstreamExamples\": {} }},",
        hell_builtins::PUBLIC_NAME_COUNT,
        hell_builtins::INTERNAL_NAME_COUNT,
        hell_builtins::type_constructors().len(),
        TypeClass::ALL.len(),
        hell_builtins::instances().len(),
        hell_builtins::UPSTREAM_EXAMPLE_COUNT
    )
    .expect("writing to String");

    output.push_str("  \"typeConstructors\": [\n");
    let mut constructors = hell_builtins::type_constructors()
        .iter()
        .collect::<Vec<_>>();
    constructors.sort_by_key(|constructor| constructor.name);
    for (index, constructor) in constructors.iter().enumerate() {
        writeln!(
            output,
            "    {{ \"name\": \"{}\", \"kind\": \"{}\", \"visibility\": \"{}\" }}{}",
            json_escape(constructor.name),
            json_escape(constructor.kind_text),
            visibility_name(constructor.visibility),
            comma(index, constructors.len())
        )
        .expect("writing to String");
    }
    output.push_str("  ],\n  \"classes\": [\n");
    let mut classes = TypeClass::ALL.to_vec();
    classes.sort_by_key(|class| class.as_str());
    for (index, class) in classes.iter().enumerate() {
        writeln!(
            output,
            "    {{ \"name\": \"{}\", \"headKind\": \"{}\" }}{}",
            class.as_str(),
            class_head_json(class.head_kind()),
            comma(index, classes.len())
        )
        .expect("writing to String");
    }
    output.push_str("  ],\n  \"instances\": [\n");
    let mut instances = hell_builtins::instances().iter().collect::<Vec<_>>();
    instances.sort_by_key(|instance| (instance.class.as_str(), instance.target));
    for (index, instance) in instances.iter().enumerate() {
        writeln!(
            output,
            "    {{ \"class\": \"{}\", \"target\": \"{}\", \"resolution\": \"{}\" }}{}",
            instance.class.as_str(),
            json_escape(instance.target),
            instance.resolution.as_str(),
            comma(index, instances.len())
        )
        .expect("writing to String");
    }
    output.push_str("  ],\n  \"terms\": [\n");
    let mut terms = hell_builtins::registry().iter().collect::<Vec<_>>();
    terms.sort_by_key(|term| term.name);
    for (index, term) in terms.iter().enumerate() {
        writeln!(
            output,
            "    {{ \"name\": \"{}\", \"visibility\": \"{}\", \"scheme\": {}, \"fixity\": {}, \"class\": {}, \"wiring\": \"{}\", \"implementation\": {}, \"claims\": [",
            json_escape(term.name),
            visibility_name(term.visibility),
            optional_json_string(term.scheme),
            fixity_json(term.fixity),
            optional_json_string(term.type_class.map(hell_builtins::TypeClass::as_str)),
            wiring_name(term.wiring),
            optional_json_string(term.implementation)
        )
        .expect("writing to String");
        let claim = hell_builtins::compatibility_claim(term.id)
            .expect("every registry term has a compatibility claim");
        for (claim_index, dimension) in claim.dimensions.iter().enumerate() {
            writeln!(
                output,
                "      {{ \"dimension\": \"{}\", \"scopes\": [",
                dimension_name(dimension.dimension),
            )
            .expect("writing to String");
            for (scope_index, scope) in dimension.scopes.iter().enumerate() {
                writeln!(
                    output,
                    "        {{ \"status\": \"{}\", \"profiles\": {}, \"platforms\": {}, \"evidence\": {}, \"normalizers\": {}, \"rationale\": {}, \"issue\": {} }}{}",
                    status_name(scope.status),
                    json_array(scope.profiles.iter().copied().map(profile_name)),
                    json_array(scope.platforms.iter().copied().map(platform_name)),
                    json_array(scope.evidence.iter().copied()),
                    json_array(scope.normalizers.iter().map(|normalizer| normalizer.as_str())),
                    optional_json_string(scope.rationale),
                    optional_json_string(scope.issue),
                    comma(scope_index, dimension.scopes.len())
                )
                .expect("writing to String");
            }
            writeln!(
                output,
                "      ] }}{}",
                comma(claim_index, claim.dimensions.len())
            )
            .expect("writing to String");
        }
        writeln!(output, "    ] }}{}", comma(index, terms.len())).expect("writing to String");
    }
    output.push_str("  ]\n}\n");
    output
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotMismatch {
    pub first_differing_byte: usize,
    pub expected_len: usize,
    pub generated_len: usize,
}

/// Compares a reviewed snapshot with the deterministic current manifest.
///
/// # Errors
///
/// Returns the first differing byte and both lengths when regeneration would
/// change the reviewed compatibility boundary.
pub fn verify_compatibility_snapshot(expected: &str) -> Result<(), SnapshotMismatch> {
    let generated = render_compatibility_json();
    if expected == generated {
        return Ok(());
    }
    let first_differing_byte = expected
        .as_bytes()
        .iter()
        .zip(generated.as_bytes())
        .position(|(expected, generated)| expected != generated)
        .unwrap_or_else(|| expected.len().min(generated.len()));
    Err(SnapshotMismatch {
        first_differing_byte,
        expected_len: expected.len(),
        generated_len: generated.len(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseEnvironment<'a> {
    pub implementation_version: &'a str,
    pub rust_toolchain: &'a str,
    pub target: &'a str,
    pub cargo_lock_checksum: &'a str,
    pub enabled_features: &'a [&'a str],
    pub oracle_executable_checksum: &'a str,
    pub known_divergences: &'a [&'a str],
}

#[must_use]
pub fn render_release_environment(environment: &ReleaseEnvironment<'_>) -> String {
    let mut features = environment.enabled_features.to_vec();
    features.sort_unstable();
    let mut divergences = environment.known_divergences.to_vec();
    divergences.sort_unstable();
    let mut output = format!(
        "# Hell Rust compatibility environment\n\n- implementation: `{}`\n- language baseline: `{}`\n- upstream commit: `{}`\n- Rust toolchain: `{}`\n- target: `{}`\n- Cargo.lock checksum: `{}`\n- enabled features: `{}`\n- oracle executable checksum: `{}`\n- architecture policy: `64-bit`\n- text/path policy: `UTF-8`\n- deterministic timezone: `UTC`\n- deterministic locale: `C/UTF-8`\n- test network: `loopback only`\n",
        environment.implementation_version,
        hell_builtins::LANGUAGE_VERSION,
        hell_builtins::UPSTREAM_COMMIT,
        environment.rust_toolchain,
        environment.target,
        environment.cargo_lock_checksum,
        features.join(","),
        environment.oracle_executable_checksum,
    );
    output.push_str("\n## Known deliberate divergences\n\n");
    if divergences.is_empty() {
        output.push_str("None.\n");
    } else {
        for divergence in divergences {
            writeln!(output, "- {divergence}").expect("writing to String");
        }
    }
    output
}

fn visibility_name(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Public => "public",
        Visibility::Internal => "internal",
    }
}

fn class_head_markdown(kind: ClassHeadKind) -> &'static str {
    match kind {
        ClassHeadKind::Type => "Type",
        ClassHeadKind::UnaryTypeConstructor => "Type -> Type",
    }
}

fn class_head_json(kind: ClassHeadKind) -> &'static str {
    match kind {
        ClassHeadKind::Type => "type",
        ClassHeadKind::UnaryTypeConstructor => "type-constructor-1",
    }
}

fn wiring_name(wiring: WiringStatus) -> &'static str {
    match wiring {
        WiringStatus::Executable => "executable",
        WiringStatus::DeclaredOnly => "declared-only",
    }
}

fn dimension_name(dimension: CompatibilityDimension) -> &'static str {
    match dimension {
        CompatibilityDimension::Parse => "parse",
        CompatibilityDimension::StaticSemantics => "static-semantics",
        CompatibilityDimension::PureRuntime => "pure-runtime",
        CompatibilityDimension::Effects => "effects",
        CompatibilityDimension::Concurrency => "concurrency",
        CompatibilityDimension::Presentation => "presentation",
        CompatibilityDimension::Platform => "platform",
        CompatibilityDimension::ResourceBehavior => "resource-behavior",
    }
}

fn status_name(status: ClaimStatus) -> &'static str {
    match status {
        ClaimStatus::Exact => "exact",
        ClaimStatus::Normalized => "normalized",
        ClaimStatus::PlatformDependent => "platform-dependent",
        ClaimStatus::DeliberateDivergence => "deliberate-divergence",
        ClaimStatus::Unverified => "unverified",
        ClaimStatus::NotApplicable => "not-applicable",
    }
}

fn profile_name(profile: ExecutionProfile) -> &'static str {
    match profile {
        ExecutionProfile::Upstream => "upstream",
        ExecutionProfile::Sandboxed => "sandboxed",
    }
}

fn platform_name(platform: ClaimPlatform) -> &'static str {
    match platform {
        ClaimPlatform::All => "all",
        ClaimPlatform::Linux => "linux",
        ClaimPlatform::MacOs => "macos",
        ClaimPlatform::Windows => "windows",
    }
}

fn json_array<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    let values = values
        .into_iter()
        .map(|value| format!("\"{}\"", json_escape(value)))
        .collect::<Vec<_>>();
    format!("[{}]", values.join(", "))
}

fn fixity_json(fixity: Option<Fixity>) -> String {
    match fixity {
        Some(Fixity::Left(precedence)) => {
            format!("{{ \"associativity\": \"left\", \"precedence\": {precedence} }}")
        }
        Some(Fixity::Right(precedence)) => {
            format!("{{ \"associativity\": \"right\", \"precedence\": {precedence} }}")
        }
        None => "null".into(),
    }
}

fn optional_json_string(value: Option<&str>) -> String {
    value.map_or_else(
        || "null".into(),
        |value| format!("\"{}\"", json_escape(value)),
    )
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                write!(escaped, "\\u{:04x}", u32::from(character)).expect("writing to String");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn comma(index: usize, length: usize) -> &'static str {
    if index + 1 == length { "" } else { "," }
}
