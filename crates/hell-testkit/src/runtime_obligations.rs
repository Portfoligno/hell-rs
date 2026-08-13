//! Registry-derived runtime evidence obligations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;

use hell_builtins::{
    AssuranceSensitivity, BuiltinSpec, ClaimPlatform, CompatibilityDimension, Demand, EffectKind,
    Visibility,
};

use crate::{CausalSignal, Digest, ObligationId};

pub(crate) fn collection_comparator_sensitive(builtin: &str) -> bool {
    matches!(
        builtin,
        "Map.fromList"
            | "Map.lookup"
            | "Map.insert"
            | "Map.delete"
            | "Map.insertWith"
            | "Map.adjust"
            | "Map.unionWith"
            | "Map.singleton"
            | "Set.fromList"
            | "Set.insert"
            | "Set.member"
            | "Set.delete"
            | "Set.union"
            | "Set.difference"
            | "Set.intersection"
            | "Set.singleton"
    )
}

/// Hashes the exact registry metadata and derived runtime obligation cells.
///
/// Consumers can bind review grouping and retained reports to this identity so
/// capability, sensitivity, demand, or obligation changes invalidate them.
#[must_use]
pub fn runtime_assurance_authority_sha256() -> Digest {
    let mut canonical = String::from("runtime-assurance-authority-v3\n");
    for spec in hell_builtins::registry()
        .iter()
        .filter(|spec| spec.visibility == Visibility::Public && spec.implementation.is_some())
    {
        writeln!(
            canonical,
            "builtin={}\tspecSha256={}",
            spec.id.0,
            runtime_assurance_spec_sha256(spec).hex()
        )
        .expect("writing to String cannot fail");
    }
    crate::sha256_bytes(canonical.as_bytes())
}

/// Hashes one builtin's exact generated assurance metadata and obligations.
#[must_use]
pub fn runtime_assurance_spec_sha256(spec: &BuiltinSpec) -> Digest {
    runtime_assurance_spec_sha256_with_projection(
        spec,
        hell_builtins::instance_head_projection(spec.name),
    )
}

fn runtime_assurance_spec_sha256_with_projection(
    spec: &BuiltinSpec,
    instance_head_projection: Option<&[hell_builtins::InstanceHeadProjection]>,
) -> Digest {
    let metadata = spec.assurance_metadata();
    let mut canonical = String::from("runtime-assurance-spec-v3\n");
    writeln!(
        canonical,
        "builtin={}\tname={}\timplementation={:?}\tdemand={:?}\ttypeClass={:?}\tinstanceHeadProjection={instance_head_projection:?}\tfamily={}\teffect={:?}\tcapabilities={:?}\tdeterminism={:?}\tsensitivities={:?}\tresourceRoles={:?}\thostFailureApplicable={}\tquirks={:?}\treachability={:?}",
        spec.id.0,
        spec.name,
        spec.implementation,
        spec.demand,
        spec.type_class,
        metadata.semantic_family,
        metadata.effect_kind,
        metadata.capabilities,
        metadata.determinism,
        metadata.sensitivities,
        metadata.resource_roles,
        metadata.host_failure_applicable,
        metadata.compatibility_quirks,
        metadata.source_reachability,
    )
    .expect("writing to String cannot fail");
    if let Some(class) = spec.type_class {
        for instance in hell_builtins::instances()
            .iter()
            .filter(|instance| instance.class == class)
        {
            writeln!(
                canonical,
                "instance={}\tresolution={}\tpremiseCount={}",
                instance.target,
                instance.resolution.as_str(),
                instance.resolution.premise_count(),
            )
            .expect("writing to String cannot fail");
        }
    }
    for cell in runtime_obligation_cells_for_spec(spec) {
        writeln!(
            canonical,
            "cell={}\tobligations={:?}\tcausal={:?}\tplatforms={:?}",
            cell.dimension.as_str(),
            cell.obligations,
            cell.causal_signal,
            cell.platforms,
        )
        .expect("writing to String cannot fail");
    }
    crate::sha256_bytes(canonical.as_bytes())
}

/// Verifies that a successful real-runtime trace entered every adapter named
/// by a case and retained each required demand boundary.
///
/// This is intentionally a producer-side validator. Cross-platform, effect,
/// task, presentation, and resource records are revalidated again when their
/// retained observation bundle is assembled.
///
/// # Errors
///
/// Returns an error for an unsupported trace schema, malformed typed event,
/// missing adapter entry, or missing target-scoped demand boundary.
pub fn validate_runtime_obligation_trace(
    trace: &str,
    case: &crate::DifferentialCase,
) -> Result<(), String> {
    let lines = trace.lines().collect::<Vec<_>>();
    if lines.first() != Some(&"{")
        || lines.get(1) != Some(&"  \"schemaVersion\": 9,")
        || lines.last() != Some(&"}")
        || lines.len() != 15
    {
        return Err("runtime obligation trace has an unsupported schema".into());
    }
    let entered = trace_builtin_ids(trace_array(trace, "enteredAdapters")?, "entered adapter")?;
    let boundaries = trace_boundaries(trace_array(trace, "forcedArguments")?)?;
    let adapter_events = trace_adapter_events(trace_array(trace, "obligationEvents")?)?;
    let task_ids = trace_task_ids(trace_array(trace, "taskEvents")?)?;
    validate_adapter_causality(&adapter_events, &task_ids)?;
    validate_nested_ord_comparator_evidence(&adapter_events)?;
    let Some(descriptor) = &case.claim_evidence else {
        return Err("runtime obligation case has no source-bound descriptor".into());
    };
    for target in &descriptor.semantic_targets {
        validate_runtime_obligation_target(target, &entered, &boundaries, &adapter_events)?;
    }
    validate_trace_callback_contracts(&adapter_events, &descriptor.callback_contracts)?;
    Ok(())
}

fn validate_nested_ord_comparator_evidence(events: &[TraceAdapterEvent]) -> Result<(), String> {
    let less = hell_builtins::lookup("Ord.lt")
        .expect("Ord.lt remains registry-backed")
        .id
        .0;
    let greater = hell_builtins::lookup("Ord.gt")
        .expect("Ord.gt remains registry-backed")
        .id
        .0;
    for parent in events.iter().filter(|event| {
        collection_comparator_sensitive(hell_builtins::registry()[usize::from(event.builtin)].name)
    }) {
        let parent_name = hell_builtins::registry()[usize::from(parent.builtin)].name;
        let direct_children = direct_ord_children(events, parent, less, greater);
        let mut selected_ordinals = BTreeSet::new();
        let mut comparators = Vec::new();
        let mut previous_ordinal = 0;
        for (ordinal, observation) in parent.comparators.iter().enumerate() {
            let expected = u64::try_from(ordinal)
                .map_err(|_| "direct comparator count exceeds u64".to_owned())?
                .saturating_add(1);
            let child_index = usize::try_from(observation.direct_child_ordinal.saturating_sub(1))
                .map_err(|_| "direct comparator ordinal exceeds usize".to_owned())?;
            let child = direct_children
                .get(child_index)
                .ok_or_else(|| "direct comparator child ordinal is missing".to_owned())?;
            if observation.invocation != expected
                || observation.direct_child_ordinal <= previous_ordinal
                || !selected_ordinals.insert(observation.direct_child_ordinal)
                || !matches!(child.builtin, builtin if builtin == less || builtin == greater)
                || observation.comparator != child.builtin
                || observation.outcome != child.outcome
                || !matches!(
                    observation.canonical_result.as_str(),
                    "{\"type\":\"Bool\",\"value\":true}" | "{\"type\":\"Bool\",\"value\":false}"
                )
            {
                return Err("direct Ord comparator observation disagrees with its child".into());
            }
            previous_ordinal = observation.direct_child_ordinal;
            comparators.push(*child);
        }
        let direct_ordinals = direct_children
            .iter()
            .enumerate()
            .map(|(index, _)| {
                u64::try_from(index)
                    .map(|index| index.saturating_add(1))
                    .map_err(|_| "direct comparator count exceeds u64".to_owned())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if selected_ordinals != direct_ordinals {
            return Err("direct Ord child is missing exact comparator authority".into());
        }
        let mut fallback_insert = !parent_name.ends_with(".fromList");
        for (index, comparator) in comparators.iter().enumerate() {
            if comparator.instance_target != parent.instance_target
                || comparator.instance_premises != parent.instance_premises
            {
                return Err(
                    "nested Ord comparator instance evidence disagrees with its collection parent"
                        .into(),
                );
            }
            if comparator.outcome != "value" {
                return Err("nested Ord comparator did not retain a value outcome".into());
            }
            if comparator.builtin == less {
                fallback_insert = true;
            }
            let invalid_order = fallback_insert
                && comparator.builtin == greater
                && (index == 0 || comparators[index - 1].builtin != less);
            if invalid_order {
                return Err("nested Ord.gt did not follow its Ord.lt probe".into());
            }
        }
    }
    Ok(())
}

fn direct_ord_children<'a>(
    events: &'a [TraceAdapterEvent],
    parent: &TraceAdapterEvent,
    less: u16,
    greater: u16,
) -> Vec<&'a TraceAdapterEvent> {
    let mut children = events
        .iter()
        .filter(|event| {
            event.owner_task == parent.owner_task
                && event.parent_sequence == Some(parent.sequence)
                && matches!(event.builtin, builtin if builtin == less || builtin == greater)
        })
        .collect::<Vec<_>>();
    children.sort_by_key(|event| event.sequence);
    children
}

fn validate_runtime_obligation_target(
    target: &crate::EvidenceTargetV2,
    entered: &[u16],
    boundaries: &[TraceBoundary<'_>],
    adapter_events: &[TraceAdapterEvent],
) -> Result<(), String> {
    if matches!(
        target.dimension,
        CompatibilityDimension::Parse | CompatibilityDimension::StaticSemantics
    ) {
        return Ok(());
    }
    let spec = hell_builtins::lookup(&target.builtin)
        .ok_or_else(|| format!("runtime trace target {:?} disappeared", target.builtin))?;
    if !entered.contains(&spec.id.0) {
        return Err(format!(
            "runtime trace never entered adapter {:?}",
            target.builtin
        ));
    }
    let matching_events = adapter_events
        .iter()
        .filter(|event| event.builtin == spec.id.0)
        .collect::<Vec<_>>();
    if matching_events.is_empty() {
        return Err(format!(
            "runtime trace has no typed adapter outcome for {:?}",
            target.builtin
        ));
    }
    if let Some(expected) = target.expected_instance_target.as_deref() {
        let permitted_nested = target
            .expected_instance_premises
            .iter()
            .map(|premise| premise.target.as_ref())
            .collect::<BTreeSet<_>>();
        let expected_events = matching_events
            .iter()
            .filter(|event| event.instance_target.as_deref() == Some(expected))
            .collect::<Vec<_>>();
        if expected_events.is_empty()
            || expected_events
                .iter()
                .any(|event| event.instance_premises != target.expected_instance_premises)
            || matching_events.iter().any(|event| {
                event.instance_target.as_deref().is_none_or(|instance| {
                    instance != expected && !permitted_nested.contains(instance)
                })
            })
        {
            return Err(format!(
                "runtime trace instance target disagrees for {:?}",
                target.builtin
            ));
        }
    }
    validate_trace_comparator_digest(target, &matching_events, adapter_events)?;
    if target.dimension == CompatibilityDimension::PureRuntime
        && spec.demand.contains(&hell_builtins::Demand::Lazy)
    {
        validate_lazy_adapter_entry_boundaries(spec, boundaries, matching_events.len())?;
    }
    validate_target_obligation_boundaries(target, spec, boundaries, &matching_events)?;
    validate_expected_lazy_argument_exit(target, spec, boundaries)
}

fn validate_trace_comparator_digest(
    target: &crate::EvidenceTargetV2,
    matching_events: &[&TraceAdapterEvent],
    all_events: &[TraceAdapterEvent],
) -> Result<(), String> {
    let Some(expected) = target.expected_comparator_trace_sha256 else {
        return Ok(());
    };
    let instance_target = target
        .expected_instance_target
        .as_deref()
        .ok_or_else(|| "comparator trace has no retained instance root".to_owned())?;
    let mut parents = matching_events.to_vec();
    parents.sort_by_key(|event| (event.owner_task, event.sequence));
    let mut records = Vec::new();
    for (parent_index, parent) in parents.iter().enumerate() {
        let parent_invocation = u64::try_from(parent_index)
            .map_err(|_| "comparator parent count exceeds u64".to_owned())?
            .saturating_add(1);
        let children = direct_ord_children(
            all_events,
            parent,
            hell_builtins::lookup("Ord.lt")
                .expect("Ord.lt remains registry-backed")
                .id
                .0,
            hell_builtins::lookup("Ord.gt")
                .expect("Ord.gt remains registry-backed")
                .id
                .0,
        );
        let mut selected_ordinals = BTreeSet::new();
        for comparison in &parent.comparators {
            let child_index = usize::try_from(comparison.direct_child_ordinal.saturating_sub(1))
                .map_err(|_| "comparator child ordinal exceeds usize".to_owned())?;
            let child = children
                .get(child_index)
                .ok_or_else(|| "comparator child ordinal is missing".to_owned())?;
            if comparison.comparator != child.builtin {
                return Err("comparator record builtin disagrees with direct child".into());
            }
            if !selected_ordinals.insert(comparison.direct_child_ordinal) {
                return Err("comparator child ordinal is duplicated".into());
            }
            let result = match comparison.canonical_result.as_str() {
                "{\"type\":\"Bool\",\"value\":true}" => true,
                "{\"type\":\"Bool\",\"value\":false}" => false,
                _ => return Err("comparator result is not canonical Bool".into()),
            };
            records.push(crate::ComparatorTraceContract {
                parent_invocation,
                direct_child_ordinal: comparison.direct_child_ordinal,
                comparator_ordinal: comparison.invocation,
                comparator: Arc::from(hell_builtins::registry()[usize::from(child.builtin)].name),
                canonical_left: Arc::from(comparison.canonical_left.as_str()),
                canonical_right: Arc::from(comparison.canonical_right.as_str()),
                result,
                outcome: Arc::from(comparison.outcome.as_str()),
            });
        }
    }
    let parent_count = u64::try_from(parents.len())
        .map_err(|_| "comparator parent count exceeds u64".to_owned())?;
    let actual = crate::comparator_trace_sha256(
        &target.builtin,
        parent_count,
        instance_target,
        &target.expected_instance_premises,
        &records,
    );
    if actual != expected {
        return Err(format!(
            "runtime comparator trace disagrees for {:?}",
            target.builtin
        ));
    }
    Ok(())
}

fn validate_target_obligation_boundaries(
    target: &crate::EvidenceTargetV2,
    spec: &hell_builtins::BuiltinSpec,
    boundaries: &[TraceBoundary<'_>],
    matching_events: &[&TraceAdapterEvent],
) -> Result<(), String> {
    for obligation in &target.obligations {
        match obligation.0.as_ref() {
            "whnf-boundary" => validate_exact_argument_states(
                spec,
                boundaries,
                hell_builtins::Demand::Whnf,
                "whnf-force-complete",
            )?,
            "deep-boundary" => {
                return Err(format!(
                    "runtime deep-demand proof is fail-closed for {:?}",
                    target.builtin
                ));
            }
            "io-execution-boundary" => validate_exact_argument_states(
                spec,
                boundaries,
                hell_builtins::Demand::OnIoExecution,
                "io-execution-complete",
            )?,
            "conditional-selected" | "conditional-unselected" => {
                validate_conditional_branch_partition(spec, boundaries)?;
            }
            _ => {}
        }
        if obligation.0.as_ref() == "bounded-materialization"
            && matching_events
                .iter()
                .any(|event| event.materialized_after < event.materialized_before)
        {
            return Err(format!(
                "runtime trace materialization moved backwards for {:?}",
                target.builtin
            ));
        }
    }
    Ok(())
}

fn validate_expected_lazy_argument_exit(
    target: &crate::EvidenceTargetV2,
    spec: &hell_builtins::BuiltinSpec,
    boundaries: &[TraceBoundary<'_>],
) -> Result<(), String> {
    let Some(expected) = target.expected_lazy_argument_exit_sha256 else {
        return Ok(());
    };
    let states = boundaries
        .iter()
        .filter(|boundary| boundary.builtin == spec.id.0 && boundary.class == "lazy-adapter-exit")
        .map(|boundary| (boundary.argument, boundary.outcome))
        .collect::<Vec<_>>();
    if states.is_empty() || crate::lazy_argument_exit_sha256(states) != expected {
        return Err(format!(
            "runtime trace lazy argument exit states disagree for {:?}",
            target.builtin
        ));
    }
    Ok(())
}

fn validate_lazy_adapter_entry_boundaries(
    spec: &hell_builtins::BuiltinSpec,
    boundaries: &[TraceBoundary<'_>],
    invocation_count: usize,
) -> Result<(), String> {
    let expected = spec
        .demand
        .iter()
        .enumerate()
        .filter(|(_, demand)| **demand == hell_builtins::Demand::Lazy)
        .map(|(index, _)| u16::try_from(index).expect("builtin arity fits u16"))
        .collect::<Vec<_>>();
    let observed = boundaries
        .iter()
        .filter(|boundary| boundary.builtin == spec.id.0 && boundary.class == "lazy-adapter-entry")
        .collect::<Vec<_>>();
    if expected.is_empty()
        || invocation_count == 0
        || observed.len() != expected.len().saturating_mul(invocation_count)
        || expected.iter().any(|argument| {
            observed
                .iter()
                .filter(|boundary| boundary.argument == *argument)
                .count()
                != invocation_count
        })
        || observed.iter().any(|boundary| {
            !expected.contains(&boundary.argument) || boundary.outcome != "not-forced"
        })
    {
        return Err(format!(
            "runtime trace lacks exact not-forced lazy adapter-entry states for {:?}",
            spec.name
        ));
    }
    Ok(())
}

fn validate_exact_argument_states(
    spec: &hell_builtins::BuiltinSpec,
    boundaries: &[TraceBoundary<'_>],
    demand: hell_builtins::Demand,
    class: &str,
) -> Result<(), String> {
    let expected = spec
        .demand
        .iter()
        .enumerate()
        .filter(|(_, observed)| **observed == demand)
        .map(|(index, _)| u16::try_from(index).expect("builtin arity fits u16"))
        .collect::<Vec<_>>();
    let observed = boundaries
        .iter()
        .filter(|boundary| boundary.builtin == spec.id.0 && boundary.class == class)
        .collect::<Vec<_>>();
    if expected.is_empty()
        || observed.len() != expected.len()
        || expected.iter().any(|argument| {
            !observed
                .iter()
                .any(|boundary| boundary.argument == *argument)
        })
        || observed.iter().any(|boundary| {
            !expected.contains(&boundary.argument)
                || match demand {
                    hell_builtins::Demand::OnIoExecution => {
                        !matches!(boundary.outcome, "value" | "error")
                    }
                    _ => boundary.outcome != "value",
                }
        })
    {
        return Err(format!(
            "runtime trace lacks exact completed {class} states for {:?}",
            spec.name
        ));
    }
    Ok(())
}

fn validate_conditional_branch_partition(
    spec: &hell_builtins::BuiltinSpec,
    boundaries: &[TraceBoundary<'_>],
) -> Result<(), String> {
    let expected = spec
        .demand
        .iter()
        .enumerate()
        .filter(|(_, demand)| **demand == hell_builtins::Demand::Lazy)
        .map(|(index, _)| u16::try_from(index).expect("builtin arity fits u16"))
        .collect::<Vec<_>>();
    let observed = boundaries
        .iter()
        .filter(|boundary| boundary.builtin == spec.id.0 && boundary.class == "conditional-branch")
        .collect::<Vec<_>>();
    let values = observed
        .iter()
        .filter(|boundary| boundary.outcome == "value")
        .count();
    let unforced = observed
        .iter()
        .filter(|boundary| boundary.outcome == "not-forced")
        .count();
    if expected.len() != 2
        || observed.len() != 2
        || values != 1
        || unforced != 1
        || expected.iter().any(|argument| {
            !observed
                .iter()
                .any(|boundary| boundary.argument == *argument)
        })
        || observed
            .iter()
            .any(|boundary| !expected.contains(&boundary.argument))
    {
        return Err(format!(
            "runtime trace lacks an exact selected/unselected conditional partition for {:?}",
            spec.name
        ));
    }
    Ok(())
}

fn validate_trace_callback_contracts(
    events: &[TraceAdapterEvent],
    contracts: &[crate::CallbackContract],
) -> Result<(), String> {
    for contract in contracts {
        let builtin = hell_builtins::lookup(&contract.builtin)
            .ok_or_else(|| "runtime callback contract target disappeared".to_owned())?
            .id
            .0;
        let mut matching_events = events
            .iter()
            .filter(|event| event.builtin == builtin)
            .collect::<Vec<_>>();
        matching_events.sort_by_key(|event| (event.owner_task, event.sequence));
        let observed = matching_events
            .into_iter()
            .flat_map(|event| &event.callbacks)
            .collect::<Vec<_>>();
        if observed.len() != contract.invocations.len() {
            return Err(format!(
                "runtime callback cardinality disagrees for {:?}",
                contract.builtin
            ));
        }
        for (actual, expected) in observed.into_iter().zip(&contract.invocations) {
            let arguments = actual
                .canonical_arguments
                .iter()
                .map(|argument| crate::sha256_bytes(argument.as_bytes()))
                .collect::<Vec<_>>();
            if actual.callback_argument != expected.callback_argument
                || actual.branch.as_str() != expected.branch.as_ref()
                || actual.outcome.as_str() != expected.outcome.as_ref()
                || arguments != expected.canonical_argument_sha256
                || crate::sha256_bytes(actual.canonical_result.as_bytes())
                    != expected.canonical_result_sha256
            {
                return Err(format!(
                    "runtime callback contract disagrees for {:?}",
                    contract.builtin
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn callback_identity_allowed(
    builtin: &str,
    callback_argument: u16,
    branch: &str,
) -> bool {
    let functor = callback_argument == 0
        && matches!(builtin, "Functor.fmap" | "<$>")
        && matches!(
            branch,
            "element" | "node" | "io-result" | "parser-result" | "just" | "right" | "second"
        );
    let pooled_map = callback_argument == 0
        && branch == "element"
        && matches!(
            builtin,
            "Async.pooledMapConcurrently" | "Async.pooledMapConcurrently_"
        );
    let pooled_for = callback_argument == 1
        && branch == "element"
        && matches!(
            builtin,
            "Async.pooledForConcurrently" | "Async.pooledForConcurrently_"
        );
    if functor || pooled_map || pooled_for {
        return true;
    }
    matches!(
        (builtin, callback_argument, branch),
        ("Function.fix", 0, "recursive")
            | ("$", 0, "function")
            | (".", 1, "inner")
            | (".", 0, "outer")
            | (
                "List.concatMap"
                    | "List.iterate'"
                    | "List.map"
                    | "List.zipWith"
                    | "Maybe.mapMaybe"
                    | "IO.mapM_"
                    | "Monad.mapM"
                    | "Monad.mapM_",
                0,
                "element",
            )
            | (
                "List.all"
                    | "List.any"
                    | "List.break"
                    | "List.dropWhile"
                    | "List.dropWhileEnd"
                    | "List.filter"
                    | "List.find"
                    | "List.findIndex"
                    | "List.findIndices"
                    | "List.partition"
                    | "List.span"
                    | "List.takeWhile"
                    | "Text.all"
                    | "Text.any"
                    | "Text.filter"
                    | "Map.all"
                    | "Map.any"
                    | "Map.filter"
                    | "Map.filterWithKey",
                0,
                "predicate",
            )
            | ("Map.adjust" | "Map.map", 0, "value")
            | ("Map.insertWith" | "Map.unionWith", 0, "collision")
            | ("List.foldl'" | "List.foldr", 0, "fold")
            | ("List.scanl'" | "List.scanr", 0, "scan")
            | ("List.mapAccumL" | "List.mapAccumR", 0, "accumulate")
            | ("List.deleteBy" | "List.groupBy", 0, "relation")
            | ("List.sortOn", 0, "key")
            | ("List.unfoldr" | "Tree.unfoldTree", 0, "seed")
            | ("Tree.map" | "Tree.foldTree", 0, "node")
            | ("Record.modify", 0, "field")
            | ("Monad.bind", 1, "continuation")
            | ("Monad.forM" | "Monad.forM_" | "IO.forM_", 1, "element")
            | ("<*>", 0, "application")
            | ("<**>", 1, "application")
            | ("Maybe.maybe", 0, "nothing")
            | ("Maybe.maybe", 1, "just")
            | ("Either.either", 0, "left")
            | ("Either.either", 1, "right")
            | ("Exit.exitCode", 0, "success")
            | ("Exit.exitCode", 1, "failure")
            | ("These.these", 0, "this")
            | ("These.these", 1, "that")
            | ("These.these", 2, "these")
            | ("Json.value", 0, "null")
            | ("Json.value", 1, "bool")
            | ("Json.value", 2, "string")
            | ("Json.value", 3, "number")
            | ("Json.value", 4, "array")
            | ("Json.value", 5, "object")
    )
}

fn validate_adapter_causality(
    events: &[TraceAdapterEvent],
    task_ids: &BTreeSet<u64>,
) -> Result<(), String> {
    let identities = events
        .iter()
        .map(|event| ((event.owner_task, event.sequence), event))
        .collect::<BTreeMap<_, _>>();
    if identities.len() != events.len() {
        return Err("runtime adapter causal identity is duplicated".into());
    }
    let mut child_counts = BTreeMap::<(Option<u64>, u64), u64>::new();
    let mut owner_sequences = BTreeMap::<Option<u64>, BTreeSet<u64>>::new();
    for event in events {
        if event
            .owner_task
            .is_some_and(|owner| !task_ids.contains(&owner))
        {
            return Err("runtime adapter owner is not a retained task".into());
        }
        owner_sequences
            .entry(event.owner_task)
            .or_default()
            .insert(event.sequence);
        if let Some(parent) = event.parent_sequence {
            let parent_identity = (event.owner_task, parent);
            if !identities.contains_key(&parent_identity) {
                return Err("runtime adapter causal parent is missing".into());
            }
            child_counts
                .entry(parent_identity)
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
        }
    }
    for sequences in owner_sequences.values() {
        let expected = 1..=u64::try_from(sequences.len())
            .map_err(|_| "runtime adapter sequence count exceeds u64".to_owned())?;
        if !sequences.iter().copied().eq(expected) {
            return Err("runtime adapter sequences are not contiguous".into());
        }
    }
    for event in events {
        let observed = child_counts
            .get(&(event.owner_task, event.sequence))
            .copied()
            .unwrap_or(0);
        if event.nested_adapters != observed {
            return Err("runtime adapter nested count does not match causal children".into());
        }
    }
    Ok(())
}

fn trace_task_ids(encoded: &str) -> Result<BTreeSet<u64>, String> {
    trace_objects(encoded)
        .map(|entry| {
            let (_, entry) = entry
                .strip_prefix("\"eventId\": ")
                .and_then(|entry| entry.split_once(", \"builtinId\": "))
                .ok_or_else(|| "runtime task event is malformed".to_owned())?;
            let (_, entry) = entry
                .split_once(", \"taskId\": ")
                .ok_or_else(|| "runtime task event is malformed".to_owned())?;
            let (task, event) = entry
                .split_once(", \"event\": \"")
                .and_then(|(task, event)| event.strip_suffix('"').map(|event| (task, event)))
                .ok_or_else(|| "runtime task event is malformed".to_owned())?;
            if !matches!(event, "started" | "completed" | "failed" | "cancelled") {
                return Err("runtime task lifecycle is unknown".into());
            }
            parse_trace_id(task, "runtime task identity")
        })
        .collect()
}

struct TraceBoundary<'a> {
    builtin: u16,
    argument: u16,
    class: &'a str,
    outcome: &'a str,
}

struct TraceAdapterEvent {
    builtin: u16,
    instance_target: Option<String>,
    instance_premises: Vec<crate::InstancePremiseEvidence>,
    outcome: String,
    owner_task: Option<u64>,
    sequence: u64,
    parent_sequence: Option<u64>,
    nested_adapters: u64,
    materialized_before: u64,
    materialized_after: u64,
    callbacks: Vec<TraceCallbackInvocation>,
    comparators: Vec<TraceComparatorInvocation>,
}

struct TraceCallbackInvocation {
    callback_argument: u16,
    branch: String,
    canonical_arguments: Vec<String>,
    outcome: String,
    canonical_result: String,
}

struct TraceComparatorInvocation {
    invocation: u64,
    direct_child_ordinal: u64,
    comparator: u16,
    canonical_left: String,
    canonical_right: String,
    outcome: String,
    canonical_result: String,
}

fn trace_array<'a>(trace: &'a str, field: &str) -> Result<&'a str, String> {
    let prefix = format!("  \"{field}\": [");
    let mut values = trace.lines().filter_map(|line| line.strip_prefix(&prefix));
    let encoded = values
        .next()
        .and_then(|value| value.strip_suffix("],"))
        .ok_or_else(|| format!("runtime trace field {field} is missing or malformed"))?;
    if values.next().is_some() {
        return Err(format!("runtime trace field {field} is repeated"));
    }
    Ok(encoded)
}

fn trace_builtin_ids(encoded: &str, label: &str) -> Result<Vec<u16>, String> {
    trace_objects(encoded)
        .map(|entry| {
            let (_event, builtin) = entry
                .strip_prefix("\"eventId\": ")
                .and_then(|entry| entry.split_once(", \"builtinId\": "))
                .ok_or_else(|| format!("{label} is malformed"))?;
            builtin
                .parse::<u16>()
                .ok()
                .filter(|id| usize::from(*id) < hell_builtins::registry().len())
                .ok_or_else(|| format!("{label} builtin is unknown"))
        })
        .collect()
}

fn trace_boundaries(encoded: &str) -> Result<Vec<TraceBoundary<'_>>, String> {
    trace_objects(encoded)
        .map(|entry| {
            let (_, entry) = entry
                .strip_prefix("\"eventId\": ")
                .and_then(|entry| entry.split_once(", \"builtinId\": "))
                .ok_or_else(|| "runtime boundary is malformed".to_owned())?;
            let (builtin, entry) = entry
                .split_once(", \"argument\": ")
                .ok_or_else(|| "runtime boundary is malformed".to_owned())?;
            let (argument, entry) = entry
                .split_once(", \"boundaryClass\": \"")
                .ok_or_else(|| "runtime boundary is malformed".to_owned())?;
            let (class, outcome) = entry
                .split_once("\", \"outcome\": \"")
                .and_then(|(class, outcome)| outcome.strip_suffix('"').map(|value| (class, value)))
                .ok_or_else(|| "runtime boundary is malformed".to_owned())?;
            if !matches!(
                class,
                "conditional-branch"
                    | "conditional-selection"
                    | "conditional-force-complete"
                    | "deep-demand"
                    | "deep-force-complete"
                    | "io-execution"
                    | "io-execution-complete"
                    | "lazy-adapter-entry"
                    | "lazy-adapter-exit"
                    | "lazy-demand"
                    | "whnf-demand"
                    | "whnf-force-complete"
            ) || !matches!(
                outcome,
                "value" | "error" | "not-forced" | "in-progress" | "cycle" | "poisoned"
            ) {
                return Err("runtime boundary class or outcome is unknown".into());
            }
            let builtin = builtin
                .parse::<u16>()
                .ok()
                .filter(|id| usize::from(*id) < hell_builtins::registry().len())
                .ok_or_else(|| "runtime boundary builtin is unknown".to_owned())?;
            let argument = argument
                .parse::<u16>()
                .ok()
                .filter(|argument| {
                    usize::from(*argument)
                        < usize::from(hell_builtins::registry()[usize::from(builtin)].arity)
                })
                .ok_or_else(|| "runtime boundary argument is unknown".to_owned())?;
            Ok(TraceBoundary {
                builtin,
                argument,
                class,
                outcome,
            })
        })
        .collect()
}

fn trace_adapter_events(encoded: &str) -> Result<Vec<TraceAdapterEvent>, String> {
    trace_objects(encoded)
        .map(|entry| {
            let (_, entry) = entry
                .strip_prefix("\"eventId\": ")
                .and_then(|entry| entry.split_once(", \"builtinId\": "))
                .ok_or_else(|| "runtime adapter outcome is malformed".to_owned())?;
            let (builtin, entry) = entry
                .split_once(", \"ownerTaskId\": ")
                .ok_or_else(|| "runtime adapter outcome is malformed".to_owned())?;
            let (owner, entry) = entry
                .split_once(", \"sequence\": ")
                .ok_or_else(|| "runtime adapter owner is malformed".to_owned())?;
            let (sequence, entry) = entry
                .split_once(", \"parentSequence\": ")
                .ok_or_else(|| "runtime adapter sequence is malformed".to_owned())?;
            let (parent, entry) = entry
                .split_once(", \"instanceTarget\": ")
                .ok_or_else(|| "runtime adapter parent is malformed".to_owned())?;
            let (instance_target, entry) = entry
                .split_once(", \"instancePremises\": [")
                .ok_or_else(|| "runtime adapter instance is malformed".to_owned())?;
            let (instance_premises, entry) = entry
                .split_once("], \"outcome\": \"")
                .ok_or_else(|| "runtime adapter premises are malformed".to_owned())?;
            let (outcome, entry) = entry
                .split_once("\", \"nestedAdapters\": ")
                .ok_or_else(|| "runtime adapter outcome is malformed".to_owned())?;
            let (nested, entry) = entry
                .split_once(", \"materializedBefore\": ")
                .ok_or_else(|| "runtime adapter outcome is malformed".to_owned())?;
            let (before, entry) = entry
                .split_once(", \"materializedAfter\": ")
                .ok_or_else(|| "runtime adapter outcome is malformed".to_owned())?;
            let (after, invocations) = entry
                .split_once(", \"callbackInvocations\": [")
                .ok_or_else(|| "runtime callback trace is malformed".to_owned())?;
            let (callbacks, comparators) = invocations
                .split_once("], \"comparatorInvocations\": [")
                .and_then(|(callbacks, comparators)| {
                    comparators
                        .strip_suffix(']')
                        .map(|comparators| (callbacks, comparators))
                })
                .ok_or_else(|| "runtime comparator trace is malformed".to_owned())?;
            if !matches!(outcome, "alias" | "error" | "io-action" | "value") {
                return Err("runtime adapter outcome is unknown".into());
            }
            let builtin = builtin
                .parse::<u16>()
                .ok()
                .filter(|id| usize::from(*id) < hell_builtins::registry().len())
                .ok_or_else(|| "runtime adapter outcome builtin is unknown".to_owned())?;
            let instance_target = parse_trace_instance_target(instance_target, builtin)?;
            let instance_premises = crate::parse_instance_premises(
                instance_premises,
                hell_builtins::BuiltinId(builtin),
                instance_target.as_deref(),
            )
            .map_err(|error| error.to_string())?;
            let nested_adapters = nested
                .parse::<u64>()
                .map_err(|_| "runtime nested adapter count is malformed".to_owned())?;
            let materialized_before = before
                .parse::<u64>()
                .map_err(|_| "runtime materialization start is malformed".to_owned())?;
            let materialized_after = after
                .parse::<u64>()
                .map_err(|_| "runtime materialization end is malformed".to_owned())?;
            if materialized_after < materialized_before {
                return Err("runtime materialization counter moved backwards".into());
            }
            let owner_task = parse_optional_trace_id(owner, "runtime adapter owner")?;
            let sequence = parse_trace_id(sequence, "runtime adapter sequence")?;
            let parent_sequence = parse_optional_trace_id(parent, "runtime adapter parent")?;
            if parent_sequence.is_some_and(|parent| parent >= sequence) {
                return Err("runtime adapter parent does not precede its child".into());
            }
            let callbacks = parse_trace_callbacks(callbacks)?;
            let comparators = parse_trace_comparators(comparators)?;
            Ok(TraceAdapterEvent {
                builtin,
                instance_target,
                instance_premises,
                outcome: outcome.to_owned(),
                owner_task,
                sequence,
                parent_sequence,
                nested_adapters,
                materialized_before,
                materialized_after,
                callbacks,
                comparators,
            })
        })
        .collect()
}

fn parse_trace_comparators(encoded: &str) -> Result<Vec<TraceComparatorInvocation>, String> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    encoded
        .split("},{")
        .enumerate()
        .map(|(index, entry)| {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            let entry = entry.strip_suffix('}').unwrap_or(entry);
            let entry = entry
                .strip_prefix("\"invocation\":")
                .ok_or_else(|| "runtime comparator invocation is malformed".to_owned())?;
            let (invocation, entry) = entry
                .split_once(",\"directChildOrdinal\":")
                .ok_or_else(|| "runtime comparator child ordinal is malformed".to_owned())?;
            let (direct_child_ordinal, entry) = entry
                .split_once(",\"comparatorBuiltinId\":")
                .ok_or_else(|| "runtime comparator builtin is malformed".to_owned())?;
            let (comparator, entry) = entry
                .split_once(",\"canonicalLeftHex\":\"")
                .ok_or_else(|| "runtime comparator left value is malformed".to_owned())?;
            let (left, entry) = entry
                .split_once("\",\"canonicalRightHex\":\"")
                .ok_or_else(|| "runtime comparator right value is malformed".to_owned())?;
            let (right, entry) = entry
                .split_once("\",\"outcome\":\"")
                .ok_or_else(|| "runtime comparator outcome is malformed".to_owned())?;
            let (outcome, result) = entry
                .split_once("\",\"canonicalResultHex\":\"")
                .and_then(|(outcome, result)| {
                    result.strip_suffix('"').map(|result| (outcome, result))
                })
                .ok_or_else(|| "runtime comparator result is malformed".to_owned())?;
            let invocation = parse_trace_id(invocation, "runtime comparator invocation")?;
            let direct_child_ordinal =
                parse_trace_id(direct_child_ordinal, "runtime comparator child ordinal")?;
            let expected = u64::try_from(index)
                .map_err(|_| "runtime comparator count exceeds u64".to_owned())?
                .saturating_add(1);
            if invocation != expected || outcome != "value" {
                return Err("runtime comparator order or outcome is invalid".into());
            }
            let comparator = comparator
                .parse::<u16>()
                .ok()
                .filter(|id| usize::from(*id) < hell_builtins::registry().len())
                .ok_or_else(|| "runtime comparator builtin is unknown".to_owned())?;
            let canonical_left = crate::decode_callback_result(left)?;
            let canonical_right = crate::decode_callback_result(right)?;
            let canonical_result = crate::decode_callback_result(result)?;
            crate::validate_canonical_typed_value(&canonical_left)
                .and_then(|()| crate::validate_canonical_typed_value(&canonical_right))
                .and_then(|()| crate::validate_canonical_typed_value(&canonical_result))
                .map_err(|error| error.to_string())?;
            Ok(TraceComparatorInvocation {
                invocation,
                direct_child_ordinal,
                comparator,
                canonical_left,
                canonical_right,
                outcome: outcome.to_owned(),
                canonical_result,
            })
        })
        .collect()
}

fn parse_trace_callbacks(encoded: &str) -> Result<Vec<TraceCallbackInvocation>, String> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    encoded
        .split("},{")
        .enumerate()
        .map(|(index, entry)| {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            let entry = entry.strip_suffix('}').unwrap_or(entry);
            let entry = entry
                .strip_prefix("\"invocation\":")
                .ok_or_else(|| "runtime callback invocation is malformed".to_owned())?;
            let (invocation, entry) = entry
                .split_once(",\"callbackArgument\":")
                .ok_or_else(|| "runtime callback argument is malformed".to_owned())?;
            let (callback_argument, entry) = entry
                .split_once(",\"branch\":\"")
                .ok_or_else(|| "runtime callback argument is malformed".to_owned())?;
            let (branch, entry) = entry
                .split_once("\",\"canonicalArgumentHex\":[")
                .ok_or_else(|| "runtime callback branch is malformed".to_owned())?;
            let (arguments, entry) = entry
                .split_once("],\"outcome\":\"")
                .ok_or_else(|| "runtime callback arguments are malformed".to_owned())?;
            let (outcome, result) = entry
                .split_once("\",\"canonicalResultHex\":\"")
                .and_then(|(outcome, result)| {
                    result.strip_suffix('"').map(|result| (outcome, result))
                })
                .ok_or_else(|| "runtime callback result is malformed".to_owned())?;
            let invocation = parse_trace_id(invocation, "runtime callback invocation")?;
            let expected = u64::try_from(index)
                .map_err(|_| "runtime callback count exceeds u64".to_owned())?
                .saturating_add(1);
            if invocation != expected {
                return Err("runtime callback invocations are not contiguous".into());
            }
            let callback_argument = callback_argument
                .parse::<u16>()
                .map_err(|_| "runtime callback argument is malformed".to_owned())?;
            if branch.is_empty()
                || !branch
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                || !matches!(outcome, "value" | "error")
            {
                return Err("runtime callback branch or outcome is unknown".into());
            }
            let canonical_result = crate::decode_callback_result(result)?;
            crate::validate_canonical_typed_value(&canonical_result)
                .map_err(|error| format!("runtime callback typed result is invalid: {error}"))?;
            let canonical_arguments = if arguments.is_empty() {
                Vec::new()
            } else {
                arguments
                    .split(',')
                    .map(|argument| {
                        let encoded = argument
                            .strip_prefix('"')
                            .and_then(|argument| argument.strip_suffix('"'))
                            .ok_or_else(|| {
                                "runtime callback argument hex is malformed".to_owned()
                            })?;
                        let value = crate::decode_callback_result(encoded)?;
                        crate::validate_canonical_typed_value(&value).map_err(|error| {
                            format!("runtime callback typed argument is invalid: {error}")
                        })?;
                        Ok(value)
                    })
                    .collect::<Result<Vec<_>, String>>()?
            };
            Ok(TraceCallbackInvocation {
                callback_argument,
                branch: branch.to_owned(),
                canonical_arguments,
                outcome: outcome.to_owned(),
                canonical_result,
            })
        })
        .collect()
}

fn parse_trace_id(value: &str, label: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("{label} is malformed"))
}

fn parse_optional_trace_id(value: &str, label: &str) -> Result<Option<u64>, String> {
    if value == "null" {
        Ok(None)
    } else {
        parse_trace_id(value, label).map(Some)
    }
}

fn parse_trace_instance_target(encoded: &str, builtin: u16) -> Result<Option<String>, String> {
    let spec = &hell_builtins::registry()[usize::from(builtin)];
    let Some(class) = spec.type_class else {
        return (encoded == "null")
            .then_some(None)
            .ok_or_else(|| "unconstrained adapter retained an instance".to_owned());
    };
    let target = encoded
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| {
            !value.is_empty() && !value.bytes().any(|byte| matches!(byte, b'"' | b'\\'))
        })
        .ok_or_else(|| "constrained adapter instance is malformed".to_owned())?;
    if hell_builtins::instance(class, target).is_none() {
        return Err("constrained adapter instance is not registry-backed".to_owned());
    }
    Ok(Some(target.to_owned()))
}

fn trace_objects(encoded: &str) -> impl Iterator<Item = &str> {
    encoded
        .split("}, {")
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            entry.strip_suffix('}').unwrap_or(entry)
        })
}

/// One applicable public runtime cell and its exact causal requirements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeObligationCell {
    pub builtin: Arc<str>,
    pub dimension: CompatibilityDimension,
    pub obligations: Vec<ObligationId>,
    pub causal_signal: CausalSignal,
    pub platforms: Vec<ClaimPlatform>,
}

/// One mandatory domain boundary for a public builtin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBoundaryRequirement {
    pub builtin: Arc<str>,
    pub class: Arc<str>,
}

/// A mandatory cross-family interaction and the exact participating builtins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeInteractionRequirement {
    pub id: Arc<str>,
    pub builtins: Vec<Arc<str>>,
}

/// One exact target proven by a platform shard's retained causal trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimePlatformTarget {
    pub builtin: Arc<str>,
    pub dimension: CompatibilityDimension,
    pub obligation_trace_sha256: Digest,
}

/// One independently retained runtime shard used for three-platform closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimePlatformShard {
    pub platform: ClaimPlatform,
    pub case_id: Arc<str>,
    pub source_sha256: Digest,
    pub candidate_source_sha256: Digest,
    pub assurance_epoch_sha256: Digest,
    pub descriptor_sha256: Digest,
    pub candidate_executable_sha256: Digest,
    pub process_helper_sha256: Option<Digest>,
    pub bundle_sha256: Digest,
    pub targets: Vec<RuntimePlatformTarget>,
}

/// Requires exactly one Linux, macOS, and Windows shard with identical source,
/// candidate, epoch, descriptor, and target sets. Every target remains bound
/// to its platform-local causal trace digest.
///
/// # Errors
///
/// Returns an error for a missing/duplicate platform, an aggregate `All`
/// label, cross-shard identity drift, duplicate targets, or target-set drift.
pub fn validate_runtime_platform_set(shards: &[RuntimePlatformShard]) -> Result<(), String> {
    if shards.len() != 3 {
        return Err("runtime platform set must contain exactly three shards".into());
    }
    let mut by_platform: [Option<&RuntimePlatformShard>; 3] = [None, None, None];
    for shard in shards {
        let index = match shard.platform {
            ClaimPlatform::Linux => 0,
            ClaimPlatform::MacOs => 1,
            ClaimPlatform::Windows => 2,
            ClaimPlatform::All => {
                return Err("runtime platform shard cannot use aggregate platform All".into());
            }
        };
        if by_platform[index].replace(shard).is_some() {
            return Err("runtime platform set repeats a platform".into());
        }
        let duplicate = shard.targets.iter().enumerate().any(|(index, target)| {
            shard.targets[..index]
                .iter()
                .any(|prior| prior.builtin == target.builtin && prior.dimension == target.dimension)
        });
        if shard.targets.is_empty() || duplicate {
            return Err("runtime platform shard has empty or duplicate targets".into());
        }
        if shard.case_id.is_empty()
            || shard.source_sha256 == Digest::default()
            || shard.candidate_source_sha256 == Digest::default()
            || shard.assurance_epoch_sha256 == Digest::default()
            || shard.descriptor_sha256 == Digest::default()
            || shard.candidate_executable_sha256 == Digest::default()
            || shard
                .process_helper_sha256
                .is_some_and(|digest| digest == Digest::default())
            || shard.bundle_sha256 == Digest::default()
            || shard
                .targets
                .iter()
                .any(|target| target.obligation_trace_sha256 == Digest::default())
        {
            return Err("runtime platform shard has an empty retained identity or digest".into());
        }
    }
    if by_platform.iter().any(Option::is_none) {
        return Err("runtime platform set is missing a required platform".into());
    }
    let baseline =
        by_platform[0].ok_or_else(|| "runtime platform set is missing Linux".to_owned())?;
    for shard in by_platform.into_iter().flatten() {
        if shard.case_id != baseline.case_id
            || shard.source_sha256 != baseline.source_sha256
            || shard.candidate_source_sha256 != baseline.candidate_source_sha256
            || shard.assurance_epoch_sha256 != baseline.assurance_epoch_sha256
            || shard.descriptor_sha256 != baseline.descriptor_sha256
            || shard.process_helper_sha256.is_some() != baseline.process_helper_sha256.is_some()
        {
            return Err("runtime platform shard identities disagree".into());
        }
        if shard.targets.len() != baseline.targets.len()
            || baseline.targets.iter().any(|expected| {
                !shard.targets.iter().any(|observed| {
                    observed.builtin == expected.builtin && observed.dimension == expected.dimension
                })
            })
        {
            return Err("runtime platform shard target sets disagree".into());
        }
    }
    if shards.iter().enumerate().any(|(index, shard)| {
        shards[..index]
            .iter()
            .any(|prior| prior.candidate_executable_sha256 == shard.candidate_executable_sha256)
    }) {
        return Err("runtime platform shards reuse a candidate executable identity".into());
    }
    if shards.iter().enumerate().any(|(index, shard)| {
        shard.process_helper_sha256.is_some_and(|digest| {
            shards[..index]
                .iter()
                .any(|prior| prior.process_helper_sha256 == Some(digest))
        })
    }) {
        return Err("runtime platform shards reuse a process helper identity".into());
    }
    Ok(())
}

/// Returns the mandatory, reviewable boundary classes for every applicable
/// builtin that has a non-ordinary domain edge.
#[must_use]
pub fn mandatory_runtime_boundaries() -> Vec<RuntimeBoundaryRequirement> {
    hell_builtins::registry()
        .iter()
        .filter(|spec| spec.visibility == Visibility::Public && spec.implementation.is_some())
        .flat_map(|spec| {
            boundary_classes(spec)
                .into_iter()
                .map(|class| RuntimeBoundaryRequirement {
                    builtin: Arc::from(spec.name),
                    class: Arc::from(class),
                })
        })
        .collect()
}

/// Returns the nine high-risk cross-family interactions required by the
/// promotion design.
#[must_use]
pub fn mandatory_runtime_interactions() -> Vec<RuntimeInteractionRequirement> {
    [
        (
            "timeout-process",
            &["Timeout.timeout", "Process.runProcess_"][..],
        ),
        (
            "race-temporary-resource",
            &["Async.race", "Temp.withSystemTempFile"][..],
        ),
        ("list-laziness-error", &["List.take", "Error.error"][..]),
        (
            "map-ordering-custom-ord",
            &["Map.fromList", "Ord.lt", "Ord.gt"][..],
        ),
        (
            "text-decode-process-capture",
            &["Text.decodeUtf8", "ByteString.readProcess_"][..],
        ),
        (
            "cwd-child-process",
            &["Process.setWorkingDir", "Process.runProcess_"][..],
        ),
        (
            "http-stream-disconnect",
            &["Http.responseStream", "Http.run"][..],
        ),
        (
            "options-platform-argv",
            &["Options.execParser", "Environment.getArgs"][..],
        ),
        (
            "json-number-presentation",
            &["Json.Number", "Json.encode", "Double.show"][..],
        ),
    ]
    .into_iter()
    .map(|(id, builtins)| RuntimeInteractionRequirement {
        id: Arc::from(id),
        builtins: builtins.iter().map(|builtin| Arc::from(*builtin)).collect(),
    })
    .collect()
}

fn boundary_classes(spec: &BuiltinSpec) -> Vec<&'static str> {
    if spec.name == "List.take" {
        return vec![
            "negative-count",
            "zero-count",
            "below-finite-length",
            "equal-finite-length",
            "above-finite-length",
            "infinite-source",
            "bottom-source-zero-count",
            "bottom-after-demanded-prefix",
        ];
    }
    if matches!(
        spec.name,
        "List.nil"
            | "List.repeat"
            | "List.iterate'"
            | "Map.singleton"
            | "Set.singleton"
            | "Tree.unfoldTree"
    ) {
        return Vec::new();
    }
    let family = spec.assurance_metadata().semantic_family;
    if family == "Integer" {
        return vec!["negative-value", "zero-value", "positive-value"];
    }
    if matches!(family, "Int" | "Double") {
        let mut classes = vec![
            "negative-value",
            "zero-value",
            "positive-value",
            "minimum-value",
            "maximum-value",
            "overflow",
        ];
        if matches!(
            spec.name,
            "Int.eq" | "Int.show" | "Int.toInteger" | "Double.fromInt"
        ) {
            classes.retain(|class| *class != "overflow");
        }
        return classes;
    }
    if family == "Text" {
        let mut classes = vec!["empty-input", "ascii", "unicode"];
        if text_can_observe_invalid_encoding(spec.name) {
            classes.push("invalid-encoding");
        }
        return classes;
    }
    if family == "Json" {
        return match spec.name {
            "Json.decode" => vec!["empty-input", "ascii", "unicode", "invalid-encoding"],
            "Json.encode" | "Json.String" => vec!["empty-input", "ascii", "unicode"],
            _ => Vec::new(),
        };
    }
    if matches!(family, "ByteString" | "CI") {
        return vec!["empty-input", "ascii", "unicode", "invalid-encoding"];
    }
    if matches!(family, "Options" | "Option" | "Argument" | "Flag") {
        return vec![
            "absent-option",
            "present-option",
            "repeated-option",
            "malformed-option",
            "end-of-options",
        ];
    }
    if family == "Tree" {
        return if spec.name == "Tree.Node" {
            vec!["empty-input", "singleton-input", "finite-input"]
        } else {
            vec!["singleton-input", "finite-input"]
        };
    }
    if matches!(family, "List" | "Map" | "Set" | "Vector") {
        return vec!["empty-input", "singleton-input", "finite-input"];
    }
    Vec::new()
}

fn text_can_observe_invalid_encoding(builtin: &str) -> bool {
    matches!(
        builtin,
        "Text.decodeUtf8"
            | "Text.getContents"
            | "Text.getLine"
            | "Text.interact"
            | "Text.readFile"
            | "Text.readProcess"
            | "Text.readProcessStdout_"
            | "Text.readProcess_"
    )
}

/// Returns the authoritative runtime obligation cells for the public registry.
///
/// Requirements are derived from adapter demand, effect kind, capability, and
/// sensitivity metadata. This deliberately does not assign one global
/// obligation family to every builtin.
#[must_use]
pub fn applicable_runtime_obligation_cells() -> Vec<RuntimeObligationCell> {
    hell_builtins::registry()
        .iter()
        .filter(|spec| spec.visibility == Visibility::Public && spec.implementation.is_some())
        .flat_map(runtime_obligation_cells_for_spec)
        .collect()
}

/// Returns the exact runtime obligation cells for one registry entry.
#[must_use]
pub fn runtime_obligation_cells_for_spec(spec: &BuiltinSpec) -> Vec<RuntimeObligationCell> {
    if spec.visibility != Visibility::Public || spec.implementation.is_none() {
        return Vec::new();
    }
    let metadata = spec.assurance_metadata();
    let mut cells = vec![cell(
        spec,
        CompatibilityDimension::PureRuntime,
        pure_runtime_obligations(spec),
        pure_runtime_signal(spec),
    )];
    if metadata.effect_kind == EffectKind::Io {
        cells.push(cell(
            spec,
            CompatibilityDimension::Effects,
            effect_obligations(spec),
            CausalSignal::EffectEvent,
        ));
    }
    if metadata
        .sensitivities
        .contains(&AssuranceSensitivity::Concurrency)
    {
        cells.push(cell(
            spec,
            CompatibilityDimension::Concurrency,
            concurrency_obligations(spec),
            CausalSignal::TaskAndCancellation,
        ));
    }
    if metadata
        .sensitivities
        .contains(&AssuranceSensitivity::Presentation)
    {
        cells.push(cell(
            spec,
            CompatibilityDimension::Presentation,
            presentation_obligations(spec),
            CausalSignal::PresentationField,
        ));
    }
    if metadata
        .sensitivities
        .contains(&AssuranceSensitivity::Platform)
    {
        cells.push(cell(
            spec,
            CompatibilityDimension::Platform,
            vec!["three-platform-observation"],
            CausalSignal::RuntimeAdapter,
        ));
    }
    if metadata
        .sensitivities
        .contains(&AssuranceSensitivity::Resource)
    {
        cells.push(cell(
            spec,
            CompatibilityDimension::ResourceBehavior,
            resource_obligations(spec),
            resource_signal(spec),
        ));
    }
    cells
}

fn cell(
    spec: &BuiltinSpec,
    dimension: CompatibilityDimension,
    obligations: Vec<&'static str>,
    causal_signal: CausalSignal,
) -> RuntimeObligationCell {
    RuntimeObligationCell {
        builtin: Arc::from(spec.name),
        dimension,
        obligations: obligations
            .into_iter()
            .map(|obligation| ObligationId(Arc::from(obligation)))
            .collect(),
        causal_signal,
        platforms: vec![
            ClaimPlatform::Linux,
            ClaimPlatform::MacOs,
            ClaimPlatform::Windows,
        ],
    }
}

fn pure_runtime_obligations(spec: &BuiltinSpec) -> Vec<&'static str> {
    let mut obligations = vec![if failure_only(spec) {
        "adapter-failure"
    } else {
        "adapter-success"
    }];
    for demand in spec.demand {
        let obligation = match demand {
            Demand::Lazy => "lazy-boundary",
            Demand::Whnf => "whnf-boundary",
            Demand::Deep => "deep-boundary",
            Demand::OnIoExecution => "io-execution-boundary",
            Demand::Conditional => "conditional-selected",
        };
        push_unique(&mut obligations, obligation);
    }
    if spec.demand.contains(&Demand::Conditional) {
        obligations.push("conditional-unselected");
    }
    if typed_result_family(spec) {
        obligations.push("typed-result");
    }
    if callback_family(spec) {
        obligations.push("callback-order");
    }
    let family = spec.assurance_metadata().semantic_family;
    if matches!(family, "List" | "Map" | "Set" | "Tree" | "Vector") {
        obligations.push("collection-interaction");
    }
    if constructor_eliminator(spec) {
        obligations.push("constructor-eliminator");
    }
    if matches!(
        family,
        "Int" | "Integer" | "Double" | "TimeOfDay" | "UTCTime" | "Day"
    ) {
        obligations.push("numeric-boundary");
    }
    if matches!(family, "Text" | "ByteString" | "Json" | "CI" | "Show") {
        obligations.push("encoding-boundary");
    }
    if text_can_observe_invalid_encoding(spec.name) {
        obligations.push("adapter-failure");
    }
    if matches!(
        family,
        "Options" | "Option" | "Argument" | "Flag" | "Alternative"
    ) {
        obligations.push("parser-composition");
    }
    obligations
}

fn typed_result_family(spec: &BuiltinSpec) -> bool {
    typed_result_scalar_family(spec.name)
        || typed_result_text_family(spec.name)
        || typed_result_collection_family(spec.name)
        || matches!(
            spec.assurance_metadata().semantic_family,
            "Bool" | "Maybe" | "Either" | "These" | "Function" | "Ord" | "Eq"
        )
}

fn typed_result_scalar_family(name: &str) -> bool {
    matches!(
        name,
        "Builder.byteString"
            | "Double.eq"
            | "Int.eq"
            | "Double.fromInt"
            | "Double.mult"
            | "Double.plus"
            | "Double.readMaybe"
            | "Double.subtract"
            | "Double.show"
            | "Double.showEFloat"
            | "Double.showFFloat"
            | "List.all"
            | "IO.stdin"
            | "IO.stdout"
            | "IO.stderr"
            | "Process.nullStream"
            | "Process.proc"
            | "Process.setEnv"
            | "Process.setStderr"
            | "Process.setStdin"
            | "Process.setStdout"
            | "Process.setWorkingDir"
            | "Exit.ExitFailure"
            | "Exit.ExitSuccess"
            | "Exit.exitCode"
            | "CI.foldedCase"
            | "CI.mk"
            | "IO.AppendMode"
            | "IO.BlockBuffering"
            | "IO.LineBuffering"
            | "IO.NoBuffering"
            | "IO.ReadMode"
            | "IO.ReadWriteMode"
            | "IO.WriteMode"
            | "Json.Array"
            | "Json.Bool"
            | "Json.Null"
            | "Json.Number"
            | "Json.Object"
            | "Json.String"
            | "Integer.mult"
            | "Integer.plus"
            | "Integer.readMaybe"
            | "Integer.subtract"
            | "List.nil"
            | "Map.singleton"
            | "Set.singleton"
    )
}

fn typed_result_text_family(name: &str) -> bool {
    matches!(
        name,
        "Text.drop"
            | "Text.all"
            | "Text.any"
            | "Text.breakOn"
            | "Text.concat"
            | "Text.dropEnd"
            | "Text.encodeUtf8"
            | "Text.eq"
            | "Text.filter"
            | "Text.isInfixOf"
            | "Text.isPrefixOf"
            | "Text.isSuffixOf"
            | "Text.intercalate"
            | "Text.length"
            | "Text.lines"
            | "Text.pack"
            | "Text.replace"
            | "Text.reverse"
            | "Text.strip"
            | "Text.stripPrefix"
            | "Text.stripSuffix"
            | "Text.splitOn"
            | "Text.take"
            | "Text.takeEnd"
            | "Text.toLower"
            | "Text.toUpper"
            | "Text.unlines"
            | "Text.unpack"
            | "Text.unwords"
            | "Text.words"
    )
}

fn typed_result_collection_family(name: &str) -> bool {
    matches!(
        name,
        "List.all"
            | "List.any"
            | "List.break"
            | "List.elem"
            | "List.elemIndex"
            | "List.elemIndices"
            | "List.dropWhile"
            | "List.dropWhileEnd"
            | "List.filter"
            | "List.find"
            | "List.findIndex"
            | "List.findIndices"
            | "List.group"
            | "List.isInfixOf"
            | "List.isPrefixOf"
            | "List.isSubsequenceOf"
            | "List.isSuffixOf"
            | "List.lookup"
            | "List.map"
            | "List.notElem"
            | "List.partition"
            | "List.span"
            | "List.takeWhile"
            | "List.zipWith"
            | "List.concatMap"
            | "Map.all"
            | "Map.any"
            | "Map.filter"
            | "Map.filterWithKey"
            | "Map.adjust"
            | "Map.map"
            | "Map.insertWith"
            | "Map.unionWith"
            | "List.foldl'"
            | "List.foldr"
            | "List.scanl'"
            | "List.scanr"
            | "List.mapAccumL"
            | "List.mapAccumR"
            | "List.deleteBy"
            | "List.sort"
            | "List.sortOn"
            | "List.nubOrd"
            | "List.groupBy"
            | "List.unfoldr"
    )
}

fn effect_obligations(spec: &BuiltinSpec) -> Vec<&'static str> {
    let mut obligations = vec![if failure_only(spec) {
        "effect-failure"
    } else {
        "effect-success"
    }];
    if host_failure_probe_required(spec) && !failure_only(spec) {
        obligations.push("effect-failure");
    }
    obligations.push("effect-ordering");
    obligations
}

fn concurrency_obligations(spec: &BuiltinSpec) -> Vec<&'static str> {
    let mut obligations = vec!["task-lifecycle", "scope-cleanup"];
    if matches!(spec.name, "Async.race" | "Timeout.timeout") {
        obligations.push("race-cancellation");
    }
    obligations
}

fn presentation_obligations(spec: &BuiltinSpec) -> Vec<&'static str> {
    let mut obligations = vec!["raw-observation"];
    if spec.name == "IO.print"
        || matches!(
            spec.assurance_metadata().semantic_family,
            "Show" | "Options" | "Diagnostic"
        )
    {
        obligations.push("normalized-shadow-diff");
    }
    obligations
}

fn resource_obligations(spec: &BuiltinSpec) -> Vec<&'static str> {
    let family = spec.assurance_metadata().semantic_family;
    if matches!(family, "List" | "Map" | "Set" | "Tree" | "Vector") {
        return vec!["bounded-materialization"];
    }
    let mut obligations = vec!["resource-audit"];
    if resource_lifecycle_traced(spec) {
        obligations.push("cleanup-trace");
    }
    obligations
}

fn pure_runtime_signal(spec: &BuiltinSpec) -> CausalSignal {
    if spec.demand.iter().any(|demand| {
        matches!(
            demand,
            Demand::Lazy | Demand::Whnf | Demand::Deep | Demand::Conditional
        )
    }) {
        CausalSignal::RuntimeAdapterAndForceTrace
    } else {
        CausalSignal::RuntimeAdapter
    }
}

fn resource_signal(spec: &BuiltinSpec) -> CausalSignal {
    if spec.name.starts_with("Async.") {
        return CausalSignal::TaskAndCancellation;
    }
    if resource_lifecycle_traced(spec)
        && !matches!(spec.name, "IO.hClose" | "Process.useHandleClose")
    {
        CausalSignal::ResourceLifecycle
    } else {
        CausalSignal::RuntimeAdapter
    }
}

fn resource_lifecycle_traced(spec: &BuiltinSpec) -> bool {
    matches!(
        spec.name,
        "IO.openFile"
            | "IO.hClose"
            | "Process.useHandleClose"
            | "Temp.withSystemTempDirectory"
            | "Temp.withSystemTempFile"
            | "Async.concurrently"
            | "Async.pooledForConcurrently"
            | "Async.pooledForConcurrently_"
            | "Async.pooledMapConcurrently"
            | "Async.pooledMapConcurrently_"
            | "Async.race"
    )
}

fn failure_only(spec: &BuiltinSpec) -> bool {
    matches!(spec.name, "Error.error" | "Exit.die" | "Exit.exitWith")
}

fn host_failure_probe_required(spec: &BuiltinSpec) -> bool {
    spec.assurance_metadata().host_failure_applicable
}

fn callback_family(spec: &BuiltinSpec) -> bool {
    let family = spec.assurance_metadata().semantic_family;
    matches!(
        spec.name,
        "$" | "."
            | "Functor.fmap"
            | "<$>"
            | "<*>"
            | "<**>"
            | "Text.all"
            | "Text.any"
            | "Text.filter"
            | "Record.modify"
            | "Monad.mapM"
            | "Monad.mapM_"
            | "Monad.forM"
            | "Monad.forM_"
    ) || matches!(
        family,
        "List"
            | "Map"
            | "Tree"
            | "Maybe"
            | "Either"
            | "Exit"
            | "These"
            | "Json"
            | "Async"
            | "IO"
            | "Monad"
            | "Functor"
            | "Function"
    ) && spec
        .scheme
        .is_some_and(|scheme| scheme.match_indices("->").count() > usize::from(spec.arity))
}

fn constructor_eliminator(spec: &BuiltinSpec) -> bool {
    matches!(
        spec.name,
        "Bool.bool"
            | "Maybe.maybe"
            | "Either.either"
            | "These.these"
            | "Json.value"
            | "Exit.exitCode"
            | "Record.get"
            | "Record.set"
            | "Record.modify"
    )
}

fn push_unique(obligations: &mut Vec<&'static str>, obligation: &'static str) {
    if !obligations.contains(&obligation) {
        obligations.push(obligation);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn every_applicable_public_runtime_cell_has_non_global_requirements() {
        let cells = applicable_runtime_obligation_cells();
        let public = hell_builtins::registry()
            .iter()
            .filter(|spec| spec.visibility == Visibility::Public && spec.implementation.is_some())
            .count();
        assert_eq!(
            cells
                .iter()
                .filter(|cell| cell.dimension == CompatibilityDimension::PureRuntime)
                .count(),
            public
        );
        assert!(cells.iter().all(|cell| !cell.obligations.is_empty()));
        assert!(cells.iter().all(|cell| cell.platforms.len() == 3));
        assert_eq!(cells.len(), 849, "public runtime scope changed");
        let dimensions = cells.iter().fold(BTreeMap::new(), |mut counts, cell| {
            *counts.entry(cell.dimension.as_str()).or_insert(0_usize) += 1;
            counts
        });
        assert_eq!(
            dimensions,
            BTreeMap::from([
                ("concurrency", 8),
                ("effects", 65),
                ("platform", 190),
                ("presentation", 68),
                ("pure-runtime", 345),
                ("resource-behavior", 173),
            ]),
            "runtime dimension applicability changed"
        );
        assert!(!cells.iter().enumerate().any(|(index, cell)| {
            cells[..index]
                .iter()
                .any(|prior| prior.builtin == cell.builtin && prior.dimension == cell.dimension)
        }));

        let families = cells
            .iter()
            .filter(|cell| cell.dimension == CompatibilityDimension::PureRuntime)
            .fold(
                BTreeMap::<Vec<ObligationId>, usize>::new(),
                |mut counts, cell| {
                    *counts.entry(cell.obligations.clone()).or_default() += 1;
                    counts
                },
            );
        assert!(
            families.len() > 12,
            "obligations collapsed into generic templates"
        );
    }

    #[test]
    fn runtime_scope_identifiers_exactly_match_the_generated_catalog_authority() {
        let boundaries = mandatory_runtime_boundaries()
            .into_iter()
            .map(|requirement| requirement.class)
            .collect::<BTreeSet<_>>();
        let catalog_boundaries = hell_builtins::assurance_catalogs::BOUNDARY_CLASSES
            .iter()
            .map(|value| Arc::<str>::from(*value))
            .collect::<BTreeSet<_>>();
        assert_eq!(boundaries, catalog_boundaries);

        let interactions = mandatory_runtime_interactions()
            .into_iter()
            .map(|requirement| requirement.id)
            .collect::<BTreeSet<_>>();
        let catalog_interactions = hell_builtins::assurance_catalogs::INTERACTION_OBLIGATIONS
            .iter()
            .map(|value| Arc::<str>::from(*value))
            .collect::<BTreeSet<_>>();
        assert_eq!(interactions, catalog_interactions);
    }

    #[test]
    fn demand_and_interaction_classes_are_exact() {
        let bool_spec = hell_builtins::lookup("Bool.bool").unwrap();
        let bool_cell = runtime_obligation_cells_for_spec(bool_spec)
            .into_iter()
            .find(|cell| cell.dimension == CompatibilityDimension::PureRuntime)
            .unwrap();
        let names = bool_cell
            .obligations
            .iter()
            .map(|obligation| obligation.0.as_ref())
            .collect::<BTreeSet<_>>();
        assert!(names.contains("conditional-selected"));
        assert!(names.contains("conditional-unselected"));
        assert!(names.contains("typed-result"));
        assert!(names.contains("constructor-eliminator"));

        let list = hell_builtins::lookup("List.map").unwrap();
        let list_cells = runtime_obligation_cells_for_spec(list);
        let list_names = list_cells[0]
            .obligations
            .iter()
            .map(|obligation| obligation.0.as_ref())
            .collect::<BTreeSet<_>>();
        assert!(list_names.contains("callback-order"));
        assert!(list_names.contains("collection-interaction"));
        assert!(!list_names.contains("conditional-selected"));

        for (builtin, argument, branch) in [
            ("Function.fix", 0, "recursive"),
            ("Maybe.mapMaybe", 0, "element"),
            ("Maybe.maybe", 0, "nothing"),
            ("Maybe.maybe", 1, "just"),
            ("Either.either", 0, "left"),
            ("Either.either", 1, "right"),
            ("These.these", 0, "this"),
            ("These.these", 1, "that"),
            ("These.these", 2, "these"),
        ] {
            assert!(callback_identity_allowed(builtin, argument, branch));
            assert!(!callback_identity_allowed(builtin, argument, "forged"));
        }
    }

    #[test]
    fn list_take_and_high_risk_interactions_are_fully_enumerated() {
        let take = mandatory_runtime_boundaries()
            .into_iter()
            .filter(|boundary| boundary.builtin.as_ref() == "List.take")
            .map(|boundary| boundary.class)
            .collect::<BTreeSet<_>>();
        assert_eq!(take.len(), 8);
        assert!(take.contains("bottom-source-zero-count"));
        assert!(take.contains("bottom-after-demanded-prefix"));

        let interactions = mandatory_runtime_interactions();
        assert_eq!(interactions.len(), 9);
        assert!(interactions.iter().all(|interaction| {
            !interaction.builtins.is_empty()
                && interaction
                    .builtins
                    .iter()
                    .all(|builtin| hell_builtins::lookup(builtin).is_some())
        }));
    }

    #[test]
    fn constructor_and_generator_outputs_do_not_claim_input_boundaries() {
        for builtin in [
            "List.nil",
            "List.repeat",
            "List.iterate'",
            "Map.singleton",
            "Set.singleton",
            "Tree.unfoldTree",
        ] {
            let spec = hell_builtins::lookup(builtin).unwrap();
            assert!(
                boundary_classes(spec).is_empty(),
                "{builtin} has no collection input whose cardinality can establish a boundary"
            );
        }
    }

    #[test]
    fn comparator_ordinals_ignore_legitimate_non_ord_direct_children() {
        let map = hell_builtins::lookup("Map.fromList").unwrap().id.0;
        let less = hell_builtins::lookup("Ord.lt").unwrap().id.0;
        let greater = hell_builtins::lookup("Ord.gt").unwrap().id.0;
        let supporting = hell_builtins::lookup("$").unwrap().id.0;
        let event = |builtin, sequence, parent_sequence| TraceAdapterEvent {
            builtin,
            instance_target: Some("Int".to_owned()),
            instance_premises: Vec::new(),
            outcome: "value".to_owned(),
            owner_task: Some(7),
            sequence,
            parent_sequence,
            nested_adapters: 0,
            materialized_before: 0,
            materialized_after: 0,
            callbacks: Vec::new(),
            comparators: Vec::new(),
        };
        let baseline = vec![
            event(map, 1, None),
            event(greater, 2, Some(1)),
            event(less, 3, Some(1)),
        ];
        let with_supporting_child = vec![
            event(map, 1, None),
            event(supporting, 2, Some(1)),
            event(greater, 3, Some(1)),
            event(less, 4, Some(1)),
        ];
        let contracts = |events: &[TraceAdapterEvent]| {
            direct_ord_children(events, &events[0], less, greater)
                .into_iter()
                .enumerate()
                .map(|(index, child)| crate::ComparatorTraceContract {
                    parent_invocation: 1,
                    direct_child_ordinal: u64::try_from(index).unwrap() + 1,
                    comparator_ordinal: u64::try_from(index).unwrap() + 1,
                    comparator: Arc::from(
                        hell_builtins::registry()[usize::from(child.builtin)].name,
                    ),
                    canonical_left: Arc::from(if child.builtin == greater {
                        "{\"type\":\"Int\",\"value\":\"2\"}"
                    } else {
                        "{\"type\":\"Int\",\"value\":\"1\"}"
                    }),
                    canonical_right: Arc::from(if child.builtin == greater {
                        "{\"type\":\"Int\",\"value\":\"1\"}"
                    } else {
                        "{\"type\":\"Int\",\"value\":\"2\"}"
                    }),
                    result: true,
                    outcome: Arc::from("value"),
                })
                .collect::<Vec<_>>()
        };
        let baseline_contracts = contracts(&baseline);
        let supporting_contracts = contracts(&with_supporting_child);
        assert_eq!(baseline_contracts, supporting_contracts);
        assert_eq!(
            crate::comparator_trace_sha256("Map.fromList", 1, "Int", &[], &baseline_contracts),
            crate::comparator_trace_sha256("Map.fromList", 1, "Int", &[], &supporting_contracts,)
        );
    }

    #[test]
    fn adapter_causal_graph_rejects_forged_edges_and_counts() {
        let tasks = BTreeSet::from([7]);
        let parent = TraceAdapterEvent {
            builtin: 1,
            instance_target: None,
            instance_premises: Vec::new(),
            outcome: "value".to_owned(),
            owner_task: Some(7),
            sequence: 1,
            parent_sequence: None,
            nested_adapters: 1,
            materialized_before: 0,
            materialized_after: 0,
            callbacks: Vec::new(),
            comparators: Vec::new(),
        };
        let child = TraceAdapterEvent {
            builtin: 2,
            instance_target: None,
            instance_premises: Vec::new(),
            outcome: "value".to_owned(),
            owner_task: Some(7),
            sequence: 2,
            parent_sequence: Some(1),
            nested_adapters: 0,
            materialized_before: 0,
            materialized_after: 0,
            callbacks: Vec::new(),
            comparators: Vec::new(),
        };
        validate_adapter_causality(&[parent, child], &tasks).expect("valid causal graph");

        let event = |owner_task, sequence, parent_sequence, nested_adapters| TraceAdapterEvent {
            builtin: 2,
            instance_target: None,
            instance_premises: Vec::new(),
            outcome: "value".to_owned(),
            owner_task,
            sequence,
            parent_sequence,
            nested_adapters,
            materialized_before: 0,
            materialized_after: 0,
            callbacks: Vec::new(),
            comparators: Vec::new(),
        };
        assert_eq!(
            validate_adapter_causality(
                &[event(Some(7), 1, None, 0), event(Some(7), 1, None, 0)],
                &tasks,
            )
            .unwrap_err(),
            "runtime adapter causal identity is duplicated"
        );
        assert_eq!(
            validate_adapter_causality(
                &[event(Some(7), 1, None, 1), event(Some(7), 3, Some(1), 0)],
                &tasks,
            )
            .unwrap_err(),
            "runtime adapter sequences are not contiguous"
        );
        assert_eq!(
            validate_adapter_causality(&[event(Some(7), 1, Some(9), 0)], &tasks).unwrap_err(),
            "runtime adapter causal parent is missing"
        );
        assert_eq!(
            validate_adapter_causality(
                &[event(Some(7), 1, None, 0), event(Some(8), 2, Some(1), 0)],
                &BTreeSet::from([7, 8]),
            )
            .unwrap_err(),
            "runtime adapter causal parent is missing"
        );
        assert_eq!(
            validate_adapter_causality(
                &[event(Some(7), 1, None, 0), event(Some(7), 2, Some(1), 0)],
                &tasks,
            )
            .unwrap_err(),
            "runtime adapter nested count does not match causal children"
        );
    }

    #[test]
    fn platform_set_requires_exact_three_shard_identity_and_targets() {
        let digest = crate::sha256_bytes(b"shared");
        let shard = |platform, bundle: &[u8]| RuntimePlatformShard {
            platform,
            case_id: "case".into(),
            source_sha256: digest,
            candidate_source_sha256: digest,
            assurance_epoch_sha256: digest,
            descriptor_sha256: digest,
            candidate_executable_sha256: crate::sha256_bytes(bundle),
            process_helper_sha256: None,
            bundle_sha256: crate::sha256_bytes(bundle),
            targets: vec![RuntimePlatformTarget {
                builtin: "Bool.bool".into(),
                dimension: CompatibilityDimension::Platform,
                obligation_trace_sha256: crate::sha256_bytes(bundle),
            }],
        };
        let linux = shard(ClaimPlatform::Linux, b"linux");
        let macos = shard(ClaimPlatform::MacOs, b"macos");
        let windows = shard(ClaimPlatform::Windows, b"windows");
        validate_runtime_platform_set(&[linux.clone(), macos.clone(), windows.clone()])
            .expect("exact platform set");
        assert!(validate_runtime_platform_set(&[linux.clone(), macos.clone()]).is_err());
        assert!(
            validate_runtime_platform_set(&[linux.clone(), linux.clone(), windows.clone()])
                .is_err()
        );
        let mut wrong_source = windows.clone();
        wrong_source.source_sha256 = crate::sha256_bytes(b"wrong-source");
        assert!(
            validate_runtime_platform_set(&[linux.clone(), macos.clone(), wrong_source]).is_err()
        );
        let mut process_shards = [linux, macos, windows];
        for (index, shard) in process_shards.iter_mut().enumerate() {
            shard.process_helper_sha256 = Some(crate::sha256_bytes(&index.to_be_bytes()));
        }
        validate_runtime_platform_set(&process_shards)
            .expect("distinct platform helper identities");
        process_shards[2].process_helper_sha256 = process_shards[0].process_helper_sha256;
        assert!(validate_runtime_platform_set(&process_shards).is_err());
    }

    #[test]
    fn runtime_authority_digest_binds_every_instance_head_projection_step() {
        use hell_builtins::InstanceHeadProjection::{ApplyArgument, FunctionArgument};

        let spec = hell_builtins::lookup("List.sort").expect("List.sort remains registered");
        let actual = hell_builtins::instance_head_projection(spec.name)
            .expect("constrained builtin has a projection");
        assert_eq!(actual, [FunctionArgument(0), ApplyArgument]);
        let baseline = runtime_assurance_spec_sha256(spec);
        for changed in [
            vec![FunctionArgument(0)],
            vec![FunctionArgument(1), ApplyArgument],
            vec![ApplyArgument, FunctionArgument(0)],
        ] {
            assert_ne!(
                runtime_assurance_spec_sha256_with_projection(spec, Some(&changed)),
                baseline
            );
        }
        assert_ne!(
            runtime_assurance_spec_sha256_with_projection(spec, None),
            baseline
        );
    }
}
