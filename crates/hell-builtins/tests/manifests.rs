use std::collections::HashSet;

const TYPE_MANIFEST: &str = include_str!("../../../builtins/type-constructors.ron");
const INSTANCE_MANIFEST: &str = include_str!("../../../builtins/instances.ron");

fn entries(manifest: &str) -> Vec<&str> {
    assert!(manifest.trim_start().starts_with("//"));
    assert!(manifest.trim_end().ends_with(']'));
    manifest
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('('))
        .inspect(|line| assert!(line.ends_with("),"), "malformed manifest entry: {line}"))
        .collect()
}

fn field<'a>(entry: &'a str, name: &str) -> &'a str {
    let marker = format!("{name}: \"");
    let value = entry
        .split_once(&marker)
        .unwrap_or_else(|| panic!("entry has no `{name}` field: {entry}"))
        .1;
    value
        .split_once('"')
        .unwrap_or_else(|| panic!("unterminated `{name}` field: {entry}"))
        .0
}

#[test]
fn type_constructor_manifest_is_the_exact_public_and_internal_snapshot() {
    let entries = entries(TYPE_MANIFEST);
    assert_eq!(entries.len(), 31);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| field(entry, "visibility") == "public")
            .count(),
        25
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| field(entry, "visibility") == "internal")
            .count(),
        6
    );

    let names: HashSet<_> = entries.iter().map(|entry| field(entry, "name")).collect();
    assert_eq!(names.len(), entries.len());

    let snapshot = entries
        .iter()
        .map(|entry| {
            format!(
                "{}:{}:{}",
                field(entry, "name"),
                field(entry, "kind"),
                field(entry, "visibility")
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    assert_eq!(
        snapshot,
        "():Type:public|Bool:Type:public|Builder:Type:public|ByteString:Type:public|CI:Type -> Type:public|Char:Type:public|Day:Type:public|DayOfWeek:Type:public|Double:Type:public|Either:Type -> Type -> Type:public|ExitCode:Type:public|Handle:Type:public|IO:Type -> Type:public|Int:Type:public|Integer:Type:public|Map:Type -> Type -> Type:public|Maybe:Type -> Type:public|Set:Type -> Type:public|Text:Type:public|These:Type -> Type -> Type:public|TimeOfDay:Type:public|Tree:Type -> Type:public|UTCTime:Type:public|Value:Type:public|Vector:Type -> Type:public|hell:Hell.NilL:Row:internal|hell:Hell.ConsL:Symbol -> Type -> Row -> Row:internal|hell:Hell.Record:Row -> Type:internal|hell:Hell.Variant:Row -> Type:internal|hell:Hell.Tagged:Symbol -> Type -> Type:internal|hell:Hell.Nullary:Type:internal"
    );
}

#[test]
fn instance_manifest_is_the_exact_closed_world_snapshot() {
    let entries = entries(INSTANCE_MANIFEST);
    assert_eq!(entries.len(), 98);

    let keys: HashSet<_> = entries
        .iter()
        .map(|entry| (field(entry, "class"), field(entry, "target")))
        .collect();
    assert_eq!(keys.len(), entries.len());

    let expected_class_counts = [
        ("Show", 22),
        ("Eq", 20),
        ("Ord", 20),
        ("Monad", 5),
        ("Functor", 7),
        ("Applicative", 6),
        ("Alternative", 2),
        ("Monoid", 6),
        ("Semigroup", 8),
        ("FoldCase", 2),
    ];
    for (class, expected) in expected_class_counts {
        assert_eq!(
            entries
                .iter()
                .filter(|entry| field(entry, "class") == class)
                .count(),
            expected,
            "wrong `{class}` instance count"
        );
    }

    let classes: HashSet<_> = entries.iter().map(|entry| field(entry, "class")).collect();
    assert_eq!(classes.len(), expected_class_counts.len());

    let snapshot_for = |class: &str| {
        entries
            .iter()
            .filter(|entry| field(entry, "class") == class)
            .map(|entry| format!("{}:{}", field(entry, "target"), field(entry, "resolution")))
            .collect::<Vec<_>>()
            .join("|")
    };
    assert_eq!(
        snapshot_for("Show"),
        "[]:entail1|Set:entail1|CI:entail1|Tree:entail1|Maybe:entail1|Vector:entail1|Either:entail2|(,):entail2|Int:direct0|Integer:direct0|Day:direct0|DayOfWeek:direct0|UTCTime:direct0|TimeOfDay:direct0|Double:direct0|Bool:direct0|Char:direct0|Text:direct0|ByteString:direct0|Builder:direct0|ExitCode:direct0|Value:direct0"
    );
    assert_eq!(
        snapshot_for("Eq"),
        "CI:entail1|[]:entail1|Set:entail1|Maybe:entail1|Either:entail2|(,):entail2|Tree:entail1|Vector:entail1|Int:direct0|Integer:direct0|Day:direct0|DayOfWeek:direct0|UTCTime:direct0|TimeOfDay:direct0|Double:direct0|Bool:direct0|Char:direct0|Text:direct0|ByteString:direct0|ExitCode:direct0"
    );
    assert_eq!(
        snapshot_for("Ord"),
        "[]:entail1|Set:entail1|CI:entail1|Maybe:entail1|Either:entail2|(,):entail2|Tree:entail1|Vector:entail1|Int:direct0|Integer:direct0|Day:direct0|DayOfWeek:direct0|UTCTime:direct0|TimeOfDay:direct0|Double:direct0|Bool:direct0|Char:direct0|Text:direct0|ByteString:direct0|ExitCode:direct0"
    );
    assert_eq!(
        snapshot_for("Monad"),
        "IO:direct0|Maybe:direct0|[]:direct0|Tree:direct0|Either:direct1"
    );
    assert_eq!(
        snapshot_for("Functor"),
        "IO:direct0|Maybe:direct0|[]:direct0|Tree:direct0|Options.Parser:direct0|Either:direct1|(,):direct1"
    );
    assert_eq!(
        snapshot_for("Applicative"),
        "IO:direct0|Maybe:direct0|[]:direct0|Tree:direct0|Options.Parser:direct0|Either:direct1"
    );
    assert_eq!(
        snapshot_for("Alternative"),
        "Options.Parser:direct0|Maybe:direct0"
    );
    assert_eq!(
        snapshot_for("Monoid"),
        "Maybe:entail1|Text:direct0|Builder:direct0|Vector:direct1|Options.Mod:direct2|[]:direct1"
    );
    assert_eq!(
        snapshot_for("Semigroup"),
        "Maybe:entail1|Either:direct2|Options.Mod:direct2|Options.InfoMod:direct1|Text:direct0|Builder:direct0|Vector:direct1|[]:direct1"
    );
    assert_eq!(snapshot_for("FoldCase"), "Text:direct0|ByteString:direct0");
}

#[test]
fn every_constrained_builtin_has_one_registry_owned_instance_head_projection() {
    for spec in hell_builtins::registry() {
        assert_eq!(
            spec.type_class.is_some(),
            hell_builtins::instance_head_projection(spec.name).is_some(),
            "instance-head projection inventory disagrees for {}",
            spec.name
        );
    }
}
