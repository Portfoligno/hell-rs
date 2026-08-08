//! Typed access to the checked-in type-constructor and instance manifests.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::Visibility;

const TYPE_CONSTRUCTOR_SOURCE: &str = include_str!("../../../builtins/type-constructors.ron");
const INSTANCE_SOURCE: &str = include_str!("../../../builtins/instances.ron");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeClass {
    Show,
    Eq,
    Ord,
    Monad,
    Functor,
    Applicative,
    Alternative,
    Monoid,
    Semigroup,
    FoldCase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClassHeadKind {
    Type,
    UnaryTypeConstructor,
}

impl TypeClass {
    pub const ALL: &'static [Self] = &[
        Self::Show,
        Self::Eq,
        Self::Ord,
        Self::Monad,
        Self::Functor,
        Self::Applicative,
        Self::Alternative,
        Self::Monoid,
        Self::Semigroup,
        Self::FoldCase,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Show => "Show",
            Self::Eq => "Eq",
            Self::Ord => "Ord",
            Self::Monad => "Monad",
            Self::Functor => "Functor",
            Self::Applicative => "Applicative",
            Self::Alternative => "Alternative",
            Self::Monoid => "Monoid",
            Self::Semigroup => "Semigroup",
            Self::FoldCase => "FoldCase",
        }
    }

    #[must_use]
    pub const fn head_kind(self) -> ClassHeadKind {
        match self {
            Self::Monad | Self::Functor | Self::Applicative | Self::Alternative => {
                ClassHeadKind::UnaryTypeConstructor
            }
            Self::Show | Self::Eq | Self::Ord | Self::Monoid | Self::Semigroup | Self::FoldCase => {
                ClassHeadKind::Type
            }
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "Show" => Self::Show,
            "Eq" => Self::Eq,
            "Ord" => Self::Ord,
            "Monad" => Self::Monad,
            "Functor" => Self::Functor,
            "Applicative" => Self::Applicative,
            "Alternative" => Self::Alternative,
            "Monoid" => Self::Monoid,
            "Semigroup" => Self::Semigroup,
            "FoldCase" => Self::FoldCase,
            _ => panic!("unknown class `{value}` in instance manifest"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InstanceResolution {
    Direct(u8),
    Entail(u8),
}

impl InstanceResolution {
    #[must_use]
    pub const fn head_arity(self) -> u8 {
        match self {
            Self::Direct(arity) | Self::Entail(arity) => arity,
        }
    }

    #[must_use]
    pub const fn premise_count(self) -> u8 {
        match self {
            Self::Direct(_) => 0,
            Self::Entail(count) => count,
        }
    }

    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            Self::Direct(arity) => format!("direct{arity}"),
            Self::Entail(arity) => format!("entail{arity}"),
        }
    }

    fn parse(value: &str) -> Self {
        if let Some(arity) = value.strip_prefix("direct") {
            return Self::Direct(parse_arity(arity, value));
        }
        if let Some(arity) = value.strip_prefix("entail") {
            return Self::Entail(parse_arity(arity, value));
        }
        panic!("unknown resolution `{value}` in instance manifest");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceSpec {
    pub class: TypeClass,
    pub target: &'static str,
    pub resolution: InstanceResolution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ManifestKind {
    Type,
    Symbol,
    Row,
}

impl ManifestKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Type => "Type",
            Self::Symbol => "Symbol",
            Self::Row => "Row",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "Type" => Self::Type,
            "Symbol" => Self::Symbol,
            "Row" => Self::Row,
            _ => panic!("unknown kind `{value}` in type-constructor manifest"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindSignature {
    pub arguments: Box<[ManifestKind]>,
    pub result: ManifestKind,
}

impl KindSignature {
    fn parse(value: &str) -> Self {
        let mut components = value
            .split(" -> ")
            .map(ManifestKind::parse)
            .collect::<Vec<_>>();
        let result = components
            .pop()
            .unwrap_or_else(|| panic!("empty kind in type-constructor manifest"));
        Self {
            arguments: components.into_boxed_slice(),
            result,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeConstructorSpec {
    pub name: &'static str,
    pub kind_text: &'static str,
    pub kind: KindSignature,
    pub visibility: Visibility,
}

#[must_use]
/// Returns the validated type-constructor source manifest.
///
/// # Panics
///
/// Panics if the checked-in manifest is malformed or names an unsupported
/// kind or visibility.
pub fn type_constructors() -> &'static [TypeConstructorSpec] {
    static CONSTRUCTORS: OnceLock<Vec<TypeConstructorSpec>> = OnceLock::new();
    CONSTRUCTORS.get_or_init(|| {
        let constructors = manifest_entries(TYPE_CONSTRUCTOR_SOURCE)
            .map(|entry| {
                let kind_text = quoted_field(entry, "kind");
                TypeConstructorSpec {
                    name: quoted_field(entry, "name"),
                    kind_text,
                    kind: KindSignature::parse(kind_text),
                    visibility: match quoted_field(entry, "visibility") {
                        "public" => Visibility::Public,
                        "internal" => Visibility::Internal,
                        value => {
                            panic!("unknown visibility `{value}` in type-constructor manifest")
                        }
                    },
                }
            })
            .collect::<Vec<_>>();
        let mut names = HashSet::new();
        for constructor in &constructors {
            assert!(
                names.insert(constructor.name),
                "duplicate type constructor `{}` in manifest",
                constructor.name
            );
        }
        constructors
    })
}

#[must_use]
pub fn type_constructor(name: &str) -> Option<&'static TypeConstructorSpec> {
    type_constructors().iter().find(|spec| spec.name == name)
}

#[must_use]
pub fn public_type_arity(name: &str) -> Option<u8> {
    let spec = type_constructor(name)?;
    if spec.visibility != Visibility::Public
        || spec.kind.result != ManifestKind::Type
        || !spec
            .kind
            .arguments
            .iter()
            .all(|kind| *kind == ManifestKind::Type)
    {
        return None;
    }
    u8::try_from(spec.kind.arguments.len()).ok()
}

#[must_use]
/// Returns the validated closed-world instance source manifest.
///
/// # Panics
///
/// Panics if the checked-in manifest is malformed or names an unsupported
/// class or resolution rule.
pub fn instances() -> &'static [InstanceSpec] {
    static INSTANCES: OnceLock<Vec<InstanceSpec>> = OnceLock::new();
    INSTANCES.get_or_init(|| {
        let instances = manifest_entries(INSTANCE_SOURCE)
            .map(|entry| InstanceSpec {
                class: TypeClass::parse(quoted_field(entry, "class")),
                target: quoted_field(entry, "target"),
                resolution: InstanceResolution::parse(quoted_field(entry, "resolution")),
            })
            .collect::<Vec<_>>();
        let mut keys = HashSet::new();
        for instance in &instances {
            assert!(
                keys.insert((instance.class, instance.target)),
                "duplicate `{} {}` instance in manifest",
                instance.class.as_str(),
                instance.target
            );
            let target_arity = target_arity(instance.target).unwrap_or_else(|| {
                panic!("instance target `{}` has no known kind", instance.target)
            });
            let expected_head_arguments = match instance.class.head_kind() {
                ClassHeadKind::UnaryTypeConstructor => {
                    target_arity.checked_sub(1).unwrap_or_else(|| {
                        panic!(
                            "higher-kinded class `{}` has saturated target `{}`",
                            instance.class.as_str(),
                            instance.target
                        )
                    })
                }
                ClassHeadKind::Type => target_arity,
            };
            assert_eq!(
                instance.resolution.head_arity(),
                expected_head_arguments,
                "instance resolution arity does not match target `{}`",
                instance.target
            );
        }
        instances
    })
}

#[must_use]
pub fn instance(class: TypeClass, target: &str) -> Option<&'static InstanceSpec> {
    instances()
        .iter()
        .find(|spec| spec.class == class && spec.target == target)
}

/// Resolves a class head using the closed manifest and recursively supplied
/// evidence for entailed parameters.
#[must_use]
pub fn resolve_instance(
    class: TypeClass,
    target: &str,
    argument_count: usize,
    mut has_premise: impl FnMut(usize) -> bool,
) -> bool {
    let Some(spec) = instance(class, target) else {
        return false;
    };
    if usize::from(spec.resolution.head_arity()) != argument_count {
        return false;
    }
    (0..usize::from(spec.resolution.premise_count())).all(&mut has_premise)
}

fn manifest_entries(source: &'static str) -> impl Iterator<Item = &'static str> {
    assert!(source.trim_end().ends_with(']'), "manifest is not a list");
    source.lines().map(str::trim).filter(|line| {
        if line.starts_with('(') {
            assert!(line.ends_with("),"), "malformed manifest entry: {line}");
            true
        } else {
            false
        }
    })
}

fn quoted_field(entry: &'static str, name: &str) -> &'static str {
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

fn parse_arity(value: &str, resolution: &str) -> u8 {
    value
        .parse()
        .unwrap_or_else(|_| panic!("invalid arity in resolution `{resolution}`"))
}

fn target_arity(target: &str) -> Option<u8> {
    public_type_arity(target).or_else(|| {
        Some(match target {
            "[]" | "Options.InfoMod" | "Options.Parser" => 1,
            "(,)" | "Options.Mod" => 2,
            _ => return None,
        })
    })
}
