use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_yaml::{Mapping, Value};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn member<'a>(mapping: &'a Mapping, name: &str) -> &'a Value {
    mapping
        .get(Value::String(name.to_owned()))
        .unwrap_or_else(|| panic!("cargo metadata lacks {name:?}"))
}

fn mapping(value: &Value) -> &Mapping {
    value
        .as_mapping()
        .expect("cargo metadata value must be an object")
}

fn sequence(value: &Value) -> &[Value] {
    value
        .as_sequence()
        .expect("cargo metadata value must be an array")
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .expect("cargo metadata value must be a string")
}

#[test]
fn independent_verifier_dependency_graph_excludes_primary_and_product_crates() {
    let mut command = Command::new("cargo");
    command
        .current_dir(repository_root())
        .arg("metadata")
        .arg("--locked")
        .arg("--format-version")
        .arg("1");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("cargo metadata must execute under supervision");
    assert!(
        output.status.success() && !output.timed_out,
        "cargo metadata did not complete successfully"
    );
    let stdout = output
        .stdout
        .complete
        .as_deref()
        .unwrap_or(&output.stdout.prefix);
    let metadata: Value =
        serde_yaml::from_slice(stdout).expect("cargo metadata must be valid JSON");
    let metadata = mapping(&metadata);

    let mut package_names = BTreeMap::new();
    let mut verifier_id = None;
    for package in sequence(member(metadata, "packages")) {
        let package = mapping(package);
        let id = text(member(package, "id")).to_owned();
        let name = text(member(package, "name")).to_owned();
        if name == "hell-release-verifier" {
            assert!(verifier_id.replace(id.clone()).is_none());
        }
        assert!(package_names.insert(id, name).is_none());
    }

    let mut dependencies = BTreeMap::<String, Vec<String>>::new();
    let resolve = mapping(member(metadata, "resolve"));
    for node in sequence(member(resolve, "nodes")) {
        let node = mapping(node);
        let id = text(member(node, "id")).to_owned();
        let deps = sequence(member(node, "deps"))
            .iter()
            .map(|dependency| text(member(mapping(dependency), "pkg")).to_owned())
            .collect();
        assert!(dependencies.insert(id, deps).is_none());
    }

    let prohibited = BTreeSet::from([
        "hell-builtins",
        "hell-ci",
        "hell-cli",
        "hell-compiler",
        "hell-core",
        "hell-digest",
        "hell-docgen",
        "hell-eval",
        "hell-runtime",
        "hell-source",
        "hell-syntax",
        "hell-testkit",
    ]);
    let verifier_id = verifier_id.expect("independent verifier package must exist");
    let mut pending = vec![verifier_id];
    let mut reached = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !reached.insert(id.clone()) {
            continue;
        }
        let name = package_names
            .get(&id)
            .unwrap_or_else(|| panic!("resolved package {id:?} lacks metadata"));
        assert!(
            !prohibited.contains(name.as_str()),
            "independent verifier reaches prohibited package {name}"
        );
        pending.extend(
            dependencies
                .get(&id)
                .unwrap_or_else(|| panic!("resolved package {id:?} lacks a dependency node"))
                .iter()
                .cloned(),
        );
    }
    assert!(reached.len() > 1, "dependency graph traversal was vacuous");
}
