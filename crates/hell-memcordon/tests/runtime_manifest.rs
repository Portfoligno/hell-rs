use hell_memcordon::{Platform, RuntimeLock, RuntimeManifest, validate_component_inventory};
use serde_json::{Value, json};

const LINUX: &[u8] = include_bytes!("fixtures/runtime-manifest-linux.json");
const WINDOWS: &[u8] = include_bytes!("fixtures/runtime-manifest-windows.json");

#[test]
fn pinned_runtime_manifests_match_lock_component_paths() {
    let lock = RuntimeLock::parse(include_str!("../../../ci/memcordon-runtime-v1.toml")).unwrap();
    for (bytes, platform) in [
        (LINUX, Platform::LinuxX86_64),
        (WINDOWS, Platform::WindowsX86_64),
    ] {
        let manifest = RuntimeManifest::parse(bytes).expect("pinned producer manifest");
        let asset = lock.asset(platform).unwrap();
        assert_eq!(manifest.target, asset.target);
        validate_component_inventory(&manifest, &asset.required_components)
            .expect("lock filenames resolve to producer paths, not role ids");
        assert!(validate_component_inventory(&manifest, &["missing".to_owned()]).is_err());
    }
}

#[test]
fn runtime_manifest_rejects_authority_structure_and_component_drift() {
    for (pointer, replacement) in [
        ("/schema_version", json!(2)),
        ("/project", json!("another-project")),
        ("/version", json!("0.5.2")),
        ("/source_commit", json!("wrong-source")),
        ("/target", json!("unsupported-target")),
        ("/components/0/id", json!("sealed-agent")),
        ("/components/0/path", json!("../memcordon")),
        ("/components/0/role", json!("sealed-agent")),
        ("/components/0/role", json!("unknown-role")),
        ("/components/0/size", json!(0)),
        (
            "/components/0/size",
            json!(hell_memcordon::MAX_EXECUTABLE_BYTES + 1),
        ),
        ("/components/0/mode", json!(0o777)),
        ("/components/0/sha256", json!("invalid-digest")),
        ("/sealed/state", json!("not-applicable")),
        ("/sealed/agent_component", json!("public-cli")),
        ("/sealed/provider_protocol", json!(99)),
        ("/sealed/mechanism", json!("unknown-mechanism")),
        ("/sealed/execution_report_schema", json!(7)),
        ("/sealed/plan_report_schema", json!(6)),
        ("/sealed/doctor_report_schema", json!(4)),
        ("/sealed/qualification_schema", json!(1)),
    ] {
        for bytes in [LINUX, WINDOWS] {
            let mut manifest: Value = serde_json::from_slice(bytes).unwrap();
            *manifest.pointer_mut(pointer).unwrap() = replacement.clone();
            assert!(
                RuntimeManifest::parse(&serde_json::to_vec(&manifest).unwrap()).is_err(),
                "accepted drift at {pointer}"
            );
        }
    }
    for bytes in [LINUX, WINDOWS] {
        for pointer in ["", "/components/0", "/sealed"] {
            let mut manifest: Value = serde_json::from_slice(bytes).unwrap();
            manifest
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".to_owned(), json!(true));
            assert!(
                RuntimeManifest::parse(&serde_json::to_vec(&manifest).unwrap()).is_err(),
                "accepted unknown field at {pointer}"
            );
        }
        let mut manifest: Value = serde_json::from_slice(bytes).unwrap();
        manifest["components"][1] = manifest["components"][0].clone();
        assert!(RuntimeManifest::parse(&serde_json::to_vec(&manifest).unwrap()).is_err());
        manifest["components"].as_array_mut().unwrap().pop();
        assert!(RuntimeManifest::parse(&serde_json::to_vec(&manifest).unwrap()).is_err());
    }
}
