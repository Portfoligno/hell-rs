use hell_memcordon::{RuntimeManifest, validate_component_inventory};

fn manifest(component_path: &str) -> Vec<u8> {
    format!(
        r#"{{
  "schema_version": 1,
  "version": "0.5.2-rc.23",
  "source_commit": "67aa1f74d9a76713ab343ea2afbe6403da7429b7",
  "target": "x86_64-pc-windows-msvc",
  "archive_sha256": "{digest}",
  "components": [{{
    "name": "memcordon.exe",
    "path": "{component_path}",
    "bytes": 1024,
    "sha256": "{digest}",
    "executable": true
  }}]
}}"#,
        digest = "a".repeat(64),
    )
    .into_bytes()
}

#[test]
fn runtime_manifest_rejects_traversal_and_missing_components() {
    assert!(RuntimeManifest::parse(&manifest("../memcordon.exe")).is_err());
    let parsed = RuntimeManifest::parse(&manifest("bin/memcordon.exe"))
        .expect("safe runtime manifest should parse");
    assert!(
        validate_component_inventory(
            &parsed,
            &[
                "memcordon.exe".to_owned(),
                "memcordon-sealed-agent.exe".to_owned()
            ]
        )
        .is_err()
    );
}
