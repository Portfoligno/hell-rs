#![cfg(unix)]

use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use hell_ci::provider_evidence::{Captured, retain_json_command};

#[test]
fn doctor_json_is_retained_before_success_or_failure_validation() {
    let root = std::env::temp_dir().join(format!("hell-doctor-evidence-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    for (name, status) in [("failed", 125), ("success", 0)] {
        let captured = Captured {
            status: ExitStatus::from_raw(status << 8),
            stdout: if status == 0 {
                br#"{"requirement":{"met":true}}"#.to_vec()
            } else {
                br#"{"requirement":{"met":false},"reason":"provider unreachable"}"#.to_vec()
            },
            stderr: Vec::new(),
            stdout_overflow: false,
            stderr_overflow: false,
        };
        let prefix = root.join(name).join("doctor");
        let result = retain_json_command(&prefix, &captured, "doctor --require sealed");
        assert_eq!(result.is_ok(), status == 0);
        if let Err(error) = result {
            assert!(error.contains("retained command stdout"));
        }
        assert_eq!(
            fs::read(prefix.with_extension("stdout")).unwrap(),
            captured.stdout
        );
        assert!(
            fs::read(prefix.with_extension("stderr"))
                .unwrap()
                .is_empty()
        );
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(prefix.with_extension("json")).unwrap()).unwrap();
        assert_eq!(receipt["exitCode"], status);
    }
    fs::remove_dir_all(root).unwrap();
}
