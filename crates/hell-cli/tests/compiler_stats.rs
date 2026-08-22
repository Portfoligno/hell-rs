use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[test]
fn hidden_compiler_stats_emit_pinned_labels_in_order() {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "hell-rs-compiler-stats-{}-{sequence}.hell",
        std::process::id()
    ));
    fs::write(&path, "main = IO.pure ()\n").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell"));
    command.arg("--check").arg(&path).arg("--compiler-stats");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("supervise compiler-stats command");
    assert!(!output.timed_out, "compiler-stats command timed out");
    fs::remove_file(path).unwrap();

    assert!(
        output.status.success(),
        "compiler stats failed: {}",
        String::from_utf8_lossy(&output.stderr.retained_bytes())
    );
    assert_eq!(output.stderr.total_bytes, 0);
    let stdout = String::from_utf8(output.stdout.complete.expect("stdout capture is complete"))
        .expect("compiler-stats stdout is UTF-8");
    let labels = stdout
        .lines()
        .map(|line| {
            line.trim_start()
                .strip_prefix("stat: ")
                .and_then(|line| line.split_once(" = "))
                .map(|(label, _)| label)
                .expect("each compiler-stat line has the pinned structure")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        labels,
        [
            "read_file",
            "parse_module_with_mode",
            "resolve_module",
            "parse",
            "cycle_detect",
            "desugar",
            "elaborate",
            "unify",
            "zonk",
            "infer",
            "check",
        ]
    );
}
