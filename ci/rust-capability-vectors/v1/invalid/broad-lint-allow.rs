#![allow(clippy::all)]

fn unapproved_read() {
    let _ = std::env::var("GITHUB_WORKFLOW_SHA");
}
