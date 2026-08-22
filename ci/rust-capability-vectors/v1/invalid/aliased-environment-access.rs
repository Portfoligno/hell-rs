use std::env as ambient_environment;

fn unapproved_read() {
    let _ = ambient_environment::var_os("GITHUB_EVENT_PATH");
}
