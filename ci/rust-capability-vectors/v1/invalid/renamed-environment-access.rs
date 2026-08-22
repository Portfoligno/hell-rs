use std::env::var as read_ambient_environment;

fn unapproved_read() {
    let _ = read_ambient_environment("GITHUB_SHA");
}
