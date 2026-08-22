mod capability_bridge {
    pub(crate) use std::env::var;
}

fn unapproved_read() {
    let _ = capability_bridge::var("GITHUB_REPOSITORY_ID");
}
