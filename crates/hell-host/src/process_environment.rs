use std::ffi::OsString;

/// The single sealed authority for capturing the native host environment.
pub(crate) struct ProcessEnvironment {
    entries: Vec<(OsString, OsString)>,
}

impl ProcessEnvironment {
    pub(crate) fn from_process() -> Self {
        Self {
            entries: std::env::vars_os().collect(),
        }
    }

    pub(crate) fn into_entries(self) -> Vec<(OsString, OsString)> {
        self.entries
    }
}
