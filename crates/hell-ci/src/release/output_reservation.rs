use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(super) struct PrerequisiteOutput {
    root: PathBuf,
    #[cfg(unix)]
    identity: (u64, u64),
    #[cfg(windows)]
    identity: std::sync::Arc<same_file::Handle>,
}

impl PrerequisiteOutput {
    /// Called after task acquisition, lease and canary validation.
    pub(super) fn bind(root: &Path) -> Result<Self, String> {
        require_directory(root)?;
        let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
        inspect_inventory(&root)?;
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::symlink_metadata(&root).map_err(|error| error.to_string())?;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(windows)]
        let identity = std::sync::Arc::new(
            same_file::Handle::from_path(&root).map_err(|error| error.to_string())?,
        );
        Ok(Self { root, identity })
    }

    fn revalidate(&self) -> Result<(), String> {
        require_directory(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::symlink_metadata(&self.root).map_err(|error| error.to_string())?;
            if (metadata.dev(), metadata.ino()) != self.identity {
                return Err("qualified evidence directory identity changed".to_owned());
            }
        }
        #[cfg(windows)]
        if same_file::Handle::from_path(&self.root).map_err(|error| error.to_string())?
            != *self.identity
        {
            return Err("qualified evidence directory identity changed".to_owned());
        }
        inspect_inventory(&self.root)
    }
}

fn require_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_dir() || redirected(&metadata) {
        return Err(format!(
            "{} is not a direct directory authority",
            path.display()
        ));
    }
    Ok(())
}

fn redirected(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    metadata.file_type().is_symlink()
}

fn inspect_inventory(root: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if redirected(&metadata) || (!metadata.is_dir() && !metadata.is_file()) {
                return Err(
                    "prerequisite evidence contains a redirected or nonregular entry".to_owned(),
                );
            }
            if directory == root {
                let allowed = if metadata.is_dir() {
                    matches!(
                        entry.file_name().to_str(),
                        Some(
                            "raw"
                                | "normalized"
                                | "adapters"
                                | "frontend"
                                | "qualification-artifacts"
                        )
                    )
                } else {
                    matches!(
                        entry.file_name().to_str(),
                        Some(
                            "acquisition.json"
                                | "release-manifest.json"
                                | "publication-report.json"
                                | "runtime-manifest.json"
                                | "package-inspect.json"
                                | "package-verify.json"
                                | "doctor.json"
                                | "canaries.json"
                                | "provider-lease.json"
                                | "pre-install-footprint.json"
                        )
                    )
                };
                if !allowed {
                    return Err("prerequisite evidence contains stale or unknown output".to_owned());
                }
            }
            if (directory == root.join("raw") || directory == root.join("normalized"))
                && (metadata.is_dir() || entry.file_name() != "provider-adoption-canary.json")
            {
                return Err("prerequisite evidence already contains operation reports".to_owned());
            }
            if directory == root.join("adapters") {
                return Err("prerequisite evidence already contains operation adapters".to_owned());
            }
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(())
}

pub(super) fn reserve(
    output: &Path,
    prerequisite: Option<&PrerequisiteOutput>,
) -> Result<(), String> {
    if let Some(prerequisite) = prerequisite {
        prerequisite.revalidate()?;
        require_directory(output)?;
        let output = fs::canonicalize(output).map_err(|error| error.to_string())?;
        if prerequisite.root != output.join("memcordon") {
            return Err(
                "qualified task evidence is not the platform output's direct memcordon child"
                    .to_owned(),
            );
        }
        let mut count = 0;
        for entry in fs::read_dir(&output).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            if entry.file_name() != "memcordon" {
                return Err("platform output contains stale payload or unknown entries".to_owned());
            }
            count += 1;
        }
        if count != 1 {
            return Err("platform prerequisite inventory is not exact".to_owned());
        }
    } else {
        match fs::symlink_metadata(output) {
            Ok(_) => return Err("platform output already exists".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect platform output: {error}")),
        }
        if let Some(parent) = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        fs::create_dir(output)
            .map_err(|error| format!("cannot reserve platform output: {error}"))?;
    }
    for name in [
        "archive",
        "conformance-evidence",
        "conformance-observations",
    ] {
        fs::create_dir(output.join(name))
            .map_err(|error| format!("cannot reserve fresh platform payload {name}: {error}"))?;
    }
    Ok(())
}

pub(crate) fn reserve_for_integration(
    output: &Path,
    prerequisite: Option<&Path>,
) -> Result<(), String> {
    let prerequisite = prerequisite.map(PrerequisiteOutput::bind).transpose()?;
    reserve(output, prerequisite.as_ref())
}
