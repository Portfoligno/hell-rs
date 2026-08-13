use std::fmt;

use hell_builtins::CompatibilityDimension;

use crate::json::{JsonValue, json_member, require_exact_json_keys};
use crate::release::schema::{object, string};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ProfileId {
    Upstream,
    Sandboxed,
}

impl ProfileId {
    pub(crate) const ALL: [Self; 2] = [Self::Upstream, Self::Sandboxed];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Sandboxed => "sandboxed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "upstream" => Ok(Self::Upstream),
            "sandboxed" => Ok(Self::Sandboxed),
            _ => Err(format!("unknown conformance profile {value:?}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ConformancePlatform {
    LinuxX86_64,
    MacosAarch64,
    WindowsX86_64,
}

impl ConformancePlatform {
    pub(crate) const ALL: [Self; 3] = [Self::LinuxX86_64, Self::MacosAarch64, Self::WindowsX86_64];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-x86_64",
            Self::MacosAarch64 => "macos-aarch64",
            Self::WindowsX86_64 => "windows-x86_64",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "linux-x86_64" => Ok(Self::LinuxX86_64),
            "macos-aarch64" => Ok(Self::MacosAarch64),
            "windows-x86_64" => Ok(Self::WindowsX86_64),
            _ => Err(format!("unknown conformance platform {value:?}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CellKey {
    pub(crate) builtin: String,
    pub(crate) dimension: CompatibilityDimension,
    pub(crate) profile: ProfileId,
    pub(crate) platform: ConformancePlatform,
}

impl CellKey {
    pub(crate) fn new(
        builtin: impl Into<String>,
        dimension: CompatibilityDimension,
        profile: ProfileId,
        platform: ConformancePlatform,
    ) -> Result<Self, String> {
        let builtin = builtin.into();
        if builtin.is_empty() || builtin.contains("::") || builtin.contains(['\0', '\n', '\r']) {
            return Err("builtin ID is empty or unsafe for a canonical cell ID".to_owned());
        }
        Ok(Self {
            builtin,
            dimension,
            profile,
            platform,
        })
    }

    pub(crate) fn canonical_id(&self) -> String {
        format!(
            "{}::{}::{}::{}",
            self.builtin,
            self.dimension.as_str(),
            self.profile.as_str(),
            self.platform.as_str()
        )
    }

    pub(crate) fn json(&self) -> JsonValue {
        object([
            ("builtin", string(&self.builtin)),
            ("dimension", string(self.dimension.as_str())),
            ("platform", string(self.platform.as_str())),
            ("profile", string(self.profile.as_str())),
        ])
    }

    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let object = value.object()?;
        require_exact_json_keys(object, &["builtin", "dimension", "platform", "profile"])?;
        Self::new(
            json_member(object, "builtin")?.string()?,
            parse_dimension(json_member(object, "dimension")?.string()?)?,
            ProfileId::parse(json_member(object, "profile")?.string()?)?,
            ConformancePlatform::parse(json_member(object, "platform")?.string()?)?,
        )
    }
}

impl fmt::Display for CellKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical_id())
    }
}

fn parse_dimension(value: &str) -> Result<CompatibilityDimension, String> {
    CompatibilityDimension::ALL
        .into_iter()
        .find(|dimension| dimension.as_str() == value)
        .ok_or_else(|| format!("unknown compatibility dimension {value:?}"))
}

// `CompatibilityDimension` is a registry-order enum but deliberately does not
// expose ordering: the release order is its explicit `ALL` array.
impl Ord for CellKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.builtin
            .cmp(&other.builtin)
            .then_with(|| dimension_index(self.dimension).cmp(&dimension_index(other.dimension)))
            .then_with(|| self.profile.cmp(&other.profile))
            .then_with(|| self.platform.cmp(&other.platform))
    }
}

impl PartialOrd for CellKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn dimension_index(dimension: CompatibilityDimension) -> usize {
    CompatibilityDimension::ALL
        .iter()
        .position(|candidate| *candidate == dimension)
        .expect("dimension belongs to the canonical enum")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_key_round_trips_and_rejects_delimiter_in_builtin() {
        let key = CellKey::new(
            "Bool.bool",
            CompatibilityDimension::PureRuntime,
            ProfileId::Upstream,
            ConformancePlatform::LinuxX86_64,
        )
        .unwrap();
        assert_eq!(
            key.canonical_id(),
            "Bool.bool::pure-runtime::upstream::linux-x86_64"
        );
        assert_eq!(CellKey::parse(&key.json()).unwrap(), key);
        assert!(
            CellKey::new(
                "unsafe::builtin",
                CompatibilityDimension::Parse,
                ProfileId::Upstream,
                ConformancePlatform::LinuxX86_64,
            )
            .is_err()
        );
    }
}
