use std::env;

use crate::Failure;

pub struct Credential {
    value: Vec<u8>,
}

pub struct GithubRuntime {
    credential: Credential,
}

impl Credential {
    pub(crate) fn expose(&self) -> &str {
        std::str::from_utf8(&self.value).expect("credential originated as UTF-8")
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.value.fill(0);
    }
}

impl GithubRuntime {
    pub(crate) fn from_process() -> Result<Self, Failure> {
        let value = env::var("GITHUB_TOKEN").map_err(|_| {
            Failure::new(
                "publisher.credential.unavailable",
                "native GITHUB_TOKEN credential is unavailable",
            )
        })?;
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(Failure::new(
                "publisher.credential.invalid",
                "native GITHUB_TOKEN credential is empty or malformed",
            ));
        }
        Ok(Self {
            credential: Credential {
                value: value.into_bytes(),
            },
        })
    }

    pub(crate) const fn credential(&self) -> &Credential {
        &self.credential
    }
}
