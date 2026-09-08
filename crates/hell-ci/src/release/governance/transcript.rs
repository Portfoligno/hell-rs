//! Explicit mutation-test-only HTTP boundary transcript. Never compiled in production.

use std::collections::VecDeque;
use std::path::Path;

use serde::Deserialize;

use super::{ApiPolicy, Failure, TransportFailure, TransportResponse, read_bounded_regular};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    requests: VecDeque<Request>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    method: String,
    url: String,
    authorization_sha256: String,
    accept: String,
    api_version: String,
    user_agent: String,
    outcome: Outcome,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Outcome {
    Response { status: u16, body: Vec<u8> },
    Error { message: String },
}

pub(super) struct Transcript {
    requests: VecDeque<Request>,
}

impl Transcript {
    pub(super) fn read(path: &Path) -> Result<Self, Failure> {
        let bytes = read_bounded_regular(path, 8 * 1024 * 1024, "governance test transcript")
            .map_err(|error| Failure::new("governance.fixture.input", error))?;
        let document: Document = serde_json::from_slice(&bytes)
            .map_err(|error| Failure::new("governance.fixture.schema", error.to_string()))?;
        if document.schema_version != 1 || document.requests.len() > 64 {
            return Err(Failure::new(
                "governance.fixture.schema",
                "test transcript version or request count differs",
            ));
        }
        Ok(Self {
            requests: document.requests,
        })
    }

    pub(super) fn request(
        &mut self,
        url: &str,
        authorization: &str,
        api: &ApiPolicy,
    ) -> Result<TransportResponse, TransportFailure> {
        let expected = self.requests.pop_front().ok_or_else(|| {
            TransportFailure::Fixture(Failure::new(
                "governance.fixture.request",
                "test transcript has no expected request",
            ))
        })?;
        if expected.method != "GET"
            || expected.url != url
            || expected.authorization_sha256
                != hell_testkit::sha256_bytes(authorization.as_bytes()).hex()
            || expected.accept != api.accept
            || expected.api_version != api.api_version
            || expected.user_agent != api.user_agent
        {
            return Err(TransportFailure::Fixture(Failure::new(
                "governance.fixture.request",
                "test request method, URL or credential/header binding differs",
            )));
        }
        match expected.outcome {
            Outcome::Response { status, body } if (100..=599).contains(&status) => {
                Ok(TransportResponse {
                    status,
                    body: Ok(body),
                })
            }
            Outcome::Response { .. } => Err(TransportFailure::Fixture(Failure::new(
                "governance.fixture.schema",
                "test response status is invalid",
            ))),
            Outcome::Error { message } => Err(TransportFailure::Request(message)),
        }
    }

    pub(super) fn require_exhausted(&self) -> Result<(), Failure> {
        if !self.requests.is_empty() {
            return Err(Failure::new(
                "governance.fixture.unconsumed",
                "test transcript contains unconsumed requests",
            ));
        }
        Ok(())
    }
}
