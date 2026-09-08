//! Explicit in-memory HTTP boundary fixture, compiled only for unit tests.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl Request {
    pub fn observed(
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Self {
        let supplied_header_count = headers.len();
        let mut headers = headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_owned()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            headers.len(),
            supplied_header_count,
            "duplicate fixture request header"
        );
        if let Some(value) = content_type {
            assert!(
                headers
                    .insert("content-type".to_owned(), value.to_owned())
                    .is_none(),
                "duplicate fixture Content-Type"
            );
        }
        Self {
            method: method.to_owned(),
            url: url.to_owned(),
            headers,
            body: body.map(<[u8]>::to_vec),
        }
    }

    pub fn github(
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Self {
        let url = if path.starts_with("https://") {
            path.to_owned()
        } else {
            format!("https://api.github.com{path}")
        };
        Self::observed(
            method,
            &url,
            &[
                ("Authorization", "Bearer test-token"),
                ("Accept", "application/vnd.github+json"),
                ("X-GitHub-Api-Version", "2026-03-10"),
                ("User-Agent", "hell-ci"),
            ],
            content_type,
            body,
        )
    }

    pub fn path(&self) -> &str {
        self.url
            .strip_prefix("https://api.github.com")
            .or_else(|| self.url.strip_prefix("https://uploads.github.com"))
            .expect("fixture request uses exact trusted origin")
    }

    pub fn display(&self) -> String {
        format!(
            "{} {} HTTP/1.1\r\n\r\n{}",
            self.method,
            self.path(),
            String::from_utf8_lossy(self.body.as_deref().unwrap_or_default())
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Outcome {
    Response { status: u16, body: Vec<u8> },
    Disconnected,
}
impl Outcome {
    pub fn response(status: u16, body: impl AsRef<[u8]>) -> Self {
        assert!((100..=599).contains(&status));
        Self::Response {
            status,
            body: body.as_ref().to_vec(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Transcript(Rc<RefCell<State>>);
struct State {
    pending: VecDeque<(Request, Outcome)>,
    observed: Vec<Request>,
}
impl Transcript {
    pub fn new(exchanges: Vec<(Request, Outcome)>) -> Self {
        assert!(exchanges.len() <= 1024, "fixture request bound");
        Self(Rc::new(RefCell::new(State {
            pending: exchanges.into(),
            observed: Vec::new(),
        })))
    }
    pub fn request(&self, request: Request) -> Result<(u16, Vec<u8>), String> {
        let mut state = self.0.borrow_mut();
        assert!(state.observed.len() < 1024, "fixture request bound");
        state.observed.push(request.clone());
        let (expected, outcome) = state
            .pending
            .pop_front()
            .expect("unexpected GitHub request: transcript exhausted");
        assert_eq!(
            request, expected,
            "GitHub fixture request differs (method, exact URL/query, headers or body)"
        );
        match outcome {
            Outcome::Response { status, body } => Ok((status, body)),
            Outcome::Disconnected => Err(
                "GitHub API request failed: fixture disconnected after remote mutation".to_owned(),
            ),
        }
    }
    pub fn finish(&self) {
        assert!(
            self.0.borrow().pending.is_empty(),
            "GitHub fixture contains unconsumed exchanges"
        );
    }
    pub fn observed(&self) -> Vec<Request> {
        self.0.borrow().observed.clone()
    }
}
