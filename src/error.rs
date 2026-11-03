use serde_json::{Value, json};
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// Each kind has a distinct, stable process exit code.
pub const KINDS: &[(&str, u8, bool, &str)] = &[
    ("usage", 2, false, "Invalid arguments or configuration."),
    (
        "auth",
        3,
        false,
        "Authentication failed or permission was denied.",
    ),
    (
        "not_found",
        4,
        false,
        "The requested resource does not exist.",
    ),
    (
        "api",
        5,
        false,
        "Splunk rejected the request or the search failed.",
    ),
    ("rate_limit", 6, true, "Splunk rate limited the request."),
    (
        "conflict",
        7,
        false,
        "Resource state conflicts with the request.",
    ),
    (
        "confirmation_required",
        8,
        false,
        "Explicit --yes is required.",
    ),
    (
        "timeout",
        9,
        false,
        "A request or wait timed out; a submitted job may still exist.",
    ),
    (
        "transport",
        10,
        false,
        "Connection or TLS failure; a submitted request may have succeeded.",
    ),
    (
        "invalid_response",
        11,
        false,
        "Splunk returned an unexpected response.",
    ),
    ("io", 12, false, "Local filesystem or output failure."),
];

#[derive(Debug)]
pub struct Error {
    pub kind: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub details: Value,
}

impl Error {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
            details: json!({}),
        }
    }
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new("usage", message)
    }
    pub fn invalid_response() -> Self {
        Self::new(
            "invalid_response",
            "Splunk returned an unexpected response; check the management URL and API compatibility",
        )
    }
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
    pub fn details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }
    pub fn exit_code(&self) -> u8 {
        KINDS
            .iter()
            .find(|k| k.0 == self.kind)
            .expect("known error kind")
            .1
    }
    pub fn envelope(&self) -> Value {
        let mut value = json!({"error": {"kind": self.kind, "message": self.message, "exit_code": self.exit_code()}});
        if let Some(hint) = &self.hint {
            value["error"]["hint"] = json!(hint);
        }
        if self.details != json!({}) {
            value["error"]["details"] = self.details.clone();
        }
        value
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new("io", error.to_string())
    }
}
