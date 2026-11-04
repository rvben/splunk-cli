use crate::{
    Error, Result,
    config::{Settings, validate_segment},
};
use base64::Engine;
use reqwest::{
    Method, Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde_json::{Value, json};
use std::time::Duration;

/// Deliberately has no Debug implementation, so credentials cannot be logged.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Credentials {
    Bearer(String),
    Session(String),
    Basic(String, String),
}
impl Credentials {
    pub fn from_env() -> Result<Self> {
        Self::optional_from_env()?.ok_or_else(|| Error::new("auth", "No complete credentials configured").hint("Run splunk-cli auth login or set SPLUNK_TOKEN, SPLUNK_SESSION_KEY, or both SPLUNK_USERNAME and SPLUNK_PASSWORD"))
    }

    pub fn optional_from_env() -> Result<Option<Self>> {
        let get = |name| std::env::var(name).ok().filter(|s| !s.is_empty());
        let token = get("SPLUNK_TOKEN");
        let session = get("SPLUNK_SESSION_KEY");
        let user = get("SPLUNK_USERNAME");
        let password = get("SPLUNK_PASSWORD");
        let methods = usize::from(token.is_some())
            + usize::from(session.is_some())
            + usize::from(user.is_some() || password.is_some());
        if methods > 1 {
            return Err(Error::usage(
                "Set only one authentication method: SPLUNK_TOKEN, SPLUNK_SESSION_KEY, or SPLUNK_USERNAME / SPLUNK_PASSWORD",
            ));
        }
        if methods == 0 {
            return Ok(None);
        }
        match (token, session, user, password) {
            (Some(token), _, _, _) => Ok(Some(Self::Bearer(token))),
            (_, Some(session), _, _) => Ok(Some(Self::Session(session))),
            (_, _, Some(user), Some(password)) => Ok(Some(Self::Basic(user, password))),
            _ => Err(Error::new("auth", "Incomplete environment credentials").hint("Set both SPLUNK_USERNAME and SPLUNK_PASSWORD, or unset them to use saved credentials")),
        }
    }

    fn redact(&self, text: &str) -> String {
        let secrets = match self {
            Self::Bearer(token) | Self::Session(token) => vec![token.clone()],
            Self::Basic(user, password) => vec![
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}")),
                password.clone(),
            ],
        };
        secrets.into_iter().fold(text.into(), |s, secret| {
            if secret.is_empty() {
                s
            } else {
                s.replace(&secret, "[REDACTED]")
            }
        })
    }
}

#[derive(Default)]
struct Warnings {
    seen: std::collections::HashSet<String>,
    suppressed: bool,
}

pub struct Client {
    http: reqwest::Client,
    pub settings: Settings,
    credentials: Credentials,
    /// Set when the credentials were saved by `auth login`, so auth failures say how to recover.
    relogin_hint: bool,
    warnings: std::sync::Mutex<Warnings>,
}

pub fn endpoint(settings: &Settings, namespaced: bool, segments: &[&str]) -> Result<Url> {
    for segment in segments {
        validate_segment(segment, "resource identifier")?;
    }
    let mut url = settings.url.clone();
    let mut path = url
        .path_segments_mut()
        .map_err(|_| Error::usage("Invalid base URL"))?;
    path.pop_if_empty();
    if namespaced {
        path.extend(["servicesNS", &settings.owner, &settings.app]);
    } else {
        path.push("services");
    }
    path.extend(segments);
    drop(path);
    Ok(url)
}

impl Client {
    pub fn new(settings: Settings, credentials: Credentials) -> Result<Self> {
        let host = settings.url.host_str().unwrap_or_default();
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if settings.url.scheme() == "http" && !loopback && !settings.allow_http {
            return Err(Error::usage(
                "Sending credentials over HTTP requires explicit --allow-http; use HTTPS when possible",
            ));
        }
        let mut headers = HeaderMap::new();
        match &credentials {
            Credentials::Bearer(value) | Credentials::Session(value) => {
                let prefix = if matches!(credentials, Credentials::Bearer(_)) {
                    "Bearer"
                } else {
                    "Splunk"
                };
                let mut header = HeaderValue::from_str(&format!("{prefix} {value}"))
                    .map_err(|_| Error::usage("Invalid authentication header value"))?;
                header.set_sensitive(true);
                headers.insert(AUTHORIZATION, header);
            }
            Credentials::Basic(_, _) => {}
        }
        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .user_agent(concat!("splunk-cli/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(settings.timeout))
            .connect_timeout(Duration::from_secs(settings.timeout.min(10)))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .danger_accept_invalid_certs(settings.insecure);
        if let Some(path) = &settings.ca_cert {
            let pem = std::fs::read(path).map_err(|error| crate::config::ca_error(path, error))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| Error::usage("CA certificate must contain PEM certificates"))?;
            if certs.is_empty() {
                return Err(Error::usage("CA certificate file contains no certificates"));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder
            .build()
            .map_err(|_| Error::new("transport", "Cannot initialize the HTTP client"))?;
        Ok(Self {
            http,
            settings,
            credentials,
            relogin_hint: false,
            warnings: Default::default(),
        })
    }

    pub fn with_relogin_hint(mut self) -> Self {
        self.relogin_hint = true;
        self
    }

    pub async fn request(
        &self,
        method: Method,
        namespaced: bool,
        segments: &[&str],
        params: &[(String, String)],
    ) -> Result<Value> {
        self.request_inner(method, namespaced, segments, params, false)
            .await
    }

    pub async fn text(&self, namespaced: bool, segments: &[&str]) -> Result<String> {
        self.request_inner(Method::GET, namespaced, segments, &[], true)
            .await?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(Error::invalid_response)
    }

    async fn request_inner(
        &self,
        method: Method,
        namespaced: bool,
        segments: &[&str],
        params: &[(String, String)],
        raw: bool,
    ) -> Result<Value> {
        let url = endpoint(&self.settings, namespaced, segments)?;
        let mut request = self.http.request(method.clone(), url);
        if let Credentials::Basic(user, password) = &self.credentials {
            request = request.basic_auth(user, Some(password));
        }
        let mut params = params.to_vec();
        if !raw {
            params.push(("output_mode".into(), "json".into()));
        }
        request = if method == Method::POST {
            request.form(&params)
        } else {
            request.query(&params)
        };
        let mut attempt = 0;
        let response = loop {
            let response = request
                .try_clone()
                .ok_or_else(|| Error::new("transport", "Cannot prepare request"))?
                .send()
                .await
                .map_err(network_error)?;
            // Only replay reads: even a failed dispatch may have created a job.
            if method == Method::GET
                && attempt < 2
                && matches!(response.status().as_u16(), 429 | 502 | 503 | 504)
            {
                let delay = match response.headers().get("retry-after") {
                    Some(value) => value
                        .to_str()
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|v| *v <= 2)
                        .map(Duration::from_secs),
                    None => Some(Duration::from_millis(250 * (1 << attempt))),
                };
                if let Some(delay) = delay {
                    attempt += 1;
                    drop(response);
                    tokio::time::sleep(delay).await;
                    continue;
                }
            }
            break response;
        };
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        // Read incrementally to enforce a hard bound even if Content-Length is absent.
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(network_error)? {
            if body.len() + chunk.len() > 32 * 1024 * 1024 {
                return Err(Error::new(
                    "invalid_response",
                    "Splunk response exceeded 32 MiB; reduce --limit or select --fields",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let parsed = serde_json::from_slice::<Value>(&body);
        if !status.is_success() {
            let kind = match status.as_u16() {
                401 | 403 => "auth",
                404 => "not_found",
                409 => "conflict",
                429 => "rate_limit",
                400 => "usage",
                _ => "api",
            };
            let message = parsed
                .as_ref()
                .ok()
                .and_then(|v| v["messages"].as_array())
                .and_then(|a| a.first())
                .and_then(|v| v["text"].as_str());
            let message = message
                .map(|s| self.credentials.redact(s))
                .unwrap_or_else(|| format!("Splunk returned HTTP {}", status.as_u16()));
            let mut details = json!({"http_status": status.as_u16()});
            if let Some(delay) = retry_after {
                details["retry_after"] = json!(
                    self.credentials
                        .redact(&delay)
                        .chars()
                        .take(256)
                        .collect::<String>()
                );
            }
            let mut error =
                Error::new(kind, message.chars().take(2048).collect::<String>()).details(details);
            error.hint = match status.as_u16() {
                401 if self.relogin_hint => Some("The saved credentials expired or were revoked; run splunk-cli auth login".into()),
                401 => Some("Run splunk-cli auth login; expired or revoked credentials need replacing. Check environment credentials, which override the saved login.".into()),
                403 => Some("Check your Splunk role permissions for this API and the selected --app / --owner.".into()),
                _ => None,
            };
            return Err(error);
        }
        if raw {
            let text = std::str::from_utf8(&body).map_err(|_| Error::invalid_response())?;
            return Ok(json!(self.credentials.redact(text)));
        }
        if body.is_empty() {
            return Ok(json!({}));
        }
        let value = parsed.map_err(|_| Error::invalid_response())?;
        if let Some(messages) = value["messages"].as_array() {
            for message in messages.iter().filter(|m| m["type"] == "WARN") {
                if let Some(text) = message["text"].as_str() {
                    let text: String = self.credentials.redact(text).chars().take(2048).collect();
                    let mut seen = self
                        .warnings
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if seen.seen.contains(&text) {
                        continue;
                    }
                    if seen.seen.len() >= 64 {
                        if !seen.suppressed {
                            seen.suppressed = true;
                            crate::output::diagnostic(format_args!(
                                "Warning: additional Splunk warnings suppressed after 64 distinct messages"
                            ));
                        }
                        continue;
                    }
                    seen.seen.insert(text.clone());
                    drop(seen);
                    crate::output::diagnostic(format_args!(
                        "Warning: {}",
                        crate::output::terminal(&text)
                    ));
                }
            }
        }
        if let Some(message) = value["messages"].as_array().and_then(|messages| {
            messages
                .iter()
                .find(|m| matches!(m["type"].as_str(), Some("ERROR" | "FATAL")))
        }) {
            let text = message["text"]
                .as_str()
                .unwrap_or("Splunk reported an error in the response");
            return Err(Error::new(
                "api",
                self.credentials
                    .redact(text)
                    .chars()
                    .take(2048)
                    .collect::<String>(),
            ));
        }
        Ok(value)
    }
}

fn network_error(error: reqwest::Error) -> Error {
    if error.is_timeout() {
        Error::new(
            "timeout",
            "Splunk request timed out; a submitted job may still be running",
        )
    } else {
        Error::new(
            "transport",
            "Cannot communicate with Splunk; check the management URL, network, and TLS certificate",
        )
    }
}
