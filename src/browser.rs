use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use reqwest::Method;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use crate::{
    Error, Result,
    client::{Client, Credentials},
    config::Settings,
};

const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
const BROWSER_START_TIMEOUT: Duration = Duration::from_secs(20);
const SESSION_CHECK_INTERVAL: Duration = Duration::from_millis(750);

/// A secret-free milestone reached during browser-session sign-in.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrowserProgress {
    StartingPrivateBrowser,
    PrivateBrowserOpened,
    WaitingForBrowserChannel,
    BrowserChannelReady,
    WaitingForSplunkPage,
    SplunkPageDetected,
    ReadingSessionCookies,
    SessionCookiesDetected,
    ValidatingSession,
    ValidationResponse(u16),
    SessionValidated,
}

impl BrowserProgress {
    /// Human-readable text that never contains browser or Splunk secrets.
    pub fn message(self) -> String {
        match self {
            Self::StartingPrivateBrowser => "starting a private browser".into(),
            Self::PrivateBrowserOpened => "private browser opened".into(),
            Self::WaitingForBrowserChannel => {
                "waiting for the localhost-only browser sign-in channel".into()
            }
            Self::BrowserChannelReady => "browser sign-in channel is ready".into(),
            Self::WaitingForSplunkPage => "waiting for an authenticated Splunk page".into(),
            Self::SplunkPageDetected => "authenticated Splunk page detected".into(),
            Self::ReadingSessionCookies => "checking Splunk-scoped session cookies".into(),
            Self::SessionCookiesDetected => "Splunk session cookies detected".into(),
            Self::ValidatingSession => {
                "validating the session with the Splunk management API".into()
            }
            Self::ValidationResponse(status) => {
                format!("management API validation returned HTTP {status}; continuing to wait")
            }
            Self::SessionValidated => "Splunk browser session validated".into(),
        }
    }
}

struct ProgressReporter<'a> {
    callback: &'a mut dyn FnMut(BrowserProgress),
    reported: HashSet<BrowserProgress>,
}

impl ProgressReporter<'_> {
    fn report(&mut self, progress: BrowserProgress) {
        if self.reported.insert(progress) {
            (self.callback)(progress);
        }
    }
}

/// Sign in through an isolated browser profile and return the Splunk session
/// key, validated against the management API.
pub async fn browser_login(
    settings: &Settings,
    preference: Option<OsString>,
    mut callback: impl FnMut(BrowserProgress),
) -> Result<String> {
    let mut progress = ProgressReporter {
        callback: &mut callback,
        reported: HashSet::new(),
    };
    let operation = async {
        match select_browser_backend(preference)? {
            BrowserBackend::Native(browser) => {
                native_browser_session(settings, browser, &mut progress).await
            }
            BrowserBackend::WindowsBridge(browser) => {
                let key = windows_browser_session(
                    settings.web_url.as_str(),
                    browser.as_deref(),
                    &mut progress,
                )
                .await?;
                progress.report(BrowserProgress::ValidatingSession);
                validate_session(settings, &key).await?;
                progress.report(BrowserProgress::SessionValidated);
                Ok(key)
            }
        }
    };
    tokio::time::timeout(LOGIN_TIMEOUT, operation)
        .await
        .map_err(|_| {
            Error::new("timeout", "Browser sign-in timed out after five minutes")
                .hint("Run auth login again to open a fresh private browser")
        })?
}

/// Confirm that the management API accepts the session key.
async fn validate_session(settings: &Settings, key: &str) -> Result<()> {
    Client::new(settings.clone(), Credentials::Session(key.into()))?
        .request(
            Method::GET,
            false,
            &["authentication", "current-context"],
            &[],
        )
        .await
        .map(drop)
}

#[derive(serde::Deserialize)]
struct BrowserSession {
    session_key: String,
}

async fn native_browser_session(
    settings: &Settings,
    browser: PathBuf,
    progress: &mut ProgressReporter<'_>,
) -> Result<String> {
    if is_firefox(&browser) {
        firefox_browser_session(settings, &browser, progress).await
    } else {
        chromium_browser_session(settings, &browser, progress).await
    }
}

async fn chromium_browser_session(
    settings: &Settings,
    browser: &Path,
    progress: &mut ProgressReporter<'_>,
) -> Result<String> {
    let private_mode = private_browsing_argument(browser);
    let profile = tempfile::tempdir().map_err(profile_error)?;
    progress.report(BrowserProgress::StartingPrivateBrowser);
    let child = spawn_browser(
        browser,
        [
            "--remote-debugging-port=0".into(),
            "--remote-debugging-address=127.0.0.1".into(),
            format!("--user-data-dir={}", profile.path().display()),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            "--disable-sync".into(),
            private_mode.into(),
            "--new-window".into(),
            settings.web_url.to_string(),
        ],
    )?;
    progress.report(BrowserProgress::PrivateBrowserOpened);
    let mut process = NativeBrowser { child, profile };
    progress.report(BrowserProgress::WaitingForBrowserChannel);
    let websocket_url = wait_for_debugger(&mut process).await?;
    progress.report(BrowserProgress::BrowserChannelReady);
    wait_for_cdp_session(&websocket_url, settings, Some(&mut process), progress).await
}

/// Firefox exposes WebDriver BiDi instead of CDP. Its BiDi server cannot read
/// cookies from private windows, so the sign-in runs in a normal window of a
/// throwaway profile that is deleted afterwards.
async fn firefox_browser_session(
    settings: &Settings,
    browser: &Path,
    progress: &mut ProgressReporter<'_>,
) -> Result<String> {
    let profile = firefox_profile().map_err(profile_error)?;
    std::fs::write(profile.path().join("user.js"), FIREFOX_PREFERENCES).map_err(profile_error)?;
    progress.report(BrowserProgress::StartingPrivateBrowser);
    let child = spawn_browser(
        browser,
        [
            "--remote-debugging-port=0".into(),
            "--profile".into(),
            profile.path().display().to_string(),
            "--no-remote".into(),
            settings.web_url.to_string(),
        ],
    )?;
    progress.report(BrowserProgress::PrivateBrowserOpened);
    let mut process = NativeBrowser { child, profile };
    progress.report(BrowserProgress::WaitingForBrowserChannel);
    let socket = wait_for_bidi_socket(&mut process).await?;
    let mut probe = BidiProbe::start(socket).await?;
    progress.report(BrowserProgress::BrowserChannelReady);
    let session =
        wait_for_browser_session(&mut probe, settings, Some(&mut process), progress).await;
    probe.close().await;
    session
}

fn profile_error(error: std::io::Error) -> Error {
    Error::new(
        "transport",
        format!("failed to create browser profile: {error}"),
    )
}

const FIREFOX_PREFERENCES: &str = r#"user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("signon.rememberSignons", false);
"#;

/// Snap-packaged Firefox has a private `/tmp`, so its profile must live in the
/// snap's own home directory to be visible to both processes.
fn firefox_profile() -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("splunk-cli-browser-");
    match dirs::home_dir()
        .map(|home| home.join("snap/firefox/common"))
        .filter(|directory| directory.is_dir())
    {
        Some(directory) => builder.tempdir_in(directory),
        None => builder.tempdir(),
    }
}

fn spawn_browser(browser: &Path, arguments: impl IntoIterator<Item = String>) -> Result<Child> {
    std::process::Command::new(browser)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            Error::new(
                "transport",
                format!("failed to start browser {}: {error}", browser.display()),
            )
        })
}

fn executable_name(browser: &Path) -> String {
    browser
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn is_firefox(browser: &Path) -> bool {
    executable_name(browser).contains("firefox")
}

fn private_browsing_argument(browser: &Path) -> &'static str {
    let executable = executable_name(browser);
    if executable.contains("msedge") || executable.contains("microsoft-edge") {
        "--inprivate"
    } else {
        "--incognito"
    }
}

struct NativeBrowser {
    child: Child,
    profile: tempfile::TempDir,
}

impl NativeBrowser {
    fn ensure_running(&mut self) -> Result<()> {
        match self.child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => Err(Error::new(
                "auth",
                format!("browser closed before Splunk sign-in completed ({status})"),
            )),
            Err(error) => Err(Error::new(
                "transport",
                format!("failed to inspect browser process: {error}"),
            )),
        }
    }
}

impl Drop for NativeBrowser {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_for_debugger(process: &mut NativeBrowser) -> Result<String> {
    let http = reqwest::Client::builder()
        // The debugging endpoint is private to this machine. Sending it to a
        // configured enterprise proxy can leak the browser control channel.
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| Error::new("transport", "Cannot initialize the HTTP client"))?;
    let started = Instant::now();
    loop {
        process.ensure_running()?;
        if let Ok(active_port) =
            std::fs::read_to_string(process.profile.path().join("DevToolsActivePort"))
            && let Some(port) = active_port.lines().next()
            && port.parse::<u16>().is_ok()
        {
            let endpoint = format!("http://127.0.0.1:{port}/json/version");
            if let Ok(response) = http.get(&endpoint).send().await
                && let Ok(document) = response.json::<Value>().await
                && let Some(url) = document.get("webSocketDebuggerUrl").and_then(Value::as_str)
            {
                return Ok(url.into());
            }
        }
        if started.elapsed() >= BROWSER_START_TIMEOUT {
            return Err(Error::new(
                "transport",
                "browser started but its private sign-in channel did not become available; set --browser (or SPLUNK_BROWSER) to Chrome, Edge, Chromium, or Firefox",
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_bidi_socket(process: &mut NativeBrowser) -> Result<BrowserSocket> {
    let started = Instant::now();
    loop {
        process.ensure_running()?;
        if let Ok(server) =
            std::fs::read_to_string(process.profile.path().join("WebDriverBiDiServer.json"))
            && let Ok(server) = serde_json::from_str::<Value>(&server)
            && let Some(port) = server
                .get("ws_port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
            && let Ok((socket, _)) = connect_async(format!("ws://127.0.0.1:{port}/session")).await
        {
            return Ok(socket);
        }
        if started.elapsed() >= BROWSER_START_TIMEOUT {
            return Err(Error::new(
                "transport",
                "Firefox started but its WebDriver BiDi sign-in channel did not become available; update Firefox or set --browser (or SPLUNK_BROWSER) to Chrome, Edge, or Chromium",
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

type BrowserSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Browser-protocol operations the sign-in loop needs from an open browser.
trait SessionProbe {
    type Page;

    /// Find a top-level page on the Splunk Web host and open it for inspection.
    async fn find_page(&mut self, host: &str) -> Result<Option<Self::Page>>;

    /// Cookies in the CDP `Network.getCookies` result shape.
    async fn cookies(&mut self, page: &Self::Page, web_url: &str) -> Result<Value>;

    async fn release(&mut self, page: Self::Page);
}

async fn wait_for_cdp_session(
    websocket_url: &str,
    settings: &Settings,
    process: Option<&mut NativeBrowser>,
    progress: &mut ProgressReporter<'_>,
) -> Result<String> {
    let (socket, _) = connect_async(websocket_url).await.map_err(|error| {
        Error::new(
            "transport",
            format!("failed to connect to browser: {error}"),
        )
    })?;
    let mut probe = CdpProbe { socket, id: 0 };
    wait_for_browser_session(&mut probe, settings, process, progress).await
}

async fn wait_for_browser_session<P: SessionProbe>(
    probe: &mut P,
    settings: &Settings,
    mut process: Option<&mut NativeBrowser>,
    progress: &mut ProgressReporter<'_>,
) -> Result<String> {
    let web_url = &settings.web_url;
    let host = web_url
        .host_str()
        .ok_or_else(|| Error::usage("Splunk Web URL has no hostname"))?;
    let is_https = web_url.scheme() == "https";
    let started = Instant::now();
    let mut last_stage = "the authenticated Splunk page";
    progress.report(BrowserProgress::WaitingForSplunkPage);

    loop {
        if let Some(process) = process.as_deref_mut() {
            process.ensure_running()?;
        }
        let Some(page) = probe.find_page(host).await? else {
            if started.elapsed() >= LOGIN_TIMEOUT {
                return Err(Error::new("auth", browser_timeout_message(last_stage)));
            }
            tokio::time::sleep(SESSION_CHECK_INTERVAL).await;
            continue;
        };
        progress.report(BrowserProgress::SplunkPageDetected);
        last_stage = "Splunk session cookies";
        progress.report(BrowserProgress::ReadingSessionCookies);
        let completed_session: Result<Option<String>> = async {
            let cookies = probe.cookies(&page, web_url.as_str()).await?;
            let Some(key) = splunk_session_key(&cookies, host, web_url.path(), is_https) else {
                return Ok(None);
            };
            progress.report(BrowserProgress::SessionCookiesDetected);
            last_stage = "Splunk management API session validation";
            progress.report(BrowserProgress::ValidatingSession);
            match validate_session(settings, &key).await {
                Ok(()) => {
                    progress.report(BrowserProgress::SessionValidated);
                    Ok(Some(key))
                }
                Err(error) if error.kind == "auth" => {
                    let status = error.details["http_status"]
                        .as_u64()
                        .and_then(|status| u16::try_from(status).ok())
                        .unwrap_or(401);
                    progress.report(BrowserProgress::ValidationResponse(status));
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        }
        .await;
        probe.release(page).await;
        if let Some(key) = completed_session? {
            return Ok(key);
        }
        if started.elapsed() >= LOGIN_TIMEOUT {
            return Err(Error::new("auth", browser_timeout_message(last_stage)));
        }
        tokio::time::sleep(SESSION_CHECK_INTERVAL).await;
    }
}

fn browser_timeout_message(stage: &str) -> String {
    format!(
        "browser sign-in timed out after five minutes while waiting for {stage}; no credential was stored"
    )
}

struct CdpProbe {
    socket: BrowserSocket,
    id: u64,
}

impl CdpProbe {
    async fn command(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<Value> {
        self.id += 1;
        let mut request = json!({"id": self.id, "method": method, "params": params});
        if let Some(session_id) = session_id {
            request["sessionId"] = Value::String(session_id.into());
        }
        browser_command(&mut self.socket, self.id, request).await
    }
}

impl SessionProbe for CdpProbe {
    /// The flattened CDP session attached to the Splunk page.
    type Page = String;

    async fn find_page(&mut self, host: &str) -> Result<Option<String>> {
        let targets = self.command("Target.getTargets", json!({}), None).await?;
        let Some(target_id) = splunk_page_target(&targets, host) else {
            return Ok(None);
        };
        let attached = self
            .command(
                "Target.attachToTarget",
                json!({"targetId": target_id, "flatten": true}),
                None,
            )
            .await?;
        attached
            .pointer("/result/sessionId")
            .and_then(Value::as_str)
            .map(|session_id| Some(session_id.to_string()))
            .ok_or_else(|| {
                Error::new(
                    "transport",
                    "browser did not open the private Splunk page session",
                )
            })
    }

    async fn cookies(&mut self, page: &String, web_url: &str) -> Result<Value> {
        let origin = reqwest::Url::parse(web_url)
            .map(|url| url.origin().ascii_serialization())
            .map_err(|_| Error::usage("Invalid Splunk Web URL"))?;
        self.command(
            "Network.getCookies",
            json!({"urls": [web_url, format!("{origin}/")]}),
            Some(page),
        )
        .await
    }

    async fn release(&mut self, page: String) {
        let _ = self
            .command("Target.detachFromTarget", json!({"sessionId": page}), None)
            .await;
    }
}

struct BidiProbe {
    socket: BrowserSocket,
    id: u64,
}

impl BidiProbe {
    async fn start(socket: BrowserSocket) -> Result<Self> {
        let mut probe = Self { socket, id: 0 };
        probe
            .command("session.new", json!({"capabilities": {}}))
            .await?;
        Ok(probe)
    }

    async fn command(&mut self, method: &str, params: Value) -> Result<Value> {
        self.id += 1;
        let request = json!({"id": self.id, "method": method, "params": params});
        browser_command(&mut self.socket, self.id, request).await
    }

    async fn close(mut self) {
        let _ = self.command("browser.close", json!({})).await;
    }
}

impl SessionProbe for BidiProbe {
    /// The top-level browsing context showing the Splunk page.
    type Page = String;

    async fn find_page(&mut self, host: &str) -> Result<Option<String>> {
        let tree = self.command("browsingContext.getTree", json!({})).await?;
        Ok(splunk_browsing_context(&tree, host))
    }

    async fn cookies(&mut self, page: &String, _web_url: &str) -> Result<Value> {
        let response = self
            .command(
                "storage.getCookies",
                json!({"partition": {"type": "context", "context": page}}),
            )
            .await?;
        Ok(bidi_cookie_document(&response))
    }

    async fn release(&mut self, _page: String) {}
}

fn splunk_page_target(document: &Value, host: &str) -> Option<String> {
    document
        .pointer("/result/targetInfos")?
        .as_array()?
        .iter()
        .find_map(|target| {
            let is_page = target.get("type").and_then(Value::as_str) == Some("page");
            let target_id = target.get("targetId").and_then(Value::as_str)?;
            let url = target.get("url").and_then(Value::as_str)?;
            (is_page && !target_id.is_empty() && url_has_host(url, host))
                .then(|| target_id.to_string())
        })
}

fn splunk_browsing_context(document: &Value, host: &str) -> Option<String> {
    document
        .pointer("/result/contexts")?
        .as_array()?
        .iter()
        .find_map(|context| {
            let id = context.get("context").and_then(Value::as_str)?;
            let url = context.get("url").and_then(Value::as_str)?;
            (!id.is_empty() && url_has_host(url, host)).then(|| id.to_string())
        })
}

fn url_has_host(url: &str, host: &str) -> bool {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(|value| value.eq_ignore_ascii_case(host)))
        .unwrap_or(false)
}

/// Map a WebDriver BiDi `storage.getCookies` reply onto the CDP cookie shape.
fn bidi_cookie_document(response: &Value) -> Value {
    let cookies = response
        .pointer("/result/cookies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|cookie| {
            let value = cookie.get("value")?;
            if value.get("type").and_then(Value::as_str) != Some("string") {
                return None;
            }
            Some(json!({
                "name": cookie.get("name")?,
                "value": value.get("value")?,
                "domain": cookie.get("domain")?,
                "path": cookie.get("path").cloned().unwrap_or_else(|| json!("/")),
                "secure": cookie.get("secure").cloned().unwrap_or(Value::Bool(false)),
                "expires": cookie.get("expiry").cloned().unwrap_or_else(|| json!(-1)),
            }))
        })
        .collect::<Vec<_>>();
    json!({"result": {"cookies": cookies}})
}

fn channel_error(error: impl std::fmt::Display) -> Error {
    Error::new(
        "transport",
        format!("browser session channel failed: {error}"),
    )
}

async fn browser_command(socket: &mut BrowserSocket, id: u64, request: Value) -> Result<Value> {
    socket
        .send(Message::Text(request.to_string().into()))
        .await
        .map_err(|error| {
            Error::new(
                "transport",
                format!("failed to query browser session: {error}"),
            )
        })?;
    while let Some(message) = socket.next().await {
        match message.map_err(channel_error)? {
            Message::Text(text) => {
                let value: Value = serde_json::from_str(text.as_str()).map_err(|error| {
                    Error::new(
                        "transport",
                        format!("browser returned invalid session data: {error}"),
                    )
                })?;
                if value.get("id").and_then(Value::as_u64) == Some(id) {
                    if value.get("error").and_then(Value::as_str) == Some("unknown command") {
                        return Err(Error::new(
                            "transport",
                            format!(
                                "this browser version does not support `{}`, which browser sign-in needs; update the browser or set --browser to another installed browser",
                                request["method"].as_str().unwrap_or("a required command")
                            ),
                        ));
                    }
                    if let Some(error) = value.get("error") {
                        let detail = match value.get("message").and_then(Value::as_str) {
                            Some(message) => format!("{error}: {message}"),
                            None => error.to_string(),
                        };
                        return Err(Error::new(
                            "transport",
                            format!("browser rejected the session query: {detail}"),
                        ));
                    }
                    return Ok(value);
                }
            }
            Message::Ping(data) => socket
                .send(Message::Pong(data))
                .await
                .map_err(channel_error)?,
            Message::Close(_) => {
                return Err(Error::new(
                    "transport",
                    "browser closed its sign-in channel",
                ));
            }
            _ => {}
        }
    }
    Err(Error::new(
        "transport",
        "browser closed its sign-in channel",
    ))
}

/// The Splunk Web session key, from the `splunkd_<port>` cookie, once the
/// matching `splunkweb_csrf_token_<port>` cookie shows the sign-in finished.
fn splunk_session_key(
    document: &Value,
    host: &str,
    web_path: &str,
    is_https: bool,
) -> Option<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let cookies = document
        .pointer("/result/cookies")?
        .as_array()?
        .iter()
        .filter_map(|cookie| {
            let name = cookie.get("name")?.as_str()?;
            let value = cookie.get("value")?.as_str()?;
            let domain = cookie.get("domain")?.as_str()?.trim_start_matches('.');
            let path = cookie.get("path").and_then(Value::as_str).unwrap_or("/");
            let secure = cookie
                .get("secure")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let expires = cookie
                .get("expires")
                .and_then(Value::as_f64)
                .unwrap_or(-1.0);
            let domain_matches = host.eq_ignore_ascii_case(domain)
                || host
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", domain.to_ascii_lowercase()));
            let usable = !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b';')
                && domain_matches
                && web_path.starts_with(path)
                && (!secure || is_https)
                && (expires <= 0.0 || expires > now);
            usable.then_some((path.len(), name, value))
        })
        .collect::<Vec<_>>();
    if !cookies
        .iter()
        .any(|(_, name, _)| name.starts_with("splunkweb_csrf_token_"))
    {
        return None;
    }
    let mut keys = cookies
        .into_iter()
        .filter(|(_, name, _)| name.starts_with("splunkd_"))
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));
    keys.into_iter().next().map(|(_, _, value)| value.into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrowserAlias {
    Auto,
    Chrome,
    Edge,
    Chromium,
    Firefox,
    WindowsChrome,
    WindowsEdge,
    WindowsChromium,
}

impl BrowserAlias {
    fn parse(value: &OsStr) -> Option<Self> {
        match value.to_str()?.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "chrome" => Some(Self::Chrome),
            "edge" => Some(Self::Edge),
            "chromium" => Some(Self::Chromium),
            "firefox" => Some(Self::Firefox),
            "windows-chrome" => Some(Self::WindowsChrome),
            "windows-edge" => Some(Self::WindowsEdge),
            "windows-chromium" => Some(Self::WindowsChromium),
            _ => None,
        }
    }

    fn native_variant(self) -> Option<Self> {
        match self {
            Self::Auto | Self::Chrome | Self::Edge | Self::Chromium | Self::Firefox => Some(self),
            Self::WindowsChrome | Self::WindowsEdge | Self::WindowsChromium => None,
        }
    }
}

enum BrowserBackend {
    Native(PathBuf),
    WindowsBridge(Option<OsString>),
}

fn select_browser_backend(preference: Option<OsString>) -> Result<BrowserBackend> {
    if cfg!(target_os = "windows") {
        return Ok(BrowserBackend::WindowsBridge(preference));
    }
    if !is_wsl() {
        return find_native_browser(preference.as_deref()).map(BrowserBackend::Native);
    }
    select_wsl_browser_backend(preference)
}

fn select_wsl_browser_backend(preference: Option<OsString>) -> Result<BrowserBackend> {
    select_wsl_browser_backend_with(preference, find_native_browser)
}

fn select_wsl_browser_backend_with(
    preference: Option<OsString>,
    find_native: impl FnOnce(Option<&OsStr>) -> Result<PathBuf>,
) -> Result<BrowserBackend> {
    if preference
        .as_deref()
        .is_some_and(looks_like_windows_browser_preference)
    {
        return Ok(BrowserBackend::WindowsBridge(preference));
    }
    match find_native(preference.as_deref()) {
        Ok(browser) => Ok(BrowserBackend::Native(browser)),
        Err(_error)
            if preference.is_none()
                || preference
                    .as_deref()
                    .and_then(BrowserAlias::parse)
                    .is_some_and(|alias| alias != BrowserAlias::Firefox) =>
        {
            Ok(BrowserBackend::WindowsBridge(preference))
        }
        Err(error) => Err(error),
    }
}

fn find_native_browser(preference: Option<&OsStr>) -> Result<PathBuf> {
    if let Some(preference) = preference {
        if let Some(alias) = BrowserAlias::parse(preference) {
            let Some(alias) = alias.native_variant() else {
                return Err(Error::usage(format!(
                    "--browser {} selects a Windows browser and can only be used on Windows or WSL",
                    preference.to_string_lossy()
                )));
            };
            return find_native_browser_alias(alias).ok_or_else(|| {
                Error::usage(format!(
                    "--browser {} was requested, but no matching browser is installed; use chrome, edge, chromium, firefox, windows-chrome, windows-edge, or an executable path",
                    preference.to_string_lossy()
                ))
            });
        }
        return resolve_program(Path::new(preference)).ok_or_else(|| {
            Error::usage(format!(
                "--browser does not identify an executable or friendly browser name: {}",
                Path::new(preference).display()
            ))
        });
    }

    default_browser_alias()
        .and_then(find_native_browser_alias)
        .or_else(|| find_native_browser_alias(BrowserAlias::Auto))
        .ok_or_else(|| {
            Error::usage(
                "browser sign-in needs Chrome, Edge, Chromium, or Firefox; install one or set --browser (or SPLUNK_BROWSER) to chrome, edge, chromium, firefox, or an executable path",
            )
        })
}

#[cfg(target_os = "linux")]
fn default_browser_alias() -> Option<BrowserAlias> {
    command_output("xdg-settings", &["get", "default-web-browser"])
        .and_then(|desktop_id| default_browser_from_desktop_id(&desktop_id))
}

#[cfg(target_os = "macos")]
fn default_browser_alias() -> Option<BrowserAlias> {
    command_output(
        "defaults",
        &[
            "read",
            "com.apple.LaunchServices/com.apple.launchservices.secure",
            "LSHandlers",
        ],
    )
    .and_then(|handlers| default_browser_from_launch_services(&handlers))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn default_browser_alias() -> Option<BrowserAlias> {
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Map an XDG desktop entry such as `firefox_firefox.desktop` to a browser.
#[cfg(any(target_os = "linux", test))]
fn default_browser_from_desktop_id(desktop_id: &str) -> Option<BrowserAlias> {
    let desktop_id = desktop_id.trim().to_ascii_lowercase();
    if desktop_id.contains("firefox") {
        Some(BrowserAlias::Firefox)
    } else if desktop_id.contains("microsoft-edge") || desktop_id.contains("msedge") {
        Some(BrowserAlias::Edge)
    } else if desktop_id.contains("chromium") {
        Some(BrowserAlias::Chromium)
    } else if desktop_id.contains("google-chrome") {
        Some(BrowserAlias::Chrome)
    } else {
        None
    }
}

/// Find the `https` handler in the LaunchServices `LSHandlers` plist dump.
#[cfg(any(target_os = "macos", test))]
fn default_browser_from_launch_services(handlers: &str) -> Option<BrowserAlias> {
    let mut depth = 0_usize;
    let mut handles_https = false;
    let mut bundle_id = None;
    for line in handlers.lines().map(str::trim) {
        if depth == 2
            && let Some((key, value)) = line.strip_suffix(';').and_then(|line| line.split_once('='))
        {
            let value = value.trim().trim_matches('"');
            match key.trim() {
                "LSHandlerURLScheme" => handles_https = value.eq_ignore_ascii_case("https"),
                "LSHandlerRoleAll" => bundle_id = Some(value.to_ascii_lowercase()),
                _ => {}
            }
        }
        let closes = line.matches(['}', ')']).count();
        depth = (depth + line.matches(['{', '(']).count()).saturating_sub(closes);
        if depth == 1 && closes > 0 {
            if handles_https {
                return match bundle_id.as_deref()? {
                    "com.google.chrome" => Some(BrowserAlias::Chrome),
                    "com.microsoft.edgemac" => Some(BrowserAlias::Edge),
                    "org.chromium.chromium" => Some(BrowserAlias::Chromium),
                    "org.mozilla.firefox" => Some(BrowserAlias::Firefox),
                    _ => None,
                };
            }
            handles_https = false;
            bundle_id = None;
        }
    }
    None
}

fn find_native_browser_alias(alias: BrowserAlias) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let absolute = [
        (
            BrowserAlias::Chrome,
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ),
        (
            BrowserAlias::Edge,
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ),
        (
            BrowserAlias::Chromium,
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ),
        (
            BrowserAlias::Firefox,
            "/Applications/Firefox.app/Contents/MacOS/firefox",
        ),
    ];
    #[cfg(not(target_os = "macos"))]
    let absolute: [(BrowserAlias, &str); 0] = [];
    for (kind, candidate) in absolute {
        if (matches!(alias, BrowserAlias::Auto) || alias == kind)
            && let Some(path) = resolve_program(Path::new(candidate))
        {
            return Some(path);
        }
    }

    let candidates: &[&str] = match alias {
        BrowserAlias::Auto => &[
            "google-chrome",
            "google-chrome-stable",
            "microsoft-edge",
            "microsoft-edge-stable",
            "chromium",
            "chromium-browser",
            "firefox",
            "firefox-esr",
        ],
        BrowserAlias::Chrome => &["google-chrome", "google-chrome-stable", "chrome"],
        BrowserAlias::Edge => &["microsoft-edge", "microsoft-edge-stable", "msedge"],
        BrowserAlias::Chromium => &["chromium", "chromium-browser"],
        BrowserAlias::Firefox => &["firefox", "firefox-esr"],
        BrowserAlias::WindowsChrome | BrowserAlias::WindowsEdge | BrowserAlias::WindowsChromium => {
            return None;
        }
    };
    candidates.iter().find_map(find_in_path)
}

fn resolve_program(candidate: &Path) -> Option<PathBuf> {
    if candidate.components().count() > 1 {
        candidate.is_file().then(|| candidate.to_path_buf())
    } else {
        find_in_path(candidate.as_os_str())
    }
}

fn find_in_path(candidate: impl AsRef<OsStr>) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|path| path.join(candidate.as_ref()))
            .find(|path| path.is_file())
    })
}

fn is_wsl() -> bool {
    cfg!(target_os = "linux")
        && (std::env::var_os("WSL_INTEROP").is_some()
            || std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .is_ok_and(|value| value.to_ascii_lowercase().contains("microsoft")))
}

fn looks_like_windows_browser_preference(preference: &OsStr) -> bool {
    if matches!(
        BrowserAlias::parse(preference),
        Some(
            BrowserAlias::WindowsChrome | BrowserAlias::WindowsEdge | BrowserAlias::WindowsChromium
        )
    ) {
        return true;
    }
    let value = preference.to_string_lossy();
    let bytes = value.as_bytes();
    value.to_ascii_lowercase().ends_with(".exe")
        || value.starts_with(r"\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

async fn windows_browser_session(
    web_url: &str,
    browser_override: Option<&OsStr>,
    progress: &mut ProgressReporter<'_>,
) -> Result<String> {
    let powershell = ["powershell.exe", "pwsh.exe"]
        .into_iter()
        .find_map(find_in_path)
        .ok_or_else(|| {
            Error::usage(
                "WSL browser sign-in needs Windows PowerShell interop; ensure powershell.exe is available on PATH",
            )
        })?;
    let bridge = render_windows_bridge(web_url, browser_override);
    let mut child = tokio::process::Command::new(powershell)
        .args(POWERSHELL_ARGS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| Error::new("transport", format!("failed to start PowerShell: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .expect("PowerShell stdin was configured as piped");
    stdin.write_all(bridge.as_bytes()).await.map_err(|error| {
        Error::new(
            "transport",
            format!("failed to send browser bridge to PowerShell: {error}"),
        )
    })?;
    drop(stdin);
    let stdout = child
        .stdout
        .take()
        .expect("PowerShell stdout was configured as piped");
    let mut stderr = child
        .stderr
        .take()
        .expect("PowerShell stderr was configured as piped");
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let mut stdout = stdout;
    let mut stdout_bytes = Vec::new();
    loop {
        let mut chunk = [0_u8; 4096];
        let read = stdout.read(&mut chunk).await.map_err(bridge_error)?;
        if read == 0 {
            break;
        }
        stdout_bytes.extend_from_slice(&chunk[..read]);
        let decoded = decode_powershell_output(&stdout_bytes);
        for output_line in decoded.lines() {
            if let Some(stage) = powershell_progress(output_line) {
                progress.report(stage);
            }
        }
    }
    child.wait().await.map_err(bridge_error)?;
    let stderr = stderr_task
        .await
        .map_err(bridge_error)?
        .map_err(bridge_error)?;

    let stdout = decode_powershell_output(&stdout_bytes);
    if let Some(encoded) = stdout
        .lines()
        .find_map(|line| line.strip_prefix("SPLUNK_RESULT:"))
    {
        return serde_json::from_str::<BrowserSession>(encoded)
            .map(|session| session.session_key)
            .map_err(|error| {
                Error::new(
                    "transport",
                    format!("browser returned invalid session data: {error}"),
                )
            });
    }
    if let Some(detail) = powershell_bridge_error(&stdout) {
        return Err(Error::new(
            "auth",
            format!("browser sign-in failed: {detail}"),
        ));
    }
    let detail = powershell_error_detail(&stderr);
    Err(Error::new(
        "auth",
        if !detail.is_empty() {
            format!("browser sign-in failed: {detail}")
        } else if stdout.lines().any(|line| line == "SPLUNK_BRIDGE_READY") {
            "browser sign-in ended before a Splunk session was returned; try again or set --browser to windows-edge or windows-chrome"
                .into()
        } else {
            "Windows PowerShell exited before starting the browser sign-in bridge; ensure WSL Windows interop is enabled and try again"
                .into()
        },
    ))
}

fn bridge_error(error: impl std::fmt::Display) -> Error {
    Error::new("transport", format!("browser bridge failed: {error}"))
}

fn powershell_progress(line: &str) -> Option<BrowserProgress> {
    let stage = line.trim().strip_prefix("SPLUNK_STAGE:")?;
    match stage {
        "starting-private-browser" => Some(BrowserProgress::StartingPrivateBrowser),
        "private-browser-opened" => Some(BrowserProgress::PrivateBrowserOpened),
        "waiting-browser-channel" => Some(BrowserProgress::WaitingForBrowserChannel),
        "browser-channel-ready" => Some(BrowserProgress::BrowserChannelReady),
        "waiting-splunk-page" => Some(BrowserProgress::WaitingForSplunkPage),
        "splunk-page-detected" => Some(BrowserProgress::SplunkPageDetected),
        "reading-session-cookies" => Some(BrowserProgress::ReadingSessionCookies),
        "session-cookies-detected" => Some(BrowserProgress::SessionCookiesDetected),
        "validating-session" => Some(BrowserProgress::ValidatingSession),
        "session-validated" => Some(BrowserProgress::SessionValidated),
        value => value
            .strip_prefix("validation-http-")
            .and_then(|status| status.parse::<u16>().ok())
            .filter(|status| (100..=599).contains(status))
            .map(BrowserProgress::ValidationResponse),
    }
}

const POWERSHELL_STDIN_BOOTSTRAP: &str =
    "$script = [Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($script))";
const POWERSHELL_ARGS: [&str; 7] = [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    POWERSHELL_STDIN_BOOTSTRAP,
];

fn decode_powershell_output(bytes: &[u8]) -> String {
    let has_utf16_le_bom = bytes.starts_with(&[0xff, 0xfe]);
    let looks_like_utf16_le = bytes.len() >= 4
        && bytes
            .iter()
            .skip(1)
            .step_by(2)
            .filter(|byte| **byte == 0)
            .count()
            * 4
            >= bytes.len();
    if has_utf16_le_bom || looks_like_utf16_le {
        let start = usize::from(has_utf16_le_bom) * 2;
        let (pairs, _) = bytes[start..].as_chunks::<2>();
        let units = pairs
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn bounded_error_detail(detail: &str) -> String {
    detail.trim().chars().take(500).collect()
}

fn powershell_bridge_error(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("SPLUNK_ERROR:"))
        .map(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .map(|detail| bounded_error_detail(&detail))
                .filter(|detail| !detail.is_empty())
                .unwrap_or_else(|| "the Windows browser bridge returned an unreadable error".into())
        })
}

fn powershell_error_detail(bytes: &[u8]) -> String {
    let output = decode_powershell_output(bytes);
    if !output.trim_start().starts_with("#< CLIXML") {
        return bounded_error_detail(&output);
    }

    let mut errors = Vec::new();
    let mut remaining = output.as_str();
    const ERROR_NODE: &str = "<S S=\"Error\"";
    while let Some(start) = remaining.find(ERROR_NODE) {
        remaining = &remaining[start + ERROR_NODE.len()..];
        let Some(content_start) = remaining.find('>') else {
            break;
        };
        remaining = &remaining[content_start + 1..];
        let Some(content_end) = remaining.find("</S>") else {
            break;
        };
        let error = decode_clixml_text(&remaining[..content_end]);
        if !error.trim().is_empty() {
            errors.push(error);
        }
        remaining = &remaining[content_end + 4..];
    }
    bounded_error_detail(&errors.join("\n"))
}

fn decode_clixml_text(value: &str) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    let mut decoded = String::with_capacity(value.len());
    let mut index = 0;
    while index < characters.len() {
        if index + 6 < characters.len()
            && characters[index] == '_'
            && characters[index + 1] == 'x'
            && characters[index + 6] == '_'
        {
            let hex = characters[index + 2..index + 6].iter().collect::<String>();
            if let Ok(codepoint) = u32::from_str_radix(&hex, 16)
                && let Some(character) = char::from_u32(codepoint)
            {
                decoded.push(character);
                index += 7;
                continue;
            }
        }
        decoded.push(characters[index]);
        index += 1;
    }
    decoded
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn powershell_hex(value: &[u8]) -> String {
    use std::fmt::Write as _;

    value.iter().fold(
        String::with_capacity(value.len() * 2),
        |mut encoded, byte| {
            write!(encoded, "{byte:02x}").expect("writing to a string cannot fail");
            encoded
        },
    )
}

fn render_windows_bridge(web_url: &str, browser: Option<&std::ffi::OsStr>) -> String {
    WINDOWS_BROWSER_BRIDGE
        .replacen("__WEB_URL_HEX__", &powershell_hex(web_url.as_bytes()), 1)
        .replacen(
            "__BROWSER_HEX__",
            &browser
                .map(|value| powershell_hex(value.to_string_lossy().as_bytes()))
                .unwrap_or_default(),
            1,
        )
}

const WINDOWS_BROWSER_BRIDGE: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
Write-Output 'SPLUNK_BRIDGE_READY'
$script:reportedStages = @{}
function Write-Stage {
    param([string]$Stage)
    if (-not $script:reportedStages.ContainsKey($Stage)) {
        $script:reportedStages[$Stage] = $true
        Write-Output ('SPLUNK_STAGE:' + $Stage)
    }
}
function ConvertFrom-HexUtf8 {
    param([string]$Hex)
    if (-not $Hex) { return '' }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return [Text.Encoding]::UTF8.GetString($bytes)
}
$webUrl = [Uri](ConvertFrom-HexUtf8 '__WEB_URL_HEX__')
$origin = $webUrl.GetLeftPart([UriPartial]::Authority)
$loginUrl = "$webUrl"
$browserPreference = ConvertFrom-HexUtf8 '__BROWSER_HEX__'
function Test-RemoteDebuggingBlocked {
    param([string]$Kind)
    $policySubkey = if ($Kind -eq 'edge') {
        'SOFTWARE\Policies\Microsoft\Edge'
    } elseif ($Kind -eq 'chromium') {
        'SOFTWARE\Policies\Chromium'
    } else {
        'SOFTWARE\Policies\Google\Chrome'
    }
    foreach ($registryRoot in @('HKLM:', 'HKCU:')) {
        $policy = Get-ItemProperty -LiteralPath ($registryRoot + '\' + $policySubkey) -Name 'RemoteDebuggingAllowed' -ErrorAction SilentlyContinue
        if ($policy -and $policy.PSObject.Properties['RemoteDebuggingAllowed'] -and [int]$policy.RemoteDebuggingAllowed -eq 0) {
            return $true
        }
    }
    return $false
}
function Get-DefaultBrowserKind {
    $choice = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -Name 'ProgId' -ErrorAction SilentlyContinue
    if (-not $choice) { return $null }
    $progId = [string]$choice.ProgId
    if ($progId -match '^MSEdgeHTM') { return 'edge' }
    if ($progId -match '^ChromeHTML') { return 'chrome' }
    if ($progId -match '^Chromium') { return 'chromium' }
    return $null
}
$browser = $null
$browserKind = $null
$browserName = $null
$remoteDebuggingBlocked = $false
if ($browserPreference -and (Test-Path -LiteralPath $browserPreference)) {
    $browser = $browserPreference
    if ($browser -match '(?i)firefox') {
        throw 'Firefox browser sign-in uses WebDriver BiDi and is only supported for Firefox installed on Linux, macOS, or inside WSL. Set --browser to edge or chrome.'
    } elseif ($browser -match '(?i)edge') {
        $browserKind = 'edge'
        $browserName = 'Microsoft Edge'
    } elseif ($browser -match '(?i)chromium') {
        $browserKind = 'chromium'
        $browserName = 'Chromium'
    } else {
        $browserKind = 'chrome'
        $browserName = 'Google Chrome'
    }
    $remoteDebuggingBlocked = Test-RemoteDebuggingBlocked $browserKind
}
if (-not $browser) {
    $requestedBrowser = if ($browserPreference) { $browserPreference.Trim().ToLowerInvariant() } else { 'auto' }
    switch -Regex ($requestedBrowser) {
        '^(auto)?$' { $candidateKinds = @('edge', 'chrome', 'chromium'); break }
        '^(edge|msedge|microsoft-edge|windows-edge)$' { $candidateKinds = @('edge'); break }
        '^(chrome|google-chrome|windows-chrome)$' { $candidateKinds = @('chrome'); break }
        '^(chromium|windows-chromium)$' { $candidateKinds = @('chromium'); break }
        '^firefox$' { throw 'Firefox browser sign-in uses WebDriver BiDi and is only supported for Firefox installed on Linux, macOS, or inside WSL. Set --browser to edge or chrome.' }
        default { throw "--browser '$browserPreference' is not a Windows browser path or friendly name. Use chrome, edge, chromium, windows-chrome, or windows-edge." }
    }
    if ($candidateKinds.Count -gt 1) {
        $defaultKind = Get-DefaultBrowserKind
        if ($defaultKind) {
            $candidateKinds = @($defaultKind) + @($candidateKinds | Where-Object { $_ -ne $defaultKind })
        }
    }
    $candidates = foreach ($kind in $candidateKinds) {
        if ($kind -eq 'edge') {
            [PSCustomObject]@{ Path = "$env:PROGRAMFILES\Microsoft\Edge\Application\msedge.exe"; Kind = 'edge'; Name = 'Microsoft Edge' }
            [PSCustomObject]@{ Path = "${env:PROGRAMFILES(X86)}\Microsoft\Edge\Application\msedge.exe"; Kind = 'edge'; Name = 'Microsoft Edge' }
            [PSCustomObject]@{ Path = "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"; Kind = 'edge'; Name = 'Microsoft Edge' }
        } elseif ($kind -eq 'chrome') {
            [PSCustomObject]@{ Path = "$env:PROGRAMFILES\Google\Chrome\Application\chrome.exe"; Kind = 'chrome'; Name = 'Google Chrome' }
            [PSCustomObject]@{ Path = "${env:PROGRAMFILES(X86)}\Google\Chrome\Application\chrome.exe"; Kind = 'chrome'; Name = 'Google Chrome' }
            [PSCustomObject]@{ Path = "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"; Kind = 'chrome'; Name = 'Google Chrome' }
        } else {
            [PSCustomObject]@{ Path = "$env:PROGRAMFILES\Chromium\Application\chrome.exe"; Kind = 'chromium'; Name = 'Chromium' }
            [PSCustomObject]@{ Path = "${env:PROGRAMFILES(X86)}\Chromium\Application\chrome.exe"; Kind = 'chromium'; Name = 'Chromium' }
            [PSCustomObject]@{ Path = "$env:LOCALAPPDATA\Chromium\Application\chrome.exe"; Kind = 'chromium'; Name = 'Chromium' }
        }
    }
    # Auto mode moves past browsers whose remote debugging is disabled by policy.
    foreach ($candidate in @($candidates | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) })) {
        if (Test-RemoteDebuggingBlocked $candidate.Kind) {
            if (-not $remoteDebuggingBlocked) { $browserName = $candidate.Name }
            $remoteDebuggingBlocked = $true
            continue
        }
        $browser = $candidate.Path
        $browserKind = $candidate.Kind
        $browserName = $candidate.Name
        $remoteDebuggingBlocked = $false
        break
    }
}
if ($remoteDebuggingBlocked) {
    throw "$browserName browser sign-in is blocked by the managed RemoteDebuggingAllowed policy. Install Chrome, Edge, Chromium, or Firefox inside WSL, or set --browser to another installed browser."
}
if (-not $browser) { throw 'Chrome, Edge, or Chromium was not found on Windows. Set --browser to chrome, edge, chromium, or a Windows executable path.' }

$profile = Join-Path $env:TEMP ("splunk-cli-browser-" + [Guid]::NewGuid().ToString('N'))
$process = $null
$socket = $null
$bridgeExitCode = 0
$requestId = 0
function Invoke-CdpCommand {
    param($Socket, [ref]$RequestId, [string]$Method, $Params, [string]$SessionId)
    $RequestId.Value++
    $requestObject = @{ id = $RequestId.Value; method = $Method; params = $Params }
    if ($SessionId) { $requestObject.sessionId = $SessionId }
    $request = $requestObject | ConvertTo-Json -Compress -Depth 6
    $requestBytes = [Text.Encoding]::UTF8.GetBytes($request)
    $Socket.SendAsync([ArraySegment[byte]]::new($requestBytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    while ($true) {
        $stream = [IO.MemoryStream]::new()
        do {
            $buffer = New-Object byte[] 65536
            $result = $Socket.ReceiveAsync([ArraySegment[byte]]::new($buffer), [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            if ($result.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) { throw 'The private browser sign-in channel closed.' }
            $stream.Write($buffer, 0, $result.Count)
        } while (-not $result.EndOfMessage)
        $candidate = [Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
        if ($candidate.id -eq $RequestId.Value) {
            if ($candidate.error) { throw "Browser rejected ${Method}: $($candidate.error.message)" }
            return $candidate
        }
    }
}
try {
    $portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $portProbe.Start()
        $debugPort = ([Net.IPEndPoint]$portProbe.LocalEndpoint).Port
    } finally {
        $portProbe.Stop()
    }
    $quotedProfile = '"' + $profile + '"'
    $quotedUrl = '"' + $loginUrl + '"'
    $privateMode = if ($browserKind -eq 'edge') { '--inprivate' } else { '--incognito' }
    $arguments = "--remote-debugging-port=$debugPort --remote-debugging-address=127.0.0.1 --user-data-dir=$quotedProfile --no-first-run --no-default-browser-check --disable-sync $privateMode --new-window $quotedUrl"
    Write-Stage 'starting-private-browser'
    $process = Start-Process -FilePath $browser -ArgumentList $arguments -PassThru
    Write-Stage 'private-browser-opened'
    Write-Stage 'waiting-browser-channel'
    $channelDeadline = [DateTime]::UtcNow.AddSeconds(20)
    $version = $null
    while (-not $version -and [DateTime]::UtcNow -lt $channelDeadline) {
        if ($process.HasExited) { throw "Browser closed before sign-in completed ($($process.ExitCode))." }
        try {
            $version = Invoke-RestMethod -UseBasicParsing "http://127.0.0.1:$debugPort/json/version" -TimeoutSec 2
        } catch {}
        if (-not $version) { Start-Sleep -Milliseconds 200 }
    }
    if (-not $version.webSocketDebuggerUrl) {
        throw 'The private browser opened, but its localhost sign-in channel did not become available within 20 seconds. Edge or Chrome may have ignored its isolated debugging options, or an enterprise browser policy may block browser automation. Set --browser to the other Windows browser and retry; progress milestones on stderr identify the failing stage.'
    }

    Write-Stage 'browser-channel-ready'
    $socket = [Net.WebSockets.ClientWebSocket]::new()
    $socket.ConnectAsync([Uri]$version.webSocketDebuggerUrl, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    $deadline = [DateTime]::UtcNow.AddMinutes(5)
    $lastStage = 'the authenticated Splunk page'
    Write-Stage 'waiting-splunk-page'
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) { throw "Browser closed before sign-in completed ($($process.ExitCode))." }
        $targets = Invoke-CdpCommand $socket ([ref]$requestId) 'Target.getTargets' @{} $null
        $target = $targets.result.targetInfos | Where-Object {
            $_.type -eq 'page' -and ($_.url -eq $origin -or $_.url.StartsWith($origin + '/'))
        } | Select-Object -First 1
        if (-not $target) {
            Start-Sleep -Milliseconds 750
            continue
        }
        Write-Stage 'splunk-page-detected'
        $lastStage = 'Splunk session cookies'
        Write-Stage 'reading-session-cookies'
        $attached = Invoke-CdpCommand $socket ([ref]$requestId) 'Target.attachToTarget' @{ targetId = $target.targetId; flatten = $true } $null
        $sessionId = $attached.result.sessionId
        try {
            $document = Invoke-CdpCommand $socket ([ref]$requestId) 'Network.getCookies' @{ urls = @("$webUrl", "$origin/") } $sessionId
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            $cookies = @($document.result.cookies | Where-Object {
                $nameIsSafe = $_.name -and $_.name -notmatch '[;=\r\n]'
                $valueIsSafe = $_.value -notmatch '[;\r\n]'
                $domain = $_.domain.TrimStart('.').ToLowerInvariant()
                $hostMatches = $webUrl.Host.ToLowerInvariant() -eq $domain -or $webUrl.Host.ToLowerInvariant().EndsWith('.' + $domain)
                $cookiePath = if ($_.path) { $_.path } else { '/' }
                $pathMatches = $webUrl.AbsolutePath.StartsWith($cookiePath)
                $notExpired = $_.expires -le 0 -or $_.expires -gt $now
                $nameIsSafe -and $valueIsSafe -and $hostMatches -and $pathMatches -and $notExpired -and (-not $_.secure -or $webUrl.Scheme -eq 'https')
            } | Sort-Object { $_.path.Length } -Descending)
            $key = $cookies | Where-Object { $_.name.StartsWith('splunkd_') -and $_.value } | Select-Object -First 1
            $csrf = $cookies | Where-Object { $_.name.StartsWith('splunkweb_csrf_token_') } | Select-Object -First 1
            if ($key -and $csrf) {
                Write-Stage 'session-cookies-detected'
                $session = @{ session_key = $key.value }
                Write-Output ('SPLUNK_RESULT:' + ($session | ConvertTo-Json -Compress))
                exit 0
            }
        } finally {
            if ($sessionId) { try { Invoke-CdpCommand $socket ([ref]$requestId) 'Target.detachFromTarget' @{ sessionId = $sessionId } $null | Out-Null } catch {} }
        }
        Start-Sleep -Milliseconds 750
    }
    throw "Browser sign-in timed out after five minutes while waiting for $lastStage; no credential was stored."
} catch {
    $message = $_.Exception.Message
    if (-not $message) { $message = [string]$_ }
    $errorBytes = [Text.Encoding]::UTF8.GetBytes($message)
    Write-Output ('SPLUNK_ERROR:' + [Convert]::ToBase64String($errorBytes))
    $bridgeExitCode = 1
} finally {
    if ($socket) {
        try { Invoke-CdpCommand $socket ([ref]$requestId) 'Browser.close' @{} $null | Out-Null } catch {}
        try { $socket.Dispose() } catch {}
    }
    if ($process -and -not $process.HasExited) { try { Stop-Process -Id $process.Id -Force } catch {} }
    if (Test-Path -LiteralPath $profile) { try { Remove-Item -LiteralPath $profile -Recurse -Force } catch {} }
}
if ($bridgeExitCode -ne 0) { exit $bridgeExitCode }
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::accept_async;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cookies(cookies: Value) -> Value {
        json!({"result": {"cookies": cookies}})
    }

    #[test]
    fn session_key_is_scoped_to_the_splunk_host_and_web_path() {
        let document = cookies(json!([
            {"name": "splunkd_443", "value": "root-key", "domain": "analytics.example.com", "path": "/", "secure": true, "expires": -1},
            {"name": "splunkd_8000", "value": "web-key", "domain": "analytics.example.com", "path": "/splunk", "secure": true, "expires": -1},
            {"name": "splunkweb_csrf_token_8000", "value": "csrf", "domain": "analytics.example.com", "path": "/splunk", "secure": true, "expires": -1},
            {"name": "splunkd_9000", "value": "other-app", "domain": "analytics.example.com", "path": "/other", "secure": true, "expires": -1},
            {"name": "splunkd_1", "value": "must-not-leak", "domain": ".microsoftonline.com", "path": "/", "secure": true, "expires": -1},
            {"name": "splunkd_2", "value": "expired", "domain": "analytics.example.com", "path": "/splunk/en-US", "secure": true, "expires": 1}
        ]));
        assert_eq!(
            splunk_session_key(&document, "analytics.example.com", "/splunk/", true).as_deref(),
            Some("web-key")
        );
        assert_eq!(
            splunk_session_key(&document, "analytics.example.com", "/splunk/", false),
            None,
            "secure cookies must not be used for plain HTTP"
        );
    }

    #[test]
    fn session_key_waits_for_the_csrf_cookie() {
        let document = cookies(json!([
            {"name": "splunkd_443", "value": "key", "domain": "analytics.example.com", "path": "/", "secure": true, "expires": -1}
        ]));
        assert_eq!(
            splunk_session_key(&document, "analytics.example.com", "/", true),
            None
        );
    }

    #[test]
    fn unsafe_session_key_values_are_never_returned() {
        let document = cookies(json!([
            {"name": "splunkd_443", "value": "key\r\nX-Evil: yes", "domain": "analytics.example.com", "path": "/", "secure": true, "expires": -1},
            {"name": "splunkweb_csrf_token_443", "value": "csrf", "domain": "analytics.example.com", "path": "/", "secure": true, "expires": -1}
        ]));
        assert_eq!(
            splunk_session_key(&document, "analytics.example.com", "/", true),
            None
        );
    }

    #[test]
    fn powershell_bridge_uses_an_isolated_profile_and_splunk_scope() {
        assert!(WINDOWS_BROWSER_BRIDGE.contains("--user-data-dir="));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("--remote-debugging-port=$debugPort"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("[Net.IPAddress]::Loopback, 0"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("AddSeconds(20)"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("AddMinutes(5)"));
        assert!(!WINDOWS_BROWSER_BRIDGE.contains("DevToolsActivePort"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("--inprivate"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("--incognito"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("$ProgressPreference = 'SilentlyContinue'"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("SPLUNK_STAGE:"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("SPLUNK_ERROR:"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("SPLUNK_RESULT:"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("Network.getCookies"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("splunkd_"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("splunkweb_csrf_token_"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("$webUrl.Host"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("__WEB_URL_HEX__"));
        assert!(!WINDOWS_BROWSER_BRIDGE.contains("X-UserToken"));
        assert!(!WINDOWS_BROWSER_BRIDGE.contains("-WebSession"));
        assert!(!WINDOWS_BROWSER_BRIDGE.contains("SERVICENOW"));
        assert!(!WINDOWS_BROWSER_BRIDGE.contains("login.microsoftonline.com"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("RemoteDebuggingAllowed"));
        let policy_check = WINDOWS_BROWSER_BRIDGE
            .find("$remoteDebuggingBlocked")
            .unwrap();
        let browser_start = WINDOWS_BROWSER_BRIDGE.find("Start-Process").unwrap();
        assert!(policy_check < browser_start);
        assert_eq!(
            powershell_hex(b"https://analytics.example.com/"),
            "68747470733a2f2f616e616c79746963732e6578616d706c652e636f6d2f"
        );
        let rendered = render_windows_bridge("https://analytics.example.com/", None);
        assert!(!rendered.contains("__WEB_URL_HEX__"));
        assert!(!rendered.contains("__BROWSER_HEX__"));
    }

    #[test]
    fn private_browsing_flag_matches_the_browser() {
        assert_eq!(
            private_browsing_argument(Path::new("/usr/bin/google-chrome")),
            "--incognito"
        );
        assert_eq!(
            private_browsing_argument(Path::new("/usr/bin/chromium")),
            "--incognito"
        );
        assert_eq!(
            private_browsing_argument(Path::new(
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
            )),
            "--inprivate"
        );
    }

    #[test]
    fn friendly_browser_names_are_case_insensitive_and_platform_aware() {
        assert_eq!(
            BrowserAlias::parse(OsStr::new("chrome")),
            Some(BrowserAlias::Chrome)
        );
        assert_eq!(
            BrowserAlias::parse(OsStr::new("EDGE")),
            Some(BrowserAlias::Edge)
        );
        assert_eq!(
            BrowserAlias::parse(OsStr::new(" Chromium ")),
            Some(BrowserAlias::Chromium)
        );
        assert_eq!(
            BrowserAlias::parse(OsStr::new("windows-edge")),
            Some(BrowserAlias::WindowsEdge)
        );
        assert_eq!(
            BrowserAlias::parse(OsStr::new("Firefox")),
            Some(BrowserAlias::Firefox)
        );
        assert_eq!(BrowserAlias::parse(OsStr::new("safari")), None);
        assert!(is_firefox(Path::new("/usr/bin/firefox")));
        assert!(is_firefox(Path::new(
            "/Applications/Firefox.app/Contents/MacOS/firefox"
        )));
        assert!(!is_firefox(Path::new("/usr/bin/google-chrome")));
        assert!(looks_like_windows_browser_preference(OsStr::new(
            "windows-chrome"
        )));
        assert!(looks_like_windows_browser_preference(OsStr::new(
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        )));
        assert!(!looks_like_windows_browser_preference(OsStr::new(
            "/usr/bin/google-chrome"
        )));
    }

    #[test]
    fn wsl_prefers_a_native_linux_browser_and_falls_back_to_windows() {
        let native =
            select_wsl_browser_backend_with(None, |_| Ok(PathBuf::from("/usr/bin/chromium")))
                .unwrap();
        assert!(
            matches!(native, BrowserBackend::Native(path) if path == Path::new("/usr/bin/chromium"))
        );

        let fallback = select_wsl_browser_backend_with(Some(OsString::from("chrome")), |_| {
            Err(Error::usage("not installed in WSL"))
        })
        .unwrap();
        assert!(matches!(
            fallback,
            BrowserBackend::WindowsBridge(Some(value)) if value == OsStr::new("chrome")
        ));

        let forced_windows =
            select_wsl_browser_backend_with(Some(OsString::from("windows-edge")), |_| {
                panic!("a forced Windows alias must not probe Linux browsers")
            })
            .unwrap();
        assert!(matches!(
            forced_windows,
            BrowserBackend::WindowsBridge(Some(value)) if value == OsStr::new("windows-edge")
        ));
    }

    #[test]
    fn wsl_never_hands_a_firefox_request_to_the_windows_bridge() {
        let result = select_wsl_browser_backend_with(Some(OsString::from("firefox")), |_| {
            Err(Error::usage("firefox is not installed"))
        });
        assert!(
            matches!(result, Err(error) if error.kind == "usage" && error.message == "firefox is not installed")
        );
    }

    #[test]
    fn default_browser_is_read_from_xdg_desktop_ids() {
        for (desktop_id, expected) in [
            ("firefox.desktop\n", Some(BrowserAlias::Firefox)),
            ("firefox_firefox.desktop", Some(BrowserAlias::Firefox)),
            ("google-chrome.desktop", Some(BrowserAlias::Chrome)),
            ("microsoft-edge.desktop", Some(BrowserAlias::Edge)),
            ("chromium_chromium.desktop", Some(BrowserAlias::Chromium)),
            ("chromium-browser.desktop", Some(BrowserAlias::Chromium)),
            ("wslview.desktop", None),
            ("", None),
        ] {
            assert_eq!(
                default_browser_from_desktop_id(desktop_id),
                expected,
                "{desktop_id}"
            );
        }
    }

    #[test]
    fn default_browser_is_read_from_the_launch_services_https_handler() {
        let handlers = r#"(
        {
        LSHandlerContentType = "public.html";
        LSHandlerRoleAll = "com.apple.safari";
    },
        {
        LSHandlerPreferredVersions =         {
            LSHandlerRoleAll = "-";
        };
        LSHandlerRoleAll = "org.mozilla.firefox";
        LSHandlerURLScheme = https;
    },
        {
        LSHandlerRoleAll = "com.google.chrome";
        LSHandlerURLScheme = http;
    }
)"#;
        assert_eq!(
            default_browser_from_launch_services(handlers),
            Some(BrowserAlias::Firefox)
        );
        assert_eq!(
            default_browser_from_launch_services(
                &handlers.replace("org.mozilla.firefox", "com.microsoft.edgemac")
            ),
            Some(BrowserAlias::Edge)
        );
        assert_eq!(
            default_browser_from_launch_services(
                &handlers.replace("org.mozilla.firefox", "com.apple.safari")
            ),
            None
        );
        assert_eq!(default_browser_from_launch_services(""), None);
    }

    #[test]
    fn powershell_bridge_prefers_the_default_browser_and_skips_blocked_ones() {
        assert!(WINDOWS_BROWSER_BRIDGE.contains("UrlAssociations\\https\\UserChoice"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("'^MSEdgeHTM'"));
        assert!(WINDOWS_BROWSER_BRIDGE.contains("'^ChromeHTML'"));
        let skip = WINDOWS_BROWSER_BRIDGE
            .find("if (Test-RemoteDebuggingBlocked $candidate.Kind)")
            .unwrap();
        let next = WINDOWS_BROWSER_BRIDGE[skip..].find("continue").unwrap();
        assert!(next < WINDOWS_BROWSER_BRIDGE[skip..].find("break").unwrap());
        assert!(WINDOWS_BROWSER_BRIDGE.contains("'^firefox$'"));
    }

    #[test]
    fn bidi_cookies_are_mapped_to_the_cdp_cookie_shape() {
        let response = json!({"type": "success", "id": 3, "result": {"cookies": [
            {"name": "splunkd_443", "value": {"type": "string", "value": "bidi-key"}, "domain": "analytics.example.com", "path": "/", "secure": true, "httpOnly": true, "size": 20},
            {"name": "splunkweb_csrf_token_443", "value": {"type": "string", "value": "csrf"}, "domain": "analytics.example.com", "path": "/", "secure": true},
            {"name": "splunkd_8000", "value": {"type": "string", "value": "old"}, "domain": "analytics.example.com", "path": "/splunk", "secure": true, "expiry": 1},
            {"name": "splunkd_9000", "value": {"type": "base64", "value": "AAE="}, "domain": "analytics.example.com", "path": "/splunk", "secure": true},
            {"name": "idp", "value": {"type": "string", "value": "must-not-leak"}, "domain": "login.microsoftonline.com", "path": "/", "secure": true}
        ]}});
        let document = bidi_cookie_document(&response);
        assert_eq!(
            document.pointer("/result/cookies/0/expires"),
            Some(&json!(-1))
        );
        assert_eq!(
            splunk_session_key(&document, "analytics.example.com", "/splunk/", true).as_deref(),
            Some("bidi-key")
        );
        assert_eq!(
            splunk_browsing_context(
                &json!({"result": {"contexts": [
                    {"context": "blank", "url": "about:blank", "children": []},
                    {"context": "splunk", "url": "https://Analytics.example.com/splunk/en-US/app/search", "children": []}
                ]}}),
                "analytics.example.com"
            )
            .as_deref(),
            Some("splunk")
        );
    }

    #[test]
    fn powershell_bridge_is_sent_over_stdin_instead_of_the_command_line() {
        assert_eq!(
            POWERSHELL_STDIN_BOOTSTRAP,
            "$script = [Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($script))"
        );
        assert!(!POWERSHELL_STDIN_BOOTSTRAP.contains("WINDOWS_BROWSER_BRIDGE"));
        assert!(!POWERSHELL_STDIN_BOOTSTRAP.contains("EncodedCommand"));
        assert!(POWERSHELL_ARGS.iter().all(|argument| argument.len() < 256));
        let bridge = render_windows_bridge("https://analytics.example.com/", None);
        assert!(
            POWERSHELL_ARGS
                .iter()
                .all(|argument| !argument.contains(&bridge))
        );
    }

    #[test]
    fn powershell_output_accepts_utf8_and_utf16_le() {
        let output = "SPLUNK_RESULT:{\"session_key\":\"safe\"}\r\n";
        let utf16 = output
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(decode_powershell_output(output.as_bytes()), output);
        assert_eq!(decode_powershell_output(&utf16), output);
    }

    #[test]
    fn powershell_progress_accepts_only_allowlisted_secret_free_stages() {
        assert_eq!(
            powershell_progress("SPLUNK_STAGE:waiting-splunk-page"),
            Some(BrowserProgress::WaitingForSplunkPage)
        );
        assert_eq!(
            powershell_progress("SPLUNK_STAGE:validation-http-401"),
            Some(BrowserProgress::ValidationResponse(401))
        );
        assert_eq!(
            powershell_progress("SPLUNK_STAGE:validation-http-999"),
            None
        );
        assert_eq!(powershell_progress("SPLUNK_STAGE:secret-value"), None);
        assert_eq!(
            powershell_progress("SPLUNK_RESULT:{\"session_key\":\"secret\"}"),
            None
        );
    }

    #[test]
    fn progress_reporter_emits_each_milestone_once() {
        let mut events = Vec::new();
        let mut callback = |progress| events.push(progress);
        let mut reporter = ProgressReporter {
            callback: &mut callback,
            reported: HashSet::new(),
        };
        reporter.report(BrowserProgress::ReadingSessionCookies);
        reporter.report(BrowserProgress::ReadingSessionCookies);
        reporter.report(BrowserProgress::ValidationResponse(401));
        reporter.report(BrowserProgress::ValidationResponse(401));
        drop(reporter);
        assert_eq!(
            events,
            vec![
                BrowserProgress::ReadingSessionCookies,
                BrowserProgress::ValidationResponse(401)
            ]
        );
    }

    #[test]
    fn powershell_progress_clixml_is_not_presented_as_an_error() {
        let progress = br#"#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress"><MS><PR N="Record"><AV>Preparing modules for first use.</AV></PR></MS></Obj></Objs>"#;
        assert_eq!(powershell_error_detail(progress), "");
    }

    #[test]
    fn powershell_bridge_error_protocol_preserves_plain_text() {
        use base64::engine::general_purpose::STANDARD;

        let encoded =
            STANDARD.encode("Browser sign-in timed out while waiting for Splunk session cookies.");
        assert_eq!(
            powershell_bridge_error(&format!(
                "SPLUNK_BRIDGE_READY\r\nSPLUNK_ERROR:{encoded}\r\n"
            ))
            .as_deref(),
            Some("Browser sign-in timed out while waiting for Splunk session cookies.")
        );
    }

    #[test]
    fn powershell_clixml_errors_are_rendered_as_plain_text() {
        let error = br#"#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">Browser rejected &quot;Target.getTargets&quot;._x000D__x000A_</S></Objs>"#;
        assert_eq!(
            powershell_error_detail(error),
            "Browser rejected \"Target.getTargets\"."
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn stdin_powershell_command_executes_and_returns_output() {
        use std::io::Write as _;

        let powershell = find_in_path("powershell.exe").expect("powershell.exe on Windows");
        let mut child = std::process::Command::new(powershell)
            .args(POWERSHELL_ARGS)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"Write-Output 'SPLUNK_BRIDGE_READY'")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            decode_powershell_output(&output.stderr)
        );
        assert_eq!(
            decode_powershell_output(&output.stdout).trim(),
            "SPLUNK_BRIDGE_READY"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn powershell_bridge_has_valid_windows_powershell_syntax() {
        use std::io::Write as _;

        let powershell = find_in_path("powershell.exe").expect("powershell.exe on Windows");
        let parser = r#"$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(), [ref]$tokens, [ref]$errors); if ($errors.Count) { $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }; exit 1 }"#;
        let mut child = std::process::Command::new(powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                parser,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(render_windows_bridge("https://analytics.example.com/", None).as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn mock_settings(server: &MockServer) -> Settings {
        Settings {
            url: crate::config::validate_url(&server.uri()).unwrap(),
            web_url: reqwest::Url::parse(&format!(
                "http://127.0.0.1:{}/splunk/",
                server.address().port()
            ))
            .unwrap(),
            app: "search".into(),
            owner: "nobody".into(),
            timeout: 5,
            ca_cert: None,
            insecure: false,
            allow_http: false,
        }
    }

    async fn mock_current_context(key: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/authentication/current-context"))
            .and(header("authorization", format!("Splunk {key}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "entry": [{"content": {"username": "jane"}}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn cdp_session_is_validated_before_returning() {
        let server = mock_current_context("validated-key").await;
        let settings = mock_settings(&server);
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let port = server.address().port();
        let cdp = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(request) = socket.next().await {
                let request = request.unwrap();
                let request: Value = serde_json::from_str(request.to_text().unwrap()).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "Network.getCookies" => {
                        assert_eq!(request["sessionId"], "attached-page");
                        assert_eq!(
                            request["params"]["urls"][0],
                            format!("http://127.0.0.1:{port}/splunk/")
                        );
                        json!({"cookies": [
                            {"name": "splunkd_8000", "value": "validated-key", "domain": "127.0.0.1", "path": "/splunk", "secure": false, "expires": -1},
                            {"name": "splunkweb_csrf_token_8000", "value": "csrf", "domain": "127.0.0.1", "path": "/splunk", "secure": false, "expires": -1}
                        ]})
                    }
                    "Target.getTargets" => json!({"targetInfos": [{
                        "type": "page",
                        "url": format!("http://127.0.0.1:{port}/splunk/en-US/app/search"),
                        "targetId": "splunk-page"
                    }]}),
                    "Target.attachToTarget" => json!({"sessionId": "attached-page"}),
                    "Target.detachFromTarget" => json!({}),
                    method => panic!("unexpected CDP method: {method}"),
                };
                socket
                    .send(Message::Text(
                        json!({"id": request["id"], "result": result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                if request["method"] == "Target.detachFromTarget" {
                    break;
                }
            }
        });

        let mut events = Vec::new();
        let mut callback = |progress| events.push(progress);
        let mut progress = ProgressReporter {
            callback: &mut callback,
            reported: HashSet::new(),
        };
        let key = wait_for_cdp_session(&format!("ws://{address}"), &settings, None, &mut progress)
            .await
            .unwrap();
        drop(progress);
        assert_eq!(key, "validated-key");
        assert_eq!(
            events,
            vec![
                BrowserProgress::WaitingForSplunkPage,
                BrowserProgress::SplunkPageDetected,
                BrowserProgress::ReadingSessionCookies,
                BrowserProgress::SessionCookiesDetected,
                BrowserProgress::ValidatingSession,
                BrowserProgress::SessionValidated,
            ]
        );
        cdp.await.unwrap();
    }

    #[tokio::test]
    async fn bidi_session_is_validated_and_the_browser_is_closed() {
        let server = mock_current_context("bidi-key").await;
        let settings = mock_settings(&server);
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let port = server.address().port();
        let bidi = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            let mut methods = Vec::new();
            while let Some(request) = socket.next().await {
                let request = request.unwrap();
                let request: Value = serde_json::from_str(request.to_text().unwrap()).unwrap();
                let method = request["method"].as_str().unwrap().to_string();
                let result = match method.as_str() {
                    "session.new" => json!({"sessionId": "bidi", "capabilities": {}}),
                    "browsingContext.getTree" => json!({"contexts": [{
                        "context": "splunk-context",
                        "url": format!("http://127.0.0.1:{port}/splunk/en-US/"),
                        "children": []
                    }]}),
                    "storage.getCookies" => {
                        assert_eq!(
                            request["params"]["partition"],
                            json!({"type": "context", "context": "splunk-context"})
                        );
                        json!({"cookies": [
                            {"name": "splunkd_8000", "value": {"type": "string", "value": "bidi-key"}, "domain": "127.0.0.1", "path": "/", "secure": false},
                            {"name": "splunkweb_csrf_token_8000", "value": {"type": "string", "value": "csrf"}, "domain": "127.0.0.1", "path": "/", "secure": false}
                        ], "partitionKey": {}})
                    }
                    "browser.close" => json!({}),
                    method => panic!("unexpected BiDi method: {method}"),
                };
                socket
                    .send(Message::Text(
                        json!({"type": "success", "id": request["id"], "result": result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                methods.push(method);
                if methods.last().map(String::as_str) == Some("browser.close") {
                    break;
                }
            }
            methods
        });

        let (socket, _) = connect_async(format!("ws://{address}")).await.unwrap();
        let mut probe = BidiProbe::start(socket).await.unwrap();
        let mut callback = |_| {};
        let mut progress = ProgressReporter {
            callback: &mut callback,
            reported: HashSet::new(),
        };
        let key = wait_for_browser_session(&mut probe, &settings, None, &mut progress)
            .await
            .unwrap();
        probe.close().await;
        assert_eq!(key, "bidi-key");
        assert_eq!(
            bidi.await.unwrap(),
            [
                "session.new",
                "browsingContext.getTree",
                "storage.getCookies",
                "browser.close"
            ]
        );
    }

    #[tokio::test]
    async fn outdated_bidi_browsers_get_an_actionable_error() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            let request = socket.next().await.unwrap().unwrap();
            let request: Value = serde_json::from_str(request.to_text().unwrap()).unwrap();
            let reply = json!({
                "type": "error",
                "id": request["id"],
                "error": "unknown command",
                "message": "session.new"
            });
            socket
                .send(Message::Text(reply.to_string().into()))
                .await
                .unwrap();
        });

        let (socket, _) = connect_async(format!("ws://{address}")).await.unwrap();
        let Err(error) = BidiProbe::start(socket).await else {
            panic!("an unknown command must be rejected");
        };
        let message = error.message;
        assert!(
            message.contains("does not support `session.new`"),
            "{message}"
        );
        assert!(message.contains("update the browser"), "{message}");
    }
}
