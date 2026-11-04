//! Explicit login and credentials scoped to a config file, profile, and server.
use crate::{
    Error, Result,
    cli::{Cli, Connection, LoginMethod},
    client::{Client, Credentials},
    config::{self, Settings},
};
use reqwest::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{IsTerminal, Read, Write},
    path::PathBuf,
};

const MAX_SECRET: usize = 64 * 1024;

/// Only non-secret metadata is stored in TOML. A missing store is a logout tombstone.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SavedState {
    pub store: Option<String>,
    pub profile: Option<String>,
    pub url: Option<String>,
}

impl SavedState {
    fn for_connection(
        options: &Connection,
        settings: &Settings,
        store: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            store: store.map(str::to_owned),
            profile: Some(config::profile_name(options)?),
            url: Some(settings.url.to_string()),
        })
    }
}

pub(crate) fn forget(
    file: &mut config::ConfigFile,
    options: &Connection,
    settings: &Settings,
) -> Result<()> {
    file.credential_states.insert(
        account(options, settings)?,
        SavedState::for_connection(options, settings, None)?,
    );
    Ok(())
}

trait Store {
    /// Reported as `credential_store` in login output.
    fn kind(&self) -> &'static str;
    fn load(&self, account: &str) -> Result<Option<String>>;
    fn save(&self, account: &str, secret: &str) -> Result<()>;
    fn delete(&self, account: &str) -> Result<bool>;
}

struct KeyringStore;

fn store_error(error: keyring::Error) -> Error {
    match error {
        keyring::Error::TooLong(_, _) => Error::new("auth", "Credential exceeds the OS credential store size limit")
            .hint("Use a shorter token, or supply credentials through environment variables"),
        keyring::Error::Ambiguous(_) => Error::new("auth", "Multiple matching OS credentials were found")
            .hint("Remove duplicate splunk-cli entries from the OS credential manager and log in again"),
        keyring::Error::BadEncoding(_) | keyring::Error::BadDataFormat(_, _) =>
            Error::new("auth", "Saved OS credential data is malformed")
                .hint("Remove the affected splunk-cli entry from the OS credential manager and log in again"),
        _ => Error::new("auth", "Cannot access the OS credential store").hint(
        "Unlock your OS credential store (Linux requires a running Secret Service), use environment credentials, or run auth login --insecure-storage to save to a plaintext file (mode 0600).",
        ),
    }
}

fn keyring_entry(account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new("splunk-cli", account).map_err(store_error)
}

impl Store for KeyringStore {
    fn kind(&self) -> &'static str {
        "keyring"
    }

    fn load(&self, account: &str) -> Result<Option<String>> {
        match keyring_entry(account)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(store_error(error)),
        }
    }

    fn save(&self, account: &str, secret: &str) -> Result<()> {
        keyring_entry(account)?
            .set_password(secret)
            .map_err(store_error)
    }

    fn delete(&self, account: &str) -> Result<bool> {
        match keyring_entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(store_error(error)),
        }
    }
}

/// Opt-in plaintext store for systems without an OS credential store. Entries
/// share the keyring account names, in `credentials.json` next to the config.
struct FileStore {
    path: PathBuf,
}

impl FileStore {
    fn for_config(options: &Connection) -> Result<Self> {
        let config = config::path(options)?;
        if config.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .eq_ignore_ascii_case("credentials.json")
        }) {
            return Err(Error::usage(
                "The config filename credentials.json is reserved for saved credentials",
            )
            .hint("Use --config with a separate filename, such as config.toml"));
        }
        Ok(Self {
            path: config.with_file_name("credentials.json"),
        })
    }

    fn read(&self) -> Result<BTreeMap<String, String>> {
        let contents = match std::fs::read(&self.path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(error.into()),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&self.path)?.permissions().mode() & 0o077 != 0 {
                return Err(Error::new(
                    "auth",
                    "The saved credential file is readable by other users",
                )
                .hint(format!(
                    "Run chmod 600 {}, or delete it and log in again",
                    self.path.display()
                )));
            }
        }
        serde_json::from_slice(&contents).map_err(|_| {
            Error::new("auth", "The saved credential file is malformed")
                .hint(format!("Delete {} and log in again", self.path.display()))
        })
    }

    fn update<T>(&self, change: impl FnOnce(&mut BTreeMap<String, String>) -> T) -> Result<T> {
        let _lock = config::lock(&self.path)?;
        let mut entries = self.read()?;
        let result = change(&mut entries);
        let contents = serde_json::to_vec_pretty(&entries)
            .map_err(|_| Error::new("io", "Cannot serialize saved credentials"))?;
        config::write_atomic(&self.path, &contents)?;
        Ok(result)
    }
}

impl Store for FileStore {
    fn kind(&self) -> &'static str {
        "file"
    }

    fn load(&self, account: &str) -> Result<Option<String>> {
        Ok(self.read()?.remove(account))
    }

    fn save(&self, account: &str, secret: &str) -> Result<()> {
        self.update(|entries| {
            entries.insert(account.into(), secret.into());
        })
    }

    fn delete(&self, account: &str) -> Result<bool> {
        if !self.path.exists() {
            return Ok(false);
        }
        self.update(|entries| entries.remove(account).is_some())
    }
}

fn account(options: &Connection, settings: &Settings) -> Result<String> {
    let profile = config::profile_name(options)?;
    let path = std::path::absolute(config::path(options)?)?;
    // Resolve existing parent aliases, including when nested config directories
    // do not exist yet. The identity stays stable across the first config save.
    let path = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => canonical_parent(parent).join(name),
        _ => path,
    };
    let mut hash = Sha256::new();
    hash.update(path.as_os_str().as_encoded_bytes());
    hash.update(b"\0");
    hash.update(profile.as_bytes());
    hash.update(b"\0");
    hash.update(settings.url.as_str().as_bytes());
    Ok(format!("profile:{:x}", hash.finalize()))
}

fn canonical_parent(path: &std::path::Path) -> std::path::PathBuf {
    if let Ok(path) = path.canonicalize() {
        return path;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => canonical_parent(parent).join(name),
        _ => path.to_owned(),
    }
}

/// Environment credentials win; otherwise the first store holding an entry is
/// used. A store error is reported only when no other store has the entry.
fn resolve_credentials(
    environment: Option<Credentials>,
    options: &Connection,
    settings: &Settings,
    stores: &[&dyn Store],
) -> Result<Credentials> {
    resolve_with_source(environment, options, settings, stores).map(|(credentials, _)| credentials)
}

fn resolve_with_source(
    environment: Option<Credentials>,
    options: &Connection,
    settings: &Settings,
    stores: &[&dyn Store],
) -> Result<(Credentials, &'static str)> {
    if let Some(credentials) = environment {
        return Ok((credentials, "environment"));
    }
    let account = account(options, settings)?;
    let state = config::read(options)?.credential_states.remove(&account);
    if state.as_ref().is_some_and(|state| state.store.is_none()) {
        return Err(
            Error::new("auth", "No saved credentials for this profile and server")
                .hint("Run splunk-cli auth login, or set environment credentials"),
        );
    }
    if state
        .as_ref()
        .and_then(|state| state.store.as_deref())
        .is_some_and(|kind| !matches!(kind, "keyring" | "file"))
    {
        return Err(
            Error::new("auth", "The selected credential store is not supported")
                .hint("Run splunk-cli auth login to select a supported credential store"),
        );
    }
    let mut failure = None;
    let mut encoded = None;
    for store in stores {
        if state
            .as_ref()
            .and_then(|state| state.store.as_deref())
            .is_some_and(|kind| kind != store.kind())
        {
            continue;
        }
        match store.load(&account) {
            Ok(Some(entry)) => {
                encoded = Some((entry, store.kind()));
                break;
            }
            Ok(None) => {}
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    let (encoded, source) = match (encoded, failure) {
        (Some(encoded), _) => encoded,
        (None, Some(error)) => return Err(error),
        (None, None) => {
            return Err(
                Error::new("auth", "No saved credentials for this profile and server")
                    .hint("Run splunk-cli auth login, or set environment credentials"),
            );
        }
    };
    serde_json::from_str(&encoded)
        .map(|credentials| (credentials, source))
        .map_err(|_| {
            Error::new("auth", "Saved credentials could not be read")
                .hint("Run splunk-cli auth login again for this profile and server")
        })
}

pub fn credentials(options: &Connection, settings: &Settings) -> Result<Credentials> {
    resolve_credentials(
        Credentials::optional_from_env()?,
        options,
        settings,
        &[&KeyringStore, &FileStore::for_config(options)?],
    )
}

fn require_terminal() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(Error::usage("Interactive login requires a terminal on stdin and stderr")
            .hint("Run auth login in a terminal, or use auth login --token-stdin with --url or a saved URL"));
    }
    Ok(())
}

fn line(prompt: &str) -> Result<String> {
    write!(std::io::stderr().lock(), "{prompt}: ")?;
    std::io::stderr().flush()?;
    let mut value = String::new();
    if std::io::stdin().read_line(&mut value)? == 0 {
        return Err(Error::usage("Login canceled: no input received"));
    }
    Ok(value.trim().to_owned())
}

fn validate_secret(secret: String) -> Result<String> {
    if secret.is_empty() || secret.len() > MAX_SECRET || secret.chars().any(char::is_control) {
        return Err(Error::usage(
            "Credential must be nonempty, at most 64 KiB, and contain no control characters",
        ));
    }
    Ok(secret)
}

fn piped_token(reader: impl Read) -> Result<String> {
    let mut token = Vec::new();
    reader
        .take((MAX_SECRET + 1) as u64)
        .read_to_end(&mut token)?;
    if token.len() > MAX_SECRET {
        return Err(Error::usage("Token exceeds 64 KiB"));
    }
    let token = String::from_utf8(token)
        .map_err(|_| Error::usage("Cannot read token from stdin as UTF-8"))?;
    validate_secret(token.trim().to_owned())
}

fn confirm(prompt: &str) -> Result<bool> {
    Ok(matches!(
        line(&format!("{prompt} [y/N]"))?
            .to_ascii_lowercase()
            .as_str(),
        "y" | "yes"
    ))
}

/// Pick the store before any credential is entered, so an unusable OS
/// credential store fails (or falls back with consent) before sign-in.
fn choose_store(
    options: &Connection,
    settings: &Settings,
    insecure_storage: bool,
    interactive: bool,
) -> Result<Box<dyn Store>> {
    let file = FileStore::for_config(options)?;
    if insecure_storage {
        return Ok(Box::new(file));
    }
    let Err(error) = KeyringStore.load(&account(options, settings)?) else {
        return Ok(Box::new(KeyringStore));
    };
    if interactive {
        crate::output::diagnostic(format_args!("{}", crate::output::terminal(&error.message)));
        if confirm(&format!(
            "Save credentials in plaintext at {} (mode 0600) instead?",
            crate::output::terminal(&file.path.to_string_lossy())
        ))? {
            return Ok(Box::new(file));
        }
    }
    Err(error)
}

pub struct LoginRequest<'a> {
    pub method: Option<LoginMethod>,
    pub username: Option<&'a str>,
    pub token_stdin: bool,
    pub browser: Option<std::ffi::OsString>,
    pub insecure_storage: bool,
}

pub async fn login(cli: &Cli, request: LoginRequest<'_>) -> Result<Value> {
    let LoginRequest {
        method,
        username,
        token_stdin,
        browser,
        insecure_storage,
    } = request;
    let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let mut options = cli.connection.clone();
    if token_stdin {
        if std::io::stdin().is_terminal() {
            return Err(Error::usage(
                "--token-stdin requires a token piped to stdin",
            ));
        }
    } else if !(matches!(method, Some(LoginMethod::Browser))
        && config::configured_url(&options)?.is_some())
    {
        // Browser sign-in with a known URL needs no prompts; everything else does.
        require_terminal()?;
    }
    if username.is_some() && !matches!(method, Some(LoginMethod::Password)) {
        return Err(Error::usage("--username requires --method password"));
    }
    options.profile = Some(config::profile_name(&options)?);
    // Read existing connection settings before prompting, so a malformed config
    // is never silently replaced. Only a missing URL is filled interactively.
    if !token_stdin && config::configured_url(&options)?.is_none() {
        options.url = Some(line("Splunk management URL (usually https://host:8089)")?);
    }
    let settings = config::resolve(&options)?;
    let method = match (token_stdin, method) {
        (true, _) => LoginMethod::Token,
        (false, Some(method)) => method,
        (false, None) => match line(
            "Authentication: 1) token [default], 2) username/password, 3) browser (SSO)",
        )?
        .as_str()
        {
            "" | "1" | "token" => LoginMethod::Token,
            "2" | "password" => LoginMethod::Password,
            "3" | "browser" => LoginMethod::Browser,
            _ => {
                return Err(Error::usage(
                    "Choose 1 (token), 2 (username/password), or 3 (browser)",
                ));
            }
        },
    };
    let store = choose_store(
        &options,
        &settings,
        insecure_storage,
        terminal && !token_stdin,
    )?;
    let credentials = if token_stdin {
        Credentials::Bearer(piped_token(std::io::stdin().lock())?)
    } else {
        match method {
            LoginMethod::Token => Credentials::Bearer(validate_secret(
                rpassword::prompt_password("Splunk token (hidden): ")?
                    .trim()
                    .to_owned(),
            )?),
            LoginMethod::Password => {
                let user = match username {
                    Some(user) => user.to_owned(),
                    None => line("Splunk username")?,
                };
                if user.trim().is_empty()
                    || user.contains(':')
                    || user.chars().any(char::is_control)
                {
                    return Err(Error::usage(
                        "Username must be nonempty and contain no colons or control characters",
                    ));
                }
                Credentials::Basic(
                    user,
                    validate_secret(rpassword::prompt_password("Splunk password (hidden): ")?)?,
                )
            }
            LoginMethod::Browser => {
                Credentials::Session(browser_session(&settings, browser, cli.quiet).await?)
            }
        }
    };
    let result = login_with(&options, settings.clone(), credentials, store.as_ref()).await?;
    // Remove a stale entry from the other store so lookups cannot find it first.
    let account = account(&options, &settings)?;
    let cleanup = if store.kind() == "file" {
        KeyringStore.delete(&account)
    } else {
        FileStore::for_config(&options)?.delete(&account)
    };
    if cleanup.is_err() && store.kind() == "file" {
        crate::output::diagnostic(format_args!(
            "Warning: an obsolete OS credential could not be removed. This connection will continue using the selected file login. Unlock the OS store and run auth migrate --to keyring to move it back."
        ));
    }
    if environment_credentials() && !cli.quiet {
        crate::output::diagnostic(format_args!(
            "Environment credentials are set and will override this saved login for subsequent commands."
        ));
    }
    Ok(result)
}

async fn browser_session(
    settings: &Settings,
    browser: Option<std::ffi::OsString>,
    quiet: bool,
) -> Result<String> {
    if !quiet {
        crate::output::diagnostic(format_args!(
            "Opening a private browser window for {}",
            settings.web_url
        ));
        crate::output::diagnostic(format_args!(
            "Complete your normal SSO sign-in there. This CLI never receives your identity-provider password."
        ));
    }
    let started = std::time::Instant::now();
    crate::interrupt::run(crate::browser::browser_login(
        settings,
        browser,
        |progress| {
            if !quiet {
                crate::output::diagnostic(format_args!(
                    "[+{:>6.1}s] browser: {}",
                    started.elapsed().as_secs_f64(),
                    progress.message()
                ));
            }
        },
    ))
    .await
}

async fn login_with(
    options: &Connection,
    settings: Settings,
    credentials: Credentials,
    store: &dyn Store,
) -> Result<Value> {
    let method = match &credentials {
        Credentials::Bearer(_) => "token",
        Credentials::Session(_) => "session",
        Credentials::Basic(_, _) => "password",
    };
    let client = Client::new(settings.clone(), credentials.clone())?;
    let response = client
        .request(
            Method::GET,
            false,
            &["authentication", "current-context"],
            &[],
        )
        .await?;
    if !response["entry"]
        .as_array()
        .and_then(|entries| entries.first())
        .is_some_and(|entry| entry["content"].is_object())
    {
        return Err(Error::invalid_response());
    }
    // Save only after validation succeeds. A failed keychain write must leave
    // the config unchanged; a failed config write restores the old credential.
    let account = account(options, &settings)?;
    let encoded = serde_json::to_string(&credentials)
        .map_err(|_| Error::new("auth", "Cannot encode credentials"))?;
    config::transaction(options, |file, path| {
        config::apply_settings(options, file)?;
        let previous = store.load(&account)?;
        store.save(&account, &encoded)?;
        file.credential_states.insert(
            account.clone(),
            SavedState::for_connection(options, &settings, Some(store.kind()))?,
        );
        if let Err(error) = config::persist(file, path) {
            let restored = match previous {
                Some(previous) => store.save(&account, &previous),
                None => store.delete(&account).map(|_| ()),
            };
            if restored.is_err() {
                return Err(Error::new(
                    "auth",
                    "Could not save connection settings or restore the previous OS credential",
                )
                .hint(
                    "Check the config file permissions and OS credential store, then log in again",
                ));
            }
            return Err(error);
        }
        Ok(())
    })?;
    Ok(
        json!({"authenticated": true, "profile": config::profile_name(options)?, "url": settings.url.as_str(),
        "credential_store": store.kind(), "method": method, "environment_credentials": environment_credentials()}),
    )
}

pub fn logout(options: &Connection) -> Result<Value> {
    let mut selected = options.clone();
    selected.profile = Some(config::profile_name(options)?);
    let options = &selected;
    let settings = config::resolve(options)?;
    let account = account(options, &settings)?;
    let removed = config::transaction(options, |file, path| {
        if file
            .credential_states
            .get(&account)
            .is_some_and(|state| state.store.is_none())
        {
            let mut removed = false;
            for store in [
                &KeyringStore as &dyn Store,
                &FileStore::for_config(options)?,
            ] {
                match store.delete(&account) {
                    Ok(deleted) => removed |= deleted,
                    Err(_) => crate::output::diagnostic(format_args!(
                        "Warning: obsolete {} credentials could not be cleared; this connection remains logged out. Retry logout when that store is available.",
                        store.kind()
                    )),
                }
            }
            return Ok(removed);
        }
        forget(file, options, &settings)?;
        remove_from_stores(
            &account,
            &[&KeyringStore, &FileStore::for_config(options)?],
            || config::persist(file, path),
        )
    })?;
    Ok(
        json!({"profile": config::profile_name(options)?, "url": settings.url.as_str(), "removed": removed,
        "environment_credentials": environment_credentials()}),
    )
}

pub fn migrate(
    options: &Connection,
    to: crate::cli::CredentialStore,
    insecure_storage: bool,
    dry_run: bool,
) -> Result<Value> {
    use crate::cli::CredentialStore;
    if matches!(to, CredentialStore::File) && !insecure_storage && !dry_run {
        return Err(
            Error::usage("Migration to a plaintext file requires --insecure-storage")
                .hint("Preview with --dry-run, or use --to keyring for the OS credential store"),
        );
    }
    let mut selected = options.clone();
    selected.profile = Some(config::profile_name(options)?);
    let options = &selected;
    let settings = config::resolve(options)?;
    let account = account(options, &settings)?;
    let file = FileStore::for_config(options)?;
    let stores: [&dyn Store; 2] = [&KeyringStore, &file];
    let target = stores[if matches!(to, CredentialStore::File) {
        1
    } else {
        0
    }];
    let change = |config: &mut config::ConfigFile, path: &std::path::Path| -> Result<Value> {
        // Deliberately migrate the saved login even when environment credentials override it.
        let (credentials, source) = resolve_with_source(None, options, &settings, &stores)?;
        let already_selected =
            source == target.kind() && config.credential_states.contains_key(&account);
        let result = json!({"dry_run": dry_run, "changed": !already_selected, "profile": config::profile_name(options)?, "url": settings.url.as_str(), "previous_store": source, "credential_store": target.kind(), "environment_credentials": environment_credentials()});
        if dry_run || already_selected {
            return Ok(result);
        }
        let encoded = serde_json::to_string(&credentials)
            .map_err(|_| Error::new("auth", "Cannot encode credentials"))?;
        let previous = target.load(&account)?;
        target.save(&account, &encoded)?;
        config.credential_states.insert(
            account.clone(),
            SavedState::for_connection(options, &settings, Some(target.kind()))?,
        );
        if let Err(error) = config::persist(config, path) {
            let restored = match previous {
                Some(ref secret) => target.save(&account, secret),
                None => target.delete(&account).map(|_| ()),
            };
            return Err(if restored.is_err() {
                Error::new(
                    "auth",
                    "Credential migration failed and the destination could not be restored",
                )
                .hint("Log in again after checking config and credential store permissions")
            } else {
                error
            });
        }
        if source != target.kind()
            && stores
                .iter()
                .find(|store| store.kind() == source)
                .is_some_and(|store| store.delete(&account).is_err())
        {
            crate::output::diagnostic(format_args!(
                "Warning: the old credential could not be removed. The selected destination will continue to be used; remove the obsolete entry when that store becomes available."
            ));
        }
        Ok(result)
    };
    if dry_run {
        change(&mut config::read(options)?, &config::path(options)?)
    } else {
        config::transaction(options, change)
    }
}

pub fn environment_credentials() -> bool {
    [
        "SPLUNK_TOKEN",
        "SPLUNK_SESSION_KEY",
        "SPLUNK_USERNAME",
        "SPLUNK_PASSWORD",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
}

pub(crate) fn rename_saved(
    options: &Connection,
    from: &str,
    to: &str,
    current_url: Option<&str>,
    file: &mut config::ConfigFile,
    keep: bool,
    commit: impl FnOnce(&config::ConfigFile) -> Result<()>,
) -> Result<Option<usize>> {
    let credential_file = FileStore::for_config(options)?;
    let stores: [&dyn Store; 2] = [&KeyringStore, &credential_file];
    let mut urls = std::collections::BTreeSet::new();
    if let Some(url) = current_url {
        urls.insert(url.to_owned());
    }
    for state in file.credential_states.values() {
        if state.profile.as_deref() == Some(from)
            && let Some(url) = &state.url
        {
            urls.insert(url.clone());
        }
    }
    let mut source_options = options.clone();
    source_options.profile = Some(from.into());
    let mut target_options = options.clone();
    target_options.profile = Some(to.into());
    let mut copied: Vec<(&dyn Store, String)> = Vec::new();
    let mut obsolete: Vec<(&dyn Store, String)> = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let change = (|| {
        for url in urls {
            let url = match config::validate_url(&url) {
                Ok(url) => url,
                Err(_) if keep => continue,
                Err(error) => {
                    return Err(error.hint(
                        "Use --keep-credentials to rename settings without moving saved logins",
                    ));
                }
            };
            if !visited.insert(url.to_string()) {
                continue;
            }
            let settings = Settings {
                web_url: url.clone(),
                url,
                app: "search".into(),
                owner: "nobody".into(),
                timeout: 30,
                ca_cert: None,
                insecure: false,
                allow_http: false,
            };
            let old = account(&source_options, &settings)?;
            let new = account(&target_options, &settings)?;
            if keep {
                forget(file, &target_options, &settings)?;
                continue;
            }
            let logged_out = file
                .credential_states
                .get(&old)
                .is_some_and(|state| state.store.is_none());
            let login = if logged_out {
                None
            } else {
                match resolve_with_source(None, &source_options, &settings, &stores) {
                    Ok(login) => Some(login),
                    Err(error) if error.kind == "auth" && error.message.starts_with("No saved credentials") => None,
                    Err(error) => return Err(error.hint("Unlock the credential store, or use --keep-credentials to rename settings and log in again under the new name")),
                }
            };
            forget(file, &source_options, &settings)?;
            if let Some((credentials, source)) = login {
                let store = *stores
                    .iter()
                    .find(|store| store.kind() == source)
                    .expect("resolved store");
                if store.load(&new)?.is_some() {
                    return Err(Error::new("conflict", "Saved credentials already exist under the destination profile name")
                        .hint("Choose another name, or remove the destination's saved login before renaming"));
                }
                let encoded = serde_json::to_string(&credentials)
                    .map_err(|_| Error::new("auth", "Cannot encode credentials"))?;
                store.save(&new, &encoded)?;
                copied.push((store, new.clone()));
                obsolete.push((store, old));
                file.credential_states.insert(
                    new,
                    SavedState::for_connection(&target_options, &settings, Some(source))?,
                );
            } else {
                forget(file, &target_options, &settings)?;
            }
        }
        commit(file)
    })();
    if let Err(error) = change {
        let mut restored = true;
        for (store, account) in &copied {
            restored &= store.delete(account).is_ok();
        }
        return Err(if restored {
            error
        } else {
            Error::new("auth", "Profile rename failed and copied credentials could not be removed").hint("The original profile and credentials remain available; remove the unused destination credentials when its store becomes available")
        });
    }
    for (store, account) in obsolete {
        if store.delete(&account).is_err() {
            crate::output::diagnostic(format_args!(
                "Warning: an obsolete credential under the old profile name could not be removed. It will not be selected; remove it when that store is available."
            ));
        }
    }
    if keep {
        crate::output::diagnostic(format_args!(
            "Warning: saved logins were kept under the old name. Run auth login for the renamed profile."
        ));
        Ok(None)
    } else {
        Ok(Some(copied.len()))
    }
}

pub fn remove_for_profile(
    options: &Connection,
    settings: &Settings,
    commit: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    let account = account(options, settings)?;
    remove_from_stores(
        &account,
        &[&KeyringStore, &FileStore::for_config(options)?],
        commit,
    )
}

fn remove_from_stores(
    account: &str,
    stores: &[&dyn Store],
    commit: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    let mut previous = Vec::new();
    let mut failure = None;
    for store in stores {
        match store.load(account) {
            Ok(Some(secret)) => previous.push((*store, secret)),
            Ok(None) => {}
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    // Match logout's file fallback: an inaccessible keyring does not prevent
    // removing a usable file credential. Without an entry, report the failure.
    if previous.is_empty()
        && let Some(error) = failure
    {
        return Err(error);
    }
    let mut deleted = Vec::new();
    let change = (|| {
        for (store, secret) in &previous {
            if store.delete(account)? {
                deleted.push((*store, secret));
            }
        }
        commit()
    })();
    if let Err(error) = change {
        let mut restored = true;
        for (store, secret) in deleted {
            restored &= store.save(account, secret).is_ok();
        }
        if !restored {
            return Err(Error::new(
                "io",
                "Profile update failed and credentials could not be restored; log in again",
            ));
        }
        return Err(error);
    }
    Ok(!deleted.is_empty())
}

/// Metadata only; a locally available credential is not proof of authentication.
pub fn status(options: &Connection, settings: &Settings) -> Result<Value> {
    load_status(options, settings).map(|(_, metadata)| metadata)
}

pub(crate) fn load_status(
    options: &Connection,
    settings: &Settings,
) -> Result<(Credentials, Value)> {
    let (credentials, source) = resolve_with_source(
        Credentials::optional_from_env()?,
        options,
        settings,
        &[&KeyringStore, &FileStore::for_config(options)?],
    )?;
    let method = match &credentials {
        Credentials::Bearer(_) => "token",
        Credentials::Session(_) => "session",
        Credentials::Basic(_, _) => "password",
    };
    let selection = if source == "environment" {
        "environment"
    } else if config::read(options)?
        .credential_states
        .contains_key(&account(options, settings)?)
    {
        "saved"
    } else {
        "legacy"
    };
    let expires_at = match &credentials {
        Credentials::Bearer(token) => token
            .split('.')
            .nth(1)
            .filter(|part| part.len() <= 16 * 1024)
            .and_then(|part| {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(part)
                    .ok()
            })
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|claims| claims["exp"].as_u64()),
        _ => None,
    };
    let expiry_status = expires_at
        .map(|expiry| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if expiry <= now {
                "expired"
            } else {
                "not_expired"
            }
        })
        .unwrap_or("unknown");
    Ok((
        credentials,
        json!({"available": true, "source": source, "method": method, "verified": false, "selection": selection,
            "expires_at": expires_at, "expiry_status": expiry_status, "expiry_source": expires_at.map(|_| "unverified_token_claim")}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::{cell::RefCell, collections::BTreeMap};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[derive(Default)]
    struct MemoryStore(RefCell<BTreeMap<String, String>>);
    impl Store for MemoryStore {
        fn kind(&self) -> &'static str {
            "keyring"
        }
        fn load(&self, account: &str) -> Result<Option<String>> {
            Ok(self.0.borrow().get(account).cloned())
        }
        fn save(&self, account: &str, secret: &str) -> Result<()> {
            self.0.borrow_mut().insert(account.into(), secret.into());
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<bool> {
            Ok(self.0.borrow_mut().remove(account).is_some())
        }
    }

    struct UnwritableStore;
    impl Store for UnwritableStore {
        fn kind(&self) -> &'static str {
            "keyring"
        }
        fn load(&self, _: &str) -> Result<Option<String>> {
            Ok(None)
        }
        fn save(&self, _: &str, _: &str) -> Result<()> {
            Err(store_error(keyring::Error::NoDefaultStore))
        }
        fn delete(&self, _: &str) -> Result<bool> {
            panic!("A failed save must not delete a credential")
        }
    }

    fn options(dir: &std::path::Path, url: &str) -> Connection {
        Cli::parse_from([
            "splunk-cli",
            "--config",
            dir.join("config.toml").to_str().unwrap(),
            "--profile",
            "work",
            "--url",
            url,
            "auth",
            "status",
        ])
        .connection
    }

    #[tokio::test]
    async fn validated_login_is_reused_and_isolated_by_server_profile_and_file() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/authentication/current-context"))
            .and(header("authorization", "Bearer synthetic-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"entry": [{"content": {"username": "test"}}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let mut options = options(dir.path(), &server.uri());
        options.config = Some(dir.path().join("nested/deep/config.toml"));
        let settings = config::resolve(&options).unwrap();
        let original_account = account(&options, &settings).unwrap();
        let store = MemoryStore::default();
        let result = login_with(
            &options,
            settings.clone(),
            Credentials::Bearer("synthetic-token".into()),
            &store,
        )
        .await
        .unwrap();
        assert_eq!(result["credential_store"], "keyring");
        assert_eq!(account(&options, &settings).unwrap(), original_account);
        assert!(!result.to_string().contains("synthetic-token"));
        let contents = std::fs::read_to_string(config::path(&options).unwrap()).unwrap();
        assert!(!contents.contains("synthetic-token"));
        assert!(
            matches!(resolve_credentials(None, &options, &settings, &[&store]).unwrap(), Credentials::Bearer(token) if token == "synthetic-token")
        );
        let mut other = settings.clone();
        other.url = config::validate_url("https://other.example:8089").unwrap();
        assert!(resolve_credentials(None, &options, &other, &[&store]).is_err());
        let mut other = options.clone();
        other.profile = Some("other".into());
        assert!(resolve_credentials(None, &other, &settings, &[&store]).is_err());
        other = options.clone();
        other.config = Some(dir.path().join("other.toml"));
        assert!(resolve_credentials(None, &other, &settings, &[&store]).is_err());
        // A supplied environment credential bypasses even a corrupt saved entry.
        store
            .save(&account(&options, &settings).unwrap(), "broken")
            .unwrap();
        assert!(
            matches!(resolve_credentials(Some(Credentials::Session("env-session".into())), &options, &settings, &[&store]).unwrap(), Credentials::Session(token) if token == "env-session")
        );
        assert!(resolve_credentials(None, &options, &settings, &[&store]).is_err());
        assert!(
            store
                .delete(&account(&options, &settings).unwrap())
                .unwrap()
        );
        assert!(
            !store
                .delete(&account(&options, &settings).unwrap())
                .unwrap()
        );
    }

    #[tokio::test]
    async fn rejected_password_login_preserves_saved_credentials_and_config() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/authentication/current-context"))
            .and(header(
                "authorization",
                "Basic dGVzdDpyZWplY3RlZC1wYXNzd29yZA==",
            ))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(json!({"messages": [{"text": "rejected-password denied"}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path(), &server.uri());
        config::save(&options, false).unwrap();
        let before = std::fs::read(config::path(&options).unwrap()).unwrap();
        let settings = config::resolve(&options).unwrap();
        let store = MemoryStore::default();
        let account = account(&options, &settings).unwrap();
        store.save(&account, "previous").unwrap();
        let error = login_with(
            &options,
            settings,
            Credentials::Basic("test".into(), "rejected-password".into()),
            &store,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind, "auth");
        assert!(!error.envelope().to_string().contains("rejected-password"));
        assert_eq!(store.load(&account).unwrap().as_deref(), Some("previous"));
        assert_eq!(
            std::fs::read(config::path(&options).unwrap()).unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn malformed_login_response_does_not_store_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path(), &server.uri());
        let store = MemoryStore::default();
        let error = login_with(
            &options,
            config::resolve(&options).unwrap(),
            Credentials::Bearer("synthetic-token".into()),
            &store,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind, "invalid_response");
        assert!(store.0.borrow().is_empty());
        assert!(!config::path(&options).unwrap().exists());
    }

    #[tokio::test]
    async fn failed_keychain_write_preserves_config_and_config_failure_restores_keychain() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"entry": [{"content": {"username": "test"}}]})),
            )
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let mut options = options(dir.path(), &server.uri());
        config::save(&options, false).unwrap();
        let before = std::fs::read(config::path(&options).unwrap()).unwrap();
        let settings = config::resolve(&options).unwrap();
        assert!(
            login_with(
                &options,
                settings.clone(),
                Credentials::Bearer("new-token".into()),
                &UnwritableStore
            )
            .await
            .is_err()
        );
        assert_eq!(
            std::fs::read(config::path(&options).unwrap()).unwrap(),
            before
        );

        // A directory cannot be a config file, so saving it must fail after
        // the in-memory keychain has accepted the replacement credential.
        options.config = Some(dir.path().to_owned());
        let store = MemoryStore::default();
        let account = account(&options, &settings).unwrap();
        store.save(&account, "previous").unwrap();
        assert!(
            login_with(
                &options,
                settings.clone(),
                Credentials::Bearer("new-token".into()),
                &store
            )
            .await
            .is_err()
        );
        assert_eq!(store.load(&account).unwrap().as_deref(), Some("previous"));
        store.delete(&account).unwrap();
        assert!(
            login_with(
                &options,
                settings,
                Credentials::Bearer("new-token".into()),
                &store
            )
            .await
            .is_err()
        );
        assert!(store.load(&account).unwrap().is_none());
    }

    struct BrokenStore;
    impl Store for BrokenStore {
        fn kind(&self) -> &'static str {
            "keyring"
        }
        fn load(&self, _: &str) -> Result<Option<String>> {
            Err(store_error(keyring::Error::NoDefaultStore))
        }
        fn save(&self, _: &str, _: &str) -> Result<()> {
            Err(store_error(keyring::Error::NoDefaultStore))
        }
        fn delete(&self, _: &str) -> Result<bool> {
            Err(store_error(keyring::Error::NoDefaultStore))
        }
    }

    #[test]
    fn file_store_is_private_and_isolated_per_account() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path(), "https://splunk.example:8089");
        let store = FileStore::for_config(&options).unwrap();
        assert_eq!(store.path, dir.path().join("credentials.json"));
        assert!(store.load("a").unwrap().is_none());
        assert!(!store.delete("a").unwrap());
        store.save("a", "first").unwrap();
        store.save("b", "second").unwrap();
        assert_eq!(store.load("a").unwrap().as_deref(), Some("first"));
        assert!(store.delete("a").unwrap());
        assert!(store.load("a").unwrap().is_none());
        assert_eq!(store.load("b").unwrap().as_deref(), Some("second"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&store.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let error = store.load("b").err().unwrap();
            assert_eq!(error.kind, "auth");
            assert!(!error.envelope().to_string().contains("second"));
            std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&store.path, "not json").unwrap();
        let error = store.load("b").err().unwrap();
        assert_eq!(error.kind, "auth");
    }

    #[test]
    fn unavailable_keyring_falls_back_to_saved_file_entry() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path(), "https://splunk.example:8089");
        let settings = config::resolve(&options).unwrap();
        let file = FileStore::for_config(&options).unwrap();
        // Without a file entry the keyring failure is what the user needs to see.
        let error = resolve_credentials(None, &options, &settings, &[&BrokenStore, &file])
            .err()
            .unwrap();
        assert!(error.message.contains("OS credential store"));
        file.save(
            &account(&options, &settings).unwrap(),
            &serde_json::to_string(&Credentials::Session("file-session".into())).unwrap(),
        )
        .unwrap();
        assert!(
            matches!(resolve_credentials(None, &options, &settings, &[&BrokenStore, &file]).unwrap(), Credentials::Session(key) if key == "file-session")
        );
    }

    #[tokio::test]
    async fn file_login_reports_file_store_and_keeps_secrets_out_of_config() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/authentication/current-context"))
            .and(header("authorization", "Splunk synthetic-session"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"entry": [{"content": {"username": "test"}}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path(), &server.uri());
        let settings = config::resolve(&options).unwrap();
        let file = FileStore::for_config(&options).unwrap();
        let result = login_with(
            &options,
            settings.clone(),
            Credentials::Session("synthetic-session".into()),
            &file,
        )
        .await
        .unwrap();
        assert_eq!(result["credential_store"], "file");
        assert_eq!(result["method"], "session");
        assert!(!result.to_string().contains("synthetic-session"));
        let contents = std::fs::read_to_string(config::path(&options).unwrap()).unwrap();
        assert!(!contents.contains("synthetic-session"));
        assert!(
            matches!(resolve_credentials(None, &options, &settings, &[&MemoryStore::default(), &file]).unwrap(), Credentials::Session(key) if key == "synthetic-session")
        );
    }

    #[test]
    fn profile_removal_cleans_both_stores_and_restores_them_on_failure() {
        let keyring = MemoryStore::default();
        let file = MemoryStore::default();
        keyring.save("account", "keyring-secret").unwrap();
        file.save("account", "file-secret").unwrap();
        assert!(
            remove_from_stores("account", &[&keyring, &file], || Err(Error::new(
                "io",
                "cannot save config"
            )))
            .is_err()
        );
        assert_eq!(
            keyring.load("account").unwrap().as_deref(),
            Some("keyring-secret")
        );
        assert_eq!(
            file.load("account").unwrap().as_deref(),
            Some("file-secret")
        );
        assert!(remove_from_stores("account", &[&keyring, &file], || Ok(())).unwrap());
        assert!(keyring.load("account").unwrap().is_none());
        assert!(file.load("account").unwrap().is_none());
        keyring.save("account", "keyring-secret").unwrap();
        assert!(remove_from_stores("account", &[&keyring, &BrokenStore], || Ok(())).unwrap());
        assert!(keyring.load("account").unwrap().is_none());
        file.save("account", "file-secret").unwrap();
        assert!(remove_from_stores("account", &[&BrokenStore, &file], || Ok(())).unwrap());
        assert!(file.load("account").unwrap().is_none());
        assert!(
            remove_from_stores("account", &[&BrokenStore, &file], || panic!(
                "must preserve settings when no store can confirm an entry"
            ))
            .is_err()
        );
    }

    #[test]
    fn piped_tokens_are_bounded_and_never_echoed_in_errors() {
        assert_eq!(
            piped_token("synthetic-token\r\n".as_bytes()).unwrap(),
            "synthetic-token"
        );
        for token in [
            String::new(),
            "synthetic\nsecret".into(),
            "x".repeat(MAX_SECRET + 1),
        ] {
            assert!(piped_token(token.as_bytes()).is_err());
        }
    }
}
