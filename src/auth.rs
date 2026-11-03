//! Explicit terminal login and credentials scoped to a config file, profile, and server.
use crate::{
    Error, Result,
    cli::{Cli, Connection, LoginMethod},
    client::{Client, Credentials},
    config::{self, Settings},
};
use reqwest::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Read, Write};

const MAX_SECRET: usize = 64 * 1024;

trait Store {
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
        "Unlock your OS credential store (Linux requires a running Secret Service), or use environment credentials. No plaintext credential fallback is used.",
        ),
    }
}

fn keyring_entry(account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new("splunk-cli", account).map_err(store_error)
}

impl Store for KeyringStore {
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

fn account(options: &Connection, settings: &Settings) -> Result<String> {
    config::validate_segment(&options.profile, "profile")?;
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
    hash.update(options.profile.as_bytes());
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

fn resolve_credentials(
    environment: Option<Credentials>,
    options: &Connection,
    settings: &Settings,
    store: &impl Store,
) -> Result<Credentials> {
    if let Some(credentials) = environment {
        return Ok(credentials);
    }
    let encoded = store.load(&account(options, settings)?)?.ok_or_else(|| {
        Error::new("auth", "No saved credentials for this profile and server")
            .hint("Run splunk-cli auth login, or set environment credentials")
    })?;
    serde_json::from_str(&encoded).map_err(|_| {
        Error::new("auth", "Saved credentials could not be read")
            .hint("Run splunk-cli auth login again for this profile and server")
    })
}

pub fn credentials(options: &Connection, settings: &Settings) -> Result<Credentials> {
    resolve_credentials(
        Credentials::optional_from_env()?,
        options,
        settings,
        &KeyringStore,
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
    eprint!("{prompt}: ");
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
    let mut token = String::new();
    reader
        .take((MAX_SECRET + 1) as u64)
        .read_to_string(&mut token)
        .map_err(|_| Error::usage("Cannot read token from stdin as UTF-8"))?;
    if token.len() > MAX_SECRET {
        return Err(Error::usage("Token exceeds 64 KiB"));
    }
    validate_secret(token.trim().to_owned())
}

pub async fn login(
    cli: &Cli,
    method: Option<LoginMethod>,
    username: Option<&str>,
    token_stdin: bool,
) -> Result<Value> {
    if token_stdin {
        if std::io::stdin().is_terminal() {
            return Err(Error::usage(
                "--token-stdin requires a token piped to stdin",
            ));
        }
    } else {
        require_terminal()?;
    }
    if username.is_some() && !matches!(method, Some(LoginMethod::Password)) {
        return Err(Error::usage("--username requires --method password"));
    }
    let mut options = cli.connection.clone();
    // Read existing connection settings before prompting, so a malformed config
    // is never silently replaced. Only a missing URL is filled interactively.
    if !token_stdin && config::configured_url(&options)?.is_none() {
        options.url = Some(line("Splunk management URL (usually https://host:8089)")?);
    }
    let settings = config::resolve(&options)?;
    let credentials = if token_stdin {
        Credentials::Bearer(piped_token(std::io::stdin().lock())?)
    } else {
        let method = match method {
            Some(method) => method,
            None => {
                match line("Authentication: 1) token [default], 2) username/password")?.as_str() {
                    "" | "1" | "token" => LoginMethod::Token,
                    "2" | "password" => LoginMethod::Password,
                    _ => return Err(Error::usage("Choose 1 (token) or 2 (username/password)")),
                }
            }
        };
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
        }
    };
    let result = login_with(&options, settings, credentials, &KeyringStore).await?;
    if environment_credentials() && !cli.quiet {
        eprintln!(
            "Environment credentials are set and will override this saved login for subsequent commands."
        );
    }
    Ok(result)
}

async fn login_with(
    options: &Connection,
    settings: Settings,
    credentials: Credentials,
    store: &impl Store,
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
    let previous = store.load(&account)?;
    let encoded = serde_json::to_string(&credentials)
        .map_err(|_| Error::new("auth", "Cannot encode credentials"))?;
    store.save(&account, &encoded)?;
    if let Err(error) = config::save(options, false) {
        let restored = match previous {
            Some(previous) => store.save(&account, &previous),
            None => store.delete(&account).map(|_| ()),
        };
        if restored.is_err() {
            return Err(Error::new(
                "auth",
                "Could not save connection settings or restore the previous OS credential",
            )
            .hint("Check the config file permissions and OS credential store, then log in again"));
        }
        return Err(error);
    }
    Ok(
        json!({"authenticated": true, "profile": options.profile, "url": settings.url.as_str(),
        "credential_store": "keyring", "method": method, "environment_credentials": environment_credentials()}),
    )
}

pub fn logout(options: &Connection) -> Result<Value> {
    let settings = config::resolve(options)?;
    let removed = KeyringStore.delete(&account(options, &settings)?)?;
    Ok(
        json!({"profile": options.profile, "url": settings.url.as_str(), "removed": removed,
        "environment_credentials": environment_credentials()}),
    )
}

fn environment_credentials() -> bool {
    [
        "SPLUNK_TOKEN",
        "SPLUNK_SESSION_KEY",
        "SPLUNK_USERNAME",
        "SPLUNK_PASSWORD",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
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
            matches!(resolve_credentials(None, &options, &settings, &store).unwrap(), Credentials::Bearer(token) if token == "synthetic-token")
        );
        let mut other = settings.clone();
        other.url = config::validate_url("https://other.example:8089").unwrap();
        assert!(resolve_credentials(None, &options, &other, &store).is_err());
        let mut other = options.clone();
        other.profile = "other".into();
        assert!(resolve_credentials(None, &other, &settings, &store).is_err());
        other = options.clone();
        other.config = Some(dir.path().join("other.toml"));
        assert!(resolve_credentials(None, &other, &settings, &store).is_err());
        // A supplied environment credential bypasses even a corrupt saved entry.
        store
            .save(&account(&options, &settings).unwrap(), "broken")
            .unwrap();
        assert!(
            matches!(resolve_credentials(Some(Credentials::Session("env-session".into())), &options, &settings, &store).unwrap(), Credentials::Session(token) if token == "env-session")
        );
        assert!(resolve_credentials(None, &options, &settings, &store).is_err());
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
