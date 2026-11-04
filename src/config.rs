use crate::{Error, Result, cli::Connection};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    /// Non-secret store selection. Tombstones prevent obsolete credentials from resurfacing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credential_states: BTreeMap<String, crate::auth::SavedState>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub url: Option<String>,
    pub app: Option<String>,
    pub owner: Option<String>,
    pub timeout: Option<u64>,
    pub ca_cert: Option<PathBuf>,
    pub web_url: Option<String>,
}

#[derive(Clone)]
pub struct Settings {
    pub url: Url,
    /// Splunk Web URL used for browser sign-in.
    pub web_url: Url,
    pub app: String,
    pub owner: String,
    pub timeout: u64,
    pub ca_cert: Option<PathBuf>,
    pub insecure: bool,
    pub allow_http: bool,
}

pub fn path(options: &Connection) -> Result<PathBuf> {
    let path = options
        .config
        .clone()
        .or_else(|| {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .or_else(|| dirs::home_dir().map(|p| p.join(".config")))
                .map(|p| p.join("splunk-cli/config.toml"))
        })
        .ok_or_else(|| Error::usage("Cannot determine the config path; set --config"))?;
    if path.to_str().is_none() {
        return Err(Error::usage("Configuration path must be UTF-8"));
    }
    Ok(path)
}

pub(crate) fn read(options: &Connection) -> Result<ConfigFile> {
    match fs::read_to_string(path(options)?) {
        Ok(contents) => toml::from_str(&contents).map_err(|_| Error::usage("Invalid config file; expected optional active_profile and [profiles.NAME] with url, web_url, app, owner, timeout, ca_cert (no credentials)")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ConfigFile::default()),
        Err(error) => Err(error.into()),
    }
}

pub fn configured_url(options: &Connection) -> Result<Option<String>> {
    let name = profile_name(options)?;
    let file = read(options)?;
    Ok(options.url.clone().or_else(|| {
        file.profiles
            .get(&name)
            .and_then(|profile| profile.url.clone())
    }))
}

pub fn resolve(options: &Connection) -> Result<Settings> {
    let name = profile_name(options)?;
    let file = read(options)?;
    let profile = file.profiles.get(&name).cloned().unwrap_or_default();
    let url = options
        .url
        .as_ref()
        .or(profile.url.as_ref())
        .ok_or_else(|| {
            Error::usage("No Splunk management URL configured")
                .hint("Set SPLUNK_URL or run splunk-cli config set --url https://host:8089")
        })?;
    let app = options
        .app
        .clone()
        .or(profile.app)
        .unwrap_or_else(|| "search".into());
    let owner = options
        .owner
        .clone()
        .or(profile.owner)
        .unwrap_or_else(|| "nobody".into());
    validate_segment(&app, "app")?;
    validate_segment(&owner, "owner")?;
    let timeout = options.timeout.or(profile.timeout).unwrap_or(30);
    if !(1..=3600).contains(&timeout) {
        return Err(Error::usage("timeout must be between 1 and 3600 seconds"));
    }
    let url = validate_url(url)?;
    let web_url = match options.web_url.as_ref().or(profile.web_url.as_ref()) {
        Some(web_url) => validate_web_url(web_url)?,
        None => default_web_url(&url),
    };
    let ca_cert = options.ca_cert.clone().or(profile.ca_cert);
    if ca_cert.as_ref().is_some_and(|path| path.to_str().is_none()) {
        return Err(Error::usage("CA certificate path must be UTF-8"));
    }
    Ok(Settings {
        url,
        web_url,
        app,
        owner,
        timeout,
        ca_cert,
        insecure: options.insecure,
        allow_http: options.allow_http,
    })
}

pub fn validate_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value)
        .map_err(|_| Error::usage("Invalid management URL; expected https://host:8089"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::usage(
            "Management URL must be HTTP(S) without credentials, query parameters, or fragment",
        ));
    }
    // Keep reverse-proxy prefixes, and let path_segments_mut handle escaping.
    let prefix = url.path().trim_end_matches('/').to_owned();
    url.set_path(&format!("{prefix}/"));
    Ok(url)
}

/// Splunk Web usually shares the management host but listens on the default HTTPS port.
fn default_web_url(management: &Url) -> Url {
    let mut url = management.clone();
    let _ = url.set_scheme("https");
    let _ = url.set_port(None);
    url.set_path("/");
    url
}

pub fn validate_web_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).map_err(|_| {
        Error::usage("Invalid Splunk Web URL; expected https://host/ or https://host/splunk/")
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::usage(
            "Splunk Web URL must be HTTP(S) without credentials, query parameters, or fragment",
        ));
    }
    let prefix = url.path().trim_end_matches('/').to_owned();
    url.set_path(&format!("{prefix}/"));
    Ok(url)
}

pub fn validate_segment(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty()
        || value == "."
        || value == ".."
        || value.contains(['/', '\\'])
        || value.chars().any(char::is_control)
    {
        return Err(Error::usage(format!(
            "Invalid {label}: must be nonempty and cannot contain path separators, control characters, or dot segments"
        )));
    }
    Ok(())
}

pub fn show(options: &Connection) -> Result<serde_json::Value> {
    let settings = resolve(options)?;
    Ok(
        serde_json::json!({"profile": profile_name(options)?, "config": path(options)?,
        "url": settings.url.as_str(), "web_url": settings.web_url.as_str(), "app": settings.app, "owner": settings.owner,
        "timeout": settings.timeout, "ca_cert": settings.ca_cert, "insecure": settings.insecure}),
    )
}

/// Serialize updates with a separate stable lock file, then replace atomically.
pub fn save(options: &Connection, dry_run: bool) -> Result<serde_json::Value> {
    let mut selected = options.clone();
    selected.profile = Some(profile_name(options)?);
    let options = &selected;
    let planned = show(options)?;
    if dry_run {
        return Ok(serde_json::json!({"dry_run": true, "settings": planned}));
    }
    transaction(options, |file, config_path| {
        apply_settings(options, file)?;
        persist(file, config_path)
    })?;
    Ok(serde_json::json!({"saved": true, "settings": show(options)?}))
}

pub(crate) fn transaction<T>(
    options: &Connection,
    change: impl FnOnce(&mut ConfigFile, &Path) -> Result<T>,
) -> Result<T> {
    let config_path = write_path(options)?;
    let _lock = lock(&config_path)?;
    let mut file = read(options)?;
    change(&mut file, &config_path)
}

pub(crate) fn apply_settings(options: &Connection, file: &mut ConfigFile) -> Result<()> {
    let profile = file.profiles.entry(profile_name(options)?).or_default();
    if options.url.is_some() {
        profile.url = options.url.clone();
    }
    if options.web_url.is_some() {
        profile.web_url = options.web_url.clone();
    }
    if options.app.is_some() {
        profile.app = options.app.clone();
    }
    if options.owner.is_some() {
        profile.owner = options.owner.clone();
    }
    if options.timeout.is_some() {
        profile.timeout = options.timeout;
    }
    if let Some(ca_cert) = &options.ca_cert {
        profile.ca_cert =
            Some(fs::canonicalize(ca_cert).map_err(|error| ca_error(ca_cert, error))?);
    }
    Ok(())
}

pub(crate) fn persist(file: &ConfigFile, config_path: &std::path::Path) -> Result<()> {
    let contents = toml::to_string_pretty(file)
        .map_err(|_| Error::new("io", "Cannot serialize configuration"))?;
    write_atomic(config_path, contents.as_bytes())
}

pub fn unset(
    options: &Connection,
    keys: &[crate::cli::SettingKey],
    dry_run: bool,
) -> Result<serde_json::Value> {
    use crate::cli::SettingKey;
    let name = profile_name(options)?;
    let update = |file: &mut ConfigFile, path: &Path| {
        let mut changed = false;
        let mut names = Vec::new();
        for key in keys {
            let label = match key {
                SettingKey::Url => "url",
                SettingKey::WebUrl => "web-url",
                SettingKey::App => "app",
                SettingKey::Owner => "owner",
                SettingKey::Timeout => "timeout",
                SettingKey::CaCert => "ca-cert",
            };
            names.push(label);
            if let Some(profile) = file.profiles.get_mut(&name) {
                changed |= match key {
                    SettingKey::Url => profile.url.take().is_some(),
                    SettingKey::WebUrl => profile.web_url.take().is_some(),
                    SettingKey::App => profile.app.take().is_some(),
                    SettingKey::Owner => profile.owner.take().is_some(),
                    SettingKey::Timeout => profile.timeout.take().is_some(),
                    SettingKey::CaCert => profile.ca_cert.take().is_some(),
                };
            }
        }
        if changed && !dry_run {
            persist(file, path)?;
        }
        Ok(
            serde_json::json!({"profile": name, "unset": names, "changed": changed, "dry_run": dry_run}),
        )
    };
    if dry_run {
        update(&mut read(options)?, &path(options)?)
    } else {
        transaction(options, update)
    }
}

pub fn profile_name(options: &Connection) -> Result<String> {
    let name = match &options.profile {
        Some(name) => name.clone(),
        None => read(options)?
            .active_profile
            .unwrap_or_else(|| "default".into()),
    };
    validate_segment(&name, "profile")?;
    Ok(name)
}

pub fn profiles(options: &Connection) -> Result<serde_json::Value> {
    let file = read(options)?;
    let selected = profile_name(options)?;
    let items: Vec<_> = file
        .profiles
        .iter()
        .map(|(name, profile)| {
            serde_json::json!({
                "name": name, "url": profile.url.as_deref().and_then(|url| validate_url(url).ok()).map(|url| url.to_string()), "valid": profile_problem(profile).is_none(), "problem": profile_problem(profile).map(|error| error.message), "app": profile.app.as_deref().unwrap_or("search"),
                "owner": profile.owner.as_deref().unwrap_or("nobody"), "active": name == &selected,
                "default": file.active_profile.as_deref().unwrap_or("default") == name
            })
        })
        .collect();
    Ok(
        serde_json::json!({"items": items, "active_profile": selected,
        "default_profile": file.active_profile.as_deref().unwrap_or("default")}),
    )
}

/// All profile mutations share the settings writer's stable lock and atomic replacement.
pub enum ProfileAction {
    Use,
    Remove {
        dry_run: bool,
        keep_credentials: bool,
    },
}

pub fn rename_profile(
    options: &Connection,
    name: &str,
    new_name: &str,
    keep_credentials: bool,
    dry_run: bool,
) -> Result<serde_json::Value> {
    validate_segment(name, "profile")?;
    validate_segment(new_name, "profile")?;
    let change = |file: &mut ConfigFile, path: &Path| {
        let profile = stored_profile(file, name)?.clone();
        if name != new_name && file.profiles.contains_key(new_name) {
            return Err(
                Error::new("conflict", "The destination profile already exists")
                    .hint("Choose an unused profile name"),
            );
        }
        if dry_run || name == new_name {
            return Ok(
                serde_json::json!({"dry_run": dry_run, "changed": name != new_name, "profile": name, "new_name": new_name, "keep_credentials": keep_credentials}),
            );
        }
        file.profiles.remove(name);
        file.profiles.insert(new_name.into(), profile.clone());
        if file.active_profile.as_deref().unwrap_or("default") == name {
            file.active_profile = Some(new_name.into());
        }
        let moved = crate::auth::rename_saved(
            options,
            name,
            new_name,
            profile.url.as_deref(),
            file,
            keep_credentials,
            |file| persist(file, path),
        )?;
        Ok(
            serde_json::json!({"changed": true, "profile": name, "new_name": new_name, "credentials_moved": moved, "active_profile": file.active_profile.as_deref().unwrap_or("default")}),
        )
    };
    if dry_run {
        change(&mut read(options)?, &path(options)?)
    } else {
        transaction(options, change)
    }
}

pub fn change_profile(
    options: &Connection,
    name: &str,
    action: ProfileAction,
) -> Result<serde_json::Value> {
    let (remove, dry_run, keep_credentials) = match action {
        ProfileAction::Use => (false, false, false),
        ProfileAction::Remove {
            dry_run,
            keep_credentials,
        } => (true, dry_run, keep_credentials),
    };
    validate_segment(name, "profile")?;
    let config_path = write_path(options)?;
    let file = read(options)?;
    let profile = stored_profile(&file, name)?;
    if dry_run {
        return Ok(
            serde_json::json!({"dry_run": true, "profile": name, "action": "remove", "url": profile.url.as_deref().and_then(|url| validate_url(url).ok()).map(|url| url.to_string()), "keep_credentials": keep_credentials}),
        );
    }
    let _lock = lock(&config_path)?;
    let mut file = read(options)?;
    let profile = stored_profile(&file, name)?;
    if remove {
        let mut scoped = options.clone();
        scoped.profile = Some(name.into());
        // Environment URL overrides must never redirect credential deletion.
        scoped.url = profile.url.clone();
        let settings = if keep_credentials {
            None
        } else {
            profile.url.as_deref().map(|url| validate_url(url).map(|url| Settings {
                web_url: default_web_url(&url), url, app: "search".into(), owner: "nobody".into(), timeout: 30, ca_cert: None, insecure: false, allow_http: false,
            }).map_err(|error| error.hint("Use --keep-credentials to remove settings with an invalid URL; remove obsolete saved credentials separately"))).transpose()?
        };
        file.profiles.remove(name);
        if file.active_profile.as_deref().unwrap_or("default") == name {
            file.active_profile = None;
        }
        let removed = if let Some(settings) = settings {
            crate::auth::forget(&mut file, &scoped, &settings)?;
            Some(crate::auth::remove_for_profile(&scoped, &settings, || persist(&file, &config_path)).map_err(|mut error| {
                if error.kind == "auth" { error.hint = Some(format!("{} To remove settings without changing saved credentials, use --keep-credentials.", error.hint.unwrap_or_default())); }
                error
            })?)
        } else {
            persist(&file, &config_path)?;
            if keep_credentials { None } else { Some(false) }
        };
        if keep_credentials {
            crate::output::diagnostic(format_args!(
                "Warning: profile settings removed; saved credentials were kept. Remote tokens have not been revoked."
            ));
        }
        Ok(
            serde_json::json!({"removed": true, "profile": name, "credentials_removed": removed,
            "active_profile": file.active_profile.as_deref().unwrap_or("default")}),
        )
    } else {
        if let Some(error) = profile_problem(profile) {
            return Err(error);
        }
        file.active_profile = Some(name.into());
        persist(&file, &config_path)?;
        Ok(serde_json::json!({"active_profile": name}))
    }
}

fn stored_profile<'a>(file: &'a ConfigFile, name: &str) -> Result<&'a Profile> {
    let profile = file
        .profiles
        .get(name)
        .ok_or_else(|| Error::new("not_found", "Profile does not exist"))?;
    Ok(profile)
}

fn profile_problem(profile: &Profile) -> Option<Error> {
    let validate = || -> Result<()> {
        if let Some(url) = &profile.url {
            validate_url(url)?;
        }
        if let Some(web_url) = &profile.web_url {
            validate_web_url(web_url)?;
        }
        if let Some(app) = &profile.app {
            validate_segment(app, "app")?;
        }
        if let Some(owner) = &profile.owner {
            validate_segment(owner, "owner")?;
        }
        if profile
            .timeout
            .is_some_and(|timeout| !(1..=3600).contains(&timeout))
        {
            return Err(Error::usage("timeout must be between 1 and 3600 seconds"));
        }
        Ok(())
    };
    validate().err()
}

/// Replace the target of a config symlink, preserving the user's dotfile link.
fn write_path(options: &Connection) -> Result<PathBuf> {
    let path = path(options)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(fs::canonicalize(path)?),
        Ok(_) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn ca_error(path: &std::path::Path, error: std::io::Error) -> Error {
    Error::usage(format!("Cannot access CA certificate {}: {error}", path.display()))
        .hint("Check --ca-cert, SPLUNK_CA_CERT, or the profile's ca_cert setting; provide a readable PEM certificate file")
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Serialize writers with a separate stable lock file next to `target`.
pub fn lock(target: &Path) -> Result<fs::File> {
    fs::create_dir_all(parent(target))?;
    let mut lock_name = target.as_os_str().to_owned();
    lock_name.push(".lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(PathBuf::from(lock_name))?;
    lock.lock()?;
    Ok(lock)
}

/// Replace `target` atomically; the temporary file is created with mode 0600 on Unix.
pub fn write_atomic(target: &Path, contents: &[u8]) -> Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(parent(target))?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(target)
        .map_err(|e| Error::from(e.error))?;
    Ok(())
}
