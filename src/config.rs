use crate::{Error, Result, cli::Connection};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub url: Option<String>,
    pub app: Option<String>,
    pub owner: Option<String>,
    pub timeout: Option<u64>,
    pub ca_cert: Option<PathBuf>,
}

#[derive(Clone)]
pub struct Settings {
    pub url: Url,
    pub app: String,
    pub owner: String,
    pub timeout: u64,
    pub ca_cert: Option<PathBuf>,
    pub insecure: bool,
    pub allow_http: bool,
}

pub fn path(options: &Connection) -> Result<PathBuf> {
    options
        .config
        .clone()
        .or_else(|| {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .or_else(|| dirs::home_dir().map(|p| p.join(".config")))
                .map(|p| p.join("splunk-cli/config.toml"))
        })
        .ok_or_else(|| Error::usage("Cannot determine the config path; set --config"))
}

fn read(options: &Connection) -> Result<ConfigFile> {
    match fs::read_to_string(path(options)?) {
        Ok(contents) => toml::from_str(&contents).map_err(|_| Error::usage("Invalid config file; expected [profiles.NAME] with url, app, owner, timeout, ca_cert (no credentials)")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ConfigFile::default()),
        Err(error) => Err(error.into()),
    }
}

pub fn configured_url(options: &Connection) -> Result<Option<String>> {
    validate_segment(&options.profile, "profile")?;
    let file = read(options)?;
    Ok(options.url.clone().or_else(|| {
        file.profiles
            .get(&options.profile)
            .and_then(|profile| profile.url.clone())
    }))
}

pub fn resolve(options: &Connection) -> Result<Settings> {
    validate_segment(&options.profile, "profile")?;
    let file = read(options)?;
    let profile = file
        .profiles
        .get(&options.profile)
        .cloned()
        .unwrap_or_default();
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
    Ok(Settings {
        url: validate_url(url)?,
        app,
        owner,
        timeout,
        ca_cert: options.ca_cert.clone().or(profile.ca_cert),
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
        serde_json::json!({"profile": options.profile, "config": path(options)?,
        "url": settings.url.as_str(), "app": settings.app, "owner": settings.owner,
        "timeout": settings.timeout, "ca_cert": settings.ca_cert, "insecure": settings.insecure}),
    )
}

/// Serialize updates with a separate stable lock file, then replace atomically.
pub fn save(options: &Connection, dry_run: bool) -> Result<serde_json::Value> {
    let planned = show(options)?;
    if dry_run {
        return Ok(serde_json::json!({"dry_run": true, "settings": planned}));
    }
    let config_path = path(options)?;
    let parent = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    fs::create_dir_all(parent)?;
    let mut lock_name = config_path.as_os_str().to_owned();
    lock_name.push(".lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(PathBuf::from(lock_name))?;
    lock.lock()?;
    let mut file = read(options)?;
    let profile = file.profiles.entry(options.profile.clone()).or_default();
    if options.url.is_some() {
        profile.url = options.url.clone();
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
        profile.ca_cert = Some(fs::canonicalize(ca_cert)?);
    }
    let contents = toml::to_string_pretty(&file)
        .map_err(|_| Error::new("io", "Cannot serialize configuration"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(config_path)
        .map_err(|e| Error::from(e.error))?;
    Ok(serde_json::json!({"saved": true, "settings": show(options)?}))
}
