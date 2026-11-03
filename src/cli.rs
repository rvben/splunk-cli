use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{io::IsTerminal, path::PathBuf};

#[derive(Debug, Parser)]
#[command(
    version,
    about,
    disable_help_subcommand = true,
    name = "splunk-cli",
    long_about = "Search and manage Splunk from the terminal.\n\nRun `splunk-cli schema` for the offline clispec contract. Secrets are read from\nSPLUNK_TOKEN, SPLUNK_SESSION_KEY, or SPLUNK_USERNAME / SPLUNK_PASSWORD, or saved\nwith `splunk-cli auth login`."
)]
pub struct Cli {
    #[command(flatten)]
    pub connection: Connection,
    /// Output format; auto selects text on a terminal and JSON when piped.
    #[arg(short = 'o', long, global = true, value_enum, default_value = "auto")]
    pub output: Format,
    /// Suppress progress messages on stderr.
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// Disable color (output is currently always free of ANSI escapes).
    #[arg(long, global = true)]
    pub no_color: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Args)]
pub struct Connection {
    /// Splunk management base URL, usually https://host:8089.
    #[arg(long, env = "SPLUNK_URL", global = true)]
    pub url: Option<String>,
    /// Named connection profile.
    #[arg(long, env = "SPLUNK_PROFILE", default_value = "default", global = true)]
    pub profile: String,
    /// Path to the TOML configuration file.
    #[arg(long, env = "SPLUNK_CONFIG", global = true)]
    pub config: Option<PathBuf>,
    /// Application namespace (defaults to search).
    #[arg(long, env = "SPLUNK_APP", global = true)]
    pub app: Option<String>,
    /// Owner namespace (defaults to nobody; use - to list all owners).
    #[arg(long, env = "SPLUNK_OWNER", global = true)]
    pub owner: Option<String>,
    /// HTTP request timeout in seconds (defaults to 30).
    #[arg(long, env = "SPLUNK_TIMEOUT", global = true, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub timeout: Option<u64>,
    /// Trust an additional PEM certificate authority.
    #[arg(long, env = "SPLUNK_CA_CERT", global = true)]
    pub ca_cert: Option<PathBuf>,
    /// Disable TLS certificate verification for this invocation.
    #[arg(long, global = true)]
    pub insecure: bool,
    /// Allow sending credentials over HTTP to a non-loopback host.
    #[arg(long, global = true)]
    pub allow_http: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    Auto,
    Json,
    Text,
}
impl Format {
    pub fn is_json(self) -> bool {
        matches!(self, Self::Json) || matches!(self, Self::Auto) && !std::io::stdout().is_terminal()
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run SPL, wait for completion, and return one page with a reusable job ID.
    Search(Search),
    /// Manage asynchronous search jobs.
    #[command(subcommand)]
    Jobs(Jobs),
    /// Discover and dispatch saved searches without triggering alert actions.
    #[command(subcommand)]
    SavedSearches(SavedSearches),
    /// Inspect indexes visible to the authenticated user.
    #[command(subcommand)]
    Indexes(Indexes),
    /// Inspect the Splunk server.
    #[command(subcommand)]
    Server(Server),
    /// Log in, check credentials, or remove saved credentials.
    #[command(subcommand)]
    Auth(Auth),
    /// Manage local connection settings; credentials are never stored here.
    #[command(subcommand)]
    Config(Config),
    /// Print the offline clispec v0.3 contract, optionally filtered to a command.
    Schema {
        /// Command path or prefix, for example: schema jobs results.
        #[arg(num_args = 0..)]
        command: Vec<String>,
    },
    /// Generate a shell completion script.
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Debug, Clone, Args)]
pub struct Page {
    /// Maximum number of records; zero/unlimited is deliberately unsupported.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=10000))]
    pub limit: u32,
    /// First record to return, starting at zero.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=i64::MAX as u64))]
    pub offset: u64,
    /// Comma-separated output fields (exact keys, including dotted Splunk keys).
    #[arg(long, value_delimiter = ',')]
    pub fields: Vec<String>,
}

#[derive(Debug, Args)]
pub struct Query {
    /// SPL query. Prefixes bare expressions with search; preserves leading |.
    pub query: String,
    /// Earliest search time (Splunk relative or absolute time).
    #[arg(long, default_value = "-24h", allow_hyphen_values = true)]
    pub earliest: String,
    /// Latest search time.
    #[arg(long, default_value = "now", allow_hyphen_values = true)]
    pub latest: String,
    /// Preview the request locally without credentials or network access.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct Search {
    /// SPL query; omitted when continuing an existing job with --cursor.
    #[arg(required_unless_present = "cursor", conflicts_with = "cursor")]
    pub query: Option<String>,
    /// Continue the existing job using next_cursor from an earlier result page.
    #[arg(long, conflicts_with_all = ["query", "offset", "earliest", "latest", "wait_timeout", "dry_run"])]
    pub cursor: Option<String>,
    /// Earliest search time (Splunk relative or absolute time).
    #[arg(long, default_value = "-24h", allow_hyphen_values = true)]
    pub earliest: String,
    /// Latest search time.
    #[arg(long, default_value = "now", allow_hyphen_values = true)]
    pub latest: String,
    /// Preview the submission locally without credentials or network access.
    #[arg(long)]
    pub dry_run: bool,
    #[command(flatten)]
    pub page: Page,
    /// Maximum wait for job completion, in seconds. The job survives a timeout.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=86400))]
    pub wait_timeout: u64,
}

#[derive(Debug, Subcommand)]
pub enum Jobs {
    /// Submit SPL and immediately return a job ID. Retrying creates another job.
    Create(Query),
    /// List visible search jobs.
    List(Page),
    /// Inspect one job, including its completion state.
    Show {
        id: String,
        #[arg(long, value_delimiter = ',')]
        fields: Vec<String>,
    },
    /// Return one page of completed results using the v2 results API.
    Results {
        id: String,
        #[command(flatten)]
        page: Page,
    },
    /// Cancel a search job. Requires --yes unless --dry-run is used.
    Cancel {
        id: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Delete a job and its results. Requires --yes unless --dry-run is used.
    Delete {
        id: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum SavedSearches {
    /// List saved searches in the selected app/owner namespace.
    List(Page),
    /// Inspect a saved search definition.
    Show {
        name: String,
        #[arg(long, value_delimiter = ',')]
        fields: Vec<String>,
    },
    /// Dispatch a new job with trigger_actions=0. Retrying may repeat SPL writes.
    Run {
        name: String,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum Indexes {
    /// List indexes.
    List(Page),
    /// Inspect one index.
    Show {
        name: String,
        #[arg(long, value_delimiter = ',')]
        fields: Vec<String>,
    },
}
#[derive(Debug, Subcommand)]
pub enum Server {
    /// Show Splunk server version and capabilities.
    Info {
        #[arg(long, value_delimiter = ',')]
        fields: Vec<String>,
    },
}
#[derive(Debug, Subcommand)]
pub enum Auth {
    /// Prompt for credentials, validate them, and save them in the OS credential store.
    Login {
        /// Authentication method; prompts when omitted.
        #[arg(long, value_enum)]
        method: Option<LoginMethod>,
        /// Username for password authentication (the password is always hidden).
        #[arg(long, requires = "method")]
        username: Option<String>,
        /// Read a token from piped stdin instead of prompting; requires --url or saved URL.
        #[arg(long, conflicts_with_all = ["method", "username"])]
        token_stdin: bool,
    },
    /// Validate credentials and show the authenticated context.
    Status,
    /// Remove credentials saved for this profile and server; does not revoke remote tokens.
    Logout,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LoginMethod {
    Token,
    Password,
}
#[derive(Debug, Subcommand)]
pub enum Config {
    /// Show the resolved connection without credentials; makes no network calls.
    Show,
    /// Show the config file path without reading it.
    Path,
    /// Save supplied flag/environment connection settings to the profile (no secrets).
    Set {
        #[arg(long)]
        dry_run: bool,
    },
}
