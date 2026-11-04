use crate::{
    Error, Result, auth,
    cli::{Auth, Cli, Command, Config, Indexes, Jobs, Page, Profiles, SavedSearches, Server},
    client::{Client, endpoint},
    config,
    interrupt::run as interrupt,
    output,
};
use reqwest::Method;
use serde_json::{Value, json};
use std::time::Duration;

pub fn normalize_query(query: &str) -> Result<String> {
    let query = query.trim();
    if query.is_empty() || query.contains('\0') {
        return Err(Error::usage("SPL query cannot be empty or contain NUL"));
    }
    if query.starts_with('|') || query.split_whitespace().next() == Some("search") {
        Ok(query.into())
    } else {
        Ok(format!("search {query}"))
    }
}

fn query_parameters(query: &str, earliest: &str, latest: &str) -> Result<Vec<(String, String)>> {
    if earliest.trim().is_empty() || latest.trim().is_empty() {
        return Err(Error::usage("Search time bounds cannot be empty"));
    }
    Ok(vec![
        ("search".into(), normalize_query(query)?),
        ("earliest_time".into(), earliest.into()),
        ("latest_time".into(), latest.into()),
        ("exec_mode".into(), "normal".into()),
    ])
}

fn client(cli: &Cli) -> Result<Client> {
    let mut options = cli.connection.clone();
    options.profile = Some(config::profile_name(&options)?);
    let settings = config::resolve(&options)?;
    let credentials = auth::credentials(&options, &settings)?;
    let client = Client::new(settings, credentials)?;
    Ok(if auth::environment_credentials() {
        client
    } else {
        client.with_relogin_hint()
    })
}

fn plan(
    cli: &Cli,
    method: &str,
    namespaced: bool,
    path: &[&str],
    parameters: &[(String, String)],
) -> Result<Value> {
    let settings = config::resolve(&cli.connection)?;
    let url = endpoint(&settings, namespaced, path)?;
    Ok(
        json!({"dry_run": true, "method": method, "url": url.as_str(), "parameters": parameters.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<serde_json::Map<String, Value>>() }),
    )
}

pub async fn execute(cli: &Cli) -> Result<Value> {
    match &cli.command {
        Command::Profile(Profiles::List) => config::profiles(&cli.connection),
        Command::Profile(Profiles::Use { name }) => {
            config::change_profile(&cli.connection, name, config::ProfileAction::Use)
        }
        Command::Profile(Profiles::Rename {
            name,
            new_name,
            keep_credentials,
            dry_run,
        }) => config::rename_profile(&cli.connection, name, new_name, *keep_credentials, *dry_run),
        Command::Profile(Profiles::Remove {
            name,
            yes,
            dry_run,
            keep_credentials,
        }) => {
            if !yes && !dry_run {
                return Err(Error::new(
                    "confirmation_required",
                    "Removing a profile requires --yes",
                )
                .hint("Preview with --dry-run, then pass --yes"));
            }
            config::change_profile(
                &cli.connection,
                name,
                config::ProfileAction::Remove {
                    dry_run: *dry_run,
                    keep_credentials: *keep_credentials,
                },
            )
        }
        Command::Config(Config::Path) => Ok(json!({"path": config::path(&cli.connection)?})),
        Command::Config(Config::Show) => config::show(&cli.connection),
        Command::Config(Config::Set { dry_run }) => config::save(&cli.connection, *dry_run),
        Command::Config(Config::Unset { keys, dry_run }) => {
            config::unset(&cli.connection, keys, *dry_run)
        }
        Command::Init(login) | Command::Auth(Auth::Login(login)) => {
            auth::login(
                cli,
                auth::LoginRequest {
                    method: login.method,
                    username: login.username.as_deref(),
                    token_stdin: login.token_stdin,
                    browser: login.browser.clone(),
                    insecure_storage: login.insecure_storage,
                },
            )
            .await
        }
        Command::Doctor { offline } => doctor(cli, *offline).await,
        Command::Auth(Auth::Migrate {
            to,
            insecure_storage,
            dry_run,
        }) => auth::migrate(&cli.connection, *to, *insecure_storage, *dry_run),
        Command::Auth(Auth::Logout) => auth::logout(&cli.connection),
        Command::Search(search) => {
            if let Some(crate::cli::SearchCommand::Check {
                query,
                file,
                dry_run,
            }) = &search.command
            {
                let text = read_query(query.as_deref(), file.as_deref())?;
                let params = vec![
                    ("q".into(), text),
                    ("parse_only".into(), "true".into()),
                    ("enable_lookups".into(), "false".into()),
                    ("reload_macros".into(), "false".into()),
                ];
                let path = &["search", "v2", "parser"];
                if *dry_run {
                    return plan(cli, "POST", true, path, &params);
                }
                let parsed = client(cli)?
                    .request(Method::POST, true, path, &params)
                    .await?;
                if !parsed.is_object() {
                    return Err(Error::invalid_response());
                }
                return Ok(json!({"valid":true,"parse_only":true,"parsed":parsed}));
            }
            if let Some(cursor) = &search.cursor {
                let mut page = search.page.clone();
                let settings = config::resolve(&cli.connection)?;
                let sid = crate::continuation::decode(&settings, cursor, &mut page)?;
                return results(&client(cli)?, &sid, &page, None)
                    .await
                    .map_err(|e| with_job(e, &sid));
            }
            let query = read_query(search.query.as_deref(), search.file.as_deref())?;
            let params = query_parameters(&query, &search.earliest, &search.latest)?;
            if search.dry_run {
                return plan(cli, "POST", true, &["search", "jobs"], &params);
            }
            let client = client(cli)?;
            let sid = create(&client, &["search", "jobs"], &params).await?;
            if !cli.quiet {
                crate::output::diagnostic(format_args!(
                    "Created search job {}; waiting for completion",
                    output::terminal(&sid)
                ));
            }
            let state = wait_for(&client, &sid, search.wait_timeout, None, false).await;
            let result = match state {
                Ok(state) => results(&client, &sid, &search.page, Some(state)).await,
                Err(error) => Err(error),
            };
            result.map_err(|error| with_job(error, &sid))
        }
        Command::Jobs(Jobs::Create(query)) => {
            let text = read_query(query.query.as_deref(), query.file.as_deref())?;
            let params = query_parameters(&text, &query.earliest, &query.latest)?;
            if query.dry_run {
                return plan(cli, "POST", true, &["search", "jobs"], &params);
            }
            let sid = create(&client(cli)?, &["search", "jobs"], &params).await?;
            Ok(json!({"job_id": sid}))
        }
        Command::Jobs(Jobs::List(page)) => {
            list(&client(cli)?, true, &["search", "jobs"], page).await
        }
        Command::Jobs(Jobs::Logs { id }) => {
            let log = interrupt(client(cli)?.text(true, &["search", "jobs", id, "search.log"]))
                .await
                .map_err(|e| with_job(e, id))?;
            Ok(json!({"job_id":id,"log":log}))
        }
        Command::Jobs(Jobs::Show { id, fields }) => {
            show(&client(cli)?, true, &["search", "jobs", id], fields).await
        }
        Command::Jobs(Jobs::Results { id, page }) => results(&client(cli)?, id, page, None)
            .await
            .map_err(|e| with_job(e, id)),
        Command::Jobs(Jobs::Export(export)) => export_results(&client(cli)?, export)
            .await
            .map_err(|error| with_job(error, &export.id)),
        Command::Jobs(Jobs::Wait(monitor) | Jobs::Watch(monitor)) => {
            let progress = matches!(cli.command, Command::Jobs(Jobs::Watch(_))) && !cli.quiet;
            let mut state = wait_for(
                &client(cli)?,
                &monitor.id,
                monitor.wait_timeout,
                Some(monitor.interval),
                progress,
            )
            .await
            .map_err(|error| with_job(error, &monitor.id))?;
            state["job_id"] = json!(monitor.id);
            Ok(state)
        }
        Command::Jobs(Jobs::Cancel { id, yes, dry_run })
        | Command::Jobs(Jobs::Delete { id, yes, dry_run }) => {
            let cancel = matches!(cli.command, Command::Jobs(Jobs::Cancel { .. }));
            let path = if cancel {
                vec!["search", "jobs", id, "control"]
            } else {
                vec!["search", "jobs", id]
            };
            let method = if cancel { Method::POST } else { Method::DELETE };
            let parameters = if cancel {
                vec![("action".into(), "cancel".into())]
            } else {
                vec![]
            };
            if *dry_run {
                return plan(cli, method.as_str(), true, &path, &parameters);
            }
            if !yes {
                return Err(Error::new(
                    "confirmation_required",
                    "This operation requires explicit confirmation",
                )
                .hint("Preview with --dry-run, then pass --yes to execute"));
            }
            let changed = match client(cli)?.request(method, true, &path, &parameters).await {
                Ok(_) => true,
                Err(error) if error.kind == "not_found" => false,
                Err(error) => return Err(error),
            };
            Ok(
                json!({"job_id": id, "action": if cancel { "cancel" } else { "delete" }, "success": true, "changed": changed}),
            )
        }
        Command::SavedSearches(SavedSearches::List(page)) => {
            list(&client(cli)?, true, &["saved", "searches"], page).await
        }
        Command::SavedSearches(SavedSearches::Show { name, fields }) => {
            show(&client(cli)?, true, &["saved", "searches", name], fields).await
        }
        Command::SavedSearches(SavedSearches::Run { name, dry_run }) => {
            let params = vec![("trigger_actions".into(), "0".into())];
            let path = ["saved", "searches", name, "dispatch"];
            if *dry_run {
                return plan(cli, "POST", true, &path, &params);
            }
            Ok(json!({"job_id": create(&client(cli)?, &path, &params).await?}))
        }
        Command::Indexes(Indexes::List(page)) => {
            list(&client(cli)?, false, &["data", "indexes"], page).await
        }
        Command::Indexes(Indexes::Show { name, fields }) => {
            show(&client(cli)?, false, &["data", "indexes", name], fields).await
        }
        Command::Server(Server::Info { fields }) => {
            show(&client(cli)?, false, &["server", "info"], fields).await
        }
        Command::Auth(Auth::Status { offline: true }) => {
            let settings = config::resolve(&cli.connection)?;
            Ok(
                json!({"authenticated": null, "offline": true, "profile": config::profile_name(&cli.connection)?,
                "url": settings.url.as_str(), "credentials": auth::status(&cli.connection, &settings)?}),
            )
        }
        Command::Auth(Auth::Status { offline: false }) => {
            let user = show(
                &client(cli)?,
                false,
                &["authentication", "current-context"],
                &[],
            )
            .await?;
            Ok(json!({"authenticated": true, "context": user}))
        }
        Command::Schema { .. } | Command::Completions { .. } => {
            unreachable!("offline commands are handled by main")
        }
    }
}

fn with_job(mut error: Error, id: &str) -> Error {
    error.details["job_id"] = json!(id);
    let recovery = format!(
        "Inspect with splunk-cli jobs show {id}; fetch completed results with splunk-cli jobs results {id}. Do not blindly resubmit SPL."
    );
    error.hint = Some(match error.hint.take() {
        Some(hint) => format!("{hint} {recovery}"),
        None => recovery,
    });
    error
}

async fn create(client: &Client, path: &[&str], params: &[(String, String)]) -> Result<String> {
    let value = interrupt(client.request(Method::POST, true, path, params)).await.map_err(|mut error| {
        if error.kind == "interrupted" { error.hint = Some("A job may have been created. Inspect splunk-cli jobs list before resubmitting SPL.".into()); }
        error
    })?;
    let sid = value["sid"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(Error::invalid_response)?;
    config::validate_segment(sid, "job ID").map_err(|_| Error::invalid_response())?;
    Ok(sid.into())
}

fn entry(value: &Value) -> Result<Value> {
    let mut content = value["content"]
        .as_object()
        .cloned()
        .ok_or_else(Error::invalid_response)?;
    if let Some(name) = value["name"].as_str() {
        content.insert("name".into(), json!(name));
    }
    if let Some(acl) = value.get("acl") {
        if let Some(owner) = acl.get("owner") {
            content.insert("owner".into(), owner.clone());
        }
        if let Some(app) = acl.get("app") {
            content.insert("app".into(), app.clone());
        }
    }
    Ok(Value::Object(content))
}

async fn show(
    client: &Client,
    namespaced: bool,
    path: &[&str],
    fields: &[String],
) -> Result<Value> {
    let value = client.request(Method::GET, namespaced, path, &[]).await?;
    let entries = value["entry"]
        .as_array()
        .ok_or_else(Error::invalid_response)?;
    if entries.is_empty() {
        return Err(Error::new(
            "not_found",
            "Splunk returned no matching resource",
        ));
    }
    if entries.len() != 1 {
        return Err(Error::new(
            "conflict",
            "Multiple resources match; select a specific --owner and --app",
        ));
    }
    Ok(output::project(entry(&entries[0])?, fields))
}

async fn list(client: &Client, namespaced: bool, path: &[&str], page: &Page) -> Result<Value> {
    let params = vec![
        ("count".into(), (page.limit + 1).to_string()),
        ("offset".into(), page.offset.to_string()),
    ];
    let value = client
        .request(Method::GET, namespaced, path, &params)
        .await?;
    let entries = value["entry"]
        .as_array()
        .ok_or_else(Error::invalid_response)?;
    let items = entries.iter().map(entry).collect::<Result<Vec<_>>>()?;
    let total = output::number(&value["paging"]["total"]);
    Ok(output::page(items, total, page))
}

fn truthy(value: &Value) -> bool {
    value == true || value == "1" || value == "true" || value == 1
}
fn check_state(state: &Value) -> Result<bool> {
    if truthy(&state["isFailed"])
        || truthy(&state["isZombie"])
        || matches!(
            state["dispatchState"].as_str(),
            Some("FAILED" | "BAD_INPUT_CANCEL" | "INTERNAL_CANCEL" | "USER_CANCEL")
        )
    {
        return Err(Error::new("api", "Splunk search failed or was canceled"));
    }
    if state["dispatchState"] == "PAUSED" {
        return Err(Error::new(
            "conflict",
            "Search job is paused; inspect it before fetching completed results",
        ));
    }
    if state.get("isDone").is_none() {
        return Err(Error::invalid_response());
    }
    Ok(truthy(&state["isDone"]))
}

async fn wait(client: &Client, sid: &str, interval: Option<u64>, progress: bool) -> Result<Value> {
    let mut delay = interval
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_millis(500));
    loop {
        let state = show(client, true, &["search", "jobs", sid], &[]).await?;
        let done = check_state(&state)?;
        if progress {
            let percent = state["doneProgress"]
                .as_f64()
                .or_else(|| state["doneProgress"].as_str().and_then(|s| s.parse().ok()))
                .filter(|number| number.is_finite())
                .unwrap_or(if done { 1.0 } else { 0.0 })
                .clamp(0.0, 1.0)
                * 100.0;
            crate::output::diagnostic(format_args!(
                "{}: {} {percent:.0}%; scanned {}; results {}",
                output::terminal(sid),
                output::terminal(state["dispatchState"].as_str().unwrap_or("RUNNING")),
                output::number(&state["scanCount"])
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".into()),
                output::number(&state["resultCount"])
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".into())
            ));
        }
        if done {
            return Ok(state);
        }
        tokio::time::sleep(delay).await;
        if interval.is_none() {
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }
}

pub(crate) async fn results(
    client: &Client,
    sid: &str,
    page: &Page,
    state: Option<Value>,
) -> Result<Value> {
    interrupt(results_inner(client, sid, page, state)).await
}

async fn results_inner(
    client: &Client,
    sid: &str,
    page: &Page,
    state: Option<Value>,
) -> Result<Value> {
    let state = match state {
        Some(state) => state,
        None => show(client, true, &["search", "jobs", sid], &[]).await?,
    };
    if !check_state(&state)? {
        return Err(Error::new(
            "conflict",
            "Search is still running; inspect jobs show and retry jobs results when isDone is true",
        ));
    }
    let mut params = vec![
        ("count".into(), (page.limit + 1).to_string()),
        ("offset".into(), page.offset.to_string()),
    ];
    for field in &page.fields {
        params.push(("f".into(), field.clone()));
    }
    let value = client
        .request(
            Method::GET,
            true,
            &["search", "v2", "jobs", sid, "results"],
            &params,
        )
        .await?;
    if truthy(&value["preview"]) {
        return Err(Error::new(
            "conflict",
            "Splunk returned preview results; retry after completion",
        ));
    }
    let items = value["results"]
        .as_array()
        .cloned()
        .ok_or_else(Error::invalid_response)?;
    if !items.iter().all(Value::is_object) {
        return Err(Error::invalid_response());
    }
    let mut result = output::page(items, output::number(&state["resultCount"]), page);
    result["fields"] = json!(page.fields);
    result["job_id"] = json!(sid);
    result["next_cursor"] = result["next_offset"]
        .as_u64()
        .map(|offset| {
            json!(crate::continuation::encode(
                &client.settings,
                sid,
                page,
                offset
            ))
        })
        .unwrap_or(Value::Null);
    Ok(result)
}

async fn doctor(cli: &Cli, offline: bool) -> Result<Value> {
    let mut checks = Vec::new();
    let mut options = cli.connection.clone();
    options.profile = Some(
        config::profile_name(&options)
            .map_err(|error| diagnostic(error, "configuration", &checks))?,
    );
    let settings =
        config::resolve(&options).map_err(|error| diagnostic(error, "configuration", &checks))?;
    checks.push(json!({"check": "configuration", "status": "ok", "message": "Management URL and namespace are valid"}));
    let (secret, credentials) = auth::load_status(&options, &settings)
        .map_err(|error| diagnostic(error, "credentials", &checks))?;
    checks.push(json!({"check": "credentials", "status": "ok", "message": format!("{} credentials available; not yet verified", credentials["source"].as_str().unwrap_or("saved"))}));
    let client = Client::new(settings.clone(), secret)
        .map_err(|error| diagnostic(error, "transport_configuration", &checks))?;
    let client = if credentials["source"] == "environment" {
        client
    } else {
        client.with_relogin_hint()
    };
    checks.push(json!({"check": "transport_configuration", "status": if settings.insecure { "warning" } else { "ok" },
        "message": if settings.insecure { "TLS certificate verification is disabled for this invocation" } else { "HTTP client and certificate trust are configured" }}));
    if offline {
        return Ok(
            json!({"ok": true, "offline": true, "profile": config::profile_name(&options)?, "url": settings.url.as_str(), "credentials": credentials, "checks": checks}),
        );
    }
    let context = show(&client, false, &["authentication", "current-context"], &[])
        .await
        .map_err(|error| diagnostic(error, "authentication", &checks))?;
    checks.push(json!({"check": "authentication", "status": "ok", "message": "Splunk accepted the credentials"}));
    let server = show(&client, false, &["server", "info"], &[])
        .await
        .map_err(|error| diagnostic(error, "server", &checks))?;
    checks
        .push(json!({"check": "server", "status": "ok", "message": "Management API is reachable"}));
    list(
        &client,
        true,
        &["search", "jobs"],
        &Page {
            limit: 1,
            offset: 0,
            fields: vec!["name".into()],
        },
    )
    .await
    .map_err(|error| diagnostic(error, "namespace", &checks))?;
    checks.push(json!({"check": "namespace", "status": "ok", "message": "Search jobs are readable in the selected app/owner namespace"}));
    list(
        &client,
        false,
        &["data", "indexes"],
        &Page {
            limit: 1,
            offset: 0,
            fields: vec!["name".into()],
        },
    )
    .await
    .map_err(|error| diagnostic(error, "indexes", &checks))?;
    checks.push(
        json!({"check": "indexes", "status": "ok", "message": "Visible indexes are readable"}),
    );
    let mut credentials = credentials;
    credentials["verified"] = json!(true);
    Ok(
        json!({"ok": true, "offline": false, "profile": config::profile_name(&options)?, "url": settings.url.as_str(),
        "credentials": credentials, "context": context, "server": server, "checks": checks}),
    )
}

fn diagnostic(mut error: Error, check: &str, passed: &[Value]) -> Error {
    let mut checks = passed.to_vec();
    checks.push(json!({"check": check, "status": "failed", "message": error.message}));
    error.details["checks"] = json!(checks);
    if error.hint.is_none() {
        error.hint = Some(match error.kind {
            "auth" => "Run splunk-cli auth login; check environment overrides and your Splunk role permissions.",
            "transport" => "Use the management port (usually 8089). For a private CA, pass --ca-cert PATH; use --insecure only for a trusted test server.",
            "usage" => "Run splunk-cli init, or inspect splunk-cli config show and profile list.",
            "invalid_response" => "Check that --url points to the Splunk management API (usually port 8089), rather than Splunk Web on port 8000.",
            _ => "Inspect the failed check and retry splunk-cli doctor after correcting it.",
        }.into());
    }
    error
}

fn read_query(query: Option<&str>, file: Option<&std::path::Path>) -> Result<String> {
    use std::io::{IsTerminal, Read};
    const MAX: usize = 1024 * 1024;
    let query = if let Some(file) = file {
        let mut reader: Box<dyn Read> = if file == std::path::Path::new("-") {
            if std::io::stdin().is_terminal() {
                return Err(Error::usage("--file - requires SPL piped to stdin"));
            }
            Box::new(std::io::stdin().lock())
        } else {
            Box::new(std::fs::File::open(file)?)
        };
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take((MAX + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX {
            return Err(Error::usage("SPL query exceeds 1 MiB"));
        }
        String::from_utf8(bytes)
            .map_err(|_| Error::usage("SPL file must contain UTF-8 text"))?
            .trim_start_matches('\u{feff}')
            .to_owned()
    } else {
        query
            .ok_or_else(|| Error::usage("Supply SPL or --file PATH (use - for stdin)"))?
            .to_owned()
    };
    if query.len() > MAX {
        return Err(Error::usage("SPL query exceeds 1 MiB"));
    }
    normalize_query(&query)
}

async fn wait_for(
    client: &Client,
    sid: &str,
    timeout: u64,
    interval: Option<u64>,
    progress: bool,
) -> Result<Value> {
    config::validate_segment(sid, "job ID")?;
    interrupt(async {
        tokio::time::timeout(
            Duration::from_secs(timeout),
            wait(client, sid, interval, progress),
        )
        .await
        .unwrap_or_else(|_| {
            Err(Error::new(
                "timeout",
                "Timed out waiting for search completion; the job is still available",
            ))
        })
    })
    .await
}

async fn export_results(client: &Client, options: &crate::cli::Export) -> Result<Value> {
    if options.stream {
        return interrupt(crate::export::stream(client, options)).await;
    }
    interrupt(export_results_inner(client, options)).await
}

async fn export_results_inner(client: &Client, options: &crate::cli::Export) -> Result<Value> {
    let state = show(client, true, &["search", "jobs", &options.id], &[]).await?;
    let mut items = Vec::new();
    let mut bytes = 2;
    let mut byte_bound = false;
    let mut page = Page {
        limit: options.page_size.min(options.max_results),
        offset: options.offset,
        fields: options.fields.clone(),
    };
    let mut last;
    loop {
        last = results(client, &options.id, &page, Some(state.clone())).await?;
        let batch = last["items"].take();
        let batch = match batch {
            Value::Array(items) => items,
            _ => return Err(Error::invalid_response()),
        };
        for item in batch {
            let size = serde_json::to_vec(&item)
                .map_err(|_| Error::invalid_response())?
                .len()
                + usize::from(!items.is_empty());
            if bytes + size > 32 * 1024 * 1024 {
                byte_bound = true;
                break;
            }
            bytes += size;
            items.push(item);
        }
        if byte_bound {
            if items.is_empty() {
                return Err(Error::new(
                    "invalid_response",
                    "One record exceeds the 32 MiB export bound; select --fields",
                ));
            }
            let offset = options.offset + items.len() as u64;
            last["has_more"] = json!(true);
            last["next_offset"] = json!(offset);
            last["next_cursor"] = json!(crate::continuation::encode(
                &client.settings,
                &options.id,
                &page,
                offset
            ));
            break;
        }
        if last["has_more"] != true || items.len() >= options.max_results as usize {
            break;
        }
        page.offset = last["next_offset"]
            .as_u64()
            .filter(|offset| *offset > page.offset && *offset <= i64::MAX as u64)
            .ok_or_else(Error::invalid_response)?;
        page.limit = options
            .page_size
            .min(options.max_results - items.len() as u32);
    }
    last["items"] = Value::Array(items);
    last["byte_limit_reached"] = json!(byte_bound);
    last["offset"] = json!(options.offset);
    last["limit"] = json!(options.max_results);
    last["page_size"] = json!(options.page_size);
    last["bounded"] = last["has_more"].clone();
    Ok(last)
}
