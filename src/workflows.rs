use crate::{
    Error, Result,
    cli::{Auth, Cli, Command, Config, Indexes, Jobs, Page, SavedSearches, Server},
    client::{Client, Credentials, endpoint},
    config, output,
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
    Client::new(config::resolve(&cli.connection)?, Credentials::from_env()?)
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
        Command::Config(Config::Path) => Ok(json!({"path": config::path(&cli.connection)?})),
        Command::Config(Config::Show) => config::show(&cli.connection),
        Command::Config(Config::Set { dry_run }) => config::save(&cli.connection, *dry_run),
        Command::Search(search) => {
            if let Some(cursor) = &search.cursor {
                let (sid, offset) = cursor.rsplit_once(':').ok_or_else(|| {
                    Error::usage("Invalid cursor; use the next_cursor from search results")
                })?;
                config::validate_segment(sid, "cursor job ID")?;
                let offset: u64 = offset
                    .parse()
                    .map_err(|_| Error::usage("Invalid cursor offset"))?;
                if offset > i64::MAX as u64 {
                    return Err(Error::usage("Cursor offset exceeds supported range"));
                }
                let mut page = search.page.clone();
                page.offset = offset;
                return results(&client(cli)?, sid, &page, None)
                    .await
                    .map_err(|e| with_job(e, sid));
            }
            let query = search
                .query
                .as_deref()
                .ok_or_else(|| Error::usage("Supply a query or --cursor"))?;
            let params = query_parameters(query, &search.earliest, &search.latest)?;
            if search.dry_run {
                return plan(cli, "POST", true, &["search", "jobs"], &params);
            }
            let client = client(cli)?;
            let sid = create(&client, &["search", "jobs"], &params).await?;
            if !cli.quiet {
                eprintln!(
                    "Created search job {}; waiting for completion",
                    output::terminal(&sid)
                );
            }
            let waited = tokio::time::timeout(
                Duration::from_secs(search.wait_timeout),
                wait(&client, &sid),
            )
            .await;
            let state = match waited {
                Ok(result) => result,
                Err(_) => Err(Error::new(
                    "timeout",
                    "Timed out waiting for search completion; the job is still available",
                )),
            };
            let result = match state {
                Ok(state) => results(&client, &sid, &search.page, Some(state)).await,
                Err(error) => Err(error),
            };
            result.map_err(|error| with_job(error, &sid))
        }
        Command::Jobs(Jobs::Create(query)) => {
            let params = query_parameters(&query.query, &query.earliest, &query.latest)?;
            if query.dry_run {
                return plan(cli, "POST", true, &["search", "jobs"], &params);
            }
            let sid = create(&client(cli)?, &["search", "jobs"], &params).await?;
            Ok(json!({"job_id": sid}))
        }
        Command::Jobs(Jobs::List(page)) => {
            list(&client(cli)?, true, &["search", "jobs"], page).await
        }
        Command::Jobs(Jobs::Show { id, fields }) => {
            show(&client(cli)?, true, &["search", "jobs", id], fields).await
        }
        Command::Jobs(Jobs::Results { id, page }) => results(&client(cli)?, id, page, None)
            .await
            .map_err(|e| with_job(e, id)),
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
        Command::Auth(Auth::Status) => {
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
    error.hint = Some(format!(
        "Inspect with splunk-cli jobs show {id}; fetch completed results with splunk-cli jobs results {id}. Do not blindly resubmit SPL."
    ));
    error
}

async fn create(client: &Client, path: &[&str], params: &[(String, String)]) -> Result<String> {
    let value = client.request(Method::POST, true, path, params).await?;
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

async fn wait(client: &Client, sid: &str) -> Result<Value> {
    let mut delay = Duration::from_millis(500);
    loop {
        let state = show(client, true, &["search", "jobs", sid], &[]).await?;
        if check_state(&state)? {
            return Ok(state);
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(5));
    }
}

async fn results(client: &Client, sid: &str, page: &Page, state: Option<Value>) -> Result<Value> {
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
    result["job_id"] = json!(sid);
    result["next_cursor"] = result["next_offset"]
        .as_u64()
        .map(|offset| json!(format!("{sid}:{offset}")))
        .unwrap_or(Value::Null);
    Ok(result)
}
