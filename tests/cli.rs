use serde_json::{Value, json};
use std::process::{Command, Output};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path, query_param},
};

const BIN: &str = env!("CARGO_BIN_EXE_splunk-cli");

fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new(BIN);
    for variable in [
        "SPLUNK_URL",
        "SPLUNK_WEB_URL",
        "SPLUNK_BROWSER",
        "SPLUNK_TOKEN",
        "SPLUNK_SESSION_KEY",
        "SPLUNK_USERNAME",
        "SPLUNK_PASSWORD",
        "SPLUNK_PROFILE",
        "SPLUNK_CONFIG",
        "SPLUNK_APP",
        "SPLUNK_OWNER",
        "SPLUNK_TIMEOUT",
        "SPLUNK_CA_CERT",
    ] {
        cmd.env_remove(variable);
    }
    cmd.env("SPLUNK_CONFIG", "/nonexistent/splunk-cli-test/config.toml")
        .args(args);
    cmd
}
fn data(out: &Output) -> Value {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("JSON stdout")
}

#[test]
fn interactive_login_refuses_without_a_terminal_before_reading_config() {
    let out = command(&["auth", "login"])
        .env("SPLUNK_URL", "invalid")
        .output()
        .unwrap();
    let failure = error(&out, 2, "usage");
    assert!(failure["message"].as_str().unwrap().contains("terminal"));
    assert!(failure["hint"].as_str().unwrap().contains("--token-stdin"));
}

#[test]
fn login_contract_declares_local_mutation_and_stdin_alternative() {
    let schema = data(&command(&["schema", "auth", "login"]).output().unwrap());
    let login = &schema["commands"][0];
    assert_eq!(login["effects"], "idempotent");
    assert!(
        login["args"]
            .as_array()
            .unwrap()
            .iter()
            .any(|arg| arg["name"] == "--token-stdin")
    );
    let out = command(&["auth", "login", "--method", "token", "--token-stdin"])
        .output()
        .unwrap();
    error(&out, 2, "usage");
}
fn error(out: &Output, code: i32, kind: &str) -> Value {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let value: Value = serde_json::from_str(stderr.lines().last().expect("error line")).unwrap();
    assert_eq!(value["error"]["kind"], kind);
    assert_eq!(value["error"]["exit_code"], code);
    value["error"].clone()
}
async fn run(server: &MockServer, args: &[&str]) -> Output {
    let mut cmd = command(args);
    cmd.env("SPLUNK_URL", server.uri())
        .env("SPLUNK_TOKEN", "test-secret");
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}
fn entries(content: Value) -> Value {
    json!({"entry": [{"name": "example", "content": content}]})
}
async fn completed(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/servicesNS/nobody/search/search/jobs/job-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(entries(json!({"isDone": "1", "resultCount": "3"}))),
        )
        .mount(server)
        .await;
}

#[test]
fn offline_schema_ignores_broken_config_and_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "this is broken TOML").unwrap();
    let out = command(&["schema"])
        .env("SPLUNK_CONFIG", &config)
        .env("SPLUNK_URL", "invalid")
        .env("SPLUNK_TOKEN", "x")
        .env("SPLUNK_SESSION_KEY", "y")
        .output()
        .unwrap();
    let schema = data(&out);
    assert_eq!(schema["clispec"], "0.3");
    assert!(schema["commands"].as_array().unwrap().len() >= 18);
    assert!(out.stderr.is_empty());
}

#[test]
fn filtered_schema_preserves_metadata_and_rejects_unknown_paths() {
    let out = command(&["schema", "jobs", "results"]).output().unwrap();
    let value = data(&out);
    assert_eq!(value["commands"].as_array().unwrap().len(), 1);
    assert_eq!(value["commands"][0]["name"], "jobs results");
    assert!(value["global_args"].is_array());
    assert!(value["errors"].is_array());
    error(
        &command(&["schema", "missing"]).output().unwrap(),
        2,
        "usage",
    );
}

#[test]
fn help_version_and_completions_work_before_setup() {
    for args in [
        &["--help"][..],
        &["jobs", "--help"],
        &["--version"],
        &["completions", "zsh"],
    ] {
        let out = command(args).output().unwrap();
        assert!(out.status.success());
        assert!(!out.stdout.is_empty());
        assert!(out.stderr.is_empty());
    }
}

#[test]
fn usage_errors_follow_the_selected_format() {
    for args in [
        &[][..],
        &["jobs"],
        &["--unknown"],
        &["search"],
        &["indexes", "list", "--limit", "0"],
        &["jobs", "list", "--limit", "10001"],
    ] {
        error(&command(args).output().unwrap(), 2, "usage");
    }
    let out = command(&["--output", "text", "--unknown"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("Error: "));
    assert!(out.stdout.is_empty());
}

#[test]
fn destructive_commands_refuse_without_confirmation_even_before_setup() {
    for action in ["cancel", "delete"] {
        error(
            &command(&["jobs", action, "job-1"]).output().unwrap(),
            8,
            "confirmation_required",
        );
    }
}

#[test]
fn dry_runs_need_no_authentication_or_network() {
    let out = command(&[
        "--url",
        "https://example.invalid:8089",
        "search",
        "index=main",
        "--dry-run",
    ])
    .output()
    .unwrap();
    let value = data(&out);
    assert_eq!(value["dry_run"], true);
    assert_eq!(value["parameters"]["search"], "search index=main");
    assert_eq!(value["parameters"]["earliest_time"], "-24h");
    assert!(!value.to_string().contains("Authorization"));
    error(
        &command(&[
            "--url",
            "https://example.invalid",
            "search",
            "  ",
            "--dry-run",
        ])
        .output()
        .unwrap(),
        2,
        "usage",
    );
}

#[test]
fn config_profiles_merge_and_environment_and_flags_override() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let mut cmd = command(&[
        "config",
        "set",
        "--profile",
        "work",
        "--url",
        "https://work.invalid:8089",
        "--app",
        "security",
    ]);
    data(&cmd.env("SPLUNK_CONFIG", &config).output().unwrap());
    data(
        &command(&[
            "config",
            "set",
            "--profile",
            "other",
            "--url",
            "https://other.invalid:8089",
        ])
        .env("SPLUNK_CONFIG", &config)
        .output()
        .unwrap(),
    );
    let out = command(&["config", "show", "--profile", "work", "--app", "override"])
        .env("SPLUNK_CONFIG", &config)
        .env("SPLUNK_URL", "https://env.invalid:8089")
        .env("SPLUNK_TOKEN", "super-secret")
        .output()
        .unwrap();
    let value = data(&out);
    assert_eq!(value["url"], "https://env.invalid:8089/");
    assert_eq!(value["app"], "override");
    let contents = std::fs::read_to_string(&config).unwrap();
    assert!(contents.contains("profiles.work") && contents.contains("profiles.other"));
    assert!(!contents.contains("super-secret"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let before = contents;
    data(
        &command(&[
            "config",
            "set",
            "--profile",
            "work",
            "--url",
            "https://preview.invalid",
            "--dry-run",
        ])
        .env("SPLUNK_CONFIG", &config)
        .output()
        .unwrap(),
    );
    assert_eq!(std::fs::read_to_string(&config).unwrap(), before);
}

#[test]
fn web_url_defaults_to_the_management_host_and_can_be_overridden() {
    let show = |args: &[&str]| {
        let mut all = vec!["config", "show"];
        all.extend_from_slice(args);
        command(&all).output().unwrap()
    };
    let value = data(&show(&["--url", "https://splunk.invalid:8089"]));
    assert_eq!(value["web_url"], "https://splunk.invalid/");
    let value = data(&show(&[
        "--url",
        "https://splunk.invalid:8089",
        "--web-url",
        "https://web.invalid:8000/en-US/",
    ]));
    assert_eq!(value["web_url"], "https://web.invalid:8000/en-US/");
    let out = command(&["config", "show", "--url", "https://splunk.invalid:8089"])
        .env("SPLUNK_WEB_URL", "not a url")
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn browser_login_and_file_storage_are_declared_in_the_contract() {
    let schema = data(&command(&["schema", "auth", "login"]).output().unwrap());
    let login = &schema["commands"][0];
    let args = login["args"].as_array().unwrap();
    for name in ["--browser", "--insecure-storage"] {
        assert!(args.iter().any(|arg| arg["name"] == name), "{name}");
    }
    assert_eq!(
        login["stdout_schema"]["properties"]["credential_store"]["enum"],
        json!(["keyring", "file"])
    );
    assert!(
        login["x-interactive"]
            .as_str()
            .unwrap()
            .contains("--method browser")
    );
}

#[test]
fn config_rejects_embedded_credentials_without_echoing_them() {
    let out = command(&[
        "config",
        "show",
        "--url",
        "https://user:secret@example.invalid:8089",
    ])
    .output()
    .unwrap();
    error(&out, 2, "usage");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("user:secret"));
}

#[tokio::test]
async fn list_pages_project_fields_and_preserve_total() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/services/data/indexes"))
        .and(header("authorization", "Bearer test-secret"))
        .and(header(
            "user-agent",
            concat!("splunk-cli/", env!("CARGO_PKG_VERSION")),
        ))
        .and(query_param("output_mode", "json"))
        .and(query_param("count", "3"))
        .and(query_param("offset", "4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"paging": {"total": 10}, "entry": [
                {"name": "a", "content": {"totalEventCount": "10", "hidden": true}},
                {"name": "b", "content": {"totalEventCount": "20", "hidden": true}},
                {"name": "c", "content": {"totalEventCount": "30"}}
            ]}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let out = run(
        &server,
        &[
            "indexes",
            "list",
            "--limit",
            "2",
            "--offset",
            "4",
            "--fields",
            "name,totalEventCount",
        ],
    )
    .await;
    let value = data(&out);
    assert_eq!(value["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        value["items"][0],
        json!({"name": "a", "totalEventCount": "10"})
    );
    assert_eq!(value["total"], 10);
    assert_eq!(value["has_more"], true);
    assert_eq!(value["next_offset"], 6);
    assert!(out.stderr.is_empty());
}

#[tokio::test]
async fn unknown_totals_use_lookahead_without_silent_truncation() {
    let server = MockServer::start().await;
    Mock::given(path("/servicesNS/nobody/search/search/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entry": [
            {"name": "a", "content": {}}, {"name": "b", "content": {}}
        ]})))
        .mount(&server)
        .await;
    let value = data(&run(&server, &["jobs", "list", "--limit", "1"]).await);
    assert_eq!(value["total"], Value::Null);
    assert_eq!(value["has_more"], true);
    assert_eq!(value["next_offset"], 1);
}

#[tokio::test]
async fn search_submits_waits_and_returns_v2_results_with_job_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/servicesNS/nobody/search/search/jobs"))
        .and(body_string_contains("search=search+index%3Dmain"))
        .and(body_string_contains("earliest_time=-1h"))
        .and(body_string_contains("exec_mode=normal"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"sid": "job-1"})))
        .expect(1)
        .mount(&server)
        .await;
    completed(&server).await;
    Mock::given(method("GET"))
        .and(path(
            "/servicesNS/nobody/search/search/v2/jobs/job-1/results",
        ))
        .and(query_param("f", "host"))
        .and(query_param("count", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"preview": false, "results": [{"host": "a"}, {"host": "b"}, {"host": "c"}]}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let out = run(
        &server,
        &[
            "search",
            "index=main",
            "--earliest",
            "-1h",
            "--limit",
            "2",
            "--fields",
            "host",
        ],
    )
    .await;
    let value = data(&out);
    assert_eq!(value["job_id"], "job-1");
    assert_eq!(value["items"], json!([{"host": "a"}, {"host": "b"}]));
    assert_eq!(value["total"], 3);
    assert_eq!(value["next_offset"], 2);
    assert!(String::from_utf8_lossy(&out.stderr).contains("Created search job job-1"));
}

#[tokio::test]
async fn running_jobs_refuse_to_present_partial_results_as_complete() {
    let server = MockServer::start().await;
    Mock::given(path("/servicesNS/nobody/search/search/jobs/job-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(entries(json!({"isDone": false}))))
        .mount(&server)
        .await;
    error(
        &run(&server, &["jobs", "results", "job-1"]).await,
        7,
        "conflict",
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn search_wait_timeout_preserves_job_and_never_retries_submission() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"sid": "job-1"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(entries(json!({"isDone": false}))))
        .mount(&server)
        .await;
    let out = run(
        &server,
        &["search", "index=main", "--wait-timeout", "1", "--quiet"],
    )
    .await;
    let value = error(&out, 9, "timeout");
    assert_eq!(value["details"]["job_id"], "job-1");
    assert!(value["hint"].as_str().unwrap().contains("jobs show job-1"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("Created search"));
}

#[tokio::test]
async fn saved_search_dispatch_encodes_names_and_disables_actions() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/servicesNS/nobody/security/saved/searches/Daily%20errors/dispatch",
        ))
        .and(body_string_contains("trigger_actions=0"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"sid": "job-2"})))
        .expect(1)
        .mount(&server)
        .await;
    let value = data(
        &run(
            &server,
            &["--app", "security", "saved-searches", "run", "Daily errors"],
        )
        .await,
    );
    assert_eq!(value["job_id"], "job-2");
}

#[tokio::test]
async fn cancellation_and_deletion_are_guarded_and_repeated_deletion_is_a_noop() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/servicesNS/nobody/search/search/jobs/job-1/control"))
        .and(body_string_contains("action=cancel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        data(&run(&server, &["jobs", "cancel", "job-1", "--yes"]).await)["changed"],
        true
    );
    Mock::given(method("DELETE"))
        .and(path("/servicesNS/nobody/search/search/jobs/job-1"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        data(&run(&server, &["jobs", "delete", "job-1", "--yes"]).await)["changed"],
        false
    );
}

#[tokio::test]
async fn http_errors_have_stable_codes_and_redact_credentials() {
    for (status, code, kind) in [
        (401, 3, "auth"),
        (403, 3, "auth"),
        (404, 4, "not_found"),
        (409, 7, "conflict"),
        (429, 6, "rate_limit"),
        (500, 5, "api"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("retry-after", "10")
                    .set_body_json(json!({"messages": [{"text": "Rejected test-secret"}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let out = run(&server, &["indexes", "list"]).await;
        let value = error(&out, code, kind);
        assert_eq!(value["details"]["http_status"], status);
        assert!(!String::from_utf8_lossy(&out.stderr).contains("test-secret"));
        if status == 429 {
            assert_eq!(value["details"]["retry_after"], "10");
        }
    }
}

#[tokio::test]
async fn redirects_are_not_followed_with_credentials() {
    let source = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/stolen", target.uri())),
        )
        .mount(&source)
        .await;
    error(&run(&source, &["indexes", "list"]).await, 5, "api");
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn malformed_success_response_is_not_treated_as_empty_results() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>Splunk Web</html>"))
        .mount(&server)
        .await;
    error(
        &run(&server, &["indexes", "list"]).await,
        11,
        "invalid_response",
    );
}

#[tokio::test]
async fn basic_and_session_authentication_use_correct_headers() {
    for (auth, envs) in [
        (
            "Basic dXNlcjpwYXNz",
            vec![("SPLUNK_USERNAME", "user"), ("SPLUNK_PASSWORD", "pass")],
        ),
        (
            "Splunk session-secret",
            vec![("SPLUNK_SESSION_KEY", "session-secret")],
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(header("authorization", auth))
            .and(path("/services/authentication/current-context"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(entries(json!({"username": "user"}))),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut cmd = command(&["auth", "status"]);
        cmd.env("SPLUNK_URL", server.uri()).envs(envs);
        let out = tokio::task::spawn_blocking(move || cmd.output().unwrap())
            .await
            .unwrap();
        assert_eq!(data(&out)["authenticated"], true);
    }
}

#[tokio::test]
async fn path_traversal_is_rejected_before_any_request() {
    let server = MockServer::start().await;
    for name in ["..", "../other", "a/b", "a\\b"] {
        error(
            &run(&server, &["saved-searches", "show", name]).await,
            2,
            "usage",
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn search_cursor_reuses_the_existing_job_without_submitting_spl() {
    let server = MockServer::start().await;
    completed(&server).await;
    Mock::given(method("GET"))
        .and(path(
            "/servicesNS/nobody/search/search/v2/jobs/job-1/results",
        ))
        .and(query_param("offset", "1"))
        .and(query_param("count", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"results": [{"host": "b"}, {"host": "c"}]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let value = data(&run(&server, &["search", "--cursor", "job-1:1", "--limit", "1"]).await);
    assert_eq!(value["job_id"], "job-1");
    assert_eq!(value["next_cursor"], "job-1:2");
    assert_eq!(value["items"], json!([{"host": "b"}]));
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
    for args in [
        &["search", "index=main", "--cursor", "job-1:1"][..],
        &["search", "--cursor", "job-1:1", "--offset", "1"],
        &["search", "--cursor", "broken"],
    ] {
        error(&run(&server, args).await, 2, "usage");
    }
}

#[tokio::test]
async fn empty_results_never_return_a_cursor_that_cannot_advance() {
    let server = MockServer::start().await;
    completed(&server).await;
    Mock::given(path(
        "/servicesNS/nobody/search/search/v2/jobs/job-1/results",
    ))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
    .mount(&server)
    .await;
    let value = data(&run(&server, &["jobs", "results", "job-1"]).await);
    assert_eq!(value["has_more"], false);
    assert!(value["next_cursor"].is_null());
    assert!(value["next_offset"].is_null());
    assert_eq!(value["truncated"], true);
    assert_eq!(value["total"], 3);
}

#[test]
fn terminal_output_escapes_untrusted_keys_values_and_controls() {
    use splunk_cli::output::render;
    let payload = json!({"items": [{"\u{1b}[2J\n\u{9b}31m": "\u{202e}value\u{7f}"}], "total": 1, "next_offset": null});
    let rendered = render(&payload, false);
    assert!(!rendered.contains(['\u{1b}', '\u{9b}', '\u{202e}', '\u{7f}']));
    assert!(rendered.contains("\\u{1b}"));
}

#[test]
fn plaintext_remote_connections_require_explicit_opt_in() {
    let out = command(&["--url", "http://example.invalid:8089", "server", "info"])
        .env("SPLUNK_TOKEN", "secret")
        .output()
        .unwrap();
    let value = error(&out, 2, "usage");
    assert!(value["message"].as_str().unwrap().contains("--allow-http"));
}

#[test]
fn relative_xdg_config_home_is_ignored() {
    let out = command(&["config", "path"])
        .env_remove("SPLUNK_CONFIG")
        .env("XDG_CONFIG_HOME", "relative")
        .output()
        .unwrap();
    assert!(std::path::Path::new(data(&out)["path"].as_str().unwrap()).is_absolute());
}

#[tokio::test]
async fn splunk_warnings_survive_projection_and_quiet_without_leaking_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/services/server/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entry": [{"name": "server", "content": {"version": "10"}}],
            "messages": [{"type": "WARN", "text": "partial test-secret\u{001b}[31m results"}]
        })))
        .mount(&server)
        .await;
    let out = run(&server, &["server", "info", "--quiet"]).await;
    assert_eq!(data(&out)["version"], "10");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Warning: partial [REDACTED]"), "{stderr}");
    assert!(!stderr.contains("test-secret"));
    assert!(!stderr.contains('\u{001b}'));
}

#[test]
fn a_closed_pipeline_exits_quietly() {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = command(&["schema"]).stdout(writer).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty());
}

#[test]
fn profile_selection_persists_and_explicit_overrides_win() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[profiles.default]\nurl='https://default.example:8089'\n[profiles.prod]\nurl='https://prod.example:8089'\n").unwrap();
    let invoke = |args: &[&str]| {
        command(args)
            .env("SPLUNK_CONFIG", &config)
            .output()
            .unwrap()
    };
    assert_eq!(
        data(&invoke(&["profile", "use", "prod"]))["active_profile"],
        "prod"
    );
    assert_eq!(data(&invoke(&["config", "show"]))["profile"], "prod");
    assert_eq!(
        data(&invoke(&["config", "show", "--profile", "default"]))["profile"],
        "default"
    );
    let listed = data(&invoke(&["profile", "list"]));
    assert_eq!(listed["items"][1]["name"], "prod");
    assert_eq!(listed["items"][1]["active"], true);
    error(&invoke(&["profile", "use", "absent"]), 4, "not_found");
    error(
        &invoke(&["profile", "remove", "prod"]),
        8,
        "confirmation_required",
    );
    assert_eq!(
        data(&invoke(&["profile", "remove", "prod", "--dry-run"]))["dry_run"],
        true
    );
    assert_eq!(data(&invoke(&["config", "show"]))["profile"], "prod");
}

#[test]
fn offline_diagnostics_report_sources_without_claiming_authenticated_or_using_network() {
    let out = command(&["doctor", "--offline"])
        .env("SPLUNK_URL", "https://unreachable.invalid:8089")
        .env("SPLUNK_TOKEN", "private-token")
        .output()
        .unwrap();
    let report = data(&out);
    assert_eq!(report["ok"], true);
    assert_eq!(report["offline"], true);
    assert_eq!(report["credentials"]["source"], "environment");
    assert_eq!(report["credentials"]["verified"], false);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("private-token"));
    let status = command(&["auth", "status", "--offline"])
        .env("SPLUNK_URL", "https://unreachable.invalid:8089")
        .env("SPLUNK_TOKEN", "private-token")
        .output()
        .unwrap();
    assert_eq!(data(&status)["authenticated"], Value::Null);
    let init = command(&["init"]).output().unwrap();
    assert!(
        error(&init, 2, "usage")["message"]
            .as_str()
            .unwrap()
            .contains("terminal")
    );
}

#[tokio::test]
async fn doctor_identifies_a_permission_failure_and_keeps_completed_checks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/services/authentication/current-context"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"messages":[{"text":"permission denied"}]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let out = run(&server, &["doctor"]).await;
    let failure = error(&out, 3, "auth");
    assert!(
        failure["hint"]
            .as_str()
            .unwrap()
            .contains("role permissions")
    );
    assert_eq!(failure["details"]["checks"][0]["status"], "ok");
    assert_eq!(failure["details"]["checks"][3]["check"], "authentication");
    assert_eq!(failure["details"]["checks"][3]["status"], "failed");
}

#[tokio::test]
async fn exports_preserve_values_and_requested_field_order_while_tables_fit_the_terminal() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/services/data/indexes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entry": [
            {"name":"main", "content":{"note":"a,\"b\"\nline", "totalEventCount":"1200", "currentDBSizeMB":"25", "ignored":"extra"}},
            {"name":"very-long-index-name-that-needs-truncation", "content":{"note":null,"totalEventCount":"0"}}
        ],"paging":{"total":2}}))).mount(&server).await;
    let csv = run(
        &server,
        &["indexes", "list", "--fields", "name,note", "-o", "csv"],
    )
    .await;
    assert!(
        csv.status.success(),
        "{}",
        String::from_utf8_lossy(&csv.stderr)
    );
    assert_eq!(
        String::from_utf8(csv.stdout).unwrap(),
        "name,note\nmain,\"a,\"\"b\"\"\nline\"\nvery-long-index-name-that-needs-truncation,\n"
    );
    let jsonl = run(
        &server,
        &["indexes", "list", "--fields", "name", "-o", "jsonl"],
    )
    .await;
    assert!(jsonl.status.success());
    let lines: Vec<Value> = String::from_utf8(jsonl.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        lines,
        vec![
            json!({"name":"main"}),
            json!({"name":"very-long-index-name-that-needs-truncation"})
        ]
    );
    let mut cmd = command(&["indexes", "list", "-o", "table"]);
    cmd.env("SPLUNK_URL", server.uri())
        .env("SPLUNK_TOKEN", "test-secret")
        .env("COLUMNS", "56");
    let text = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.starts_with("NAME"), "{text}");
    assert!(!text.contains("ignored"));
    assert!(!text.contains("\"main\""));
    assert!(
        text.lines().all(|line| line.chars().count() <= 56),
        "{text}"
    );
    assert!(text.contains('…'));
}

#[test]
fn spl_files_and_stdin_share_validation_and_dry_run_never_submits() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("query.spl");
    std::fs::write(&file, "\u{feff}| makeresults\n| eval message=\"hello\"\n").unwrap();
    let out = command(&["search", "--file", file.to_str().unwrap(), "--dry-run"])
        .env("SPLUNK_URL", "https://offline.invalid:8089")
        .output()
        .unwrap();
    assert_eq!(
        data(&out)["parameters"]["search"],
        "| makeresults\n| eval message=\"hello\""
    );
    let mut child = command(&["jobs", "create", "--file", "-", "--dry-run"])
        .env("SPLUNK_URL", "https://offline.invalid:8089")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"index=main\n| head 2\n")
        .unwrap();
    assert_eq!(
        data(&child.wait_with_output().unwrap())["parameters"]["search"],
        "search index=main\n| head 2"
    );
    error(
        &command(&["search", "index=main", "--file", file.to_str().unwrap()])
            .output()
            .unwrap(),
        2,
        "usage",
    );
    error(
        &command(&[
            "search",
            "--cursor",
            "job-1:2",
            "--file",
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap(),
        2,
        "usage",
    );
    std::fs::write(&file, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    error(
        &command(&["search", "--file", file.to_str().unwrap(), "--dry-run"])
            .output()
            .unwrap(),
        2,
        "usage",
    );
}

#[tokio::test]
async fn watch_polls_an_existing_job_and_keeps_progress_off_stdout() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET")).and(path("/servicesNS/nobody/search/search/jobs/job-1"))
        .respond_with(move |_: &wiremock::Request| {
            let done = calls.fetch_add(1, Ordering::SeqCst) > 0;
            ResponseTemplate::new(200).set_body_json(entries(json!({"isDone":done,"dispatchState":if done {"DONE"} else {"RUNNING"},"doneProgress":if done {1.0} else {0.5},"scanCount":"20","resultCount":"3"})))
        }).expect(3).mount(&server).await;
    let out = run(
        &server,
        &[
            "jobs",
            "watch",
            "job-1",
            "--interval",
            "1",
            "--wait-timeout",
            "5",
        ],
    )
    .await;
    assert_eq!(data(&out)["job_id"], "job-1");
    assert_eq!(data(&out)["dispatchState"], "DONE");
    let progress = String::from_utf8(out.stderr).unwrap();
    assert!(progress.contains("RUNNING"), "{progress}");
    assert!(progress.contains("50%"), "{progress}");
    let out = run(&server, &["jobs", "wait", "job-1", "--quiet"]).await;
    assert_eq!(data(&out)["isDone"], true);
    assert!(out.stderr.is_empty());
    // Three GETs across the two commands, no submission or cancel request.
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn bounded_export_reads_pages_of_one_job_and_returns_a_continuation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicesNS/nobody/search/search/jobs/job-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(entries(json!({"isDone":true,"resultCount":"5"}))),
        )
        .expect(1)
        .mount(&server)
        .await;
    for (offset, count, items) in [
        ("0", "3", json!([{"n":"1"},{"n":"2"},{"n":"3"}])),
        ("2", "2", json!([{"n":"3"},{"n":"4"}])),
    ] {
        Mock::given(method("GET"))
            .and(path(
                "/servicesNS/nobody/search/search/v2/jobs/job-1/results",
            ))
            .and(query_param("offset", offset))
            .and(query_param("count", count))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"results":items,"preview":false})),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    let out = run(
        &server,
        &[
            "jobs",
            "export",
            "job-1",
            "--max-results",
            "3",
            "--page-size",
            "2",
        ],
    )
    .await;
    let value = data(&out);
    assert_eq!(value["items"], json!([{"n":"1"},{"n":"2"},{"n":"3"}]));
    assert_eq!(value["job_id"], "job-1");
    assert_eq!(value["has_more"], true);
    assert_eq!(value["next_cursor"], "job-1:3");
    assert_eq!(value["next_offset"], 3);
    assert_eq!(value["limit"], 3);
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}

#[test]
fn new_command_contracts_describe_effects_bounded_exports_and_offline_auth() {
    let spec = data(&command(&["schema"]).output().unwrap());
    let commands = spec["commands"].as_array().unwrap();
    let find = |name: &str| commands.iter().find(|c| c["name"] == name).unwrap();
    for name in ["init", "profile use", "profile remove"] {
        assert_eq!(find(name)["effects"], "idempotent");
    }
    assert_eq!(
        find("jobs export")["pagination"]["limit_arg"],
        "--max-results"
    );
    assert_eq!(find("profile list")["cardinality"], "bounded");
    let auth = jsonschema::validator_for(&find("auth status")["stdout_schema"]).unwrap();
    assert!(auth.is_valid(&json!({"authenticated":null,"offline":true,"profile":"default","url":"https://host:8089/","credentials":{"source":"environment","available":true,"verified":false,"method":"token"}})));
    let removal = jsonschema::validator_for(&find("profile remove")["stdout_schema"]).unwrap();
    assert!(removal.is_valid(
        &json!({"dry_run":true,"profile":"work","action":"remove","url":"https://host:8089"})
    ));
}

#[tokio::test]
async fn authorization_diagnostics_redact_encoded_basic_credentials_and_explain_permissions() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/services/server/info"))
        .respond_with(ResponseTemplate::new(403).set_body_json(
            json!({"messages":[{"text":"Rejected Basic dXNlcjpwYXNzd29yZA== password"}]}),
        ))
        .mount(&server)
        .await;
    let mut cmd = command(&["server", "info"]);
    cmd.env("SPLUNK_URL", server.uri())
        .env("SPLUNK_USERNAME", "user")
        .env("SPLUNK_PASSWORD", "password");
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    let failure = error(&out, 3, "auth");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("dXNlcjpwYXNzd29yZA=="));
    assert!(
        failure["hint"]
            .as_str()
            .unwrap()
            .contains("role permissions")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn ctrl_c_preserves_the_job_and_returns_recovery_details() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicesNS/nobody/search/search/jobs/job-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(entries(json!({"isDone":false,"dispatchState":"RUNNING"}))),
        )
        .mount(&server)
        .await;
    let mut child = command(&["jobs", "watch", "job-1", "--quiet", "--interval", "60"])
        .env("SPLUNK_URL", server.uri())
        .env("SPLUNK_TOKEN", "test-secret")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while server.received_requests().await.unwrap().is_empty()
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    while child.try_wait().unwrap().is_none() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    let failure = error(&child.wait_with_output().unwrap(), 130, "interrupted");
    assert_eq!(failure["details"]["job_id"], "job-1");
    assert!(
        failure["hint"]
            .as_str()
            .unwrap()
            .contains("jobs results job-1")
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}

#[test]
fn profile_previews_hide_invalid_urls_and_settings_can_be_removed_without_keyring_access() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "[profiles.work]\nurl='https://user:private-secret@host:8089'\n",
    )
    .unwrap();
    let invoke = |args: &[&str]| {
        command(args)
            .env("SPLUNK_CONFIG", &config)
            .output()
            .unwrap()
    };
    let listed = data(&invoke(&["profile", "list"]));
    assert_eq!(listed["items"][0]["valid"], false);
    assert_eq!(listed["items"][0]["url"], Value::Null);
    let preview = data(&invoke(&["profile", "remove", "work", "--dry-run"]));
    assert_eq!(preview["url"], Value::Null);
    assert!(!preview.to_string().contains("private-secret"));
    assert!(!dir.path().join("config.toml.lock").exists());
    error(&invoke(&["profile", "use", "work"]), 2, "usage");
    let removed = data(&invoke(&[
        "profile",
        "remove",
        "work",
        "--keep-credentials",
        "--yes",
    ]));
    assert_eq!(removed["removed"], true);
    assert_eq!(removed["credentials_removed"], Value::Null);
    assert!(
        data(&invoke(&["profile", "list"]))["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn export_failure_never_emits_partial_records_and_empty_pages_stop_continuation() {
    for failure in [true, false] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicesNS/nobody/search/search/jobs/job-1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(entries(json!({"isDone":true,"resultCount":"5"}))),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/servicesNS/nobody/search/search/v2/jobs/job-1/results",
            ))
            .and(query_param("offset", "0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"results":[{"n":"1"},{"n":"2"},{"n":"3"}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/servicesNS/nobody/search/search/v2/jobs/job-1/results",
            ))
            .and(query_param("offset", "2"))
            .respond_with(if failure {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(json!({"results":[]}))
            })
            .expect(1)
            .mount(&server)
            .await;
        let out = run(
            &server,
            &[
                "jobs",
                "export",
                "job-1",
                "--max-results",
                "5",
                "--page-size",
                "2",
                "--output",
                if failure { "csv" } else { "json" },
            ],
        )
        .await;
        if failure {
            assert_eq!(error(&out, 5, "api")["details"]["job_id"], "job-1");
        } else {
            let value = data(&out);
            assert_eq!(value["items"], json!([{"n":"1"},{"n":"2"}]));
            assert_eq!(value["truncated"], true);
            assert_eq!(value["has_more"], false);
            assert_eq!(value["next_cursor"], Value::Null);
        }
    }
}

#[tokio::test]
async fn a_closed_stderr_pipeline_does_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/services/server/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entry":[{"name":"server","content":{"version":"10"}}],"messages":[{"type":"WARN","text":"warning"}]})))
        .mount(&server).await;
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut cmd = command(&["server", "info"]);
    cmd.env("SPLUNK_URL", server.uri())
        .env("SPLUNK_TOKEN", "fixture")
        .stderr(writer);
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    assert!(out.status.success(), "{:?}", out.status);
}

#[cfg(unix)]
#[tokio::test]
async fn ctrl_c_still_works_while_fetching_results_after_waiting() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/servicesNS/nobody/search/search/jobs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"sid":"job-1"})))
        .mount(&server)
        .await;
    completed(&server).await;
    Mock::given(method("GET"))
        .and(path(
            "/servicesNS/nobody/search/search/v2/jobs/job-1/results",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(30))
                .set_body_json(json!({"results":[]})),
        )
        .mount(&server)
        .await;
    let mut child = command(&["search", "| makeresults", "--quiet"])
        .env("SPLUNK_URL", server.uri())
        .env("SPLUNK_TOKEN", "fixture")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|r| r.url.path().ends_with("/results"))
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    while child.try_wait().unwrap().is_none() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    assert_eq!(
        error(&child.wait_with_output().unwrap(), 130, "interrupted")["details"]["job_id"],
        "job-1"
    );
}

#[tokio::test]
async fn export_byte_bound_returns_records_and_a_precise_continuation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicesNS/nobody/search/search/jobs/job-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(entries(json!({"isDone":true,"resultCount":"5000"}))),
        )
        .mount(&server)
        .await;
    let row = json!({"payload":"x".repeat(8192)});
    Mock::given(method("GET"))
        .and(path(
            "/servicesNS/nobody/search/search/v2/jobs/job-1/results",
        ))
        .respond_with(move |request: &wiremock::Request| {
            let offset: usize = request
                .url
                .query_pairs()
                .find(|(key, _)| key == "offset")
                .unwrap()
                .1
                .parse()
                .unwrap();
            ResponseTemplate::new(200)
                .set_body_json(json!({"results":vec![row.clone(); (5000-offset).min(1001)]}))
        })
        .mount(&server)
        .await;
    let out = run(&server, &["jobs", "export", "job-1"]).await;
    let value = data(&out);
    assert_eq!(value["items"].as_array().unwrap().len(), 4088);
    assert_eq!(value["next_offset"], 4088);
    assert_eq!(value["next_cursor"], "job-1:4088");
    assert_eq!(value["byte_limit_reached"], true);
    assert_eq!(value["bounded"], true);
    assert!(serde_json::to_vec(&value["items"]).unwrap().len() <= 32 * 1024 * 1024);
}

#[tokio::test]
async fn splunk_error_text_is_actionable_redacted_and_keeps_job_recovery() {
    let server = MockServer::start().await;
    completed(&server).await;
    Mock::given(method("GET"))
        .and(path(
            "/servicesNS/nobody/search/search/v2/jobs/job-1/results",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"messages":[{"type":"ERROR","text":"Lookup missing; supplied test-secret"}]}),
        ))
        .mount(&server)
        .await;
    let failure = error(&run(&server, &["jobs", "results", "job-1"]).await, 5, "api");
    assert_eq!(failure["message"], "Lookup missing; supplied [REDACTED]");
    assert!(
        failure["hint"]
            .as_str()
            .unwrap()
            .contains("jobs results job-1")
    );
}

#[tokio::test]
async fn repeated_splunk_warnings_are_shown_once_per_invocation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entry":[{"name":"job-1","content":{"isDone":true,"resultCount":"1"}}],
            "results":[{"value":"one"}],"messages":[{"type":"WARN","text":"Same warning"}]
        })))
        .mount(&server)
        .await;
    let out = run(&server, &["jobs", "results", "job-1"]).await;
    assert_eq!(data(&out)["items"], json!([{"value":"one"}]));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr)
            .matches("Warning: Same warning")
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn config_updates_preserve_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("actual.toml");
    let alias = dir.path().join("config.toml");
    std::fs::write(
        &target,
        "[profiles.default]\nurl='https://old.example:8089'\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let out = command(&["config", "set", "--url", "https://new.example:8089"])
        .env("SPLUNK_CONFIG", &alias)
        .output()
        .unwrap();
    assert_eq!(data(&out)["saved"], true);
    assert!(alias.is_symlink());
    assert!(
        std::fs::read_to_string(&target)
            .unwrap()
            .contains("https://new.example:8089")
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_return_structured_errors_instead_of_panicking() {
    use std::os::unix::ffi::OsStringExt;
    let path = std::ffi::OsString::from_vec(b"/tmp/splunk-\xff".to_vec());
    let out = command(&["config", "path"])
        .env("SPLUNK_CONFIG", &path)
        .output()
        .unwrap();
    error(&out, 2, "usage");
    let out = command(&[
        "config",
        "show",
        "--url",
        "https://example.invalid:8089",
        "--ca-cert",
    ])
    .arg(path)
    .output()
    .unwrap();
    error(&out, 2, "usage");
}

#[cfg(unix)]
#[tokio::test]
async fn ctrl_c_interrupts_a_blocked_output_writer() {
    use std::io::Read;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicesNS/nobody/search/search/jobs/job-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(entries(json!({"isDone":true,"large":"x".repeat(512*1024)}))),
        )
        .mount(&server)
        .await;
    let mut child = command(&["jobs", "wait", "job-1", "--quiet"])
        .env("SPLUNK_URL", server.uri())
        .env("SPLUNK_TOKEN", "fixture")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let reading = tokio::task::spawn_blocking(move || {
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut [0u8; 1])
            .unwrap();
        child
    });
    let mut child = match tokio::time::timeout(std::time::Duration::from_secs(10), reading).await {
        Ok(result) => result.unwrap(),
        Err(_) => {
            Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status()
                .unwrap();
            panic!("No output within 10 seconds");
        }
    };
    Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(130));
    let stderr = String::from_utf8(out.stderr).unwrap();
    let error: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
    assert_eq!(error["error"]["kind"], "interrupted");
    assert_eq!(error["error"]["details"]["job_id"], "job-1");
}

#[test]
fn text_usage_errors_keep_readable_lines_and_one_error_prefix() {
    let out = command(&["--output", "text", "--unknown"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.starts_with("Error: unexpected argument"), "{text}");
    assert!(text.contains("\n\nUsage:"), "{text}");
    assert!(!text.contains("\\n"));
}

#[tokio::test]
async fn json_errors_escape_terminal_controls_without_changing_decoded_messages() {
    let server = MockServer::start().await;
    let message = "Rejected \u{009b}31m\u{202e}value";
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"messages":[{"text":message}]})),
        )
        .mount(&server)
        .await;
    let out = run(&server, &["server", "info", "--output", "json"]).await;
    assert_eq!(error(&out, 2, "usage")["message"], message);
    assert!(!String::from_utf8_lossy(&out.stderr).contains(['\u{009b}', '\u{202e}']));
}

#[test]
fn missing_ca_certificates_have_configuration_context_and_recovery_hints() {
    let dir = tempfile::tempdir().unwrap();
    for args in [&["doctor", "--offline"][..], &["config", "set"]] {
        let mut cmd = command(args);
        cmd.env("SPLUNK_CONFIG", dir.path().join("config.toml"));
        cmd.args([
            "--url",
            "https://example.invalid:8089",
            "--ca-cert",
            "/nonexistent/splunk-cli-missing-ca.pem",
        ])
        .env("SPLUNK_TOKEN", "fixture");
        let failure = error(&cmd.output().unwrap(), 2, "usage");
        assert!(
            failure["message"]
                .as_str()
                .unwrap()
                .contains("CA certificate")
        );
        assert!(failure["hint"].as_str().unwrap().contains("--ca-cert"));
    }
}

#[cfg(windows)]
#[tokio::test]
async fn detached_windows_processes_can_wait_without_a_console_handler() {
    use std::os::windows::process::CommandExt;
    let server = MockServer::start().await;
    completed(&server).await;
    let mut cmd = command(&["jobs", "wait", "job-1", "--quiet"]);
    cmd.creation_flags(0x00000008) // DETACHED_PROCESS: no console for Ctrl-C registration.
        .env("SPLUNK_URL", server.uri())
        .env("SPLUNK_TOKEN", "fixture");
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    assert_eq!(data(&out)["job_id"], "job-1");
}

#[tokio::test]
async fn raw_event_tables_show_event_context_without_internal_splunk_columns() {
    let server = MockServer::start().await;
    completed(&server).await;
    Mock::given(method("GET")).and(path("/servicesNS/nobody/search/search/v2/jobs/job-1/results"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results":[{"_raw":"raw-message","_time":"2026-11-03T12:00:00Z","host":"fixture","_bkt":"internal-bucket","_cd":"internal-position"}]})))
        .mount(&server).await;
    let out = run(&server, &["jobs", "results", "job-1", "--output", "text"]).await;
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("raw-message"));
    assert!(text.contains("_TIME"));
    assert!(!text.contains("_BKT"));
    assert!(!text.contains("internal-bucket"));
}

#[tokio::test]
async fn file_login_integrates_with_active_profiles_diagnostics_and_scoped_removal() {
    use std::io::Write;
    use std::process::Stdio;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/services/authentication/current-context"))
        .and(header("authorization", "Bearer file-test-token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(entries(json!({"username": "test"}))),
        )
        .expect(3)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let config = config.to_str().unwrap().to_owned();
    let url = server.uri();
    let first = tokio::task::spawn_blocking(move || {
        let login = |name: &str| {
            let mut child = command(&[
                "init",
                "--profile",
                name,
                "--config",
                &config,
                "--url",
                &url,
                "--web-url",
                "https://web.invalid/splunk/",
                "--token-stdin",
                "--insecure-storage",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"file-test-token\n")
                .unwrap();
            data(&child.wait_with_output().unwrap())
        };
        assert_eq!(login("work")["credential_store"], "file");
        assert_eq!(login("other")["credential_store"], "file");
        config
    })
    .await
    .unwrap();
    let invoke = |args: &[&str]| {
        let mut all = vec!["--config", &first];
        all.extend_from_slice(args);
        command(&all).output().unwrap()
    };
    data(&invoke(&["profile", "use", "work"]));
    let status = data(&invoke(&["auth", "status", "--offline"]));
    assert_eq!(status["profile"], "work");
    assert_eq!(status["credentials"]["source"], "file");
    assert!(status["authenticated"].is_null());
    let doctor = data(&invoke(&["doctor", "--offline"]));
    assert_eq!(doctor["credentials"]["source"], "file");
    assert_eq!(
        data(&invoke(&["config", "show"]))["web_url"],
        "https://web.invalid/splunk/"
    );
    let config = first.clone();
    let online = tokio::task::spawn_blocking(move || {
        command(&["--config", &config, "auth", "status"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(data(&online)["authenticated"], true);
    let removed = data(&invoke(&["profile", "remove", "work", "--yes"]));
    assert_eq!(removed["credentials_removed"], true);
    let remaining: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("credentials.json")).unwrap())
            .unwrap();
    assert_eq!(remaining.as_object().unwrap().len(), 1);
    data(&invoke(&["profile", "use", "other"]));
    assert_eq!(
        data(&invoke(&["auth", "status", "--offline"]))["credentials"]["source"],
        "file"
    );
    data(&invoke(&["profile", "remove", "other", "--yes"]));
    let remaining: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("credentials.json")).unwrap())
            .unwrap();
    assert!(remaining.as_object().unwrap().is_empty());
    let schema = data(&command(&["schema", "init"]).output().unwrap());
    assert!(
        schema["commands"][0]["args"]
            .as_array()
            .unwrap()
            .iter()
            .any(|arg| arg["name"] == "--browser")
    );
}

#[test]
fn config_cannot_collide_with_the_credential_store() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("credentials.json");
    let out = command(&[
        "auth",
        "login",
        "--url",
        "https://splunk.invalid:8089",
        "--config",
        config.to_str().unwrap(),
        "--token-stdin",
        "--insecure-storage",
    ])
    .output()
    .unwrap();
    let failure = error(&out, 2, "usage");
    assert!(failure["message"].as_str().unwrap().contains("reserved"));
    assert!(!config.exists());
}
