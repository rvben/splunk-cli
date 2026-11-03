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
