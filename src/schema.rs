//! Command arguments are derived from Clap; effects and output contracts live here.
use crate::{Error, Result, error::KINDS};
use serde_json::{Value, json};

fn argument(arg: &clap::Arg) -> Value {
    let id = arg.get_id().as_str();
    let name = arg
        .get_long()
        .map(|name| format!("--{name}"))
        .unwrap_or_else(|| id.to_owned());
    let kind = if !arg.get_action().takes_values() {
        "boolean"
    } else if matches!(
        id,
        "limit" | "offset" | "timeout" | "wait_timeout" | "interval" | "max_results" | "page_size"
    ) {
        "integer"
    } else if matches!(id, "fields" | "command" | "keys") {
        "string[]"
    } else {
        "string"
    };
    let mut value = json!({"name": name, "type": kind, "description": arg.get_help().map(ToString::to_string).unwrap_or_default()});
    if arg.is_required_set() {
        value["required"] = json!(true);
    }
    if let Some(short) = arg.get_short() {
        value["short"] = json!(format!("-{short}"));
    }
    if let Some(env) = arg.get_env() {
        value["env"] = json!(env.to_string_lossy());
    }
    if let Some(default) = arg.get_default_values().first() {
        let default = default.to_string_lossy();
        value["default"] = match kind {
            "integer" | "boolean" => {
                serde_json::from_str(&default).unwrap_or_else(|_| json!(default))
            }
            _ => json!(default),
        };
    }
    if let Some(possible) = arg
        .get_value_parser()
        .possible_values()
        .filter(|_| kind != "boolean")
    {
        value["enum"] = json!(
            possible
                .flat_map(|v| v
                    .get_name_and_aliases()
                    .map(str::to_owned)
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );
    }
    value
}

fn describe(command: &clap::Command, name: &str) -> Value {
    let collection = command
        .get_arguments()
        .any(|a| matches!(a.get_id().as_str(), "limit" | "max_results"));
    let effects = match name {
        "search" | "jobs create" | "saved-searches run" => "non_idempotent",
        "jobs cancel" | "jobs delete" | "config set" | "auth login" | "auth logout" | "init"
        | "profile use" | "profile remove" | "profile rename" | "config unset" | "auth migrate" => {
            "idempotent"
        }
        _ => "read_only",
    };
    let args: Vec<_> = command
        .get_arguments()
        .filter(|a| !a.is_global_set() && !matches!(a.get_id().as_str(), "help" | "version"))
        .map(argument)
        .collect();
    let mut value = json!({"name": name, "description": command.get_about().map(ToString::to_string).unwrap_or_default(),
        "effects": effects, "mutating": effects != "read_only", "stability": "stable", "args": args,
        "cardinality": if collection { "unbounded" } else { "single" }, "stdout_schema": {"type": "object"}});
    if collection {
        value["pagination"] =
            json!({"style": "offset", "limit_arg": "--limit", "offset_arg": "--offset"});
        value["fields_arg"] = json!("--fields");
        value["stdout_schema"] = json!({"type": "object", "required": ["items", "total", "offset", "limit", "has_more", "next_offset"], "properties": {
            "items": {"type": "array", "items": {"type": "object"}}, "total": {"type": ["integer", "null"]},
            "offset": {"type": "integer"}, "limit": {"type": "integer"}, "has_more": {"type": "boolean"}, "next_offset": {"type": ["integer", "null"]}}});
        if name == "search" {
            value["pagination"] = json!({"style": "cursor", "cursor_field": "next_cursor", "cursor_arg": "--cursor", "limit_arg": "--limit"});
            value["x-pagination-note"] = json!(
                "With --cursor this command is read-only and reuses the existing job; without --cursor it submits a non-idempotent search. Pass next_cursor without a query, or use jobs results JOB_ID."
            );
        }
    }
    match name {
        "search check" => {
            value["stdout_schema"] = json!({"type":"object","required":["valid","parse_only","parsed"],"properties":{"valid":{"const":true},"parse_only":{"const":true},"parsed":{"type":"object"}}});
        }
        "jobs logs" => {
            value["stdout_schema"] = json!({"type":"object","required":["job_id","log"],"properties":{"job_id":{"type":"string"},"log":{"type":"string"}}});
        }
        "auth migrate" => {
            value["stdout_schema"] = json!({"type":"object", "required":["profile","url","credential_store","previous_store","changed","dry_run","environment_credentials"], "properties":{
                "profile":{"type":"string"},"url":{"type":"string"},"credential_store":{"enum":["keyring","file"]},"previous_store":{"enum":["keyring","file"]},"changed":{"type":"boolean"},"dry_run":{"type":"boolean"},"environment_credentials":{"type":"boolean"}
            }});
        }
        "profile rename" => {
            value["stdout_schema"] = json!({"type":"object", "required":["profile","new_name","changed"], "properties":{
                "profile":{"type":"string"},"new_name":{"type":"string"},"changed":{"type":"boolean"},"dry_run":{"type":"boolean"},"credentials_moved":{"type":["integer","null"],"minimum":0},"active_profile":{"type":"string"},"keep_credentials":{"type":"boolean"}
            }});
        }
        "config unset" => {
            value["stdout_schema"] = json!({"type":"object", "required":["profile","unset","changed","dry_run"], "properties":{
                "profile":{"type":"string"},"unset":{"type":"array","items":{"type":"string"}},"changed":{"type":"boolean"},"dry_run":{"type":"boolean"}
            }});
        }
        "jobs create" | "saved-searches run" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}});
        }
        "jobs results" | "jobs export" | "search" => {
            value["stdout_schema"]["required"]
                .as_array_mut()
                .unwrap()
                .push(json!("job_id"));
            value["stdout_schema"]["properties"]["job_id"] = json!({"type": "string"});
            value["stdout_schema"]["required"]
                .as_array_mut()
                .unwrap()
                .push(json!("next_cursor"));
            value["stdout_schema"]["properties"]["next_cursor"] =
                json!({"type": ["string", "null"]});
            value["stdout_schema"]["properties"]["fields"] =
                json!({"type":"array","items":{"type":"string"}});
        }
        "jobs cancel" | "jobs delete" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["job_id", "action", "success", "changed"], "properties": {
                "job_id": {"type": "string"}, "action": {"enum": ["cancel", "delete"]}, "success": {"type": "boolean"}, "changed": {"type": "boolean"}}});
        }
        "auth login" | "init" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["authenticated", "profile", "url", "credential_store", "method", "environment_credentials"], "properties": {
                "authenticated": {"const": true}, "profile": {"type": "string"}, "url": {"type": "string"},
                "credential_store": {"enum": ["keyring", "file"]}, "method": {"enum": ["token", "password", "session"]}, "environment_credentials": {"type": "boolean"}}});
            value["x-interactive"] = json!(
                "Requires terminal stdin and stderr, unless --token-stdin is supplied or --method browser is used with a configured URL. Prompts never appear on stdout. --method browser opens a private browser window for SSO and waits up to 5 minutes. When the OS credential store is unavailable, a terminal session asks before saving to a plaintext file; --insecure-storage opts in without asking."
            );
        }
        "auth logout" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["profile", "url", "removed", "environment_credentials"], "properties": {
                "profile": {"type": "string"}, "url": {"type": "string"}, "removed": {"type": "boolean"}, "environment_credentials": {"type": "boolean"}}});
        }
        "auth status" => {
            value["stdout_schema"] = json!({"oneOf": [
                {"type": "object", "required": ["authenticated", "context"], "properties": {"authenticated": {"const": true}, "context": {"type": "object"}}},
                {"type": "object", "required": ["authenticated", "offline", "profile", "url", "credentials"], "properties": {"authenticated": {"type": "null"}, "offline": {"const": true}, "profile": {"type": "string"}, "url": {"type": "string"}, "credentials": {"type": "object"}}}
            ]});
            value["x-offline-note"] = json!(
                "--offline checks local credential availability; authenticated is null because credentials have not been verified against Splunk."
            );
        }
        "doctor" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["ok", "offline", "profile", "url", "credentials", "checks"], "properties": {
                "ok": {"const": true}, "offline": {"type": "boolean"}, "profile": {"type": "string"}, "url": {"type": "string"}, "credentials": {"type": "object"},
                "checks": {"type": "array", "items": {"type": "object", "required": ["check", "status", "message"], "properties": {"check": {"type": "string"}, "status": {"enum": ["ok", "warning", "failed"]}, "message": {"type": "string"}}}}}});
            value["x-failure-note"] = json!(
                "Failures use the standard error envelope and exit code; details.checks contains completed checks and the failed check. No search is submitted."
            );
        }
        "jobs wait" | "jobs watch" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["job_id", "isDone"], "properties": {"job_id": {"type": "string"}}});
            value["x-progress-note"] = json!(
                "Watch progress goes to stderr, final state to stdout. Timeout and Ctrl-C preserve the job and return its ID in error.details.job_id."
            );
        }
        "profile list" => {
            value["cardinality"] = json!("bounded");
            value["stdout_schema"] = json!({"type": "object", "required": ["items", "active_profile", "default_profile"], "properties": {
                "items": {"type": "array", "items": {"type": "object"}}, "active_profile": {"type": "string"}, "default_profile": {"type": "string"}}});
        }
        "profile use" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["active_profile"], "properties": {"active_profile": {"type": "string"}}});
        }
        "profile remove" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["removed", "profile", "credentials_removed", "active_profile"], "properties": {
                "removed": {"const": true}, "profile": {"type": "string"}, "credentials_removed": {"type": ["boolean", "null"]}, "active_profile": {"type": "string"}}});
        }
        "config path" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}})
        }
        "config set" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["saved", "settings"], "properties": {
            "saved": {"const": true}, "settings": {"type": "object"}}})
        }
        _ => {}
    }
    if command.get_arguments().any(|a| a.get_id() == "dry_run")
        && !matches!(name, "auth migrate" | "profile rename" | "config unset")
    {
        let normal = value["stdout_schema"].clone();
        let preview = if name == "config set" {
            json!({"type": "object", "required": ["dry_run", "settings"], "properties": {"dry_run": {"const": true}, "settings": {"type": "object"}}})
        } else if name == "profile remove" {
            json!({"type": "object", "required": ["dry_run", "profile", "action", "url"], "properties": {"dry_run": {"const": true}, "profile": {"type": "string"}, "action": {"const": "remove"}, "url": {"type": ["string", "null"]}}})
        } else {
            json!({"type": "object", "required": ["dry_run", "method", "url", "parameters"], "properties": {
                "dry_run": {"const": true}, "method": {"enum": ["POST", "DELETE"]}, "url": {"type": "string"}, "parameters": {"type": "object", "additionalProperties": {"type": "string"}}}})
        };
        value["stdout_schema"] = json!({"oneOf": [normal, preview]});
    }
    if command.get_arguments().any(|a| a.get_id() == "fields") {
        value["fields_arg"] = json!("--fields");
    }
    if matches!(name, "jobs cancel" | "jobs delete" | "profile remove") {
        value["confirmation_bypass_arg"] = json!("--yes");
    }
    if effects == "non_idempotent" {
        value["x-retry-note"] = json!(
            "No automatic submission retries. Splunk does not provide an idempotency key for dispatch. Inspect the existing job before resubmitting; SPL may write data. Subsequent safe GET requests may retry transient HTTP responses."
        );
    }
    if name == "jobs export" {
        for key in ["bounded", "byte_limit_reached"] {
            value["stdout_schema"]["required"]
                .as_array_mut()
                .unwrap()
                .push(json!(key));
            value["stdout_schema"]["properties"][key] = json!({"type": "boolean"});
        }
        value["pagination"] =
            json!({"style": "offset", "limit_arg": "--max-results", "offset_arg": "--offset"});
        value["x-export-note"] = json!(
            "Reads only the named completed job. Buffered mode stops at --max-results or 32 MiB of record JSON. --stream writes page-bounded CSV/JSONL to --output-file, advances a durable checkpoint after each synced page, and returns a summary. --resume verifies the durable prefix and discards only an uncommitted tail. Streaming CSV requires --fields. --max-results bounds each invocation."
        );
        let buffered = value["stdout_schema"].clone();
        let streamed = json!({"type":"object","required":["job_id","streamed","output_file","checkpoint","record_format","exported","written","bytes","has_more","next_offset"],"properties":{
            "job_id":{"type":"string"},"streamed":{"const":true},"output_file":{"type":"string"},"checkpoint":{"type":"string"},"record_format":{"enum":["csv","jsonl"]},"exported":{"type":"integer","minimum":0},"written":{"type":"integer","minimum":0},"bytes":{"type":"integer","minimum":0},"has_more":{"type":"boolean"},"next_offset":{"type":["integer","null"]}
        }});
        value["stdout_schema"] = json!({"oneOf":[buffered,streamed]});
        value["x-local-effects"] = json!(
            "With --stream this command creates local output/checkpoint/lock files; --resume may truncate bytes after the durable checkpoint. It never mutates or resubmits the remote job."
        );
    }
    if matches!(name, "auth status" | "doctor") {
        let credentials = json!({"type":"object","properties":{
            "available":{"type":"boolean"},"source":{"enum":["environment","keyring","file"]},"method":{"enum":["token","session","password"]},"verified":{"type":"boolean"},"selection":{"enum":["environment","saved","legacy"]},"expires_at":{"type":["integer","null"],"minimum":0},"expiry_status":{"enum":["expired","not_expired","unknown"]},"expiry_source":{"enum":["unverified_token_claim",null]}
        }});
        if name == "doctor" {
            value["stdout_schema"]["properties"]["credentials"] = credentials;
        } else {
            value["stdout_schema"]["oneOf"][1]["properties"]["credentials"] = credentials;
        }
        value["x-expiry-note"] = json!(
            "JWT exp is an unverified diagnostic claim, never an authentication decision. Opaque tokens, passwords and sessions have unknown expiry; online checks remain authoritative."
        );
    }
    if name == "schema" {
        value["stdout_schema"] = json!({"$ref": "https://clispec.dev/schema/v0.3.json"});
    }
    if name == "completions" {
        value.as_object_mut().unwrap().remove("cardinality");
        value.as_object_mut().unwrap().remove("stdout_schema");
        value["output_kind"] = json!("opaque");
        value["media_type"] = json!("text/plain");
    }
    value
}

fn walk(command: &clap::Command, prefix: &str, commands: &mut Vec<Value>) {
    for child in command.get_subcommands() {
        let name = format!("{prefix}{}", child.get_name());
        if child.has_subcommands() {
            if child.get_name() == "search" {
                commands.push(describe(child, &name));
            }
            walk(child, &format!("{name} "), commands);
        } else {
            commands.push(describe(child, &name));
        }
    }
}

pub fn contract() -> Value {
    let mut cli = crate::cli::command();
    cli.build();
    let mut commands = Vec::new();
    walk(&cli, "", &mut commands);
    json!({"clispec": "0.3", "name": "splunk-cli", "version": env!("CARGO_PKG_VERSION"),
        "description": env!("CARGO_PKG_DESCRIPTION"), "output": {"tty": "text", "piped": "json"},
        "global_args": cli.get_arguments().filter(|a| a.is_global_set()).map(argument).collect::<Vec<_>>(),
        "commands": commands,
        "errors": KINDS.iter().map(|(kind, code, retryable, description)| json!({"kind": kind, "exit_code": code, "retryable": retryable, "description": description})).collect::<Vec<_>>(),
        "extensions": {"record_formats": ["csv", "jsonl"], "warnings": "Splunk WARN messages go to stderr even with --quiet. Closed stdout pipelines exit successfully.", "credential_env_vars": ["SPLUNK_TOKEN", "SPLUNK_SESSION_KEY", "SPLUNK_USERNAME", "SPLUNK_PASSWORD"]}})
}

pub fn filtered(prefix: &str) -> Result<Value> {
    let mut value = contract();
    if !prefix.is_empty() {
        let commands = value["commands"].as_array_mut().unwrap();
        commands.retain(|command| {
            command["name"]
                .as_str()
                .is_some_and(|name| name == prefix || name.starts_with(&format!("{prefix} ")))
        });
        if commands.is_empty() {
            return Err(Error::usage(
                "Unknown schema command path; run splunk-cli schema",
            ));
        }
    }
    Ok(value)
}

pub fn contract_json() -> String {
    serde_json::to_string_pretty(&contract()).expect("JSON value")
}
