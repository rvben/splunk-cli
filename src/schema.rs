//! Command arguments are derived from Clap; effects and output contracts live here.
use crate::{Error, Result, cli::Cli, error::KINDS};
use clap::CommandFactory;
use serde_json::{Value, json};

fn argument(arg: &clap::Arg) -> Value {
    let id = arg.get_id().as_str();
    let name = arg
        .get_long()
        .map(|name| format!("--{name}"))
        .unwrap_or_else(|| id.to_owned());
    let kind = if !arg.get_action().takes_values() {
        "boolean"
    } else if matches!(id, "limit" | "offset" | "timeout" | "wait_timeout") {
        "integer"
    } else if matches!(id, "fields" | "command") {
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
                .map(|v| v.get_name().to_owned())
                .collect::<Vec<_>>()
        );
    }
    value
}

fn describe(command: &clap::Command, name: &str) -> Value {
    let collection = command.get_arguments().any(|a| a.get_id() == "limit");
    let effects = match name {
        "search" | "jobs create" | "saved-searches run" => "non_idempotent",
        "jobs cancel" | "jobs delete" | "config set" | "auth login" | "auth logout" => "idempotent",
        _ => "read_only",
    };
    let args: Vec<_> = command
        .get_arguments()
        .filter(|a| !a.is_global_set() && !matches!(a.get_id().as_str(), "help" | "version"))
        .map(argument)
        .collect();
    let mut value = json!({"name": name, "description": command.get_about().map(ToString::to_string).unwrap_or_default(),
        "effects": effects, "mutating": effects != "read_only", "stability": "experimental", "args": args,
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
                "Pass next_cursor to search --cursor without a query to reuse the existing job, or use jobs results JOB_ID."
            );
        }
    }
    match name {
        "jobs create" | "saved-searches run" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}});
        }
        "jobs results" | "search" => {
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
        }
        "jobs cancel" | "jobs delete" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["job_id", "action", "success", "changed"], "properties": {
                "job_id": {"type": "string"}, "action": {"enum": ["cancel", "delete"]}, "success": {"type": "boolean"}, "changed": {"type": "boolean"}}});
        }
        "auth login" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["authenticated", "profile", "url", "credential_store", "method", "environment_credentials"], "properties": {
                "authenticated": {"const": true}, "profile": {"type": "string"}, "url": {"type": "string"},
                "credential_store": {"const": "keyring"}, "method": {"enum": ["token", "password", "session"]}, "environment_credentials": {"type": "boolean"}}});
            value["x-interactive"] = json!(
                "Requires terminal stdin and stderr, unless --token-stdin is supplied. Prompts never appear on stdout."
            );
        }
        "auth logout" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["profile", "url", "removed", "environment_credentials"], "properties": {
                "profile": {"type": "string"}, "url": {"type": "string"}, "removed": {"type": "boolean"}, "environment_credentials": {"type": "boolean"}}});
        }
        "auth status" => {
            value["stdout_schema"] = json!({"type": "object", "required": ["authenticated", "context"], "properties": {
            "authenticated": {"const": true}, "context": {"type": "object"}}})
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
    if command.get_arguments().any(|a| a.get_id() == "dry_run") {
        let normal = value["stdout_schema"].clone();
        let preview = if name == "config set" {
            json!({"type": "object", "required": ["dry_run", "settings"], "properties": {"dry_run": {"const": true}, "settings": {"type": "object"}}})
        } else {
            json!({"type": "object", "required": ["dry_run", "method", "url", "parameters"], "properties": {
                "dry_run": {"const": true}, "method": {"enum": ["POST", "DELETE"]}, "url": {"type": "string"}, "parameters": {"type": "object", "additionalProperties": {"type": "string"}}}})
        };
        value["stdout_schema"] = json!({"oneOf": [normal, preview]});
    }
    if command.get_arguments().any(|a| a.get_id() == "fields") {
        value["fields_arg"] = json!("--fields");
    }
    if matches!(name, "jobs cancel" | "jobs delete") {
        value["confirmation_bypass_arg"] = json!("--yes");
    }
    if effects == "non_idempotent" {
        value["x-retry-note"] = json!(
            "No automatic retries. Splunk does not provide an idempotency key for this workflow. Inspect the existing job before resubmitting; SPL may write data."
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
            walk(child, &format!("{name} "), commands);
        } else {
            commands.push(describe(child, &name));
        }
    }
}

pub fn contract() -> Value {
    let mut cli = Cli::command();
    cli.build();
    let mut commands = Vec::new();
    walk(&cli, "", &mut commands);
    json!({"clispec": "0.3", "name": "splunk-cli", "version": env!("CARGO_PKG_VERSION"),
        "description": env!("CARGO_PKG_DESCRIPTION"), "output": {"tty": "text", "piped": "json"},
        "global_args": cli.get_arguments().filter(|a| a.is_global_set()).map(argument).collect::<Vec<_>>(),
        "commands": commands,
        "errors": KINDS.iter().map(|(kind, code, retryable, description)| json!({"kind": kind, "exit_code": code, "retryable": retryable, "description": description})).collect::<Vec<_>>(),
        "extensions": {"credential_env_vars": ["SPLUNK_TOKEN", "SPLUNK_SESSION_KEY", "SPLUNK_USERNAME", "SPLUNK_PASSWORD"]}})
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
