use crate::{
    Result,
    cli::{Cli, Command, Format, Indexes, Jobs, Page, SavedSearches, Server},
};
use serde_json::{Value, json};
use std::io::{IsTerminal, Write};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub fn project(mut value: Value, fields: &[String]) -> Value {
    if !fields.is_empty()
        && let Some(map) = value.as_object_mut()
    {
        map.retain(|key, _| fields.contains(key));
    }
    value
}

pub fn number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

pub fn page(mut items: Vec<Value>, total: Option<u64>, options: &Page) -> Value {
    let has_extra = items.len() > options.limit as usize;
    items.truncate(options.limit as usize);
    let next = options.offset + items.len() as u64;
    let has_more = !items.is_empty() && total.map_or(has_extra, |total| next < total);
    let truncated = items.is_empty() && total.is_some_and(|total| options.offset < total);
    let items: Vec<Value> = items
        .into_iter()
        .map(|v| project(v, &options.fields))
        .collect();
    let mut value = json!({"items": items, "total": total, "offset": options.offset, "limit": options.limit,
        "has_more": has_more, "next_offset": if has_more { Some(next) } else { None }});
    if truncated {
        value["truncated"] = json!(true);
    }
    value
}

fn rows(value: &Value) -> Vec<&Value> {
    value
        .get("items")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_else(|| vec![value])
}

fn columns(rows: &[&Value], fields: &[String]) -> Vec<String> {
    if !fields.is_empty() {
        return fields.to_vec();
    }
    let mut columns = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        if let Some(map) = row.as_object() {
            for key in map.keys() {
                if seen.insert(key) {
                    columns.push(key.clone());
                }
            }
        }
    }
    columns
}

fn cell(value: &Value) -> String {
    terminal(&raw_cell(value))
}

fn raw_cell(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        _ => value.to_string(),
    }
}

fn fit(text: &str, width: usize) -> String {
    if UnicodeWidthStr::width(text) <= width {
        return text.into();
    }
    let mut result = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let size = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + size > width.saturating_sub(1) {
            break;
        }
        result.push(ch);
        used += size;
    }
    if width > 0 {
        result.push('…');
    }
    result
}

pub(crate) fn quote_csv(text: String) -> String {
    if text.contains([',', '\n', '\r', '"']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

fn width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v: &usize| *v > 0)
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(100)
        .clamp(10, 500)
}

fn summary(value: &Value) -> String {
    let count = value["items"].as_array().map_or(0, Vec::len);
    let mut text = format!("{count} records");
    if !value["total"].is_null() {
        text.push_str(&format!("; total: {}", cell(&value["total"])));
    }
    if let Some(cursor) = value["next_cursor"].as_str() {
        text.push_str(&format!("; continue: --cursor {}", terminal(cursor)));
    } else if let Some(offset) = value["next_offset"].as_u64() {
        text.push_str(&format!("; next offset: {offset}"));
    }
    if value["byte_limit_reached"] == true {
        text.push_str("; 32 MiB export bound reached");
    }
    if value["truncated"] == true {
        text.push_str("; results truncated by Splunk");
    }
    text
}

fn heading(key: &str) -> String {
    terminal(match key {
        "totalEventCount" => "EVENTS",
        "currentDBSizeMB" => "SIZE (MiB)",
        "dispatchState" => "STATE",
        "doneProgress" => "PROGRESS",
        "resultCount" => "RESULTS",
        "runDuration" => "TIME (s)",
        "is_scheduled" => "SCHEDULED",
        "cron_schedule" => "SCHEDULE",
        _ => return terminal(&key.to_uppercase()),
    })
}

fn table_cell(key: &str, value: &Value) -> String {
    if value.is_null() {
        return "—".into();
    }
    if matches!(key, "disabled" | "is_scheduled" | "active" | "default") {
        if value == true || value == "1" || value == 1 {
            return "yes".into();
        }
        if value == false || value == "0" || value == 0 {
            return "no".into();
        }
    }
    let number = value
        .as_f64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()));
    match (key, number.filter(|n| n.is_finite())) {
        ("doneProgress", Some(number)) => format!("{:.0}%", number.clamp(0.0, 1.0) * 100.0),
        ("runDuration", Some(number)) => format!("{number:.1}"),
        _ => cell(value),
    }
}

fn table(value: &Value, fields: &[String], preferred: &[&str], terminal_width: usize) -> String {
    let rows = rows(value);
    let mut columns = columns(&rows, fields);
    let available_columns = columns.len();
    if fields.is_empty() && !preferred.is_empty() {
        let selected: Vec<_> = preferred
            .iter()
            .filter(|key| columns.iter().any(|c| c == **key))
            .map(|k| (*k).into())
            .collect();
        if !selected.is_empty() {
            columns = selected;
        }
    }
    // Keep at least one visible column, even on very narrow terminals.
    columns.truncate(((terminal_width + 2) / 6).max(1));
    let mut widths: Vec<usize> = columns
        .iter()
        .map(|key| {
            rows.iter()
                .map(|row| UnicodeWidthStr::width(table_cell(key, &row[key]).as_str()))
                .chain(std::iter::once(UnicodeWidthStr::width(
                    heading(key).as_str(),
                )))
                .max()
                .unwrap_or(1)
                .clamp(1, terminal_width)
        })
        .collect();
    let spacing = widths.len().saturating_sub(1) * 2;
    while widths.iter().sum::<usize>() + spacing > terminal_width {
        if let Some((index, _)) = widths
            .iter()
            .enumerate()
            .filter(|(_, w)| **w > 1)
            .max_by_key(|(_, w)| **w)
        {
            widths[index] -= 1;
        } else {
            break;
        }
    }
    let line = |cells: Vec<String>| {
        cells
            .iter()
            .zip(&widths)
            .enumerate()
            .map(|(index, (cell, width))| {
                let text = fit(cell, *width);
                if index + 1 == widths.len() {
                    text
                } else {
                    format!(
                        "{text}{}",
                        " ".repeat(width.saturating_sub(UnicodeWidthStr::width(text.as_str())))
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut lines = Vec::new();
    if rows.is_empty() {
        lines.push("No results.".into());
    } else {
        lines.push(line(columns.iter().map(|key| heading(key)).collect()));
        lines.extend(rows.iter().map(|row| {
            line(
                columns
                    .iter()
                    .map(|key| table_cell(key, &row[key]))
                    .collect(),
            )
        }));
    }
    if available_columns > columns.len() {
        lines.extend(wrap(
            &format!(
                "Showing {} of {available_columns} columns; use --output json for all columns.",
                columns.len()
            ),
            terminal_width,
        ));
    }
    if rows.iter().any(|row| {
        columns.iter().zip(&widths).any(|(key, width)| {
            UnicodeWidthStr::width(table_cell(key, &row[key]).as_str()) > *width
        })
    }) {
        lines.extend(wrap(
            "Values shortened to fit; use --output json for complete values.",
            terminal_width,
        ));
    }
    lines.extend(wrap(&summary(value), terminal_width));
    if let Some(job) = value["job_id"].as_str() {
        lines.extend(wrap(&format!("Job: {}", terminal(job)), terminal_width));
    }
    lines.join("\n")
}

fn details(value: &Value, indent: usize, lines: &mut Vec<String>) {
    if let Some(map) = value.as_object() {
        let label_width = map
            .keys()
            .map(|key| UnicodeWidthStr::width(terminal(key).as_str()))
            .max()
            .unwrap_or(0)
            .min(40);
        for (key, value) in map {
            let key = terminal(key);
            let padding =
                " ".repeat(label_width.saturating_sub(UnicodeWidthStr::width(key.as_str())));
            if value.is_object() {
                lines.push(format!("{}{key}:", " ".repeat(indent)));
                details(value, indent + 2, lines);
            } else if let Some(checks) = value.as_array().filter(|_| key == "checks") {
                lines.push(format!("{}{key}:", " ".repeat(indent)));
                for check in checks {
                    lines.push(format!(
                        "{}[{}] {}: {}",
                        " ".repeat(indent + 2),
                        cell(&check["status"]),
                        cell(&check["check"]),
                        cell(&check["message"])
                    ));
                }
            } else {
                lines.push(format!(
                    "{}{key}:{padding} {}",
                    " ".repeat(indent),
                    if value.is_null() {
                        "—".into()
                    } else {
                        cell(value)
                    }
                ));
            }
        }
    } else {
        lines.push(format!("{}{}", " ".repeat(indent), cell(value)));
    }
}

pub fn render(value: &Value, json_output: bool) -> String {
    if json_output {
        return value.to_string();
    }
    if value["items"].is_array() {
        return table(value, &[], &[], width());
    }
    let mut lines = Vec::new();
    details(value, 0, &mut lines);
    lines.join("\n")
}

fn fields(cli: &Cli) -> &[String] {
    match &cli.command {
        Command::Search(search) => &search.page.fields,
        Command::Jobs(Jobs::Export(export)) => &export.fields,
        Command::Jobs(Jobs::List(page) | Jobs::Results { page, .. })
        | Command::Indexes(Indexes::List(page))
        | Command::SavedSearches(SavedSearches::List(page)) => &page.fields,
        Command::Jobs(Jobs::Show { fields, .. })
        | Command::Indexes(Indexes::Show { fields, .. })
        | Command::SavedSearches(SavedSearches::Show { fields, .. })
        | Command::Server(Server::Info { fields }) => fields,
        _ => &[],
    }
}

/// Machine exports contain records only; collection metadata remains on stderr.
pub fn emit(value: &Value, cli: &Cli) -> Result<()> {
    let terminal_output = std::io::stdout().is_terminal();
    let inherited: Vec<String> = value["fields"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let selected = if fields(cli).is_empty() {
        &inherited
    } else {
        fields(cli)
    };
    let mut text = match cli.output {
        Format::Json | Format::Auto if cli.output.is_json() => {
            terminal_json(&value.to_string(), terminal_output)
        }
        Format::Csv => {
            let rows = rows(value);
            let columns = columns(&rows, selected);
            let escape = |text: String| {
                let text = if terminal_output {
                    terminal(&text)
                } else {
                    text
                };
                quote_csv(text)
            };
            let mut lines = vec![
                columns
                    .iter()
                    .cloned()
                    .map(escape)
                    .collect::<Vec<_>>()
                    .join(","),
            ];
            lines.extend(rows.iter().map(|row| {
                columns
                    .iter()
                    .map(|key| escape(raw_cell(&row[key])))
                    .collect::<Vec<_>>()
                    .join(",")
            }));
            lines.join("\n")
        }
        Format::Jsonl => rows(value)
            .iter()
            .map(|row| terminal_json(&row.to_string(), terminal_output))
            .collect::<Vec<_>>()
            .join("\n"),
        _ if value["items"].is_array() => {
            let preferred: &[&str] = match cli.command {
                Command::Search(_) | Command::Jobs(Jobs::Results { .. } | Jobs::Export(_))
                    if rows(value).iter().any(|row| row.get("_raw").is_some()) =>
                {
                    &["_time", "host", "source", "sourcetype", "_raw"]
                }
                Command::Indexes(_) => &["name", "totalEventCount", "currentDBSizeMB", "disabled"],
                Command::Jobs(Jobs::List(_)) => &[
                    "sid",
                    "dispatchState",
                    "doneProgress",
                    "resultCount",
                    "runDuration",
                ],
                Command::SavedSearches(_) => &[
                    "name",
                    "disabled",
                    "is_scheduled",
                    "cron_schedule",
                    "owner",
                    "app",
                ],
                Command::Profile(_) => &["name", "active", "valid", "url", "app", "owner"],
                _ => &[],
            };
            let fallback;
            let preferred = if matches!(cli.command, Command::Jobs(Jobs::List(_)))
                && !rows(value).iter().any(|row| row.get("sid").is_some())
            {
                fallback = preferred
                    .iter()
                    .map(|key| if *key == "sid" { "name" } else { *key })
                    .collect::<Vec<_>>();
                &fallback
            } else {
                preferred
            };
            table(value, selected, preferred, width())
        }
        _ => render(value, false),
    };
    if !cli.output.is_json()
        && !matches!(cli.output, Format::Csv | Format::Jsonl)
        && value["items"].as_array().is_some_and(Vec::is_empty)
    {
        let hint = match cli.command {
            Command::Profile(_) => "Create a connection with splunk-cli init --profile work.",
            Command::Indexes(_) => {
                "Check your Splunk role and index permissions with an administrator."
            }
            Command::SavedSearches(_) => {
                "Check --app and --owner, or list all visible owners with --owner -."
            }
            Command::Jobs(Jobs::List(_)) => {
                "Create a job with splunk-cli jobs create 'index=main | head 10'."
            }
            _ => "Check the SPL, time range, permissions, and result offset.",
        };
        text.push('\n');
        text.push_str(&wrap(hint, width()).join("\n"));
    }
    if matches!(cli.output, Format::Csv | Format::Jsonl)
        && value["items"].is_array()
        && (!cli.quiet || value["has_more"] == true || value["truncated"] == true)
    {
        crate::output::diagnostic(format_args!("{}", summary(value)));
        if let Some(job) = value["job_id"].as_str() {
            crate::output::diagnostic(format_args!("Job: {}", terminal(job)));
        }
    }
    if text.is_empty() {
        Ok(())
    } else {
        write_bytes(format!("{text}\n").as_bytes())
    }
}

/// Escape terminal controls, including C1 and bidirectional formatting controls.
pub fn terminal(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if unsafe_terminal(ch) {
                ch.escape_default().to_string()
            } else {
                ch.to_string()
            }
        })
        .collect()
}

pub fn write(value: &Value, json_output: bool) -> Result<()> {
    write_bytes(format!("{}\n", render(value, json_output)).as_bytes())
}

/// A consumer such as `head` may close stdout early; that is a successful pipeline.
pub fn write_bytes(bytes: &[u8]) -> Result<()> {
    match std::io::stdout().lock().write_all(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let size = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + size > width {
            lines.push(std::mem::take(&mut line));
            used = 0;
        }
        line.push(ch);
        used += size;
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Diagnostics must not panic when a downstream reader closes stderr.
pub fn diagnostic(message: std::fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr().lock(), "{message}");
}

fn unsafe_terminal(ch: char) -> bool {
    ch.is_control()
        || matches!(ch, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// JSON escapes preserve decoded values while preventing terminal control effects.
fn terminal_json(text: &str, is_terminal: bool) -> String {
    if !is_terminal {
        return text.into();
    }
    text.chars()
        .map(|ch| {
            if unsafe_terminal(ch) {
                format!("\\u{:04x}", ch as u32)
            } else {
                ch.to_string()
            }
        })
        .collect()
}

/// Keep diagnostic paragraphs readable while escaping controls within each line.
pub fn terminal_lines(text: &str) -> String {
    text.split('\n')
        .map(terminal)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Stderr is often a terminal even when stdout is piped. JSON escapes are lossless.
pub fn diagnostic_json(value: &Value) {
    diagnostic(format_args!("{}", terminal_json(&value.to_string(), true)));
}
