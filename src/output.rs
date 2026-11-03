use crate::{Result, cli::Page};
use serde_json::{Value, json};
use std::io::Write;

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

/// Plain text uses tabs and JSON-escaped strings, so event data cannot inject ANSI.
pub fn render(value: &Value, json_output: bool) -> String {
    if json_output {
        return serde_json::to_string(value).expect("JSON value");
    }
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut columns = Vec::<String>::new();
        for item in items {
            if let Some(map) = item.as_object() {
                for key in map.keys() {
                    if !columns.contains(key) {
                        columns.push(key.clone());
                    }
                }
            }
        }
        let mut lines = vec![
            columns
                .iter()
                .map(|key| terminal(key))
                .collect::<Vec<_>>()
                .join("\t"),
        ];
        for item in items {
            lines.push(
                columns
                    .iter()
                    .map(|key| item.get(key).map(cell).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join("\t"),
            );
        }
        if items.is_empty() {
            lines = vec!["No results.".into()];
        }
        lines.push(format!(
            "{} records; total: {}; next offset: {}",
            items.len(),
            value["total"],
            value["next_offset"]
        ));
        if let Some(job) = value["job_id"].as_str() {
            lines.push(format!("Job: {}", cell(&json!(job))));
        }
        return lines.join("\n");
    }
    if let Some(map) = value.as_object() {
        return map
            .iter()
            .map(|(key, value)| format!("{}: {}", terminal(key), cell(value)))
            .collect::<Vec<_>>()
            .join("\n");
    }
    cell(value)
}

fn cell(value: &Value) -> String {
    // JSON escaping also neutralizes tabs, newlines, ESC, and other controls.
    terminal(&value.to_string())
}

/// Escape terminal controls, including C1 and bidirectional formatting controls.
pub fn terminal(text: &str) -> String {
    text.chars().map(|ch| {
        if ch.is_control() || matches!(ch, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            ch.escape_default().to_string()
        } else { ch.to_string() }
    }).collect()
}

pub fn write(value: &Value, json_output: bool) -> Result<()> {
    writeln!(std::io::stdout().lock(), "{}", render(value, json_output))?;
    Ok(())
}
