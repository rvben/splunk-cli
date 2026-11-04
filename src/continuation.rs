//! Opaque, versioned continuation context. Contains no credentials or SPL.
use crate::{Error, Result, cli::Page, config::Settings};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    url: String,
    app: String,
    owner: String,
    fields: Vec<String>,
    job_id: String,
    offset: u64,
}

pub fn encode(settings: &Settings, sid: &str, page: &Page, offset: u64) -> String {
    let value = Cursor {
        url: settings.url.to_string(),
        app: settings.app.clone(),
        owner: settings.owner.clone(),
        fields: page.fields.clone(),
        job_id: sid.into(),
        offset,
    };
    format!(
        "v1.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).expect("cursor JSON"))
    )
}

pub fn decode(settings: &Settings, token: &str, page: &mut Page) -> Result<String> {
    let invalid = || Error::usage("Invalid continuation; use next_cursor from search results");
    if token.len() > 64 * 1024 {
        return Err(invalid());
    }
    let (sid, offset) = if let Some(encoded) = token.strip_prefix("v1.") {
        let value: Cursor =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        if value.url != settings.url.as_str()
            || value.app != settings.app
            || value.owner != settings.owner
        {
            return Err(Error::usage(
                "Continuation belongs to a different server or app/owner namespace",
            )
            .hint("Select the original connection and namespace, or start a new search"));
        }
        if !page.fields.is_empty() && page.fields != value.fields {
            return Err(
                Error::usage("Continuation fields differ from the original search")
                    .hint("Omit --fields to reuse the original selection"),
            );
        }
        page.fields = value.fields;
        (value.job_id, value.offset)
    } else {
        let (sid, offset) = token.rsplit_once(':').ok_or_else(invalid)?;
        let offset = offset.parse::<u64>().map_err(|_| invalid())?;
        crate::output::diagnostic(format_args!(
            "Warning: legacy continuation has no connection context; use the new next_cursor for subsequent pages"
        ));
        (sid.into(), offset)
    };
    crate::config::validate_segment(&sid, "cursor job ID")?;
    if offset > i64::MAX as u64 {
        return Err(invalid());
    }
    page.offset = offset;
    Ok(sid)
}
