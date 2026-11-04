//! Page-bounded file exports. Data is synced before atomically advancing a checkpoint.
use crate::{
    Error, Result,
    cli::{Export, Page, RecordFormat},
    client::Client,
    config, output,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    url: String,
    app: String,
    owner: String,
    job_id: String,
    fields: Vec<String>,
    format: RecordFormat,
    output_file: PathBuf,
    total: Option<u64>,
    start_offset: u64,
    next_offset: u64,
    exported: u64,
    bytes: u64,
    sha256: String,
    header_written: bool,
    has_more: bool,
}

fn location(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| Error::usage("Export paths must name a file"))?;
    Ok(parent.canonicalize()?.join(name))
}

fn regular(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => Err(Error::usage(
            "Export and checkpoint paths must be regular files, not symlinks",
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn exclusive(path: &Path) -> Result<File> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(PathBuf::from(name))?;
    lock.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => {
            Error::new("conflict", "Another export holds this output or checkpoint")
                .hint("Wait for the existing writer to finish; do not remove its lock file")
        }
        std::fs::TryLockError::Error(error) => error.into(),
    })?;
    Ok(lock)
}

fn save(path: &Path, state: &Checkpoint) -> Result<()> {
    let bytes = serde_json::to_vec(state).map_err(|_| Error::invalid_response())?;
    config::write_atomic(path, &bytes)?;
    #[cfg(unix)]
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}

fn csv(value: &Value) -> String {
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        _ => value.to_string(),
    };
    output::quote_csv(text)
}

pub async fn stream(client: &Client, options: &Export) -> Result<Value> {
    if options.record_format == RecordFormat::Csv && options.fields.is_empty() {
        return Err(Error::usage(
            "Streaming CSV requires --fields for a stable header across pages",
        ));
    }
    let file_path = location(
        options
            .output_file
            .as_deref()
            .ok_or_else(|| Error::usage("--stream requires --output-file"))?,
    )?;
    let checkpoint_path = location(&options.checkpoint.clone().unwrap_or_else(|| {
        let mut name = file_path.as_os_str().to_owned();
        name.push(".checkpoint.json");
        PathBuf::from(name)
    }))?;
    let mut file_lock = file_path.as_os_str().to_owned();
    file_lock.push(".lock");
    let mut checkpoint_lock = checkpoint_path.as_os_str().to_owned();
    checkpoint_lock.push(".lock");
    if file_path == checkpoint_path || checkpoint_path == file_lock || file_path == checkpoint_lock
    {
        return Err(Error::usage(
            "Output, checkpoint and their lock paths must be distinct",
        ));
    }
    regular(&file_path)?;
    regular(&checkpoint_path)?;
    crate::interrupt::run(stream_to(client, options, &file_path, &checkpoint_path)).await.map_err(|mut error| {
        let resumable = checkpoint_path.is_file() && (
            matches!(error.kind, "interrupted" | "transport" | "timeout" | "rate_limit" | "io") ||
            (error.kind == "api" && error.details["http_status"].as_u64().is_some_and(|s| s >= 500))
        );
        error.details["output_file"] = json!(file_path);
        error.details["checkpoint"] = json!(checkpoint_path);
        error.details["resumable"] = json!(resumable);
        if resumable && error.hint.is_none() {
            error.hint = Some("Correct the error, then repeat the original export with --resume. The checkpoint records durable pages; the existing Splunk job is preserved.".into());
        }
        error
    })
}

async fn stream_to(
    client: &Client,
    options: &Export,
    file_path: &Path,
    checkpoint_path: &Path,
) -> Result<Value> {
    let _output_lock = exclusive(file_path)?;
    let _checkpoint_lock = exclusive(checkpoint_path)?;
    // Validate the job before creating or repairing local data.
    let state = client
        .request(
            reqwest::Method::GET,
            true,
            &["search", "jobs", &options.id],
            &[],
        )
        .await?;
    let content = state["entry"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|e| e.get("content"))
        .ok_or_else(Error::invalid_response)?
        .clone();
    if !crate::workflows::check_state(&content)? {
        return Err(Error::new(
            "conflict",
            "Search is still running; wait with jobs wait before exporting",
        ));
    }
    let total = output::number(&content["resultCount"]);
    let mut digest = Sha256::new();
    let mut checkpoint;
    let mut file;
    if options.resume {
        let metadata = fs::metadata(checkpoint_path)?;
        if metadata.len() > 1024 * 1024 {
            return Err(Error::usage("Export checkpoint exceeds 1 MiB"));
        }
        checkpoint = serde_json::from_slice::<Checkpoint>(&fs::read(checkpoint_path)?)
            .map_err(|_| Error::usage("Invalid export checkpoint"))?;
        if checkpoint.version != 1
            || checkpoint.url != client.settings.url.as_str()
            || checkpoint.app != client.settings.app
            || checkpoint.owner != client.settings.owner
            || checkpoint.job_id != options.id
            || checkpoint.fields != options.fields
            || checkpoint.format != options.record_format
            || checkpoint.output_file != file_path
            || checkpoint.total != total
            || (options.offset != 0 && checkpoint.start_offset != options.offset)
            || checkpoint.next_offset > i64::MAX as u64
        {
            return Err(Error::usage("Checkpoint does not match this connection, job, fields, format, output file, or result count").hint("Reuse the original export options; use a new file for a different export"));
        }
        let mut open = OpenOptions::new();
        open.read(true).write(true);
        if checkpoint.bytes == 0 {
            open.create(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        file = open.open(file_path)?;
        if file.metadata()?.len() < checkpoint.bytes {
            return Err(Error::new(
                "conflict",
                "Export file is shorter than its durable checkpoint",
            ).hint("Restore the original output and checkpoint together; resume cannot reconstruct missing durable bytes"));
        }
        let mut prefix = (&mut file).take(checkpoint.bytes);
        let mut buffer = [0u8; 65536];
        loop {
            let n = prefix.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
        }
        if format!("{:x}", digest.clone().finalize()) != checkpoint.sha256 {
            return Err(Error::new(
                "conflict",
                "Export data changed since its checkpoint; refusing to resume",
            )
            .hint(
                "Restore the original output and checkpoint together, or choose a new output file",
            ));
        }
        file.set_len(checkpoint.bytes)?;
        file.seek(SeekFrom::Start(checkpoint.bytes))?;
        file.sync_all()?;
    } else {
        if file_path.exists() || checkpoint_path.exists() {
            return Err(
                Error::new("conflict", "Export output or checkpoint already exists")
                    .hint("Use --resume with the original options, or choose a new output file"),
            );
        }
        checkpoint = Checkpoint {
            version: 1,
            url: client.settings.url.to_string(),
            app: client.settings.app.clone(),
            owner: client.settings.owner.clone(),
            job_id: options.id.clone(),
            fields: options.fields.clone(),
            format: options.record_format,
            output_file: file_path.to_owned(),
            total,
            start_offset: options.offset,
            next_offset: options.offset,
            exported: 0,
            bytes: 0,
            sha256: format!("{:x}", digest.clone().finalize()),
            header_written: false,
            has_more: true,
        };
        save(checkpoint_path, &checkpoint)?;
        let mut open = OpenOptions::new();
        open.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        file = open.open(file_path)?;
        file.sync_all()?;
    }
    #[cfg(unix)]
    File::open(file_path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    let mut written = 0u32;
    while checkpoint.has_more && written < options.max_results {
        let page = Page {
            limit: options.page_size.min(options.max_results - written),
            offset: checkpoint.next_offset,
            fields: options.fields.clone(),
        };
        let value =
            crate::workflows::results(client, &options.id, &page, Some(content.clone())).await?;
        if value["truncated"] == true {
            return Err(Error::new(
                "invalid_response",
                "Splunk truncated results before the expected end; durable export preserved",
            ));
        }
        let rows = value["items"]
            .as_array()
            .ok_or_else(Error::invalid_response)?;
        if (rows.is_empty() && value["has_more"] == true) || rows.len() > page.limit as usize {
            return Err(Error::new(
                "invalid_response",
                "Export page did not advance within its requested bound",
            ));
        }
        if options.record_format == RecordFormat::Csv && !checkpoint.header_written {
            let header = options
                .fields
                .iter()
                .map(|s| csv(&json!(s)))
                .collect::<Vec<_>>()
                .join(",")
                + "\n";
            file.write_all(header.as_bytes())?;
            digest.update(header.as_bytes());
            checkpoint.bytes += header.len() as u64;
            checkpoint.header_written = true;
        }
        for row in rows {
            let record = match options.record_format {
                RecordFormat::Jsonl => row.to_string(),
                RecordFormat::Csv => options
                    .fields
                    .iter()
                    .map(|s| csv(&row[s]))
                    .collect::<Vec<_>>()
                    .join(","),
            } + "\n";
            file.write_all(record.as_bytes())?;
            digest.update(record.as_bytes());
            checkpoint.bytes += record.len() as u64;
        }
        file.sync_all()?;
        checkpoint.exported += rows.len() as u64;
        checkpoint.next_offset = page.offset + rows.len() as u64;
        checkpoint.has_more = value["has_more"] == true;
        checkpoint.sha256 = format!("{:x}", digest.clone().finalize());
        save(checkpoint_path, &checkpoint)?;
        written += rows.len() as u32;
    }
    Ok(
        json!({"job_id":options.id,"streamed":true,"output_file":file_path,"checkpoint":checkpoint_path,"record_format":options.record_format,"exported":checkpoint.exported,"written":written,"bytes":checkpoint.bytes,"has_more":checkpoint.has_more,"next_offset":if checkpoint.has_more { Some(checkpoint.next_offset) } else { None }}),
    )
}
