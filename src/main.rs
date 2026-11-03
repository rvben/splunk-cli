use clap::{CommandFactory, Parser, error::ErrorKind};
use splunk_cli::{
    Error,
    cli::{Cli, Command, Format},
    interrupt, output, schema, workflows,
};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            // Parse only the output selector, without trusting any other invalid input.
            let args: Vec<String> = std::env::args().skip(1).collect();
            let mut format = Format::Auto;
            let mut index = 0;
            while index < args.len() {
                let arg = &args[index];
                if arg == "--" {
                    break;
                }
                let value = if arg == "-o" || arg == "--output" {
                    index += 1;
                    args.get(index).map(String::as_str)
                } else {
                    arg.strip_prefix("--output=")
                        .or_else(|| arg.strip_prefix("-o").filter(|s| !s.is_empty()))
                };
                match value {
                    Some("json") => format = Format::Json,
                    Some("text" | "table") => format = Format::Text,
                    Some("csv") => format = Format::Csv,
                    Some("jsonl" | "ndjson") => format = Format::Jsonl,
                    Some("auto") => format = Format::Auto,
                    _ => {}
                }
                index += 1;
            }
            return fail(Error::usage(error.to_string().trim()), format.is_json());
        }
    };
    let json_output = cli.output.is_json();
    let result = match &cli.command {
        Command::Schema { command } => {
            schema::filtered(&command.join(" ")).and_then(|value| output::write(&value, true))
        }
        Command::Completions { shell } => {
            let mut command = Cli::command();
            let mut bytes = Vec::new();
            clap_complete::generate(*shell, &mut command, "splunk-cli", &mut bytes);
            output::write_bytes(&bytes)
        }
        _ => match workflows::execute(&cli).await {
            Err(error) => Err(error),
            Ok(value) => {
                let job = value.get("job_id").cloned();
                let writer = tokio::task::spawn_blocking(move || output::emit(&value, &cli));
                tokio::select! {
                    result = writer => result.unwrap_or_else(|_| Err(Error::new("io", "Output writer failed"))),
                    _ = interrupt::signal() => {
                        let mut error = Error::new("interrupted", "Output interrupted");
                        if let Some(job) = job { error.details = serde_json::json!({"job_id": job}); error.hint = Some("The Splunk job is still available; retrieve it with jobs results or jobs export.".into()); }
                        let code = error.exit_code();
                        fail(error, json_output);
                        // The writer can be blocked on a downstream pipe. Runtime shutdown
                        // would wait for that blocking thread; no remote work remains here.
                        std::process::exit(i32::from(code));
                    }
                }
            }
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(error, json_output),
    }
}

fn fail(error: Error, json_output: bool) -> ExitCode {
    if json_output {
        output::diagnostic_json(&error.envelope());
    } else {
        if let Some(checks) = error.details["checks"].as_array() {
            for check in checks {
                crate::output::diagnostic(format_args!(
                    "[{}] {}: {}",
                    output::terminal(check["status"].as_str().unwrap_or("failed")),
                    output::terminal(check["check"].as_str().unwrap_or("check")),
                    output::terminal(check["message"].as_str().unwrap_or(""))
                ));
            }
        }
        crate::output::diagnostic(format_args!(
            "Error: {}",
            output::terminal_lines(
                error
                    .message
                    .strip_prefix("error: ")
                    .unwrap_or(&error.message)
            )
        ));
        if let Some(hint) = &error.hint {
            crate::output::diagnostic(format_args!("{}", output::terminal_lines(hint)));
        }
    }
    ExitCode::from(error.exit_code())
}
