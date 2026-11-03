use clap::{CommandFactory, Parser, error::ErrorKind};
use splunk_cli::{
    Error,
    cli::{Cli, Command, Format},
    output, schema, workflows,
};
use std::{io::Write, process::ExitCode};

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
                    Some("text") => format = Format::Text,
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
            std::io::stdout()
                .lock()
                .write_all(&bytes)
                .map_err(Error::from)
        }
        _ => workflows::execute(&cli)
            .await
            .and_then(|value| output::write(&value, json_output)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(error, json_output),
    }
}

fn fail(error: Error, json_output: bool) -> ExitCode {
    if json_output {
        eprintln!("{}", error.envelope());
    } else {
        eprintln!("Error: {}", output::terminal(&error.to_string()));
        if let Some(hint) = &error.hint {
            eprintln!("{}", output::terminal(hint));
        }
    }
    ExitCode::from(error.exit_code())
}
