//! The `rowboat` binary.

use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = rowboat::cli::Cli::parse();
    match rowboat::cli::run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rowboat: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
