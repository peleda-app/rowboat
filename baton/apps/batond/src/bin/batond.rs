//! `batond --config FILE`: runs the blind server until SIGINT or SIGTERM.

use std::path::PathBuf;
use std::process::ExitCode;

use batond::{Clocks, Config, start};
use tracing::{error, info};

const USAGE: &str = "usage: batond --config FILE";

async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_ansi(false)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.as_slice() {
        [flag, path] if flag == "--config" => PathBuf::from(path),
        [flag] if flag == "--help" || flag == "-h" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let config = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let running = match start(&config, Clocks::system()).await {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "cannot start");
                return ExitCode::FAILURE;
            }
        };
        info!(
            node = %running.node.node_id(),
            groups = config.groups.len(),
            drop = running.drop_addr.is_some(),
            "batond running"
        );
        signal().await;
        info!("shutting down");
        running.stop().await;
        ExitCode::SUCCESS
    })
}
