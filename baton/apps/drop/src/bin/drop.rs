//! `drop`: runs the drop service until SIGINT or SIGTERM.
//!
//! `drop --config FILE` or `drop --realm NAME [--listen ADDR] [--data-dir DIR]
//! [--tokens-file FILE] [--open]`; flags override the file.

use std::process::ExitCode;

use baton_drop_service::{Config, start};
use tracing::{error, info};

const USAGE: &str = "usage: drop --config FILE | drop --realm NAME [--listen ADDR] [--data-dir DIR] [--tokens-file FILE] [--open]";

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
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let config = match Config::from_args(args) {
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
        let running = match start(&config, baton_drop::system_clock()).await {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "cannot start");
                return ExitCode::FAILURE;
            }
        };
        info!(listen = %running.addr, tls = config.tls.is_some(), "drop service running");
        signal().await;
        info!("shutting down");
        running.stop().await;
        ExitCode::SUCCESS
    })
}
