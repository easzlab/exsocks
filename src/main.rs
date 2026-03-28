use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tracing::{error, info};

use exsocks::config::AppConfig;
use exsocks::error::SocksError;
use exsocks::server;

fn build_version_string() -> &'static str {
    Box::leak(
        format!(
            "{}\nGit Commit: {}\nBuild Time: {}\nRust: {}",
            env!("CARGO_PKG_VERSION"),
            env!("GIT_COMMIT"),
            env!("BUILD_TIME"),
            env!("RUSTC_VERSION_INFO"),
        )
        .into_boxed_str(),
    )
}

#[derive(Parser, Debug)]
#[command(name = "exsocks")]
#[command(about = "High-performance SOCKS5 proxy server")]
#[command(version = build_version_string())]
struct Args {
    /// Bind address
    #[arg(short, long)]
    bind: Option<SocketAddr>,

    /// Max concurrent connections
    #[arg(short, long)]
    max_connections: Option<usize>,

    /// Log directory
    #[arg(long)]
    log_dir: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long)]
    log_level: Option<String>,

    /// Configuration file path
    #[arg(short, long)]
    config: Option<PathBuf>,
}

fn init_logging(log_dir: &PathBuf, log_level: &str) -> tracing_appender::non_blocking::WorkerGuard {
    std::fs::create_dir_all(log_dir).expect("Failed to create log directory");

    let file_appender = tracing_appender::rolling::daily(log_dir, "exsocks.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();

    guard
}

#[tokio::main]
async fn main() -> Result<(), SocksError> {
    let args = Args::parse();

    let mut config =
        AppConfig::load(args.config.as_ref()).map_err(|e| SocksError::Config(e.to_string()))?;

    config.apply_cli_args(
        args.bind,
        args.max_connections,
        args.log_dir.clone(),
        args.log_level.clone(),
        None,
    );

    let _guard = init_logging(&config.log_dir, &config.log_level);

    info!("Starting exsocks server");
    info!("Configuration: {:?}", config);

    if let Err(e) = server::run(config).await {
        error!("Server error: {}", e);
        return Err(e);
    }

    Ok(())
}
