// std
use std::path::PathBuf;
// third-party
use clap::CommandFactory;
use tracing::level_filters::LevelFilter;
use tracing::{
    debug,
    // error,
    // info
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
// internal
use prover::{AppArgs, AppArgsConfig, metrics::init_metrics, run_prover};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // debug!("Args: {:?}", std::env::args());

    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    // let app_args = AppArgs::parse();
    let app_args = <AppArgs as CommandFactory>::command().get_matches();
    debug!("Arguments: {:?}", app_args);

    let app_ars_config = if !app_args.get_flag("no_config") {
        // Unwrap safe - default value provided
        let config_path = app_args.get_one::<PathBuf>("config_path").unwrap();
        debug!("Reading config path: {:?}...", config_path);
        let config_str = std::fs::read_to_string(config_path)?;
        let config: AppArgsConfig = toml::from_str(config_str.as_str())?;
        debug!("Config: {:?}", config);
        config
    } else {
        AppArgsConfig::default()
    };

    // Merge command line args & config
    let app_args = AppArgs::from_merged(app_args, Some(app_ars_config));
    debug!("Arguments (merged with config): {:?}", app_args);

    // Application cli arguments checks
    if app_args.ws_rpc_url.is_some() {
        if app_args.ksc_address.is_none()
            || app_args.ksc_address.is_none()
            || app_args.tsc_address.is_none()
        {
            return Err("Please provide smart contract addresses".into());
        }
    } else if app_args.mock_sc.is_none() {
        return Err("Please provide rpc url (--ws-rpc-url) or mock (--mock-sc)".into());
    }

    init_metrics(app_args.metrics_ip, &app_args.metrics_port);

    run_prover(app_args).await
}
