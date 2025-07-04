use std::net::IpAddr;
use std::path::PathBuf;
// third-party
use alloy::primitives::Address;
use clap::Parser;
use clap_config::ClapConfig;
use clap::ArgAction::SetTrue;
use url::Url;

/// Broadcast channel size
///
/// A Bounded tokio broadcast channel is used to send RLN proof to the Verifier
/// Warning: There should be only one client receiving the proof, but if there are many, a too
///          low value could stall all the proof services
const ARGS_DEFAULT_BROADCAST_CHANNEL_SIZE: &str = "100";
/// Number of proof services (tasks)
///
/// This service is waiting for new tx to generate the RLN proof. Increase this value
/// if you need to process more Transactions in //.
const ARGS_DEFAULT_PROOF_SERVICE_COUNT: &str = "8";
/// Transaction channel size
///
/// Used by grpc service to send the transaction to one of the proof services. A too low value could stall
/// the grpc service when it receives a transaction.
const ARGS_DEFAULT_TRANSACTION_CHANNEL_SIZE: &str = "100";
/// Proof sender channel size
///
/// Used by grpc service to send the generated proof to the Verifier. A too low value could stall
/// the broadcast channel.
const ARGS_DEFAULT_PROOF_SENDER_CHANNEL_SIZE: &str = "100";

#[derive(Debug, Clone, Parser, ClapConfig)]
#[command(about = "RLN prover service", long_about = None)]
pub struct AppArgs {
    #[arg(short = 'i', long = "ip", default_value = "::1", help = "Service ip")]
    pub(crate) ip: IpAddr,
    #[arg(
        short = 'p',
        long = "port",
        default_value = "50051",
        help = "Service port"
    )]
    pub(crate) port: u16,
    #[arg(
        short = 'u',
        long = "ws-rpc-url",
        help = "Websocket rpc url (e.g. wss://eth-mainnet.g.alchemy.com/v2/your-api-key)"
    )]
    pub(crate) ws_rpc_url: Option<Url>,
    #[arg(long = "db", help = "Db path", default_value = "./storage/db")]
    pub(crate) db_path: PathBuf,
    #[arg(
        long = "tree",
        help = "Merkle tree path",
        default_value = "./storage/tree"
    )]
    pub(crate) merkle_tree_path: PathBuf,
    #[arg(short = 'k', long = "ksc", help = "Karma smart contract address")]
    pub(crate) ksc_address: Option<Address>,
    #[arg(short = 'r', long = "rlnsc", help = "RLN smart contract address")]
    pub(crate) rlnsc_address: Option<Address>,
    #[arg(short = 't', long = "tsc", help = "KarmaTiers smart contract address")]
    pub(crate) tsc_address: Option<Address>,
    #[arg(
        help_heading = "mock",
        long = "mock-sc", help = "Test only - mock smart contracts", action)]
    pub(crate) mock_sc: Option<bool>,
    #[arg(
        help_heading = "mock",
        long = "mock-user",
        help = "Test only - register user (requite --mock-sc to be enabled)",
        action
    )]
    pub(crate) mock_user: Option<PathBuf>,
    #[arg(
        short = 'c',
        long = "config",
        help = "Config file path",
        default_value = "./config.toml",
        help_heading = "config"
    )]
    pub(crate) config_path: PathBuf,
    #[arg(
        long = "no-config",
        help = "Dont read a config file",
        default_missing_value = "false",
        action = SetTrue,
        help_heading = "config"
    )]
    pub(crate) no_config: Option<bool>,
    // Hidden option - expect user set it via a config file
    #[arg(
        long = "broadcast-channel-size",
        help = "Broadcast bounded channel size",
        default_value = ARGS_DEFAULT_BROADCAST_CHANNEL_SIZE,
        hide = true,
    )] // see const doc for more info
    pub(crate) broadcast_channel_size: usize,
    #[arg(
        long = "proof-service",
        help = "Number of proof service (tasks) to generate proof",
        default_value = ARGS_DEFAULT_PROOF_SERVICE_COUNT,
        hide = true,
    )] // see const doc for more info
    pub(crate) proof_service_count: u16,
    #[arg(
        long = "transaction-channel-size",
        help = "Proof bounded channel size",
        default_value = ARGS_DEFAULT_TRANSACTION_CHANNEL_SIZE,
        hide = true,
    )] // see const doc for more info
    pub(crate) transaction_channel_size: usize,
    #[arg(
        long = "proof-sender-channel-size",
        help = "Proof bounded sender channel size",
        default_value = ARGS_DEFAULT_PROOF_SENDER_CHANNEL_SIZE,
        hide = true,
    )] // see const doc for more info
    pub(crate) proof_sender_channel_size: usize,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use super::*;

    #[test]
    fn test_args_config_merge() {

        let config_port = 42942;
        let config = AppArgsConfig {
            ip: None,
            port: Some(config_port),
            mock_sc: Some(true),
            ..Default::default()
        };

        {
            let args_1 = vec!["program", "--ip", "127.0.0.1", "--port", "50051"];
            let cmd = <AppArgs as CommandFactory>::command();
            let app_args = cmd.try_get_matches_from(args_1).unwrap(); //  .get_matches();
            let app_args_2 = AppArgs::from_merged(app_args, Some(config.clone()));
            assert_eq!(app_args_2.port, 50051);
        }
        {
            let args_2 = vec!["program", "--ip", "127.0.0.1"];
            let cmd = <AppArgs as CommandFactory>::command();
            let app_args = cmd.try_get_matches_from(args_2).unwrap(); //  .get_matches();
            let app_args_2 = AppArgs::from_merged(app_args, Some(config));
            assert_eq!(app_args_2.port, config_port);
        }
    }
}

