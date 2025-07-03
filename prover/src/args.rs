use std::net::IpAddr;
use std::path::PathBuf;
// third-party
use alloy::primitives::Address;
use clap::Parser;
use clap_config::ClapConfig;
use clap::ArgAction::SetTrue;
use clap::ArgGroup;
use url::Url;

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
    #[arg(long = "mock-sc", help = "Test only - mock smart contracts", action)]
    pub(crate) mock_sc: Option<bool>,
    #[arg(
        long = "mock-user",
        help = "Test only - register user (requite --mock-sc to be enabled)",
        action
    )]
    pub(crate) mock_user: Option<PathBuf>,

    #[arg(
        long = "config",
        help = "Config file path",
        default_value = "./config.toml",
    )]
    pub(crate) config_path: PathBuf,
    #[arg(
        long = "no-config",
        help = "Dont read a config file",
        default_missing_value = "false",
        action = SetTrue,
    )]
    pub(crate) no_config: Option<bool>,
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
            ws_rpc_url: None,
            db_path: None,
            merkle_tree_path: None,
            ksc_address: None,
            rlnsc_address: None,
            tsc_address: None,
            mock_sc: Some(true),
            mock_user: None,
            config_path: None,
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

