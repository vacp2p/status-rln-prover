use std::net::IpAddr;
// third-party
use alloy::primitives::Address;
use clap::Parser;
use url::Url;

#[derive(Debug, Clone, Parser)]
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
        long = "ws_rpc_url",
        help = "Websocket rpc url (e.g. wss://eth-mainnet.g.alchemy.com/v2/your-api-key)"
    )]
    pub(crate) ws_rpc_url: Url,
    #[arg(short = 'k', long = "ksc", help = "Karma smart contract address")]
    pub(crate) ksc_address: Address,
    #[arg(short = 'r', long = "rlnsc", help = "RLN smart contract address")]
    pub(crate) rlnsc_address: Address,
}
