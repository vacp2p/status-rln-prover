use std::net::IpAddr;

use clap::Parser;

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
        short = 'r',
        long = "rpc_url",
        help = "Websocket rpc url (e.g. wss://eth-mainnet.g.alchemy.com/v2/your-api-key)"
    )]
    pub(crate) rpc_url: String,
}
