use alloy::{
    hex,
    network::Ethereum,
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
    transports::ws::WsConnect,
};
use smart_contract::AlloyWsProvider;
use std::{error::Error, str::FromStr};
use url::Url;

const PRIVATE_KEY: &str = "";

sol! {
    #[sol(rpc)]
    contract RLNSC {
        event MemberRegistered(uint256 identityCommitment, uint256 index);
        event MemberSlashed(uint256 index, address slasher);
        struct User {
            address userAddress;
            uint256 index;
        }
        function members(uint256 commitment) public view returns (User memory);
        function SET_SIZE() public view returns (uint256);
        function identityCommitmentIndex() public view returns (uint256);
        function karma() public view returns (address);
        function SLASHER_ROLE() public view returns (bytes32);
        function REGISTER_ROLE() public view returns (bytes32);
        function hasRole(bytes32 role, address account) public view returns (bool);
        function getRoleAdmin(bytes32 role) public view returns (bytes32);
        function grantRole(bytes32 role, address account) public;
        function revokeRole(bytes32 role, address account) public;
        function renounceRole(bytes32 role, address account) public;
        function register(uint256 identityCommitment, address user) external;
        function slash(uint256 identityCommitment) external;
        function initialize(address _owner, address _slasher, address _register, uint256 depth, address _token) public;
    }
}

impl RLNSC::RLNSCInstance<AlloyWsProvider> {
    pub async fn try_new_with_signer(
        rpc_url: Url,
        address: Address,
        private_key: &str,
    ) -> Result<
        RLNSC::RLNSCInstance<impl alloy::providers::Provider>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let ws_connect = WsConnect::new(rpc_url.as_str());
        let signer = PrivateKeySigner::from_str(private_key)?;
        let provider = ProviderBuilder::new()
            .network::<Ethereum>()
            .wallet(signer)
            .connect_ws(ws_connect)
            .await?;
        Ok(RLNSC::new(address, provider))
    }
}

#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub identity_commitment: U256,
    pub user_address: Address,
    pub index: U256,
}

#[derive(Debug, Clone)]
pub struct RegistryInfo {
    pub set_size: U256,
    pub current_index: U256,
    pub karma_address: Address,
    pub is_full: bool,
    pub available_slots: U256,
}

#[derive(Debug, Clone)]
pub enum MemberStatus {
    Registered(MemberInfo),
    NotRegistered,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("Testing KarmaRLN Contract Interaction");

    let ws_rpc_url = "wss://public.sepolia.rpc.status.network/ws";
    let contract_address = "0xc98994691E96D2f4CA2a718Bc8FDF30bd21d1c59";
    let test_identity_commitment = U256::from(0);
    let test_user_address = Address::from_str("0x360a45F70De193090A1b13dA8393A02F9119aeCd")?;

    println!("Connecting to RPC: {}", ws_rpc_url);

    let contract_addr = Address::from_str(contract_address)
        .map_err(|e| format!("Invalid contract address: {}", e))?;

    let url = Url::parse(ws_rpc_url)?;

    // Connect to KarmaRLN contract with signer
    let rln_contract = if !PRIVATE_KEY.is_empty() {
        match RLNSC::RLNSCInstance::try_new_with_signer(url, contract_addr, PRIVATE_KEY).await {
            Ok(contract) => {
                println!(
                    "Successfully connected to RLN contract with signer at {}",
                    contract_addr
                );
                contract
            }
            Err(e) => {
                eprintln!("Failed to connect to contract with signer: {}", e);
                return Err(e);
            }
        }
    } else {
        return Err("Private key not provided".into());
    };

    println!("\nTesting RLN Contract Functions:");
    println!("=====================================");

    // Test 1: Get registry information
    match (
        rln_contract.SET_SIZE().call().await,
        rln_contract.identityCommitmentIndex().call().await,
        rln_contract.karma().call().await,
    ) {
        (Ok(set_size), Ok(current_index), Ok(karma_address)) => {
            let is_full = current_index >= set_size;
            let available_slots = if is_full {
                U256::ZERO
            } else {
                set_size - current_index
            };

            println!("Registry Info:");
            println!("   Set size: {}", set_size);
            println!("   Current index: {}", current_index);
            println!("   Karma address: {}", karma_address);
            println!("   Is full: {}", is_full);
            println!("   Available slots: {}", available_slots);
        }
        _ => {
            eprintln!("Failed to get registry info");
        }
    }

    // Test 2: Check if specific member is registered
    match rln_contract.members(test_identity_commitment).call().await {
        Ok(member) => {
            if member.userAddress != Address::ZERO {
                println!("Member {} is registered:", test_identity_commitment);
                println!("   User address: {}", member.userAddress);
                println!("   Index: {}", member.index);
            } else {
                println!("Member {} is not registered", test_identity_commitment);
            }
        }
        Err(e) => {
            eprintln!("Failed to check member status: {}", e);
        }
    }

    // Test 3: Get role information
    match (
        rln_contract.SLASHER_ROLE().call().await,
        rln_contract.REGISTER_ROLE().call().await,
    ) {
        (Ok(slasher_role), Ok(register_role)) => {
            println!("Role Information:");
            println!("   Slasher role: 0x{}", hex::encode(slasher_role));
            println!("   Register role: 0x{}", hex::encode(register_role));
        }
        _ => {
            eprintln!("Failed to get roles");
        }
    }

    // Test 4: Check permissions for test user
    match (
        rln_contract.REGISTER_ROLE().call().await,
        rln_contract.SLASHER_ROLE().call().await,
    ) {
        (Ok(register_role), Ok(slasher_role)) => {
            match rln_contract
                .hasRole(register_role, test_user_address)
                .call()
                .await
            {
                Ok(can_register) => {
                    println!(
                        "Account {} can register: {}",
                        test_user_address, can_register
                    );
                }
                Err(e) => eprintln!("Failed to check register permission: {}", e),
            }

            match rln_contract
                .hasRole(slasher_role, test_user_address)
                .call()
                .await
            {
                Ok(can_slash) => {
                    println!("Account {} can slash: {}", test_user_address, can_slash);
                }
                Err(e) => eprintln!("Failed to check slash permission: {}", e),
            }
        }
        _ => {
            eprintln!("Failed to get roles for permission check");
        }
    }

    // Test 5: Check if new member already exists before registering
    match rln_contract.members(test_identity_commitment).call().await {
        Ok(member) => {
            if member.userAddress == Address::ZERO {
                println!("Attempting to register new member...");
                println!("   Identity commitment: {}", test_identity_commitment);
                println!("   User address: {}", test_user_address);

                // Test 6: Register new member
                match rln_contract
                    .register(test_identity_commitment, test_user_address)
                    .send()
                    .await
                {
                    Ok(pending_tx) => {
                        match pending_tx.get_receipt().await {
                            Ok(receipt) => {
                                if receipt.status() {
                                    println!("Registration successful!");
                                    println!(
                                        "   Transaction hash: 0x{}",
                                        hex::encode(receipt.transaction_hash)
                                    );
                                    println!("   Block number: {:?}", receipt.block_number);
                                    println!("   Gas used: {}", receipt.gas_used);

                                    // Test 7: Verify registration was successful
                                    match rln_contract
                                        .members(test_identity_commitment)
                                        .call()
                                        .await
                                    {
                                        Ok(verified_member) => {
                                            if verified_member.userAddress != Address::ZERO {
                                                println!("Registration verified:");
                                                println!(
                                                    "   User: {}",
                                                    verified_member.userAddress
                                                );
                                                println!("   Index: {}", verified_member.index);
                                            } else {
                                                println!("Registration not found in verification");
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to verify registration: {}", e);
                                        }
                                    }
                                } else {
                                    println!("Registration transaction failed");
                                }
                            }
                            Err(e) => eprintln!("Failed to get receipt: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Failed to send registration transaction: {}", e),
                }
            } else {
                println!("Member {} already registered:", test_identity_commitment);
                println!("   User: {}", member.userAddress);
                println!("   Index: {}", member.index);
            }
        }
        Err(e) => {
            eprintln!("Failed to check if member exists: {}", e);
        }
    }

    // Test 8: Slash a member
    match rln_contract.members(test_identity_commitment).call().await {
        Ok(member) => {
            if member.userAddress != Address::ZERO {
                println!("Attempting to slash member {}:", test_identity_commitment);
                println!("   User: {}", member.userAddress);
                println!("   Index: {}", member.index);
                match rln_contract.slash(test_identity_commitment).send().await {
                    Ok(pending_tx) => match pending_tx.get_receipt().await {
                        Ok(receipt) => {
                            if receipt.status() {
                                println!("Slashing successful!");
                                println!(
                                    "   Transaction hash: 0x{}",
                                    hex::encode(receipt.transaction_hash)
                                );
                                println!("   Block number: {:?}", receipt.block_number);
                                println!("   Gas used: {}", receipt.gas_used);
                            } else {
                                println!("Slashing transaction failed");
                            }
                        }
                        Err(e) => eprintln!("Failed to get receipt: {}", e),
                    },
                    Err(e) => eprintln!("Failed to send slashing transaction: {}", e),
                }
            } else {
                println!(
                    "Member {} is not registered, cannot slash",
                    test_identity_commitment
                );
            }
        }
        Err(e) => {
            eprintln!("Failed to check member for slashing: {}", e);
        }
    }

    println!("\nTesting completed!");
    Ok(())
}
