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
    contract KarmaTiersSC {
        event TiersUpdated();

        error InvalidTxAmount();
        error EmptyTierName();
        error EmptyTiersArray();
        error TierNotFound();
        error TierNameTooLong(uint256 nameLength, uint256 maxLength);
        error NonContiguousTiers(uint8 index, uint256 expectedMinKarma, uint256 actualMinKarma);
        error InvalidTierRange(uint256 minKarma, uint256 maxKarma);

        struct Tier {
            uint256 minKarma;
            uint256 maxKarma;
            string name;
            uint32 txPerEpoch;
        }

        uint256 public constant MAX_TIER_NAME_LENGTH = 32;
        Tier[] public tiers;

        function updateTiers(Tier[] calldata newTiers) external;
        function getTierIdByKarmaBalance(uint256 karmaBalance) external view returns (uint8);
        function getTierCount() external view returns (uint256 count);
        function getTierById(uint8 tierId) external view returns (Tier memory tier);
    }
}

impl KarmaTiersSC::KarmaTiersSCInstance<AlloyWsProvider> {
    pub async fn try_new_with_signer(
        rpc_url: Url,
        address: Address,
        private_key: &str,
    ) -> Result<
        KarmaTiersSC::KarmaTiersSCInstance<impl alloy::providers::Provider>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let ws_connect = WsConnect::new(rpc_url.as_str());
        let signer = PrivateKeySigner::from_str(private_key)?;
        let provider = ProviderBuilder::new()
            .network::<Ethereum>()
            .wallet(signer)
            .connect_ws(ws_connect)
            .await?;
        Ok(KarmaTiersSC::new(address, provider))
    }
}

#[derive(Debug, Clone)]
pub struct TierInfo {
    pub min_karma: U256,
    pub max_karma: U256,
    pub name: String,
    pub tx_per_epoch: u32,
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub tier_count: U256,
    pub max_tier_name_length: U256,
    pub is_empty: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("Testing KarmaTiers Contract Interaction");

    let ws_rpc_url = "wss://public.sepolia.rpc.status.network/ws";
    let contract_address = "0x011b9de308BE357BbF24EfB387a270a14A04E5d2";

    println!("Connecting to RPC: {}", ws_rpc_url);

    let contract_addr = Address::from_str(contract_address)
        .map_err(|e| format!("Invalid contract address: {}", e))?;

    let url = Url::parse(ws_rpc_url)?;

    // Connect to KarmaTiers contract
    let karma_tiers_contract = match KarmaTiersSC::KarmaTiersSCInstance::try_new_with_signer(
        url.clone(),
        contract_addr,
        PRIVATE_KEY,
    )
    .await
    {
        Ok(contract) => {
            println!(
                "Successfully connected to KarmaTiers contract for reading at {}",
                contract_addr
            );
            contract
        }
        Err(e) => {
            eprintln!("Failed to connect to contract for reading: {}", e);
            return Err(e);
        }
    };

    println!("\nChecking Current Contract State:");
    println!("=====================================");

    // Test 1: Get current tier count and contract info
    let contract_info = match (
        karma_tiers_contract.getTierCount().call().await,
        karma_tiers_contract.MAX_TIER_NAME_LENGTH().call().await,
    ) {
        (Ok(tier_count), Ok(max_length)) => {
            let is_empty = tier_count == U256::ZERO;
            println!("Current tier count: {}", tier_count);
            println!("Maximum tier name length: {}", max_length);
            println!("Contract is empty: {}", is_empty);

            ContractInfo {
                tier_count,
                max_tier_name_length: max_length,
                is_empty,
            }
        }
        _ => {
            eprintln!("Failed to get contract info");
            return Err("Failed to get contract info".into());
        }
    };

    let mut curren_tier_count_u8 = 0;
    if !contract_info.is_empty {
        println!("\nCurrent tiers in contract:");
        println!("============================");

        curren_tier_count_u8 = contract_info.tier_count.as_limbs()[0] as u8;

        for i in 0..curren_tier_count_u8 {
            match karma_tiers_contract.getTierById(i).call().await {
                Ok(tier) => {
                    println!(
                        "Tier {}: {} ({} - {}) - {} tx/epoch",
                        i, tier.name, tier.minKarma, tier.maxKarma, tier.txPerEpoch
                    );
                }
                Err(e) => {
                    eprintln!("Failed to get tier {}: {}", i, e);
                }
            }
        }
    }

    // Test 3: Create tiers
    let test_tiers = vec![
        KarmaTiersSC::Tier {
            minKarma: U256::from(0),
            maxKarma: U256::from(10),
            name: "NoTier".to_string(),
            txPerEpoch: 6,
        },
        KarmaTiersSC::Tier {
            minKarma: U256::from(10),
            maxKarma: U256::from(49),
            name: "Basic".to_string(),
            txPerEpoch: 6,
        },
        KarmaTiersSC::Tier {
            minKarma: U256::from(50),
            maxKarma: U256::from(99),
            name: "Active".to_string(),
            txPerEpoch: 120,
        },
        KarmaTiersSC::Tier {
            minKarma: U256::from(100),
            maxKarma: U256::from(499),
            name: "Regular".to_string(),
            txPerEpoch: 720,
        },
        KarmaTiersSC::Tier {
            minKarma: U256::from(500),
            maxKarma: U256::from(999),
            name: "Power User".to_string(),
            txPerEpoch: 86400,
        },
        KarmaTiersSC::Tier {
            minKarma: U256::from(1000),
            maxKarma: U256::from(4999),
            name: "S-Tier".to_string(),
            txPerEpoch: 432000,
        },
    ];

    println!(
        "Attempting to update tiers with {} new tiers:",
        test_tiers.len()
    );
    for (i, tier) in test_tiers.iter().enumerate() {
        println!(
            "  Tier {}: {} ({} - {}) - {} tx/epoch",
            i, tier.name, tier.minKarma, tier.maxKarma, tier.txPerEpoch
        );
    }

    if !PRIVATE_KEY.is_empty() && curren_tier_count_u8 == 0 {
        match karma_tiers_contract.updateTiers(test_tiers).send().await {
            Ok(pending_tx) => match pending_tx.get_receipt().await {
                Ok(receipt) => {
                    if receipt.status() {
                        println!("Tier update successful!");
                        println!(
                            "   Transaction hash: 0x{}",
                            hex::encode(receipt.transaction_hash)
                        );
                        println!("   Block number: {:?}", receipt.block_number);
                        println!("   Gas used: {}", receipt.gas_used);
                    } else {
                        println!("Tier update transaction failed");
                    }
                }
                Err(e) => eprintln!("Failed to get receipt: {}", e),
            },
            Err(e) => eprintln!("Failed to send tier update transaction: {}", e),
        }
    }

    // Test 4: Verify the update by reading the contract again
    println!("\nVerifying tier update:");
    println!("=======================");

    match karma_tiers_contract.getTierCount().call().await {
        Ok(new_tier_count) => {
            println!("New tier count: {}", new_tier_count);

            if new_tier_count > U256::ZERO {
                println!("\nUpdated tiers in contract:");
                println!("============================");

                let tier_count_u8 = new_tier_count.as_limbs()[0] as u8;

                for i in 0..tier_count_u8 {
                    match karma_tiers_contract.getTierById(i).call().await {
                        Ok(tier) => {
                            println!(
                                "Tier {}: {} ({} - {}) - {} tx/epoch",
                                i, tier.name, tier.minKarma, tier.maxKarma, tier.txPerEpoch
                            );
                        }
                        Err(e) => {
                            eprintln!("Failed to get tier {}: {}", i, e);
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to get new tier count: {}", e);
        }
    }

    // Test 7: Test tier lookup by karma balance (updated for new tier ranges)
    println!("\nTesting tier lookup by karma balance:");
    println!("======================================");

    let test_karma_balances = vec![
        U256::from(0),    // Below all tiers
        U256::from(10),   // Basic tier (min)
        U256::from(25),   // Basic tier (mid)
        U256::from(49),   // Basic tier (max)
        U256::from(50),   // Active tier (min)
        U256::from(75),   // Active tier (mid)
        U256::from(99),   // Active tier (max)
        U256::from(100),  // Regular tier (min)
        U256::from(250),  // Regular tier (mid)
        U256::from(499),  // Regular tier (max)
        U256::from(500),  // Power User tier (min)
        U256::from(750),  // Power User tier (mid)
        U256::from(999),  // Power User tier (max)
        U256::from(1000), // S-Tier (min)
        U256::from(2500), // S-Tier (mid)
        U256::from(4999), // S-Tier (max)
        U256::from(5000), // Above all tiers
    ];

    for karma_balance in test_karma_balances {
        match karma_tiers_contract
            .getTierIdByKarmaBalance(karma_balance)
            .call()
            .await
        {
            Ok(tier_id) => {
                println!("Karma balance {} -> Tier ID: {}", karma_balance, tier_id);

                match karma_tiers_contract.getTierById(tier_id).call().await {
                    Ok(tier) => {
                        println!(
                            "  Tier details: {} ({} - {}) - {} tx/epoch",
                            tier.name, tier.minKarma, tier.maxKarma, tier.txPerEpoch
                        );
                    }
                    Err(e) => {
                        eprintln!("  Failed to get tier details: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("Karma balance {} -> Error: {}", karma_balance, e);
            }
        }
    }

    // Test 8: Test with invalid tier ID
    println!("\nTesting with invalid tier ID:");
    println!("=====================");

    let invalid_tier_id = 255u8;
    match karma_tiers_contract
        .getTierById(invalid_tier_id)
        .call()
        .await
    {
        Ok(_tier) => {
            println!(
                "Unexpectedly found a tier for invalid tier ID {}",
                invalid_tier_id
            );
        }
        Err(e) => {
            println!(
                "Expected error for invalid tier ID {}: {}",
                invalid_tier_id, e
            );
        }
    }

    println!("\nTesting completed!");
    Ok(())
}
