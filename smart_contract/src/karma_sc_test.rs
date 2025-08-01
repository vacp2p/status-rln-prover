use alloy::{
    network::Ethereum,
    primitives::{Address, U256},
    providers::ProviderBuilder,
    sol,
    transports::ws::WsConnect,
};
use std::{error::Error, str::FromStr};
use url::Url;

use smart_contract::AlloyWsProvider;

sol! {
    #[sol(rpc)]
    contract KarmaSC {
        event Transfer(address indexed from, address indexed to, uint256 value);
        event AccountSlashed(address indexed account, uint256 amount);
        function balanceOf(address account) public view returns (uint256);
        function slashedAmountOf(address account) public view returns (uint256);
        function totalSupply() public view returns (uint256);
        function externalSupply() public view returns (uint256);
        function slashPercentage() public view returns (uint256);
        function calculateSlashAmount(uint256 value) public view returns (uint256);
        function getRewardDistributors() external view returns (address[] memory);
        function totalDistributorAllocation() public view returns (uint256);
        function totalSlashAmount() public view returns (uint256);
    }
}

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

impl KarmaSC::KarmaSCInstance<AlloyWsProvider> {
    pub async fn try_new(
        rpc_url: Url,
        address: Address,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let ws_connect = WsConnect::new(rpc_url.as_str());

        let provider = ProviderBuilder::new()
            .network::<Ethereum>()
            .connect_ws(ws_connect)
            .await?;

        Ok(KarmaSC::new(address, provider))
    }
}

impl KarmaTiersSC::KarmaTiersSCInstance<AlloyWsProvider> {
    pub async fn try_new(
        rpc_url: Url,
        address: Address,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let ws_connect = WsConnect::new(rpc_url.as_str());

        let provider = ProviderBuilder::new()
            .network::<Ethereum>()
            .connect_ws(ws_connect)
            .await?;

        Ok(KarmaTiersSC::new(address, provider))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("Testing Karma Contract Interaction with Signed Types");

    let rpc_url = "wss://public.sepolia.rpc.status.network/ws";
    let karma_contract_address = "0x9ADD5A2F68d0d95F74C751a2081EFF57Ff1C836F";
    let karma_tiers_contract_address = "0x011b9de308BE357BbF24EfB387a270a14A04E5d2";
    let test_account = "0x360a45F70De193090A1b13dA8393A02F9119aeCd";

    println!("Connecting to RPC: {}", rpc_url);

    let karma_contract_addr = Address::from_str(karma_contract_address)
        .map_err(|e| format!("Invalid karma contract address: {}", e))?;
    let karma_tiers_contract_addr = Address::from_str(karma_tiers_contract_address)
        .map_err(|e| format!("Invalid karma tiers contract address: {}", e))?;
    let account_addr =
        Address::from_str(test_account).map_err(|e| format!("Invalid account address: {}", e))?;

    let url = Url::parse(rpc_url)?;

    // Connect to Karma contract
    let karma_contract =
        match KarmaSC::KarmaSCInstance::try_new(url.clone(), karma_contract_addr).await {
            Ok(contract) => {
                println!(
                    "Successfully connected to Karma contract at {}",
                    karma_contract_addr
                );
                contract
            }
            Err(e) => {
                eprintln!("Failed to connect to karma contract: {}", e);
                return Err(e);
            }
        };

    // Connect to KarmaTiers contract
    let karma_tiers_contract =
        match KarmaTiersSC::KarmaTiersSCInstance::try_new(url, karma_tiers_contract_addr).await {
            Ok(contract) => {
                println!(
                    "Successfully connected to KarmaTiers contract at {}",
                    karma_tiers_contract_addr
                );
                contract
            }
            Err(e) => {
                eprintln!("Failed to connect to karma tiers contract: {}", e);
                return Err(e);
            }
        };

    println!("\nTesting Contract Functions:");
    println!("=====================================");

    // Test Karma Contract Functions with signed types
    println!("\n--- Karma Contract Tests ---");

    // Test 1: Get account balance
    match karma_contract.balanceOf(account_addr).call().await {
        Ok(balance) => {
            let balance_i64: i64 = balance.try_into().unwrap_or(-1);
            println!(
                "Account {} balance: {} KARMA (signed: {})",
                account_addr, balance, balance_i64
            );
        }
        Err(e) => {
            eprintln!("Failed to get balance: {}", e);
        }
    }

    // Test 2: Get slashed amount
    match karma_contract.slashedAmountOf(account_addr).call().await {
        Ok(result) => {
            let slashed_i64: i64 = result.try_into().unwrap_or(-1);
            println!(
                "Account {} slashed amount: {} (signed: {})",
                account_addr, result, slashed_i64
            );
        }
        Err(e) => {
            eprintln!("Failed to get slashed amount: {}", e);
        }
    }

    // Test 3: Get total supply
    match karma_contract.totalSupply().call().await {
        Ok(result) => {
            let total_supply_i64: i64 = result.try_into().unwrap_or(-1);
            println!(
                "Total supply: {} KARMA (signed: {})",
                result, total_supply_i64
            );
        }
        Err(e) => {
            eprintln!("Failed to get total supply: {}", e);
        }
    }

    // Test 4: Get external supply
    match karma_contract.externalSupply().call().await {
        Ok(result) => {
            let external_supply_i64: i64 = result.try_into().unwrap_or(-1);
            println!(
                "External supply: {} KARMA (signed: {})",
                result, external_supply_i64
            );
        }
        Err(e) => {
            eprintln!("Failed to get external supply: {}", e);
        }
    }

    // Test 5: Get slash percentage
    match karma_contract.slashPercentage().call().await {
        Ok(result) => {
            let slash_percentage_i64: i64 = result.try_into().unwrap_or(-1);
            println!(
                "Current slash percentage: {} (signed: {})",
                result, slash_percentage_i64
            );
        }
        Err(e) => {
            eprintln!("Failed to get slash percentage: {}", e);
        }
    }

    // Test 6: Calculate slash amount for a test value
    let test_karma = U256::from(1000);
    match karma_contract.calculateSlashAmount(test_karma).call().await {
        Ok(result) => {
            let slash_amount_i64: i64 = result.try_into().unwrap_or(-1);
            println!(
                "Slash amount for {} KARMA would be: {} (signed: {})",
                test_karma, result, slash_amount_i64
            );
        }
        Err(e) => {
            eprintln!("Failed to calculate slash amount: {}", e);
        }
    }

    // Test 7: Get reward distributors
    match karma_contract.getRewardDistributors().call().await {
        Ok(result) => {
            println!(
                "Reward distributors count: {} (signed: {})",
                result.len(),
                result.len() as i32
            );
            for (i, distributor) in result.iter().enumerate() {
                println!("  Distributor {}: {}", i as i32, distributor);
            }
        }
        Err(e) => {
            eprintln!("Failed to get reward distributors: {}", e);
        }
    }

    // Test 8: Get total distributor allocation
    match karma_contract.totalDistributorAllocation().call().await {
        Ok(result) => {
            let allocation_i64: i64 = result.try_into().unwrap_or(-1);
            println!(
                "Total distributor allocation: {} KARMA (signed: {})",
                result, allocation_i64
            );
        }
        Err(e) => {
            eprintln!("Failed to get total distributor allocation: {}", e);
        }
    }

    // Test 9: Get total slash amount
    match karma_contract.totalSlashAmount().call().await {
        Ok(result) => {
            let total_slash_i64: i64 = result.try_into().unwrap_or(-1);
            println!(
                "Total slash amount: {} KARMA (signed: {})",
                result, total_slash_i64
            );
        }
        Err(e) => {
            eprintln!("Failed to get total slash amount: {}", e);
        }
    }

    // Test KarmaTiers Contract Functions
    println!("\n--- KarmaTiers Contract Tests ---");

    // Test 1: Get tier count
    match karma_tiers_contract.getTierCount().call().await {
        Ok(count) => {
            let tier_count_i32: i32 = count.try_into().unwrap_or(-1);
            println!(
                "Total number of tiers: {} (signed: {})",
                count, tier_count_i32
            );

            // Check if tiers exist, if not, update them
            if count == U256::from(0) {
                println!("No tiers found. Updating tiers with default configuration...");

                // Define default tiers
                let default_tiers = vec![
                    KarmaTiersSC::Tier {
                        minKarma: U256::from(0),
                        maxKarma: U256::from(99),
                        name: "Basic".to_string(),
                        txPerEpoch: 10,
                    },
                    KarmaTiersSC::Tier {
                        minKarma: U256::from(100),
                        maxKarma: U256::from(499),
                        name: "Advanced".to_string(),
                        txPerEpoch: 50,
                    },
                    KarmaTiersSC::Tier {
                        minKarma: U256::from(500),
                        maxKarma: U256::from(999),
                        name: "Expert".to_string(),
                        txPerEpoch: 100,
                    },
                    KarmaTiersSC::Tier {
                        minKarma: U256::from(1000),
                        maxKarma: U256::from(9999),
                        name: "Master".to_string(),
                        txPerEpoch: 200,
                    },
                ];

                match karma_tiers_contract
                    .updateTiers(default_tiers.clone())
                    .call()
                    .await
                {
                    Ok(_) => {
                        println!(
                            "Successfully updated tiers with {} default tiers",
                            default_tiers.len()
                        );

                        // Verify the update
                        match karma_tiers_contract.getTierCount().call().await {
                            Ok(new_count) => {
                                let new_count_i32: i32 = new_count.try_into().unwrap_or(-1);
                                println!(
                                    "New tier count: {} (signed: {})",
                                    new_count, new_count_i32
                                );
                            }
                            Err(e) => {
                                eprintln!("Failed to verify tier count after update: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to update tiers: {}", e);
                        println!("Note: This might be because you don't have owner permissions");
                    }
                }
            } else {
                println!("Tiers already exist. Skipping tier update.");
            }
        }
        Err(e) => {
            eprintln!("Failed to get tier count: {}", e);
        }
    }

    // Test 2: Get tier by karma balance
    let test_karma_balance = U256::from(500);
    match karma_tiers_contract
        .getTierIdByKarmaBalance(test_karma_balance)
        .call()
        .await
    {
        Ok(tier_id) => {
            let tier_id_i32: i32 = tier_id as i32;
            println!(
                "Tier ID for karma balance {}: {} (signed: {})",
                test_karma_balance, tier_id, tier_id_i32
            );
        }
        Err(e) => {
            eprintln!("Failed to get tier ID by karma balance: {}", e);
        }
    }

    // Test 3: Get tier by ID (if tiers exist)
    let tier_id_to_test = 0u8; // Test the first tier
    match karma_tiers_contract
        .getTierById(tier_id_to_test)
        .call()
        .await
    {
        Ok(tier) => {
            let min_karma_i64: i64 = tier.minKarma.try_into().unwrap_or(-1);
            let max_karma_i64: i64 = tier.maxKarma.try_into().unwrap_or(-1);
            let tx_per_epoch_i32: i32 = tier.txPerEpoch as i32;

            println!("Tier {} details:", tier_id_to_test);
            println!("  Name: {}", tier.name);
            println!("  Min Karma: {} (signed: {})", tier.minKarma, min_karma_i64);
            println!("  Max Karma: {} (signed: {})", tier.maxKarma, max_karma_i64);
            println!(
                "  Transactions per epoch: {} (signed: {})",
                tier.txPerEpoch, tx_per_epoch_i32
            );
        }
        Err(e) => {
            eprintln!("Failed to get tier by ID {}: {}", tier_id_to_test, e);
        }
    }

    println!("\nTesting completed!");

    Ok(())
}
