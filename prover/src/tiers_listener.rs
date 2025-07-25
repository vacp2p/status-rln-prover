// third-party
use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder, WsConnect},
    sol_types::SolEvent,
    transports::{RpcError, TransportError},
};
use futures::StreamExt;
use tracing::error;
// internal
use crate::error::AppError;
use crate::user_db::UserDb;
use smart_contract::{AlloyWsProvider, KarmaTiersSC};
use smart_contract::KarmaTiersSC::KarmaTiersSCInstance;
use crate::tier::TierLimits;

pub(crate) struct TiersListener {
    rpc_url: String,
    sc_address: Address,
    user_db: UserDb,
}

impl TiersListener {
    pub(crate) fn new(rpc_url: &str, sc_address: Address, user_db: UserDb) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            sc_address,
            user_db,
        }
    }

    /// Create a provider (aka connect to websocket url)
    async fn setup_provider_ws(&self) -> Result<AlloyWsProvider, RpcError<TransportError>> {
        let ws = WsConnect::new(self.rpc_url.as_str());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        Ok(provider)
    }

    /// Listen to Smart Contract specified events
    pub(crate) async fn listen(&self) -> Result<(), AppError> {
        let provider = self.setup_provider_ws().await.map_err(AppError::from)?;

        let filter = alloy::rpc::types::Filter::new()
            .address(self.sc_address)
            .event(KarmaTiersSC::TiersUpdated::SIGNATURE)
            ;

        // Subscribe to logs matching the filter.
        let subscription = provider.clone().subscribe_logs(&filter).await?;
        let mut stream = subscription.into_stream();

        // Loop through the incoming event logs
        while let Some(log) = stream.next().await {

            if let Ok(_tu) = KarmaTiersSC::TiersUpdated::decode_log_data(log.data()) {

                let tier_limits = match KarmaTiersSCInstance::get_tiers_from_provider(&provider, self.sc_address).await {
                    Ok(tier_limits) => tier_limits,
                    Err(e) => {
                        error!("Error while getting tiers limits from smart contract: {}", e);
                        return Err(AppError::from(e));
                    }
                };

                if let Err(e) = self.user_db.on_tier_limits_updated(TierLimits::from(tier_limits)) {
                    // If there is an error here, we assume this is an error by the user
                    // updating the Tier limits (and thus we don't want to shut down the prover)
                    error!("Error while updating tier limits: {}", e);
                }
            } else {
                // Should never happen as TiersUpdated is empty
                eprintln!("Error decoding log data");
                // It's also useful to print the raw log data for debugging
                eprintln!("Raw log topics: {:?}", log.topics());
                eprintln!("Raw log data: {:?}", log.data());
            }

            /*
            if let Ok(tier_added) = KarmaTiersSC::TierAdded::decode_log_data(log.data()) {
                let tier_id: TierIndex = tier_added.tierId.into();
                if let Err(e) = self.user_db.on_new_tier(tier_id, Tier::from(tier_added)) {
                    // If there is an error here, we assume this is an error by the user
                    // updating the Tier limits (and thus we don't want to shut down the prover)
                    error!("Error while adding tier (index: {:?}): {}", tier_id, e);
                }
            } else {
                match KarmaTiersSC::TierUpdated::decode_log_data(log.data()) {
                    Ok(tier_updated) => {
                        let tier_id: TierIndex = tier_updated.tierId.into();
                        if let Err(e) = self
                            .user_db
                            .on_tier_updated(tier_updated.tierId.into(), Tier::from(tier_updated))
                        {
                            // If there is an error here, we assume this is an error by the user
                            // updating the Tier limits (and thus we don't want to shut down the prover)
                            error!("Error while updating tier (index: {:?}): {}", tier_id, e);
                        };
                    }
                    Err(e) => {
                        eprintln!("Error decoding log data: {e:?}");
                        // It's also useful to print the raw log data for debugging
                        eprintln!("Raw log topics: {:?}", log.topics());
                        eprintln!("Raw log data: {:?}", log.data());
                    }
                }
            }
            */
        }

        Ok(())
    }
}
