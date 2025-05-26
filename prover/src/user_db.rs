use std::collections::BTreeMap;
use std::ops::Bound::Included;
use std::sync::{Arc, LazyLock};
// third-party
use alloy::primitives::{Address, U256};
use parking_lot::RwLock;
use rln::protocol::keygen;
use scc::HashMap;
use tokio::sync::Notify;
use tracing::debug;
// internal
use crate::epoch_service::{Epoch, EpochSlice};
use crate::error::AppError;
use rln_proof::RlnUserIdentity;

#[derive(Debug, Clone, Copy)]
struct TierLimit(u64);

impl From<TierLimit> for u64 {
    fn from(value: TierLimit) -> Self {
        value.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct KarmaAmount(U256);

impl KarmaAmount {
    const ZERO: KarmaAmount = KarmaAmount(U256::ZERO);
}

static TIER_LIMITS: LazyLock<BTreeMap<KarmaAmount, (TierLimit, String)>> = LazyLock::new(|| {
    BTreeMap::from([
        (
            KarmaAmount(U256::from(10)),
            (TierLimit(6), "Basic".to_string()),
        ),
        (
            KarmaAmount(U256::from(50)),
            (TierLimit(120), "Active".to_string()),
        ),
        (
            KarmaAmount(U256::from(100)),
            (TierLimit(720), "Regular".to_string()),
        ),
        (
            KarmaAmount(U256::from(500)),
            (TierLimit(14440), "Regular".to_string()),
        ),
        (
            KarmaAmount(U256::from(1000)),
            (TierLimit(86400), "Power User".to_string()),
        ),
        (
            KarmaAmount(U256::from(5000)),
            (TierLimit(432000), "S-Tier".to_string()),
        ),
    ])
});

trait KarmaAmountExt {
    async fn karma_amount(&self, address: &Address) -> U256;
}

#[derive(Debug)]
pub(crate) struct UserDb<KSC: KarmaAmountExt> {
    inner: HashMap<Address, RlnUserIdentity>,
    inner_counter: HashMap<Address, (u64, u64)>,
    epoch_changes: Arc<Notify>,
    epoch_ref: Arc<RwLock<(Epoch, EpochSlice)>>,
    current_epoch: Epoch,
    current_epoch_slice: EpochSlice,
    tier_limits: BTreeMap<KarmaAmount, (TierLimit, String)>,
    karma_sc: KSC,
}

impl<KSC> UserDb<KSC>
where
    KSC: KarmaAmountExt,
{
    fn new(karma_sc: KSC) -> Self {
        Self {
            inner: Default::default(),
            inner_counter: Default::default(),
            epoch_changes: Arc::new(Default::default()),
            epoch_ref: Arc::new(Default::default()),
            current_epoch: Default::default(),
            current_epoch_slice: Default::default(),
            tier_limits: TIER_LIMITS.clone(),
            karma_sc,
        }
    }

    fn register(&self, address: Address) -> bool {
        let (identity_secret_hash, id_commitment) = keygen();
        self.inner
            .insert(
                address,
                RlnUserIdentity::from((identity_secret_hash, id_commitment)),
            )
            .map(|()| true)
            .unwrap_or(false)
    }

    fn incr_tx_counter(&self, address: &Address, incr_value: Option<u64>) -> bool {
        if self.inner.contains(address) {
            let incr_value = incr_value.unwrap_or(1);
            let mut entry = self.inner_counter.entry(*address).or_insert((0, 0));
            *entry = (entry.0 + incr_value, entry.1 + incr_value);
            true
        } else {
            false
        }
    }

    /// Get user tier info
    async fn user_tier_info(&self, address: &Address) -> Option<UserTierInfo> {
        if self.inner.contains(address) {
            let (epoch_tx_count, epoch_slice_tx_count) = self
                .inner_counter
                .get(address)
                .map(|ref_v| (ref_v.0, ref_v.1))
                .unwrap_or((0, 0));

            let karma_amount = self.karma_sc.karma_amount(address).await;
            let range_res = self.tier_limits.range((
                Included(&KarmaAmount::ZERO),
                Included(&KarmaAmount(karma_amount)),
            ));
            let tier_info_: Option<(&KarmaAmount, &(TierLimit, String))> =
                range_res.into_iter().last();

            let user_tier_info = {
                let mut t = UserTierInfo {
                    current_epoch: self.current_epoch.into(),
                    current_epoch_slice: self.current_epoch_slice.into(),
                    epoch_tx_count,
                    epoch_slice_tx_count,
                    tier: None,
                    tier_limit: None,
                };
                if let Some(tier_info) = tier_info_ {
                    t.tier = Some(tier_info.1.1.clone());
                    t.tier_limit = Some(tier_info.1.0.into());
                }
                t
            };

            Some(user_tier_info)
        } else {
            None
        }
    }

    async fn listen_for_epoch_changes(&mut self) -> Result<(), AppError> {
        loop {
            self.epoch_changes.notified().await;
            let (new_epoch, new_epoch_slice) = *self.epoch_ref.read();
            debug!(
                "new epoch: {:?}, new epoch slice: {:?}",
                new_epoch, new_epoch_slice
            );
            self.update_on_epoch_changes(new_epoch, new_epoch_slice);
        }
    }

    fn update_on_epoch_changes(&mut self, new_epoch: Epoch, new_epoch_slice: EpochSlice) {
        if new_epoch > self.current_epoch {
            self.inner_counter.clear();
        } else if new_epoch_slice > self.current_epoch_slice {
            self.inner_counter.retain(|_a, v| {
                *v = (v.0, 0);
                true
            });
        }

        self.current_epoch = new_epoch;
        self.current_epoch_slice = new_epoch_slice;
    }
}

#[derive(Debug, PartialEq)]
struct UserTierInfo {
    current_epoch: i64,
    current_epoch_slice: i64,
    epoch_tx_count: u64,
    epoch_slice_tx_count: u64,
    tier: Option<String>,
    tier_limit: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    struct MockKarmaSc {}
    impl MockKarmaSc {
        fn new() -> Self {
            Self {}
        }
    }

    impl KarmaAmountExt for MockKarmaSc {
        async fn karma_amount(&self, _address: &Address) -> U256 {
            U256::from(10)
        }
    }

    #[tokio::test]
    async fn test_incr_tx_counter() {
        let user_db = UserDb::new(MockKarmaSc::new());
        let address = Address::new([0; 20]);

        assert_eq!(user_db.incr_tx_counter(&address, None), false);
        let tier_info = user_db.user_tier_info(&address).await;
        assert_eq!(tier_info, None);
        user_db.register(address);
        assert_eq!(user_db.incr_tx_counter(&address, None), true);
        let tier_info = user_db.user_tier_info(&address).await.unwrap();
        assert_eq!(tier_info.epoch_tx_count, 1);
        assert_eq!(tier_info.epoch_slice_tx_count, 1);
    }

    #[tokio::test]
    async fn test_update_on_epoch_changes() {
        let epoch = Epoch::from(11);
        let epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));
        let mut user_db = UserDb {
            inner: Default::default(),
            inner_counter: Default::default(),
            epoch_changes: Default::default(),
            epoch_ref: epoch_store.clone(),
            current_epoch: epoch,
            current_epoch_slice: epoch_slice,
            // tier_limits: TIER_LIMITS.clone(),
            tier_limits: Default::default(),
            karma_sc: MockKarmaSc::new(),
        };

        let addr_1 = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
        let addr_1_tx_count = 2;
        let addr_2 = address!("0xb20a608c624Ca5003905aA834De7156C68b2E1d0");
        let addr_2_tx_count = 820;
        user_db.register(addr_1);
        // (0..addr_1_tx_count).into_iter().for_each(|_i| { user_db.incr_tx_counter(&addr_1); });
        user_db.incr_tx_counter(&addr_1, Some(addr_1_tx_count));
        user_db.register(addr_2);
        // (0..addr_2_tx_count).into_iter().for_each(|_i| { user_db.incr_tx_counter(&addr_2); });
        user_db.incr_tx_counter(&addr_2, Some(addr_2_tx_count));

        // incr epoch slice (42 -> 43)
        {
            user_db.update_on_epoch_changes(epoch, epoch_slice + 1);
            let addr_1_tier_info = user_db.user_tier_info(&addr_1).await.unwrap();
            assert_eq!(addr_1_tier_info.epoch_tx_count, addr_1_tx_count);
            assert_eq!(addr_1_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(addr_1_tier_info.tier, Some("Basic".to_string()));

            let addr_2_tier_info = user_db.user_tier_info(&addr_2).await.unwrap();
            assert_eq!(addr_2_tier_info.epoch_tx_count, addr_2_tx_count);
            assert_eq!(addr_2_tier_info.epoch_slice_tx_count, 0);
            // assert_eq!(addr_2_tier_info.tier, "");
        }

        // incr epoch (11 -> 12, epoch slice reset)
        {
            user_db.update_on_epoch_changes(epoch + 1, EpochSlice::from(0));
            let addr_1_tier_info = user_db.user_tier_info(&addr_1).await.unwrap();
            assert_eq!(addr_1_tier_info.epoch_tx_count, 0);
            assert_eq!(addr_1_tier_info.epoch_slice_tx_count, 0);

            let addr_2_tier_info = user_db.user_tier_info(&addr_2).await.unwrap();
            assert_eq!(addr_2_tier_info.epoch_tx_count, 0);
            assert_eq!(addr_2_tier_info.epoch_slice_tx_count, 0);
        }
    }
}
