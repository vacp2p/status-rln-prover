use std::collections::BTreeMap;
use std::ops::Bound::Included;
use std::ops::Deref;
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

pub trait KarmaAmountExt {
    async fn karma_amount(&self, address: &Address) -> U256;
}

#[derive(Debug, Default, Clone)]
pub(crate) struct UserRegistry {
    inner: HashMap<Address, RlnUserIdentity>,
}
impl UserRegistry {
    fn register(&self, address: Address) -> bool {
        let (identity_secret_hash, id_commitment) = keygen();
        self.inner
            .insert(
                address,
                RlnUserIdentity::from((identity_secret_hash, id_commitment)),
            )
            .is_ok()
    }
}

impl Deref for UserRegistry {
    type Target = HashMap<Address, RlnUserIdentity>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct TxRegistry {
    inner: HashMap<Address, (u64, u64)>,
}
impl Deref for TxRegistry {
    type Target = HashMap<Address, (u64, u64)>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl TxRegistry {
    /// Update the transaction counter for the given address
    ///
    /// If incr_value is None, the counter will be incremented by 1
    /// If incr_value is Some(x), the counter will be incremented by x
    ///
    /// Returns the new counter value OR None if the address is not registered
    pub fn incr_counter(&self, address: &Address, incr_value: Option<u64>) -> Option<u64> {
        if self.inner.contains(address) {
            let incr_value = incr_value.unwrap_or(1);
            let mut entry = self.inner.entry(*address).or_insert((0, 0));
            *entry = (entry.0 + incr_value, entry.1 + incr_value);
            println!("entry: {:?}", entry);
            Some(entry.0)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct UserDb<KSC: KarmaAmountExt> {
    user_registry: Arc<UserRegistry>,
    tx_registry: Arc<TxRegistry>,
    epoch_changes: Arc<Notify>,
    epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>,
    current_epoch: Epoch,
    current_epoch_slice: EpochSlice,
    tier_limits: BTreeMap<KarmaAmount, (TierLimit, String)>,
    karma_sc: KSC,
}

impl<KSC> UserDb<KSC>
where
    KSC: KarmaAmountExt,
{
    pub(crate) fn new(
        karma_sc: KSC,
        epoch_changes_notifier: Arc<Notify>,
        epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>,
    ) -> Self {
        Self {
            user_registry: Default::default(),
            tx_registry: Default::default(),
            epoch_changes: epoch_changes_notifier,
            epoch_store,
            current_epoch: Default::default(),
            current_epoch_slice: Default::default(),
            tier_limits: TIER_LIMITS.clone(),
            karma_sc,
        }
    }

    pub fn user_registry_db(&self) -> Arc<UserRegistry> {
        self.user_registry.clone()
    }

    pub fn tx_registry_db(&self) -> Arc<TxRegistry> {
        self.tx_registry.clone()
    }

    /// Get user tier info
    async fn user_tier_info(&self, address: &Address) -> Option<UserTierInfo> {
        if self.user_registry.contains(address) {
            let (epoch_tx_count, epoch_slice_tx_count) = self
                .tx_registry
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
                    karma_amount,
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

    pub async fn listen_for_epoch_changes(&mut self) -> Result<(), AppError> {
        loop {
            self.epoch_changes.notified().await;
            let (new_epoch, new_epoch_slice) = *self.epoch_store.read();
            debug!(
                "new epoch: {:?}, new epoch slice: {:?}",
                new_epoch, new_epoch_slice
            );
            self.update_on_epoch_changes(new_epoch, new_epoch_slice);
        }
    }

    /// Internal - used by listen_for_epoch_changes
    fn update_on_epoch_changes(&mut self, new_epoch: Epoch, new_epoch_slice: EpochSlice) {
        if new_epoch > self.current_epoch {
            self.tx_registry.clear();
        } else if new_epoch_slice > self.current_epoch_slice {
            self.tx_registry.retain(|_a, v| {
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
    karma_amount: U256,
    tier: Option<String>,
    tier_limit: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    struct MockKarmaSc {}

    impl KarmaAmountExt for MockKarmaSc {
        async fn karma_amount(&self, _address: &Address) -> U256 {
            U256::from(10)
        }
    }

    const ADDR_1: Address = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const ADDR_2: Address = address!("0xb20a608c624Ca5003905aA834De7156C68b2E1d0");

    struct MockKarmaSc2 {}

    impl KarmaAmountExt for MockKarmaSc2 {
        async fn karma_amount(&self, address: &Address) -> U256 {
            if address == &ADDR_1 {
                U256::from(10)
            } else if address == &ADDR_2 {
                U256::from(2000)
            } else {
                U256::ZERO
            }
        }
    }

    #[tokio::test]
    async fn test_incr_tx_counter() {
        let user_db = UserDb::new(MockKarmaSc {}, Default::default(), Default::default());
        let addr = Address::new([0; 20]);

        assert_eq!(user_db.tx_registry.incr_counter(&addr, None), None);
        let tier_info = user_db.user_tier_info(&addr).await;
        assert_eq!(tier_info, None);
        user_db.user_registry.register(addr);
        assert_eq!(user_db.tx_registry.incr_counter(&addr, None), Some(0));
        let tier_info = user_db.user_tier_info(&addr).await.unwrap();
        assert_eq!(tier_info.epoch_tx_count, 1);
        assert_eq!(tier_info.epoch_slice_tx_count, 1);
    }

    #[tokio::test]
    async fn test_update_on_epoch_changes() {
        let epoch = Epoch::from(11);
        let epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));
        let mut user_db = UserDb {
            user_registry: Default::default(),
            tx_registry: Default::default(),
            epoch_changes: Default::default(),
            epoch_store: epoch_store.clone(),
            current_epoch: epoch,
            current_epoch_slice: epoch_slice,
            tier_limits: TIER_LIMITS.clone(),
            karma_sc: MockKarmaSc2 {},
        };

        let addr_1_tx_count = 2;
        let addr_2_tx_count = 820;
        user_db.user_registry.register(ADDR_1);
        user_db
            .tx_registry
            .incr_counter(&ADDR_1, Some(addr_1_tx_count));
        user_db.user_registry.register(ADDR_2);
        user_db
            .tx_registry
            .incr_counter(&ADDR_2, Some(addr_2_tx_count));

        // incr epoch slice (42 -> 43)
        {
            user_db.update_on_epoch_changes(epoch, epoch_slice + 1);
            let addr_1_tier_info = user_db.user_tier_info(&ADDR_1).await.unwrap();
            assert_eq!(addr_1_tier_info.epoch_tx_count, addr_1_tx_count);
            assert_eq!(addr_1_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(addr_1_tier_info.tier, Some("Basic".to_string()));

            let addr_2_tier_info = user_db.user_tier_info(&ADDR_2).await.unwrap();
            assert_eq!(addr_2_tier_info.epoch_tx_count, addr_2_tx_count);
            assert_eq!(addr_2_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(addr_2_tier_info.tier, Some("Power User".to_string()));
        }

        // incr epoch (11 -> 12, epoch slice reset)
        {
            user_db.update_on_epoch_changes(epoch + 1, EpochSlice::from(0));
            let addr_1_tier_info = user_db.user_tier_info(&ADDR_1).await.unwrap();
            assert_eq!(addr_1_tier_info.epoch_tx_count, 0);
            assert_eq!(addr_1_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(addr_1_tier_info.tier, Some("Basic".to_string()));

            let addr_2_tier_info = user_db.user_tier_info(&ADDR_2).await.unwrap();
            assert_eq!(addr_2_tier_info.epoch_tx_count, 0);
            assert_eq!(addr_2_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(addr_2_tier_info.tier, Some("Power User".to_string()));
        }
    }
}
