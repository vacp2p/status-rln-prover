use std::collections::{BTreeMap, HashSet};
use std::ops::Bound::Included;
use std::ops::{Add, Deref};
use std::sync::Arc;
// third-party
use alloy::primitives::{Address, U256};
use parking_lot::RwLock;
use rln::protocol::keygen;
use scc::HashMap;
use tokio::sync::Notify;
use derive_more::{Add, From, Into};
use tracing::debug;
// internal
use crate::epoch_service::{Epoch, EpochSlice};
use crate::error::AppError;
use crate::tier::{KarmaAmount, TIER_LIMITS, TierLimit, TierName};
use rln_proof::RlnUserIdentity;

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

    fn has_user(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }

    fn get_user(&self, address: &Address) -> Option<RlnUserIdentity> {
        self.inner.get(address).map(|entry| entry.clone())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, From, Into)]
#[derive(Add)]
pub(crate) struct EpochCounter(u64);

#[derive(Debug, Default, Clone, Copy, PartialEq, From, Into)]
#[derive(Add)]
pub(crate) struct EpochSliceCounter(u64);

#[derive(Debug, Default, Clone)]
pub(crate) struct TxRegistry {
    inner: HashMap<Address, (EpochCounter, EpochSliceCounter)>,
}

impl Deref for TxRegistry {
    type Target = HashMap<Address, (EpochCounter, EpochSliceCounter)>;

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
    /// Returns the new value of the counter
    pub fn incr_counter(&self, address: &Address, incr_value: Option<u64>) -> EpochSliceCounter {
        let incr_value = incr_value.unwrap_or(1);
        let mut entry = self.inner.entry(*address).or_default();
        *entry = (entry.0 + EpochCounter(incr_value), entry.1 + EpochSliceCounter(incr_value));
        entry.1
    }
}

#[derive(Debug, PartialEq)]
pub struct UserTierInfo {
    pub(crate) current_epoch: Epoch,
    pub(crate) current_epoch_slice: EpochSlice,
    pub(crate) epoch_tx_count: u64,
    pub(crate) epoch_slice_tx_count: u64,
    karma_amount: U256,
    pub(crate) tier_name: Option<TierName>,
    pub(crate) tier_limit: Option<TierLimit>,
}

#[derive(Debug, thiserror::Error)]
pub enum UserTierInfoError {
    #[error("User {0} not registered")]
    NotRegistered(Address),
}

pub trait KarmaAmountExt {
    async fn karma_amount(&self, address: &Address) -> U256;
}

/// User registration + tx counters + tier limits storage
#[derive(Debug, Clone)]
pub struct UserDb {
    user_registry: Arc<UserRegistry>,
    tx_registry: Arc<TxRegistry>,
    tier_limits: Arc<RwLock<BTreeMap<KarmaAmount, (TierLimit, TierName)>>>,
    tier_limits_next: Arc<RwLock<BTreeMap<KarmaAmount, (TierLimit, TierName)>>>,
    epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>,
}

impl UserDb {
    fn on_new_epoch(&self) {
        self.tx_registry.clear()
    }

    fn on_new_epoch_slice(&self) {
        self.tx_registry.retain(|_a, v| {
            *v = (v.0, Default::default());
            true
        });

        let tier_limits_updated = self.tier_limits_next.read().is_empty();
        if tier_limits_updated {
            let mut guard = self.tier_limits_next.write();
            // mem::take will clear the BTreeMap in tier_limits_next
            let new_tier_limits = std::mem::take(&mut *guard);
            debug!("Installing new tier limits: {:?}", new_tier_limits);
            *self.tier_limits.write() = new_tier_limits;
        }
    }

    pub fn get_user(&self, address: &Address) -> Option<RlnUserIdentity> {
        self.user_registry.get_user(address)
    }

    pub(crate) fn on_new_tx(&self, address: &Address) -> Option<EpochSliceCounter> {
        if self.user_registry.has_user(address) {
            Some(self.tx_registry.incr_counter(address, None))
        } else {
            None
        }
    }

    pub(crate) fn on_new_tier_limits(
        &self,
        tier_limits: BTreeMap<KarmaAmount, (TierLimit, TierName)>,
    ) -> Result<(), SetTierLimitsError> {
        #[derive(Default)]
        struct Context<'a> {
            tier_names: HashSet<TierName>,
            prev_karma_amount: Option<&'a KarmaAmount>,
            prev_tier_limit: Option<&'a TierLimit>,
            i: usize,
        }

        let _context = tier_limits.iter().try_fold(
            Context::default(),
            |mut state, (karma_amount, (tier_limit, tier_name))| {
                if karma_amount <= state.prev_karma_amount.unwrap_or(&KarmaAmount::ZERO) {
                    return Err(SetTierLimitsError::InvalidKarmaAmount);
                }

                if tier_limit <= state.prev_tier_limit.unwrap_or(&TierLimit::from(0)) {
                    return Err(SetTierLimitsError::InvalidTierLimit);
                }

                if state.tier_names.contains(tier_name) {
                    return Err(SetTierLimitsError::NonUniqueTierName);
                }

                state.prev_karma_amount = Some(karma_amount);
                state.prev_tier_limit = Some(tier_limit);
                state.tier_names.insert(tier_name.clone());
                state.i += 1;
                Ok(state)
            },
        )?;

        *self.tier_limits_next.write() = tier_limits;
        Ok(())
    }

    /// Get user tier info
    pub(crate) async fn user_tier_info<KSC: KarmaAmountExt>(
        &self,
        address: &Address,
        karma_sc: KSC,
    ) -> Result<UserTierInfo, UserTierInfoError> {
        if self.user_registry.has_user(address) {
            let (epoch_tx_count, epoch_slice_tx_count) = self
                .tx_registry
                .get(address)
                .map(|ref_v| (ref_v.0, ref_v.1))
                .unwrap_or_default();

            let karma_amount = karma_sc.karma_amount(address).await;
            let guard = self.tier_limits.read();
            let range_res = guard.range((
                Included(&KarmaAmount::ZERO),
                Included(&KarmaAmount::from(karma_amount)),
            ));
            let tier_info: Option<(TierLimit, TierName)> =
                range_res.into_iter().last().map(|o| o.1.clone());
            drop(guard);

            let user_tier_info = {
                let (current_epoch, current_epoch_slice) = *self.epoch_store.read();
                let mut t = UserTierInfo {
                    current_epoch,
                    current_epoch_slice,
                    epoch_tx_count: epoch_tx_count.into(),
                    epoch_slice_tx_count: epoch_slice_tx_count.into(),
                    karma_amount,
                    tier_name: None,
                    tier_limit: None,
                };
                if let Some((tier_limit, tier_name)) = tier_info {
                    t.tier_name = Some(tier_name);
                    t.tier_limit = Some(tier_limit);
                }
                t
            };

            Ok(user_tier_info)
        } else {
            Err(UserTierInfoError::NotRegistered(*address))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SetTierLimitsError {
    #[error("Invalid Karma amount (must be increasing)")]
    InvalidKarmaAmount,
    #[error("Invalid Tier limit (must be increasing)")]
    InvalidTierLimit,
    #[error("Non unique Tier name")]
    NonUniqueTierName,
}

/// Async service to update a UserDb on epoch changes
#[derive(Debug)]
pub struct UserDbService {
    user_db: UserDb,
    epoch_changes: Arc<Notify>,
}

impl UserDbService {
    pub(crate) fn new(
        epoch_changes_notifier: Arc<Notify>,
        epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>,
    ) -> Self {
        Self {
            user_db: UserDb {
                user_registry: Default::default(),
                tx_registry: Default::default(),
                tier_limits: Arc::new(RwLock::new(TIER_LIMITS.clone())),
                tier_limits_next: Arc::new(Default::default()),
                epoch_store,
            },
            epoch_changes: epoch_changes_notifier,
        }
    }

    pub fn get_user_db(&self) -> UserDb {
        self.user_db.clone()
    }

    pub async fn listen_for_epoch_changes(&self) -> Result<(), AppError> {
        let (mut current_epoch, mut current_epoch_slice) = *self.user_db.epoch_store.read();

        loop {
            self.epoch_changes.notified().await;
            let (new_epoch, new_epoch_slice) = *self.user_db.epoch_store.read();
            debug!(
                "new epoch: {:?}, new epoch slice: {:?}",
                new_epoch, new_epoch_slice
            );
            self.update_on_epoch_changes(
                &mut current_epoch,
                new_epoch,
                &mut current_epoch_slice,
                new_epoch_slice,
            );
        }
    }

    /// Internal - used by listen_for_epoch_changes
    fn update_on_epoch_changes(
        &self,
        current_epoch: &mut Epoch,
        new_epoch: Epoch,
        current_epoch_slice: &mut EpochSlice,
        new_epoch_slice: EpochSlice,
    ) {
        if new_epoch > *current_epoch {
            self.user_db.on_new_epoch()
        } else if new_epoch_slice > *current_epoch_slice {
            self.user_db.on_new_epoch_slice()
        }

        *current_epoch = new_epoch;
        *current_epoch_slice = new_epoch_slice;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use claims::assert_err;

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
        let user_db = UserDb {
            user_registry: Default::default(),
            tx_registry: Default::default(),
            tier_limits: Arc::new(RwLock::new(TIER_LIMITS.clone())),
            tier_limits_next: Arc::new(Default::default()),
            epoch_store: Arc::new(RwLock::new(Default::default())),
        };
        let addr = Address::new([0; 20]);

        // Try to update tx counter without registering first
        assert_eq!(user_db.on_new_tx(&addr), None);
        let tier_info = user_db.user_tier_info(&addr, MockKarmaSc {}).await;
        // User is not registered -> no tier info
        assert!(matches!(
            tier_info,
            Err(UserTierInfoError::NotRegistered(_))
        ));
        // Register user + update tx counter
        user_db.user_registry.register(addr);
        assert_eq!(user_db.on_new_tx(&addr), Some(EpochSliceCounter(1)));
        let tier_info = user_db.user_tier_info(&addr, MockKarmaSc {}).await.unwrap();
        assert_eq!(tier_info.epoch_tx_count, 1);
        assert_eq!(tier_info.epoch_slice_tx_count, 1);
    }

    #[tokio::test]
    async fn test_update_on_epoch_changes() {
        let mut epoch = Epoch::from(11);
        let mut epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));
        let user_db_service = UserDbService::new(Default::default(), epoch_store);
        let user_db = user_db_service.get_user_db();

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
            let new_epoch = epoch;
            let new_epoch_slice = epoch_slice + 1;
            user_db_service.update_on_epoch_changes(
                &mut epoch,
                new_epoch,
                &mut epoch_slice,
                new_epoch_slice,
            );
            let addr_1_tier_info = user_db
                .user_tier_info(&ADDR_1, MockKarmaSc2 {})
                .await
                .unwrap();
            assert_eq!(addr_1_tier_info.epoch_tx_count, addr_1_tx_count);
            assert_eq!(addr_1_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(addr_1_tier_info.tier_name, Some(TierName::from("Basic")));

            let addr_2_tier_info = user_db
                .user_tier_info(&ADDR_2, MockKarmaSc2 {})
                .await
                .unwrap();
            assert_eq!(addr_2_tier_info.epoch_tx_count, addr_2_tx_count);
            assert_eq!(addr_2_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(
                addr_2_tier_info.tier_name,
                Some(TierName::from("Power User"))
            );
        }

        // incr epoch (11 -> 12, epoch slice reset)
        {
            let new_epoch = epoch + 1;
            let new_epoch_slice = EpochSlice::from(0);
            user_db_service.update_on_epoch_changes(
                &mut epoch,
                new_epoch,
                &mut epoch_slice,
                new_epoch_slice,
            );
            let addr_1_tier_info = user_db
                .user_tier_info(&ADDR_1, MockKarmaSc2 {})
                .await
                .unwrap();
            assert_eq!(addr_1_tier_info.epoch_tx_count, 0);
            assert_eq!(addr_1_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(addr_1_tier_info.tier_name, Some(TierName::from("Basic")));

            let addr_2_tier_info = user_db
                .user_tier_info(&ADDR_2, MockKarmaSc2 {})
                .await
                .unwrap();
            assert_eq!(addr_2_tier_info.epoch_tx_count, 0);
            assert_eq!(addr_2_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(
                addr_2_tier_info.tier_name,
                Some(TierName::from("Power User"))
            );
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_set_tier_limits() {

        // Check if we can update tier limits (and it updates after an epoch slice change)

        let mut epoch = Epoch::from(11);
        let mut epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));
        let user_db_service = UserDbService::new(Default::default(), epoch_store);
        let user_db = user_db_service.get_user_db();

        let tier_limits = BTreeMap::from([
            (KarmaAmount::from(100), (TierLimit::from(100), TierName::from("Basic"))),
            (KarmaAmount::from(200), (TierLimit::from(200), TierName::from("Power User"))),
            (KarmaAmount::from(300), (TierLimit::from(300), TierName::from("Elite User"))),
        ]);

        user_db.on_new_tier_limits(tier_limits.clone()).unwrap();
        // Check it is not yet installed
        assert_ne!(*user_db.tier_limits.read(), tier_limits);
        assert_eq!(*user_db.tier_limits_next.read(), tier_limits);

        let new_epoch = epoch;
        let new_epoch_slice = epoch_slice + 1;
        user_db_service.update_on_epoch_changes(
            &mut epoch,
            new_epoch,
            &mut epoch_slice,
            new_epoch_slice,
        );

        // Should be installed now
        assert_eq!(*user_db.tier_limits.read(), tier_limits);
        // And the tier_limits_next field is expected to be empty
        assert_eq!(*user_db.tier_limits_next.read(), BTreeMap::new());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_set_invalid_tier_limits() {

        // Check we cannot update with invalid tier limits

        let epoch = Epoch::from(11);
        let epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));
        let user_db_service = UserDbService::new(Default::default(), epoch_store);
        let user_db = user_db_service.get_user_db();

        let tier_limits_original = user_db.tier_limits.read().clone();

        {
            let tier_limits = BTreeMap::from([
                (KarmaAmount::from(100), (TierLimit::from(100), TierName::from("Basic"))),
                (KarmaAmount::from(200), (TierLimit::from(200), TierName::from("Power User"))),
                (KarmaAmount::from(199), (TierLimit::from(300), TierName::from("Elite User"))),
            ]);

            assert_err!(user_db.on_new_tier_limits(tier_limits.clone()));
            assert_eq!(*user_db.tier_limits.read(), tier_limits_original);
        }

        {
            let tier_limits = BTreeMap::from([
                (KarmaAmount::from(100), (TierLimit::from(100), TierName::from("Basic"))),
                (KarmaAmount::from(200), (TierLimit::from(200), TierName::from("Power User"))),
                (KarmaAmount::from(300), (TierLimit::from(300), TierName::from("Basic"))),
            ]);

            assert_err!(user_db.on_new_tier_limits(tier_limits.clone()));
            assert_eq!(*user_db.tier_limits.read(), tier_limits_original);
        }


    }

}
