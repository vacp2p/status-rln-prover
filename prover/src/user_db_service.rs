use std::ops::Deref;
use std::sync::Arc;
// third-party
use alloy::primitives::{Address, U256};
use ark_bn254::Fr;
use derive_more::{Add, From, Into};
use parking_lot::RwLock;
use rln::hashers::poseidon_hash;
use rln::poseidon_tree::{MerkleProof, PoseidonTree};
use rln::protocol::keygen;
use scc::HashMap;
use tokio::sync::Notify;
use tracing::debug;
// internal
use crate::epoch_service::{Epoch, EpochSlice};
use crate::error::{AppError, GetMerkleTreeProofError, RegisterError};
use crate::tier::{TierLimit, TierLimits, TierName};
use rln_proof::{RlnUserIdentity, ZerokitMerkleTree};
use smart_contract::{KarmaAmountExt, Tier, TierIndex};

const MERKLE_TREE_HEIGHT: usize = 20;

#[derive(Debug, Clone, Copy, From, Into)]
struct MerkleTreeIndex(usize);

#[derive(Debug, Clone, Copy, Default, PartialOrd, PartialEq, From, Into)]
pub struct RateLimit(u64);

impl RateLimit {
    pub(crate) const ZERO: RateLimit = RateLimit(0);

    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl From<RateLimit> for Fr {
    fn from(rate_limit: RateLimit) -> Self {
        Fr::from(rate_limit.0)
    }
}

#[derive(Clone)]
pub(crate) struct UserRegistry {
    inner: HashMap<Address, (RlnUserIdentity, MerkleTreeIndex)>,
    merkle_tree: Arc<RwLock<PoseidonTree>>,
    rate_limit: RateLimit,
}

impl std::fmt::Debug for UserRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserRegistry {{ inner: {:?} }}", self.inner)
    }
}

impl Default for UserRegistry {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            // unwrap safe - no config
            merkle_tree: Arc::new(RwLock::new(
                PoseidonTree::new(MERKLE_TREE_HEIGHT, Default::default(), Default::default())
                    .unwrap(),
            )),
            rate_limit: Default::default(),
        }
    }
}

impl From<RateLimit> for UserRegistry {
    fn from(rate_limit: RateLimit) -> Self {
        Self {
            inner: Default::default(),
            // unwrap safe - no config
            merkle_tree: Arc::new(RwLock::new(
                PoseidonTree::new(MERKLE_TREE_HEIGHT, Default::default(), Default::default())
                    .unwrap(),
            )),
            rate_limit,
        }
    }
}

impl UserRegistry {
    fn register(&self, address: Address) -> Result<Fr, RegisterError> {
        let (identity_secret_hash, id_commitment) = keygen();
        let index = self.inner.len();

        self.inner
            .insert(
                address,
                (
                    RlnUserIdentity::from((
                        identity_secret_hash,
                        id_commitment,
                        Fr::from(self.rate_limit),
                    )),
                    MerkleTreeIndex(index),
                ),
            )
            .map_err(|_e| RegisterError::AlreadyRegistered(address))?;

        let rate_commit = poseidon_hash(&[id_commitment, Fr::from(u64::from(self.rate_limit))]);
        self.merkle_tree
            .write()
            .set(index, rate_commit)
            .map_err(|e| RegisterError::TreeError(e.to_string()))?;
        Ok(id_commitment)
    }

    fn has_user(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }

    fn get_user(&self, address: &Address) -> Option<RlnUserIdentity> {
        self.inner.get(address).map(|entry| entry.0.clone())
    }

    fn get_merkle_proof(&self, address: &Address) -> Result<MerkleProof, GetMerkleTreeProofError> {
        let index = self
            .inner
            .get(address)
            .map(|entry| entry.1)
            .ok_or(GetMerkleTreeProofError::NotRegistered)?;
        self.merkle_tree
            .read()
            .proof(index.into())
            .map_err(|e| GetMerkleTreeProofError::TreeError(e.to_string()))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, From, Into, Add)]
pub(crate) struct EpochCounter(u64);

#[derive(Debug, Default, Clone, Copy, PartialEq, From, Into, Add)]
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
        *entry = (
            entry.0 + EpochCounter(incr_value),
            entry.1 + EpochSliceCounter(incr_value),
        );
        entry.1
    }
}

#[derive(Debug, PartialEq)]
pub struct UserTierInfo {
    pub(crate) current_epoch: Epoch,
    pub(crate) current_epoch_slice: EpochSlice,
    pub(crate) epoch_tx_count: u64,
    pub(crate) epoch_slice_tx_count: u64,
    pub(crate) karma_amount: U256,
    pub(crate) tier_name: Option<TierName>,
    pub(crate) tier_limit: Option<TierLimit>,
}

#[derive(Debug, thiserror::Error)]
pub enum UserTierInfoError<E: std::error::Error> {
    #[error("User {0} not registered")]
    NotRegistered(Address),
    #[error(transparent)]
    Contract(E),
}

/// User registration + tx counters + tier limits storage
#[derive(Debug, Clone)]
pub struct UserDb {
    user_registry: Arc<UserRegistry>,
    tx_registry: Arc<TxRegistry>,
    tier_limits: Arc<RwLock<TierLimits>>,
    tier_limits_next: Arc<RwLock<TierLimits>>,
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

        let tier_limits_next_has_updates = !self.tier_limits_next.read().is_empty();
        if tier_limits_next_has_updates {
            let mut guard = self.tier_limits_next.write();
            // mem::take will clear the TierLimits in tier_limits_next
            let new_tier_limits = std::mem::take(&mut *guard);
            debug!("Installing new tier limits: {:?}", new_tier_limits);
            *self.tier_limits.write() = new_tier_limits;
        }
    }

    pub fn on_new_user(&self, address: Address) -> Result<Fr, RegisterError> {
        self.user_registry.register(address)
    }

    pub fn get_user(&self, address: &Address) -> Option<RlnUserIdentity> {
        self.user_registry.get_user(address)
    }

    pub fn get_merkle_proof(
        &self,
        address: &Address,
    ) -> Result<MerkleProof, GetMerkleTreeProofError> {
        self.user_registry.get_merkle_proof(address)
    }

    pub(crate) fn on_new_tx(
        &self,
        address: &Address,
        incr_value: Option<u64>,
    ) -> Option<EpochSliceCounter> {
        if self.user_registry.has_user(address) {
            Some(self.tx_registry.incr_counter(address, incr_value))
        } else {
            None
        }
    }

    pub(crate) fn on_new_tier_limits(
        &self,
        tier_limits: TierLimits,
    ) -> Result<(), SetTierLimitsError> {
        let tier_limits = tier_limits.clone().filter_inactive();
        tier_limits.validate()?;
        *self.tier_limits_next.write() = tier_limits;
        Ok(())
    }

    pub(crate) fn on_new_tier(
        &self,
        tier_index: TierIndex,
        tier: Tier,
    ) -> Result<(), SetTierLimitsError> {
        let mut tier_limits = self.tier_limits.read().clone();
        tier_limits.insert(tier_index, tier);
        tier_limits.validate()?;
        // Write
        *self.tier_limits_next.write() = tier_limits;
        Ok(())
    }

    pub(crate) fn on_tier_updated(
        &self,
        tier_index: TierIndex,
        tier: Tier,
    ) -> Result<(), SetTierLimitsError> {
        let mut tier_limits = self.tier_limits.read().clone();
        if !tier_limits.contains_key(&tier_index) {
            return Err(SetTierLimitsError::InvalidTierIndex);
        }
        tier_limits.entry(tier_index).and_modify(|e| *e = tier);
        tier_limits.validate()?;
        // Write
        *self.tier_limits_next.write() = tier_limits;
        Ok(())
    }

    /// Get user tier info
    pub(crate) async fn user_tier_info<E: std::error::Error, KSC: KarmaAmountExt<Error = E>>(
        &self,
        address: &Address,
        karma_sc: &KSC,
    ) -> Result<UserTierInfo, UserTierInfoError<E>> {
        if self.user_registry.has_user(address) {
            let (epoch_tx_count, epoch_slice_tx_count) = self
                .tx_registry
                .get(address)
                .map(|ref_v| (ref_v.0, ref_v.1))
                .unwrap_or_default();

            let karma_amount = karma_sc
                .karma_amount(address)
                .await
                .map_err(|e| UserTierInfoError::Contract(e))?;
            let tier_limits_guard = self.tier_limits.read();
            let tier_info = tier_limits_guard.get_tier_by_karma(&karma_amount);
            drop(tier_limits_guard);

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
                if let Some((_tier_index, tier)) = tier_info {
                    t.tier_name = Some(tier.name.into());
                    // TODO
                    t.tier_limit = Some(0.into());
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
    #[error("Invalid Karma max amount (min: {0} vs max: {1})")]
    InvalidMaxAmount(U256, U256),
    #[error("Invalid Tier limit (must be increasing)")]
    InvalidTierLimit,
    #[error("Invalid Tier index (must be increasing)")]
    InvalidTierIndex,
    #[error("Non unique Tier name")]
    NonUniqueTierName,
    #[error("Non active Tier")]
    InactiveTier,
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
        rate_limit: RateLimit,
        tier_limits: TierLimits,
    ) -> Self {
        Self {
            user_db: UserDb {
                user_registry: Arc::new(UserRegistry::from(rate_limit)),
                tx_registry: Default::default(),
                tier_limits: Arc::new(RwLock::new(tier_limits)),
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
    // std
    use std::collections::BTreeMap;
    // third-party
    use alloy::primitives::address;
    use async_trait::async_trait;
    use claims::{assert_err, assert_matches};
    use derive_more::Display;

    #[derive(Debug, Display, thiserror::Error)]
    struct DummyError();

    struct MockKarmaSc {}

    #[async_trait]
    impl KarmaAmountExt for MockKarmaSc {
        type Error = DummyError;

        async fn karma_amount(&self, _address: &Address) -> Result<U256, Self::Error> {
            Ok(U256::from(10))
        }
    }

    const ADDR_1: Address = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const ADDR_2: Address = address!("0xb20a608c624Ca5003905aA834De7156C68b2E1d0");

    struct MockKarmaSc2 {}

    #[async_trait]
    impl KarmaAmountExt for MockKarmaSc2 {
        type Error = DummyError;

        async fn karma_amount(&self, address: &Address) -> Result<U256, Self::Error> {
            if address == &ADDR_1 {
                Ok(U256::from(10))
            } else if address == &ADDR_2 {
                Ok(U256::from(2000))
            } else {
                Ok(U256::ZERO)
            }
        }
    }

    #[test]
    fn test_user_register() {
        let user_db = UserDb {
            user_registry: Default::default(),
            tx_registry: Default::default(),
            tier_limits: Arc::new(RwLock::new(Default::default())),
            tier_limits_next: Arc::new(Default::default()),
            epoch_store: Arc::new(RwLock::new(Default::default())),
        };
        let addr = Address::new([0; 20]);
        user_db.user_registry.register(addr).unwrap();
        assert_matches!(
            user_db.user_registry.register(addr),
            Err(RegisterError::AlreadyRegistered(_))
        );
    }

    #[tokio::test]
    async fn test_incr_tx_counter() {
        let user_db = UserDb {
            user_registry: Default::default(),
            tx_registry: Default::default(),
            tier_limits: Arc::new(RwLock::new(Default::default())),
            tier_limits_next: Arc::new(Default::default()),
            epoch_store: Arc::new(RwLock::new(Default::default())),
        };
        let addr = Address::new([0; 20]);

        // Try to update tx counter without registering first
        assert_eq!(user_db.on_new_tx(&addr, None), None);
        let tier_info = user_db.user_tier_info(&addr, &MockKarmaSc {}).await;
        // User is not registered -> no tier info
        assert!(matches!(
            tier_info,
            Err(UserTierInfoError::NotRegistered(_))
        ));
        // Register user
        user_db.user_registry.register(addr).unwrap();
        // Now update user tx counter
        assert_eq!(user_db.on_new_tx(&addr, None), Some(EpochSliceCounter(1)));
        let tier_info = user_db
            .user_tier_info(&addr, &MockKarmaSc {})
            .await
            .unwrap();
        assert_eq!(tier_info.epoch_tx_count, 1);
        assert_eq!(tier_info.epoch_slice_tx_count, 1);
    }

    #[tokio::test]
    async fn test_update_on_epoch_changes() {
        let mut epoch = Epoch::from(11);
        let mut epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));

        let tier_limits = BTreeMap::from([
            (
                TierIndex::from(0),
                Tier {
                    name: "Basic".into(),
                    min_karma: U256::from(10),
                    max_karma: U256::from(49),
                    tx_per_epoch: 5,
                    active: true,
                },
            ),
            (
                TierIndex::from(1),
                Tier {
                    name: "Active".into(),
                    min_karma: U256::from(50),
                    max_karma: U256::from(99),
                    tx_per_epoch: 10,
                    active: true,
                },
            ),
            (
                TierIndex::from(2),
                Tier {
                    name: "Regular".into(),
                    min_karma: U256::from(100),
                    max_karma: U256::from(499),
                    tx_per_epoch: 15,
                    active: true,
                },
            ),
            (
                TierIndex::from(3),
                Tier {
                    name: "Power User".into(),
                    min_karma: U256::from(500),
                    max_karma: U256::from(4999),
                    tx_per_epoch: 20,
                    active: true,
                },
            ),
            (
                TierIndex::from(4),
                Tier {
                    name: "S-Tier".into(),
                    min_karma: U256::from(5000),
                    max_karma: U256::from(U256::MAX),
                    tx_per_epoch: 25,
                    active: true,
                },
            ),
        ]);

        let user_db_service = UserDbService::new(
            Default::default(),
            epoch_store,
            10.into(),
            tier_limits.into(),
        );
        let user_db = user_db_service.get_user_db();

        let addr_1_tx_count = 2;
        let addr_2_tx_count = 820;
        user_db.user_registry.register(ADDR_1).unwrap();
        user_db
            .tx_registry
            .incr_counter(&ADDR_1, Some(addr_1_tx_count));
        user_db.user_registry.register(ADDR_2).unwrap();
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
                .user_tier_info(&ADDR_1, &MockKarmaSc2 {})
                .await
                .unwrap();
            assert_eq!(addr_1_tier_info.epoch_tx_count, addr_1_tx_count);
            assert_eq!(addr_1_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(addr_1_tier_info.tier_name, Some(TierName::from("Basic")));

            let addr_2_tier_info = user_db
                .user_tier_info(&ADDR_2, &MockKarmaSc2 {})
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
                .user_tier_info(&ADDR_1, &MockKarmaSc2 {})
                .await
                .unwrap();
            assert_eq!(addr_1_tier_info.epoch_tx_count, 0);
            assert_eq!(addr_1_tier_info.epoch_slice_tx_count, 0);
            assert_eq!(addr_1_tier_info.tier_name, Some(TierName::from("Basic")));

            let addr_2_tier_info = user_db
                .user_tier_info(&ADDR_2, &MockKarmaSc2 {})
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

        let user_db_service = UserDbService::new(
            Default::default(),
            epoch_store,
            10.into(),
            Default::default(),
        );
        let user_db = user_db_service.get_user_db();
        let tier_limits_original = user_db.tier_limits.read().clone();

        let tier_limits = BTreeMap::from([
            (
                TierIndex::from(1),
                Tier {
                    name: "Basic".into(),
                    min_karma: U256::from(10),
                    max_karma: U256::from(49),
                    tx_per_epoch: 5,
                    active: true,
                },
            ),
            (
                TierIndex::from(2),
                Tier {
                    name: "Power User".into(),
                    min_karma: U256::from(50),
                    max_karma: U256::from(299),
                    tx_per_epoch: 20,
                    active: true,
                },
            ),
        ]);
        let tier_limits = TierLimits::from(tier_limits);

        user_db.on_new_tier_limits(tier_limits.clone()).unwrap();
        // Check it is not yet installed
        assert_ne!(*user_db.tier_limits.read(), tier_limits);
        assert_eq!(*user_db.tier_limits.read(), tier_limits_original);
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
        assert!(user_db.tier_limits_next.read().is_empty());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_set_invalid_tier_limits() {
        // Check we cannot update with invalid tier limits

        let epoch = Epoch::from(11);
        let epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));
        let user_db_service = UserDbService::new(
            Default::default(),
            epoch_store,
            10.into(),
            Default::default(),
        );
        let user_db = user_db_service.get_user_db();

        let tier_limits_original = user_db.tier_limits.read().clone();

        // Invalid: non unique index
        {
            let tier_limits = BTreeMap::from([
                (
                    TierIndex::from(0),
                    Tier {
                        min_karma: Default::default(),
                        max_karma: Default::default(),
                        name: "Basic".to_string(),
                        tx_per_epoch: 100,
                        active: true,
                    },
                ),
                (
                    TierIndex::from(0),
                    Tier {
                        min_karma: Default::default(),
                        max_karma: Default::default(),
                        name: "Power User".to_string(),
                        tx_per_epoch: 200,
                        active: true,
                    },
                ),
            ]);
            let tier_limits = TierLimits::from(tier_limits);

            assert_err!(user_db.on_new_tier_limits(tier_limits.clone()));
            assert_eq!(*user_db.tier_limits.read(), tier_limits_original);
        }

        // Invalid: min Karma amount not increasing
        {
            let tier_limits = BTreeMap::from([
                (
                    TierIndex::from(0),
                    Tier {
                        min_karma: U256::from(10),
                        max_karma: U256::from(49),
                        name: "Basic".to_string(),
                        tx_per_epoch: 5,
                        active: true,
                    },
                ),
                (
                    TierIndex::from(1),
                    Tier {
                        min_karma: U256::from(50),
                        max_karma: U256::from(99),
                        name: "Power User".to_string(),
                        tx_per_epoch: 10,
                        active: true,
                    },
                ),
                (
                    TierIndex::from(2),
                    Tier {
                        min_karma: U256::from(60),
                        max_karma: U256::from(99),
                        name: "Power User".to_string(),
                        tx_per_epoch: 15,
                        active: true,
                    },
                ),
            ]);
            let tier_limits = TierLimits::from(tier_limits);

            assert_err!(user_db.on_new_tier_limits(tier_limits.clone()));
            assert_eq!(*user_db.tier_limits.read(), tier_limits_original);
        }

        // Invalid: Non unique tier name
        {
            let tier_limits = BTreeMap::from([
                (
                    TierIndex::from(0),
                    Tier {
                        min_karma: U256::from(10),
                        max_karma: U256::from(49),
                        name: "Basic".to_string(),
                        tx_per_epoch: 5,
                        active: true,
                    },
                ),
                (
                    TierIndex::from(1),
                    Tier {
                        min_karma: U256::from(50),
                        max_karma: U256::from(99),
                        name: "Power User".to_string(),
                        tx_per_epoch: 10,
                        active: true,
                    },
                ),
                (
                    TierIndex::from(2),
                    Tier {
                        min_karma: U256::from(100),
                        max_karma: U256::from(999),
                        name: "Power User".to_string(),
                        tx_per_epoch: 15,
                        active: true,
                    },
                ),
            ]);
            let tier_limits = TierLimits::from(tier_limits);

            assert_err!(user_db.on_new_tier_limits(tier_limits.clone()));
            assert_eq!(*user_db.tier_limits.read(), tier_limits_original);
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_set_invalid_tier_limits_2() {
        // Check we cannot update with invalid tier limits

        let epoch = Epoch::from(11);
        let epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));
        let user_db_service = UserDbService::new(
            Default::default(),
            epoch_store,
            10.into(),
            Default::default(),
        );
        let user_db = user_db_service.get_user_db();

        let tier_limits_original = user_db.tier_limits.read().clone();

        // Invalid: inactive tier
        {
            let tier_limits = BTreeMap::from([
                (
                    TierIndex::from(0),
                    Tier {
                        min_karma: U256::from(10),
                        max_karma: U256::from(49),
                        name: "Basic".to_string(),
                        tx_per_epoch: 5,
                        active: true,
                    },
                ),
                (
                    TierIndex::from(1),
                    Tier {
                        min_karma: U256::from(50),
                        max_karma: U256::from(99),
                        name: "Power User".to_string(),
                        tx_per_epoch: 10,
                        active: true,
                    },
                ),
            ]);
            let tier_limits = TierLimits::from(tier_limits);

            assert_err!(user_db.on_new_tier_limits(tier_limits.clone()));
            assert_eq!(*user_db.tier_limits.read(), tier_limits_original);
        }

        // Invalid: non-increasing tx_per_epoch
        {
            let tier_limits = BTreeMap::from([
                (
                    TierIndex::from(0),
                    Tier {
                        min_karma: U256::from(10),
                        max_karma: U256::from(49),
                        name: "Basic".to_string(),
                        tx_per_epoch: 5,
                        active: true,
                    },
                ),
                (
                    TierIndex::from(1),
                    Tier {
                        min_karma: U256::from(50),
                        max_karma: U256::from(99),
                        name: "Power User".to_string(),
                        tx_per_epoch: 5,
                        active: true,
                    },
                ),
            ]);
            let tier_limits = TierLimits::from(tier_limits);

            assert_err!(user_db.on_new_tier_limits(tier_limits.clone()));
            assert_eq!(*user_db.tier_limits.read(), tier_limits_original);
        }
    }
}
