// std
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
// third-party
use tokio::sync::Notify;
use tracing::debug;
// internal
use crate::epoch_service::{Epoch, EpochSlice};
use crate::error::AppError;
use crate::tier::TierLimits;
use crate::user_db::UserDb;
use crate::user_db_error::UserDbOpenError;
use crate::user_db_types::RateLimit;

/// Async service to update a UserDb on epoch changes
#[derive(Debug)]
pub struct UserDbService {
    user_db: UserDb,
    epoch_changes: Arc<Notify>,
}

impl UserDbService {
    pub fn new(
        db_path: PathBuf,
        merkle_tree_path: PathBuf,
        epoch_changes_notifier: Arc<Notify>,
        epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>,
        rate_limit: RateLimit,
        tier_limits: TierLimits,
    ) -> Result<Self, UserDbOpenError> {
        let user_db = UserDb::new(
            db_path,
            merkle_tree_path,
            epoch_store,
            tier_limits,
            rate_limit,
        )?;
        Ok(Self {
            user_db,
            epoch_changes: epoch_changes_notifier,
        })
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
