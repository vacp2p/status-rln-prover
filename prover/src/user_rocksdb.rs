use std::path::{Path, PathBuf};
use std::sync::Arc;
// third-party
use alloy::primitives::{Address, U256};
use ark_bn254::Fr;
use parking_lot::RwLock;
use rln::{hashers::poseidon_hash, poseidon_tree::MerkleProof, protocol::keygen};
use rocksdb::{ColumnFamilyDescriptor, DB, Options, WriteBatch, ColumnFamily};
use tokio::sync::Notify;
use tracing::debug;
// internal
use crate::epoch_service::{Epoch, EpochSlice};
use crate::error::AppError;
use crate::rocksdb_operands::{EpochCounterDeserializer, EpochIncr, EpochIncrSerializer, counter_operands, EpochCounterSerializer};
use crate::tier::{ValidateTierLimitsError, TierLimit, TierLimits, TierName};
use crate::user_db_serialization::{
    MerkleTreeIndexSerializer, RlnUserIdentityDeserializer, RlnUserIdentitySerializer,
    TierDeserializer, TierLimitsDeserializer, TierLimitsSerializer,
};
use crate::user_db_types::{EpochCounter, EpochSliceCounter, MerkleTreeIndex, RateLimit};
use crate::user_db_error::{RegisterError2, SetTierLimitsError, TxCounterError, UserDbOpenError, UserTierInfoError};
use rln_proof::RlnUserIdentity;
use smart_contract::{KarmaAmountExt, Tier, TierIndex};

pub const USER_CF: &str = "user";
pub const TX_COUNTER_CF: &str = "tx_counter";
pub const TIER_LIMITS_CF: &str = "tier_limits";

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

const TIER_LIMITS_KEY: &[u8; 7] = b"CURRENT";
const TIER_LIMITS_NEXT_KEY: &[u8; 4] = b"NEXT";

#[derive(Debug, Clone)]
struct UserRocksDb {
    db: Arc<DB>,
    // merkle_tree: Arc<RwLock<PmTree>>,
    rate_limit: RateLimit,
    epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>,
}

impl UserRocksDb {
    
    /// Returns a new `UserRocksDB` instance
    pub fn new(
        db_path: PathBuf,
        tier_limits: TierLimits,
        epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>,
    ) -> Result<Self, UserDbOpenError> {
        
        let db_options = {
            let mut db_opts = Options::default();
            db_opts.set_max_open_files(820);
            db_opts.create_if_missing(true);
            db_opts.create_missing_column_families(true);
            db_opts
        };
        
        let mut tx_counter_cf_opts = Options::default();
        tx_counter_cf_opts.set_merge_operator_associative("counter operator", counter_operands);

        let db = DB::open_cf_descriptors(
            &db_options,
            db_path,
            vec![
                // Db column for users, key: User address, value: RlnUserIdentity
                ColumnFamilyDescriptor::new(USER_CF, Options::default()),
                // Db column for user tx counters, key: User address, value: EpochCounters
                ColumnFamilyDescriptor::new(TX_COUNTER_CF, tx_counter_cf_opts.clone()),
                // Db column for tier limits - key: current && next, value: TierLimits
                // Note: only 2 keys in this column
                ColumnFamilyDescriptor::new(TIER_LIMITS_CF, Options::default()),
            ],
        )?;

        debug_assert!(tier_limits.validate().is_ok());
        let tier_limits_serializer = TierLimitsSerializer::default();
        let mut buffer = Vec::with_capacity(tier_limits_serializer.size_hint(tier_limits.len()));
        tier_limits_serializer.serialize(&tier_limits, &mut buffer)?;

        // unwrap safe - db is always created with this column
        let cf = db.cf_handle(TIER_LIMITS_CF).unwrap();
        db.delete_cf(cf, TIER_LIMITS_NEXT_KEY.as_slice())?;
        db.put_cf(cf, TIER_LIMITS_KEY.as_slice(), buffer)?;

        Ok(Self {
            db: Arc::new(db),
            rate_limit: Default::default(),
            epoch_store,
        })
    }

    fn get_user_cf(&self) -> &ColumnFamily {
        // unwrap safe - db is always created with this column
        self.db.cf_handle(USER_CF).unwrap()
    }
    
    fn get_counter_cf(&self) -> &ColumnFamily {
        // unwrap safe - db is always created with this column 
        self.db.cf_handle(TX_COUNTER_CF).unwrap()
    }
    
    fn get_tier_limits_cf(&self) -> &ColumnFamily {
        // unwrap safe - db is always created with this column 
        self.db.cf_handle(TIER_LIMITS_CF).unwrap()
    }
    
    fn register(&self, address: Address) -> Result<Fr, RegisterError2> {
        
        let rln_identity_serializer = RlnUserIdentitySerializer {};
        let merkle_index_serializer = MerkleTreeIndexSerializer {};

        let (identity_secret_hash, id_commitment) = keygen();
        let index = 1;

        let rln_identity = RlnUserIdentity::from((
            identity_secret_hash,
            id_commitment,
            Fr::from(self.rate_limit),
        ));

        let key = address.as_slice();
        let mut buffer =
            vec![0; rln_identity_serializer.size_hint() + merkle_index_serializer.size_hint()];
        
        // unwrap safe - this is serialized by the Prover + RlnUserIdentitySerializer is unit tested
        rln_identity_serializer.serialize(&rln_identity, &mut buffer).unwrap();
        merkle_index_serializer.serialize(&MerkleTreeIndex::from(index), &mut buffer);

        let cf_user = self.get_user_cf();
        
        match self.db.get_cf(cf_user, key) {
            Ok(Some(_)) => {
                return Err(RegisterError2::AlreadyRegistered(address));
            }
            Ok(None) => {

                let cf_counter = self.get_counter_cf();
                let mut db_batch = WriteBatch::new();
                db_batch.put_cf(cf_user, key, buffer.as_slice());
                db_batch.put_cf(cf_counter, key, EpochCounterSerializer::default().as_slice());
                
                self.db
                    .write(db_batch)
                    .map_err(RegisterError2::Db)?;
            }
            Err(e) => {
                return Err(RegisterError2::Db(e));
            }
        }

        // TODO / FIXME
        let _rate_commit = poseidon_hash(&[id_commitment, Fr::from(u64::from(self.rate_limit))]);
        // TODO: merkle tree
        Ok(id_commitment)
    }

    fn has_user(&self, address: Address) -> Result<bool, rocksdb::Error> {
        let cf_user = self.get_user_cf();
        self.db
            .get_pinned_cf(cf_user, address.as_slice())
            .map(|value| value.is_some())
    }

    pub fn get_user(&self, address: Address) -> Option<RlnUserIdentity> {
        let cf_user = self.get_user_cf();
        let rln_identity_deserializer = RlnUserIdentityDeserializer {};
        match self.db.get_pinned_cf(cf_user, address.as_slice()) {
            Ok(Some(value)) => {
                // Here we silence the error - this is safe as the prover controls this
                rln_identity_deserializer.deserialize(&value).ok()
            }
            Ok(None) => None,
            Err(_e) => None,
        }
    }

    fn incr_tx_counter(
        &self,
        address: &Address,
        incr_value: Option<u64>,
    ) -> Result<(), TxCounterError> {
        
        let incr_value = incr_value.unwrap_or(1);
        let cf_counter = self.get_counter_cf();

        let (epoch, epoch_slice) = *self.epoch_store.read();
        // FIXME: no as
        let incr = EpochIncr {
            epoch: epoch.0 as u64,
            epoch_slice: epoch_slice.0 as u64,
            incr_value,
        };
        let incr_ser = EpochIncrSerializer {};
        let mut buffer = Vec::with_capacity(incr_ser.size_hint());
        incr_ser.serialize(&incr, &mut buffer);

        self.db
            .merge_cf(cf_counter, address.as_slice(), buffer)
            .map_err(TxCounterError::Db)
    }

    fn get_tx_counter(
        &self,
        address: &Address,
    ) -> Result<(EpochCounter, EpochSliceCounter), TxCounterError> {
        
        let deserializer = EpochCounterDeserializer {};
        let cf_counter = self.get_counter_cf();
        
        match self.db.get_cf(cf_counter, address.as_slice()) {
            Ok(Some(value)) => {
                let (_, counter) = deserializer.deserialize(&value).unwrap();
                let (epoch, epoch_slice) = *self.epoch_store.read();

                // TODO: no as
                let cmp = (
                    counter.epoch == epoch.0 as u64,
                    counter.epoch_slice == epoch_slice.0 as u64,
                );

                match cmp {
                    (true, true) => {
                        // EpochCounter stored in DB == epoch store 
                        // We query for an epoch / epoch slice and this is what is stored in the Db
                        // Return the counters
                        Ok((
                            counter.epoch_counter.into(),
                            counter.epoch_slice_counter.into(),
                        ))
                    },
                    (true, false) => {
                        // EpochCounter.epoch_slice (stored in Db) != epoch_store.epoch_slice
                        // We query for an epoch slice after what is stored in Db
                        // This can happen if no Tx has updated the epoch slice counter (yet)
                        Ok((counter.epoch_counter.into(), EpochSliceCounter::from(0)))
                    },
                    (false, true) => {
                        // EpochCounter.epoch (stored in DB) != epoch_store.epoch
                        // We query for an epoch after what is stored in Db
                        // This can happen if no Tx has updated the epoch counter (yet)
                        Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
                    },
                    (false, false) => {
                        // EpochCounter (stored in DB) != epoch_store
                        // Outdated value (both for epoch & epoch slice)
                        Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
                    },
                }
            }
            Ok(None) => {
                Err(TxCounterError::NotRegistered(*address))
            }
            Err(e) => Err(TxCounterError::Db(e)),
        }
    }

    // pub

    fn on_new_epoch(&self) {}

    fn on_new_epoch_slice(&self) {}

    pub fn on_new_user(&self, address: &Address) -> Result<Fr, RegisterError2> {
        self.register(address.clone())
    }

    pub fn get_merkle_proof(&self, address: &Address) -> Result<MerkleProof, RegisterError2> {
        todo!()
    }

    pub(crate) fn on_new_tx(&self, address: &Address, incr_value: Option<u64>) -> Result<(), TxCounterError> {
        
        let has_user = self.has_user(*address)
            .map_err(TxCounterError::Db)?;
        
        if has_user {
            self.incr_tx_counter(address, incr_value)
        } else {
            Err(TxCounterError::NotRegistered(*address))
        }
    }

    fn get_tier_limits(&self) -> Result<TierLimits, rocksdb::Error> {

        let cf = self.get_tier_limits_cf();
        // Unwrap safe - Db is initialized with valid tier limits
        let buffer = self.db.get_cf(cf, TIER_LIMITS_KEY.as_slice())?.unwrap();
        let tier_limits_deserializer = TierLimitsDeserializer {
            tier_deserializer: TierDeserializer {},
        };

        // Unwrap safe - serialized by the prover (should always deserialize)
        let (_, tier_limits) = tier_limits_deserializer.deserialize(&buffer).unwrap();
        Ok(tier_limits)
    }

    pub(crate) fn on_new_tier(
        &self,
        tier_index: TierIndex,
        tier: Tier,
    ) -> Result<(), SetTierLimitsError> {

        let mut tier_limits = self.get_tier_limits()?;
        tier_limits.insert(tier_index, tier);
        tier_limits.validate()?;

        // Serialize
        let tier_limits_serializer = TierLimitsSerializer::default();
        let mut buffer = Vec::with_capacity(tier_limits_serializer.size_hint(tier_limits.len()));
        // Unwrap safe - already validated - should always serialize
        tier_limits_serializer.serialize(&tier_limits, &mut buffer).unwrap();

        // Write
        let cf = self.get_tier_limits_cf();
        self.db
            .put_cf(cf, TIER_LIMITS_NEXT_KEY.as_slice(), buffer)
            .map_err(SetTierLimitsError::Db)
    }

    pub(crate) fn on_tier_updated(
        &self,
        tier_index: TierIndex,
        tier: Tier,
    ) -> Result<(), SetTierLimitsError> {

        let mut tier_limits = self.get_tier_limits()?;
        if !tier_limits.contains_key(&tier_index) {
            return Err(SetTierLimitsError::InvalidUpdateTierIndex);
        }
        
        tier_limits.entry(tier_index).and_modify(|e| *e = tier);
        tier_limits.validate()?;

        // Serialize
        let tier_limits_serializer = TierLimitsSerializer::default();
        let mut buffer = Vec::with_capacity(tier_limits_serializer.size_hint(tier_limits.len()));
        // Unwrap safe - already validated - should always serialize
        tier_limits_serializer.serialize(&tier_limits, &mut buffer).unwrap();

        // Write
        let cf = self.get_tier_limits_cf();
        self.db
            .put_cf(cf, TIER_LIMITS_NEXT_KEY.as_slice(), buffer)
            .map_err(SetTierLimitsError::Db)?;

        Ok(())
    }

    /// Get user tier info
    pub(crate) async fn user_tier_info<E: std::error::Error, KSC: KarmaAmountExt<Error = E>>(
        &self,
        address: &Address,
        karma_sc: &KSC,
    ) -> Result<UserTierInfo, UserTierInfoError<E>> {

        let has_user = self.has_user(*address)
            .map_err(UserTierInfoError::Db)?;

        if !has_user {
            return Err(UserTierInfoError::NotRegistered(*address));
        }

        let (epoch_tx_count, epoch_slice_tx_count) = self.get_tx_counter(address)?;

        let karma_amount = karma_sc
            .karma_amount(address)
            .await
            .map_err(|e| UserTierInfoError::Contract(e))?;

        let tier_limits = self.get_tier_limits()?;
        let tier_info = tier_limits.get_tier_by_karma(&karma_amount);
        
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
                t.tier_limit = Some(tier.tx_per_epoch.into());
            }
            t
        };

        Ok(user_tier_info)
    }
}

/// Async service to update a UserDb on epoch changes
#[derive(Debug)]
pub struct UserDbService2 {
    user_db: UserRocksDb,
    epoch_changes: Arc<Notify>,
}

impl UserDbService2 {
    pub fn new(
        db_path: PathBuf,
        epoch_changes_notifier: Arc<Notify>,
        epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>,
        rate_limit: RateLimit,
        tier_limits: TierLimits,
    ) -> Result<Self, UserDbOpenError> {
        
        let user_db = UserRocksDb::new(db_path, tier_limits, epoch_store)?;
        Ok(Self {
            user_db,
            epoch_changes: epoch_changes_notifier,
        })
    }

    pub fn get_user_db(&self) -> UserRocksDb {
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
    // internal
    use crate::tier::TierName;
    use crate::user_db_serialization::{TierDeserializer, TierSerializer};

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
        let temp_folder = tempfile::tempdir().unwrap();
        let epoch_store = Arc::new(RwLock::new(Default::default()));
        let user_db = UserRocksDb::new(
            PathBuf::from(temp_folder.path()),
            Default::default(),
            epoch_store,
        ).unwrap();

        let addr = Address::new([0; 20]);
        user_db.register(addr).unwrap();
        assert_matches!(
            user_db.register(addr),
            Err(RegisterError2::AlreadyRegistered(_))
        );

        assert!(user_db.get_user(addr).is_some());
        assert_eq!(user_db.get_tx_counter(&addr).unwrap(), (0.into(), 0.into()));

        assert!(user_db.get_user(ADDR_1).is_none());
        user_db.register(ADDR_1).unwrap();

        // TODO: split unit test
        assert!(user_db.get_user(ADDR_1).is_some());
        assert_eq!(user_db.get_tx_counter(&addr).unwrap(), (0.into(), 0.into()));
        user_db.incr_tx_counter(&addr, Some(42)).unwrap();
        assert_eq!(
            user_db.get_tx_counter(&addr).unwrap(),
            (42.into(), 42.into())
        );
    }

    #[tokio::test]
    async fn test_incr_tx_counter() {
        let temp_folder = tempfile::tempdir().unwrap();
        let epoch_store = Arc::new(RwLock::new(Default::default()));
        let user_db = UserRocksDb::new(
            PathBuf::from(temp_folder.path()),
            Default::default(),
            epoch_store,
        ).unwrap();

        let addr = Address::new([0; 20]);

        // Try to update tx counter without registering first
        assert_matches!(user_db.on_new_tx(&addr, None), Err(TxCounterError::NotRegistered(_)));

        let tier_info = user_db.user_tier_info(&addr, &MockKarmaSc {}).await;
        // User is not registered -> no tier info
        assert!(matches!(
            tier_info,
            Err(UserTierInfoError::NotRegistered(_))
        ));
        // Register user
        user_db.register(addr).unwrap();
        // Now update user tx counter
        assert_matches!(user_db.on_new_tx(&addr, None), Ok(()));
        let tier_info = user_db
            .user_tier_info(&addr, &MockKarmaSc {})
            .await
            .unwrap();
        assert_eq!(tier_info.epoch_tx_count, 1);
        assert_eq!(tier_info.epoch_slice_tx_count, 1);
    }
    #[tokio::test]
    async fn test_update_on_epoch_changes() {
        let temp_folder = tempfile::tempdir().unwrap();
        let mut epoch = Epoch::from(11);
        let mut epoch_slice = EpochSlice::from(42);
        let epoch_store = Arc::new(RwLock::new((epoch, epoch_slice)));

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
                    name: "Active".into(),
                    min_karma: U256::from(50),
                    max_karma: U256::from(99),
                    tx_per_epoch: 10,
                    active: true,
                },
            ),
            (
                TierIndex::from(3),
                Tier {
                    name: "Regular".into(),
                    min_karma: U256::from(100),
                    max_karma: U256::from(499),
                    tx_per_epoch: 15,
                    active: true,
                },
            ),
            (
                TierIndex::from(4),
                Tier {
                    name: "Power User".into(),
                    min_karma: U256::from(500),
                    max_karma: U256::from(4999),
                    tx_per_epoch: 20,
                    active: true,
                },
            ),
            (
                TierIndex::from(5),
                Tier {
                    name: "S-Tier".into(),
                    min_karma: U256::from(5000),
                    max_karma: U256::from(9999),
                    tx_per_epoch: 25,
                    active: true,
                },
            ),
        ]);
        
        let tier_limits: TierLimits = tier_limits.into();
        tier_limits.validate().unwrap();

        let user_db_service = UserDbService2::new(
            temp_folder.path().to_path_buf(),
            Default::default(),
            epoch_store.clone(),
            10.into(),
            tier_limits,
        ).unwrap();
        let user_db = user_db_service.get_user_db();

        let addr_1_tx_count = 2;
        let addr_2_tx_count = 820;
        user_db.register(ADDR_1).unwrap();
        user_db.incr_tx_counter(&ADDR_1, Some(addr_1_tx_count));
        println!("user_db tx counter: {:?}", user_db.get_tx_counter(&ADDR_1));
        user_db.register(ADDR_2).unwrap();
        user_db.incr_tx_counter(&ADDR_2, Some(addr_2_tx_count));

        // incr epoch slice (42 -> 43)
        {
            let new_epoch = epoch;
            let new_epoch_slice = epoch_slice + 1;
            // FIXME: UserRocksDb rely on EpochStore so is there still need for this func?
            user_db_service.update_on_epoch_changes(
                &mut epoch,
                new_epoch,
                &mut epoch_slice,
                new_epoch_slice,
            );

            let mut guard = epoch_store.write();
            *guard = (new_epoch, epoch_slice);
            drop(guard);

            // FIXME / TODO
            // Pb: we get the tx counter but we would need to specify the epoch / epoch slice
            //     or get_tx_counter check against the current epoch / epoch_slice
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
            // FIXME: same here
            user_db_service.update_on_epoch_changes(
                &mut epoch,
                new_epoch,
                &mut epoch_slice,
                new_epoch_slice,
            );
            let mut guard = epoch_store.write();
            *guard = (new_epoch, epoch_slice);
            drop(guard);

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
}
