use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
// third-party
use alloy::primitives::{Address, U256};
use ark_bn254::Fr;
use claims::debug_assert_lt;
use parking_lot::RwLock;
use rln::{
    hashers::poseidon_hash,
    pm_tree_adapter::PmtreeConfig,
    poseidon_tree::{MerkleProof, PoseidonTree},
    protocol::keygen,
};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, Options, ReadOptions, WriteBatch, WriteBatchWithIndex,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch::Receiver;
use tracing::error;
// internal
use crate::epoch_service::{Epoch, EpochSlice};
use crate::error::GetMerkleTreeProofError;
use crate::rocksdb_operands::{
    EpochCounterDeserializer, EpochCounterSerializer, EpochIncr, EpochIncrSerializer,
    epoch_counters_operands, u64_counter_operands,
};
use crate::tier::{TierLimit, TierLimits, TierMatch, TierName};
use crate::user_db_error::{
    MerkleTreeIndexError, RegisterError, SetTierLimitsError, TxCounterError, UserDbOpenError,
    UserMerkleTreeIndexError, UserTierInfoError,
};
use crate::user_db_serialization::{
    MerkleTreeIndexDeserializer, MerkleTreeIndexSerializer, RlnUserIdentityDeserializer,
    RlnUserIdentitySerializer, TierDeserializer, TierLimitsDeserializer, TierLimitsSerializer,
};
use crate::user_db_types::{EpochCounter, EpochSliceCounter, MerkleTreeIndex, RateLimit};
use rln_proof::{RlnUserIdentity, ZerokitMerkleTree};
use smart_contract::{KarmaAmountExt, Tier, TierIndex};

const MERKLE_TREE_HEIGHT: usize = 20;
pub const USER_CF: &str = "user";
pub const MERKLE_TREE_COUNTER_CF: &str = "mtree";
pub const TX_COUNTER_CF: &str = "tx_counter";
pub const TIER_LIMITS_CF: &str = "tier_limits";

const MERKLE_TREE_INDEX_KEY: &[u8; 4] = b"TREE";
const TIER_LIMITS_KEY: &[u8; 7] = b"CURRENT";
const TIER_LIMITS_NEXT_KEY: &[u8; 4] = b"NEXT";

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

#[derive(Serialize, Deserialize)]
struct PmTreeConfigJson {
    path: PathBuf,
    temporary: bool,
    cache_capacity: u64,
    flush_every_ms: u64,
    mode: String,
    use_compression: bool,
}

#[derive(Clone)]
pub(crate) struct UserDb {
    db: Arc<DB>,
    merkle_tree: Arc<RwLock<PoseidonTree>>,
    rate_limit: RateLimit,
    pub(crate) epoch_changes: Receiver<(Epoch, EpochSlice)>,
}

impl std::fmt::Debug for UserDb {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("UserDb")
            .field("db", &self.db)
            .field("rate limit", &self.rate_limit)
            .field("epoch changes", &self.epoch_changes)
            .finish()
    }
}

impl UserDb {
    /// Returns a new `UserRocksDB` instance
    pub fn new(
        db_path: PathBuf,
        merkle_tree_path: PathBuf,
        epoch_changes: Receiver<(Epoch, EpochSlice)>,
        tier_limits: TierLimits,
        rate_limit: RateLimit,
    ) -> Result<Self, UserDbOpenError> {
        let db_options = {
            let mut db_opts = Options::default();
            db_opts.set_max_open_files(820);
            db_opts.create_if_missing(true);
            db_opts.create_missing_column_families(true);
            db_opts
        };

        let mut tx_counter_cf_opts = Options::default();
        tx_counter_cf_opts
            .set_merge_operator_associative("counters operator", epoch_counters_operands);
        let mut user_mtree_cf_opts = Options::default();
        user_mtree_cf_opts.set_merge_operator_associative("counter operator", u64_counter_operands);

        let db = DB::open_cf_descriptors(
            &db_options,
            db_path,
            vec![
                // Db column for users, key: User address, value: RlnUserIdentity + MerkleTreeIndex
                ColumnFamilyDescriptor::new(USER_CF, Options::default()),
                // Db column for merkle tree index, key: tree, value: counter
                ColumnFamilyDescriptor::new(MERKLE_TREE_COUNTER_CF, user_mtree_cf_opts),
                // Db column for user tx counters, key: User address, value: EpochCounters
                ColumnFamilyDescriptor::new(TX_COUNTER_CF, tx_counter_cf_opts),
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

        let db = Arc::new(db);

        // merkle tree index

        let cf_mtree = db.cf_handle(MERKLE_TREE_COUNTER_CF).unwrap();
        if let Err(e) = Self::get_merkle_tree_index_(db.clone(), cf_mtree) {
            match e {
                MerkleTreeIndexError::DbUninitialized => {
                    // Check if the value is already there (e.g. after a restart)
                    // if not, we create it
                    db.merge_cf(cf_mtree, MERKLE_TREE_INDEX_KEY, 0u64.to_le_bytes())?;
                }
                _ => return Err(UserDbOpenError::MerkleTreeIndex(e)),
            }
        }

        // merkle tree

        let config_ = PmTreeConfigJson {
            path: merkle_tree_path,
            temporary: false,
            cache_capacity: 100_000,
            flush_every_ms: 12_000,
            mode: "HighThroughput".to_string(),
            use_compression: false,
        };
        let config_str = serde_json::to_string(&config_)?;
        // Note: in Zerokit 0.8 this is the only way to initialize a PmTreeConfig
        let config = PmtreeConfig::from_str(config_str.as_str())?;
        let tree = PoseidonTree::new(MERKLE_TREE_HEIGHT, Default::default(), config)?;

        Ok(Self {
            db,
            merkle_tree: Arc::new(RwLock::new(tree)),
            rate_limit,
            epoch_changes,
        })
    }

    fn get_user_cf(&self) -> &ColumnFamily {
        // unwrap safe - db is always created with this column
        self.db.cf_handle(USER_CF).unwrap()
    }

    fn get_mtree_cf(&self) -> &ColumnFamily {
        // unwrap safe - db is always created with this column
        self.db.cf_handle(MERKLE_TREE_COUNTER_CF).unwrap()
    }

    fn get_counter_cf(&self) -> &ColumnFamily {
        // unwrap safe - db is always created with this column
        self.db.cf_handle(TX_COUNTER_CF).unwrap()
    }

    fn get_tier_limits_cf(&self) -> &ColumnFamily {
        // unwrap safe - db is always created with this column
        self.db.cf_handle(TIER_LIMITS_CF).unwrap()
    }

    fn register(&self, address: Address) -> Result<Fr, RegisterError> {
        let rln_identity_serializer = RlnUserIdentitySerializer {};
        let merkle_index_serializer = MerkleTreeIndexSerializer {};
        let merkle_index_deserializer = MerkleTreeIndexDeserializer {};

        let (identity_secret_hash, id_commitment) = keygen();

        let rln_identity = RlnUserIdentity::from((
            identity_secret_hash,
            id_commitment,
            Fr::from(self.rate_limit),
        ));

        let key = address.as_slice();
        let mut buffer =
            vec![0; rln_identity_serializer.size_hint() + merkle_index_serializer.size_hint()];

        // unwrap safe - this is serialized by the Prover + RlnUserIdentitySerializer is unit tested
        rln_identity_serializer
            .serialize(&rln_identity, &mut buffer)
            .unwrap();

        let cf_user = self.get_user_cf();

        let _index = match self.db.get_cf(cf_user, key) {
            Ok(Some(_)) => {
                return Err(RegisterError::AlreadyRegistered(address));
            }
            Ok(None) => {
                let rate_commit =
                    poseidon_hash(&[id_commitment, Fr::from(u64::from(self.rate_limit))]);

                let cf_mtree = self.get_mtree_cf();
                let cf_counter = self.get_counter_cf();

                // Note: this should be updated with everything added to db_batch
                debug_assert_lt!(
                    MERKLE_TREE_INDEX_KEY.len()
                        + size_of::<u64>()
                        + (2 * size_of::<Address>())
                        + EpochCounterSerializer::size_hint_()
                        + buffer.len(),
                    1024
                );
                let mut db_batch = WriteBatchWithIndex::new(1024, true);

                // Read the new index
                // Unwrap safe - just used merge_cf
                let batch_read = db_batch
                    .get_from_batch_and_db_cf(
                        &*self.db,
                        cf_mtree,
                        MERKLE_TREE_INDEX_KEY,
                        &ReadOptions::default(),
                    )?
                    .unwrap();
                // Increase merkle tree index
                db_batch.merge_cf(cf_mtree, MERKLE_TREE_INDEX_KEY, 1i64.to_le_bytes());
                // Unwrap safe - serialization is handled by the prover
                let (_, new_index) = merkle_index_deserializer
                    .deserialize(batch_read.as_slice())
                    .unwrap();

                // Note: write to Merkle tree in the Db transaction so if the write fails
                //       the Db transaction will also fails
                self.merkle_tree
                    .write()
                    .set(new_index.into(), rate_commit)
                    .map_err(|e| RegisterError::TreeError(e.to_string()))?;

                // Add index for user
                merkle_index_serializer.serialize(&new_index, &mut buffer);
                // Put user
                db_batch.put_cf(cf_user, key, buffer.as_slice());
                // Put user tx counter
                db_batch.put_cf(
                    cf_counter,
                    key,
                    EpochCounterSerializer::default().as_slice(),
                );

                self.db.write_wbwi(&db_batch).map_err(RegisterError::Db)?;
                new_index
            }
            Err(e) => {
                return Err(RegisterError::Db(e));
            }
        };

        Ok(id_commitment)
    }

    fn has_user(&self, address: &Address) -> Result<bool, rocksdb::Error> {
        let cf_user = self.get_user_cf();
        self.db
            .get_pinned_cf(cf_user, address.as_slice())
            .map(|value| value.is_some())
    }

    pub fn get_user(&self, address: &Address) -> Option<RlnUserIdentity> {
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

    pub fn get_user_merkle_tree_index(
        &self,
        address: &Address,
    ) -> Result<MerkleTreeIndex, UserMerkleTreeIndexError> {
        let cf_user = self.get_user_cf();
        let rln_identity_serializer = RlnUserIdentitySerializer {};
        let merkle_tree_index_deserializer = MerkleTreeIndexDeserializer {};
        match self.db.get_pinned_cf(cf_user, address.as_slice()) {
            Ok(Some(buffer)) => {
                // Here we silence the error - this is safe as the prover controls this
                let start = rln_identity_serializer.size_hint();
                let (_, index) = merkle_tree_index_deserializer
                    .deserialize(&buffer[start..])
                    .unwrap();
                Ok(index)
            }
            Ok(None) => Err(UserMerkleTreeIndexError::NotRegistered(*address)),
            Err(e) => Err(UserMerkleTreeIndexError::Db(e)),
        }
    }

    /// Remove user
    ///
    /// Warning: don't use this func. if user is registered in a smart contract (unless you == 💪)
    ///          This function is intended to be used if registration to the smart contract fails
    pub(crate) fn remove_user(&self, address: &Address, sc_registered: bool) -> bool {
        let cf_user = self.get_user_cf();
        let cf_counter = self.get_counter_cf();

        let mut db_batch = WriteBatch::new();

        if !sc_registered {
            let user_index = self.get_user_merkle_tree_index(address);
            let user_index = match user_index {
                Ok(user_index) => user_index,
                Err(UserMerkleTreeIndexError::NotRegistered(_)) => {
                    return true;
                }
                _ => {
                    error!("Error getting user index: {:?}", user_index);
                    return false;
                }
            };

            if usize::from(user_index) == self.merkle_tree.read().leaves_set() {
                // Only delete it if this is the last index
                if let Err(e) = self.merkle_tree.write().delete(user_index.into()) {
                    error!("Error deleting user in merkle tree: {:?}", e);
                    return false;
                }
            }
        }

        // Remove user
        db_batch.delete_cf(cf_user, address.as_slice());
        // Remove user tx counter
        db_batch.delete_cf(cf_counter, address.as_slice());
        self.db.write(db_batch).unwrap();

        true
    }

    fn incr_tx_counter(
        &self,
        address: &Address,
        incr_value: Option<u64>,
    ) -> Result<EpochSliceCounter, TxCounterError> {
        let incr_value = incr_value.unwrap_or(1);
        let cf_counter = self.get_counter_cf();

        let (epoch, epoch_slice) = { *self.epoch_changes.borrow() };
        let incr = EpochIncr {
            epoch,
            epoch_slice,
            incr_value,
        };
        let incr_ser = EpochIncrSerializer {};
        let mut buffer = Vec::with_capacity(incr_ser.size_hint());
        incr_ser.serialize(&incr, &mut buffer);

        // Create a transaction
        // By using a WriteBatchWithIndex, we can "read your own writes" so here we incr then read the new value
        // https://rocksdb.org/blog/2015/02/27/write-batch-with-index.html
        let mut batch = WriteBatchWithIndex::new(buffer.len() + size_of::<Address>(), true);
        batch.merge_cf(cf_counter, address.as_slice(), buffer);
        let res = batch.get_from_batch_and_db_cf(
            &*self.db,
            cf_counter,
            address.as_slice(),
            &ReadOptions::default(),
        )?;
        self.db.write_wbwi(&batch).map_err(TxCounterError::Db)?;
        let (_, epoch_slice_counter) = self.counters_from_key(address, res)?;

        Ok(epoch_slice_counter)
    }

    fn get_tx_counter(
        &self,
        address: &Address,
    ) -> Result<(EpochCounter, EpochSliceCounter), TxCounterError> {
        let cf_counter = self.get_counter_cf();
        match self.db.get_cf(cf_counter, address.as_slice()) {
            Ok(v) => self.counters_from_key(address, v),
            Err(e) => Err(TxCounterError::Db(e)),
        }
    }

    fn counters_from_key(
        &self,
        address: &Address,
        key: Option<Vec<u8>>,
    ) -> Result<(EpochCounter, EpochSliceCounter), TxCounterError> {
        let deserializer = EpochCounterDeserializer {};

        match key {
            Some(value) => {
                let (_, counter) = deserializer.deserialize(&value).unwrap();
                let (epoch, epoch_slice) = { *self.epoch_changes.borrow() };

                let cmp = (counter.epoch == epoch, counter.epoch_slice == epoch_slice);

                match cmp {
                    (true, true) => {
                        // EpochCounter stored in DB == epoch store
                        // We query for an epoch / epoch slice and this is what is stored in the Db
                        // Return the counters
                        Ok((
                            counter.epoch_counter.into(),
                            counter.epoch_slice_counter.into(),
                        ))
                    }
                    (true, false) => {
                        // EpochCounter.epoch_slice (stored in Db) != epoch_store.epoch_slice
                        // We query for an epoch slice after what is stored in Db
                        // This can happen if no Tx has updated the epoch slice counter (yet)
                        Ok((counter.epoch_counter.into(), EpochSliceCounter::from(0)))
                    }
                    (false, true) => {
                        // EpochCounter.epoch (stored in DB) != epoch_store.epoch
                        // We query for an epoch after what is stored in Db
                        // This can happen if no Tx has updated the epoch counter (yet)
                        Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
                    }
                    (false, false) => {
                        // EpochCounter (stored in DB) != epoch_store
                        // Outdated value (both for epoch & epoch slice)
                        Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
                    }
                }
            }
            None => Err(TxCounterError::NotRegistered(*address)),
        }
    }

    // pub

    pub(crate) fn on_new_epoch(&self) {}

    pub(crate) fn on_new_epoch_slice(&self) {}

    pub fn on_new_user(&self, address: &Address) -> Result<Fr, RegisterError> {
        self.register(*address)
    }

    #[cfg(test)]
    fn get_merkle_tree_index(&self) -> Result<MerkleTreeIndex, MerkleTreeIndexError> {
        let cf_mtree = self.get_mtree_cf();
        Self::get_merkle_tree_index_(self.db.clone(), cf_mtree)
    }

    fn get_merkle_tree_index_(
        db: Arc<DB>,
        cf: &ColumnFamily,
    ) -> Result<MerkleTreeIndex, MerkleTreeIndexError> {
        let deserializer = MerkleTreeIndexDeserializer {};

        match db.get_cf(cf, MERKLE_TREE_INDEX_KEY) {
            Ok(Some(v)) => {
                // Unwrap safe - serialization is done by the prover
                let (_, index) = deserializer.deserialize(v.as_slice()).unwrap();
                Ok(index)
            }
            Ok(None) => Err(MerkleTreeIndexError::DbUninitialized),
            Err(e) => Err(MerkleTreeIndexError::Db(e)),
        }
    }

    pub fn get_merkle_proof(
        &self,
        address: &Address,
    ) -> Result<MerkleProof, GetMerkleTreeProofError> {
        let index = self
            .get_user_merkle_tree_index(address)
            .map_err(GetMerkleTreeProofError::MerkleTree)?;
        self.merkle_tree
            .read()
            .proof(index.into())
            .map_err(|e| GetMerkleTreeProofError::TreeError(e.to_string()))
    }

    pub(crate) fn on_new_tx(
        &self,
        address: &Address,
        incr_value: Option<u64>,
    ) -> Result<EpochSliceCounter, TxCounterError> {
        let has_user = self.has_user(address).map_err(TxCounterError::Db)?;

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
        tier_limits_serializer
            .serialize(&tier_limits, &mut buffer)
            .unwrap();

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
        tier_limits_serializer
            .serialize(&tier_limits, &mut buffer)
            .unwrap();

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
        let has_user = self.has_user(address).map_err(UserTierInfoError::Db)?;

        if !has_user {
            return Err(UserTierInfoError::NotRegistered(*address));
        }

        let (epoch_tx_count, epoch_slice_tx_count) = self.get_tx_counter(address)?;

        let karma_amount = karma_sc
            .karma_amount(address)
            .await
            .map_err(|e| UserTierInfoError::Contract(e))?;

        let tier_limits = self.get_tier_limits()?;
        let tier_match = tier_limits.get_tier_by_karma(&karma_amount);

        let user_tier_info = {
            let (current_epoch, current_epoch_slice) = { *self.epoch_changes.borrow() };
            let mut t = UserTierInfo {
                current_epoch,
                current_epoch_slice,
                epoch_tx_count: epoch_tx_count.into(),
                epoch_slice_tx_count: epoch_slice_tx_count.into(),
                karma_amount,
                tier_name: None,
                tier_limit: None,
            };

            // FIXME: Proto changes to return AboveHighest / UnderLowest
            if let TierMatch::Matched(_tier_index, tier) = tier_match {
                t.tier_name = Some(tier.name.into());
                t.tier_limit = Some(TierLimit::from(tier.tx_per_epoch));
            }

            t
        };

        Ok(user_tier_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // third-party
    use alloy::primitives::address;
    use async_trait::async_trait;
    use claims::assert_matches;
    use derive_more::Display;
    use tokio::sync::watch::channel;

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

    /*
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
    */

    #[test]
    fn test_user_register() {
        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();
        let (_, epock_changes) = channel(Default::default());
        let user_db = UserDb::new(
            PathBuf::from(temp_folder.path()),
            PathBuf::from(temp_folder_tree.path()),
            epock_changes,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let addr = Address::new([0; 20]);
        user_db.register(addr).unwrap();
        assert_matches!(
            user_db.register(addr),
            Err(RegisterError::AlreadyRegistered(_))
        );

        assert!(user_db.get_user(&addr).is_some());
        assert_eq!(user_db.get_tx_counter(&addr).unwrap(), (0.into(), 0.into()));

        assert!(user_db.get_user(&ADDR_1).is_none());
        user_db.register(ADDR_1).unwrap();

        assert!(user_db.get_user(&ADDR_1).is_some());
        assert_eq!(user_db.get_tx_counter(&addr).unwrap(), (0.into(), 0.into()));
        user_db.incr_tx_counter(&addr, Some(42)).unwrap();
        assert_eq!(
            user_db.get_tx_counter(&addr).unwrap(),
            (42.into(), 42.into())
        );
    }

    #[test]
    fn test_get_tx_counter() {
        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();
        let (_, epock_changes) = channel(Default::default());
        let user_db = UserDb::new(
            PathBuf::from(temp_folder.path()),
            PathBuf::from(temp_folder_tree.path()),
            epock_changes,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let addr = Address::new([0; 20]);

        user_db.register(addr).unwrap();

        let (ec, ecs) = user_db.get_tx_counter(&addr).unwrap();
        assert_eq!(ec, 0.into());
        assert_eq!(ecs, 0.into());
        let ecs_2 = user_db.incr_tx_counter(&addr, Some(42)).unwrap();
        assert_eq!(ecs_2, 42.into());
    }

    #[tokio::test]
    async fn test_incr_tx_counter() {
        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();
        let (_, epock_changes) = channel(Default::default());
        let user_db = UserDb::new(
            PathBuf::from(temp_folder.path()),
            PathBuf::from(temp_folder_tree.path()),
            epock_changes,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let addr = Address::new([0; 20]);

        // Try to update tx counter without registering first
        assert_matches!(
            user_db.on_new_tx(&addr, None),
            Err(TxCounterError::NotRegistered(_))
        );

        let tier_info = user_db.user_tier_info(&addr, &MockKarmaSc {}).await;
        // User is not registered -> no tier info
        assert!(matches!(
            tier_info,
            Err(UserTierInfoError::NotRegistered(_))
        ));
        // Register user
        user_db.register(addr).unwrap();
        // Now update user tx counter
        assert_eq!(
            user_db.on_new_tx(&addr, None),
            Ok(EpochSliceCounter::from(1))
        );
        let tier_info = user_db
            .user_tier_info(&addr, &MockKarmaSc {})
            .await
            .unwrap();
        assert_eq!(tier_info.epoch_tx_count, 1);
        assert_eq!(tier_info.epoch_slice_tx_count, 1);
    }

    #[tokio::test]
    async fn test_persistent_storage() {
        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();
        let (_, epock_changes) = channel(Default::default());

        let addr = Address::new([0; 20]);
        {
            let user_db = UserDb::new(
                PathBuf::from(temp_folder.path()),
                PathBuf::from(temp_folder_tree.path()),
                epock_changes.clone(),
                Default::default(),
                Default::default(),
            )
            .unwrap();

            assert_eq!(
                user_db.get_merkle_tree_index().unwrap(),
                MerkleTreeIndex::from(0)
            );
            // Register user
            user_db.register(ADDR_1).unwrap();
            assert_eq!(
                user_db.get_merkle_tree_index().unwrap(),
                MerkleTreeIndex::from(1)
            );
            // + 1 user
            user_db.register(ADDR_2).unwrap();
            assert_eq!(
                user_db.get_merkle_tree_index().unwrap(),
                MerkleTreeIndex::from(2)
            );
            assert_eq!(
                user_db.get_user_merkle_tree_index(&ADDR_1).unwrap(),
                MerkleTreeIndex::from(0)
            );
            assert_eq!(
                user_db.get_user_merkle_tree_index(&ADDR_2).unwrap(),
                MerkleTreeIndex::from(1)
            );

            assert_eq!(
                user_db.on_new_tx(&ADDR_1, Some(2)),
                Ok(EpochSliceCounter::from(2))
            );
            assert_eq!(
                user_db.on_new_tx(&ADDR_2, Some(1000)),
                Ok(EpochSliceCounter::from(1000))
            );

            // Should be dropped but let's make it explicit
            drop(user_db);
        }

        {
            // Reopen Db and check that is inside
            let user_db = UserDb::new(
                PathBuf::from(temp_folder.path()),
                PathBuf::from(temp_folder_tree.path()),
                epock_changes,
                Default::default(),
                Default::default(),
            )
            .unwrap();

            assert_eq!(user_db.has_user(&addr).unwrap(), false);
            assert_eq!(user_db.has_user(&ADDR_1).unwrap(), true);
            assert_eq!(user_db.has_user(&ADDR_2).unwrap(), true);
            assert_eq!(
                user_db.get_tx_counter(&ADDR_1).unwrap(),
                (2.into(), 2.into())
            );
            assert_eq!(
                user_db.get_tx_counter(&ADDR_2).unwrap(),
                (1000.into(), 1000.into())
            );

            assert_eq!(
                user_db.get_merkle_tree_index().unwrap(),
                MerkleTreeIndex::from(2)
            );
            assert_eq!(
                user_db.get_user_merkle_tree_index(&ADDR_1).unwrap(),
                MerkleTreeIndex::from(0)
            );
            assert_eq!(
                user_db.get_user_merkle_tree_index(&ADDR_2).unwrap(),
                MerkleTreeIndex::from(1)
            );
        }
    }

    #[test]
    fn test_user_reg_merkle_tree_fail() {
        // Try to register some users but init UserDb so the merkle tree write will fail (after 1st register)
        // This tests ensures that the DB and the MerkleTree stays in sync

        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();
        let (_, epoch_changes) = channel(Default::default());

        let mut user_db = UserDb::new(
            PathBuf::from(temp_folder.path()),
            PathBuf::from(temp_folder_tree.path()),
            epoch_changes,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let temp_folder_tree_2 = tempfile::tempdir().unwrap();
        let config_ = PmTreeConfigJson {
            path: temp_folder_tree_2.path().to_path_buf(),
            temporary: false,
            cache_capacity: 100_000,
            flush_every_ms: 12_000,
            mode: "HighThroughput".to_string(),
            use_compression: false,
        };
        let config_str = serde_json::to_string(&config_).unwrap();
        let config = PmtreeConfig::from_str(config_str.as_str()).unwrap();
        let tree = PoseidonTree::new(1, Default::default(), config).unwrap();
        let tree = Arc::new(RwLock::new(tree));
        user_db.merkle_tree = tree.clone();

        let addr = Address::new([0; 20]);

        assert_eq!(tree.read().leaves_set(), 0);
        user_db.register(addr).unwrap();
        assert_eq!(tree.read().leaves_set(), 1);
        user_db.register(ADDR_1).unwrap();
        assert_eq!(tree.read().leaves_set(), 2);

        let res = user_db.register(ADDR_2);
        assert_matches!(res, Err(RegisterError::TreeError(_)));
        assert_eq!(user_db.has_user(&ADDR_1), Ok(true));
        assert_eq!(user_db.has_user(&ADDR_2), Ok(false));
        assert_eq!(tree.read().leaves_set(), 2);
    }

    #[test]
    fn test_user_remove() {
        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();
        let (_, epoch_changes) = channel(Default::default());

        let user_db = UserDb::new(
            PathBuf::from(temp_folder.path()),
            PathBuf::from(temp_folder_tree.path()),
            epoch_changes,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        user_db.register(ADDR_1).unwrap();
        let mtree_index_add_addr_1 = user_db.merkle_tree.read().leaves_set();
        user_db.register(ADDR_2).unwrap();
        let mtree_index_add_addr_2 = user_db.merkle_tree.read().leaves_set();
        assert_ne!(mtree_index_add_addr_1, mtree_index_add_addr_2);
        user_db.remove_user(&ADDR_2, false);
        let mtree_index_after_rm_addr_2 = user_db.merkle_tree.read().leaves_set();
        assert_eq!(user_db.has_user(&ADDR_1), Ok(true));
        assert_eq!(user_db.has_user(&ADDR_2), Ok(false));
        // No reuse of index in PmTree (as this is a generic impl and could lead to security issue:
        // like replay attack...)
        assert_eq!(mtree_index_after_rm_addr_2, mtree_index_add_addr_2);
    }
}
