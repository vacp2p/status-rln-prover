use std::path::{Path, PathBuf};
use std::collections::BTreeMap;
use std::string::FromUtf8Error;
use std::sync::Arc;
use alloy::primitives::{Address, U256};
use ark_bn254::Fr;
use derive_more::{From, Into};
use parking_lot::RwLock;
use rln::poseidon_tree::MerkleProof;
use rln::protocol::keygen;
use rln::utils::{bytes_le_to_fr, fr_to_bytes_le};
use rocksdb::{
    ColumnFamilyDescriptor, Options, WriteBatch,
    DB,
};
use nom::{
    Parser,
    multi::length_count,
    error::{
        context,
        ContextError
    },
    number::complete::le_u32,
    bytes::complete::take,
    IResult
};
use rln::hashers::poseidon_hash;
use tokio::sync::Notify;
use tracing::debug;
use rln_proof::RlnUserIdentity;
use smart_contract::{KarmaAmountExt, Tier, TierIndex};
use crate::epoch_service::{Epoch, EpochSlice};
use crate::error::AppError;
use crate::rocksdb_operands::{
    counter_operands,
    EpochCounterDeserializer,
    EpochIncr,
    EpochIncrSerializer
};
use crate::tier::TierLimits;
use crate::user_db_service::{EpochCounter, EpochSliceCounter, RateLimit, SetTierLimitsError, UserDb, UserRegistry, UserTierInfo, UserTierInfoError};

pub const USER_CF: &str = "user";
pub const TX_COUNTER_CF: &str = "tx_counter";
pub const TIER_LIMITS_CF: &str = "tier_limits";

#[derive(Debug, Clone, Copy, From, Into)]
struct MerkleTreeIndex(usize);

struct RlnUserIdentitySerializer {}

impl RlnUserIdentitySerializer {
    fn serialize(&self, value: &RlnUserIdentity, buffer: &mut Vec<u8>) {
        buffer.extend(fr_to_bytes_le(&value.commitment));
        buffer.extend(fr_to_bytes_le(&value.secret_hash));
        buffer.extend(fr_to_bytes_le(&value.user_limit));
    }

    fn size_hint(&self) -> usize {
        // Note: RlnUserIdentity has 3 fields of type 'Fr' (each = u256 = 32 bytes)
        32 * 3
    }
}

struct RlnUserIdentityDeserializer {}

impl RlnUserIdentityDeserializer {

    // FIXME: return a Result if buffer is not large enough?
    fn deserialize(&self, buffer: &[u8]) -> RlnUserIdentity {

        // TODO / optim - ark serialize
        let (commitment, offset) = bytes_le_to_fr(buffer);
        let (secret_hash, offset) = bytes_le_to_fr(&buffer[offset..]);
        let (user_limit, _offset) = bytes_le_to_fr(&buffer[offset..]);

        RlnUserIdentity {
            commitment,
            secret_hash,
            user_limit,
        }
    }
}

struct MerkleTreeIndexSerializer {}

impl MerkleTreeIndexSerializer {
    fn serialize(&self, value: &MerkleTreeIndex, buffer: &mut Vec<u8>) {
        buffer.extend(value.0.to_le_bytes());
    }

    fn size_hint(&self) -> usize {
        // Note: Assume usize size == 8 bytes
        8
    }
}

#[derive(Default)]
struct TierSerializer {}

impl TierSerializer {
    fn serialize(&self, value: &Tier, buffer: &mut Vec<u8>) {
        // TODO: can we use size_of::<U256> ?
        buffer.extend(value.min_karma.to_le_bytes::<32>().as_slice());
        buffer.extend(value.max_karma.to_le_bytes::<32>().as_slice());

        // TODO: no as
        let name_len = value.name.len() as u32;
        buffer.extend(name_len.to_le_bytes());
        buffer.extend(value.name.as_bytes());
        buffer.extend(value.tx_per_epoch.to_le_bytes().as_slice());
        buffer.push(u8::from(value.active))
    }

    fn size_hint(&self) -> usize {
        size_of::<Tier>()
    }
}

struct TierDeserializer {}

type nomError<'a> = nom::error::Error<&'a [u8]>;

#[derive(Debug, PartialEq)]
pub enum TierDeserializeError<I> {
    Utf8Error(FromUtf8Error),
    Nom(I, nom::error::ErrorKind),
}

impl<I> nom::error::ParseError<I> for TierDeserializeError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        TierDeserializeError::Nom(input, kind)
    }

    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I> ContextError<I> for TierDeserializeError<I> {}

impl TierDeserializer {
    fn deserialize<'a>(&self, buffer: &'a [u8]) -> IResult<&'a [u8], Tier, TierDeserializeError<&'a [u8]>> {

        let (input, min_karma) = take(32usize)(buffer)?;
        // TODO: fallible?
        let min_karma = U256::from_le_slice(min_karma);
        let (input, max_karma) = take(32usize)(input)?;
        // TODO: fallible?
        let max_karma = U256::from_le_slice(max_karma);
        let (input, name_len) = le_u32(input)?;
        // TODO: no as
        let name_len_ = name_len as usize;
        let (input, name) = take(name_len_)(input)?;
        let name = String::from_utf8(name.to_vec())
            .map_err(|e| nom::Err::Error(TierDeserializeError::Utf8Error(e)))?;
        let (input, tx_per_epoch) = le_u32(input)?;
        let (input, active) = take(1usize)(input)?;
        let active = !(active[0] == 0);

        Ok((input, Tier {
            min_karma,
            max_karma,
            name,
            tx_per_epoch,
            active,
        }))
    }
}

#[derive(Default)]
struct TierLimitsSerializer {
    tier_serializer: TierSerializer,
}

impl TierLimitsSerializer {
    fn serialize(&self, value: &TierLimits, buffer: &mut Vec<u8>) {

        let len = value.len() as u32;
        buffer.extend(len.to_le_bytes());

        let mut tier_buffer = Vec::with_capacity(self.tier_serializer.size_hint());

        value
            .iter()
            .for_each(|(k, v)| {
                buffer.push(k.into());
                self.tier_serializer.serialize(v, &mut tier_buffer);
                buffer.extend_from_slice(&tier_buffer);
                tier_buffer.clear();
            });
    }

    fn size_hint(&self, len: usize) -> usize {
        size_of::<u32>() + len * self.tier_serializer.size_hint()
    }
}

struct TierLimitsDeserializer {}

impl TierLimitsDeserializer {

    fn deserialize<'a>(&self, buffer: &'a [u8]) -> IResult<&'a [u8], TierLimits, TierDeserializeError<&'a [u8]>> {

        let deser = TierDeserializer {};
        let (input, tiers): (&[u8], Vec<(TierIndex, Tier)>) = length_count(
            le_u32,
            context(
                "Tier index & Tier deser", |input: &'a [u8]| {
                    let (input, tier_index) = take(1usize)(input)?;
                    let tier_index = TierIndex::from(tier_index[0]);
                    let (input, tier) = deser.deserialize(input)?;
                    Ok((input, (tier_index, tier)))
                }
            )
        ).parse(buffer)?;

        // FIXME: can avoid clone?
        let map = BTreeMap::from_iter(tiers.clone().into_iter());

        Ok((
            input,
            TierLimits::from(map)
        ))

    }
}


#[derive(thiserror::Error, Debug)]
pub enum RegisterError2 {
    #[error("User (address: {0:?}) has already been registered")]
    AlreadyRegistered(Address),
    #[error("Db error: {0}")]
    // DbError(String),
    DbError(String),
    #[error("Merkle tree error: {0}")]
    TreeError(String),
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
    pub fn new(db_path: PathBuf, tier_limits: TierLimits, epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>) -> Self {
        // TODO: try try_from impl
        let db_opts = Self::default_db_opts();
        // FIXME: no unwrap
        let mut db = Self::db_open(&db_path, db_opts).expect("rocksdb open error");

        // TODO: re-enable
        // debug_assert!(tier_limits.validate().is_ok());
        let tier_limits_serializer = TierLimitsSerializer::default();
        let mut buffer = Vec::with_capacity(tier_limits_serializer.size_hint(tier_limits.len()));
        tier_limits_serializer.serialize(&tier_limits, &mut buffer);

        // unwrap safe - db is always created with this column
        let cf = db.cf_handle(TIER_LIMITS_CF).unwrap();
        // TODO: no unwrap
        db.delete_cf(cf, TIER_LIMITS_NEXT_KEY.as_slice()).unwrap();
        db.put_cf(cf, TIER_LIMITS_KEY.as_slice(), buffer).unwrap();

        Self {
            db: Arc::new(db),
            rate_limit: Default::default(),
            epoch_store,
        }
    }

    pub fn default_db_opts() -> Options {
        let mut db_opts = Options::default();
        db_opts.set_max_open_files(820);
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts
    }

    fn db_open(db_path: &Path, db_opts: Options) -> Result<DB, rocksdb::Error> {
        
        let mut tx_counter_cf_opts = Options::default();
        // TODO: name
        tx_counter_cf_opts.set_merge_operator_associative(
            "counter merge operator",
            counter_operands
        );
        
        let db = DB::open_cf_descriptors(
            &db_opts,
            db_path,
            vec![
                ColumnFamilyDescriptor::new(USER_CF, Options::default()),
                ColumnFamilyDescriptor::new(TX_COUNTER_CF, tx_counter_cf_opts.clone()),
                ColumnFamilyDescriptor::new(TIER_LIMITS_CF, Options::default()),
            ],
        )?;

        Ok(db)
    }

    fn register(&self, address: Address) -> Result<Fr, RegisterError2> {

        let rln_identity_serializer = RlnUserIdentitySerializer {};
        let merke_index_serializer = MerkleTreeIndexSerializer {};

        let (identity_secret_hash, id_commitment) = keygen();
        let index = 1;

        let rln_identity = RlnUserIdentity::from((
            identity_secret_hash,
            id_commitment,
            Fr::from(self.rate_limit)
        ));

        let key = address.as_slice();
        let mut buffer = vec![0; rln_identity_serializer.size_hint() + merke_index_serializer.size_hint()];
        rln_identity_serializer.serialize(&rln_identity, &mut buffer);
        merke_index_serializer.serialize(&MerkleTreeIndex(index), &mut buffer);
        
        // unwrap safe - db is always created with this column
        let cf_user = self.db.cf_handle(USER_CF).unwrap();
        // FIXME
        // let cf_counter = self.db.cf_handle(TX_COUNTER_EPOCH_CF).unwrap();
        // let cf_counter_slice = self.db.cf_handle(TX_COUNTER_EPOCH_SLICE_CF).unwrap();

        println!("get key: {:?}", key);
        match self.db.get_cf(cf_user, key) {
            Ok(Some(_)) => {
                return Err(RegisterError2::AlreadyRegistered(address));
            },
            Ok(None) => {

                let mut db_batch = WriteBatch::new();
                db_batch.put_cf(cf_user, key, buffer.as_slice());
                // db_batch.put_cf(cf_counter, key, 0u64.to_le_bytes());
                // db_batch.put_cf(cf_counter_slice, key, 0u64.to_le_bytes());

                self.db.write(db_batch)
                    .map_err(|e| {
                        RegisterError2::DbError(e.to_string())
                    })?;
            },
            Err(e) => {
                return Err(RegisterError2::DbError(e.to_string()));
            },
        }

        let rate_commit = poseidon_hash(&[id_commitment, Fr::from(u64::from(self.rate_limit))]);
        // TODO: merkle tree
        Ok(id_commitment)
    }

    fn has_user(&self, address: Address) -> Result<bool, RegisterError2> {
        
       // TODO: perf get_pinned 
        let cf_user = self.db.cf_handle(USER_CF).unwrap();
       self.db
           .get_cf(cf_user, address.as_slice())
           .map(|value| {
               value.is_some()
           })
           .map_err(|e| RegisterError2::DbError(e.to_string()))
    }

    pub fn get_user(&self, address: Address) -> Option<RlnUserIdentity> {

        // unwrap safe - db is always created with this column
        let cf_user = self.db.cf_handle(USER_CF).unwrap();
        let rln_identity_deserializer = RlnUserIdentityDeserializer {};
        match self.db
            .get_cf(cf_user, address.as_slice()) {
            Ok(Some(value)) => {
                Some(rln_identity_deserializer.deserialize(&value))
            },
            Ok(None) => None,
            Err(_e) => None,
        }
    }

    fn incr_tx_counter(&self, address: &Address, incr_value: Option<u64>) -> Result<(), RegisterError2> {
        
        let incr_value = incr_value.unwrap_or(1);
        // unwrap safe - db is always created with this column
        let cf_counter = self.db.cf_handle(TX_COUNTER_CF).unwrap();
        // let cf_counter_epoch_slice = self.db.cf_handle(TX_COUNTER_EPOCH_SLICE_CF).unwrap();

        let (epoch, epoch_slice) = *self.epoch_store.read();
        // FIXME: no as
        let incr = EpochIncr {
            epoch: epoch.0 as u64,
            epoch_slice: epoch_slice.0 as u64,
            incr_value,
        };
        println!("incr: {:?}", incr);
        let incr_ser = EpochIncrSerializer {};
        let mut buffer = Vec::with_capacity(incr_ser.size_hint());
        incr_ser.serialize(&incr, &mut buffer);
        println!("incr buf: {:?}", buffer);

        let mut db_batch = WriteBatch::new();
        db_batch.merge_cf(cf_counter, address.as_slice(), buffer);

        self.db.write(db_batch)
            .map_err(|e| {
                RegisterError2::DbError(e.to_string())
            })
    }
    
    fn get_tx_counter(&self, address: &Address) -> Result<(EpochCounter, EpochSliceCounter), RegisterError2> {

        let counter_deser = EpochCounterDeserializer {};

        // unwrap safe - db is always created with this column
        let cf_counter = self.db.cf_handle(TX_COUNTER_CF).unwrap();
        match self.db
            .get_cf(cf_counter, address.as_slice()) {
            Ok(Some(value)) => {
                let (_, counter) = counter_deser.deserialize(&value).unwrap();
                
                let (epoch, epoch_slice) = *self.epoch_store.read();
                
                println!("get tx_counter: {:?}", counter);
                println!("current epoch: {:?} - slice {:?}", epoch, epoch_slice);
                
                // TODO / FIXME
                
                let cmp = (counter.epoch == epoch.0 as u64, counter.epoch_slice == epoch_slice.0 as u64);
                
                match cmp {
                    (true, true) => {
                        Ok(
                            (counter.epoch_counter.into(), counter.epoch_slice_counter.into())
                        )
                    },
                    (true, false) => {
                        Ok(
                            (counter.epoch_counter.into(), EpochSliceCounter::from(0))
                        )
                    },
                    (false, true) => {

                        Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
                    },
                    (false, false) => {
                        Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
                    },
                }
                
                
                /*
                if (counter.epoch == epoch.0 as u64 && counter.epoch_slice == epoch_slice.0 as u64) {
                    Ok(
                        (counter.epoch.into(), counter.epoch_slice_counter.into())
                    )
                } else {
                    Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
                }
                */
                
            },
            Ok(None) => {
                // FIXME: Should we return Err or 0 ?
                // Err(RegisterError2::DbError(String::from("Tx counter is empty")))
                Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
            },
            Err(e) => {
                Err(RegisterError2::DbError(e.to_string()))
            },
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

    pub(crate) fn on_new_tx(
        &self,
        address: &Address,
        incr_value: Option<u64>,
    ) -> Option<()> {

        // FIXME: should has_user return a Result here?
        if let Ok(has_user) = self.has_user(*address) {
            if (has_user) {
                // FIXME: no unwrap
                Some(self.incr_tx_counter(address, incr_value).unwrap())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub(crate) fn on_new_tier(
        &self,
        tier_index: TierIndex,
        tier: Tier,
    ) -> Result<(), SetTierLimitsError> {

        let cf = self.db.cf_handle(TIER_LIMITS_CF).unwrap();
        let buffer = match self.db.get_cf(cf, TIER_LIMITS_KEY.as_slice()) {
            Ok(Some(buffer)) => {
                buffer
            },
            Ok(None) => {
                unimplemented!()
            },
            Err(e) => {
                unimplemented!()
            }
        };

        let tier_limits_deserializer = TierLimitsDeserializer {};
        let (_, mut tier_limits) = tier_limits_deserializer.deserialize(&buffer).unwrap();
        tier_limits.insert(tier_index, tier);
        tier_limits.validate()?;

        // Serialize
        let tier_limits_serializer = TierLimitsSerializer::default();
        let mut buffer = Vec::with_capacity(tier_limits_serializer.size_hint(tier_limits.len()));
        tier_limits_serializer.serialize(&tier_limits, &mut buffer);

        // Write
        // TODO: no unwrap
        self.db.put_cf(cf, TIER_LIMITS_NEXT_KEY.as_slice(), buffer).unwrap();

        Ok(())
    }

    pub(crate) fn on_tier_updated(
        &self,
        tier_index: TierIndex,
        tier: Tier,
    ) -> Result<(), SetTierLimitsError> {

        let cf = self.db.cf_handle(TIER_LIMITS_CF).unwrap();
        let buffer = match self.db.get_cf(cf, TIER_LIMITS_KEY.as_slice()) {
            Ok(Some(buffer)) => {
                buffer
            },
            Ok(None) => {
                unimplemented!()
            },
            Err(e) => {
                unimplemented!()
            }
        };

        let tier_limits_deserializer = TierLimitsDeserializer {};
        let (_, mut tier_limits) = tier_limits_deserializer.deserialize(&buffer).unwrap();
        if !tier_limits.contains_key(&tier_index) {
            return Err(SetTierLimitsError::InvalidTierIndex);
        }
        tier_limits.entry(tier_index).and_modify(|e| *e = tier);
        tier_limits.validate()?;

        // Serialize
        let tier_limits_serializer = TierLimitsSerializer::default();
        let mut buffer = Vec::with_capacity(tier_limits_serializer.size_hint(tier_limits.len()));
        tier_limits_serializer.serialize(&tier_limits, &mut buffer);

        // Write
        // TODO: no unwrap
        self.db.put_cf(cf, TIER_LIMITS_NEXT_KEY.as_slice(), buffer).unwrap();

        Ok(())
    }

    /// Get user tier info
    pub(crate) async fn user_tier_info<E: std::error::Error, KSC: KarmaAmountExt<Error = E>>(
        &self,
        address: &Address,
        karma_sc: &KSC,
    ) -> Result<UserTierInfo, UserTierInfoError<E>> {

        // TODO: no unwrap
        if self.has_user(*address).unwrap() {

            // TODO: no unwrap
            let (epoch_tx_count, epoch_slice_tx_count) = self.get_tx_counter(address)
                .unwrap();

            let karma_amount = karma_sc
                .karma_amount(address)
                .await
                .map_err(|e| UserTierInfoError::Contract(e))?;

            // let tier_limits_guard = self.tier_limits.read();
            let cf = self.db.cf_handle(TIER_LIMITS_CF).unwrap();
            let buffer = match self.db.get_cf(cf, TIER_LIMITS_KEY.as_slice()) {
                Ok(Some(buffer)) => {
                    buffer
                },
                Ok(None) => {
                    unimplemented!()
                },
                Err(e) => {
                    unimplemented!()
                }
            };

            let tier_limits_deserializer = TierLimitsDeserializer {};
            let (_, tier_limits) = tier_limits_deserializer.deserialize(&buffer).unwrap();
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

/// Async service to update a UserDb on epoch changes
#[derive(Debug)]
pub struct UserDbService2 {
    user_db: UserRocksDb,
    epoch_changes: Arc<Notify>,
}

impl UserDbService2 {
    pub(crate) fn new(
        db_path: PathBuf,
        epoch_changes_notifier: Arc<Notify>,
        epoch_store: Arc<RwLock<(Epoch, EpochSlice)>>,
        rate_limit: RateLimit,
        tier_limits: TierLimits,
    ) -> Self {
        
        Self {
            // FIXME
            user_db: UserRocksDb::new(db_path, tier_limits, epoch_store), 
            epoch_changes: epoch_changes_notifier,
        }
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
    use crate::tier::TierName;
    use crate::user_db_service::UserDbService;

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
        let user_db = UserRocksDb::new(PathBuf::from(temp_folder.path()), Default::default(), epoch_store);

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
        assert_eq!(user_db.get_tx_counter(&addr).unwrap(), (42.into(), 42.into()));
    }

    #[test]
    fn test_tier_serializer() {
        
        let tier = Tier {
            name: "Basic".into(),
            min_karma: U256::from(10),
            max_karma: U256::from(49),
            tx_per_epoch: 5,
            active: true,
        };
        
        let ser = TierSerializer {};
        let deser = TierDeserializer {};
        
        let mut buffer = Vec::with_capacity(ser.size_hint());
        ser.serialize(&tier, &mut buffer);
        
        let (_, tier_deser) = deser.deserialize(&mut buffer).unwrap();
        
        assert_eq!(tier, tier_deser);
    }
    
    #[tokio::test]
    async fn test_incr_tx_counter() {

        let temp_folder = tempfile::tempdir().unwrap();
        let epoch_store = Arc::new(RwLock::new(Default::default()));
        let user_db = UserRocksDb::new(PathBuf::from(temp_folder.path()), Default::default(), epoch_store);

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
        user_db.register(addr).unwrap();
        // Now update user tx counter
        assert_eq!(user_db.on_new_tx(&addr, None), Some(()));
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
                    max_karma: U256::from(9999),
                    tx_per_epoch: 25,
                    active: true,
                },
            ),
        ]);

        let user_db_service = UserDbService2::new(
            temp_folder.path().to_path_buf(), 
            Default::default(),
            epoch_store.clone(),
            10.into(),
            tier_limits.into(),
        );
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
