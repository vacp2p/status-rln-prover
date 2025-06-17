use std::path::{Path, PathBuf};
use std::sync::Arc;
use alloy::primitives::Address;
use ark_bn254::Fr;
use derive_more::{From, Into};
use rln::protocol::keygen;
use rln::utils::{bytes_le_to_fr, fr_to_bytes_le};
use rocksdb::{
    checkpoint::Checkpoint, ColumnFamilyDescriptor, Direction, IteratorMode, Options, WriteBatch,
    DB,
};
use rln_proof::RlnUserIdentity;
use crate::rocksdb_operator::counter_merge;
use crate::user_db_service::{EpochSliceCounter, RateLimit};

pub const USER_CF: &str = "user";
pub const TX_COUNTER_CF: &str = "tx";

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

    fn deserialize(&self, buffer: &[u8]) -> RlnUserIdentity {

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

struct UserRocksDb {
    db: Arc<DB>,
    // merkle_tree: Arc<RwLock<PmTree>>,
    rate_limit: RateLimit,
}

impl UserRocksDb {

    /// Returns a new `UserRocksDB` instance
    pub fn new(db_path: PathBuf) -> Self {
        // TODO: try try_from impl
        let db_opts = Self::default_db_opts();
        // FIXME: no unwrap
        Self::new_with_options(&db_path, db_opts).expect("rocksdb open error")
    }

    pub fn default_db_opts() -> Options {
        let mut db_opts = Options::default();
        db_opts.set_max_open_files(820);
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts
    }

    fn new_with_options(db_path: &Path, db_opts: Options) -> Result<Self, rocksdb::Error> {
        
        let mut tx_counter_cf_opts = Options::default();
        tx_counter_cf_opts.set_merge_operator_associative("counter merge operator", counter_merge);
        
        let db = DB::open_cf_descriptors(
            &db_opts,
            db_path,
            vec![
                ColumnFamilyDescriptor::new(USER_CF, Options::default()),
                ColumnFamilyDescriptor::new(TX_COUNTER_CF, tx_counter_cf_opts),
            ],
        )?;

        let db = Arc::new(db);

        Ok(Self {
            db,
            rate_limit: Default::default(), // FIXME
        })
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
        let cf_counter = self.db.cf_handle(TX_COUNTER_CF).unwrap();

        println!("get key: {:?}", key);
        match self.db.get_cf(cf_user, key) {
            Ok(Some(_)) => {
                return Err(RegisterError2::AlreadyRegistered(address));
            },
            Ok(None) => {

                
                let mut db_batch = WriteBatch::new();
                db_batch.put_cf(cf_user, key, buffer.as_slice());
                db_batch.put_cf(cf_counter, key, 0u64.to_le_bytes());

                self.db.write(db_batch)
                    .map_err(|e| {
                        RegisterError2::DbError(e.to_string())
                    })?;
            },
            Err(e) => {
                return Err(RegisterError2::DbError(e.to_string()));
            },
        }

        // let rate_commit = poseidon_hash(&[id_commitment, Fr::from(u64::from(self.rate_limit))]);
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

    fn get_user(&self, address: Address) -> Option<RlnUserIdentity> {

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
        self
            .db
            .merge_cf(cf_counter, address.as_slice(), incr_value.to_le_bytes())
            .map_err(|e| {
                RegisterError2::DbError(e.to_string())
            })
    }
    
    fn get_tx_counter(&self, address: &Address) -> Result<EpochSliceCounter, RegisterError2> {

        // unwrap safe - db is always created with this column
        let cf_counter = self.db.cf_handle(TX_COUNTER_CF).unwrap();
        match self.db
            .get_cf(cf_counter, address.as_slice()) {
            Ok(Some(value)) => {
                Ok(EpochSliceCounter::from(
                    u64::from_le_bytes(
                        value.as_slice().try_into().unwrap()
                    )
                ))
            },
            Ok(None) => {
                Err(RegisterError2::DbError(String::from("Tx counter is empty")))
            },
            Err(e) => {
                Err(RegisterError2::DbError(e.to_string()))
            },
        }
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

    const ADDR_1: Address = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const ADDR_2: Address = address!("0xb20a608c624Ca5003905aA834De7156C68b2E1d0");

    #[test]
    fn test_user_register() {

        let temp_folder = tempfile::tempdir().unwrap();
        let user_db = UserRocksDb::new(PathBuf::from(temp_folder.path()));

        let addr = Address::new([0; 20]);
        user_db.register(addr).unwrap();
        assert_matches!(
            user_db.register(addr),
            Err(RegisterError2::AlreadyRegistered(_))
        );

        assert!(user_db.get_user(addr).is_some());
        assert_eq!(user_db.get_tx_counter(&addr).unwrap(), 0.into());
        
        assert!(user_db.get_user(ADDR_1).is_none());
        user_db.register(ADDR_1).unwrap();
        
        // TODO: split unit test
        assert!(user_db.get_user(ADDR_1).is_some());
        assert_eq!(user_db.get_tx_counter(&addr).unwrap(), 0.into());
        user_db.incr_tx_counter(&addr, Some(42)).unwrap();
        assert_eq!(user_db.get_tx_counter(&addr).unwrap(), 42.into());
    }
}
