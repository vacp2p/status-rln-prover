use rocksdb::MergeOperands;

#[derive(Debug, Default, PartialEq)]
pub struct EpochCounter {
    pub epoch: u64,
    pub epoch_slice: u64,
    pub epoch_counter: u64,
    pub epoch_slice_counter: u64,
}

struct EpochCounterSerializer {}

impl EpochCounterSerializer {
    
    fn serialize(&self, value: &EpochCounter, buffer: &mut Vec<u8>) {
        buffer.extend(value.epoch.to_le_bytes());
        buffer.extend(value.epoch_slice.to_le_bytes());
        buffer.extend(value.epoch_counter.to_le_bytes());
        buffer.extend(value.epoch_slice_counter.to_le_bytes());
    }

    fn size_hint(&self) -> usize {
        size_of::<EpochCounter>()
    }
}

pub struct EpochCounterDeserializer {}

impl EpochCounterDeserializer {
    pub fn deserialize(&self, buffer: &[u8]) -> EpochCounter {
        let epoch = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
        let epoch_slice = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
        let epoch_counter = u64::from_le_bytes(buffer[16..24].try_into().unwrap());
        let epoch_slice_counter = u64::from_le_bytes(buffer[24..32].try_into().unwrap());
        EpochCounter { epoch, epoch_slice, epoch_counter, epoch_slice_counter }
    }
}

#[derive(Debug, Default)]
pub struct EpochIncr {
    pub epoch: u64,
    pub epoch_slice: u64,
    pub incr_value: i64,
}

pub struct EpochIncrSerializer {}

impl EpochIncrSerializer {
    pub fn serialize(&self, value: &EpochIncr, buffer: &mut Vec<u8>) {
        buffer.extend(value.epoch.to_le_bytes());
        buffer.extend(value.epoch_slice.to_le_bytes());
        buffer.extend(value.incr_value.to_le_bytes());
    }

    pub fn size_hint(&self) -> usize {
        size_of::<u64>() * 3
    }
}

pub struct EpochIncrDeserializer {}

impl EpochIncrDeserializer {
    pub fn deserialize(&self, buffer: &[u8]) -> EpochIncr {
        let epoch = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
        let epoch_slice = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
        let incr_value = i64::from_le_bytes(buffer[16..24].try_into().unwrap());
        EpochIncr { epoch, epoch_slice, incr_value }
    }
}

pub fn epoch_incr_operands(
    _key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {

    let counter_ser = EpochCounterSerializer {};
    let counter_deser = EpochCounterDeserializer {};
    let ser = EpochIncrSerializer {};
    let deser = EpochIncrDeserializer {};

    // Current epoch counter struct (stored in DB)
    let current = if let Some(existing_val) = existing_val {
         counter_deser.deserialize(existing_val)
    } else {
        Default::default()
    };

    // Iter over merge operands (can have multiple one with DBBatch)
    let counter_value = operands.iter().fold(current, |mut acc, x| {

        let epoch_incr = deser.deserialize(x);
        println!("[op] acc: {:?}", acc);
        println!("[op] epoch incr: {:?}", epoch_incr);
        // TODO - optim: partial deser ? 
        // TODO: check if increasing ? debug_assert otherwise?
        
        if acc == Default::default() {

            acc = EpochCounter {
                epoch: epoch_incr.epoch,
                epoch_slice: epoch_incr.epoch_slice,
                epoch_counter: epoch_incr.incr_value as u64,
                epoch_slice_counter: epoch_incr.incr_value as u64,
            }
            
        } else if epoch_incr.epoch != acc.epoch {
            // New epoch
            // TODO: no 'as'
            println!("new epoch");
            acc = EpochCounter {
                epoch: epoch_incr.epoch,
                epoch_slice: 0,
                epoch_counter: epoch_incr.incr_value as u64,
                epoch_slice_counter: epoch_incr.incr_value as u64,
            }
        } else if epoch_incr.epoch_slice != acc.epoch_slice {
            // New epoch slice
            // TODO: no 'as'
            println!("diff slice");
            acc = EpochCounter {
                epoch: epoch_incr.epoch,
                epoch_slice: epoch_incr.epoch_slice,
                epoch_counter: acc.epoch_counter.saturating_add(epoch_incr.epoch_slice),
                epoch_slice_counter: epoch_incr.incr_value as u64,
            }
        } else {
            acc = EpochCounter {
                epoch: acc.epoch,
                epoch_slice: acc.epoch_slice,
                epoch_counter: acc.epoch_counter.saturating_add_signed(epoch_incr.incr_value),
                epoch_slice_counter: acc.epoch_slice_counter.saturating_add_signed(epoch_incr.incr_value),
            }
        }

        acc
    });

    let mut buffer = Vec::with_capacity(ser.size_hint());
    counter_ser.serialize(&counter_value, &mut buffer);
    Some(buffer.to_vec())
}


#[cfg(test)]
mod tests {
    use super::*;
    // std
    // third-party
    use rocksdb::{Options, WriteBatch, DB};
    use tempfile::TempDir;

    #[test]
    fn test_operator_2() {
        let tmp_path = TempDir::new().unwrap().path().to_path_buf();
        let options = {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.set_merge_operator("operator2", epoch_incr_operands, epoch_incr_operands);
            opts
        };
        let db = DB::open(&options, tmp_path).unwrap();
        let key_1 = "foo1";
        let key_2 = "baz42";

        println!("key_1: {:?}", key_1.as_bytes());

        let value_1 = EpochIncr {
            epoch: 0,
            epoch_slice: 0,
            incr_value: 2,
        };
        let epoch_incr_ser = EpochIncrSerializer {};
        let epoch_incr_deser = EpochIncrDeserializer {};
        let epoch_counter_deser = EpochCounterDeserializer {};

        let mut buffer = Vec::with_capacity(epoch_incr_ser.size_hint());
        epoch_incr_ser.serialize(&value_1, &mut buffer);
        println!("Merge...");
        // db.merge(key_1, buffer).unwrap();

        let mut db_batch = WriteBatch::default();
        db_batch.merge(key_1, &buffer);
        db_batch.merge(key_1, &buffer);
        db.write(db_batch).unwrap();

        let get_key_1 = db.get(&key_1).unwrap().unwrap();
        let get_value_1 = epoch_counter_deser.deserialize(&get_key_1);

        println!("db get: {:?}", get_value_1);

        // new epoch slice
        {
            let value_2 = EpochIncr {
                epoch: 0,
                epoch_slice: 1,
                incr_value: 1,
            };

            let mut buffer = Vec::with_capacity(epoch_incr_ser.size_hint());
            epoch_incr_ser.serialize(&value_2, &mut buffer);
            println!("Merge...");
            db.merge(key_1, buffer).unwrap();

            let get_key_1 = db.get(&key_1).unwrap().unwrap();
            let get_value_2 = epoch_counter_deser.deserialize(&get_key_1);
            println!("db get (after value 2): {:?}", get_value_2);
        }
        
        // new epoch
        {
            let value_3 = EpochIncr {
                epoch: 1,
                epoch_slice: 0,
                incr_value: 3,
            };

            let mut buffer = Vec::with_capacity(epoch_incr_ser.size_hint());
            epoch_incr_ser.serialize(&value_3, &mut buffer);
            println!("Merge...");
            db.merge(key_1, buffer).unwrap();

            let get_key_1 = db.get(&key_1).unwrap().unwrap();
            let get_value_3 = epoch_counter_deser.deserialize(&get_key_1);
            println!("db get (after value 3): {:?}", get_value_3);
        }
    }
}