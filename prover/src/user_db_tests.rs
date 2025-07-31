#[cfg(test)]
mod user_db_tests {
    // std
    use std::path::PathBuf;
    use std::sync::Arc;
    // third-party
    use crate::epoch_service::{Epoch, EpochSlice};
    use alloy::primitives::{Address, address};
    use parking_lot::RwLock;
    // internal
    use crate::user_db::UserDb;
    use crate::user_db_types::{EpochCounter, EpochSliceCounter, MerkleTreeIndex};

    const ADDR_1: Address = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const ADDR_2: Address = address!("0xb20a608c624Ca5003905aA834De7156C68b2E1d0");

    #[tokio::test]
    async fn test_incr_tx_counter_2() {
        // Same as test_incr_tx_counter but multi users AND multi incr

        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();

        let epoch_store = Arc::new(RwLock::new(Default::default()));
        let epoch = 1;
        let epoch_slice = 42;
        *epoch_store.write() = (Epoch::from(epoch), EpochSlice::from(epoch_slice));

        let user_db = UserDb::new(
            PathBuf::from(temp_folder.path()),
            PathBuf::from(temp_folder_tree.path()),
            epoch_store,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Register users
        user_db.register(ADDR_1).unwrap();
        user_db.register(ADDR_2).unwrap();

        assert_eq!(
            user_db.get_tx_counter(&ADDR_1),
            Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
        );
        assert_eq!(
            user_db.get_tx_counter(&ADDR_2),
            Ok((EpochCounter::from(0), EpochSliceCounter::from(0)))
        );

        // Now update user tx counter
        assert_eq!(
            user_db.on_new_tx(&ADDR_1, None),
            Ok(EpochSliceCounter::from(1))
        );
        assert_eq!(
            user_db.on_new_tx(&ADDR_1, None),
            Ok(EpochSliceCounter::from(2))
        );
        assert_eq!(
            user_db.on_new_tx(&ADDR_1, Some(2)),
            Ok(EpochSliceCounter::from(4))
        );

        assert_eq!(
            user_db.on_new_tx(&ADDR_2, None),
            Ok(EpochSliceCounter::from(1))
        );

        assert_eq!(
            user_db.on_new_tx(&ADDR_2, None),
            Ok(EpochSliceCounter::from(2))
        );

        assert_eq!(
            user_db.get_tx_counter(&ADDR_1),
            Ok((EpochCounter::from(4), EpochSliceCounter::from(4)))
        );

        assert_eq!(
            user_db.get_tx_counter(&ADDR_2),
            Ok((EpochCounter::from(2), EpochSliceCounter::from(2)))
        );
    }

    #[tokio::test]
    async fn test_persistent_storage() {
        let temp_folder = tempfile::tempdir().unwrap();
        let temp_folder_tree = tempfile::tempdir().unwrap();
        let epoch_store = Arc::new(RwLock::new(Default::default()));

        let addr = Address::new([0; 20]);
        {
            let user_db = UserDb::new(
                PathBuf::from(temp_folder.path()),
                PathBuf::from(temp_folder_tree.path()),
                epoch_store.clone(),
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
                epoch_store,
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
}
