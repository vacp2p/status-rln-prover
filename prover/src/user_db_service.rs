// std
use std::path::PathBuf;
// third-party
use tokio::sync::watch::Receiver;
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
}

impl UserDbService {
    pub fn new(
        db_path: PathBuf,
        merkle_tree_path: PathBuf,
        epoch_changes: Receiver<(Epoch, EpochSlice)>,
        rate_limit: RateLimit,
        tier_limits: TierLimits,
    ) -> Result<Self, UserDbOpenError> {
        let user_db = UserDb::new(
            db_path,
            merkle_tree_path,
            epoch_changes,
            tier_limits,
            rate_limit,
        )?;
        Ok(Self { user_db })
    }

    pub fn get_user_db(&self) -> UserDb {
        self.user_db.clone()
    }

    pub async fn listen_for_epoch_changes(&self) -> Result<(), AppError> {
        let (mut current_epoch, mut current_epoch_slice) = { *self.user_db.epoch_changes.borrow() };
        let mut epoch_changes = self.user_db.epoch_changes.clone();

        loop {
            if let Err(recv_error) = epoch_changes.changed().await {
                debug!(
                    "Sender closed. App is likely shutting down. Error: {:?}",
                    recv_error
                );

                return Ok(());
            }
            let (new_epoch, new_epoch_slice) = { *self.user_db.epoch_changes.borrow() };
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
