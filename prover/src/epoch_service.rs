use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;
// third-party
use chrono::{DateTime, NaiveDate, NaiveDateTime, OutOfRangeError, TimeDelta, Utc};
use parking_lot::RwLock;
use tokio::sync::Notify;
use tracing::debug;
// internal
use crate::error::AppError;

/// Duration of an epoch (1 day)
const EPOCH_DURATION: Duration = Duration::from_secs(TimeDelta::days(1).num_seconds() as u64);
/// Minimum duration returned by EpochService::compute_wait_until()
const WAIT_UNTIL_MIN_DURATION: Duration = Duration::from_secs(5);

/// An Epoch tracking service
///
/// The service keeps track of the current epoch (duration: 1 day) and the current epoch slice
/// (duration: configurable, < 1 day, usually in minutes)
pub struct EpochService {
    /// A subdivision of an epoch (in minutes or seconds)
    epoch_slice_duration: Duration,
    /// Current epoch and epoch slice
    pub current_epoch: Arc<RwLock<(Epoch, EpochSlice)>>,
    /// Genesis time (aka when the service has been started at the first time)
    genesis: DateTime<Utc>,
    /// Channel to notify when an epoch / epoch slice has just changed
    pub epoch_changes: Arc<Notify>,
}

impl EpochService {
    pub(crate) async fn listen_for_new_epoch(&self) -> Result<(), AppError> {
        let epoch_slice_count =
            Self::compute_epoch_slice_count(EPOCH_DURATION, self.epoch_slice_duration);
        debug!("epoch slice in an epoch: {}", epoch_slice_count);

        let (mut current_epoch, mut current_epoch_slice, mut wait_until) =
            match self.compute_wait_until(&|| Utc::now(), &|| tokio::time::Instant::now()) {
                Ok((current_epoch, current_epoch_slice, wait_until)) => {
                    (current_epoch, current_epoch_slice, wait_until)
                }
                Err(_e) => {
                    // sleep and try again (only one retry)
                    tokio::time::sleep(WAIT_UNTIL_MIN_DURATION).await;
                    self.compute_wait_until(&|| Utc::now(), &|| tokio::time::Instant::now())?
                }
            };

        debug!("wait until: {:?}", wait_until);
        *self.current_epoch.write() = (current_epoch.into(), current_epoch_slice.into());

        loop {
            debug!("wait until: {:?}", wait_until);
            // XXX: Should we check the drift between now() and wait_until ?
            tokio::time::sleep_until(wait_until).await;
            {
                let now_ = tokio::time::Instant::now();
                debug!("awake at: {:?}, drift by: {:?}", now_, now_ - wait_until);
            }
            // Note: could use checked_add() here, but it's quite impossible to have an overflow here
            //       it would mean that the epoch_slice_duration is insanely large and wait_until
            //       overflows as a timestamp
            wait_until += self.epoch_slice_duration;

            current_epoch_slice += 1;
            if current_epoch_slice == epoch_slice_count {
                current_epoch_slice = 0;
                current_epoch += 1;
            }
            *self.current_epoch.write() = (current_epoch.into(), current_epoch_slice.into());
            debug!(
                "epoch: {}, epoch slice: {}",
                current_epoch, current_epoch_slice
            );

            // println!("Epoch changed: {}", current_epoch);
            self.epoch_changes.notify_one();
        }

        // Ok(())
    }

    fn compute_wait_until<T, F: Fn() -> DateTime<Utc>, TF: Fn() -> T>(
        &self,
        now: &F,
        now2: &TF,
    ) -> Result<(i64, i64, T), WaitUntilError>
    where
        T: Add<Duration, Output = T>,
    {
        let (current_epoch, now_date) = EpochService::compute_current_epoch(self.genesis, now);
        debug!("current_epoch: {}", current_epoch);
        // self.current_epoch.store(current_epoch, Ordering::SeqCst);

        let current_epoch_slice =
            EpochService::compute_current_epoch_slice(now_date, self.epoch_slice_duration, now);
        debug!("current epoch slice: {}", current_epoch_slice);

        // time to wait to next epoch slice
        let day_start = DateTime::from_naive_utc_and_offset(now_date.into(), Utc);
        // Note:
        // unwrap safe -> epoch_slice_duration < epoch duration checked in constructor
        let epoch_slice_next: DateTime<Utc> = day_start.add(
            self.epoch_slice_duration
                .checked_mul(current_epoch_slice as u32 + 1)
                .unwrap(),
        );

        debug!("epoch slice next: {}", epoch_slice_next);

        // Note: to_std() will return an Error if now > epoch_slice_next
        //       This can happen if epoch_slice_next is very close to now()
        let wait_until = (epoch_slice_next - now())
            .to_std()
            .map_err(WaitUntilError::OutOfRange)?;
        if wait_until < WAIT_UNTIL_MIN_DURATION {
            return Err(WaitUntilError::TooLow(wait_until, WAIT_UNTIL_MIN_DURATION));
        }

        let wait_until = now2() + wait_until;
        Ok((current_epoch, current_epoch_slice, wait_until))
    }

    /// Number of epoch slices in an epoch
    fn compute_epoch_slice_count(epoch_duration: Duration, epoch_slice_duration: Duration) -> i64 {
        (epoch_duration.as_secs() / epoch_slice_duration.as_secs()) as i64
    }

    /// Compute current epoch (since genesis)
    fn compute_current_epoch<F: Fn() -> DateTime<Utc>>(
        genesis: DateTime<Utc>,
        now: &F,
    ) -> (i64, NaiveDate) {
        debug_assert!(now().date_naive() >= genesis.date_naive());

        let genesis_date = genesis.date_naive();
        let now_date = now().date_naive();
        let diff = now_date - genesis_date;
        (diff.num_days(), now_date)
    }

    /// Compute current epoch slice
    /// now_date: today's date (usually returned by: compute_current_epoch)
    fn compute_current_epoch_slice<F: Fn() -> DateTime<Utc>>(
        now_date: NaiveDate,
        epoch_slice_duration: Duration,
        now: F,
    ) -> i64 {
        debug_assert!(epoch_slice_duration.as_secs() > 0);
        debug_assert!(i32::try_from(epoch_slice_duration.as_secs()).is_ok());

        let day_start_ = NaiveDateTime::from(now_date);
        let day_start = DateTime::from_naive_utc_and_offset(day_start_, chrono::Utc);
        // debug!("start of day: {}", day_start);

        // Note:
        // cannot unwrap -> epoch_slice_duration.as_secs() as i32 is checked
        // + epoch_slice_duration is checked > 0
        let elapsed_for_epoch = (now() - day_start)
            .checked_div(epoch_slice_duration.as_secs() as i32)
            .unwrap();
        // debug!("elapsed for epoch: {}", elapsed_for_epoch.num_seconds());
        elapsed_for_epoch.num_seconds()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EpochServiceInitError {
    #[error("epoch slice duration is too large (cannot fit in i32) or == 0")]
    InvalidEpochSliceDuration,
    #[error("genesis is in the future")]
    InvalidGenesis,
}

impl TryFrom<(Duration, DateTime<Utc>)> for EpochService {
    type Error = EpochServiceInitError;

    fn try_from(
        (epoch_slice_duration, genesis): (Duration, DateTime<Utc>),
    ) -> Result<Self, Self::Error> {
        if genesis >= Utc::now() {
            return Err(EpochServiceInitError::InvalidGenesis);
        }

        if epoch_slice_duration.as_secs() == 0
            || i32::try_from(epoch_slice_duration.as_secs()).is_err()
            || epoch_slice_duration < WAIT_UNTIL_MIN_DURATION
            || epoch_slice_duration >= (EPOCH_DURATION / 2)
        {
            return Err(EpochServiceInitError::InvalidEpochSliceDuration);
        }

        // TODO: should we check the division: epoch_duration / epoch_slice_duration ?

        Ok(Self {
            epoch_slice_duration,
            current_epoch: Arc::new(Default::default()),
            genesis,
            epoch_changes: Arc::new(Default::default()),
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum WaitUntilError {
    #[error("Computation error: {0}")]
    OutOfRange(#[from] OutOfRangeError),
    #[error("Wait until is too low: {0:?} (min value: {1:?}")]
    TooLow(Duration, Duration),
}

/// An Epoch (wrapper type over i64)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Epoch(pub(crate) i64);

impl Add<i64> for Epoch {
    type Output = Self;

    fn add(self, rhs: i64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl From<i64> for Epoch {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<Epoch> for i64 {
    fn from(value: Epoch) -> Self {
        value.0
    }
}

/// An Epoch slice (wrapper type over i64)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EpochSlice(pub(crate) i64);

impl Add<i64> for EpochSlice {
    type Output = Self;

    fn add(self, rhs: i64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl From<i64> for EpochSlice {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<EpochSlice> for i64 {
    fn from(value: EpochSlice) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveDateTime, TimeDelta};
    use futures::TryFutureExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tracing_test::traced_test;

    /*
    #[tokio::test]
    async fn test_wait_until_0() {
        let wait_until = tokio::time::Instant::now() + Duration::from_secs(10);
        println!("Should wait until: {:?}", wait_until);
        tokio::time::sleep(Duration::from_secs(3)).await;
        tokio::time::sleep_until(wait_until).await;
        println!("Wake up at: {:?}", tokio::time::Instant::now());
    }
    */

    #[test]
    fn test_wait_until() {
        // Check wait_until is correctly computed

        let date_0 = NaiveDate::from_ymd_opt(2025, 5, 14).unwrap();
        let datetime_0 = date_0.and_hms_opt(0, 0, 0).unwrap();

        {
            // standard wait until in epoch 0, epoch slice 1

            let genesis: DateTime<Utc> = DateTime::from_naive_utc_and_offset(datetime_0, Utc);
            let epoch_slice_duration = Duration::from_secs(60);
            let epoch_service = EpochService::try_from((epoch_slice_duration, genesis)).unwrap();

            let now = || {
                let mut now_0: NaiveDateTime = date_0.and_hms_opt(0, 0, 0).unwrap();
                // Set now_0 to be in epoch slice 1
                now_0 += epoch_slice_duration;
                DateTime::from_naive_utc_and_offset(now_0, chrono::Utc)
            };

            let (epoch, epoch_slice, wait_until): (_, _, DateTime<Utc>) =
                epoch_service.compute_wait_until(&now, &now).unwrap();

            assert_eq!(epoch, 0);
            assert_eq!(epoch_slice, 1);
            assert_eq!(
                wait_until,
                DateTime::<Utc>::from_naive_utc_and_offset(datetime_0, Utc)
                    + 2 * epoch_slice_duration
            );
        }

        {
            // standard wait until (but in epoch 1)

            let genesis: DateTime<Utc> = DateTime::from_naive_utc_and_offset(datetime_0, Utc);
            let epoch_slice_duration = Duration::from_secs(60);
            let epoch_service = EpochService::try_from((epoch_slice_duration, genesis)).unwrap();

            let now = || {
                let mut now_0: NaiveDateTime = date_0.and_hms_opt(0, 0, 0).unwrap();
                // Set now_0 to be in epoch 1
                now_0 += EPOCH_DURATION;
                // Set now_0 to be in epoch 1, epoch slice 1
                now_0 += epoch_slice_duration;
                // Add 30 secs (but should still wait until epoch slice 2 starts)
                now_0 += epoch_slice_duration / 2;
                chrono::DateTime::from_naive_utc_and_offset(now_0, Utc)
            };

            let (epoch, epoch_slice, wait_until): (_, _, DateTime<Utc>) =
                epoch_service.compute_wait_until(&now, &now).unwrap();

            assert_eq!(epoch, 1);
            assert_eq!(epoch_slice, 1);
            assert_eq!(
                wait_until,
                DateTime::<Utc>::from_naive_utc_and_offset(datetime_0, Utc)
                    + EPOCH_DURATION
                    + 2 * epoch_slice_duration
            );
        }

        {
            // Check for WaitUntilError::TooLow

            let genesis: DateTime<Utc> =
                chrono::DateTime::from_naive_utc_and_offset(datetime_0, Utc);
            let epoch_slice_duration = Duration::from_secs(60);
            let epoch_service = EpochService::try_from((epoch_slice_duration, genesis)).unwrap();
            let epoch_slice_duration_minus_1 =
                epoch_slice_duration - WAIT_UNTIL_MIN_DURATION + Duration::from_secs(1);

            let now = || {
                let mut now_0: NaiveDateTime = date_0
                    .and_hms_opt(0, 0, epoch_slice_duration_minus_1.as_secs() as u32)
                    .unwrap();
                // Set now_0 to be in epoch slice 1
                now_0 += epoch_slice_duration;
                chrono::DateTime::from_naive_utc_and_offset(now_0, chrono::Utc)
            };

            let res = epoch_service.compute_wait_until(&now, &now);

            assert!(matches!(res, Err(WaitUntilError::TooLow(_, _))));
        }
    }

    #[test]
    fn test_compute_epoch_slice_count() {
        // test the computation of the number of epoch slices in an epoch

        assert_eq!(
            EpochService::compute_epoch_slice_count(
                Duration::from_secs(TimeDelta::days(1).num_seconds() as u64),
                Duration::from_secs(TimeDelta::hours(1).num_seconds() as u64)
            ),
            24
        );
        assert_eq!(
            EpochService::compute_epoch_slice_count(
                Duration::from_secs(TimeDelta::days(1).num_seconds() as u64),
                Duration::from_secs(TimeDelta::minutes(30).num_seconds() as u64)
            ),
            48
        );
    }

    #[test]
    fn test_compute_current_epoch() {
        let day_ = 14;
        let genesis_0: NaiveDateTime = NaiveDate::from_ymd_opt(2025, 5, day_)
            .unwrap()
            .and_hms_opt(4, 0, 0)
            .unwrap();
        let genesis: DateTime<Utc> =
            chrono::DateTime::from_naive_utc_and_offset(genesis_0, chrono::Utc);

        let now_f = move || {
            let now_0: NaiveDateTime = NaiveDate::from_ymd_opt(2025, 5, day_ + 2)
                .unwrap()
                .and_hms_opt(4, 0, 0)
                .unwrap();
            // let genesis = DateTime:: new(2025, 05, 18, 4, 0, 0).unwrap();
            let now: DateTime<Utc> =
                chrono::DateTime::from_naive_utc_and_offset(now_0, chrono::Utc);
            now
        };

        assert_eq!(EpochService::compute_current_epoch(genesis, &now_f).0, 2);
    }

    #[test]
    fn test_compute_current_epoch_slice() {
        let day = NaiveDate::from_ymd_opt(2025, 5, 14).unwrap();
        let now_date = day.clone();

        let now_f = move || {
            let now_0: NaiveDateTime = day.and_hms_opt(0, 4, 0).unwrap();
            let now: DateTime<Utc> =
                chrono::DateTime::from_naive_utc_and_offset(now_0, chrono::Utc);
            now
        };
        let now_f_2 = move || {
            let now_0: NaiveDateTime = day.and_hms_opt(0, 5, 59).unwrap();
            let now: DateTime<Utc> =
                chrono::DateTime::from_naive_utc_and_offset(now_0, chrono::Utc);
            now
        };
        let now_f_3 = move || {
            let now_0: NaiveDateTime = day.and_hms_opt(0, 6, 0).unwrap();
            let now: DateTime<Utc> =
                chrono::DateTime::from_naive_utc_and_offset(now_0, chrono::Utc);
            now
        };

        // epoch_slice == 2 minutes
        let epoch_slice_duration = Duration::from_secs(60 * 2);

        // Note: 4-minute diff -> expect == 2
        assert_eq!(
            EpochService::compute_current_epoch_slice(now_date, epoch_slice_duration, now_f),
            2
        );
        // Note: 5 minutes and 59 seconds diff -> still expect == 2
        assert_eq!(
            EpochService::compute_current_epoch_slice(
                now_date,
                epoch_slice_duration,
                Box::new(now_f_2)
            ),
            2
        );
        // Note: 6 minutes diff -> expect == 3
        assert_eq!(
            EpochService::compute_current_epoch_slice(
                now_date,
                epoch_slice_duration,
                Box::new(now_f_3)
            ),
            3
        );
    }

    #[derive(thiserror::Error, Debug)]
    enum AppErrorExt {
        #[error("AppError: {0}")]
        AppError(#[from] AppError),
        #[error("Future timeout")]
        Elapsed,
    }

    #[tokio::test]
    #[traced_test]
    async fn test_notify() {
        // Test epoch_service is really notifying when an epoch or epoch slice has just changed

        let epoch_slice_duration = Duration::from_secs(10);
        let epoch_service = EpochService::try_from((epoch_slice_duration, Utc::now())).unwrap();
        let notifier = epoch_service.epoch_changes.clone();
        let counter_0 = Arc::new(AtomicU64::new(0));
        let counter = counter_0.clone();

        let res = tokio::try_join!(
            epoch_service
                .listen_for_new_epoch()
                .map_err(|e| AppErrorExt::AppError(e)),
            // Wait for 3 epoch slices + 100 ms (to wait to receive notif + counter incr)
            tokio::time::timeout(
                epoch_slice_duration * 3 + Duration::from_millis(100),
                async move {
                    loop {
                        notifier.notified().await;
                        debug!("[Notified] Epoch update...");
                        let _v = counter.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok::<(), AppErrorExt>(())
                }
            )
            .map_err(|_e| AppErrorExt::Elapsed)
        );
        assert!(matches!(res, Err(AppErrorExt::Elapsed)));
        assert_eq!(counter_0.load(Ordering::SeqCst), 3);
    }
}
