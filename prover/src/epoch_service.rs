use std::ops::Add;
use std::time::Duration;
// third-party
use chrono::{DateTime, NaiveDate, NaiveDateTime, OutOfRangeError, TimeDelta, Utc};
use derive_more::{Deref, From, Into};
use tokio::{
    sync::watch::{Receiver, Sender, channel},
    time::{Instant, sleep, sleep_until},
};
use tracing::{debug, info};
// internal
use crate::error::AppError;

/// Duration of an epoch (1 day)
const EPOCH_DURATION: Duration = Duration::from_secs(TimeDelta::days(1).num_seconds() as u64);

/// Minimum duration returned by EpochService::compute_wait_until()
const WAIT_UNTIL_MIN_DURATION: Duration = Duration::from_millis(100);

/// An Epoch tracking service
///
/// The service keeps track of the current epoch (duration: 1 day) and the current epoch slice
/// (duration: configurable, < 1 day, usually in minutes)
pub struct EpochService {
    /// A subdivision of an epoch (in minutes or seconds)
    epoch_slice_duration: Duration,
    /// Sender to notify when an epoch / epoch slice has just changed
    epoch_sender: Sender<(Epoch, EpochSlice)>,
    /// Receiver that can be cloned for receivers
    epoch_receiver: Receiver<(Epoch, EpochSlice)>,
    /// Genesis time (aka when the service has been started at the first time)
    genesis: DateTime<Utc>,
}

impl EpochService {
    pub fn epoch_changes(&self) -> Receiver<(Epoch, EpochSlice)> {
        self.epoch_receiver.clone()
    }

    pub(crate) async fn listen_for_new_epoch(&self) -> Result<(), AppError> {
        let epoch_slice_count =
            Self::compute_epoch_slice_count(EPOCH_DURATION, self.epoch_slice_duration);
        debug!("epoch slice in an epoch: {}", epoch_slice_count);

        let mut last_sent_epoch: Option<i64> = None;
        let mut last_sent_epoch_slice: Option<i64> = None;
        loop {
            // Recalculate current state based on actual time every iteration to avoid drift
            let (current_epoch, current_epoch_slice, wait_until) =
                match self.compute_wait_until(&|| Utc::now(), &|| tokio::time::Instant::now()) {
                    Ok((current_epoch, current_epoch_slice, wait_until)) => {
                        (current_epoch, current_epoch_slice, wait_until)
                    }
                    Err(err) => match err {
                        EpochServiceError::WaitUntilOutOfRange(_) => {
                            return Err(AppError::EpochError(err));
                        }
                        EpochServiceError::TooLow(wait_until, min_duration) => {
                            info!(
                                "wait_until is too low: {:?} (min value: {:?})",
                                wait_until, min_duration
                            );
                            // Sleep and try recalculate everything in next iteration
                            sleep(WAIT_UNTIL_MIN_DURATION).await;
                            continue;
                        }
                    },
                };

            match (last_sent_epoch, last_sent_epoch_slice) {
                (None, None) => {
                    // First-time setup, store the current values but do not notify
                    last_sent_epoch = Some(current_epoch);
                    last_sent_epoch_slice = Some(current_epoch_slice);
                }
                (Some(prev_epoch), Some(prev_slice)) => {
                    // Notify if either the epoch or slice has changed
                    if current_epoch != prev_epoch || current_epoch_slice != prev_slice {
                        self.epoch_sender
                            .send((current_epoch.into(), current_epoch_slice.into()))
                            .expect("epoch receiver should still be alive");
                    }
                    last_sent_epoch = Some(current_epoch);
                    last_sent_epoch_slice = Some(current_epoch_slice);
                }
                _ => unreachable!("Epoch and slice should either both be set or both be None"),
            }

            debug!("wait for: {:?}", wait_until - Instant::now());
            sleep_until(wait_until).await;
            debug!("drift by: {:?}\n", Instant::now() - wait_until);
        }
    }

    fn compute_wait_until<T, F: Fn() -> DateTime<Utc>, TF: Fn() -> T>(
        &self,
        now: &F,
        now2: &TF,
    ) -> Result<(i64, i64, T), EpochServiceError>
    where
        T: Add<Duration, Output = T>,
    {
        let (current_epoch, now_date) = EpochService::compute_current_epoch(self.genesis, now);
        debug!("current epoch: {}", current_epoch);

        let current_epoch_slice =
            EpochService::compute_current_epoch_slice(now_date, self.epoch_slice_duration, now);
        debug!("current epoch slice: {}", current_epoch_slice);

        // Time to wait to next epoch slice
        let day_start = DateTime::from_naive_utc_and_offset(now_date.into(), Utc);
        // Note:
        // unwrap safe -> epoch_slice_duration < epoch duration checked in constructor
        let next_epoch_slice: DateTime<Utc> = day_start.add(
            self.epoch_slice_duration
                .checked_mul(current_epoch_slice as u32 + 1)
                .unwrap(),
        );

        debug!("next epoch slice: {}", next_epoch_slice);

        // Note: to_std() will return an Error if now > next_epoch_slice
        //       This can happen if next_epoch_slice is very close to now()
        let wait_until = (next_epoch_slice - now())
            .to_std()
            .map_err(EpochServiceError::WaitUntilOutOfRange)?;

        if wait_until < WAIT_UNTIL_MIN_DURATION {
            return Err(EpochServiceError::TooLow(
                wait_until,
                WAIT_UNTIL_MIN_DURATION,
            ));
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
        now: &F,
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
            || epoch_slice_duration <= WAIT_UNTIL_MIN_DURATION
            || epoch_slice_duration >= (EPOCH_DURATION / 2)
        {
            return Err(EpochServiceInitError::InvalidEpochSliceDuration);
        }

        // TODO: should we check the division: epoch_duration / epoch_slice_duration ?

        // Calculate the initial epoch and epoch slice
        let now = Utc::now();
        let (current_epoch, now_date) = Self::compute_current_epoch(genesis, &|| now);
        let current_epoch_slice =
            Self::compute_current_epoch_slice(now_date, epoch_slice_duration, &|| now);
        let (epoch_sender, epoch_receiver) =
            channel((Epoch(current_epoch), EpochSlice(current_epoch_slice)));

        Ok(Self {
            epoch_slice_duration,
            epoch_sender,
            epoch_receiver,
            genesis,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EpochServiceError {
    #[error("Computation error: {0}")]
    WaitUntilOutOfRange(#[from] OutOfRangeError),
    #[error("Wait until is too low: {0:?} (min value: {1:?}")]
    TooLow(Duration, Duration),
}

/// An Epoch (wrapper type over i64)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, From, Into, Deref)]
pub(crate) struct Epoch(i64);

impl Add<i64> for Epoch {
    type Output = Self;

    fn add(self, rhs: i64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

/// An Epoch slice (wrapper type over i64)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, From, Into, Deref)]
pub(crate) struct EpochSlice(i64);

impl Add<i64> for EpochSlice {
    type Output = Self;

    fn add(self, rhs: i64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveDateTime, TimeDelta};
    use parking_lot::Mutex;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use tracing::info;
    use tracing_test::traced_test;

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
            // Check OutOfRange case: when time advances between now() calls
            let genesis: DateTime<Utc> =
                chrono::DateTime::from_naive_utc_and_offset(datetime_0, Utc);
            let epoch_slice_duration = Duration::from_secs(60);
            let epoch_service = EpochService::try_from((epoch_slice_duration, genesis)).unwrap();

            // Simulate time drift: first 3 now() calls return the same time for consistent epoch/slice,
            // 4th call jumps past slice boundary to trigger expected OutOfRangeError
            let call_count = std::cell::Cell::new(0);
            let now = || {
                let count = call_count.get();
                call_count.set(count + 1);

                if count < 3 {
                    // Return a fixed time within the current epoch slice
                    let now_0 = date_0.and_hms_opt(0, 0, 0).unwrap() + epoch_slice_duration / 2;
                    chrono::DateTime::from_naive_utc_and_offset(now_0, chrono::Utc)
                } else {
                    // Advance time past the next epoch slice boundary
                    let now_0 = date_0.and_hms_opt(0, 0, 0).unwrap()
                        + epoch_slice_duration * 1
                        + Duration::from_secs(1);
                    chrono::DateTime::from_naive_utc_and_offset(now_0, chrono::Utc)
                }
            };

            let res = epoch_service.compute_wait_until(&now, &|| Duration::from_secs(0));

            // expect OutOfRange error
            assert!(matches!(
                res,
                Err(EpochServiceError::WaitUntilOutOfRange(_))
            ));
        }

        {
            // Check for TooLow case: when wait_until is too low
            let genesis: DateTime<Utc> =
                chrono::DateTime::from_naive_utc_and_offset(datetime_0, Utc);
            let epoch_slice_duration = Duration::from_secs(60);
            let epoch_service = EpochService::try_from((epoch_slice_duration, genesis)).unwrap();

            let now = || {
                // Start at beginning of epoch slice 1 (60 seconds from day start)
                let mut now_0: NaiveDateTime = date_0.and_hms_opt(0, 1, 0).unwrap();

                // Add almost a full epoch slice duration, leaving only 50ms until next boundary
                now_0 += epoch_slice_duration - WAIT_UNTIL_MIN_DURATION / 2;

                chrono::DateTime::from_naive_utc_and_offset(now_0, chrono::Utc)
            };

            let res = epoch_service.compute_wait_until(&now, &now);

            // expect TooLow error
            assert!(matches!(res, Err(EpochServiceError::TooLow(_, _))));
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
            EpochService::compute_current_epoch_slice(now_date, epoch_slice_duration, &now_f),
            2
        );
        // Note: 5 minutes and 59 seconds diff -> still expect == 2
        assert_eq!(
            EpochService::compute_current_epoch_slice(now_date, epoch_slice_duration, &now_f_2),
            2
        );
        // Note: 6 minutes diff -> expect == 3
        assert_eq!(
            EpochService::compute_current_epoch_slice(now_date, epoch_slice_duration, &now_f_3),
            3
        );
    }

    #[derive(thiserror::Error, Debug)]
    enum AppErrorExt {
        #[error("AppError: {0}")]
        AppError(#[from] AppError),
    }

    #[tokio::test]
    #[traced_test]
    async fn test_notify() {
        // Test that multiple receivers using changed().await + borrow() work correctly
        // Each receiver should see the same sequence of changes

        let date_0 = NaiveDate::from_ymd_opt(2025, 5, 14).unwrap();
        let datetime_0 = date_0.and_hms_opt(0, 0, 0).unwrap();
        let genesis: DateTime<Utc> = DateTime::from_naive_utc_and_offset(datetime_0, Utc);

        let epoch_slice_duration = Duration::from_secs(10);
        let epoch_service = EpochService::try_from((epoch_slice_duration, genesis)).unwrap();

        let receiver_count = 5;
        let counters: Vec<Arc<AtomicU64>> =
            (0..receiver_count).map(|_| Default::default()).collect();
        let notifications_seen: Vec<Arc<Mutex<Vec<(Epoch, EpochSlice)>>>> =
            (0..receiver_count).map(|_| Default::default()).collect();

        let mut receiver_tasks = Vec::new();

        // Spawn multiple receivers, each with its own receiver
        for i in 0..receiver_count {
            let mut epoch_changes = epoch_service.epoch_changes();
            let counter = counters[i].clone();
            let notifications = notifications_seen[i].clone();

            let task = tokio::spawn(async move {
                loop {
                    if let Err(recv_error) = epoch_changes.changed().await {
                        info!(
                            "[receiver {}] Error receiving epoch change: {:?}",
                            i, recv_error
                        );
                        break;
                    };
                    debug!("[receiver {}] Epoch update using borrow()...", i);

                    let current_value = { *epoch_changes.borrow() };
                    debug!("[receiver {}] Read value: {:?}", i, current_value);

                    notifications.lock().push(current_value);
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            });
            receiver_tasks.push(task);
        }

        let producer_task = epoch_service.listen_for_new_epoch();

        // Wait for 3 epoch slices + 500 ms (to wait to receive notification + counter incr)
        let res = tokio::time::timeout(
            epoch_slice_duration * 3 + Duration::from_millis(500),
            async {
                tokio::select! {
                    _ = producer_task => {},
                    _ = futures::future::join_all(receiver_tasks) => {},
                }
            },
        )
        .await;

        assert!(res.is_err());

        // Check that all receivers got the same number of notifications
        for (i, counter) in counters.iter().enumerate() {
            let count = counter.load(Ordering::SeqCst);
            debug!("receiver {} count: {}", i, count);
            assert_eq!(
                count, 3,
                "receiver {} should have 3 notifications, got {}",
                i, count
            );
        }

        // Check that all receivers saw the same sequence of notifications
        let first_receiver_notifications = notifications_seen[0].lock().clone();
        for i in 1..receiver_count {
            let receiver_notifications = notifications_seen[i].lock().clone();
            assert_eq!(
                first_receiver_notifications, receiver_notifications,
                "receiver {} saw different notifications than receiver 0",
                i
            );
        }

        debug!(
            "All receivers saw the same sequence: {:?}",
            first_receiver_notifications
        );
    }
}
