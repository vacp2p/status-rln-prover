use std::collections::{BTreeMap, HashSet};
use std::ops::{ControlFlow, Deref, DerefMut};
use std::ops::{ControlFlow, Deref, DerefMut};
// third-party
use alloy::primitives::U256;
use alloy::primitives::U256;
use derive_more::{From, Into};
// internal
// use crate::user_db_service::SetTierLimitsError;
use smart_contract::{Tier, TierIndex};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, From, Into)]
pub struct TierLimit(u32);

#[derive(Debug, Clone, PartialEq, Eq, Hash, From, Into)]
pub struct TierName(String);

impl From<&str> for TierName {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug, Clone, Default, From, Into, PartialEq)]
pub struct TierLimits(BTreeMap<TierIndex, Tier>);

impl Deref for TierLimits {
    type Target = BTreeMap<TierIndex, Tier>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TierLimits {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TierLimits {
    /// Filter inactive Tier (rejected by function validate)
    pub(crate) fn filter_inactive(&mut self) -> Self {
        let map = std::mem::take(&mut self.0);
        let map_filtered = map.into_iter().filter(|(_k, v)| v.active).collect();
        Self(map_filtered)
    }

    /// Validate tier limits (unique names, increasing min & max karma, no overlaps)
    pub(crate) fn validate(&self) -> Result<(), SetTierLimitsError> {
        #[derive(Default)]
        struct Context<'a> {
            tier_names: HashSet<String>,
            prev_min_karma: Option<&'a U256>,
            prev_max_karma: Option<&'a U256>,
            prev_tx_per_epoch: Option<&'a u32>,
            prev_index: Option<&'a TierIndex>,
        }

        let _context =
            self.0
                .iter()
                .try_fold(Context::default(), |mut state, (tier_index, tier)| {
                    if !tier.active {
                        return Err(SetTierLimitsError::InactiveTier);
                    }

                    if tier.min_karma >= tier.max_karma {
                        return Err(SetTierLimitsError::InvalidMaxKarmaAmount(
                            tier.min_karma,
                            tier.max_karma,
                        ));
                    }

                    if tier.min_karma <= *state.prev_min_karma.unwrap_or(&U256::ZERO) {
                        return Err(SetTierLimitsError::InvalidMinKarmaAmount);
                    }

                    if let Some(prev_max) = state.prev_max_karma {
                        if tier.min_karma <= *prev_max {
                            return Err(SetTierLimitsError::InvalidMinKarmaAmount);
                        }
                    }

                    if tier.tx_per_epoch <= *state.prev_tx_per_epoch.unwrap_or(&0) {
                        return Err(ValidateTierLimitsError::InvalidTierLimit);
                    }

                    if state.tier_names.contains(&tier.name) {
                        return Err(ValidateTierLimitsError::NonUniqueTierName);
                    }

                    state.prev_min_karma = Some(&tier.min_karma);
                    state.prev_max_karma = Some(&tier.max_karma);
                    state.prev_tx_per_epoch = Some(&tier.tx_per_epoch);
                    state.tier_names.insert(tier.name.clone());
                    state.prev_index = Some(tier_index);
                    Ok(state)
                })?;

        Ok(())
    }

    /// Given some karma amount, find the matching Tier
    pub(crate) fn get_tier_by_karma(&self, karma_amount: &U256) -> Option<(TierIndex, Tier)> {
        struct Context<'a> {
            prev: Option<(&'a TierIndex, &'a Tier)>,
        }

        let ctx_initial = Context { prev: None };
        let ctx = self
            .0
            .iter()
            .try_fold(ctx_initial, |mut state, (tier_index, tier)| {
                if !tier.active {
                    ControlFlow::Continue(state)
                } else if karma_amount < &tier.min_karma {
                    ControlFlow::Break(state)
                } else {
                    state.prev = Some((tier_index, tier));
                    ControlFlow::Continue(state)
                }
            });

        if let Some(ctx) = ctx.break_value() {
            ctx.prev.map(|p| (*p.0, p.1.clone()))
        } else {
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidateTierLimitsError {
    #[error("Invalid Karma amount (must be increasing)")]
    InvalidKarmaAmount,
    #[error("Invalid Karma max amount (min: {0} vs max: {1})")]
    InvalidMaxAmount(U256, U256),
    #[error("Invalid Tier limit (must be increasing)")]
    InvalidTierLimit,
    #[error("Invalid Tier index (must be increasing)")]
    InvalidTierIndex,
    #[error("Non unique Tier name")]
    NonUniqueTierName,
    #[error("Non active Tier")]
    InactiveTier,
}
