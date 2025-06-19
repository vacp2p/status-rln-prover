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
        }

        let _context = self
            .0
            .iter()
            .try_fold(Context::default(), |mut state, (_, tier)| {
                if !tier.active {
                    return Err(SetTierLimitsError::InactiveTier);
                }

                if tier.min_karma >= tier.max_karma {
                    return Err(SetTierLimitsError::InvalidMaxKarmaAmount);
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
                    return Err(SetTierLimitsError::InvalidTierLimit);
                }

                if state.tier_names.contains(&tier.name) {
                    return Err(SetTierLimitsError::NonUniqueTierName);
                }

                state.prev_min_karma = Some(&tier.min_karma);
                state.prev_max_karma = Some(&tier.max_karma);
                state.prev_tx_per_epoch = Some(&tier.tx_per_epoch);
                state.tier_names.insert(tier.name.clone());
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

        match ctx {
            ControlFlow::Break(state) | ControlFlow::Continue(state) => {
                state.prev.map(|p| (*p.0, p.1.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tier_limits_tests {
    use super::*;
    use alloy::primitives::U256;
    use std::collections::BTreeMap;

    #[test]
    fn test_validate_with_empty_tier_limits() {
        let tier_limits = TierLimits::default();

        assert!(tier_limits.validate().is_ok());
    }

    #[test]
    fn test_filter_inactive_removes_inactive_tiers() {
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 6,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 120,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(2),
            Tier {
                name: "Power User".to_string(),
                min_karma: U256::from(500),
                max_karma: U256::from(999),
                tx_per_epoch: 86400,
                active: false,
            },
        );
        let mut tier_limits = TierLimits::from(map);

        let filtered = tier_limits.filter_inactive();

        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_validate_success_with_valid_tiers() {
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 6,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 120,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(2),
            Tier {
                name: "Regular".to_string(),
                min_karma: U256::from(100),
                max_karma: U256::from(499),
                tx_per_epoch: 720,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        assert!(tier_limits.validate().is_ok());
    }

    #[test]
    fn test_validate_fails_with_inactive_tier() {
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 6,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 120,
                active: false,
            },
        );
        let tier_limits = TierLimits::from(map);

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::InactiveTier)
        ));
    }

    #[test]
    fn test_validate_with_non_sequential_tier_indices() {
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 6,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(3),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 120,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(7),
            Tier {
                name: "Regular".to_string(),
                min_karma: U256::from(100),
                max_karma: U256::from(499),
                tx_per_epoch: 720,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        assert!(tier_limits.validate().is_ok());
    }

    #[test]
    fn test_validate_failed_when_karma_overlapping_between_tier() {
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(100),
                tx_per_epoch: 6,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(150),
                tx_per_epoch: 120,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::InvalidMinKarmaAmount)
        ));
    }

    #[test]
    fn test_validate_fails_when_min_karma_equal_or_greater_max_karma() {
        let mut tier_limits = TierLimits::default();
        tier_limits.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(100),
                max_karma: U256::from(100),
                tx_per_epoch: 6,
                active: true,
            },
        );

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::InvalidMaxKarmaAmount)
        ));

        let mut tier_limits = TierLimits::default();
        tier_limits.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(500),
                max_karma: U256::from(100),
                tx_per_epoch: 6,
                active: true,
            },
        );

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::InvalidMaxKarmaAmount)
        ));
    }

    #[test]
    fn test_validate_fails_with_non_increasing_or_decreasing_min_karma() {
        // Case 1: Duplicate min_karma values
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 6,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(99),
                tx_per_epoch: 120,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::InvalidMinKarmaAmount)
        ));

        // Case 2: Decreasing min_karma values
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 6,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 120,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::InvalidMinKarmaAmount)
        ));
    }

    #[test]
    fn test_validate_fails_with_non_increasing_or_decreasing_tx_per_epoch() {
        // Case 1: Duplicate tx_per_epoch values
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 120,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 120,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::InvalidTierLimit)
        ));

        // Case 2: Decreasing tx_per_epoch values
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 120,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 6,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::InvalidTierLimit)
        ));
    }

    #[test]
    fn test_validate_fails_with_duplicate_tier_names() {
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 6,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 120,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::NonUniqueTierName)
        ));
    }

    #[test]
    fn test_get_tier_by_karma_bounds_and_ranges() {
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 6,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 120,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(2),
            Tier {
                name: "Regular".to_string(),
                min_karma: U256::from(100),
                max_karma: U256::from(499),
                tx_per_epoch: 720,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        // Case 1: Zero karma
        let result = tier_limits.get_tier_by_karma(&U256::ZERO);
        assert!(result.is_none());

        // Case 2: Karma below all tiers
        let result = tier_limits.get_tier_by_karma(&U256::from(5));
        assert!(result.is_none());

        // Case 3: Exact match on min_karma
        let result = tier_limits.get_tier_by_karma(&U256::from(10));
        assert!(result.is_some());
        let (index, tier) = result.unwrap();
        assert_eq!(index, TierIndex::from(0));
        assert_eq!(tier.name, "Basic");

        // Case 4: Karma within a tier range
        let result = tier_limits.get_tier_by_karma(&U256::from(250));
        assert!(result.is_some());
        let (index, tier) = result.unwrap();
        assert_eq!(index, TierIndex::from(2));
        assert_eq!(tier.name, "Regular");

        // Case 5: Exact match on a tier boundary (start of second tier)
        let result = tier_limits.get_tier_by_karma(&U256::from(50));
        assert!(result.is_some());
        let (index, tier) = result.unwrap();
        assert_eq!(index, TierIndex::from(1));
        assert_eq!(tier.name, "Active");

        // Case 6: Karma above all tiers
        let result = tier_limits.get_tier_by_karma(&U256::from(1000));
        assert!(result.is_some());
        let (index, tier) = result.unwrap();
        assert_eq!(index, TierIndex::from(2));
        assert_eq!(tier.name, "Regular");
    }

    #[test]
    fn test_get_tier_by_karma_ignores_inactive_tiers() {
        let mut map = BTreeMap::new();
        map.insert(
            TierIndex::from(0),
            Tier {
                name: "Basic".to_string(),
                min_karma: U256::from(10),
                max_karma: U256::from(49),
                tx_per_epoch: 6,
                active: false,
            },
        );
        map.insert(
            TierIndex::from(1),
            Tier {
                name: "Active".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 120,
                active: true,
            },
        );
        let tier_limits = TierLimits::from(map);

        let result = tier_limits.get_tier_by_karma(&U256::from(25));

        assert!(result.is_none());
    }
}
