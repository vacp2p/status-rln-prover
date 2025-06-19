use std::collections::{BTreeMap, HashSet};
use std::ops::{ControlFlow, Deref, DerefMut};
// third-party
use alloy::primitives::U256;
use derive_more::{From, Into};
// internal
use crate::user_db_service::SetTierLimitsError;
use smart_contract::{Tier, TierIndex};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, From, Into)]
pub struct TierLimit(u64);

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
                        return Err(SetTierLimitsError::InvalidTierLimit);
                    }

                    if state.tier_names.contains(&tier.name) {
                        return Err(SetTierLimitsError::NonUniqueTierName);
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
                name: "Regular".to_string(),
                min_karma: U256::from(100),
                max_karma: U256::from(499),
                tx_per_epoch: 720,
                active: true,
            },
        );
        map.insert(
            TierIndex::from(3),
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

        assert_eq!(filtered.len(), 3);
        assert!(!filtered.contains_key(&TierIndex::from(3)));
    }

    #[test]
    fn test_filter_inactive_keeps_all_active_tiers() {
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
        let mut tier_limits = TierLimits::from(map);
        let original_count = tier_limits.len();

        let filtered = tier_limits.filter_inactive();

        assert_eq!(filtered.len(), original_count);
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
    fn test_min_karma_and_max_karmar_overlapping_between_tier() {
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
    fn test_validate_fails_when_min_karma_equals_max_karma() {
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
            Err(SetTierLimitsError::InvalidMaxKarmaAmount(_, _))
        ));
    }

    #[test]
    fn test_validate_fails_when_min_karma_greater_than_max_karma() {
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
            Err(SetTierLimitsError::InvalidMaxKarmaAmount(_, _))
        ));
    }

    #[test]
    fn test_validate_fails_with_non_increasing_min_karma() {
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
    }

    #[test]
    fn test_validate_fails_with_decreasing_min_karma() {
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
    fn test_validate_fails_with_non_increasing_tx_per_epoch() {
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
    }

    #[test]
    fn test_validate_fails_with_decreasing_tx_per_epoch() {
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
    fn test_get_tier_by_karma_exact_min() {
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
        let tier_limits = TierLimits::from(map);

        let result = tier_limits.get_tier_by_karma(&U256::from(10));

        assert!(result.is_some());
        let (index, tier) = result.unwrap();
        assert_eq!(index, TierIndex::from(0));
        assert_eq!(tier.name, "Basic");
    }

    #[test]
    fn test_get_tier_by_karma_between_min_max() {
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

        let result = tier_limits.get_tier_by_karma(&U256::from(250));

        assert!(result.is_some());
        let (index, tier) = result.unwrap();
        assert_eq!(index, TierIndex::from(2));
        assert_eq!(tier.name, "Regular");
    }

    #[test]
    fn test_get_tier_by_karma_at_tier_boundary() {
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
        let tier_limits = TierLimits::from(map);

        let result = tier_limits.get_tier_by_karma(&U256::from(50));

        assert!(result.is_some());
        let (index, tier) = result.unwrap();
        assert_eq!(index, TierIndex::from(1));
        assert_eq!(tier.name, "Active");
    }

    #[test]
    fn test_get_tier_by_karma_above_all_tiers() {
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

        let result = tier_limits.get_tier_by_karma(&U256::from(1000));

        assert!(result.is_some());
        let (index, tier) = result.unwrap();
        assert_eq!(index, TierIndex::from(2));
        assert_eq!(tier.name, "Regular");
    }

    #[test]
    fn test_get_tier_by_karma_below_all_tiers() {
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
        let tier_limits = TierLimits::from(map);

        let result = tier_limits.get_tier_by_karma(&U256::from(5));

        assert!(result.is_none());
    }

    #[test]
    fn test_get_tier_by_karma_with_empty_tier_limits() {
        let tier_limits = TierLimits::default();

        let result = tier_limits.get_tier_by_karma(&U256::from(100));

        assert!(result.is_none());
    }

    #[test]
    fn test_get_tier_by_karma_zero_karma() {
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
        let tier_limits = TierLimits::from(map);

        let result = tier_limits.get_tier_by_karma(&U256::ZERO);

        assert!(result.is_none());
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

    #[test]
    fn test_tier_update() {
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
        let mut tier_limits = TierLimits::from(map);

        tier_limits.insert(
            TierIndex::from(1),
            Tier {
                name: "Active Update".to_string(),
                min_karma: U256::from(50),
                max_karma: U256::from(99),
                tx_per_epoch: 240,
                active: true,
            },
        );

        assert!(tier_limits.validate().is_ok());

        let tier = tier_limits.get(&TierIndex::from(1)).unwrap();
        assert_eq!(tier.name, "Active Update");
    }

    #[test]
    fn test_tier_inactive_during_update() {
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

        let mut tier_limits = TierLimits::from(map);

        assert!(tier_limits.validate().is_ok());

        tier_limits.get_mut(&TierIndex::from(1)).unwrap().active = false;
        tier_limits.get_mut(&TierIndex::from(2)).unwrap().active = false;

        assert!(matches!(
            tier_limits.validate(),
            Err(SetTierLimitsError::InactiveTier)
        ));

        let filtered = tier_limits.filter_inactive();

        assert!(filtered.validate().is_ok());
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key(&TierIndex::from(0)));
    }
}
