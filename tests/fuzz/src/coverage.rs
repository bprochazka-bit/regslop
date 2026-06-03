//! Endpoint coverage tracking.
//!
//! Hard rule 4 (CLAUDE-fuzz.md): "Track which endpoints have been hit by your
//! generators. The op generator should weigh undercovered endpoints higher."
//!
//! `Coverage` counts how many times each contract operation has been emitted.
//! The operation generator consults it to bias selection toward the
//! least-covered op within whatever category the weighted walk lands on, so a
//! long run converges to even coverage instead of leaving the rare ops (rename,
//! security) starved.

use std::collections::BTreeMap;

/// Every operation the harness runner understands, grouped by the category the
/// weighted walk uses. This is the authoritative list the generator and the
/// coverage report share; it mirrors `runner::endpoint` in the harness.
pub const ALL_OPS: &[&str] = &[
    // lifecycle
    "hive_create", "hive_load", "hive_save", "hive_close",
    // key
    "key_create", "key_delete", "key_rename", "key_list", "key_info",
    // value
    "value_set", "value_delete", "value_get",
    // security
    "key_security_get", "key_security_set",
    // diagnostics
    "hive_dump", "hive_checksum", "hive_validate",
];

#[derive(Default, Clone)]
pub struct Coverage {
    counts: BTreeMap<String, u64>,
}

impl Coverage {
    pub fn new() -> Self {
        let mut counts = BTreeMap::new();
        for op in ALL_OPS {
            counts.insert((*op).to_string(), 0);
        }
        Coverage { counts }
    }

    pub fn record(&mut self, op: &str) {
        *self.counts.entry(op.to_string()).or_insert(0) += 1;
    }

    pub fn count(&self, op: &str) -> u64 {
        self.counts.get(op).copied().unwrap_or(0)
    }

    /// Of `candidates`, the op with the fewest recorded emissions so far. Ties
    /// break by the order in `candidates`, keeping selection deterministic.
    pub fn least_covered<'a>(&self, candidates: &[&'a str]) -> &'a str {
        candidates
            .iter()
            .min_by_key(|op| self.count(op))
            .copied()
            .unwrap_or(candidates[0])
    }

    /// Fraction of known ops emitted at least once, in `[0.0, 1.0]`.
    pub fn fraction_hit(&self) -> f64 {
        let hit = ALL_OPS.iter().filter(|op| self.count(op) > 0).count();
        hit as f64 / ALL_OPS.len() as f64
    }

    /// Ops never emitted. The runner should drive these higher; an empty result
    /// means full endpoint coverage.
    pub fn unhit(&self) -> Vec<&'static str> {
        ALL_OPS.iter().copied().filter(|op| self.count(op) == 0).collect()
    }

    /// `(op, count)` pairs sorted by op name, for the coverage report.
    pub fn report(&self) -> Vec<(String, u64)> {
        ALL_OPS.iter().map(|op| ((*op).to_string(), self.count(op))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn least_covered_prefers_zero() {
        let mut c = Coverage::new();
        c.record("key_create");
        c.record("key_create");
        c.record("key_delete");
        assert_eq!(c.least_covered(&["key_create", "key_delete", "key_rename"]), "key_rename");
    }

    #[test]
    fn fraction_and_unhit_track_each_other() {
        let mut c = Coverage::new();
        assert_eq!(c.fraction_hit(), 0.0);
        assert_eq!(c.unhit().len(), ALL_OPS.len());
        for op in ALL_OPS {
            c.record(op);
        }
        assert_eq!(c.fraction_hit(), 1.0);
        assert!(c.unhit().is_empty());
    }
}
