//! Recovery sequence generator.
//!
//! Produces cases for the harness recovery runner (`tests/harness/src/recovery.rs`,
//! driven by `--recovery-tests-dir`). Each case is `{name, point, operations}`:
//! the operations up to and including the last `hive_save` are the committed
//! baseline; the operations after it are the uncommitted mutation M. The harness
//! captures the intended state (baseline + M) in memory, calls
//! `POST /test/crash_save { point }` instead of a normal save, reloads, and
//! asserts the recovered hive equals the intended state. A mismatch is data loss
//! or corruption in libreg's log replay.
//!
//! Unlike the operation fuzzer, every op here MUST succeed: the recovery runner
//! fails the whole case if any build op returns `ok: false`. So this generator
//! stays inside a safe subset (it only ever targets keys it has created, sets
//! well-formed values, and uses only SDDL SID aliases libreg accepts) and leaves
//! the malformed-input fuzzing to op_fuzz.

use crate::generators::values;
use crate::rng::Rng;
use serde::Serialize;
use serde_json::{json, Map, Value};

/// The three crash points libreg's `/test/crash_save` honors (CONTRACTS 0.1.9
/// "Transaction Log Behavior" / test-mode endpoints).
pub const CRASH_POINTS: &[&str] = &["after_first_log", "after_log_before_primary", "after_primary"];

/// SDDL built only from aliases libreg's agent currently accepts (SY/BA/BU/WD/RC),
/// so a `key_security_set` in the mutation always succeeds. (The missing standard
/// aliases are issue #102; using them here would just make ops fail, not test
/// recovery.)
const SAFE_SDDL: &[&str] = &[
    "O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;BU)",
    "O:SYG:SYD:(A;;KA;;;BA)(A;;KR;;;WD)",
    "O:BAG:BAD:(A;;KA;;;SY)",
];

#[derive(Serialize)]
pub struct RecSeq {
    pub name: String,
    pub point: String,
    pub operations: Vec<Value>,
}

impl RecSeq {
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).unwrap_or_default()
    }
}

fn op(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

/// A value_set op on `key` with a random well-formed payload.
fn value_set(rng: &mut Rng, key: &str, name: &str) -> Value {
    let (ty, data) = values::value(rng);
    op(vec![
        ("op", json!("value_set")),
        ("handle", json!("$h")),
        ("key", json!(key)),
        ("name", json!(name)),
        ("type", json!(ty)),
        ("data", data),
    ])
}

/// Generate one recovery case from `seed`. `keys` are simple unique names so
/// every op targets something that exists.
pub fn generate(seed: u64, point_idx: usize) -> RecSeq {
    let mut rng = Rng::new(seed);
    let mut ops: Vec<Value> = Vec::new();
    let path = format!("/tmp/rec_{seed:016x}.hiv");
    ops.push(op(vec![
        ("op", json!("hive_create")),
        ("path", json!(path)),
        ("capture", json!("h")),
    ]));

    // Baseline: a few keys and values, then commit with hive_save.
    let baseline_keys = rng.range(1, 4) as usize;
    let mut keys: Vec<String> = Vec::new();
    for i in 0..baseline_keys {
        let k = format!("Base{i}");
        ops.push(op(vec![("op", json!("key_create")), ("handle", json!("$h")), ("path", json!(k.clone()))]));
        if rng.chance(1, 2) {
            ops.push(value_set(&mut rng, &k, &format!("v{i}")));
        }
        keys.push(k);
    }
    ops.push(op(vec![("op", json!("hive_save")), ("handle", json!("$h"))]));

    // Mutation M (uncommitted): 1 to 5 ops the crash must recover. Each succeeds.
    let m = rng.range(1, 5) as usize;
    for j in 0..m {
        match rng.below(4) {
            // Add a new key.
            0 => {
                let k = format!("New{j}");
                ops.push(op(vec![("op", json!("key_create")), ("handle", json!("$h")), ("path", json!(k.clone()))]));
                keys.push(k);
            }
            // Set a value on an existing key (or root).
            1 => {
                let key = if keys.is_empty() || rng.chance(1, 4) { String::new() } else { rng.choice(&keys).clone() };
                ops.push(value_set(&mut rng, &key, &format!("m{j}")));
            }
            // Delete a baseline key (recursive, so it always succeeds).
            2 if !keys.is_empty() => {
                let idx = rng.below(keys.len() as u64) as usize;
                let k = keys.remove(idx);
                ops.push(op(vec![
                    ("op", json!("key_delete")),
                    ("handle", json!("$h")),
                    ("path", json!(k)),
                    ("recursive", json!(true)),
                ]));
            }
            // Set security on an existing key (or root) with a safe SDDL.
            _ => {
                let key = if keys.is_empty() || rng.chance(1, 4) { String::new() } else { rng.choice(&keys).clone() };
                let sddl = *rng.choice(SAFE_SDDL);
                ops.push(op(vec![
                    ("op", json!("key_security_set")),
                    ("handle", json!("$h")),
                    ("path", json!(key)),
                    ("sddl", json!(sddl)),
                ]));
            }
        }
    }
    // Guarantee at least one uncommitted mutation (so recovery has work to do).
    if ops.iter().rposition(|o| o.get("op").and_then(|v| v.as_str()) == Some("hive_save"))
        == Some(ops.len() - 1)
    {
        ops.push(value_set(&mut rng, "", "fallback_m"));
    }

    let point = CRASH_POINTS[point_idx % CRASH_POINTS.len()].to_string();
    RecSeq { name: format!("recfuzz_{seed:016x}_{point}"), point, operations: ops }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        for i in 0..50u64 {
            assert_eq!(generate(i, i as usize % 3).to_yaml(), generate(i, i as usize % 3).to_yaml());
        }
    }

    #[test]
    fn has_baseline_save_and_uncommitted_mutation() {
        for seed in 0..200u64 {
            let s = generate(seed.wrapping_mul(0x9E37_79B9), seed as usize);
            let save_pos = s
                .operations
                .iter()
                .rposition(|o| o.get("op").and_then(|v| v.as_str()) == Some("hive_save"))
                .expect("must have a baseline hive_save");
            // At least one op after the last save: the mutation M to recover.
            assert!(save_pos < s.operations.len() - 1, "no uncommitted mutation after save");
            // No hive_save appears in the mutation tail (M must stay uncommitted).
            for o in &s.operations[save_pos + 1..] {
                assert_ne!(o.get("op").and_then(|v| v.as_str()), Some("hive_save"));
            }
        }
    }

    #[test]
    fn point_is_valid() {
        for seed in 0..30u64 {
            let s = generate(seed, seed as usize);
            assert!(CRASH_POINTS.contains(&s.point.as_str()));
        }
    }
}
