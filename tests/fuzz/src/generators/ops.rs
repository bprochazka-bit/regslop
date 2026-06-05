//! Weighted random operation sequence generator.
//!
//! Produces an `OpSeq` that serializes to the harness YAML test format. The walk
//! follows the category weights from CLAUDE-fuzz.md:
//!
//!   30% key ops, 30% value ops, 15% security, 10% lifecycle,
//!   10% boundary-pushing, 5% intentional misuse.
//!
//! Within a category the specific op is chosen to drive endpoint coverage even
//! (hard rule 4): mostly the least-covered op, with a fraction of purely random
//! picks for exploration. Arguments reuse keys created earlier in the same
//! sequence, so list/delete/rename/value ops land on real keys instead of always
//! erroring, which is what surfaces allocator and index bugs.
//!
//! Every sequence is self-contained: it creates one hive, operates on it, and
//! saves (so the structural and roundtrip axes have a hive to grade). The whole
//! sequence is a deterministic function of its seed.

use crate::coverage::Coverage;
use crate::generators::{paths, values};
use crate::rng::Rng;
use serde::Serialize;
use serde_json::{json, Map, Value};

/// Canned valid SDDL strings (owner, group, DACL). Reused so set/get round-trips
/// land on descriptors the agents actually parse.
const SDDL_POOL: &[&str] = &[
    "O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;BU)",
    "O:BAG:BAD:(A;;KA;;;SY)",
    "O:SYG:SYD:(A;;KA;;;BA)(A;;KR;;;WD)",
    "O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;BU)(A;;KR;;;AU)",
];

/// One generated test: serializes straight to the harness YAML format
/// (`name`, `tags`, `operations`, `expect`).
#[derive(Serialize)]
pub struct OpSeq {
    pub name: String,
    pub tags: Vec<String>,
    pub operations: Vec<Value>,
    pub expect: ExpectOut,
}

#[derive(Serialize)]
pub struct ExpectOut {
    pub semantic_equal: bool,
}

impl OpSeq {
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).unwrap_or_default()
    }
}

/// Mutable walk state: the single open hive and the keys created so far.
struct State {
    handle: String,
    /// Logical hive file path, reused by the save/close/reload macro.
    path: String,
    keys: Vec<String>,
}

impl State {
    /// An existing key to operate on: a previously created one most of the time,
    /// else the always-present root (`""`).
    fn existing_key(&self, rng: &mut Rng) -> String {
        if self.keys.is_empty() || rng.chance(1, 5) {
            String::new()
        } else {
            rng.choice(&self.keys).clone()
        }
    }
}

/// Build an operation object from `(key, value)` pairs. Using a serde_json map
/// keeps the value typing (ints, arrays, null) intact through YAML emission.
fn op(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

/// Choose an op within a category: mostly the least-covered (drives coverage to
/// even), occasionally a random pick for exploration.
fn pick<'a>(rng: &mut Rng, cov: &Coverage, candidates: &[&'a str]) -> &'a str {
    if rng.chance(1, 5) {
        rng.choice(candidates)
    } else {
        cov.least_covered(candidates)
    }
}

const KEY_OPS: &[&str] = &["key_create", "key_delete", "key_rename", "key_list", "key_info"];
const VALUE_OPS: &[&str] = &["value_set", "value_delete", "value_get"];
const SECURITY_OPS: &[&str] = &["key_security_get", "key_security_set"];
const DIAG_OPS: &[&str] = &["hive_dump", "hive_checksum", "hive_validate"];

/// Limits on the expensive boundary cases. The defaults preserve the historical
/// behavior (deep paths and a >507-entry subkey list to drive lf/lh -> ri
/// promotion). Runs against the network VM should lower both: hundreds of
/// `key_create` round-trips per sequence are painfully slow over the link, and
/// deep paths overflow the harness JSON parser (issue #121).
#[derive(Clone, Copy)]
pub struct GenOpts {
    /// Max key-path depth for generated paths and the deep-path boundary case.
    pub max_depth: usize,
    /// Max sibling count for the many-subkeys boundary case.
    pub max_subkeys: u64,
}

impl Default for GenOpts {
    fn default() -> Self {
        GenOpts { max_depth: 64, max_subkeys: 520 }
    }
}

/// Generate one sequence of about `body_len` body operations with default
/// (unrestricted) limits.
pub fn generate(seed: u64, body_len: usize, cov: &mut Coverage) -> OpSeq {
    generate_with(seed, body_len, cov, GenOpts::default())
}

/// Generate one sequence with explicit limits (see [`GenOpts`]). `cov` is updated
/// with every op emitted so a later sequence in the same run keeps balancing.
pub fn generate_with(seed: u64, body_len: usize, cov: &mut Coverage, opts: GenOpts) -> OpSeq {
    let mut rng = Rng::new(seed);
    let mut ops: Vec<Value> = Vec::new();

    let handle = "h".to_string();
    // A unique logical path per seed; the harness maps it onto each agent's fs.
    let path = format!("/tmp/fuzz_{seed:016x}.hiv");
    let mut st = State { handle: handle.clone(), path: path.clone(), keys: Vec::new() };

    ops.push(op(vec![
        ("op", json!("hive_create")),
        ("path", json!(path)),
        ("capture", json!(handle)),
    ]));
    cov.record("hive_create");

    // Category cumulative weights: key 30, value 30, security 15, lifecycle 10,
    // boundary 10, misuse 5 -> total 100.
    const CAT_CUM: &[u64] = &[30, 60, 75, 85, 95, 100];

    for _ in 0..body_len {
        match rng.weighted(CAT_CUM) {
            0 => key_op(&mut rng, cov, &mut st, &mut ops, opts),
            1 => value_op(&mut rng, cov, &mut st, &mut ops),
            2 => security_op(&mut rng, cov, &mut st, &mut ops),
            3 => lifecycle_op(&mut rng, cov, &mut st, &mut ops),
            4 => boundary_op(&mut rng, cov, &mut st, &mut ops, opts),
            _ => misuse_op(&mut rng, cov, &mut st, &mut ops),
        }
    }

    // Always finish with a save so there is a persisted hive to grade, then a
    // close half the time (exercising the close path and post-close snapshot).
    // Handles must be the `$h` reference the runner substitutes, not the bare
    // capture name, or the op hits a nonexistent handle and silently no-ops.
    ops.push(op(vec![("op", json!("hive_save")), ("handle", h(&st))]));
    cov.record("hive_save");
    if rng.chance(1, 2) {
        ops.push(op(vec![("op", json!("hive_close")), ("handle", h(&st))]));
        cov.record("hive_close");
    }

    OpSeq {
        name: format!("fuzz_{seed:016x}_n{body_len}"),
        // Graded on the cross-agent axes. (`fuzz` itself is reported separately
        // by the harness for the client fuzzer, so we tag the axes we want
        // scored here.)
        tags: vec!["semantic".into(), "structural".into(), "roundtrip".into()],
        operations: ops,
        expect: ExpectOut { semantic_equal: true },
    }
}

fn h(st: &State) -> Value {
    json!(format!("${}", st.handle))
}

fn key_op(rng: &mut Rng, cov: &mut Coverage, st: &mut State, ops: &mut Vec<Value>, opts: GenOpts) {
    let chosen = pick(rng, cov, KEY_OPS);
    cov.record(chosen);
    match chosen {
        "key_create" => {
            let p = if rng.chance(1, 2) {
                paths::common_path(rng)
            } else {
                paths::key_path_capped(rng, opts.max_depth)
            };
            ops.push(op(vec![("op", json!("key_create")), ("handle", h(st)), ("path", json!(p.clone()))]));
            if !p.is_empty() && !st.keys.contains(&p) {
                st.keys.push(p);
            }
        }
        "key_delete" => {
            let p = st.existing_key(rng);
            let recursive = rng.chance(1, 2);
            ops.push(op(vec![
                ("op", json!("key_delete")),
                ("handle", h(st)),
                ("path", json!(p.clone())),
                ("recursive", json!(recursive)),
            ]));
            if recursive {
                st.keys.retain(|k| k != &p && !k.starts_with(&format!("{p}\\")));
            } else {
                st.keys.retain(|k| k != &p);
            }
        }
        "key_rename" => {
            let p = st.existing_key(rng);
            let new_name = paths::component(rng);
            ops.push(op(vec![
                ("op", json!("key_rename")),
                ("handle", h(st)),
                ("path", json!(p)),
                ("new_name", json!(new_name)),
            ]));
        }
        "key_list" => {
            let p = st.existing_key(rng);
            ops.push(op(vec![("op", json!("key_list")), ("handle", h(st)), ("path", json!(p))]));
        }
        _ => {
            let p = st.existing_key(rng);
            ops.push(op(vec![("op", json!("key_info")), ("handle", h(st)), ("path", json!(p))]));
        }
    }
}

fn value_op(rng: &mut Rng, cov: &mut Coverage, st: &mut State, ops: &mut Vec<Value>) {
    let chosen = pick(rng, cov, VALUE_OPS);
    cov.record(chosen);
    let key = st.existing_key(rng);
    let name = if rng.chance(1, 6) { String::new() } else { paths::component(rng) };
    match chosen {
        "value_set" => {
            let (ty, data) = values::value(rng);
            ops.push(op(vec![
                ("op", json!("value_set")),
                ("handle", h(st)),
                ("key", json!(key)),
                ("name", json!(name)),
                ("type", json!(ty)),
                ("data", data),
            ]));
        }
        "value_delete" => {
            ops.push(op(vec![
                ("op", json!("value_delete")),
                ("handle", h(st)),
                ("key", json!(key)),
                ("name", json!(name)),
            ]));
        }
        _ => {
            ops.push(op(vec![
                ("op", json!("value_get")),
                ("handle", h(st)),
                ("key", json!(key)),
                ("name", json!(name)),
            ]));
        }
    }
}

fn security_op(rng: &mut Rng, cov: &mut Coverage, st: &mut State, ops: &mut Vec<Value>) {
    let chosen = pick(rng, cov, SECURITY_OPS);
    cov.record(chosen);
    let p = st.existing_key(rng);
    if chosen == "key_security_set" {
        let sddl = *rng.choice(SDDL_POOL);
        ops.push(op(vec![
            ("op", json!("key_security_set")),
            ("handle", h(st)),
            ("path", json!(p)),
            ("sddl", json!(sddl)),
        ]));
    } else {
        ops.push(op(vec![("op", json!("key_security_get")), ("handle", h(st)), ("path", json!(p))]));
    }
}

fn lifecycle_op(rng: &mut Rng, cov: &mut Coverage, st: &mut State, ops: &mut Vec<Value>) {
    match rng.below(5) {
        // Save + close + reload from disk, rebinding the same handle var. This
        // is the only path that exercises hive_load, and it folds an on-disk
        // round trip into the middle of the sequence (a strong roundtrip probe).
        0 => {
            ops.push(op(vec![("op", json!("hive_save")), ("handle", h(st))]));
            cov.record("hive_save");
            ops.push(op(vec![("op", json!("hive_close")), ("handle", h(st))]));
            cov.record("hive_close");
            ops.push(op(vec![
                ("op", json!("hive_load")),
                ("path", json!(st.path.clone())),
                ("capture", json!(st.handle.clone())),
            ]));
            cov.record("hive_load");
        }
        // Intermediate save.
        1 => {
            cov.record("hive_save");
            ops.push(op(vec![("op", json!("hive_save")), ("handle", h(st))]));
        }
        // Diagnostic read (dump/checksum/validate), which also covers those
        // endpoints.
        _ => {
            let chosen = pick(rng, cov, DIAG_OPS);
            cov.record(chosen);
            ops.push(op(vec![("op", json!(chosen)), ("handle", h(st))]));
        }
    }
}

fn boundary_op(rng: &mut Rng, cov: &mut Coverage, st: &mut State, ops: &mut Vec<Value>, opts: GenOpts) {
    cov.record("key_create");
    match rng.below(3) {
        // Very deep path (clamped to the configured max depth).
        0 => {
            let depth = (rng.range(24, 64) as usize).clamp(1, opts.max_depth.max(1));
            let p: Vec<String> = (0..depth).map(|_| paths::component(rng)).collect();
            let p = p.join("\\");
            ops.push(op(vec![("op", json!("key_create")), ("handle", h(st)), ("path", json!(p.clone()))]));
            st.keys.push(p);
        }
        // Long single-component name (around the 255 boundary).
        1 => {
            let len = *rng.choice(&[254usize, 255, 256, 257]);
            let p = "L".repeat(len);
            ops.push(op(vec![("op", json!("key_create")), ("handle", h(st)), ("path", json!(p.clone()))]));
            st.keys.push(p);
        }
        // Many sibling subkeys under one parent: drives the lf -> lh -> ri
        // subkey-list promotion (CONTRACTS.md invariant 11: an lf/lh leaf holds
        // at most 507 entries, more promotes to ri). 520 just clears that
        // threshold; larger counts are left to a dedicated stress run so the
        // general op fuzzer keeps its throughput up.
        _ => {
            let parent = paths::common_path(rng);
            let count = (*rng.choice(&[8u64, 32, 64, 520])).min(opts.max_subkeys.max(1));
            for i in 0..count {
                let p = format!("{parent}\\s{i:05}");
                ops.push(op(vec![("op", json!("key_create")), ("handle", h(st)), ("path", json!(p))]));
                cov.record("key_create");
            }
            st.keys.push(parent);
        }
    }
}

fn misuse_op(rng: &mut Rng, cov: &mut Coverage, st: &mut State, ops: &mut Vec<Value>) {
    // Deliberately invalid requests. Both agents must reject them identically;
    // a divergence here is a finding (triaged, possibly a spec question, since a
    // differ failure on a malformed input may be acceptable per CLAUDE-fuzz.md).
    match rng.below(5) {
        // Bogus (never-issued) handle.
        0 => {
            cov.record("key_list");
            ops.push(op(vec![
                ("op", json!("key_list")),
                ("handle", json!("h_bogus_handle")),
                ("path", json!("")),
            ]));
        }
        // Path starting with a separator (CONTRACTS.md: paths never start with one).
        1 => {
            cov.record("key_create");
            ops.push(op(vec![
                ("op", json!("key_create")),
                ("handle", h(st)),
                ("path", json!("\\LeadingSep")),
            ]));
        }
        // Type/data mismatch on value_set.
        2 => {
            cov.record("value_set");
            let key = st.existing_key(rng);
            let (ty, data) = values::type_mismatch(rng);
            ops.push(op(vec![
                ("op", json!("value_set")),
                ("handle", h(st)),
                ("key", json!(key)),
                ("name", json!("bad")),
                ("type", json!(ty)),
                ("data", data),
            ]));
        }
        // Unknown value type name.
        3 => {
            cov.record("value_set");
            let key = st.existing_key(rng);
            ops.push(op(vec![
                ("op", json!("value_set")),
                ("handle", h(st)),
                ("key", json!(key)),
                ("name", json!("weird")),
                ("type", json!("REG_NOT_A_TYPE")),
                ("data", json!("x")),
            ]));
        }
        // Get a value that was never set.
        _ => {
            cov.record("value_get");
            let key = st.existing_key(rng);
            ops.push(op(vec![
                ("op", json!("value_get")),
                ("handle", h(st)),
                ("key", json!(key)),
                ("name", json!("definitely_missing_value")),
            ]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness_format::TestDef;

    #[test]
    fn deterministic_same_seed() {
        let mut c1 = Coverage::new();
        let mut c2 = Coverage::new();
        let a = generate(0x1234, 40, &mut c1).to_yaml();
        let b = generate(0x1234, 40, &mut c2).to_yaml();
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_differ() {
        let mut c = Coverage::new();
        let a = generate(1, 40, &mut c).to_yaml();
        let b = generate(2, 40, &mut c).to_yaml();
        assert_ne!(a, b);
    }

    #[test]
    fn parses_as_a_harness_testdef() {
        // The whole point: every generated sequence must round-trip through the
        // harness's own TestDef parser. This catches format drift immediately.
        let mut c = Coverage::new();
        for seed in 0..50u64 {
            let yaml = generate(seed.wrapping_mul(0x9E37_79B9), 60, &mut c).to_yaml();
            let td: TestDef = serde_yaml::from_str(&yaml)
                .unwrap_or_else(|e| panic!("seed {seed}: TestDef parse failed: {e}\n{yaml}"));
            assert!(!td.operations.is_empty());
            assert!(td.tags.iter().any(|t| t == "semantic"));
            // First op is always the hive_create that captures the handle.
            let first = &td.operations[0];
            let op_key = serde_yaml::Value::String("op".to_string());
            assert_eq!(
                first.get(&op_key).and_then(|v| v.as_str()),
                Some("hive_create")
            );
        }
    }

    #[test]
    fn long_run_reaches_full_endpoint_coverage() {
        let mut c = Coverage::new();
        for i in 0..400u64 {
            generate(i.wrapping_mul(2_654_435_761), 40, &mut c);
        }
        assert!(c.unhit().is_empty(), "endpoints never hit: {:?}", c.unhit());
    }

    #[test]
    fn handles_are_substitutable_references() {
        // Every `handle` field must be the `$h` reference the runner substitutes
        // (or a deliberately bogus literal in misuse ops), never the bare capture
        // name `h`: a bare `h` is an unknown handle and the op silently no-ops,
        // which once made the trailing hive_save fail and produced phantom
        // roundtrip failures. `capture` is the opposite: it is the bare name.
        let mut c = Coverage::new();
        for seed in 0..200u64 {
            let seq = generate(seed.wrapping_mul(0x9E37_79B9), 50, &mut c);
            for o in &seq.operations {
                if let Some(handle) = o.get("handle").and_then(|v| v.as_str()) {
                    assert_ne!(
                        handle, "h",
                        "op {:?} has a bare capture-name handle that will not substitute",
                        o.get("op")
                    );
                }
                if let Some(cap) = o.get("capture").and_then(|v| v.as_str()) {
                    assert_eq!(cap, "h", "capture must be the bare var name");
                }
            }
        }
    }

    #[test]
    fn every_op_is_a_known_endpoint() {
        let mut c = Coverage::new();
        for seed in 0..100u64 {
            let seq = generate(seed, 50, &mut c);
            for o in &seq.operations {
                let name = o.get("op").and_then(|v| v.as_str()).unwrap();
                assert!(
                    crate::coverage::ALL_OPS.contains(&name),
                    "emitted unknown op {name}"
                );
            }
        }
    }
}
