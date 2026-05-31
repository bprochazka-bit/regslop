//! Semantic differ: canonical JSON equality, per CONTRACTS.md "Canonical JSON
//! Form". Both agents are expected to emit already-canonical JSON, but the
//! harness re-normalizes defensively before comparing so that whitespace, map
//! key order, and array order never cause spurious diffs.
//!
//! Timestamps: `last_write` cannot agree to the second across two independent
//! implementations, so it is normalized away by default. CONTRACTS.md treats
//! the canonical form as the equality target but does not say how cross-agent
//! timestamp skew is reconciled; that gap is filed in
//! tests/harness/spec-questions.md. Pass `ignore_timestamps: false` for a
//! strict comparison.

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Diff {
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct SemanticOptions {
    pub ignore_timestamps: bool,
}

impl Default for SemanticOptions {
    fn default() -> Self {
        SemanticOptions { ignore_timestamps: true }
    }
}

/// Compute the set of semantic differences between two canonical dumps. An
/// empty result means the two hives are semantically equal.
pub fn diff(left: &Value, right: &Value, opts: &SemanticOptions) -> Vec<Diff> {
    let l = normalize(left, opts);
    let r = normalize(right, opts);
    let mut out = Vec::new();
    diff_rec("", &l, &r, &mut out);
    out
}

const TS_SENTINEL: &str = "<ignored-timestamp>";

/// Recursively canonicalize: drop timestamps if requested, sort object keys
/// (serde_json's default Map already does this), and sort arrays of named
/// objects by name, case insensitively.
fn normalize(v: &Value, opts: &SemanticOptions) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                if opts.ignore_timestamps && k == "last_write" {
                    out.insert(k.clone(), Value::String(TS_SENTINEL.to_string()));
                } else {
                    out.insert(k.clone(), normalize(val, opts));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            let mut normed: Vec<Value> = items.iter().map(|i| normalize(i, opts)).collect();
            let all_named = !normed.is_empty()
                && normed.iter().all(|i| i.get("name").and_then(|n| n.as_str()).is_some());
            if all_named {
                normed.sort_by(|a, b| {
                    let na = a.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let nb = b.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    na.to_ascii_lowercase()
                        .cmp(&nb.to_ascii_lowercase())
                        .then_with(|| na.cmp(nb))
                });
            }
            Value::Array(normed)
        }
        other => other.clone(),
    }
}

fn diff_rec(path: &str, l: &Value, r: &Value, out: &mut Vec<Diff>) {
    match (l, r) {
        (Value::Object(lm), Value::Object(rm)) => {
            let mut keys: Vec<&String> = lm.keys().chain(rm.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match (lm.get(k), rm.get(k)) {
                    (Some(lv), Some(rv)) => diff_rec(&child, lv, rv, out),
                    (Some(_), None) => out.push(Diff {
                        path: child,
                        detail: "present on left, missing on right".to_string(),
                    }),
                    (None, Some(_)) => out.push(Diff {
                        path: child,
                        detail: "missing on left, present on right".to_string(),
                    }),
                    (None, None) => unreachable!(),
                }
            }
        }
        (Value::Array(la), Value::Array(ra)) => {
            if la.len() != ra.len() {
                out.push(Diff {
                    path: path.to_string(),
                    detail: format!("array length differs: left={}, right={}", la.len(), ra.len()),
                });
                return;
            }
            for (i, (lv, rv)) in la.iter().zip(ra.iter()).enumerate() {
                diff_rec(&format!("{path}[{i}]"), lv, rv, out);
            }
        }
        (lv, rv) if lv != rv => out.push(Diff {
            path: path.to_string(),
            detail: format!("value differs: left={lv}, right={rv}"),
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(name: &str, subkeys: Value, values: Value) -> Value {
        json!({
            "name": name,
            "last_write": "2026-01-01T00:00:00Z",
            "class_name": null,
            "security": { "sddl": "O:BAG:BA" },
            "values": values,
            "subkeys": subkeys,
        })
    }

    #[test]
    fn identical_hives_have_no_diff() {
        let h = json!({ "format_version": "0.1.0", "root": key("", json!([]), json!([])) });
        assert!(diff(&h, &h, &SemanticOptions::default()).is_empty());
    }

    #[test]
    fn subkey_order_does_not_matter() {
        let a = key("", json!([key("Alpha", json!([]), json!([])), key("Beta", json!([]), json!([]))]), json!([]));
        let b = key("", json!([key("Beta", json!([]), json!([])), key("Alpha", json!([]), json!([]))]), json!([]));
        assert!(diff(&a, &b, &SemanticOptions::default()).is_empty());
    }

    #[test]
    fn timestamps_ignored_by_default_but_not_when_strict() {
        let mut a = key("", json!([]), json!([]));
        let mut b = key("", json!([]), json!([]));
        a["last_write"] = json!("2026-01-01T00:00:00Z");
        b["last_write"] = json!("2026-05-30T09:00:00Z");
        assert!(diff(&a, &b, &SemanticOptions::default()).is_empty());
        let strict = SemanticOptions { ignore_timestamps: false };
        assert_eq!(diff(&a, &b, &strict).len(), 1);
    }

    #[test]
    fn differing_value_data_is_caught() {
        let a = key("", json!([]), json!([{ "name": "X", "type": "REG_DWORD", "data": 1 }]));
        let b = key("", json!([]), json!([{ "name": "X", "type": "REG_DWORD", "data": 2 }]));
        let d = diff(&a, &b, &SemanticOptions::default());
        assert_eq!(d.len(), 1);
        assert!(d[0].path.contains("data"));
    }

    #[test]
    fn missing_subkey_is_caught() {
        let a = key("", json!([key("Only", json!([]), json!([]))]), json!([]));
        let b = key("", json!([]), json!([]));
        let d = diff(&a, &b, &SemanticOptions::default());
        assert!(!d.is_empty());
    }
}
