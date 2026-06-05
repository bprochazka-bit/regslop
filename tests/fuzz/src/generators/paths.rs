//! Realistic key path generator.
//!
//! Real hives are not random strings: they are shallow trees of recognizable
//! names (Software, Vendor, Policies) with the occasional deep or oddly named
//! key. The generator draws mostly from a vocabulary so sequences create and
//! revisit the same paths (which is what exercises subkey indexing, the free
//! list, and rename or delete of existing keys), and occasionally emits a
//! boundary-pushing name to stress the format layer.
//!
//! Path rules from CONTRACTS.md: separator is a single backslash, paths never
//! start with a separator, and `""` is the hive root.

use crate::rng::Rng;

/// Common registry path components. Reused across a sequence so generated
/// operations collide on the same keys.
pub const VOCAB: &[&str] = &[
    "Software", "System", "Vendor", "Product", "Settings", "Policies", "Classes",
    "CurrentVersion", "Microsoft", "Windows", "Run", "Services", "Control",
    "Parameters", "Config", "App", "Data", "Cache", "User", "Default", "Env",
    "Keyboard", "Network", "Driver", "Foo", "Bar", "Baz", "Alpha", "Beta",
];

/// Names that have historically broken registry implementations. Drawn rarely.
/// None contain a backslash (that would change the path depth) but they probe
/// the name-encoding and length-handling paths in nk cells.
pub const TRICKY: &[&str] = &[
    " ",                        // single space
    "  leading",                // leading spaces
    "trailing  ",               // trailing spaces
    "Mixed.Case_Name-123",      // punctuation
    "with space",               // embedded space
    "(Default)",                // looks like the default-value sentinel
    "UPPER",                    // case-folding probe (pairs with "upper")
    "upper",
    "Ünïçødé",                  // non-ASCII: forces wide (UTF-16) nk name
    "emoji_\u{1F600}",          // astral plane -> surrogate pair
    "tab\there",                // embedded control char
    "dot.",                     // trailing dot
    "...",                      // all dots
];

/// A single path component (no separators), suitable for a `new_name` in a
/// rename or one level of a path. Mostly vocabulary, rarely tricky, rarely a
/// long generated name.
pub fn component(rng: &mut Rng) -> String {
    match rng.below(100) {
        0..=84 => rng.choice(VOCAB).to_string(),
        85..=94 => rng.choice(TRICKY).to_string(),
        // Long name: probes the 255-char (per-component) and nk name-length
        // fields. Lengths cluster around the common 255 boundary.
        _ => {
            let len = match rng.below(4) {
                0 => 254,
                1 => 255,
                2 => 256,
                _ => rng.range(1, 300),
            } as usize;
            "k".repeat(len)
        }
    }
}

/// A full key path of one or more components joined by a single backslash.
/// Depth is weighted shallow (most real keys are 1 to 4 deep) with a long tail
/// for deep-path stress, clamped to `max_depth`. Capping matters for runs
/// against the network VM (deep paths are slow and overflow the harness JSON
/// parser, issue #121); pass a large value for unrestricted local runs.
pub fn key_path_capped(rng: &mut Rng, max_depth: usize) -> String {
    let depth = match rng.below(100) {
        0..=9 => 1,
        10..=44 => 2,
        45..=74 => 3,
        75..=89 => 4,
        90..=96 => rng.range(5, 8) as usize,
        // Deep path: stress the recursion and the subkey-list chain.
        _ => rng.range(16, 64) as usize,
    }
    .clamp(1, max_depth.max(1));
    let mut parts = Vec::with_capacity(depth);
    for _ in 0..depth {
        parts.push(component(rng));
    }
    parts.join("\\")
}

/// Unrestricted depth (the historical behavior): up to ~64 deep.
pub fn key_path(rng: &mut Rng) -> String {
    key_path_capped(rng, 64)
}

/// A shallow path biased toward reuse: depth 1 to 3 drawn purely from the
/// vocabulary, so create/list/delete/rename land on the same handful of keys
/// within a sequence and actually collide.
pub fn common_path(rng: &mut Rng) -> String {
    let depth = rng.range(1, 3) as usize;
    let mut parts = Vec::with_capacity(depth);
    for _ in 0..depth {
        parts.push(rng.choice(VOCAB).to_string());
    }
    parts.join("\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_starts_with_separator() {
        let mut r = Rng::new(1);
        for _ in 0..5000 {
            let p = key_path(&mut r);
            assert!(!p.starts_with('\\'), "path started with separator: {p:?}");
        }
    }

    #[test]
    fn common_path_uses_vocab_only() {
        let mut r = Rng::new(2);
        for _ in 0..2000 {
            let p = common_path(&mut r);
            for comp in p.split('\\') {
                assert!(VOCAB.contains(&comp), "unexpected component {comp:?} in {p:?}");
            }
        }
    }

    #[test]
    fn deterministic() {
        let mut a = Rng::new(123);
        let mut b = Rng::new(123);
        for _ in 0..1000 {
            assert_eq!(key_path(&mut a), key_path(&mut b));
        }
    }
}
