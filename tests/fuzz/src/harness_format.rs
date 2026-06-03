//! Mirror of the harness's test-definition parse format.
//!
//! The harness (`tests/harness/src/runner.rs`) is a binary crate, so we cannot
//! depend on it as a library. This struct is a deliberate copy of its `TestDef`
//! / `Expect`, used only to assert that every sequence we emit parses exactly as
//! the harness will parse it. If the harness changes its format, this mirror and
//! the generator both need updating, and the `parses_as_a_harness_testdef` test
//! is what will catch the drift.
//!
//! Keep field names, defaults, and types identical to the harness.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TestDef {
    #[allow(dead_code)]
    pub name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub operations: Vec<serde_yaml::Mapping>,
    #[serde(default)]
    #[allow(dead_code)]
    pub expect: Expect,
}

#[derive(Debug, Default, Deserialize)]
pub struct Expect {
    #[serde(default)]
    #[allow(dead_code)]
    pub semantic_equal: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    pub structural_valid: Option<Vec<String>>,
}
