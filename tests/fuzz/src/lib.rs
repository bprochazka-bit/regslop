//! libreg fuzzing core.
//!
//! Shared, deterministic building blocks for the three fuzzer binaries
//! (`op_fuzz`, `data_fuzz`, `hive_fuzz`):
//!
//! - [`rng`]: a fixed SplitMix64 so a seed fully determines a run.
//! - [`generators`]: weighted operation sequences, realistic paths, per-type
//!   value payloads.
//! - [`coverage`]: endpoint coverage tracking that steers the op generator.
//! - [`triage`]: classify, dedup, and minimize failures.
//! - [`harness_runner`]: invoke the differential harness binary on generated
//!   YAML and parse its verdict (the fuzzer never reimplements the differ).
//!
//! The harness is the judge: generators here only produce inputs and hand them
//! to `tests/harness`.

pub mod coverage;
pub mod generators;
pub mod harness_format;
pub mod harness_runner;
pub mod rng;
pub mod triage;
