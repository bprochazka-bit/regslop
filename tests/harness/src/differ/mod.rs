//! Differ modules. Each implements one comparison axis from CONTRACTS.md's
//! "Test Categories": semantic (canonical JSON equality), structural
//! (invariants 1 to 18), and bytewise (exact file equality). Roundtrip and
//! recovery are orchestrated by the runner using these primitives.

pub mod bytewise;
pub mod sddl;
pub mod semantic;
pub mod structural;
