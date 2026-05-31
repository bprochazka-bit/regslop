//! Write a minimal empty hive to a file, for manual verification against
//! offreg (step 3's acceptance check) before the harness is wired up.
//!
//! Usage:
//!
//! ```text
//!   cargo run --example make_empty_hive -- /tmp/empty.hiv
//! ```
//!
//! Then load `/tmp/empty.hiv` on the Windows side via offreg (ORLoadHive)
//! and confirm it opens without error.

use std::process::ExitCode;

use libreg::format::empty_hive::{build_empty_hive, EmptyHiveOptions};

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: make_empty_hive <output-path>");
        return ExitCode::FAILURE;
    };

    let bytes = build_empty_hive(&EmptyHiveOptions::default());
    match std::fs::write(&path, &bytes) {
        Ok(()) => {
            println!("wrote {} bytes to {path}", bytes.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to write {path}: {e}");
            ExitCode::FAILURE
        }
    }
}
