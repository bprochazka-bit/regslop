//! Bytewise differ: exact file equality. Allocator divergence between two
//! independent implementations is expected at this stage, so a bytewise
//! mismatch when the semantic comparison passes is a warning, not a failure
//! (CONTRACTS.md "Test Categories", and hard rule 4 in the harness CLAUDE.md).
//!
//! The harness compares the `sha256_file` reported by `/hive/checksum` rather
//! than reading the files directly, because the Windows agent's hive lives on a
//! remote VM the harness cannot open.

#[derive(Debug, Clone, PartialEq)]
pub enum ByteVerdict {
    Equal,
    Differ { left: String, right: String },
}

pub fn compare(left_file_sha: &str, right_file_sha: &str) -> ByteVerdict {
    if left_file_sha == right_file_sha {
        ByteVerdict::Equal
    } else {
        ByteVerdict::Differ {
            left: left_file_sha.to_string(),
            right: right_file_sha.to_string(),
        }
    }
}
