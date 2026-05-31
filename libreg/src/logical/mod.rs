//! Layer 2: logical registry operations (keys, values, security).
//!
//! This layer turns byte-level cells into a key tree. It calls DOWN into the
//! allocator (Layer 1) and the format structures (Layer 0) and never up.
//! The unit of work here is the [`Hive`]: an allocator image plus the root
//! key offset, with operations that preserve the tree invariants the harness
//! checks (each created key appears under its parent, siblings stay
//! name-sorted, security cells stay a consistent ring with exact refcounts).
//!
//! What works so far: key creation (single keys and full paths, creating any
//! missing intermediates), case-insensitive lookup, and subkey enumeration.
//! Values (step 5), deletion (step 7), lh to ri promotion (step 8), and sk
//! sharing (step 10) are not implemented yet.

pub mod index;
pub mod key;
pub mod security;

use crate::alloc::HiveImage;
use crate::format::base_block::{BaseBlock, BASE_BLOCK_SIZE};
use crate::format::empty_hive::{build_empty_hive, EmptyHiveOptions};
use crate::format::security_descriptor::default_key_security_descriptor_bytes;
use crate::format::FormatError;

/// Errors from logical-layer operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalError {
    /// A lower-layer parse or serialize error.
    Format(FormatError),
    /// A well-formed request this version does not implement yet.
    Unsupported(&'static str),
    /// A path component named a key that does not exist.
    NotFound,
}

impl From<FormatError> for LogicalError {
    fn from(e: FormatError) -> Self {
        LogicalError::Format(e)
    }
}

impl core::fmt::Display for LogicalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LogicalError::Format(e) => write!(f, "format error: {e}"),
            LogicalError::Unsupported(what) => write!(f, "unsupported: {what}"),
            LogicalError::NotFound => write!(f, "key not found"),
        }
    }
}

impl std::error::Error for LogicalError {}

/// A registry hive: an allocator-managed image plus the root key offset.
pub struct Hive {
    image: HiveImage,
    root_offset: u32,
    last_written: u64,
}

impl Hive {
    /// Create a fresh, empty hive (one root key, no subkeys).
    pub fn new_empty() -> Hive {
        let bytes = build_empty_hive(&EmptyHiveOptions::default());
        Hive::from_file_bytes(&bytes).expect("a freshly built empty hive parses")
    }

    /// Wrap an in-memory hive file: parse its base block, then manage its
    /// hive bins data with the allocator.
    pub fn from_file_bytes(file: &[u8]) -> Result<Hive, LogicalError> {
        let bb = BaseBlock::parse(file)?;
        let end = BASE_BLOCK_SIZE + bb.hbins_size as usize;
        let bins = file[BASE_BLOCK_SIZE..end].to_vec();
        Ok(Hive {
            image: HiveImage::from_bins(bins),
            root_offset: bb.root_cell_offset,
            last_written: bb.last_written,
        })
    }

    /// Serialize the hive back to a complete file (base block + bins).
    pub fn to_file(&self) -> Vec<u8> {
        self.image.to_hive_file(self.root_offset, self.last_written)
    }

    /// Offset of the root key node.
    pub fn root_offset(&self) -> u32 {
        self.root_offset
    }

    /// Create the key named by `path` (backslash-separated, relative to the
    /// root; `""` is the root). Any missing intermediate keys are created.
    /// Returns the offset of the leaf key. Creating a key that already
    /// exists is a no-op that returns its existing offset.
    pub fn create_key(&mut self, path: &str) -> Result<u32, LogicalError> {
        let mut current = self.root_offset;
        for component in components(path) {
            current = self.ensure_child(current, component)?;
        }
        Ok(current)
    }

    /// Subkey names of the key at `path`, in canonical (name-sorted) order.
    pub fn subkeys(&self, path: &str) -> Result<Vec<String>, LogicalError> {
        let off = self.resolve(path)?.ok_or(LogicalError::NotFound)?;
        let nk = key::read_nk(&self.image, off)?;
        Ok(index::list_entries(&self.image, &nk)?
            .into_iter()
            .map(|(_, name)| name)
            .collect())
    }

    /// Offset of the key at `path`, or `None` if any component is missing.
    pub fn resolve(&self, path: &str) -> Result<Option<u32>, LogicalError> {
        let mut current = self.root_offset;
        for component in components(path) {
            match self.find_child(current, component)? {
                Some(off) => current = off,
                None => return Ok(None),
            }
        }
        Ok(Some(current))
    }

    fn ensure_child(&mut self, parent_off: u32, name: &str) -> Result<u32, LogicalError> {
        match self.find_child(parent_off, name)? {
            Some(off) => Ok(off),
            None => self.add_child(parent_off, name),
        }
    }

    fn find_child(&self, parent_off: u32, name: &str) -> Result<Option<u32>, LogicalError> {
        let parent = key::read_nk(&self.image, parent_off)?;
        for (off, child_name) in index::list_entries(&self.image, &parent)? {
            if key::name_eq(name, &child_name) {
                return Ok(Some(off));
            }
        }
        Ok(None)
    }

    fn add_child(&mut self, parent_off: u32, name: &str) -> Result<u32, LogicalError> {
        // Every created key gets its own sk carrying the ratified default
        // descriptor, spliced into the root's sk ring (sharing is step 10).
        let anchor = key::read_nk(&self.image, self.root_offset)?.security_offset;
        let sk_off = security::add_sk(
            &mut self.image,
            anchor,
            default_key_security_descriptor_bytes(),
        )?;

        // Allocate and write the child nk.
        let child = key::build_child_nk(name, parent_off, sk_off, self.last_written);
        let payload = child.to_payload();
        let child_off = self.image.alloc(payload.len());
        self.image.content_mut(child_off)[..payload.len()].copy_from_slice(&payload);

        // Link it into the parent's subkey list and persist the parent.
        let mut parent = key::read_nk(&self.image, parent_off)?;
        index::insert_subkey(&mut self.image, &mut parent, child_off, name)?;
        key::write_nk_inplace(&mut self.image, parent_off, &parent);

        Ok(child_off)
    }

    #[cfg(test)]
    fn image(&self) -> &HiveImage {
        &self.image
    }
}

/// Split a hive path into its non-empty components. A leading, trailing, or
/// doubled separator yields no empty component; `""` yields nothing (root).
fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split('\\').filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::base_block::BaseBlock;
    use crate::format::hbin::walk;
    use crate::format::lh::{name_hash, HashLeaf};
    use crate::format::nk::OFFSET_NONE;
    use crate::format::sk::SecurityCell;
    use std::collections::{BTreeMap, BTreeSet};

    /// Deterministic SplitMix64, matching the allocator/base_block tests.
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Collect the sk ring starting at `start`, following flink until it
    /// returns. Panics if the ring does not close within a sane bound.
    fn sk_ring(hive: &Hive, start: u32) -> Vec<(u32, SecurityCell)> {
        let mut out = Vec::new();
        let mut cur = start;
        loop {
            let sk = SecurityCell::parse(hive.image().content(cur)).expect("sk parses");
            let next = sk.flink;
            out.push((cur, sk));
            cur = next;
            if cur == start {
                break;
            }
            assert!(out.len() < 1000, "sk ring did not close");
        }
        out
    }

    /// Assert the hive serializes to a file that parses and walks cleanly.
    fn assert_loadable(hive: &Hive) {
        let file = hive.to_file();
        let bb = BaseBlock::parse(&file).expect("base block parses");
        assert!(bb.checksum_valid(), "checksum valid");
        assert!(bb.is_clean(), "clean hive");
        let data = &file[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + bb.hbins_size as usize];
        walk(data).expect("bins walk cleanly");
    }

    #[test]
    fn create_single_key_under_root() {
        let mut hive = Hive::new_empty();
        let off = hive.create_key("Software").expect("create");

        let root = key::read_nk(hive.image(), hive.root_offset()).unwrap();
        assert_eq!(root.subkey_count, 1);
        assert_ne!(root.subkeys_list_offset, OFFSET_NONE);

        // The list is a one-element lh pointing at the new child.
        let leaf = HashLeaf::parse(hive.image().content(root.subkeys_list_offset)).unwrap();
        assert_eq!(leaf.entries.len(), 1);
        assert_eq!(leaf.entries[0].key_offset, off);
        assert_eq!(leaf.entries[0].name_hash, name_hash("Software"));

        // The child nk is well-formed and points back at the root.
        let child = key::read_nk(hive.image(), off).unwrap();
        assert_eq!(key::key_name_string(&child), "Software");
        assert!(child.name_is_ascii());
        assert_eq!(child.parent, hive.root_offset());
        assert_eq!(child.subkey_count, 0);
        assert_eq!(child.subkeys_list_offset, OFFSET_NONE);

        assert_loadable(&hive);
    }

    #[test]
    fn child_carries_the_ratified_default_security() {
        let mut hive = Hive::new_empty();
        let off = hive.create_key("Software").unwrap();
        let child = key::read_nk(hive.image(), off).unwrap();

        let sk = SecurityCell::parse(hive.image().content(child.security_offset)).unwrap();
        assert_eq!(sk.descriptor, default_key_security_descriptor_bytes());
        assert_eq!(sk.refcount, 1);

        // Ring now has the root sk plus the one child sk: a 2-element ring
        // whose forward and backward links are mutually consistent.
        let root = key::read_nk(hive.image(), hive.root_offset()).unwrap();
        let ring = sk_ring(&hive, root.security_offset);
        assert_eq!(ring.len(), 2, "root sk + child sk");
        for i in 0..ring.len() {
            let (off, sk) = &ring[i];
            let (next_off, _) = &ring[(i + 1) % ring.len()];
            assert_eq!(sk.flink, *next_off, "flink chains");
            let (_, next_sk) = &ring[(i + 1) % ring.len()];
            assert_eq!(next_sk.blink, *off, "blink mirrors flink");
        }
    }

    #[test]
    fn nested_path_creates_intermediates() {
        let mut hive = Hive::new_empty();
        let leaf = hive.create_key("A\\B\\C").expect("create nested");

        assert_eq!(hive.subkeys("").unwrap(), vec!["A"]);
        assert_eq!(hive.subkeys("A").unwrap(), vec!["B"]);
        assert_eq!(hive.subkeys("A\\B").unwrap(), vec!["C"]);
        assert_eq!(hive.resolve("A\\B\\C").unwrap(), Some(leaf));
        assert_eq!(hive.resolve("A\\B\\D").unwrap(), None);

        // Each intermediate points at its single child as parent expects.
        let b = hive.resolve("A\\B").unwrap().unwrap();
        let c = key::read_nk(hive.image(), leaf).unwrap();
        assert_eq!(c.parent, b);
        assert_loadable(&hive);
    }

    #[test]
    fn siblings_are_kept_name_sorted() {
        let mut hive = Hive::new_empty();
        // Insert out of order and in mixed case.
        hive.create_key("Beta").unwrap();
        hive.create_key("Alpha").unwrap();
        hive.create_key("gamma").unwrap();
        hive.create_key("delta").unwrap();
        // Case-insensitive ascending: ALPHA, BETA, DELTA, GAMMA.
        assert_eq!(
            hive.subkeys("").unwrap(),
            vec!["Alpha", "Beta", "delta", "gamma"]
        );
        let root = key::read_nk(hive.image(), hive.root_offset()).unwrap();
        assert_eq!(root.subkey_count, 4);
        assert_loadable(&hive);
    }

    #[test]
    fn create_is_idempotent() {
        let mut hive = Hive::new_empty();
        let first = hive.create_key("Software\\Microsoft").unwrap();
        let again = hive.create_key("Software\\Microsoft").unwrap();
        assert_eq!(first, again, "re-creating returns the same offset");

        // No duplicate children appeared at either level.
        assert_eq!(hive.subkeys("").unwrap(), vec!["Software"]);
        assert_eq!(hive.subkeys("Software").unwrap(), vec!["Microsoft"]);
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let mut hive = Hive::new_empty();
        let off = hive.create_key("Software").unwrap();
        assert_eq!(hive.resolve("SOFTWARE").unwrap(), Some(off));
        assert_eq!(hive.resolve("software").unwrap(), Some(off));
        // And re-creating under a different casing does not duplicate.
        assert_eq!(hive.create_key("SOFTWARE").unwrap(), off);
        assert_eq!(hive.subkeys("").unwrap().len(), 1);
    }

    #[test]
    fn deterministic_same_sequence_same_bytes() {
        fn build() -> Vec<u8> {
            let mut hive = Hive::new_empty();
            for p in [
                "Software\\Acme",
                "Software\\Beta",
                "System\\Setup",
                "Software\\Acme\\Inner",
            ] {
                hive.create_key(p).unwrap();
            }
            hive.to_file()
        }
        assert_eq!(build(), build(), "Hard Rule 5: reproducible bytes");
    }

    #[test]
    fn tree_invariant_holds_over_random_creates() {
        let mut hive = Hive::new_empty();
        let mut rng = SplitMix64(0x5EED_1234);
        let names = ["alpha", "bravo", "charlie", "delta"];
        // Model: parent path -> set of child names created under it.
        let mut model: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for _ in 0..120 {
            // Build a random path of depth 1..=3 from the small name set.
            let depth = 1 + rng.below(3) as usize;
            let mut comps = Vec::new();
            for _ in 0..depth {
                comps.push(names[rng.below(names.len() as u64) as usize]);
            }
            let path = comps.join("\\");
            hive.create_key(&path).expect("create");

            // Update the model: each prefix gains the next component.
            let mut prefix = String::new();
            for c in &comps {
                model
                    .entry(prefix.clone())
                    .or_default()
                    .insert(c.to_string());
                prefix = if prefix.is_empty() {
                    (*c).to_string()
                } else {
                    format!("{prefix}\\{c}")
                };
            }

            // After every create the bins still walk cleanly.
            walk(hive.image().bins()).expect("walk after create");
        }

        // Every modelled node enumerates exactly its children, name-sorted.
        for (node, children) in &model {
            let mut want: Vec<String> = children.iter().cloned().collect();
            want.sort_by(|a, b| key::cmp_name(a, b));
            assert_eq!(&hive.subkeys(node).unwrap(), &want, "children of {node:?}");
            assert!(hive.resolve(node).unwrap().is_some());
        }
        assert_loadable(&hive);
    }
}
