//! Layer 2: logical registry operations (keys, values, security).
//!
//! This layer turns byte-level cells into a key tree. It calls DOWN into the
//! allocator (Layer 1) and the format structures (Layer 0) and never up.
//! The unit of work here is the [`Hive`]: an allocator image plus the root
//! key offset, with operations that preserve the tree invariants the harness
//! checks (each created key appears under its parent, siblings stay
//! name-sorted, security cells stay a consistent ring with exact refcounts).
//!
//! What works: key create/delete (single keys and full paths, recursive
//! delete), case-insensitive lookup, subkey enumeration across all list forms
//! with lh->ri promotion, value set/get/delete (inline, plain, and big-data db
//! cells), and descriptor-shared sk cells with refcounting. Transaction logs
//! (step 11) are the main piece not yet implemented.

pub mod index;
pub mod key;
pub mod security;
pub mod value;

use crate::alloc::HiveImage;
use crate::format::base_block::{BaseBlock, BASE_BLOCK_SIZE};
use crate::format::empty_hive::{build_empty_hive, EmptyHiveOptions};
use crate::format::nk::OFFSET_NONE;
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
    /// A non-recursive delete was asked to remove a key that still has
    /// subkeys.
    HasSubkeys,
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
            LogicalError::HasSubkeys => write!(f, "key has subkeys (use recursive delete)"),
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
        // The base block's hbins_size field is attacker/corruption controlled,
        // so bound it against the actual file before slicing (a malformed hive
        // must error, not panic).
        let end = BASE_BLOCK_SIZE + bb.hbins_size as usize;
        if end > file.len() {
            return Err(LogicalError::Format(FormatError::OutOfBounds {
                structure: "hive bins data",
                offset: BASE_BLOCK_SIZE,
                need: bb.hbins_size as usize,
                available: file.len().saturating_sub(BASE_BLOCK_SIZE),
            }));
        }
        let bins = file[BASE_BLOCK_SIZE..end].to_vec();
        let hive = Hive {
            image: HiveImage::from_bins(bins),
            root_offset: bb.root_cell_offset,
            last_written: bb.last_written,
        };
        // The root offset must frame a real nk, or every later operation that
        // dereferences it would fault. Cell::parse_at is bounds-safe.
        hive.check_root()?;
        Ok(hive)
    }

    /// Serialize the hive back to a complete file (base block + bins).
    pub fn to_file(&self) -> Vec<u8> {
        self.image.to_hive_file(self.root_offset, self.last_written)
    }

    /// Check the root offset frames a valid nk. Uses the bounds-safe cell
    /// framer so a bogus offset returns an error rather than panicking.
    fn check_root(&self) -> Result<(), LogicalError> {
        let cell =
            crate::format::cell::Cell::parse_at(self.image.bins(), self.root_offset as usize)?;
        crate::format::nk::KeyNode::parse(cell.data)?;
        Ok(())
    }

    /// Structural validation of the hive: a list of problem descriptions
    /// (empty means valid). Checks the cell walk (invariants 5, 6, 9, 10) and
    /// that the root cell frames an nk. This is the offline structural check
    /// behind `GET /hive/validate`; deeper differential checks are the
    /// harness's job.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if let Err(e) = crate::format::hbin::walk(self.image.bins()) {
            problems.push(format!("cell walk failed: {e}"));
        }
        match crate::format::cell::Cell::parse_at(self.image.bins(), self.root_offset as usize) {
            Ok(cell) => {
                if let Err(e) = crate::format::nk::KeyNode::parse(cell.data) {
                    problems.push(format!("root is not a valid nk: {e}"));
                }
            }
            Err(e) => problems.push(format!("root cell invalid: {e}")),
        }
        problems
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

    /// Set the value `name` on the key at `path` to `data` of type
    /// `data_type` (a REG_* code; data is raw bytes). Creates the value or
    /// replaces an existing one of that name. The default value is name `""`.
    pub fn set_value(
        &mut self,
        path: &str,
        name: &str,
        data_type: u32,
        data: &[u8],
    ) -> Result<(), LogicalError> {
        let off = self.resolve(path)?.ok_or(LogicalError::NotFound)?;
        value::set(&mut self.image, off, name, data_type, data)
    }

    /// Get the value `name` on the key at `path` as `(type, data)`, or `None`
    /// when the key has no such value.
    pub fn get_value(
        &self,
        path: &str,
        name: &str,
    ) -> Result<Option<(u32, Vec<u8>)>, LogicalError> {
        let off = self.resolve(path)?.ok_or(LogicalError::NotFound)?;
        value::get(&self.image, off, name)
    }

    /// Value names on the key at `path`, in stored order.
    pub fn values(&self, path: &str) -> Result<Vec<String>, LogicalError> {
        let off = self.resolve(path)?.ok_or(LogicalError::NotFound)?;
        value::list_names(&self.image, off)
    }

    /// Delete the value `name` from the key at `path`, returning whether it
    /// existed. Frees the value's cells.
    pub fn delete_value(&mut self, path: &str, name: &str) -> Result<bool, LogicalError> {
        let off = self.resolve(path)?.ok_or(LogicalError::NotFound)?;
        value::delete(&mut self.image, off, name)
    }

    /// Delete the key at `path`, detaching it from its parent and freeing its
    /// nk, subkey/value lists, value data, and its share of its sk. With
    /// `recursive` false, a key that still has subkeys is rejected
    /// ([`LogicalError::HasSubkeys`]); with it true, the whole subtree goes.
    /// The root key cannot be deleted.
    pub fn delete_key(&mut self, path: &str, recursive: bool) -> Result<(), LogicalError> {
        let key_off = self.resolve(path)?.ok_or(LogicalError::NotFound)?;
        if key_off == self.root_offset {
            return Err(LogicalError::Unsupported("cannot delete the root key"));
        }
        let nk = key::read_nk(&self.image, key_off)?;
        if nk.subkey_count > 0 && !recursive {
            return Err(LogicalError::HasSubkeys);
        }

        // Detach from the parent first, while this key's nk is still valid for
        // the name lookup the rebuild needs; then free the subtree.
        let mut parent = key::read_nk(&self.image, nk.parent)?;
        index::remove_subkey(&mut self.image, &mut parent, key_off)?;
        key::write_nk_inplace(&mut self.image, nk.parent, &parent);
        free_subtree(&mut self.image, key_off)?;
        Ok(())
    }

    /// The raw self-relative security descriptor bytes of the key at `path`.
    /// The agent converts these to/from SDDL on the wire (CONTRACTS Security).
    pub fn key_security(&self, path: &str) -> Result<Vec<u8>, LogicalError> {
        let off = self.resolve(path)?.ok_or(LogicalError::NotFound)?;
        let nk = key::read_nk(&self.image, off)?;
        let sk = crate::format::sk::SecurityCell::parse(self.image.content(nk.security_offset))?;
        Ok(sk.descriptor)
    }

    /// Set the security descriptor of the key at `path` to `descriptor` (raw
    /// self-relative bytes; the agent converts from SDDL). The key is pointed
    /// at the sk that carries this descriptor, sharing an existing one (with a
    /// refcount bump) or allocating a new sk, and its previous sk reference is
    /// released (freed when it drops to zero). Setting the descriptor a key
    /// already has is a no-op.
    pub fn set_key_security(
        &mut self,
        path: &str,
        descriptor: Vec<u8>,
    ) -> Result<(), LogicalError> {
        let off = self.resolve(path)?.ok_or(LogicalError::NotFound)?;
        let mut nk = key::read_nk(&self.image, off)?;
        let old_sk = nk.security_offset;

        // The root's sk is always a live ring member to search from / link to.
        let anchor = key::read_nk(&self.image, self.root_offset)?.security_offset;
        let new_sk = security::ensure_sk(&mut self.image, anchor, descriptor)?;
        if new_sk != old_sk {
            nk.security_offset = new_sk;
            key::write_nk_inplace(&mut self.image, off, &nk);
        }
        // Drop the key's old reference. When the descriptor was unchanged this
        // exactly undoes the bump ensure_sk just made (a clean no-op).
        security::release_sk(&mut self.image, old_sk)?;
        Ok(())
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
        // A created key carries the ratified default descriptor, shared with
        // every other key that has the same descriptor (offreg deduplicates;
        // see ref_multi.hiv). Since the root carries the same descriptor, the
        // common case reuses the root's sk and bumps its refcount.
        let anchor = key::read_nk(&self.image, self.root_offset)?.security_offset;
        let sk_off = security::ensure_sk(
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

/// Free a key and its entire subtree: every descendant key, their subkey and
/// value lists (and ri leaves), value data cells, sk references, and nk cells.
/// Does NOT detach `key_off` from its parent (the caller does that first, while
/// the nk is still valid for its name). Post-order, so a cell is freed only
/// after everything reachable through it.
fn free_subtree(image: &mut HiveImage, key_off: u32) -> Result<(), LogicalError> {
    let nk = key::read_nk(image, key_off)?;
    for (child_off, _) in index::list_entries(image, &nk)? {
        free_subtree(image, child_off)?;
    }
    if nk.subkeys_list_offset != OFFSET_NONE {
        index::free_subkey_list(image, nk.subkeys_list_offset)?;
    }
    value::free_all(image, &nk)?;
    security::release_sk(image, nk.security_offset)?;
    image.free(key_off);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::base_block::BaseBlock;
    use crate::format::hbin::walk;
    use crate::format::lh::{name_hash, HashLeaf};
    use crate::format::sk::SecurityCell;
    use crate::format::vk::ValueKey;
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
    fn child_shares_the_root_security_cell() {
        // offreg shares one sk for keys with an identical descriptor (the
        // root and its children all use the ratified default), bumping the
        // refcount rather than allocating a per-key sk. See ref_multi.hiv.
        let mut hive = Hive::new_empty();
        let off = hive.create_key("Software").unwrap();
        let child = key::read_nk(hive.image(), off).unwrap();
        let root = key::read_nk(hive.image(), hive.root_offset()).unwrap();

        // The child points at the very same sk cell as the root.
        assert_eq!(child.security_offset, root.security_offset, "shared sk");

        let sk = SecurityCell::parse(hive.image().content(child.security_offset)).unwrap();
        assert_eq!(sk.descriptor, default_key_security_descriptor_bytes());
        assert_eq!(sk.refcount, 2, "root + one child reference the sk");

        // The ring is still a single lone sk (self-linked).
        let ring = sk_ring(&hive, root.security_offset);
        assert_eq!(ring.len(), 1, "one shared sk, not one per key");
        assert_eq!(ring[0].1.flink, root.security_offset);
        assert_eq!(ring[0].1.blink, root.security_offset);
    }

    #[test]
    fn many_keys_share_one_sk_with_summed_refcount() {
        // Mirrors ref_multi.hiv: 6 children plus the root share one sk with
        // refcount 7 (the step 10 invariant, pulled forward to match offreg).
        let mut hive = Hive::new_empty();
        for name in ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot"] {
            hive.create_key(name).unwrap();
        }
        let root = key::read_nk(hive.image(), hive.root_offset()).unwrap();
        let ring = sk_ring(&hive, root.security_offset);
        assert_eq!(ring.len(), 1, "single shared sk");
        assert_eq!(ring[0].1.refcount, 7, "root + 6 children");
        assert_loadable(&hive);
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

    // REG_* type codes used by the value tests.
    const REG_SZ: u32 = 1;
    const REG_BINARY: u32 = 3;
    const REG_DWORD: u32 = 4;

    #[test]
    fn set_and_get_inline_value() {
        let mut hive = Hive::new_empty();
        hive.create_key("Software").unwrap();
        hive.set_value("Software", "Count", REG_DWORD, &7u32.to_le_bytes())
            .unwrap();

        let (ty, data) = hive.get_value("Software", "Count").unwrap().unwrap();
        assert_eq!(ty, REG_DWORD);
        assert_eq!(data, 7u32.to_le_bytes());

        // 4-byte data is stored inline: no extra data cell allocated, so the
        // key's value list points straight at the vk.
        assert_eq!(hive.values("Software").unwrap(), vec!["Count"]);
        let nk = key::read_nk(hive.image(), hive.resolve("Software").unwrap().unwrap()).unwrap();
        assert_eq!(nk.value_count, 1);
        assert_loadable(&hive);
    }

    #[test]
    fn set_and_get_out_of_line_value() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        // Larger than 4 bytes: stored in a separate data cell.
        let blob: Vec<u8> = (0..64u8).collect();
        hive.set_value("K", "Blob", REG_BINARY, &blob).unwrap();

        let (ty, data) = hive.get_value("K", "Blob").unwrap().unwrap();
        assert_eq!(ty, REG_BINARY);
        assert_eq!(data, blob);
        assert_loadable(&hive);
    }

    #[test]
    fn default_value_uses_empty_name() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        hive.set_value("K", "", REG_SZ, b"hi\0").unwrap();
        let (ty, data) = hive.get_value("K", "").unwrap().unwrap();
        assert_eq!(ty, REG_SZ);
        assert_eq!(data, b"hi\0");
        assert_eq!(hive.values("K").unwrap(), vec![""]);
    }

    #[test]
    fn setting_same_name_replaces() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        // Start inline, then replace with out-of-line data of a new type.
        hive.set_value("K", "V", REG_DWORD, &1u32.to_le_bytes())
            .unwrap();
        let long: Vec<u8> = vec![0xEE; 40];
        hive.set_value("K", "V", REG_BINARY, &long).unwrap();

        let (ty, data) = hive.get_value("K", "V").unwrap().unwrap();
        assert_eq!(ty, REG_BINARY);
        assert_eq!(data, long);
        // Still a single value, not a duplicate.
        assert_eq!(hive.values("K").unwrap(), vec!["V"]);
        assert_loadable(&hive);
    }

    #[test]
    fn value_lookup_is_case_insensitive() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        hive.set_value("K", "Path", REG_SZ, b"x\0").unwrap();
        assert!(hive.get_value("K", "PATH").unwrap().is_some());
        assert!(hive.get_value("K", "path").unwrap().is_some());
        // Re-setting under different casing replaces rather than duplicates.
        hive.set_value("K", "PATH", REG_SZ, b"y\0").unwrap();
        assert_eq!(hive.values("K").unwrap().len(), 1);
    }

    #[test]
    fn multiple_values_on_one_key() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        hive.set_value("K", "a", REG_DWORD, &1u32.to_le_bytes())
            .unwrap();
        hive.set_value("K", "b", REG_BINARY, &[9u8; 50]).unwrap();
        hive.set_value("K", "c", REG_DWORD, &3u32.to_le_bytes())
            .unwrap();
        assert_eq!(hive.values("K").unwrap(), vec!["a", "b", "c"]);
        assert_eq!(
            hive.get_value("K", "b").unwrap().unwrap(),
            (REG_BINARY, vec![9u8; 50])
        );
        assert_loadable(&hive);
    }

    #[test]
    fn missing_value_is_none() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        assert_eq!(hive.get_value("K", "nope").unwrap(), None);
        assert_eq!(hive.values("K").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn values_are_byte_deterministic() {
        fn build() -> Vec<u8> {
            let mut hive = Hive::new_empty();
            hive.create_key("Software\\App").unwrap();
            hive.set_value("Software\\App", "Mode", REG_DWORD, &2u32.to_le_bytes())
                .unwrap();
            hive.set_value("Software\\App", "Name", REG_SZ, b"x\0")
                .unwrap();
            hive.set_value("Software\\App", "Data", REG_BINARY, &[1u8; 32])
                .unwrap();
            hive.to_file()
        }
        assert_eq!(build(), build(), "Hard Rule 5: reproducible bytes");
    }

    /// Allocated-cell count of a hive's bins, used to check delete reclaims.
    fn allocated_cells(hive: &Hive) -> usize {
        walk(hive.image().bins()).expect("walk").allocated_cells
    }

    fn root_sk_refcount(hive: &Hive) -> u32 {
        let root = key::read_nk(hive.image(), hive.root_offset()).unwrap();
        SecurityCell::parse(hive.image().content(root.security_offset))
            .unwrap()
            .refcount
    }

    #[test]
    fn delete_value_removes_just_that_value() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        hive.set_value("K", "a", REG_DWORD, &1u32.to_le_bytes())
            .unwrap();
        hive.set_value("K", "b", REG_SZ, b"x\0").unwrap();

        assert!(hive.delete_value("K", "a").unwrap(), "existed");
        assert_eq!(hive.values("K").unwrap(), vec!["b"]);
        assert_eq!(hive.get_value("K", "a").unwrap(), None);
        assert!(!hive.delete_value("K", "a").unwrap(), "already gone");
        assert_loadable(&hive);
    }

    #[test]
    fn delete_last_value_drops_the_list() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        // An out-of-line value: deleting it must free both the vk and the data
        // cell, returning the allocation count to the pre-set value.
        let before = allocated_cells(&hive);
        hive.set_value("K", "big", REG_BINARY, &[7u8; 64]).unwrap();
        hive.delete_value("K", "big").unwrap();
        assert_eq!(hive.values("K").unwrap(), Vec::<String>::new());
        assert_eq!(allocated_cells(&hive), before, "vk + data + list reclaimed");
        let nk = key::read_nk(hive.image(), hive.resolve("K").unwrap().unwrap()).unwrap();
        assert_eq!(nk.values_list_offset, OFFSET_NONE);
        assert_loadable(&hive);
    }

    #[test]
    fn delete_leaf_key_reclaims_to_empty() {
        let mut hive = Hive::new_empty();
        let empty_alloc = allocated_cells(&hive); // root nk + root sk
        hive.create_key("Software").unwrap();
        hive.delete_key("Software", false).unwrap();

        assert_eq!(hive.subkeys("").unwrap(), Vec::<String>::new());
        let root = key::read_nk(hive.image(), hive.root_offset()).unwrap();
        assert_eq!(root.subkey_count, 0);
        assert_eq!(root.subkeys_list_offset, OFFSET_NONE);
        assert_eq!(
            allocated_cells(&hive),
            empty_alloc,
            "child nk + lh reclaimed"
        );
        assert_eq!(root_sk_refcount(&hive), 1, "shared sk back to root only");
        assert_loadable(&hive);
    }

    #[test]
    fn delete_nonempty_key_requires_recursive() {
        let mut hive = Hive::new_empty();
        hive.create_key("A\\B").unwrap();
        assert_eq!(hive.delete_key("A", false), Err(LogicalError::HasSubkeys));
        // Nothing changed.
        assert_eq!(hive.subkeys("").unwrap(), vec!["A"]);
        assert_eq!(hive.subkeys("A").unwrap(), vec!["B"]);
    }

    #[test]
    fn recursive_delete_removes_the_whole_subtree() {
        let mut hive = Hive::new_empty();
        let empty_alloc = allocated_cells(&hive);
        hive.create_key("A\\B\\C").unwrap();
        hive.create_key("A\\D").unwrap();
        hive.set_value("A\\B\\C", "v", REG_DWORD, &9u32.to_le_bytes())
            .unwrap();

        hive.delete_key("A", true).unwrap();
        assert_eq!(hive.resolve("A").unwrap(), None);
        assert_eq!(hive.subkeys("").unwrap(), Vec::<String>::new());
        assert_eq!(
            allocated_cells(&hive),
            empty_alloc,
            "entire subtree reclaimed"
        );
        assert_eq!(root_sk_refcount(&hive), 1);
        assert_loadable(&hive);
    }

    #[test]
    fn cannot_delete_root() {
        let mut hive = Hive::new_empty();
        assert!(matches!(
            hive.delete_key("", false),
            Err(LogicalError::Unsupported(_))
        ));
    }

    #[test]
    fn delete_decrements_shared_sk_refcount() {
        let mut hive = Hive::new_empty();
        hive.create_key("A").unwrap();
        hive.create_key("B").unwrap();
        assert_eq!(root_sk_refcount(&hive), 3, "root + A + B");
        hive.delete_key("A", false).unwrap();
        assert_eq!(root_sk_refcount(&hive), 2);
        hive.delete_key("B", false).unwrap();
        assert_eq!(root_sk_refcount(&hive), 1);
    }

    #[test]
    fn delete_then_recreate() {
        let mut hive = Hive::new_empty();
        hive.create_key("X\\Y").unwrap();
        hive.delete_key("X", true).unwrap();
        // Re-creating the same path works after the cells were reclaimed.
        let off = hive.create_key("X\\Y").unwrap();
        assert_eq!(hive.resolve("X\\Y").unwrap(), Some(off));
        assert_loadable(&hive);
    }

    #[test]
    fn delete_is_byte_deterministic() {
        fn build() -> Vec<u8> {
            let mut hive = Hive::new_empty();
            for k in ["a", "b", "c", "d"] {
                hive.create_key(k).unwrap();
            }
            hive.delete_key("b", false).unwrap();
            hive.delete_key("d", false).unwrap();
            hive.to_file()
        }
        assert_eq!(build(), build(), "Hard Rule 5 across deletes");
    }

    /// Deterministic test blob of `n` bytes.
    fn blob(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// Parse the vk of the first value of the key at `path`.
    fn first_value_vk(hive: &Hive, path: &str) -> ValueKey {
        let off = hive.resolve(path).unwrap().unwrap();
        let nk = key::read_nk(hive.image(), off).unwrap();
        let list = hive.image().content(nk.values_list_offset);
        let vk_off = u32::from_le_bytes([list[0], list[1], list[2], list[3]]);
        ValueKey::parse(hive.image().content(vk_off)).unwrap()
    }

    #[test]
    fn big_value_round_trips_through_a_db_cell() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        let data = blob(100_000);
        hive.set_value("K", "blob", REG_BINARY, &data).unwrap();

        // Read back identical.
        assert_eq!(
            hive.get_value("K", "blob").unwrap().unwrap(),
            (REG_BINARY, data.clone())
        );

        // It is actually stored as a db cell (not one giant plain cell).
        let vk = first_value_vk(&hive, "K");
        assert!(!vk.is_inline());
        assert_eq!(vk.data_len() as usize, 100_000);
        assert_eq!(
            &hive.image().content(vk.data_offset)[0..2],
            b"db",
            "data offset points at a db cell"
        );
        assert_loadable(&hive);
    }

    #[test]
    fn db_boundary_is_16344() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();

        // 16344 bytes: a single plain data cell (no db).
        hive.set_value("K", "edge", REG_BINARY, &blob(16344))
            .unwrap();
        assert_eq!(hive.get_value("K", "edge").unwrap().unwrap().1, blob(16344));
        assert_ne!(
            &hive.image().content(first_value_vk(&hive, "K").data_offset)[0..2],
            b"db",
            "16344 stays a plain data cell"
        );

        // 16345 bytes: promotes to a db cell.
        hive.set_value("K", "edge", REG_BINARY, &blob(16345))
            .unwrap();
        assert_eq!(hive.get_value("K", "edge").unwrap().unwrap().1, blob(16345));
        assert_eq!(
            &hive.image().content(first_value_vk(&hive, "K").data_offset)[0..2],
            b"db",
            "16345 needs a db cell"
        );
        assert_loadable(&hive);
    }

    #[test]
    fn big_value_survives_save_and_reload() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        let data = blob(70_000);
        hive.set_value("K", "v", REG_BINARY, &data).unwrap();

        let reloaded = Hive::from_file_bytes(&hive.to_file()).unwrap();
        assert_eq!(
            reloaded.get_value("K", "v").unwrap().unwrap(),
            (REG_BINARY, data)
        );
    }

    #[test]
    fn deleting_big_value_reclaims_all_segments() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        let before = walk(hive.image().bins()).unwrap().allocated_cells;
        hive.set_value("K", "v", REG_BINARY, &blob(100_000))
            .unwrap();
        hive.delete_value("K", "v").unwrap();
        // The db cell, segment list, and every segment cell are freed.
        assert_eq!(walk(hive.image().bins()).unwrap().allocated_cells, before);
        assert_loadable(&hive);
    }

    #[test]
    fn replacing_big_value_with_small_frees_segments() {
        let mut hive = Hive::new_empty();
        hive.create_key("K").unwrap();
        hive.set_value("K", "v", REG_BINARY, &blob(100_000))
            .unwrap();
        // Replace with inline data; the old db structure must be released.
        hive.set_value("K", "v", REG_DWORD, &1u32.to_le_bytes())
            .unwrap();
        assert_eq!(
            hive.get_value("K", "v").unwrap().unwrap(),
            (REG_DWORD, 1u32.to_le_bytes().to_vec())
        );
        // And back to big again still round-trips.
        hive.set_value("K", "v", REG_BINARY, &blob(40_000)).unwrap();
        assert_eq!(hive.get_value("K", "v").unwrap().unwrap().1, blob(40_000));
        assert_loadable(&hive);
    }

    /// The sk descriptor a key currently points at.
    fn sk_descriptor(hive: &Hive, path: &str) -> Vec<u8> {
        hive.key_security(path).unwrap()
    }

    fn sk_offset(hive: &Hive, path: &str) -> u32 {
        let off = hive.resolve(path).unwrap().unwrap();
        key::read_nk(hive.image(), off).unwrap().security_offset
    }

    #[test]
    fn set_key_security_changes_the_descriptor() {
        // A descriptor distinct from the ratified default the root carries.
        let custom = crate::format::sk::default_security_descriptor();
        let mut hive = Hive::new_empty();
        hive.create_key("A").unwrap();
        assert_eq!(root_sk_refcount(&hive), 2, "root + A share the default sk");

        hive.set_key_security("A", custom.clone()).unwrap();
        assert_eq!(sk_descriptor(&hive, "A"), custom);
        // A moved to its own sk; the shared default is back to just the root.
        assert_ne!(
            sk_offset(&hive, "A"),
            sk_offset(&hive, ""),
            "A no longer shares root sk"
        );
        assert_eq!(root_sk_refcount(&hive), 1);
        assert_loadable(&hive);
    }

    #[test]
    fn setting_the_same_descriptor_is_a_noop() {
        let mut hive = Hive::new_empty();
        hive.create_key("A").unwrap();
        let before_off = sk_offset(&hive, "A");
        let before_rc = root_sk_refcount(&hive);

        hive.set_key_security("A", default_key_security_descriptor_bytes())
            .unwrap();
        assert_eq!(sk_offset(&hive, "A"), before_off, "still the shared sk");
        assert_eq!(root_sk_refcount(&hive), before_rc, "refcount unchanged");
    }

    #[test]
    fn keys_with_the_same_new_descriptor_share_one_sk() {
        let custom = crate::format::sk::default_security_descriptor();
        let mut hive = Hive::new_empty();
        hive.create_key("A").unwrap();
        hive.create_key("B").unwrap();
        hive.set_key_security("A", custom.clone()).unwrap();
        hive.set_key_security("B", custom.clone()).unwrap();

        assert_eq!(sk_offset(&hive, "A"), sk_offset(&hive, "B"), "shared sk");
        assert_eq!(sk_descriptor(&hive, "A"), custom);
        assert_eq!(sk_descriptor(&hive, "B"), custom);
        // The shared custom sk has refcount 2; the root's default is back to 1.
        let custom_rc = SecurityCell::parse(hive.image().content(sk_offset(&hive, "A")))
            .unwrap()
            .refcount;
        assert_eq!(custom_rc, 2);
        assert_eq!(root_sk_refcount(&hive), 1);
        assert_loadable(&hive);
    }

    #[test]
    fn set_security_survives_save_and_reload() {
        let custom = crate::format::sk::default_security_descriptor();
        let mut hive = Hive::new_empty();
        hive.create_key("A").unwrap();
        hive.set_key_security("A", custom.clone()).unwrap();

        let reloaded = Hive::from_file_bytes(&hive.to_file()).unwrap();
        assert_eq!(reloaded.key_security("A").unwrap(), custom);
    }

    #[test]
    fn from_file_bytes_rejects_truncated_bins() {
        // The base block claims a 4096-byte hbin but only 100 bytes follow.
        let bytes = Hive::new_empty().to_file();
        let truncated = &bytes[..BASE_BLOCK_SIZE + 100];
        assert!(matches!(
            Hive::from_file_bytes(truncated),
            Err(LogicalError::Format(_))
        ));
    }

    #[test]
    fn from_file_bytes_rejects_bogus_root_offset() {
        let mut bytes = Hive::new_empty().to_file();
        // Root cell offset lives at base block offset 36; point it past the bins.
        bytes[36..40].copy_from_slice(&0x00ff_ffffu32.to_le_bytes());
        assert!(matches!(
            Hive::from_file_bytes(&bytes),
            Err(LogicalError::Format(_))
        ));
    }

    #[test]
    fn from_file_bytes_round_trips_a_real_hive() {
        let mut hive = Hive::new_empty();
        hive.create_key("Software\\App").unwrap();
        let reloaded = Hive::from_file_bytes(&hive.to_file()).unwrap();
        assert_eq!(reloaded.subkeys("Software").unwrap(), vec!["App"]);
    }

    #[test]
    fn validate_passes_for_valid_hives() {
        let mut hive = Hive::new_empty();
        assert!(hive.validate().is_empty(), "empty: {:?}", hive.validate());
        hive.create_key("A\\B").unwrap();
        hive.set_value("A", "v", REG_DWORD, &1u32.to_le_bytes())
            .unwrap();
        assert!(
            hive.validate().is_empty(),
            "populated: {:?}",
            hive.validate()
        );
    }

    #[test]
    fn validate_flags_structural_corruption() {
        // Root stays intact (so it loads), but the sk cell's size is zeroed,
        // which the cell walk catches.
        let mut bytes = Hive::new_empty().to_file();
        let sk_size_field = BASE_BLOCK_SIZE + 0x78; // sk cell at bins offset 0x78
        bytes[sk_size_field..sk_size_field + 4].copy_from_slice(&0u32.to_le_bytes());
        let hive = Hive::from_file_bytes(&bytes).expect("loads, root still valid");
        assert!(!hive.validate().is_empty(), "walk corruption flagged");
    }
}
