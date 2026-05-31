//! Build a hive with subkeys and write it to a path, for manual offreg or
//! harness testing.
//!
//! Usage: `cargo run --example make_key_hive -- /tmp/out.hiv Key1 Key2 ...`
//! With no key names it writes a hive holding a single `Test` subkey, the
//! ref_one_ascii.hiv shape.

use libreg::logical::Hive;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: make_key_hive <path> [keys...]");
    let keys: Vec<String> = args.collect();

    let mut hive = Hive::new_empty();
    if keys.is_empty() {
        hive.create_key("Test").expect("create");
    } else {
        for k in &keys {
            hive.create_key(k).expect("create");
        }
    }

    std::fs::write(&path, hive.to_file()).expect("write");
    println!("wrote {path}");
}
