//! Build script. It joins every armored key in `allowlist/` into one file in
//! `OUT_DIR` so the binary can embed the allowlist.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

/// Directory that holds the armored engineer keys, relative to the crate.
const ALLOWLIST_DIR: &str = "../../allowlist";

/// Stop the build with a message on stderr.
fn fail(message: &str) -> ! {
    println!("cargo:warning={message}");
    eprintln!("{message}");
    exit(1);
}

fn main() {
    let dir = Path::new(ALLOWLIST_DIR);
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={ALLOWLIST_DIR}");

    let Ok(entries) = fs::read_dir(dir) else {
        fail(&format!("allowlist directory {ALLOWLIST_DIR} is missing"));
    };

    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            fail(&format!("cannot read an entry in {ALLOWLIST_DIR}"));
        };
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "asc") {
            files.push(path);
        }
    }
    files.sort();

    if files.is_empty() {
        fail(&format!(
            "allowlist directory {ALLOWLIST_DIR} holds no .asc files, copy the team keys from tkhq/keys first"
        ));
    }

    let mut joined = String::new();
    for path in &files {
        println!("cargo:rerun-if-changed={}", path.display());
        let Ok(text) = fs::read_to_string(path) else {
            fail(&format!("cannot read allowlist key {}", path.display()));
        };
        joined.push_str(text.trim_end());
        joined.push('\n');
    }

    let Ok(out_dir) = env::var("OUT_DIR") else {
        fail("OUT_DIR is not set");
    };
    let out_path = Path::new(&out_dir).join("allowlist.asc");
    if fs::write(&out_path, joined).is_err() {
        fail(&format!("cannot write {}", out_path.display()));
    }
}
