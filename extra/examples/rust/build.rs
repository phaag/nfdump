// The nfdump read ABI is currently compiled into libnffile itself - there
// is no separate libnfdump-abi yet (see nfdump.h) - and this example
// deliberately builds against the in-tree build rather than an installed
// one (see ../README.md for the `pkg-config`-based alternative once
// `make install` has been run). Override with the NFDUMP_ROOT env var if
// your build lives somewhere other than three directories up from this
// crate (i.e. somewhere other than the repo this file ships in).

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let root = env::var("NFDUMP_ROOT").unwrap_or_else(|_| format!("{manifest_dir}/../../.."));
    let libdir = PathBuf::from(root).join("src/libnffile/.libs");

    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-lib=dylib=nffile");
    println!("cargo:rerun-if-env-changed=NFDUMP_ROOT");

    // Not set up here: the shared library isn't installed, so the dynamic
    // loader needs DYLD_LIBRARY_PATH (macOS) / LD_LIBRARY_PATH (Linux)
    // pointed at libdir at *run* time too - see this directory's README.
}
