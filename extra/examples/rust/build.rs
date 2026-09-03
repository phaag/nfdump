// Prefers the installed nfdump ABI, found via pkg-config (invoked
// directly with std::process::Command, no `pkg-config` crate needed); if
// pkg-config can't find it, falls back to the default install prefix
// (/usr/local). If nfdump isn't there either, the build fails - this
// crate doesn't reach into the nfdump source tree at all, so it builds
// identically whether or not you happen to be inside a checkout of it.

use std::env;
use std::process::Command;

fn pkg_config_libs(package: &str) -> Option<String> {
    let pkg_config = env::var("PKG_CONFIG").unwrap_or_else(|_| "pkg-config".to_string());
    let output = Command::new(pkg_config).args(["--libs", package]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn main() {
    println!("cargo:rerun-if-env-changed=PKG_CONFIG");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PREFIX");

    if let Some(libs) = pkg_config_libs("nfdump") {
        // Installed: trust pkg-config's own -L/-l flags. The installed
        // library resolves its own dependencies at run time - no loader
        // path override needed.
        for flag in libs.split_whitespace() {
            if let Some(dir) = flag.strip_prefix("-L") {
                println!("cargo:rustc-link-search=native={dir}");
            } else if let Some(name) = flag.strip_prefix("-l") {
                println!("cargo:rustc-link-lib=dylib={name}");
            }
        }
        return;
    }

    // pkg-config can't see nfdump (check PKG_CONFIG_PATH if you expected
    // it to). Assume the default install prefix instead; if nfdump isn't
    // there, linking fails with a normal "library not found" error.
    let prefix = env::var("PREFIX").unwrap_or_else(|_| "/usr/local".to_string());
    println!("cargo:rustc-link-search=native={prefix}/lib");
    println!("cargo:rustc-link-lib=dylib=nfdump");
}
