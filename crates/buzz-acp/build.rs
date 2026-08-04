//! Build script for buzz-acp.
//!
//! Its only job is forcing a rebuild whenever the source-SHA env vars that
//! `src/authorization.rs` bakes in via `option_env!` change. Without this,
//! a cached/incremental build can silently keep the previous invocation's
//! `BUZZ_BUILD_SOURCE_SHA` (or `GIT_SHA`) baked into the binary even after
//! the actual source commit has moved on.

fn main() {
    println!("cargo:rerun-if-env-changed=BUZZ_BUILD_SOURCE_SHA");
    println!("cargo:rerun-if-env-changed=GIT_SHA");
}
