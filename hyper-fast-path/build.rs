use beeper::build::clang_args;
use std::{env, fs, os::unix::fs::symlink, path::PathBuf, process::Command};
use xbpf::build::Builder;

/// The compilers that may know about the `__arena` address space, in the order
/// they are tried. Anything older than clang 19 does not.
const CLANG: &[&str] = &[
    "clang",
    "/usr/lib/llvm-21/bin/clang",
    "/usr/lib/llvm-20/bin/clang",
    "/usr/lib/llvm-19/bin/clang",
];

/// Whether `clang` can compile an access to arena memory.
fn supports_arena(clang: &str) -> bool {
    let args = ["-target", "bpf", "-dM", "-E", "-x", "c", "/dev/null"];
    let Ok(out) = Command::new(clang).args(args).output() else {
        return false;
    };

    let macros = String::from_utf8_lossy(&out.stdout);
    out.status.success() && macros.contains("__BPF_FEATURE_ADDR_SPACE_CAST")
}

/// Puts a clang that can compile the fast path at the front of `PATH`.
///
/// `libbpf-cargo` runs whichever `clang` it finds there and offers no way to
/// point it at another one, so a link to a suitable compiler is placed in a
/// directory of its own and that directory goes first.
fn select_clang() {
    let Some(clang) = CLANG.iter().find(|clang| supports_arena(clang)) else {
        panic!("no clang with `__arena` support found, install clang 19 or newer");
    };

    if *clang == CLANG[0] {
        return;
    }

    let dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("bin");
    fs::create_dir_all(&dir).expect("create clang dir");

    let link = dir.join("clang");
    let _ = fs::remove_file(&link);
    symlink(clang, &link).expect("link clang");

    let path = env::var("PATH").unwrap_or_default();
    let path = format!("{}:{path}", dir.display());

    // a build script runs on its own thread with nothing else reading the
    // environment, and this happens before anything is compiled
    unsafe { env::set_var("PATH", path) };
}

fn main() {
    select_clang();

    Builder::new()
        .clang_arg(clang_args().iter())
        .tracing_ring_buf_size(32768)
        .export_headers()
        .build();
}
