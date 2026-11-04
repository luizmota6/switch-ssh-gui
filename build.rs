//! No Windows, copia o OpenGL por software (Mesa llvmpipe) para junto do .exe.
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=mesa/x64");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    // OUT_DIR = target/<perfil>/build/<pacote>-<hash>/out
    let Some(bin_dir) = out.ancestors().nth(3) else { return };
    for f in ["opengl32.dll", "libgallium_wgl.dll"] {
        let src = manifest.join("mesa").join("x64").join(f);
        let dst = bin_dir.join(f);
        let same = fs::metadata(&dst).ok().map(|m| m.len()) == fs::metadata(&src).ok().map(|m| m.len());
        if src.exists() && !same {
            if let Err(e) = fs::copy(&src, &dst) {
                println!("cargo:warning=não foi possível copiar {f}: {e}");
            }
        }
    }
}
