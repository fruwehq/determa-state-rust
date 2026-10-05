use std::fs;
use std::path::{Path, PathBuf};

fn collect(root: &Path, suffix: &str, output: &mut Vec<PathBuf>) {
    for item in fs::read_dir(root).expect("source directory") {
        let path = item.expect("source entry").path();
        if path.is_dir() {
            collect(&path, suffix, output);
        } else if path.extension().and_then(|s| s.to_str()) == Some(suffix)
            && !path.ends_with("src/format1/runtime_conformance.rs")
        {
            output.push(path);
        }
    }
}
fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=schema");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    let mut files = vec![
        PathBuf::from("build.rs"),
        PathBuf::from("Cargo.toml"),
        PathBuf::from("Cargo.lock"),
    ];
    collect(Path::new("src"), "rs", &mut files);
    collect(Path::new("schema"), "json", &mut files);
    files.sort();
    let mut generated = String::from("const BUNDLED_SOURCE_CLOSURE: &[(&str, &[u8])] = &[\n");
    for path in files {
        let relative = path.to_str().expect("UTF-8 source path").replace('\\', "/");
        generated.push_str(&format!("    ({relative:?}, include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{relative}\"))),\n"));
    }
    generated.push_str("];\n");
    let destination = PathBuf::from(std::env::var("OUT_DIR").expect("Cargo output directory"))
        .join("bundled_source_closure.rs");
    fs::write(destination, generated).expect("write bundled source closure");
}
