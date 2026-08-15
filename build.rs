// build.rs
use std::path::PathBuf;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=/c_libraries/libLZR.h");
    println!("cargo:rerun-if-changed=/c_libraries/libLZR.c");
    println!("cargo:rerun-if-changed=/c_libraries/kl4e.h");
    println!("cargo:rerun-if-changed=/c_libraries/kl4e.c");

    cc::Build::new()
        .file("c_libraries/libLZR.c")
        .file("c_libraries/kl4e.c")
        .compile("libLZR");

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for
        .header("c_libraries/libLZR.h")
        .header("c_libraries/kl4e.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        // Then unwrap the Result and panic on failure
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}