extern crate bindgen;

use bindgen::Abi;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

static PROTO_INPUT_DIRECTORY: &str = "proto";
static PROTO_INPUT_FILE: &str = "mpc.proto";
static PKCS_11_SPEC_VERSION: &str = "v3.0";
static PKCS_11_HEADERS_DIRECTORY: &str = "PKCS11-SPECS";

fn main() -> Result<(), Box<dyn Error>> {
    set_package_info().expect("Could not set package info");

    generate_bindings();

    compile_protofiles(PROTO_INPUT_DIRECTORY, PROTO_INPUT_FILE)
}

fn compile_protofiles(
    proto_input_directory: &str,
    proto_input_file: &str,
) -> Result<(), Box<dyn Error>> {
    let proto_input_filepath = Path::new(proto_input_directory).join(proto_input_file);

    tonic_build::configure()
        .build_server(false)
        .compile(&[proto_input_filepath], &[proto_input_directory])?;
    Ok(())
}

fn generate_bindings() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");
    let header_location = PathBuf::from(PKCS_11_HEADERS_DIRECTORY)
        .join(PKCS_11_SPEC_VERSION)
        .join("headers");
    let bindings = bindgen::Builder::default()
        .set_platform_abi_type()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", header_location.to_str().unwrap()))
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let out_file = out_dir.join("bindings.rs");
    bindings
        .write_to_file(out_file)
        .expect("Couldn't write bindings!");
}

trait AbiTypeOverrider {
    fn set_platform_abi_type(self) -> Self;
}

impl AbiTypeOverrider for bindgen::Builder {
    /// https://doc.rust-lang.org/nomicon/ffi.html#foreign-calling-conventions
    #[cfg(target_os = "windows")]
    fn set_platform_abi_type(self) -> Self {
        self.override_abi(Abi::System, ".*")
    }

    #[cfg(target_os = "linux")]
    fn set_platform_abi_type(self) -> Self {
        self.override_abi(Abi::C, ".*")
    }
}

fn set_package_info() -> Result<(), Box<dyn Error>> {
    let version = env!("CARGO_PKG_VERSION");

    let mut version_parts = version.split('.');
    let major = version_parts
        .next()
        .expect("Major version not defined")
        .parse::<u8>()?;
    let minor = version_parts
        .next()
        .expect("Minor version not defined")
        .parse::<u8>()?;

    let major_version = format!("pub const IMPLEMENTATION_MAJOR_VERSION: u8 = {major};\n",);
    let minor_version = format!("pub const IMPLEMENTATION_MINOR_VERSION: u8 = {minor};\n",);

    let out_dir = env::var("OUT_DIR")?;
    let dest_path = format!("{}/package_info.rs", out_dir);
    let mut file = File::create(&dest_path)?;
    file.write_all(major_version.as_bytes())?;
    file.write_all(minor_version.as_bytes())?;
    Ok(())
}
