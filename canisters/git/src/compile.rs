//! Day 1 spike -- Track B rung R0 (see ../../../ROADMAP.md): compile the
//! WebAssembly text format (WAT) to a wasm binary, on-chain.
//!
//! This proves the source-to-artifact pipeline end to end with the smallest
//! possible real compiler: pure Rust, deterministic, no filesystem, threads,
//! or network -- exactly the constraints a canister imposes. The heavy rungs
//! (a real language frontend, sharded codegen across a canister fleet) build
//! on the same shape: bytes in, wasm bytes out, no side effects.

use candid::CandidType;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Summary of a compiled module. Returned instead of raw bytes when you just
/// want to eyeball the result over `dfx canister call` (a blob prints as a
/// wall of escapes; a length and a hash do not).
#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub struct CompileInfo {
    /// Size of the emitted wasm binary in bytes.
    pub wasm_len: u64,
    /// Lowercase hex sha256 of the emitted wasm binary. Deterministic, so two
    /// replicas (or two calls) on the same input produce the same digest.
    pub sha256_hex: String,
}

/// Compile WAT source to a wasm binary. Pure and deterministic: the same
/// input always yields byte-identical output, which is what makes it safe to
/// run under consensus (every replica re-executes and must agree).
///
/// Note this is an *assembler*: it translates text to bytes but does not
/// type-check. Use `compile_wat_checked` (or call `validate_wasm` yourself)
/// before deploying, so semantically-invalid modules are rejected.
pub fn compile_wat(text: &str) -> Result<Vec<u8>, String> {
    wat::parse_str(text).map_err(|e| e.to_string())
}

/// Full wasm validation: structure, types, and the parts the assembler does
/// not check. This is the gate a module must pass before it is deployable.
pub fn validate_wasm(wasm: &[u8]) -> Result<(), String> {
    wasmparser::Validator::new()
        .validate_all(wasm)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Assemble WAT and validate the result. Returns deployable wasm or an error.
pub fn compile_wat_checked(text: &str) -> Result<Vec<u8>, String> {
    let wasm = compile_wat(text)?;
    validate_wasm(&wasm)?;
    Ok(wasm)
}

/// Summarize a wasm binary (length + sha256). Shared by the WAT and language
/// compile-info endpoints.
pub fn info_of(wasm: &[u8]) -> CompileInfo {
    CompileInfo {
        wasm_len: wasm.len() as u64,
        sha256_hex: hex::encode(Sha256::digest(wasm)),
    }
}

/// Compile, validate, and summarize -- without shipping the bytes back. Fails
/// if the module would not be deployable, so the summary reflects a module you
/// could actually install.
pub fn compile_wat_info(text: &str) -> Result<CompileInfo, String> {
    Ok(info_of(&compile_wat_checked(text)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but non-trivial module: exports an `add` function.
    const ADD_WAT: &str = r#"
        (module
          (func $add (param $a i32) (param $b i32) (result i32)
            local.get $a
            local.get $b
            i32.add)
          (export "add" (func $add)))
    "#;

    #[test]
    fn emits_wasm_magic_and_version() {
        let wasm = compile_wat(ADD_WAT).expect("valid WAT should compile");
        // Every wasm binary starts with the magic "\0asm" and version 1.
        assert_eq!(&wasm[0..4], b"\0asm");
        assert_eq!(&wasm[4..8], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn compilation_is_deterministic() {
        let a = compile_wat(ADD_WAT).unwrap();
        let b = compile_wat(ADD_WAT).unwrap();
        assert_eq!(a, b, "same input must produce byte-identical output");
    }

    #[test]
    fn info_reports_length_and_hash() {
        let wasm = compile_wat(ADD_WAT).unwrap();
        let info = compile_wat_info(ADD_WAT).unwrap();
        assert_eq!(info.wasm_len, wasm.len() as u64);
        assert_eq!(info.sha256_hex, hex::encode(Sha256::digest(&wasm)));
        assert_eq!(info.sha256_hex.len(), 64);
    }

    #[test]
    fn malformed_wat_is_an_error_not_a_panic() {
        // Syntactically broken input (unbalanced parens) is rejected.
        let err = compile_wat("(module (func $bad").expect_err("malformed WAT must fail");
        assert!(!err.is_empty(), "error message should be populated");
    }

    // A type-invalid module: `i32.add` with no operands on the stack.
    const TYPE_INVALID_WAT: &str = "(module (func $bad (result i32) i32.add))";

    #[test]
    fn wat_is_an_assembler_not_a_validator() {
        // Finding (Day 1 spike): `wat` translates text to bytes but does NOT
        // type-check. This module is semantically invalid yet still assembles.
        let wasm = compile_wat(TYPE_INVALID_WAT)
            .expect("assembler accepts type-invalid but syntactically-valid input");
        assert_eq!(&wasm[0..4], b"\0asm");
    }

    #[test]
    fn validation_rejects_what_the_assembler_accepts() {
        // The validation pass catches what the assembler does not.
        let wasm = compile_wat(TYPE_INVALID_WAT).unwrap();
        assert!(validate_wasm(&wasm).is_err(), "type-invalid module must fail validation");
        assert!(
            compile_wat_checked(TYPE_INVALID_WAT).is_err(),
            "checked compile must reject a type-invalid module"
        );
    }

    #[test]
    fn valid_module_passes_validation() {
        let wasm = compile_wat_checked(ADD_WAT).expect("valid module compiles and validates");
        assert!(validate_wasm(&wasm).is_ok());
    }

    #[test]
    fn empty_module_compiles() {
        let wasm = compile_wat("(module)").expect("empty module is valid");
        assert_eq!(&wasm[0..4], b"\0asm");
    }
}
