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
use wasmparser::WasmFeatures;

/// The wasm proposals the IC accepts at `install_code`, and so the set the
/// gate validates against. Pinned here rather than left to wasmparser's
/// default: the default is a moving target (every wasmparser release turns
/// on whatever has shipped since, and the 0.263 default already accepts GC,
/// exceptions and wide arithmetic), while the replica's set is a decision
/// recorded in its own source. A module validated against a wider set can
/// pass here and be refused at install, after the push has been accepted.
///
/// Source: `wasmtime_validation_config` in the replica's
/// `rs/embedders/src/wasm_utils/validation.rs` (dfinity/ic master, read
/// 2026-11-13), over wasmtime 48. Three layers make the set, and a sync
/// with the replica has to read all three:
/// - wasmtime's own default, wasmparser's `WASM3` (the 2.0 proposals plus
///   GC, tail calls, extended-const, function references, multi-memory,
///   relaxed SIMD, threads, exceptions, memory64; wide arithmetic is not
///   in it, so it is off without a line saying so);
/// - the replica's wasmtime build (`Cargo.toml`: `cranelift`, `gc`,
///   `gc-null`, `parallel-compilation`, `runtime`), without the `threads`
///   feature, which turns threads off;
/// - the function's explicit switches: on, bulk memory, reference types,
///   memory64, tail calls; off, exceptions, function references, GC,
///   multi-memory (on for execution only, for the replica's own stable
///   memory), relaxed SIMD (nondeterministic), extended-const.
///
/// This is the proposal set only. The replica also checks what a module
/// imports and exports, its tables (funcref only, no `table.grow` or
/// `table.set`), its memory sizes, and more, and the gate does not repeat
/// those; what passes here can still be refused at install for one of
/// them.
pub const IC_FEATURES: WasmFeatures = WasmFeatures::WASM2
    .union(WasmFeatures::MEMORY64)
    .union(WasmFeatures::TAIL_CALL);

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
/// not check, against the proposals the IC accepts (`IC_FEATURES`). This is
/// the gate a module must pass before it is deployable.
pub fn validate_wasm(wasm: &[u8]) -> Result<(), String> {
    wasmparser::Validator::new_with_features(IC_FEATURES)
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

    // The validator pin. Each proposal the IC turns off, in a module that
    // uses nothing else: the assembler accepts it (the text format knows
    // every proposal) and the gate refuses it.
    const OFF_ON_THE_IC: &[(&str, &str)] = &[
        ("gc", "(module (type (struct (field i32))))"),
        ("exceptions", "(module (tag (param i32)))"),
        (
            "function references",
            "(module (type $t (func)) (func (param (ref $t)) local.get 0 call_ref $t))",
        ),
        ("multi-memory", "(module (memory 1) (memory 1))"),
        (
            "relaxed simd",
            "(module (func (param v128 v128) (result v128) local.get 0 local.get 1 i8x16.relaxed_swizzle))",
        ),
        (
            "extended-const",
            "(module (global i32 (i32.add (i32.const 1) (i32.const 2))))",
        ),
        ("threads", "(module (memory 1 1 shared))"),
        (
            "wide arithmetic",
            "(module (func (param i64 i64 i64 i64) (result i64 i64) local.get 0 local.get 1 local.get 2 local.get 3 i64.add128))",
        ),
    ];

    #[test]
    fn the_gate_refuses_what_the_ic_turns_off() {
        for (proposal, text) in OFF_ON_THE_IC {
            let wasm = compile_wat(text).unwrap_or_else(|e| panic!("{proposal}: assembles: {e}"));
            let err = validate_wasm(&wasm).expect_err(proposal);
            assert!(!err.is_empty(), "{proposal}: the refusal names its reason");
            assert!(
                compile_wat_checked(text).is_err(),
                "{proposal}: the checked compile refuses it too"
            );
        }
    }

    // The drift the pin stops, as of wasmparser 0.263: its default validator
    // accepts every one of those modules, so before the pin each passed the
    // gate and failed at install. This documents the dependency, not the
    // IC; when a wasmparser release turns one of them off by default, drop
    // that proposal from this test, not from OFF_ON_THE_IC.
    #[test]
    fn the_default_validator_accepts_what_the_ic_turns_off() {
        for (proposal, text) in OFF_ON_THE_IC {
            let wasm = compile_wat(text).unwrap();
            assert!(
                wasmparser::Validator::new().validate_all(&wasm).is_ok(),
                "{proposal}: the default validator accepts it, so the pin is what refuses it"
            );
        }
    }

    // What the IC keeps on, each in a module that exercises it and that the
    // replica's other checks would install (funcref tables only, no
    // table.set). The 2.0 specification's proposals, then memory64 and
    // tail calls.
    const ON_ON_THE_IC: &[(&str, &str)] = &[
        ("mutable global", "(module (global (mut i32) (i32.const 0)))"),
        (
            "sign extension",
            "(module (func (param i32) (result i32) local.get 0 i32.extend8_s))",
        ),
        (
            "saturating float-to-int",
            "(module (func (param f32) (result i32) local.get 0 i32.trunc_sat_f32_s))",
        ),
        (
            "multi-value",
            "(module (func (result i32 i32) i32.const 1 i32.const 2))",
        ),
        (
            "bulk memory",
            "(module (memory 1) (func (param i32 i32 i32) local.get 0 local.get 1 local.get 2 memory.copy))",
        ),
        (
            "reference types",
            "(module (table 1 funcref) (func (result funcref) i32.const 0 table.get 0))",
        ),
        (
            "simd",
            "(module (func (param v128 v128) (result v128) local.get 0 local.get 1 i32x4.add))",
        ),
        ("memory64", "(module (memory i64 1))"),
        ("tail call", "(module (func $f return_call $f))"),
    ];

    #[test]
    fn the_gate_accepts_what_the_ic_keeps_on() {
        for (proposal, text) in ON_ON_THE_IC {
            compile_wat_checked(text).unwrap_or_else(|e| panic!("{proposal}: {e}"));
        }
    }

    #[test]
    fn the_pin_is_the_ic_set() {
        // WASM2 and the two additions, and none of what wasmparser turns on
        // by default beyond them. Flag by flag rather than one equality, so
        // a flag added to this list is a check that can fire.
        let pinned = IC_FEATURES;
        assert!(pinned.contains(WasmFeatures::WASM2));
        assert!(pinned.memory64() && pinned.tail_call());
        for off in [
            WasmFeatures::GC,
            WasmFeatures::EXCEPTIONS,
            WasmFeatures::FUNCTION_REFERENCES,
            WasmFeatures::MULTI_MEMORY,
            WasmFeatures::RELAXED_SIMD,
            WasmFeatures::EXTENDED_CONST,
            WasmFeatures::THREADS,
            WasmFeatures::WIDE_ARITHMETIC,
            WasmFeatures::COMPONENT_MODEL,
        ] {
            assert!(!pinned.intersects(off), "{off:?} is off on the IC");
        }
    }
}
