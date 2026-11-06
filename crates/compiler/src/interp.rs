//! R6 spike (see ROADMAP.md): run a wasm32-wasip1 module inside a canister by
//! INTERPRETING it with wasmi and providing WASI host functions.
//!
//! This is the execution engine for hosting real rustc on-chain. rustc.wasm is
//! far too large to be a canister's own code (the 10 MiB code-section cap), so
//! it must live as *data* in stable memory and be interpreted. This harness
//! proves that path with a minimal WASI surface -- enough to capture stdout and
//! honor proc_exit. Scaling to rustc means growing the WASI implementation into
//! a full filesystem over stable memory (the bulk of the remaining R6 work).
//!
//! Note: this is the interpreter path (rustc-as-data), which is distinct from
//! wasi2ic (which rewrites a wasm module to BE a canister -- unusable for
//! rustc, which exceeds the code-section limit). Here the WASI calls are host
//! functions bridging the inner module's memory, not import rewrites.

use wasmi::{Caller, Engine, Extern, Linker, Module, Store};

/// Host state for one run: captured stdout/stderr.
#[derive(Default)]
struct Wasi {
    output: Vec<u8>,
}

pub struct RunResult {
    pub output: Vec<u8>,
    pub exit_code: i32,
}

// A few wasip1 errno values.
const ERRNO_SUCCESS: i32 = 0;
const ERRNO_BADF: i32 = 8;
const ERRNO_FAULT: i32 = 21;

/// Interpret a wasm32-wasip1 module: instantiate it under a minimal WASI host,
/// call its `_start` export, and return captured output + exit code. Never
/// traps the canister -- a guest trap becomes an Err.
pub fn run_wasip1(module_bytes: &[u8]) -> Result<RunResult, String> {
    let engine = Engine::default();
    let module = Module::new(&engine, module_bytes).map_err(|e| format!("load module: {e}"))?;
    let mut store = Store::new(&engine, Wasi::default());
    let mut linker = Linker::new(&engine);

    // wasi_snapshot_preview1::fd_write(fd, iovs, iovs_len, nwritten) -> errno
    // Gathers the guest's iovecs from its linear memory; fd 1/2 are captured.
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_write",
            |mut caller: Caller<Wasi>, fd: i32, iovs: i32, iovs_len: i32, nwritten: i32| -> i32 {
                let mem = match caller.get_export("memory").and_then(Extern::into_memory) {
                    Some(m) => m,
                    None => return ERRNO_FAULT,
                };
                let mut captured = Vec::new();
                let mut total: u32 = 0;
                {
                    // Guest pointers are unsigned wasm32 addresses arriving as
                    // i32 bit-patterns; bounds-check in u64 so a huge pointer
                    // (e.g. -1 = 0xffff_ffff) cannot wrap 32-bit usize math
                    // past the check and panic the slice below.
                    let data = mem.data(&caller);
                    let mem_len = data.len() as u64;
                    for i in 0..iovs_len.max(0) as u64 {
                        let rec = iovs as u32 as u64 + i * 8;
                        if rec + 8 > mem_len {
                            return ERRNO_FAULT;
                        }
                        let rec = rec as usize;
                        let ptr =
                            u32::from_le_bytes(data[rec..rec + 4].try_into().unwrap()) as u64;
                        let len =
                            u32::from_le_bytes(data[rec + 4..rec + 8].try_into().unwrap()) as u64;
                        if ptr + len > mem_len {
                            return ERRNO_FAULT;
                        }
                        captured.extend_from_slice(&data[ptr as usize..(ptr + len) as usize]);
                        total = total.wrapping_add(len as u32);
                    }
                }
                match fd {
                    1 | 2 => caller.data_mut().output.extend_from_slice(&captured),
                    _ => return ERRNO_BADF,
                }
                if mem
                    .write(&mut caller, nwritten as u32 as usize, &total.to_le_bytes())
                    .is_err()
                {
                    return ERRNO_FAULT;
                }
                ERRNO_SUCCESS
            },
        )
        .map_err(|e| format!("link fd_write: {e}"))?;

    // wasi_snapshot_preview1::proc_exit(code) -- unwinds with the exit status,
    // which we recover after the call rather than treating as a trap.
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "proc_exit",
            |_caller: Caller<Wasi>, code: i32| -> Result<(), wasmi::Error> {
                Err(wasmi::Error::i32_exit(code))
            },
        )
        .map_err(|e| format!("link proc_exit: {e}"))?;

    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| format!("instantiate: {e}"))?;

    let start = instance
        .get_func(&store, "_start")
        .ok_or("module has no _start export")?;

    let inputs: [wasmi::Val; 0] = [];
    let mut outputs: [wasmi::Val; 0] = [];
    let outcome = start.call(&mut store, &inputs, &mut outputs);
    // Move the captured output out; rustc's can be large, don't copy it.
    let output = std::mem::take(&mut store.data_mut().output);
    match outcome {
        Ok(()) => Ok(RunResult {
            output,
            exit_code: 0,
        }),
        Err(e) => match e.i32_exit_status() {
            Some(code) => Ok(RunResult { output, exit_code: code }),
            None => Err(format!("guest trap: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A wasip1 module that writes "hello\n" to fd 1 and returns.
    const HELLO_WAT: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 100) "hello\n")
          (func (export "_start")
            (i32.store (i32.const 0) (i32.const 100)) ;; iov.buf  = 100
            (i32.store (i32.const 4) (i32.const 6))   ;; iov.len  = 6
            (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))
    "#;

    #[test]
    fn interprets_wasip1_and_captures_stdout() {
        let wasm = wat::parse_str(HELLO_WAT).unwrap();
        let r = run_wasip1(&wasm).unwrap();
        assert_eq!(r.output, b"hello\n");
        assert_eq!(r.exit_code, 0);
    }

    #[test]
    fn proc_exit_yields_clean_exit_code() {
        let wat = r#"
            (module
              (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
              (func (export "_start") (call $exit (i32.const 42))))
        "#;
        let r = run_wasip1(&wat::parse_str(wat).unwrap()).unwrap();
        assert_eq!(r.exit_code, 42);
        assert!(r.output.is_empty());
    }

    #[test]
    fn out_of_bounds_fd_write_pointers_yield_fault_not_panic() {
        // iovs = -1 (pointer 0xffff_ffff) and an iovec whose buf+len exceeds
        // memory: both must come back as ERRNO_FAULT (21), not a host panic.
        let wat = r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
              (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
              (memory (export "memory") 1)
              (func (export "_start")
                ;; iovs pointer itself out of bounds
                (if (i32.ne (call $fd_write (i32.const 1) (i32.const -1) (i32.const 1) (i32.const 8))
                            (i32.const 21))
                  (then (call $exit (i32.const 1))))
                ;; iovec buffer out of bounds: buf = 0xffffff00, len = 0x200
                (i32.store (i32.const 0) (i32.const 0xffffff00))
                (i32.store (i32.const 4) (i32.const 0x200))
                (if (i32.ne (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8))
                            (i32.const 21))
                  (then (call $exit (i32.const 2))))))
        "#;
        let r = run_wasip1(&wat::parse_str(wat).unwrap()).unwrap();
        assert_eq!(r.exit_code, 0, "host rejected bad pointers cleanly");
        assert!(r.output.is_empty(), "nothing was captured");
    }

    #[test]
    fn guest_trap_is_an_error_not_a_canister_trap() {
        // unreachable instruction -> guest trap -> Err, never crashes the host.
        let wat = r#"(module (func (export "_start") unreachable))"#;
        assert!(run_wasip1(&wat::parse_str(wat).unwrap()).is_err());
    }
}
