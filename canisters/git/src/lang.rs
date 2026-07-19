//! R1-R3 (see ROADMAP.md): a minimal real language compiled to wasm in-canister.
//!
//! Unlike R0's WAT assembler, this is an actual compiler -- lexer, parser, and
//! code generator -- for a small language that is *not* already wasm. There is
//! one backend: every module compiles in isolation to a `link::ModuleObject`
//! whose call sites are symbolic relocations, and `link::link` patches them
//! once global function indices are assigned. A whole program is just the
//! one-module link of itself, so the same emitter serves single-shot compiles
//! (R1), resumable compiles (R2), and separate compilation (R3/R4).
//!
//! Grammar (zero or more imports, then one or more i32 function definitions):
//!
//!   module  := use* func+
//!   use     := "use" ident "(" int ")" ";"
//!   func    := "fn" ident "(" params? ")" "=" expr ";"
//!   params  := ident ("," ident)*
//!   expr    := term (("+" | "-") term)*
//!   term    := factor (("*" | "/") factor)*
//!   factor  := "-" factor | primary
//!   primary := int | ident | ident "(" args? ")" | "(" expr ")"
//!
//! All values are i32. Functions may call any function in the module (forward
//! references allowed) or any declared via `use name(arity);`, and each is
//! exported by its name. `//` starts a comment. Output is validated before it
//! is returned.

// --- tokens -----------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Fn,
    Ident(String),
    Int(i32),
    Plus,
    Minus,
    Star,
    Slash,
    LParen,
    RParen,
    Comma,
    Eq,
    Semi,
    Eof,
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut toks = Vec::new();
    while i < b.len() {
        let c = b[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // line comment
        if c == '/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        match c {
            '+' => toks.push(Tok::Plus),
            '-' => toks.push(Tok::Minus),
            '*' => toks.push(Tok::Star),
            '/' => toks.push(Tok::Slash),
            '(' => toks.push(Tok::LParen),
            ')' => toks.push(Tok::RParen),
            ',' => toks.push(Tok::Comma),
            '=' => toks.push(Tok::Eq),
            ';' => toks.push(Tok::Semi),
            _ if c.is_ascii_digit() => {
                let start = i;
                while i < b.len() && (b[i] as char).is_ascii_digit() {
                    i += 1;
                }
                let n: i64 = src[start..i].parse().map_err(|_| "bad integer literal")?;
                if n > i32::MAX as i64 {
                    return Err(format!("integer out of range: {n}"));
                }
                toks.push(Tok::Int(n as i32));
                continue; // i already advanced past the digits
            }
            _ if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < b.len() && {
                    let ch = b[i] as char;
                    ch.is_ascii_alphanumeric() || ch == '_'
                } {
                    i += 1;
                }
                let word = &src[start..i];
                toks.push(if word == "fn" {
                    Tok::Fn
                } else {
                    Tok::Ident(word.to_string())
                });
                continue; // i already advanced past the word
            }
            _ => return Err(format!("unexpected character: {c:?}")),
        }
        i += 1;
    }
    toks.push(Tok::Eof);
    Ok(toks)
}

// --- ast --------------------------------------------------------------------

#[derive(Clone, Copy)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
}

enum Expr {
    Int(i32),
    Var(String),
    Neg(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
}

struct Func {
    name: String,
    params: Vec<String>,
    body: Expr,
}

// --- parser (recursive descent) ---------------------------------------------

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos]
    }
    fn bump(&mut self) -> Tok {
        let t = self.toks[self.pos].clone();
        self.pos += 1;
        t
    }
    fn eat(&mut self, want: &Tok) -> Result<(), String> {
        if self.peek() == want {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected {want:?}, found {:?}", self.peek()))
        }
    }
    fn ident(&mut self) -> Result<String, String> {
        match self.bump() {
            Tok::Ident(s) => Ok(s),
            t => Err(format!("expected identifier, found {t:?}")),
        }
    }

    fn func(&mut self) -> Result<Func, String> {
        self.eat(&Tok::Fn)?;
        let name = self.ident()?;
        self.eat(&Tok::LParen)?;
        let mut params = Vec::new();
        if self.peek() != &Tok::RParen {
            loop {
                params.push(self.ident()?);
                if self.peek() == &Tok::Comma {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }
        self.eat(&Tok::RParen)?;
        self.eat(&Tok::Eq)?;
        let body = self.expr()?;
        self.eat(&Tok::Semi)?;
        Ok(Func { name, params, body })
    }

    fn expr(&mut self) -> Result<Expr, String> {
        let mut left = self.term()?;
        loop {
            let op = match self.peek() {
                Tok::Plus => BinOp::Add,
                Tok::Minus => BinOp::Sub,
                _ => break,
            };
            self.pos += 1;
            let right = self.term()?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn term(&mut self) -> Result<Expr, String> {
        let mut left = self.factor()?;
        loop {
            let op = match self.peek() {
                Tok::Star => BinOp::Mul,
                Tok::Slash => BinOp::Div,
                _ => break,
            };
            self.pos += 1;
            let right = self.factor()?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn factor(&mut self) -> Result<Expr, String> {
        if self.peek() == &Tok::Minus {
            self.pos += 1;
            return Ok(Expr::Neg(Box::new(self.factor()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.bump() {
            Tok::Int(n) => Ok(Expr::Int(n)),
            Tok::LParen => {
                let e = self.expr()?;
                self.eat(&Tok::RParen)?;
                Ok(e)
            }
            Tok::Ident(name) => {
                if self.peek() == &Tok::LParen {
                    self.pos += 1;
                    let mut args = Vec::new();
                    if self.peek() != &Tok::RParen {
                        loop {
                            args.push(self.expr()?);
                            if self.peek() == &Tok::Comma {
                                self.pos += 1;
                            } else {
                                break;
                            }
                        }
                    }
                    self.eat(&Tok::RParen)?;
                    Ok(Expr::Call(name, args))
                } else {
                    Ok(Expr::Var(name))
                }
            }
            t => Err(format!("unexpected token in expression: {t:?}")),
        }
    }
}

/// A declared external function this module calls but does not define.
struct Import {
    name: String,
    arity: usize,
}

/// A parsed module: imports declared via `use name(arity);`, then funcs.
struct ParsedModule {
    imports: Vec<Import>,
    funcs: Vec<Func>,
}

/// Parse a module: zero or more `use name(arity);` import declarations, then one
/// or more function definitions. `use` is an ordinary identifier here, only
/// special at the start of a declaration.
fn parse_module(src: &str) -> Result<ParsedModule, String> {
    let toks = lex(src)?;
    let mut p = Parser { toks, pos: 0 };
    let mut imports = Vec::new();
    while matches!(p.peek(), Tok::Ident(s) if s == "use") {
        p.pos += 1; // 'use'
        let name = p.ident()?;
        p.eat(&Tok::LParen)?;
        let arity = match p.bump() {
            Tok::Int(n) if n >= 0 => n as usize,
            t => return Err(format!("expected import arity, found {t:?}")),
        };
        p.eat(&Tok::RParen)?;
        p.eat(&Tok::Semi)?;
        imports.push(Import { name, arity });
    }
    let mut funcs = Vec::new();
    while p.peek() != &Tok::Eof {
        funcs.push(p.func()?);
    }
    if funcs.is_empty() {
        return Err("module defines no functions".into());
    }
    Ok(ParsedModule { imports, funcs })
}

/// Compile a whole program (a single module) to validated deployable wasm:
/// the one-module link of itself.
pub fn compile_checked(src: &str) -> Result<Vec<u8>, String> {
    link::link(&[link::compile_module(src)?])
}

/// Generate an n-function synthetic program for measuring compile cost:
/// `fn f0() = 0; fn f1() = f0() + 1; ...`, a chain so codegen touches calls,
/// exports, and arithmetic. Requires n >= 1.
pub fn synthetic_program(n: u32) -> String {
    let mut s = String::from("fn f0() = 0;\n");
    for i in 1..n {
        s.push_str(&format!("fn f{i}() = f{}() + {i};\n", i - 1));
    }
    s
}

/// Resumable compilation (R2): parse once, then codegen a bounded batch of
/// functions per call, holding the in-progress `link::Compiler` in heap (which
/// persists across update calls). This lets a program too large to compile in
/// one message's instruction budget finish across several messages.
pub mod job {
    use super::link::{self, Compiler};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    thread_local! {
        static JOBS: RefCell<HashMap<u64, Compiler>> = RefCell::new(HashMap::new());
        static NEXT_ID: Cell<u64> = Cell::new(1);
    }

    /// Parse and prepare a job; returns its id. No codegen happens yet.
    pub fn start(src: &str) -> Result<u64, String> {
        let c = Compiler::new(src)?;
        let id = NEXT_ID.with(|n| {
            let id = n.get();
            n.set(id + 1);
            id
        });
        JOBS.with(|j| j.borrow_mut().insert(id, c));
        Ok(id)
    }

    /// Codegen up to `batch` more functions. Returns (done, done_funcs, total).
    pub fn step(id: u64, batch: usize) -> Result<(bool, usize, usize), String> {
        JOBS.with(|j| {
            let mut jobs = j.borrow_mut();
            let c = jobs.get_mut(&id).ok_or("no such compile job")?;
            for _ in 0..batch {
                if !c.emit_next()? {
                    break;
                }
            }
            Ok((c.emitted() == c.total(), c.emitted(), c.total()))
        })
    }

    /// Finish a fully-codegen'd job: link (which validates) and return the
    /// wasm. Removes the job. Errors -- leaving the job steppable -- if it is
    /// not yet complete.
    pub fn take(id: u64) -> Result<Vec<u8>, String> {
        JOBS.with(|j| {
            let mut jobs = j.borrow_mut();
            let c = jobs.get(&id).ok_or("no such compile job")?;
            if c.emitted() < c.total() {
                return Err(format!(
                    "job not finished: {}/{} functions",
                    c.emitted(),
                    c.total()
                ));
            }
            let c = jobs.remove(&id).expect("job checked present");
            link::link(&[c.finish()?])
        })
    }
}

/// R3: separate compilation across modules.
///
/// Each module compiles in isolation, knowing only the *interfaces* (name +
/// arity) of functions it imports via `use`, never their bodies. Every call is
/// emitted as a symbolic relocation -- a fixed 5-byte LEB128 slot the linker
/// patches once it assigns global function indices. This is the seam R4
/// distributes: run `compile_module` on many canisters, `link` on a
/// coordinator.
pub mod link {
    use super::{parse_module, BinOp, Expr, Func};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use wasm_encoder::{
        CodeSection, Encode, ExportKind, ExportSection, FunctionSection, Module, TypeSection,
        ValType,
    };

    /// A function signature: name and argument count.
    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct Sig {
        pub name: String,
        pub arity: u32,
    }

    /// A separately-compiled module object: the functions it defines (with
    /// codegen'd bodies carrying unresolved call relocations) and the imports
    /// it expects the linker to satisfy. Portable (serde) so it can travel
    /// between canisters.
    #[derive(Serialize, Deserialize, Clone)]
    pub struct ModuleObject {
        pub exports: Vec<Sig>,
        pub imports: Vec<Sig>,
        bodies: Vec<FuncBody>,
    }

    #[derive(Serialize, Deserialize, Clone)]
    struct FuncBody {
        arity: u32,
        /// wasm code: the expression's instructions followed by `end` (0x0b).
        /// Call sites hold a 5-byte placeholder patched by the linker. Hex in
        /// the serde form: JSON would otherwise encode each byte as a number,
        /// ~4x the payload on the R4 coordinator<->worker hot path.
        #[serde(with = "hex::serde")]
        code: Vec<u8>,
        relocs: Vec<Reloc>,
    }

    #[derive(Serialize, Deserialize, Clone)]
    struct Reloc {
        /// Byte offset within `code` of the 5-byte call-index slot.
        offset: u32,
        /// Function name the call targets; resolved to a global index at link.
        name: String,
    }

    /// Write a u32 as a fixed 5-byte (non-minimal) unsigned LEB128 into a slot.
    /// Valid wasm: a u32 index may occupy up to 5 bytes. Fixed width lets the
    /// linker patch call sites in place without shifting following bytes.
    fn patch_u32_5(v: u32, slot: &mut [u8]) {
        slot[0] = (v & 0x7f) as u8 | 0x80;
        slot[1] = ((v >> 7) & 0x7f) as u8 | 0x80;
        slot[2] = ((v >> 14) & 0x7f) as u8 | 0x80;
        slot[3] = ((v >> 21) & 0x7f) as u8 | 0x80;
        slot[4] = ((v >> 28) & 0x7f) as u8; // bits 28-31, no continuation bit
    }

    // --- separate compile ---------------------------------------------------

    fn emit(
        e: &Expr,
        params: &[String],
        known: &HashMap<String, u32>,
        code: &mut Vec<u8>,
        relocs: &mut Vec<Reloc>,
    ) -> Result<(), String> {
        match e {
            Expr::Int(n) => {
                code.push(0x41); // i32.const
                n.encode(code);
            }
            Expr::Var(name) => {
                let idx = params
                    .iter()
                    .position(|p| p == name)
                    .ok_or_else(|| format!("unknown variable: {name}"))?;
                code.push(0x20); // local.get
                (idx as u32).encode(code);
            }
            Expr::Neg(inner) => {
                code.push(0x41);
                0i32.encode(code);
                emit(inner, params, known, code, relocs)?;
                code.push(0x6b); // i32.sub
            }
            Expr::Bin(op, l, r) => {
                emit(l, params, known, code, relocs)?;
                emit(r, params, known, code, relocs)?;
                code.push(match op {
                    BinOp::Add => 0x6a,
                    BinOp::Sub => 0x6b,
                    BinOp::Mul => 0x6c,
                    BinOp::Div => 0x6d,
                });
            }
            Expr::Call(name, args) => {
                let arity = *known.get(name).ok_or_else(|| {
                    format!("unknown function: {name} (declare with `use {name}(N);` if external)")
                })?;
                if args.len() as u32 != arity {
                    return Err(format!(
                        "{name} takes {arity} argument(s), got {}",
                        args.len()
                    ));
                }
                for a in args {
                    emit(a, params, known, code, relocs)?;
                }
                code.push(0x10); // call
                relocs.push(Reloc {
                    offset: code.len() as u32,
                    name: name.clone(),
                });
                code.extend_from_slice(&[0, 0, 0, 0, 0]); // patched at link
            }
        }
        Ok(())
    }

    /// Stepwise module compiler: parse once (`new`), then codegen one function
    /// per `emit_next` call. `compile_module` drives it to completion in one
    /// go; the resumable job (R2) holds one in heap and steps it across update
    /// calls. Progress is the number of bodies emitted -- no separate cursor.
    pub struct Compiler {
        funcs: Vec<Func>,
        /// The names this module may call: its own functions plus its imports.
        known: HashMap<String, u32>, // name -> arity
        imports: Vec<Sig>,
        exports: Vec<Sig>,
        bodies: Vec<FuncBody>,
    }

    impl Compiler {
        /// Parse and build the name table (all functions, so forward references
        /// resolve). Rejects duplicate names. No codegen happens yet.
        pub fn new(src: &str) -> Result<Self, String> {
            let m = parse_module(src)?;
            let mut known: HashMap<String, u32> = HashMap::new();
            for f in &m.funcs {
                if known
                    .insert(f.name.clone(), f.params.len() as u32)
                    .is_some()
                {
                    return Err(format!("duplicate function: {}", f.name));
                }
            }
            for imp in &m.imports {
                if known.insert(imp.name.clone(), imp.arity as u32).is_some() {
                    return Err(format!("import '{}' shadows a definition", imp.name));
                }
            }
            let imports = m
                .imports
                .iter()
                .map(|i| Sig {
                    name: i.name.clone(),
                    arity: i.arity as u32,
                })
                .collect();
            Ok(Self {
                funcs: m.funcs,
                known,
                imports,
                exports: Vec::new(),
                bodies: Vec::new(),
            })
        }

        pub fn total(&self) -> usize {
            self.funcs.len()
        }

        /// Functions codegen'd so far.
        pub fn emitted(&self) -> usize {
            self.bodies.len()
        }

        /// Codegen the next not-yet-compiled function. Ok(false) once all are
        /// done. On error nothing is recorded, so the call can be retried.
        pub fn emit_next(&mut self) -> Result<bool, String> {
            let Some(f) = self.funcs.get(self.bodies.len()) else {
                return Ok(false);
            };
            let mut code = Vec::new();
            let mut relocs = Vec::new();
            emit(&f.body, &f.params, &self.known, &mut code, &mut relocs)?;
            code.push(0x0b); // end
            let arity = f.params.len() as u32;
            self.exports.push(Sig {
                name: f.name.clone(),
                arity,
            });
            self.bodies.push(FuncBody {
                arity,
                code,
                relocs,
            });
            Ok(true)
        }

        /// The finished object. Errors if functions remain uncompiled.
        pub fn finish(self) -> Result<ModuleObject, String> {
            if self.emitted() < self.total() {
                return Err(format!(
                    "compile unfinished: {}/{} functions",
                    self.emitted(),
                    self.total()
                ));
            }
            Ok(ModuleObject {
                exports: self.exports,
                imports: self.imports,
                bodies: self.bodies,
            })
        }
    }

    /// Compile a module in isolation. Calls may target this module's own
    /// functions or any declared via `use`; each is emitted as an unresolved
    /// relocation. The module knows nothing of other modules' bodies.
    pub fn compile_module(src: &str) -> Result<ModuleObject, String> {
        let mut c = Compiler::new(src)?;
        while c.emit_next()? {}
        c.finish()
    }

    // --- link ---------------------------------------------------------------

    /// Link separately-compiled objects into one wasm binary: assign a global
    /// index to every exported function, check every import resolves with a
    /// matching arity, patch all call relocations, then validate.
    pub fn link(objects: &[ModuleObject]) -> Result<Vec<u8>, String> {
        // Global symbol table over all modules' exports, in module/definition
        // order. Duplicate names across modules are a link error.
        let mut symbols: HashMap<String, (u32, u32)> = HashMap::new(); // name -> (index, arity)
        let mut funcs: Vec<&FuncBody> = Vec::new();
        for obj in objects {
            for (sig, body) in obj.exports.iter().zip(&obj.bodies) {
                let index = funcs.len() as u32;
                if symbols
                    .insert(sig.name.clone(), (index, sig.arity))
                    .is_some()
                {
                    return Err(format!(
                        "duplicate exported function across modules: {}",
                        sig.name
                    ));
                }
                funcs.push(body);
            }
        }
        // Interface check: every declared import must resolve, with the arity
        // the importer expected.
        for obj in objects {
            for imp in &obj.imports {
                match symbols.get(&imp.name) {
                    None => return Err(format!("unresolved import: {}", imp.name)),
                    Some((_, arity)) if *arity != imp.arity => {
                        return Err(format!(
                            "import '{}' expects arity {} but definition has arity {}",
                            imp.name, imp.arity, arity
                        ))
                    }
                    Some(_) => {}
                }
            }
        }

        // Distinct arities -> function types (dedup so N same-arity funcs share
        // one type). type_of[arity] = type index.
        let mut arities: Vec<u32> = funcs.iter().map(|b| b.arity).collect();
        arities.sort_unstable();
        arities.dedup();
        let type_of: HashMap<u32, u32> = arities
            .iter()
            .enumerate()
            .map(|(i, &a)| (a, i as u32))
            .collect();

        let mut types = TypeSection::new();
        for &a in &arities {
            types
                .ty()
                .function(vec![ValType::I32; a as usize], vec![ValType::I32]);
        }
        let mut functions = FunctionSection::new();
        for b in &funcs {
            functions.function(type_of[&b.arity]);
        }
        // Every function is exported by name, in index (definition) order.
        let mut names: Vec<(&String, u32)> = symbols.iter().map(|(n, (i, _))| (n, *i)).collect();
        names.sort_by_key(|(_, i)| *i);
        let mut exports = ExportSection::new();
        for (name, index) in names {
            exports.export(name, ExportKind::Func, index);
        }
        // Code: body = local decl vector (empty) + code, relocations patched
        // in place before the raw body is added.
        let mut codes = CodeSection::new();
        for b in &funcs {
            let mut body = Vec::with_capacity(1 + b.code.len());
            body.push(0); // zero local declarations
            body.extend_from_slice(&b.code);
            for r in &b.relocs {
                let (index, _) = symbols
                    .get(&r.name)
                    .ok_or_else(|| format!("dangling relocation: {}", r.name))?;
                let off = 1 + r.offset as usize;
                patch_u32_5(*index, &mut body[off..off + 5]);
            }
            codes.raw(&body);
        }

        let mut module = Module::new();
        module
            .section(&types)
            .section(&functions)
            .section(&exports)
            .section(&codes);
        let wasm = module.finish();
        crate::compile::validate_wasm(&wasm)?;
        Ok(wasm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Execute a named i32 export of a wasm binary with wasmi.
    fn exec(wasm: &[u8], func: &str, args: &[i32]) -> i32 {
        let engine = wasmi::Engine::default();
        let module = wasmi::Module::new(&engine, wasm).expect("wasmi loads module");
        let mut store = wasmi::Store::new(&engine, ());
        let linker = wasmi::Linker::<()>::new(&engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .expect("instantiates");
        let f = instance
            .get_func(&store, func)
            .unwrap_or_else(|| panic!("export {func} exists"));
        let mut result = [wasmi::Val::I32(0)];
        let vals: Vec<wasmi::Val> = args.iter().map(|a| wasmi::Val::I32(*a)).collect();
        f.call(&mut store, &vals, &mut result).expect("call succeeds");
        match &result[0] {
            wasmi::Val::I32(v) => *v,
            other => panic!("expected i32 result, got {other:?}"),
        }
    }

    /// Compile a single source, then execute a named export.
    fn run(src: &str, func: &str, args: &[i32]) -> i32 {
        let wasm = compile_checked(src).expect("program compiles and validates");
        exec(&wasm, func, args)
    }

    #[test]
    fn arithmetic_and_precedence() {
        assert_eq!(run("fn f() = 2 + 3 * 4;", "f", &[]), 14);
        assert_eq!(run("fn f() = (2 + 3) * 4;", "f", &[]), 20);
        assert_eq!(run("fn f() = 20 / 4 - 1;", "f", &[]), 4);
        assert_eq!(run("fn f() = -5 + 8;", "f", &[]), 3);
    }

    #[test]
    fn params_and_variables() {
        assert_eq!(run("fn add(a, b) = a + b;", "add", &[2, 3]), 5);
        assert_eq!(run("fn sq(x) = x * x;", "sq", &[7]), 49);
    }

    #[test]
    fn function_calls_including_forward_reference() {
        // `hyp2` calls `sq`, which is defined afterward (forward reference).
        let src = "fn hyp2(a, b) = sq(a) + sq(b); fn sq(x) = x * x;";
        assert_eq!(run(src, "hyp2", &[3, 4]), 25);
    }

    #[test]
    fn comments_are_ignored() {
        let src = "// a doubler\nfn dbl(x) = x + x; // inline\n";
        assert_eq!(run(src, "dbl", &[21]), 42);
    }

    #[test]
    fn errors_do_not_panic() {
        assert!(compile_checked("fn f() = 1 +;").is_err(), "parse error");
        assert!(compile_checked("fn f() = g();").is_err(), "unknown function");
        assert!(compile_checked("fn f() = x;").is_err(), "unknown variable");
        assert!(
            compile_checked("fn f(a) = a; fn f(b) = b;").is_err(),
            "duplicate fn"
        );
        assert!(
            compile_checked("fn add(a,b)=a+b; fn g()=add(1);").is_err(),
            "arity"
        );
        assert!(compile_checked("").is_err(), "empty program");
    }

    #[test]
    fn resumable_job_equals_one_shot() {
        let src = synthetic_program(10);
        let one_shot = compile_checked(&src).unwrap();

        let id = job::start(&src).unwrap();
        // Take before finishing must fail, not corrupt the job.
        assert!(job::take(id).is_err(), "cannot take an unfinished job");
        // Codegen in batches of 3.
        let (mut done, mut count) = (false, 0);
        while !done {
            let (d, done_funcs, total) = job::step(id, 3).unwrap();
            done = d;
            count = done_funcs;
            assert_eq!(total, 10);
        }
        assert_eq!(count, 10);
        let staged = job::take(id).unwrap();

        assert_eq!(one_shot, staged, "resumable compile must be byte-identical");
        assert!(job::take(id).is_err(), "job is consumed after take");
    }

    // --- R3: separate compilation + linking ---------------------------------

    #[test]
    fn separate_compile_then_link_executes() {
        // Two modules compiled in isolation: `math` defines sq; `app` imports
        // sq (interface only) and defines dist2 in terms of it.
        let math = link::compile_module("fn sq(x) = x * x;").unwrap();
        let app =
            link::compile_module("use sq(1); fn dist2(a, b) = sq(a) + sq(b);").unwrap();
        assert_eq!(app.imports.len(), 1, "app declares one import");

        let wasm = link::link(&[math, app]).unwrap();
        // Cross-module call resolved by the linker: dist2(3,4) = 9 + 16 = 25.
        assert_eq!(exec(&wasm, "dist2", &[3, 4]), 25);
        // Both modules' functions are exported in the linked binary.
        assert_eq!(exec(&wasm, "sq", &[6]), 36);
    }

    #[test]
    fn module_object_survives_serde_roundtrip() {
        // The candid seam sends objects between calls as serde_json bytes; that
        // round-trip must not change the linked output.
        let m1 = link::compile_module("fn sq(x) = x * x;").unwrap();
        let m2 = link::compile_module("use sq(1); fn dist2(a,b) = sq(a) + sq(b);").unwrap();
        let direct = link::link(&[m1.clone(), m2.clone()]).unwrap();

        let r1 = serde_json::from_slice(&serde_json::to_vec(&m1).unwrap()).unwrap();
        let r2 = serde_json::from_slice(&serde_json::to_vec(&m2).unwrap()).unwrap();
        let via_serde = link::link(&[r1, r2]).unwrap();

        assert_eq!(direct, via_serde, "serde round-trip changed linked wasm");
    }

    #[test]
    fn link_resolves_order_independently() {
        // Same result whether the defining module comes before or after the
        // importer -- separate compilation does not care about link order.
        let math = link::compile_module("fn sq(x) = x * x;").unwrap();
        let app = link::compile_module("use sq(1); fn quad(x) = sq(sq(x));").unwrap();
        let wasm = link::link(&[app, math]).unwrap(); // importer first
        assert_eq!(exec(&wasm, "quad", &[2]), 16);
    }

    #[test]
    fn link_error_cases() {
        // Unresolved import: nothing provides sq.
        let lone = link::compile_module("use sq(1); fn f(x) = sq(x);").unwrap();
        assert!(link::link(&[lone]).is_err(), "unresolved import");

        // Arity mismatch between declared interface and definition.
        let def = link::compile_module("fn sq(x) = x * x;").unwrap();
        let bad = link::compile_module("use sq(2); fn g(a, b) = sq(a, b);").unwrap();
        assert!(link::link(&[def, bad]).is_err(), "import arity mismatch");

        // Duplicate exported name across modules.
        let a = link::compile_module("fn dup() = 1;").unwrap();
        let b = link::compile_module("fn dup() = 2;").unwrap();
        assert!(link::link(&[a, b]).is_err(), "duplicate export");

        // Calling an undeclared external is a separate-compile error, caught
        // before linking.
        assert!(
            link::compile_module("fn f(x) = ext(x);").is_err(),
            "undeclared external call"
        );
    }
}
