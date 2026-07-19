//! R1 (see ROADMAP.md): a minimal real language compiled to wasm in-canister.
//!
//! Unlike R0's WAT assembler, this is an actual compiler -- lexer, parser, and
//! code generator -- for a small language that is *not* already wasm. It emits
//! wasm directly via `wasm-encoder` (no LLVM), which is the approach the
//! ROADMAP takes toward richer languages: own the compiler, target wasm.
//!
//! Grammar (one or more i32 function definitions):
//!
//!   program := func+
//!   func    := "fn" ident "(" params? ")" "=" expr ";"
//!   params  := ident ("," ident)*
//!   expr    := term (("+" | "-") term)*
//!   term    := factor (("*" | "/") factor)*
//!   factor  := "-" factor | primary
//!   primary := int | ident | ident "(" args? ")" | "(" expr ")"
//!
//! All values are i32. Functions may call any function in the program (forward
//! references allowed) and each is exported by its name. `//` starts a comment.
//! Output is validated before it is returned.

use std::collections::HashMap;
use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function, FunctionSection, Instruction, Module,
    TypeSection, ValType,
};

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

    fn program(&mut self) -> Result<Vec<Func>, String> {
        let mut funcs = Vec::new();
        while self.peek() != &Tok::Eof {
            funcs.push(self.func()?);
        }
        if funcs.is_empty() {
            return Err("program defines no functions".into());
        }
        Ok(funcs)
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

// --- codegen (emit wasm via wasm-encoder) -----------------------------------

struct FnCtx<'a> {
    params: &'a [String],
    funcs: &'a HashMap<String, (u32, usize)>, // name -> (function index, arity)
}

fn emit(f: &mut Function, e: &Expr, ctx: &FnCtx) -> Result<(), String> {
    match e {
        Expr::Int(n) => {
            f.instruction(&Instruction::I32Const(*n));
        }
        Expr::Var(name) => {
            let idx = ctx
                .params
                .iter()
                .position(|p| p == name)
                .ok_or_else(|| format!("unknown variable: {name}"))?;
            f.instruction(&Instruction::LocalGet(idx as u32));
        }
        Expr::Neg(inner) => {
            f.instruction(&Instruction::I32Const(0));
            emit(f, inner, ctx)?;
            f.instruction(&Instruction::I32Sub);
        }
        Expr::Bin(op, l, r) => {
            emit(f, l, ctx)?;
            emit(f, r, ctx)?;
            f.instruction(&match op {
                BinOp::Add => Instruction::I32Add,
                BinOp::Sub => Instruction::I32Sub,
                BinOp::Mul => Instruction::I32Mul,
                BinOp::Div => Instruction::I32DivS,
            });
        }
        Expr::Call(name, args) => {
            let (idx, arity) = ctx
                .funcs
                .get(name)
                .ok_or_else(|| format!("unknown function: {name}"))?;
            if args.len() != *arity {
                return Err(format!(
                    "{name} takes {arity} argument(s), got {}",
                    args.len()
                ));
            }
            for a in args {
                emit(f, a, ctx)?;
            }
            f.instruction(&Instruction::Call(*idx));
        }
    }
    Ok(())
}

fn codegen(funcs: &[Func]) -> Result<Vec<u8>, String> {
    // Resolve names to (index, arity); reject duplicates. Iteration order over
    // the Vec is deterministic; the map is only used for lookups.
    let mut index: HashMap<String, (u32, usize)> = HashMap::new();
    for (i, f) in funcs.iter().enumerate() {
        if index
            .insert(f.name.clone(), (i as u32, f.params.len()))
            .is_some()
        {
            return Err(format!("duplicate function: {}", f.name));
        }
    }

    let mut types = TypeSection::new();
    let mut functions = FunctionSection::new();
    let mut exports = ExportSection::new();
    let mut codes = CodeSection::new();

    for (i, f) in funcs.iter().enumerate() {
        types
            .ty()
            .function(vec![ValType::I32; f.params.len()], vec![ValType::I32]);
        functions.function(i as u32);
        exports.export(&f.name, ExportKind::Func, i as u32);

        let mut body = Function::new(std::iter::empty()); // params are the only locals
        let ctx = FnCtx {
            params: &f.params,
            funcs: &index,
        };
        emit(&mut body, &f.body, &ctx)?;
        body.instruction(&Instruction::End);
        codes.function(&body);
    }

    let mut module = Module::new();
    module.section(&types);
    module.section(&functions);
    module.section(&exports);
    module.section(&codes);
    Ok(module.finish())
}

/// Compile source to a wasm binary. Pure and deterministic.
pub fn compile(src: &str) -> Result<Vec<u8>, String> {
    let toks = lex(src)?;
    let funcs = Parser { toks, pos: 0 }.program()?;
    codegen(&funcs)
}

/// Compile and validate. Returns deployable wasm or an error.
pub fn compile_checked(src: &str) -> Result<Vec<u8>, String> {
    let wasm = compile(src)?;
    crate::compile::validate_wasm(&wasm)?;
    Ok(wasm)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile, then execute a named export with wasmi to check semantics.
    fn run(src: &str, func: &str, args: &[i32]) -> i32 {
        let wasm = compile_checked(src).expect("program compiles and validates");
        let engine = wasmi::Engine::default();
        let module = wasmi::Module::new(&engine, &wasm[..]).expect("wasmi loads module");
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
        assert!(compile("fn f() = 1 +;").is_err(), "parse error");
        assert!(compile("fn f() = g();").is_err(), "unknown function");
        assert!(compile("fn f() = x;").is_err(), "unknown variable");
        assert!(compile("fn f(a) = a; fn f(b) = b;").is_err(), "duplicate fn");
        assert!(compile("fn add(a,b)=a+b; fn g()=add(1);").is_err(), "arity");
        assert!(compile("").is_err(), "empty program");
    }
}
