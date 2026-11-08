//! What a deploy job is, as both sides of the boundary read it
//! (docs/CANISTER_SPLIT.md, section 4): the configs a job snapshots, the
//! kind of source a path names, and the job itself -- each leg's config
//! with its proven artifact.

use crate::proof::Artifact;
use candid::CandidType;
use serde::{Deserialize, Serialize};

/// How to install the compiled wasm into the target.
///
/// `Upgrade` preserves the target's stable memory (the default -- safe for
/// stateful targets); `Reinstall` wipes all state. The very first deploy to an
/// empty target always uses plain install regardless, since upgrade requires an
/// existing module.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
pub enum DeployMode {
    #[default]
    #[serde(rename = "upgrade")]
    Upgrade,
    #[serde(rename = "reinstall")]
    Reinstall,
}

impl DeployMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "upgrade" => Ok(Self::Upgrade),
            "reinstall" => Ok(Self::Reinstall),
            _ => Err(format!("mode must be 'upgrade' or 'reinstall', got '{s}'")),
        }
    }
}

/// What to build and where to install it, per repo.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct DeployConfig {
    /// Target canister principal (text form) to install the compiled wasm into.
    /// The git canister must be one of its controllers.
    pub target: String,
    /// Path to the source within the repo tree. The compiler is chosen by
    /// extension: `.wat` (R0 assembler) or `.lang` (R1 language). Aliased from
    /// the old `wat_path` field so existing configs still load.
    #[serde(alias = "wat_path")]
    pub source_path: String,
    /// Install mode; defaults to Upgrade for configs written before this field
    /// existed.
    #[serde(default)]
    pub mode: DeployMode,
}

/// What builds the configured source, chosen by file extension. The single
/// place the extension list lives: `set_config` validates by parsing it, `run`
/// dispatches on it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SourceKind {
    /// R0 assembler.
    Wat,
    /// R1 language compiler.
    Lang,
    /// A prebuilt artifact (build locally with real rustc, commit the wasm),
    /// validated and used as-is.
    Wasm,
}

impl SourceKind {
    pub fn from_path(path: &str) -> Result<Self, String> {
        if path.ends_with(".wat") {
            Ok(Self::Wat)
        } else if path.ends_with(".lang") {
            Ok(Self::Lang)
        } else if path.ends_with(".wasm") {
            Ok(Self::Wasm)
        } else {
            Err("source_path must end in .wat, .lang, or .wasm".into())
        }
    }

    /// The source kind a repo may deploy from `path`. A governed repo deploys
    /// committed `.wasm` only (docs/CANISTER_SPLIT.md, phase 2 step 3): the
    /// voters approve the exact module, `<repo>#app` records its hash, and
    /// nothing the compiler produces reaches a governed backend.
    pub fn for_repo(governed: bool, path: &str) -> Result<Self, String> {
        let kind = Self::from_path(path)?;
        if governed && kind != Self::Wasm {
            return Err(format!(
                "a governed repo deploys committed .wasm only; {path} would be compiled here"
            ));
        }
        Ok(kind)
    }
}

/// Track A, phase E2: what a push deploys to an EVM chain, per repo. The
/// artifact is a committed hex file (creation bytecode) at `source_path` --
/// build-locally-commit-the-artifact, same rung as the wasm path's `.wasm`
/// SourceKind. The chain, key, and RPC provider come from the global
/// evm::EvmConfig; this only names the artifact and its gas budget.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmDeployConfig {
    /// Path within the repo tree to the creation bytecode as hex text (.hex).
    pub source_path: String,
    /// Gas limit for the CREATE transaction.
    pub gas_limit: u64,
}

/// What a job deploys, fixed when it is queued: each configured leg's config
/// as it stood then, with its artifact or why it could not be resolved (a
/// missing file, say -- recorded at drain time like any failed deploy).
/// Running a job reads neither the configs nor the object store, so a
/// config edit or a push after queueing cannot change what it deploys.
/// The authority keeps queued ones in their own stable map (records.rs).
#[derive(CandidType, Deserialize)]
pub struct Job {
    pub wasm: Option<(DeployConfig, Result<Artifact, String>)>,
    pub evm: Option<(EvmDeployConfig, Result<Artifact, String>)>,
}

/// Decode a hex artifact (0x-optional, surrounding whitespace tolerated) to
/// creation bytecode. The single decode path: the deploy leg and the registry
/// publisher must hash identical bytes, or the on-chain registry entry would
/// diverge from the bytecode_sha256 in the deploy history.
///
/// Shared, because "the committed file is hex text" is a fact about the
/// artifact format: the git side decodes for the registry publisher's
/// operator path, the authority the proven blob a job carries. The signer
/// itself takes bytes (`evm::deploy_bytecode`).
pub fn decode_bytecode_hex(text: &str) -> Result<Vec<u8>, String> {
    let s = text.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("bad bytecode hex: {e}"))?;
    if bytes.is_empty() {
        return Err("empty bytecode".into());
    }
    Ok(bytes)
}

/// The creation bytecode in an EVM artifact's committed bytes.
pub fn bytecode_of(path: &str, bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let text = String::from_utf8(bytes).map_err(|_| format!("{path} is not valid UTF-8"))?;
    decode_bytecode_hex(&text)
}
