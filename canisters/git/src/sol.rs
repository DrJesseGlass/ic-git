//! Track S: Solana signing spine (see ROADMAP.md and VISION.md section 4,
//! phase S0 -- the mirror of E0).
//!
//! The canister derives its own Solana address from a threshold Ed25519
//! public key (`schnorr_public_key` / `sign_with_schnorr`), builds and signs
//! a legacy transfer transaction, and broadcasts it through the SOL RPC
//! canister's `sendTransaction`. As with the EVM leg, nothing trusts an
//! off-chain signer: the key exists only as shares across the subnet, so a
//! transaction from this address *is* an attestation the canister made it.
//!
//! Hand-rolled, matching evm.rs's stance: base58, compact-u16 (shortvec),
//! and the legacy message layout are together smaller than any dependency,
//! and the SOL RPC candid is mirrored by hand the way evm.rs mirrors the
//! EVM RPC canister.
//!
//! What is structurally different from the EVM leg:
//! - No nonce, no send lock. Replay protection is the recent blockhash
//!   embedded in the message; it expires after ~150 blocks (~60-90s), so
//!   sign-and-broadcast must complete inside that window. Two identical
//!   transfers signed against the same blockhash are one transaction to the
//!   network (identical bytes, identical signature) -- dedupe for free.
//! - No typed `getLatestBlockhash` on the SOL RPC canister: a raw JSON
//!   blockhash could never reach consensus across nodes. The documented
//!   pattern is `getSlot` (with its consensus rounding) then `getBlock` for
//!   that slot's blockhash, which is what `recent_blockhash` does.

use crate::store;
use candid::{CandidType, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};

// --- base58 ------------------------------------------------------------------

pub mod base58 {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    pub fn encode(input: &[u8]) -> String {
        // Repeated division: digits is the little-endian base-58 value.
        let mut digits: Vec<u8> = Vec::new();
        for &byte in input {
            let mut carry = byte as u32;
            for d in digits.iter_mut() {
                carry += (*d as u32) << 8;
                *d = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        let zeros = input.iter().take_while(|&&b| b == 0).count();
        let mut s = String::with_capacity(zeros + digits.len());
        s.extend(std::iter::repeat('1').take(zeros));
        s.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
        s
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let mut bytes: Vec<u8> = Vec::new();
        for c in s.bytes() {
            let v = ALPHABET
                .iter()
                .position(|&a| a == c)
                .ok_or_else(|| format!("bad base58 character {:?}", c as char))?
                as u32;
            let mut carry = v;
            for b in bytes.iter_mut() {
                carry += (*b as u32) * 58;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let zeros = s.bytes().take_while(|&c| c == b'1').count();
        let mut out = vec![0u8; zeros];
        out.extend(bytes.iter().rev());
        Ok(out)
    }
}

fn parse_pubkey(s: &str) -> Result<[u8; 32], String> {
    let bytes = base58::decode(s)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("address must be 32 bytes, got {}", v.len()))
}

// --- compact-u16 (shortvec) --------------------------------------------------
// Solana's length prefix: little-endian base-128 varint capped at u16.

fn shortvec_len(out: &mut Vec<u8>, mut len: u16) {
    loop {
        let byte = (len & 0x7f) as u8;
        len >>= 7;
        if len == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

// --- legacy message + transfer instruction -----------------------------------

/// System program id: 32 zero bytes ("11111111111111111111111111111111").
const SYSTEM_PROGRAM: [u8; 32] = [0u8; 32];

/// SystemInstruction::Transfer discriminant (bincode u32) followed by
/// lamports (u64), both little-endian.
fn transfer_instruction_data(lamports: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data
}

/// The legacy (non-versioned) message for a single system transfer:
/// header, account keys, recent blockhash, one compiled instruction.
/// This is the exact byte string `sign_with_schnorr` signs (Ed25519 signs
/// the message itself; there is no prehash).
fn transfer_message(from: &[u8; 32], to: &[u8; 32], lamports: u64, blockhash: &[u8; 32]) -> Vec<u8> {
    // from is the fee payer (writable, signer); to is writable; the system
    // program is read-only and unsigned. A self-transfer collapses to one
    // writable signer account.
    let self_transfer = from == to;
    let keys: Vec<&[u8; 32]> = if self_transfer {
        vec![from, &SYSTEM_PROGRAM]
    } else {
        vec![from, to, &SYSTEM_PROGRAM]
    };
    let program_index = (keys.len() - 1) as u8;
    let account_indexes: [u8; 2] = if self_transfer { [0, 0] } else { [0, 1] };

    let mut msg = Vec::with_capacity(3 + 1 + keys.len() * 32 + 32 + 16);
    // header: signatures required, read-only signed, read-only unsigned
    msg.extend_from_slice(&[1, 0, 1]);
    shortvec_len(&mut msg, keys.len() as u16);
    for k in keys {
        msg.extend_from_slice(k);
    }
    msg.extend_from_slice(blockhash);
    shortvec_len(&mut msg, 1); // one instruction
    msg.push(program_index);
    shortvec_len(&mut msg, account_indexes.len() as u16);
    msg.extend_from_slice(&account_indexes);
    let data = transfer_instruction_data(lamports);
    shortvec_len(&mut msg, data.len() as u16);
    msg.extend_from_slice(&data);
    msg
}

/// The wire transaction: compact array of signatures, then the message.
fn assemble_transaction(signature: &[u8; 64], message: &[u8]) -> Vec<u8> {
    let mut tx = Vec::with_capacity(1 + 64 + message.len());
    shortvec_len(&mut tx, 1);
    tx.extend_from_slice(signature);
    tx.extend_from_slice(message);
    tx
}

// --- threshold Ed25519 (management canister, hand-mirrored) ------------------

#[derive(CandidType, Deserialize, Clone)]
enum SchnorrAlgorithm {
    #[serde(rename = "bip340secp256k1")]
    Bip340secp256k1,
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(CandidType, Deserialize, Clone)]
struct SchnorrKeyId {
    algorithm: SchnorrAlgorithm,
    name: String,
}

#[derive(CandidType)]
struct SchnorrPublicKeyArgs {
    canister_id: Option<Principal>,
    derivation_path: Vec<Vec<u8>>,
    key_id: SchnorrKeyId,
}

#[derive(CandidType, Deserialize)]
struct SchnorrPublicKeyReply {
    public_key: Vec<u8>,
    #[allow(dead_code)]
    chain_code: Vec<u8>,
}

/// `aux : opt schnorr_aux` (BIP-341 tweaks only, irrelevant to Ed25519) is
/// omitted: candid fills an absent opt field with null at the callee.
#[derive(CandidType)]
struct SignWithSchnorrArgs {
    message: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    key_id: SchnorrKeyId,
}

#[derive(CandidType, Deserialize)]
struct SignWithSchnorrReply {
    signature: Vec<u8>,
}

fn key_id(cfg: &SolConfig) -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: cfg.key_name.clone(),
    }
}

/// The canister's Ed25519 public key (32 bytes), cached in META after the
/// first management-canister round trip, keyed by key name so switching
/// test_key_1 -> key_1 cannot serve the stale key. Mirrors evm.rs.
async fn public_key(cfg: &SolConfig) -> Result<[u8; 32], String> {
    const CACHE_KEY: &str = "sol:pubkey";
    if let Some((name, pk)) = store::meta_get_json::<(String, Vec<u8>)>(CACHE_KEY) {
        if name == cfg.key_name {
            return pk
                .try_into()
                .map_err(|_| "cached public key is not 32 bytes".into());
        }
    }
    let reply: SchnorrPublicKeyReply = intercanister::call(
        Principal::management_canister(),
        "schnorr_public_key",
        (SchnorrPublicKeyArgs {
            canister_id: None,
            derivation_path: vec![],
            key_id: key_id(cfg),
        },),
    )
    .await?;
    store::meta_set_json(CACHE_KEY, &(cfg.key_name.clone(), reply.public_key.clone()));
    reply
        .public_key
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32-byte ed25519 key, got {}", v.len()))
}

/// Sign a message (the full message bytes -- Ed25519 has no prehash).
/// Returns the 64-byte signature.
async fn sign_message(cfg: &SolConfig, message: &[u8]) -> Result<[u8; 64], String> {
    let reply: SignWithSchnorrReply = intercanister::call_with_payment(
        Principal::management_canister(),
        "sign_with_schnorr",
        (SignWithSchnorrArgs {
            message: message.to_vec(),
            derivation_path: vec![],
            key_id: key_id(cfg),
        },),
        SIGN_CYCLES,
    )
    .await?;
    reply
        .signature
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 64-byte signature, got {}", v.len()))
}

// --- SOL RPC canister (hand-mirrored candid subset) --------------------------
// Only the methods this module calls and the types they reach. Reply variants
// mirror every arm the canister can return; argument records may be subtypes.

#[derive(CandidType, Deserialize, Debug, Clone)]
enum SolanaCluster {
    Mainnet,
    Devnet,
    Testnet,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
struct HttpHeader {
    value: String,
    name: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
struct RpcEndpoint {
    url: String,
    headers: Option<Vec<HttpHeader>>,
}

/// One provider, as it appears in `Inconsistent` replies. The `Supported`
/// arm's provider enum is mirrored as a catch-all string-free variant list;
/// only Debug-rendering touches it.
#[derive(CandidType, Deserialize, Debug, Clone)]
enum SupportedProvider {
    AlchemyMainnet,
    AlchemyDevnet,
    AnkrMainnet,
    AnkrDevnet,
    ChainstackMainnet,
    ChainstackDevnet,
    DrpcMainnet,
    DrpcDevnet,
    HeliusMainnet,
    HeliusDevnet,
    PublicNodeMainnet,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum RpcSource {
    Supported(SupportedProvider),
    Custom(RpcEndpoint),
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum RpcSources {
    Custom(Vec<RpcSource>),
    Default(SolanaCluster),
}

#[derive(CandidType, Deserialize, Debug)]
enum ConsensusStrategy {
    Equality,
    Threshold { total: Option<u8>, min: u8 },
}

#[derive(CandidType, Deserialize, Debug)]
struct RpcConfig {
    #[serde(rename = "responseSizeEstimate")]
    response_size_estimate: Option<u64>,
    #[serde(rename = "responseConsensus")]
    response_consensus: Option<ConsensusStrategy>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum RejectionCode {
    NoError,
    CanisterError,
    SysTransient,
    DestinationInvalid,
    Unknown,
    SysFatal,
    CanisterReject,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum ProviderError {
    TooFewCycles { expected: u128, received: u128 },
    InvalidRpcConfig(String),
    UnsupportedCluster(String),
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum HttpOutcallError {
    IcError {
        code: RejectionCode,
        message: String,
    },
    InvalidHttpJsonRpcResponse {
        status: u16,
        body: String,
        #[serde(rename = "parsingError")]
        parsing_error: Option<String>,
    },
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum RpcError {
    JsonRpcError(JsonRpcError),
    ProviderError(ProviderError),
    ValidationError(String),
    HttpOutcallError(HttpOutcallError),
}

impl RpcError {
    fn render(&self) -> String {
        format!("{self:?}")
    }
}

#[derive(CandidType, Deserialize, Debug)]
enum RpcResult<T> {
    Ok(T),
    Err(RpcError),
}

#[derive(CandidType, Deserialize, Debug)]
enum MultiResult<T> {
    Consistent(RpcResult<T>),
    Inconsistent(Vec<(RpcSource, RpcResult<T>)>),
}

impl<T> MultiResult<T> {
    /// Collapse to a plain Result; `Inconsistent` means the consensus we
    /// asked for was not reached, which is failure. Mirrors evm.rs.
    fn into_result(self, what: &str) -> Result<T, String> {
        match self {
            Self::Consistent(RpcResult::Ok(v)) => Ok(v),
            Self::Consistent(RpcResult::Err(e)) => Err(format!("{what}: {}", e.render())),
            Self::Inconsistent(results) => Err(format!(
                "{what}: providers disagree: {:?}",
                results
                    .iter()
                    .map(|(src, r)| format!(
                        "{src:?} -> {}",
                        match r {
                            RpcResult::Ok(_) => "ok".to_string(),
                            RpcResult::Err(e) => e.render(),
                        }
                    ))
                    .collect::<Vec<_>>()
            )),
        }
    }
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum CommitmentLevel {
    #[serde(rename = "processed")]
    Processed,
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "finalized")]
    Finalized,
}

#[derive(CandidType, Deserialize, Debug)]
struct GetSlotParams {
    commitment: Option<CommitmentLevel>,
    #[serde(rename = "minContextSlot")]
    min_context_slot: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
enum TransactionDetails {
    #[serde(rename = "accounts")]
    Accounts,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "signatures")]
    Signatures,
}

#[derive(CandidType, Deserialize, Debug)]
enum BlockCommitment {
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "finalized")]
    Finalized,
}

#[derive(CandidType, Deserialize, Debug)]
struct GetBlockParams {
    slot: u64,
    #[serde(rename = "transactionDetails")]
    transaction_details: Option<TransactionDetails>,
    commitment: Option<BlockCommitment>,
    #[serde(rename = "maxSupportedTransactionVersion")]
    max_supported_transaction_version: Option<u8>,
    rewards: Option<bool>,
}

/// Subset of ConfirmedBlock: candid skips wire fields the expected record
/// omits, and the blockhash is all this module reads.
#[derive(CandidType, Deserialize, Debug)]
struct ConfirmedBlock {
    blockhash: String,
    #[serde(rename = "parentSlot")]
    #[allow(dead_code)]
    parent_slot: u64,
}

#[derive(CandidType, Deserialize, Debug)]
struct GetBalanceParams {
    pubkey: String,
    commitment: Option<CommitmentLevel>,
    #[serde(rename = "minContextSlot")]
    min_context_slot: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
enum SendTransactionEncoding {
    #[serde(rename = "base58")]
    Base58,
    #[serde(rename = "base64")]
    Base64,
}

#[derive(CandidType, Deserialize, Debug)]
struct SendTransactionParams {
    transaction: String,
    encoding: Option<SendTransactionEncoding>,
    #[serde(rename = "skipPreflight")]
    skip_preflight: Option<bool>,
    #[serde(rename = "preflightCommitment")]
    preflight_commitment: Option<CommitmentLevel>,
    #[serde(rename = "maxRetries")]
    max_retries: Option<u32>,
    #[serde(rename = "minContextSlot")]
    min_context_slot: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
struct GetSignatureStatusesParams {
    signatures: Vec<String>,
    #[serde(rename = "searchTransactionHistory")]
    search_transaction_history: Option<bool>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum TransactionConfirmationStatus {
    #[serde(rename = "processed")]
    Processed,
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "finalized")]
    Finalized,
}

/// TransactionError is a large recursive variant; this module only renders
/// it, so it is mirrored as candid's reserved (any) -- decoded and dropped.
#[derive(CandidType, Deserialize, Debug, Clone)]
struct TransactionStatus {
    slot: u64,
    err: Option<candid::Reserved>,
    #[serde(rename = "confirmationStatus")]
    confirmation_status: Option<TransactionConfirmationStatus>,
}

// --- config ------------------------------------------------------------------

/// Global Solana signing/broadcast configuration (META key `sol:config`).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SolConfig {
    /// Principal (text) of the SOL RPC canister. Mainnet: tghme-zyaaa-aaaar-qarca-cai.
    pub sol_rpc: String,
    /// Threshold Schnorr key name: dfx_test_key locally, test_key_1 / key_1 on ICP.
    pub key_name: String,
    /// Target cluster: "mainnet", "devnet", or "testnet".
    pub cluster: String,
    /// Custom JSON-RPC URLs. Empty selects the SOL RPC canister's default
    /// provider set for the cluster; non-empty uses exactly these endpoints.
    #[serde(default)]
    pub rpc_urls: Vec<String>,
}

/// Cycles attached to each sign_with_schnorr call (the ed25519 fee matches
/// ECDSA's ~26.15B on the fiduciary subnet); surplus refunded.
const SIGN_CYCLES: u128 = 30_000_000_000;
/// Cycles attached to each SOL RPC call; the canister refunds surplus, and
/// its per-call cost (multi-provider HTTPS outcalls) runs above the EVM
/// RPC canister's, hence the higher figure.
const RPC_CYCLES: u128 = 10_000_000_000;

const CONFIG_KEY: &str = "sol:config";

fn parse_cluster(cluster: &str) -> Result<SolanaCluster, String> {
    match cluster {
        "mainnet" => Ok(SolanaCluster::Mainnet),
        "devnet" => Ok(SolanaCluster::Devnet),
        "testnet" => Ok(SolanaCluster::Testnet),
        other => Err(format!(
            "unknown cluster {other:?}; expected mainnet, devnet, or testnet"
        )),
    }
}

pub fn set_config(
    sol_rpc: String,
    key_name: String,
    cluster: String,
    rpc_urls: Vec<String>,
) -> Result<(), String> {
    Principal::from_text(&sol_rpc).map_err(|e| format!("bad sol_rpc principal: {e}"))?;
    parse_cluster(&cluster)?;
    let cfg = SolConfig {
        sol_rpc,
        key_name,
        cluster,
        rpc_urls,
    };
    store::meta_set_json(CONFIG_KEY, &cfg);
    Ok(())
}

pub fn get_config() -> Option<SolConfig> {
    store::meta_get_json(CONFIG_KEY)
}

fn require_config() -> Result<SolConfig, String> {
    get_config().ok_or_else(|| "no Solana config; call sol_set_config first".into())
}

fn sources(cfg: &SolConfig) -> Result<RpcSources, String> {
    if cfg.rpc_urls.is_empty() {
        return Ok(RpcSources::Default(parse_cluster(&cfg.cluster)?));
    }
    Ok(RpcSources::Custom(
        cfg.rpc_urls
            .iter()
            .map(|url| {
                RpcSource::Custom(RpcEndpoint {
                    url: url.clone(),
                    headers: None,
                })
            })
            .collect(),
    ))
}

fn rpc_principal(cfg: &SolConfig) -> Result<Principal, String> {
    Principal::from_text(&cfg.sol_rpc).map_err(|e| format!("bad sol_rpc principal: {e}"))
}

/// All-but-one consensus across providers, as in evm.rs: one flaky provider
/// must not fail the call. None with a single custom URL (nothing to vote).
fn consensus(cfg: &SolConfig) -> Option<ConsensusStrategy> {
    let n = if cfg.rpc_urls.is_empty() {
        3 // the SOL RPC canister's default provider count per cluster
    } else {
        cfg.rpc_urls.len()
    };
    if n < 2 {
        return None;
    }
    Some(ConsensusStrategy::Threshold {
        min: (n - 1) as u8,
        total: Some(n as u8),
    })
}

fn rpc_config(cfg: &SolConfig) -> Option<RpcConfig> {
    consensus(cfg).map(|c| RpcConfig {
        response_size_estimate: None,
        response_consensus: Some(c),
    })
}

async fn rpc_call<A, T>(cfg: &SolConfig, method: &str, arg: A, what: &str) -> Result<T, String>
where
    A: CandidType,
    T: serde::de::DeserializeOwned + CandidType,
{
    let multi: MultiResult<T> = intercanister::call_with_payment(
        rpc_principal(cfg)?,
        method,
        (sources(cfg)?, rpc_config(cfg), arg),
        RPC_CYCLES,
    )
    .await?;
    multi.into_result(what)
}

// --- chain reads -------------------------------------------------------------

/// A recent finalized blockhash, via getSlot (rounded for consensus) then
/// getBlock. The rounded slot can land on a skipped slot, so a miss walks
/// back one slot at a time a few steps before giving up.
async fn recent_blockhash(cfg: &SolConfig) -> Result<(u64, String, [u8; 32]), String> {
    // getSlot's own config type adds a roundingError field; the shared
    // RpcConfig is a valid candid subtype of it (the absent opt field decodes
    // as null), leaving the rounding at the canister's default of 20 slots.
    let slot: u64 = rpc_call(
        cfg,
        "getSlot",
        Some(GetSlotParams {
            commitment: Some(CommitmentLevel::Finalized),
            min_context_slot: None,
        }),
        "getSlot",
    )
    .await?;
    let mut last_err = String::new();
    for back in 0..4u64 {
        let candidate = slot.saturating_sub(back);
        let block: Option<ConfirmedBlock> = rpc_call(
            cfg,
            "getBlock",
            GetBlockParams {
                slot: candidate,
                transaction_details: Some(TransactionDetails::None),
                commitment: Some(BlockCommitment::Finalized),
                max_supported_transaction_version: Some(0),
                rewards: Some(false),
            },
            "getBlock",
        )
        .await?;
        match block {
            Some(b) => {
                let hash = parse_pubkey(&b.blockhash)
                    .map_err(|e| format!("bad blockhash from getBlock: {e}"))?;
                return Ok((candidate, b.blockhash, hash));
            }
            None => last_err = format!("no block at slot {candidate} (skipped)"),
        }
    }
    Err(format!("getBlock: {last_err}"))
}

// --- sign and broadcast ------------------------------------------------------

/// The canister's Solana address (base58 of its Ed25519 public key). First
/// call derives and caches the key.
pub async fn address() -> Result<String, String> {
    let cfg = require_config()?;
    let pk = public_key(&cfg).await?;
    Ok(base58::encode(&pk))
}

/// Lamport balance of the canister's own address (finalized commitment).
pub async fn balance() -> Result<u64, String> {
    let cfg = require_config()?;
    let pk = public_key(&cfg).await?;
    rpc_call(
        &cfg,
        "getBalance",
        GetBalanceParams {
            pubkey: base58::encode(&pk),
            commitment: Some(CommitmentLevel::Finalized),
            min_context_slot: None,
        },
        "getBalance",
    )
    .await
}

/// Outcome of a broadcast transfer.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SolTxOutcome {
    /// Transaction signature (base58) -- Solana's transaction id.
    pub signature: String,
    pub from: String,
    /// The blockhash the message was signed against; the transaction dies
    /// with it (~150 blocks) if never accepted.
    pub blockhash: String,
    /// Slot the blockhash came from.
    pub blockhash_slot: u64,
}

/// S0: sign and broadcast a system transfer from the canister's address.
/// No nonce and no send lock (replay scope is the blockhash); the ~60-90s
/// blockhash validity bounds the sign-and-broadcast window instead.
pub async fn send_lamports(to: String, lamports: u64) -> Result<SolTxOutcome, String> {
    let cfg = require_config()?;
    let to = parse_pubkey(&to)?;
    let from = public_key(&cfg).await?;
    let (slot, blockhash_b58, blockhash) = recent_blockhash(&cfg).await?;
    let message = transfer_message(&from, &to, lamports, &blockhash);
    let signature = sign_message(&cfg, &message).await?;
    let tx = assemble_transaction(&signature, &message);

    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&tx);
    let accepted: String = rpc_call(
        &cfg,
        "sendTransaction",
        SendTransactionParams {
            transaction: encoded,
            encoding: Some(SendTransactionEncoding::Base64),
            skip_preflight: None,
            preflight_commitment: None,
            max_retries: None,
            min_context_slot: None,
        },
        "sendTransaction",
    )
    .await?;
    Ok(SolTxOutcome {
        signature: accepted,
        from: base58::encode(&from),
        blockhash: blockhash_b58,
        blockhash_slot: slot,
    })
}

/// Confirmation status of a transaction signature: None while unknown to the
/// cluster, otherwise "processed" / "confirmed" / "finalized", with "failed:"
/// prefixed when the transaction errored. The Solana analog of evm_receipt.
pub async fn signature_status(signature: String) -> Result<Option<String>, String> {
    let cfg = require_config()?;
    let statuses: Vec<Option<TransactionStatus>> = rpc_call(
        &cfg,
        "getSignatureStatuses",
        GetSignatureStatusesParams {
            signatures: vec![signature],
            search_transaction_history: Some(true),
        },
        "getSignatureStatuses",
    )
    .await?;
    Ok(statuses.into_iter().next().flatten().map(|s| {
        let level = match s.confirmation_status {
            Some(TransactionConfirmationStatus::Finalized) => "finalized",
            Some(TransactionConfirmationStatus::Confirmed) => "confirmed",
            _ => "processed",
        };
        if s.err.is_some() {
            format!("failed: {level} slot {}", s.slot)
        } else {
            format!("{level} slot {}", s.slot)
        }
    }))
}

// --- tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_vectors() {
        assert_eq!(base58::encode(&[]), "");
        // The system program id: 32 zero bytes, 32 ones.
        assert_eq!(
            base58::encode(&[0u8; 32]),
            "11111111111111111111111111111111"
        );
        // Canonical vector shared by every base58 implementation.
        let payload = hex::decode("00010966776006953d5567439e5e39f86a0d273beed61967f6").unwrap();
        assert_eq!(
            base58::encode(&payload),
            "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
        );
        assert_eq!(base58::decode("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM").unwrap(), payload);
        // Round trip with leading zeros preserved.
        let bytes = [0u8, 0, 255, 1, 2, 3, 42];
        assert_eq!(base58::decode(&base58::encode(&bytes)).unwrap(), bytes);
        assert!(base58::decode("bad0char").is_err()); // 0 is not in the alphabet
    }

    #[test]
    fn shortvec_vectors() {
        // Vectors from the Solana shortvec documentation.
        let enc = |n: u16| {
            let mut v = Vec::new();
            shortvec_len(&mut v, n);
            v
        };
        assert_eq!(enc(0x0000), vec![0x00]);
        assert_eq!(enc(0x007f), vec![0x7f]);
        assert_eq!(enc(0x0080), vec![0x80, 0x01]);
        assert_eq!(enc(0x00ff), vec![0xff, 0x01]);
        assert_eq!(enc(0x0100), vec![0x80, 0x02]);
        assert_eq!(enc(0x7fff), vec![0xff, 0xff, 0x01]);
        assert_eq!(enc(0xffff), vec![0xff, 0xff, 0x03]);
    }

    #[test]
    fn transfer_instruction_layout() {
        let data = transfer_instruction_data(1_000_000);
        assert_eq!(data.len(), 12);
        assert_eq!(&data[..4], &[2, 0, 0, 0]); // Transfer discriminant, u32 LE
        assert_eq!(&data[4..], &1_000_000u64.to_le_bytes());
    }

    #[test]
    fn transfer_message_layout() {
        let from = [0x11u8; 32];
        let to = [0x22u8; 32];
        let blockhash = [0x33u8; 32];
        let msg = transfer_message(&from, &to, 5_000, &blockhash);

        assert_eq!(&msg[..3], &[1, 0, 1]); // header
        assert_eq!(msg[3], 3); // three account keys (shortvec fits one byte)
        assert_eq!(&msg[4..36], &from);
        assert_eq!(&msg[36..68], &to);
        assert_eq!(&msg[68..100], &SYSTEM_PROGRAM);
        assert_eq!(&msg[100..132], &blockhash);
        assert_eq!(msg[132], 1); // one instruction
        assert_eq!(msg[133], 2); // program id index (system program, last key)
        assert_eq!(msg[134], 2); // two account indexes
        assert_eq!(&msg[135..137], &[0, 1]); // from, to
        assert_eq!(msg[137], 12); // data length
        assert_eq!(&msg[138..150], &transfer_instruction_data(5_000)[..]);
        assert_eq!(msg.len(), 150);
    }

    #[test]
    fn self_transfer_collapses_accounts() {
        let key = [0x44u8; 32];
        let blockhash = [0x55u8; 32];
        let msg = transfer_message(&key, &key, 1, &blockhash);
        assert_eq!(msg[3], 2); // two keys: payer + system program
        assert_eq!(&msg[4..36], &key);
        assert_eq!(&msg[36..68], &SYSTEM_PROGRAM);
        assert_eq!(msg[101], 1); // program id index
        assert_eq!(&msg[103..105], &[0, 0]); // both instruction accounts are the payer
    }

    #[test]
    fn transaction_assembly() {
        let sig = [0xabu8; 64];
        let msg = vec![1, 2, 3];
        let tx = assemble_transaction(&sig, &msg);
        assert_eq!(tx[0], 1); // one signature
        assert_eq!(&tx[1..65], &sig);
        assert_eq!(&tx[65..], &msg[..]);
    }

    #[test]
    fn cluster_parsing() {
        assert!(parse_cluster("devnet").is_ok());
        assert!(parse_cluster("mainnet").is_ok());
        assert!(parse_cluster("testnet").is_ok());
        assert!(parse_cluster("Devnet").is_err());
    }

    #[test]
    fn pubkey_parsing_rejects_wrong_length() {
        assert!(parse_pubkey("11111111111111111111111111111111").is_ok());
        assert!(parse_pubkey("1111").is_err());
        assert!(parse_pubkey("not-base58-0OIl").is_err());
    }
}
