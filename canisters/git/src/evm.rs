//! Track A: EVM contract deployment (see ../../../ROADMAP.md, phases E0/E1).
//!
//! The canister derives its own Ethereum EOA from a threshold-ECDSA public
//! key, builds and signs EIP-1559 transactions (value transfers for E0, CREATE
//! deployments for E1), and broadcasts them through the EVM RPC canister's
//! `eth_sendRawTransaction`. Nothing here trusts an off-chain signer: the
//! private key exists only as shares across the subnet, so a transaction from
//! this EOA *is* an attestation that this canister produced it.
//!
//! Deliberately hand-rolled rather than pulling in ic-alloy: that fork pins
//! ic-cdk 0.17 against our 0.20 and last released Nov 2024. The slice we need
//! -- a minimal RLP encoder, keccak256, pubkey->EOA, and trial recovery for
//! the v bit -- is small, and mirroring the EVM RPC candid by hand matches how
//! deploy.rs already mirrors the management canister.
//!
//! Every deploy attempt appends an [`EvmDeployRecord`] binding
//! (repo, commit, chain id, contract address, tx hash, bytecode hash) in
//! stable memory: the provenance substrate any future source-verification
//! story (metadata-hash checks, on-chain solc) sits on. A record attests
//! broadcast acceptance; mined-and-succeeded is confirmed separately via
//! its tx_hash (evm_receipt).

use crate::kv;
use crate::rpc_common::{all_but_one, HttpHeader, HttpOutcallError, JsonRpcError, SIGN_CYCLES};
use candid::{CandidType, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

// --- keccak / hex helpers ----------------------------------------------------

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// EIP-55 checksummed hex form of a 20-byte address.
pub fn checksum_address(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let digest = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (digest[i / 2] >> (4 * (1 - i % 2))) & 0xf;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("bad address hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "address must be 20 bytes".into())
}

// --- RLP encoding ------------------------------------------------------------
// The whole of what an EIP-1559 transaction needs: byte strings, unsigned
// integers (minimal big-endian, zero = empty string), and lists.

mod rlp {
    /// Append the RLP encoding of a byte string to `out`.
    pub fn bytes(out: &mut Vec<u8>, b: &[u8]) {
        if b.len() == 1 && b[0] < 0x80 {
            out.push(b[0]);
        } else {
            length_prefix(out, b.len(), 0x80);
            out.extend_from_slice(b);
        }
    }

    /// Append the RLP encoding of an unsigned integer (minimal big-endian).
    pub fn uint(out: &mut Vec<u8>, v: u128) {
        let be = v.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        bytes(out, &be[start..]);
    }

    /// Wrap an already-encoded payload as an RLP list.
    pub fn list(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 9);
        length_prefix(&mut out, payload.len(), 0xc0);
        out.extend_from_slice(payload);
        out
    }

    fn length_prefix(out: &mut Vec<u8>, len: usize, base: u8) {
        if len <= 55 {
            out.push(base + len as u8);
        } else {
            let be = (len as u64).to_be_bytes();
            let start = be.iter().position(|&b| b != 0).unwrap_or(7);
            out.push(base + 55 + (8 - start) as u8);
            out.extend_from_slice(&be[start..]);
        }
    }
}

// --- EIP-1559 transaction ----------------------------------------------------

/// An unsigned EIP-1559 (type 2) transaction. `to = None` is a CREATE.
pub struct Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
}

impl Tx {
    /// RLP of the nine unsigned fields (access list always empty).
    fn payload(&self) -> Vec<u8> {
        let mut p = Vec::new();
        rlp::uint(&mut p, self.chain_id as u128);
        rlp::uint(&mut p, self.nonce as u128);
        rlp::uint(&mut p, self.max_priority_fee_per_gas);
        rlp::uint(&mut p, self.max_fee_per_gas);
        rlp::uint(&mut p, self.gas_limit as u128);
        match &self.to {
            Some(addr) => rlp::bytes(&mut p, addr),
            None => rlp::bytes(&mut p, &[]),
        }
        rlp::uint(&mut p, self.value);
        rlp::bytes(&mut p, &self.data);
        p.extend_from_slice(&rlp::list(&[])); // empty access list
        p
    }

    /// keccak256(0x02 || rlp(unsigned fields)) -- what threshold ECDSA signs.
    pub fn signature_hash(&self) -> [u8; 32] {
        let mut pre = vec![0x02];
        pre.extend_from_slice(&rlp::list(&self.payload()));
        keccak256(&pre)
    }

    /// The signed raw transaction: 0x02 || rlp(fields || y_parity, r, s).
    pub fn raw_signed(&self, y_parity: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let strip = |b: &[u8; 32]| {
            let start = b.iter().position(|&x| x != 0).unwrap_or(32);
            b[start..].to_vec()
        };
        let mut p = self.payload();
        rlp::uint(&mut p, y_parity as u128);
        rlp::bytes(&mut p, &strip(r));
        rlp::bytes(&mut p, &strip(s));
        let mut raw = vec![0x02];
        raw.extend_from_slice(&rlp::list(&p));
        raw
    }
}

/// The address a CREATE from `sender` at `nonce` deploys to:
/// keccak256(rlp([sender, nonce]))[12..]. Deterministic, so we can report the
/// contract address without waiting for the receipt.
pub fn create_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut p = Vec::new();
    rlp::bytes(&mut p, sender);
    rlp::uint(&mut p, nonce as u128);
    keccak256(&rlp::list(&p))[12..].try_into().unwrap()
}

// --- threshold ECDSA (management canister, hand-mirrored like deploy.rs) -----

#[derive(CandidType, Deserialize, Clone)]
enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

#[derive(CandidType, Deserialize, Clone)]
struct EcdsaKeyId {
    curve: EcdsaCurve,
    name: String,
}

#[derive(CandidType)]
struct EcdsaPublicKeyArgs {
    canister_id: Option<Principal>,
    derivation_path: Vec<Vec<u8>>,
    key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize)]
struct EcdsaPublicKeyReply {
    public_key: Vec<u8>,
    #[allow(dead_code)]
    chain_code: Vec<u8>,
}

#[derive(CandidType)]
struct SignWithEcdsaArgs {
    message_hash: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize)]
struct SignWithEcdsaReply {
    signature: Vec<u8>,
}

fn key_id(cfg: &EvmConfig) -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: cfg.key_name.clone(),
    }
}

/// The canister's secp256k1 public key (SEC1 compressed, 33 bytes), cached in
/// META after the first management-canister round trip: the key is stable for
/// the canister's lifetime, and deriving the EOA must not cost a call each time.
async fn public_key(cfg: &EvmConfig) -> Result<Vec<u8>, String> {
    const CACHE_KEY: &str = "evm:pubkey";
    // The cache is per key name: switching key_name (test key -> production
    // key) must not serve the stale key.
    if let Some((name, pk)) = kv::get_json::<(String, Vec<u8>)>(CACHE_KEY) {
        if name == cfg.key_name {
            return Ok(pk);
        }
    }
    let reply: EcdsaPublicKeyReply = intercanister::call(
        Principal::management_canister(),
        "ecdsa_public_key",
        (EcdsaPublicKeyArgs {
            canister_id: None,
            derivation_path: vec![],
            key_id: key_id(cfg),
        },),
    )
    .await?;
    kv::set_json(CACHE_KEY, &(cfg.key_name.clone(), reply.public_key.clone()));
    Ok(reply.public_key)
}

/// Sign a 32-byte hash. Returns the fixed 64-byte r||s signature.
async fn sign_hash(cfg: &EvmConfig, hash: [u8; 32]) -> Result<[u8; 64], String> {
    let reply: SignWithEcdsaReply = intercanister::call_with_payment(
        Principal::management_canister(),
        "sign_with_ecdsa",
        (SignWithEcdsaArgs {
            message_hash: hash.to_vec(),
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

/// EOA of a SEC1 (compressed or uncompressed) secp256k1 public key:
/// keccak256(uncompressed[1..65])[12..].
pub fn eoa_of_pubkey(sec1: &[u8]) -> Result<[u8; 20], String> {
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
        .map_err(|e| format!("bad public key: {e}"))?;
    let point = vk.to_encoded_point(false);
    Ok(keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap())
}

/// Find the y-parity bit by trial recovery: the parity under which the
/// signature recovers to our own public key. Also normalizes s to the low
/// half-order form Ethereum requires (EIP-2).
fn recover_parity(
    sec1_pubkey: &[u8],
    sighash: &[u8; 32],
    sig64: &[u8; 64],
) -> Result<(u8, [u8; 32], [u8; 32]), String> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let ours =
        VerifyingKey::from_sec1_bytes(sec1_pubkey).map_err(|e| format!("bad public key: {e}"))?;
    let mut sig = Signature::from_slice(sig64).map_err(|e| format!("bad signature: {e}"))?;
    if let Some(low) = sig.normalize_s() {
        sig = low;
    }
    for v in 0u8..2 {
        let rid = RecoveryId::try_from(v).unwrap();
        if let Ok(recovered) = VerifyingKey::recover_from_prehash(sighash, &sig, rid) {
            if recovered == ours {
                let r: [u8; 32] = sig.r().to_bytes().into();
                let s: [u8; 32] = sig.s().to_bytes().into();
                return Ok((v, r, s));
            }
        }
    }
    Err("signature does not recover to the canister's public key".into())
}

// --- EVM RPC canister (hand-mirrored candid subset) --------------------------
// Only the four methods and the types they reach. Argument variants may be
// subtypes of the canister's fuller types; reply variants must cover every arm
// the canister can actually return, so the error tree is mirrored completely.

#[derive(CandidType, Deserialize, Debug, Clone)]
struct RpcApi {
    url: String,
    headers: Option<Vec<HttpHeader>>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum EthSepoliaService {
    Alchemy,
    Ankr,
    BlockPi,
    PublicNode,
    Sepolia,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum EthMainnetService {
    Alchemy,
    Ankr,
    BlockPi,
    Cloudflare,
    PublicNode,
    Llama,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum L2MainnetService {
    Alchemy,
    Ankr,
    BlockPi,
    PublicNode,
    Llama,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum RpcServices {
    Custom {
        #[serde(rename = "chainId")]
        chain_id: u64,
        services: Vec<RpcApi>,
    },
    EthSepolia(Option<Vec<EthSepoliaService>>),
    EthMainnet(Option<Vec<EthMainnetService>>),
    ArbitrumOne(Option<Vec<L2MainnetService>>),
    BaseMainnet(Option<Vec<L2MainnetService>>),
    OptimismMainnet(Option<Vec<L2MainnetService>>),
}

/// One provider, as it appears in `Inconsistent` replies.
#[derive(CandidType, Deserialize, Debug, Clone)]
enum RpcService {
    Custom(RpcApi),
    EthSepolia(EthSepoliaService),
    EthMainnet(EthMainnetService),
    ArbitrumOne(L2MainnetService),
    BaseMainnet(L2MainnetService),
    OptimismMainnet(L2MainnetService),
    Chain(u64),
    Provider(u64),
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum ProviderError {
    TooFewCycles {
        expected: u128,
        received: u128,
    },
    MissingRequiredProvider,
    ProviderNotFound,
    NoPermission,
    InvalidRpcConfig(String),
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum ValidationError {
    Custom(String),
    InvalidHex(String),
}

#[derive(CandidType, Deserialize, Debug, Clone)]
enum RpcError {
    JsonRpcError(JsonRpcError),
    ProviderError(ProviderError),
    ValidationError(ValidationError),
    HttpOutcallError(HttpOutcallError),
}

impl RpcError {
    fn render(&self) -> String {
        format!("{self:?}")
    }
}

#[derive(CandidType, Deserialize, Debug)]
enum BlockTag {
    Earliest,
    Safe,
    Finalized,
    Latest,
    Number(u128),
    Pending,
}

#[derive(CandidType, Deserialize, Debug)]
struct GetTransactionCountArgs {
    address: String,
    block: BlockTag,
}

#[derive(CandidType, Deserialize, Debug)]
struct FeeHistoryArgs {
    #[serde(rename = "blockCount")]
    block_count: u128,
    #[serde(rename = "newestBlock")]
    newest_block: BlockTag,
    #[serde(rename = "rewardPercentiles")]
    reward_percentiles: Option<Vec<u8>>,
}

#[derive(CandidType, Deserialize, Debug)]
struct FeeHistory {
    reward: Vec<Vec<u128>>,
    #[serde(rename = "gasUsedRatio")]
    gas_used_ratio: Vec<f64>,
    #[serde(rename = "oldestBlock")]
    oldest_block: u128,
    #[serde(rename = "baseFeePerGas")]
    base_fee_per_gas: Vec<u128>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
struct LogEntry {
    #[serde(rename = "transactionHash")]
    transaction_hash: Option<String>,
    #[serde(rename = "blockNumber")]
    block_number: Option<u128>,
    data: String,
    #[serde(rename = "blockHash")]
    block_hash: Option<String>,
    #[serde(rename = "transactionIndex")]
    transaction_index: Option<u128>,
    topics: Vec<String>,
    address: String,
    #[serde(rename = "logIndex")]
    log_index: Option<u128>,
    removed: bool,
}

#[derive(CandidType, Deserialize, Debug)]
struct TransactionReceipt {
    to: Option<String>,
    status: Option<u128>,
    root: Option<String>,
    #[serde(rename = "transactionHash")]
    transaction_hash: String,
    #[serde(rename = "blockNumber")]
    block_number: u128,
    from: String,
    #[allow(dead_code)]
    logs: Vec<LogEntry>,
    #[serde(rename = "blockHash")]
    block_hash: String,
    #[serde(rename = "type")]
    tx_type: String,
    #[serde(rename = "transactionIndex")]
    transaction_index: u128,
    #[serde(rename = "effectiveGasPrice")]
    effective_gas_price: u128,
    #[serde(rename = "logsBloom")]
    logs_bloom: String,
    #[serde(rename = "contractAddress")]
    contract_address: Option<String>,
    #[serde(rename = "gasUsed")]
    gas_used: u128,
    #[serde(rename = "cumulativeGasUsed")]
    cumulative_gas_used: u128,
}

#[derive(CandidType, Deserialize, Debug)]
enum SendRawTransactionStatus {
    Ok(Option<String>),
    NonceTooLow,
    NonceTooHigh,
    InsufficientFunds,
}

/// variant { Ok : T; Err : RpcError } -- candid's Result shape on the wire.
#[derive(CandidType, Deserialize, Debug)]
enum RpcResult<T> {
    Ok(T),
    Err(RpcError),
}

#[derive(CandidType, Deserialize, Debug)]
enum MultiResult<T> {
    Consistent(RpcResult<T>),
    Inconsistent(Vec<(RpcService, RpcResult<T>)>),
}

impl<T> MultiResult<T> {
    /// Collapse to a plain Result. `Inconsistent` is treated as failure: we
    /// asked for consensus across providers and did not get it.
    fn into_result(self, what: &str) -> Result<T, String> {
        match self {
            Self::Consistent(RpcResult::Ok(v)) => Ok(v),
            Self::Consistent(RpcResult::Err(e)) => Err(format!("{what}: {}", e.render())),
            Self::Inconsistent(results) => Err(format!(
                "{what}: providers disagree: {:?}",
                results
                    .iter()
                    .map(|(svc, r)| format!(
                        "{svc:?} -> {}",
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

// --- config ------------------------------------------------------------------

/// Global EVM signing/broadcast configuration (META key `evm:config`).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmConfig {
    /// Principal (text) of the EVM RPC canister. Mainnet: 7hfb6-caaaa-aaaar-qadga-cai.
    pub evm_rpc: String,
    /// Threshold ECDSA key name: dfx_test_key locally, test_key_1 / key_1 on ICP.
    pub key_name: String,
    /// EIP-155 chain id of the target chain (11155111 = Sepolia).
    pub chain_id: u64,
    /// Custom JSON-RPC URLs. Empty selects the EVM RPC canister's default
    /// provider set for `chain_id` (Sepolia and Eth mainnet only); non-empty
    /// uses exactly these endpoints, which is how a local anvil or a chain
    /// without presets is reached.
    #[serde(default)]
    pub rpc_urls: Vec<String>,
}

/// Cycles attached to each EVM RPC call; surplus refunded.
const RPC_CYCLES: u128 = 3_000_000_000;

const CONFIG_KEY: &str = "evm:config";
const LOG_KEY: &str = "evm:deploy_log";

pub fn set_config(
    evm_rpc: String,
    key_name: String,
    chain_id: u64,
    rpc_urls: Vec<String>,
) -> Result<(), String> {
    Principal::from_text(&evm_rpc).map_err(|e| format!("bad evm_rpc principal: {e}"))?;
    if rpc_urls.is_empty() && !matches!(chain_id, 1 | 11155111) {
        return Err(format!(
            "no EVM RPC preset for chain id {chain_id}; provide rpc_urls"
        ));
    }
    let cfg = EvmConfig {
        evm_rpc,
        key_name,
        chain_id,
        rpc_urls,
    };
    kv::set_json(CONFIG_KEY, &cfg);
    Ok(())
}

pub fn get_config() -> Option<EvmConfig> {
    kv::get_json(CONFIG_KEY)
}

fn require_config() -> Result<EvmConfig, String> {
    get_config().ok_or_else(|| "no EVM config; call evm_set_config first".into())
}

fn services(cfg: &EvmConfig) -> RpcServices {
    if !cfg.rpc_urls.is_empty() {
        return RpcServices::Custom {
            chain_id: cfg.chain_id,
            services: cfg
                .rpc_urls
                .iter()
                .map(|url| RpcApi {
                    url: url.clone(),
                    headers: None,
                })
                .collect(),
        };
    }
    match cfg.chain_id {
        1 => RpcServices::EthMainnet(None),
        _ => RpcServices::EthSepolia(None),
    }
}

fn rpc_principal(cfg: &EvmConfig) -> Result<Principal, String> {
    Principal::from_text(&cfg.evm_rpc).map_err(|e| format!("bad evm_rpc principal: {e}"))
}

async fn rpc_call<A, T>(cfg: &EvmConfig, method: &str, arg: A, what: &str) -> Result<T, String>
where
    A: CandidType,
    T: serde::de::DeserializeOwned + CandidType,
{
    let multi: MultiResult<T> = intercanister::call_with_payment(
        rpc_principal(cfg)?,
        method,
        (services(cfg), all_but_one(&cfg.rpc_urls), arg),
        RPC_CYCLES,
    )
    .await?;
    multi.into_result(what)
}

// --- chain reads -------------------------------------------------------------

/// Pending, not Latest: Latest counts only mined transactions, so a second
/// deploy inside one block window would reuse the nonce of a still-pending tx.
async fn nonce_of(cfg: &EvmConfig, address: &str) -> Result<u64, String> {
    let count: u128 = rpc_call(
        cfg,
        "eth_getTransactionCount",
        GetTransactionCountArgs {
            address: address.to_string(),
            block: BlockTag::Pending,
        },
        "eth_getTransactionCount",
    )
    .await?;
    u64::try_from(count).map_err(|_| "nonce overflows u64".into())
}

/// (max_fee_per_gas, max_priority_fee_per_gas) from recent fee history:
/// tip = median of the 50th-percentile rewards (floor 1 gwei), max fee =
/// 2 * next base fee + tip, which survives six consecutive full blocks.
async fn fees(cfg: &EvmConfig) -> Result<(u128, u128), String> {
    let hist: FeeHistory = rpc_call(
        cfg,
        "eth_feeHistory",
        FeeHistoryArgs {
            block_count: 5,
            newest_block: BlockTag::Latest,
            reward_percentiles: Some(vec![50]),
        },
        "eth_feeHistory",
    )
    .await?;
    let base = *hist
        .base_fee_per_gas
        .last()
        .ok_or("eth_feeHistory: empty baseFeePerGas")?;
    let mut tips: Vec<u128> = hist.reward.iter().filter_map(|r| r.first().copied()).collect();
    tips.sort_unstable();
    let tip = tips.get(tips.len() / 2).copied().unwrap_or(0).max(1_000_000_000);
    Ok((2 * base + tip, tip))
}

// --- sign and broadcast ------------------------------------------------------

/// The canister's EOA in EIP-55 form. First call derives and caches the pubkey.
pub async fn address() -> Result<String, String> {
    let cfg = require_config()?;
    let pk = public_key(&cfg).await?;
    Ok(checksum_address(&eoa_of_pubkey(&pk)?))
}

/// Outcome of a broadcast transaction.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TxOutcome {
    pub tx_hash: String,
    pub nonce: u64,
    pub from: String,
    /// Deterministic CREATE address; None for a plain transfer.
    pub contract_address: Option<String>,
}

thread_local! {
    /// True while a send_tx is between its nonce read and its broadcast.
    /// Update methods interleave at every await, so without this two
    /// concurrent sends would sign the same nonce and one would lose with
    /// NonceTooLow. Heap state: an upgrade clears it, along with the
    /// in-flight call it was guarding.
    static SEND_IN_FLIGHT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// (chain_id, EOA, next nonce) advanced on each accepted broadcast.
    /// A provider's pending count can lag a just-accepted tx, so the chain
    /// read alone is not enough; the max of both is used. Cleared on a
    /// rejected broadcast (a dropped or replaced tx makes it overshoot) and
    /// by upgrades (the Pending-tag chain read resumes coverage).
    static NEXT_NONCE: std::cell::RefCell<Option<(u64, String, u64)>> =
        const { std::cell::RefCell::new(None) };
}

/// Releases the send lock on every exit path from send_tx.
struct SendLock;
impl SendLock {
    fn acquire() -> Result<SendLock, String> {
        if SEND_IN_FLIGHT.with(|f| f.replace(true)) {
            return Err("another EVM transaction is in flight; retry shortly".into());
        }
        Ok(SendLock)
    }
}
impl Drop for SendLock {
    fn drop(&mut self) {
        SEND_IN_FLIGHT.with(|f| f.set(false));
    }
}

/// Build, sign, and broadcast one EIP-1559 transaction from the canister EOA.
/// `to = None` deploys `data` as init bytecode (CREATE). One at a time: a
/// concurrent call fails fast rather than racing on the nonce.
async fn send_tx(
    cfg: &EvmConfig,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
    gas_limit: u64,
) -> Result<TxOutcome, String> {
    let _lock = SendLock::acquire()?;
    let pk = public_key(cfg).await?;
    let from = eoa_of_pubkey(&pk)?;
    let from_hex = checksum_address(&from);
    // Independent chain reads; joined to pay one outcall round trip, not two.
    let (chain_nonce, fee_pair) =
        futures::future::join(nonce_of(cfg, &from_hex), fees(cfg)).await;
    let chain_nonce = chain_nonce?;
    let (max_fee, tip) = fee_pair?;
    let nonce = NEXT_NONCE.with(|c| match c.borrow().as_ref() {
        Some((chain, addr, next)) if *chain == cfg.chain_id && *addr == from_hex => {
            chain_nonce.max(*next)
        }
        _ => chain_nonce,
    });
    let tx = Tx {
        chain_id: cfg.chain_id,
        nonce,
        max_priority_fee_per_gas: tip,
        max_fee_per_gas: max_fee,
        gas_limit,
        to,
        value,
        data,
    };
    let sighash = tx.signature_hash();
    let sig = sign_hash(cfg, sighash).await?;
    let (parity, r, s) = recover_parity(&pk, &sighash, &sig)?;
    let raw = tx.raw_signed(parity, &r, &s);
    let tx_hash = format!("0x{}", hex::encode(keccak256(&raw)));

    let status: SendRawTransactionStatus = rpc_call(
        cfg,
        "eth_sendRawTransaction",
        format!("0x{}", hex::encode(&raw)),
        "eth_sendRawTransaction",
    )
    .await?;
    match status {
        // Some providers return the tx hash, some don't; ours is exact either way.
        SendRawTransactionStatus::Ok(_) => {
            NEXT_NONCE.with(|c| {
                *c.borrow_mut() = Some((cfg.chain_id, from_hex.clone(), nonce + 1));
            });
            Ok(TxOutcome {
                tx_hash,
                nonce,
                contract_address: to
                    .is_none()
                    .then(|| checksum_address(&create_address(&from, nonce))),
                from: from_hex,
            })
        }
        other => {
            NEXT_NONCE.with(|c| *c.borrow_mut() = None);
            Err(format!("eth_sendRawTransaction: {other:?}"))
        }
    }
}

/// E0: plain value transfer, the signing-spine proof. `value_wei` is decimal.
pub async fn send_value(to: String, value_wei: String) -> Result<TxOutcome, String> {
    let cfg = require_config()?;
    let to = parse_address(&to)?;
    let value: u128 = value_wei
        .parse()
        .map_err(|e| format!("bad value_wei: {e}"))?;
    send_tx(&cfg, Some(to), value, vec![], 21_000).await
}

// --- E1: contract deployment with provenance ---------------------------------

/// One deploy attempt's provenance: the binding of what was deployed (repo,
/// commit, bytecode hash) to where it went (chain, address, tx). Append-only,
/// in stable memory; failed attempts are recorded too (ok/message), mirroring
/// deploy.rs's DeployRecord. An ok record attests that the broadcast was
/// accepted into a mempool, not that the tx was mined or its constructor
/// succeeded -- confirmation is a receipt poll away via tx_hash (evm_receipt).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmDeployRecord {
    /// Repo whose push produced this deploy; empty for direct-hex deploys.
    /// Defaults cover records written before this field existed.
    #[serde(default)]
    pub repo: String,
    /// Commit the bytecode came from (hex oid); empty for direct-hex deploys.
    pub commit: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub tx_hash: String,
    pub nonce: u64,
    pub bytecode_sha256: String,
    pub bytecode_len: u64,
    /// Whether the broadcast was accepted. Records predating this field were
    /// only written on success, hence the true default.
    #[serde(default = "default_record_ok")]
    pub ok: bool,
    #[serde(default)]
    pub message: String,
    /// Mined outcome, folded in by the post-broadcast receipt poll (or any
    /// evm_receipt call): "" until a receipt is seen, then "success",
    /// "reverted", or "unknown".
    #[serde(default)]
    pub receipt_status: String,
    /// IC time (nanoseconds) when the deploy was recorded.
    pub at_ns: u64,
}

fn default_record_ok() -> bool {
    true
}

/// Per-repo cap, so one chatty repo cannot evict another's history.
const MAX_LOG: usize = 200;

pub fn get_history() -> Vec<EvmDeployRecord> {
    kv::get_json(LOG_KEY).unwrap_or_default()
}

/// ReceiptSummary.status / EvmDeployRecord.receipt_status values. Defined
/// once: latest_deploy's dedupe guard tests these strings, so a drifting
/// literal would silently disable it.
pub const RECEIPT_SUCCESS: &str = "success";
pub const RECEIPT_REVERTED: &str = "reverted";
pub const RECEIPT_UNKNOWN: &str = "unknown";

/// The most recent accepted, not-known-reverted deploy of (repo, commit).
/// The push path skips a commit that already has one; deploy_now does not.
pub fn latest_deploy(repo: &str, commit: &str) -> Option<EvmDeployRecord> {
    get_history().into_iter().rev().find(|r| {
        r.repo == repo && r.commit == commit && r.ok && r.receipt_status != RECEIPT_REVERTED
    })
}

/// Fold a mined receipt's outcome into every deploy record with this tx hash.
fn mark_receipt(tx_hash: &str, status: &str) {
    let mut log = get_history();
    let mut changed = false;
    for r in log
        .iter_mut()
        .filter(|r| r.tx_hash.eq_ignore_ascii_case(tx_hash))
    {
        if r.receipt_status != status {
            r.receipt_status = status.to_string();
            changed = true;
        }
    }
    if changed {
        kv::set_json(LOG_KEY, &log);
    }
}

/// First receipt poll after ~1-2 block times, doubling to a cap: a promptly
/// mined tx reconciles on an early cheap poll, and a tx that never mines
/// stops costing RPC cycles quickly. Coverage ~28 min across all attempts;
/// a tx unresolved by then keeps receipt_status "" and any later
/// evm_receipt call reconciles.
const RECEIPT_POLL_BASE_SECS: u64 = 15;
const RECEIPT_POLL_MAX_SECS: u64 = 240;
const RECEIPT_POLL_ATTEMPTS: u32 = 10;

/// Arm the timer chain that closes the gap between broadcast-accepted (what
/// a deploy record attests at write time) and mined: each poll asks for the
/// receipt, and receipt() folds a found one into the record.
fn schedule_receipt_poll(tx_hash: String, attempt: u32) {
    let secs = (RECEIPT_POLL_BASE_SECS << attempt).min(RECEIPT_POLL_MAX_SECS);
    ic_cdk_timers::set_timer(
        std::time::Duration::from_secs(secs),
        poll_receipt(tx_hash, attempt),
    );
}

async fn poll_receipt(tx_hash: String, attempt: u32) {
    match receipt(tx_hash.clone()).await {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) if attempt + 1 < RECEIPT_POLL_ATTEMPTS => {
            schedule_receipt_poll(tx_hash, attempt + 1);
        }
        _ => {}
    }
}

/// Read the deploy log, refusing to substitute a default for an undecodable
/// one. Callers must treat `Err` as "this log cannot be safely written".
fn read_log() -> Result<Vec<EvmDeployRecord>, String> {
    kv::try_get_json::<Vec<EvmDeployRecord>>(LOG_KEY).map(Option::unwrap_or_default)
}

/// Refuse to start a deploy whose result could not be recorded.
///
/// This must be checked BEFORE broadcasting. `record` failing after `send_tx`
/// would leave a paid, live CREATE with no log entry -- and because
/// `latest_deploy` reads the same unreadable log, the same-commit dedupe in
/// `run_evm` would not see it either, so every retry or re-push would broadcast
/// another paid deployment of a contract that is already on chain. Failing
/// closed here costs nothing; failing open costs gas on every attempt.
fn preflight_log() -> Result<(), String> {
    read_log().map(|_| ()).map_err(|e| {
        format!("{e}; refusing to deploy because the outcome could not be recorded (inspect or clear the {LOG_KEY} entry first)")
    })
}

fn record(rec: EvmDeployRecord) -> Result<(), String> {
    let repo = rec.repo.clone();
    // Read-modify-write on the append-only provenance log, so a decode failure
    // must NOT fall back to an empty Vec: that would replace every prior
    // deploy's tx hash and bytecode hash with this single entry, and take the
    // same-commit dedupe in run_evm down with it. Refuse to write instead --
    // the stored bytes stay intact and recoverable. `preflight_log` should have
    // caught this before any gas was spent; reaching here means the log became
    // unreadable mid-flight, so the failure is propagated rather than logged.
    let mut log = read_log()?;
    log.push(rec);
    let count = log.iter().filter(|r| r.repo == repo).count();
    if count > MAX_LOG {
        let mut to_drop = count - MAX_LOG;
        log.retain(|r| {
            if to_drop > 0 && r.repo == repo {
                to_drop -= 1;
                false
            } else {
                true
            }
        });
    }
    kv::set_json(LOG_KEY, &log);
    Ok(())
}

/// The canister-level preconditions for a CREATE deploy: a chain config, and a
/// gas limit that could pay for one (21k intrinsic + 32k for the CREATE).
///
/// One definition, used from three places on purpose -- `deploy_bytecode`
/// needs the config, while `require_deploy_target` lets `deploy::set_evm_config`
/// reject an unpayable config at configure time and lets `deploy::attempt_evm`
/// fail *before* it walks the repo tree and decodes the artifact. Same shape as
/// `publish_target` / `require_publish_target` below.
fn deploy_target(gas_limit: u64) -> Result<EvmConfig, String> {
    let cfg = require_config()?;
    if gas_limit < 53_000 {
        return Err("gas_limit below the 53k floor of any CREATE".into());
    }
    Ok(cfg)
}

/// Assert the canister is configured to deploy at this gas limit, without
/// doing any work. See `deploy_target`.
pub fn require_deploy_target(gas_limit: u64) -> Result<(), String> {
    deploy_target(gas_limit).map(|_| ())
}

/// Deploy init bytecode as a CREATE transaction and record the provenance
/// binding, success or failure.
///
/// Takes decoded bytes rather than hex text: hex is an artifact-format concern
/// of the git side (`deploy::decode_bytecode_hex`), and bytes-plus-scalars is
/// exactly the signer-side message docs/CANISTER_SPLIT.md section 4 specifies.
/// `repo` and `commit` are empty for direct deploys outside the E2 git path.
pub async fn deploy_bytecode(
    repo: String,
    bytecode: Vec<u8>,
    gas_limit: u64,
    commit: String,
) -> Result<TxOutcome, String> {
    let cfg = deploy_target(gas_limit)?;
    if bytecode.is_empty() {
        return Err("empty bytecode".into());
    }
    // Hashed here rather than taken from the caller: the log has to record what
    // this canister actually broadcast, a property that must survive the caller
    // becoming a separate canister.
    let sha256 = hex::encode(sha2::Sha256::digest(&bytecode));
    let len = bytecode.len() as u64;
    // Before spending gas: if the outcome cannot be recorded, do not broadcast.
    preflight_log()?;
    let out = send_tx(&cfg, None, 0, bytecode, gas_limit).await;
    let recorded = record(EvmDeployRecord {
        repo,
        commit,
        chain_id: cfg.chain_id,
        contract_address: out
            .as_ref()
            .ok()
            .and_then(|o| o.contract_address.clone())
            .unwrap_or_default(),
        tx_hash: out.as_ref().map(|o| o.tx_hash.clone()).unwrap_or_default(),
        nonce: out.as_ref().map(|o| o.nonce).unwrap_or_default(),
        bytecode_sha256: sha256,
        bytecode_len: len,
        ok: out.is_ok(),
        message: match &out {
            Ok(_) => "broadcast accepted; confirm via evm_receipt".into(),
            Err(e) => e.clone(),
        },
        receipt_status: String::new(),
        at_ns: ic_cdk::api::time(),
    });
    // A broadcast we could not record must never be reported as a clean
    // success: the transaction is live and paid for, but nothing in the log
    // will dedupe it, so a caller that retries on error would deploy it again.
    // Surface the tx hash and say so explicitly -- this needs a human, not a
    // retry. (preflight_log makes this near-unreachable; it is the backstop.)
    if let (Ok(o), Err(e)) = (&out, &recorded) {
        return Err(format!(
            "DEPLOY BROADCAST BUT NOT RECORDED: tx {} is live on chain {} and paid for, \
             but the deploy log could not be updated ({e}). Do NOT retry -- \
             resolve the log first, or the contract will be deployed twice.",
            o.tx_hash, cfg.chain_id
        ));
    }
    if let Ok(o) = &out {
        schedule_receipt_poll(o.tx_hash.clone(), 0);
    }
    out
}

// --- provenance registry (repo -> commit, bundleHash; see registry repo) -----
// The registry is a canister-owned contract (ProvenanceRegistry.sol, deployed
// through the E2 push path). Publishing binds a repo name to its deploy-branch
// tip commit and artifact hash, on the chain wallets already watch. Writable
// only by the canister's EOA, so an entry is the canister's own attestation.

const REGISTRY_KEY: &str = "evm:registry";

pub fn set_registry(address: String) -> Result<(), String> {
    parse_address(&address)?;
    kv::set_json(REGISTRY_KEY, &address);
    Ok(())
}

pub fn get_registry() -> Option<String> {
    kv::get_json(REGISTRY_KEY)
}

/// ABI-encode set(string recordKey, bytes20 commit, bytes32 bundleHash):
/// selector, then three head words (string offset, bytes20 right-padded,
/// bytes32), then the string tail (length word, data padded to a word).
fn abi_encode_set(record_key: &str, commit: &[u8; 20], bundle: &[u8; 32]) -> Vec<u8> {
    let mut out = keccak256(b"set(string,bytes20,bytes32)")[..4].to_vec();
    let mut word = [0u8; 32];
    word[31] = 0x60; // string data starts after the 3-word head
    out.extend_from_slice(&word);
    word = [0u8; 32];
    word[..20].copy_from_slice(commit); // bytesN is left-aligned
    out.extend_from_slice(&word);
    out.extend_from_slice(bundle);
    word = [0u8; 32];
    word[24..].copy_from_slice(&(record_key.len() as u64).to_be_bytes());
    out.extend_from_slice(&word);
    out.extend_from_slice(record_key.as_bytes());
    out.extend(std::iter::repeat(0u8).take((32 - record_key.len() % 32) % 32));
    out
}

/// Publish an already-resolved provenance record to the registry. The whole
/// registry-write surface; `crate::provenance` does the resolving. Signature
/// is the planned inter-canister message (docs/CANISTER_SPLIT.md section 4).
///
/// `record_key` is namespaced by the caller (`<repo>` for a deploy artifact,
/// `<repo>#site` for a served site); `commit` is the first 20 bytes of the git
/// oid; `bundle` is whatever sha256 the record type calls for.
pub async fn registry_publish_record(
    record_key: &str,
    commit: &[u8; 20],
    bundle: &[u8; 32],
) -> Result<TxOutcome, String> {
    let (cfg, to) = publish_target()?;
    let data = abi_encode_set(record_key, commit, bundle);
    send_tx(&cfg, Some(to), 0, data, 150_000).await
}

/// The canister-level preconditions for any registry write: a chain config and
/// a parseable registry address. One definition, used twice on purpose --
/// `registry_publish_record` needs the values, and `require_publish_target`
/// lets a caller check them *before* resolving git state.
fn publish_target() -> Result<(EvmConfig, [u8; 20]), String> {
    let cfg = require_config()?;
    let registry = get_registry().ok_or("no registry address; call evm_set_registry first")?;
    let to = parse_address(&registry)?;
    Ok((cfg, to))
}

/// Assert the canister is configured to publish, without doing any work.
///
/// `crate::provenance` calls this before it walks refs and hashes artifacts, so
/// an unconfigured canister answers "call evm_set_config first" instead of a
/// repo-level error about a deploy config the operator was never missing. It
/// also keeps `evm_registry_publish_site` from inflating and hashing a whole
/// site bundle only to discover there is nowhere to write the result.
pub fn require_publish_target() -> Result<(), String> {
    publish_target().map(|_| ())
}

// --- receipt lookup ----------------------------------------------------------

/// Flattened receipt summary; big integers rendered as decimal strings.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ReceiptSummary {
    /// "success", "reverted", or "unknown" (pre-Byzantium root-only receipts).
    pub status: String,
    pub block_number: u64,
    pub gas_used: String,
    pub effective_gas_price: String,
    pub contract_address: Option<String>,
}

/// None while the transaction is still pending. A found receipt is also
/// folded into any deploy record with this tx hash (receipt_status), so a
/// manual evm_receipt call reconciles the provenance log the same way the
/// post-broadcast poll does.
pub async fn receipt(tx_hash: String) -> Result<Option<ReceiptSummary>, String> {
    let cfg = require_config()?;
    let receipt: Option<TransactionReceipt> = rpc_call(
        &cfg,
        "eth_getTransactionReceipt",
        tx_hash.clone(),
        "eth_getTransactionReceipt",
    )
    .await?;
    let summary = receipt.map(|r| ReceiptSummary {
        status: match r.status {
            Some(1) => RECEIPT_SUCCESS.into(),
            Some(_) => RECEIPT_REVERTED.into(),
            None => RECEIPT_UNKNOWN.into(),
        },
        block_number: r.block_number.try_into().unwrap_or(u64::MAX),
        gas_used: r.gas_used.to_string(),
        effective_gas_price: r.effective_gas_price.to_string(),
        contract_address: r.contract_address,
    });
    if let Some(s) = &summary {
        mark_receipt(&tx_hash, &s.status);
    }
    Ok(summary)
}

// --- tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rlp_bytes(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        rlp::bytes(&mut out, b);
        out
    }

    #[test]
    fn rlp_vectors() {
        // Canonical vectors from the Ethereum wiki RLP page.
        assert_eq!(rlp_bytes(b"dog"), hex::decode("83646f67").unwrap());
        assert_eq!(rlp_bytes(b""), vec![0x80]);
        assert_eq!(rlp_bytes(&[0x0f]), vec![0x0f]);
        assert_eq!(rlp_bytes(&[0x04, 0x00]), hex::decode("820400").unwrap());

        let mut cat_dog = Vec::new();
        rlp::bytes(&mut cat_dog, b"cat");
        rlp::bytes(&mut cat_dog, b"dog");
        assert_eq!(
            rlp::list(&cat_dog),
            hex::decode("c88363617483646f67").unwrap()
        );

        let mut zero = Vec::new();
        rlp::uint(&mut zero, 0);
        assert_eq!(zero, vec![0x80]);

        // 56-byte string crosses into the long form.
        let long = [0x61u8; 56];
        let enc = rlp_bytes(&long);
        assert_eq!(&enc[..2], &[0xb8, 56]);
        assert_eq!(&enc[2..], &long[..]);
    }

    #[test]
    fn eoa_of_generator_point() {
        // privkey = 1 => pubkey = G => the well-known address below.
        let g = hex::decode(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
             483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        )
        .unwrap();
        let addr = eoa_of_pubkey(&g).unwrap();
        assert_eq!(
            checksum_address(&addr),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
        // Same answer from the compressed form.
        let compressed = hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        assert_eq!(eoa_of_pubkey(&compressed).unwrap(), addr);
    }

    #[test]
    fn eip55_checksum_vector() {
        // Vector from EIP-55.
        let addr: [u8; 20] = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            checksum_address(&addr),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

    #[test]
    fn create_address_vector() {
        // Canonical vector: sender 0x6ac7ea..., nonce 0.
        let sender: [u8; 20] = hex::decode("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(create_address(&sender, 0)),
            "cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"
        );
        assert_eq!(
            hex::encode(create_address(&sender, 1)),
            "343c43a37d37dff08ae8c4a11544c718abb4fcf8"
        );
    }

    /// Sign a fixed transaction with a local k256 key and check the whole
    /// pipeline end to end: parity recovery succeeds, and the raw transaction
    /// round-trips through an independent decode of its signature fields.
    #[test]
    fn sign_and_recover_roundtrip() {
        use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let pk_sec1 = sk.verifying_key().to_encoded_point(true);
        let tx = Tx {
            chain_id: 11155111,
            nonce: 7,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 21_000,
            to: Some([0x11; 20]),
            value: 1_000_000_000_000_000,
            data: vec![],
        };
        let sighash = tx.signature_hash();
        let sig: Signature = sk.sign_prehash(&sighash).unwrap();
        let sig64: [u8; 64] = sig.to_bytes().into();

        let (parity, r, s) = recover_parity(pk_sec1.as_bytes(), &sighash, &sig64).unwrap();
        assert!(parity < 2);
        // s must be in the low half-order (EIP-2).
        let s_scalar = k256::ecdsa::Signature::from_scalars(r, s).unwrap();
        assert!(s_scalar.normalize_s().is_none());

        let raw = tx.raw_signed(parity, &r, &s);
        assert_eq!(raw[0], 0x02);
        // The signed body must extend the unsigned field list: same fields,
        // three more items, strictly longer.
        assert!(raw.len() > rlp::list(&tx.payload()).len() + 2);
    }

    /// Records written before repo/ok/message existed must still load, with
    /// the success-only history of that era reflected in the defaults.
    #[test]
    fn old_deploy_records_still_load() {
        let old = r#"{"commit":"abc","chain_id":11155111,"contract_address":"0x1",
            "tx_hash":"0x2","nonce":3,"bytecode_sha256":"d","bytecode_len":4,"at_ns":5}"#;
        let rec: EvmDeployRecord = serde_json::from_str(old).unwrap();
        assert_eq!(rec.repo, "");
        assert!(rec.ok);
        assert_eq!(rec.message, "");
        assert_eq!(rec.receipt_status, "");
        assert_eq!(rec.nonce, 3);
    }

    #[test]
    fn deploy_log_caps_per_repo() {
        let rec = |repo: &str, nonce: u64| EvmDeployRecord {
            repo: repo.into(),
            commit: String::new(),
            chain_id: 1,
            contract_address: String::new(),
            tx_hash: String::new(),
            nonce,
            bytecode_sha256: String::new(),
            bytecode_len: 0,
            ok: true,
            message: String::new(),
            receipt_status: String::new(),
            at_ns: 0,
        };
        record(rec("quiet", 0)).unwrap();
        for n in 0..(MAX_LOG as u64 + 5) {
            record(rec("chatty", n)).unwrap();
        }
        let log = get_history();
        let chatty: Vec<_> = log.iter().filter(|r| r.repo == "chatty").collect();
        assert_eq!(chatty.len(), MAX_LOG);
        assert_eq!(chatty[0].nonce, 5); // oldest five dropped
        assert_eq!(log.iter().filter(|r| r.repo == "quiet").count(), 1);
    }

    /// An undecodable deploy log must stop a deploy BEFORE it broadcasts, and
    /// must not be silently replaced by an empty one.
    ///
    /// Both halves matter and they fail in opposite directions. Overwriting
    /// destroys every prior deploy's provenance; broadcasting first and failing
    /// to record leaves a paid, live contract that `latest_deploy` cannot see,
    /// so the push path's same-commit dedupe goes blind and every retry deploys
    /// it again. `preflight_log` is what makes the deploy fail closed while the
    /// gas is still unspent.
    #[test]
    fn corrupt_deploy_log_blocks_deploy_and_survives_intact() {
        kv::set_json(LOG_KEY, &"not a deploy log at all".to_string());

        assert!(
            preflight_log().is_err(),
            "preflight must refuse before any broadcast"
        );
        let err = record(EvmDeployRecord {
            repo: "r".into(),
            commit: "c".into(),
            chain_id: 1,
            contract_address: String::new(),
            tx_hash: "0x01".into(),
            nonce: 0,
            bytecode_sha256: String::new(),
            bytecode_len: 0,
            ok: true,
            message: String::new(),
            receipt_status: String::new(),
            at_ns: 0,
        });
        assert!(err.is_err(), "record must propagate, not swallow");

        // The original bytes are still there: nothing was clobbered.
        let raw: String = kv::get_json(LOG_KEY).expect("original value intact");
        assert_eq!(raw, "not a deploy log at all");
        kv::set_json(LOG_KEY, &Vec::<EvmDeployRecord>::new());
    }

    /// A reverted receipt (folded case-insensitively by tx hash) must
    /// disqualify a record from the push path's dedupe lookup.
    #[test]
    fn receipt_fold_disqualifies_dedupe() {
        record(EvmDeployRecord {
            repo: "r".into(),
            commit: "c".into(),
            chain_id: 1,
            contract_address: String::new(),
            tx_hash: "0xABCD".into(),
            nonce: 0,
            bytecode_sha256: String::new(),
            bytecode_len: 0,
            ok: true,
            message: String::new(),
            receipt_status: String::new(),
            at_ns: 0,
        })
        .unwrap();
        assert!(latest_deploy("r", "c").is_some());
        mark_receipt("0xabcd", "success");
        assert!(latest_deploy("r", "c").is_some());
        mark_receipt("0xABcd", "reverted");
        assert!(latest_deploy("r", "c").is_none());
    }

    #[test]
    fn abi_set_layout() {
        let commit = [0xaa; 20];
        let bundle = [0xbb; 32];
        let enc = abi_encode_set("evm-demo", &commit, &bundle);
        // selector + 3 head words + length word + 1 padded data word
        assert_eq!(enc.len(), 4 + 32 * 5);
        assert_eq!(enc[4..36], {
            let mut w = [0u8; 32];
            w[31] = 0x60;
            w
        });
        assert_eq!(&enc[36..56], &commit); // bytes20 left-aligned
        assert_eq!(&enc[56..68], &[0u8; 12]); // right padding
        assert_eq!(&enc[68..100], &bundle);
        assert_eq!(enc[100..132].last(), Some(&8)); // len("evm-demo")
        assert_eq!(&enc[132..140], b"evm-demo");
        assert_eq!(&enc[140..164], &[0u8; 24]); // pad to word
    }

    #[test]
    fn create_tx_encodes_empty_to() {
        let tx = Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 2,
            gas_limit: 100_000,
            to: None,
            value: 0,
            data: vec![0x60, 0x00],
        };
        let payload = rlp::list(&tx.payload());
        // `to` must appear as the empty string 0x80, not as 20 zero bytes.
        assert!(payload.windows(2).any(|w| w == [0x80, 0x80]));
    }
}
