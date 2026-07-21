//! Wire shapes and policy shared by the chain-RPC canister mirrors (evm.rs,
//! sol.rs). Only the layer that is genuinely common lives here: the IC
//! HTTPS-outcall error surface and the consensus configuration that the EVM
//! RPC and SOL RPC canisters expose verbatim, plus the threshold-signature
//! fee. The per-canister candid (provider enums, error trees, method params)
//! stays hand-mirrored in each module: those interfaces drift independently,
//! and sharing them would couple mirrors of canisters we don't control.

use candid::CandidType;
use serde::Deserialize;

/// Cycles attached to each threshold-signature call (sign_with_ecdsa and
/// sign_with_schnorr both cost ~26.15B on the fiduciary subnet); surplus
/// refunded.
pub const SIGN_CYCLES: u128 = 30_000_000_000;

/// Provider count both RPC canisters contact per chain/cluster when no custom
/// URLs are configured. An upstream change to the default provider sets would
/// mis-tune the all-but-one threshold, so it is named rather than a literal.
const DEFAULT_PROVIDERS: usize = 3;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct HttpHeader {
    pub value: String,
    pub name: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum RejectionCode {
    NoError,
    SysFatal,
    SysTransient,
    DestinationInvalid,
    CanisterReject,
    CanisterError,
    Unknown,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum HttpOutcallError {
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

#[derive(CandidType, Deserialize, Debug)]
pub enum ConsensusStrategy {
    Equality,
    Threshold { min: u8, total: Option<u8> },
}

#[derive(CandidType, Deserialize, Debug)]
pub struct RpcConfig {
    #[serde(rename = "responseSizeEstimate")]
    pub response_size_estimate: Option<u64>,
    #[serde(rename = "responseConsensus")]
    pub response_consensus: Option<ConsensusStrategy>,
}

/// Consensus strategy for RPC reads: with several providers, accept agreement
/// of all but one, so a single flaky provider (a failed outcall, a lagging
/// node) cannot fail the whole call the way the default all-must-agree
/// Equality strategy does. A single custom URL gets no strategy (nothing to
/// vote).
pub fn all_but_one(rpc_urls: &[String]) -> Option<RpcConfig> {
    let n = if rpc_urls.is_empty() {
        DEFAULT_PROVIDERS
    } else {
        rpc_urls.len()
    };
    if n < 2 {
        return None;
    }
    Some(RpcConfig {
        response_size_estimate: None,
        response_consensus: Some(ConsensusStrategy::Threshold {
            min: (n - 1) as u8,
            total: Some(n as u8),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_but_one_thresholds() {
        // Default provider set votes 2-of-3.
        match all_but_one(&[]) {
            Some(RpcConfig {
                response_consensus:
                    Some(ConsensusStrategy::Threshold {
                        min: 2,
                        total: Some(3),
                    }),
                ..
            }) => {}
            other => panic!("unexpected: {other:?}"),
        }
        // A single custom URL has nothing to vote.
        assert!(all_but_one(&["http://localhost:8545".into()]).is_none());
        // Two URLs vote 1-of-2.
        let urls = vec!["a".to_string(), "b".to_string()];
        match all_but_one(&urls) {
            Some(RpcConfig {
                response_consensus:
                    Some(ConsensusStrategy::Threshold {
                        min: 1,
                        total: Some(2),
                    }),
                ..
            }) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }
}
