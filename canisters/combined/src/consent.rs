//! ICRC-21 consent messages and the ICRC-10 standards list, for the
//! combined canister: both sides' descriptions (ic_git_authority::consent,
//! ic_git_git::consent), the authority's asked first.

pub use ic_git_common::consent::{ConsentMessageRequest, ConsentMessageResponse, Standard};

pub fn supported_standards() -> Vec<Standard> {
    ic_git_common::consent::supported_standards()
}

/// The consent text for `method` called with the candid-encoded `arg`.
pub fn consent_message(req: ConsentMessageRequest) -> ConsentMessageResponse {
    ic_git_common::consent::consent_message(req, &[ic_git_authority::consent::describe, ic_git_git::consent::describe])
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::encode_args;
    use ic_git_common::consent::{ConsentMessage, ConsentMessageMetadata, ConsentMessageSpec, DeviceSpec, ErrorInfo, Icrc21Error};

    fn generic(method: &str, arg: Vec<u8>) -> Result<String, Icrc21Error> {
        let req = ConsentMessageRequest {
            method: method.to_string(),
            arg,
            user_preferences: ConsentMessageSpec {
                metadata: ConsentMessageMetadata { language: "en".into(), utc_offset_minutes: Some(-240) },
                device_spec: Some(DeviceSpec::GenericDisplay),
            },
        };
        consent_message(req).map(|info| match info.consent_message {
            ConsentMessage::GenericDisplayMessage(t) => t,
            other => panic!("expected a generic message, got {other:?}"),
        })
    }

    /// Both sides' methods are described here, and one neither has is
    /// refused: blind signing is the failure mode this exists to prevent.
    #[test]
    fn both_sides_methods_are_described_and_the_rest_refused() {
        assert!(generic("create_repo", encode_args(("ic-vote",)).unwrap()).unwrap().contains("\"ic-vote\""));
        assert!(generic("create_push_token", encode_args(("ic-vote",)).unwrap()).unwrap().contains("push token"));
        let err = generic("charge_rent_now", encode_args(()).unwrap()).unwrap_err();
        assert!(matches!(err, Icrc21Error::UnsupportedCanisterCall(ErrorInfo { ref description }) if description.contains("charge_rent_now")));
    }
}
