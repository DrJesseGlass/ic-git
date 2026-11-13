//! The git side's consent messages (ic_git_common::consent): the push-token
//! calls, which are the git canister's. A method absent here is not the
//! git side's; the canister asks its other side, if it has one, and
//! refuses otherwise.

use ic_git_common::consent::{args, prefix, unavailable, Icrc21Error};

/// The text for `method` called with the candid-encoded `arg`, or `None`
/// for a method that is not the git side's.
pub fn describe(method: &str, arg: &[u8]) -> Option<Result<String, Icrc21Error>> {
    let m = method;
    Some(match method {
        "create_push_token" => (|| {
            // `days` and `key` are trailing opts: an argument without them
            // decodes as None.
            let (repo, days, key): (String, Option<u32>, Option<String>) = args(arg, m)?;
            let refuse = |e: String| unavailable(m, e);
            // Describe only a lifetime and a key the call would accept.
            let days = crate::tokens::lifetime(days).map_err(refuse)?;
            let key = key
                .map(|k| crate::signed_push::parse_public_key(&k))
                .transpose()
                .map_err(refuse)?;
            let lasts = format!(
                "for {days} day{} from now, or until it is revoked if that is sooner",
                if days == 1 { "" } else { "s" }
            );
            Ok(match key {
                None => format!(
                    "Mint a push token for \"{repo}\". Anyone holding the token can push to the \
                     repository {lasts}."
                ),
                Some(k) => format!(
                    "Mint a push token for \"{repo}\" bound to the SSH key {}. A push with it must \
                     also be signed by that key; it works {lasts}.",
                    crate::signed_push::fingerprint(&k)
                ),
            })
        })(),
        "revoke_push_token" => args::<(String,)>(arg, m)
            .map(|(token,)| format!("Revoke the push token beginning {}. Pushes with it will be refused.", prefix(&token, 8))),
        "revoke_push_token_id" => (|| {
            let (id,): (String,) = args(arg, m)?;
            // Describe only an id the call would accept, not arbitrary text.
            crate::tokens::check_id(&id).map_err(|e| unavailable(m, e))?;
            Ok(format!("Revoke the push token with id {id}. Pushes with it will be refused."))
        })(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::encode_args;

    #[test]
    fn every_token_method_has_a_message_with_its_arguments_in_it() {
        let cases: Vec<(&str, Vec<u8>, &[&str])> = vec![
            ("create_push_token", encode_args(("ic-vote",)).unwrap(), &["push token", "for 30 days", "revoked"]),
            ("create_push_token", encode_args(("ic-vote", Some(1u32))).unwrap(), &["for 1 day from now"]),
            ("create_push_token", encode_args(("ic-vote", Some(90u32))).unwrap(), &["for 90 days"]),
            (
                "create_push_token",
                encode_args(("ic-vote", None::<u32>, Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKX+WM3RHsIaqzeD1rg3zUF4Y9Py92QmWG7n+3f2051F me@laptop"))).unwrap(),
                &["bound to the SSH key SHA256:AJwEzIG2jf+W4YxJdLVmVNYmuyYEjyZpuDAtIkdMTw8", "signed by that key", "30 days"],
            ),
            ("revoke_push_token_id", encode_args(("0123456789abcdef",)).unwrap(), &["id 0123456789abcdef", "refused"]),
            ("revoke_push_token", encode_args(("0123456789abcdef0123456789abcdef",)).unwrap(), &["01234567...", "refused"]),
        ];
        for (method, arg, expect) in cases {
            let text = describe(method, &arg).expect("a token method").unwrap_or_else(|e| panic!("{method}: {e:?}"));
            for needle in expect {
                assert!(text.contains(needle), "{method}: expected {needle:?} in {text:?}");
            }
        }
        assert!(describe("create_repo", &encode_args(("r",)).unwrap()).is_none(), "the authority's");
        // A token the call would refuse is not described.
        assert!(describe("create_push_token", &encode_args(("ic-vote", Some(400u32))).unwrap()).unwrap().is_err());
        assert!(describe("revoke_push_token_id", &encode_args(("not hex",)).unwrap()).unwrap().is_err());
    }
}
