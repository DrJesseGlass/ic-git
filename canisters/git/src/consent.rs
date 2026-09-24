//! ICRC-21 consent messages and the ICRC-10 standards list.
//!
//! A wallet that signs on a user's behalf (OISY, through ICRC-49) asks the
//! target canister, before signing, for a sentence a person can read: what
//! this call does, with the actual arguments decoded. Without it the wallet
//! refuses to sign at all, which is the right default -- a signature over
//! bytes the signer cannot read is blind signing -- and it is why no console
//! write reached this canister before this module existed.
//!
//! The list here is closed. A method with no entry gets
//! `UnsupportedCanisterCall`, so the wallet refuses it rather than showing a
//! vague message; adding a method to the console means adding it here.
//! The text describes what the call does to the caller's balance and repos,
//! since that is what the person is consenting to.

use candid::{CandidType, Deserialize, Nat, Principal};

// --- ICRC-10 -----------------------------------------------------------------

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Standard {
    pub name: String,
    pub url: String,
}

pub fn supported_standards() -> Vec<Standard> {
    let icrc = |n: &str| Standard {
        name: format!("ICRC-{n}"),
        url: format!("https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-{n}/ICRC-{n}.md"),
    };
    vec![icrc("10"), icrc("21")]
}

// --- ICRC-21 types, field names as the standard spells them ------------------

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConsentMessageMetadata {
    pub language: String,
    pub utc_offset_minutes: Option<i16>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum DeviceSpec {
    GenericDisplay,
    LineDisplay {
        characters_per_line: u16,
        lines_per_page: u16,
    },
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConsentMessageSpec {
    pub metadata: ConsentMessageMetadata,
    pub device_spec: Option<DeviceSpec>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConsentMessageRequest {
    pub method: String,
    pub arg: Vec<u8>,
    pub user_preferences: ConsentMessageSpec,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub lines: Vec<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ConsentMessage {
    GenericDisplayMessage(String),
    LineDisplayMessage { pages: Vec<Page> },
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConsentInfo {
    pub consent_message: ConsentMessage,
    pub metadata: ConsentMessageMetadata,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorInfo {
    pub description: String,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Icrc21Error {
    UnsupportedCanisterCall(ErrorInfo),
    ConsentMessageUnavailable(ErrorInfo),
    InsufficientPayment(ErrorInfo),
    GenericError { error_code: Nat, description: String },
}

pub type ConsentMessageResponse = Result<ConsentInfo, Icrc21Error>;

// --- the messages ------------------------------------------------------------

/// The consent text for `method` called with the candid-encoded `arg`.
pub fn consent_message(req: ConsentMessageRequest) -> ConsentMessageResponse {
    let text = describe(&req.method, &req.arg)?;
    let consent_message = match req.user_preferences.device_spec {
        Some(DeviceSpec::LineDisplay { characters_per_line, lines_per_page }) => {
            ConsentMessage::LineDisplayMessage {
                pages: paginate(&text, characters_per_line as usize, lines_per_page as usize),
            }
        }
        _ => ConsentMessage::GenericDisplayMessage(text),
    };
    Ok(ConsentInfo {
        consent_message,
        metadata: ConsentMessageMetadata {
            // The only language these messages come in. A wallet that asked
            // for another still gets English, and is told so here.
            language: "en".to_string(),
            utc_offset_minutes: req.user_preferences.metadata.utc_offset_minutes,
        },
    })
}

fn describe(method: &str, arg: &[u8]) -> Result<String, Icrc21Error> {
    fn args<'a, T: candid::utils::ArgumentDecoder<'a>>(arg: &'a [u8], method: &str) -> Result<T, Icrc21Error> {
        candid::decode_args::<T>(arg).map_err(|e| {
            Icrc21Error::ConsentMessageUnavailable(ErrorInfo {
                description: format!("the arguments to {method} could not be decoded: {e}"),
            })
        })
    }
    let m = method;
    Ok(match method {
        "deposit" => "Deposit the cycles attached to this call into your ic-git balance.".to_string(),
        "deposit_from_cycles_ledger" => {
            let (amount,): (u64,) = args(arg, m)?;
            format!(
                "Deposit {} into your ic-git balance, taken from the allowance you approved \
                 on the cycles ledger. The ledger's fee comes out of this amount.",
                cycles(amount)
            )
        }
        "create_repo" => {
            let (repo,): (String,) = args(arg, m)?;
            format!(
                "Create the repository \"{repo}\" on ic-git. You become its owner, and the \
                 creation fee is charged to your ic-git balance."
            )
        }
        "create_app_canister" => {
            let (repo, amount): (String, u64) = args(arg, m)?;
            format!(
                "Create an app canister for \"{repo}\" with {} from your ic-git balance. \
                 You and ic-git will both control it; ic-git installs what the repository \
                 deploys into it.",
                cycles(amount)
            )
        }
        "top_up_app_canister" => {
            let (repo, amount): (String, u64) = args(arg, m)?;
            format!("Send {} from your ic-git balance to the app canister of \"{repo}\".", cycles(amount))
        }
        "create_push_token" => {
            let (repo,): (String,) = args(arg, m)?;
            format!(
                "Mint a push token for \"{repo}\". Anyone holding the token can push to the \
                 repository until it is revoked."
            )
        }
        "revoke_push_token" => {
            let (token,): (String,) = args(arg, m)?;
            format!("Revoke the push token beginning {}. Pushes with it will be refused.", prefix(&token, 8))
        }
        "add_member" => {
            let (repo, who, role): (String, Principal, String) = args(arg, m)?;
            let power = match role.as_str() {
                "writer" => "push, mint push tokens, and configure what the repository deploys and serves",
                "voter" => "approve or reject commits before the repository deploys them",
                _ => "hold that role",
            };
            format!("Add {who} to \"{repo}\" as a {role}: they will be able to {power}.")
        }
        "remove_member" => {
            let (repo, who): (String, Principal) = args(arg, m)?;
            format!("Remove {who} from \"{repo}\". They lose every role they held there.")
        }
        "set_required_votes" => {
            let (repo, k): (String, u32) = args(arg, m)?;
            if k == 0 {
                format!("Let pushes to \"{repo}\" deploy without any approvals.")
            } else {
                format!(
                    "Require {k} approval{} from the voters of \"{repo}\" before a pushed \
                     commit is deployed or served as its site. A site served today goes \
                     down until a commit is approved.",
                    if k == 1 { "" } else { "s" }
                )
            }
        }
        "vote" => {
            let (repo, commit, approve): (String, String, bool) = args(arg, m)?;
            format!(
                "{} commit {} in \"{repo}\" for deployment and for serving as its site.",
                if approve { "Approve" } else { "Reject" },
                prefix(&commit, 12)
            )
        }
        "set_wasm_deploy" => {
            let (repo, target, path): (String, String, String) = args(arg, m)?;
            let into = if target == "app" {
                "its app canister".to_string()
            } else {
                format!("canister {target}")
            };
            format!("On every push to \"{repo}\", build or install {path} from the pushed commit into {into}.")
        }
        "set_deploy_mode" => {
            let (repo, mode): (String, String) = args(arg, m)?;
            match mode.as_str() {
                "reinstall" => format!(
                    "Set deploys of \"{repo}\" to REINSTALL. Every deploy will WIPE ALL STATE in \
                     the target canister before installing. This stays in force until set back \
                     to upgrade."
                ),
                "upgrade" => format!(
                    "Set deploys of \"{repo}\" to upgrade: the target canister keeps its state \
                     across deploys."
                ),
                other => format!("Set the deploy mode of \"{repo}\" to \"{other}\"."),
            }
        }
        "deploy_now" => {
            let (repo,): (String,) = args(arg, m)?;
            format!(
                "Deploy the current tip of \"{repo}\" now, without a push. Every deploy leg the \
                 repository has configured runs: a wasm leg installs in the configured install \
                 mode, and an EVM leg broadcasts a NEW contract creation transaction on the \
                 configured chain even if this commit was already deployed there. The fee for \
                 each leg is charged to your ic-git balance."
            )
        }
        "set_site" => {
            let (repo, root): (String, String) = args(arg, m)?;
            let from = if root.is_empty() {
                "the repository root".to_string()
            } else {
                format!("its directory {root}/")
            };
            format!(
                "Serve \"{repo}\" as a website at /site/{repo}/, from {from} in the newest \
                 commit on its deploy branch that has the approvals the repo requires (the \
                 tip, when none are required)."
            )
        }
        "evm_registry_publish_site" => {
            let (repo,): (String,) = args(arg, m)?;
            format!(
                "Publish a provenance record for the site of \"{repo}\" to the EVM registry: \
                 the commit and the hash of the page it serves. The EVM action fee is charged \
                 to your ic-git balance."
            )
        }
        _ => {
            return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                description: format!("ic-git has no consent message for \"{method}\"; it will not be signed blind"),
            }))
        }
    })
}

/// Cycles for a person: T with three decimals from 10 B up, B with one
/// decimal from 1 B, M below. Integer arithmetic only, so 2 T is "2.000 T".
fn cycles(n: u64) -> String {
    const T: u64 = 1_000_000_000_000;
    const B: u64 = 1_000_000_000;
    const M: u64 = 1_000_000;
    if n >= 10 * B {
        format!("{}.{:03} T cycles", n / T, (n % T) / B)
    } else if n >= B {
        format!("{}.{} B cycles", n / B, (n % B) / (B / 10))
    } else {
        format!("{} M cycles", n / M)
    }
}

/// The first `n` characters of `s` with an ellipsis, or all of it if it is
/// that short. Counts characters, not bytes: the arguments this trims come
/// from the caller and need not be ASCII.
fn prefix(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}...", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Wrap `text` at word boundaries into lines of at most `width` characters
/// and group them into pages of `per_page` lines. A word longer than a line
/// is split rather than dropped; a zero width or page size is treated as one.
/// Width is counted in characters, never bytes: interpolated arguments such
/// as a wasm path or a repo name may be non-ASCII, and slicing one inside a
/// multibyte character would trap the whole consent call.
fn paginate(text: &str, width: usize, per_page: usize) -> Vec<Page> {
    let width = width.max(1);
    let per_page = per_page.max(1);
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    let mut line_chars = 0usize;
    for word in text.split_whitespace() {
        let mut word: Vec<char> = word.chars().collect();
        while word.len() > width {
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
                line_chars = 0;
            }
            lines.push(word[..width].iter().collect());
            word.drain(..width);
        }
        if line.is_empty() {
            line.extend(word.iter());
            line_chars = word.len();
        } else if line_chars + 1 + word.len() <= width {
            line.push(' ');
            line.extend(word.iter());
            line_chars += 1 + word.len();
        } else {
            lines.push(std::mem::replace(&mut line, word.iter().collect()));
            line_chars = word.len();
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
        .chunks(per_page)
        .map(|c| Page { lines: c.to_vec() })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::encode_args;

    fn generic(method: &str, arg: Vec<u8>) -> Result<String, Icrc21Error> {
        let req = ConsentMessageRequest {
            method: method.to_string(),
            arg,
            user_preferences: ConsentMessageSpec {
                metadata: ConsentMessageMetadata { language: "en".into(), utc_offset_minutes: Some(-240) },
                device_spec: Some(DeviceSpec::GenericDisplay),
            },
        };
        consent_message(req).map(|info| {
            assert_eq!(info.metadata.language, "en");
            assert_eq!(info.metadata.utc_offset_minutes, Some(-240));
            match info.consent_message {
                ConsentMessage::GenericDisplayMessage(t) => t,
                other => panic!("expected a generic message, got {other:?}"),
            }
        })
    }

    #[test]
    fn every_console_method_has_a_message_with_its_arguments_in_it() {
        let p = Principal::from_text("3kq6u-eptpm-egjdi-5qvjv-twk23-m4ymt-qqrcs-tdkvy-ob7zx-x6qq3-wqe").unwrap();
        let cases: Vec<(&str, Vec<u8>, &[&str])> = vec![
            ("deposit_from_cycles_ledger", encode_args((2_100_000_000_000u64,)).unwrap(), &["2.100 T cycles", "allowance"]),
            ("create_repo", encode_args(("ic-vote",)).unwrap(), &["\"ic-vote\"", "owner"]),
            ("create_app_canister", encode_args(("ic-vote", 1_000_000_000_000u64)).unwrap(), &["1.000 T cycles", "both control"]),
            ("top_up_app_canister", encode_args(("ic-vote", 500_000_000_000u64)).unwrap(), &["0.500 T cycles", "app canister"]),
            ("create_push_token", encode_args(("ic-vote",)).unwrap(), &["push token", "until it is revoked"]),
            ("revoke_push_token", encode_args(("0123456789abcdef0123456789abcdef",)).unwrap(), &["01234567...", "refused"]),
            ("add_member", encode_args(("ic-vote", p, "voter")).unwrap(), &["3kq6u-eptpm", "voter", "approve or reject"]),
            ("remove_member", encode_args(("ic-vote", p)).unwrap(), &["Remove 3kq6u-eptpm", "every role"]),
            ("set_required_votes", encode_args(("ic-vote", 2u32)).unwrap(), &["Require 2 approvals"]),
            ("set_required_votes", encode_args(("ic-vote", 0u32)).unwrap(), &["without any approvals"]),
            ("vote", encode_args(("ic-vote", "0123456789abcdef0123456789abcdef01234567", true)).unwrap(), &["Approve commit 0123456789ab..."]),
            ("vote", encode_args(("ic-vote", "0123456789abcdef0123456789abcdef01234567", false)).unwrap(), &["Reject commit"]),
            ("set_wasm_deploy", encode_args(("ic-vote", "app", "app.wasm")).unwrap(), &["app.wasm", "its app canister"]),
            ("set_deploy_mode", encode_args(("ic-vote", "reinstall")).unwrap(), &["REINSTALL", "WIPE ALL STATE"]),
            ("set_deploy_mode", encode_args(("ic-vote", "upgrade")).unwrap(), &["keeps its state"]),
            ("deploy_now", encode_args(("ic-vote",)).unwrap(), &["now, without a push", "NEW contract creation", "already deployed", "fee for each leg"]),
            ("set_site", encode_args(("ic-vote", "site")).unwrap(), &["site/", "/site/ic-vote/"]),
            ("set_site", encode_args(("ic-vote", "")).unwrap(), &["repository root"]),
            ("evm_registry_publish_site", encode_args(("ic-vote",)).unwrap(), &["provenance record", "EVM action fee"]),
            ("deposit", encode_args(()).unwrap(), &["attached to this call"]),
        ];
        for (method, arg, expect) in cases {
            let text = generic(method, arg).unwrap_or_else(|e| panic!("{method}: {e:?}"));
            for needle in expect {
                assert!(text.contains(needle), "{method}: expected {needle:?} in {text:?}");
            }
        }
    }

    #[test]
    fn an_unlisted_method_is_refused_not_described_vaguely() {
        // Blind signing is the failure mode this module exists to prevent:
        // a method it does not know must be an error the wallet shows, not
        // a message that says nothing.
        let err = generic("charge_rent_now", encode_args(()).unwrap()).unwrap_err();
        assert!(matches!(err, Icrc21Error::UnsupportedCanisterCall(ErrorInfo { ref description }) if description.contains("charge_rent_now")));
    }

    #[test]
    fn arguments_that_do_not_decode_are_an_error_not_a_guess() {
        // The wrong shape for create_repo: a number where the name goes.
        let err = generic("create_repo", encode_args((7u64,)).unwrap()).unwrap_err();
        assert!(matches!(err, Icrc21Error::ConsentMessageUnavailable(ErrorInfo { ref description }) if description.contains("create_repo")));
    }

    #[test]
    fn cycles_read_the_way_the_console_prints_them() {
        assert_eq!(cycles(2_000_000_000_000), "2.000 T cycles");
        assert_eq!(cycles(2_100_000_000_000), "2.100 T cycles");
        assert_eq!(cycles(10_000_000_000), "0.010 T cycles");
        assert_eq!(cycles(1_500_000_000), "1.5 B cycles");
        assert_eq!(cycles(100_000_000), "100 M cycles");
    }

    #[test]
    fn line_display_wraps_at_words_and_pages_by_lines() {
        let req = ConsentMessageRequest {
            method: "create_repo".into(),
            arg: encode_args(("ic-vote",)).unwrap(),
            user_preferences: ConsentMessageSpec {
                metadata: ConsentMessageMetadata { language: "en".into(), utc_offset_minutes: None },
                device_spec: Some(DeviceSpec::LineDisplay { characters_per_line: 20, lines_per_page: 3 }),
            },
        };
        let info = consent_message(req).unwrap();
        let ConsentMessage::LineDisplayMessage { pages } = info.consent_message else { panic!("expected line display") };
        assert!(!pages.is_empty());
        let mut all = Vec::new();
        for page in &pages {
            assert!(page.lines.len() <= 3);
            for l in &page.lines {
                assert!(l.chars().count() <= 20, "line too long: {l:?}");
                assert!(!l.starts_with(' ') && !l.ends_with(' '));
                all.push(l.clone());
            }
        }
        // Nothing lost in wrapping: the words come back in order.
        let rejoined = all.join(" ");
        assert_eq!(rejoined, generic("create_repo", encode_args(("ic-vote",)).unwrap()).unwrap());
        // A word longer than a line is split, not dropped.
        let pages = paginate("abcdefghijklmnopqrstuvwxyz end", 10, 5);
        assert_eq!(pages[0].lines, vec!["abcdefghij", "klmnopqrst", "uvwxyz end"]);
    }

    #[test]
    fn line_display_splits_non_ascii_text_on_character_boundaries() {
        // A wasm path or repo name is whatever the caller typed. Wrapping
        // must count characters: a byte index landing inside a multibyte
        // character would trap the consent call and leave the wallet blind.
        let path = "\u{e9}t\u{e9}/\u{4f60}\u{597d}/\u{1f680}\u{1f680}app.wasm";
        let text = generic("set_wasm_deploy", encode_args(("ic-vote", "app", path)).unwrap()).unwrap();
        for width in 1..=12 {
            let pages = paginate(&text, width, 4);
            let lines: Vec<&String> = pages.iter().flat_map(|p| p.lines.iter()).collect();
            assert!(lines.iter().all(|l| l.chars().count() <= width), "width {width}: {lines:?}");
            let rejoined: String = lines.iter().map(|l| l.as_str()).collect::<Vec<_>>().join(" ");
            assert_eq!(rejoined.replace(' ', ""), text.replace(' ', ""), "width {width}");
        }
        // The same goes for the trimmed identifiers.
        assert_eq!(prefix("\u{4f60}\u{597d}\u{1f680}\u{e9}t\u{e9}", 4), "\u{4f60}\u{597d}\u{1f680}\u{e9}...");
        assert_eq!(prefix("\u{4f60}\u{597d}", 4), "\u{4f60}\u{597d}");
    }

    #[test]
    fn standards_list_names_both() {
        let names: Vec<String> = supported_standards().into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["ICRC-10", "ICRC-21"]);
    }
}
