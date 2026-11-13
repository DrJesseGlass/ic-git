//! ICRC-21 consent messages and the ICRC-10 standards list: the types,
//! as the standard spells them, and the answer built from one side's
//! descriptions.
//!
//! A wallet that signs on a user's behalf (OISY, through ICRC-49) asks the
//! target canister, before signing, for a sentence a person can read: what
//! this call does, with the actual arguments decoded. Without it the wallet
//! refuses to sign at all, which is the right default -- a signature over
//! bytes the signer cannot read is blind signing -- and it is why no console
//! write reached ic-git before this existed.
//!
//! Each side describes its own methods (`ic_git_authority::consent`,
//! `ic_git_git::consent`), and a canister answers with whichever it holds:
//! the two-canister builds each with one side's, the combined build with
//! both. The list is closed. A method with no description gets
//! `UnsupportedCanisterCall`, so the wallet refuses it rather than showing a
//! vague message; adding a method to the console means adding it to a
//! side's list. The text describes what the call does to the caller's
//! balance and repos, since that is what the person is consenting to.

use candid::{CandidType, Deserialize, Nat};

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

/// One side's descriptions: the text for `method` called with the
/// candid-encoded `arg`, `None` for a method the side does not have.
pub type Describe = fn(&str, &[u8]) -> Option<Result<String, Icrc21Error>>;

// --- the answer --------------------------------------------------------------

/// The consent text for the request, from the sides' descriptions in
/// turn; a method none describes is refused, not described vaguely.
pub fn consent_message(req: ConsentMessageRequest, describe: &[Describe]) -> ConsentMessageResponse {
    let text = describe
        .iter()
        .find_map(|d| d(&req.method, &req.arg))
        .unwrap_or_else(|| {
            Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                description: format!("ic-git has no consent message for \"{}\"; it will not be signed blind", req.method),
            }))
        })?;
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

/// The arguments of `method`, or the error the wallet shows when they do
/// not decode.
pub fn args<'a, T: candid::utils::ArgumentDecoder<'a>>(arg: &'a [u8], method: &str) -> Result<T, Icrc21Error> {
    candid::decode_args::<T>(arg).map_err(|e| {
        Icrc21Error::ConsentMessageUnavailable(ErrorInfo {
            description: format!("the arguments to {method} could not be decoded: {e}"),
        })
    })
}

/// A call the method would refuse is not described: the wallet shows why.
pub fn unavailable(method: &str, e: String) -> Icrc21Error {
    Icrc21Error::ConsentMessageUnavailable(ErrorInfo {
        description: format!("{method}: {e}"),
    })
}

/// The first `n` characters of `s` with an ellipsis, or all of it if it is
/// that short. Counts characters, not bytes: the arguments this trims come
/// from the caller and need not be ASCII.
pub fn prefix(s: &str, n: usize) -> String {
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
pub fn paginate(text: &str, width: usize, per_page: usize) -> Vec<Page> {
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

    fn only_ping(method: &str, arg: &[u8]) -> Option<Result<String, Icrc21Error>> {
        (method == "ping").then(|| args::<(String,)>(arg, method).map(|(what,)| format!("Ping {what}.")))
    }

    fn request(method: &str, arg: Vec<u8>, device_spec: Option<DeviceSpec>) -> ConsentMessageRequest {
        ConsentMessageRequest {
            method: method.into(),
            arg,
            user_preferences: ConsentMessageSpec {
                metadata: ConsentMessageMetadata { language: "fr".into(), utc_offset_minutes: Some(-240) },
                device_spec,
            },
        }
    }

    /// The sides are asked in turn; a method none describes is refused
    /// by name, and arguments that do not decode are an error, not a
    /// guess. The answer is English whatever was asked for.
    #[test]
    fn a_method_no_side_describes_is_refused_by_name() {
        let arg = candid::encode_args(("there",)).unwrap();
        let info = consent_message(request("ping", arg.clone(), Some(DeviceSpec::GenericDisplay)), &[only_ping]).unwrap();
        assert_eq!(info.consent_message, ConsentMessage::GenericDisplayMessage("Ping there.".into()));
        assert_eq!(info.metadata.language, "en");
        assert_eq!(info.metadata.utc_offset_minutes, Some(-240));
        let err = consent_message(request("charge_rent_now", arg.clone(), None), &[only_ping]).unwrap_err();
        assert!(matches!(err, Icrc21Error::UnsupportedCanisterCall(ErrorInfo { ref description }) if description.contains("charge_rent_now")));
        let err = consent_message(request("ping", candid::encode_args((7u64,)).unwrap(), None), &[only_ping]).unwrap_err();
        assert!(matches!(err, Icrc21Error::ConsentMessageUnavailable(ErrorInfo { ref description }) if description.contains("ping")));
        let none: &[Describe] = &[];
        assert!(consent_message(request("ping", arg, None), none).is_err());
    }

    #[test]
    fn line_display_wraps_at_words_and_pages_by_lines() {
        let text = "Create the repository \"ic-vote\" on ic-git. You become its owner, and the creation fee is charged to your ic-git balance.";
        let pages = paginate(text, 20, 3);
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
        assert_eq!(all.join(" "), text);
        // A word longer than a line is split, not dropped.
        let pages = paginate("abcdefghijklmnopqrstuvwxyz end", 10, 5);
        assert_eq!(pages[0].lines, vec!["abcdefghij", "klmnopqrst", "uvwxyz end"]);
        // The request's device spec picks the form.
        let arg = candid::encode_args(("a longer name than a line",)).unwrap();
        let info = consent_message(request("ping", arg, Some(DeviceSpec::LineDisplay { characters_per_line: 8, lines_per_page: 2 })), &[only_ping]).unwrap();
        let ConsentMessage::LineDisplayMessage { pages } = info.consent_message else { panic!("expected line display") };
        assert!(pages.iter().all(|p| p.lines.len() <= 2 && p.lines.iter().all(|l| l.chars().count() <= 8)));
    }

    #[test]
    fn line_display_splits_non_ascii_text_on_character_boundaries() {
        // A wasm path or repo name is whatever the caller typed. Wrapping
        // must count characters: a byte index landing inside a multibyte
        // character would trap the consent call and leave the wallet blind.
        let text = "On every push, install \u{e9}t\u{e9}/\u{4f60}\u{597d}/\u{1f680}\u{1f680}app.wasm into its app canister.";
        for width in 1..=12 {
            let pages = paginate(text, width, 4);
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
