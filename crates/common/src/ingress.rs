//! The ingress filter (`canister_inspect_message`): which signed messages
//! a canister takes in at all.
//!
//! A canister pays for every ingress message it accepts, by its bytes,
//! whether or not the call then does anything: a call its guard refuses,
//! or one whose argument does not decode, costs it the same as one that
//! runs. Without a filter anyone can send any method a 2 MiB argument, as
//! often as the subnet lets them, and the canister pays for each. The
//! filter runs before that charge, on one replica, and costs the canister
//! nothing; what it refuses is never charged.
//!
//! It refuses only what the call would refuse anyway, or could do nothing
//! with: a method only another canister calls, an operator's method from
//! anyone else, the anonymous principal where a call needs a caller, and
//! an argument larger than any real one. One bound is the filter's own:
//! the size of a tenant's argument (`MAX_ARG`), which no call here comes
//! near.
//!
//! A tenant's call is taken only from a caller it could be for: each side
//! asks its own state (its `standing`) whether the caller has a part in
//! the repo the call names, an account that covers the repo it would
//! create, a deposit to finish. A stranger is left the calls that are
//! anyone's, and those are small: a first deposit (a number), a query
//! sent as an update (`MAX_READ_ARG`), a consent message
//! (`MAX_CONSENT_ARG`).
//!
//! It is not an access check. A call from another canister never passes
//! through it, and a replica that skips it is not caught: every guard and
//! every check a method makes stays where it is. What is left after it is
//! the price of a message that is taken, which no filter removes: its
//! fixed part, and its bytes up to those bounds.
//!
//! Each side lists its methods' rules (its `ingress.rs`); a method with no
//! rule is refused, and each canister's tests hold its list to its `.did`.

use candid::Principal;
use ic_dev_kit_rs::http::HttpRequest;

/// The most an argument may weigh from a caller who is not an operator,
/// in bytes. The largest a tenant sends is a list of eight domain names
/// or an SSH public key, a few kilobytes.
pub const MAX_ARG: usize = 16 << 10;

/// The most a query's argument may weigh when it is sent as an update:
/// a repo's name, a principal, a commit, a small request.
pub const MAX_READ_ARG: usize = 1 << 10;

/// The same for the consent message, which anyone may ask for and whose
/// argument carries another call's inside it: the largest one described
/// is a list of eight domain names, under three kilobytes.
pub const MAX_CONSENT_ARG: usize = 8 << 10;

/// The same for a deposit from a ledger, whose argument is one number
/// and which a caller with no account yet must be able to send.
pub const MAX_DEPOSIT_ARG: usize = 64;

/// Who may send a method as an ingress message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Nobody: only canisters call it. The text is the refusal.
    NotIngress(&'static str),
    /// Operators, with an argument of any size.
    Operator,
    /// Anyone but the anonymous principal, with at most `MAX_ARG`, whom
    /// the side then finds to have standing for this call (its
    /// `standing`, by the method).
    SignedIn,
    /// The same, for a call on the repo its first argument names: the
    /// side asks whether the caller has a part in that repo.
    Member,
    /// Anyone, with at most `MAX_READ_ARG`: the queries, which may be
    /// called as updates for a certified answer.
    Anyone,
    /// Anyone, with at most `MAX_CONSENT_ARG`: the ICRC-21 consent
    /// message, which a wallet may ask for before its user has signed in.
    Consent,
    /// `http_request_update`, from anyone and of any size as far as this
    /// goes: the canister reads the request itself, and takes it only
    /// with a push token (`http_request_less_body`).
    Push,
}

/// Is the message taken? `rule` is the method's, `None` for a method the
/// canister does not list; `operator` is the canister's own rule applied
/// to `caller`; `arg_len` the argument's size in bytes. `Err` is the
/// refusal, as the caller reads it.
pub fn decide(method: &str, rule: Option<Rule>, caller: &Principal, operator: bool, arg_len: usize) -> Result<(), String> {
    let Some(rule) = rule else {
        return Err(format!("{method}: this canister takes no such call"));
    };
    let cap = match rule {
        // Refused from operators too: the method would refuse them.
        Rule::NotIngress(why) => return Err(format!("{method}: {why}")),
        Rule::Push => return Ok(()),
        // An operator's argument is as large as the call needs (a module,
        // a source text), and an operator is refused nothing else here.
        _ if operator => return Ok(()),
        Rule::Operator => return Err(format!("{caller} is not an operator (a controller or on the admin allowlist)")),
        Rule::SignedIn | Rule::Member if *caller == Principal::anonymous() => {
            return Err(format!("sign in first: the anonymous principal cannot call {method}"));
        }
        Rule::SignedIn | Rule::Member => MAX_ARG,
        Rule::Anyone => MAX_READ_ARG,
        Rule::Consent => MAX_CONSENT_ARG,
    };
    if arg_len > cap {
        return Err(format!("{method}: the argument is {arg_len} bytes, and a call of it carries at most {cap}"));
    }
    Ok(())
}

/// Does the side ask its own state about the caller, once `decide` has
/// taken the message? Not of an operator, who is refused nothing.
pub fn asks_standing(rule: Option<Rule>, operator: bool) -> bool {
    !operator && matches!(rule, Some(Rule::SignedIn | Rule::Member))
}

/// The first argument of a call, when it is a text: the repo a tenant's
/// call names. `None` for an argument the method itself could not read.
pub fn first_text(arg: &[u8]) -> Option<String> {
    candid::de::IDLDeserialize::new(arg).ok()?.get_value::<String>().ok()
}

/// A method's rule in a side's list.
pub fn find(rules: &[(&str, Rule)], method: &str) -> Option<Rule> {
    rules.iter().find(|(name, _)| *name == method).map(|(_, rule)| *rule)
}

/// What is wrong between a canister's `.did` and its rules, for its
/// tests: a method the service declares with no rule, which the filter
/// would refuse; a query that is not anyone's or an operator's to read,
/// or an update that is anyone's. Empty when they agree.
pub fn against_did(did: &str, rule: impl Fn(&str) -> Option<Rule>) -> Vec<String> {
    let mut wrong = Vec::new();
    for (method, query) in did_methods(did) {
        match rule(&method) {
            None => wrong.push(format!("{method} has no rule")),
            Some(Rule::Anyone) if !query => wrong.push(format!("{method} is an update, and anyone's")),
            Some(Rule::Anyone | Rule::Operator) => {}
            Some(r) if query => wrong.push(format!("{method} is a query, under {r:?}")),
            Some(_) => {}
        }
    }
    wrong
}

/// The rules of a list that name no method of the `.did`, or name one
/// twice. Empty when there are none.
pub fn stale(did: &str, rules: &[(&str, Rule)]) -> Vec<String> {
    let declared: Vec<String> = did_methods(did).into_iter().map(|(m, _)| m).collect();
    let mut wrong = Vec::new();
    for (i, (name, _)) in rules.iter().enumerate() {
        if !declared.iter().any(|m| m == name) {
            wrong.push(format!("{name} is not in the .did"));
        }
        if rules[..i].iter().any(|(earlier, _)| earlier == name) {
            wrong.push(format!("{name} is listed twice"));
        }
    }
    wrong
}

/// The methods a `.did`'s service declares, each with whether it is a
/// query: its lines of the form `  name : (...) -> (...) query;`.
fn did_methods(did: &str) -> Vec<(String, bool)> {
    let service = did.find("\nservice").map(|at| &did[at..]).unwrap_or("");
    service
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.strip_prefix("  ")?.split_once(" : ")?;
            let named = !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            named.then(|| (name.to_string(), rest.trim_end().ends_with(" query;")))
        })
        .collect()
}

/// The request of an `http_request_update` argument without its body,
/// which is left where it is: a push is up to 2 MiB of pack, and the
/// filter has a small budget and reads only the route and the token.
pub fn http_request_less_body(arg: &[u8]) -> Result<HttpRequest, String> {
    let head: Head = candid::decode_one(arg).map_err(|e| format!("http_request_update: not an HTTP request ({e})"))?;
    Ok(HttpRequest {
        method: head.method,
        url: head.url,
        headers: head.headers,
        body: Vec::new(),
    })
}

/// The gateway's request record, its body unread.
#[derive(candid::CandidType, serde::Deserialize)]
struct Head {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    #[allow(dead_code)]
    body: Unread,
}

/// A `vec nat8` stepped over in one move, not copied or walked byte by
/// byte.
struct Unread;

impl candid::CandidType for Unread {
    fn _ty() -> candid::types::Type {
        <Vec<u8> as candid::CandidType>::ty()
    }
    fn idl_serialize<S: candid::types::Serializer>(&self, serializer: S) -> Result<(), S::Error> {
        serializer.serialize_blob(&[])
    }
}

impl<'de> serde::Deserialize<'de> for Unread {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Skip;
        impl<'de> serde::de::Visitor<'de> for Skip {
            type Value = Unread;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a blob")
            }
            fn visit_bytes<E>(self, _: &[u8]) -> Result<Unread, E> {
                Ok(Unread)
            }
        }
        d.deserialize_bytes(Skip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> Principal {
        Principal::from_slice(&[7; 29])
    }

    #[test]
    fn a_method_without_a_rule_is_refused() {
        let e = decide("no_such", None, &user(), true, 0).unwrap_err();
        assert!(e.contains("no_such") && e.contains("no such call"), "{e}");
    }

    #[test]
    fn a_canisters_call_is_refused_from_everyone() {
        let rule = Some(Rule::NotIngress("only the authority may call this"));
        for operator in [false, true] {
            let e = decide("set_approved", rule, &user(), operator, 10).unwrap_err();
            assert_eq!(e, "set_approved: only the authority may call this");
        }
    }

    #[test]
    fn an_operators_call_is_an_operators_alone() {
        let rule = Some(Rule::Operator);
        assert_eq!(decide("run_wasm", rule, &user(), true, 2 << 20), Ok(()));
        let e = decide("run_wasm", rule, &user(), false, 10).unwrap_err();
        assert!(e.contains("is not an operator"), "{e}");
        assert!(decide("run_wasm", rule, &Principal::anonymous(), false, 10).is_err());
    }

    #[test]
    fn a_tenants_call_needs_a_caller_and_a_small_argument() {
        let rule = Some(Rule::SignedIn);
        assert_eq!(decide("create_repo", rule, &user(), false, MAX_ARG), Ok(()));
        let e = decide("create_repo", rule, &user(), false, MAX_ARG + 1).unwrap_err();
        assert!(e.contains("at most 16384"), "{e}");
        let e = decide("create_repo", rule, &Principal::anonymous(), false, 10).unwrap_err();
        assert!(e.contains("sign in first"), "{e}");
        // An operator is a tenant too, and bound by neither.
        assert_eq!(decide("create_repo", rule, &user(), true, 2 << 20), Ok(()));
        assert_eq!(decide("create_repo", rule, &Principal::anonymous(), true, 10), Ok(()));
    }

    #[test]
    fn a_read_is_anyones_but_small() {
        for (rule, cap) in [(Rule::Anyone, MAX_READ_ARG), (Rule::Consent, MAX_CONSENT_ARG)] {
            assert_eq!(decide("m", Some(rule), &Principal::anonymous(), false, cap), Ok(()));
            assert!(decide("m", Some(rule), &Principal::anonymous(), false, cap + 1).is_err());
        }
    }

    #[test]
    fn a_call_on_a_repo_is_bounded_as_a_tenants_and_then_the_sides_to_ask() {
        assert_eq!(decide("vote", Some(Rule::Member), &user(), false, MAX_ARG), Ok(()));
        assert!(decide("vote", Some(Rule::Member), &user(), false, MAX_ARG + 1).is_err());
        assert!(decide("vote", Some(Rule::Member), &Principal::anonymous(), false, 10).is_err());
        for rule in [Rule::SignedIn, Rule::Member] {
            assert!(asks_standing(Some(rule), false));
            assert!(!asks_standing(Some(rule), true), "an operator is not asked");
        }
        for rule in [Rule::Anyone, Rule::Consent, Rule::Operator, Rule::Push] {
            assert!(!asks_standing(Some(rule), false));
        }
        assert!(!asks_standing(None, false));
    }

    #[test]
    fn the_repo_a_call_names_is_its_first_argument() {
        let arg = candid::encode_args(("my-repo", 7u64, Some("why"))).unwrap();
        assert_eq!(first_text(&arg).as_deref(), Some("my-repo"));
        assert_eq!(first_text(&candid::encode_args((7u64, "x")).unwrap()), None);
        assert_eq!(first_text(&candid::encode_args(()).unwrap()), None);
        assert_eq!(first_text(b"junk"), None);
    }

    #[test]
    fn a_push_is_left_to_the_canister() {
        assert_eq!(decide("http_request_update", Some(Rule::Push), &Principal::anonymous(), false, 2 << 20), Ok(()));
    }

    const DID: &str = "type T = record { a : text };\nservice : (InitArg) -> {\n  // a comment\n  read : (text) -> (T) query;\n  write : (T) -> ();\n  bench : (text) -> (T) query;\n}\n";

    #[test]
    fn a_did_and_its_rules_are_held_together() {
        let rules = [("read", Rule::Anyone), ("write", Rule::SignedIn), ("bench", Rule::Operator)];
        assert_eq!(against_did(DID, |m| find(&rules, m)), Vec::<String>::new());
        assert_eq!(stale(DID, &rules), Vec::<String>::new());
        // A method without a rule, a query a tenant's, an update anyone's.
        assert_eq!(against_did(DID, |m| find(&rules[..2], m)), ["bench has no rule"]);
        let swapped = [("read", Rule::SignedIn), ("write", Rule::Anyone), ("bench", Rule::Operator)];
        assert_eq!(against_did(DID, |m| find(&swapped, m)), ["read is a query, under SignedIn", "write is an update, and anyone's"]);
        // A rule for a method that is gone, and one given twice.
        let more = [("read", Rule::Anyone), ("gone", Rule::Anyone), ("read", Rule::Operator)];
        assert_eq!(stale(DID, &more), ["gone is not in the .did", "read is listed twice"]);
    }

    /// The gateway's record as it sends it, with a field this side does
    /// not name.
    #[derive(candid::CandidType)]
    struct Sent {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        certificate_version: Option<u16>,
    }

    #[test]
    fn the_request_is_read_without_its_body() {
        let sent = Sent {
            method: "POST".into(),
            url: "/r.git/git-receive-pack".into(),
            headers: vec![("Authorization".into(), "Basic aWM6dA==".into())],
            body: vec![0xAB; 2_000_000],
            certificate_version: Some(2),
        };
        let arg = candid::encode_one(&sent).unwrap();
        let req = http_request_less_body(&arg).unwrap();
        assert_eq!((req.method.as_str(), req.url.as_str()), ("POST", "/r.git/git-receive-pack"));
        assert_eq!(req.headers, sent.headers);
        assert!(req.body.is_empty());
        // The canister's own type reads the same bytes.
        let whole: HttpRequest = candid::decode_one(&arg).unwrap();
        assert_eq!(whole.body.len(), 2_000_000);
    }

    #[test]
    fn what_is_not_a_request_is_refused() {
        assert!(http_request_less_body(b"junk").is_err());
        assert!(http_request_less_body(&candid::encode_one("text").unwrap()).is_err());
    }
}
