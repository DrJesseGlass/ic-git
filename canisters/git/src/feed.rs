//! Activity feeds (docs/GOVERNANCE.md, section 6): what happened, as Atom,
//! so anyone affected hears about it without anything being stored about
//! them. Any feed reader subscribes, or a feed-to-email service.
//!
//! - `GET /feed/<repo>`: a commit awaiting votes, a ballot with its reason,
//!   a threshold reached, a policy ballot, a deploy (or its failure), a
//!   record published to the registry.
//! - `GET /feed`: ic-git itself. The governor's proposals, ballots and
//!   outcomes, mirrored here on a timer -- the governor has no controllers
//!   and so can never learn to serve a feed -- and the `ic-git#canister`
//!   record this canister publishes after an upgrade.
//!
//! Each feed keeps its newest `MAX_EVENTS` events in stable memory; the
//! records themselves live elsewhere (the deploy history, the registry, the
//! governor's log), so a feed is a notification surface, not evidence.
//! Served on the raw gateway, like `/api` (no response certification).

use candid::{CandidType, Principal};
use ic_dev_kit_rs::http::HttpResponse;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::store;
use crate::tenancy::{self, Vote};

/// The most events kept per feed.
pub const MAX_EVENTS: usize = 200;
/// How often ic-git asks the governor what changed.
#[cfg_attr(test, allow(dead_code))]
pub const GOVERNOR_POLL_SECS: u64 = 300;
/// The most governor log pages one poll reads.
#[cfg_attr(test, allow(dead_code))]
const GOVERNOR_LOG_PAGES: usize = 10;

// --- events ---------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub seq: u64,
    pub at_ns: u64,
    /// awaiting, ballot, reached, policy, deployed, deploy-failed,
    /// published, proposal, executed, withdrawn.
    pub kind: String,
    pub title: String,
    pub detail: String,
    /// The commit or proposal the event is about, when it is about one.
    pub subject: Option<String>,
    /// Who did it, as a principal, when someone did.
    pub actor: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Log {
    next: u64,
    events: Vec<Event>,
}

/// Which feed an event lands in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Feed {
    Repo(String),
    /// ic-git itself: the governor's doings and the canister record.
    Canister,
}

impl Feed {
    fn key(&self) -> String {
        match self {
            Feed::Repo(r) => format!("feed:repo:{r}"),
            Feed::Canister => "feed:ic-git".to_string(),
        }
    }

    fn title(&self) -> String {
        match self {
            Feed::Repo(r) => format!("{r} on ic-git"),
            Feed::Canister => "ic-git".to_string(),
        }
    }

    fn path(&self) -> String {
        match self {
            Feed::Repo(r) => format!("/feed/{r}"),
            Feed::Canister => "/feed".to_string(),
        }
    }
}

fn load(feed: &Feed) -> Log {
    // A feed that no longer decodes starts over: it is a notification
    // surface, and a stuck one would hide every later event, which is worse
    // than losing the old ones (the records they pointed at are elsewhere).
    store::meta_get_json(&feed.key()).unwrap_or_default()
}

pub fn events(feed: &Feed) -> Vec<Event> {
    load(feed).events
}

struct New {
    at_ns: u64,
    kind: &'static str,
    title: String,
    detail: String,
    subject: Option<String>,
    actor: Option<String>,
}

fn append(feed: &Feed, new: Vec<New>) -> u64 {
    if new.is_empty() {
        return 0;
    }
    let mut log = load(feed);
    let n = new.len() as u64;
    for e in new {
        log.events.push(Event {
            seq: log.next,
            at_ns: e.at_ns,
            kind: e.kind.to_string(),
            title: e.title,
            detail: e.detail,
            subject: e.subject,
            actor: e.actor,
        });
        log.next += 1;
    }
    if log.events.len() > MAX_EVENTS {
        let drop = log.events.len() - MAX_EVENTS;
        log.events.drain(0..drop);
    }
    store::meta_set_json(&feed.key(), &log);
    n
}

fn one(feed: &Feed, kind: &'static str, title: String, detail: String, subject: Option<String>, actor: Option<&Principal>) {
    append(
        feed,
        vec![New {
            at_ns: tenancy::now_ns(),
            kind,
            title,
            detail,
            subject,
            actor: actor.map(Principal::to_text),
        }],
    );
}

fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

fn count_text(approvals: u32, objections: u32, required: u32) -> String {
    if objections == 0 {
        format!("{approvals} of {required}")
    } else {
        format!("{approvals} of {required}, {objections} objecting")
    }
}

fn decision_text(decision: Vote) -> &'static str {
    match decision {
        Vote::Approve => "approve",
        Vote::Reject => "reject",
        Vote::Object => "object",
    }
}

/// `reason` as the ballot stores it (`tenancy::ballot_reason`): trimmed,
/// and an empty one is none. The feed takes the caller's text, so without
/// this a reason padded with whitespace -- accepted, since the 1 KB bound
/// is on the trimmed text -- would grow the feed past what a ballot holds.
fn with_reason(text: String, reason: Option<&str>) -> String {
    match reason.map(str::trim).filter(|r| !r.is_empty()) {
        Some(r) => format!("{text}. Reason: {r}"),
        None => text,
    }
}

// --- repo events ------------------------------------------------------------

/// After a push: the deploy branch moved to a commit the repo's voters have
/// not approved. Nothing for a repo that requires no votes, or a push that
/// left the deploy branch where it was.
pub fn after_push(repo: &str, tip_before: Option<store::Oid>) {
    let Some(branch) = store::head_target(repo) else { return };
    let Some(tip) = store::get_ref(repo, &branch) else { return };
    if tip_before.as_ref() == Some(&tip) {
        return;
    }
    let hex = store::oid_hex(&tip);
    let Some(t) = tenancy::tally(repo, &hex) else { return };
    if t.required == 0 || t.reached {
        return;
    }
    one(
        &Feed::Repo(repo.to_string()),
        "awaiting",
        format!("commit {} awaits votes", short(&hex)),
        format!("{hex} on {branch} needs {} to deploy and be served", count_text(t.approvals, t.objections, t.required)),
        Some(hex),
        None,
    );
}

/// A ballot on a commit, and the count it left. `was_reached` is the
/// commit's standing before it, so a ballot that brings the commit to the
/// threshold is followed by a "reached" event.
pub fn ballot(repo: &str, who: &Principal, commit: &str, decision: Vote, reason: Option<&str>, t: &ic_multisig::Tally, was_reached: bool) {
    let feed = Feed::Repo(repo.to_string());
    one(
        &feed,
        "ballot",
        format!("{} commit {}", decision_text(decision), short(commit)),
        with_reason(
            format!("{who} voted {} on {commit}: now {}", decision_text(decision), count_text(t.approvals, t.objections, t.required)),
            reason,
        ),
        Some(commit.to_string()),
        Some(who),
    );
    if t.required > 0 && t.reached && !was_reached {
        one(
            &feed,
            "reached",
            format!("commit {} reached {} votes", short(commit), t.required),
            format!("{commit} may now be served and deployed"),
            Some(commit.to_string()),
            None,
        );
    }
}

/// A ballot on a policy change, and whether it applied the change.
pub fn policy_ballot(repo: &str, who: &Principal, change: &str, decision: Vote, reason: Option<&str>, t: &ic_multisig::Tally) {
    let feed = Feed::Repo(repo.to_string());
    one(
        &feed,
        "policy",
        format!("{} policy change: {change}", decision_text(decision)),
        with_reason(
            format!("{who} voted {} on \"{change}\": now {}", decision_text(decision), count_text(t.approvals, t.objections, t.required)),
            reason,
        ),
        Some(change.to_string()),
        Some(who),
    );
    if t.reached {
        one(
            &feed,
            "policy",
            format!("policy changed: {change}"),
            format!("\"{change}\" reached {} votes and is in effect", t.required),
            Some(change.to_string()),
            None,
        );
    }
}

/// A wasm deploy's outcome, from the record the deploy history keeps.
pub fn deployed(repo: &str, r: &crate::deploy::DeployRecord) {
    let feed = Feed::Repo(repo.to_string());
    if r.ok {
        one(
            &feed,
            "deployed",
            format!("commit {} deployed to {}", short(&r.commit), r.target),
            format!("{} installed into {} from {}: module sha256 {}", r.commit, r.target, r.source_path, r.wasm_sha256),
            Some(r.commit.clone()),
            None,
        );
    } else {
        one(
            &feed,
            "deploy-failed",
            format!("deploy of commit {} failed", short(&r.commit)),
            format!("{}: {}", r.commit, r.message),
            Some(r.commit.clone()),
            None,
        );
    }
}

/// An EVM deploy's outcome.
pub fn evm_deployed(repo: &str, commit: &str, ok: bool, message: &str) {
    let feed = Feed::Repo(repo.to_string());
    if ok {
        one(
            &feed,
            "deployed",
            format!("commit {} deployed to the EVM", short(commit)),
            format!("{commit}: {message}"),
            Some(commit.to_string()),
            None,
        );
    } else {
        one(
            &feed,
            "deploy-failed",
            format!("EVM deploy of commit {} failed", short(commit)),
            format!("{commit}: {message}"),
            Some(commit.to_string()),
            None,
        );
    }
}

/// A registry record was broadcast. The key says whose feed: a repo's
/// (`<repo>`, `<repo>#site`, `<repo>#app`) or ic-git's own
/// (`ic-git#canister`). Broadcast, not mined: the record exists once the
/// chain includes the transaction.
pub fn published(key: &str, commit: &str, tx_hash: &str) {
    let feed = if key == crate::provenance::CANISTER_KEY {
        Feed::Canister
    } else {
        Feed::Repo(key.split('#').next().unwrap_or(key).to_string())
    };
    one(
        &feed,
        "published",
        format!("record {key} published for commit {}", short(commit)),
        format!("{key} -> {commit}, transaction {tx_hash} broadcast to the registry"),
        Some(commit.to_string()),
        None,
    );
}

// --- the governor, mirrored ----------------------------------------------------

/// The governor's types, as much of them as the feed reads
/// (canisters/governor/governor.did). Candid lets a reader leave fields out.
#[derive(CandidType, Deserialize, Clone, Debug)]
enum Change {
    Upgrade { commit: String, module_sha256: String },
    Policy { approvers: Vec<Principal>, threshold: u32 },
    Handover { successor: Principal },
}

impl Change {
    fn describe(&self) -> String {
        match self {
            Change::Upgrade { commit, module_sha256 } => format!("upgrade ic-git to commit {} (module sha256 {})", short(commit), module_sha256),
            Change::Policy { approvers, threshold } => format!("policy {} of {}", threshold, approvers.len()),
            Change::Handover { successor } => format!("hand ic-git over to {successor}"),
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct GovBallot {
    approver: Principal,
    decision: Vote,
    reason: Option<String>,
    at_ns: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct GovCount {
    approvals: u32,
    objections: u32,
    required: u32,
    reached: bool,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct GovProposal {
    id: u64,
    change: Change,
    proposer: Principal,
    at_ns: u64,
    ballots: Vec<GovBallot>,
    count: GovCount,
    last_error: Option<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct GovLogEntry {
    id: u64,
    change: Change,
    proposer: Principal,
    ballots: Vec<GovBallot>,
    at_ns: u64,
    outcome: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct GovLogPage {
    entries: Vec<GovLogEntry>,
    next: Option<u64>,
}

const GOVERNOR_KEY: &str = "feed:governor";
const MIRROR_KEY: &str = "feed:governor:mirror";

/// What of the governor the feed has already reported.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
struct Mirror {
    /// Bumped by every `set_governor` that resets the mirror, so a poll
    /// that was awaiting the old governor's answers when it happened can
    /// tell, and drops them rather than reconciling them into the new
    /// mirror (wrong events, and a cursor moved past history the new
    /// governor has not reported).
    #[serde(default)]
    generation: u64,
    /// The governor's log position consumed so far.
    cursor: u64,
    /// Open proposals: their ballots (approver, time) and standing seen.
    open: BTreeMap<u64, Seen>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
struct Seen {
    ballots: Vec<(String, u64)>,
    reached: bool,
    last_error: Option<String>,
}

pub fn governor() -> Option<Principal> {
    store::meta_get_json::<String>(GOVERNOR_KEY).and_then(|s| Principal::from_text(s).ok())
}

/// Point the feed at the governor, or at nothing. The mirror starts over
/// with a new governor; the events already reported stay.
pub fn set_governor(governor: Option<Principal>) {
    let before = self::governor();
    match governor {
        Some(p) => store::meta_set_json(GOVERNOR_KEY, &p.to_text()),
        None => store::meta_set_json(GOVERNOR_KEY, &Option::<String>::None),
    }
    if before != governor {
        let generation = mirror().generation + 1;
        store::meta_set_json(MIRROR_KEY, &Mirror { generation, ..Mirror::default() });
    }
    arm_governor_timer();
}

fn mirror() -> Mirror {
    store::meta_get_json(MIRROR_KEY).unwrap_or_default()
}

/// The events a fresh look at the governor adds, and the mirror moved past
/// them. Pure, so it is tested without a governor: `open` is `proposals()`,
/// `pages` the log from `m.cursor` on.
fn reconcile(m: &mut Mirror, open: &[GovProposal], pages: &[GovLogPage]) -> Vec<New> {
    let mut out = Vec::new();
    let note_proposal = |m: &mut Mirror, out: &mut Vec<New>, id: u64, change: &Change, proposer: &Principal, at_ns: u64, ballots: &[GovBallot]| {
        let seen = m.open.entry(id).or_insert_with(|| {
            out.push(New {
                at_ns,
                kind: "proposal",
                title: format!("proposal {id}: {}", change.describe()),
                detail: format!("{proposer} proposed to {}", change.describe()),
                subject: Some(id.to_string()),
                actor: Some(proposer.to_text()),
            });
            Seen::default()
        });
        for b in ballots {
            let key = (b.approver.to_text(), b.at_ns);
            if seen.ballots.contains(&key) {
                continue;
            }
            seen.ballots.push(key);
            out.push(New {
                at_ns: b.at_ns,
                kind: "ballot",
                title: format!("{} proposal {id}", decision_text(b.decision)),
                detail: with_reason(
                    format!("{} voted {} on proposal {id} ({})", b.approver, decision_text(b.decision), change.describe()),
                    b.reason.as_deref(),
                ),
                subject: Some(id.to_string()),
                actor: Some(b.approver.to_text()),
            });
        }
    };
    for p in open {
        note_proposal(m, &mut out, p.id, &p.change, &p.proposer, p.at_ns, &p.ballots);
        let seen = m.open.get_mut(&p.id).expect("noted");
        if p.count.reached && !seen.reached {
            seen.reached = true;
            out.push(New {
                at_ns: p.ballots.iter().map(|b| b.at_ns).max().unwrap_or(p.at_ns),
                kind: "reached",
                title: format!("proposal {} reached {} votes", p.id, p.count.required),
                detail: format!("{}: {}", p.change.describe(), count_text(p.count.approvals, p.count.objections, p.count.required)),
                subject: Some(p.id.to_string()),
                actor: None,
            });
        }
        if p.last_error.is_some() && p.last_error != seen.last_error {
            seen.last_error = p.last_error.clone();
            out.push(New {
                at_ns: p.ballots.iter().map(|b| b.at_ns).max().unwrap_or(p.at_ns),
                kind: "deploy-failed",
                title: format!("proposal {} failed to execute", p.id),
                detail: format!("{}: {}", p.change.describe(), p.last_error.clone().unwrap_or_default()),
                subject: Some(p.id.to_string()),
                actor: None,
            });
        }
    }
    for page in pages {
        for e in &page.entries {
            // A log entry's time is when it closed; a proposal it reports
            // for the first time opened no later than its first ballot.
            let opened = e.ballots.iter().map(|b| b.at_ns).min().unwrap_or(e.at_ns).min(e.at_ns);
            note_proposal(m, &mut out, e.id, &e.change, &e.proposer, opened, &e.ballots);
            m.open.remove(&e.id);
            let kind = if e.outcome.starts_with("executed") { "executed" } else { "withdrawn" };
            out.push(New {
                at_ns: e.at_ns,
                kind,
                title: format!("proposal {} {}", e.id, if kind == "executed" { "executed" } else { "withdrawn" }),
                detail: format!("{}: {}", e.change.describe(), e.outcome),
                subject: Some(e.id.to_string()),
                actor: None,
            });
            m.cursor += 1;
        }
    }
    // Ballots carry their own time, so a tick that catches up on several
    // things lists them in the order they happened.
    out.sort_by_key(|e| e.at_ns);
    out
}

#[cfg(not(test))]
thread_local! {
    static TIMER: std::cell::Cell<Option<ic_cdk_timers::TimerId>> = const { std::cell::Cell::new(None) };
    static POLLING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Poll the governor every `GOVERNOR_POLL_SECS` while one is set. Called
/// from init, post_upgrade (timers do not survive an upgrade) and
/// `set_governor`.
#[cfg(not(test))]
pub fn arm_governor_timer() {
    TIMER.with(|t| {
        if let Some(id) = t.take() {
            ic_cdk_timers::clear_timer(id);
        }
        if governor().is_some() {
            let id = ic_cdk_timers::set_timer_interval(std::time::Duration::from_secs(GOVERNOR_POLL_SECS), || async {
                let _ = poll_governor().await;
            });
            t.set(Some(id));
        }
    });
}

#[cfg(test)]
pub fn arm_governor_timer() {}

#[cfg(test)]
pub async fn poll_governor() -> Result<u64, String> {
    Err("no governor in tests".to_string())
}

/// Ask the governor what changed and report it. Returns how many events
/// that added. One poll at a time: a second one while the first awaits
/// would report the same changes twice. A poll whose governor was changed
/// while it awaited reports nothing: its answers are the old governor's.
#[cfg(not(test))]
pub async fn poll_governor() -> Result<u64, String> {
    use ic_cdk::call::Call;
    let gov = governor().ok_or("no governor set; call feed_set_governor first")?;
    if POLLING.with(|p| p.replace(true)) {
        return Err("a poll is already running".to_string());
    }
    let result = async {
        let open = Call::bounded_wait(gov, "proposals")
            .await
            .map_err(|e| format!("governor proposals: {e}"))?
            .candid::<Vec<GovProposal>>()
            .map_err(|e| format!("governor proposals undecodable: {e}"))?;
        let mut pages = Vec::new();
        let start = mirror();
        let mut from = start.cursor;
        for _ in 0..GOVERNOR_LOG_PAGES {
            let page = Call::bounded_wait(gov, "log")
                .with_args(&(from, 100u32))
                .await
                .map_err(|e| format!("governor log: {e}"))?
                .candid::<GovLogPage>()
                .map_err(|e| format!("governor log undecodable: {e}"))?;
            let next = page.next;
            let empty = page.entries.is_empty();
            pages.push(page);
            match next {
                Some(n) if !empty => from = n,
                _ => break,
            }
        }
        // Read the mirror after the awaits: a set_governor meanwhile reset
        // it, and these answers are then the old governor's.
        let mut m = mirror();
        if m.generation != start.generation {
            return Err("the governor changed during the poll; its answers are discarded".to_string());
        }
        let new = reconcile(&mut m, &open, &pages);
        let n = append(&Feed::Canister, new);
        store::meta_set_json(MIRROR_KEY, &m);
        Ok(n)
    }
    .await;
    POLLING.with(|p| p.set(false));
    result
}

// --- Atom -------------------------------------------------------------------

/// GET /feed and /feed/<repo>. `host` is the request's Host header, for the
/// feed's own link; without one the raw gateway's name for this canister.
pub fn serve(repo: Option<&str>, host: Option<&str>) -> HttpResponse {
    let feed = match repo {
        None => Feed::Canister,
        Some(r) if store::repo_exists(r) => Feed::Repo(r.to_string()),
        Some(_) => return crate::git_response(404, "text/plain", b"no such repo\n".to_vec()),
    };
    let canister = self_id();
    let host = host.map(str::to_string).unwrap_or_else(|| format!("{canister}.raw.icp0.io"));
    let scheme = if host.starts_with("localhost") || host.starts_with("127.") || host.contains(".localhost") {
        "http"
    } else {
        "https"
    };
    let body = atom(&feed, &events(&feed), &canister, &format!("{scheme}://{host}"));
    let mut res = crate::git_response(200, "application/atom+xml; charset=utf-8", body.into_bytes());
    res.headers.push(("X-Content-Type-Options".to_string(), "nosniff".to_string()));
    res
}

fn self_id() -> String {
    #[cfg(test)]
    {
        "aaaaa-aa".to_string()
    }
    #[cfg(not(test))]
    {
        ic_cdk::api::canister_self().to_text()
    }
}

fn atom(feed: &Feed, events: &[Event], canister: &str, base: &str) -> String {
    let id = match feed {
        Feed::Repo(r) => format!("urn:ic-git:{canister}:repo:{r}"),
        Feed::Canister => format!("urn:ic-git:{canister}"),
    };
    let updated = events.last().map_or_else(tenancy::now_ns, |e| e.at_ns);
    let mut s = String::with_capacity(1024 + events.len() * 512);
    s.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    s.push_str("<feed xmlns=\"http://www.w3.org/2005/Atom\">\n");
    s.push_str(&format!("  <title>{}</title>\n", esc(&feed.title())));
    s.push_str(&format!("  <id>{}</id>\n", esc(&id)));
    s.push_str(&format!(
        "  <link rel=\"self\" type=\"application/atom+xml\" href=\"{}{}\"/>\n",
        esc(base),
        esc(&feed.path())
    ));
    s.push_str(&format!("  <updated>{}</updated>\n", rfc3339(updated)));
    s.push_str("  <author><name>ic-git</name></author>\n");
    for e in events.iter().rev() {
        s.push_str("  <entry>\n");
        s.push_str(&format!("    <id>{}:{}</id>\n", esc(&id), e.seq));
        s.push_str(&format!("    <title>{}</title>\n", esc(&e.title)));
        s.push_str(&format!("    <updated>{}</updated>\n", rfc3339(e.at_ns)));
        if let Some(a) = &e.actor {
            s.push_str(&format!("    <author><name>{}</name></author>\n", esc(a)));
        }
        s.push_str(&format!("    <category term=\"{}\"/>\n", esc(&e.kind)));
        s.push_str(&format!("    <content type=\"text\">{}</content>\n", esc(&e.detail)));
        s.push_str("  </entry>\n");
    }
    s.push_str("</feed>\n");
    s
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            // XML 1.0 has no way to carry these; they come only from a
            // reason or a message, where a space loses nothing.
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Nanoseconds since the epoch as RFC 3339, UTC, whole seconds.
pub fn rfc3339(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 4])
    }

    #[test]
    fn rfc3339_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000_000_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(951_782_400_000_000_000), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(4_102_444_799_000_000_000), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn escapes_xml_and_drops_control_characters() {
        assert_eq!(esc("a<b>&\"c\"\u{1}d\n"), "a&lt;b&gt;&amp;&quot;c&quot; d\n");
    }

    /// A repo's feed: valid Atom, newest first, capped.
    #[test]
    fn repo_feed_is_atom_newest_first() {
        store::create_repo("feed-a").unwrap();
        let res = serve(Some("feed-a"), None);
        assert_eq!(res.status_code, 200);
        let body = String::from_utf8(res.body).unwrap();
        assert!(body.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<feed xmlns=\"http://www.w3.org/2005/Atom\">"));
        assert!(body.contains("<title>feed-a on ic-git</title>"));
        assert!(body.contains("href=\"https://aaaaa-aa.raw.icp0.io/feed/feed-a\""));
        assert!(!body.contains("<entry>"));

        let feed = Feed::Repo("feed-a".into());
        for i in 0..(MAX_EVENTS + 5) {
            tenancy::set_test_now(1_700_000_000_000_000_000 + i as u64 * 1_000_000_000);
            one(&feed, "ballot", format!("event {i}"), "<detail & more>".into(), None, Some(&p(1)));
        }
        let res = serve(Some("feed-a"), Some("localhost:4943"));
        let body = String::from_utf8(res.body).unwrap();
        assert!(body.contains("href=\"http://localhost:4943/feed/feed-a\""));
        assert_eq!(body.matches("<entry>").count(), MAX_EVENTS);
        let first = body.find("event 204").unwrap();
        let second = body.find("event 203").unwrap();
        assert!(first < second, "newest first");
        assert!(!body.contains("event 4\n") && !body.contains(">event 4<"), "the oldest fell off");
        assert!(body.contains("&lt;detail &amp; more&gt;"));
        assert!(body.contains(&format!("<author><name>{}</name></author>", p(1))));
        assert!(body.contains("<updated>2023-11-14T22:16:44Z</updated>"), "{body}");
        assert!(body.contains("<id>urn:ic-git:aaaaa-aa:repo:feed-a:204</id>"));
        assert_eq!(serve(Some("no-such-feed"), None).status_code, 404);
    }

    /// The governor mirror reports each proposal, ballot, threshold and
    /// outcome once, in time order, and moves its cursor past the log.
    #[test]
    fn governor_mirror_reports_each_change_once() {
        let up = Change::Upgrade { commit: "a".repeat(40), module_sha256: "b".repeat(64) };
        let ballot = |who: u8, at: u64, d: Vote, reason: Option<&str>| GovBallot {
            approver: p(who),
            decision: d,
            reason: reason.map(str::to_string),
            at_ns: at,
        };
        let proposal = |ballots: Vec<GovBallot>, reached: bool, last_error: Option<&str>| GovProposal {
            id: 7,
            change: up.clone(),
            proposer: p(1),
            at_ns: 100,
            count: GovCount { approvals: ballots.len() as u32, objections: 0, required: 2, reached },
            ballots,
            last_error: last_error.map(str::to_string),
        };
        let mut m = Mirror::default();
        // First look: a proposal with one ballot.
        let new = reconcile(&mut m, &[proposal(vec![ballot(1, 110, Vote::Approve, None)], false, None)], &[]);
        let kinds: Vec<_> = new.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["proposal", "ballot"]);
        assert!(new[0].title.contains("proposal 7: upgrade ic-git to commit aaaaaaaaaaaa"));
        // Nothing changed: nothing new.
        assert!(reconcile(&mut m, &[proposal(vec![ballot(1, 110, Vote::Approve, None)], false, None)], &[]).is_empty());
        // An objection with a reason, then the ballot that reaches K.
        let new = reconcile(
            &mut m,
            &[proposal(vec![ballot(1, 110, Vote::Approve, None), ballot(2, 120, Vote::Object, Some("not rebuilt"))], false, None)],
            &[],
        );
        assert_eq!(new.len(), 1);
        assert!(new[0].detail.ends_with("Reason: not rebuilt"), "{}", new[0].detail);
        let new = reconcile(
            &mut m,
            &[proposal(
                vec![ballot(1, 110, Vote::Approve, None), ballot(2, 130, Vote::Approve, None), ballot(3, 140, Vote::Approve, None)],
                true,
                Some("install rejected"),
            )],
            &[],
        );
        let kinds: Vec<_> = new.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["ballot", "ballot", "reached", "deploy-failed"]);
        // The same error again is not news; it is executed from the log, and
        // a proposal that opened and closed between polls is reported whole.
        let page = GovLogPage {
            entries: vec![
                GovLogEntry {
                    id: 7,
                    change: up.clone(),
                    proposer: p(1),
                    ballots: vec![ballot(1, 110, Vote::Approve, None), ballot(2, 130, Vote::Approve, None), ballot(3, 140, Vote::Approve, None)],
                    at_ns: 150,
                    outcome: "executed: upgraded".into(),
                },
                GovLogEntry {
                    id: 8,
                    change: Change::Handover { successor: p(9) },
                    proposer: p(2),
                    ballots: vec![ballot(2, 160, Vote::Approve, None)],
                    at_ns: 170,
                    outcome: "withdrawn".into(),
                },
            ],
            next: None,
        };
        let new = reconcile(&mut m, &[], &[page]);
        let kinds: Vec<_> = new.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["executed", "proposal", "ballot", "withdrawn"]);
        assert_eq!(m.cursor, 2);
        assert!(m.open.is_empty());
        assert!(new[3].detail.contains("hand ic-git over to"));
    }

    /// A padded reason is recorded trimmed, as the ballot holds it, and a
    /// blank one as none.
    #[test]
    fn reasons_are_trimmed_in_the_feed() {
        assert_eq!(with_reason("x".into(), Some(&format!("  {}  \n", "padded"))), "x. Reason: padded");
        assert_eq!(with_reason("x".into(), Some("   ")), "x");
        assert_eq!(with_reason("x".into(), None), "x");
    }

    /// Naming a different governor resets the mirror and bumps its
    /// generation, which a poll in flight checks; the same governor again
    /// keeps it.
    #[test]
    fn set_governor_resets_the_mirror_once_per_change() {
        store::meta_set_json(MIRROR_KEY, &Mirror { generation: 3, cursor: 9, open: BTreeMap::new() });
        set_governor(Some(p(1)));
        assert_eq!(governor(), Some(p(1)));
        assert_eq!(mirror(), Mirror { generation: 4, cursor: 0, open: BTreeMap::new() });
        store::meta_set_json(MIRROR_KEY, &Mirror { generation: 4, cursor: 2, open: BTreeMap::new() });
        set_governor(Some(p(1)));
        assert_eq!(mirror().cursor, 2, "the same governor keeps the mirror");
        set_governor(None);
        assert_eq!(governor(), None);
        assert_eq!(mirror().generation, 5);
    }

    /// The canister's own feed takes the canister record; a repo's record
    /// goes to the repo, whatever its suffix.
    #[test]
    fn published_records_land_in_the_right_feed() {
        store::create_repo("feed-b").unwrap();
        published("feed-b#site", &"c".repeat(40), "0xtx1");
        published("feed-b", &"d".repeat(40), "0xtx2");
        published(crate::provenance::CANISTER_KEY, &"e".repeat(40), "0xtx3");
        let repo = events(&Feed::Repo("feed-b".into()));
        assert_eq!(repo.len(), 2);
        assert!(repo[0].title.starts_with("record feed-b#site published"));
        let own = events(&Feed::Canister);
        assert!(own.iter().any(|e| e.detail.contains("0xtx3")));
        assert!(String::from_utf8(serve(None, None).body).unwrap().contains("<title>ic-git</title>"));
    }

    /// A push to a gated repo reports the unapproved tip once; a ballot that
    /// reaches the threshold reports the ballot and the threshold.
    #[test]
    fn push_and_ballots_on_a_gated_repo() {
        let owner = p(5);
        tenancy::credit(&owner, 10_000_000_000);
        tenancy::create_repo("feed-c", &owner, false).unwrap();
        tenancy::set_required_votes("feed-c", &owner, false, 1).unwrap();
        let commit = store::put_object(store::ObjectType::Commit, b"tree 0000000000000000000000000000000000000000\n\nfirst\n");
        let before = store::get_ref("feed-c", "refs/heads/main");
        store::set_ref("feed-c", "refs/heads/main", commit).unwrap();
        after_push("feed-c", before.clone());
        after_push("feed-c", Some(commit)); // the branch did not move
        let ev = events(&Feed::Repo("feed-c".into()));
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].kind, "awaiting");
        assert!(ev[0].detail.contains("needs 0 of 1"), "{}", ev[0].detail);

        let hex = store::oid_hex(&commit);
        let was = tenancy::tally("feed-c", &hex).map_or(false, |t| t.reached);
        let t = tenancy::cast_ballot("feed-c", &owner, &hex, Vote::Approve, Some("looks right".into())).unwrap();
        ballot("feed-c", &owner, &hex, Vote::Approve, Some("looks right"), &t, was);
        let ev = events(&Feed::Repo("feed-c".into()));
        let kinds: Vec<_> = ev.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, ["awaiting", "ballot", "reached"]);
        assert!(ev[1].detail.ends_with("Reason: looks right"));
        assert_eq!(ev[1].actor.as_deref(), Some(owner.to_text().as_str()));
    }
}
