//! The move of the git side's state to the git canister
//! (docs/CANISTER_SPLIT.md, phase 3 step 13): the freeze, the paged export,
//! the import that pulls the pages, and the digest each side computes over
//! its own copy.
//!
//! **The freeze.** An operator switch (`freeze`) puts the git side in
//! read-only mode. What writes it from outside is refused with `FROZEN`,
//! which names the cut: pushes, token minting, `create_repo`, `set_site`
//! and the object admin calls (the canister endpoints check, so the
//! refusal comes before any charge; this side's `GitSide` refuses the
//! authority's asks; and `store::set_ref`, `store::create_repo` and
//! `tokens::mint` refuse too, the backstop behind a write path the
//! endpoints do not gate). Reads go on: fetches,
//! `/site/`, `/api`, the token listings. What the authority decides
//! (membership, ballots, signing policy) stays open, since it reaches this
//! side only through the mirrors, which the authority rewrites at the cut
//! and which are not copied.
//!
//! **The export.** `export_page` walks every git-side record in a fixed
//! order -- repos, refs, objects, push tokens, labels, site configs (`Kind`)
//! -- and in key order within each, a page at a time, each page naming
//! where the next starts (`Cursor`). It is an update call, so a canister
//! that pulls the pages gets what this one replied, through consensus.
//! Operators may read it, and so may the one importing canister an
//! operator names (`set_importer`). Only a frozen store is exported: the
//! copy of a moving one would be of no moment in particular.
//!
//! **The import.** The git canister, frozen itself, pulls the pages from
//! the canister an operator names (`import_start`) on a timer chain, one
//! page a tick, and applies each: an object is taken only if its bytes
//! hash to its id, a label or site config only under its own META prefix,
//! so a wrong page cannot write anything else. Every kind but tokens only
//! grows on a frozen exporter, so the copy is add-only and an import can
//! be run again; tokens can still go (a revoke, or a membership change
//! through the mirrors), so an import that starts over drops the tokens it
//! holds first. `import_status` says how far it is; a page that could not
//! be pulled stops the chain with its error on record, and `import_start`
//! again resumes from the page it stopped at.
//!
//! **The digest.** `digest_step` folds the same walk into one hash, a page
//! a step, so a store of any size is digested across messages: for each
//! record `acc = sha256(acc, kind, len(key), key, len(value), value)`, in
//! order, with the record count and bytes beside it. The importer digests
//! its copy once every page is taken; an operator steps the exporter's.
//! The cut proceeds when the two agree, and only then. A thaw clears the
//! digest, since what it was of has moved on.
//!
//! What is not copied: the push-certificate seed (a secret; the git
//! canister makes its own, and a nonce lives for minutes), the mirrors
//! (rewritten at the cut), the outbox (drained before it), the served
//! commits (derived from refs and the mirrors), and the operators (each
//! canister keeps its own).

use crate::{kv, store, tokens};
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::cell::Cell;

const FROZEN_KEY: &str = "transfer:frozen";
const IMPORTER_KEY: &str = "transfer:importer";
const DIGEST_KEY: &str = "transfer:digest";
const IMPORT_KEY: &str = "transfer:import";

/// Why a write is refused while the git side is frozen.
pub const FROZEN: &str = "the git side is frozen for its move to the git canister (docs/CANISTER_SPLIT.md, step 16): \
                          pushes, push tokens, new repos, site configs and the object admin calls wait for the cut";

/// The most bytes of keys and values one exported page carries: under half
/// the message limit, leaving candid's framing and the rest of the reply
/// room to spare.
pub const PAGE_BYTES: usize = 1 << 20;

/// The most bytes of keys and values one digest step reads. A step is a
/// message of its own, with its own instruction limit; hashing is cheap
/// against reading, so a step takes more than a page.
pub const DIGEST_BYTES: usize = 4 << 20;

/// The largest record a page can carry and still be replied: one object
/// could in principle outgrow it (deltas resolved at ingest can make an
/// object larger than any one pushed pack), and such a record is refused
/// by name rather than lost in a reply the system drops.
pub const MAX_RECORD: usize = 3 << 19;

// --- the freeze --------------------------------------------------------------

pub fn frozen() -> bool {
    kv::get_json::<bool>(FROZEN_KEY).unwrap_or(false)
}

/// Refused while frozen, with the message that names the cut.
pub fn check_unfrozen() -> Result<(), String> {
    if frozen() {
        Err(FROZEN.to_string())
    } else {
        Ok(())
    }
}

/// Refused unless frozen: the export and the digest are of a store that
/// does not move.
fn check_frozen() -> Result<(), String> {
    if frozen() {
        Ok(())
    } else {
        Err("freeze first: the export and its digest are of a store that does not move".to_string())
    }
}

/// Freeze the git side. Idempotent.
pub fn freeze() -> Result<(), String> {
    kv::set_json(FROZEN_KEY, &true);
    Ok(())
}

/// Thaw it, and forget the digest, which was of the frozen store. Refused
/// while an import runs here: it digests what it copied once it has it.
pub fn unfreeze() -> Result<(), String> {
    if import_running() {
        return Err("an import is running; it finishes frozen".to_string());
    }
    kv::remove(FROZEN_KEY);
    kv::remove(DIGEST_KEY);
    Ok(())
}

// --- the importer -----------------------------------------------------------

/// Name the one canister that may read the export besides operators.
/// `me` is this canister, which cannot import from itself.
pub fn set_importer(importer: Principal, me: Principal) -> Result<(), String> {
    if importer == Principal::anonymous() {
        return Err("the importer cannot be the anonymous principal".to_string());
    }
    if importer == me {
        return Err("this canister cannot be its own importer".to_string());
    }
    kv::set_json(IMPORTER_KEY, &importer.to_text());
    Ok(())
}

pub fn importer() -> Option<Principal> {
    kv::get_json::<String>(IMPORTER_KEY).and_then(|t| Principal::from_text(t).ok())
}

/// Who may read the export: an operator (`operator` is the canister's own
/// rule, applied to the caller), or the named importer.
pub fn may_export(caller: &Principal, operator: bool) -> Result<(), String> {
    if operator || importer() == Some(*caller) {
        Ok(())
    } else {
        Err("only an operator or the named importer may read the export".to_string())
    }
}

// --- the records ------------------------------------------------------------

/// What the git side holds, in the order it is walked.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Repo name -> HEAD target.
    Repos,
    /// "<repo>\0<refname>" -> the 20 bytes of the oid.
    Refs,
    /// The 20 bytes of the oid -> the stored value (type code, length,
    /// zlib stream).
    Objects,
    /// hex(sha256(token)) -> the record (tokens.rs).
    Tokens,
    /// META "label:<label>" -> the holder's name.
    Labels,
    /// META "site:<repo>" -> the site config.
    Sites,
}

/// Entries of one kind as a page carries them: key and value bytes.
type Entries = Vec<(Vec<u8>, Vec<u8>)>;

impl Kind {
    const ALL: [Kind; 6] = [Kind::Repos, Kind::Refs, Kind::Objects, Kind::Tokens, Kind::Labels, Kind::Sites];

    fn next(self) -> Option<Kind> {
        Kind::ALL.iter().skip_while(|k| **k != self).nth(1).copied()
    }

    /// The META prefix of a kind kept there.
    fn prefix(self) -> Option<&'static str> {
        match self {
            Kind::Labels => Some("label:"),
            Kind::Sites => Some("site:"),
            _ => None,
        }
    }

    /// A page of this kind's records after `after` (a key of this kind, as
    /// a cursor carries it), within `budget`.
    fn page(self, after: Option<&[u8]>, budget: usize) -> Result<Entries, String> {
        // Every kind but objects is keyed by text.
        let text = || {
            after
                .map(|b| String::from_utf8(b.to_vec()).map_err(|_| "the cursor is not a key of this kind".to_string()))
                .transpose()
        };
        let out: Entries = match self {
            Kind::Repos => store::export_repos(text()?.as_ref(), budget)
                .into_iter()
                .map(|(k, v)| (k.into_bytes(), v.into_bytes()))
                .collect(),
            Kind::Refs => store::export_refs(text()?.as_ref(), budget)
                .into_iter()
                .map(|(k, v)| (k.into_bytes(), v.as_slice().to_vec()))
                .collect(),
            Kind::Objects => {
                // Blob<20> takes anything shorter too, so the length is
                // checked here.
                let after = match after {
                    Some(a) if a.len() == 20 => Some(ic_git_types::oid::Oid::try_from(a).unwrap()),
                    Some(_) => return Err("the cursor is not an oid".to_string()),
                    None => None,
                };
                store::export_objects(after.as_ref(), budget)
                    .into_iter()
                    .map(|(k, v)| (k.as_slice().to_vec(), v))
                    .collect()
            }
            Kind::Tokens => store::export_tokens(text()?.as_ref(), budget)
                .into_iter()
                .map(|(k, v)| (k.into_bytes(), v.into_bytes()))
                .collect(),
            Kind::Labels | Kind::Sites => {
                // A cursor outside the prefix would start the range
                // elsewhere and end the kind with records left.
                let prefix = self.prefix().unwrap();
                let after = text()?;
                if after.as_deref().is_some_and(|a| !a.starts_with(prefix)) {
                    return Err(format!("the cursor is not a {self:?} key: it does not start with {prefix:?}"));
                }
                kv::export_prefix(prefix, after.as_deref(), budget)
                    .into_iter()
                    .map(|(k, v)| (k.into_bytes(), v))
                    .collect()
            }
        };
        if let Some((k, v)) = out.iter().find(|(k, v)| k.len() + v.len() > MAX_RECORD) {
            return Err(format!(
                "the {self:?} record {} is {} bytes, over the {MAX_RECORD} a page can carry",
                hex::encode(k),
                k.len() + v.len()
            ));
        }
        Ok(out)
    }
}

/// Where a page starts: the records of `kind` after the key `after`, or
/// its first when `after` is none. No cursor at all means the beginning.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Cursor {
    pub kind: Kind,
    pub after: Option<Vec<u8>>,
}

/// One record, as its map holds it.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Record {
    pub kind: Kind,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A page of the walk: its records, and where the next page starts, or
/// nothing when this was the last.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct Page {
    pub records: Vec<Record>,
    pub next: Option<Cursor>,
}

/// The walk from `cursor`, within `budget` bytes of keys and values; a
/// kind that runs out within the budget is followed by the next.
fn walk(cursor: Option<Cursor>, budget: usize) -> Result<Page, String> {
    let (mut kind, mut after) = match cursor {
        None => (Kind::Repos, None),
        Some(c) => (c.kind, c.after),
    };
    let mut records = Vec::new();
    let mut used = 0;
    loop {
        let entries = kind.page(after.as_deref(), budget.saturating_sub(used).max(1))?;
        let Some((last, _)) = entries.last() else {
            match kind.next() {
                Some(k) => {
                    kind = k;
                    after = None;
                    continue;
                }
                None => return Ok(Page { records, next: None }),
            }
        };
        after = Some(last.clone());
        for (key, value) in entries {
            used += key.len() + value.len();
            records.push(Record { kind, key, value });
        }
        if used >= budget {
            return Ok(Page { records, next: Some(Cursor { kind, after }) });
        }
    }
}

/// A page of the export (operators and the importer; the canister checks
/// `may_export`). From the beginning with no cursor, else from where the
/// last page said.
pub fn export_page(cursor: Option<Cursor>) -> Result<Page, String> {
    check_frozen()?;
    walk(cursor, PAGE_BYTES)
}

/// Take one exported record in. Each kind's write checks what it can:
/// the key's shape, and for an object that its bytes are the object.
fn apply(r: &Record) -> Result<(), String> {
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| format!("a {:?} key or value is not text", r.kind));
    match r.kind {
        Kind::Repos => {
            store::import_repo(text(&r.key)?, text(&r.value)?);
            Ok(())
        }
        Kind::Refs => {
            let oid = ic_git_types::oid::Oid::try_from(r.value.as_slice()).ok().filter(|o| o.as_slice().len() == 20);
            store::import_ref(text(&r.key)?, oid.ok_or("a ref's value is an oid of 20 bytes")?)
        }
        Kind::Objects => {
            let oid = ic_git_types::oid::Oid::try_from(r.key.as_slice()).ok().filter(|o| o.as_slice().len() == 20);
            store::import_object(oid.ok_or("an object's key is an oid of 20 bytes")?, r.value.clone())
        }
        Kind::Tokens => {
            tokens::import_record(&text(&r.key)?, text(&r.value)?);
            Ok(())
        }
        Kind::Labels | Kind::Sites => {
            let key = text(&r.key)?;
            let prefix = r.kind.prefix().unwrap();
            if !key.starts_with(prefix) {
                return Err(format!("a {:?} record's key starts with {prefix:?}, not {key:?}", r.kind));
            }
            kv::set_bytes(&key, r.value.clone());
            Ok(())
        }
    }
}

// --- the digest -------------------------------------------------------------

/// How far the digest is: the walk's next page, what it has folded so far.
#[derive(Serialize, Deserialize, Clone)]
struct DigestState {
    next: Option<Cursor>,
    done: bool,
    records: u64,
    bytes: u64,
    /// The running hash, hex.
    acc: String,
}

/// The digest as reported: the count and bytes of the records folded so
/// far, and the hash once every record is in.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct Digest {
    pub done: bool,
    pub records: u64,
    pub bytes: u64,
    pub sha256: Option<String>,
}

fn digest_state() -> Option<DigestState> {
    kv::get_json(DIGEST_KEY)
}

fn report(st: &DigestState) -> Digest {
    Digest {
        done: st.done,
        records: st.records,
        bytes: st.bytes,
        sha256: st.done.then(|| st.acc.clone()),
    }
}

/// The digest so far, if one was started since the freeze.
pub fn digest() -> Option<Digest> {
    digest_state().as_ref().map(report)
}

/// Fold one record into the running hash.
fn fold(acc: &[u8], r: &Record) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(acc);
    h.update([r.kind as u8]);
    h.update((r.key.len() as u64).to_le_bytes());
    h.update(&r.key);
    h.update((r.value.len() as u64).to_le_bytes());
    h.update(&r.value);
    h.finalize().into()
}

/// One step of the digest (operators and the importer): the next
/// `budget` bytes of the walk folded in. The first step starts it; a step
/// after the last answers the finished digest again.
fn digest_step_with(budget: usize) -> Result<Digest, String> {
    check_frozen()?;
    let mut st = digest_state().unwrap_or(DigestState {
        next: None,
        done: false,
        records: 0,
        bytes: 0,
        acc: hex::encode([0u8; 32]),
    });
    if st.done {
        return Ok(report(&st));
    }
    let page = walk(st.next.clone(), budget)?;
    let mut acc: [u8; 32] = hex::decode(&st.acc)
        .ok()
        .and_then(|a| a.try_into().ok())
        .ok_or("the digest's state is unreadable; unfreeze and freeze to start it again")?;
    for r in &page.records {
        acc = fold(&acc, r);
        st.records += 1;
        st.bytes += (r.key.len() + r.value.len()) as u64;
    }
    st.acc = hex::encode(acc);
    st.done = page.next.is_none();
    st.next = page.next;
    kv::set_json(DIGEST_KEY, &st);
    Ok(report(&st))
}

pub fn digest_step() -> Result<Digest, String> {
    digest_step_with(DIGEST_BYTES)
}

// --- the import -------------------------------------------------------------

/// How far the import is: whose pages, where the next starts, what it
/// has taken, and why it stopped if it did.
#[derive(Serialize, Deserialize, Clone)]
struct ImportState {
    source: String,
    next: Option<Cursor>,
    copied: bool,
    pages: u64,
    records: u64,
    bytes: u64,
    error: Option<String>,
}

/// The import as reported.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct ImportStatus {
    pub source: Principal,
    /// A tick is in flight or armed. False once every page and digest
    /// step is done, or a page could not be pulled (`error` says).
    pub running: bool,
    pub pages: u64,
    pub records: u64,
    pub bytes: u64,
    /// Every page taken; the digest of the copy follows.
    pub copied: bool,
    pub error: Option<String>,
    /// The copy's digest, once `copied`.
    pub digest: Option<Digest>,
}

thread_local! {
    /// True from `import_start` until the chain of ticks ends. Heap
    /// state: an upgrade clears it, and an operator starts the import
    /// again, which resumes.
    static IMPORTING: Cell<bool> = const { Cell::new(false) };
}

fn import_running() -> bool {
    IMPORTING.with(|f| f.get())
}

fn import_state() -> Option<ImportState> {
    kv::get_json(IMPORT_KEY)
}

fn save_import(st: &ImportState) {
    kv::set_json(IMPORT_KEY, st);
}

pub fn import_status() -> Option<ImportStatus> {
    let st = import_state()?;
    Some(ImportStatus {
        source: Principal::from_text(&st.source).ok()?,
        running: import_running(),
        pages: st.pages,
        records: st.records,
        bytes: st.bytes,
        copied: st.copied,
        error: st.error,
        digest: st.copied.then(digest).flatten(),
    })
}

/// Start, or resume, the import from `source` (operators). This canister
/// must be frozen, so its copy holds still for the digest. An import on
/// record from the same source that stopped short of the last page
/// resumes from the page it stopped at; one that has every page starts
/// over, so a copy that did not match can be pulled again (the tokens
/// dropped first; the rest is add-only). An import from another source is
/// refused until `import_reset`.
pub fn import_start(source: Principal, me: Principal) -> Result<(), String> {
    if source == me {
        return Err("this canister cannot import from itself".to_string());
    }
    if source == Principal::anonymous() {
        return Err("the source cannot be the anonymous principal".to_string());
    }
    if !frozen() {
        return Err("freeze this canister first: the copy holds still for its digest".to_string());
    }
    if import_running() {
        return Err("the import is running; import_status says how far".to_string());
    }
    let fresh = ImportState {
        source: source.to_text(),
        next: None,
        copied: false,
        pages: 0,
        records: 0,
        bytes: 0,
        error: None,
    };
    let st = match import_state() {
        Some(st) if st.source != fresh.source => {
            return Err(format!("an import from {} is on record; import_reset before importing from {source}", st.source));
        }
        Some(st) if !st.copied => ImportState { error: None, ..st },
        // Every page in: start over, the tokens of the last pull dropped
        // first. A first import clears nothing: what this canister holds
        // of its own, tokens included, is its own, and the digest will
        // say whether the copy is the original alone.
        Some(_) => {
            store::clear_tokens();
            kv::remove(DIGEST_KEY);
            fresh
        }
        None => fresh,
    };
    save_import(&st);
    arm_import();
    Ok(())
}

/// Forget the import on record (operators), not what it copied. Refused
/// while it runs.
pub fn import_reset() -> Result<(), String> {
    if import_running() {
        return Err("the import is running; it cannot be reset meanwhile".to_string());
    }
    kv::remove(IMPORT_KEY);
    Ok(())
}

/// One step: the next page pulled by `fetch` and applied, or, every page
/// taken, one step of the copy's digest. Answers whether more remains.
async fn import_step(fetch: impl AsyncFn(Principal, Option<Cursor>) -> Result<Page, String>) -> Result<bool, String> {
    let Some(st) = import_state() else {
        return Ok(false);
    };
    if st.copied {
        return Ok(!digest_step()?.done);
    }
    let source = Principal::from_text(&st.source).map_err(|e| format!("the source on record does not parse: {e}"))?;
    let cursor = st.next.clone();
    let page = fetch(source, cursor.clone()).await?;
    // Reset while the page was on its way: the page is not for this import.
    let Some(mut st) = import_state() else {
        return Ok(false);
    };
    if st.copied || st.next != cursor {
        return Ok(false);
    }
    for r in &page.records {
        apply(r)?;
    }
    st.pages += 1;
    st.records += page.records.len() as u64;
    st.bytes += page.records.iter().map(|r| (r.key.len() + r.value.len()) as u64).sum::<u64>();
    st.copied = page.next.is_none();
    st.next = page.next;
    if st.copied {
        // The copy's digest starts now: one an operator stepped while the
        // pages were still coming was of less than the copy.
        kv::remove(DIGEST_KEY);
    }
    save_import(&st);
    Ok(true)
}

/// A step, with a failure put on record: the chain stops there, and
/// `import_start` resumes it.
pub async fn import_tick(fetch: impl AsyncFn(Principal, Option<Cursor>) -> Result<Page, String>) -> bool {
    match import_step(fetch).await {
        Ok(more) => more,
        Err(e) => {
            if let Some(mut st) = import_state() {
                st.error = Some(e);
                save_import(&st);
            }
            false
        }
    }
}

/// Resets the running flag when a tick ends, however it ends: a trap in a
/// callback drops the future, and the flag must not outlive it.
#[cfg(not(any(test, feature = "testing")))]
struct Importing;

#[cfg(not(any(test, feature = "testing")))]
impl Drop for Importing {
    fn drop(&mut self) {
        IMPORTING.with(|f| f.set(false));
    }
}

/// The exporter's `export_page`, by a bounded-wait call: a page is at most
/// `PAGE_BYTES` and a cursor names it, so a lost answer is asked for again.
#[cfg(not(any(test, feature = "testing")))]
async fn fetch_page(source: Principal, cursor: Option<Cursor>) -> Result<Page, String> {
    let fail = |e: String| format!("export_page of {source}: {e}");
    let reply: Result<Page, String> = ic_cdk::call::Call::bounded_wait(source, "export_page")
        .with_arg(cursor)
        .await
        .map_err(|e| fail(e.to_string()))?
        .candid()
        .map_err(|e| fail(e.to_string()))?;
    reply.map_err(|e| format!("{source} refused the export: {e}"))
}

/// Run the next tick as soon as the canister is idle, and the one after
/// it when that is done: each tick is a message of its own, so a copy of
/// any size crosses within the limits of one.
#[cfg(not(any(test, feature = "testing")))]
fn arm_import() {
    if IMPORTING.with(|f| f.replace(true)) {
        return;
    }
    ic_cdk_timers::set_timer(std::time::Duration::ZERO, async {
        let importing = Importing;
        if import_tick(fetch_page).await {
            drop(importing);
            arm_import();
        }
    });
}

/// Tests drive the ticks themselves; a timer cannot fire outside a
/// canister. The running flag is theirs to set (`set_running_for_tests`).
#[cfg(any(test, feature = "testing"))]
fn arm_import() {}

#[cfg(any(test, feature = "testing"))]
pub fn set_running_for_tests(running: bool) {
    IMPORTING.with(|f| f.set(running));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::for_authority::Git;
    use crate::store::ObjectType;
    use futures::executor::block_on;
    use ic_git_types::git_side::GitSide;
    use std::cell::RefCell;

    fn alice() -> Principal {
        Principal::from_slice(&[9; 8])
    }

    fn me() -> Principal {
        Principal::from_slice(&[1; 8])
    }

    fn other() -> Principal {
        Principal::from_slice(&[2; 8])
    }

    /// A store with something of every kind: two repos (one whose label
    /// differs from its name), their refs and objects, a token each, a
    /// site config.
    fn seed() {
        store::create_repo("mover").unwrap();
        store::create_repo("Other.App").unwrap();
        let c1 = store::commit_file_for_tests("mover", "a.txt", b"alpha", None);
        store::commit_file_for_tests("mover", "b.txt", &vec![7u8; 3000], Some(c1));
        store::set_ref("mover", "refs/tags/v1", c1).unwrap();
        store::commit_file_for_tests("Other.App", "index.html", b"<h1>hi</h1>", None);
        tokens::mint("mover", "tok-mover", alice(), Some(5), None).unwrap();
        tokens::mint("Other.App", "tok-other", alice(), Some(5), None).unwrap();
        crate::site::set_config("Other.App", "/".into()).unwrap();
    }

    fn all(budget: usize) -> Vec<Record> {
        let mut cursor = None;
        let mut out = Vec::new();
        loop {
            let page = walk(cursor, budget).unwrap();
            out.extend(page.records);
            match page.next {
                Some(c) => cursor = Some(c),
                None => return out,
            }
        }
    }

    /// Frozen, the writes the authority asks for and the message every
    /// refused write carries; thawed, they go through again.
    #[test]
    fn the_freeze_refuses_the_writes_and_names_the_cut() {
        static GIT: Git = Git { is_operator: |_| false };
        assert!(!frozen());
        assert_eq!(check_unfrozen(), Ok(()));
        store::create_repo("cold").unwrap();
        freeze().unwrap();
        assert!(frozen());
        let err = check_unfrozen().unwrap_err();
        assert!(err.contains("step 16") && err.contains("pushes"), "{err}");
        assert_eq!(block_on(GIT.check_new_repo("warm")), Ok(Err(FROZEN.into())));
        assert_eq!(block_on(GIT.create_repo("warm")), Ok(Err(FROZEN.into())));
        assert_eq!(block_on(GIT.create_repo("cold")), Ok(Ok(())), "a repo that exists is the authority's own earlier call");
        assert_eq!(block_on(GIT.set_site("cold", "".into())), Ok(Err(FROZEN.into())));
        assert!(!store::repo_exists("warm"));
        assert!(crate::site::get_config("cold").is_none());
        unfreeze().unwrap();
        assert_eq!(block_on(GIT.create_repo("warm")), Ok(Ok(())));
        assert_eq!(block_on(GIT.set_site("cold", "".into())), Ok(Ok(())));
    }

    /// Only operators and the named importer read the export, and only
    /// of a frozen store; the importer is named once each time and is
    /// never this canister.
    #[test]
    fn the_export_is_read_by_operators_and_the_named_importer_of_a_frozen_store() {
        assert_eq!(may_export(&alice(), true), Ok(()));
        assert!(may_export(&alice(), false).unwrap_err().contains("named importer"));
        assert!(set_importer(me(), me()).unwrap_err().contains("own importer"));
        assert!(set_importer(Principal::anonymous(), me()).is_err());
        set_importer(alice(), me()).unwrap();
        assert_eq!(importer(), Some(alice()));
        assert_eq!(may_export(&alice(), false), Ok(()));
        assert!(may_export(&other(), false).is_err());
        assert!(export_page(None).unwrap_err().contains("freeze first"));
        assert!(digest_step().unwrap_err().contains("freeze first"));
        freeze().unwrap();
        assert!(export_page(None).is_ok());
    }

    /// The walk visits every record, kinds in their order and keys in
    /// theirs, the same however small the pages; a page always advances;
    /// a cursor that is not a key of its kind is refused.
    #[test]
    fn the_export_walks_every_record_in_order_however_it_is_paged() {
        seed();
        freeze().unwrap();
        let whole = all(usize::MAX);
        let paged = all(64);
        assert_eq!(whole, paged);
        let kinds: Vec<Kind> = whole.iter().map(|r| r.kind).collect();
        assert!(kinds.windows(2).all(|w| w[0] <= w[1]), "kinds in order");
        for kind in Kind::ALL {
            let keys: Vec<&Vec<u8>> = whole.iter().filter(|r| r.kind == kind).map(|r| &r.key).collect();
            assert!(keys.windows(2).all(|w| w[0] < w[1]), "{kind:?} keys in order");
        }
        let count = |k: Kind| whole.iter().filter(|r| r.kind == k).count();
        assert_eq!(count(Kind::Repos), 2);
        assert_eq!(count(Kind::Refs), 3);
        assert_eq!(count(Kind::Objects), 9, "three commits, each with its tree and blob");
        assert_eq!(count(Kind::Tokens), 2);
        assert_eq!(count(Kind::Labels), 2);
        assert_eq!(count(Kind::Sites), 1);
        assert!(whole.iter().any(|r| r.kind == Kind::Labels && r.key == b"label:other-app"));
        assert!(whole.iter().any(|r| r.kind == Kind::Sites && r.key == b"site:Other.App"));
        // The first page of a small budget stops after one record and
        // says where the next starts.
        let first = export_page(None).unwrap();
        assert!(first.next.is_none(), "everything fits in one real page");
        let small = walk(None, 1).unwrap();
        assert_eq!(small.records.len(), 1);
        assert_eq!(small.next, Some(Cursor { kind: Kind::Repos, after: Some(b"Other.App".to_vec()) }));
        assert!(walk(Some(Cursor { kind: Kind::Objects, after: Some(vec![1, 2, 3]) }), 1).unwrap_err().contains("not an oid"));
        assert!(walk(Some(Cursor { kind: Kind::Repos, after: Some(vec![0xff]) }), 1).unwrap_err().contains("not a key"));
        assert!(walk(Some(Cursor { kind: Kind::Labels, after: Some(b"a".to_vec()) }), 1).unwrap_err().contains("label:"));
        assert!(walk(Some(Cursor { kind: Kind::Sites, after: Some(b"label:x".to_vec()) }), 1).unwrap_err().contains("site:"));
        // A page never takes a second record that would put it over the
        // budget: with the 3000-byte blob among records of a few dozen
        // bytes, no page of 3100 holds more than that blob and what fit
        // before it.
        let mut cursor = None;
        loop {
            let page = walk(cursor, 3100).unwrap();
            let bytes: usize = page.records.iter().map(|r| r.key.len() + r.value.len()).sum();
            assert!(bytes <= 3100 || page.records.len() == 1, "{bytes} bytes in {} records", page.records.len());
            match page.next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
    }

    /// While a chain of ticks runs, nothing that would pull the store from
    /// under it goes through: the thaw, another start, the reset.
    #[test]
    fn a_running_import_refuses_the_thaw_another_start_and_the_reset() {
        freeze().unwrap();
        import_start(other(), me()).unwrap();
        set_running_for_tests(true);
        assert!(import_status().unwrap().running);
        assert!(unfreeze().unwrap_err().contains("running"));
        assert!(import_start(other(), me()).unwrap_err().contains("running"));
        assert!(import_reset().unwrap_err().contains("running"));
        assert!(frozen());
        set_running_for_tests(false);
        assert!(!import_status().unwrap().running);
        import_reset().unwrap();
        unfreeze().unwrap();
    }

    /// A canister's own tokens survive its first import; a pull that
    /// starts over drops only what the last pull brought.
    #[test]
    fn a_first_import_keeps_the_canisters_own_tokens() {
        store::create_repo("mine").unwrap();
        tokens::mint("mine", "tok-mine", alice(), Some(5), None).unwrap();
        freeze().unwrap();
        import_start(other(), me()).unwrap();
        assert_eq!(tokens::list("mine").len(), 1, "a first import clears nothing");
        let empty = Page { records: vec![], next: None };
        assert!(block_on(import_tick(async |_, _| Ok(empty.clone()))));
        assert!(import_status().unwrap().copied);
        import_start(other(), me()).unwrap();
        assert!(tokens::list("mine").is_empty(), "starting over drops the tokens");
    }

    /// A digest stepped on the importer before the copy is whole is not
    /// the copy's: the chain starts the digest afresh when the last page
    /// is in.
    #[test]
    fn the_copys_digest_starts_when_the_copy_is_whole() {
        freeze().unwrap();
        let early = digest_step().unwrap();
        assert!(early.done && early.records == 0);
        import_start(other(), me()).unwrap();
        let one = Page {
            records: vec![Record { kind: Kind::Repos, key: b"r".to_vec(), value: b"refs/heads/main".to_vec() }],
            next: None,
        };
        while block_on(import_tick(async |_, _| Ok(one.clone()))) {}
        let st = import_status().unwrap();
        assert_eq!(st.error, None);
        let d = st.digest.unwrap();
        assert!(d.done);
        assert_eq!(d.records, 1, "the early digest of nothing was not kept");
    }

    /// An object whose stream inflates past its stated length is refused
    /// after one byte too many, not after the whole stream.
    #[test]
    fn an_object_that_inflates_past_its_length_is_refused_early() {
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&vec![0u8; 50 << 20]).unwrap();
        let stream = enc.finish().unwrap();
        assert!(stream.len() < 100_000, "zeros compress");
        let mut value = vec![ObjectType::Blob as u8];
        value.extend_from_slice(&1000u32.to_le_bytes());
        value.extend_from_slice(&stream);
        let key = [3u8; 20];
        let err = apply(&Record { kind: Kind::Objects, key: key.to_vec(), value }).unwrap_err();
        assert!(err.contains("1001 bytes, 1000 stated"), "{err}");
    }

    /// The digest is the same in one step or many, follows the records
    /// (a token more changes it), and is forgotten by a thaw.
    #[test]
    fn the_digest_is_one_hash_however_it_is_stepped() {
        seed();
        freeze().unwrap();
        let one = digest_step_with(usize::MAX).unwrap();
        assert!(one.done && one.records == 19, "{one:?}");
        let sha = one.sha256.clone().unwrap();
        assert_eq!(digest_step().unwrap(), one, "a step after the last answers the same");
        unfreeze().unwrap();
        assert_eq!(digest(), None);
        freeze().unwrap();
        let mut steps = 0;
        let many = loop {
            let d = digest_step_with(100).unwrap();
            steps += 1;
            if d.done {
                break d;
            }
            assert_eq!(d.sha256, None);
        };
        assert!(steps > 3);
        assert_eq!(many, one);
        unfreeze().unwrap();
        tokens::mint("mover", "tok-late", alice(), Some(5), None).unwrap();
        freeze().unwrap();
        let changed = digest_step_with(usize::MAX).unwrap();
        assert_eq!(changed.records, 20);
        assert_ne!(changed.sha256.unwrap(), sha);
    }

    /// The pages served by a fake exporter: each by the cursor it was
    /// asked with, as `walk` produced them; a page can be made to fail.
    struct Pages {
        pages: Vec<(Option<Cursor>, Page)>,
        fail_at: RefCell<Option<usize>>,
        asked: RefCell<Vec<Option<Cursor>>>,
    }

    impl Pages {
        fn of(budget: usize) -> Self {
            let mut cursor = None;
            let mut pages = Vec::new();
            loop {
                let page = walk(cursor.clone(), budget).unwrap();
                let next = page.next.clone();
                pages.push((cursor, page));
                match next {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            Pages { pages, fail_at: RefCell::new(None), asked: RefCell::new(Vec::new()) }
        }

        async fn fetch(&self, _source: Principal, cursor: Option<Cursor>) -> Result<Page, String> {
            let index = self.pages.iter().position(|(c, _)| *c == cursor).expect("a cursor the exporter gave");
            self.asked.borrow_mut().push(cursor);
            if *self.fail_at.borrow() == Some(index) {
                return Err("the exporter was away".into());
            }
            Ok(self.pages[index].1.clone())
        }

        async fn run(&self) {
            while import_tick(|s, c| self.fetch(s, c)).await {}
        }
    }

    /// A fresh store, filled from the pages, holds what the exporter did:
    /// the same digest, repos, refs, objects, tokens (indexed, so listed),
    /// labels and site configs. Pulled again onto itself it changes
    /// nothing. A failed page stops the import with its error on record
    /// and `import_start` resumes from that page; a finished one starts
    /// over.
    #[test]
    fn an_import_rebuilds_the_store_and_its_digest_matches() {
        seed();
        freeze().unwrap();
        let expected = digest_step_with(usize::MAX).unwrap();
        let pages = Pages::of(200);
        assert!(pages.pages.len() > 5);
        let refs = store::list_refs("mover");
        let objects: Vec<Record> = all(usize::MAX).into_iter().filter(|r| r.kind == Kind::Objects).collect();
        let token_ids: Vec<String> = tokens::list("mover").into_iter().map(|t| t.id).collect();
        let pages_data = pages.pages.clone();
        let expected_there = expected.clone();
        std::thread::spawn(move || {
            let expected = expected_there;
            let pages = Pages { pages: pages_data, fail_at: RefCell::new(Some(2)), asked: RefCell::new(Vec::new()) };
            assert!(import_start(other(), me()).unwrap_err().contains("freeze this canister first"));
            freeze().unwrap();
            assert!(import_start(me(), me()).unwrap_err().contains("itself"));
            import_start(other(), me()).unwrap();
            assert!(import_start(alice(), me()).unwrap_err().contains("import_reset"));
            block_on(pages.run());
            let st = import_status().unwrap();
            assert_eq!((st.pages, st.copied, st.running), (2, false, false));
            assert!(st.error.as_deref().unwrap().contains("away"), "{st:?}");
            assert_eq!(st.digest, None);
            *pages.fail_at.borrow_mut() = None;
            import_start(other(), me()).unwrap();
            block_on(pages.run());
            let st = import_status().unwrap();
            assert_eq!(st.error, None);
            assert!(st.copied);
            assert_eq!(st.pages as usize, pages.pages.len());
            assert_eq!(st.records, expected.records);
            assert_eq!(st.digest, Some(expected.clone()), "the copy digests as the original");
            // The third page was asked for twice: once failed, once taken.
            assert_eq!(pages.asked.borrow().iter().filter(|c| **c == pages.pages[2].0).count(), 2);
            assert_eq!(store::list_repos(), vec!["Other.App".to_string(), "mover".to_string()]);
            assert_eq!(store::list_refs("mover"), refs);
            for r in &objects {
                let oid = ic_git_types::oid::Oid::try_from(r.key.as_slice()).unwrap();
                assert!(store::get_object_stored(&oid).is_some());
            }
            assert_eq!(tokens::list("mover").into_iter().map(|t| t.id).collect::<Vec<_>>(), token_ids);
            assert_eq!(store::label_holder("other-app").as_deref(), Some("Other.App"));
            assert_eq!(crate::site::get_config("Other.App").unwrap().root, "");
            assert_eq!(store::head_target("Other.App").as_deref(), Some("refs/heads/main"));
            assert!(unfreeze().is_ok(), "nothing runs");
            assert!(import_start(other(), me()).unwrap_err().contains("freeze"));
            freeze().unwrap();
            // Finished: starting again starts over.
            import_start(other(), me()).unwrap();
            let st = import_status().unwrap();
            assert_eq!((st.pages, st.copied), (0, false));
            assert!(tokens::list("mover").is_empty(), "tokens are dropped first");
            block_on(pages.run());
            assert_eq!(import_status().unwrap().digest, Some(expected.clone()));
            import_reset().unwrap();
            assert_eq!(import_status(), None);
        })
        .join()
        .unwrap();
        // Onto itself: nothing changes.
        for (_, page) in &pages.pages {
            for r in &page.records {
                apply(r).unwrap();
            }
        }
        unfreeze().unwrap();
        freeze().unwrap();
        assert_eq!(digest_step_with(usize::MAX).unwrap(), expected);
    }

    /// A record the importer cannot trust is refused, and writes nothing:
    /// an object whose bytes are not the object, a META key outside the
    /// kind's prefix, a ref whose value is not an oid.
    #[test]
    fn an_import_refuses_what_it_cannot_trust() {
        let blob = store::put_object(ObjectType::Blob, b"real");
        let value = store::export_objects(None, usize::MAX).into_iter().find(|(k, _)| *k == blob).unwrap().1;
        let mut wrong_key = [0u8; 20];
        wrong_key[0] = 1;
        let err = apply(&Record { kind: Kind::Objects, key: wrong_key.to_vec(), value: value.clone() }).unwrap_err();
        assert!(err.contains("hashes to something else"), "{err}");
        assert!(!store::has_object(&ic_git_types::oid::Oid::try_from(&wrong_key[..]).unwrap()));
        let mut bad_type = value.clone();
        bad_type[0] = 9;
        assert!(apply(&Record { kind: Kind::Objects, key: wrong_key.to_vec(), value: bad_type }).unwrap_err().contains("type code"));
        let mut short_len = value.clone();
        short_len[1] = 3;
        assert!(apply(&Record { kind: Kind::Objects, key: wrong_key.to_vec(), value: short_len }).unwrap_err().contains("stated"));
        assert!(apply(&Record { kind: Kind::Objects, key: vec![1, 2], value }).unwrap_err().contains("20 bytes"));
        assert!(apply(&Record { kind: Kind::Labels, key: b"auth".to_vec(), value: b"x".to_vec() }).unwrap_err().contains("label:"));
        assert!(apply(&Record { kind: Kind::Sites, key: b"label:x".to_vec(), value: b"x".to_vec() }).unwrap_err().contains("site:"));
        assert_eq!(kv::get_bytes("auth"), None);
        assert!(apply(&Record { kind: Kind::Refs, key: b"r\0refs/heads/main".to_vec(), value: vec![1, 2, 3] }).unwrap_err().contains("20 bytes"));
        assert!(apply(&Record { kind: Kind::Refs, key: b"no-nul".to_vec(), value: vec![0; 20] }).unwrap_err().contains("names a repo"));
        assert!(apply(&Record { kind: Kind::Repos, key: vec![0xff], value: b"refs/heads/main".to_vec() }).unwrap_err().contains("not text"));
        // A page with such a record stops the import there, on record.
        freeze().unwrap();
        import_start(other(), me()).unwrap();
        let bad = Page { records: vec![Record { kind: Kind::Labels, key: b"auth".to_vec(), value: vec![] }], next: None };
        assert!(!block_on(import_tick(async |_, _| Ok(bad.clone()))));
        let st = import_status().unwrap();
        assert!(st.error.unwrap().contains("label:"));
        assert!(!st.copied);
    }

    /// A record too large for a page is refused by name, not lost in a
    /// reply the system would drop.
    #[test]
    fn an_oversize_record_is_refused_by_name() {
        // Bytes zlib cannot shrink, so the stored value is as large as the
        // content.
        let mut x: u64 = 7;
        let noise: Vec<u8> = (0..MAX_RECORD + 1)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (x >> 33) as u8
            })
            .collect();
        let big = store::put_object(ObjectType::Blob, &noise);
        freeze().unwrap();
        let err = export_page(None).unwrap_err();
        assert!(err.contains(&store::oid_hex(&big)) && err.contains("over the"), "{err}");
    }
}
