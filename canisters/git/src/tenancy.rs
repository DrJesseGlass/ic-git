//! Multi-tenancy: accounts, ownership, membership, votes, and pricing.
//! Design: docs/TENANCY.md.
//!
//! One rule underneath everything here: a tenant pays, in cycles, for what
//! their repo costs the shared canister, and an action that would overdraw
//! is refused before it runs. Balances are prepaid and held by this canister
//! (a deposit literally becomes canister cycles), so it can never be drained
//! by tenants; the only cycles it spends on a repo are cycles that repo's
//! owner already paid in.
//!
//! Who pays: the repo's **owner**. Members with the `Writer` role can push
//! and mint tokens against the owner's balance; `Voter` members can approve
//! commits for deploy but touch nothing else. Operators -- controllers and
//! the legacy admin allowlist -- are exempt from every charge, and repos
//! created before tenancy existed have no owner and are treated as
//! operator-owned.
//!
//! Every function that needs the caller takes it as a parameter, and time
//! goes through [`now_ns`], so all of this is unit-testable off-chain.

use crate::store;
use candid::{CandidType, Principal};
use ic_dev_kit_rs::auth;
use serde::{Deserialize, Serialize};

// --- pricing -----------------------------------------------------------------

/// Prices in cycles. Defaults are deliberately simple round numbers above the
/// IC's own rates (a 13-node subnet stores a GiB for ~127K cycles/s, i.e.
/// ~3.7K cycles per byte-year; an ingress byte costs ~2K cycles) so the
/// canister runs at a margin rather than a loss. Operators can retune with
/// `set_pricing`; the current table is public via `get_pricing`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Pricing {
    /// One-time fee to create a repo.
    pub create_repo: u64,
    /// Per push: a base charge plus a per-byte charge on the request body.
    pub push_base: u64,
    pub push_per_byte: u64,
    /// Storage rent, per byte of ingested pack data, per year. Charged by the
    /// hourly rent timer, pro rata.
    pub rent_per_byte_year: u64,
    /// One EVM action (a deploy or a registry publish): a threshold-ECDSA
    /// signature plus RPC outcalls. Priced above `rpc_common::SIGN_CYCLES`.
    pub evm_action: u64,
    /// One wasm install into a target canister from the deploy queue.
    pub ic_deploy: u64,
}

impl Default for Pricing {
    fn default() -> Self {
        Pricing {
            create_repo: 1_000_000_000,
            push_base: 100_000_000,
            push_per_byte: 5_000,
            rent_per_byte_year: 5_000,
            evm_action: 50_000_000_000,
            ic_deploy: 5_000_000_000,
        }
    }
}

const PRICING_KEY: &str = "tenancy:pricing";
const YEAR_NS: u128 = 365 * 24 * 3600 * 1_000_000_000;

pub fn pricing() -> Pricing {
    store::meta_get_json(PRICING_KEY).unwrap_or_default()
}

pub fn set_pricing(p: Pricing) {
    store::meta_set_json(PRICING_KEY, &p);
}

/// Settle rent every hour. Timers do not survive upgrades, so init and
/// post_upgrade both call this.
#[cfg(not(test))]
pub fn arm_rent_timer() {
    ic_cdk_timers::set_timer_interval(std::time::Duration::from_secs(3600), || async {
        let _ = charge_rent_all();
    });
}

#[cfg(test)]
pub fn arm_rent_timer() {}

// --- time --------------------------------------------------------------------

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(1_700_000_000_000_000_000) };
}

/// Nanoseconds since the epoch; settable in tests.
pub fn now_ns() -> u64 {
    #[cfg(test)]
    {
        TEST_NOW.with(|t| t.get())
    }
    #[cfg(not(test))]
    {
        ic_cdk::api::time()
    }
}

#[cfg(test)]
pub fn set_test_now(ns: u64) {
    TEST_NOW.with(|t| t.set(ns));
}

// --- accounts ----------------------------------------------------------------

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default)]
pub struct Account {
    /// Spendable cycles.
    pub balance: u64,
    /// Lifetime totals, for the console.
    pub deposited: u64,
    pub spent: u64,
    pub created_ns: u64,
}

fn account(p: &Principal) -> Account {
    store::account_get(&p.to_text()).unwrap_or_default()
}

fn save_account(p: &Principal, a: &Account) {
    store::account_set(&p.to_text(), a);
}

pub fn get_account(p: &Principal) -> Account {
    account(p)
}

pub fn balance(p: &Principal) -> u64 {
    account(p).balance
}

/// Add cycles to a principal's balance.
pub fn credit(p: &Principal, amount: u64) -> Account {
    let mut a = account(p);
    if a.created_ns == 0 {
        a.created_ns = now_ns();
    }
    a.balance = a.balance.saturating_add(amount);
    a.deposited = a.deposited.saturating_add(amount);
    save_account(p, &a);
    a
}

/// Take cycles from a principal's balance, refusing to overdraw.
pub fn debit(p: &Principal, amount: u64, what: &str) -> Result<(), String> {
    let mut a = account(p);
    if a.balance < amount {
        return Err(format!(
            "insufficient balance for {what}: need {amount} cycles, have {}",
            a.balance
        ));
    }
    a.balance -= amount;
    a.spent = a.spent.saturating_add(amount);
    save_account(p, &a);
    Ok(())
}

// --- repo metadata -------------------------------------------------------------

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum Role {
    /// May push, mint and revoke tokens, and configure the site/deploys.
    Writer,
    /// May approve commits for deploy. Nothing else.
    Voter,
}

impl Role {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "writer" => Ok(Role::Writer),
            "voter" => Ok(Role::Voter),
            _ => Err(format!("role must be 'writer' or 'voter', got '{s}'")),
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Member {
    pub principal: Principal,
    pub role: Role,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct RepoMeta {
    /// Who pays. `None` for repos created before tenancy existed: those are
    /// operator repos and exempt from charges.
    pub owner: Option<Principal>,
    #[serde(default)]
    pub members: Vec<Member>,
    /// Bytes of pack data ingested by pushes to this repo: what rent is
    /// charged on. Objects are content-addressed and shared across repos, so
    /// this is attribution, not a measure of unique storage.
    #[serde(default)]
    pub storage_bytes: u64,
    /// When rent was last settled up to.
    #[serde(default)]
    pub rent_paid_to_ns: u64,
    /// Set when the owner could not cover rent. Pushes and deploys are
    /// refused until a deposit clears it; serving continues.
    #[serde(default)]
    pub delinquent: bool,
    /// Approvals a commit needs from voters before the deploy queue will run
    /// it. 0 means deploys run on push, as before.
    #[serde(default)]
    pub required_votes: u32,
    /// The user-owned canister this repo's IC deploys install into, once one
    /// has been created from the owner's balance (docs/TENANCY.md, phase 3).
    #[serde(default)]
    pub app_canister: Option<Principal>,
    #[serde(default)]
    pub created_ns: u64,
}

pub fn meta(repo: &str) -> Option<RepoMeta> {
    store::repo_meta_get(repo)
}

fn save_meta(repo: &str, m: &RepoMeta) {
    store::repo_meta_set(repo, m);
}

/// Metadata for any existing repo: legacy repos get an ownerless record.
fn meta_or_legacy(repo: &str) -> Result<RepoMeta, String> {
    if let Some(m) = meta(repo) {
        return Ok(m);
    }
    if !store::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    Ok(RepoMeta {
        owner: None,
        members: Vec::new(),
        storage_bytes: 0,
        rent_paid_to_ns: now_ns(),
        delinquent: false,
        required_votes: 0,
        app_canister: None,
        created_ns: 0,
    })
}

/// Operators are the controllers plus the legacy admin allowlist. Callers
/// pass `operator` in from lib.rs (controller checks need the IC); here we
/// only consult the allowlist, which is host-testable.
fn allowlisted(p: &Principal) -> bool {
    auth::is_principal_authorized(*p).unwrap_or(false)
}

/// A repo whose owner pays nothing: ownerless (legacy) or operator-owned.
fn exempt(m: &RepoMeta) -> bool {
    match &m.owner {
        None => true,
        Some(o) => allowlisted(o),
    }
}

pub fn is_exempt(repo: &str) -> bool {
    meta_or_legacy(repo).map(|m| exempt(&m)).unwrap_or(false)
}

/// Return cycles taken by `debit` for an action that then failed. Unlike
/// `credit`, this does not count as a deposit.
pub fn refund(p: &Principal, amount: u64) {
    let mut a = account(p);
    a.balance = a.balance.saturating_add(amount);
    a.spent = a.spent.saturating_sub(amount);
    save_account(p, &a);
}

// --- permissions -----------------------------------------------------------------

pub fn is_owner(m: &RepoMeta, p: &Principal) -> bool {
    m.owner.as_ref() == Some(p)
}

fn has_role(m: &RepoMeta, p: &Principal, role: Role) -> bool {
    m.members.iter().any(|x| &x.principal == p && x.role == role)
}

/// Owner, or an operator: may change members, config, and deploy settings.
pub fn can_admin(repo: &str, p: &Principal, operator: bool) -> Result<RepoMeta, String> {
    let m = meta_or_legacy(repo)?;
    if operator || is_owner(&m, p) {
        Ok(m)
    } else {
        Err(format!("{p} does not own repo {repo}"))
    }
}

/// Owner, writer, or operator: may push and manage tokens.
pub fn can_write(repo: &str, p: &Principal, operator: bool) -> Result<RepoMeta, String> {
    let m = meta_or_legacy(repo)?;
    if operator || is_owner(&m, p) || has_role(&m, p, Role::Writer) {
        Ok(m)
    } else {
        Err(format!("{p} may not write to repo {repo}"))
    }
}

/// Owner or voter: may cast a ballot.
pub fn can_vote(repo: &str, p: &Principal) -> Result<RepoMeta, String> {
    let m = meta_or_legacy(repo)?;
    if is_owner(&m, p) || has_role(&m, p, Role::Voter) {
        Ok(m)
    } else {
        Err(format!("{p} is not a voter on repo {repo}"))
    }
}

// --- repo lifecycle ------------------------------------------------------------

/// Create a repo owned by `who`. Non-operators pay the creation fee, which is
/// also what "a positive balance" means in practice: an account that cannot
/// cover it cannot create.
pub fn create_repo(name: &str, who: &Principal, operator: bool) -> Result<(), String> {
    if *who == Principal::anonymous() {
        return Err("sign in first: the anonymous principal cannot own a repo".into());
    }
    if store::repo_exists(name) {
        return Err(format!("repo '{name}' already exists"));
    }
    if !operator {
        debit(who, pricing().create_repo, "create_repo")?;
    }
    store::create_repo(name)?;
    save_meta(
        name,
        &RepoMeta {
            owner: Some(*who),
            members: Vec::new(),
            storage_bytes: 0,
            rent_paid_to_ns: now_ns(),
            delinquent: false,
            required_votes: 0,
            app_canister: None,
            created_ns: now_ns(),
        },
    );
    Ok(())
}

pub fn add_member(
    repo: &str,
    who: &Principal,
    operator: bool,
    target: Principal,
    role: Role,
) -> Result<Vec<Member>, String> {
    let mut m = can_admin(repo, who, operator)?;
    if target == Principal::anonymous() {
        return Err("the anonymous principal cannot be a member".into());
    }
    if is_owner(&m, &target) {
        return Err("the owner already has every role".into());
    }
    m.members.retain(|x| x.principal != target);
    m.members.push(Member {
        principal: target,
        role,
    });
    save_meta(repo, &m);
    Ok(m.members)
}

pub fn remove_member(
    repo: &str,
    who: &Principal,
    operator: bool,
    target: Principal,
) -> Result<Vec<Member>, String> {
    let mut m = can_admin(repo, who, operator)?;
    let before = m.members.len();
    m.members.retain(|x| x.principal != target);
    if m.members.len() == before {
        return Err(format!("{target} is not a member of {repo}"));
    }
    save_meta(repo, &m);
    Ok(m.members)
}

/// Hand a repo to a new owner, who pays from then on.
pub fn transfer_repo(
    repo: &str,
    who: &Principal,
    operator: bool,
    new_owner: Principal,
) -> Result<(), String> {
    let mut m = can_admin(repo, who, operator)?;
    if new_owner == Principal::anonymous() {
        return Err("cannot transfer to the anonymous principal".into());
    }
    m.owner = Some(new_owner);
    m.members.retain(|x| x.principal != new_owner);
    save_meta(repo, &m);
    Ok(())
}

pub fn set_required_votes(repo: &str, who: &Principal, operator: bool, k: u32) -> Result<(), String> {
    let mut m = can_admin(repo, who, operator)?;
    m.required_votes = k;
    save_meta(repo, &m);
    Ok(())
}

/// Repos a principal owns or is a member of.
pub fn repos_of(p: &Principal) -> Vec<String> {
    store::repo_meta_all::<RepoMeta>()
        .into_iter()
        .filter(|(_, m)| is_owner(m, p) || m.members.iter().any(|x| &x.principal == p))
        .map(|(name, _)| name)
        .collect()
}

// --- votes ----------------------------------------------------------------------

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Ballot {
    pub principal: Principal,
    pub approve: bool,
    pub at_ns: u64,
}

pub fn votes(repo: &str, commit_hex: &str) -> Vec<Ballot> {
    store::votes_get(repo, commit_hex).unwrap_or_default()
}

/// Cast or replace a ballot. Returns the approvals so far and the threshold.
pub fn vote(
    repo: &str,
    who: &Principal,
    commit_hex: &str,
    approve: bool,
) -> Result<(u32, u32), String> {
    let m = can_vote(repo, who)?;
    let oid = store::parse_oid(commit_hex)?;
    if !store::has_object(&oid) {
        return Err(format!("no such commit in {repo}: {commit_hex}"));
    }
    let mut ballots = votes(repo, commit_hex);
    ballots.retain(|b| &b.principal != who);
    ballots.push(Ballot {
        principal: *who,
        approve,
        at_ns: now_ns(),
    });
    store::votes_set(repo, commit_hex, &ballots);
    Ok((approvals(&m, &ballots), m.required_votes))
}

/// Approvals that count: from the owner or a current voter.
fn approvals(m: &RepoMeta, ballots: &[Ballot]) -> u32 {
    ballots
        .iter()
        .filter(|b| b.approve && (is_owner(m, &b.principal) || has_role(m, &b.principal, Role::Voter)))
        .count() as u32
}

/// May the deploy queue run this commit? Yes when the repo requires no votes
/// (the default) or enough voters have approved.
pub fn approved(repo: &str, commit_hex: &str) -> bool {
    match meta(repo) {
        None => true,
        Some(m) if m.required_votes == 0 => true,
        Some(m) => approvals(&m, &votes(repo, commit_hex)) >= m.required_votes,
    }
}

// --- charges ------------------------------------------------------------------------

/// Charge a push against the repo owner and attribute its bytes to the repo.
/// Called before the pack is ingested; an `Err` means the push must be
/// refused untouched.
pub fn charge_push(repo: &str, bytes: usize) -> Result<(), String> {
    let mut m = meta_or_legacy(repo)?;
    if exempt(&m) {
        return Ok(());
    }
    if m.delinquent {
        return Err(format!("repo {repo} is behind on storage rent; deposit cycles to resume"));
    }
    let p = pricing();
    let fee = p
        .push_base
        .saturating_add(p.push_per_byte.saturating_mul(bytes as u64));
    let owner = m.owner.expect("non-exempt repo has an owner");
    debit(&owner, fee, "push")?;
    m.storage_bytes = m.storage_bytes.saturating_add(bytes as u64);
    save_meta(repo, &m);
    Ok(())
}

/// Charge a deploy-queue action (an IC install, an EVM deploy or publish).
pub fn charge_action(repo: &str, cycles: u64, what: &str) -> Result<(), String> {
    let m = meta_or_legacy(repo)?;
    if exempt(&m) {
        return Ok(());
    }
    if m.delinquent {
        return Err(format!("repo {repo} is behind on storage rent; deposit cycles to resume"));
    }
    debit(&m.owner.expect("non-exempt repo has an owner"), cycles, what)
}

/// Rent due for `bytes` held from `from_ns` to `to_ns`.
fn rent_due(p: &Pricing, bytes: u64, from_ns: u64, to_ns: u64) -> u64 {
    if to_ns <= from_ns {
        return 0;
    }
    let elapsed = (to_ns - from_ns) as u128;
    let due = (bytes as u128) * (p.rent_per_byte_year as u128) * elapsed / YEAR_NS;
    due.min(u64::MAX as u128) as u64
}

/// Settle rent on every tenant repo up to now. An owner who cannot cover it
/// pays what they have and the repo goes delinquent; a later deposit and the
/// next tick clear it. Returns (repos charged, cycles collected).
pub fn charge_rent_all() -> (u32, u64) {
    let p = pricing();
    let now = now_ns();
    let mut charged = 0u32;
    let mut collected = 0u64;
    for (name, mut m) in store::repo_meta_all::<RepoMeta>() {
        if exempt(&m) {
            continue;
        }
        let owner = m.owner.expect("non-exempt repo has an owner");
        let due = rent_due(&p, m.storage_bytes, m.rent_paid_to_ns, now);
        if due > 0 {
            match debit(&owner, due, "rent") {
                Ok(()) => {
                    collected = collected.saturating_add(due);
                    m.delinquent = false;
                }
                Err(_) => {
                    let have = balance(&owner);
                    if have > 0 {
                        let _ = debit(&owner, have, "rent (partial)");
                        collected = collected.saturating_add(have);
                    }
                    m.delinquent = true;
                }
            }
            charged += 1;
        } else if m.delinquent && balance(&owner) > 0 {
            m.delinquent = false;
        }
        m.rent_paid_to_ns = now;
        save_meta(&name, &m);
    }
    (charged, collected)
}

/// Public view of a repo's tenancy state.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct RepoInfo {
    pub owner: Option<Principal>,
    pub members: Vec<Member>,
    pub storage_bytes: u64,
    pub delinquent: bool,
    pub required_votes: u32,
    pub app_canister: Option<Principal>,
    pub exempt: bool,
}

pub fn repo_info(repo: &str) -> Option<RepoInfo> {
    let m = meta_or_legacy(repo).ok()?;
    Some(RepoInfo {
        exempt: exempt(&m),
        owner: m.owner,
        members: m.members,
        storage_bytes: m.storage_bytes,
        delinquent: m.delinquent,
        required_votes: m.required_votes,
        app_canister: m.app_canister,
    })
}

pub fn set_app_canister(repo: &str, canister: Principal) -> Result<(), String> {
    let mut m = meta_or_legacy(repo)?;
    m.app_canister = Some(canister);
    save_meta(repo, &m);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 8])
    }

    #[test]
    fn create_requires_identity_and_fee() {
        let alice = p(1);
        assert!(create_repo("t-anon", &Principal::anonymous(), false).is_err());
        // No balance: refused, and the repo does not exist afterwards.
        assert!(create_repo("t-poor", &alice, false).unwrap_err().contains("insufficient"));
        assert!(!store::repo_exists("t-poor"));
        credit(&alice, pricing().create_repo);
        create_repo("t-ok", &alice, false).unwrap();
        assert_eq!(balance(&alice), 0);
        let m = meta("t-ok").unwrap();
        assert_eq!(m.owner, Some(alice));
        assert!(!super::exempt(&m));
        // Operators pay nothing and still own what they create.
        let op = p(9);
        create_repo("t-op", &op, true).unwrap();
        assert_eq!(meta("t-op").unwrap().owner, Some(op));
    }

    #[test]
    fn roles_gate_write_admin_and_vote() {
        let (alice, bob, carol, dave) = (p(11), p(12), p(13), p(14));
        credit(&alice, 10_000_000_000);
        create_repo("t-roles", &alice, false).unwrap();
        // Strangers can do nothing.
        assert!(can_write("t-roles", &bob, false).is_err());
        assert!(can_admin("t-roles", &bob, false).is_err());
        assert!(can_vote("t-roles", &bob).is_err());
        // Only the owner (or an operator) adds members.
        assert!(add_member("t-roles", &bob, false, carol, Role::Writer).is_err());
        add_member("t-roles", &alice, false, bob, Role::Writer).unwrap();
        add_member("t-roles", &alice, false, carol, Role::Voter).unwrap();
        assert!(can_write("t-roles", &bob, false).is_ok());
        assert!(can_admin("t-roles", &bob, false).is_err());
        assert!(can_vote("t-roles", &bob).is_err());
        assert!(can_vote("t-roles", &carol).is_ok());
        assert!(can_write("t-roles", &carol, false).is_err());
        // An operator can act on anyone's repo.
        assert!(can_admin("t-roles", &dave, true).is_ok());
        // Re-adding changes the role rather than duplicating.
        let members = add_member("t-roles", &alice, false, bob, Role::Voter).unwrap();
        assert_eq!(members.iter().filter(|m| m.principal == bob).count(), 1);
        assert!(can_vote("t-roles", &bob).is_ok());
        remove_member("t-roles", &alice, false, bob).unwrap();
        assert!(remove_member("t-roles", &alice, false, bob).is_err());
        // Transfer: the new owner pays and loses any member row.
        add_member("t-roles", &alice, false, dave, Role::Writer).unwrap();
        transfer_repo("t-roles", &alice, false, dave).unwrap();
        let m = meta("t-roles").unwrap();
        assert_eq!(m.owner, Some(dave));
        assert!(m.members.iter().all(|x| x.principal != dave));
        assert!(can_admin("t-roles", &alice, false).is_err());
    }

    #[test]
    fn push_fee_storage_and_rent() {
        let alice = p(21);
        let pr = pricing();
        credit(&alice, pr.create_repo + pr.push_base + pr.push_per_byte * 1000 + 1);
        create_repo("t-rent", &alice, false).unwrap();
        // A push charges base + per byte and attributes the bytes.
        charge_push("t-rent", 1000).unwrap();
        assert_eq!(balance(&alice), 1);
        assert_eq!(meta("t-rent").unwrap().storage_bytes, 1000);
        // Cannot afford another push.
        assert!(charge_push("t-rent", 1).unwrap_err().contains("insufficient"));
        // One year of rent on 1000 bytes.
        let start = now_ns();
        set_test_now(start + YEAR_NS as u64);
        let (charged, collected) = charge_rent_all();
        assert_eq!(charged, 1);
        // Owner had 1 cycle: pays it, goes delinquent.
        assert_eq!(collected, 1);
        assert!(meta("t-rent").unwrap().delinquent);
        assert!(charge_push("t-rent", 1).unwrap_err().contains("rent"));
        assert!(charge_action("t-rent", 5, "evm").unwrap_err().contains("rent"));
        // A deposit and the next tick clear it, charging the elapsed rent.
        credit(&alice, 1_000_000_000);
        set_test_now(start + 2 * YEAR_NS as u64);
        let (_, collected2) = charge_rent_all();
        assert_eq!(collected2, 1000 * pr.rent_per_byte_year);
        assert!(!meta("t-rent").unwrap().delinquent);
        assert!(charge_push("t-rent", 1).is_ok());
        set_test_now(start);
    }

    #[test]
    fn legacy_and_operator_repos_are_exempt() {
        store::create_repo("t-legacy").unwrap();
        assert!(meta("t-legacy").is_none());
        charge_push("t-legacy", 10_000_000).unwrap();
        assert!(charge_action("t-legacy", u64::MAX, "evm").is_ok());
        assert!(repo_info("t-legacy").unwrap().exempt);
        // Anyone may push to a legacy repo only as an operator; tokens still
        // gate the HTTP path.
        assert!(can_write("t-legacy", &p(31), false).is_err());
        assert!(can_write("t-legacy", &p(31), true).is_ok());
        // A repo without metadata costs no rent.
        let (charged, _) = charge_rent_all();
        assert!(!store::repo_meta_all::<RepoMeta>().iter().any(|(n, _)| n == "t-legacy"));
        let _ = charged;
    }

    #[test]
    fn votes_gate_deploys() {
        let (alice, v1, v2, w) = (p(41), p(42), p(43), p(44));
        credit(&alice, 10_000_000_000);
        create_repo("t-vote", &alice, false).unwrap();
        let blob = store::put_object(store::ObjectType::Blob, b"x");
        let commit = store::oid_hex(&blob); // any stored object stands in for a commit here
        // No threshold: approved by default.
        assert!(approved("t-vote", &commit));
        set_required_votes("t-vote", &alice, false, 2).unwrap();
        assert!(!approved("t-vote", &commit));
        add_member("t-vote", &alice, false, v1, Role::Voter).unwrap();
        add_member("t-vote", &alice, false, v2, Role::Voter).unwrap();
        add_member("t-vote", &alice, false, w, Role::Writer).unwrap();
        // Writers cannot vote; unknown commits are refused.
        assert!(vote("t-vote", &w, &commit, true).is_err());
        assert!(vote("t-vote", &v1, &"0".repeat(40), true).is_err());
        assert_eq!(vote("t-vote", &v1, &commit, true).unwrap(), (1, 2));
        assert!(!approved("t-vote", &commit));
        // The owner counts as a voter.
        assert_eq!(vote("t-vote", &alice, &commit, true).unwrap(), (2, 2));
        assert!(approved("t-vote", &commit));
        // A ballot can be changed; a removed voter's ballot stops counting.
        assert_eq!(vote("t-vote", &alice, &commit, false).unwrap(), (1, 2));
        assert_eq!(vote("t-vote", &v2, &commit, true).unwrap(), (2, 2));
        remove_member("t-vote", &alice, false, v2).unwrap();
        assert!(!approved("t-vote", &commit));
        assert_eq!(votes("t-vote", &commit).len(), 3);
        assert_eq!(repos_of(&v1), vec!["t-vote".to_string()]);
    }
}
