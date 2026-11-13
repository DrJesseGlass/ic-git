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

use crate::clock::now_ns;
use crate::mirrors::Mirror;
use ic_git_types::oid::{parse_oid, Oid};
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
    /// The git canister's floor (crate::funding): under it, the rent
    /// timer sends the floor's worth from what tenants paid for git-side
    /// work. A table written before the field reads the default.
    #[serde(default = "default_git_canister_floor")]
    pub git_canister_floor: u64,
}

fn default_git_canister_floor() -> u64 {
    1_000_000_000_000
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
            git_canister_floor: default_git_canister_floor(),
        }
    }
}

const PRICING_KEY: &str = "tenancy:pricing";
const YEAR_NS: u128 = 365 * 24 * 3600 * 1_000_000_000;

pub fn pricing() -> Pricing {
    crate::kv::get_json(PRICING_KEY).unwrap_or_default()
}

pub fn set_pricing(p: Pricing) {
    crate::kv::set_json(PRICING_KEY, &p);
}

/// Settle rent every hour, then fund the git canister from what was
/// collected (crate::funding). Timers do not survive upgrades, so init
/// and post_upgrade both call this.
#[cfg(not(any(test, feature = "testing")))]
pub fn arm_rent_timer() {
    ic_cdk_timers::set_timer_interval(std::time::Duration::from_secs(3600), || async {
        let _ = charge_rent_all();
        let _ = crate::funding::top_up_git().await;
    });
}

#[cfg(any(test, feature = "testing"))]
pub fn arm_rent_timer() {}

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
    crate::records::account_get(&p.to_text()).unwrap_or_default()
}

fn save_account(p: &Principal, a: &Account) {
    crate::records::account_set(&p.to_text(), a);
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
    /// Refuse pushes with a token that is not bound to an SSH key, so every
    /// push carries a certificate its key signed (signed_push.rs). Off by
    /// default.
    #[serde(default)]
    pub require_signed_push: bool,
    /// Governed (docs/GOVERNANCE.md, section 2): this canister is the app
    /// canister's only controller, so its code changes only by an approved
    /// commit's deploy, and the policy that approves is locked -- required
    /// votes stay above 0, and changing them, the voters, the owner or the
    /// deploy config is itself a vote (`propose_policy_change`). One-way.
    #[serde(default)]
    pub governed: bool,
    /// Policy changes with ballots on them and not yet applied.
    #[serde(default)]
    pub proposals: Vec<PolicyChange>,
    /// The label the repo holds (`labels::repo_label`), as the git side
    /// reported it when the repo was created: what the name service
    /// announces it under. `None` for a repo that holds none: one whose
    /// name maps to no label, or to one an older repo holds.
    #[serde(default)]
    pub label: Option<String>,
}

pub fn meta(repo: &str) -> Option<RepoMeta> {
    crate::records::repo_meta_get(repo)
}

/// Save a repo's metadata, and mark the git side's mirrors the change
/// touches (mirrors.rs). The flow that made the change awaits
/// `mirrors::flush` next; a flow that cannot (post_upgrade) leaves the
/// marks to `mirrors::resume`.
fn save_meta(repo: &str, m: &RepoMeta) {
    let prev = meta(repo);
    crate::records::repo_meta_set(repo, m);
    let (push, votes, approvers) = mirrored(m);
    let was = prev.as_ref().map(mirrored);
    if was.as_ref().map(|w| &w.0) != Some(&push) {
        crate::mirrors::mark(repo, Mirror::PushPolicy);
    }
    if was.as_ref().map(|w| (w.1, &w.2)) != Some((votes, &approvers)) {
        crate::mirrors::mark(repo, Mirror::Approved);
    }
}

// --- the git side's mirrors (mirror.rs) -----------------------------------------

/// Who may push, as the git side checks it: the owner and the writers.
fn push_policy(m: &RepoMeta) -> crate::to_git::PushPolicy {
    crate::to_git::PushPolicy {
        writers: m
            .owner
            .iter()
            .copied()
            .chain(m.members.iter().filter(|x| x.role == Role::Writer).map(|x| x.principal))
            .collect(),
        require_signed_push: m.require_signed_push,
    }
}

/// What in a repo's metadata the mirrors depend on: the push policy, and
/// the threshold and approvers that decide which commits are approved.
fn mirrored(m: &RepoMeta) -> (crate::to_git::PushPolicy, u32, Vec<Principal>) {
    let voters = m.members.iter().filter(|x| x.role == Role::Voter).map(|x| x.principal);
    (push_policy(m), m.required_votes, m.owner.iter().copied().chain(voters).collect())
}

/// The repo's commits that reach its threshold, by ballot key; `None` when
/// it requires no votes. Every commit with a ballot is counted, so this is
/// as current as the ballots and the policy.
fn approved_keys(repo: &str, m: &RepoMeta) -> Option<Vec<String>> {
    if m.required_votes == 0 {
        return None;
    }
    let pol = policy(m);
    let commits = crate::records::vote_subject_keys(repo, "commit:");
    Some(
        commits
            .into_iter()
            .filter(|key| {
                let hash = key
                    .strip_prefix("commit:")
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|h| <[u8; 32]>::try_from(h).ok());
                hash.is_some_and(|h| count_subject(repo, &pol, &Subject::new("commit", h)).reached)
            })
            .collect(),
    )
}

/// The repo's push policy as the git side mirrors it; `None` for a repo
/// this side has no record of.
pub fn push_policy_of(repo: &str) -> Option<crate::to_git::PushPolicy> {
    meta(repo).map(|m| push_policy(&m))
}

/// The repo's approved commits as the git side mirrors them (`None` inside
/// when it requires no votes); `None` for a repo this side has no record
/// of.
pub fn approved_of(repo: &str) -> Option<Option<Vec<String>>> {
    meta(repo).map(|m| approved_keys(repo, &m))
}

/// Does the repo exist? Every repo has metadata: the authority creates
/// them all (`create_repo`), and a one-time upgrade path gave the ones
/// created before tenancy an ownerless record.
pub fn repo_exists(repo: &str) -> bool {
    meta(repo).is_some()
}

/// Metadata for an existing repo.
fn existing(repo: &str) -> Result<RepoMeta, String> {
    meta(repo).ok_or_else(|| format!("no such repo: {repo}"))
}

/// A repo on the git side and the authority's record of it, as one
/// created before tenancy has: ownerless, exempt from charges, and only
/// operators may push to it. For tests, which otherwise create repos on the
/// git side alone.
#[cfg(any(test, feature = "testing"))]
pub fn test_repo(name: &str) {
    let label = ic_git_git::store::check_new_repo(name).ok();
    ic_git_git::store::create_repo(name).unwrap();
    save_meta(name, &RepoMeta {
        owner: None,
        members: Vec::new(),
        storage_bytes: 0,
        rent_paid_to_ns: now_ns(),
        delinquent: false,
        required_votes: 0,
        app_canister: None,
        created_ns: 0,
        require_signed_push: false,
        governed: false,
        proposals: Vec::new(),
        label,
    });
    // Its mirrors, as create_repo's flush leaves them.
    futures::executor::block_on(crate::mirrors::flush(name));
}

/// The one operator rule: controllers and the admin allowlist, and never
/// this canister itself. The `is_admin` guard applies it to the caller, the
/// push-token checks to a token's minter, and `exempt` to a repo's owner.
/// The self exclusion is deliberate: code this canister runs on its own
/// behalf (timers, its own calls) is not an operator, even if its principal
/// were put on the allowlist.
///
/// Both halves are read live, so a repo's exemption follows its owner:
/// removing a controller or an allowlist entry makes its repos pay from the
/// next charge on.
pub fn is_operator(p: &Principal) -> bool {
    !is_self(p) && (is_controller(p) || auth::is_principal_authorized(*p).unwrap_or(false))
}

#[cfg(any(test, feature = "testing"))]
thread_local! {
    static TEST_CONTROLLERS: std::cell::RefCell<Vec<Principal>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(any(test, feature = "testing"))]
pub fn set_test_controller(p: Principal, on: bool) {
    TEST_CONTROLLERS.with(|c| {
        let mut c = c.borrow_mut();
        c.retain(|x| x != &p);
        if on {
            c.push(p);
        }
    });
}

fn is_controller(p: &Principal) -> bool {
    #[cfg(any(test, feature = "testing"))]
    {
        TEST_CONTROLLERS.with(|c| c.borrow().contains(p))
    }
    #[cfg(not(any(test, feature = "testing")))]
    {
        ic_cdk::api::is_controller(p)
    }
}

fn is_self(p: &Principal) -> bool {
    #[cfg(any(test, feature = "testing"))]
    {
        let _ = p;
        false
    }
    #[cfg(not(any(test, feature = "testing")))]
    {
        *p == ic_cdk::api::canister_self()
    }
}

/// A repo whose owner pays nothing: ownerless (legacy) or operator-owned.
fn exempt(m: &RepoMeta) -> bool {
    match &m.owner {
        None => true,
        Some(o) => is_operator(o),
    }
}

pub fn is_exempt(repo: &str) -> bool {
    existing(repo).map(|m| exempt(&m)).unwrap_or(false)
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
    let m = existing(repo)?;
    if operator || is_owner(&m, p) {
        Ok(m)
    } else {
        Err(format!("{p} does not own repo {repo}"))
    }
}

/// Owner or voter: may cast a ballot. Decided by the vote policy itself, so
/// whoever passes here is exactly an approver `record` accepts.
pub fn can_vote(repo: &str, p: &Principal) -> Result<RepoMeta, String> {
    let m = existing(repo)?;
    if policy(&m).is_approver(&Approver::from(*p)) {
        Ok(m)
    } else {
        Err(format!("{p} is not a voter on repo {repo}"))
    }
}

// --- repo lifecycle ------------------------------------------------------------

/// A repo name taken at this side while the git side is asked to create
/// it: who holds it, the fee they paid, and the label the git side gave
/// the name, so a refusal can be refunded and a lost answer settled by
/// asking again.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Reservation {
    owner: Principal,
    fee: u64,
    label: String,
}

fn reservation_key(name: &str) -> String {
    format!("tenancy:reserved:{name}")
}

fn reservation(name: &str) -> Option<Reservation> {
    crate::kv::get_json(&reservation_key(name))
}

/// How often one call asks the git side to create a reserved name before
/// leaving the reservation to a later call.
const CREATE_ASKS: u32 = 3;

/// Create a repo owned by `who`. Non-operators pay the creation fee, which is
/// also what "a positive balance" means in practice: an account that cannot
/// cover it cannot create.
///
/// The git side is asked twice: whether the name can be created, then to
/// create it. Between the two this side reserves the name and takes the
/// fee, so a second creation of the name is refused while the first waits,
/// and the fee is accounted for whatever the git side answers: a refusal
/// refunds it and releases the name; an answer that does not come is asked
/// for again, since the name is reserved and nothing else can have taken
/// it (the git side's `create_repo` is idempotent); and if it still does
/// not come, the owner keeps the reservation and the fee, and a later
/// `create_repo` of the name by them finishes it without paying again.
pub async fn create_repo(name: &str, who: &Principal, operator: bool) -> Result<(), String> {
    if *who == Principal::anonymous() {
        return Err("sign in first: the anonymous principal cannot own a repo".into());
    }
    if let Some(r) = reservation(name) {
        if r.owner != *who {
            return Err(format!("repo name '{name}' is reserved: a creation of it is waiting for the git side"));
        }
        return settle(name).await;
    }
    if repo_exists(name) {
        return Err(format!("repo '{name}' already exists"));
    }
    // Every refusal the git side can make, before the fee is taken: an
    // update that returns Err keeps its state changes, so a debit followed
    // by a refused name would keep the fee.
    let label = match crate::to_git::check_new_repo(name).await {
        Ok(Ok(label)) => label,
        Ok(Err(e)) => return Err(e),
        Err(f) => {
            return Err(format!(
                "the git side did not say whether '{name}' can be created ({f}); nothing was charged, try again"
            ))
        }
    };
    // Another creation of the name may have got this far while the git
    // side answered.
    if reservation(name).is_some() || repo_exists(name) {
        return Err(format!("repo name '{name}' was taken while the git side answered"));
    }
    let fee = if operator { 0 } else { pricing().create_repo };
    if fee > 0 {
        debit(who, fee, "create_repo")?;
    }
    let r = Reservation {
        owner: *who,
        fee,
        label,
    };
    crate::kv::set_json(&reservation_key(name), &r);
    settle(name).await
}

/// Ask the git side to create a reserved name, and settle the reservation
/// by its answer. The owner may call `create_repo` again while an earlier
/// call waits, so the reservation is read again after each answer and
/// settled only if it is still there: the first answer back settles it,
/// and a later one finds it settled, with the repo recorded (Ok) or the
/// fee refunded (Err).
async fn settle(name: &str) -> Result<(), String> {
    let mut failure = None;
    for _ in 0..CREATE_ASKS {
        let reply = crate::to_git::create_repo(name).await;
        let Some(r) = reservation(name) else {
            return if repo_exists(name) {
                Ok(())
            } else {
                Err(format!("the creation of '{name}' was settled meanwhile: it was refused and refunded"))
            };
        };
        match reply {
            Ok(Ok(())) => {
                crate::kv::remove(&reservation_key(name));
                save_meta(
                    name,
                    &RepoMeta {
                        owner: Some(r.owner),
                        members: Vec::new(),
                        storage_bytes: 0,
                        rent_paid_to_ns: now_ns(),
                        delinquent: false,
                        required_votes: 0,
                        app_canister: None,
                        created_ns: now_ns(),
                        require_signed_push: false,
                        governed: false,
                        proposals: Vec::new(),
                        label: Some(r.label),
                    },
                );
                crate::mirrors::flush(name).await;
                return Ok(());
            }
            Ok(Err(e)) => {
                crate::kv::remove(&reservation_key(name));
                if r.fee > 0 {
                    refund(&r.owner, r.fee);
                }
                return Err(e);
            }
            Err(f) => failure = Some(f),
        }
    }
    let f = failure.expect("asked at least once");
    let owner = reservation(name).map(|r| r.owner.to_text()).unwrap_or_default();
    Err(format!(
        "the git side did not answer the creation of '{name}' ({f}); the name and the fee are kept for {owner}: \
         call create_repo again to finish"
    ))
}

/// On a governed repo, a change to who approves or what deploys is a vote,
/// not an owner's call: the owner-only mutators refuse it and point at the
/// one path that takes it. `variant` names the PolicyChange arm when the
/// caller has one to point at.
pub fn locked(m: &RepoMeta, what: &str, variant: Option<&str>) -> Result<(), String> {
    if m.governed {
        let arm = variant.map(|v| format!(" ({v})")).unwrap_or_default();
        return Err(format!(
            "repo is governed: {what} is a policy change, which the voters decide; \
             cast it with propose_policy_change{arm}"
        ));
    }
    Ok(())
}

pub async fn add_member(
    repo: &str,
    who: &Principal,
    operator: bool,
    target: Principal,
    role: Role,
) -> Result<Vec<Member>, String> {
    let mut m = can_admin(repo, who, operator)?;
    // Writers do not approve, so a governed repo's owner still manages them;
    // a voter row, added or replaced, is the policy.
    if role == Role::Voter || has_role(&m, &target, Role::Voter) {
        locked(&m, "changing the voters", Some("AddVoter, RemoveVoter"))?;
    }
    add_member_in(&mut m, target, role)?;
    save_meta(repo, &m);
    crate::mirrors::flush(repo).await;
    Ok(m.members)
}

fn add_member_in(m: &mut RepoMeta, target: Principal, role: Role) -> Result<(), String> {
    if target == Principal::anonymous() {
        return Err("the anonymous principal cannot be a member".into());
    }
    if is_owner(m, &target) {
        return Err("the owner already has every role".into());
    }
    m.members.retain(|x| x.principal != target);
    m.members.push(Member {
        principal: target,
        role,
    });
    Ok(())
}

pub async fn remove_member(
    repo: &str,
    who: &Principal,
    operator: bool,
    target: Principal,
) -> Result<Vec<Member>, String> {
    let mut m = can_admin(repo, who, operator)?;
    if has_role(&m, &target, Role::Voter) {
        locked(&m, "removing a voter", Some("RemoveVoter"))?;
    }
    remove_member_in(&mut m, repo, target)?;
    save_meta(repo, &m);
    crate::mirrors::flush(repo).await;
    Ok(m.members)
}

fn remove_member_in(m: &mut RepoMeta, repo: &str, target: Principal) -> Result<(), String> {
    let before = m.members.len();
    m.members.retain(|x| x.principal != target);
    if m.members.len() == before {
        return Err(format!("{target} is not a member of {repo}"));
    }
    check_policy(m)
}

/// Hand a repo to a new owner, who pays from then on.
pub async fn transfer_repo(
    repo: &str,
    who: &Principal,
    operator: bool,
    new_owner: Principal,
) -> Result<(), String> {
    let mut m = can_admin(repo, who, operator)?;
    locked(&m, "transferring the repo", Some("Transfer"))?;
    transfer_in(&mut m, new_owner)?;
    save_meta(repo, &m);
    crate::mirrors::flush(repo).await;
    Ok(())
}

fn transfer_in(m: &mut RepoMeta, new_owner: Principal) -> Result<(), String> {
    if new_owner == Principal::anonymous() {
        return Err("cannot transfer to the anonymous principal".into());
    }
    m.owner = Some(new_owner);
    m.members.retain(|x| x.principal != new_owner);
    check_policy(m)
}

/// Approvals a commit needs before it deploys. A `k` above the owner plus
/// voters is refused: a threshold nobody could reach is a configuration
/// error, not a strict policy, and `vote` would refuse every ballot under it.
pub async fn set_required_votes(repo: &str, who: &Principal, operator: bool, k: u32) -> Result<(), String> {
    let mut m = can_admin(repo, who, operator)?;
    locked(&m, "changing the required votes", Some("RequiredVotes"))?;
    set_required_votes_in(&mut m, k)?;
    save_meta(repo, &m);
    crate::mirrors::flush(repo).await;
    Ok(())
}

fn set_required_votes_in(m: &mut RepoMeta, k: u32) -> Result<(), String> {
    if m.governed && k == 0 {
        return Err("a governed repo keeps at least one required vote: with 0 a push would deploy unapproved".into());
    }
    m.required_votes = k;
    check_policy(m)
}

// --- governance ------------------------------------------------------------------
//
// docs/GOVERNANCE.md, section 2. `govern` is the one-way step (apps.rs makes
// the controller change; this records it); from then on the mutators above
// are locked and every change to the policy, or to what the deploy installs,
// goes through `propose_policy_change`: a ballot on the change itself, under
// the same K-of-N rule and the same objection rule as a commit, applied the
// moment it is reached.

/// A change to a governed repo's policy, or to what its deploy installs.
/// Serialized canonically (serde_json, field order fixed) to make the vote
/// subject: the same change proposed twice is one subject, so approvals
/// accumulate on it.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PolicyChange {
    RequiredVotes { k: u32 },
    AddVoter { principal: Principal },
    RemoveVoter { principal: Principal },
    Transfer { new_owner: Principal },
    /// The wasm deploy's target canister and source path (set_wasm_deploy).
    WasmDeploy { target: String, source_path: String },
    /// The install mode, "upgrade" or "reinstall" (set_deploy_mode).
    DeployMode { mode: String },
}

impl PolicyChange {
    /// The change in a sentence fragment, for the feed. The wallet's consent
    /// message (consent.rs) has its own, shortened for a signer's screen.
    pub fn describe(&self) -> String {
        match self {
            PolicyChange::RequiredVotes { k } => format!("require {k} vote{} per commit", if *k == 1 { "" } else { "s" }),
            PolicyChange::AddVoter { principal } => format!("add {principal} as a voter"),
            PolicyChange::RemoveVoter { principal } => format!("remove voter {principal}"),
            PolicyChange::Transfer { new_owner } => format!("transfer the repo to {new_owner}"),
            PolicyChange::WasmDeploy { target, source_path } => format!("deploy {source_path} to canister {target}"),
            PolicyChange::DeployMode { mode } => format!("set the install mode to {mode}"),
        }
    }

    fn subject(&self) -> Subject {
        let canonical = serde_json::to_vec(self).expect("a PolicyChange serializes");
        Subject::of_bytes("policy", &canonical)
    }

    /// Why this change could not apply to `m` now, if it could not. Checked
    /// when proposed, so nobody votes on an impossible change, and again
    /// when applied, since the policy may have moved under it.
    fn check(&self, m: &RepoMeta, repo: &str) -> Result<(), String> {
        let mut trial = m.clone();
        self.apply_to(&mut trial, repo)
    }

    /// Apply to the metadata (the deploy config is applied by the caller,
    /// which owns that module; here it is only checked to be applicable, so
    /// the caller's apply cannot fail after the ballots are cleared). Fails
    /// without saving anything.
    fn apply_to(&self, m: &mut RepoMeta, repo: &str) -> Result<(), String> {
        match self {
            PolicyChange::RequiredVotes { k } => set_required_votes_in(m, *k),
            PolicyChange::AddVoter { principal } => add_member_in(m, *principal, Role::Voter),
            PolicyChange::RemoveVoter { principal } => {
                if !has_role(m, principal, Role::Voter) {
                    return Err(format!("{principal} is not a voter on {repo}"));
                }
                remove_member_in(m, repo, *principal)
            }
            PolicyChange::Transfer { new_owner } => transfer_in(m, *new_owner),
            PolicyChange::WasmDeploy { target, source_path } => {
                Principal::from_text(target).map_err(|e| format!("bad target principal: {e}"))?;
                crate::deploy::SourceKind::for_repo(m.governed, source_path).map(|_| ())
            }
            PolicyChange::DeployMode { mode } => {
                crate::deploy::DeployMode::parse(mode)?;
                // set_mode has nothing to change the mode of without one.
                if crate::configs::get_wasm(repo).is_none() {
                    return Err(format!("{repo} has no deploy config to set the install mode of; propose WasmDeploy first"));
                }
                Ok(())
            }
        }
    }
}

/// How many pending policy changes one approver may hold an approval on. A
/// change is pending by approval: the ballot that proposes it is an
/// approval, and a change nobody approves any more is dropped. So the
/// pending list is bounded by this times the approvers, and no one voter
/// can fill it for the others: the changes they hold are theirs to
/// withdraw, and a slot nobody else approves goes with the withdrawal. A
/// single cap on the repo would let one voter propose up to it and lock
/// everyone else's policy changes out, with nothing the others could do
/// but approve one of theirs.
const MAX_HELD_PROPOSALS: usize = 8;

/// A pending or just-decided policy change and where its ballots stand.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Proposal {
    pub change: PolicyChange,
    pub ballots: Vec<Ballot>,
    pub approvals: u32,
    pub objections: u32,
    pub required: u32,
    pub reached: bool,
}

/// Mark the repo governed, before its app canister's controllers change:
/// the flag locks the policy, and the lock must hold while the controller
/// call is in flight, or the owner could set required votes to 0 meanwhile
/// and the repo would end up governed in name while every push deploys
/// unapproved into a canister this canister alone controls. The caller
/// clears the flag again (`unmark_governed`) if the controller call fails.
/// Owner only: an operator may do anything to this canister, but handing a
/// tenant's backend to it is the tenant's decision. Refused with no app
/// canister, when already governed (a second call while the first is in
/// flight included), or with required votes at 0: governing a repo whose
/// pushes deploy unapproved would lock in nothing. Returns the app canister.
pub fn mark_governed(repo: &str, who: &Principal) -> Result<Principal, String> {
    let mut m = meta(repo).ok_or_else(|| format!("no such repo: {repo}"))?;
    if !is_owner(&m, who) {
        return Err(format!("{who} does not own repo {repo}; only the owner can govern it"));
    }
    if m.governed {
        return Err(format!("repo {repo} is already governed"));
    }
    let app = m
        .app_canister
        .ok_or_else(|| format!("repo {repo} has no app canister; call create_app_canister"))?;
    if m.required_votes == 0 {
        return Err("set required votes to 1 or more first: a governed repo deploys only approved commits".into());
    }
    if let Some(cfg) = crate::configs::get_wasm(repo) {
        crate::deploy::SourceKind::for_repo(true, &cfg.source_path)
            .map_err(|e| format!("{e}; point the deploy config at a committed .wasm first"))?;
    }
    m.governed = true;
    save_meta(repo, &m);
    Ok(app)
}

/// The controller call `mark_governed` was made for has failed: the app
/// canister is as it was, so the repo is not governed after all. The only
/// way the flag comes off.
pub fn unmark_governed(repo: &str) {
    if let Some(mut m) = meta(repo) {
        m.governed = false;
        save_meta(repo, &m);
    }
}

/// Cast a ballot on a policy change. Any approver may; the change is
/// validated against the current policy before the ballot is taken, and
/// applied -- to the metadata here, to the deploy config by the caller when
/// `apply_deploy` is returned -- the moment approvals minus objections reach
/// the threshold. Its ballots are then cleared, so proposing the same change
/// again later starts from nothing.
///
/// A change is proposed by approving it: the first ballot on a change not
/// pending must be an approval (there is nothing to reject yet), and a
/// pending change whose approvals fall to none -- its approvers having
/// replaced theirs with rejections -- is withdrawn, ballots and all. Each
/// approver holds at most `MAX_HELD_PROPOSALS` pending changes that way.
///
/// Works on an ungoverned repo too, where the owner could also just make
/// the change -- but not with no votes required: under K = 0 every subject
/// is reached at once, so any voter's ballot would apply any change (the
/// repo to themselves, say). There is nothing to vote on; the owner changes
/// it.
pub async fn propose_policy_change(
    repo: &str,
    who: &Principal,
    change: PolicyChange,
    decision: Vote,
    reason: Option<String>,
) -> Result<(Tally, Option<PolicyChange>), String> {
    let mut m = can_vote(repo, who)?;
    if m.required_votes == 0 {
        return Err(format!("{repo} requires no votes, so there is nothing to vote on; the owner changes its policy directly"));
    }
    let subj = change.subject();
    let pending = m.proposals.contains(&change);
    if !pending && decision != Vote::Approve {
        return Err(format!("no such policy change is pending on {repo}; a change is proposed by approving it"));
    }
    if let Err(e) = change.check(&m, repo) {
        if pending {
            // It could apply when proposed; the policy has moved under it
            // since (a voter it would remove left, say). Every later ballot
            // would be refused here, so it is dropped, ballots and all,
            // rather than listed as pending for good.
            VoteStore { repo }.save(&subj, Vec::new());
            m.proposals.retain(|p| p != &change);
            save_meta(repo, &m);
            crate::mirrors::flush(repo).await;
            return Err(format!("{e}; the pending proposal is dropped"));
        }
        return Err(e);
    }
    if !pending && held_proposals(repo, &m, who) >= MAX_HELD_PROPOSALS {
        return Err(format!(
            "{who} already approves {MAX_HELD_PROPOSALS} pending policy changes on {repo}; \
             withdraw one (a Reject ballot on it) or see one decided first"
        ));
    }
    let reason = ballot_reason(decision, reason)?;
    let mut approval = Approval::new(Approver::from(*who), decision.into(), now_ns());
    approval.reason = reason;
    let tally = ic_multisig::record(&mut VoteStore { repo }, &policy(&m), &subj, approval)
        .map_err(|e| e.to_string())?;
    let mut apply_deploy = None;
    if tally.reached {
        // `check` just passed on this same `m`, so this applies.
        change.apply_to(&mut m, repo)?;
        if matches!(change, PolicyChange::WasmDeploy { .. } | PolicyChange::DeployMode { .. }) {
            apply_deploy = Some(change.clone());
        }
        VoteStore { repo }.save(&subj, Vec::new());
        m.proposals.retain(|p| p != &change);
    } else if tally.approvals == 0 {
        // The last approval it had was just replaced: withdrawn. The other
        // ballots go with it; they were on a change nobody proposes.
        VoteStore { repo }.save(&subj, Vec::new());
        m.proposals.retain(|p| p != &change);
    } else if !pending {
        m.proposals.push(change);
    }
    save_meta(repo, &m);
    crate::mirrors::flush(repo).await;
    Ok((tally, apply_deploy))
}

/// The pending changes `who` holds an approval on.
fn held_proposals(repo: &str, m: &RepoMeta, who: &Principal) -> usize {
    let me = Approver::from(*who);
    m.proposals
        .iter()
        .filter(|c| {
            VoteStore { repo }
                .load(&c.subject())
                .iter()
                .any(|a| a.approver == me && a.decision == Decision::Approve)
        })
        .count()
}

/// The repo's pending policy changes, each with its ballots and count.
pub fn proposals(repo: &str) -> Vec<Proposal> {
    let Some(m) = meta(repo) else { return Vec::new() };
    let pol = policy(&m);
    m.proposals
        .iter()
        .map(|change| {
            let subj = change.subject();
            let records = VoteStore { repo }.load(&subj);
            let ballots = Ballots::assume_checked(&subj, records.clone());
            let t = ic_multisig::tally_checked(&pol, &subj, &ballots);
            Proposal {
                change: change.clone(),
                ballots: records.into_iter().filter_map(|a| ballot(a, Some(&pol))).collect(),
                approvals: t.approvals,
                objections: t.objections,
                required: t.required,
                reached: t.reached,
            }
        })
        .collect()
}

/// Repos a principal owns or is a member of.
pub fn repos_of(p: &Principal) -> Vec<String> {
    crate::records::repo_meta_all::<RepoMeta>()
        .into_iter()
        .filter(|(_, m)| is_owner(m, p) || m.members.iter().any(|x| &x.principal == p))
        .map(|(name, _)| name)
        .collect()
}

// --- votes ----------------------------------------------------------------------
//
// The rules -- who counts, one ballot per approver, threshold reached or not
// -- live in the ic-multisig crate, shared with ic-vote. This module only
// supplies the policy (owner plus voters, threshold = required_votes), the
// subject (the commit), and storage over the VOTES stable map, scoped by repo.

use ic_multisig::{Approval, Approver, Ballots, Decision, Policy, Store, Subject};
pub use ic_multisig::Tally;

/// Which way a ballot goes. Approve counts 1, Reject 0 (a "no", or an
/// approval withdrawn), Object -1 with a reason: a commit passes when
/// approvals minus objections reach the threshold. The crate's `Decision`
/// with ic-git's candid name.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vote {
    Approve,
    Reject,
    Object,
}

impl From<Vote> for Decision {
    fn from(v: Vote) -> Self {
        match v {
            Vote::Approve => Decision::Approve,
            Vote::Reject => Decision::Reject,
            Vote::Object => Decision::Object,
        }
    }
}

impl From<Decision> for Vote {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Approve => Vote::Approve,
            Decision::Reject => Vote::Reject,
            Decision::Object => Vote::Object,
        }
    }
}

/// A ballot as the API reports it. Converted from the crate's record.
/// `approve` stays for clients that predate `decision`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Ballot {
    pub principal: Principal,
    pub approve: bool,
    pub decision: Vote,
    pub reason: Option<String>,
    pub at_ns: u64,
    /// Whether the tally counts this ballot: its caster is the owner or a
    /// voter right now. A ballot stays on record when its caster leaves the
    /// policy, and stops counting.
    pub counts: bool,
}

/// The API view of a stored record under `pol`, the repo's policy if it has
/// one. `None` only for an approver that is not a principal, which this
/// store never writes: every ballot here comes from an authenticated caller.
fn ballot(a: Approval, pol: Option<&Policy>) -> Option<Ballot> {
    Some(Ballot {
        principal: a.approver.principal()?,
        counts: pol.is_some_and(|p| p.is_approver(&a.approver)),
        approve: a.approves(),
        decision: a.decision.into(),
        reason: a.reason,
        at_ns: a.at_ns,
    })
}

fn policy(m: &RepoMeta) -> Policy {
    let approvers = m
        .owner
        .iter()
        .copied()
        .chain(
            m.members
                .iter()
                .filter(|x| x.role == Role::Voter)
                .map(|x| x.principal),
        )
        .map(Approver::from);
    Policy::new(approvers, m.required_votes)
}

/// The policy must stay reachable: `record` refuses every ballot under a
/// threshold above the approver count, so the mutators that raise the
/// threshold or shrink the approver set check here before saving.
fn check_policy(m: &RepoMeta) -> Result<(), String> {
    policy(m)
        .validate()
        .map_err(|e| format!("{e}; lower required_votes or add voters first"))
}

fn subject(oid: &Oid) -> Subject {
    Subject::of_short_hash("commit", oid.as_slice())
}

/// Ballots of one repo, keyed in the VOTES map by the subject key.
struct VoteStore<'a> {
    repo: &'a str,
}

impl Store for VoteStore<'_> {
    fn load(&self, subject: &Subject) -> Vec<Approval> {
        crate::records::votes_get(self.repo, &subject.key()).unwrap_or_default()
    }

    fn save(&mut self, subject: &Subject, ballots: Vec<Approval>) {
        crate::records::votes_set(self.repo, &subject.key(), &ballots);
    }
}

pub fn votes(repo: &str, commit_hex: &str) -> Vec<Ballot> {
    let Ok(oid) = parse_oid(commit_hex) else {
        return Vec::new();
    };
    let pol = meta(repo).map(|m| policy(&m));
    VoteStore { repo }
        .load(&subject(&oid))
        .into_iter()
        .filter_map(|a| ballot(a, pol.as_ref()))
        .collect()
}

/// The count of a commit's stored ballots under `pol`.
fn count(repo: &str, pol: &Policy, oid: &Oid) -> Tally {
    // These ballots came out of the store `record` wrote, and each was
    // checked on the way in (the caller was authenticated by the IC; there
    // is no signature to verify). The crate is told so, rather than asked
    // to re-verify a list that has nothing to verify.
    count_subject(repo, pol, &subject(oid))
}

fn count_subject(repo: &str, pol: &Policy, subj: &Subject) -> Tally {
    let ballots = Ballots::assume_checked(subj, VoteStore { repo }.load(subj));
    ic_multisig::tally_checked(pol, subj, &ballots)
}

/// A count as ic-git reports it: the same answer as `approved`. With no
/// votes required an objection is on record but gates nothing, where the
/// crate alone would have it wait for an approval.
fn ungated(mut t: Tally, m: &RepoMeta) -> Tally {
    t.reached |= m.required_votes == 0;
    t
}

/// The standing of a commit under its repo's policy: the ballots that count
/// and whether they reach the threshold. With no votes required there is
/// nothing to count, and `reached` is true. `None` for a repo that does
/// not exist, or a commit id that does not parse.
pub fn tally(repo: &str, commit_hex: &str) -> Option<Tally> {
    let m = meta(repo)?;
    let oid = parse_oid(commit_hex).ok()?;
    Some(ungated(count(repo, &policy(&m), &oid), &m))
}

/// A ballot's reason as it is stored, or why the ballot is refused: trimmed,
/// and an empty one is no reason. An objection must have one, and none may
/// be longer than 1 KB. The rule is the crate's (`Approval::validate`); it
/// is here so the consent message describes only a ballot `cast_ballot`
/// would accept.
pub fn ballot_reason(decision: Vote, reason: Option<String>) -> Result<Option<String>, String> {
    let mut probe = Approval::new(Approver::from_bytes(Vec::new()), decision.into(), 0);
    probe.reason = reason.map(|r| r.trim().to_string()).filter(|r| !r.is_empty());
    probe.validate().map_err(|e| e.to_string())?;
    Ok(probe.reason)
}

/// A ballot cast: the tally it leaves -- approvals and objections so far,
/// the threshold, and whether it is reached -- and whether the threshold
/// was reached before it, read once the git side had answered, so the
/// feed can tell a ballot that reached it from one cast after.
#[derive(Clone, Debug)]
pub struct Cast {
    pub tally: Tally,
    pub was_reached: bool,
}

/// Cast or replace a ballot. An objection must give a reason (at most 1 KB);
/// a reason on an approval or rejection is kept but not required.
///
/// The git side is asked whether it holds the commit before the ballot is
/// counted; one it does not answer for is not cast, and the voter asks
/// again.
pub async fn cast_ballot(
    repo: &str,
    who: &Principal,
    commit_hex: &str,
    decision: Vote,
    reason: Option<String>,
) -> Result<Cast, String> {
    can_vote(repo, who)?;
    let oid = parse_oid(commit_hex)?;
    match crate::to_git::has_commit(&oid).await {
        Ok(true) => {}
        Ok(false) => return Err(format!("no such commit in {repo}: {commit_hex}")),
        Err(f) => {
            return Err(format!(
                "the git side did not say whether it holds {commit_hex} ({f}); the ballot is not cast, try again"
            ))
        }
    }
    // The policy may have changed while the git side answered.
    let m = can_vote(repo, who)?;
    let was_reached = ungated(count(repo, &policy(&m), &oid), &m).reached;
    let mut approval = Approval::new(Approver::from(*who), decision.into(), now_ns());
    approval.reason = ballot_reason(decision, reason)?;
    let tally = ic_multisig::record(&mut VoteStore { repo }, &policy(&m), &subject(&oid), approval)
        .map(|t| ungated(t, &m))
        .map_err(|e| e.to_string())?;
    // The write asks the git side to retry the served commit's deploy
    // (mirrors::mark_ballot): the site and the app follow the approvals
    // there (phase 3, step 9).
    crate::mirrors::mark_ballot(repo);
    crate::mirrors::flush(repo).await;
    Ok(Cast { tally, was_reached })
}

/// The original two-way ballot, kept for clients that predate objections.
pub async fn vote(
    repo: &str,
    who: &Principal,
    commit_hex: &str,
    approve: bool,
) -> Result<Cast, String> {
    let decision = if approve { Vote::Approve } else { Vote::Reject };
    cast_ballot(repo, who, commit_hex, decision, None).await
}

/// May the deploy queue run this commit? Yes when the repo requires no votes
/// (the default) or enough voters have approved.
pub fn approved(repo: &str, commit_hex: &str) -> bool {
    let Some(m) = meta(repo) else { return true };
    if m.required_votes == 0 {
        return true;
    }
    let Ok(oid) = parse_oid(commit_hex) else { return false };
    reached(repo, &policy(&m), &oid)
}

fn reached(repo: &str, pol: &Policy, oid: &Oid) -> bool {
    count(repo, pol, oid).reached
}

// --- charges ------------------------------------------------------------------------

/// Charge a push against the repo owner and attribute its bytes to the repo.
/// Called before the pack is ingested; an `Err` means the push must be
/// refused untouched.
pub fn charge_push(repo: &str, bytes: usize) -> Result<(), String> {
    let mut m = existing(repo)?;
    if exempt(&m) {
        // No fee, but an owned repo still counts its bytes: if the owner
        // stops being an operator, rent covers what was pushed meanwhile.
        // An ownerless repo has no one to charge them to.
        if m.owner.is_some() {
            m.storage_bytes = m.storage_bytes.saturating_add(bytes as u64);
            save_meta(repo, &m);
        }
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
    // The push is git-side work: its fee funds the git canister.
    crate::funding::earn(fee);
    m.storage_bytes = m.storage_bytes.saturating_add(bytes as u64);
    save_meta(repo, &m);
    Ok(())
}

/// Charge a deploy-queue action (an IC install, an EVM deploy or publish).
/// Returns who paid, `None` for an exempt repo, so a caller whose action
/// then fails before consuming anything can `refund` that principal.
pub fn charge_action(repo: &str, cycles: u64, what: &str) -> Result<Option<Principal>, String> {
    let m = existing(repo)?;
    if exempt(&m) {
        return Ok(None);
    }
    if m.delinquent {
        return Err(format!("repo {repo} is behind on storage rent; deposit cycles to resume"));
    }
    let owner = m.owner.expect("non-exempt repo has an owner");
    debit(&owner, cycles, what)?;
    Ok(Some(owner))
}

/// Give back part of a `charge_action` charge. `payer` is what it returned;
/// an exempt repo (`None`) paid nothing and gets nothing.
pub fn refund_action(payer: Option<Principal>, cycles: u64) {
    if let (Some(p), true) = (payer, cycles > 0) {
        refund(&p, cycles);
    }
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
    for (name, mut m) in crate::records::repo_meta_all::<RepoMeta>() {
        if exempt(&m) {
            // Keep the rent clock running, so an owner who stops being an
            // operator pays from then on, not back to the repo's creation.
            if m.rent_paid_to_ns < now {
                m.rent_paid_to_ns = now;
                save_meta(&name, &m);
            }
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
    // Rent is for the bytes the git canister holds: it funds the git
    // canister.
    crate::funding::earn(collected);
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
    pub require_signed_push: bool,
    pub governed: bool,
}

pub fn repo_info(repo: &str) -> Option<RepoInfo> {
    let m = existing(repo).ok()?;
    Some(RepoInfo {
        exempt: exempt(&m),
        owner: m.owner,
        members: m.members,
        storage_bytes: m.storage_bytes,
        delinquent: m.delinquent,
        required_votes: m.required_votes,
        app_canister: m.app_canister,
        require_signed_push: m.require_signed_push,
        governed: m.governed,
    })
}

/// Whether the repo is governed (govern_app_canister).
pub fn is_governed(repo: &str) -> bool {
    meta(repo).is_some_and(|m| m.governed)
}

/// Whether an install into `target` is an install into the repo's governed
/// app canister -- what the deploy queue records as `<repo>#app`. A governed
/// repo whose deploy config points elsewhere installs nothing into the
/// governed canister, so there is nothing to record.
pub fn governed_target(repo: &str, target: &str) -> bool {
    meta(repo).is_some_and(|m| m.governed && m.app_canister.is_some_and(|c| c.to_text() == target))
}

/// Turn required signed pushes on or off (owner or operator).
pub async fn set_require_signed_push(repo: &str, who: &Principal, operator: bool, on: bool) -> Result<(), String> {
    let mut m = can_admin(repo, who, operator)?;
    m.require_signed_push = on;
    save_meta(repo, &m);
    crate::mirrors::flush(repo).await;
    Ok(())
}

pub fn set_app_canister(repo: &str, canister: Principal) -> Result<(), String> {
    let mut m = existing(repo)?;
    m.app_canister = Some(canister);
    save_meta(repo, &m);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::set_test_now;
    use crate::store;

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 8])
    }

    // The flows that await the git side, driven to completion: in one
    // canister every answer is ready at once. These shadow the module's
    // async functions for the tests below, which read as the calls they
    // make.
    fn run<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    fn create_repo(name: &str, who: &Principal, operator: bool) -> Result<(), String> {
        run(super::create_repo(name, who, operator))
    }

    fn add_member(repo: &str, who: &Principal, operator: bool, target: Principal, role: Role) -> Result<Vec<Member>, String> {
        run(super::add_member(repo, who, operator, target, role))
    }

    fn remove_member(repo: &str, who: &Principal, operator: bool, target: Principal) -> Result<Vec<Member>, String> {
        run(super::remove_member(repo, who, operator, target))
    }

    fn transfer_repo(repo: &str, who: &Principal, operator: bool, new_owner: Principal) -> Result<(), String> {
        run(super::transfer_repo(repo, who, operator, new_owner))
    }

    fn set_required_votes(repo: &str, who: &Principal, operator: bool, k: u32) -> Result<(), String> {
        run(super::set_required_votes(repo, who, operator, k))
    }

    fn set_require_signed_push(repo: &str, who: &Principal, operator: bool, on: bool) -> Result<(), String> {
        run(super::set_require_signed_push(repo, who, operator, on))
    }

    fn cast_ballot(repo: &str, who: &Principal, commit_hex: &str, decision: Vote, reason: Option<String>) -> Result<Tally, String> {
        run(super::cast_ballot(repo, who, commit_hex, decision, reason)).map(|c| c.tally)
    }

    fn vote(repo: &str, who: &Principal, commit_hex: &str, approve: bool) -> Result<Tally, String> {
        run(super::vote(repo, who, commit_hex, approve)).map(|c| c.tally)
    }

    fn propose_policy_change(repo: &str, who: &Principal, change: PolicyChange, decision: Vote, reason: Option<String>) -> Result<(Tally, Option<PolicyChange>), String> {
        run(super::propose_policy_change(repo, who, change, decision, reason))
    }


    /// (approvals, required) of a successful vote.
    fn counts(t: Result<Tally, String>) -> (u32, u32) {
        let t = t.unwrap();
        (t.approvals, t.required)
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
        // A name store refuses (bad, or a taken label) costs nothing.
        credit(&alice, pricing().create_repo);
        for refused in [".dot", "T_OK", "_"] {
            assert!(create_repo(refused, &alice, false).is_err(), "{refused}");
            assert_eq!(balance(&alice), pricing().create_repo, "{refused}");
        }
    }

    #[test]
    fn roles_gate_write_admin_and_vote() {
        let (alice, bob, carol, dave) = (p(11), p(12), p(13), p(14));
        credit(&alice, 10_000_000_000);
        create_repo("t-roles", &alice, false).unwrap();
        // Strangers can do nothing.
        assert!(crate::mirror::may_write("t-roles", &bob, false).is_err());
        assert!(can_admin("t-roles", &bob, false).is_err());
        assert!(can_vote("t-roles", &bob).is_err());
        // Only the owner (or an operator) adds members.
        assert!(add_member("t-roles", &bob, false, carol, Role::Writer).is_err());
        add_member("t-roles", &alice, false, bob, Role::Writer).unwrap();
        add_member("t-roles", &alice, false, carol, Role::Voter).unwrap();
        assert!(crate::mirror::may_write("t-roles", &bob, false).is_ok());
        assert!(can_admin("t-roles", &bob, false).is_err());
        assert!(can_vote("t-roles", &bob).is_err());
        assert!(can_vote("t-roles", &carol).is_ok());
        assert!(crate::mirror::may_write("t-roles", &carol, false).is_err());
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
        let pool_before = crate::funding::pool();
        // A push charges base + per byte and attributes the bytes.
        charge_push("t-rent", 1000).unwrap();
        assert_eq!(balance(&alice), 1);
        assert_eq!(meta("t-rent").unwrap().storage_bytes, 1000);
        // The fee is git-side work: it funds the git canister.
        let fee = pr.push_base + pr.push_per_byte * 1000;
        assert_eq!(crate::funding::pool(), pool_before + fee);
        // Cannot afford another push.
        assert!(charge_push("t-rent", 1).unwrap_err().contains("insufficient"));
        assert_eq!(crate::funding::pool(), pool_before + fee, "a refused push earns nothing");
        // One year of rent on 1000 bytes.
        let start = now_ns();
        set_test_now(start + YEAR_NS as u64);
        let (charged, collected) = charge_rent_all();
        assert_eq!(charged, 1);
        // Owner had 1 cycle: pays it, goes delinquent.
        assert_eq!(collected, 1);
        assert_eq!(crate::funding::pool(), pool_before + fee + 1, "rent funds the git canister too");
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

    /// An action charge names its payer, and refunding that payer restores
    /// the balance exactly: what a registry publish that fails before its
    /// broadcast relies on.
    #[test]
    fn charged_action_names_payer_for_refund() {
        let bob = p(22);
        let pr = pricing();
        credit(&bob, pr.create_repo + 100);
        create_repo("t-refund", &bob, false).unwrap();
        let before = balance(&bob);
        assert_eq!(charge_action("t-refund", 60, "evm"), Ok(Some(bob)));
        assert_eq!(balance(&bob), before - 60);
        refund(&bob, 60);
        assert_eq!(balance(&bob), before);
        // refund_action: a partial refund to the payer; nothing for an
        // exempt repo's None payer.
        charge_action("t-refund", 60, "evm").unwrap();
        refund_action(Some(bob), 25);
        assert_eq!(balance(&bob), before - 35);
        refund_action(None, 25);
        assert_eq!(balance(&bob), before - 35);
    }

    /// Phase 3 step 7: the authority answers which repos exist, and their
    /// labels, from its own records. A repo the git side holds and the
    /// authority has no record of does not exist for it. One created before
    /// tenancy has an ownerless record, and is exempt.
    #[test]
    fn legacy_repos_are_ownerless_and_exempt() {
        store::create_repo("t-unknown").unwrap();
        assert!(!repo_exists("t-unknown"));
        assert!(charge_push("t-unknown", 1).unwrap_err().contains("no such repo"));
        test_repo("t-legacy");
        let m = meta("t-legacy").unwrap();
        assert_eq!((m.owner, m.label.as_deref()), (None, Some("t-legacy")));

        charge_push("t-legacy", 10_000_000).unwrap();
        assert_eq!(meta("t-legacy").unwrap().storage_bytes, 0, "no one to charge the bytes to");
        assert_eq!(charge_action("t-legacy", u64::MAX, "evm"), Ok(None));
        assert!(repo_info("t-legacy").unwrap().exempt);
        // Anyone may push to a legacy repo only as an operator; tokens still
        // gate the HTTP path.
        assert!(crate::mirror::may_write("t-legacy", &p(31), false).is_err());
        assert!(crate::mirror::may_write("t-legacy", &p(31), true).is_ok());
        // Rent passes it by.
        charge_rent_all();
        assert!(!meta("t-legacy").unwrap().delinquent);
    }

    /// A repo created through the authority records its label.
    #[test]
    fn repos_record_their_labels() {
        let owner = p(32);
        credit(&owner, 10_000_000_000);
        create_repo("My_Labelled", &owner, false).unwrap();
        assert_eq!(meta("My_Labelled").unwrap().label.as_deref(), Some("my-labelled"));
    }

    /// A controller off the allowlist is an operator for billing too, and
    /// the exemption follows it: once removed, its repo pays, with rent from
    /// then on rather than back to creation.
    #[test]
    fn controller_owned_repos_are_exempt_while_controller() {
        let c = p(61);
        set_test_controller(c, true);
        assert!(is_operator(&c));
        create_repo("t-ctl", &c, true).unwrap();
        assert!(repo_info("t-ctl").unwrap().exempt);
        assert_eq!(charge_action("t-ctl", 5, "evm"), Ok(None));
        // A push is free but its bytes still count, for rent if the
        // exemption ends.
        charge_push("t-ctl", 1000).unwrap();
        assert_eq!(balance(&c), 0);
        assert_eq!(meta("t-ctl").unwrap().storage_bytes, 1000);
        // A year exempt: no rent, and the clock moves with it.
        let start = now_ns();
        set_test_now(start + YEAR_NS as u64);
        charge_rent_all();
        assert!(!meta("t-ctl").unwrap().delinquent);
        assert_eq!(meta("t-ctl").unwrap().rent_paid_to_ns, start + YEAR_NS as u64);
        // Removed as controller: the repo is billed like any tenant's.
        set_test_controller(c, false);
        assert!(!is_operator(&c));
        assert!(!repo_info("t-ctl").unwrap().exempt);
        assert!(charge_action("t-ctl", 5, "evm").unwrap_err().contains("insufficient"));
        let pr = pricing();
        credit(&c, 1_000_000_000);
        set_test_now(start + 2 * YEAR_NS as u64);
        let (_, collected) = charge_rent_all();
        assert_eq!(collected, 1000 * pr.rent_per_byte_year);
        set_test_now(start);
    }

    #[test]
    fn only_the_owner_requires_signed_pushes() {
        let (alice, w) = (p(51), p(52));
        credit(&alice, 10_000_000_000);
        create_repo("t-signed", &alice, false).unwrap();
        add_member("t-signed", &alice, false, w, Role::Writer).unwrap();
        assert!(!crate::mirror::requires_signed_push("t-signed"));
        assert!(set_require_signed_push("t-signed", &w, false, true).is_err());
        set_require_signed_push("t-signed", &alice, false, true).unwrap();
        assert!(crate::mirror::requires_signed_push("t-signed"));
        assert!(repo_info("t-signed").unwrap().require_signed_push);
        set_require_signed_push("t-signed", &alice, false, false).unwrap();
        assert!(!crate::mirror::requires_signed_push("t-signed"));
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
        // A threshold nobody could reach is refused; add voters first.
        assert!(set_required_votes("t-vote", &alice, false, 2).is_err());
        add_member("t-vote", &alice, false, v1, Role::Voter).unwrap();
        add_member("t-vote", &alice, false, v2, Role::Voter).unwrap();
        add_member("t-vote", &alice, false, w, Role::Writer).unwrap();
        set_required_votes("t-vote", &alice, false, 2).unwrap();
        assert!(!approved("t-vote", &commit));
        // Writers cannot vote; unknown commits are refused.
        assert!(vote("t-vote", &w, &commit, true).is_err());
        assert!(vote("t-vote", &v1, &"0".repeat(40), true).is_err());
        assert_eq!(counts(vote("t-vote", &v1, &commit, true)), (1, 2));
        assert!(!approved("t-vote", &commit));
        // The owner counts as a voter.
        let t = vote("t-vote", &alice, &commit, true).unwrap();
        assert_eq!((t.approvals, t.required, t.reached), (2, 2, true));
        assert!(approved("t-vote", &commit));
        // A ballot can be changed; a removed voter's ballot stops counting.
        assert_eq!(counts(vote("t-vote", &alice, &commit, false)), (1, 2));
        assert_eq!(counts(vote("t-vote", &v2, &commit, true)), (2, 2));
        remove_member("t-vote", &alice, false, v2).unwrap();
        assert!(!approved("t-vote", &commit));
        assert_eq!(votes("t-vote", &commit).len(), 3);
        // Shrinking the approvers below the threshold is refused too, by
        // removal or by a transfer that drops the new owner's voter row.
        assert!(remove_member("t-vote", &alice, false, v1).is_err());
        assert!(transfer_repo("t-vote", &alice, false, v1).is_err());
        assert_eq!(meta("t-vote").unwrap().owner, Some(alice));
        assert_eq!(repos_of(&v1), vec!["t-vote".to_string()]);
    }

    /// An objection counts -1 and must say why; one more approval outweighs
    /// it. The wiring here is thin (the rule is the crate's), so this checks
    /// what ic-git adds: the reason's handling, the API view, and that
    /// `approved` -- what the site and the deploy queue ask -- follows the
    /// net count.
    #[test]
    fn objections_count_against_and_carry_a_reason() {
        let (alice, v1, v2) = (p(61), p(62), p(63));
        credit(&alice, 10_000_000_000);
        create_repo("t-obj", &alice, false).unwrap();
        let blob = store::put_object(store::ObjectType::Blob, b"y");
        let commit = store::oid_hex(&blob);
        add_member("t-obj", &alice, false, v1, Role::Voter).unwrap();
        add_member("t-obj", &alice, false, v2, Role::Voter).unwrap();
        // With no votes required an objection is recorded and gates
        // nothing: the ballot's reply, the API's count and `approved` agree.
        let t = cast_ballot("t-obj", &v1, &commit, Vote::Object, Some("early".into())).unwrap();
        assert_eq!((t.objections, t.required, t.reached), (1, 0, true));
        assert!(tally("t-obj", &commit).is_some_and(|t| t.reached) && approved("t-obj", &commit));
        vote("t-obj", &v1, &commit, false).unwrap();
        set_required_votes("t-obj", &alice, false, 1).unwrap();
        assert!(tally("t-obj", &commit).is_some_and(|t| !t.reached));

        let t = cast_ballot("t-obj", &alice, &commit, Vote::Approve, None).unwrap();
        assert_eq!((t.approvals, t.objections, t.required, t.reached), (1, 0, 1, true));
        assert!(approved("t-obj", &commit));

        // No reason, or a blank one: refused, and the approval still stands.
        let e = cast_ballot("t-obj", &v1, &commit, Vote::Object, None).unwrap_err();
        assert!(e.contains("reason"), "{e}");
        assert!(cast_ballot("t-obj", &v1, &commit, Vote::Object, Some("  ".into())).is_err());
        assert!(cast_ballot("t-obj", &v1, &commit, Vote::Object, Some("x".repeat(1025))).is_err());
        assert!(approved("t-obj", &commit));

        // With a reason: the commit drops below the threshold.
        let t = cast_ballot("t-obj", &v1, &commit, Vote::Object, Some(" skips the migration ".into())).unwrap();
        assert_eq!((t.approvals, t.objections, t.reached), (1, 1, false));
        assert!(!approved("t-obj", &commit));
        let b = votes("t-obj", &commit);
        let obj = b.iter().find(|b| b.principal == v1).unwrap();
        assert_eq!((obj.decision, obj.approve), (Vote::Object, false));
        assert_eq!(obj.reason.as_deref(), Some("skips the migration"));
        let yes = b.iter().find(|b| b.principal == alice).unwrap();
        assert_eq!((yes.decision, yes.approve, yes.reason.as_deref()), (Vote::Approve, true, None));

        // Not a veto: one more approval outweighs it.
        let t = cast_ballot("t-obj", &v2, &commit, Vote::Approve, None).unwrap();
        assert_eq!((t.approvals, t.objections, t.reached), (2, 1, true));
        assert!(approved("t-obj", &commit));

        // A rejection weighs nothing either way; the old two-way call maps
        // onto it. The objector changing to reject lifts the objection.
        assert_eq!(counts(vote("t-obj", &v2, &commit, false)), (1, 1));
        assert!(!approved("t-obj", &commit));
        let t = vote("t-obj", &v1, &commit, false).unwrap();
        assert_eq!((t.approvals, t.objections, t.reached), (1, 0, true));
        assert!(approved("t-obj", &commit));
        // An approval may carry a reason too; a rejection may as well.
        let t = cast_ballot("t-obj", &v2, &commit, Vote::Approve, Some("reviewed".into())).unwrap();
        assert_eq!(t.approvals, 2);
        assert_eq!(
            votes("t-obj", &commit).iter().find(|b| b.principal == v2).unwrap().reason.as_deref(),
            Some("reviewed")
        );
    }

    /// The git side's mirrors (mirror.rs) follow every change the authority
    /// makes -- members, threshold, ballots, the signed-push flag -- and an
    /// upgrade from a release without them fills them in.
    #[test]
    fn the_mirrors_follow_the_authority() {
        use crate::mirror;
        let (alice, v1, w) = (p(91), p(92), p(93));
        credit(&alice, 10_000_000_000);
        create_repo("t-mirror", &alice, false).unwrap();
        let c = store::put_object(store::ObjectType::Blob, b"mirrored");
        let hex = store::oid_hex(&c);
        assert_eq!(mirror::commit_key(c.as_slice()), subject(&c).key(), "both sides name a commit alike");

        assert!(mirror::approved("t-mirror").is_none(), "no votes required: the tip is served");
        add_member("t-mirror", &alice, false, v1, Role::Voter).unwrap();
        add_member("t-mirror", &alice, false, w, Role::Writer).unwrap();
        assert!(mirror::may_write("t-mirror", &alice, false).is_ok());
        assert!(mirror::may_write("t-mirror", &w, false).is_ok());
        assert!(mirror::may_write("t-mirror", &v1, false).is_err(), "voters do not push");

        set_required_votes("t-mirror", &alice, false, 1).unwrap();
        assert!(!mirror::approved("t-mirror").unwrap().contains(&c));
        vote("t-mirror", &alice, &hex, true).unwrap();
        assert!(mirror::approved("t-mirror").unwrap().contains(&c));
        set_required_votes("t-mirror", &alice, false, 2).unwrap();
        assert!(!mirror::approved("t-mirror").unwrap().contains(&c), "a raised threshold");
        vote("t-mirror", &v1, &hex, true).unwrap();
        assert!(mirror::approved("t-mirror").unwrap().contains(&c));
        cast_ballot("t-mirror", &v1, &hex, Vote::Object, Some("no".into())).unwrap();
        assert!(!mirror::approved("t-mirror").unwrap().contains(&c), "an objection");

        assert!(!mirror::requires_signed_push("t-mirror"));
        set_require_signed_push("t-mirror", &alice, false, true).unwrap();
        assert!(mirror::requires_signed_push("t-mirror"));
    }

    /// A governed repo deploys committed .wasm only: governing waits for a
    /// .wasm config, and afterwards neither a policy change nor the config
    /// setter (which a ballot applies through) accepts a compiled source.
    #[test]
    fn governed_repo_deploys_wasm_only() {
        let (alice, app) = (p(81), p(82));
        credit(&alice, 10_000_000_000);
        create_repo("t-wasm", &alice, false).unwrap();
        set_app_canister("t-wasm", app).unwrap();
        set_required_votes("t-wasm", &alice, false, 1).unwrap();
        let target = app.to_text();

        run(crate::configs::set_wasm("t-wasm", target.clone(), "app.wat".into())).unwrap();
        let e = mark_governed("t-wasm", &alice).unwrap_err();
        assert!(e.contains(".wasm only") && e.contains("app.wat"), "{e}");
        assert!(!meta("t-wasm").unwrap().governed);
        run(crate::configs::set_wasm("t-wasm", target.clone(), "app.wasm".into())).unwrap();
        assert_eq!(mark_governed("t-wasm", &alice).unwrap(), app);

        for path in ["app.wat", "src/app.lang"] {
            let change = PolicyChange::WasmDeploy { target: target.clone(), source_path: path.into() };
            let e = propose_policy_change("t-wasm", &alice, change, Vote::Approve, None).unwrap_err();
            assert!(e.contains(".wasm only"), "{e}");
            assert!(run(crate::configs::set_wasm("t-wasm", target.clone(), path.into())).is_err());
        }
        assert!(proposals("t-wasm").is_empty());
        let change = PolicyChange::WasmDeploy { target: target.clone(), source_path: "v2.wasm".into() };
        let (t, apply) = propose_policy_change("t-wasm", &alice, change, Vote::Approve, None).unwrap();
        assert!(t.reached && apply.is_some());
    }

    /// Governing locks the policy: the owner's mutators refuse what is now
    /// the voters' decision, required votes cannot reach 0, and the one path
    /// left -- a ballot on the change -- applies it exactly when the same
    /// rule a commit passes under is met. Writers stay the owner's.
    #[test]
    fn governed_repo_decides_its_policy_by_vote() {
        let (alice, v1, v2, w, app) = (p(71), p(72), p(73), p(74), p(75));
        credit(&alice, 10_000_000_000);
        create_repo("t-gov", &alice, false).unwrap();
        add_member("t-gov", &alice, false, v1, Role::Voter).unwrap();
        add_member("t-gov", &alice, false, w, Role::Writer).unwrap();

        // Ungoverned with no votes required there is nothing to vote on: a
        // ballot would be reached at once, whatever it said.
        let e = propose_policy_change("t-gov", &v1, PolicyChange::Transfer { new_owner: v1 }, Vote::Reject, None).unwrap_err();
        assert!(e.contains("requires no votes"), "{e}");
        assert_eq!(meta("t-gov").unwrap().owner, Some(alice));

        // Preconditions: an app canister and votes required; owner only.
        assert!(mark_governed("t-gov", &alice).unwrap_err().contains("no app canister"));
        set_app_canister("t-gov", app).unwrap();
        assert!(mark_governed("t-gov", &alice).unwrap_err().contains("required votes"));
        assert!(!meta("t-gov").unwrap().governed);
        set_required_votes("t-gov", &alice, false, 1).unwrap();
        assert!(mark_governed("t-gov", &v1).unwrap_err().contains("only the owner"));
        // The flag goes on before the controller call and locks the policy
        // while it is in flight; a failed call takes it off again.
        assert_eq!(mark_governed("t-gov", &alice).unwrap(), app);
        assert!(repo_info("t-gov").unwrap().governed);
        assert!(set_required_votes("t-gov", &alice, false, 0).unwrap_err().contains("propose_policy_change"));
        assert!(mark_governed("t-gov", &alice).unwrap_err().contains("already governed"));
        unmark_governed("t-gov");
        assert!(!repo_info("t-gov").unwrap().governed);
        set_required_votes("t-gov", &alice, false, 1).unwrap();
        assert_eq!(mark_governed("t-gov", &alice).unwrap(), app);
        assert!(repo_info("t-gov").unwrap().governed);
        assert!(governed_target("t-gov", &app.to_text()));
        assert!(!governed_target("t-gov", &p(99).to_text()));

        // Locked: the owner's direct changes to the policy are refused...
        fn locked<T: std::fmt::Debug>(r: Result<T, String>) -> bool {
            r.unwrap_err().contains("propose_policy_change")
        }
        assert!(locked(set_required_votes("t-gov", &alice, false, 2)));
        assert!(locked(set_required_votes("t-gov", &alice, false, 0)));
        assert!(locked(add_member("t-gov", &alice, false, v2, Role::Voter)));
        assert!(locked(add_member("t-gov", &alice, false, v1, Role::Writer))); // demotes a voter
        assert!(locked(remove_member("t-gov", &alice, false, v1)));
        assert!(locked(transfer_repo("t-gov", &alice, false, v1)));
        // ...and writers are still the owner's to manage.
        remove_member("t-gov", &alice, false, w).unwrap();
        add_member("t-gov", &alice, false, w, Role::Writer).unwrap();

        // A change nobody could apply is refused before any ballot.
        let e = propose_policy_change("t-gov", &alice, PolicyChange::RequiredVotes { k: 0 }, Vote::Approve, None).unwrap_err();
        assert!(e.contains("at least one required vote"), "{e}");
        assert!(propose_policy_change("t-gov", &alice, PolicyChange::RequiredVotes { k: 5 }, Vote::Approve, None).is_err());
        assert!(propose_policy_change("t-gov", &alice, PolicyChange::RemoveVoter { principal: w }, Vote::Approve, None).is_err());
        assert!(propose_policy_change("t-gov", &alice, PolicyChange::DeployMode { mode: "wipe".into() }, Vote::Approve, None).is_err());
        // Only approvers propose.
        assert!(propose_policy_change("t-gov", &w, PolicyChange::RequiredVotes { k: 2 }, Vote::Approve, None).is_err());

        // K = 1 of 2: the owner's approval alone applies a change.
        let (t, apply) = propose_policy_change("t-gov", &alice, PolicyChange::AddVoter { principal: v2 }, Vote::Approve, None).unwrap();
        assert!(t.reached && apply.is_none());
        assert!(meta("t-gov").unwrap().members.iter().any(|m| m.principal == v2 && m.role == Role::Voter));
        assert!(proposals("t-gov").is_empty(), "an applied change is no longer pending");
        let (t, _) = propose_policy_change("t-gov", &alice, PolicyChange::RequiredVotes { k: 2 }, Vote::Approve, None).unwrap();
        assert!(t.reached);
        assert_eq!(meta("t-gov").unwrap().required_votes, 2);

        // K = 2 of 3 now: a proposal waits, is listed with its ballots, an
        // objection holds it, and a second approval over the objection does
        // not reach (1 + 1 - 1 < 2) until a third.
        let change = PolicyChange::RequiredVotes { k: 1 };
        let (t, _) = propose_policy_change("t-gov", &v1, change.clone(), Vote::Approve, None).unwrap();
        assert_eq!((t.approvals, t.required, t.reached), (1, 2, false));
        let pending = proposals("t-gov");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].change, change);
        assert_eq!((pending[0].approvals, pending[0].ballots.len()), (1, 1));
        assert_eq!(meta("t-gov").unwrap().required_votes, 2, "not applied yet");
        let (t, _) = propose_policy_change("t-gov", &v2, change.clone(), Vote::Object, Some("too low for three voters".into())).unwrap();
        assert_eq!((t.approvals, t.objections, t.reached), (1, 1, false));
        let (t, _) = propose_policy_change("t-gov", &alice, change.clone(), Vote::Approve, None).unwrap();
        assert_eq!((t.approvals, t.objections, t.reached), (2, 1, false));
        assert_eq!(proposals("t-gov")[0].ballots.len(), 3);
        // The objector relents: reached, applied, ballots cleared.
        let (t, _) = propose_policy_change("t-gov", &v2, change.clone(), Vote::Approve, None).unwrap();
        assert!(t.reached);
        assert_eq!(meta("t-gov").unwrap().required_votes, 1);
        assert!(proposals("t-gov").is_empty());
        // Proposing the same change again starts from nothing.
        let (t, _) = propose_policy_change("t-gov", &v1, PolicyChange::RequiredVotes { k: 2 }, Vote::Approve, None).unwrap();
        assert!(t.reached, "K is 1 again, so one approval applies");
        let (t, _) = propose_policy_change("t-gov", &v1, PolicyChange::RequiredVotes { k: 1 }, Vote::Approve, None).unwrap();
        assert_eq!((t.approvals, t.reached), (1, false), "the old ballots on this change were cleared");

        // Deploy config changes are decided here but applied by the caller;
        // an install mode with no config to set it on is refused up front,
        // not after the ballots are cleared.
        let e = propose_policy_change("t-gov", &v1, PolicyChange::DeployMode { mode: "reinstall".into() }, Vote::Approve, None).unwrap_err();
        assert!(e.contains("no deploy config"), "{e}");
        run(crate::configs::set_wasm("t-gov", app.to_text(), "app.wasm".into())).unwrap();
        let (t, apply) = propose_policy_change("t-gov", &v1, PolicyChange::DeployMode { mode: "reinstall".into() }, Vote::Approve, None).unwrap();
        assert!(!t.reached && apply.is_none());
        let (t, apply) = propose_policy_change("t-gov", &alice, PolicyChange::DeployMode { mode: "reinstall".into() }, Vote::Approve, None).unwrap();
        assert!(t.reached);
        assert_eq!(apply, Some(PolicyChange::DeployMode { mode: "reinstall".into() }));

        // Removing a voter and transferring go the same way; a removed
        // voter's ballots stop counting on every pending proposal.
        let (t, _) = propose_policy_change("t-gov", &alice, PolicyChange::Transfer { new_owner: v1 }, Vote::Approve, None).unwrap();
        assert!(!t.reached);
        let (t, _) = propose_policy_change("t-gov", &v1, PolicyChange::Transfer { new_owner: v1 }, Vote::Approve, None).unwrap();
        assert!(t.reached);
        assert_eq!(meta("t-gov").unwrap().owner, Some(v1));
        assert!(!meta("t-gov").unwrap().members.iter().any(|m| m.principal == v1));
        // alice is now a non-member: she cannot propose, and governance holds.
        assert!(propose_policy_change("t-gov", &alice, PolicyChange::RequiredVotes { k: 1 }, Vote::Approve, None).is_err());
        assert!(meta("t-gov").unwrap().governed);

        // A pending change the policy moved under is dropped at the next
        // ballot, not listed for good. Owner v1, voter v2, K = 2; alice is
        // voted back in so that removing v2 would leave a reachable policy
        // and the proposal waits. v2 then becomes the owner by vote, which
        // takes v2 out of the members: removing v2 as a voter can no longer
        // apply.
        for who in [&v1, &v2] {
            propose_policy_change("t-gov", who, PolicyChange::AddVoter { principal: alice }, Vote::Approve, None).unwrap();
        }
        let (t, _) = propose_policy_change("t-gov", &v2, PolicyChange::RemoveVoter { principal: v2 }, Vote::Approve, None).unwrap();
        assert!(!t.reached);
        assert_eq!(proposals("t-gov").len(), 2, "k:1 and remove v2 pending");
        for who in [&v1, &v2] {
            propose_policy_change("t-gov", who, PolicyChange::Transfer { new_owner: v2 }, Vote::Approve, None).unwrap();
        }
        assert_eq!(meta("t-gov").unwrap().owner, Some(v2));
        let e = propose_policy_change("t-gov", &alice, PolicyChange::RemoveVoter { principal: v2 }, Vote::Approve, None).unwrap_err();
        assert!(e.contains("dropped"), "{e}");
        assert_eq!(proposals("t-gov").len(), 1, "only k:1 is still pending");

        // A change is proposed by approving it: a rejection of nothing is
        // refused. The k:1 change still pending was v1's, and v1 is no
        // approver since the transfer: the next ballot on it finds no
        // approval that counts and withdraws it.
        let wasm = |i: usize| PolicyChange::WasmDeploy { target: app.to_text(), source_path: format!("{i}.wasm") };
        let e = propose_policy_change("t-gov", &v2, wasm(0), Vote::Reject, None).unwrap_err();
        assert!(e.contains("proposed by approving"), "{e}");
        assert_eq!(proposals("t-gov").len(), 1);
        let (t, _) = propose_policy_change("t-gov", &v2, PolicyChange::RequiredVotes { k: 1 }, Vote::Reject, None).unwrap();
        assert_eq!(t.approvals, 0);
        assert!(proposals("t-gov").is_empty(), "nobody who counts approves it");

        // Each approver holds a bounded number of pending changes, and one
        // at the bound locks nobody else out. Owner v2, voter alice, K = 2.
        for i in 0..=MAX_HELD_PROPOSALS {
            let r = propose_policy_change("t-gov", &alice, wasm(i), Vote::Approve, None);
            if i < MAX_HELD_PROPOSALS {
                assert!(r.is_ok(), "{i}: {r:?}");
            } else {
                assert!(r.unwrap_err().contains("already approves"));
            }
        }
        assert_eq!(proposals("t-gov").len(), MAX_HELD_PROPOSALS);
        assert!(propose_policy_change("t-gov", &v2, wasm(MAX_HELD_PROPOSALS), Vote::Approve, None).is_ok());
        // A ballot on a change already pending is not a new one, and a
        // rejection beside a counting approval leaves it pending.
        let (t, _) = propose_policy_change("t-gov", &alice, wasm(MAX_HELD_PROPOSALS), Vote::Object, Some("no".into())).unwrap();
        assert_eq!((t.approvals, t.objections, t.reached), (1, 1, false));
        assert_eq!(proposals("t-gov").len(), MAX_HELD_PROPOSALS + 1);
        // Withdrawing: alice replaces her sole approval on one with a
        // rejection, so it is dropped, and the slot is hers again.
        let (t, _) = propose_policy_change("t-gov", &alice, wasm(0), Vote::Reject, None).unwrap();
        assert_eq!((t.approvals, t.reached), (0, false));
        assert!(!proposals("t-gov").iter().any(|p| p.change == wasm(0)), "withdrawn");
        assert!(propose_policy_change("t-gov", &alice, wasm(0), Vote::Reject, None).is_err(), "and its ballots went with it");
        assert!(propose_policy_change("t-gov", &alice, wasm(99), Vote::Approve, None).is_ok());
    }

    // --- phase 3 step 8: the flows that await the git side, against one that
    // refuses, does not run, or loses its answer (to_git::flaky) ------------

    use crate::to_git::flaky::{Flaky, Inject};
    use std::rc::Rc;

    /// Creating a repo reserves the name and takes the fee, then asks the
    /// git side: a refusal refunds and releases; a lost answer is asked
    /// again, and the git side's idempotent create makes that safe; an
    /// answer that never comes leaves the name and the fee with the owner,
    /// who finishes later without paying again.
    #[test]
    fn creating_a_repo_settles_what_the_git_side_answers() {
        let git = Rc::new(Flaky::new());
        crate::to_git::set_test_side(Some(git.clone()));
        let alice = p(41);
        let fee = pricing().create_repo;
        credit(&alice, 10 * fee);

        git.inject("create_repo", Inject::Refuse);
        assert!(create_repo("t-flaky", &alice, false).unwrap_err().contains("refused"));
        assert_eq!(balance(&alice), 10 * fee, "refunded");
        assert!(!repo_exists("t-flaky") && !store::repo_exists("t-flaky"));

        git.inject("create_repo", Inject::Lost);
        create_repo("t-flaky", &alice, false).unwrap();
        assert_eq!(balance(&alice), 9 * fee, "one fee");
        assert!(repo_exists("t-flaky") && store::repo_exists("t-flaky"));
        assert_eq!(git.count("create_repo"), 3, "refused, lost, asked again");
        assert_eq!(meta("t-flaky").unwrap().owner, Some(alice));
        assert!(crate::mirror::may_write("t-flaky", &alice, false).is_ok(), "mirrored once created");

        for _ in 0..CREATE_ASKS {
            git.inject("create_repo", Inject::Lost);
        }
        let e = create_repo("t-kept", &alice, false).unwrap_err();
        assert!(e.contains("kept"), "{e}");
        assert_eq!(balance(&alice), 8 * fee, "the fee is kept with the name");
        assert!(!repo_exists("t-kept") && store::repo_exists("t-kept"), "created, answer lost");
        assert!(!repo_exists("t-kept"), "reserved, not recorded");
        let bob = p(42);
        credit(&bob, fee);
        assert!(create_repo("t-kept", &bob, false).unwrap_err().contains("reserved"));
        assert_eq!(balance(&bob), fee);
        create_repo("t-kept", &alice, false).unwrap();
        assert_eq!(balance(&alice), 8 * fee, "no second fee");
        assert_eq!(meta("t-kept").unwrap().owner, Some(alice));
        assert!(store::repo_exists("t-kept"));
        assert!(create_repo("t-kept", &alice, false).unwrap_err().contains("already exists"));

        // The question before the fee: unanswered, nothing is charged or
        // reserved, and the next call starts over.
        git.inject("check_new_repo", Inject::Lost);
        assert!(create_repo("t-unasked", &alice, false).unwrap_err().contains("nothing was charged"));
        assert_eq!(balance(&alice), 8 * fee);
        create_repo("t-unasked", &alice, false).unwrap();
        assert_eq!(balance(&alice), 7 * fee);
        crate::to_git::set_test_side(None);
    }

    /// A git side on which another call of this canister settles the
    /// reservation while a create_repo waits for its answer: the real one,
    /// whose create_repo records the repo as the other call would, then
    /// answers as told.
    struct Meanwhile {
        real: Flaky,
        refuse: std::cell::Cell<bool>,
    }

    impl ic_git_types::git_side::GitSide for Meanwhile {
        fn set_deploy_configs<'a>(&'a self, repo: &'a str, seq: u64, configs: ic_git_types::git_side::DeployConfigs) -> ic_git_types::side::Fut<'a, ic_git_types::side::Reply<()>> {
            self.real.set_deploy_configs(repo, seq, configs)
        }
        fn set_push_policy<'a>(&'a self, repo: &'a str, seq: u64, policy: ic_git_types::git_side::PushPolicy) -> ic_git_types::side::Fut<'a, ic_git_types::side::Reply<()>> {
            self.real.set_push_policy(repo, seq, policy)
        }
        fn set_approved<'a>(&'a self, repo: &'a str, seq: u64, approved: Option<Vec<String>>, retry: Option<ic_git_types::git_side::Retry>) -> ic_git_types::side::Fut<'a, ic_git_types::side::Reply<()>> {
            self.real.set_approved(repo, seq, approved, retry)
        }
        fn set_site<'a>(&'a self, repo: &'a str, root: String) -> ic_git_types::side::Fut<'a, ic_git_types::side::Reply<Result<(), String>>> {
            self.real.set_site(repo, root)
        }
        fn check_new_repo<'a>(&'a self, name: &'a str) -> ic_git_types::side::Fut<'a, ic_git_types::side::Reply<Result<String, String>>> {
            self.real.check_new_repo(name)
        }
        fn create_repo<'a>(&'a self, name: &'a str) -> ic_git_types::side::Fut<'a, ic_git_types::side::Reply<Result<(), String>>> {
            Box::pin(async move {
                let reply = self.real.create_repo(name).await;
                // The other call's answer came first and settled the name.
                let r = reservation(name).expect("reserved while asked");
                crate::kv::remove(&reservation_key(name));
                save_meta(
                    name,
                    &RepoMeta {
                        owner: Some(r.owner),
                        members: Vec::new(),
                        storage_bytes: 0,
                        rent_paid_to_ns: now_ns(),
                        delinquent: false,
                        required_votes: 0,
                        app_canister: None,
                        created_ns: now_ns(),
                        require_signed_push: false,
                        governed: false,
                        proposals: Vec::new(),
                        label: Some(r.label),
                    },
                );
                if self.refuse.get() {
                    Ok(Err("refused by the git side".into()))
                } else {
                    reply
                }
            })
        }
        fn has_commit<'a>(&'a self, oid: &'a ic_git_types::oid::Oid) -> ic_git_types::side::Fut<'a, ic_git_types::side::Reply<bool>> {
            self.real.has_commit(oid)
        }
        fn record_artifact<'a>(&'a self, repo: &'a str, kind: ic_git_types::git_side::RecordKind) -> ic_git_types::side::Fut<'a, ic_git_types::side::Reply<Result<ic_git_types::git_side::Attested, String>>> {
            self.real.record_artifact(repo, kind)
        }
        fn release_job<'a>(&'a self, repo: &'a str) -> ic_git_types::side::Fut<'a, ic_git_types::side::Reply<Result<ic_git_types::git_side::Release, String>>> {
            self.real.release_job(repo)
        }
    }

    /// A create_repo whose reservation another call settled while it
    /// waited takes that settlement: the repo is the owner's once, and
    /// the fee is neither charged nor refunded again, whatever this
    /// call's answer says.
    #[test]
    fn a_creation_settled_meanwhile_is_not_settled_again() {
        let git = Rc::new(Meanwhile { real: Flaky::new(), refuse: std::cell::Cell::new(false) });
        crate::to_git::set_test_side(Some(git.clone()));
        let alice = p(43);
        let fee = pricing().create_repo;
        credit(&alice, 10 * fee);

        create_repo("t-meanwhile", &alice, false).unwrap();
        assert_eq!(balance(&alice), 9 * fee, "one fee");
        assert_eq!(meta("t-meanwhile").unwrap().owner, Some(alice));

        git.refuse.set(true);
        create_repo("t-meanwhile-2", &alice, false).unwrap();
        assert_eq!(balance(&alice), 8 * fee, "the other call's settlement stands: no refund");
        assert_eq!(meta("t-meanwhile-2").unwrap().owner, Some(alice));
        crate::to_git::set_test_side(None);
    }

    /// A ballot counts only once the git side has said it holds the commit:
    /// one it does not answer for is not cast, and the voter asks again.
    #[test]
    fn a_ballot_waits_for_the_git_side_to_confirm_the_commit() {
        let git = Rc::new(Flaky::new());
        crate::to_git::set_test_side(Some(git.clone()));
        let alice = p(43);
        credit(&alice, 10_000_000_000);
        create_repo("t-ballot", &alice, false).unwrap();
        set_required_votes("t-ballot", &alice, false, 1).unwrap();
        let c = store::put_object(store::ObjectType::Blob, b"ballot");
        let hex = store::oid_hex(&c);

        git.inject("has_commit", Inject::Lost);
        let e = vote("t-ballot", &alice, &hex, true).unwrap_err();
        assert!(e.contains("not cast"), "{e}");
        assert!(votes("t-ballot", &hex).is_empty());
        assert!(!crate::mirror::approved("t-ballot").unwrap().contains(&c));

        vote("t-ballot", &alice, &hex, true).unwrap();
        assert!(crate::mirror::approved("t-ballot").unwrap().contains(&c));
        crate::to_git::set_test_side(None);
    }

    /// A mirror write the git side does not take leaves its mark, and the
    /// retry (a timer in the canister) delivers the mirror's current state;
    /// one whose answer was lost landed, and is sent again all the same,
    /// which the git side takes as the newer write it is.
    #[test]
    fn a_mirror_write_the_git_side_does_not_take_is_retried() {
        use crate::mirrors::{self, Mirror};
        let git = Rc::new(Flaky::new());
        crate::to_git::set_test_side(Some(git.clone()));
        let (alice, w) = (p(44), p(45));
        credit(&alice, 10_000_000_000);
        create_repo("t-retry", &alice, false).unwrap();
        assert!(mirrors::pending("t-retry").is_empty());

        git.inject("set_push_policy", Inject::NotDelivered);
        add_member("t-retry", &alice, false, w, Role::Writer).unwrap();
        assert!(crate::mirror::may_write("t-retry", &w, false).is_err(), "the git side has not taken the write");
        assert_eq!(mirrors::pending("t-retry"), vec![Mirror::PushPolicy]);
        run(mirrors::flush_all());
        assert!(crate::mirror::may_write("t-retry", &w, false).is_ok());
        assert!(mirrors::pending("t-retry").is_empty());

        git.inject("set_push_policy", Inject::Lost);
        remove_member("t-retry", &alice, false, w).unwrap();
        assert!(crate::mirror::may_write("t-retry", &w, false).is_err(), "landed");
        assert_eq!(mirrors::pending("t-retry"), vec![Mirror::PushPolicy]);
        run(mirrors::flush_all());
        assert!(mirrors::pending("t-retry").is_empty());
        assert!(crate::mirror::may_write("t-retry", &w, false).is_err());

        // The approved set likewise, from a ballot. A ballot's write asks
        // the git side to retry the served commit's deploy, saying what
        // the app runs (nothing it can vouch for here: never deployed),
        // and so does the retry of the write, until the git side has
        // taken one; a change that is no ballot does not ask.
        set_required_votes("t-retry", &alice, false, 1).unwrap();
        assert_eq!(git.retries.borrow().last(), Some(&None));
        let c = store::put_object(store::ObjectType::Blob, b"retry");
        let writes = git.retries.borrow().len();
        git.inject("set_approved", Inject::NotDelivered);
        vote("t-retry", &alice, &store::oid_hex(&c), true).unwrap();
        assert!(!crate::mirror::approved("t-retry").unwrap().contains(&c));
        assert_eq!(mirrors::pending("t-retry"), vec![Mirror::Approved]);
        run(mirrors::flush_all());
        assert!(crate::mirror::approved("t-retry").unwrap().contains(&c));
        assert!(mirrors::pending("t-retry").is_empty());
        let ask = Some(ic_git_types::git_side::Retry { running: None });
        assert_eq!(git.retries.borrow()[writes..], [ask.clone(), ask]);
        add_member("t-retry", &alice, false, w, Role::Voter).unwrap();
        assert_eq!(git.retries.borrow().last(), Some(&None));
        crate::to_git::set_test_side(None);
    }
}
