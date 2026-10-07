# Governance -- who can change what, and how everyone knows

ic-git vouches for other dapps' code. That is only worth as much as the
guarantee behind ic-git's own code, so the aim is one unbroken chain:

> A page is the recorded page; it talks only to backends running approved
> code; only ic-git can change those backends; only an approved vote can
> change ic-git; and everyone affected hears about each change.

| Link | Mechanism | Status |
|---|---|---|
| The page is the recorded page | registry records + the extensions (docs/EXTENSION.md) | done |
| The page talks only to approved backends | the extensions' network check (section 4) | design |
| Backends run approved code | certified module hash vs the on-chain deploy record (section 3) | design |
| Only ic-git can change a backend | governed app canisters (section 2) | design |
| Only a vote can change ic-git | the governor (section 5) | design |
| Nobody is surprised | activity feeds, then push (section 6) | design |

## 1. Votes

Every repo has approvers (the owner and members with the voter role) and a
threshold K (`required_votes`). A commit may be served or deployed once its
ballots reach K, counted as:

- approve: +1;
- object: -1, with a reason (a short text or a link).

A commit passes when approvals minus objections reach K. An objection
blocks nothing on its own: it costs one more approval to overcome, and it
notifies every other approver at once (section 6), so a malicious or
mistaken change is slowed and seen rather than vetoed. There is no veto.
Each approver's latest ballot counts; withdrawing an approval is casting
another ballot.

The count lives in `ic-multisig` (a new tally rule there), so ic-git's
deploy approvals, ic-vote's trustees and the governor (section 5) share it.

## 2. Governed app canisters

Today an app canister's controllers are its owner and ic-git, so the owner
can install code no vote approved. A repo can opt in to governance, once
and for good:

- ic-git becomes the app canister's only controller; the owner is removed.
  From then on the backend changes only by an approved commit's deploy.
- The repo's policy is locked with it: K can no longer be lowered to 0, and
  changing K or the approvers is itself a vote under the current policy.
  Otherwise an owner could set K to 0, or make themselves sole approver,
  and push anything.
- There is no way back to owner control except an approved commit -- that
  is the point, and the price: a broken backend is fixed by an approved
  commit, not directly.

The lock is a vote on the change itself: `propose_policy_change` takes a
ballot on "require K", "add or remove this voter", "transfer to", or "what
the deploy installs" (the deploy config is part of it, since a source path
or an install mode changed by the owner alone would put unapproved code,
or a wipe, into the governed canister), counted over the current approvers
with the same objection rule as a commit, and applied the moment it is
reached. Writers stay the owner's: a writer only pushes, and a push
deploys only once approved. docs/TENANCY.md, "Governed app canisters".

Governance stays opt-in, because ungoverned use has real reasons (fast
iteration, frontend provenance only, a backend governed by its own DAO).
What keeps that honest is that users see the difference (section 4).

## 3. Certified reads, and the deploy record

A client must be able to learn a canister's running module hash and its
controllers without trusting whoever answers. The IC certifies both
(`read_state` on `/canister/<id>/module_hash` and `/controllers`); the
reader checks the certificate's BLS signature against the pinned NNS root
key (through the subnet delegation) and its time against a freshness bound.
This goes into the shared core (`core/verifier.js`), so the loader, the
extensions and the CLI all get it. It is the largest new piece.

What the hash must equal comes from the chain, not from ic-git's answers:
when ic-git deploys an approved commit to a governed canister, it publishes
`<repo>#app` to the registry -- the commit and sha256 of the installed
module -- as it publishes `<repo>#site` for pages.

## 4. The extensions' backend check

A page's calls to the IC go to `icp-api.io/api/v2/canister/<id>/...`, which
an extension sees. So the extensions enforce it rather than trust it: a
verified page may call only

- governed canisters (ic-git their only controller) whose certified module
  hash equals their `<repo>#app` record, and
- system canisters controlled by the NNS (the ledgers, the CMC).

Anything else is blocked -- Firefox in its request listener, Chrome by a
rule built from the allowed list -- and the stop page says which canister
and why. A site whose backend is ungoverned is not stopped (its code is not
tampered) but is marked: "this site's owner can change its backend without
approval".

## 5. The governor: ic-git under its own rules

The live ic-git canister (`umobs`) must stay where it is (its threshold
signing keys are bound to its principal; docs/CANISTER_SPLIT.md), so it is
governed by a second, small canister, the governor, as its only controller:

- An upgrade is a proposal: the target, the module (staged in chunks; its
  sha256 is what is voted on), the install mode and the argument's hash.
- Approvers vote with the section 1 rule. Starting policy: 1 of 1 (the
  current operator), with approvers added later -- each addition a vote
  under the policy in force.
- A proposal that reaches K is executed by the governor (`install_code`),
  and recorded: in its own log, in `verified.json` as today, and on chain.
- The governor itself is immutable: it has no controller. Replacing it is a
  proposal of its own kind, "hand ic-git to this successor", voted like an
  upgrade.
- Approvers check what they vote on the way verified.json is made: rebuild
  the commit with `tools/reproducible-build.sh` and compare the module hash.

The handover (umobs' controllers set to the governor alone) is the one
step that cannot be undone, so it is rehearsed end to end on a local
replica first -- proposal, vote, objection, upgrade, successor handover --
and the governor's own build is reproducible and recorded before it gets
control. Afterwards the extensions also check umobs' certified controllers.

## 6. Notifications

- **Activity feeds (first):** each repo, and the governor, serve an Atom
  feed: commit awaiting votes, ballot cast (with its reason), threshold
  reached, deployed, record published. Any feed reader subscribes, or a
  feed-to-email service; nothing is stored about the reader.
- **Push (later, opt-in):** Dmail is the candidate -- a Dmail notification
  channel per repo that voters and users subscribe to with their wallet.
  Sending uses Dmail's REST API with a developer key, through a
  non-replicated HTTPS outcall; a key in a canister is visible to node
  operators, which is acceptable for notifications as long as it can be
  rotated. To be confirmed against Dmail's developer access before it is
  built. Generic webhooks (ntfy, Discord) are the fallback.
- **Extension alerts (optional):** off by default -- a commit awaiting your
  vote, a new deploy on a site you use.

An objection notifies the other approvers immediately; that is when they
need to look.

## Order of work

1. The tally rule in `ic-multisig` (object -1), and ic-git's adapter.
   Done: ic-multisig 0.2.0, ic-git v0.3.3 (`cast_ballot`).
2. Governed app canisters, the policy lock and the `<repo>#app` deploy
   record (canister release). Built: `govern_app_canister`,
   `propose_policy_change`, docs/TENANCY.md "Governed app canisters".
3. The certified `read_state` reader in the core. Done: docs/CERTIFIED.md.
4. The extensions' backend check (section 4), on 2 and 3. Built:
   `checkBackends` in the core, enforced by both extensions, shown by the
   loader (docs/EXTENSION.md, "What the page talks to").
5. Activity feeds.
6. The governor: build, rehearse locally, record, then the mainnet handover.
7. Push notifications (Dmail), once confirmed.

## Open questions

- Freshness bound for certified reads: settled at five minutes, stale is
  a warning, a signature or delegation failure stops (docs/CERTIFIED.md).
- Chrome's first visit to a site with new backend canisters: settled by
  judging the expected list (ic-git, the system canisters, the site's app
  canister) with the site and installing the allow rules with the pin, so
  no extra reload; a canister outside that list is blocked.
- The wallet path (OISY sending a page's call from its own window): out
  of the extensions' sight; documented, not shimmed (docs/EXTENSION.md).
- How a governed backend's emergency is handled without an escape hatch
  (expedited proposals with a lower K and a short delay, or none).
- Whether objections should also extend a waiting period before a passing
  commit deploys, giving others time to look.
