# Security

## Reporting a vulnerability

Report it privately, not in a public issue or pull request:

    https://github.com/DrJesseGlass/ic-git/security/advisories/new

That form opens a draft advisory only the maintainer and you can see. Say
what you found, how to reproduce it, and which piece it is in (below).
Expect an acknowledgement within a week.

A bug that is not a security problem is an ordinary issue:
https://github.com/DrJesseGlass/ic-git/issues/new/choose

## What counts

ic-git's promise is that what a user runs is what was recorded, and that
nobody but the recorded owners can change what is recorded. Anything that
breaks that promise is in scope, in particular:

- the canister on `umobs-yiaaa-aaaab-agyrq-cai`: push authentication
  (tokens, signed pushes, `set_require_signed_push`), repo membership and
  votes, tenant balances and charging, the deploy queue and its provenance
  log, the admin and `/api/...` surfaces;
- the governor (`canisters/governor`, docs/GOVERNOR.md): any way to change
  the canister's code without a K-of-N vote;
- the verification core (`core/verifier.js`) and everything built on it:
  the loader (`loader/index.html`), the Chrome and Firefox extensions
  (`extension/`, `extension-firefox/`), `tools/verify.mjs`. A served page
  that passes the check without matching its record is the worst case;
- the reproducible build (REPRODUCIBLE_BUILD.md): a way to make a module
  whose hash matches the attested source but whose behaviour differs.

## What does not

- The `.raw.icp0.io` domain carries no response certification. That is the
  documented trust model (ARCHITECTURE.md, "Trust model"): the verifiers
  check the bytes, not the transport.
- The registry is on Sepolia. Testnet reorganisations and testnet ether
  are not vulnerabilities.
- A dependency advisory with no reachable path in this code. Dependabot
  files those (`.github/dependabot.yml`); if you believe a path exists,
  that is a report.
- Resource exhaustion of a canister by paid, metered calls: the tenant
  pays for them (docs/TENANCY.md).

## Supported versions

Only what is running: the module on `umobs-yiaaa-aaaab-agyrq-cai`
(`tools/check-module-hash.sh` says which release that is) and the current
store versions of the extensions (docs/EXTENSION.md). Older releases are
not patched.

## How a fix ships

A fix is a release like any other: built reproducibly, its module hash
attested, and installed by a governor vote (docs/GOVERNOR.md). That path
takes days, not hours. The advisory is published, with credit to the
reporter if wanted, once the fixed module is live.
