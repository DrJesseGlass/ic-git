# Certified reads -- a canister's code and controllers, on the IC's word

`Verifier.readCanisterState(canisterId)` in `core/verifier.js` answers two
questions about any canister without trusting the node that answers:
what module hash is it running, and who controls it. Those two are what
the extensions' backend check (docs/GOVERNANCE.md, section 3) and the
check of ic-git's own canister will stand on, so this reader is the
foundation that leg is built on. It ships in the core before either uses
it.

## Why a certificate, and not a query

Everything else the core reads from the IC is an anonymous query whose
reply is one replica's unsigned word, and that is enough there because
every object read is checked against a hash the caller already holds (a
git object against its SHA-1, a served page against its registry record).
A module hash and a controller list have no such anchor: they are the
fact being asked for. A single replica could answer with whatever it
liked.

So the reader asks for them through `read_state`, whose reply is a
**state certificate**: a hash tree holding the requested paths, and a
signature over the tree's root by the subnet that hosts the canister.
The subnet's signing key is in turn certified by the **NNS root key**
through a delegation certificate. The root key is pinned in the core
(`DEFAULTS.rootKey`, the 133-byte DER the IC publishes); a reader that
fetched it from the network it is checking would prove nothing.
`tools/certified-test.mjs --live` compares the pin with what
`/api/v2/status` reports.

## What is checked

Five checks, in order; the first to fail ends the read, and the result is
`certified: false` with the reason in `checks`.

| Check | Claim | What fails it |
|---|---|---|
| C1 | the reply is a certificate | HTTP error, no `certificate`, malformed CBOR, a bad canister id |
| C2 | the signing key is delegated by the NNS root key | a delegation certificate not signed by the root key, carrying a delegation of its own (the spec forbids nesting), missing the subnet's public key or canister ranges, or whose ranges do not cover the canister |
| C3 | the certificate is signed by that key | a BLS12-381 signature over `"ic-state-root" ++ root hash` that does not verify, or does not decode as a curve point |
| C4 | the certificate is dated | no `/time` in the tree |
| C5 | the tree shows the module hash and controllers | either path pruned (the certificate hides it), controllers absent or not a list |

A canister on an application subnet comes with a delegation (C2 reports
the subnet). An NNS canister -- the ICP ledger, the cycles minting
canister -- is signed by the root key directly, with no delegation; the
reader accepts both, and in both the chain ends at the pinned key.

The path lookup follows the interface specification's three answers:
`found`, `absent` (the labels at some level show the path is not in the
state) and `unknown` (a pruned subtree hides whether it is). They are
not the same. A canister with no module installed has no
`module_hash` label, and the reader reports `moduleHash: null`; a
certificate whose `module_hash` is pruned shows nothing, and the reader
fails C5 rather than report a value it was not shown. The tamper suite
builds exactly that certificate -- pruning keeps the root hash, so the
signature still holds -- and checks it is refused.

## Freshness: stale is a warning

A certificate is the IC's statement about one moment. An old one,
however genuine, can show a module since replaced. The reader compares
`/time` with the clock and sets `stale: true` when they differ by more
than `DEFAULTS.freshMs` (5 minutes, either direction, so a wrong local
clock shows too). Stale does not fail the read: the result is still
`certified: true`, and the C4 detail begins `STALE:`. The caller decides.
The extensions will show a stale read as a warning, not a stop (open
decision 1 in docs/GOVERNANCE.md, settled this way: a signature or
delegation failure stops; staleness warns).

A certificate with no `/time` at all fails C4: freshness could not be
judged, and a reader that cannot say when the state was true should not
say what it was.

## The BLS verifier

Verifying the signature is the one part of this that cannot be written
small and checked by eye. It is BLS12-381 in the IC's layout: signatures
in G1 (48 bytes), public keys in G2 (96 bytes), hash-to-curve with the
`BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` suite. The core uses an
audited implementation, `@noble/curves`, vendored whole as
`core/bls12-381.js`: its `bls12_381.shortSignatures` and nothing else,
bundled by esbuild into a classic-script IIFE (`NobleBls`) so the loader
can inline it and an extension's background worker can `importScripts`
it. It is 150 KB unminified, so it can be read against the package.

The file is generated, never edited. `tools/vendor-bls.mjs` pins the
package versions and the bundler, and `--check` fails when the committed
file is not a fresh bundle of those pins -- a reviewer who does not want
to trust the committed bytes regenerates them and diffs. The header
records the versions and the bundle's sha256. The repo is ASCII-only, and
the package's comments use a few mathematical characters; the tool spells
each out from a fixed table (`^2` for a squared sign, `alpha` for the
letter) and refuses a bundle holding any character the table does not
name, so nothing in code is ever rewritten by guess.

The core never trusts a certificate it could not check: with
`core/bls12-381.js` not loaded, every read fails C2 or C3 with
`BLS verifier not loaded`. The suite covers that case.

## Where it is carried

`tools/sync-core.mjs` copies `core/bls12-381.js` next to
`core/verifier.js` into every place the core lives: inline in
`loader/index.html` (a `// === bls ===` block before the core block), and
as `bls12-381.js` in both extension packages, which load it first
(`importScripts` in Chrome, the `scripts` list in Firefox). The loader's
registry record is its hash, so the loader is republished when the core
changes; the extensions' SHA256SUMS likewise.

## Tests

`tools/certified-test.mjs`:

- fixed vectors (`tools/vectors/read_state.json`): `read_state` replies
  captured from mainnet for ic-git's canister (delegated, subnet
  `qxesv-...`) and the ICP ledger (root-signed), with the module hash,
  controllers, subnet and time they held; the reader is run with the
  clock set a second after each certificate;
- freshness: six minutes either side is stale and still certified; the
  bound is configurable (`freshMs`);
- a tamper suite, on both vectors: a flipped signature byte and a
  47-byte signature (C3); an altered module hash leaf and an altered
  time leaf, which break the signed root (C3); a pruned module hash or
  controllers, which keeps the root and must be noticed (C5); another
  root key (C2 for the delegated certificate, C3 for the root-signed);
  the core loaded without the BLS file (C2/C3, never certified); and on
  the delegated one: a certificate from one subnet asked about a
  canister on another (C2, outside the ranges), a nested delegation
  (C2), hidden canister ranges (C2), an altered delegation signature
  (C2), a pruned `/time` (C4); a reply with no certificate, an HTTP
  error and a bad id (C1);
- `--live`: both canisters certify against mainnet now, and the pinned
  root key equals the one `/api/v2/status` reports.

A read takes well under a second: the two pairings dominate.

## What this does not do yet

It reads; it does not judge. Whether a module hash is the *approved* one
(the `<repo>#app` record), whether the controllers are the right ones
(ic-git alone for a governed canister, the governor alone for ic-git,
the NNS root for system canisters), and what the extensions block on a
wrong answer, are the next leg (docs/GOVERNANCE.md, sections 2 and 3).
The delegation certificate's own `/time` is not checked, following the
reference agents; the top-level certificate's time is what freshness
means.
