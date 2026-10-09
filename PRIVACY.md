# Privacy: ic-git verifier (browser extension)

The published policy is the page https://drjesseglass.github.io/ic-git/privacy/
(docs/privacy/index.html); this is the same text.

The ic-git verifier extensions for Chrome and Firefox check pages served
by the ic-git canister (`umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io`) against
their public record on chain before the page runs.

**What leaves your browser.** To check a site, the extension reads public
records only, and these requests name the site being checked (for
example `ic-vote`):

- the page itself, and the site's info (which canister is its backend),
  from the ic-git canister;
- the canister's public git objects, from the Internet Computer's public
  query endpoint `icp-api.io`;
- the site's record in the registry contract on Ethereum Sepolia, from
  two public RPC endpoints, `ethereum-sepolia-rpc.publicnode.com` and
  `sepolia.gateway.tenderly.co`;
- for the canisters the site's page may call (the ic-git canister, the
  site's own backend canister, and the Internet Computer's system
  canisters: its ledgers and the cycles minting canister) -- and, in
  Firefox, any other canister the page calls, when it first calls it:
  each one's certified code hash and controllers, from `icp-api.io`, and
  the backend's approved-build record, from the same two RPC endpoints.

So the operators of those endpoints -- the Internet Computer's public
API gateway and the two RPC providers -- see which ic-git site is being
checked, which canisters it calls, and from which network address: when
you open one of its pages, every ten minutes after while the browser
stays open, and (in Firefox) when a page first calls a canister not yet
checked. This is why the Chrome Web Store listing declares "Web history"
and the Firefox manifest declares browsing activity.

**What does not.** No page content, nothing you type, and no
identifier; nothing at all to the extension's developer, who runs no
server, analytics or accounts. The extension does not read or send
anything from other sites, forms, wallets or cookies. To stop an ic-git
page from calling a canister that is not approved, it looks at the
address of each call the page makes to the Internet Computer -- which
canister it names -- and nothing else of the call; beyond the check of
that canister above, it is not sent anywhere.

**What is kept.** For the browser session only: which ic-git sites
verified, their records, the checked page, and which canisters each may
call (so a verified page loads without another check). Nothing is kept
after the browser closes.

**Source.** The extension's code is public at
https://github.com/DrJesseGlass/ic-git (`extension/`,
`extension-firefox/`), and the hash of every file in each release is
recorded on chain (docs/EXTENSION.md, "Releases").
