# Privacy: ic-git verifier (browser extension)

The ic-git verifier extensions for Chrome and Firefox check pages served
by the ic-git canister (`umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io`) against
their public record on chain before the page runs.

**What leaves your browser.** To check a site, the extension reads public
records only, and these requests name the site being checked (for
example `ic-vote`):

- the page itself, from the ic-git canister;
- the canister's public git objects, from the Internet Computer's public
  query endpoint `icp-api.io`;
- the site's record in the registry contract on Ethereum Sepolia, from
  two public RPC endpoints, `ethereum-sepolia-rpc.publicnode.com` and
  `sepolia.gateway.tenderly.co`.

Those services see an ordinary request for public data, as a browser
visiting the same addresses would. This is why the Chrome Web Store
listing declares "Web history" and the Firefox manifest declares
browsing activity.

**What does not.** Nothing is sent to the extension's developer or to
anyone else. The extension has no server, no analytics, no accounts, and
does not read or send anything from other sites, forms, wallets or
cookies.

**What is kept.** For the browser session only: which ic-git sites
verified, their records, and the checked page (so a verified page loads
without another check). Nothing is kept after the browser closes.

**Source.** The extension's code is public at
https://github.com/DrJesseGlass/ic-git (`extension/`,
`extension-firefox/`), and the hash of every file in each release is
recorded on chain (docs/EXTENSION.md, "Releases").
