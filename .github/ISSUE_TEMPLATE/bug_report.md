---
name: Bug report
about: Something ic-git does wrong. Security problems go to the private form instead (SECURITY.md).
title: ''
labels: bug
assignees: ''
---

<!-- If this is a security problem, stop: report it privately at
     https://github.com/DrJesseGlass/ic-git/security/advisories/new -->

## Where

Which piece: the canister (`umobs-...` on mainnet, or a local replica), the
governor, the repo browser, the loader, the Chrome or Firefox extension
(version from its store page or `tools/extension-sums.mjs`), or a tool in
`tools/`. For the canister, the module hash from
`tools/check-module-hash.sh` if you have it.

## What you did

The exact commands, URL, or clicks. For git, the command and its full
output (`GIT_TRACE=1 GIT_CURL_VERBOSE=1` when the remote misbehaves).

## What happened

Output, error text, or a screenshot. Paste text as text.

## What you expected

## Anything else

Wallet or principal involved (never a token or a key), repo name, the
commit or site record if a verification failed.
