# demo/hello -- deploy on push, end to end

The shortest honest demonstration of what ic-git is for: a canister that got
onto the Internet Computer because someone ran `git push`, with no CI runner,
no build server and no deploy key anywhere in the chain.

```
git push  ->  ic-git canister  ->  deploy queue  ->  install_code  ->  app canister
             (the git remote)     (reads app.wasm      (management
                                   from the commit)     canister)
```

`hello_canister` is a ~365 KB Rust canister that serves one page describing
how it arrived, and reads its own commit back out of ic-git's `/api` to prove
it. Its source and its compiled `app.wasm` are both in the pushed commit, so
the repo browser shows exactly what was deployed and
`get_deploy_history(repo)` binds that commit oid to the wasm sha256.

## Run it

```sh
demo/hello/setup.sh --network local                          # local replica
demo/hello/setup.sh --network ic --identity <operator>       # mainnet
```

The script is idempotent. It builds the wasm, creates the repo, creates the
repo's own app canister (1T cycles, `create_app_canister`), points
`set_wasm_deploy(repo, "app", "app.wasm")` at it, mints a push token, pushes,
and waits for the deploy queue to report. It prints the app canister's URL.

The caller must be an ic-git operator (`list_authorized`) or a tenant with a
funded balance. An operator's repo is exempt from the tenancy charges and its
app canister is created from ic-git's own cycles; a tenant pays for the repo,
the push, the canister and the deploy out of a prepaid balance
(docs/TENANCY.md).

## Layout

```
demo/hello/Cargo.toml     standalone crate -- its own [workspace] table keeps
                          it out of the ic-git workspace and the attested build
demo/hello/src/lib.rs     http_request serving one page, plus whoami
demo/hello/src/index.html the page (self-contained; no external resources)
demo/hello/build.sh       build + stage dist/ (the tree that gets pushed)
demo/hello/setup.sh       the whole demo against local or ic
```

`dist/` is what ends up in the repo on the canister: the source, and
`app.wasm` at the path the deploy config names.
