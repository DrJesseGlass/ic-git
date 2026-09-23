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
how it arrived. It reads `GET /api/<repo>/deploys` on ic-git -- the deploy
log, which records each install and the canister it went into -- and shows
the last commit that was actually installed into it, not the branch tip: a
push that is queued, held for votes, or failed is named as such, not
credited. Its source and its compiled `app.wasm` are both in the pushed
commit, so the repo browser shows exactly what was deployed.

The ic-git canister id, its HTTP origin and the repo name are compiled into
the module (`build.sh --git-canister --git-origin --repo`, read with `env!`
in `lib.rs`), so a build for a local replica describes the local replica and
a bare `cargo build` refuses rather than describing mainnet.

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
demo/hello/build.sh       build for one deployment + stage dist/ (the tree
                          that gets pushed)
demo/hello/setup.sh       the whole demo against local or ic
```

`dist/` is what ends up in the repo on the canister: the source, and
`app.wasm` at the path the deploy config names.
