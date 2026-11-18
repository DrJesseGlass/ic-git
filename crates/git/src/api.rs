//! Read-only JSON API for the repo browser (`browser/index.html`).
//!
//!   GET /api/repos
//!   GET /api/<repo>/refs
//!   GET /api/<repo>/commits/<rev>?n=<count>     first-parent walk
//!   GET /api/<repo>/commit/<rev>
//!   GET /api/<repo>/tree/<rev>[/<path>]
//!   GET /api/<repo>/blob/<rev>/<path>
//!   GET /api/<repo>/diff/<rev>[?base=<rev>]     the files that changed
//!   GET /api/<repo>/compare/<rev>[?base=<rev>]  where two histories part
//!
//! The git side's half; the authority's routes (a repo's info, votes,
//! proposals and deploys, accounts, pricing) are in api_authority.rs, which
//! the canister asks first.
//!
//! `<rev>` is HEAD, a 40-hex oid, a bare branch or tag name, or a full ref
//! name. Segments are split on `/` first and percent-decoded second, so a
//! branch named `feature/login` is addressed as `feature%2Flogin`.
//! Path components are percent-decoded the same way.
//!
//! Every response that resolved a commit carries `X-Ic-Git-Commit`, the same
//! binding `/site` responses carry, so the page can show exactly which commit
//! it is looking at. Blobs are served as `text/plain` with `nosniff` whatever
//! their extension: this is a data endpoint for a page that renders content
//! itself, never a place from which markup executes.
//!
//! `/diff` is the files that differ between two commits' trees (diff.rs):
//! from `base` to `<rev>`, where `base` is the commit's first parent
//! unless the query names another rev, and nothing at all for a commit
//! with no parent, whose every file is then added. It names the blobs on
//! each side and reads none: the page fetches the two with `/blob` at the
//! `base` and `commit` this answers with, by `old_path` (or `path`) and
//! `path`, and works out the lines itself. The files come in path order,
//! within `DIFF_LIMITS`; `truncated` says the list stops short. A name
//! that is not UTF-8 is given as `/tree` gives it, with the replacement
//! character, and cannot be fetched by it.
//!
//! `/compare` is `<rev>` (the head) against `base`, the repo's HEAD unless
//! the query names another rev (graph.rs): their merge base, how many
//! commits each has that the other has not (`ahead`, the head's;
//! `behind`, the base's), and the head's own, newest first, as `/commits`
//! gives a commit, at most `MAX_COMMITS` of them (`truncated` says there
//! are more). What the head changed is then `/diff/<head>?base=` the
//! merge base. Two histories that share nothing have a null merge base.
//! The walk loads at most `COMPARE_COMMITS` commits; two revs further
//! apart than that are answered 422.

use crate::diff;
use crate::graph;
use crate::object;
use crate::site;
use crate::store::{self, ObjectType, Oid};
use crate::httpjson::{decode, error, json, ApiPath};
use ic_dev_kit_rs::http::{self, HttpResponse};
use serde::Serialize;

const DEFAULT_COMMITS: usize = 30;
const MAX_COMMITS: usize = 200;
/// How many commits one `/compare` loads to find where two histories
/// part.
const COMPARE_COMMITS: usize = 5000;
/// How many changed files one `/diff` lists, and how many directories it
/// opens to find them.
const DIFF_LIMITS: diff::Limits = diff::Limits { changes: 1000, dirs: 4000 };

#[derive(Serialize)]
struct RepoInfo {
    name: String,
    head: String,
    site: bool,
}

#[derive(Serialize)]
struct RefInfo {
    name: String,
    oid: String,
}

#[derive(Serialize)]
struct Ident {
    name: String,
    email: String,
    time: u64,
    tz: String,
}

#[derive(Serialize)]
struct CommitInfo {
    oid: String,
    tree: String,
    parents: Vec<String>,
    author: Option<Ident>,
    committer: Option<Ident>,
    message: String,
}

#[derive(Serialize)]
struct Entry {
    name: String,
    mode: String,
    kind: &'static str,
    oid: String,
}

#[derive(Serialize)]
struct TreeInfo {
    commit: String,
    path: String,
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct CompareInfo {
    head: String,
    base: String,
    /// Null for two histories that share nothing.
    merge_base: Option<String>,
    ahead: usize,
    behind: usize,
    /// The head's own commits, newest first.
    commits: Vec<CommitInfo>,
    truncated: bool,
}

#[derive(Serialize)]
struct DiffSide {
    oid: String,
    mode: String,
    kind: &'static str,
}

#[derive(Serialize)]
struct DiffFile {
    path: String,
    status: &'static str,
    /// Where a renamed file was.
    #[serde(skip_serializing_if = "Option::is_none")]
    old_path: Option<String>,
    old: Option<DiffSide>,
    new: Option<DiffSide>,
}

#[derive(Serialize)]
struct DiffInfo {
    commit: String,
    /// The commit compared against; null for a commit with no parent.
    base: Option<String>,
    files: Vec<DiffFile>,
    truncated: bool,
}

/// Answer a GET under `/api/` that the authority's half (api_authority.rs)
/// did not. `url` is the full request URL, for the query.
pub fn handle(req: &ApiPath, url: &str) -> HttpResponse {
    let query = http::extract_query_params(url);
    if req.rest == "repos" {
        return json(200, &repos(), None);
    }
    let Some((repo, what, arg, more)) = req.repo_route() else {
        return error(404, "not found");
    };
    let repo = match decode(repo) {
        Ok(r) => r,
        Err(e) => return error(400, &e),
    };
    if !store::repo_exists(&repo) {
        return error(404, "no such repo");
    }
    match (what, arg, more) {
        ("refs", None, None) => {
            let refs: Vec<RefInfo> = store::list_refs(&repo)
                .into_iter()
                .map(|(name, oid)| RefInfo {
                    name,
                    oid: store::oid_hex(&oid),
                })
                .collect();
            json(200, &refs, None)
        }
        ("commits", Some(rev), None) => {
            let n = query
                .get("n")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_COMMITS)
                .clamp(1, MAX_COMMITS);
            with_rev(&repo, rev, |tip| {
                let mut out = Vec::new();
                let mut cur = Some(tip);
                while let (Some(oid), true) = (cur, out.len() < n) {
                    let info = commit_info(&oid)?;
                    cur = info.parents.first().and_then(|p| store::parse_oid(p).ok());
                    out.push(info);
                }
                Ok(json(200, &out, Some(&tip)))
            })
        }
        ("commit", Some(rev), None) => {
            with_rev(&repo, rev, |tip| Ok(json(200, &commit_info(&tip)?, Some(&tip))))
        }
        ("tree", Some(rev), sub) => {
            let sub = match decode(sub.unwrap_or("")) {
                Ok(s) => s,
                Err(e) => return error(400, &e),
            };
            with_rev(&repo, rev, |tip| {
                let (ty, content) = object::node_at_path(&tip, &sub)?;
                if ty != ObjectType::Tree {
                    return Err(format!("'{sub}' is not a directory"));
                }
                let mut entries: Vec<Entry> = object::tree_entries(&content)?
                    .into_iter()
                    .map(|e| Entry {
                        name: String::from_utf8_lossy(&e.name).into_owned(),
                        kind: kind_of(&e.mode),
                        mode: e.mode,
                        oid: store::oid_hex(&e.oid),
                    })
                    .collect();
                // Directories first, then by name -- what every browser shows.
                entries.sort_by(|a, b| {
                    (a.kind != "tree").cmp(&(b.kind != "tree")).then(a.name.cmp(&b.name))
                });
                Ok(json(
                    200,
                    &TreeInfo {
                        commit: store::oid_hex(&tip),
                        path: sub.trim_matches('/').to_string(),
                        entries,
                    },
                    Some(&tip),
                ))
            })
        }
        ("blob", Some(rev), Some(sub)) => {
            let sub = match decode(sub) {
                Ok(s) => s,
                Err(e) => return error(400, &e),
            };
            with_rev(&repo, rev, |tip| {
                let body = object::blob_at_path(&tip, &sub)?;
                if body.len() > site::MAX_BODY {
                    return Ok(error(413, "file exceeds the single-response limit"));
                }
                let mut res = crate::git_response(200, "text/plain; charset=utf-8", body);
                res.headers
                    .push(("X-Content-Type-Options".to_string(), "nosniff".to_string()));
                res.headers
                    .push(("X-Ic-Git-Commit".to_string(), store::oid_hex(&tip)));
                res.headers
                    .push(("X-Ic-Git-Path".to_string(), sub.trim_matches('/').to_string()));
                Ok(res)
            })
        }
        ("compare", Some(rev), None) => {
            let base = match query.get("base").filter(|b| !b.is_empty()).map(|b| decode(b)) {
                Some(Ok(b)) => b,
                Some(Err(e)) => return error(400, &e),
                None => "HEAD".to_string(),
            };
            with_rev(&repo, rev, |head| {
                let base = resolve_rev(&repo, &base)?;
                let Some(c) = graph::compare(&base, &head, COMPARE_COMMITS)? else {
                    return Ok(error(422, "the two are too many commits apart to compare"));
                };
                let commits = c.ahead.iter().take(MAX_COMMITS).map(commit_info).collect::<Result<Vec<_>, _>>()?;
                let info = CompareInfo {
                    head: store::oid_hex(&head),
                    base: store::oid_hex(&base),
                    merge_base: c.merge_base.as_ref().map(store::oid_hex),
                    ahead: c.ahead.len(),
                    behind: c.behind,
                    truncated: c.ahead.len() > commits.len(),
                    commits,
                };
                Ok(json(200, &info, Some(&head)))
            })
        }
        ("diff", Some(rev), None) => {
            // An empty `base=` is no base named.
            let base = match query.get("base").filter(|b| !b.is_empty()).map(|b| decode(b)) {
                Some(Ok(b)) => Some(b),
                Some(Err(e)) => return error(400, &e),
                None => None,
            };
            with_rev(&repo, rev, |tip| {
                let (tree, parents) = commit_tree(&tip)?;
                let base = match base {
                    Some(b) => Some(resolve_rev(&repo, &b)?),
                    None => parents.first().copied(),
                };
                let old = base.as_ref().map(|b| commit_tree(b).map(|(tree, _)| tree)).transpose()?;
                let d = diff::tree_diff(old.as_ref(), &tree, DIFF_LIMITS)?;
                let text = |p: &[u8]| String::from_utf8_lossy(p).into_owned();
                let side = |s: diff::Side| DiffSide { oid: store::oid_hex(&s.oid), kind: kind_of(&s.mode), mode: s.mode };
                let files = d
                    .changes
                    .into_iter()
                    .map(|c| DiffFile {
                        path: text(&c.path),
                        status: c.status.as_str(),
                        old_path: c.old_path.as_deref().map(text),
                        old: c.old.map(side),
                        new: c.new.map(side),
                    })
                    .collect();
                let info = DiffInfo { commit: store::oid_hex(&tip), base: base.as_ref().map(store::oid_hex), files, truncated: d.truncated };
                Ok(json(200, &info, Some(&tip)))
            })
        }
        _ => error(404, "not found"),
    }
}

/// A commit's tree and parents.
fn commit_tree(oid: &Oid) -> Result<(Oid, Vec<Oid>), String> {
    let (ty, content) = store::get_object_parsed(oid).ok_or("commit object missing")?;
    if ty != ObjectType::Commit {
        return Err(format!("{} is not a commit", store::oid_hex(oid)));
    }
    let refs = object::commit_refs(&content)?;
    Ok((refs.tree, refs.parents))
}

fn repos() -> Vec<RepoInfo> {
    store::list_repos()
        .into_iter()
        .map(|name| RepoInfo {
            head: store::head_target(&name).unwrap_or_default(),
            site: site::get_config(&name).is_some(),
            name,
        })
        .collect()
}

/// Resolve `rev`, then run `f`; a resolution failure is a 404 and an error
/// from `f` (a bad path, a missing object) is also a 404 with its message.
fn with_rev(
    repo: &str,
    rev: &str,
    f: impl FnOnce(Oid) -> Result<HttpResponse, String>,
) -> HttpResponse {
    let rev = match decode(rev) {
        Ok(r) => r,
        Err(e) => return error(400, &e),
    };
    match resolve_rev(repo, &rev).and_then(f) {
        Ok(res) => res,
        Err(e) => error(404, &e),
    }
}

fn resolve_rev(repo: &str, rev: &str) -> Result<Oid, String> {
    let oid = if rev == "HEAD" {
        let branch = store::head_target(repo).ok_or("no such repo")?;
        store::get_ref(repo, &branch).ok_or("HEAD points at an unborn branch")?
    } else if let (40, Ok(oid)) = (rev.len(), store::parse_oid(rev)) {
        if !store::has_object(&oid) {
            return Err(format!("no such object: {rev}"));
        }
        oid
    } else {
        [
            rev.to_string(),
            format!("refs/heads/{rev}"),
            format!("refs/tags/{rev}"),
        ]
        .iter()
        .find_map(|name| store::get_ref(repo, name))
        .ok_or_else(|| format!("no such ref: {rev}"))?
    };
    peel(oid)
}

/// Follow annotated tags to the commit they name.
fn peel(mut oid: Oid) -> Result<Oid, String> {
    for _ in 0..8 {
        match store::get_object_parsed(&oid).ok_or("object missing")? {
            (ObjectType::Tag, content) => oid = object::tag_target(&content)?,
            (ObjectType::Commit, _) => return Ok(oid),
            (ty, _) => return Err(format!("{} is a {}, not a commit", store::oid_hex(&oid), ty.as_str())),
        }
    }
    Err("tag chain too deep".into())
}

fn commit_info(oid: &Oid) -> Result<CommitInfo, String> {
    let (ty, content) = store::get_object_parsed(oid).ok_or("commit object missing")?;
    if ty != ObjectType::Commit {
        return Err(format!("{} is not a commit", store::oid_hex(oid)));
    }
    let refs = object::commit_refs(&content)?;
    let meta = object::commit_meta(&content);
    Ok(CommitInfo {
        oid: store::oid_hex(oid),
        tree: store::oid_hex(&refs.tree),
        parents: refs.parents.iter().map(store::oid_hex).collect(),
        author: meta.author.as_deref().and_then(ident),
        committer: meta.committer.as_deref().and_then(ident),
        message: meta.message,
    })
}

/// "Name <email> 1234567890 +0000" -> Ident. Tolerates a missing timezone or
/// timestamp (hand-made objects) by leaving them empty/zero.
fn ident(s: &str) -> Option<Ident> {
    let (name, rest) = s.split_once('<')?;
    let (email, rest) = rest.split_once('>')?;
    let mut it = rest.split_whitespace();
    let time = it.next().and_then(|t| t.parse().ok()).unwrap_or(0);
    let tz = it.next().unwrap_or("").to_string();
    Some(Ident {
        name: name.trim().to_string(),
        email: email.to_string(),
        time,
        tz,
    })
}

fn kind_of(mode: &str) -> &'static str {
    match mode {
        m if object::is_tree_mode(m) => "tree",
        "160000" => "commit",
        "120000" => "symlink",
        _ => "blob",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compare_is_against_head_or_the_base_named() {
        let (c1, c2) = seed("api-compare");
        // A branch off c1, one commit of its own: HEAD (c2) is the base.
        let t = store::put_object(ObjectType::Tree, b"");
        let side = store::put_object(
            ObjectType::Commit,
            format!("tree {}\nparent {}\nauthor Ann <ann@x> 1700000005 +0000\ncommitter Ann <ann@x> 1700000005 +0000\n\nside\n", store::oid_hex(&t), store::oid_hex(&c1)).as_bytes(),
        );
        store::set_ref("api-compare", "refs/heads/feature/side", side).unwrap();
        let res = get("/api/api-compare/compare/feature%2Fside");
        assert_eq!(res.status_code, 200);
        assert_eq!(header(&res, "X-Ic-Git-Commit"), Some(store::oid_hex(&side).as_str()));
        let v = body_json(&res);
        assert_eq!(v["head"], store::oid_hex(&side));
        assert_eq!(v["base"], store::oid_hex(&c2));
        assert_eq!(v["merge_base"], store::oid_hex(&c1));
        assert_eq!((v["ahead"].as_u64(), v["behind"].as_u64()), (Some(1), Some(1)));
        assert_eq!(v["truncated"], false);
        assert_eq!(v["commits"].as_array().unwrap().len(), 1);
        assert_eq!(v["commits"][0]["oid"], store::oid_hex(&side));
        assert_eq!(v["commits"][0]["message"], "side\n");
        // What the branch changed is its diff against the merge base.
        let d = body_json(&get(&format!("/api/api-compare/diff/feature%2Fside?base={}", v["merge_base"].as_str().unwrap())));
        assert_eq!(d["files"][0]["path"], "a.txt");
        assert_eq!(d["files"][0]["status"], "deleted");
        // A base named; the head contained in it: nothing ahead.
        let v = body_json(&get("/api/api-compare/compare/v1?base=feature%2Fside"));
        assert_eq!(v["merge_base"], store::oid_hex(&c1));
        assert_eq!((v["ahead"].as_u64(), v["behind"].as_u64()), (Some(0), Some(1)));
        assert_eq!(v["commits"].as_array().unwrap().len(), 0);
        // An empty base is none named.
        assert_eq!(body_json(&get("/api/api-compare/compare/v1?base="))["base"], store::oid_hex(&c2));
        for (url, status) in [
            ("/api/api-compare/compare/nope", 404),
            ("/api/api-compare/compare/HEAD?base=nope", 404),
            ("/api/api-compare/compare/HEAD?base=%zz", 400),
            ("/api/api-compare/compare", 404),
        ] {
            assert_eq!(get(url).status_code, status, "{url}");
        }
    }

    #[test]
    fn a_diff_is_against_the_first_parent_or_the_base_named() {
        let (c1, c2) = seed("api-diff");
        // c2 added "sub dir"/b.txt over its parent c1.
        let res = get("/api/api-diff/diff/HEAD");
        assert_eq!(res.status_code, 200);
        assert_eq!(header(&res, "X-Ic-Git-Commit"), Some(store::oid_hex(&c2).as_str()));
        let v = body_json(&res);
        assert_eq!(v["commit"], store::oid_hex(&c2));
        assert_eq!(v["base"], store::oid_hex(&c1));
        assert_eq!(v["truncated"], false);
        let files = v["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["path"], "sub dir/b.txt");
        assert_eq!(files[0]["status"], "added");
        assert!(files[0]["old"].is_null());
        assert!(files[0].get("old_path").is_none());
        assert_eq!(files[0]["new"]["mode"], "100644");
        assert_eq!(files[0]["new"]["kind"], "blob");
        // The blob it names is the one /blob serves at the commit and path.
        let b = store::put_object(ObjectType::Blob, b"bravo\n");
        assert_eq!(files[0]["new"]["oid"], store::oid_hex(&b));
        // A commit with no parent: nothing to compare against, all added.
        let root = body_json(&get("/api/api-diff/diff/v1"));
        assert!(root["base"].is_null());
        assert_eq!(root["files"][0]["path"], "a.txt");
        assert_eq!(root["files"][0]["status"], "added");
        // A base named in the query, here the other way round: deleted.
        let back = body_json(&get("/api/api-diff/diff/v1?base=HEAD"));
        assert_eq!(back["commit"], store::oid_hex(&c1));
        assert_eq!(back["base"], store::oid_hex(&c2));
        assert_eq!(back["files"][0]["status"], "deleted");
        assert!(back["files"][0]["new"].is_null());
        // An empty base is none named: the first parent.
        assert_eq!(body_json(&get("/api/api-diff/diff/HEAD?base="))["base"], store::oid_hex(&c1));
        // A commit against itself: nothing.
        let same = body_json(&get(&format!("/api/api-diff/diff/HEAD?base={}", store::oid_hex(&c2))));
        assert_eq!(same["files"].as_array().unwrap().len(), 0);
        // A branch with a slash in its name, as base, percent-encoded.
        store::set_ref("api-diff", "refs/heads/feature/login", c1).unwrap();
        let named = body_json(&get("/api/api-diff/diff/HEAD?base=feature%2Flogin"));
        assert_eq!(named["base"], store::oid_hex(&c1));
        for (url, status) in [
            ("/api/api-diff/diff/nope", 404),
            ("/api/api-diff/diff/HEAD?base=nope", 404),
            ("/api/api-diff/diff/HEAD?base=%zz", 400),
            ("/api/api-diff/diff/HEAD/extra", 404),
            ("/api/api-diff/diff", 404),
        ] {
            assert_eq!(get(url).status_code, status, "{url}");
        }
    }

    /// The git side's half of /api, as the canister asks it once the
    /// authority's half has passed.
    fn get(url: &str) -> HttpResponse {
        let path = http::extract_path(url);
        match ApiPath::parse(path) {
            Some(req) => handle(&req, url),
            None => error(404, "not found"),
        }
    }

    fn body_json(res: &HttpResponse) -> serde_json::Value {
        serde_json::from_slice(&res.body).unwrap()
    }

    fn header<'a>(res: &'a HttpResponse, k: &str) -> Option<&'a str> {
        res.headers.iter().find(|(h, _)| h == k).map(|(_, v)| v.as_str())
    }

    /// Two commits: c1 (a.txt) -> c2 (a.txt, "sub dir"/b.txt), a tag ref on c1.
    fn seed(repo: &str) -> (Oid, Oid) {
        store::create_repo(repo).unwrap();
        let a = store::put_object(ObjectType::Blob, b"alpha\n");
        let b = store::put_object(ObjectType::Blob, b"bravo\n");
        let mut t1 = Vec::new();
        t1.extend_from_slice(b"100644 a.txt\0");
        t1.extend_from_slice(a.as_slice());
        let t1 = store::put_object(ObjectType::Tree, &t1);
        let c1 = store::put_object(
            ObjectType::Commit,
            format!(
                "tree {}\nauthor Ann <ann@x> 1700000000 +0100\ncommitter Bob <bob@x> 1700000001 +0000\n\nfirst\n\nbody line\n",
                store::oid_hex(&t1)
            )
            .as_bytes(),
        );
        let mut sub = Vec::new();
        sub.extend_from_slice(b"100644 b.txt\0");
        sub.extend_from_slice(b.as_slice());
        let sub = store::put_object(ObjectType::Tree, &sub);
        let mut t2 = Vec::new();
        t2.extend_from_slice(b"40000 sub dir\0");
        t2.extend_from_slice(sub.as_slice());
        t2.extend_from_slice(b"100644 a.txt\0");
        t2.extend_from_slice(a.as_slice());
        let t2 = store::put_object(ObjectType::Tree, &t2);
        let c2 = store::put_object(
            ObjectType::Commit,
            format!(
                "tree {}\nparent {}\nauthor Ann <ann@x> 1700000002 +0100\ncommitter Ann <ann@x> 1700000002 +0100\n\nsecond\n",
                store::oid_hex(&t2),
                store::oid_hex(&c1)
            )
            .as_bytes(),
        );
        let branch = store::head_target(repo).unwrap();
        store::set_ref(repo, &branch, c2).unwrap();
        store::set_ref(repo, "refs/tags/v1", c1).unwrap();
        (c1, c2)
    }

    #[test]
    fn lists_repos_and_refs() {
        seed("api-list");
        let res = get("/api/repos");
        assert_eq!(res.status_code, 200);
        let v = body_json(&res);
        let me = v
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "api-list")
            .expect("repo listed");
        assert_eq!(me["head"], "refs/heads/main");
        assert_eq!(me["site"], false);

        let refs = body_json(&get("/api/api-list/refs"));
        let names: Vec<&str> = refs.as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"refs/heads/main"));
        assert!(names.contains(&"refs/tags/v1"));
    }

    #[test]
    fn walks_commits_first_parent_with_limit() {
        let (c1, c2) = seed("api-log");
        let res = get("/api/api-log/commits/HEAD");
        assert_eq!(res.status_code, 200);
        assert_eq!(header(&res, "X-Ic-Git-Commit"), Some(store::oid_hex(&c2).as_str()));
        let v = body_json(&res);
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["oid"], store::oid_hex(&c2));
        assert_eq!(arr[1]["oid"], store::oid_hex(&c1));
        assert_eq!(arr[0]["message"], "second\n");
        assert_eq!(arr[1]["author"]["name"], "Ann");
        assert_eq!(arr[1]["author"]["email"], "ann@x");
        assert_eq!(arr[1]["author"]["time"], 1700000000u64);
        assert_eq!(arr[1]["author"]["tz"], "+0100");
        assert_eq!(arr[1]["committer"]["name"], "Bob");
        assert_eq!(arr[1]["message"], "first\n\nbody line\n");

        let one = body_json(&get("/api/api-log/commits/main?n=1"));
        assert_eq!(one.as_array().unwrap().len(), 1);
        // A tag name and a raw oid both resolve.
        let tagged = body_json(&get("/api/api-log/commit/v1"));
        assert_eq!(tagged["oid"], store::oid_hex(&c1));
        let by_oid = body_json(&get(&format!("/api/api-log/commit/{}", store::oid_hex(&c1))));
        assert_eq!(by_oid["parents"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn lists_trees_and_serves_blobs() {
        let (_, c2) = seed("api-tree");
        let root = body_json(&get("/api/api-tree/tree/HEAD"));
        assert_eq!(root["commit"], store::oid_hex(&c2));
        assert_eq!(root["path"], "");
        let entries = root["entries"].as_array().unwrap();
        // Directory sorts first.
        assert_eq!(entries[0]["name"], "sub dir");
        assert_eq!(entries[0]["kind"], "tree");
        assert_eq!(entries[1]["name"], "a.txt");
        assert_eq!(entries[1]["kind"], "blob");
        assert_eq!(entries[1]["mode"], "100644");

        // Percent-decoded path, trailing slash tolerated.
        let sub = body_json(&get("/api/api-tree/tree/HEAD/sub%20dir/"));
        assert_eq!(sub["path"], "sub dir");
        assert_eq!(sub["entries"][0]["name"], "b.txt");

        let blob = get("/api/api-tree/blob/HEAD/sub%20dir/b.txt");
        assert_eq!(blob.status_code, 200);
        assert_eq!(blob.body, b"bravo\n");
        assert_eq!(header(&blob, "Content-Type"), Some("text/plain; charset=utf-8"));
        assert_eq!(header(&blob, "X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(header(&blob, "X-Ic-Git-Path"), Some("sub dir/b.txt"));
        assert_eq!(header(&blob, "X-Ic-Git-Commit"), Some(store::oid_hex(&c2).as_str()));

        // A slash in a branch name travels percent-encoded as one segment.
        store::set_ref("api-tree", "refs/heads/feature/login", c2).unwrap();
        let slashy = get("/api/api-tree/tree/feature%2Flogin/sub%20dir");
        assert_eq!(slashy.status_code, 200, "{}", String::from_utf8_lossy(&slashy.body));
        assert_eq!(body_json(&slashy)["path"], "sub dir");
        assert_eq!(get("/api/api-tree/commit/feature%2Flogin").status_code, 200);

        // Old commit sees the old tree.
        let old = body_json(&get("/api/api-tree/tree/v1"));
        assert_eq!(old["entries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn errors_are_json_404s() {
        seed("api-err");
        for (url, status) in [
            ("/api/nope/refs", 404),
            ("/api/api-err/tree/nope", 404),
            ("/api/api-err/tree/HEAD/missing", 404),
            ("/api/api-err/tree/HEAD/a.txt", 404),
            ("/api/api-err/blob/HEAD/sub%20dir", 404),
            ("/api/api-err/blob/HEAD", 404),
            ("/api/api-err/whatever", 404),
            ("/api/api-err/blob/HEAD/%zz", 400),
            ("/api/", 404),
        ] {
            let res = get(url);
            assert_eq!(res.status_code, status, "{url}");
            assert_eq!(header(&res, "Content-Type"), Some("application/json"), "{url}");
            assert!(body_json(&res)["error"].is_string(), "{url}");
        }
    }
}
