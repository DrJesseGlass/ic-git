//! Read-only JSON API for the repo browser (`browser/index.html`).
//!
//!   GET /api/repos
//!   GET /api/<repo>/refs
//!   GET /api/<repo>/commits/<rev>?n=<count>     first-parent walk
//!   GET /api/<repo>/commit/<rev>
//!   GET /api/<repo>/tree/<rev>[/<path>]
//!   GET /api/<repo>/blob/<rev>/<path>
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

use crate::object;
use crate::site;
use crate::store::{self, ObjectType, Oid};
use ic_dev_kit_rs::http::{self, HttpResponse};
use serde::Serialize;

const DEFAULT_COMMITS: usize = 30;
const MAX_COMMITS: usize = 200;

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

/// Dispatch a GET whose path starts with `/api/`. `url` is the full request
/// URL (path + query).
pub fn handle(url: &str) -> HttpResponse {
    let path = http::extract_path(url);
    let query = http::extract_query_params(url);
    let Some(rest) = path.strip_prefix("/api/") else {
        return error(404, "not found");
    };
    let rest = rest.trim_end_matches('/');
    if rest == "repos" {
        return json(200, &repos(), None);
    }
    let segs: Vec<&str> = rest.splitn(4, '/').collect();
    let (Some(repo), Some(what)) = (segs.first(), segs.get(1)) else {
        return error(404, "not found");
    };
    let repo = match decode(repo) {
        Ok(r) => r,
        Err(e) => return error(400, &e),
    };
    if !store::repo_exists(&repo) {
        return error(404, "no such repo");
    }
    match (*what, segs.get(2).copied(), segs.get(3).copied()) {
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
        _ => error(404, "not found"),
    }
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
        "40000" | "040000" => "tree",
        "160000" => "commit",
        "120000" => "symlink",
        _ => "blob",
    }
}

/// Minimal percent-decoding; the result must be UTF-8.
fn decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3).ok_or("truncated percent-escape")?;
            let v = u8::from_str_radix(std::str::from_utf8(hex).map_err(|_| "bad escape")?, 16)
                .map_err(|_| "bad percent-escape")?;
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "path is not UTF-8".to_string())
}

fn json<T: Serialize>(status: u16, value: &T, commit: Option<&Oid>) -> HttpResponse {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    let mut res = crate::git_response(status, "application/json", body);
    res.headers
        .push(("X-Content-Type-Options".to_string(), "nosniff".to_string()));
    if let Some(c) = commit {
        res.headers
            .push(("X-Ic-Git-Commit".to_string(), store::oid_hex(c)));
    }
    res
}

fn error(status: u16, msg: &str) -> HttpResponse {
    #[derive(Serialize)]
    struct Err<'a> {
        error: &'a str,
    }
    json(status, &Err { error: msg }, None)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let res = handle("/api/repos");
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

        let refs = body_json(&handle("/api/api-list/refs"));
        let names: Vec<&str> = refs.as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"refs/heads/main"));
        assert!(names.contains(&"refs/tags/v1"));
    }

    #[test]
    fn walks_commits_first_parent_with_limit() {
        let (c1, c2) = seed("api-log");
        let res = handle("/api/api-log/commits/HEAD");
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

        let one = body_json(&handle("/api/api-log/commits/main?n=1"));
        assert_eq!(one.as_array().unwrap().len(), 1);
        // A tag name and a raw oid both resolve.
        let tagged = body_json(&handle("/api/api-log/commit/v1"));
        assert_eq!(tagged["oid"], store::oid_hex(&c1));
        let by_oid = body_json(&handle(&format!("/api/api-log/commit/{}", store::oid_hex(&c1))));
        assert_eq!(by_oid["parents"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn lists_trees_and_serves_blobs() {
        let (_, c2) = seed("api-tree");
        let root = body_json(&handle("/api/api-tree/tree/HEAD"));
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
        let sub = body_json(&handle("/api/api-tree/tree/HEAD/sub%20dir/"));
        assert_eq!(sub["path"], "sub dir");
        assert_eq!(sub["entries"][0]["name"], "b.txt");

        let blob = handle("/api/api-tree/blob/HEAD/sub%20dir/b.txt");
        assert_eq!(blob.status_code, 200);
        assert_eq!(blob.body, b"bravo\n");
        assert_eq!(header(&blob, "Content-Type"), Some("text/plain; charset=utf-8"));
        assert_eq!(header(&blob, "X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(header(&blob, "X-Ic-Git-Path"), Some("sub dir/b.txt"));
        assert_eq!(header(&blob, "X-Ic-Git-Commit"), Some(store::oid_hex(&c2).as_str()));

        // A slash in a branch name travels percent-encoded as one segment.
        store::set_ref("api-tree", "refs/heads/feature/login", c2).unwrap();
        let slashy = handle("/api/api-tree/tree/feature%2Flogin/sub%20dir");
        assert_eq!(slashy.status_code, 200, "{}", String::from_utf8_lossy(&slashy.body));
        assert_eq!(body_json(&slashy)["path"], "sub dir");
        assert_eq!(handle("/api/api-tree/commit/feature%2Flogin").status_code, 200);

        // Old commit sees the old tree.
        let old = body_json(&handle("/api/api-tree/tree/v1"));
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
            let res = handle(url);
            assert_eq!(res.status_code, status, "{url}");
            assert_eq!(header(&res, "Content-Type"), Some("application/json"), "{url}");
            assert!(body_json(&res)["error"].is_string(), "{url}");
        }
    }
}
