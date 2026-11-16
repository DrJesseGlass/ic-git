//! Response certification for what the git canister serves (VISION.md,
//! F0.5). The IC's HTTP gateway at a non-raw host, and at every custom
//! domain, which has no raw form, passes a response to the browser only
//! with a certificate the subnet signed over it, so a replica that
//! answers a query with other bytes is caught at the gateway, with no
//! client change. The raw hosts pass everything, as before, and the
//! verifying clients (core/verifier.js) go on checking by hash: a
//! certificate says the subnet served these bytes, the registry record
//! says they are the committed ones.
//!
//! What is certified: every URL a site answers at the canister's own
//! host (`/site/<repo>`, `/site/<repo>/`, and each file and directory of
//! the bundle under them, as site.rs `serve` answers them), the 404 for
//! any other URL under a site, the 404 for a repo with no site, and
//! `/.well-known/ic-domains`. Everything else is declared uncertified
//! (the protocol's "no certification" expression, which the gateway
//! passes as it passes the raw host): the git protocol, whose answers
//! depend on the request body and are checked by the client against its
//! refs (ARCHITECTURE.md, "Trust model"); `/api`; the index; and a site
//! at its own domain, where the URL names no repo, until that form is
//! certified too (docs/TENANCY.md, "Custom domains"). A site of more than
//! `SITE_FILE_CAP` files is declared uncertified as a whole rather than
//! certified in part.
//!
//! The tree is heap state: rebuilt from stable memory at install and
//! upgrade (`rebuild`) and recomputed for a site whenever what it serves
//! can change (`site_changed`: the config, the served commit, a push, a
//! ref written by an operator). Each URL is certified by asking `serve`
//! for it, so the certified bytes and the served bytes are one function's
//! answer. Body hashes are kept by blob, so a push that changes one file
//! hashes one file.

use crate::site;
use crate::store::Oid;
use ic_certification::HashTree;
use ic_dev_kit_rs::http::HttpResponse;
use ic_http_certification::{
    DefaultCelBuilder, DefaultResponseCertification, DefaultResponseOnlyCelExpression, HttpCertification,
    HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry, HttpResponse as CertResponse, StatusCode,
    CERTIFICATE_EXPRESSION_HEADER_NAME,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// How many URLs (files, and directories with an index) a site may have
/// and be certified. Each is one hash at every change of the site and
/// one tree entry; past this the site is declared uncertified as a
/// whole, which the raw host and the verifying clients serve as before.
pub const SITE_FILE_CAP: usize = 2000;

/// The response headers the certificate covers: what a client reads. The
/// body and the status are always covered.
const CERTIFIED_HEADERS: [&str; 5] = ["Content-Type", "Cache-Control", "X-Ic-Git-Repo", "X-Ic-Git-Commit", "X-Ic-Git-Path"];

fn cel() -> &'static DefaultResponseOnlyCelExpression<'static> {
    static CEL: OnceLock<DefaultResponseOnlyCelExpression<'static>> = OnceLock::new();
    CEL.get_or_init(|| {
        DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                CERTIFIED_HEADERS.to_vec(),
            ))
            .build()
    })
}

fn cel_text() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(|| cel().to_string())
}

fn skip_text() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(|| DefaultCelBuilder::skip_certification().to_string())
}

/// The header every certified response carries, naming what its
/// certificate covers. Part of the response before it is hashed, so
/// site.rs puts it on every answer of `serve` and on the domains file.
pub fn expression_header() -> (String, String) {
    (CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_text().to_string())
}

#[derive(Default)]
struct State {
    /// Exact URLs: every file and directory of every certified site, and
    /// the domains file.
    exact: BTreeMap<String, HttpCertification>,
    /// Per repo with a site config, the wildcard under `/site/<repo>`:
    /// the certified miss, or skip for a site past the cap.
    sites: BTreeMap<String, HttpCertification>,
    /// The wildcard under `/site`: the 404 for a repo with no site.
    no_site: Option<HttpCertification>,
    /// The sha256 of each blob served, by oid.
    bodies: BTreeMap<Vec<u8>, [u8; 32]>,
    /// In tests, a smaller cap.
    cap: usize,
}

thread_local! {
    static TREE: RefCell<HttpCertificationTree> = RefCell::new(HttpCertificationTree::default());
    static STATE: RefCell<State> = RefCell::new(State { cap: SITE_FILE_CAP, ..State::default() });
}

/// How many body hashes are kept before the cache starts over.
const BODY_CACHE: usize = 20_000;

fn cert_response(res: &HttpResponse) -> CertResponse<'_> {
    CertResponse::builder()
        .with_status_code(StatusCode::from_u16(res.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .with_headers(res.headers.clone())
        .with_body(res.body.as_slice())
        .build()
}

/// The certification of a response `serve` or `domains_response` gave:
/// `None` only for a response without the expression header, which none
/// of theirs is.
fn certify(res: &HttpResponse, body_hash: Option<[u8; 32]>) -> Option<HttpCertification> {
    HttpCertification::response_only(cel(), &cert_response(res), body_hash).ok()
}

fn body_hash(s: &mut State, oid: &Oid, body: &[u8]) -> [u8; 32] {
    let key = oid.as_slice().to_vec();
    if let Some(h) = s.bodies.get(&key) {
        return *h;
    }
    if s.bodies.len() >= BODY_CACHE {
        s.bodies.clear();
    }
    let h: [u8; 32] = Sha256::digest(body).into();
    s.bodies.insert(key, h);
    h
}

fn insert(path: &HttpCertificationPath, c: &HttpCertification) {
    TREE.with(|t| t.borrow_mut().insert(&HttpCertificationTreeEntry::new(path, c)));
}

fn delete(path: &HttpCertificationPath, c: &HttpCertification) {
    TREE.with(|t| t.borrow_mut().delete(&HttpCertificationTreeEntry::new(path, c)));
}

/// The tree's root, as the IC certifies it: set after every change.
fn publish() {
    let root = TREE.with(|t| t.borrow().root_hash());
    #[cfg(target_arch = "wasm32")]
    ic_cdk::api::certified_data_set(root);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = root;
}

/// Start over from stable memory: at install, after an upgrade, and when
/// an import has copied another canister's sites here.
pub fn rebuild() {
    TREE.with(|t| *t.borrow_mut() = HttpCertificationTree::default());
    let cap = STATE.with(|s| s.borrow().cap);
    STATE.with(|s| *s.borrow_mut() = State { cap, ..State::default() });
    // The catch-all, spelled as the protocol spells it: the wildcard of
    // the empty path.
    insert(&HttpCertificationPath::wildcard(""), &HttpCertification::skip());
    if let Some(c) = certify(&site::no_site(), None) {
        insert(&HttpCertificationPath::wildcard("/site"), &c);
        STATE.with(|s| s.borrow_mut().no_site = Some(c));
    }
    domains_entry();
    for (repo, _) in site::all_configs() {
        site_entries(&repo);
    }
    publish();
}

/// What a site serves may have changed: its config, its served commit,
/// a push, a ref an operator wrote.
pub fn site_changed(repo: &str) {
    site_entries(repo);
    publish();
}

/// The domains file changed.
pub fn domains_changed() {
    domains_entry();
    publish();
}

const DOMAINS_URL: &str = "/.well-known/ic-domains";

fn domains_entry() {
    let path = HttpCertificationPath::exact(DOMAINS_URL);
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        if let Some(old) = s.exact.remove(DOMAINS_URL) {
            delete(&path, &old);
        }
        if let Some(c) = certify(&site::domains_response(), None) {
            insert(&path, &c);
            s.exact.insert(DOMAINS_URL.to_string(), c);
        }
    });
}

/// The URLs of a site, from the sub-paths `serve` takes: "" is the root,
/// at both `/site/<repo>` and `/site/<repo>/`.
fn urls(repo: &str, sub: &str) -> Vec<String> {
    if sub.is_empty() {
        vec![format!("/site/{repo}"), format!("/site/{repo}/")]
    } else {
        vec![format!("/site/{repo}/{sub}")]
    }
}

fn site_entries(repo: &str) {
    let wild = HttpCertificationPath::wildcard(format!("/site/{repo}"));
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        // Out with the old: every exact URL of the site, and its wildcard.
        let prefix = format!("/site/{repo}");
        let old: Vec<String> = s
            .exact
            .range(prefix.clone()..)
            .map(|(k, _)| k.clone())
            .take_while(|k| k == &prefix || k.starts_with(&format!("{prefix}/")))
            .collect();
        for url in old {
            if let Some(c) = s.exact.remove(&url) {
                delete(&HttpCertificationPath::exact(url), &c);
            }
        }
        if let Some(c) = s.sites.remove(repo) {
            delete(&wild, &c);
        }
        // A repo with no site: the `/site` wildcard answers for it.
        if site::get_config(repo).is_none() {
            return;
        }
        let cap = s.cap;
        let subs = match site::bundle_paths(repo, cap) {
            Ok(subs) => subs,
            Err(()) => {
                let c = HttpCertification::skip();
                insert(&wild, &c);
                s.sites.insert(repo.to_string(), c);
                return;
            }
        };
        for sub in subs {
            let (res, blob) = site::served(repo, &sub);
            let hash = blob.map(|oid| body_hash(&mut s, &oid, &res.body));
            let Some(c) = certify(&res, hash) else { continue };
            for url in urls(repo, &sub) {
                insert(&HttpCertificationPath::exact(url.clone()), &c);
                s.exact.insert(url, c);
            }
        }
        if let Some(c) = certify(&site::miss(repo), None) {
            insert(&wild, &c);
            s.sites.insert(repo.to_string(), c);
        }
    });
}

/// The entry that answers for a URL path: its exact entry; else the
/// wildcard of its site; else, under `/site`, the no-site wildcard; else
/// the root wildcard, which declares no certification.
fn lookup(path: &str) -> (HttpCertificationPath<'static>, HttpCertification) {
    STATE.with(|s| {
        let s = s.borrow();
        if let Some(c) = s.exact.get(path) {
            return (HttpCertificationPath::exact(path.to_string()), *c);
        }
        if let Some(rest) = path.strip_prefix("/site").filter(|r| r.is_empty() || r.starts_with('/')) {
            let repo = rest.trim_start_matches('/').split('/').next().unwrap_or("");
            if let Some(c) = s.sites.get(repo) {
                return (HttpCertificationPath::wildcard(format!("/site/{repo}")), *c);
            }
            if let Some(c) = s.no_site {
                return (HttpCertificationPath::wildcard("/site"), c);
            }
        }
        (HttpCertificationPath::wildcard(""), HttpCertification::skip())
    })
}

/// The witness for a URL path: the expression path the header names, the
/// pruned tree, and whether the entry declares no certification.
pub(crate) fn witness(path: &str) -> Option<(Vec<String>, HashTree, bool)> {
    let (entry_path, c) = lookup(path);
    let entry = HttpCertificationTreeEntry::new(&entry_path, &c);
    let tree = TREE.with(|t| t.borrow().witness(&entry, path).ok())?;
    Some((entry_path.to_expr_path(), tree, c == HttpCertification::skip()))
}

/// The two headers the gateway reads, for the response the canister is
/// about to give at `url`: the expression (replacing the one `serve` put
/// there when the entry declares no certification) and the certificate
/// with the witness. Only in a query with a certificate to give; an
/// update's answer is not verified.
pub fn attach(url: &str, res: &mut HttpResponse) {
    let Some(cert) = data_certificate() else { return };
    let path = ic_dev_kit_rs::http::extract_path(url);
    let Some((expr_path, tree, skip)) = witness(path) else { return };
    res.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(CERTIFICATE_EXPRESSION_HEADER_NAME));
    let expr = if skip { skip_text() } else { cel_text() };
    res.headers.push((CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), expr.to_string()));
    res.headers.push(certificate_header(&cert, &tree, &expr_path));
}

/// The IC's certificate over this canister's certified data, in a query.
/// Off the IC (tests) there is none.
fn data_certificate() -> Option<Vec<u8>> {
    #[cfg(target_arch = "wasm32")]
    {
        ic_cdk::api::data_certificate()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

/// The IC-Certificate header: the certificate, the witness and the
/// expression path, each CBOR then base64, as the gateway reads them.
fn certificate_header(cert: &[u8], tree: &HashTree, expr_path: &[String]) -> (String, String) {
    use ic_http_certification::utils::{build_v2_certificate_header_value, cbor_encode_to_base64};
    (
        ic_http_certification::CERTIFICATE_HEADER_NAME.to_string(),
        build_v2_certificate_header_value(cert, tree, &cbor_encode_to_base64(&expr_path)),
    )
}

#[cfg(test)]
pub(crate) fn set_cap_for_tests(cap: usize) {
    STATE.with(|s| s.borrow_mut().cap = cap);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{self, ObjectType};

    fn tree(entries: &[(&str, &str, &Oid)]) -> Oid {
        let mut t = Vec::new();
        for (mode, name, oid) in entries {
            t.extend_from_slice(format!("{mode} {name}\0").as_bytes());
            t.extend_from_slice(oid.as_slice());
        }
        store::put_object(ObjectType::Tree, &t)
    }

    fn commit(repo: &str, root: &Oid) -> Oid {
        let c = format!(
            "tree {}\nauthor a <a@a> 0 +0000\ncommitter a <a@a> 0 +0000\n\nmsg\n",
            store::oid_hex(root)
        );
        let oid = store::put_object(ObjectType::Commit, c.as_bytes());
        let branch = store::head_target(repo).unwrap();
        store::set_ref(repo, &branch, oid).unwrap();
        oid
    }

    /// A site: index.html, app/main.js, docs/index.html, docs/a.txt.
    fn site(repo: &str, index: &[u8]) -> Oid {
        let index = store::put_object(ObjectType::Blob, index);
        let js = store::put_object(ObjectType::Blob, b"console.log(1)");
        let a = store::put_object(ObjectType::Blob, b"a");
        let app = tree(&[("100644", "main.js", &js)]);
        let docs = tree(&[("100644", "a.txt", &a), ("100644", "index.html", &index)]);
        let root = tree(&[("40000", "app", &app), ("40000", "docs", &docs), ("100644", "index.html", &index)]);
        commit(repo, &root)
    }

    fn root() -> [u8; 32] {
        TREE.with(|t| t.borrow().root_hash())
    }

    /// The witness for `path` proves the tree's root, and names `expr`.
    fn proves(path: &str, expr: &[&str]) -> bool {
        let (expr_path, tree, _) = witness(path).expect("a witness");
        tree.digest() == root() && expr_path == expr
    }

    /// The response the canister gives at `url` is the one certified
    /// there: its certification, recomputed, is the entry's.
    fn served_as_certified(url: &str) -> bool {
        let (repo, sub) = url.strip_prefix("/site/").unwrap().split_once('/').unwrap_or((url.strip_prefix("/site/").unwrap(), ""));
        let res = site::serve(repo, sub);
        let hash = Some(Sha256::digest(&res.body).into());
        let (_, c) = lookup(url);
        certify(&res, hash) == Some(c)
    }

    #[test]
    fn a_site_is_certified_url_by_url_and_the_rest_declared() {
        store::create_repo("web").unwrap();
        crate::mirror::ungated_for_tests("web");
        site("web", b"<h1>one</h1>");
        rebuild();
        // No site yet: the no-site 404, under /site.
        assert!(proves("/site/web/", &["http_expr", "site", "<*>"]));
        site::set_config("web", String::new()).unwrap();
        let before = root();
        for url in ["/site/web", "/site/web/", "/site/web/index.html", "/site/web/app/main.js", "/site/web/docs", "/site/web/docs/", "/site/web/docs/a.txt", "/site/web/docs/index.html"] {
            let expr: Vec<&str> = std::iter::once("http_expr").chain(url.split('/').skip(1)).chain(["<$>"]).collect();
            assert!(proves(url, &expr), "{url}");
            assert!(served_as_certified(url), "{url}");
        }
        // A directory without an index, a slash after a file, an empty
        // component: misses, certified as the site's one miss.
        for url in ["/site/web/app", "/site/web/app/", "/site/web/index.html/", "/site/web/app//main.js", "/site/web/nope"] {
            assert!(proves(url, &["http_expr", "site", "web", "<*>"]), "{url}");
            assert!(served_as_certified(url), "{url}");
            assert_eq!(site::serve("web", url.strip_prefix("/site/web/").unwrap_or("")).status_code, 404, "{url}");
        }
        // `/site/web//`: the empty path after the repo is a miss too.
        assert_eq!(site::serve("web", "/").status_code, 404);
        // Another repo: the no-site 404; everything else: declared.
        assert!(proves("/site/other/x", &["http_expr", "site", "<*>"]));
        assert!(proves("/site", &["http_expr", "site", "<*>"]));
        let (_, _, skip) = witness("/api/repos").unwrap();
        assert!(skip);
        assert!(proves("/api/repos", &["http_expr", "<*>"]));
        assert!(proves("/web.git/info/refs", &["http_expr", "<*>"]));
        assert!(proves("/.well-known/ic-domains", &["http_expr", ".well-known", "ic-domains", "<$>"]));
        assert_eq!(certify(&site::domains_response(), None), Some(lookup("/.well-known/ic-domains").1));

        // A push moves the tip: the root changes, the new page is certified.
        site("web", b"<h1>two</h1>");
        site::advance("web");
        assert_ne!(root(), before);
        assert!(served_as_certified("/site/web/index.html"));
        assert_eq!(site::serve("web", "").body, b"<h1>two</h1>");
        // Past the cap, the site is declared uncertified as a whole.
        set_cap_for_tests(3);
        site_changed("web");
        let (_, _, skip) = witness("/site/web/index.html").unwrap();
        assert!(skip);
        assert!(proves("/site/web/index.html", &["http_expr", "site", "web", "<*>"]));
        set_cap_for_tests(SITE_FILE_CAP);
        // Serving off: the no-site 404 again, and nothing of the site left.
        site::clear_config_for_tests("web");
        site_changed("web");
        assert!(proves("/site/web/index.html", &["http_expr", "site", "<*>"]));
        assert!(STATE.with(|s| s.borrow().exact.keys().all(|k| !k.starts_with("/site/web"))));
    }
}
