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
//! What is certified, at the canister's own host: every URL a site
//! answers (`/site/<repo>`, `/site/<repo>/`, and each file and directory
//! of the bundle under them, as site.rs `serve` answers them), the 404
//! for any other URL under a site, the 404 for a repo with no site, and
//! `/.well-known/ic-domains`. At a site's own domains (docs/TENANCY.md,
//! "Custom domains"): every URL of the site, `/` and `/<path>`, and its
//! 404 for the rest, each certified with the request's Host and method
//! (GET and HEAD), since the tree is one tree for every host and the
//! gateway matches it by the path: a domain's `/` is told from another's,
//! and from the canister host's own index at `/`, by the Host the
//! certificate covers. Everything else is declared uncertified (the
//! protocol's "no certification" expression, which the gateway passes as
//! it passes the raw host): the git protocol, whose answers depend on the
//! request body and are checked by the client against its refs
//! (ARCHITECTURE.md, "Trust model"), and `/api`. A site of more than
//! `SITE_FILE_CAP` files is declared uncertified as a whole rather than
//! certified in part.
//!
//! One tree, matched by the path, has edges. Where a domain's site has a
//! page, the canister host answers the same path with something else
//! (its index at `/`, a 404, a site under `/site/`), and that answer is
//! certified beside it (a "shadow"), and so is every other domain's 404
//! (a "cross"), so no host loses the path: a path with an entry for one
//! host and none for another cannot be witnessed for the other, since
//! its exact entry sits above the root wildcard the other's 404 is at.
//! The API, the feeds and the git protocol have no fixed answer, so at a
//! domain page under `/api/`, `/feed/` or a `.git/` path the canister
//! host's shadow is the declaration itself, uncertified as before
//! (`canister_host_answer`); the declaration sits at the page's own
//! leaf, so a replica can pass it for the domain's page too: a site's
//! page at such a path is no better certified than the API is. What
//! remains is a domain's 404 under `/site/`, where the canister host
//! holds its sites under wildcards more specific than the root's: the
//! gateway's check fails there. And the Host an entry covers is the
//! domain as it is written, which is what a browser sends: a request
//! whose Host spells it otherwise (a port, capitals, a trailing dot) is
//! routed to the site and given no entry made for another spelling, so
//! it passes where the root wildcard answers and fails at a page.
//!
//! The tree is heap state: rebuilt from stable memory at install and
//! upgrade (`rebuild`) and recomputed for a site whenever what it serves
//! can change (`site_changed`: the config, the domains, the served
//! commit, a push, a ref written by an operator; `repos_changed` for the
//! index). Each URL is certified by asking `serve` for it, so the
//! certified bytes and the served bytes are one function's answer. Body
//! hashes are kept by blob, so a push that changes one file hashes one
//! file.

use crate::site;
use crate::store::Oid;
use ic_certification::HashTree;
use ic_dev_kit_rs::http::HttpResponse;
use ic_http_certification::{
    DefaultCelBuilder, DefaultFullCelExpression, DefaultResponseCertification, DefaultResponseOnlyCelExpression,
    HttpCertification, HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry,
    HttpRequest as CertRequest, HttpResponse as CertResponse, Method, StatusCode, CERTIFICATE_EXPRESSION_HEADER_NAME,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// How many URLs (files, and directories with an index) a site may have
/// and be certified. Each is one hash at every change of the site and
/// one tree entry; past this the site is declared uncertified as a
/// whole, which the raw host and the verifying clients serve as before.
pub const SITE_FILE_CAP: usize = 2000;

/// How many entries a site's domains may add (its URLs, times its
/// domains, times the two methods); past this the domain form is left
/// as it was before it was certified: declared uncertified.
pub const DOMAIN_ENTRY_CAP: usize = 16_000;

/// The response headers the certificate covers: what a client reads. The
/// body and the status are always covered.
const CERTIFIED_HEADERS: [&str; 5] = ["Content-Type", "Cache-Control", "X-Ic-Git-Repo", "X-Ic-Git-Commit", "X-Ic-Git-Path"];

/// The methods a domain's entries are made for: the request's method is
/// in its hash.
const METHODS: [&str; 2] = ["GET", "HEAD"];

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

/// The domain form: the request's Host and method are in the hash too.
fn full_cel() -> &'static DefaultFullCelExpression<'static> {
    static CEL: OnceLock<DefaultFullCelExpression<'static>> = OnceLock::new();
    CEL.get_or_init(|| {
        DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["host"])
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

fn full_text() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(|| full_cel().to_string())
}

fn skip_text() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(|| DefaultCelBuilder::skip_certification().to_string())
}

/// The header every certified response carries, naming what its
/// certificate covers. Part of the response before it is hashed, so
/// site.rs puts it on every answer of `serve` and on the pages beside
/// it; `attach` replaces it when the entry it found covers otherwise.
pub fn expression_header() -> (String, String) {
    (CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_text().to_string())
}

fn set_expression(res: &mut HttpResponse, text: &str) {
    res.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(CERTIFICATE_EXPRESSION_HEADER_NAME));
    res.headers.push((CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), text.to_string()));
}

/// What an entry's certificate covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Nothing: declared uncertified.
    Skip,
    /// The response, at its path.
    Response,
    /// The response, at its path, for the request's Host and method.
    Full,
}

impl Kind {
    fn text(self) -> &'static str {
        match self {
            Kind::Skip => skip_text(),
            Kind::Response => cel_text(),
            Kind::Full => full_text(),
        }
    }
}

/// A site's entries at its own domains.
#[derive(Default)]
struct Domain {
    /// (host, method, path): each URL of the site.
    exact: BTreeMap<(String, String, String), HttpCertification>,
    /// (host, method): the site's 404 for every other path, at the root
    /// wildcard.
    miss: BTreeMap<(String, String), HttpCertification>,
}

#[derive(Default)]
struct State {
    /// Exact URLs at the canister host: every file and directory of
    /// every certified site, and the domains file.
    exact: BTreeMap<String, HttpCertification>,
    /// Per repo with a site config, the wildcard under `/site/<repo>`:
    /// the certified miss, or skip for a site past the cap.
    sites: BTreeMap<String, HttpCertification>,
    /// The wildcard under `/site`: the 404 for a repo with no site.
    no_site: Option<HttpCertification>,
    /// Per repo, its entries at its domains.
    domains: BTreeMap<String, Domain>,
    /// The canister host's answers at the paths of the domains' sites
    /// that have no exact entry of their own.
    shadow: BTreeMap<String, HttpCertification>,
    /// (host, method, path): each domain's 404 at the paths other
    /// domains' sites have and it has not.
    cross: BTreeMap<(String, String, String), HttpCertification>,
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

/// The request a domain's entry is made for: the method and the Host,
/// which are what its hash covers (the path is the tree's).
fn request(method: &str, path: &str, host: &str) -> CertRequest<'static> {
    CertRequest::builder()
        .with_method(Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET))
        .with_url(path.to_string())
        .with_headers(vec![("host".to_string(), host.to_string())])
        .build()
}

/// The certification of a response `serve` or its neighbours gave:
/// `None` only for a response without the expression header, which none
/// of theirs is.
fn certify(res: &HttpResponse, body_hash: Option<[u8; 32]>) -> Option<HttpCertification> {
    HttpCertification::response_only(cel(), &cert_response(res), body_hash).ok()
}

fn certify_full(method: &str, path: &str, host: &str, res: &HttpResponse, body_hash: Option<[u8; 32]>) -> Option<HttpCertification> {
    HttpCertification::full(full_cel(), &request(method, path, host), &cert_response(res), body_hash).ok()
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
    STATE.with(|s| between(&mut s.borrow_mut()));
    publish();
}

/// What a site serves may have changed: its config, its domains, its
/// served commit, a push, a ref an operator wrote.
pub fn site_changed(repo: &str) {
    site_entries(repo);
    STATE.with(|s| between(&mut s.borrow_mut()));
    publish();
}

/// The domains file changed.
pub fn domains_changed() {
    domains_entry();
    publish();
}

/// The list of repos changed: the index at `/`, where a domain's site
/// has its root too, is certified beside it.
pub fn repos_changed() {
    STATE.with(|s| between(&mut s.borrow_mut()));
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

/// The URLs of a site at the canister host, from the sub-paths `serve`
/// takes: "" is the root, at both `/site/<repo>` and `/site/<repo>/`.
fn urls(repo: &str, sub: &str) -> Vec<String> {
    if sub.is_empty() {
        vec![format!("/site/{repo}"), format!("/site/{repo}/")]
    } else {
        vec![format!("/site/{repo}/{sub}")]
    }
}

/// The URL of a site's sub-path at its own domain: the root is `/`.
fn domain_url(sub: &str) -> String {
    format!("/{sub}")
}

fn site_entries(repo: &str) {
    let wild = HttpCertificationPath::wildcard(format!("/site/{repo}"));
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        // Out with the old: every exact URL of the site, its wildcard, and
        // its domains' entries. The root and the rest are two walks: in
        // key order another repo's root can sit between them
        // (`/site/web-2` before `/site/web/`).
        let root = format!("/site/{repo}");
        let under = format!("{root}/");
        let mut old: Vec<String> = s.exact.range(under.clone()..).map(|(k, _)| k.clone()).take_while(|k| k.starts_with(&under)).collect();
        old.push(root);
        for url in old {
            if let Some(c) = s.exact.remove(&url) {
                delete(&HttpCertificationPath::exact(url), &c);
            }
        }
        if let Some(c) = s.sites.remove(repo) {
            delete(&wild, &c);
        }
        if let Some(d) = s.domains.remove(repo) {
            for ((_, _, path), c) in &d.exact {
                delete(&HttpCertificationPath::exact(path.clone()), c);
            }
            for c in d.miss.values() {
                delete(&HttpCertificationPath::wildcard(""), c);
            }
        }
        // A repo with no site: the `/site` wildcard answers for it.
        let Some(cfg) = site::get_config(repo) else {
            return;
        };
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
        let hosts = cfg.domains;
        let with_domains = !hosts.is_empty() && subs.len() * hosts.len() * METHODS.len() <= DOMAIN_ENTRY_CAP;
        let mut domain = Domain::default();
        for sub in subs {
            let (mut res, blob) = site::served(repo, &sub);
            let hash = blob.map(|oid| body_hash(&mut s, &oid, &res.body));
            let Some(c) = certify(&res, hash) else { continue };
            for url in urls(repo, &sub) {
                insert(&HttpCertificationPath::exact(url.clone()), &c);
                s.exact.insert(url, c);
            }
            if with_domains {
                set_expression(&mut res, full_text());
                let path = domain_url(&sub);
                for host in &hosts {
                    for method in METHODS {
                        let Some(c) = certify_full(method, &path, host, &res, hash) else { continue };
                        insert(&HttpCertificationPath::exact(path.clone()), &c);
                        domain.exact.insert((host.clone(), method.to_string(), path.clone()), c);
                    }
                }
            }
        }
        let mut miss = site::miss(repo);
        if let Some(c) = certify(&miss, None) {
            insert(&wild, &c);
            s.sites.insert(repo.to_string(), c);
        }
        if with_domains {
            set_expression(&mut miss, full_text());
            for host in &hosts {
                for method in METHODS {
                    let Some(c) = certify_full(method, "/", host, &miss, None) else { continue };
                    insert(&HttpCertificationPath::wildcard(""), &c);
                    domain.miss.insert((host.clone(), method.to_string()), c);
                }
            }
            s.domains.insert(repo.to_string(), domain);
        }
    });
}

/// What the canister host answers at a path a domain's site has, so
/// that the path keeps an entry for both hosts: its index at `/`, a site
/// under `/site/`, or its 404. `None` where the canisters' routers answer
/// with something this module cannot certify ahead: the API, the feeds
/// (`/feed`, `/feed/<repo>`: the combined build's), and the git protocol
/// (`/<repo>.git/...`), whose answers depend on the request or the
/// moment; those paths are declared uncertified at the path itself,
/// since the root wildcard's declaration cannot be witnessed past the
/// domain's entry there.
fn canister_host_answer(path: &str) -> Option<HttpResponse> {
    if path == "/" {
        return Some(site::index_response());
    }
    if path.starts_with("/api/") || path == "/feed" || path.starts_with("/feed/") || path.contains(".git/") {
        return None;
    }
    if let Some((repo, sub)) = site::site_path(path) {
        return Some(site::serve(repo, sub));
    }
    Some(site::not_found())
}

/// The paths the domains' sites have, between them.
fn domain_paths(s: &State) -> BTreeSet<String> {
    s.domains.values().flat_map(|d| d.exact.keys().map(|(_, _, p)| p.clone())).collect()
}

/// Recompute what the other hosts answer at the paths the domains' sites
/// have: the shadows and the crosses.
fn between(s: &mut State) {
    shadows(s);
    crosses(s);
}

/// Recompute the shadows: the canister host's answers at every path a
/// domain's site has and no exact entry covers, or the declaration that
/// there is no certification where the answer is the routers'.
fn shadows(s: &mut State) {
    for (path, c) in std::mem::take(&mut s.shadow) {
        delete(&HttpCertificationPath::exact(path), &c);
    }
    for path in domain_paths(s) {
        if s.exact.contains_key(&path) {
            continue;
        }
        let c = match canister_host_answer(&path) {
            Some(res) => match certify(&res, None) {
                Some(c) => c,
                None => continue,
            },
            None => HttpCertification::skip(),
        };
        insert(&HttpCertificationPath::exact(path.clone()), &c);
        s.shadow.insert(path, c);
    }
}

/// Recompute the crosses: each domain's 404, for its hosts and methods,
/// at every path another domain's site has and it has not, so that the
/// path, an exact leaf, keeps an entry for every host. The 404 is one
/// certification per host and method, whatever the path (the request
/// hash covers the method and the Host, not the path), so a cross is a
/// tree entry and no hash; only the entries that changed are touched.
fn crosses(s: &mut State) {
    let paths = domain_paths(s);
    let mut want = BTreeMap::new();
    for d in s.domains.values() {
        for ((host, method), c) in &d.miss {
            for path in &paths {
                let key = (host.clone(), method.clone(), path.clone());
                if !d.exact.contains_key(&key) {
                    want.insert(key, *c);
                }
            }
        }
    }
    let had = std::mem::replace(&mut s.cross, want);
    for (key, c) in &had {
        if s.cross.get(key) != Some(c) {
            delete(&HttpCertificationPath::exact(key.2.clone()), c);
        }
    }
    for (key, c) in &s.cross {
        if had.get(key) != Some(c) {
            insert(&HttpCertificationPath::exact(key.2.clone()), c);
        }
    }
}

/// The entry that answers for a request: at a site's own domain, the
/// site's entry for the Host, the method and the path, its 404 at a path
/// another domain's site has (a cross), or its 404 at the root wildcard,
/// and none of them for a Host that is not the domain as written: the
/// gateway hashes the header it was sent, not the name it routes to;
/// at the canister host, the path's exact entry (a site's
/// URL, the domains file, a shadow); else the wildcard of its site; else,
/// under `/site`, the no-site wildcard; else the root wildcard, which
/// declares no certification.
fn lookup(path: &str, host: Option<&str>, method: &str) -> (HttpCertificationPath<'static>, HttpCertification, Kind) {
    STATE.with(|s| {
        let s = s.borrow();
        if let Some(repo) = site::repo_for_host(host) {
            // The domains file is answered on every host.
            if path == DOMAINS_URL {
                if let Some(c) = s.exact.get(path) {
                    return (HttpCertificationPath::exact(path.to_string()), *c, Kind::Response);
                }
            }
            let sent = host.unwrap_or_default();
            let name = site::host_name(sent);
            if let Some(d) = s.domains.get(&repo).filter(|_| sent == name) {
                let key = (name.clone(), method.to_string(), path.to_string());
                if let Some(c) = d.exact.get(&key).or_else(|| s.cross.get(&key)) {
                    return (HttpCertificationPath::exact(path.to_string()), *c, Kind::Full);
                }
                if let Some(c) = d.miss.get(&(name, method.to_string())) {
                    return (HttpCertificationPath::wildcard(""), *c, Kind::Full);
                }
            }
            return (HttpCertificationPath::wildcard(""), HttpCertification::skip(), Kind::Skip);
        }
        if let Some(c) = s.exact.get(path) {
            return (HttpCertificationPath::exact(path.to_string()), *c, Kind::Response);
        }
        if let Some(c) = s.shadow.get(path) {
            let kind = if *c == HttpCertification::skip() { Kind::Skip } else { Kind::Response };
            return (HttpCertificationPath::exact(path.to_string()), *c, kind);
        }
        if let Some((repo, _)) = site::site_path(path) {
            if let Some(c) = s.sites.get(repo) {
                let kind = if *c == HttpCertification::skip() { Kind::Skip } else { Kind::Response };
                return (HttpCertificationPath::wildcard(format!("/site/{repo}")), *c, kind);
            }
            if let Some(c) = s.no_site {
                return (HttpCertificationPath::wildcard("/site"), c, Kind::Response);
            }
        }
        (HttpCertificationPath::wildcard(""), HttpCertification::skip(), Kind::Skip)
    })
}

/// The witness for a request: the expression path the header names, the
/// pruned tree, and what the entry covers.
pub(crate) fn witness(path: &str, host: Option<&str>, method: &str) -> Option<(Vec<String>, HashTree, Kind)> {
    let (entry_path, c, kind) = lookup(path, host, method);
    let entry = HttpCertificationTreeEntry::new(&entry_path, &c);
    let tree = TREE.with(|t| t.borrow().witness(&entry, path).ok())?;
    Some((entry_path.to_expr_path(), tree, kind))
}

/// The two headers the gateway reads, for the response the canister is
/// about to give to a request: the expression (replacing the one `serve`
/// put there when the entry found covers otherwise) and the certificate
/// with the witness. Only in a query with a certificate to give; an
/// update's answer is not verified.
pub fn attach(url: &str, host: Option<&str>, method: &str, res: &mut HttpResponse) {
    let Some(cert) = data_certificate() else { return };
    let path = ic_dev_kit_rs::http::extract_path(url);
    let Some((expr_path, tree, kind)) = witness(path, host, method) else { return };
    set_expression(res, kind.text());
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

    /// The witness for `path` at the canister host proves the tree's
    /// root, and names `expr`.
    fn proves(path: &str, expr: &[&str]) -> bool {
        proves_at(path, None, "GET", expr)
    }

    fn proves_at(path: &str, host: Option<&str>, method: &str, expr: &[&str]) -> bool {
        let (expr_path, tree, _) = witness(path, host, method).expect("a witness");
        tree.digest() == root() && expr_path == expr
    }

    fn kind_at(path: &str, host: Option<&str>, method: &str) -> Kind {
        witness(path, host, method).expect("a witness").2
    }

    /// The response the canister gives at `url` on its own host is the
    /// one certified there: its certification, recomputed, is the entry's.
    fn served_as_certified(url: &str) -> bool {
        let (repo, sub) = site::site_path(url).expect("a site URL");
        let res = site::serve(repo, sub);
        let hash = Some(Sha256::digest(&res.body).into());
        let (_, c, _) = lookup(url, None, "GET");
        certify(&res, hash) == Some(c)
    }

    /// The response the canister gives for `sub` at a domain is the one
    /// certified there for that Host and method: the gateway recomputes
    /// the request hash from the request it forwarded.
    fn served_at_domain_as_certified(repo: &str, host: &str, method: &str, sub: &str) -> bool {
        let mut res = site::serve(repo, sub);
        set_expression(&mut res, full_text());
        let path = domain_url(sub);
        let hash = Some(Sha256::digest(&res.body).into());
        let (_, c, kind) = lookup(&path, Some(host), method);
        kind == Kind::Full && certify_full(method, &path, host, &res, hash) == Some(c)
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
        assert_eq!(kind_at("/api/repos", None, "GET"), Kind::Skip);
        assert!(proves("/api/repos", &["http_expr", "<*>"]));
        assert!(proves("/web.git/info/refs", &["http_expr", "<*>"]));
        assert!(proves("/", &["http_expr", "<*>"]));
        assert!(proves("/.well-known/ic-domains", &["http_expr", ".well-known", "ic-domains", "<$>"]));
        assert_eq!(certify(&site::domains_response(), None), Some(lookup("/.well-known/ic-domains", None, "GET").1));

        // A push moves the tip: the root changes, the new page is certified.
        site("web", b"<h1>two</h1>");
        site::advance("web");
        assert_ne!(root(), before);
        assert!(served_as_certified("/site/web/index.html"));
        assert_eq!(site::serve("web", "").body, b"<h1>two</h1>");
        // Past the cap, the site is declared uncertified as a whole.
        set_cap_for_tests(3);
        site_changed("web");
        assert_eq!(kind_at("/site/web/index.html", None, "GET"), Kind::Skip);
        assert!(proves("/site/web/index.html", &["http_expr", "site", "web", "<*>"]));
        set_cap_for_tests(SITE_FILE_CAP);
        // Serving off: the no-site 404 again, and nothing of the site left.
        site::clear_config_for_tests("web");
        site_changed("web");
        assert!(proves("/site/web/index.html", &["http_expr", "site", "<*>"]));
        assert!(STATE.with(|s| s.borrow().exact.keys().all(|k| !k.starts_with("/site/web"))));
    }

    #[test]
    fn a_site_whose_name_sorts_between_another_and_its_pages_leaves_that_site_whole() {
        for repo in ["web", "web-2"] {
            store::create_repo(repo).unwrap();
            crate::mirror::ungated_for_tests(repo);
            site(repo, b"<h1>one</h1>");
        }
        rebuild();
        site::set_config("web", String::new()).unwrap();
        site::set_config("web-2", String::new()).unwrap();
        // `web` loses its docs: a commit with the root index only.
        let index = store::put_object(ObjectType::Blob, b"<h1>two</h1>");
        let root = tree(&[("100644", "index.html", &index)]);
        commit("web", &root);
        site::advance("web");
        // Nothing stale under /site/web/, and web-2 is as it was.
        assert!(proves("/site/web/docs/a.txt", &["http_expr", "site", "web", "<*>"]));
        assert!(served_as_certified("/site/web/docs/a.txt"));
        assert!(served_as_certified("/site/web/index.html"));
        assert!(served_as_certified("/site/web-2/docs/a.txt"));
        assert!(served_as_certified("/site/web-2"));
        let keys: Vec<String> = STATE.with(|s| s.borrow().exact.keys().filter(|k| k.starts_with("/site/web/")).cloned().collect());
        assert_eq!(keys, ["/site/web/", "/site/web/index.html"]);
    }

    #[test]
    fn a_site_at_its_domains_is_certified_by_host_and_the_canister_host_keeps_its_paths() {
        for repo in ["web", "other"] {
            store::create_repo(repo).unwrap();
            crate::mirror::ungated_for_tests(repo);
            site(repo, format!("<h1>{repo}</h1>").as_bytes());
            site::set_config(repo, String::new()).unwrap();
        }
        rebuild();
        // Before any domain: the index at / is declared, like the rest.
        assert_eq!(kind_at("/", None, "GET"), Kind::Skip);
        site::set_domains("web", vec!["app.example".into(), "www.app.example".into()]).unwrap();
        site::set_domains("other", vec!["other.example".into()]).unwrap();
        // Each URL of each site, for each of its hosts and both methods,
        // as the gateway would recompute it from the forwarded request.
        for (repo, host) in [("web", "app.example"), ("web", "www.app.example"), ("other", "other.example")] {
            for sub in ["", "index.html", "app/main.js", "docs", "docs/", "docs/a.txt"] {
                for method in METHODS {
                    assert!(served_at_domain_as_certified(repo, host, method, sub), "{repo} {host} {method} {sub:?}");
                }
            }
            let expr: Vec<&str> = vec!["http_expr", "docs", "a.txt", "<$>"];
            assert!(proves_at("/docs/a.txt", Some(host), "GET", &expr), "{host}");
            assert!(proves_at("/", Some(host), "HEAD", &["http_expr", "", "<$>"]), "{host}");
            // The site's 404 for the rest, at the root wildcard, for this
            // host.
            assert!(proves_at("/nope", Some(host), "GET", &["http_expr", "<*>"]), "{host}");
            assert_eq!(kind_at("/nope", Some(host), "GET"), Kind::Full);
            // A Host spelled otherwise is routed to the site all the same,
            // and gets no entry made for the domain as written: the gateway
            // would hash the header it sent and find another.
            for sent in [format!("{host}:443"), host.to_uppercase(), format!("{host}.")] {
                assert_eq!(site::repo_for_host(Some(&sent)).as_deref(), Some(repo), "{sent}");
                for path in ["/", "/docs/a.txt", "/nope"] {
                    let (entry, c, kind) = lookup(path, Some(&sent), "GET");
                    assert_eq!(kind, Kind::Skip, "{sent} {path}");
                    assert_eq!(c, HttpCertification::skip(), "{sent} {path}");
                    assert_eq!(entry.to_expr_path(), ["http_expr", "<*>"], "{sent} {path}");
                }
            }
        }
        // The two sites' roots are told apart by the Host: different leaves.
        let (_, web, _) = lookup("/", Some("app.example"), "GET");
        let (_, other, _) = lookup("/", Some("other.example"), "GET");
        assert_ne!(web, other);
        // A host that is nobody's domain is the canister host: the index.
        assert_eq!(kind_at("/", Some("nobody.example"), "GET"), Kind::Response);
        // The canister host keeps every path the domains took: its index
        // at /, certified beside the domains' roots; its 404 at their
        // pages; its own site at /site/web/index.html, as before.
        assert!(proves("/", &["http_expr", "", "<$>"]));
        assert_eq!(certify(&site::index_response(), None), Some(lookup("/", None, "GET").1));
        assert!(proves("/index.html", &["http_expr", "index.html", "<$>"]));
        assert_eq!(certify(&site::not_found(), None), Some(lookup("/index.html", None, "GET").1));
        assert!(proves("/site/web/index.html", &["http_expr", "site", "web", "index.html", "<$>"]));
        assert!(served_as_certified("/site/web/index.html"));
        // A new repo changes the index: recertified.
        let before = lookup("/", None, "GET").1;
        store::create_repo("third").unwrap();
        repos_changed();
        assert_ne!(before, lookup("/", None, "GET").1);
        assert_eq!(certify(&site::index_response(), None), Some(lookup("/", None, "GET").1));
        // What the routers answer otherwise gets no shadow: a domain page
        // at /feed must not certify a 404 over the combined build's feed.
        for path in ["/feed", "/feed/web", "/web.git/info/refs"] {
            assert!(canister_host_answer(path).is_none(), "{path}");
        }
        // At a domain, a doubled slash is the miss the root wildcard holds
        // for the host, as /site/<repo>//x is at the canister host: served
        // and certified agree.
        let mut res = site::serve("web", site::domain_path("//index.html"));
        assert_eq!(res.status_code, 404);
        set_expression(&mut res, full_text());
        let (_, c, kind) = lookup("//index.html", Some("app.example"), "GET");
        assert_eq!(kind, Kind::Full);
        assert_eq!(certify_full("GET", "/", "app.example", &res, None), Some(c));
        // The two sites had the same paths: nothing between them. `other`
        // loses its docs: at its domain, /docs/a.txt is now a path only
        // web's site has, an exact leaf above the root wildcard; its 404
        // is certified there for it (a cross), as served, both methods.
        assert!(STATE.with(|s| s.borrow().cross.is_empty()));
        let index = store::put_object(ObjectType::Blob, b"<h1>other</h1>");
        let root = tree(&[("100644", "index.html", &index)]);
        commit("other", &root);
        site::advance("other");
        for method in METHODS {
            assert!(proves_at("/docs/a.txt", Some("other.example"), method, &["http_expr", "docs", "a.txt", "<$>"]), "{method}");
            assert!(served_at_domain_as_certified("other", "other.example", method, "docs/a.txt"), "{method}");
        }
        assert_eq!(site::serve("other", "docs/a.txt").status_code, 404);
        // The same 404 as at a path nobody has; web's page is as it was;
        // nothing crosses the other way, web having every path.
        assert_eq!(lookup("/docs/a.txt", Some("other.example"), "GET").1, lookup("/nope", Some("other.example"), "GET").1);
        assert!(proves_at("/nope", Some("other.example"), "GET", &["http_expr", "<*>"]));
        assert!(served_at_domain_as_certified("web", "app.example", "GET", "docs/a.txt"));
        assert!(STATE.with(|s| s.borrow().cross.keys().all(|(h, _, _)| h == "other.example")));
        // Domains off: the entries, the shadows and the crosses go, the
        // index is declared again.
        site::set_domains("web", vec![]).unwrap();
        site::set_domains("other", vec![]).unwrap();
        assert_eq!(kind_at("/", None, "GET"), Kind::Skip);
        assert!(proves("/index.html", &["http_expr", "<*>"]));
        assert!(STATE.with(|s| s.borrow().domains.is_empty() && s.borrow().shadow.is_empty() && s.borrow().cross.is_empty()));
    }

    #[test]
    fn a_domain_page_at_a_route_of_the_canister_leaves_the_route_declared_at_its_own_leaf() {
        store::create_repo("web").unwrap();
        crate::mirror::ungated_for_tests("web");
        // A site with files where the routers answer: api/repos, feed,
        // web.git/info/refs.
        let blob = store::put_object(ObjectType::Blob, b"[]");
        let api = tree(&[("100644", "repos", &blob)]);
        let info = tree(&[("100644", "refs", &blob)]);
        let git = tree(&[("40000", "info", &info)]);
        let root_tree = tree(&[("40000", "api", &api), ("100644", "feed", &blob), ("100644", "index.html", &blob), ("40000", "web.git", &git)]);
        commit("web", &root_tree);
        site::set_config("web", String::new()).unwrap();
        rebuild();
        site::set_domains("web", vec!["app.example".into()]).unwrap();
        for (path, sub) in [("/api/repos", "api/repos"), ("/feed", "feed"), ("/web.git/info/refs", "web.git/info/refs")] {
            // The domain's page is an exact leaf at the path.
            assert!(served_at_domain_as_certified("web", "app.example", "GET", sub), "{path}");
            // The canister host's answer there is the routers': declared
            // uncertified, at the same leaf, where its witness is whole
            // (the root wildcard's would not show the path absent).
            let expr: Vec<&str> = std::iter::once("http_expr").chain(path.split('/').skip(1)).chain(["<$>"]).collect();
            assert_eq!(kind_at(path, None, "GET"), Kind::Skip, "{path}");
            assert_eq!(lookup(path, None, "GET").1, HttpCertification::skip(), "{path}");
            assert!(proves(path, &expr), "{path}");
        }
        // A route the site has no page at is under the root wildcard still.
        assert!(proves("/api/other", &["http_expr", "<*>"]));
        // Domains off: the declarations at the leaves go with the pages.
        site::set_domains("web", vec![]).unwrap();
        assert!(proves("/api/repos", &["http_expr", "<*>"]));
        assert!(STATE.with(|s| s.borrow().shadow.is_empty()));
    }
}
