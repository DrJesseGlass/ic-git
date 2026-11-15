//! The old URLs after the cut (docs/CANISTER_SPLIT.md, step 16.6): umobs
//! served sites and git before the git canister existed, and links and
//! remotes still name it. Once the git canister is named, the authority
//! answers a read of `/site/...` or `/<repo>.git/...` with a permanent
//! redirect to the same path and query on the git canister.
//!
//! The new host is the request's own with this canister's id swapped for
//! the git canister's, so the `raw.` gateway, the domain and a local port
//! all carry over -- under the IC's own gateway domains only (`GATEWAYS`),
//! so a forged Host cannot point the redirect anywhere else. Any other
//! host (a custom domain, or none) goes to the git canister's raw gateway
//! on icp0.io, where its sites are served (site.rs: no response
//! certification yet).
//!
//! Only reads (GET, HEAD) are redirected. Git follows a redirect on its
//! first request (`http.followRedirects`, default `initial`) and sends the
//! rest of the exchange to the new remote; a POST to the old one is a
//! client that never asked first, and gets the 404 it always got.

use candid::Principal;

/// Where a request to this canister now lives, or `None` when it is not
/// one of the git canister's paths, or not a read.
pub fn location(method: &str, url: &str, host: Option<&str>, me: Principal, git: Principal) -> Option<String> {
    if method != "GET" && method != "HEAD" {
        return None;
    }
    let path = url.split('?').next().unwrap_or(url);
    if !moved(path) {
        return None;
    }
    let me = me.to_text();
    let git = git.to_text();
    let host = host
        .map(str::to_ascii_lowercase)
        .and_then(|h| h.strip_prefix(me.as_str()).map(str::to_string))
        .filter(|rest| gateway(rest))
        .map(|rest| format!("{git}{rest}"));
    Some(match host {
        Some(h) => format!("{}://{h}{url}", scheme(&h)),
        None => format!("https://{git}.raw.icp0.io{url}"),
    })
}

/// A path the git canister answers now: a site, or a repo's git service.
fn moved(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("/site/") {
        return !rest.is_empty();
    }
    path.strip_prefix('/')
        .and_then(|p| p.split_once(".git/"))
        .is_some_and(|(repo, rest)| !repo.is_empty() && !repo.contains('/') && !rest.is_empty())
}

/// The IC's gateway domains, as what follows a canister's id in a host.
const GATEWAYS: [&str; 6] = [".icp0.io", ".raw.icp0.io", ".ic0.app", ".raw.ic0.app", ".localhost", ".raw.localhost"];

/// Is `rest` (the host after the canister id) one of `GATEWAYS`, with a
/// port only on the local one?
fn gateway(rest: &str) -> bool {
    let (name, port) = match rest.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (rest, None),
    };
    let local = name.ends_with(".localhost");
    GATEWAYS.contains(&name) && port.is_none_or(|p| local && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The local replica's gateway speaks plain HTTP; every other host here is
/// a boundary node's, which speaks HTTPS.
fn scheme(host: &str) -> &'static str {
    let name = host.rsplit_once(':').map_or(host, |(n, _)| n);
    if name == "localhost" || name.ends_with(".localhost") {
        "http"
    } else {
        "https"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (Principal, Principal) {
        (
            Principal::from_text("umobs-yiaaa-aaaab-agyrq-cai").unwrap(),
            Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap(),
        )
    }

    /// The same path and query on the git canister, under the request's
    /// own domain with the id swapped: raw or not, local with its port.
    #[test]
    fn the_old_urls_go_to_the_git_canister() {
        let (me, git) = ids();
        let at = |url: &str, host: &str| location("GET", url, Some(host), me, git);
        assert_eq!(
            at("/site/app/index.html", "umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io").as_deref(),
            Some("https://ryjl3-tyaaa-aaaaa-aaaba-cai.raw.icp0.io/site/app/index.html")
        );
        assert_eq!(
            at("/app.git/info/refs?service=git-upload-pack", "umobs-yiaaa-aaaab-agyrq-cai.icp0.io").as_deref(),
            Some("https://ryjl3-tyaaa-aaaaa-aaaba-cai.icp0.io/app.git/info/refs?service=git-upload-pack")
        );
        assert_eq!(
            at("/site/app/", "umobs-yiaaa-aaaab-agyrq-cai.raw.localhost:4950").as_deref(),
            Some("http://ryjl3-tyaaa-aaaaa-aaaba-cai.raw.localhost:4950/site/app/")
        );
        assert_eq!(
            location("HEAD", "/site/app/", None, me, git).as_deref(),
            Some("https://ryjl3-tyaaa-aaaaa-aaaba-cai.raw.icp0.io/site/app/"),
            "no host: the git canister's raw gateway"
        );
        assert_eq!(
            at("/site/app/", "git.example.org").as_deref(),
            Some("https://ryjl3-tyaaa-aaaaa-aaaba-cai.raw.icp0.io/site/app/"),
            "another domain likewise"
        );
        assert_eq!(
            at("/site/app/", "umobs-yiaaa-aaaab-agyrq-caiX.icp0.io").as_deref(),
            Some("https://ryjl3-tyaaa-aaaaa-aaaba-cai.raw.icp0.io/site/app/"),
            "a host that only starts with the id is another domain"
        );
        assert_eq!(
            at("/site/app/", "UMOBS-yiaaa-aaaab-agyrq-cai.RAW.icp0.io").as_deref(),
            Some("https://ryjl3-tyaaa-aaaaa-aaaba-cai.raw.icp0.io/site/app/"),
            "hosts compare without case"
        );
        // A forged Host cannot steer the redirect off the IC's domains.
        for forged in [
            "umobs-yiaaa-aaaab-agyrq-cai.evil.example",
            "umobs-yiaaa-aaaab-agyrq-cai.icp0.io.evil.example",
            "umobs-yiaaa-aaaab-agyrq-cai.icp0.io:8443",
            "umobs-yiaaa-aaaab-agyrq-cai.localhost:x",
            "umobs-yiaaa-aaaab-agyrq-cai.icp0.io/evil",
        ] {
            assert_eq!(
                at("/site/app/", forged).as_deref(),
                Some("https://ryjl3-tyaaa-aaaaa-aaaba-cai.raw.icp0.io/site/app/"),
                "{forged}"
            );
        }
    }

    /// The authority's own paths, a write, and paths that are not a repo's
    /// stay here.
    #[test]
    fn the_rest_stays() {
        let (me, git) = ids();
        let host = Some("umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io");
        for url in ["/", "/feed", "/feed/app", "/api/pricing", "/site/", "/.git/info/refs", "/a/b.git/info/refs", "/app.git/", "/app.git"] {
            assert_eq!(location("GET", url, host, me, git), None, "{url}");
        }
        assert_eq!(location("POST", "/app.git/git-receive-pack", host, me, git), None);
    }
}
