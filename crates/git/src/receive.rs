//! receive-pack: push command parsing, validation, and report-status
//! (milestone 3). Pack decoding lives in pack.rs next to the encoder.
//!
//! Flow: parse "old-oid new-oid refname" commands, ingest the trailing
//! packfile, then per command check old-value match, connectivity (every
//! object reachable from the new tip exists), and fast-forward, applying
//! the ones that pass. The reply is a report-status body; auth happens in
//! lib.rs before this module is reached.
//!
//! A signed push (signed_push.rs) sends a push certificate instead of the
//! plain command list, and its commands are the `<old> <new> <ref>` lines
//! inside the certificate. `parse_request` reads either form, so lib.rs can
//! check the signature before the push is charged or its pack is read, and
//! the commands that run are exactly the ones that were signed.

use crate::jobs;
use crate::object;
use crate::pack;
use crate::signed_push::{self, PushCert};
use crate::smart_http::{parse_pkt_lines, pkt_line, FLUSH_PKT, ZERO_OID};
use crate::store::{self, ObjectType, Oid};
use std::collections::BTreeSet;

struct Command {
    old: Option<Oid>,
    new: Option<Oid>,
    refname: String,
}

/// A parsed receive-pack request: the commands to run, the certificate
/// they came in if the push was signed, and where the packfile starts.
pub struct Request {
    commands: Vec<Command>,
    pub cert: Option<PushCert>,
    pack_start: usize,
}

pub fn parse_request(body: &[u8]) -> Result<Request, String> {
    let (lines, pack_start) = parse_pkt_lines(body)?;
    let signed = lines
        .first()
        .is_some_and(|l| l.starts_with(b"push-cert\0") || l.as_slice() == b"push-cert\n");
    if !signed {
        let mut commands = Vec::new();
        for line in &lines {
            if line.is_empty() {
                break; // flush ends the command section
            }
            let line = std::str::from_utf8(line).map_err(|_| "non-utf8 command")?;
            // Capabilities ride after NUL on the first command line.
            let line = line.split_once('\0').map_or(line, |(cmd, _caps)| cmd);
            commands.push(parse_command(line)?);
        }
        return Ok(Request { commands, cert: None, pack_start });
    }
    // The certificate's lines run from after `push-cert` to `push-cert-end`.
    let end = lines
        .iter()
        .position(|l| l.as_slice() == b"push-cert-end\n")
        .ok_or("push certificate without push-cert-end")?;
    let cert = signed_push::parse_cert(&lines[1..end].concat())?;
    let commands = cert
        .commands
        .iter()
        .map(|l| parse_command(l))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Request { commands, cert: Some(cert), pack_start })
}

fn parse_command(line: &str) -> Result<Command, String> {
    let mut parts = line.trim_end().splitn(3, ' ');
    let (old, new, refname) = (
        parts.next().ok_or("short command")?,
        parts.next().ok_or("short command")?,
        parts.next().ok_or("short command")?,
    );
    let parse = |hex: &str| -> Result<Option<Oid>, String> {
        if hex == ZERO_OID {
            Ok(None)
        } else {
            store::parse_oid(hex).map(Some)
        }
    };
    // The store keeps refs under refs/ only (`store::set_ref`). Said here,
    // where the request is read and nothing has been charged: `handle`
    // took a command for applicable once `check_command` passed it, which
    // never looked at the name, so a push naming `HEAD` or `main` trapped
    // there, after its owner had paid for it.
    if !refname.starts_with("refs/") {
        return Err(format!("{refname}: a ref is pushed under refs/ (refs/heads/..., refs/tags/...)"));
    }
    Ok(Command {
        old: parse(old)?,
        new: parse(new)?,
        refname: refname.to_string(),
    })
}

/// How many commits one push's fast-forward checks may load between them.
/// A fast-forward is found within the commits the push brought; it is a
/// push that is none, or one of a ref far behind, that walks on, and a
/// push may name any number of refs.
pub const ANCESTRY_WALK: usize = 100_000;

/// What one push's commands share (`check_command`), so that the work of
/// a push is that of what it brings and not of what the repo holds times
/// the refs it names.
///
/// Until 2026-11 each command walked every object the repo's refs reach,
/// trees and blobs with the commits, to know where its own walk could
/// stop, and each walked the new tip's history again to see the old one
/// in it. A push of a thousand refs, which is a few kilobytes and is
/// charged as that, was a thousand walks of the whole repo.
struct Walk<'a> {
    repo: &'a str,
    /// Objects known to be whole: the history the repo's refs reach, read
    /// at the first command that needs it (a push of deletes never
    /// does), and what this push's commands have walked since.
    known: Option<BTreeSet<Oid>>,
    /// What is left of `ANCESTRY_WALK`.
    ancestry: usize,
}

impl<'a> Walk<'a> {
    fn new(repo: &'a str) -> Self {
        Walk { repo, known: None, ancestry: ANCESTRY_WALK }
    }

    /// Is everything `new` reaches in the store?
    fn connected(&mut self, new: &Oid) -> Result<(), String> {
        let repo = self.repo;
        let known = self.known.get_or_insert_with(|| {
            let tips: Vec<Oid> = store::list_refs(repo).into_iter().map(|(_, o)| o).collect();
            pack::history(&tips)
        });
        pack::connected(new, known)
    }

    /// Is `old` an ancestor of `new`? Parents only, nearest first, so the
    /// tip a fast-forward builds on is met within the commits it adds;
    /// non-commit objects end their branch of the walk. `None` when the
    /// push's walks ran out before it was found.
    fn is_ancestor(&mut self, old: &Oid, new: &Oid) -> Option<bool> {
        let mut visited: BTreeSet<Oid> = BTreeSet::new();
        let mut queue: std::collections::VecDeque<Oid> = [*new].into();
        while let Some(oid) = queue.pop_front() {
            if oid == *old {
                return Some(true);
            }
            if !visited.insert(oid) {
                continue;
            }
            if self.ancestry == 0 {
                return None;
            }
            self.ancestry -= 1;
            if let Some((ObjectType::Commit, content)) = store::get_object_parsed(&oid) {
                if let Ok(refs) = object::commit_refs(&content) {
                    queue.extend(refs.parents);
                }
            }
        }
        Some(false)
    }
}

fn check_command(walk: &mut Walk, cmd: &Command) -> Result<(), String> {
    let repo = walk.repo;
    let current = store::get_ref(repo, &cmd.refname);
    if current != cmd.old {
        return Err("ref changed since advertisement".into());
    }
    let Some(new) = cmd.new else {
        // A delete. The deploy branch is not deleted by a push: the
        // fast-forward rule below holds a ref only while it exists, so a
        // delete and a create, in one push or two, put any history on
        // it. On the branch the site and the deploys follow that is the
        // rule undone; on any other it is how a branch is rewritten
        // here, and the old-value match is the whole check.
        if jobs::deploy_branch(repo).as_deref() == Some(cmd.refname.as_str()) {
            return Err("the deploy branch is not deleted by a push: its history only moves forward".into());
        }
        return Ok(());
    };
    // Connectivity: everything reachable from the new tip must exist now;
    // the history the refs reach bounds the walk to what this push
    // introduced.
    walk.connected(&new).map_err(|e| format!("missing objects: {e}"))?;
    // Branch tips must be commits (git refuses e.g. `push <blob>:refs/heads/x`;
    // an advertised head that isn't a commit breaks clone/fetch clients).
    if cmd.refname.starts_with("refs/heads/") {
        let tip = store::get_object_stored(&new).expect("connectivity checked");
        if tip.object_type != ObjectType::Commit {
            return Err(format!(
                "branch tip must be a commit, not a {}",
                tip.object_type.as_str()
            ));
        }
    }
    if let Some(old) = cmd.old {
        match walk.is_ancestor(&old, &new) {
            Some(true) => {}
            Some(false) => return Err("non-fast-forward".into()),
            None => {
                return Err(format!(
                    "not found to be a fast-forward within the {ANCESTRY_WALK} commits a push's checks may walk; push fewer refs at once"
                ))
            }
        }
    }
    Ok(())
}

/// Result of a receive-pack request: the report-status body to return, plus
/// the commit to deploy if the push moved the repo's deploy branch (its HEAD
/// symref target) and a deploy config exists. The caller runs the deploy.
pub struct Outcome {
    pub report: Vec<u8>,
    pub deploy_commit: Option<Oid>,
}

/// A report-status that refuses the whole push, before anything is read:
/// `unpack refused`, then `ng <ref> <reason>` for every command. This is
/// how a refusal reaches the pusher -- git prints each as
/// `! [remote rejected] <ref> (<reason>)` -- whereas the body of a non-200
/// reply is dropped for a bare "HTTP 403". With no command to name (an
/// unparseable request), the reason rides on the unpack line instead, which
/// git prints as `unpack failed: <reason>`. Newlines in `reason` are folded.
pub fn refuse(request: &Result<Request, String>, reason: &str) -> Vec<u8> {
    let reason = reason.replace('\n', " ");
    let commands = request.as_ref().map(|r| r.commands.as_slice()).unwrap_or(&[]);
    if commands.is_empty() {
        let mut report = pkt_line(format!("unpack {reason}\n").as_bytes());
        report.extend_from_slice(FLUSH_PKT);
        return report;
    }
    let mut report = pkt_line(b"unpack refused\n");
    for cmd in commands {
        report.extend_from_slice(&pkt_line(format!("ng {} {reason}\n", cmd.refname).as_bytes()));
    }
    report.extend_from_slice(FLUSH_PKT);
    report
}

/// The request's pack, resolved and measured and not yet stored
/// (pack::prepare), for the caller to charge by before `handle` stores it.
/// `None` for a push of pure deletes, which carries no pack. An unreadable
/// pack is the report-status that says so: `unpack <why>`, and `ng` for
/// every command.
pub fn prepare(request: &Request, body: &[u8]) -> Result<Option<pack::Prepared>, Vec<u8>> {
    let pack_bytes = body.get(request.pack_start..).unwrap_or(&[]);
    if pack_bytes.is_empty() {
        return Ok(None);
    }
    pack::prepare(pack_bytes).map(Some).map_err(|e| {
        let mut report = pkt_line(format!("unpack {}\n", e.replace('\n', " ")).as_bytes());
        for cmd in &request.commands {
            report.extend_from_slice(&pkt_line(format!("ng {} unpacker error\n", cmd.refname).as_bytes()));
        }
        report.extend_from_slice(FLUSH_PKT);
        report
    })
}

/// The bytes a push is charged for and its repo's rent counts: what its
/// pack adds to the store, and never less than the request's own bytes.
pub fn billed_bytes(body: &[u8], prepared: &Option<pack::Prepared>) -> u64 {
    (body.len() as u64).max(prepared.as_ref().map_or(0, pack::Prepared::stored_bytes))
}

/// Handle an authenticated receive-pack request, already parsed by
/// `parse_request`, with its pack already read by `prepare`: store the
/// pack's objects and apply the commands.
pub fn handle(repo: &str, request: Request, prepared: Option<pack::Prepared>) -> Outcome {
    let mut report = Vec::new();
    let mut deploy_commit = None;
    let commands = request.commands;
    if let Some(prepared) = prepared {
        prepared.store();
    }

    // Hoisted out of the command loop: both are loop-invariant stable reads.
    let deploy_branch = jobs::deploy_branch(repo);
    let deploy_configured = jobs::any_config(repo);

    report.extend_from_slice(&pkt_line(b"unpack ok\n"));
    let mut walk = Walk::new(repo);
    for cmd in &commands {
        // A ref the store will not take is that command's refusal, not a
        // trap: by here the push is charged, and a trap would keep the
        // charge and tell the pusher nothing. (The store refuses a name
        // outside refs/, which `parse_command` has refused already, and
        // any write once this side is frozen for its move, which can
        // begin while the charge is awaited.)
        let applied = check_command(&mut walk, cmd).and_then(|()| match cmd.new {
            Some(new) => store::set_ref(repo, &cmd.refname, new).map(|()| Some(new)),
            None => {
                store::delete_ref(repo, &cmd.refname);
                Ok(None)
            }
        });
        match applied {
            Ok(set) => {
                // If this push moved the deploy branch and a deploy is
                // configured, hand the tip back for the caller to build
                // and install (first slice of m4).
                if set.is_some() && deploy_configured && deploy_branch.as_deref() == Some(cmd.refname.as_str()) {
                    deploy_commit = set;
                }
                report.extend_from_slice(&pkt_line(format!("ok {}\n", cmd.refname).as_bytes()));
            }
            Err(e) => {
                report.extend_from_slice(&pkt_line(format!("ng {} {e}\n", cmd.refname).as_bytes()))
            }
        }
    }
    report.extend_from_slice(FLUSH_PKT);
    Outcome { report, deploy_commit }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real signed push, end to end below HTTP: the request git sent is
    /// parsed, its certificate passes the key-bound check for the key it was
    /// signed with, and handling it ingests the pack and moves the ref to
    /// exactly the commit the certificate names.
    #[test]
    fn a_real_signed_push_is_checked_and_applied() {
        const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKX+WM3RHsIaqzeD1rg3zUF4Y9Py92QmWG7n+3f2051F";
        const T: u64 = 1_790_000_000;
        let hex_body: String = include_str!("../testdata/signed-push-request.hex")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect();
        let body = hex::decode(hex_body.trim()).unwrap();
        signed_push::set_seed_once(&[5; 32]);
        store::create_repo("signed").unwrap();

        let request = parse_request(&body).unwrap();
        let cert = request.cert.as_ref().expect("a signed push carries a certificate");
        assert_eq!(request.commands.len(), 1);
        // The bound key passes; another key, another repo, or a late push do not.
        signed_push::check("signed", Some(KEY), Some(cert), true, T + 5).unwrap();
        let other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH";
        let err = signed_push::check("signed", Some(other), Some(cert), true, T + 5).unwrap_err();
        assert!(err.contains("not by the key bound"), "{err}");
        assert!(signed_push::check("unsigned", Some(KEY), Some(cert), true, T + 5).is_err());
        assert!(signed_push::check("signed", Some(KEY), Some(cert), true, T + 601).is_err());

        let prepared = prepare(&request, &body).unwrap();
        assert!(prepared.is_some());
        assert_eq!(billed_bytes(&body, &prepared), body.len() as u64, "a pack of whole objects stores less than it sends");
        let outcome = handle("signed", request, prepared);
        let report = String::from_utf8_lossy(&outcome.report);
        assert!(report.contains("unpack ok") && report.contains("ok refs/heads/main"), "{report}");
        assert_eq!(
            store::get_ref("signed", "refs/heads/main").map(|o| store::oid_hex(&o)).as_deref(),
            Some("cef80612845a57d04f793619713e8b62234a8381")
        );
    }

    #[test]
    fn a_refusal_names_every_ref() {
        let mut body = Vec::new();
        for r in ["refs/heads/main", "refs/tags/v1"] {
            body.extend_from_slice(&pkt_line(format!("{ZERO_OID} cef80612845a57d04f793619713e8b62234a8381 {r}\n").as_bytes()));
        }
        body.extend_from_slice(FLUSH_PKT);
        let report = String::from_utf8(refuse(&parse_request(&body), "sign it\nplease")).unwrap();
        assert!(report.contains("unpack refused\n"));
        assert!(report.contains("ng refs/heads/main sign it please\n"));
        assert!(report.contains("ng refs/tags/v1 sign it please\n"));
        assert!(report.ends_with("0000"));
        // Unparseable: no ref to name, so the reason rides on the unpack line.
        let report = String::from_utf8(refuse(&Err("bad".into()), "x")).unwrap();
        assert_eq!(report, format!("{}0000", String::from_utf8(pkt_line(b"unpack x\n")).unwrap()));
    }

    /// An unsigned request still parses to its plain command list.
    #[test]
    fn an_unsigned_request_has_no_certificate() {
        let mut body = pkt_line(
            format!("{ZERO_OID} cef80612845a57d04f793619713e8b62234a8381 refs/heads/main\0 report-status\n").as_bytes(),
        );
        body.extend_from_slice(FLUSH_PKT);
        let r = parse_request(&body).unwrap();
        assert!(r.cert.is_none());
        assert_eq!(r.commands[0].refname, "refs/heads/main");
        assert_eq!(r.pack_start, body.len());
    }

    /// A command naming a ref outside refs/ is refused where the request
    /// is read, before anything is charged, signed or not; and a ref the
    /// store will not take is that command's `ng`, not a trap.
    #[test]
    fn a_ref_outside_refs_is_refused_before_the_charge() {
        const NEW: &str = "cef80612845a57d04f793619713e8b62234a8381";
        for name in ["HEAD", "main", "heads/main", "refsx/heads/main", " refs/heads/main"] {
            let mut body = pkt_line(format!("{ZERO_OID} {NEW} {name}\0 report-status\n").as_bytes());
            body.extend_from_slice(FLUSH_PKT);
            let request = parse_request(&body);
            let e = request.as_ref().err().unwrap_or_else(|| panic!("{name} parsed"));
            assert!(e.contains("under refs/"), "{e}");
            let report = String::from_utf8(refuse(&request, e)).unwrap();
            assert!(report.contains("unpack") && report.contains("under refs/"), "{report}");
        }
        // One bad name among good ones refuses the push whole.
        let mut body = pkt_line(format!("{ZERO_OID} {NEW} refs/heads/main\0 report-status\n").as_bytes());
        body.extend_from_slice(&pkt_line(format!("{ZERO_OID} {NEW} HEAD\n").as_bytes()));
        body.extend_from_slice(FLUSH_PKT);
        assert!(parse_request(&body).is_err());

        // The backstop: a command the store refuses is reported, and the
        // ones beside it are applied.
        store::create_repo("ref-outside").unwrap();
        let tip = store::commit_file_for_tests("ref-outside", "f", b"1", None);
        let branch = store::head_target("ref-outside").unwrap();
        let commands = vec![
            Command { old: None, new: Some(tip), refname: "HEAD".into() },
            Command { old: None, new: Some(tip), refname: "refs/tags/v1".into() },
        ];
        let out = handle("ref-outside", Request { commands, cert: None, pack_start: 0 }, None);
        let report = String::from_utf8(out.report).unwrap();
        assert!(report.contains("ng HEAD refname must start with refs/"), "{report}");
        assert!(report.contains("ok refs/tags/v1"), "{report}");
        assert_eq!(store::get_ref("ref-outside", "refs/tags/v1"), Some(tip));
        assert_eq!(store::get_ref("ref-outside", &branch), Some(tip), "the branch is where it was");
        assert_eq!(store::get_ref("ref-outside", "HEAD"), None);
    }

    /// The deploy branch moves forward only, by any push: a delete of it
    /// is refused, so a delete and a create, in one push or in two,
    /// cannot put other history on it. Another branch is deleted and
    /// made again freely.
    #[test]
    fn the_deploy_branch_is_not_rewritten_by_a_delete_and_a_create() {
        store::create_repo("ff-rule").unwrap();
        let branch = store::head_target("ff-rule").unwrap();
        let c1 = store::commit_file_for_tests("ff-rule", "f", b"1", None);
        let c2 = store::commit_file_for_tests("ff-rule", "f", b"2", Some(c1));
        // History that does not contain the tip.
        let other = {
            let tree = store::put_object(ObjectType::Tree, b"");
            store::put_object(ObjectType::Commit, format!("tree {}\n\nunrelated\n", store::oid_hex(&tree)).as_bytes())
        };
        let cmd = |old: Option<Oid>, new: Option<Oid>, name: &str| Command { old, new, refname: name.into() };
        let push = |commands: Vec<Command>| {
            String::from_utf8(handle("ff-rule", Request { commands, cert: None, pack_start: 0 }, None).report).unwrap()
        };
        // The rule itself.
        let report = push(vec![cmd(Some(c2), Some(other), &branch)]);
        assert!(report.contains(&format!("ng {branch} non-fast-forward")), "{report}");
        // Around it, in one push: the delete is refused, and so the
        // create, which finds the ref where it was.
        let report = push(vec![cmd(Some(c2), None, &branch), cmd(None, Some(other), &branch)]);
        assert!(report.contains(&format!("ng {branch} the deploy branch is not deleted")), "{report}");
        assert!(report.contains(&format!("ng {branch} ref changed since advertisement")), "{report}");
        assert_eq!(store::get_ref("ff-rule", &branch), Some(c2));
        // And in two.
        let report = push(vec![cmd(Some(c2), None, &branch)]);
        assert!(report.contains("the deploy branch is not deleted"), "{report}");
        assert_eq!(store::get_ref("ff-rule", &branch), Some(c2));
        // Forward still goes.
        let c3 = store::put_object(
            ObjectType::Commit,
            format!("tree {}\nparent {}\n\n3\n", store::oid_hex(&store::put_object(ObjectType::Tree, b"")), store::oid_hex(&c2)).as_bytes(),
        );
        assert!(push(vec![cmd(Some(c2), Some(c3), &branch)]).contains(&format!("ok {branch}")));
        // Another branch is rewritten that way, as before.
        let side = "refs/heads/side";
        assert!(push(vec![cmd(None, Some(c1), side)]).contains("ok refs/heads/side"));
        let report = push(vec![cmd(Some(c1), None, side), cmd(None, Some(other), side)]);
        assert_eq!(report.matches("ok refs/heads/side").count(), 2, "{report}");
        assert_eq!(store::get_ref("ff-rule", side), Some(other));
    }

    /// A push's commands share what they have walked: the history the
    /// refs reach is read once, a command builds on what an earlier one
    /// of the same push brought, and an object that is not there is still
    /// found missing. The fast-forward checks share a number of commits
    /// they may load, and a command past it is refused for that, not let
    /// through.
    #[test]
    fn the_commands_of_a_push_share_one_walk() {
        store::create_repo("one-walk").unwrap();
        let branch = store::head_target("one-walk").unwrap();
        let tree = store::put_object(ObjectType::Tree, b"");
        let commit = |tag: &str, tree: &Oid, parent: Option<&Oid>| {
            let parent = parent.map_or(String::new(), |p| format!("parent {}\n", store::oid_hex(p)));
            store::put_object(ObjectType::Commit, format!("tree {}\n{parent}\none-walk {tag}\n", store::oid_hex(tree)).as_bytes())
        };
        let mut line = vec![commit("0", &tree, None)];
        for i in 1..12 {
            line.push(commit(&i.to_string(), &tree, line.last()));
        }
        store::set_ref("one-walk", &branch, line[5]).unwrap();
        let cmd = |old: Option<Oid>, new: Oid, name: &str| Command { old, new: Some(new), refname: name.into() };

        let mut walk = Walk::new("one-walk");
        assert!(walk.known.is_none(), "nothing is read before a command needs it");
        // A fast-forward, and a second ref on top of what the first brought.
        check_command(&mut walk, &cmd(Some(line[5]), line[8], &branch)).unwrap();
        let known = walk.known.clone().unwrap();
        assert!(line[..=8].iter().all(|c| known.contains(c)) && !known.contains(&line[9]));
        check_command(&mut walk, &cmd(None, line[11], "refs/heads/next")).unwrap();
        assert!(walk.known.as_ref().unwrap().contains(&line[11]));
        // A commit whose tree the store does not hold is missing objects,
        // whatever is known beside it, and adds nothing to what is known.
        let absent = Oid::try_from([7u8; 20].as_slice()).unwrap();
        let broken = commit("broken", &absent, Some(&line[11]));
        let e = check_command(&mut walk, &cmd(None, broken, "refs/heads/broken")).unwrap_err();
        assert!(e.contains("missing objects"), "{e}");
        assert!(!walk.known.as_ref().unwrap().contains(&broken));

        // The fast-forward checks: the tip a push builds on is met first,
        // so it costs the commits the push adds.
        let before = walk.ancestry;
        assert_eq!(walk.is_ancestor(&line[8], &line[11]), Some(true));
        assert_eq!(before - walk.ancestry, 3);
        // One that is none walks to the root, and the next finds nothing
        // left to walk with.
        let other = commit("other", &tree, None);
        walk.ancestry = 12;
        assert_eq!(walk.is_ancestor(&other, &line[11]), Some(false));
        assert_eq!(walk.ancestry, 0);
        let e = check_command(&mut walk, &cmd(Some(line[5]), line[11], &branch)).unwrap_err();
        assert!(e.contains("not found to be a fast-forward within"), "{e}");
        assert_eq!(walk.is_ancestor(&line[11], &line[11]), Some(true), "the tip itself costs nothing");
    }

    #[test]
    fn branch_tip_must_be_commit() {
        store::create_repo("tip-check").unwrap();
        let blob = store::put_object(ObjectType::Blob, b"not a commit");
        let cmd = Command {
            old: None,
            new: Some(blob),
            refname: "refs/heads/main".to_string(),
        };
        let err = check_command(&mut Walk::new("tip-check"), &cmd).unwrap_err();
        assert!(err.contains("must be a commit"), "{err}");

        // Non-branch refs may point at any object type.
        let cmd = Command {
            refname: "refs/tags/raw".to_string(),
            ..cmd
        };
        assert!(check_command(&mut Walk::new("tip-check"), &cmd).is_ok());
    }
}
