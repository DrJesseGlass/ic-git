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

use crate::deploy;
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
    Ok(Command {
        old: parse(old)?,
        new: parse(new)?,
        refname: refname.to_string(),
    })
}

/// Is `old` an ancestor of `new`? Parents-only walk; non-commit objects end
/// their branch of the walk.
fn is_ancestor(old: &Oid, new: &Oid) -> bool {
    let mut visited: BTreeSet<Oid> = BTreeSet::new();
    let mut queue = vec![*new];
    while let Some(oid) = queue.pop() {
        if oid == *old {
            return true;
        }
        if !visited.insert(oid) {
            continue;
        }
        if let Some((ObjectType::Commit, content)) = store::get_object_parsed(&oid) {
            if let Ok(refs) = object::commit_refs(&content) {
                queue.extend(refs.parents);
            }
        }
    }
    false
}

fn check_command(repo: &str, cmd: &Command) -> Result<(), String> {
    let current = store::get_ref(repo, &cmd.refname);
    if current != cmd.old {
        return Err("ref changed since advertisement".into());
    }
    let Some(new) = cmd.new else {
        return Ok(()); // delete: old-value match is the whole check
    };
    // Connectivity: everything reachable from the new tip must exist now;
    // current tips bound the walk to what this push introduced.
    let tips: Vec<Oid> = store::list_refs(repo).into_iter().map(|(_, o)| o).collect();
    pack::closure(&[new], &tips).map_err(|e| format!("missing objects: {e}"))?;
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
        if !is_ancestor(&old, &new) {
            return Err("non-fast-forward".into());
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
/// reply is dropped for a bare "HTTP 403". `reason` must be one line.
pub fn refuse(request: &Result<Request, String>, reason: &str) -> Vec<u8> {
    let reason = reason.replace('\n', " ");
    let mut report = pkt_line(b"unpack refused\n");
    if let Ok(r) = request {
        for cmd in &r.commands {
            report.extend_from_slice(&pkt_line(format!("ng {} {reason}\n", cmd.refname).as_bytes()));
        }
    }
    report.extend_from_slice(FLUSH_PKT);
    report
}

/// Handle an authenticated receive-pack request, already parsed by
/// `parse_request` (an unparseable one is reported as an unpack error).
pub fn handle(repo: &str, request: Result<Request, String>, body: &[u8]) -> Outcome {
    let mut report = Vec::new();
    let mut deploy_commit = None;
    let (commands, pack_start) = match request {
        Ok(r) => (r.commands, r.pack_start),
        Err(e) => {
            report.extend_from_slice(&pkt_line(format!("unpack {e}\n").as_bytes()));
            report.extend_from_slice(FLUSH_PKT);
            return Outcome { report, deploy_commit };
        }
    };

    // A push of pure deletes/no-ops carries no pack.
    let pack_bytes = &body[pack_start..];
    if !pack_bytes.is_empty() {
        if let Err(e) = pack::ingest_pack(pack_bytes) {
            report.extend_from_slice(&pkt_line(format!("unpack {e}\n").as_bytes()));
            for cmd in &commands {
                report.extend_from_slice(&pkt_line(
                    format!("ng {} unpacker error\n", cmd.refname).as_bytes(),
                ));
            }
            report.extend_from_slice(FLUSH_PKT);
            return Outcome { report, deploy_commit };
        }
    }

    // Hoisted out of the command loop: both are loop-invariant stable reads.
    let deploy_branch = deploy::deploy_branch(repo);
    let deploy_configured = deploy::any_config(repo);

    report.extend_from_slice(&pkt_line(b"unpack ok\n"));
    for cmd in &commands {
        match check_command(repo, cmd) {
            Ok(()) => {
                match cmd.new {
                    Some(new) => {
                        store::set_ref(repo, &cmd.refname, new).expect("checked command applies");
                        // If this push moved the deploy branch and a deploy is
                        // configured, hand the tip back for the caller to build
                        // and install (first slice of m4).
                        if deploy_configured
                            && deploy_branch.as_deref() == Some(cmd.refname.as_str())
                        {
                            deploy_commit = Some(new);
                        }
                    }
                    None => store::delete_ref(repo, &cmd.refname),
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

        let outcome = handle("signed", Ok(request), &body);
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
        // Unparseable: the unpack line alone.
        let report = String::from_utf8(refuse(&Err("bad".into()), "x")).unwrap();
        assert_eq!(report, format!("{}0000", String::from_utf8(pkt_line(b"unpack refused\n")).unwrap()));
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

    #[test]
    fn branch_tip_must_be_commit() {
        store::create_repo("tip-check").unwrap();
        let blob = store::put_object(ObjectType::Blob, b"not a commit");
        let cmd = Command {
            old: None,
            new: Some(blob),
            refname: "refs/heads/main".to_string(),
        };
        let err = check_command("tip-check", &cmd).unwrap_err();
        assert!(err.contains("must be a commit"), "{err}");

        // Non-branch refs may point at any object type.
        let cmd = Command {
            refname: "refs/tags/raw".to_string(),
            ..cmd
        };
        assert!(check_command("tip-check", &cmd).is_ok());
    }
}
