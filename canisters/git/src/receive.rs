//! receive-pack: push command parsing, validation, and report-status
//! (milestone 3). Pack decoding lives in pack.rs next to the encoder.
//!
//! Flow: parse "old-oid new-oid refname" commands, ingest the trailing
//! packfile, then per command check old-value match, connectivity (every
//! object reachable from the new tip exists), and fast-forward, applying
//! the ones that pass. The reply is a report-status body; auth happens in
//! lib.rs before this module is reached.

use crate::deploy;
use crate::object;
use crate::pack;
use crate::smart_http::{parse_pkt_lines, pkt_line, FLUSH_PKT, ZERO_OID};
use crate::store::{self, ObjectType, Oid};
use std::collections::BTreeSet;

struct Command {
    old: Option<Oid>,
    new: Option<Oid>,
    refname: String,
}

fn parse_commands(body: &[u8]) -> Result<(Vec<Command>, usize), String> {
    let (lines, consumed) = parse_pkt_lines(body)?;
    let mut commands = Vec::new();
    for line in &lines {
        if line.is_empty() {
            break; // flush ends the command section
        }
        let line = std::str::from_utf8(line).map_err(|_| "non-utf8 command")?;
        // Capabilities ride after NUL on the first command line.
        let line = line
            .split_once('\0')
            .map_or(line, |(cmd, _caps)| cmd)
            .trim_end();
        let mut parts = line.splitn(3, ' ');
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
        commands.push(Command {
            old: parse(old)?,
            new: parse(new)?,
            refname: refname.to_string(),
        });
    }
    Ok((commands, consumed))
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

/// Handle an authenticated receive-pack request.
pub fn handle(repo: &str, body: &[u8]) -> Outcome {
    let mut report = Vec::new();
    let mut deploy_commit = None;
    let (commands, pack_start) = match parse_commands(body) {
        Ok(parsed) => parsed,
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
