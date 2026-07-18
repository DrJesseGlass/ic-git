//! receive-pack: push command parsing, validation, and report-status
//! (milestone 3). Pack decoding lives in pack.rs next to the encoder.
//!
//! Flow: parse "old-oid new-oid refname" commands, ingest the trailing
//! packfile, then per command check old-value match, connectivity (every
//! object reachable from the new tip exists), and fast-forward, applying
//! the ones that pass. The reply is a report-status body; auth happens in
//! lib.rs before this module is reached.

use crate::object;
use crate::pack;
use crate::smart_http::{parse_pkt_lines, pkt_line, FLUSH_PKT};
use crate::store::{self, ObjectType, Oid};
use std::collections::BTreeSet;

const ZERO_OID: &str = "0000000000000000000000000000000000000000";

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
        let line = line.split('\0').next().unwrap_or(line).trim_end();
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
    if let Some(old) = cmd.old {
        if !is_ancestor(&old, &new) {
            return Err("non-fast-forward".into());
        }
    }
    Ok(())
}

/// Handle an authenticated receive-pack request; returns the report-status
/// body.
pub fn handle(repo: &str, body: &[u8]) -> Vec<u8> {
    let mut report = Vec::new();
    let (commands, pack_start) = match parse_commands(body) {
        Ok(parsed) => parsed,
        Err(e) => {
            report.extend_from_slice(&pkt_line(format!("unpack {e}\n").as_bytes()));
            report.extend_from_slice(FLUSH_PKT);
            return report;
        }
    };

    // A push of pure deletes/no-ops carries no pack.
    let pack_bytes = &body[pack_start..];
    let unpack = if pack_bytes.is_empty() {
        Ok(())
    } else {
        pack::ingest_pack(pack_bytes).map(|_| ())
    };

    match &unpack {
        Ok(()) => report.extend_from_slice(&pkt_line(b"unpack ok\n")),
        Err(e) => report.extend_from_slice(&pkt_line(format!("unpack {e}\n").as_bytes())),
    }

    for cmd in &commands {
        let result = match &unpack {
            Err(_) => Err("unpacker error".to_string()),
            Ok(()) => check_command(repo, cmd).map(|()| match cmd.new {
                Some(new) => {
                    store::set_ref(repo, &cmd.refname, new).expect("checked command applies");
                }
                None => store::delete_ref(repo, &cmd.refname),
            }),
        };
        match result {
            Ok(()) => {
                // TODO(m4): if cmd.refname is the deploy branch, enqueue a
                // DeployJob here and arm the zero-delay timer.
                report.extend_from_slice(&pkt_line(format!("ok {}\n", cmd.refname).as_bytes()));
            }
            Err(e) => report
                .extend_from_slice(&pkt_line(format!("ng {} {e}\n", cmd.refname).as_bytes())),
        }
    }
    report.extend_from_slice(FLUSH_PKT);
    report
}
