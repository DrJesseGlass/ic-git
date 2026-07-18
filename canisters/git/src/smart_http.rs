//! Git smart-HTTP protocol pieces: pkt-line codec and ref advertisement.
//!
//! Reference: git's Documentation/gitprotocol-http.txt and gitprotocol-pack.txt.

use crate::store;

/// Encode one pkt-line: 4 hex length bytes (incl. the 4) + payload.
pub fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// The `0000` flush packet.
pub fn flush_pkt() -> &'static [u8] {
    b"0000"
}

/// Parse pkt-lines from a buffer. Flush packets appear as empty slices.
/// Returns (lines, bytes_consumed); stops cleanly at a truncated tail so the
/// receive-pack parser can hand the remainder to the packfile reader.
pub fn parse_pkt_lines(buf: &[u8]) -> Result<(Vec<Vec<u8>>, usize), String> {
    let mut lines = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        let len_hex = std::str::from_utf8(&buf[pos..pos + 4]).map_err(|_| "bad pkt len")?;
        let len = usize::from_str_radix(len_hex, 16).map_err(|_| "bad pkt len")?;
        if len == 0 {
            // flush-pkt: record and include the standard post-flush stop here;
            // callers decide whether more sections follow.
            lines.push(Vec::new());
            pos += 4;
            return Ok((lines, pos));
        }
        if len < 4 || pos + len > buf.len() {
            return Err("truncated pkt-line".into());
        }
        lines.push(buf[pos + 4..pos + len].to_vec());
        pos += len;
    }
    Ok((lines, pos))
}

const UPLOAD_PACK_CAPS: &str = "multi_ack_detailed no-done side-band-64k ofs-delta agent=ic-git/0.1";
const RECEIVE_PACK_CAPS: &str = "report-status delete-refs ofs-delta agent=ic-git/0.1";

/// Body of `GET /<repo>.git/info/refs?service=<service>`.
///
/// Smart-HTTP advertisement: a `# service=` header pkt, a flush, then refs
/// sorted by name with capabilities appended to the first line. An empty repo
/// advertises the zero-id `capabilities^{}` line so clients still learn caps.
pub fn advertisement(repo: &str, service: &str) -> Vec<u8> {
    let caps = match service {
        "git-upload-pack" => UPLOAD_PACK_CAPS,
        _ => RECEIVE_PACK_CAPS,
    };

    let mut body = pkt_line(format!("# service={service}\n").as_bytes());
    body.extend_from_slice(flush_pkt());

    let refs: Vec<(String, String)> = store::list_refs(repo)
        .into_iter()
        .map(|(name, oid)| (name, hex::encode(oid.as_slice())))
        .collect();

    // HEAD first (points at the symref target's oid), then refs sorted by name.
    let head = store::head_target(repo).and_then(|target| {
        refs.iter()
            .find(|(name, _)| *name == target)
            .map(|(_, oid)| (format!("HEAD\0{caps} symref=HEAD:{target}"), oid.clone()))
    });

    let mut lines: Vec<(String, String)> = Vec::new();
    match head {
        Some((head_line, oid)) => {
            lines.push((head_line, oid));
            lines.extend(refs.into_iter().map(|(n, o)| (n, o)));
        }
        None => {
            if let Some((first, rest)) = refs.split_first() {
                lines.push((format!("{}\0{caps}", first.0), first.1.clone()));
                lines.extend(rest.iter().cloned());
            } else {
                lines.push((
                    format!("capabilities^{{}}\0{caps}"),
                    "0".repeat(40),
                ));
            }
        }
    }

    for (name, oid) in lines {
        body.extend_from_slice(&pkt_line(format!("{oid} {name}\n").as_bytes()));
    }
    body.extend_from_slice(flush_pkt());
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkt_line_roundtrip() {
        let encoded = [pkt_line(b"hello\n"), flush_pkt().to_vec()].concat();
        let (lines, consumed) = parse_pkt_lines(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(lines, vec![b"hello\n".to_vec(), Vec::new()]);
    }

    #[test]
    fn pkt_line_length_prefix() {
        assert_eq!(pkt_line(b"a"), b"0005a".to_vec());
    }
}
