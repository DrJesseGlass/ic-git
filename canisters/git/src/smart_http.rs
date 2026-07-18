//! Git smart-HTTP protocol pieces: pkt-line codec, service definitions, and
//! ref advertisement.
//!
//! Reference: git's Documentation/gitprotocol-http.txt and gitprotocol-pack.txt.

use crate::store;

/// The two smart-HTTP services. Parsed once at the routing boundary; the
/// service name, capabilities, and content-types all derive from this.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "git-upload-pack" => Some(Service::UploadPack),
            "git-receive-pack" => Some(Service::ReceivePack),
            _ => None,
        }
    }

    fn caps(self) -> &'static str {
        match self {
            Service::UploadPack => {
                "multi_ack_detailed no-done side-band-64k ofs-delta agent=ic-git/0.1"
            }
            Service::ReceivePack => "report-status delete-refs ofs-delta agent=ic-git/0.1",
        }
    }
}

/// The `0000` flush packet.
pub const FLUSH_PKT: &[u8] = b"0000";

/// Encode one pkt-line: 4 hex length bytes (incl. the 4) + payload.
pub fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
    out.extend_from_slice(payload);
    out
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

/// Body of `GET /<repo>.git/info/refs?service=<service>`.
///
/// Smart-HTTP advertisement: a `# service=` header pkt, a flush, then refs
/// sorted by name with capabilities appended to the first line. HEAD
/// (resolved through `head_target`) leads when its target exists; an empty
/// repo advertises the zero-id `capabilities^{}` line so clients still learn
/// caps.
pub fn advertisement(repo: &str, service: Service, head_target: &str) -> Vec<u8> {
    let mut caps = service.caps().to_string();
    let mut entries = store::list_refs(repo);
    if let Some(oid) = entries
        .iter()
        .find(|(name, _)| name == head_target)
        .map(|(_, oid)| *oid)
    {
        caps.push_str(&format!(" symref=HEAD:{head_target}"));
        entries.insert(0, ("HEAD".to_string(), oid));
    }

    let mut body = pkt_line(format!("# service={}\n", service.name()).as_bytes());
    body.extend_from_slice(FLUSH_PKT);
    if entries.is_empty() {
        body.extend_from_slice(&pkt_line(
            format!("{} capabilities^{{}}\0{caps}\n", "0".repeat(40)).as_bytes(),
        ));
    } else {
        for (i, (name, oid)) in entries.iter().enumerate() {
            let oid = hex::encode(oid.as_slice());
            let line = if i == 0 {
                format!("{oid} {name}\0{caps}\n")
            } else {
                format!("{oid} {name}\n")
            };
            body.extend_from_slice(&pkt_line(line.as_bytes()));
        }
    }
    body.extend_from_slice(FLUSH_PKT);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkt_line_roundtrip() {
        let encoded = [pkt_line(b"hello\n"), FLUSH_PKT.to_vec()].concat();
        let (lines, consumed) = parse_pkt_lines(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(lines, vec![b"hello\n".to_vec(), Vec::new()]);
    }

    #[test]
    fn pkt_line_length_prefix() {
        assert_eq!(pkt_line(b"a"), b"0005a".to_vec());
    }
}
