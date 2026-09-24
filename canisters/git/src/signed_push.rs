//! Key-bound pushes: git push certificates signed with an SSH key.
//!
//! A canister cannot speak SSH (docs/TENANCY.md, "Identity"), but stock git
//! can sign a push over HTTPS. When the receive-pack advertisement carries
//! `push-cert=<nonce>`, a client configured with
//!
//! ```text
//! git config gpg.format ssh
//! git config user.signingkey ~/.ssh/id_ed25519.pub
//! git config push.gpgSign if-asked
//! ```
//!
//! sends, in place of the plain command list, a certificate:
//!
//! ```text
//! certificate version 0.1
//! pusher SHA256:<key fingerprint> <time> <tz>
//! pushee <remote url, credentials stripped>
//! nonce <the advertised nonce>
//!
//! <old> <new> <refname>
//! ...
//! -----BEGIN SSH SIGNATURE-----
//! ...
//! -----END SSH SIGNATURE-----
//! ```
//!
//! The signature (OpenSSH's SSHSIG format, namespace "git") covers every
//! line before `-----BEGIN`, so it binds the exact ref updates -- and, the
//! commits being content-addressed, the pushed history -- and the nonce.
//!
//! A token bound to a key (tokens.rs) authorizes a push only with a
//! certificate that key signed. The nonce is `<unix seconds>-<hmac>`, an
//! HMAC over the repo and the time under a secret seed, the same stateless
//! scheme as git's own receive.certNonceSeed: the advertisement is a query
//! and writes nothing, and a nonce is accepted for `NONCE_SLOP_S` seconds,
//! for the repo it was issued for, so a certificate cannot be replayed later
//! or against another repo. A gateway that rewrote the advertised nonce
//! cannot produce one that verifies.
//!
//! Only ssh-ed25519 keys are accepted.

use crate::store;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use sha2::{Digest, Sha256, Sha512};

/// How long an advertised nonce stays valid, in seconds: an advertisement,
/// the client signing, and the push request all fit in it.
pub const NONCE_SLOP_S: u64 = 600;
const SEED_KEY: &str = "push-cert:seed";
const KEY_TYPE: &str = "ssh-ed25519";
const NAMESPACE: &str = "git";

// --- SSH wire encoding -------------------------------------------------------

/// Reads SSH wire `string`s (uint32 big-endian length, then bytes).
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("truncated SSH encoding".into());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        self.bytes(n)
    }
    fn done(&self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("trailing bytes in SSH encoding".into())
        }
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

// --- public keys -------------------------------------------------------------

/// An ssh-ed25519 public key: its 32 key bytes and its canonical text,
/// `ssh-ed25519 <base64>` with any comment dropped.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    pub key: [u8; 32],
    pub text: String,
}

fn key_from_blob(blob: &[u8]) -> Result<[u8; 32], String> {
    let mut r = Reader(blob);
    let ty = r.string()?;
    if ty != KEY_TYPE.as_bytes() {
        return Err(format!(
            "only {KEY_TYPE} keys are supported, not {}",
            String::from_utf8_lossy(ty)
        ));
    }
    let key = r.string()?;
    r.done()?;
    key.try_into().map_err(|_| "an ssh-ed25519 key is 32 bytes".to_string())
}

fn blob_of(key: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, KEY_TYPE.as_bytes());
    put_string(&mut blob, key);
    blob
}

/// Parse an OpenSSH public key line (the contents of `id_ed25519.pub`).
pub fn parse_public_key(line: &str) -> Result<PublicKey, String> {
    let mut parts = line.split_whitespace();
    let (ty, b64) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if ty != KEY_TYPE {
        return Err(format!(
            "only {KEY_TYPE} keys are supported (the contents of ~/.ssh/id_ed25519.pub)"
        ));
    }
    let blob = STANDARD.decode(b64).map_err(|_| "the key's base64 does not decode".to_string())?;
    let key = key_from_blob(&blob)?;
    Ok(PublicKey {
        key,
        text: format!("{KEY_TYPE} {}", STANDARD.encode(blob_of(&key))),
    })
}

/// `ssh-keygen -l` style fingerprint: `SHA256:<base64, unpadded>`. It is
/// also what git writes on a certificate's `pusher` line.
pub fn fingerprint(key: &PublicKey) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob_of(&key.key))))
}

// --- SSHSIG ------------------------------------------------------------------

/// Verify an armored SSHSIG signature over `message` by `key`, in the "git"
/// namespace (PROTOCOL.sshsig in OpenSSH).
pub fn verify_sshsig(armored: &str, message: &[u8], key: &PublicKey) -> Result<(), String> {
    let body: String = armored
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != "-----BEGIN SSH SIGNATURE-----")
        .skip(1)
        .take_while(|l| *l != "-----END SSH SIGNATURE-----")
        .collect();
    let blob = STANDARD.decode(body).map_err(|_| "the push signature does not decode".to_string())?;
    let mut r = Reader(&blob);
    if r.bytes(6)? != b"SSHSIG" || r.u32()? != 1 {
        return Err("not an SSH signature (SSHSIG version 1)".into());
    }
    let signer = key_from_blob(r.string()?)?;
    let namespace = r.string()?;
    let reserved = r.string()?;
    let hash_alg = r.string()?;
    let sig = r.string()?;
    r.done()?;
    if signer != key.key {
        return Err(format!(
            "the push is signed by {}, not by the key bound to this token ({})",
            fingerprint(&PublicKey { key: signer, text: String::new() }),
            fingerprint(key)
        ));
    }
    if namespace != NAMESPACE.as_bytes() {
        return Err("the push signature is not in the \"git\" namespace".into());
    }
    let digest: Vec<u8> = match hash_alg {
        b"sha512" => Sha512::digest(message).to_vec(),
        b"sha256" => Sha256::digest(message).to_vec(),
        _ => return Err("unsupported SSH signature hash".into()),
    };
    let mut sig_r = Reader(sig);
    if sig_r.string()? != KEY_TYPE.as_bytes() {
        return Err("the push signature is not ssh-ed25519".into());
    }
    let sig_bytes: [u8; 64] = sig_r
        .string()?
        .try_into()
        .map_err(|_| "an ed25519 signature is 64 bytes".to_string())?;
    sig_r.done()?;
    let mut signed = b"SSHSIG".to_vec();
    put_string(&mut signed, namespace);
    put_string(&mut signed, reserved);
    put_string(&mut signed, hash_alg);
    put_string(&mut signed, &digest);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key.key)
        .map_err(|_| "the bound key is not a valid ed25519 point".to_string())?;
    vk.verify_strict(&signed, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
        .map_err(|_| "the push signature does not verify".to_string())
}

// --- the certificate ---------------------------------------------------------

/// A push certificate as receive-pack collected it: the lines between the
/// `push-cert` line and `push-cert-end`, joined.
#[derive(Debug)]
pub struct PushCert {
    /// Everything before the signature: what was signed.
    pub payload: Vec<u8>,
    pub signature: String,
    pub nonce: String,
    /// The `<old> <new> <refname>` lines: the push's commands.
    pub commands: Vec<String>,
}

pub fn parse_cert(text: &[u8]) -> Result<PushCert, String> {
    let text = std::str::from_utf8(text).map_err(|_| "non-utf8 push certificate")?;
    let sig_at = text
        .find("-----BEGIN SSH SIGNATURE-----")
        .ok_or("the push certificate is not SSH-signed (gpg.format=ssh)")?;
    let (payload, signature) = text.split_at(sig_at);
    let (header, commands) = payload
        .split_once("\n\n")
        .ok_or("push certificate without a command section")?;
    let mut lines = header.lines();
    if lines.next() != Some("certificate version 0.1") {
        return Err("unsupported push certificate version".into());
    }
    let nonce = lines
        .find_map(|l| l.strip_prefix("nonce "))
        .ok_or("push certificate without a nonce")?
        .to_string();
    Ok(PushCert {
        payload: payload.as_bytes().to_vec(),
        signature: signature.to_string(),
        nonce,
        commands: commands.lines().map(str::to_string).collect(),
    })
}

// --- nonces ------------------------------------------------------------------

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |b: u8| k.iter().map(|x| x ^ b).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(msg).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

fn seed() -> Option<Vec<u8>> {
    store::meta_get_json::<String>(SEED_KEY).and_then(|h| hex::decode(h).ok())
}

pub fn has_seed() -> bool {
    seed().is_some()
}

/// Store the nonce seed, once. `bytes` come from raw_rand.
pub fn set_seed_once(bytes: &[u8]) {
    if !has_seed() && bytes.len() >= 32 {
        store::meta_set_json(SEED_KEY, &hex::encode(&bytes[..32]));
    }
}

fn mac(seed: &[u8], repo: &str, t: u64) -> String {
    hex::encode(&hmac_sha256(seed, format!("{repo}\0{t}").as_bytes())[..16])
}

/// The nonce to advertise for `repo` at `now_s`; `None` until the seed
/// exists, and then the advertisement offers no push-cert.
pub fn nonce(repo: &str, now_s: u64) -> Option<String> {
    Some(format!("{now_s}-{}", mac(&seed()?, repo, now_s)))
}

/// Was `nonce` issued by this canister for `repo`, within `NONCE_SLOP_S`?
pub fn check_nonce(repo: &str, nonce: &str, now_s: u64) -> Result<(), String> {
    let seed = seed().ok_or("push certificates are not enabled yet")?;
    let (t, m) = nonce.split_once('-').ok_or("malformed push nonce")?;
    let t: u64 = t.parse().map_err(|_| "malformed push nonce")?;
    if m != mac(&seed, repo, t) {
        return Err("the push nonce was not issued for this repo".into());
    }
    if t > now_s || now_s - t > NONCE_SLOP_S {
        return Err("the push nonce has expired; push again".into());
    }
    Ok(())
}

// --- the decision ------------------------------------------------------------

/// How to sign, for the refusals that ask for it.
pub const HOW_TO_SIGN: &str = "sign pushes with that key: git config gpg.format ssh; \
     git config user.signingkey <its .pub file>; git config push.gpgSign if-asked";

/// May a push proceed, given the key its token is bound to, the
/// certificate it carried, and whether the repo requires key-bound tokens?
///
/// - Unbound token: refused if the repo requires signed pushes, otherwise
///   allowed; a certificate it happens to carry is not checked.
/// - Bound token: needs a certificate with a nonce this canister issued for
///   this repo within `NONCE_SLOP_S`, signed by exactly that key. The
///   commands the push runs are the ones in the certificate (receive.rs), so
///   what was signed is what happens.
pub fn check(repo: &str, key: Option<&str>, cert: Option<&PushCert>, required: bool, now_s: u64) -> Result<(), String> {
    let Some(key) = key else {
        return if required {
            Err(format!(
                "{repo} requires signed pushes: mint a push token bound to your SSH public key, and {HOW_TO_SIGN}"
            ))
        } else {
            Ok(())
        };
    };
    let key = parse_public_key(key)?;
    let cert = cert.ok_or_else(|| {
        format!("this push token is bound to the SSH key {}: {HOW_TO_SIGN}", fingerprint(&key))
    })?;
    check_nonce(repo, &cert.nonce, now_s)?;
    verify_sshsig(&cert.signature, &cert.payload, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway key and a certificate real git 2.50.1 signed with it:
    // `git push --signed` against a server advertising push-cert=NONCE.
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKX+WM3RHsIaqzeD1rg3zUF4Y9Py92QmWG7n+3f2051F fixture@ic-git";
    const NONCE: &str = "1790000000-0123456789abcdef0123456789abcdef";
    const CERT: &str = "certificate version 0.1\n\
pusher SHA256:AJwEzIG2jf+W4YxJdLVmVNYmuyYEjyZpuDAtIkdMTw8  1790284627 -0400\n\
pushee http://127.0.0.1:18733/r.git/\n\
nonce 1790000000-0123456789abcdef0123456789abcdef\n\
\n\
0000000000000000000000000000000000000000 cef80612845a57d04f793619713e8b62234a8381 refs/heads/main\n\
-----BEGIN SSH SIGNATURE-----\n\
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgpf5YzdEewhqrN4PWuDfNQXhj0/\n\
L3ZCZYbuf7d/bTnUUAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5\n\
AAAAQF1lqTf6dv9XwNAg+gFDGBL8NyUgg/Q6yjhy4nW4+v8Cdl6M5NsRCf3gqSqvTggiEO\n\
8d+TB0fNBGCY9yIqhoQQA=\n\
-----END SSH SIGNATURE-----\n";

    #[test]
    fn a_real_git_push_certificate_verifies() {
        let key = parse_public_key(KEY).unwrap();
        assert_eq!(fingerprint(&key), "SHA256:AJwEzIG2jf+W4YxJdLVmVNYmuyYEjyZpuDAtIkdMTw8");
        let cert = parse_cert(CERT.as_bytes()).unwrap();
        assert_eq!(cert.nonce, NONCE);
        assert_eq!(
            cert.commands,
            vec!["0000000000000000000000000000000000000000 cef80612845a57d04f793619713e8b62234a8381 refs/heads/main"]
        );
        verify_sshsig(&cert.signature, &cert.payload, &key).unwrap();
    }

    #[test]
    fn any_change_to_the_certificate_breaks_the_signature() {
        let key = parse_public_key(KEY).unwrap();
        // A different target commit, and a different nonce.
        for (from, to) in [("cef80612", "cef80613"), ("nonce 1790000000", "nonce 1790000001")] {
            let cert = parse_cert(CERT.replacen(from, to, 1).as_bytes()).unwrap();
            assert!(verify_sshsig(&cert.signature, &cert.payload, &key).is_err(), "{to}");
        }
    }

    #[test]
    fn another_key_is_named_in_the_refusal() {
        let other = PublicKey { key: [7; 32], text: String::new() };
        let cert = parse_cert(CERT.as_bytes()).unwrap();
        let err = verify_sshsig(&cert.signature, &cert.payload, &other).unwrap_err();
        assert!(err.contains("SHA256:AJwEzIG2"), "{err}");
    }

    #[test]
    fn public_keys_parse_to_canonical_text() {
        let k = parse_public_key(KEY).unwrap();
        assert_eq!(k.text, KEY.rsplit_once(' ').unwrap().0);
        assert_eq!(parse_public_key(&k.text).unwrap(), k);
        assert!(parse_public_key("ssh-rsa AAAAB3NzaC1yc2E x").unwrap_err().contains("ssh-ed25519"));
        assert!(parse_public_key("ssh-ed25519 !!!").is_err());
        // An ecdsa blob under an ed25519 label is refused.
        let mut blob = Vec::new();
        put_string(&mut blob, b"ecdsa-sha2-nistp256");
        put_string(&mut blob, &[1; 32]);
        assert!(parse_public_key(&format!("ssh-ed25519 {}", STANDARD.encode(blob))).is_err());
    }

    #[test]
    fn a_certificate_needs_an_ssh_signature_and_a_nonce() {
        assert!(parse_cert(b"certificate version 0.1\nnonce x\n\ncmd\n-----BEGIN PGP SIGNATURE-----\n").is_err());
        assert!(parse_cert(b"certificate version 0.1\n\ncmd\n-----BEGIN SSH SIGNATURE-----\n").is_err());
        assert!(parse_cert(b"certificate version 0.2\nnonce x\n\ncmd\n-----BEGIN SSH SIGNATURE-----\n").is_err());
    }

    /// The fixture certificate with a nonce this canister would issue now.
    /// Its signature is then stale (the nonce is signed), which is what the
    /// policy tests below need: they check what is refused before and after
    /// the signature is reached.
    fn cert_with_nonce(n: &str) -> PushCert {
        parse_cert(CERT.replace(NONCE, n).as_bytes()).unwrap()
    }

    #[test]
    fn the_policy_for_bound_unbound_and_required() {
        set_seed_once(&[5; 32]);
        let now = 2_000;
        let n = nonce("r", now).unwrap();
        let fresh = cert_with_nonce(&n);
        // Unbound, not required: allowed with or without a certificate.
        assert!(check("r", None, None, false, now).is_ok());
        assert!(check("r", None, Some(&fresh), false, now).is_ok());
        // Unbound, required: refused, saying how to fix it.
        let err = check("r", None, None, true, now).unwrap_err();
        assert!(err.contains("requires signed pushes") && err.contains("gpg.format ssh"), "{err}");
        // Bound: no certificate is refused, naming the key.
        let err = check("r", Some(KEY), None, false, now).unwrap_err();
        assert!(err.contains("SHA256:AJwEzIG2"), "{err}");
        // Bound: a nonce from elsewhere or too old is refused before the
        // signature is looked at.
        assert!(check("r", Some(KEY), Some(&cert_with_nonce(&nonce("s", now).unwrap())), false, now)
            .unwrap_err()
            .contains("this repo"));
        assert!(check("r", Some(KEY), Some(&fresh), false, now + NONCE_SLOP_S + 1)
            .unwrap_err()
            .contains("expired"));
        // Bound, fresh nonce, but the signature covered the old nonce.
        assert!(check("r", Some(KEY), Some(&fresh), true, now)
            .unwrap_err()
            .contains("does not verify"));
    }

    /// RFC 4231, test case 2.
    #[test]
    fn hmac_matches_rfc_4231() {
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn nonces_are_bound_to_repo_and_time() {
        assert!(nonce("r", 100).is_none());
        assert!(check_nonce("r", "100-x", 100).is_err());
        set_seed_once(&[3; 32]);
        set_seed_once(&[4; 32]); // once: the first seed stays
        let n = nonce("r", 1_000).unwrap();
        assert!(check_nonce("r", &n, 1_000).is_ok());
        assert!(check_nonce("r", &n, 1_000 + NONCE_SLOP_S).is_ok());
        assert!(check_nonce("r", &n, 1_001 + NONCE_SLOP_S).unwrap_err().contains("expired"));
        assert!(check_nonce("r", &n, 999).is_err(), "issued in the future");
        assert!(check_nonce("other", &n, 1_000).unwrap_err().contains("this repo"));
        assert!(check_nonce("r", &n.replace("1000-", "1001-"), 1_001).is_err());
        assert!(check_nonce("r", "garbage", 1_000).is_err());
    }
}
