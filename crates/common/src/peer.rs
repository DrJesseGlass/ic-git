//! The other canister's principal (docs/CANISTER_SPLIT.md, phase 3 step
//! 12b): where each side keeps it, and the one rule for who may call the
//! endpoints that take the other side's messages. The authority is told
//! the git canister's id by an operator, the git canister the authority's
//! at init; until then nothing may call, and after that only it.

use candid::Principal;

/// One side's record of the other canister.
pub struct Peer {
    /// The META key its principal is kept under, as text.
    pub key: &'static str,
    /// What to call it in a refusal.
    pub name: &'static str,
}

impl Peer {
    pub fn get(&self) -> Option<Principal> {
        crate::kv::get_json::<String>(self.key).and_then(|t| Principal::from_text(t).ok())
    }

    pub fn set(&self, id: Principal) {
        crate::kv::set_json(self.key, &id.to_text());
    }

    /// Is `caller` the other canister? Before it is named, nothing is.
    pub fn check_caller(&self, caller: &Principal) -> Result<(), String> {
        match self.get() {
            Some(peer) if peer == *caller => Ok(()),
            Some(_) => Err(format!("only the {} may call this", self.name)),
            None => Err(format!("no {} is set; only it may call this", self.name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_named_peer_may_call() {
        const PEER: Peer = Peer {
            key: "peer:test",
            name: "other canister",
        };
        let peer = Principal::from_slice(&[1; 8]);
        let other = Principal::from_slice(&[2; 8]);
        assert_eq!(PEER.get(), None);
        assert_eq!(PEER.check_caller(&peer), Err("no other canister is set; only it may call this".into()));
        PEER.set(peer);
        assert_eq!(PEER.get(), Some(peer));
        assert_eq!(PEER.check_caller(&peer), Ok(()));
        assert_eq!(PEER.check_caller(&other), Err("only the other canister may call this".into()));
        assert!(PEER.check_caller(&Principal::anonymous()).is_err());
    }
}
