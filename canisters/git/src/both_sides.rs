//! Tests that run both sides of the cut together: an authority decision,
//! carried across by the canister's glue, and its effect on the git side.
//! Each side's own behavior is tested in its crate.

use crate::clock::set_test_now;
use crate::tenancy::{self, Role};
use crate::{mirror, tokens};
use candid::Principal;

const T0: u64 = 1_000 * 86_400 * 1_000_000_000;

/// Against the real write rule: removing a writer, demoting one to
/// voter, and transferring the repo each revoke the tokens of whoever
/// lost write access, and only theirs -- as the change is saved, through
/// the push-policy mirror (mirror::set_push_policy), with no sweep.
#[test]
fn losing_write_access_revokes_your_tokens() {
    set_test_now(T0);
    let (owner, w1, w2, next) = (Principal::from_slice(&[9; 8]), Principal::from_slice(&[10; 8]), Principal::from_slice(&[11; 8]), Principal::from_slice(&[12; 8]));
    tenancy::credit(&owner, 10_000_000_000);
    tenancy::create_repo("acl", &owner, false).unwrap();
    tenancy::add_member("acl", &owner, false, w1, Role::Writer).unwrap();
    tenancy::add_member("acl", &owner, false, w2, Role::Writer).unwrap();
    tokens::mint("acl", "tok-owner", owner, None, None).unwrap();
    tokens::mint("acl", "tok-w1", w1, None, None).unwrap();
    tokens::mint("acl", "tok-w2", w2, None, None).unwrap();
    let sweep = || tokens::revoke_unless("acl", |p| mirror::may_write("acl", p, false).is_ok());

    tenancy::remove_member("acl", &owner, false, w1).unwrap();
    assert_eq!(tokens::authorize("tok-w1"), None);
    assert_eq!(tokens::authorize("tok-w2").as_deref(), Some("acl"));

    tenancy::add_member("acl", &owner, false, w2, Role::Voter).unwrap();
    assert_eq!(tokens::authorize("tok-w2"), None);

    assert_eq!(tokens::authorize("tok-owner").as_deref(), Some("acl"));
    tenancy::transfer_repo("acl", &owner, false, next).unwrap();
    assert_eq!(tokens::authorize("tok-owner"), None);
    assert_eq!(sweep(), 0, "nothing was left for a sweep");
}
