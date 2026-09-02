//! Prints candid encodings the console's JavaScript codec is tested against
//! (browser/index.html, "candid" block; runner: tools/console-codec-test.mjs).
//! Run with `cargo test --test candid_vectors -- --nocapture`.
use candid::{encode_args, encode_one, CandidType, Nat, Principal};
use serde::Deserialize;

#[derive(CandidType, Deserialize)]
struct Account {
    balance: u64,
    deposited: u64,
    spent: u64,
    created_ns: u64,
}

#[derive(CandidType, Deserialize)]
enum Role {
    Writer,
    Voter,
}

#[derive(CandidType, Deserialize)]
struct Member {
    principal: Principal,
    role: Role,
}

#[derive(CandidType)]
struct IcrcAccount {
    owner: Principal,
    subaccount: Option<Vec<u8>>,
}

#[derive(CandidType)]
struct ApproveArgs {
    from_subaccount: Option<Vec<u8>>,
    spender: IcrcAccount,
    amount: Nat,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[test]
fn print_vectors() {
    let p = Principal::from_text("umobs-yiaaa-aaaab-agyrq-cai").unwrap();
    let q = Principal::from_text("3kq6u-eptpm-egjdi-5qvjv-twk23-m4ymt-qqrcs-tdkvy-ob7zx-x6qq3-wqe").unwrap();
    let v: Vec<(&str, Vec<u8>)> = vec![
        ("args:text", encode_args(("ic-git",)).unwrap()),
        ("args:text,principal,text", encode_args(("ic-git", q, "writer")).unwrap()),
        ("args:nat64", encode_args((1_000_000_000_000u64,)).unwrap()),
        ("args:text,text,bool", encode_args(("r", "0123456789abcdef0123456789abcdef01234567", true)).unwrap()),
        ("args:text,nat32", encode_args(("r", 2u32)).unwrap()),
        ("args:approve", encode_args((ApproveArgs {
            from_subaccount: None,
            spender: IcrcAccount { owner: p, subaccount: None },
            amount: Nat::from(5_000_000_000u64),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },)).unwrap()),
        ("reply:result_unit_ok", encode_one(Ok::<(), String>(())).unwrap()),
        ("reply:result_unit_err", encode_one(Err::<(), String>("insufficient balance".into())).unwrap()),
        ("reply:result_text_ok", encode_one(Ok::<String, String>("274f84a4".into())).unwrap()),
        ("reply:result_nat64_ok", encode_one(Ok::<u64, String>(123_456_789_012u64)).unwrap()),
        ("reply:result_vote_ok", encode_one(Ok::<(u32, u32), String>((1, 2))).unwrap()),
        ("reply:result_members_ok", encode_one(Ok::<Vec<Member>, String>(vec![Member { principal: q, role: Role::Voter }])).unwrap()),
        ("reply:result_account_ok", encode_one(Ok::<Account, String>(Account { balance: 7, deposited: 8, spent: 1, created_ns: 1_700_000_000_000_000_000 })).unwrap()),
        ("reply:result_principal_ok", encode_one(Ok::<Principal, String>(p)).unwrap()),
        ("reply:icrc2_approve_ok", encode_one(Ok::<Nat, ()>(Nat::from(42u64))).unwrap()),
    ];
    println!("VECTORS_BEGIN");
    for (name, bytes) in v {
        println!("{name} {}", hex::encode(bytes));
    }
    println!("VECTORS_END");
}
