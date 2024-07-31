use hex_literal::hex;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, Extension, KeyConstraint, PrivateCredential, Request,
    Unparsed,
};
use ssh_key::private::KeypairData;

use super::fixtures;

pub fn expected() -> Request {
    Request::AddIdConstrained(AddIdentityConstrained {
        identity: AddIdentity {
            credential: PrivateCredential::Key {
                privkey: KeypairData::Ecdsa(fixtures::demo_key()),
                comment: "baloo@angela".to_string(),
            },
        },
        constraints: vec![KeyConstraint::Extension(Extension {
            name: "restrict-destination-v00@openssh.com".to_string(),
            details: Unparsed::from(
                hex!(
                    "                                    00
                    0002 6f00 0000 0c00 0000 0000 0000 0000
                    0000 0000 0002 5700 0000 0000 0000 0a67
                    6974 6875 622e 636f 6d00 0000 0000 0000
                    3300 0000 0b73 7368 2d65 6432 3535 3139
                    0000 0020 e32a aa79 15ce b9b4 49d1 ba50
                    ea2a 28bb 1a6e 01f9 0bda 245a 2d1d 8769
                    7d18 a265 0000 0001 9700 0000 0773 7368
                    2d72 7361 0000 0003 0100 0100 0001 8100
                    a3ee 774d c50a 3081 c427 8ec8 5c2e ba8f
                    1228 a986 7b7e 5534 ef0c fea6 1c12 fd8f
                    568d 5246 3851 ed60 bf09 c62d 594e 8467
                    98ae 765a 3204 4aeb e3ca 0945 da0d b0bb
                    aad6 d6f2 0224 84be da18 2b0e aff0 b9e9
                    224c cbf0 4265 fc5d d675 b300 ec52 0cf8
                    15b2 67ab 3816 1f36 a96d 57df e158 2a81
                    cb02 0d21 1fb9 7488 3a25 327b da97 04a4
                    48dc 6205 e413 6604 1575 7524 79ec 2a06
                    cb58 d961 49ca 9bd9 49b2 4644 32ca d44b
                    b4bf b7f1 31b1 9310 9f96 63be e59f 0249
                    2358 ec68 9d8c c219 ed0e 3332 3036 9f59
                    c6ae 54c3 933c 030a cc3e c2a1 4f19 0035
                    efd7 277c 658e 5915 6bba 3d7a cfa5 f2bf
                    1be3 2706 f3d3 0419 ef95 cae6 d292 6fb1
                    4dc9 e204 b384 d3e2 393e 4b87 613d e014
                    0b9c be6c 3622 ad88 0ce0 60bb b849 f3b6
                    7672 6955 90ec 1dfc d402 b841 daf0 b79d
                    59a8 4c4a 6d0a 5350 d9fe 123a a84f 0bea
                    363e 24ab 1e50 5022 344e 14bf 6243 b124
                    25e6 3d45 996e 18e9 0a0e 7a8b ed9a 07a0
                    a62b 6246 867e 7b2b 99a3 d0c3 5d05 7038
                    fd69 f01f a5e8 3d62 732b 9372 bb6c c1de
                    7019 a7e4 b986 942c fa9d 6f37 5ff0 b239
                    0000 0000 6800 0000 1365 6364 7361 2d73
                    6861 322d 6e69 7374 7032 3536 0000 0008
                    6e69 7374 7032 3536 0000 0041 0449 8a48
                    4363 4047 b33a 6c64 64cc bba2 92a0 c050
                    7d9e 4b79 611a d832 336e 1b93 7cee e460
                    83a0 8bad ba39 c007 53ff 2eaf d262 95d1
                    4db0 d166 7660 1ffe f93a 6872 4800 0000
                    0000"
                )
                .to_vec(),
            ),
        })],
    })
}
