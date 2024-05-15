use ssh_agent_lib::proto::{AddIdentity, AddIdentityConstrained, Credential, KeyConstraint, Request};
use ssh_key::private::KeypairData;

use super::fixtures;

pub fn expected() -> Request {
    Request::AddIdConstrained(AddIdentityConstrained {
        identity: AddIdentity {
            credential: Credential::Key {
                privkey: KeypairData::Ecdsa(fixtures::demo_key()),
                comment: "baloo@angela".to_string(),
            },
        },
        constraints: vec![KeyConstraint::Lifetime(2)],
    })
}
