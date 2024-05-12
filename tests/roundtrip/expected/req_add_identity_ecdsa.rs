use ssh_agent_lib::proto::{AddIdentity, Credential, Request};
use ssh_key::private::KeypairData;

use super::fixtures;

pub fn expected() -> Request {
    Request::AddIdentity(AddIdentity {
        credential: Credential::Key {
            privkey: KeypairData::Ecdsa(fixtures::demo_key()),
            comment: "baloo@angela".to_string(),
        }
    })
}
