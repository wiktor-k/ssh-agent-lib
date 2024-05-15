use ssh_agent_lib::proto::{Identity, Response};
use ssh_key::public::KeyData;

use super::fixtures;

pub fn expected() -> Response {
    Response::IdentitiesAnswer(vec![Identity {
        pubkey: KeyData::Ecdsa(fixtures::demo_key().into()),
        comment: "baloo@angela".to_string(),
    }])
}
