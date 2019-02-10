use super::{to_bytes, from_bytes, Blob};
use super::public_key::{PublicKey, RsaPublicKey};
use super::message::{Message, SignRequest, Identity};
use super::signature::Signature;

#[test]
fn blob_serialization() {
    let key = PublicKey::Rsa(RsaPublicKey {
        e: vec![1, 0, 1],
        n: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    let serde_key = PublicKey::from_blob(&key.to_blob().unwrap()).unwrap();
    assert_eq!(key, serde_key);
}

#[test]
fn message_serialization() {
    let key = PublicKey::Rsa(RsaPublicKey {
        e: vec![1, 0, 1],
        n: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    
    let sign_req = Message::SignRequest(
        SignRequest {
            pubkey_blob: key.to_blob().unwrap(),
            data: b"data".to_vec(),
            flags: 24
        }
    );
    let serde_sign_req: Message = from_bytes(&to_bytes(&sign_req).unwrap()).unwrap();
    assert_eq!(sign_req, serde_sign_req);
    
    let sign_resp = Message::SignResponse(
        Signature {
            algorithm: "signature algorithm".to_string(),
            blob: b"signature_blob".to_vec()
        }.to_blob().unwrap()
    );
    let serde_sign_resp: Message = from_bytes(&to_bytes(&sign_resp).unwrap()).unwrap();
    assert_eq!(sign_resp, serde_sign_resp);
    
    let success = Message::Success;
    let serde_success: Message = from_bytes(&to_bytes(&success).unwrap()).unwrap();
    assert_eq!(success, serde_success);
    
    let ident_ans = Message::IdentitiesAnswer(
        vec![
            Identity {
                pubkey_blob: b"key_blob_1".to_vec(),
                comment: "comment_1".to_string()
            },
            Identity {
                pubkey_blob: b"key_blob_2".to_vec(),
                comment: "".to_string()
            }
        ]
    );
    let serde_ident_ans: Message = from_bytes(&to_bytes(&ident_ans).unwrap()).unwrap();
    assert_eq!(ident_ans, serde_ident_ans);
}

#[test]
fn raw_protocol_test() {
    let (
        add_id_dsa_bytes,
        add_id_ecdsa_bytes,
        add_id_ed25519_bytes,
        add_id_rsa_bytes
    ): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>
    ) = from_bytes(include_bytes!("add_id_requests.bin")).unwrap();
    
    let add_id_dsa: Message = from_bytes(&add_id_dsa_bytes).unwrap();
    let add_id_ecdsa: Message = from_bytes(&add_id_ecdsa_bytes).unwrap();
    let add_id_ed25519: Message = from_bytes(&add_id_ed25519_bytes).unwrap();
    let add_id_rsa: Message = from_bytes(&add_id_rsa_bytes).unwrap();
    
    let requests = vec![add_id_dsa, add_id_ecdsa, add_id_ed25519, add_id_rsa];
    
    let mut identities = vec![];
    
    for request in requests {
        match request {
            Message::AddIdentity(identity) => {
                let pubkey = PublicKey::from(identity.privkey);
                identities.push(Identity {
                    pubkey_blob: pubkey.to_blob().unwrap(),
                    comment: identity.comment
                });
                ()
            },
            _ => panic!("Wrong request type: {:?}", request)
        }
    }
    
    let response = Message::IdentitiesAnswer(identities);
    let response_bytes = to_bytes(&to_bytes(&response).unwrap()).unwrap();
    
    assert_eq!(response_bytes.as_slice(), &include_bytes!("id_ans_response.bin")[..]);
}
