use super::{to_bytes, from_bytes, Blob};
use super::public_key::*;
use super::private_key::*;
use super::message::{Message, SignRequest, Identity, Extension};
use super::signature::Signature;

#[test]
fn pubkey_blob_serialization() {
    let rsa_key = PublicKey::Rsa(RsaPublicKey {
        e: vec![1, 0, 1],
        n: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    let serde_rsa_key = PublicKey::from_blob(&rsa_key.to_blob().unwrap()).unwrap();
    assert_eq!(rsa_key, serde_rsa_key);
    
    let dss_key = PublicKey::Dss(DssPublicKey {
        p: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        q: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        g: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        y: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    let serde_dss_key = PublicKey::from_blob(&dss_key.to_blob().unwrap()).unwrap();
    assert_eq!(dss_key, serde_dss_key);
    
    let ed25519_key = PublicKey::Ed25519(Ed25519PublicKey {
        enc_a: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    let serde_ed25519_key = PublicKey::from_blob(&ed25519_key.to_blob().unwrap()).unwrap();
    assert_eq!(ed25519_key, serde_ed25519_key);
    
    let ecdsa_key = PublicKey::EcDsa(EcDsaPublicKey {
        identifier: "some_identifier".to_string(),
        q: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    let serde_ecdsa_key = PublicKey::from_blob(&ecdsa_key.to_blob().unwrap()).unwrap();
    assert_eq!(ecdsa_key, serde_ecdsa_key);
}

#[test]
fn privkey_blob_serialization() {
    let rsa_key = PrivateKey::Rsa(RsaPrivateKey {
        e: vec![1, 0, 1],
        n: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        d: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        iqmp: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        p: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        q: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    let serde_rsa_key = PrivateKey::from_blob(&rsa_key.to_blob().unwrap()).unwrap();
    assert_eq!(rsa_key, serde_rsa_key);
    
    let dss_key = PrivateKey::Dss(DssPrivateKey {
        p: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        q: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        g: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        y: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        x: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    let serde_dss_key = PrivateKey::from_blob(&dss_key.to_blob().unwrap()).unwrap();
    assert_eq!(dss_key, serde_dss_key);
    
    let ed25519_key = PrivateKey::Ed25519(Ed25519PrivateKey {
        enc_a: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        k_enc_a: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    let serde_ed25519_key = PrivateKey::from_blob(&ed25519_key.to_blob().unwrap()).unwrap();
    assert_eq!(ed25519_key, serde_ed25519_key);
    
    let ecdsa_key = PrivateKey::EcDsa(EcDsaPrivateKey {
        identifier: "some_identifier".to_string(),
        q: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        d: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    });
    let serde_ecdsa_key = PrivateKey::from_blob(&ecdsa_key.to_blob().unwrap()).unwrap();
    assert_eq!(ecdsa_key, serde_ecdsa_key);
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

#[test]
fn test_extension() {
    let extension_bytes: &[u8] = &[0, 0, 0, 24, 115, 101, 115, 115, 105, 111, 110, 45, 98, 105, 110, 100, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0, 51, 0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 177, 185, 198, 92, 165, 45, 127, 95, 202, 195, 226, 63, 6, 115, 10, 104, 18, 137, 172, 240, 153, 154, 174, 74, 83, 7, 1, 204, 14, 177, 153, 40, 0, 0, 0, 32, 175, 96, 42, 133, 218, 171, 58, 220, 97, 78, 155, 114, 20, 67, 90, 133, 24, 185, 156, 71, 128, 163, 234, 195, 202, 15, 160, 177, 130, 229, 114, 164, 0, 0, 0, 83, 0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 64, 4, 235, 93, 135, 144, 110, 220, 24, 17, 150, 40, 11, 143, 37, 207, 58, 215, 159, 23, 233, 95, 218, 115, 22, 205, 101, 55, 159, 146, 42, 121, 190, 229, 82, 75, 174, 143, 199, 121, 141, 52, 155, 73, 215, 119, 220, 104, 241, 116, 83, 96, 129, 184, 12, 93, 93, 33, 243, 171, 236, 201, 123, 17, 1, 0];
    let extension: Extension = from_bytes(&extension_bytes).unwrap();
    assert_eq!(extension.extension_type, "session-bind@openssh.com");
}
