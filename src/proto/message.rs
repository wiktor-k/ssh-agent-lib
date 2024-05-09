//! Agent protocol message structures.

mod add_remove;
mod extension;
mod identity;
mod request;
mod response;
mod sign;
mod unparsed;

pub use self::{
    add_remove::*, extension::*, identity::*, request::*, response::*, sign::*, unparsed::*,
};
#[doc(hidden)]
/// For compatibility with pre-0.5.0 type alias in this module
/// that duplicated crate::proto::error::ProtoResult
pub use super::Result;

#[cfg(test)]
mod tests {
    // Note: yes, some of those tests carry a private key, this is a key that
    //       was generated for the purpose of those tests

    use hex_literal::hex;
    use p256::{
        elliptic_curve::{bigint::Uint, ScalarPrimitive},
        EncodedPoint,
    };
    use ssh_encoding::{Decode, Encode};
    use ssh_key::{
        private::{EcdsaKeypair, EcdsaPrivateKey, RsaPrivateKey},
        public::KeyData,
        Algorithm, Certificate, Mpint,
    };

    use super::*;
    use crate::proto::PrivateKeyData;

    // Expose this function to all tests under `crate::proto::message`
    pub(super) fn demo_key() -> EcdsaKeypair {
        EcdsaKeypair::NistP256 {
            public: EncodedPoint::from_affine_coordinates(
                &hex!("cb244fcdb89de95bc8fd766e6b139abfc2649fb063b6c5e5a939e067e2a0d215").into(),
                &hex!("0a660daca78f6c24a0425373d6ea83e36f8a1f8b828a60e77a97a9441bcc0987").into(),
                false,
            ),
            private: EcdsaPrivateKey::from(p256::SecretKey::new(
                ScalarPrimitive::new(Uint::from_be_hex(
                    "ffd9f2ce4d0ee5870d8dc7cf771a7669a0b96fe44bb58a8a0bc75a76b4f78240",
                ))
                .unwrap(),
            )),
        }
    }

    #[test]
    fn test_parse_identities() {
        let msg: &[u8] = &hex!(
            "
            0c000000010000006800000013656364
            73612d736861322d6e69737470323536
            000000086e6973747032353600000041
            04cb244fcdb89de95bc8fd766e6b139a
            bfc2649fb063b6c5e5a939e067e2a0d2
            150a660daca78f6c24a0425373d6ea83
            e36f8a1f8b828a60e77a97a9441bcc09
            870000000c62616c6f6f40616e67656c
            61"
        );
        let mut reader = msg;

        let out = Response::decode(&mut reader).expect("parse message");

        let expected = Response::IdentitiesAnswer(vec![Identity {
            pubkey: KeyData::Ecdsa(demo_key().into()),
            comment: "baloo@angela".to_string(),
        }]);
        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
        assert_eq!(buf, msg);
    }

    #[test]
    fn test_parse_certificates() {
        let msg: &[u8] = &hex!(
            "
            190000001c7373682d7273612d
            636572742d763031406f70656e737368 2e636f6d000003200000001c7373682d
            7273612d636572742d763031406f7065 6e7373682e636f6d00000020c551bbbb
            4b7a8cd1f0e5f01689926b0253d51cd2 30aec837b6439f86ad4f9b9a00000003
            0100010000018100e041915757995631 9a7f810b747b25187f5ff26556f7ff03
            7b57fa7d5911d55abd59438d98a2205a 87def0805ea6d8881f9790a010cbe0a2
            0d6145abac98de4fa3fc0f2b53b8241d b205b79e64e0a7ccd33f9f2cd34ae9d2
            ce791bc6aabc8fe1951e37a7af04b3fa 0b029710e7e958403c7bf6d40c13b264
            834f37402ec6630c486014b68413793d b3340bceb6aa4c703170048b59c944c5
            2678f91f872d169619eb39066bc78021 925efd226113f2523ecbefdaf5caa853
            36b760e7e458f7abd1af48917a778805 535dcf45345b2ed4c4aab2286bd12f38
            "
            "
            1173e856e95929ac27515608606f07ff 8514188e2e9b14c822cfd8ce12946f2b
            562c3f51b4a86317ebce585a832af467 f8ea27fd3ed1aa59d187825e9e771ad8
            c383f6fdef2853ed22579bc00a7fcf52 d9906d25dcd5e80ae35115aeb4bcba67
            1fa865c26bde46272806c4991fc9d548 878d2b99ba522083b8863d7c434c21bd
            42da838ed0355ad2fde62e8d0684bcc1 94f2911f235c85ffd3b2b4870e95460a
            2d3422130ccecf610000000000000001 000000010000000664617272656e0000
            000a0000000664617272656e00000000 660f5cc400000000660f6b3c00000000
            00000082000000157065726d69742d58 31312d666f7277617264696e67000000
            00000000177065726d69742d6167656e 742d666f7277617264696e6700000000
            000000167065726d69742d706f72742d 666f7277617264696e67000000000000
            "
            "
            000a7065726d69742d70747900000000 0000000e7065726d69742d757365722d
            72630000000000000000000000330000 000b7373682d65643235353139000000
            20dc83ccfc6ef8488b329f7360572863 25de5905237e55d7711e0a0a8d792ce2
            cb000000530000000b7373682d656432 353531390000004001f88ec5a9f1cbd5
            4c1668b3e33ac6f52c32dff0c51207fb b55a55b88b8809c369e9ac008e3228dd
            90978ff2d6bebd9bbb392883bcb56d9f 81f6afc200ce270300000180063980b0
            5c8b42329056de1f025eb78d68fdf1b2 631811302c75913b86e81b288c975e6b
            ff04cf464705a2ce23de7085c2ff79e7 5cfefd393f4b0420253b55269f9307cc
            627b8ac6579c5fb3dbf9c5c39658a285 57e83132419a98491ef0aae35a785937
            f0785e5ae430c83edb0a91b95efa6b84 0851a8c4c025b00752330dd153be15be
            "
            "
            190f79b0d31548877e5fcecd498c8206 488dc0f8c25216db63850e86a82194aa
            a94dc3585f35cf73bb8f464566d6821d e52f18d5ee37a7e718e228adf314668d
            b1285eea7e34fa71e9ff787eeac0bf3f 97d038a5dd9ecf6a9782a6d1354f5a74
            be42c6cd15aaf6efa77e06018e0a8d90 dcaffac60972a58e39e2773269ab3ac3
            0d352d66586cf8e19a821b29016b0f75 aaaad7caf17ed4913665999fe491e0bd
            2c08141dafeeb08bfe5bedea52ab46e3 3851def2204462b59fa83f853d1e3645
            c6b7e4d8e4d95fe3b74e34fe3e37c53d 026be9c19643ab4014bb82ef922208af
            68435bdc89bdbe0518655bb3ea28078b ebb7bde88ff44970181bd381000000c1
            00e0dd19b95c563d9198f0f4e4b19677 fd17465875757da008b93c0138fd89d7
            1a1f5669d967b69814462530642a5595 de4ee39a838ac8d38136cc2c20f7a7e6
            "
            "
            2bbba10146a35a2b8fba51b70a0b1a43 b43fd26b84ae5a7d1ef7857eab7b2301
            0c1d35c3cc1c781407f45875684a63a2 5a3f71fd32f0984dab7b70febadb1fe4
            4395f80a228f46f3f7dd05205d453c40 4d88712d2051cfac3a33e888a6fea26b
            332f5ac58edfad6a64cb16e39280aacc 607d32f90fb6fe45b21bd288fe9d4fc6
            b2000000c100faba9137f37dc9ab8b28 21ce0c444b03f5ea6ea5059488214ecc
            cc02417c601e32e923710d2dc1417bfe 293502aed390eb93e544a51fd4686b4b
            520e49f559e259b9cd1c2e08e41cfb36 b4979bd5f4f6917d73aeb4a47d7cfc71
            14ec7773aec5a54b0cdc4244cdd1db8a cc8c98955bf1abbe35db3dc7f540ff8a
            858a61399001f0f9c4c440de7a50ab1a 55ff1bb24f3ecdba42ca8a34a83bc76f
            fc5687d9093ba4eba91723b9ae5acdcf c650d8d95b5e8fda85ce957075079d2a
            "
            "
            134f4ed9b181000000c100e4f8860753 2262eaf1db3f11d02535c32a7506acb9
            bcd2b3e9b852a71fea134921015399be 8830db4000b7f33ec3af71b56448178b
            d4d3310ad322855c80aff5bf29fbeebd bbb09a3f09cd5fc017f0d004c08c3f56
            9e4efc15c5fa9474e0bae15e7b416ca5 bd0f053d869f3908bc042bd111af7fc5
            97ef541f70140ccdbae1d5bc781d3dc1 4b3a113f939f1da21d2031d4f37805d3
            6fc420a728ffbeed8e1e1ddb8d4d232d f1e02a152965694139f38b5a60b9198c
            513ac733f51f2c04164de10000000c62 616c6f6f40616e67656c610100000002
        "
        );
        let mut reader = msg;

        let out = Request::decode(&mut reader).expect("parse message");

        let certificate = &hex!(
            "
            0000001c7373682d7273612d63657274 2d763031406f70656e7373682e636f6d
            00000020c551bbbb4b7a8cd1f0e5f016 89926b0253d51cd230aec837b6439f86
            Ad4f9b9a000000030100010000018100 e0419157579956319a7f810b747b2518
            7f5ff26556f7ff037b57fa7d5911d55a bd59438d98a2205a87def0805ea6d888
            1f9790a010cbe0a20d6145abac98de4f a3fc0f2b53b8241db205b79e64e0a7cc
            " "
            D33f9f2cd34ae9d2ce791bc6aabc8fe1 951e37a7af04b3fa0b029710e7e95840
            3c7bf6d40c13b264834f37402ec6630c 486014b68413793db3340bceb6aa4c70
            3170048b59c944c52678f91f872d1696 19eb39066bc78021925efd226113f252
            3ecbefdaf5caa85336b760e7e458f7ab d1af48917a778805535dcf45345b2ed4
            C4aab2286bd12f381173e856e95929ac 27515608606f07ff8514188e2e9b14c8
            " "
            22cfd8ce12946f2b562c3f51b4a86317 ebce585a832af467f8ea27fd3ed1aa59
            D187825e9e771ad8c383f6fdef2853ed 22579bc00a7fcf52d9906d25dcd5e80a
            E35115aeb4bcba671fa865c26bde4627 2806c4991fc9d548878d2b99ba522083
            B8863d7c434c21bd42da838ed0355ad2 fde62e8d0684bcc194f2911f235c85ff
            D3b2b4870e95460a2d3422130ccecf61 00000000000000010000000100000006
            " "
            64617272656e0000000a000000066461 7272656e00000000660f5cc400000000
            660f6b3c000000000000008200000015 7065726d69742d5831312d666f727761
            7264696e670000000000000017706572 6d69742d6167656e742d666f72776172
            64696e6700000000000000167065726d 69742d706f72742d666f727761726469
            6e67000000000000000a7065726d6974 2d707479000000000000000e7065726d
            " "
            69742d757365722d7263000000000000 0000000000330000000b7373682d6564
            323535313900000020dc83ccfc6ef848 8b329f736057286325de5905237e55d7
            711e0a0a8d792ce2cb00000053000000 0b7373682d6564323535313900000040
            01f88ec5a9f1cbd54c1668b3e33ac6f5 2c32dff0c51207fbb55a55b88b8809c3
            69e9ac008e3228dd90978ff2d6bebd9b bb392883bcb56d9f81f6afc200ce2703
        "
        )[..];
        let mut reader = certificate;
        let certificate = Certificate::decode(&mut reader).unwrap();

        let expected = Request::AddIdConstrained(AddIdentityConstrained {
            identity: AddIdentity {
                credential: Credential::Cert {
                    algorithm: Algorithm::new("ssh-rsa").unwrap(),
                    certificate,
                    privkey: PrivateKeyData::Rsa(RsaPrivateKey {
                        d: Mpint::from_bytes(&hex!(
                            "
                            063980B05C8B42329056DE1F025EB78D 68FDF1B2631811302C75913B86E81B28
                            8C975E6BFF04CF464705A2CE23DE7085 C2FF79E75CFEFD393F4B0420253B5526
                            9F9307CC627B8AC6579C5FB3DBF9C5C3 9658A28557E83132419A98491EF0AAE3
                            5A785937F0785E5AE430C83EDB0A91B9 5EFA6B840851A8C4C025B00752330DD1
                            53BE15BE190F79B0D31548877E5FCECD 498C8206488DC0F8C25216DB63850E86
                            A82194AAA94DC3585F35CF73BB8F4645 66D6821DE52F18D5EE37A7E718E228AD
                            F314668DB1285EEA7E34FA71E9FF787E EAC0BF3F97D038A5DD9ECF6A9782A6D1
                            354F5A74BE42C6CD15AAF6EFA77E0601 8E0A8D90DCAFFAC60972A58E39E27732
                            69AB3AC30D352D66586CF8E19A821B29 016B0F75AAAAD7CAF17ED4913665999F
                            E491E0BD2C08141DAFEEB08BFE5BEDEA 52AB46E33851DEF2204462B59FA83F85
                            3D1E3645C6B7E4D8E4D95FE3B74E34FE 3E37C53D026BE9C19643AB4014BB82EF
                            922208AF68435BDC89BDBE0518655BB3 EA28078BEBB7BDE88FF44970181BD381
                            "
                        ))
                        .unwrap(),
                        iqmp: Mpint::from_bytes(&hex!(
                            "
                            00E0DD19B95C563D9198F0F4E4B19677 FD17465875757DA008B93C0138FD89D7
                            1A1F5669D967B69814462530642A5595 DE4EE39A838AC8D38136CC2C20F7A7E6
                            2BBBA10146A35A2B8FBA51B70A0B1A43 B43FD26B84AE5A7D1EF7857EAB7B2301
                            0C1D35C3CC1C781407F45875684A63A2 5A3F71FD32F0984DAB7B70FEBADB1FE4
                            4395F80A228F46F3F7DD05205D453C40 4D88712D2051CFAC3A33E888A6FEA26B
                            332F5AC58EDFAD6A64CB16E39280AACC 607D32F90FB6FE45B21BD288FE9D4FC6
                            B2"
                        ))
                        .unwrap(),
                        p: Mpint::from_bytes(&hex!(
                            "
                            00FABA9137F37DC9AB8B2821CE0C444 B03F5EA6EA5059488214ECCCC02417C
                            601E32E923710D2DC1417BFE293502A ED390EB93E544A51FD4686B4B520E49
                            F559E259B9CD1C2E08E41CFB36B4979 BD5F4F6917D73AEB4A47D7CFC7114EC
                            7773AEC5A54B0CDC4244CDD1DB8ACC8 C98955BF1ABBE35DB3DC7F540FF8A85
                            8A61399001F0F9C4C440DE7A50AB1A5 5FF1BB24F3ECDBA42CA8A34A83BC76F
                            FC5687D9093BA4EBA91723B9AE5ACDC FC650D8D95B5E8FDA85CE957075079D
                            2A134F4ED9B181"
                        ))
                        .unwrap(),
                        q: Mpint::from_bytes(&hex!(
                            "
                            00E4F88607532262EAF1DB3F11D0253 5C32A7506ACB9BCD2B3E9B852A71FEA
                            134921015399BE8830DB4000B7F33EC 3AF71B56448178BD4D3310AD322855C
                            80AFF5BF29FBEEBDBBB09A3F09CD5FC 017F0D004C08C3F569E4EFC15C5FA94
                            74E0BAE15E7B416CA5BD0F053D869F3 908BC042BD111AF7FC597EF541F7014
                            0CCDBAE1D5BC781D3DC14B3A113F939 F1DA21D2031D4F37805D36FC420A728
                            FFBEED8E1E1DDB8D4D232DF1E02A152 965694139F38B5A60B9198C513AC733
                            F51F2C04164DE1"
                        ))
                        .unwrap(),
                    }),
                    comment: "baloo@angela".to_string(),
                },
            },
            constraints: vec![KeyConstraint::Lifetime(2)],
        });
        assert_eq!(out, expected);

        let mut buf = vec![];
        expected.encode(&mut buf).expect("serialize message");
        assert_eq!(buf, msg);
    }
}
