use hex_literal::hex;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, KeyConstraint, PrivateCredential, PrivateKeyData, Request,
};
use ssh_key::{private::RsaPrivateKey, Algorithm, Mpint};

use super::fixtures;

pub fn expected() -> Request {
    Request::AddIdConstrained(AddIdentityConstrained {
        identity: AddIdentity {
            credential: PrivateCredential::Cert {
                algorithm: Algorithm::new("ssh-rsa").unwrap(),
                certificate: fixtures::demo_certificate(),
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
    })
}
