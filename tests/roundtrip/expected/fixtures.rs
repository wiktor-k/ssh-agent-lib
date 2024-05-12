use hex_literal::hex;
use ssh_encoding::Decode;
use ssh_key::{
    private::{EcdsaKeypair, EcdsaPrivateKey},
    Certificate,
};

pub fn demo_key() -> EcdsaKeypair {
    EcdsaKeypair::NistP256 {
        public: p256::EncodedPoint::from_affine_coordinates(
            &hex!(
                "cb244fcdb89de95bc8fd766e6b139abf"
                "c2649fb063b6c5e5a939e067e2a0d215"
            )
            .into(),
            &hex!(
                "0a660daca78f6c24a0425373d6ea83e3"
                "6f8a1f8b828a60e77a97a9441bcc0987"
            )
            .into(),
            false,
        ),
        private: EcdsaPrivateKey::from(p256::SecretKey::new(
            p256::elliptic_curve::ScalarPrimitive::new(
                p256::elliptic_curve::bigint::Uint::from_be_slice(&hex!(
                    "ffd9f2ce4d0ee5870d8dc7cf771a7669"
                    "a0b96fe44bb58a8a0bc75a76b4f78240"
                )),
            )
            .unwrap(),
        )),
    }
}

pub fn demo_certificate() -> Certificate {
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
    Certificate::decode(&mut reader).unwrap()
}
