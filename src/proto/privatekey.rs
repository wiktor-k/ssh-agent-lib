use core::fmt;

use ssh_encoding::{Decode, Encode, Reader, Writer};
use ssh_key::{
    private::{self, DsaPrivateKey, Ed25519Keypair, RsaPrivateKey},
    Algorithm, EcdsaCurve, Error, Result,
};
use subtle::{Choice, ConstantTimeEq};

/// Elliptic Curve Digital Signature Algorithm (ECDSA) private/public key pair.
#[derive(Clone, Debug)]
pub enum EcdsaPrivateKey {
    /// NIST P-256 ECDSA private key.
    NistP256(private::EcdsaPrivateKey<32>),

    /// NIST P-384 ECDSA private key.
    NistP384(private::EcdsaPrivateKey<48>),

    /// NIST P-521 ECDSA private key.
    NistP521(private::EcdsaPrivateKey<66>),
}

impl ConstantTimeEq for EcdsaPrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        let private_key_a = match self {
            Self::NistP256(private) => private.as_slice(),
            Self::NistP384(private) => private.as_slice(),
            Self::NistP521(private) => private.as_slice(),
        };

        let private_key_b = match other {
            Self::NistP256(private) => private.as_slice(),
            Self::NistP384(private) => private.as_slice(),
            Self::NistP521(private) => private.as_slice(),
        };

        private_key_a.ct_eq(private_key_b)
    }
}

impl Eq for EcdsaPrivateKey {}

impl PartialEq for EcdsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl EcdsaPrivateKey {
    fn decode_as(reader: &mut impl Reader, curve: EcdsaCurve) -> Result<Self> {
        match curve {
            EcdsaCurve::NistP256 => {
                private::EcdsaPrivateKey::<32>::decode(reader).map(Self::NistP256)
            }
            EcdsaCurve::NistP384 => {
                private::EcdsaPrivateKey::<48>::decode(reader).map(Self::NistP384)
            }
            EcdsaCurve::NistP521 => {
                private::EcdsaPrivateKey::<66>::decode(reader).map(Self::NistP521)
            }
        }
    }
}

impl Encode for EcdsaPrivateKey {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        match self {
            Self::NistP256(private) => private.encoded_len(),
            Self::NistP384(private) => private.encoded_len(),
            Self::NistP521(private) => private.encoded_len(),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        match self {
            Self::NistP256(private) => private.encode(writer),
            Self::NistP384(private) => private.encode(writer),
            Self::NistP521(private) => private.encode(writer),
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub enum PrivateKeyData {
    /// Digital Signature Algorithm (DSA) private key.
    Dsa(DsaPrivateKey),

    /// ECDSA private key.
    Ecdsa(EcdsaPrivateKey),

    // Note: OpenSSH is a little inconsistent, Ed25519 is the only one
    // algorithm that will always encode the full key pair.
    /// Ed25519 key pair.
    Ed25519(Ed25519Keypair),
    /// RSA private key.
    Rsa(RsaPrivateKey),
}

impl PrivateKeyData {
    /// Decode [`PrivateKeyData`] for the specified algorithm.
    pub fn decode_as(reader: &mut impl Reader, algorithm: Algorithm) -> Result<Self> {
        match algorithm {
            Algorithm::Dsa => DsaPrivateKey::decode(reader).map(Self::Dsa),
            Algorithm::Ecdsa { curve } => {
                EcdsaPrivateKey::decode_as(reader, curve).map(Self::Ecdsa)
            }
            Algorithm::Ed25519 => Ed25519Keypair::decode(reader).map(Self::Ed25519),
            Algorithm::Rsa { .. } => RsaPrivateKey::decode(reader).map(Self::Rsa),
            #[allow(unreachable_patterns)]
            _ => Err(Error::AlgorithmUnknown),
        }
    }
}

impl fmt::Debug for PrivateKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dsa(_) => write!(f, "PrivateKeyData::Dsa"),
            Self::Ecdsa(_) => write!(f, "PrivateKeyData::Ecdsa"),
            Self::Ed25519(_) => write!(f, "PrivateKeyData::Ed25519"),
            Self::Rsa(_) => write!(f, "PrivateKeyData::Rsa"),
        }
    }
}

impl Encode for PrivateKeyData {
    fn encoded_len(&self) -> ssh_encoding::Result<usize> {
        match self {
            Self::Dsa(key) => key.encoded_len(),
            Self::Ecdsa(key) => key.encoded_len(),
            Self::Ed25519(key) => key.encoded_len(),
            Self::Rsa(key) => key.encoded_len(),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
        match self {
            Self::Dsa(key) => key.encode(writer)?,
            Self::Ecdsa(key) => key.encode(writer)?,
            Self::Ed25519(key) => key.encode(writer)?,
            Self::Rsa(key) => key.encode(writer)?,
        }

        Ok(())
    }
}

impl ConstantTimeEq for PrivateKeyData {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Note: constant-time with respect to key *data* comparisons, not algorithms
        match (self, other) {
            (Self::Dsa(a), Self::Dsa(b)) => a.ct_eq(b),
            (Self::Ecdsa(a), Self::Ecdsa(b)) => a.ct_eq(b),
            (Self::Ed25519(a), Self::Ed25519(b)) => a.ct_eq(b),
            (Self::Rsa(a), Self::Rsa(b)) => a.ct_eq(b),
            #[allow(unreachable_patterns)]
            _ => Choice::from(0),
        }
    }
}

impl Eq for PrivateKeyData {}

impl PartialEq for PrivateKeyData {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
