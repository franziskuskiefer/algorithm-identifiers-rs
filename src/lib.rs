use std::{convert::TryFrom, io::Write, usize};

use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

const U32_LEN: usize = std::mem::size_of::<u32>();

/// Signature key types.
/// This uses the TLS IANA parameters
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy, TlsSerialize, TlsDeserialize)]
#[repr(u16)]
pub enum SignatureKeyType {
    /// EdDSA Curve25519 key
    Ed25519 = 0x0807,

    /// EdDSA Curve448 key
    Ed448 = 0x0808,

    /// ECDSA NIST P256 key with SHA 256 (ecdsa_secp256r1_sha256)
    EcdsaP256Sha256 = 0x0403,

    /// ECDSA NIST P521 key with SHA 512 (ecdsa_secp521r1_sha512)
    EcdsaP521Sha512 = 0x0603,
}

/// KEM key types.
/// This uses the TLS IANA parameters
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy, TlsSerialize, TlsDeserialize)]
#[repr(u16)]
pub enum KemKeyType {
    /// ECDH Curve25519 key
    X25519 = 29,

    /// ECDH Curve448 key
    X448 = 30,

    /// ECDH NIST P256 key (secp256r1)
    P256 = 23,

    /// ECDH NIST P384 key (secp384r1)
    P384 = 24,

    /// ECDH NIST P521 key (secp521r1)
    P521 = 25,
}

/// Asymmetric key types.
/// This can either be a signature key or a KEM key.
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
pub enum AsymmetricKeyType {
    SignatureKey(SignatureKeyType),
    KemKey(KemKeyType),
}

impl From<SignatureKeyType> for AsymmetricKeyType {
    fn from(t: SignatureKeyType) -> Self {
        Self::SignatureKey(t)
    }
}

impl From<KemKeyType> for AsymmetricKeyType {
    fn from(t: KemKeyType) -> Self {
        Self::KemKey(t)
    }
}

impl tls_codec::Serialize for AsymmetricKeyType {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> core::result::Result<(), tls_codec::Error> {
        writer.write(match self {
            // XXX: pull out the outer type ser/de
            AsymmetricKeyType::SignatureKey(_) => &[0],
            AsymmetricKeyType::KemKey(_) => &[1],
        })?;
        match self {
            AsymmetricKeyType::SignatureKey(k) => k.tls_serialize(writer),
            AsymmetricKeyType::KemKey(k) => k.tls_serialize(writer),
        }
    }
}

impl Deserialize for AsymmetricKeyType {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> core::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut outer_type = [0u8; 1];
        bytes.read_exact(&mut outer_type)?;
        match u8::from_be_bytes(outer_type) {
            0 => Ok(Self::SignatureKey(SignatureKeyType::tls_deserialize(
                bytes,
            )?)),
            1 => Ok(Self::KemKey(KemKeyType::tls_deserialize(bytes)?)),
            _ => Err(tls_codec::Error::DecodingError(format!(
                "Unknown asymmetric outer key type {:?}",
                outer_type
            ))),
        }
    }
}

impl TlsSize for AsymmetricKeyType {
    fn serialized_len(&self) -> usize {
        1 + match self {
            AsymmetricKeyType::SignatureKey(k) => k.serialized_len(),
            AsymmetricKeyType::KemKey(k) => k.serialized_len(),
        }
    }
}

pub enum Error {
    /// Unknown key type.
    InvalidKeyType(usize),
}

impl TryFrom<u16> for SignatureKeyType {
    type Error = Error;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0x0807 => Ok(SignatureKeyType::Ed25519),
            0x0808 => Ok(SignatureKeyType::Ed448),
            0x0403 => Ok(SignatureKeyType::EcdsaP256Sha256),
            0x0603 => Ok(SignatureKeyType::EcdsaP521Sha512),
            _ => Err(Error::InvalidKeyType(value as usize)),
        }
    }
}

impl From<KemType> for KemKeyType {
    fn from(kem: KemType) -> Self {
        match kem {
            KemType::DhKemP256 => Self::P256,
            KemType::DhKem25519 => Self::X25519,
            KemType::DhKem448 => Self::X448,
            KemType::DhKemP384 => Self::P384,
            KemType::DhKemP521 => Self::P521,
        }
    }
}

impl From<KemType> for AsymmetricKeyType {
    fn from(kem: KemType) -> Self {
        Self::KemKey(KemKeyType::from(kem))
    }
}

impl Into<u16> for SignatureKeyType {
    fn into(self) -> u16 {
        self as u16
    }
}

impl Into<u16> for KemKeyType {
    fn into(self) -> u16 {
        self as u16
    }
}

/// Symmetric key types
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
pub enum SymmetricKeyType {
    /// An AES 128 secret
    Aes128,

    /// An AES 256 secret
    Aes256,

    /// A ChaCha20 secret
    ChaCha20,

    /// A generic secret type for a secret of a given length.
    Any(u16),
}

impl TlsSize for SymmetricKeyType {
    #[inline]
    fn serialized_len(&self) -> usize {
        U32_LEN
    }
}

impl Serialize for SymmetricKeyType {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> core::result::Result<(), tls_codec::Error> {
        let self_u32: u32 = self.into();
        self_u32.tls_serialize(writer)
    }
}

impl Deserialize for SymmetricKeyType {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> core::result::Result<Self, tls_codec::Error> {
        let mut self_bytes = [0u8; U32_LEN];
        bytes.read_exact(&mut self_bytes)?;
        Self::try_from(u32::from_be_bytes(self_bytes)).map_err(|_e| tls_codec::Error::InvalidInput)
    }
}

impl SymmetricKeyType {
    /// Get the length of the secret.
    pub const fn len(&self) -> usize {
        match self {
            SymmetricKeyType::Aes128 => 16,
            SymmetricKeyType::Aes256 => 32,
            SymmetricKeyType::ChaCha20 => 32,
            SymmetricKeyType::Any(l) => *l as usize,
        }
    }
}

impl TryFrom<u32> for SymmetricKeyType {
    type Error = Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value & 0xFFFF {
            0 => Ok(SymmetricKeyType::Aes128),
            1 => Ok(SymmetricKeyType::Aes256),
            2 => Ok(SymmetricKeyType::ChaCha20),
            3 => Ok(SymmetricKeyType::Any((value >> 16) as u16)),
            _ => Err(Error::InvalidKeyType(value as usize)),
        }
    }
}

impl Into<u32> for &SymmetricKeyType {
    fn into(self) -> u32 {
        (*self).into()
    }
}

impl Into<u32> for SymmetricKeyType {
    fn into(self) -> u32 {
        match self {
            SymmetricKeyType::Aes128 => 0,
            SymmetricKeyType::Aes256 => 1,
            SymmetricKeyType::ChaCha20 => 2,
            SymmetricKeyType::Any(l) => 3u32 | (u32::from(l) << 16),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
#[repr(u16)]
/// AEAD types
pub enum AeadType {
    /// AES GCM 128
    Aes128Gcm = 0x0001,

    /// AES GCM 256
    Aes256Gcm = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,

    /// HPKE Export-only
    HpkeExport = 0xFFFF,
}

#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
#[repr(u8)]
#[allow(non_camel_case_types)]
/// Hash types
/// This uses the TLS IANA parameters where possible (SHA-1 and SHA-2)
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
/// SHA-3 is assigned 0x07-0x0A
/// SHAKE 128 and 256 are assigned 0x0B and 0x0C
pub enum HashType {
    Sha1 = 0x02,
    Sha2_224 = 0x03,
    Sha2_256 = 0x04,
    Sha2_384 = 0x05,
    Sha2_512 = 0x06,
    Sha3_224 = 0x07,
    Sha3_256 = 0x08,
    Sha3_384 = 0x09,
    Sha3_512 = 0x0A,
    Shake_128 = 0x0B,
    Shake_256 = 0x0C,
}

#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
#[repr(u16)]
/// KEM types
/// Value are taken from the HPKE RFC (not published yet)
/// TODO: update when HPKE has been published and values have been registered with
///       IANA.
pub enum KemType {
    /// DH KEM on P256
    DhKemP256 = 0x0010,

    /// DH KEM on P384
    DhKemP384 = 0x0011,

    /// DH KEM on P521
    DhKemP521 = 0x0012,

    /// DH KEM on x25519
    DhKem25519 = 0x0020,

    /// DH KEM on x448
    DhKem448 = 0x0021,
}

#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
#[repr(u16)]
/// KDF types
/// Value are taken from the HPKE RFC (not published yet)
/// TODO: update when HPKE has been published and values have been registered with
///       IANA.
pub enum KdfType {
    /// HKDF SHA 256
    HkdfSha256 = 0x0001,

    /// HKDF SHA 384
    HkdfSha384 = 0x0002,

    /// HKDF SHA 512
    HkdfSha512 = 0x0003,
}
