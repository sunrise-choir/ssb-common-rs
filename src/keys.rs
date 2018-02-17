//! TODO update description once you figured out how to represent stuff in types
//!
//! Operations for dealing with the public and secret keys used by ssb. This
//! mostly deals with their representation in base64 and with a suffix
//! indicating the cryptographic primitive.
//!
//! `Base64PublicKeyBuf` (owned) and `Base64PrivateKey` (reference) represent
//! strings which are valid base64 encodings of ssb keys.
//! `MultiPublicKeyBuf` (owned) and `MultiSecretKey` (reference) are string
//! encodings that include a suffix indicating the cryptographic primitive.

use std::convert::From;

use sodiumoxide::crypto::sign;

// TODO serde (de)serialization traits?

/// An ssb public key. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
///
/// New instances can be either created via a `From` implementation, or through
/// one of the parsing functions. // TODO are there multiple? What about key generation functions?
// TODO derive traits?
pub enum PublicKey {
    /// An [Ed25519](http://ed25519.cr.yp.to/) public key, as used by
    /// `sodiumoxide::crypto::sign`.
    Ed25519(sign::PublicKey),
}

impl PublicKey {
    // TODO keep this?
    // /// Returns which cryptographic primitive is used for this `PublicKey`.
    // fn crypto_primitive(&self) -> CryptoPrimitive {
    //     match *self {
    //         PublicKey::Ed25519(_) => CryptoPrimitive::Ed25519,
    //     }
    // }
}

impl From<sign::PublicKey> for PublicKey {
    fn from(ed25519_pk: sign::PublicKey) -> PublicKey {
        PublicKey::Ed25519(ed25519_pk)
    }
}

/// An ssb secret key. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
///
/// When a `SecretKey` goes out of scope its contents will be zeroed out.
///
/// New instances can be either created via a `From` implementation, or through
/// one of the parsing functions. // TODO are there multiple? What about key generation functions?
// TODO derive traits?
pub enum SecretKey {
    /// An [Ed25519](http://ed25519.cr.yp.to/) secret key, as used by
    /// `sodiumoxide::crypto::sign`.
    Ed25519(sign::SecretKey),
}

impl SecretKey {
    // TODO keep this?
    // /// Returns which cryptographic primitive is used for this `SecretKey`.
    // fn crypto_primitive(&self) -> CryptoPrimitive {
    //     match *self {
    //         SecretKey::Ed25519(_) => CryptoPrimitive::Ed25519,
    //     }
    // }
}

impl From<sign::SecretKey> for SecretKey {
    fn from(ed25519_sk: sign::SecretKey) -> SecretKey {
        SecretKey::Ed25519(ed25519_sk)
    }
}

/// Randomly generate a secret key and a corresponding public key. This function
/// does not specifiy which cryptographic primitive it will use and should be
/// preferred over those that do.
///
/// THREAD SAFETY: `gen_keypair()`` is thread-safe provided that you have called
/// `sodiumoxide::init()`` once before using any other function from sodiumoxide.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let (pk, sk) = sign::gen_keypair();
    (PublicKey::from(pk), SecretKey::from(sk))
}

/// Randomly generate a secret key and a corresponding public key, using the
/// ed25519 cryptographic primitive.
///
/// THREAD SAFETY: `gen_keypair()`` is thread-safe provided that you have called
/// `sodiumoxide::init()`` once before using any other function from sodiumoxide.
pub fn gen_keypair_ed25519() -> (PublicKey, SecretKey) {
    let (pk, sk) = sign::gen_keypair();
    (PublicKey::from(pk), SecretKey::from(sk))
}

/// Randomly generate a secret key and a corresponding public key from a seed,
/// using the ed25519 cryptographic primitive.
pub fn keypair_from_seed_ed25519(seed: &sign::Seed) -> (PublicKey, SecretKey) {
    let (pk, sk) = sign::keypair_from_seed(seed);
    (PublicKey::from(pk), SecretKey::from(sk))
}

// TODO Should this be added? This would make the abstraction leaky and would
// also make adding new primitives a breaking change.
// /// The different cryptographic primitives that can be used for ssb keys.
// ///
// /// Currently, only one such primitive ([Ed25519](http://ed25519.cr.yp.to/)) is
// /// supported.
// // TODO derive traits?
// pub enum CryptoPrimitive {
//     /// The [Ed25519](http://ed25519.cr.yp.to/) cryptographic primitive.
//     Ed25519,
// }
//
// impl CryptoPrimitive {
//     /// Randomly generate a secret key and a corresponding public key, using the
//     /// given primitive.
//     ///
//     /// THREAD SAFETY: `gen_keypair()`` is thread-safe provided that you have called
//     /// `sodiumoxide::init()`` once before using any other function from sodiumoxide.
//     pub fn gen_keypair(&self) -> (PublicKey, SecretKey) {
//         match *self {
//             CryptoPrimitive::Ed25519 => gen_keypair_ed25519(),
//         }
//     }
//
//     /// Return the number of bytes in a public key of this primitive.
//     pub fn public_key_bytes(&self) -> usize {
//         match *self {
//             CryptoPrimitive::Ed25519 => sign::PUBLICKEYBYTES,
//         }
//     }
//
//     /// Return the number of bytes in a secret key of this primitive.
//     pub fn secret_key_bytes(&self) -> usize {
//         match *self {
//             CryptoPrimitive::Ed25519 => sign::SECRETKEYBYTES,
//         }
//     }
//
//     /// Return the number of bytes in a signature of this primitive.
//     pub fn signature_bytes(&self) -> usize {
//         match *self {
//             CryptoPrimitive::Ed25519 => sign::SIGNATUREBYTES,
//         }
//     }
// }
