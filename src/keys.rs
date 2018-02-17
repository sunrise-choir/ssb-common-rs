//! TODO update description once you figured out how to represent stuff in types
//! - as of now, only one primitive (ed25519)
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
use std::ops::{Index, Range, RangeTo, RangeFrom, RangeFull};

use sodiumoxide::crypto::sign;

/// An ssb public key. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
///
/// New instances can be either created via a `From` implementation, or through
/// one of the parsing functions. // TODO are there multiple? What about key generation functions?
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PublicKey {
    /// An [Ed25519](http://ed25519.cr.yp.to/) public key, as used by
    /// `sodiumoxide::crypto::sign`.
    Ed25519(sign::PublicKey),
}

impl PublicKey {
    /// Return the length (in bytes) of the key.
    pub fn len(&self) -> usize {
        match *self {
            PublicKey::Ed25519(_) => sign::PUBLICKEYBYTES,
        }
    }

    /// Verify the given signed message with this `PublicKey`. On success,
    /// return a `Vec<u8>` containing the message without the signature.
    pub fn verify(&self, signed_message: &[u8]) -> Result<Vec<u8>, ()> {
        match *self {
            PublicKey::Ed25519(ref pk) => sign::verify(signed_message, pk),
        }
    }

    /// Verify the given message with this `PublicKey` and the given `Signature`.
    ///
    /// # Panics
    /// Panics if this `PublicKey` and the `Signature` use different
    /// cryptographic primitives.
    pub fn verify_detached(&self, signature: &Signature, signed_message: &[u8]) -> bool {
        match *self {
            PublicKey::Ed25519(ref pk) => {
                match *signature {
                    Signature::Ed25519(ref sig) => sign::verify_detached(sig, signed_message, pk),
                }
            }
        }
    }

    /// Verify the given message with this `PublicKey` and the given `Signature`.
    /// Return `None` if this `PublicKey` and the `Signature` use different
    /// cryptographic primitives.
    pub fn try_verify_detached(&self,
                               signature: &Signature,
                               signed_message: &[u8])
                               -> Option<bool> {
        match *self {
            PublicKey::Ed25519(ref pk) => {
                match *signature {
                    Signature::Ed25519(ref sig) => {
                        Some(sign::verify_detached(sig, signed_message, pk))
                    }
                }
            }
        }
    }

    /// Return whether this `PublicKey` uses the ed25519 cryptographic primitive.
    pub fn is_ed25519(&self) -> bool {
        match *self {
            PublicKey::Ed25519(_) => true,
        }
    }

    /// Return whether this `PublicKey` uses the same cryptographic primitive as
    /// the given `SecretKey`.
    pub fn matches_secret_key(&self, secret_key: &SecretKey) -> bool {
        match *self {
            PublicKey::Ed25519(_) => secret_key.is_ed25519(),
        }
    }

    /// Return whether this `PublicKey` uses the same cryptographic primitive as
    /// the given `Signature`.
    pub fn matches_signature(&self, signature: &Signature) -> bool {
        match *self {
            PublicKey::Ed25519(_) => signature.is_ed25519(),
        }
    }
}

impl From<sign::PublicKey> for PublicKey {
    fn from(ed25519_pk: sign::PublicKey) -> PublicKey {
        PublicKey::Ed25519(ed25519_pk)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match *self {
            PublicKey::Ed25519(ref pk) => pk.as_ref(),
        }
    }
}

/// Allows to access the byte contents of a `PublicKey` as a slice.
impl Index<Range<usize>> for PublicKey {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        match *self {
            PublicKey::Ed25519(ref pk) => pk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `PublicKey` as a slice.
impl Index<RangeTo<usize>> for PublicKey {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        match *self {
            PublicKey::Ed25519(ref pk) => pk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `PublicKey` as a slice.
impl Index<RangeFrom<usize>> for PublicKey {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        match *self {
            PublicKey::Ed25519(ref pk) => pk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `PublicKey` as a slice.
impl Index<RangeFull> for PublicKey {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        match *self {
            PublicKey::Ed25519(ref pk) => pk.index(_index),
        }
    }
}

/// An ssb secret key. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
///
/// When a `SecretKey` goes out of scope its contents will be zeroed out.
///
/// New instances can be either created via a `From` implementation, or through
/// one of the parsing functions. // TODO are there multiple? What about key generation functions?
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SecretKey {
    /// An [Ed25519](http://ed25519.cr.yp.to/) secret key, as used by
    /// `sodiumoxide::crypto::sign`.
    Ed25519(sign::SecretKey),
}

impl SecretKey {
    /// Return the length (in bytes) of the key.
    pub fn len(&self) -> usize {
        match *self {
            SecretKey::Ed25519(_) => sign::SECRETKEYBYTES,
        }
    }

    /// Sign a message with this `SecretKey`, returning the resulting message in
    /// a `Vec<u8>`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match *self {
            SecretKey::Ed25519(ref sk) => sign::sign(message, sk),
        }
    }

    /// Sign a message with this `SecretKey`, returning only the signature.
    pub fn sign_detached(&self, message: &[u8]) -> Signature {
        match *self {
            SecretKey::Ed25519(ref sk) => Signature::from(sign::sign_detached(message, sk)),
        }
    }

    /// Return whether this `SecretKey` uses the ed25519 cryptographic primitive.
    pub fn is_ed25519(&self) -> bool {
        match *self {
            SecretKey::Ed25519(_) => true,
        }
    }
}

impl From<sign::SecretKey> for SecretKey {
    fn from(ed25519_sk: sign::SecretKey) -> SecretKey {
        SecretKey::Ed25519(ed25519_sk)
    }
}

/// Allows to access the byte contents of a `SecretKey` as a slice.
impl Index<Range<usize>> for SecretKey {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        match *self {
            SecretKey::Ed25519(ref sk) => sk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `SecretKey` as a slice.
impl Index<RangeTo<usize>> for SecretKey {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        match *self {
            SecretKey::Ed25519(ref sk) => sk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `SecretKey` as a slice.
impl Index<RangeFrom<usize>> for SecretKey {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        match *self {
            SecretKey::Ed25519(ref sk) => sk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `SecretKey` as a slice.
impl Index<RangeFull> for SecretKey {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        match *self {
            SecretKey::Ed25519(ref sk) => sk.index(_index),
        }
    }
}

/// An ssb signature. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Signature {
    /// An [Ed25519](http://ed25519.cr.yp.to/) signature, as used by
    /// `sodiumoxide::crypto::sign`.
    Ed25519(sign::Signature),
}

impl Signature {
    /// Return the length (in bytes) of the signature.
    pub fn len(&self) -> usize {
        match *self {
            Signature::Ed25519(_) => sign::SIGNATUREBYTES,
        }
    }

    /// Return whether this `Signature` uses the ed25519 cryptographic primitive.
    pub fn is_ed25519(&self) -> bool {
        match *self {
            Signature::Ed25519(_) => true,
        }
    }
}

impl From<sign::Signature> for Signature {
    fn from(ed25519_sig: sign::Signature) -> Signature {
        Signature::Ed25519(ed25519_sig)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match *self {
            Signature::Ed25519(ref sig) => sig.as_ref(),
        }
    }
}

/// Allows to access the byte contents of a `Signature` as a slice.
impl Index<Range<usize>> for Signature {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        match *self {
            Signature::Ed25519(ref sig) => sig.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `Signature` as a slice.
impl Index<RangeTo<usize>> for Signature {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        match *self {
            Signature::Ed25519(ref sig) => sig.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `Signature` as a slice.
impl Index<RangeFrom<usize>> for Signature {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        match *self {
            Signature::Ed25519(ref sig) => sig.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `Signature` as a slice.
impl Index<RangeFull> for Signature {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        match *self {
            Signature::Ed25519(ref sig) => sig.index(_index),
        }
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
