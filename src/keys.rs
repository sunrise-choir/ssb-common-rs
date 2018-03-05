//! Operations for dealing with the public and secret keys used in ssb.
//!
//! The `PublicKey`, `SecretKey` and `Signature` types abstract over the
//! (potentially multiple) cryptographic primitives supported by ssb. These
//! types should be used when dealing with keys in application logic.
//!
//! Aside from providing these types, this module also implements the encoding
//! used in ssb to store and transmit keys.

use std::convert::{From, TryInto};
use std::str::FromStr;
use std::ops::{Index, Range, RangeTo, RangeFrom, RangeFull};
use std::fmt;

use sodiumoxide::crypto::sign;
use base64::{encode_config_buf, decode_config_slice, STANDARD};
use regex::{Regex, RegexBuilder};
use serde::{self, Serialize, Serializer, Deserialize, Deserializer};

/// An ssb public key. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(_PublicKey);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum _PublicKey {
    // An [Ed25519](http://ed25519.cr.yp.to/) public key, as used by
    // `sodiumoxide::crypto::sign`.
    Ed25519(sign::PublicKey),
}

impl PublicKey {
    /// Return the length (in bytes) of the key.
    pub fn len(&self) -> usize {
        match self.0 {
            _PublicKey::Ed25519(_) => sign::PUBLICKEYBYTES,
        }
    }

    /// Verify the given signed message with this `PublicKey`. On success,
    /// return a `Vec<u8>` containing the message without the signature.
    pub fn verify(&self, signed_message: &[u8]) -> Result<Vec<u8>, ()> {
        match self.0 {
            _PublicKey::Ed25519(ref pk) => sign::verify(signed_message, pk),
        }
    }

    /// Verify the given message with this `PublicKey` and the given `Signature`.
    ///
    /// # Panics
    /// Panics if this `PublicKey` and the `Signature` use different
    /// cryptographic primitives.
    pub fn verify_detached(&self, signature: &Signature, signed_message: &[u8]) -> bool {
        match self.0 {
            _PublicKey::Ed25519(ref pk) => {
                match signature.0 {
                    _Signature::Ed25519(ref sig) => sign::verify_detached(sig, signed_message, pk),
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
        match self.0 {
            _PublicKey::Ed25519(ref pk) => {
                match signature.0 {
                    _Signature::Ed25519(ref sig) => {
                        Some(sign::verify_detached(sig, signed_message, pk))
                    }
                }
            }
        }
    }

    /// Return whether this `PublicKey` uses the ed25519 cryptographic primitive.
    pub fn is_ed25519(&self) -> bool {
        match self.0 {
            _PublicKey::Ed25519(_) => true,
        }
    }

    /// Return whether this `PublicKey` uses a cryptographic primitive that is
    /// currently considered secure.
    ///
    /// The return value of this method may change as new versions of this
    /// module are released.
    pub fn is_considered_secure(&self) -> bool {
        match self.0 {
            _PublicKey::Ed25519(_) => true,
        }
    }

    /// Return whether this `PublicKey` uses the same cryptographic primitive as
    /// the given `SecretKey`.
    pub fn matches_secret_key(&self, secret_key: &SecretKey) -> bool {
        match self.0 {
            _PublicKey::Ed25519(_) => secret_key.is_ed25519(),
        }
    }

    /// Return whether this `PublicKey` uses the same cryptographic primitive as
    /// the given `Signature`.
    pub fn matches_signature(&self, signature: &Signature) -> bool {
        match self.0 {
            _PublicKey::Ed25519(_) => signature.is_ed25519(),
        }
    }

    /// Encode the `PublicKey` as a `String`.
    pub fn to_encoding(&self) -> String {
        match self.0 {
            _PublicKey::Ed25519(ref bytes) => {
                let mut buf = String::with_capacity(SSB_PK_ED25519_ENCODED_LEN);
                encode_config_buf(bytes, STANDARD, &mut buf);
                debug_assert!(buf.len() == ED25519_PK_BASE64_LEN);

                buf.push_str(ED25519_SUFFIX);
                debug_assert!(buf.len() == SSB_PK_ED25519_ENCODED_LEN);

                buf
            }
        }
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_encoding())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The error when failing to parse a `PublicKey` from a string.
#[derive(Debug, Copy, Clone)]
pub struct PublicKeyParseError;

impl fmt::Display for PublicKeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid public key encoding")
    }
}

/// This can be used to parse an encoded `PublicKey`.
impl FromStr for PublicKey {
    /// Fails if the given string does not contain an encoding of a `PublicKey`.
    type Err = PublicKeyParseError;

    fn from_str(enc: &str) -> Result<PublicKey, PublicKeyParseError> {
        if !encodes_public_key(enc) {
            Err(PublicKeyParseError)
        } else {
            let mut buf = [0; sign::PUBLICKEYBYTES];

            match decode_config_slice(&enc[..ED25519_PK_BASE64_LEN], STANDARD, &mut buf) {
                Ok(_) => Ok(PublicKey(_PublicKey::Ed25519(sign::PublicKey(buf)))),
                Err(_) => Err(PublicKeyParseError),
            }
        }

    }
}

impl From<sign::PublicKey> for PublicKey {
    fn from(ed25519_pk: sign::PublicKey) -> PublicKey {
        PublicKey(_PublicKey::Ed25519(ed25519_pk))
    }
}

impl TryInto<sign::PublicKey> for PublicKey {
    /// Fails if the underlying cryptographic primitive is not ed25519.
    type Error = ();

    fn try_into(self) -> Result<sign::PublicKey, Self::Error> {
        match self.0 {
            _PublicKey::Ed25519(pk) => Ok(pk),
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self.0 {
            _PublicKey::Ed25519(ref pk) => pk.as_ref(),
        }
    }
}

/// Allows to access the byte contents of a `PublicKey` as a slice.
impl Index<Range<usize>> for PublicKey {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        match self.0 {
            _PublicKey::Ed25519(ref pk) => pk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `PublicKey` as a slice.
impl Index<RangeTo<usize>> for PublicKey {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        match self.0 {
            _PublicKey::Ed25519(ref pk) => pk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `PublicKey` as a slice.
impl Index<RangeFrom<usize>> for PublicKey {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        match self.0 {
            _PublicKey::Ed25519(ref pk) => pk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `PublicKey` as a slice.
impl Index<RangeFull> for PublicKey {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        match self.0 {
            _PublicKey::Ed25519(ref pk) => pk.index(_index),
        }
    }
}

/// An ssb secret key. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
///
/// When a `SecretKey` goes out of scope its contents are zeroed out.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(_SecretKey);

#[derive(Clone, PartialEq, Eq, Debug)]
enum _SecretKey {
    /// An [Ed25519](http://ed25519.cr.yp.to/) secret key, as used by
    /// `sodiumoxide::crypto::sign`.
    Ed25519(sign::SecretKey),
}

impl SecretKey {
    /// Return the length (in bytes) of the key.
    pub fn len(&self) -> usize {
        match self.0 {
            _SecretKey::Ed25519(_) => sign::SECRETKEYBYTES,
        }
    }

    /// Sign a message with this `SecretKey`, returning the resulting message in
    /// a `Vec<u8>`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self.0 {
            _SecretKey::Ed25519(ref sk) => sign::sign(message, sk),
        }
    }

    /// Sign a message with this `SecretKey`, returning only the signature.
    pub fn sign_detached(&self, message: &[u8]) -> Signature {
        match self.0 {
            _SecretKey::Ed25519(ref sk) => Signature::from(sign::sign_detached(message, sk)),
        }
    }

    /// Return whether this `SecretKey` uses the ed25519 cryptographic primitive.
    pub fn is_ed25519(&self) -> bool {
        match self.0 {
            _SecretKey::Ed25519(_) => true,
        }
    }

    /// Return whether this `SecretKey` uses a cryptographic primitive that is
    /// currently considered secure.
    ///
    /// The return value of this method may change as new versions of this
    /// module are released.
    pub fn is_considered_secure(&self) -> bool {
        match self.0 {
            _SecretKey::Ed25519(_) => true,
        }
    }

    /// Encode the `SecretKey` as a `String`.
    pub fn to_encoding(&self) -> String {
        match self.0 {
            _SecretKey::Ed25519(ref bytes) => {
                let mut buf = String::with_capacity(SSB_SK_ED25519_ENCODED_LEN);
                encode_config_buf(&bytes[..], STANDARD, &mut buf);
                debug_assert!(buf.len() == ED25519_SK_BASE64_LEN);

                buf.push_str(ED25519_SUFFIX);
                debug_assert!(buf.len() == SSB_SK_ED25519_ENCODED_LEN);

                buf
            }
        }
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_encoding())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The error when failing to parse a `PublicKey` from a string.
#[derive(Debug, Copy, Clone)]
pub struct SecretKeyParseError;

impl fmt::Display for SecretKeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid secret key encoding")
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<sign::SecretKey> for SecretKey {
    fn from(ed25519_sk: sign::SecretKey) -> SecretKey {
        SecretKey(_SecretKey::Ed25519(ed25519_sk))
    }
}

impl TryInto<sign::SecretKey> for SecretKey {
    /// Fails if the underlying cryptographic primitive is not ed25519.
    type Error = ();

    fn try_into(self) -> Result<sign::SecretKey, Self::Error> {
        match self.0 {
            _SecretKey::Ed25519(sk) => Ok(sk),
        }
    }
}

/// Allows to access the byte contents of a `SecretKey` as a slice.
impl Index<Range<usize>> for SecretKey {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        match self.0 {
            _SecretKey::Ed25519(ref sk) => sk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `SecretKey` as a slice.
impl Index<RangeTo<usize>> for SecretKey {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        match self.0 {
            _SecretKey::Ed25519(ref sk) => sk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `SecretKey` as a slice.
impl Index<RangeFrom<usize>> for SecretKey {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        match self.0 {
            _SecretKey::Ed25519(ref sk) => sk.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `SecretKey` as a slice.
impl Index<RangeFull> for SecretKey {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        match self.0 {
            _SecretKey::Ed25519(ref sk) => sk.index(_index),
        }
    }
}

/// This can be used to parse an encoded `SecretKey`.
impl FromStr for SecretKey {
    /// Fails if the given string does not contain an encoding of a `SecretKey`.
    type Err = SecretKeyParseError;

    fn from_str(enc: &str) -> Result<SecretKey, SecretKeyParseError> {
        if !encodes_secret_key(enc) {
            Err(SecretKeyParseError)
        } else {
            let mut buf = [0; sign::SECRETKEYBYTES];

            match decode_config_slice(&enc[..ED25519_SK_BASE64_LEN], STANDARD, &mut buf) {
                Ok(_) => Ok(SecretKey(_SecretKey::Ed25519(sign::SecretKey(buf)))),
                Err(_) => Err(SecretKeyParseError),
            }
        }

    }
}

/// An ssb signature. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature(_Signature);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum _Signature {
    /// An [Ed25519](http://ed25519.cr.yp.to/) signature, as used by
    /// `sodiumoxide::crypto::sign`.
    Ed25519(sign::Signature),
}

impl Signature {
    /// Return the length (in bytes) of the signature.
    pub fn len(&self) -> usize {
        match self.0 {
            _Signature::Ed25519(_) => sign::SIGNATUREBYTES,
        }
    }

    /// Return whether this `Signature` uses the ed25519 cryptographic primitive.
    pub fn is_ed25519(&self) -> bool {
        match self.0 {
            _Signature::Ed25519(_) => true,
        }
    }

    /// Return whether this `Signature` uses a cryptographic primitive that is
    /// currently considered secure.
    ///
    /// The return value of this method may change as new versions of this
    /// module are released.
    pub fn is_considered_secure(&self) -> bool {
        match self.0 {
            _Signature::Ed25519(_) => true,
        }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<sign::Signature> for Signature {
    fn from(ed25519_sig: sign::Signature) -> Signature {
        Signature(_Signature::Ed25519(ed25519_sig))
    }
}

impl TryInto<sign::Signature> for Signature {
    /// Fails if the underlying cryptographic primitive is not ed25519.
    type Error = ();

    fn try_into(self) -> Result<sign::Signature, Self::Error> {
        match self.0 {
            _Signature::Ed25519(sig) => Ok(sig),
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self.0 {
            _Signature::Ed25519(ref sig) => sig.as_ref(),
        }
    }
}

/// Allows to access the byte contents of a `Signature` as a slice.
impl Index<Range<usize>> for Signature {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        match self.0 {
            _Signature::Ed25519(ref sig) => sig.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `Signature` as a slice.
impl Index<RangeTo<usize>> for Signature {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        match self.0 {
            _Signature::Ed25519(ref sig) => sig.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `Signature` as a slice.
impl Index<RangeFrom<usize>> for Signature {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        match self.0 {
            _Signature::Ed25519(ref sig) => sig.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `Signature` as a slice.
impl Index<RangeFull> for Signature {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        match self.0 {
            _Signature::Ed25519(ref sig) => sig.index(_index),
        }
    }
}

/// Randomly generate a secret key and a corresponding public key. This function
/// does not specifiy which cryptographic primitive it will use and should be
/// preferred over those that do.
///
/// THREAD SAFETY: `gen_keypair()` is thread-safe provided that you have called
/// `sodiumoxide::init()` once before using any other function from sodiumoxide.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let (pk, sk) = sign::gen_keypair();
    (PublicKey::from(pk), SecretKey::from(sk))
}

/// Randomly generate a secret key and a corresponding public key, using the
/// ed25519 cryptographic primitive.
///
/// THREAD SAFETY: `gen_keypair()` is thread-safe provided that you have called
/// `sodiumoxide::init()` once before using any other function from sodiumoxide.
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

/// The suffix indicating the ed25519 cryptographic primitive.
const ED25519_SUFFIX: &'static str = ".ed25519";
/// Length of a base64 encoded ed25519 public key.
const ED25519_PK_BASE64_LEN: usize = 44;
/// Length of an encoded ssb `PublicKey` which uses the ed25519 cryptographic primitive.
const SSB_PK_ED25519_ENCODED_LEN: usize = ED25519_PK_BASE64_LEN + 8;
/// Length of a base64 encoded ed25519 secret key.
const ED25519_SK_BASE64_LEN: usize = 88;
/// Length of an encoded ssb `SecretKey` which uses the ed25519 cryptographic primitive.
const SSB_SK_ED25519_ENCODED_LEN: usize = ED25519_SK_BASE64_LEN + 8;

lazy_static! {
    static ref PUBLIC_KEY_RE: Regex = RegexBuilder::new(r"^[0-9A-Za-z\+/]{43}=\.ed25519$").dot_matches_new_line(true).build().unwrap();

    static ref SECRET_KEY_RE: Regex = RegexBuilder::new(r"^[0-9A-Za-z\+/]{86}==\.ed25519$").dot_matches_new_line(true).build().unwrap();
}

/// Check whether a given string is the encoding of a `PublicKey`.
pub fn encodes_public_key(enc: &str) -> bool {
    PUBLIC_KEY_RE.is_match(enc)
}

/// Check whether a given string is the encoding of a `SecretKey`.
pub fn encodes_secret_key(enc: &str) -> bool {
    SECRET_KEY_RE.is_match(enc)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::{to_string, from_str};

    #[test]
    fn ed25519() {
        let (pk, sk) = gen_keypair_ed25519();
        assert!(pk.matches_secret_key(&sk));

        let plain_text = [0u8, 1, 2, 3, 4, 5, 6, 7];

        let signed_text = sk.sign(&plain_text);
        assert_eq!(&pk.verify(&signed_text).unwrap()[..], &plain_text[..]);

        let detached_sig = sk.sign_detached(&plain_text);
        assert!(pk.verify_detached(&detached_sig, &plain_text));
    }

    #[test]
    fn test_encodes_public_key() {
        assert!(encodes_public_key("zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"));
        // too short
        assert!(!encodes_public_key("urF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"));
        // too long
        assert!(!encodes_public_key("azurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"));
        // invalid character
        assert!(!encodes_public_key("-urF8X68ArfRM71dFmKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"));
        // very invalid character
        assert!(!encodes_public_key("💖8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"));
        // incorrect suffix
        assert!(!encodes_public_key("zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25518"));
        // no trailing =
        assert!(!encodes_public_key("zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hAf.ed25518"));
    }

    #[test]
    fn test_encodes_secret_key() {
        assert!(encodes_secret_key("KISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"));
        // too short
        assert!(!encodes_secret_key("ISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"));
        // too long
        assert!(!encodes_secret_key("aKISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"));
        // invalid character
        assert!(!encodes_secret_key("-ISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"));
        // very invalid character
        assert!(!encodes_secret_key("💖ctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"));
        // incorrect suffix
        assert!(!encodes_secret_key("aKISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25518"));
        // no trailing ==
        assert!(!encodes_secret_key("aKISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQf=.ed25519"));
    }

    #[test]
    fn serde_ed25519() {
        let (pk, sk) = gen_keypair_ed25519();
        let pk_enc = to_string(&pk).unwrap();
        let sk_enc = to_string(&sk).unwrap();

        assert_eq!(from_str::<PublicKey>(&pk_enc).unwrap(), pk);
        assert_eq!(from_str::<SecretKey>(&sk_enc).unwrap(), sk);

        let parsed_pk = from_str::<PublicKey>("\"zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519\"")
            .unwrap();
        assert!(parsed_pk.is_ed25519());

        // too short
        assert!(from_str::<PublicKey>("\"urF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519\"")
                    .is_err());
        // too long
        assert!(from_str::<PublicKey>("\"azurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519\"")
                    .is_err());
        // invalid character
        assert!(from_str::<PublicKey>("\"-urF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519\"")
                    .is_err());
        // very invalid character
        assert!(from_str::<PublicKey>("\"💖8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519\"")
                    .is_err());
        // invalid suffix
        assert!(from_str::<PublicKey>("\"zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25518\"")
                    .is_err());
        // no trailing =
        assert!(from_str::<PublicKey>("\"zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hAf.ed25519\"")
                    .is_err());

        let parsed_sk = from_str::<SecretKey>("\"KISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519\"").unwrap();
        assert!(parsed_sk.is_ed25519());

        // too short
        assert!(from_str::<SecretKey>("\"ISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519\"").is_err());
        // too long
        assert!(from_str::<SecretKey>("\"aKISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519\"").is_err());
        // invalid character
        assert!(from_str::<SecretKey>("\"-ISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519\"").is_err());
        // very invalid character
        assert!(from_str::<SecretKey>("\"💖ctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519\"").is_err());
        // invalid suffix
        assert!(from_str::<SecretKey>("\"KISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25518\"").is_err());
        // no trailing ==
        assert!(from_str::<SecretKey>("\"KISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQf=.ed25519\"").is_err());
    }
}
