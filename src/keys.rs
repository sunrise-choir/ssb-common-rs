//! Operations for dealing with the public and secret keys used in ssb.
//!
//! The `PublicKey`, `SecretKey` and `Signature` types abstract over the
//! (potentially multiple) cryptographic primitives supported by ssb. These
//! types should be used when dealing with keys in application logic.
//!
//! Aside from providing these types, this module also implements the encoding
//! used in ssb to store and transmit keys.
//!
//! `PublicKeyEncodingBuf` (owned), `PublicKeyEncoding` (reference),
//! `SecretKeyEncodingBuf` (owned) and `SecretKeyEncoding` (reference) are
//! typesafe wrappers around `Strings` and `&str`s that always hold valid
//! encodings of ssb keys.
//!
//! When given strings which are expected to encode keys, the `FromStr` impls of
//! `PublicKey` and `SecretKey` should be used for decoding. Encodings should be
//! created via the `new` functions of `PublicKeyEnodingBuf` and
//! `SecretKeyEncodingBuf`.

use std::convert::{From, TryInto, TryFrom};
use std::str::FromStr;
use std::borrow::ToOwned;
use std::ops::{Index, Range, RangeTo, RangeFrom, RangeFull};
use std::fmt;

use sodiumoxide::crypto::sign;
use sodiumoxide::utils::memzero;
use base64::{encode_config_buf, decode_config_slice, STANDARD};
use regex::{Regex, RegexBuilder};

/// An ssb public key. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
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

    /// Return whether this `PublicKey` uses a cryptographic primitive that is
    /// currently considered secure.
    ///
    /// The return value of this method may change as new versions of this
    /// module are released.
    pub fn is_considered_secure(&self) -> bool {
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

    /// Create a `PublicKey` from a `PublicKeyEncoding`.
    ///
    /// Prefer to directly use the `FromStr` impl.
    pub fn from_encoding(enc: &PublicKeyEncoding) -> PublicKey {
        if enc.0.ends_with(ED25519_SUFFIX) {
            let mut bytes = [0u8; sign::PUBLICKEYBYTES];

            match decode_config_slice(&enc.0[..ED25519_PK_BASE64_LEN], STANDARD, &mut bytes) {
                Ok(len) => debug_assert!(len == sign::PUBLICKEYBYTES),
                Err(_) => unreachable!(),
            }

            PublicKey::Ed25519(sign::PublicKey(bytes))
        } else {
            unreachable!()
        }
    }
}

impl From<sign::PublicKey> for PublicKey {
    fn from(ed25519_pk: sign::PublicKey) -> PublicKey {
        PublicKey::Ed25519(ed25519_pk)
    }
}

impl TryInto<sign::PublicKey> for PublicKey {
    /// Fails if the underlying cryptographic primitive is not ed25519.
    type Error = ();

    fn try_into(self) -> Result<sign::PublicKey, Self::Error> {
        match self {
            PublicKey::Ed25519(pk) => Ok(pk),
        }
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

impl From<PublicKeyEncodingBuf> for PublicKey {
    fn from(enc: PublicKeyEncodingBuf) -> PublicKey {
        PublicKey::from_encoding(&enc.to_public_key_encoding())
    }
}

/// This can be used to parse an encoded `PublicKey`.
impl FromStr for PublicKey {
    /// Fails if the given string does not contain an encoding of a `PublicKey`.
    type Err = ();

    fn from_str(enc: &str) -> Result<PublicKey, ()> {
        if !encodes_public_key(enc) {
            Err(())
        } else {
            let mut buf = [0; sign::PUBLICKEYBYTES];

            match decode_config_slice(&enc[..ED25519_PK_BASE64_LEN], STANDARD, &mut buf) {
                Ok(_) => Ok(PublicKey::Ed25519(sign::PublicKey(buf))),
                Err(_) => Err(()),
            }
        }

    }
}

/// An ssb secret key. This type abstracts over the fact that ssb can support
/// multiple cryptographic primitives.
///
/// When a `SecretKey` goes out of scope its contents are zeroed out.
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

    /// Return whether this `SecretKey` uses a cryptographic primitive that is
    /// currently considered secure.
    ///
    /// The return value of this method may change as new versions of this
    /// module are released.
    pub fn is_considered_secure(&self) -> bool {
        match *self {
            SecretKey::Ed25519(_) => true,
        }
    }

    /// Create a `SecretKey` from a `SecretKeyEncoding`.
    ///
    /// Prefer to directly use the `FromStr` impl.
    pub fn from_encoding(enc: &SecretKeyEncoding) -> SecretKey {
        if enc.0.ends_with(ED25519_SUFFIX) {
            let mut bytes = [0u8; sign::SECRETKEYBYTES];

            match decode_config_slice(&enc.0[..ED25519_SK_BASE64_LEN], STANDARD, &mut bytes) {
                Ok(len) => debug_assert!(len == sign::SECRETKEYBYTES),
                Err(_) => unreachable!(),
            }

            SecretKey::Ed25519(sign::SecretKey(bytes))
        } else {
            unreachable!()
        }
    }
}

impl From<sign::SecretKey> for SecretKey {
    fn from(ed25519_sk: sign::SecretKey) -> SecretKey {
        SecretKey::Ed25519(ed25519_sk)
    }
}

impl TryInto<sign::SecretKey> for SecretKey {
    /// Fails if the underlying cryptographic primitive is not ed25519.
    type Error = ();

    fn try_into(self) -> Result<sign::SecretKey, Self::Error> {
        match self {
            SecretKey::Ed25519(sk) => Ok(sk),
        }
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

impl From<SecretKeyEncodingBuf> for SecretKey {
    fn from(enc: SecretKeyEncodingBuf) -> SecretKey {
        SecretKey::from_encoding(&enc.to_secret_key_encoding())
    }
}

/// This can be used to parse an encoded `SecretKey`.
impl FromStr for SecretKey {
    /// Fails if the given string does not contain an encoding of a `SecretKey`.
    type Err = ();

    fn from_str(enc: &str) -> Result<SecretKey, ()> {
        if !encodes_secret_key(enc) {
            Err(())
        } else {
            let mut buf = [0; sign::SECRETKEYBYTES];

            match decode_config_slice(&enc[..ED25519_SK_BASE64_LEN], STANDARD, &mut buf) {
                Ok(_) => Ok(SecretKey::Ed25519(sign::SecretKey(buf))),
                Err(_) => Err(()),
            }
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

    /// Return whether this `Signature` uses a cryptographic primitive that is
    /// currently considered secure.
    ///
    /// The return value of this method may change as new versions of this
    /// module are released.
    pub fn is_considered_secure(&self) -> bool {
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

impl TryInto<sign::Signature> for Signature {
    /// Fails if the underlying cryptographic primitive is not ed25519.
    type Error = ();

    fn try_into(self) -> Result<sign::Signature, Self::Error> {
        match self {
            Signature::Ed25519(sig) => Ok(sig),
        }
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

/// An owned utf8-encoding of a `PublicKey`.
///
/// This is a thin wrapper around `String`: Every `PublicKeyEncodingBuf` is also
/// a string (so the conversion is zero-cost), but not every `String` is the
/// encoding of a `PublicKey`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PublicKeyEncodingBuf(String);

impl PublicKeyEncodingBuf {
    /// Create a new `PublicKeyEncodingBuf`, encoding the given `PublicKey`.
    fn new(pk: &PublicKey) -> PublicKeyEncodingBuf {
        match *pk {
            PublicKey::Ed25519(ref bytes) => {
                let mut buf = String::with_capacity(SSB_PK_ED25519_ENCODED_LEN);
                encode_config_buf(bytes, STANDARD, &mut buf);
                debug_assert!(buf.len() == ED25519_PK_BASE64_LEN);

                buf.push_str(ED25519_SUFFIX);
                debug_assert!(buf.len() == SSB_PK_ED25519_ENCODED_LEN);

                PublicKeyEncodingBuf(buf)
            }
        }
    }

    /// Convert into a `PublicKeyEncoding` (which behaves like a reference).
    pub fn to_public_key_encoding(&self) -> PublicKeyEncoding {
        PublicKeyEncoding(&self.0)
    }
}

impl From<PublicKey> for PublicKeyEncodingBuf {
    fn from(pk: PublicKey) -> PublicKeyEncodingBuf {
        PublicKeyEncodingBuf::new(&pk)
    }
}

/// Convert into a `String` (zero-cost operation).
impl Into<String> for PublicKeyEncodingBuf {
    fn into(self) -> String {
        self.0
    }
}

/// Use this `PublicKeyEncondingBuf` as an `str` reference (zero-cost operation).
impl AsRef<str> for PublicKeyEncodingBuf {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PublicKeyEncodingBuf {
    type Error = ();
    fn try_from(enc: String) -> Result<Self, Self::Error> {
        if encodes_public_key(&enc) {
            Ok(PublicKeyEncodingBuf(enc))
        } else {
            Err(())
        }
    }
}

/// A reference to a utf8-encoding of a `PublicKey`.
///
/// This is a thin wrapper around `str`: Every `PublicKeyEncoding` is also
/// an str (so the conversion is zero-cost), but not every `str` is the
/// encoding of a `PublicKey`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PublicKeyEncoding<'a>(&'a str);

impl<'a> PublicKeyEncoding<'a> {
    /// Convert into an owned `PublicKeyEncodingBuf`.
    pub fn to_public_key_encoding_buf(&self) -> PublicKeyEncodingBuf {
        PublicKeyEncodingBuf(self.0.to_owned())
    }
}

/// Use this `PublicKeyEnconding` as an `str` reference (zero-cost operation).
impl<'a> AsRef<str> for PublicKeyEncoding<'a> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'a> TryFrom<&'a str> for PublicKeyEncoding<'a> {
    type Error = ();
    fn try_from(enc: &'a str) -> Result<Self, Self::Error> {
        if encodes_public_key(enc) {
            Ok(PublicKeyEncoding(enc))
        } else {
            Err(())
        }
    }
}

/// An owned utf8-encoding of a `SecretKey`.
///
/// This is a thin wrapper around `String`: Every `SecretKeyEncodingBuf` is also
/// a string (so the conversion is zero-cost), but not every `String` is the
/// encoding of a `SecretKey`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKeyEncodingBuf(String);

impl SecretKeyEncodingBuf {
    /// Create a new `PublicKeyEncodingBuf`, encoding the given `PublicKey`.
    pub fn new(sk: &SecretKey) -> SecretKeyEncodingBuf {
        match *sk {
            SecretKey::Ed25519(ref bytes) => {
                let mut buf = String::with_capacity(SSB_SK_ED25519_ENCODED_LEN);
                encode_config_buf(&bytes[..], STANDARD, &mut buf);
                debug_assert!(buf.len() == ED25519_SK_BASE64_LEN);

                buf.push_str(ED25519_SUFFIX);
                debug_assert!(buf.len() == SSB_SK_ED25519_ENCODED_LEN);

                SecretKeyEncodingBuf(buf)
            }
        }
    }

    /// Convert into a `SecretKeyEncoding` (which behaves like a reference).
    pub fn to_secret_key_encoding(&self) -> SecretKeyEncoding {
        SecretKeyEncoding(&self.0)
    }
}

impl fmt::Debug for SecretKeyEncodingBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecretKeyEncodingBuf(\"****.ed25519\")")
    }
}

impl Drop for SecretKeyEncodingBuf {
    /// Zero out the memory.
    fn drop(&mut self) {
        memzero(unsafe { self.0.as_bytes_mut() })
    }
}

impl From<SecretKey> for SecretKeyEncodingBuf {
    fn from(sk: SecretKey) -> SecretKeyEncodingBuf {
        SecretKeyEncodingBuf::new(&sk)
    }
}

/// Use this `SecretKeyEncondingBuf` as an `str` reference (zero-cost operation).
impl AsRef<str> for SecretKeyEncodingBuf {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretKeyEncodingBuf {
    type Error = ();
    fn try_from(enc: String) -> Result<Self, Self::Error> {
        if encodes_secret_key(&enc) {
            Ok(SecretKeyEncodingBuf(enc))
        } else {
            Err(())
        }
    }
}

/// A reference to a utf8-encoding of a `SecretKey`.
///
/// This is a thin wrapper around `str`: Every `SecretKeyEncoding` is also
/// an str (so the conversion is zero-cost), but not every `str` is the
/// encoding of a `SecretKey`.
#[derive(PartialEq, Eq)]
pub struct SecretKeyEncoding<'a>(&'a str);

impl<'a> SecretKeyEncoding<'a> {
    /// Convert into an owned `SecretKeyEncodingBuf`.
    pub fn to_secret_key_encoding_buf(&self) -> SecretKeyEncodingBuf {
        SecretKeyEncodingBuf(self.0.to_owned())
    }
}

impl<'a> fmt::Debug for SecretKeyEncoding<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecretKeyEncoding(\"****.ed25519\")")
    }
}

/// Use this `SecretKeyEnconding` as an `str` reference (zero-cost operation).
impl<'a> AsRef<str> for SecretKeyEncoding<'a> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'a> TryFrom<&'a str> for SecretKeyEncoding<'a> {
    type Error = ();
    fn try_from(enc: &'a str) -> Result<Self, Self::Error> {
        if encodes_secret_key(enc) {
            Ok(SecretKeyEncoding(enc))
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn encoding_ed25519() {
        let (pk, sk) = gen_keypair_ed25519();
        let pk_enc = PublicKeyEncodingBuf::from(pk.clone());
        let sk_enc = SecretKeyEncodingBuf::from(sk.clone());

        assert_eq!(PublicKey::from(pk_enc.clone()), pk);
        assert_eq!(SecretKey::from(sk_enc.clone()), sk);

        let parsed_pk = "zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"
            .parse::<PublicKey>()
            .unwrap();
        assert!(parsed_pk.is_ed25519());

        // too short
        assert!("urF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"
                    .parse::<PublicKey>()
                    .is_err());
        // too long
        assert!("azurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"
                    .parse::<PublicKey>()
                    .is_err());
        // invalid character
        assert!("-urF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"
                    .parse::<PublicKey>()
                    .is_err());
        // very invalid character
        assert!("💖8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519"
                    .parse::<PublicKey>()
                    .is_err());
        // invalid suffix
        assert!("zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25518"
                    .parse::<PublicKey>()
                    .is_err());
        // no trailing =
        assert!("zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hAf.ed25519"
                    .parse::<PublicKey>()
                    .is_err());

        let parsed_sk = "KISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"
            .parse::<SecretKey>()
            .unwrap();
        assert!(parsed_sk.is_ed25519());

        // too short
        assert!("ISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"
                    .parse::<SecretKey>()
                    .is_err());
        // too long
        assert!("aKISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"
                    .parse::<SecretKey>()
                    .is_err());
        // invalid character
        assert!("-ISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"
                    .parse::<SecretKey>()
                    .is_err());
        // very invalid character
        assert!("💖ctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25519"
                    .parse::<SecretKey>()
                    .is_err());
        // invalid suffix
        assert!("KISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQ==.ed25518"
                    .parse::<SecretKey>()
                    .is_err());
        // no trailing ==
        assert!("KISUctzp8hH6VGSsG0drx+b3AFDuU1Q9/qX0gxtcOt9cDW7SbU0x7DJqlQ42fbpoPYjdJSO7Wty4a6JLu9NOJQf=.ed25519"
                    .parse::<SecretKey>()
                    .is_err());
    }
}
