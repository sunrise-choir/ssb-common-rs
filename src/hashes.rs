//! Operations for dealing with the hashes used in ssb.
//!
//! The `Hash`type abstracts over the (potentially multiple) cryptographic primitives supported by
//! ssb. This module also implements the encoding used in ssb to store and transmit hashes.

use std::convert::{From, TryInto};
use std::str::FromStr;
use std::ops::{Index, Range, RangeTo, RangeFrom, RangeFull};
use std::fmt;

use sodiumoxide::crypto::hash::sha256;
use base64::{encode_config_buf, decode_config_slice, STANDARD};
use serde::{self, Serialize, Serializer, Deserialize, Deserializer};
use regex::Regex;

/// An ssb hash. This type abstracts over the fact that ssb can support multiple cryptographic
/// primitives.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(_Hash);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum _Hash {
    // A sha256 hash, as used by `sodiumoxide::crypto::hash::sha256`.
    Sha256(sha256::Digest),
}

/// Hash a message and return an ssb `Hash`. This function does not specifiy which cryptographic
/// primitive it will use and should be preferred over those that do.
pub fn hash(m: &[u8]) -> Hash {
    hash_sha256(m)
}

/// Hash a message and return an ssb `Hash`, using the sha256 cryptographic primitive.
pub fn hash_sha256(m: &[u8]) -> Hash {
    Hash::from(sha256::hash(m))
}

impl Hash {
    /// Return the length (in bytes) of the hash digest.
    pub fn len(&self) -> usize {
        match self.0 {
            _Hash::Sha256(_) => sha256::DIGESTBYTES,
        }
    }

    /// Return whether this `Hash` uses the sha256 cryptographic primitive.
    pub fn is_sha256(&self) -> bool {
        match self.0 {
            _Hash::Sha256(_) => true,
        }
    }

    /// Return whether this `Hash` uses a cryptographic primitive that is
    /// currently considered secure.
    ///
    /// The return value of this method may change as new versions of this
    /// module are released.
    pub fn is_considered_secure(&self) -> bool {
        match self.0 {
            _Hash::Sha256(_) => true,
        }
    }

    /// Encode the `Hash` as a `String`.
    pub fn to_encoding(&self) -> String {
        match self.0 {
            _Hash::Sha256(ref bytes) => {
                let mut buf = String::with_capacity(SSB_DIGEST_SHA256_ENCODED_LEN);
                encode_config_buf(bytes, STANDARD, &mut buf);
                debug_assert!(buf.len() == SHA256_DIGEST_BASE64_LEN);

                buf.push_str(SHA256_SUFFIX);
                debug_assert!(buf.len() == SSB_DIGEST_SHA256_ENCODED_LEN);

                buf
            }
        }
    }

    /// The length of the `String` returned by `self.to_encoding()`.
    pub fn encoding_len(&self) -> usize {
        match self.0 {
            _Hash::Sha256(_) => SSB_DIGEST_SHA256_ENCODED_LEN,
        }
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_encoding())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The error when failing to parse a `Hash` from a string.
#[derive(Debug, Copy, Clone)]
pub struct HashParseError;

impl fmt::Display for HashParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid hash encoding")
    }
}

/// This can be used to parse an encoded `Hash`.
impl FromStr for Hash {
    /// Fails if the given string does not contain an encoding of a `Hash`.
    type Err = HashParseError;

    fn from_str(enc: &str) -> Result<Hash, HashParseError> {
        if !encodes_hash(enc) {
            Err(HashParseError)
        } else {
            let mut buf = [0; sha256::DIGESTBYTES];

            match decode_config_slice(&enc[..SHA256_DIGEST_BASE64_LEN], STANDARD, &mut buf) {
                Ok(_) => Ok(Hash(_Hash::Sha256(sha256::Digest(buf)))),
                Err(_) => Err(HashParseError),
            }
        }

    }
}

impl From<sha256::Digest> for Hash {
    fn from(sha256_digest: sha256::Digest) -> Hash {
        Hash(_Hash::Sha256(sha256_digest))
    }
}

impl TryInto<sha256::Digest> for Hash {
    /// Fails if the underlying cryptographic primitive is not sha256.
    type Error = ();

    fn try_into(self) -> Result<sha256::Digest, Self::Error> {
        match self.0 {
            _Hash::Sha256(digest) => Ok(digest),
        }
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        match self.0 {
            _Hash::Sha256(ref digest) => digest.as_ref(),
        }
    }
}

/// Allows to access the byte contents of a `Hash` as a slice.
impl Index<Range<usize>> for Hash {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        match self.0 {
            _Hash::Sha256(ref digest) => digest.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `Hash` as a slice.
impl Index<RangeTo<usize>> for Hash {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        match self.0 {
            _Hash::Sha256(ref digest) => digest.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `Hash` as a slice.
impl Index<RangeFrom<usize>> for Hash {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        match self.0 {
            _Hash::Sha256(ref digest) => digest.index(_index),
        }
    }
}

/// Allows to access the byte contents of a `Hash` as a slice.
impl Index<RangeFull> for Hash {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        match self.0 {
            _Hash::Sha256(ref digest) => digest.index(_index),
        }
    }
}

/// The suffix indicating the sha256 cryptographic primitive.
const SHA256_SUFFIX: &'static str = ".sha256";
/// Length of a base64 encoded ed25519 public key.
const SHA256_DIGEST_BASE64_LEN: usize = 44;
/// Length of an encoded ssb `PublicKey` which uses the ed25519 cryptographic primitive.
const SSB_DIGEST_SHA256_ENCODED_LEN: usize = SHA256_DIGEST_BASE64_LEN + 7;

lazy_static! {
    static ref HASH_RE: Regex = Regex::new(r"^[0-9A-Za-z\+/]{43}=\.sha256$").unwrap();
}

/// Check whether a given string is the encoding of a `Hash`.
pub fn encodes_hash(enc: &str) -> bool {
    HASH_RE.is_match(enc)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::{to_string, from_str};

    #[test]
    fn test_encodes_hash() {
        assert!(encodes_hash("zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha256"));
        // too short
        assert!(!encodes_hash("urF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha256"));
        // too long
        assert!(!encodes_hash("azurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha256"));
        // invalid character
        assert!(!encodes_hash("-urF8X68ArfRM71dFmKh36W0xDM8QmOnAS5bYOq8hA=.sha256"));
        // very invalid character
        assert!(!encodes_hash("💖8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha256"));
        // incorrect suffix
        assert!(!encodes_hash("zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha257"));
        // no trailing =
        assert!(!encodes_hash("zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hAf.sha256"));
    }

    #[test]
    fn serde_sha256() {
        let digest = hash_sha256(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let digest_enc = to_string(&digest).unwrap();

        assert_eq!(from_str::<Hash>(&digest_enc).unwrap(), digest);

        let parsed_digest = from_str::<Hash>("\"zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha256\"")
            .unwrap();
        assert!(parsed_digest.is_sha256());

        // too short
        assert!(from_str::<Hash>("\"urF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha256\"")
                    .is_err());
        // too long
        assert!(from_str::<Hash>("\"azurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha256\"")
                    .is_err());
        // invalid character
        assert!(from_str::<Hash>("\"-urF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha256\"")
                    .is_err());
        // very invalid character
        assert!(from_str::<Hash>("\"💖8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha256\"")
                    .is_err());
        // invalid suffix
        assert!(from_str::<Hash>("\"zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.sha255\"")
                    .is_err());
        // no trailing =
        assert!(from_str::<Hash>("\"zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hAf.sha256\"")
                    .is_err());
    }
}
