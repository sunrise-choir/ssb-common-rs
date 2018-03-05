//! The cypherlinks used in ssb.

use std::convert::From;
use std::fmt;
use std::str::FromStr;

use serde::{self, Serialize, Serializer, Deserialize, Deserializer};

use keys::PublicKey;

/// The id of a feed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeedId(PublicKey);

impl FeedId {
    /// Create a new `FeedId` for the given `PublicKey`.
    pub fn new(pk: PublicKey) -> FeedId {
        FeedId(pk)
    }

    /// Get a reference to the underlying `PublicKey`.
    pub fn get_ref(&self) -> &PublicKey {
        &self.0
    }

    /// Unwrap this `FeedId`, returning the underlying `PublicKey`.
    pub fn into_inner(self) -> PublicKey {
        self.0
    }

    /// Encode the `FeedId` as a `String`.
    pub fn to_encoding(&self) -> String {
        let mut buf = String::with_capacity(self.0.encoding_len());
        buf.push_str("@");
        buf.push_str(&self.0.to_encoding());
        buf
    }

    /// The length of the `String` returned by `self.to_encoding()`.
    pub fn encoding_len(&self) -> usize {
        1 + self.0.encoding_len()
    }
}

impl Serialize for FeedId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_encoding())
    }
}

impl<'de> Deserialize<'de> for FeedId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The error when failing to parse a `FeedId` from a string.
#[derive(Debug, Copy, Clone)]
pub struct FeedIdParseError;

impl fmt::Display for FeedIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid feed id encoding")
    }
}

/// This can be used to parse an encoded `FeedId`.
impl FromStr for FeedId {
    /// Fails if the given string does not contain an encoding of a `FeedId`.
    type Err = FeedIdParseError;

    fn from_str(enc: &str) -> Result<FeedId, FeedIdParseError> {
        if enc.starts_with("@") {
            enc[1..]
                .parse::<PublicKey>()
                .map(|pk| FeedId(pk))
                .map_err(|_| FeedIdParseError)
        } else {
            Err(FeedIdParseError)
        }
    }
}

impl From<PublicKey> for FeedId {
    fn from(pk: PublicKey) -> FeedId {
        FeedId::new(pk)
    }
}

impl From<FeedId> for PublicKey {
    fn from(feed_id: FeedId) -> PublicKey {
        feed_id.0
    }
}

// TODO MsgId, BlobId, Link (an enum of either a FeedId, MsgId or BlobId)

#[cfg(test)]
mod tests {
    use serde_json::{to_string, from_str};

    use super::*;
    use keys::gen_keypair;

    #[test]
    fn serde_feed_id() {
        assert!("".parse::<FeedId>().is_err());
        assert!("@".parse::<FeedId>().is_err());
        assert!("%".parse::<FeedId>().is_err());
        assert!("@foo".parse::<FeedId>().is_err());

        let (pk, _) = gen_keypair();
        let feed_id = FeedId::new(pk);
        let feed_id_enc = to_string(&feed_id).unwrap();

        assert_eq!(from_str::<FeedId>(&feed_id_enc).unwrap(), feed_id);
    }
}
