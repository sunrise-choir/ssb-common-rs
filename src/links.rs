//! The cypherlinks used in ssb.

use std::convert::From;
use std::fmt;
use std::str::FromStr;

use serde::{self, Serialize, Serializer, Deserialize, Deserializer};

use keys::PublicKey;
use hashes::Hash as SSBHash;

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

/// The id of a feed, referencing a `PublicKey` instead of owning it.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeedIdRef<'a>(&'a PublicKey);

impl<'a> FeedIdRef<'a> {
    /// Create a new `FeedIdRef` for the given `&'a PublicKey`.
    pub fn new(pk: &'a PublicKey) -> FeedIdRef<'a> {
        FeedIdRef(pk)
    }

    /// Get a reference to the underlying `PublicKey`.
    pub fn get_ref(&self) -> &PublicKey {
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

impl<'a> Serialize for FeedIdRef<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_encoding())
    }
}

/// The id of a message.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(SSBHash);

impl MessageId {
    /// Create a new `MessageId` for the given `Hash`.
    pub fn new(hash: SSBHash) -> MessageId {
        MessageId(hash)
    }

    /// Get a reference to the underlying `Hash`.
    pub fn get_ref(&self) -> &SSBHash {
        &self.0
    }

    /// Unwrap this `MessageId`, returning the underlying `Hash`.
    pub fn into_inner(self) -> SSBHash {
        self.0
    }

    /// Encode the `MessageId` as a `String`.
    pub fn to_encoding(&self) -> String {
        let mut buf = String::with_capacity(self.0.encoding_len());
        buf.push_str("%");
        buf.push_str(&self.0.to_encoding());
        buf
    }

    /// The length of the `String` returned by `self.to_encoding()`.
    pub fn encoding_len(&self) -> usize {
        1 + self.0.encoding_len()
    }
}

impl Serialize for MessageId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_encoding())
    }
}

impl<'de> Deserialize<'de> for MessageId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The error when failing to parse a `MessageId` from a string.
#[derive(Debug, Copy, Clone)]
pub struct MessageIdParseError;

impl fmt::Display for MessageIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid message id encoding")
    }
}

/// This can be used to parse an encoded `MessageId`.
impl FromStr for MessageId {
    /// Fails if the given string does not contain an encoding of a `MessageId`.
    type Err = MessageIdParseError;

    fn from_str(enc: &str) -> Result<MessageId, MessageIdParseError> {
        if enc.starts_with("%") {
            enc[1..]
                .parse::<SSBHash>()
                .map(|hash| MessageId(hash))
                .map_err(|_| MessageIdParseError)
        } else {
            Err(MessageIdParseError)
        }
    }
}

impl From<SSBHash> for MessageId {
    fn from(hash: SSBHash) -> MessageId {
        MessageId::new(hash)
    }
}

impl From<MessageId> for SSBHash {
    fn from(message_id: MessageId) -> SSBHash {
        message_id.0
    }
}

/// The id of a message, referencing a `Hash` instead of owning it.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageIdRef<'a>(&'a SSBHash);

impl<'a> MessageIdRef<'a> {
    /// Create a new `MessageIdRef` for the given `&'a Hash`.
    pub fn new(hash: &'a SSBHash) -> MessageIdRef<'a> {
        MessageIdRef(hash)
    }

    /// Get a reference to the underlying `Hash`.
    pub fn get_ref(&self) -> &SSBHash {
        self.0
    }

    /// Encode the `MessageId` as a `String`.
    pub fn to_encoding(&self) -> String {
        let mut buf = String::with_capacity(self.0.encoding_len());
        buf.push_str("%");
        buf.push_str(&self.0.to_encoding());
        buf
    }

    /// The length of the `String` returned by `self.to_encoding()`.
    pub fn encoding_len(&self) -> usize {
        1 + self.0.encoding_len()
    }
}

impl<'a> Serialize for MessageIdRef<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_encoding())
    }
}

// TODO BlobId, Link (an enum of either a FeedId, MsgId or BlobId)

#[cfg(test)]
mod tests {
    use serde_json::{to_string, from_str};

    use super::*;
    use keys::gen_keypair;
    use hashes::hash;

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

    #[test]
    fn serde_message_id() {
        assert!("".parse::<MessageId>().is_err());
        assert!("@".parse::<MessageId>().is_err());
        assert!("%".parse::<MessageId>().is_err());
        assert!("@foo".parse::<MessageId>().is_err());

        let digest = hash(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let message_id = MessageId::new(digest);
        let message_id_enc = to_string(&message_id).unwrap();

        assert_eq!(from_str::<MessageId>(&message_id_enc).unwrap(), message_id);
    }
}
