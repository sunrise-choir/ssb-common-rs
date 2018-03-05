//! The cypherlinks used in ssb.

use std::convert::{From, TryInto};
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

    /// Encode the `MessageIdRef` as a `String`.
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

/// The id of a blob.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId(SSBHash);

impl BlobId {
    /// Create a new `BlobId` for the given `Hash`.
    pub fn new(hash: SSBHash) -> BlobId {
        BlobId(hash)
    }

    /// Get a reference to the underlying `Hash`.
    pub fn get_ref(&self) -> &SSBHash {
        &self.0
    }

    /// Unwrap this `BlobId`, returning the underlying `Hash`.
    pub fn into_inner(self) -> SSBHash {
        self.0
    }

    /// Encode the `BlobId` as a `String`.
    pub fn to_encoding(&self) -> String {
        let mut buf = String::with_capacity(self.0.encoding_len());
        buf.push_str("&");
        buf.push_str(&self.0.to_encoding());
        buf
    }

    /// The length of the `String` returned by `self.to_encoding()`.
    pub fn encoding_len(&self) -> usize {
        1 + self.0.encoding_len()
    }
}

impl Serialize for BlobId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_encoding())
    }
}

impl<'de> Deserialize<'de> for BlobId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The error when failing to parse a `BlobId` from a string.
#[derive(Debug, Copy, Clone)]
pub struct BlobIdParseError;

impl fmt::Display for BlobIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid blob id encoding")
    }
}

/// This can be used to parse an encoded `BlobId`.
impl FromStr for BlobId {
    /// Fails if the given string does not contain an encoding of a `BlobId`.
    type Err = BlobIdParseError;

    fn from_str(enc: &str) -> Result<BlobId, BlobIdParseError> {
        if enc.starts_with("&") {
            enc[1..]
                .parse::<SSBHash>()
                .map(|hash| BlobId(hash))
                .map_err(|_| BlobIdParseError)
        } else {
            Err(BlobIdParseError)
        }
    }
}

impl From<SSBHash> for BlobId {
    fn from(hash: SSBHash) -> BlobId {
        BlobId::new(hash)
    }
}

impl From<BlobId> for SSBHash {
    fn from(blob_id: BlobId) -> SSBHash {
        blob_id.0
    }
}

/// The id of a blob, referencing a `Hash` instead of owning it.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobIdRef<'a>(&'a SSBHash);

impl<'a> BlobIdRef<'a> {
    /// Create a new `BlobIdRef` for the given `&'a Hash`.
    pub fn new(hash: &'a SSBHash) -> BlobIdRef<'a> {
        BlobIdRef(hash)
    }

    /// Get a reference to the underlying `Hash`.
    pub fn get_ref(&self) -> &SSBHash {
        self.0
    }

    /// Encode the `BlobIdRef` as a `String`.
    pub fn to_encoding(&self) -> String {
        let mut buf = String::with_capacity(self.0.encoding_len());
        buf.push_str("&");
        buf.push_str(&self.0.to_encoding());
        buf
    }

    /// The length of the `String` returned by `self.to_encoding()`.
    pub fn encoding_len(&self) -> usize {
        1 + self.0.encoding_len()
    }
}

impl<'a> Serialize for BlobIdRef<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_encoding())
    }
}

/// A cypherlink, either the id of a feed, a message or a blob.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Link {
    /// A feed id.
    Feed(FeedId),
    /// A message id.
    Message(MessageId),
    /// A blob id.
    Blob(BlobId),
}

impl Link {
    /// Returns whether this `Link` is a feed id.
    pub fn is_feed(&self) -> bool {
        match *self {
            Link::Feed(_) => true,
            _ => false,
        }
    }

    /// Returns whether this `Link` is a message id.
    pub fn is_message(&self) -> bool {
        match *self {
            Link::Message(_) => true,
            _ => false,
        }
    }

    /// Returns whether this `Link` is a blob id.
    pub fn is_blob(&self) -> bool {
        match *self {
            Link::Blob(_) => true,
            _ => false,
        }
    }
}

impl Serialize for Link {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        match self {
            &Link::Feed(feed_id) => feed_id.serialize(serializer),
            &Link::Message(message_id) => message_id.serialize(serializer),
            &Link::Blob(blob_id) => blob_id.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Link {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The error when failing to parse a `Link` from a string.
#[derive(Debug, Copy, Clone)]
pub struct LinkParseError;

impl fmt::Display for LinkParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid link encoding")
    }
}

/// This can be used to parse an encoded `Link`.
impl FromStr for Link {
    /// Fails if the given string does not contain an encoding of a `Link`.
    type Err = LinkParseError;

    fn from_str(enc: &str) -> Result<Link, LinkParseError> {
        if enc.starts_with("@") {
            enc.parse::<FeedId>()
                .map(|feed_id| Link::Feed(feed_id))
                .map_err(|_| LinkParseError)
        } else if enc.starts_with("%") {
            enc.parse::<MessageId>()
                .map(|message_id| Link::Message(message_id))
                .map_err(|_| LinkParseError)
        } else if enc.starts_with("&") {
            enc.parse::<BlobId>()
                .map(|blob_id| Link::Blob(blob_id))
                .map_err(|_| LinkParseError)
        } else {
            Err(LinkParseError)
        }
    }
}

impl From<FeedId> for Link {
    fn from(feed_id: FeedId) -> Link {
        Link::Feed(feed_id)
    }
}

impl TryInto<FeedId> for Link {
    /// Fails if the the link is not a feed id.
    type Error = ();

    fn try_into(self) -> Result<FeedId, Self::Error> {
        match self {
            Link::Feed(feed_id) => Ok(feed_id),
            _ => Err(()),
        }
    }
}

impl From<MessageId> for Link {
    fn from(message_id: MessageId) -> Link {
        Link::Message(message_id)
    }
}

impl TryInto<MessageId> for Link {
    /// Fails if the the link is not a message id.
    type Error = ();

    fn try_into(self) -> Result<MessageId, Self::Error> {
        match self {
            Link::Message(message_id) => Ok(message_id),
            _ => Err(()),
        }
    }
}

impl From<BlobId> for Link {
    fn from(blob_id: BlobId) -> Link {
        Link::Blob(blob_id)
    }
}

impl TryInto<BlobId> for Link {
    /// Fails if the the link is not a blob id.
    type Error = ();

    fn try_into(self) -> Result<BlobId, Self::Error> {
        match self {
            Link::Blob(blob_id) => Ok(blob_id),
            _ => Err(()),
        }
    }
}

/// A cypherlink, either the id of a feed, a message or a blob. This references its content rather
/// than owning it.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinkRef<'a> {
    /// A feed id.
    Feed(FeedIdRef<'a>),
    /// A message id.
    Message(MessageIdRef<'a>),
    /// A blob id.
    Blob(BlobIdRef<'a>),
}

impl<'a> LinkRef<'a> {
    /// Returns whether this `LinkRef` is a feed id.
    pub fn is_feed(&self) -> bool {
        match *self {
            LinkRef::Feed(_) => true,
            _ => false,
        }
    }

    /// Returns whether this `LinkRef` is a message id.
    pub fn is_message(&self) -> bool {
        match *self {
            LinkRef::Message(_) => true,
            _ => false,
        }
    }

    /// Returns whether this `LinkRef` is a blob id.
    pub fn is_blob(&self) -> bool {
        match *self {
            LinkRef::Blob(_) => true,
            _ => false,
        }
    }
}

impl<'a> Serialize for LinkRef<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        match self {
            &LinkRef::Feed(feed_id) => feed_id.serialize(serializer),
            &LinkRef::Message(message_id) => message_id.serialize(serializer),
            &LinkRef::Blob(blob_id) => blob_id.serialize(serializer),
        }
    }
}

impl<'a> From<FeedIdRef<'a>> for LinkRef<'a> {
    fn from(feed_id: FeedIdRef<'a>) -> LinkRef<'a> {
        LinkRef::Feed(feed_id)
    }
}

impl<'a> TryInto<FeedIdRef<'a>> for LinkRef<'a> {
    /// Fails if the the link is not a feed id.
    type Error = ();

    fn try_into(self) -> Result<FeedIdRef<'a>, Self::Error> {
        match self {
            LinkRef::Feed(feed_id) => Ok(feed_id),
            _ => Err(()),
        }
    }
}

impl<'a> From<MessageIdRef<'a>> for LinkRef<'a> {
    fn from(message_id: MessageIdRef<'a>) -> LinkRef<'a> {
        LinkRef::Message(message_id)
    }
}

impl<'a> TryInto<MessageIdRef<'a>> for LinkRef<'a> {
    /// Fails if the the link is not a message id.
    type Error = ();

    fn try_into(self) -> Result<MessageIdRef<'a>, Self::Error> {
        match self {
            LinkRef::Message(message_id) => Ok(message_id),
            _ => Err(()),
        }
    }
}

impl<'a> From<BlobIdRef<'a>> for LinkRef<'a> {
    fn from(blob_id: BlobIdRef<'a>) -> LinkRef<'a> {
        LinkRef::Blob(blob_id)
    }
}

impl<'a> TryInto<BlobIdRef<'a>> for LinkRef<'a> {
    /// Fails if the the link is not a blob id.
    type Error = ();

    fn try_into(self) -> Result<BlobIdRef<'a>, Self::Error> {
        match self {
            LinkRef::Blob(blob_id) => Ok(blob_id),
            _ => Err(()),
        }
    }
}

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
        assert!("%".parse::<MessageId>().is_err());
        assert!("@".parse::<MessageId>().is_err());
        assert!("%foo".parse::<MessageId>().is_err());

        let digest = hash(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let message_id = MessageId::new(digest);
        let message_id_enc = to_string(&message_id).unwrap();

        assert_eq!(from_str::<MessageId>(&message_id_enc).unwrap(), message_id);
    }

    #[test]
    fn serde_blob_id() {
        assert!("".parse::<BlobId>().is_err());
        assert!("&".parse::<BlobId>().is_err());
        assert!("%".parse::<BlobId>().is_err());
        assert!("&foo".parse::<BlobId>().is_err());

        let digest = hash(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let blob_id = BlobId::new(digest);
        let blob_id_enc = to_string(&blob_id).unwrap();

        assert_eq!(from_str::<BlobId>(&blob_id_enc).unwrap(), blob_id);
    }

    #[test]
    fn serde_link() {
        let (pk, _) = gen_keypair();
        let feed_link = Link::from(FeedId::new(pk));
        let feed_link_enc = to_string(&feed_link).unwrap();
        assert_eq!(from_str::<Link>(&feed_link_enc).unwrap(), feed_link);

        let message_digest = hash(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let message_link = Link::from(MessageId::new(message_digest));
        let message_link_enc = to_string(&message_link).unwrap();
        assert_eq!(from_str::<Link>(&message_link_enc).unwrap(), message_link);

        let blob_digest = hash(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let blob_link = Link::from(BlobId::new(blob_digest));
        let blob_link_enc = to_string(&blob_link).unwrap();
        assert_eq!(from_str::<Link>(&blob_link_enc).unwrap(), blob_link);
    }
}
