//! The messages used in ssb.

use serde_json::Number;

use links::{MessageId, FeedId};

/// The timestamps used in ssb.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Timestamp(Number);

/// The sequence numbers used in ssb.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SequenceNumber(Number);

/// A message (the kind of thing that is stored in the database).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Message<T> {
    previous: Option<MessageId>,
    author: FeedId,
    sequence: SequenceNumber,
    timestamp: Timestamp,
    hash: PossibleHash,
    content: T,
    signature: String, // TODO create a type for this
}

impl<T> Message<T> {
    /// Get the `MessageId` of the previous message (if there is any).
    pub fn previous(&self) -> Option<MessageId> {
        self.previous
    }

    /// Get a reference to the `MessageId` of the previous message (if there is any).
    pub fn previous_ref(&self) -> &Option<MessageId> {
        &self.previous
    }

    /// Get the `FeedId` of the author of the message.
    pub fn author(&self) -> FeedId {
        self.author
    }

    /// Get a reference to the `FeedId` of the author of the message.
    pub fn author_ref(&self) -> &FeedId {
        &self.author
    }

    /// Get a reference to the sequence number of the message.
    pub fn sequence_ref(&self) -> &SequenceNumber {
        &self.sequence
    }

    /// Consume the message and return it's sequence number.
    pub fn into_sequence(self) -> SequenceNumber {
        self.sequence
    }

    /// Get a reference to the timestamp of the message.
    pub fn timestamp_ref(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Consume the message and return it's timestamp.
    pub fn into_timestamp(self) -> Timestamp {
        self.timestamp
    }

    /// Get a reference to the content of the message.
    pub fn content_ref(&self) -> &T {
        &self.content
    }

    /// Consume the message and return it's content.
    pub fn into_content(self) -> T {
        self.content
    }
}

// TODO keep this private, or make it public? If made public, adding new hashes becomes a breaking
// change.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PossibleHash {
    Sha256,
}

#[cfg(test)]
mod tests {
    use serde_json::{to_string, from_str, Value};

    use super::*;
    use keys::gen_keypair;
    use hashes::hash;

    #[test]
    fn deserialize_message() {
        let msg = r#"{
  "previous": "%XphMUkWQtomKjXQvFGfsGYpt69sgEY7Y4Vou9cEuJho=.sha256",
  "author": "@FCX/tsDLpubCPKKfIrw4gc+SQkHcaD17s7GI6i/ziWY=.ed25519",
  "sequence": 2,
  "timestamp": 1514517078157,
  "hash": "sha256",
  "content": {
    "type": "post",
    "text": "Second post!"
  },
  "signature": "z7W1ERg9UYZjNfE72ZwEuJF79khG+eOHWFp6iF+KLuSrw8Lqa6IousK4cCn9T5qFa8E14GVek4cAMmMbjqDnAg==.sig.ed25519"
}"#;
        let deserialized = from_str::<Message<Value>>(msg).unwrap();
        assert_eq!(deserialized.previous(), Some(from_str::<MessageId>(r#""%XphMUkWQtomKjXQvFGfsGYpt69sgEY7Y4Vou9cEuJho=.sha256""#).unwrap()));
        assert_eq!(deserialized.author(),
                   from_str::<FeedId>(r#""@FCX/tsDLpubCPKKfIrw4gc+SQkHcaD17s7GI6i/ziWY=.ed25519""#)
                       .unwrap());
        // assert_eq!(deserialized.sequence_ref(), &SequenceNumber(Number::from_f64(2.0).unwrap()));
        // assert_eq!(deserialized.timestamp_ref(), &Timestamp(Number::from_f64(1514517078157.0).unwrap()));
        assert_eq!(deserialized.hash, PossibleHash::Sha256);
        assert_eq!(deserialized.signature,
                   "z7W1ERg9UYZjNfE72ZwEuJF79khG+eOHWFp6iF+KLuSrw8Lqa6IousK4cCn9T5qFa8E14GVek4cAMmMbjqDnAg==.sig.ed25519");
        assert_eq!(deserialized.content_ref(),
                   &from_str::<Value>(r#"{
            "type": "post",
            "text": "Second post!"
        }"#)
                            .unwrap());
    }
}
