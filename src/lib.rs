//! Common types and data for the ssb ecosystem
#![deny(missing_docs)]
#![feature(try_from)]

extern crate sodiumoxide;

// TODO move the directory stuff into a module, and mke the consts public
/// The network identifier of the main ssb network.
const MAINNET_IDENTIFIER: [u8; 32] = [212, 161, 203, 136, 166, 111, 2, 248, 219, 99, 92, 226, 100,
                                      65, 204, 93, 172, 27, 8, 66, 12, 234, 172, 35, 8, 57, 183,
                                      85, 132, 90, 159, 251];

/// The name of the directory where ssb stores its data by default.
///
/// Note that ssb always looks for a hidden directory, so the actual path used
/// will be `".ssb"`, not `"ssb"`. The directory is resolved from the home
/// directory of the user. So a full path could for example be
/// `"/home/foobar/.ssb"` (on linux).
const DEFAULT_SSB_DIRECTORY_NAME: &'static str = "ssb";

/// Applications should read this environment variable to use an ssb directory
/// other than the default one.
const ENV_SSB_DIRECTORY_NAME: &'static str = "ssb_appname";

pub mod keys;
