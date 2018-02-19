//! Helpers for working with the default directory (layout) of ssb.

/// The name of the directory where ssb stores its data by default.
///
/// Note that ssb always looks for a hidden directory, so the actual path used
/// will be `".ssb"`, not `"ssb"`. The directory is resolved from the home
/// directory of the user. So a full path could for example be
/// `"/home/foobar/.ssb"` (on linux).
pub const DEFAULT_SSB_DIRECTORY_NAME: &'static str = "ssb";

/// Applications should read this environment variable to use an ssb directory
/// other than the default one.
pub const ENV_SSB_DIRECTORY_NAME: &'static str = "ssb_appname";
