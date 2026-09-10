//! Shared, side-effect-free contracts for the AAPH proof of concept.
pub mod action;
pub mod agent;
pub mod audit;
pub mod budget;
pub mod canonical;
pub mod crypto;
pub mod ids;
pub mod mandate;
pub mod permit;
pub mod policy;
pub mod signed;
pub mod state;

use serde::{Deserialize, Serialize};

/// A UTC instant represented as signed Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UtcTimestamp(i64);

impl UtcTimestamp {
    /// Constructs a timestamp from Unix seconds.
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Returns the signed Unix timestamp in seconds.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }
}
