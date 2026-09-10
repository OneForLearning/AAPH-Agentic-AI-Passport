//! Strongly typed identifiers used across domain objects.

use serde::{Deserialize, Serialize};

macro_rules! identifier {
    ($name:ident) => {
        #[doc = concat!("Strongly typed `", stringify!($name), "` value.")]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates an identifier from a non-empty string.
            ///
            /// # Errors
            /// Returns [`IdentifierError::Empty`] for an empty string.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(IdentifierError::Empty);
                }
                Ok(Self(value))
            }

            /// Returns the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

/// Error raised while constructing an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierError {
    /// Empty identifiers are forbidden.
    Empty,
}

impl std::fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("identifier must not be empty")
    }
}

impl std::error::Error for IdentifierError {}

identifier!(AgentId);
identifier!(ReleaseId);
identifier!(InstanceId);
identifier!(SessionId);
identifier!(MandateId);
identifier!(BudgetId);
identifier!(RequestId);
identifier!(PermitId);
identifier!(Jti);
identifier!(EffectOperationId);
identifier!(PepId);
identifier!(BudgetReservationId);
identifier!(PolicyVersion);

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    use super::{AgentId, IdentifierError, SessionId};

    #[test]
    fn identifier_types_are_distinct() {
        assert_ne!(TypeId::of::<AgentId>(), TypeId::of::<SessionId>());
    }

    #[test]
    fn empty_identifier_is_rejected() {
        assert_eq!(AgentId::new(""), Err(IdentifierError::Empty));
    }
}
