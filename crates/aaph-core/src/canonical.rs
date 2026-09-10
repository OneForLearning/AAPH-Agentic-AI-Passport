//! RFC 8785 canonical JSON and unambiguous domain-separated transcripts.

use serde::Serialize;

/// Canonicalization failures are closed and do not expose source data.
#[derive(Debug)]
pub enum CanonicalError {
    /// RFC 8785 serialization failed.
    Serialization(serde_json::Error),
    /// A transcript component cannot be represented by its fixed-width length.
    LengthOverflow,
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(_) => formatter.write_str("canonical JSON serialization failed"),
            Self::LengthOverflow => formatter.write_str("transcript component is too long"),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Produces RFC 8785 JSON bytes with the maintained `serde_jcs` implementation.
///
/// # Errors
/// Returns an error if the value cannot be represented as canonical JSON.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    serde_jcs::to_vec(value).map_err(CanonicalError::Serialization)
}

/// Builds an unambiguous transcript using big-endian fixed-width lengths.
///
/// # Errors
/// Returns an error if a component exceeds the supported length representation.
pub fn transcript(domain: &[u8], canonical_payload: &[u8]) -> Result<Vec<u8>, CanonicalError> {
    let domain_len = u32::try_from(domain.len()).map_err(|_| CanonicalError::LengthOverflow)?;
    let payload_len =
        u64::try_from(canonical_payload.len()).map_err(|_| CanonicalError::LengthOverflow)?;
    let mut output = Vec::with_capacity(4 + domain.len() + 8 + canonical_payload.len());
    output.extend_from_slice(&domain_len.to_be_bytes());
    output.extend_from_slice(domain);
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(canonical_payload);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct LogicalObject<'a> {
        z: u8,
        a: &'a str,
    }

    #[test]
    fn canonical_json_has_stable_key_order() {
        let bytes = canonical_json(&LogicalObject { z: 1, a: "value" }).unwrap();
        assert_eq!(bytes, br#"{"a":"value","z":1}"#);
    }

    #[test]
    fn transcript_boundaries_are_unambiguous() {
        assert_ne!(
            transcript(b"ab", b"c").unwrap(),
            transcript(b"a", b"bc").unwrap()
        );
    }
}
