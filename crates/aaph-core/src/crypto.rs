//! SHA-384 digests, strict base64url values, and Ed25519 key operations.

use std::path::Path;
use std::{fs::OpenOptions, io::Write as _};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha384};

use crate::canonical::{canonical_json, transcript, CanonicalError};

pub const ACTION_PROPOSAL_DOMAIN: &[u8] = b"AAPH-POC-ACTION-PROPOSAL-V1\0";
pub const EXECUTION_PERMIT_DOMAIN: &[u8] = b"AAPH-POC-EXECUTION-PERMIT-V1\0";
pub const CONTAINMENT_EVENT_DOMAIN: &[u8] = b"AAPH-POC-CONTAINMENT-EVENT-V1\0";
pub const AUDIT_EVENT_DOMAIN: &[u8] = b"AAPH-POC-AUDIT-EVENT-V1\0";
const PUBLIC_KEY_FINGERPRINT_DOMAIN: &[u8] = b"AAPH-POC-PUBLIC-KEY-FINGERPRINT-V1\0";

#[derive(Debug)]
pub enum CryptoError {
    Canonical(CanonicalError),
    InvalidBase64Url,
    InvalidLength,
    InvalidSignature,
    Io(std::io::Error),
    MissingEnvironmentVariable,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(error) => write!(formatter, "{error}"),
            Self::InvalidBase64Url => formatter.write_str("invalid canonical base64url"),
            Self::InvalidLength => formatter.write_str("invalid cryptographic value length"),
            Self::InvalidSignature => formatter.write_str("Ed25519 signature verification failed"),
            Self::Io(_) => formatter.write_str("key material I/O failed"),
            Self::MissingEnvironmentVariable => {
                formatter.write_str("key environment variable is missing")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<CanonicalError> for CryptoError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

fn strict_decode(value: &str, expected_len: usize) -> Result<Vec<u8>, CryptoError> {
    if value.contains('=') || value.chars().any(char::is_whitespace) {
        return Err(CryptoError::InvalidBase64Url);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidBase64Url)?;
    if decoded.len() != expected_len {
        return Err(CryptoError::InvalidLength);
    }
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(CryptoError::InvalidBase64Url);
    }
    Ok(decoded)
}

macro_rules! encoded_value {
    ($name:ident, $len:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
            /// Parses a strict base64url value of the required fixed width.
            ///
            /// # Errors
            /// Returns an error for padding, alphabet, canonicalization, or length.
            pub fn parse(value: impl Into<String>) -> Result<Self, CryptoError> {
                let value = value.into();
                strict_decode(&value, $len)?;
                Ok(Self(value))
            }
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
            fn from_bytes(bytes: &[u8]) -> Self {
                Self(URL_SAFE_NO_PAD.encode(bytes))
            }
            /// Strictly decodes the value to its fixed-width bytes.
            ///
            /// # Errors
            /// Returns an error if the internally held representation is invalid.
            pub fn decode_bytes(&self) -> Result<Vec<u8>, CryptoError> {
                strict_decode(&self.0, $len)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(D::Error::custom)
            }
        }
    };
}

encoded_value!(PublicKeyValue, 32);
encoded_value!(SignatureValue, 64);
encoded_value!(Digest384Value, 48);

/// Private signing key material. Debug output is always redacted and serialization is unavailable.
pub struct SigningKeyMaterial(SigningKey);

impl std::fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SigningKeyMaterial([REDACTED])")
    }
}

impl SigningKeyMaterial {
    #[must_use]
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// Loads a strict base64url-encoded 32-byte seed from a file.
    ///
    /// # Errors
    /// Returns an error for I/O, encoding, or length failures.
    pub fn from_path(path: &Path) -> Result<Self, CryptoError> {
        let value = std::fs::read_to_string(path).map_err(CryptoError::Io)?;
        Self::from_encoded(value.trim())
    }

    /// Loads a strict base64url-encoded 32-byte seed from an environment variable.
    ///
    /// # Errors
    /// Returns an error if the variable is absent or its value is invalid.
    pub fn from_env(variable: &str) -> Result<Self, CryptoError> {
        let value = std::env::var(variable).map_err(|_| CryptoError::MissingEnvironmentVariable)?;
        Self::from_encoded(&value)
    }

    /// Loads a strict base64url-encoded 32-byte seed.
    ///
    /// # Errors
    /// Returns an error if encoding or length is invalid.
    pub fn from_encoded(value: &str) -> Result<Self, CryptoError> {
        let decoded = strict_decode(value, 32)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKeyValue {
        PublicKeyValue::from_bytes(self.0.verifying_key().as_bytes())
    }
}

/// Generates a development key pair in `directory`.
///
/// The private seed is written to `signing.key` and the public key to `public.key`.
/// Neither value is returned or logged.
///
/// # Errors
/// Returns an error for filesystem failures or if a target exists without `overwrite`.
pub fn generate_development_keypair(directory: &Path, overwrite: bool) -> Result<(), CryptoError> {
    std::fs::create_dir_all(directory).map_err(CryptoError::Io)?;
    let secret_path = directory.join("signing.key");
    let public_path = directory.join("public.key");
    if !overwrite && (secret_path.exists() || public_path.exists()) {
        return Err(CryptoError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "refusing to overwrite development key material",
        )));
    }
    let key = SigningKeyMaterial::generate();
    let mut secret_options = OpenOptions::new();
    secret_options.write(true);
    let mut public_options = OpenOptions::new();
    public_options.write(true);
    #[cfg(unix)]
    {
        secret_options.mode(0o600);
        public_options.mode(0o644);
    }
    if overwrite {
        secret_options.create(true).truncate(true);
        public_options.create(true).truncate(true);
    } else {
        secret_options.create_new(true);
        public_options.create_new(true);
    }
    let mut secret_file = secret_options.open(&secret_path).map_err(CryptoError::Io)?;
    secret_file
        .write_all(URL_SAFE_NO_PAD.encode(key.0.to_bytes()).as_bytes())
        .map_err(CryptoError::Io)?;
    let mut public_file = public_options.open(&public_path).map_err(CryptoError::Io)?;
    public_file
        .write_all(key.public_key().as_str().as_bytes())
        .map_err(CryptoError::Io)?;
    #[cfg(unix)]
    {
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
            .map_err(CryptoError::Io)?;
        std::fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o644))
            .map_err(CryptoError::Io)?;
    }
    Ok(())
}

/// Computes a domain-separated SHA-384 digest over canonical JSON.
///
/// # Errors
/// Returns an error if canonicalization or transcript construction fails.
pub fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest384Value, CryptoError> {
    let canonical = canonical_json(value)?;
    let transcript = transcript(domain, &canonical)?;
    Ok(Digest384Value::from_bytes(&Sha384::digest(transcript)))
}

/// Signs a domain-separated canonical transcript with Ed25519.
///
/// # Errors
/// Returns an error if canonicalization or transcript construction fails.
pub fn sign<T: Serialize>(
    domain: &[u8],
    value: &T,
    key: &SigningKeyMaterial,
) -> Result<SignatureValue, CryptoError> {
    let canonical = canonical_json(value)?;
    let transcript = transcript(domain, &canonical)?;
    Ok(SignatureValue::from_bytes(
        &key.0.sign(&transcript).to_bytes(),
    ))
}

/// Verifies an Ed25519 signature over a domain-separated canonical transcript.
///
/// # Errors
/// Returns an error for invalid encodings, keys, signatures, or canonicalization.
pub fn verify<T: Serialize>(
    domain: &[u8],
    value: &T,
    public_key: &PublicKeyValue,
    signature: &SignatureValue,
) -> Result<(), CryptoError> {
    let public_bytes: [u8; 32] = public_key
        .decode_bytes()?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)?;
    let signature_bytes: [u8; 64] = signature
        .decode_bytes()?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_bytes).map_err(|_| CryptoError::InvalidLength)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let canonical = canonical_json(value)?;
    let transcript = transcript(domain, &canonical)?;
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Computes the domain-separated SHA-384 fingerprint of a public key.
///
/// # Errors
/// Returns an error if canonicalization fails.
pub fn public_key_fingerprint(public_key: &PublicKeyValue) -> Result<Digest384Value, CryptoError> {
    digest(PUBLIC_KEY_FINGERPRINT_DOMAIN, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_debug_is_redacted() {
        let key = SigningKeyMaterial::from_encoded("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap();
        assert_eq!(format!("{key:?}"), "SigningKeyMaterial([REDACTED])");
    }

    #[test]
    fn base64url_is_strict() {
        assert!(PublicKeyValue::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_err());
        assert!(PublicKeyValue::parse("not+base64/url").is_err());
        assert!(PublicKeyValue::parse("AA").is_err());
        assert!(SignatureValue::parse(" A").is_err());
    }

    #[test]
    fn development_key_generation_refuses_implicit_overwrite() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("aaph-keygen-test-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        generate_development_keypair(&directory, false).unwrap();
        assert!(generate_development_keypair(&directory, false).is_err());
        generate_development_keypair(&directory, true).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn development_key_generation_uses_minimal_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "aaph-keygen-permissions-test-{}-{unique}",
            std::process::id()
        ));
        generate_development_keypair(&directory, false).unwrap();
        let private_mode = std::fs::metadata(directory.join("signing.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let public_mode = std::fs::metadata(directory.join("public.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(private_mode, 0o600);
        assert_eq!(public_mode, 0o644);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
