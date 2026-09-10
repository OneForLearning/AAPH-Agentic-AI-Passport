//! `NON_PRODUCTION_DEMO` profile `AAPH-POC-ID-UUIDV7-1`.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct IdGenerationError;

pub trait IdGenerator: Send + Sync {
    /// Generates a `UUIDv7` identifier.
    ///
    /// # Errors
    /// Returns an error if time or operating-system randomness is unavailable.
    fn uuid_v7(&self) -> Result<String, IdGenerationError>;
    /// Generates a CSPRNG nonce.
    ///
    /// # Errors
    /// Returns an error if operating-system randomness is unavailable.
    fn nonce(&self) -> Result<String, IdGenerationError>;
}
pub struct ProductionIdGenerator;
impl IdGenerator for ProductionIdGenerator {
    fn uuid_v7(&self) -> Result<String, IdGenerationError> {
        let timestamp = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| IdGenerationError)?
                .as_millis(),
        )
        .map_err(|_| IdGenerationError)?;
        if timestamp > 0x0000_ffff_ffff_ffff {
            return Err(IdGenerationError);
        }
        let mut b = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut b)
            .map_err(|_| IdGenerationError)?;
        let t = timestamp.to_be_bytes();
        b[..6].copy_from_slice(&t[2..]);
        b[6] = (b[6] & 15) | 0x70;
        b[8] = (b[8] & 63) | 0x80;
        Ok(format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]))
    }
    fn nonce(&self) -> Result<String, IdGenerationError> {
        let mut b = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut b)
            .map_err(|_| IdGenerationError)?;
        Ok(URL_SAFE_NO_PAD.encode(b))
    }
}
#[cfg(test)]
pub struct DeterministicIdGenerator {
    values: std::sync::Mutex<std::collections::VecDeque<String>>,
}
#[cfg(test)]
impl DeterministicIdGenerator {
    pub fn new(v: impl IntoIterator<Item = String>) -> Self {
        Self {
            values: std::sync::Mutex::new(v.into_iter().collect()),
        }
    }
    fn next(&self) -> Result<String, IdGenerationError> {
        self.values
            .lock()
            .map_err(|_| IdGenerationError)?
            .pop_front()
            .ok_or(IdGenerationError)
    }
}
#[cfg(test)]
impl IdGenerator for DeterministicIdGenerator {
    fn uuid_v7(&self) -> Result<String, IdGenerationError> {
        self.next()
    }
    fn nonce(&self) -> Result<String, IdGenerationError> {
        self.next()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_ids_match_profile() {
        let g = ProductionIdGenerator;
        let a = g.uuid_v7().unwrap();
        let b = g.uuid_v7().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "7");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"));
        assert_eq!(g.nonce().unwrap().len(), 22);
    }

    #[test]
    fn deterministic_generator_uses_explicit_test_sequence() {
        let generator = DeterministicIdGenerator::new([
            "01890f3e-4c00-7000-8000-000000000001".to_owned(),
            "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        ]);
        assert_eq!(
            generator.uuid_v7().unwrap(),
            "01890f3e-4c00-7000-8000-000000000001"
        );
        assert_eq!(generator.nonce().unwrap(), "AAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn restart_keeps_identifiers_unique() {
        let before = ProductionIdGenerator.uuid_v7().unwrap();
        let after = ProductionIdGenerator.uuid_v7().unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn concurrent_issuance_has_no_collision() {
        let handles: Vec<_> = (0..32)
            .map(|_| std::thread::spawn(|| ProductionIdGenerator.uuid_v7().unwrap()))
            .collect();
        let mut ids = std::collections::BTreeSet::new();
        for handle in handles {
            assert!(ids.insert(handle.join().unwrap()));
        }
        assert_eq!(ids.len(), 32);
    }
}
