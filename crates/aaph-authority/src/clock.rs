use aaph_core::UtcTimestamp;

pub trait Clock: Send + Sync {
    fn now(&self) -> UtcTimestamp;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UtcTimestamp {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .unwrap_or(0);
        UtcTimestamp::from_unix_seconds(seconds)
    }
}

#[cfg(test)]
pub struct FixedClock(pub i64);

#[cfg(test)]
impl Clock for FixedClock {
    fn now(&self) -> UtcTimestamp {
        UtcTimestamp::from_unix_seconds(self.0)
    }
}
