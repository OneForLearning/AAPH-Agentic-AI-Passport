//! Pure multi-dimensional persistent budget registry.

use crate::ids::{BudgetId, BudgetReservationId, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetAmounts {
    pub action_count: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

impl BudgetAmounts {
    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            action_count: self.action_count.checked_add(other.action_count)?,
            read_bytes: self.read_bytes.checked_add(other.read_bytes)?,
            write_bytes: self.write_bytes.checked_add(other.write_bytes)?,
        })
    }
    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            action_count: self.action_count.checked_sub(other.action_count)?,
            read_bytes: self.read_bytes.checked_sub(other.read_bytes)?,
            write_bytes: self.write_bytes.checked_sub(other.write_bytes)?,
        })
    }
    fn fits_within(self, capacity: Self) -> bool {
        self.action_count <= capacity.action_count
            && self.read_bytes <= capacity.read_bytes
            && self.write_bytes <= capacity.write_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReservationState {
    Available,
    Reserved,
    Committed,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableReservation {
    pub reservation_id: BudgetReservationId,
    pub session_id: SessionId,
    pub amounts: BudgetAmounts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetReservation {
    session_id: SessionId,
    amounts: BudgetAmounts,
    state: ReservationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetLedger {
    id: BudgetId,
    capacity: BudgetAmounts,
    consumed: BudgetAmounts,
    reserved: BudgetAmounts,
    reservations: BTreeMap<BudgetReservationId, BudgetReservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    Overflow,
    CapacityExceeded,
    DuplicateReservation,
    UnknownReservation,
    AlreadyCommitted,
    CommitAfterRelease,
    ReleaseAfterCommit,
    InvariantViolation,
}

impl BudgetLedger {
    #[must_use]
    pub fn new(id: BudgetId, capacity: BudgetAmounts) -> Self {
        Self {
            id,
            capacity,
            consumed: BudgetAmounts::default(),
            reserved: BudgetAmounts::default(),
            reservations: BTreeMap::new(),
        }
    }
    #[must_use]
    pub const fn consumed(&self) -> BudgetAmounts {
        self.consumed
    }
    #[must_use]
    pub const fn reserved(&self) -> BudgetAmounts {
        self.reserved
    }

    /// Transitions an available request to RESERVED.
    ///
    /// # Errors
    /// Returns an error for duplicates, overflow, or capacity exhaustion.
    pub fn reserve(&mut self, request: AvailableReservation) -> Result<(), BudgetError> {
        if self.reservations.contains_key(&request.reservation_id) {
            return Err(BudgetError::DuplicateReservation);
        }
        let next_reserved = self
            .reserved
            .checked_add(request.amounts)
            .ok_or(BudgetError::Overflow)?;
        let total = self
            .consumed
            .checked_add(next_reserved)
            .ok_or(BudgetError::Overflow)?;
        if !total.fits_within(self.capacity) {
            return Err(BudgetError::CapacityExceeded);
        }
        self.reservations.insert(
            request.reservation_id,
            BudgetReservation {
                session_id: request.session_id,
                amounts: request.amounts,
                state: ReservationState::Reserved,
            },
        );
        self.reserved = next_reserved;
        self.ensure_invariant()
    }

    /// Commits a reserved amount into irreversible consumption.
    ///
    /// # Errors
    /// Returns an error for unknown or non-reserved reservations or arithmetic failure.
    pub fn commit(&mut self, reservation_id: &BudgetReservationId) -> Result<(), BudgetError> {
        let reservation = self
            .reservations
            .get(reservation_id)
            .ok_or(BudgetError::UnknownReservation)?;
        match reservation.state {
            ReservationState::Committed => return Err(BudgetError::AlreadyCommitted),
            ReservationState::Released => return Err(BudgetError::CommitAfterRelease),
            ReservationState::Available => return Err(BudgetError::InvariantViolation),
            ReservationState::Reserved => {}
        }
        let amounts = reservation.amounts;
        let next_consumed = self
            .consumed
            .checked_add(amounts)
            .ok_or(BudgetError::Overflow)?;
        let next_reserved = self
            .reserved
            .checked_sub(amounts)
            .ok_or(BudgetError::InvariantViolation)?;
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or(BudgetError::UnknownReservation)?;
        reservation.state = ReservationState::Committed;
        self.consumed = next_consumed;
        self.reserved = next_reserved;
        self.ensure_invariant()
    }

    /// Releases a reservation. Repeating release for the same ID is idempotent.
    ///
    /// # Errors
    /// Returns an error for unknown IDs, committed reservations, or arithmetic failure.
    pub fn release(&mut self, reservation_id: &BudgetReservationId) -> Result<(), BudgetError> {
        let reservation = self
            .reservations
            .get(reservation_id)
            .ok_or(BudgetError::UnknownReservation)?;
        match reservation.state {
            ReservationState::Released => return Ok(()),
            ReservationState::Committed => return Err(BudgetError::ReleaseAfterCommit),
            ReservationState::Available => return Err(BudgetError::InvariantViolation),
            ReservationState::Reserved => {}
        }
        let amounts = reservation.amounts;
        let next_reserved = self
            .reserved
            .checked_sub(amounts)
            .ok_or(BudgetError::InvariantViolation)?;
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or(BudgetError::UnknownReservation)?;
        reservation.state = ReservationState::Released;
        self.reserved = next_reserved;
        self.ensure_invariant()
    }

    /// Releases every uncommitted reservation belonging to a closed session.
    ///
    /// # Errors
    /// Returns an error only if the internal arithmetic invariant is violated.
    pub fn close_session(&mut self, session_id: &SessionId) -> Result<(), BudgetError> {
        let ids: Vec<_> = self
            .reservations
            .iter()
            .filter(|(_, reservation)| {
                &reservation.session_id == session_id
                    && reservation.state == ReservationState::Reserved
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.release(&id)?;
        }
        Ok(())
    }

    fn ensure_invariant(&self) -> Result<(), BudgetError> {
        let total = self
            .consumed
            .checked_add(self.reserved)
            .ok_or(BudgetError::Overflow)?;
        if total.fits_within(self.capacity) {
            Ok(())
        } else {
            Err(BudgetError::InvariantViolation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn amounts(actions: u64, reads: u64, writes: u64) -> BudgetAmounts {
        BudgetAmounts {
            action_count: actions,
            read_bytes: reads,
            write_bytes: writes,
        }
    }
    fn reservation(id: &str, session: &str, amounts: BudgetAmounts) -> AvailableReservation {
        AvailableReservation {
            reservation_id: BudgetReservationId::new(id).unwrap(),
            session_id: SessionId::new(session).unwrap(),
            amounts,
        }
    }
    fn ledger(capacity: BudgetAmounts) -> BudgetLedger {
        BudgetLedger::new(BudgetId::new("budget").unwrap(), capacity)
    }

    #[test]
    fn each_dimension_exhausts_independently() {
        for (capacity, excessive) in [
            (amounts(1, 100, 100), amounts(2, 0, 0)),
            (amounts(10, 1, 100), amounts(0, 2, 0)),
            (amounts(10, 100, 1), amounts(0, 0, 2)),
        ] {
            let mut value = ledger(capacity);
            assert_eq!(
                value.reserve(reservation("r", "s", excessive)),
                Err(BudgetError::CapacityExceeded)
            );
        }
    }

    #[test]
    fn reservation_sequences_preserve_the_invariant() {
        let mut value = ledger(amounts(5, 100, 100));
        value
            .reserve(reservation("r1", "s", amounts(1, 40, 0)))
            .unwrap();
        value
            .reserve(reservation("r2", "s", amounts(1, 0, 50)))
            .unwrap();
        value
            .commit(&BudgetReservationId::new("r1").unwrap())
            .unwrap();
        value
            .release(&BudgetReservationId::new("r2").unwrap())
            .unwrap();
        value
            .release(&BudgetReservationId::new("r2").unwrap())
            .unwrap();
        assert_eq!(value.consumed(), amounts(1, 40, 0));
        assert_eq!(value.reserved(), BudgetAmounts::default());
    }

    #[test]
    fn invalid_terminal_transitions_are_rejected() {
        let mut committed = ledger(amounts(5, 100, 100));
        let id = BudgetReservationId::new("r1").unwrap();
        committed
            .reserve(reservation("r1", "s", amounts(1, 1, 0)))
            .unwrap();
        committed.commit(&id).unwrap();
        assert_eq!(committed.commit(&id), Err(BudgetError::AlreadyCommitted));
        assert_eq!(committed.release(&id), Err(BudgetError::ReleaseAfterCommit));
        let mut released = ledger(amounts(5, 100, 100));
        released
            .reserve(reservation("r2", "s", amounts(1, 1, 0)))
            .unwrap();
        let released_id = BudgetReservationId::new("r2").unwrap();
        released.release(&released_id).unwrap();
        assert_eq!(
            released.commit(&released_id),
            Err(BudgetError::CommitAfterRelease)
        );
    }

    #[test]
    fn closing_session_releases_only_pending_and_never_consumed() {
        let mut value = ledger(amounts(5, 100, 100));
        value
            .reserve(reservation("committed", "old", amounts(1, 10, 0)))
            .unwrap();
        value
            .reserve(reservation("pending", "old", amounts(1, 20, 0)))
            .unwrap();
        value
            .commit(&BudgetReservationId::new("committed").unwrap())
            .unwrap();
        value
            .close_session(&SessionId::new("old").unwrap())
            .unwrap();
        assert_eq!(value.consumed(), amounts(1, 10, 0));
        assert_eq!(value.reserved(), BudgetAmounts::default());
        value
            .reserve(reservation("new", "new", amounts(1, 10, 0)))
            .unwrap();
        assert_eq!(value.consumed(), amounts(1, 10, 0));
    }

    #[test]
    fn arithmetic_overflow_fails_closed() {
        let mut value = ledger(amounts(u64::MAX, u64::MAX, u64::MAX));
        value
            .reserve(reservation("r1", "s", amounts(u64::MAX, 0, 0)))
            .unwrap();
        value
            .commit(&BudgetReservationId::new("r1").unwrap())
            .unwrap();
        assert_eq!(
            value.reserve(reservation("r2", "s", amounts(1, 0, 0))),
            Err(BudgetError::Overflow)
        );
    }
}
