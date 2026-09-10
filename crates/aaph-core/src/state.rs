//! Closed state machines for instances and sessions.

use crate::ids::{InstanceId, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstanceState {
    Active,
    Contained,
    RecoveryPending,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Created,
    Active,
    Terminated,
    Expired,
    Revoked,
}

/// Unforgeable-at-API-level evidence consumed when recovery completes.
#[derive(Debug)]
pub struct RecoveryValidation {
    _private: (),
}

impl RecoveryValidation {
    /// Creates evidence after a caller has completed its external validation.
    #[must_use]
    pub const fn validated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    InvalidTransition,
    EpochOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstance {
    id: InstanceId,
    state: InstanceState,
    containment_epoch: u64,
}

impl AgentInstance {
    #[must_use]
    pub const fn new(id: InstanceId) -> Self {
        Self {
            id,
            state: InstanceState::Active,
            containment_epoch: 0,
        }
    }
    #[must_use]
    pub const fn state(&self) -> InstanceState {
        self.state
    }
    #[must_use]
    pub const fn containment_epoch(&self) -> u64 {
        self.containment_epoch
    }
    /// Contains an active instance and increments its epoch.
    ///
    /// # Errors
    /// Returns an error for an invalid transition or epoch overflow.
    pub fn contain(&mut self) -> Result<(), TransitionError> {
        if self.state != InstanceState::Active {
            return Err(TransitionError::InvalidTransition);
        }
        self.containment_epoch = self
            .containment_epoch
            .checked_add(1)
            .ok_or(TransitionError::EpochOverflow)?;
        self.state = InstanceState::Contained;
        Ok(())
    }
    /// Moves a contained instance into recovery.
    ///
    /// # Errors
    /// Returns an error unless the instance is contained.
    pub fn request_recovery(&mut self) -> Result<(), TransitionError> {
        if self.state != InstanceState::Contained {
            return Err(TransitionError::InvalidTransition);
        }
        self.state = InstanceState::RecoveryPending;
        Ok(())
    }
    /// Reactivates an instance using explicit validation evidence.
    ///
    /// # Errors
    /// Returns an error unless recovery is pending.
    pub fn complete_recovery(&mut self, _proof: RecoveryValidation) -> Result<(), TransitionError> {
        if self.state != InstanceState::RecoveryPending {
            return Err(TransitionError::InvalidTransition);
        }
        self.state = InstanceState::Active;
        Ok(())
    }
    /// Irreversibly revokes an instance.
    ///
    /// # Errors
    /// Returns an error if it is already revoked.
    pub fn revoke(&mut self) -> Result<(), TransitionError> {
        if self.state == InstanceState::Revoked {
            return Err(TransitionError::InvalidTransition);
        }
        self.state = InstanceState::Revoked;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSession {
    id: SessionId,
    state: SessionState,
}

impl AgentSession {
    #[must_use]
    pub const fn new(id: SessionId) -> Self {
        Self {
            id,
            state: SessionState::Created,
        }
    }
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }
    /// Activates a created session.
    ///
    /// # Errors
    /// Returns an error unless the session is newly created.
    pub fn activate(&mut self) -> Result<(), TransitionError> {
        self.transition_from_nonterminal(SessionState::Active, &[SessionState::Created])
    }
    /// Terminates a nonterminal session.
    ///
    /// # Errors
    /// Returns an error if the session is terminal.
    pub fn terminate(&mut self) -> Result<(), TransitionError> {
        self.transition_from_nonterminal(
            SessionState::Terminated,
            &[SessionState::Created, SessionState::Active],
        )
    }
    /// Expires a nonterminal session.
    ///
    /// # Errors
    /// Returns an error if the session is terminal.
    pub fn expire(&mut self) -> Result<(), TransitionError> {
        self.transition_from_nonterminal(
            SessionState::Expired,
            &[SessionState::Created, SessionState::Active],
        )
    }
    /// Revokes a nonterminal session.
    ///
    /// # Errors
    /// Returns an error if the session is terminal.
    pub fn revoke(&mut self) -> Result<(), TransitionError> {
        self.transition_from_nonterminal(
            SessionState::Revoked,
            &[SessionState::Created, SessionState::Active],
        )
    }
    fn transition_from_nonterminal(
        &mut self,
        target: SessionState,
        allowed: &[SessionState],
    ) -> Result<(), TransitionError> {
        if !allowed.contains(&self.state) {
            return Err(TransitionError::InvalidTransition);
        }
        self.state = target;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn instance() -> AgentInstance {
        AgentInstance::new(InstanceId::new("i").unwrap())
    }
    fn session() -> AgentSession {
        AgentSession::new(SessionId::new("s").unwrap())
    }

    #[test]
    fn state_json_is_stable() {
        let instance = [
            (InstanceState::Active, "ACTIVE"),
            (InstanceState::Contained, "CONTAINED"),
            (InstanceState::RecoveryPending, "RECOVERY_PENDING"),
            (InstanceState::Revoked, "REVOKED"),
        ];
        for (value, name) in instance {
            let json = format!("\"{name}\"");
            assert_eq!(serde_json::to_string(&value).unwrap(), json);
            assert_eq!(serde_json::from_str::<InstanceState>(&json).unwrap(), value);
        }
        let session = [
            (SessionState::Created, "CREATED"),
            (SessionState::Active, "ACTIVE"),
            (SessionState::Terminated, "TERMINATED"),
            (SessionState::Expired, "EXPIRED"),
            (SessionState::Revoked, "REVOKED"),
        ];
        for (value, name) in session {
            let json = format!("\"{name}\"");
            assert_eq!(serde_json::to_string(&value).unwrap(), json);
            assert_eq!(serde_json::from_str::<SessionState>(&json).unwrap(), value);
        }
    }

    #[test]
    fn all_instance_transitions_work() {
        let mut value = instance();
        value.contain().unwrap();
        value.request_recovery().unwrap();
        value
            .complete_recovery(RecoveryValidation::validated())
            .unwrap();
        value.revoke().unwrap();
        assert_eq!(value.state(), InstanceState::Revoked);
    }

    #[test]
    fn revocation_applies_from_each_non_revoked_instance_state() {
        let mut active = instance();
        active.revoke().unwrap();
        let mut contained = instance();
        contained.contain().unwrap();
        contained.revoke().unwrap();
        let mut pending = instance();
        pending.contain().unwrap();
        pending.request_recovery().unwrap();
        pending.revoke().unwrap();
    }

    #[test]
    fn containment_epoch_is_monotonic() {
        let mut value = instance();
        value.contain().unwrap();
        assert_eq!(value.containment_epoch(), 1);
        value.request_recovery().unwrap();
        value
            .complete_recovery(RecoveryValidation::validated())
            .unwrap();
        value.contain().unwrap();
        assert_eq!(value.containment_epoch(), 2);
        assert_eq!(value.contain(), Err(TransitionError::InvalidTransition));
        assert_eq!(value.containment_epoch(), 2);
    }

    #[test]
    fn containment_epoch_overflow_is_rejected_without_mutation() {
        let json = r#"{"id":"i","state":"ACTIVE","containment_epoch":18446744073709551615}"#;
        let mut value: AgentInstance = serde_json::from_str(json).unwrap();
        assert_eq!(value.contain(), Err(TransitionError::EpochOverflow));
        assert_eq!(value.state(), InstanceState::Active);
        assert_eq!(value.containment_epoch(), u64::MAX);
    }

    #[test]
    fn invalid_instance_transitions_are_rejected() {
        let mut value = instance();
        assert_eq!(
            value.request_recovery(),
            Err(TransitionError::InvalidTransition)
        );
        assert_eq!(
            value.complete_recovery(RecoveryValidation::validated()),
            Err(TransitionError::InvalidTransition)
        );
        value.revoke().unwrap();
        assert_eq!(value.revoke(), Err(TransitionError::InvalidTransition));
    }

    #[test]
    fn all_session_terminal_transitions_work() {
        let mut active = session();
        active.activate().unwrap();
        active.terminate().unwrap();
        let mut expired = session();
        expired.expire().unwrap();
        let mut revoked = session();
        revoked.activate().unwrap();
        revoked.revoke().unwrap();
    }

    #[test]
    fn terminal_sessions_never_reactivate() {
        for mut value in [session(), session(), session()] {
            value.activate().unwrap();
            match value.state() {
                SessionState::Active => value.terminate().unwrap(),
                _ => unreachable!(),
            }
            assert_eq!(value.activate(), Err(TransitionError::InvalidTransition));
        }
        let mut expired = session();
        expired.expire().unwrap();
        assert_eq!(expired.activate(), Err(TransitionError::InvalidTransition));
        let mut revoked = session();
        revoked.revoke().unwrap();
        assert_eq!(revoked.activate(), Err(TransitionError::InvalidTransition));
    }
}
