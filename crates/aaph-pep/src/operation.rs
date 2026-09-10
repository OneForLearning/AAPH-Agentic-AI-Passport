use crate::executor::{self, EffectResult};
use crate::sandbox::{SandboxError, Workspace};
use aaph_core::action::CanonicalActionRequest;
use std::sync::Arc;

/// Narrow composition boundary between verified requests and file effects.
pub trait OperationExecutor: Send + Sync {
    /// Executes one already verified canonical operation.
    ///
    /// # Errors
    ///
    /// Returns a sandbox error when scope or limits are violated, or when the
    /// capability-backed operation fails closed.
    fn execute(&self, request: &CanonicalActionRequest) -> Result<EffectResult, SandboxError>;
}

pub struct WorkspaceOperationExecutor {
    workspace: Arc<Workspace>,
}

impl WorkspaceOperationExecutor {
    #[must_use]
    pub fn new(workspace: Arc<Workspace>) -> Self {
        Self { workspace }
    }
}

impl OperationExecutor for WorkspaceOperationExecutor {
    fn execute(&self, request: &CanonicalActionRequest) -> Result<EffectResult, SandboxError> {
        executor::execute(&self.workspace, request)
    }
}
