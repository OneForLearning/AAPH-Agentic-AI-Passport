use crate::sandbox::{SandboxError, Workspace};
use aaph_core::action::{ActionKind, CanonicalActionRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResult {
    pub action: ActionKind,
    pub resource: String,
    pub entries: Option<Vec<String>>,
    pub content: Option<String>,
    pub sha256: Option<String>,
    pub bytes: u64,
}

/// Executes one canonical request through the supplied workspace capability.
///
/// # Errors
///
/// Returns a sandbox error for invalid scope, exceeded limits, or I/O failure.
pub fn execute(
    workspace: &Workspace,
    request: &CanonicalActionRequest,
) -> Result<EffectResult, SandboxError> {
    if request.destination().is_some() {
        return Err(SandboxError::Path);
    }
    let mut result = EffectResult {
        action: request.action(),
        resource: request.resource().to_owned(),
        entries: None,
        content: None,
        sha256: None,
        bytes: 0,
    };
    match request.action() {
        ActionKind::ListDirectory => result.entries = Some(workspace.list(request.resource())?),
        ActionKind::ReadFile => {
            let data = workspace.read(
                request.resource(),
                request.size_bytes().ok_or(SandboxError::Limit)?,
            )?;
            result.bytes = u64::try_from(data.len()).map_err(|_| SandboxError::Limit)?;
            result.content = Some(String::from_utf8(data).map_err(|_| SandboxError::Io)?);
        }
        ActionKind::ComputeSha256 => {
            let data = workspace.read(
                request.resource(),
                request.size_bytes().ok_or(SandboxError::Limit)?,
            )?;
            result.bytes = u64::try_from(data.len()).map_err(|_| SandboxError::Limit)?;
            let mut encoded = String::with_capacity(64);
            for byte in Sha256::digest(data) {
                write!(&mut encoded, "{byte:02x}").map_err(|_| SandboxError::Io)?;
            }
            result.sha256 = Some(encoded);
        }
        ActionKind::WriteReport => {
            let size = request.size_bytes().ok_or(SandboxError::Limit)?;
            workspace.write_report(request.resource(), size)?;
            result.bytes = size;
        }
    }
    Ok(result)
}
