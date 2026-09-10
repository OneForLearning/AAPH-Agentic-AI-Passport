use cap_std::fs::{Dir, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP: AtomicU64 = AtomicU64::new(1);

pub struct Workspace {
    root: Dir,
    max_entries: usize,
    max_read: u64,
    max_write: u64,
}

impl Workspace {
    /// Opens the root directory as a capability with explicit limits.
    ///
    /// # Errors
    /// Returns an I/O error when the directory capability cannot be opened.
    pub fn open(
        path: &Path,
        max_entries: usize,
        max_read: u64,
        max_write: u64,
    ) -> Result<Self, std::io::Error> {
        let root = Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
        Ok(Self {
            root,
            max_entries,
            max_read,
            max_write,
        })
    }
    /// Lists a bounded logical inbox directory.
    ///
    /// # Errors
    /// Returns a sandbox error for invalid paths, limits, or I/O failures.
    pub fn list(&self, path: &str) -> Result<Vec<String>, SandboxError> {
        validate(path, "inbox/")?;
        let mut names = Vec::new();
        for entry in self.root.read_dir(path).map_err(|_| SandboxError::Io)? {
            let entry = entry.map_err(|_| SandboxError::Io)?;
            if names.len() >= self.max_entries {
                return Err(SandboxError::Limit);
            }
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }
    /// Reads a bounded logical inbox file.
    ///
    /// # Errors
    /// Returns a sandbox error for invalid paths, limits, or I/O failures.
    pub fn read(&self, path: &str, declared: u64) -> Result<Vec<u8>, SandboxError> {
        validate(path, "inbox/")?;
        if declared > self.max_read {
            return Err(SandboxError::Limit);
        }
        let metadata = self
            .root
            .symlink_metadata(path)
            .map_err(|_| SandboxError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(SandboxError::Path);
        }
        let file = self.root.open(path).map_err(|_| SandboxError::Io)?;
        let cap = usize::try_from(declared).map_err(|_| SandboxError::Limit)?;
        let mut data = Vec::new();
        file.take(declared.saturating_add(1))
            .read_to_end(&mut data)
            .map_err(|_| SandboxError::Io)?;
        if data.len() > cap {
            return Err(SandboxError::Limit);
        }
        Ok(data)
    }
    /// Atomically writes a bounded report under the output directory.
    ///
    /// # Errors
    /// Returns a sandbox error for invalid paths, limits, or I/O failures.
    pub fn write_report(&self, path: &str, size: u64) -> Result<(), SandboxError> {
        validate(path, "output/")?;
        if size > self.max_write {
            return Err(SandboxError::Limit);
        }
        let parent = Path::new(path).parent().ok_or(SandboxError::Path)?;
        self.root.open_dir(parent).map_err(|_| SandboxError::Path)?;
        let temp = format!("{}.aaph-tmp-{}", path, TEMP.fetch_add(1, Ordering::Relaxed));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = self
                .root
                .open_with(&temp, &options)
                .map_err(|_| SandboxError::Io)?;
            let length = usize::try_from(size).map_err(|_| SandboxError::Limit)?;
            file.write_all(&vec![b'#'; length])
                .map_err(|_| SandboxError::Io)?;
            file.sync_all().map_err(|_| SandboxError::Io)?;
            self.root
                .rename(&temp, &self.root, path)
                .map_err(|_| SandboxError::Io)
        })();
        if result.is_err() {
            let _ = self.root.remove_file(&temp);
        }
        result
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SandboxError {
    Path,
    Limit,
    Io,
}
/// Validates a logical path against an allowed prefix.
///
/// # Errors
/// Returns a path error when the logical path is ambiguous or out of scope.
pub fn validate(path: &str, prefix: &str) -> Result<(), SandboxError> {
    if path.is_empty()
        || path.contains('\0')
        || path.contains('\\')
        || path.contains('%')
        || !path.starts_with(prefix)
    {
        return Err(SandboxError::Path);
    }
    let parsed = Path::new(path);
    if parsed.is_absolute() {
        return Err(SandboxError::Path);
    }
    for component in parsed.components() {
        match component {
            Component::Normal(part) if !part.to_string_lossy().contains(':') => {}
            _ => return Err(SandboxError::Path),
        }
    }
    Ok(())
}
