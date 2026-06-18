/// Windows long path support utilities.
///
/// Windows historically limits paths to MAX_PATH (260 characters).
/// Two complementary mechanisms break this limit:
///
/// 1. **Application Manifest** (`longPathAware=true`): Requires Windows 10 build 1607+
///    AND the registry key `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled=1`.
///    When both conditions are met, `std::fs` and `PathBuf` work without any path prefix.
///    This is the cleanest solution but depends on system configuration.
///
/// 2. **Extended-length path prefix (`\\?\`)**: Always works on Windows Vista+ regardless of
///    registry settings.  A path starting with `\\?\` bypasses the MAX_PATH limit entirely,
///    supporting paths up to 32,767 characters.  Restrictions:
///    - The path MUST be absolute.
///    - Forward slashes are NOT allowed; use only backslashes.
///    - Components like `.` and `..` are NOT resolved; the path must be fully normalised first.
///
/// This module provides [`to_extended_path`] which canonicalises a `Path` and adds the
/// `\\?\` prefix when running on Windows, giving us long-path support even without the
/// registry opt-in.
///
/// On non-Windows platforms the function is a no-op — it simply returns the input path.

use std::path::{Path, PathBuf};

/// Convert a path to its Windows extended-length form (`\\?\<absolute_path>`).
///
/// The function:
/// 1. Makes the path absolute (using the current directory if needed).
/// 2. Normalises separators to backslash.
/// 3. Prepends `\\?\` if not already present.
///
/// Returns the original path unchanged on non-Windows platforms.
///
/// # Panics
/// Does not panic.  If the path cannot be made absolute the original is returned as-is.
#[cfg(windows)]
pub fn to_extended_path(path: &Path) -> PathBuf {
    // Already an extended path — return as-is.
    let raw = path.to_string_lossy();
    if raw.starts_with(r"\\?\") || raw.starts_with(r"\\.\") {
        return path.to_path_buf();
    }

    // Make the path absolute.
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => return path.to_path_buf(),
        }
    };

    // Normalise to backslashes and build the \\?\ form.
    let abs_str = abs.to_string_lossy();
    // Canonicalise already converts `/` to `\` on Windows; do it manually here in case
    // the path does not yet exist (canonicalize requires existence).
    let normalised = abs_str.replace('/', "\\");

    // Handle UNC paths:  \\server\share  →  \\?\UNC\server\share
    if normalised.starts_with(r"\\") {
        // Skip the leading \\ and produce \\?\UNC\<rest>
        let rest = &normalised[2..];
        PathBuf::from(format!(r"\\?\UNC\{}", rest))
    } else {
        PathBuf::from(format!(r"\\?\{}", normalised))
    }
}

#[cfg(not(windows))]
#[inline]
pub fn to_extended_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// Convert a `PathBuf` to its extended-length form.
///
/// Convenience wrapper around [`to_extended_path`].
#[inline]
pub fn extend_path(path: PathBuf) -> PathBuf {
    to_extended_path(&path)
}

/// Remove the `\\?\` prefix from a path for display / NFS wire encoding purposes.
///
/// NFS clients must never see the `\\?\` prefix — they only understand POSIX-style paths.
/// Use this when converting a Windows path back to a string for logging or protocol output.
#[cfg(windows)]
pub fn strip_extended_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        // Restore as a UNC path
        PathBuf::from(format!(r"\\{}", stripped))
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

#[cfg(not(windows))]
#[inline]
pub fn strip_extended_prefix(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn test_extended_prefix_added() {
        let p = Path::new(r"C:\Users\test\file.txt");
        let ep = to_extended_path(p);
        assert!(ep.to_string_lossy().starts_with(r"\\?\"));
    }

    #[cfg(windows)]
    #[test]
    fn test_extended_prefix_not_doubled() {
        let p = Path::new(r"\\?\C:\already");
        let ep = to_extended_path(p);
        assert_eq!(ep.to_string_lossy().matches(r"\\?\").count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn test_strip_extended_prefix() {
        let p = Path::new(r"\\?\C:\Users\test");
        let stripped = strip_extended_prefix(p);
        assert_eq!(stripped.to_string_lossy(), r"C:\Users\test");
    }

    #[cfg(windows)]
    #[test]
    fn test_unc_path() {
        let p = Path::new(r"\\server\share\file.txt");
        let ep = to_extended_path(p);
        assert!(ep.to_string_lossy().starts_with(r"\\?\UNC\"));
    }
}
