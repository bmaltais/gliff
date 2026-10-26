//! Who is viewing this machine, for the loop guard (see [`gliff_proto::Origin`]).
//!
//! A server records each client it serves in a file under
//! `$XDG_RUNTIME_DIR/gliff/`, named by its process id and removed when the
//! session ends. A client on the same machine lists the files in its `Hello`.
//! A file whose process is gone (a server killed before it could clean up) is
//! ignored and swept.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use gliff_proto::Viewer;

/// An opaque identity of this machine: a hash of its machine id, so the id
/// itself never leaves the machine. `None` when the machine has none.
pub fn machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .map(|id| id.trim().to_owned())
        .find(|id| !id.is_empty())
        .map(|id| hash_id(&id))
}

/// FNV-1a over the id, run under two salts to fill 128 bits. It is not a
/// secret-keeping hash; it only keeps the raw machine id off the wire.
fn hash_id(id: &str) -> String {
    let run = |salt: &str| {
        salt.bytes()
            .chain(id.bytes())
            .fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
            })
    };
    format!("{:016x}{:016x}", run("gliff:a:"), run("gliff:b:"))
}

/// The directory under the user's runtime directory (`hypr_ipc::runtime_dir`,
/// which also covers ssh sessions that start without `XDG_RUNTIME_DIR`).
fn dir_in(runtime: &Path) -> PathBuf {
    runtime.join("gliff")
}

/// The record of one served viewer; dropping it removes the file.
pub struct Registration {
    path: PathBuf,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Record that `machine` is viewing `output` of this machine. `None` when
/// the directory cannot be written.
pub fn register(runtime: &Path, machine: &str, output: &str) -> Option<Registration> {
    register_in(&dir_in(runtime), std::process::id(), machine, output)
        .map_err(|e| tracing::warn!(error = %e, "cannot record the viewer; the loop guard is off for it"))
        .ok()
}

fn register_in(dir: &Path, pid: u32, machine: &str, output: &str) -> io::Result<Registration> {
    fs::create_dir_all(dir)?;
    let path = dir.join(pid.to_string());
    fs::write(&path, format!("{machine}\n{output}\n"))?;
    Ok(Registration { path })
}

/// The machines viewing this one right now.
pub fn viewers(runtime: &Path) -> Vec<Viewer> {
    viewers_in(&dir_in(runtime))
}

fn viewers_in(dir: &Path) -> Vec<Viewer> {
    entries_in(dir).into_iter().map(|(_, v)| v).collect()
}

fn entries_in(dir: &Path) -> Vec<(u32, Viewer)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let pid = entry
            .file_name()
            .to_str()
            .and_then(|pid| pid.parse::<u32>().ok())
            .filter(|pid| Path::new("/proc").join(pid.to_string()).exists());
        let Some(pid) = pid else {
            let _ = fs::remove_file(&path);
            continue;
        };
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let mut lines = text.lines();
        if let (Some(machine), Some(output)) = (lines.next(), lines.next()) {
            found.push((
                pid,
                Viewer {
                    machine: machine.to_owned(),
                    output: output.to_owned(),
                },
            ));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_ids_are_stable_and_distinct() {
        assert_eq!(hash_id("abc"), hash_id("abc"));
        assert_ne!(hash_id("abc"), hash_id("abd"));
        assert_eq!(hash_id("abc").len(), 32);
    }

    #[test]
    fn a_registration_lasts_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let reg = register_in(dir.path(), std::process::id(), "m", "gliff-1").unwrap();
        assert_eq!(
            viewers_in(dir.path()),
            vec![Viewer {
                machine: "m".into(),
                output: "gliff-1".into()
            }]
        );
        drop(reg);
        assert!(viewers_in(dir.path()).is_empty());
    }

    #[test]
    fn a_dead_process_is_ignored_and_swept() {
        let dir = tempfile::tempdir().unwrap();
        // The kernel's pid limit is below this, so no such process exists.
        let ghost = dir.path().join("4294967295");
        fs::write(&ghost, "m\nDP-1\n").unwrap();
        assert!(viewers_in(dir.path()).is_empty());
        assert!(!ghost.exists());
    }
}
