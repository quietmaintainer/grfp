use std::collections::HashMap;
use std::fs::{self, File, Metadata};
use std::io::{self, Cursor, Read, Take};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use filetime::{FileTime, set_file_mtime};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::io::MAX_FILE;

const MAGIC: &[u8; 4] = b"GRB1";
const MAX_MANIFEST: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Kind {
    File,
    Directory,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    path: String,
    kind: Kind,
    bytes: u64,
    modified_seconds: i64,
    modified_nanos: u32,
    readonly: bool,
    unix_mode: Option<u32>,
}

fn portable_component(name: &str) -> bool {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with([' ', '.'])
        || name
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
    {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap()
        .trim_end()
        .to_ascii_uppercase();
    !(matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix)
            .is_some_and(|n| "123456789¹²³".contains(n) && !n.is_empty() && n.chars().count() == 1)
    }))
}

fn check_manifest(entries: &[Entry]) -> Result<u64> {
    ensure!(!entries.is_empty(), "Bundle manifest is empty");
    let mut seen = HashMap::with_capacity(entries.len());
    let mut bytes = 0u64;
    for (i, entry) in entries.iter().enumerate() {
        ensure!(
            entry.path.split('/').all(portable_component),
            "Invalid or nonportable bundle path: {:?}",
            entry.path
        );
        match entry.path.rsplit_once('/') {
            Some((parent, _)) => ensure!(
                seen.get(parent) == Some(&Kind::Directory),
                "Bundle path has no preceding parent directory"
            ),
            None => ensure!(i == 0, "Bundle has multiple root entries"),
        }
        ensure!(
            seen.insert(entry.path.as_str(), entry.kind).is_none(),
            "Duplicate bundle path: {:?}",
            entry.path
        );
        ensure!(
            entry.modified_nanos < 1_000_000_000
                && (-11_644_473_600..=253_402_300_799).contains(&entry.modified_seconds)
                && entry.unix_mode.is_none_or(|mode| mode <= 0o777),
            "Unsupported metadata for {:?}",
            entry.path
        );
        ensure!(
            entry.kind == Kind::File || entry.bytes == 0,
            "Directory entry contains file data"
        );
        ensure!(
            entry.bytes <= MAX_FILE - bytes,
            "Bundle exceeds the file size limit"
        );
        bytes += entry.bytes;
    }
    Ok(bytes)
}

fn regular(meta: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    meta.is_file() || meta.is_dir()
}

fn unix_mode(meta: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

pub(crate) struct Input {
    pub bytes: u64,
    prefix: Cursor<Vec<u8>>,
    pending: std::iter::Peekable<std::vec::IntoIter<(PathBuf, u64)>>,
    file: Option<Take<File>>,
}

impl Input {
    pub(crate) fn new(source: &Path) -> Result<Self> {
        ensure!(
            regular(&fs::symlink_metadata(source)?),
            "Bundle input must be a regular file or directory"
        );
        let source = source.canonicalize()?;
        let root = source
            .file_name()
            .and_then(|n| n.to_str())
            .context("Bundle input needs a UTF-8 filename")?;
        let mut entries = Vec::new();
        let mut files = Vec::new();
        for item in WalkDir::new(&source)
            .sort_by_file_name()
            .follow_root_links(false)
        {
            let item = item?;
            let meta = fs::symlink_metadata(item.path())?;
            ensure!(
                regular(&meta),
                "Unsupported filesystem entry: {}",
                item.path().display()
            );
            let mut path = root.to_owned();
            for part in item.path().strip_prefix(&source)?.components() {
                path.push('/');
                path.push_str(
                    part.as_os_str()
                        .to_str()
                        .context("Expected a UTF-8 filename")?,
                );
            }
            let (kind, bytes) = if meta.is_file() {
                files.push((item.into_path(), meta.len()));
                (Kind::File, meta.len())
            } else {
                (Kind::Directory, 0)
            };
            let modified = FileTime::from_last_modification_time(&meta);
            entries.push(Entry {
                path,
                kind,
                bytes,
                modified_seconds: modified.unix_seconds(),
                modified_nanos: modified.nanoseconds(),
                readonly: meta.permissions().readonly(),
                unix_mode: unix_mode(&meta),
            });
        }
        let content = check_manifest(&entries)?;
        let metadata = serde_json::to_vec(&entries)?;
        ensure!(
            metadata.len() <= MAX_MANIFEST,
            "Bundle manifest is too large"
        );
        let mut prefix = Vec::with_capacity(8 + metadata.len());
        prefix.extend_from_slice(MAGIC);
        prefix.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        prefix.extend_from_slice(&metadata);
        Ok(Self {
            bytes: content + prefix.len() as u64,
            prefix: Cursor::new(prefix),
            pending: files.into_iter().peekable(),
            file: None,
        })
    }
}

impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.prefix.read(out)?;
        if n != 0 || out.is_empty() {
            return Ok(n);
        }
        loop {
            if let Some(file) = &mut self.file {
                if file.limit() > 0 {
                    let n = file.read(out)?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Bundle input shrank",
                        ));
                    }
                    return Ok(n);
                }
                if file.get_mut().read(&mut [0])? != 0 {
                    return Err(io::Error::other("Bundle input grew"));
                }
                self.file = None;
            }
            let Some((path, bytes)) = self.pending.peek() else {
                return Ok(0);
            };
            let meta = fs::symlink_metadata(path)?;
            if !regular(&meta) || !meta.is_file() || meta.len() != *bytes {
                return Err(io::Error::other("Bundle input changed during packing"));
            }
            self.file = Some(File::open(path)?.take(*bytes));
            self.pending.next();
        }
    }
}

fn restore_metadata(path: &Path, entry: &Entry) -> Result<()> {
    set_file_mtime(
        path,
        FileTime::from_unix_time(entry.modified_seconds, entry.modified_nanos),
    )?;
    let mut permissions = fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(mode) = entry.unix_mode {
            permissions.set_mode(mode);
        } else if entry.readonly {
            permissions.set_mode(permissions.mode() & !0o222);
        }
    }
    #[cfg(not(unix))]
    permissions.set_readonly(entry.readonly);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

pub(crate) fn restore(mut input: impl Read, bytes: u64, stage: &Path) -> Result<(String, usize)> {
    let mut header = [0; 8];
    input.read_exact(&mut header)?;
    ensure!(&header[..4] == MAGIC, "Expected a GRFP file bundle");
    let length = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
    ensure!(
        (1..=MAX_MANIFEST).contains(&length),
        "Invalid bundle manifest length"
    );
    let mut metadata = vec![0; length];
    input.read_exact(&mut metadata)?;
    let entries: Vec<Entry> = serde_json::from_slice(&metadata)?;
    let content = check_manifest(&entries)?;
    ensure!(
        content + (8 + length) as u64 == bytes,
        "Bundle content length mismatch"
    );

    for entry in &entries {
        let path = stage.join(&entry.path);
        match entry.kind {
            Kind::Directory => fs::create_dir(path)?,
            Kind::File => {
                let mut file = File::options().write(true).create_new(true).open(&path)?;
                let copied = io::copy(&mut (&mut input).take(entry.bytes), &mut file)?;
                ensure!(
                    copied == entry.bytes,
                    "Incomplete bundle file: {}",
                    entry.path
                );
            }
        }
    }
    ensure!(input.read(&mut [0])? == 0, "Trailing bundle content");
    for entry in entries.iter().rev() {
        restore_metadata(&stage.join(&entry.path), entry)?;
    }
    Ok((entries[0].path.clone(), entries.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_paths_are_rejected_before_any_entry_is_written() -> Result<()> {
        let stage = tempfile::tempdir()?;
        for path in [
            "root/../escape",
            "/root/file",
            "root/file:stream",
            "root/COM1.txt",
            "root",
            "root/missing/file",
        ] {
            let entry = |path: &str, kind| Entry {
                path: path.into(),
                kind,
                bytes: 0,
                modified_seconds: 0,
                modified_nanos: 0,
                readonly: false,
                unix_mode: None,
            };
            let manifest =
                serde_json::to_vec(&[entry("root", Kind::Directory), entry(path, Kind::File)])?;
            let bytes = [
                MAGIC.as_slice(),
                &(manifest.len() as u32).to_le_bytes(),
                &manifest,
            ]
            .concat();
            assert!(
                restore(bytes.as_slice(), bytes.len() as u64, stage.path()).is_err(),
                "{path}"
            );
            assert_eq!(stage.path().read_dir()?.count(), 0);
        }
        Ok(())
    }
}
