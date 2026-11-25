use std::fs::{self, File, OpenOptions};
use std::io::{Read, Result as IoResult, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
pub(crate) use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};

pub(crate) type Hash = [u8; 32];
pub(crate) const MAX_FILE: u64 = (1 << 53) - 1;

pub(crate) fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    s
}

pub(crate) fn hash_from_text(s: &str) -> Result<Hash> {
    ensure!(s.len() == 64, "Invalid SHA-256 length");
    let digit = |b: u8| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => anyhow::bail!("Invalid SHA-256 hexadecimal digit"),
    };
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        *out = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(result)
}

pub(crate) fn size(file: &File) -> Result<u64> {
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= MAX_FILE,
        "Expected a regular input file"
    );
    Ok(meta.len())
}

pub(crate) fn read_up_to(mut read: impl Read, n: usize) -> IoResult<Vec<u8>> {
    let mut bytes = vec![0; n];
    let mut used = 0;
    while used < n {
        let count = read.read(&mut bytes[used..])?;
        if count == 0 {
            break;
        }
        used += count;
    }
    bytes.truncate(used);
    Ok(bytes)
}

pub(crate) fn read_at(mut file: &File, pos: u64, n: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(pos))?;
    Ok(read_up_to(file, n)?)
}

pub(crate) fn exact_at(file: &File, pos: u64, n: usize) -> Result<Vec<u8>> {
    let bytes = read_at(file, pos, n)?;
    ensure!(bytes.len() == n, "Truncated input");
    Ok(bytes)
}

pub(crate) fn write_at(mut file: &File, pos: u64, bytes: &[u8]) -> Result<()> {
    file.seek(SeekFrom::Start(pos))?;
    file.write_all(bytes)?;
    Ok(())
}

pub(crate) fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

pub(crate) fn ensure_new(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("Output already exists: {}", path.display()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn atomic<T>(path: &Path, action: impl FnOnce(&mut File) -> Result<T>) -> Result<T> {
    ensure_new(path)?;
    let mut stage = NamedTempFile::new_in(parent(path))?;
    let result = action(stage.as_file_mut())?;
    stage
        .persist_noclobber(path)
        .with_context(|| format!("Publish {}", path.display()))?;
    Ok(result)
}

pub(crate) fn atomic_files<T>(
    paths: &[PathBuf],
    action: impl FnOnce(&mut [NamedTempFile]) -> Result<T>,
) -> Result<T> {
    let mut staged = Vec::with_capacity(paths.len());
    for path in paths {
        ensure_new(path)?;
        staged.push(NamedTempFile::new_in(parent(path))?);
    }
    let result = action(&mut staged)?;
    let mut published = Vec::with_capacity(paths.len());
    // Make the primary path visible after its companion files.
    for (file, path) in staged.into_iter().zip(paths).rev() {
        if let Err(error) = file.persist_noclobber(path) {
            for path in published {
                let _ = fs::remove_file(path);
            }
            return Err(error).with_context(|| format!("Publish {}", path.display()));
        }
        published.push(path);
    }
    Ok(result)
}

pub(crate) fn scratch(path: &Path) -> Result<TempDir> {
    ensure_new(path)?;
    Ok(tempfile::Builder::new()
        .prefix(".grfp-")
        .tempdir_in(parent(path))?)
}

pub(crate) fn publish(stage: &Path, target: &Path, files: &[&str]) -> Result<()> {
    fs::create_dir(target).with_context(|| format!("Create {}", target.display()))?;
    let mut published: Vec<PathBuf> = Vec::new();
    let result = (|| {
        for name in files {
            let src = stage.join(name);
            let dst = target.join(name);
            if fs::hard_link(&src, &dst).is_err() {
                let mut input = File::open(src)?;
                let mut file = OpenOptions::new().write(true).create_new(true).open(&dst)?;
                published.push(dst);
                std::io::copy(&mut input, &mut file)?;
            } else {
                published.push(dst);
            }
        }
        Ok(())
    })();
    if result.is_err() {
        for path in published {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir(target);
    }
    result
}

pub(crate) fn deflate(bytes: &[u8], level: u32) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(bytes.len() + bytes.len() / 8 + 128);
    let status = Compress::new(Compression::new(level), false).compress_vec(
        bytes,
        &mut output,
        FlushCompress::Finish,
    )?;
    ensure!(
        status == Status::StreamEnd,
        "DEFLATE output buffer exhausted"
    );
    Ok(output)
}

pub(crate) fn inflate(bytes: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut decoder = Decompress::new(false);
    let mut output = Vec::with_capacity(length + 1);
    let status = decoder.decompress_vec(bytes, &mut output, FlushDecompress::Finish)?;
    ensure!(
        status == Status::StreamEnd
            && output.len() == length
            && decoder.total_in() == bytes.len() as u64,
        "Invalid DEFLATE length"
    );
    Ok(output)
}

pub(crate) struct Bytes<'a> {
    raw: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Bytes<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw, pos: 0 }
    }
    pub(crate) fn left(&self) -> &'a [u8] {
        &self.raw[self.pos..]
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.left().len(), "Truncated record");
        let result = &self.raw[self.pos..self.pos + n];
        self.pos += n;
        Ok(result)
    }
    pub(crate) fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    pub(crate) fn vint(&mut self, max_shift: u32) -> Result<u64> {
        let mut result = 0;
        for shift in (0..=max_shift).step_by(7) {
            let b = self.byte()?;
            result |= u64::from(b & 127) << shift;
            if b < 128 {
                ensure!(shift == 0 || b != 0, "Noncanonical variable integer");
                return Ok(result);
            }
        }
        anyhow::bail!("Invalid variable integer")
    }
}

pub(crate) fn put_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}

pub(crate) fn put32(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}

pub(crate) fn append_bounded(out: &mut Vec<u8>, data: &[u8], limit: usize) -> Result<()> {
    ensure!(
        data.len() <= limit - out.len(),
        "Expansion exceeds declared output length"
    );
    out.extend_from_slice(data);
    Ok(())
}
