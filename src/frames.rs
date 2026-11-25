//! GRP1 framing and catalog recovery for global16.
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::gf16::{self, Recovery};
use crate::io::{Digest, Hash, Sha256, exact_at, hash, hash_from_text, hex, put32, read_at, size};
use crate::recipe::{self, Profile, validate_block_size};
use crate::security::{self, Seal, Signature, SignatureStatus, TAG_BYTES};
use crate::text::{GROUP, PAGE};

const SYNC: &[u8; 8] = b"GRP1\r\n\x1a\n";
pub(crate) const FRAME: usize = 81;
pub(crate) const META: u8 = 0;
pub(crate) const DATA: u8 = 3;
pub(crate) const PARITY: u8 = 4;
const CAT_BLOCK: usize = 65_536;
const MAX_META: usize = 16 * 1024 * 1024;
const MAX_BODY: usize = GROUP + 19 * (GROUP / PAGE) + TAG_BYTES;

#[derive(Clone, Copy)]
pub(crate) struct Sha(pub Hash);

impl Serialize for Sha {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for Sha {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        let text = String::deserialize(input)?;
        hash_from_text(&text)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct GroupMeta(pub usize, pub Option<Sha>, pub Sha);

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Catalog {
    format: String,
    encoder: String,
    stripe: String,
    pub percent: usize,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_sha256: Option<Sha>,
    pub grf_footer: Sha,
    pub profile: Profile,
    pub groups: Vec<GroupMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_size: Option<usize>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bundle: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Seal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

pub(crate) fn parity_count(k: usize, percent: usize) -> usize {
    (k * percent).div_ceil(100)
}

pub(crate) fn check_size(bytes: u64, percent: usize, block_size: usize) -> Result<()> {
    validate_block_size(block_size)?;
    ensure!(
        percent <= 100,
        "Parity must be a whole percentage from 0 to 100"
    );
    let k = bytes.div_ceil(block_size as u64);
    ensure!(
        k < gf16::LIMIT as u64,
        "Source exceeds the global16 group limit"
    );
    let k = k as usize;
    gf16::check(k + 1, parity_count(k, percent))
}

impl Catalog {
    pub(crate) fn new(
        bytes: u64,
        percent: usize,
        block_size: usize,
        profile: Profile,
        groups: Vec<GroupMeta>,
        original: Hash,
        footer: Hash,
    ) -> Self {
        Self {
            format: "GRP1".into(),
            encoder: "grf1-group-v1".into(),
            stripe: "global16".into(),
            percent,
            bytes,
            original_sha256: Some(Sha(original)),
            grf_footer: Sha(footer),
            profile,
            groups,
            block_size: (block_size != GROUP).then_some(block_size),
            bundle: false,
            encryption: None,
            signature: None,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "GRP1" && self.stripe == "global16" && self.encoder == "grf1-group-v1",
            "Expected a global16 GRP1 archive containing GRF1 groups"
        );
        check_size(self.bytes, self.percent, self.block_size())?;
        self.profile.validate()?;
        let encrypted = self.encryption.is_some();
        ensure!(
            encrypted == self.original_sha256.is_none()
                && self
                    .encryption
                    .as_ref()
                    .is_none_or(|seal| seal.original_digest.len() == 32 + TAG_BYTES)
                && self
                    .signature
                    .as_ref()
                    .is_none_or(|signature| signature.signature.len() == 64),
            "Invalid catalog authentication fields"
        );
        ensure!(
            self.groups.len() as u64 == self.bytes.div_ceil(self.block_size() as u64),
            "Invalid catalog group count"
        );
        for (i, group) in self.groups.iter().enumerate() {
            let n = self.raw_size(i);
            let tag = if encrypted { TAG_BYTES } else { 0 };
            ensure!(
                group.1.is_none() == encrypted
                    && (1 + tag..=n + 19 * n.div_ceil(PAGE) + tag).contains(&group.0),
                "Invalid catalog group length"
            );
        }
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let catalog: Self = serde_json::from_slice(bytes)?;
        catalog.validate()?;
        if catalog.signature.is_some() {
            ensure!(
                serde_json::to_vec(&catalog)? == bytes,
                "Signed catalog must use canonical GRFP JSON"
            );
        }
        Ok(catalog)
    }

    pub(crate) fn sign(&mut self, path: &Path) -> Result<()> {
        ensure!(self.signature.is_none(), "Catalog already signed");
        self.signature = Some(security::sign(&serde_json::to_vec(self)?, path)?);
        Ok(())
    }

    pub(crate) fn verify_signature(&self, path: Option<&Path>) -> Result<Option<SignatureStatus>> {
        let Some(signature) = &self.signature else {
            ensure!(
                path.is_none(),
                "A trusted public key requires a signed archive"
            );
            return Ok(None);
        };
        let mut unsigned = self.clone();
        unsigned.signature = None;
        Ok(Some(
            signature.verify(&serde_json::to_vec(&unsigned)?, path)?,
        ))
    }

    pub(crate) fn block_size(&self) -> usize {
        self.block_size.unwrap_or(GROUP)
    }

    pub(crate) fn recipe_header(&self) -> Vec<u8> {
        recipe::header(self.bytes, self.block_size(), self.encryption.is_some())
    }

    pub(crate) fn raw_size(&self, i: usize) -> usize {
        let block = self.block_size() as u64;
        (self.bytes - i as u64 * block).min(block) as usize
    }
}

pub(crate) struct Layout {
    pub parts: Vec<Vec<u8>>,
    pub d: usize,
    pub r: usize,
    pub width: usize,
}

pub(crate) fn layout(model: &Catalog, meta: &[u8]) -> Result<Layout> {
    ensure!(
        (1..=MAX_META).contains(&meta.len()),
        "Invalid global catalog length"
    );
    let mut prefixed = Vec::with_capacity(4 + meta.len());
    put32(&mut prefixed, meta.len());
    prefixed.extend_from_slice(meta);
    let parts: Vec<_> = prefixed.chunks(CAT_BLOCK).map(<[u8]>::to_vec).collect();
    let d = parts.len() + model.groups.len();
    let r = parity_count(model.groups.len(), model.percent);
    gf16::check(d, r)?;
    let width = gf16::even(
        model
            .groups
            .iter()
            .map(|g| g.0)
            .fold(parts[0].len(), usize::max),
    );
    Ok(Layout { parts, d, r, width })
}

pub(crate) fn coordinate(d: usize, i: usize) -> u32 {
    (d as u32) << 16 | i as u32
}

pub(crate) fn header(kind: u8, index: u32, id: &Hash, body: &[u8]) -> [u8; FRAME] {
    let mut header = [0; FRAME];
    header[..8].copy_from_slice(SYNC);
    header[8] = kind;
    header[9..13].copy_from_slice(&index.to_le_bytes());
    header[13..17].copy_from_slice(&(body.len() as u32).to_le_bytes());
    header[17..49].copy_from_slice(id);
    let mut digest = Sha256::new_with_prefix(&header[8..49]);
    digest.update(body);
    header[49..].copy_from_slice(&digest.finalize());
    header
}

#[derive(Clone, Copy)]
pub(crate) struct Entry {
    pub source: usize,
    pub at: u64,
    pub length: usize,
    pub hash: Hash,
}

#[derive(Default)]
struct Candidate {
    d: usize,
    data: HashMap<usize, Entry>,
    parity: HashMap<usize, Entry>,
}

pub(crate) struct Scan {
    pub catalog: Catalog,
    pub catalog_bytes: Vec<u8>,
    pub groups: Vec<Option<Entry>>,
    pub parity: Vec<Option<Entry>>,
    pub copies: usize,
    pub rejected: usize,
    pub from_parity: usize,
}

pub(crate) fn load(
    files: &[File],
    entry: Option<Entry>,
    length: usize,
    expected: Option<&Hash>,
) -> Result<Option<Vec<u8>>> {
    let Some(entry) = entry else {
        return Ok(None);
    };
    if entry.length != length || expected.is_some_and(|expected| *expected != entry.hash) {
        return Ok(None);
    }
    let bytes = read_at(&files[entry.source], entry.at + FRAME as u64, length)?;
    Ok((bytes.len() == length && hash(&bytes) == entry.hash).then_some(bytes))
}

fn next_marker(file: &File, mut from: u64, end: u64) -> Result<u64> {
    while end - from >= SYNC.len() as u64 {
        let block = read_at(file, from, (128 * 1024).min(end - from) as usize)?;
        if let Some(i) = memchr::memmem::find(&block, SYNC) {
            return Ok(from + i as u64);
        }
        if block.len() <= SYNC.len() {
            break;
        }
        from += (block.len() - SYNC.len() + 1) as u64;
    }
    Ok(end)
}

fn bootstrap(files: &[File], expected: &Hash, frames: &Candidate) -> Result<(Vec<u8>, usize)> {
    let d = frames.d;
    let mut rows: Vec<_> = frames.parity.iter().collect();
    rows.sort_unstable_by_key(|(_, frame)| (frame.source, frame.at));
    let ids: Vec<_> = rows.into_iter().map(|(&i, _)| i).collect();
    let missing: Vec<_> = (0..d).filter(|i| !frames.data.contains_key(i)).collect();
    let read = |entry: &Entry| {
        load(files, Some(*entry), entry.length, None)?
            .ok_or_else(|| anyhow::anyhow!("Global frame changed during recovery"))
    };
    let mut recovered = HashMap::new();
    let solve = |targets: Vec<usize>, recovered: &mut HashMap<usize, Vec<u8>>| -> Result<()> {
        if targets.is_empty() {
            return Ok(());
        }
        ensure!(
            !ids.is_empty() && missing.len() <= ids.len(),
            "No recoverable global catalog: insufficient parity"
        );
        let width = frames.parity[&ids[0]].length;
        ensure!(
            width.is_multiple_of(2) && ids.iter().all(|i| frames.parity[i].length == width),
            "Invalid global parity width"
        );
        let width = width.min(CAT_BLOCK);
        let wanted: Vec<_> = targets.into_iter().map(|i| (i, width)).collect();
        gf16::decode(
            Recovery {
                systematic: d,
                missing: &missing,
                rows: &ids,
                wanted: &wanted,
                width,
            },
            |i| read(&frames.data[&i]),
            |i| read(&frames.parity[&i]),
            |i, b| {
                recovered.insert(i, b.to_vec());
                Ok(())
            },
        )
    };
    let first = match frames.data.get(&0) {
        Some(entry) => read(entry)?,
        None => {
            solve(vec![0], &mut recovered)?;
            recovered[&0].clone()
        }
    };
    ensure!(first.len() >= 4, "Short global catalog");
    let length = u32::from_le_bytes(first[..4].try_into().unwrap()) as usize;
    let count = (4 + length).div_ceil(CAT_BLOCK);
    ensure!(
        (1..=MAX_META).contains(&length) && count <= d,
        "Invalid global catalog length"
    );
    solve(
        missing
            .iter()
            .copied()
            .filter(|&i| i > 0 && i < count)
            .collect(),
        &mut recovered,
    )?;
    let mut catalog = Vec::with_capacity(4 + length);
    for i in 0..count {
        let bytes = if i == 0 {
            first.clone()
        } else if let Some(bytes) = recovered.get(&i) {
            bytes.clone()
        } else {
            read(&frames.data[&i])?
        };
        let n = (4 + length - i * CAT_BLOCK).min(CAT_BLOCK);
        ensure!(
            bytes.len() >= n && (recovered.contains_key(&i) || bytes.len() == n),
            "Invalid global catalog shard length"
        );
        catalog.extend_from_slice(&bytes[..n]);
    }
    let bytes = catalog.split_off(4);
    ensure!(
        hash(&bytes) == *expected,
        "Recovered catalog identity mismatch"
    );
    Ok((bytes, recovered.len()))
}

pub(crate) fn scan(files: &[File]) -> Result<Scan> {
    let mut candidates: HashMap<Hash, Candidate> = HashMap::new();
    let mut meta: Option<(Hash, Catalog, Vec<u8>)> = None;
    let mut copies = 0;
    let mut rejected = 0;
    let mut unique = 0;
    for (source, file) in files.iter().enumerate() {
        let end = size(file)?;
        let mut pos = 0;
        while pos + FRAME as u64 <= end {
            let h = exact_at(file, pos, FRAME)?;
            if &h[..8] == SYNC {
                let kind = h[8];
                let index = u32::from_le_bytes(h[9..13].try_into().unwrap());
                let n = u32::from_le_bytes(h[13..17].try_into().unwrap()) as usize;
                let id: Hash = h[17..49].try_into().unwrap();
                let d = (index >> 16) as usize;
                let slot = (index & 65_535) as usize;
                let header_ok = match kind {
                    META => index == 0 && (1..=MAX_META).contains(&n),
                    DATA => d > 0 && slot < d && (1..=MAX_BODY).contains(&n),
                    PARITY => d > 0 && d + slot < gf16::LIMIT && (1..=MAX_BODY).contains(&n),
                    _ => false,
                };
                if header_ok && pos + (FRAME + n) as u64 <= end {
                    let body = exact_at(file, pos + FRAME as u64, n)?;
                    let mut check = Sha256::new_with_prefix(&h[8..49]);
                    check.update(&body);
                    let digest: Hash = check.finalize().into();
                    if digest == h[49..] {
                        let hash = hash(&body);
                        if kind == META {
                            ensure!(hash == id, "Catalog identity mismatch");
                            if let Some((owner, _, _)) = &meta {
                                ensure!(*owner == id, "Conflicting protected archive catalogs");
                            } else {
                                let catalog = Catalog::decode(&body)?;
                                meta = Some((id, catalog, body));
                            }
                            copies += 1;
                        } else {
                            let frames = candidates.entry(id).or_default();
                            ensure!(
                                frames.d == 0 || frames.d == d,
                                "Conflicting global geometries"
                            );
                            frames.d = d;
                            let entries = if kind == DATA {
                                &mut frames.data
                            } else {
                                &mut frames.parity
                            };
                            if let Some(previous) = entries.get(&slot) {
                                ensure!(
                                    previous.hash == hash,
                                    "Conflicting copies of a protected frame"
                                );
                            } else {
                                unique += 1;
                                ensure!(
                                    unique <= 2 * (gf16::LIMIT + 1),
                                    "Too many protected frames"
                                );
                                entries.insert(
                                    slot,
                                    Entry {
                                        source,
                                        at: pos,
                                        length: n,
                                        hash,
                                    },
                                );
                            }
                        }
                        pos += (FRAME + n) as u64;
                        continue;
                    }
                }
                rejected += 1;
            }
            pos = next_marker(file, pos + 1, end)?;
        }
    }
    let mut from_parity = 0;
    let (id, catalog, catalog_bytes) = match meta {
        Some(meta) => meta,
        None => {
            ensure!(candidates.len() == 1, "No unambiguous global16 catalog");
            let (&id, frames) = candidates.iter().next().unwrap();
            let (bytes, repaired) = bootstrap(files, &id, frames)?;
            from_parity = repaired;
            (id, Catalog::decode(&bytes)?, bytes)
        }
    };
    let frames = candidates.remove(&id).unwrap_or_default();
    let Layout { parts, d, r, .. } = layout(&catalog, &catalog_bytes)?;
    ensure!(
        frames.d == 0 || frames.d == d,
        "Catalog and coded geometry disagree"
    );
    if parts
        .iter()
        .enumerate()
        .all(|(i, body)| frames.data.get(&i).is_some_and(|e| e.hash == hash(body)))
    {
        copies += 1;
    }
    let groups = (parts.len()..d)
        .map(|i| frames.data.get(&i).copied())
        .collect();
    let parity = (0..r).map(|i| frames.parity.get(&i).copied()).collect();
    Ok(Scan {
        catalog,
        catalog_bytes,
        groups,
        parity,
        copies,
        rejected,
        from_parity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn bootstraps_two_erased_catalog_shards() -> Result<()> {
        // The scanner works from frame coordinates and hashes before it
        // knows the raw group records. Use small wire bodies to isolate it.
        let shards: Vec<_> = (0..540usize)
            .map(|i| vec![i as u8, (i >> 8) as u8, 7])
            .collect();
        let groups = shards
            .iter()
            .map(|b| GroupMeta(b.len(), Some(Sha(hash(b))), Sha(hash(b))))
            .collect();
        let model = Catalog::new(
            shards.len() as u64 * GROUP as u64,
            1,
            GROUP,
            Profile::default(),
            groups,
            [0; 32],
            [1; 32],
        );
        let meta = serde_json::to_vec(&model)?;
        let Layout {
            mut parts,
            d,
            r,
            width,
        } = layout(&model, &meta)?;
        assert_eq!(parts.len(), 2);
        parts.extend(shards);
        let id = hash(&meta);
        let mut file = tempfile::tempfile()?;
        for (i, data) in parts.iter().enumerate().skip(2) {
            file.write_all(&header(DATA, coordinate(d, i), &id, data))?;
            file.write_all(data)?;
        }
        gf16::encode(
            d,
            r,
            width,
            |i| Ok(parts[i].clone()),
            |p, body| {
                file.write_all(&header(PARITY, coordinate(d, p), &id, body))?;
                file.write_all(body)?;
                Ok(())
            },
        )?;
        let recovered = scan(&[file])?;
        assert_eq!(recovered.catalog_bytes, meta);
        assert_eq!(recovered.from_parity, 2);
        assert_eq!(recovered.groups.len(), 540);
        Ok(())
    }
}
