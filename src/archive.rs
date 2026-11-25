//! Encode and recover global16 GRFP archives with bounded output batches.
use std::borrow::Cow;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::bundle;
use crate::frames::{self, Catalog, DATA, FRAME, GroupMeta, Layout, META, PARITY, Scan, Sha};
use crate::gf16::{self, Recovery};
use crate::groups::{self, Replay};
use crate::io::{
    Digest, Hash, Sha256, atomic, atomic_files, exact_at, hash, hex, parent, publish, read_at,
    scratch, size, write_at,
};
use crate::recipe::{self, DEFAULT_BLOCK_SIZE, Profile};
use crate::security::{self, Cipher};

pub use crate::security::{SignatureStatus, generate_encryption_key, generate_signing_key};

const MAX_VOLUMES: usize = 64;

pub struct PackOptions<'a> {
    pub parity: usize,
    pub block_size: usize,
    pub recovery_volumes: usize,
    pub bundle: bool,
    pub encrypt_key: Option<&'a Path>,
    pub sign_key: Option<&'a Path>,
}

impl Default for PackOptions<'_> {
    fn default() -> Self {
        Self {
            parity: 5,
            block_size: DEFAULT_BLOCK_SIZE,
            recovery_volumes: 0,
            bundle: false,
            encrypt_key: None,
            sign_key: None,
        }
    }
}

#[derive(Default)]
pub struct ReadOptions<'a> {
    pub volumes: &'a [PathBuf],
    pub key: Option<&'a Path>,
    pub trusted_key: Option<&'a Path>,
}

fn open_components(source: &Path, volumes: &[PathBuf]) -> Result<Vec<File>> {
    ensure!(volumes.len() <= MAX_VOLUMES, "Too many recovery volumes");
    std::iter::once(source)
        .chain(volumes.iter().map(PathBuf::as_path))
        .map(|path| {
            File::open(path).with_context(|| format!("Open archive component {}", path.display()))
        })
        .collect()
}

fn offsets(model: &Catalog) -> Vec<u64> {
    let mut at = model.recipe_header().len() as u64;
    model
        .groups
        .iter()
        .map(|entry| {
            let offset = at;
            at += entry.0 as u64;
            offset
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub original_bytes: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub original_sha256: String,
    pub grf_bytes: u64,
    pub grf_footer: String,
    pub protected_bytes: u64,
    pub protected_sha256: String,
    pub groups: usize,
    pub block_size: usize,
    pub fec: &'static str,
    pub stripes: usize,
    pub parity_percent: usize,
    pub inner_format: &'static str,
    pub inner_bytes: u64,
    pub parity_frames: usize,
    pub parity_payload_bytes: u64,
    pub framing_and_catalog_bytes: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recovery_volumes: Vec<PathBuf>,
}

fn check_volumes(volumes: usize, parity_rows: usize) -> Result<()> {
    ensure!(
        volumes <= MAX_VOLUMES && volumes <= parity_rows,
        "Recovery volumes must be at most {MAX_VOLUMES} and cannot exceed the {parity_rows} parity rows"
    );
    Ok(())
}

fn write_archive(
    inner: &Path,
    target: &Path,
    catalog: &Catalog,
    meta: &[u8],
    volumes: usize,
) -> Result<Stats> {
    let original = File::open(inner)?;
    let id = hash(meta);
    let Layout { parts, d, r, width } = frames::layout(catalog, meta)?;
    let positions = offsets(catalog);
    check_volumes(volumes, r)?;
    let mut paths = vec![target.to_path_buf()];
    for i in 1..=volumes {
        let mut path = target.as_os_str().to_os_string();
        path.push(format!(".rec.{i:03}"));
        paths.push(path.into());
    }
    let head = catalog.recipe_header();
    ensure!(
        exact_at(&original, 0, head.len())? == head,
        "Inner recipe header mismatch"
    );
    atomic_files(&paths, |outputs| {
        let mut archive_hash = Sha256::new();
        let mut recipe_hash = Sha256::new_with_prefix(&head);
        let mut inner_bytes = head.len() as u64;
        let mut protected_bytes = 0;
        let mut emit = |output: usize, kind, index, body: &[u8]| -> Result<()> {
            let header = frames::header(kind, index, &id, body);
            let out = &mut outputs[output];
            out.write_all(&header)?;
            out.write_all(body)?;
            if output == 0 {
                archive_hash.update(header);
                archive_hash.update(body);
                protected_bytes += (FRAME + body.len()) as u64;
            }
            Ok(())
        };
        let load = |i: usize| -> Result<Vec<u8>> {
            if i < parts.len() {
                return Ok(parts[i].clone());
            }
            let i = i - parts.len();
            let GroupMeta(n, _, expected) = &catalog.groups[i];
            let bytes = exact_at(&original, positions[i], *n)?;
            ensure!(
                hash(&bytes) == expected.0,
                "Inner recipe group checksum mismatch"
            );
            Ok(bytes)
        };
        for i in 0..d {
            let body = load(i)?;
            if i >= parts.len() {
                recipe_hash.update(&body);
                inner_bytes += body.len() as u64;
            }
            emit(0, DATA, frames::coordinate(d, i), &body)?;
        }
        gf16::encode(d, r, width, load, |p, body| {
            let output = if volumes == 0 { 0 } else { 1 + p % volumes };
            emit(output, PARITY, frames::coordinate(d, p), body)
        })?;
        let group_bytes = inner_bytes - head.len() as u64;
        let footer: Hash = recipe_hash.finalize().into();
        ensure!(
            footer == catalog.grf_footer.0
                && exact_at(&original, inner_bytes, 32)? == footer
                && size(&original)? == inner_bytes + 32,
            "Inner recipe checksum or length mismatch"
        );
        inner_bytes += 32;
        for output in 0..=volumes {
            emit(output, META, 0, meta)?;
        }
        let parity_payload_bytes = r as u64 * width as u64;
        Ok(Stats {
            original_bytes: catalog.bytes,
            original_sha256: catalog
                .original_sha256
                .map(|digest| hex(&digest.0))
                .unwrap_or_default(),
            grf_bytes: inner_bytes,
            grf_footer: hex(&footer),
            protected_bytes,
            protected_sha256: hex(&archive_hash.finalize()),
            groups: catalog.groups.len(),
            block_size: catalog.block_size(),
            fec: "global16",
            stripes: 1,
            parity_percent: catalog.percent,
            inner_format: match &head[..4] {
                b"GRF1" => "GRF1",
                b"GRF2" => "GRF2",
                _ => "GRFE",
            },
            inner_bytes,
            parity_frames: r,
            parity_payload_bytes,
            framing_and_catalog_bytes: protected_bytes
                - group_bytes
                - if volumes == 0 {
                    parity_payload_bytes
                } else {
                    0
                },
            recovery_volumes: paths[1..].to_vec(),
        })
    })
}

fn seal(inner: &Path, target: &Path, catalog: Catalog, volumes: usize) -> Result<Stats> {
    catalog.validate()?;
    let meta = serde_json::to_vec(&catalog)?;
    write_archive(inner, target, &catalog, &meta, volumes)
}

pub fn pack(source: &Path, target: &Path, profile: Profile, parity: usize) -> Result<Stats> {
    pack_with(
        source,
        target,
        profile,
        &PackOptions {
            parity,
            ..PackOptions::default()
        },
    )
}

pub fn pack_with(
    source: &Path,
    target: &Path,
    profile: Profile,
    options: &PackOptions<'_>,
) -> Result<Stats> {
    let bundle = options.bundle || fs::metadata(source)?.is_dir();
    let (bytes, input): (_, Box<dyn Read>) = if bundle {
        let input = bundle::Input::new(source)?;
        (input.bytes, Box::new(input))
    } else {
        let file = File::open(source)?;
        (size(&file)?, Box::new(file))
    };
    let block = options.block_size;
    frames::check_size(bytes, options.parity, block)?;
    check_volumes(
        options.recovery_volumes,
        frames::parity_count(bytes.div_ceil(block as u64) as usize, options.parity),
    )?;
    let encryption = options
        .encrypt_key
        .map(|path| {
            let salt = security::random_bytes()?;
            Ok::<_, anyhow::Error>((Cipher::new(path, &salt, bytes, block, bundle)?, salt))
        })
        .transpose()?;
    let temp = scratch(target)?;
    let inner = temp.path().join("recipe.grf");
    let mut groups = Vec::new();
    let head = recipe::header(bytes, block, encryption.is_some());
    let (original, footer) = atomic(&inner, |out| {
        out.write_all(&head)?;
        let mut footer = Sha256::new_with_prefix(&head);
        let mut digest = Sha256::new();
        recipe::encode(input, bytes, block, &profile, |raw, mut wire| {
            let plaintext_digest = if let Some((cipher, _)) = &encryption {
                cipher.encrypt(groups.len() as u64, &mut wire)?;
                None
            } else {
                Some(Sha(hash(raw)))
            };
            groups.push(GroupMeta(wire.len(), plaintext_digest, Sha(hash(&wire))));
            digest.update(raw);
            footer.update(&wire);
            out.write_all(&wire)?;
            Ok(())
        })?;
        let footer: Hash = footer.finalize().into();
        out.write_all(&footer)?;
        Ok((digest.finalize().into(), footer))
    })?;
    let mut catalog = Catalog::new(
        bytes,
        options.parity,
        block,
        profile,
        groups,
        original,
        footer,
    );
    catalog.bundle = bundle;
    if let Some((cipher, salt)) = encryption {
        catalog.original_sha256 = None;
        catalog.encryption = Some(cipher.seal_digest(salt, original)?);
    }
    if let Some(path) = options.sign_key {
        catalog.sign(path)?;
    }
    let mut stats = seal(&inner, target, catalog, options.recovery_volumes)?;
    stats.original_sha256 = hex(&original);
    Ok(stats)
}

/// Attach global16 parity to the exact inner wire, verifying the supplied profile.
pub fn protect(inner: &Path, target: &Path, profile: Profile, parity: usize) -> Result<Stats> {
    protect_with_volumes(inner, target, profile, parity, 0)
}

pub fn protect_with_volumes(
    inner: &Path,
    target: &Path,
    profile: Profile,
    parity: usize,
    volumes: usize,
) -> Result<Stats> {
    crate::io::ensure_new(target)?;
    let mut original = Sha256::new();
    let mut groups = Vec::new();
    let (stats, footer) = recipe::walk(inner, |group, stats| {
        frames::check_size(stats.bytes, parity, stats.block_size)?;
        let bytes = groups::restore(group, &[])?.bytes;
        ensure!(
            groups::pack(&bytes, &profile)? == group.wire,
            "Encoder profile does not reproduce GRF1 group {}",
            stats.groups
        );
        groups.push(GroupMeta(
            group.wire.len(),
            Some(Sha(hash(&bytes))),
            Sha(hash(&group.wire)),
        ));
        original.update(bytes);
        Ok(())
    })?;
    seal(
        inner,
        target,
        Catalog::new(
            stats.bytes,
            parity,
            stats.block_size,
            profile,
            groups,
            original.finalize().into(),
            footer,
        ),
        volumes,
    )
}

struct OpenArchive {
    files: Vec<File>,
    scan: Scan,
    signature: Option<SignatureStatus>,
}

impl OpenArchive {
    fn new(source: &Path, options: &ReadOptions<'_>) -> Result<Self> {
        Self::from_files(
            open_components(source, options.volumes)?,
            options.trusted_key,
        )
    }

    fn from_files(files: Vec<File>, trusted_key: Option<&Path>) -> Result<Self> {
        let scan = frames::scan(&files)?;
        let signature = scan.catalog.verify_signature(trusted_key)?;
        Ok(Self {
            files,
            scan,
            signature,
        })
    }
}

fn group(files: &[File], scan: &Scan, i: usize) -> Result<Option<Vec<u8>>> {
    let GroupMeta(length, _, digest) = &scan.catalog.groups[i];
    frames::load(files, scan.groups[i], *length, Some(&digest.0))
}

fn intact_group(scan: &Scan, i: usize) -> bool {
    let GroupMeta(n, _, digest) = &scan.catalog.groups[i];
    scan.groups[i].is_some_and(|e| e.length == *n && e.hash == digest.0)
}

struct Original<'a> {
    catalog: &'a Catalog,
    cipher: Option<Cipher>,
    digest: Hash,
    damaged: Option<File>,
}

impl<'a> Original<'a> {
    fn new(catalog: &'a Catalog, key: Option<&Path>, damaged: Option<&Path>) -> Result<Self> {
        ensure!(
            damaged.is_none() || (catalog.encryption.is_none() && !catalog.bundle),
            "--damaged requires an unencrypted single-file archive"
        );
        let (cipher, digest) = match (&catalog.encryption, key) {
            (Some(seal), Some(key)) => {
                let cipher = Cipher::new(
                    key,
                    &seal.salt.0,
                    catalog.bytes,
                    catalog.block_size(),
                    catalog.bundle,
                )?;
                let digest = cipher.open_digest(seal)?;
                (Some(cipher), digest)
            }
            (Some(_), None) => anyhow::bail!("Encrypted archive requires --key"),
            (None, Some(_)) => anyhow::bail!("Archive is unencrypted"),
            (None, None) => (
                None,
                catalog
                    .original_sha256
                    .context("Missing original checksum")?
                    .0,
            ),
        };
        Ok(Self {
            catalog,
            cipher,
            digest,
            damaged: damaged.map(File::open).transpose()?,
        })
    }

    fn damaged_group(&self, i: usize) -> Result<Vec<u8>> {
        match &self.damaged {
            Some(file) => read_at(
                file,
                i as u64 * self.catalog.block_size() as u64,
                self.catalog.raw_size(i),
            ),
            None => Ok(Vec::new()),
        }
    }

    fn matches_group(&self, i: usize, bytes: &[u8]) -> bool {
        bytes.len() == self.catalog.raw_size(i)
            && self.catalog.groups[i]
                .1
                .is_none_or(|digest| hash(bytes) == digest.0)
    }

    fn donor_wire(&self, i: usize) -> Result<Option<Vec<u8>>> {
        let source = self.damaged_group(i)?;
        if !self.matches_group(i, &source) {
            return Ok(None);
        }
        let GroupMeta(n, _, digest) = &self.catalog.groups[i];
        let wire = groups::pack(&source, &self.catalog.profile)?;
        Ok((wire.len() == *n && hash(&wire) == digest.0).then_some(wire))
    }

    fn restore_group(&self, i: usize, wire: &[u8]) -> Result<Replay> {
        let mut sealed;
        let wire = match &self.cipher {
            Some(cipher) => {
                sealed = wire.to_vec();
                cipher.decrypt(i as u64, &mut sealed)?
            }
            None => wire,
        };
        let original = self.damaged_group(i)?;
        let result = groups::restore(&groups::parse(wire, self.catalog.raw_size(i))?, &original)?;
        ensure!(
            self.matches_group(i, &result.bytes),
            "Original group {i} checksum mismatch"
        );
        Ok(result)
    }
}

struct ParityDecoder<'a> {
    files: &'a [File],
    scan: &'a Scan,
    layout: Layout,
    rows: Vec<usize>,
}

impl<'a> ParityDecoder<'a> {
    fn new(files: &'a [File], scan: &'a Scan) -> Result<Self> {
        let layout = frames::layout(&scan.catalog, &scan.catalog_bytes)?;
        let rows = scan
            .parity
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| entry.is_some_and(|e| e.length == layout.width).then_some(i))
            .collect();
        Ok(Self {
            files,
            scan,
            layout,
            rows,
        })
    }

    fn decode(
        &self,
        missing: &[usize],
        wanted: &[usize],
        mut load: impl FnMut(usize) -> Result<Vec<u8>>,
        mut save: impl FnMut(usize, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let Layout {
            parts, d, width, ..
        } = &self.layout;
        let catalog = &self.scan.catalog;
        let missing: Vec<_> = missing.iter().map(|i| parts.len() + i).collect();
        let wanted: Vec<_> = wanted
            .iter()
            .map(|&i| (parts.len() + i, catalog.groups[i].0))
            .collect();
        gf16::decode(
            Recovery {
                systematic: *d,
                missing: &missing,
                rows: &self.rows,
                wanted: &wanted,
                width: *width,
            },
            |i| {
                if let Some(part) = parts.get(i) {
                    Ok(part.clone())
                } else {
                    load(i - parts.len())
                }
            },
            |p| {
                frames::load(self.files, self.scan.parity[p], *width, None)?
                    .ok_or_else(|| anyhow::anyhow!("Global parity changed while reading"))
            },
            |i, bytes| {
                let i = i - parts.len();
                ensure!(
                    hash(bytes) == catalog.groups[i].2.0,
                    "Rebuilt recipe group {i} checksum mismatch"
                );
                save(i, bytes)
            },
        )
    }
}

pub fn reprotect(source: &Path, target: &Path, parity: Option<usize>) -> Result<Stats> {
    reprotect_with_volumes(source, target, parity, 0)
}

pub fn reprotect_with_volumes(
    source: &Path,
    target: &Path,
    parity: Option<usize>,
    volumes: usize,
) -> Result<Stats> {
    let temp = scratch(target)?;
    let opened = OpenArchive::new(source, &ReadOptions::default())?;
    let scan = &opened.scan;
    let inner = temp.path().join("recipe.grf");
    let mut out = File::create(&inner)?;
    let head = scan.catalog.recipe_header();
    let mut wire_hash = Sha256::new_with_prefix(&head);
    out.write_all(&head)?;
    for i in 0..scan.catalog.groups.len() {
        let bytes = group(&opened.files, scan, i)?.ok_or_else(|| {
            anyhow::anyhow!("Missing group {i}. Recover the input archive before changing parity.")
        })?;
        out.write_all(&bytes)?;
        wire_hash.update(&bytes);
    }
    let footer: Hash = wire_hash.finalize().into();
    ensure!(footer == scan.catalog.grf_footer.0, "Inner footer mismatch");
    out.write_all(&footer)?;
    drop(out);
    let mut catalog = opened.scan.catalog;
    let percent = parity.unwrap_or(catalog.percent);
    ensure!(
        catalog.signature.is_none() || catalog.percent == percent,
        "Changing a signed catalog's parity requires packing and signing it again"
    );
    catalog.percent = percent;
    seal(&inner, target, catalog, volumes)
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct RebuildStats {
    intact_recipe_groups: usize,
    recipe_groups_from_original: usize,
    recipe_groups_from_parity: usize,
    missing_parity_frames: usize,
    reused_original_pages: usize,
    rebuilt_original_pages: usize,
    replayed_original_bytes: u64,
    decoded_tape_bytes: u64,
}

fn rebuild(
    opened: &OpenArchive,
    input: &Original<'_>,
    inner: &File,
    mut original: impl Write,
) -> Result<RebuildStats> {
    let scan = &opened.scan;
    let catalog = &scan.catalog;
    let decoder = ParityDecoder::new(&opened.files, scan)?;
    let starts = offsets(catalog);
    let mut stats = RebuildStats {
        missing_parity_frames: decoder.layout.r - decoder.rows.len(),
        ..RebuildStats::default()
    };
    let mut missing = Vec::new();
    for (i, &pos) in starts.iter().enumerate() {
        if let Some(bytes) = group(&opened.files, scan, i)? {
            write_at(inner, pos, &bytes)?;
            stats.intact_recipe_groups += 1;
        } else {
            missing.push(i);
        }
    }
    let mut left = missing.len();
    let mut wanted = Vec::new();
    for i in missing {
        if input.damaged.is_some()
            && left > decoder.rows.len()
            && let Some(wire) = input.donor_wire(i)?
        {
            write_at(inner, starts[i], &wire)?;
            left -= 1;
            stats.recipe_groups_from_original += 1;
        } else {
            wanted.push(i);
        }
    }
    decoder.decode(
        &wanted,
        &wanted,
        |i| exact_at(inner, starts[i], catalog.groups[i].0),
        |i, bytes| write_at(inner, starts[i], bytes),
    )?;
    stats.recipe_groups_from_parity = wanted.len();
    let head = catalog.recipe_header();
    write_at(inner, 0, &head)?;
    let mut wire_hash = Sha256::new_with_prefix(&head);
    let mut raw_hash = Sha256::new();
    let mut replay = Replay::default();
    let mut pos = head.len() as u64;
    for (i, GroupMeta(n, _, wire_expected)) in catalog.groups.iter().enumerate() {
        let wire = exact_at(inner, pos, *n)?;
        pos += *n as u64;
        ensure!(
            hash(&wire) == wire_expected.0,
            "Recipe group {i} checksum mismatch"
        );
        wire_hash.update(&wire);
        let restored = input.restore_group(i, &wire)?;
        original.write_all(&restored.bytes)?;
        raw_hash.update(&restored.bytes);
        replay.add(&restored);
    }
    let footer: Hash = wire_hash.finalize().into();
    let digest: Hash = raw_hash.finalize().into();
    ensure!(
        footer == catalog.grf_footer.0 && digest == input.digest,
        "Final original or inner recipe digest mismatch"
    );
    write_at(inner, pos, &footer)?;
    stats.reused_original_pages = replay.reused_pages;
    stats.rebuilt_original_pages = replay.rebuilt_pages;
    stats.replayed_original_bytes = replay.replayed_bytes;
    stats.decoded_tape_bytes = replay.decoded_tape_bytes;
    Ok(stats)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStats {
    #[serde(flatten)]
    pub archive: Stats,
    pub intact_catalog_copies: usize,
    pub catalog_pieces_from_parity: usize,
    pub rejected_frames: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureStatus>,
    #[serde(flatten)]
    rebuild: RebuildStats,
}

pub fn recover(source: &Path, target: &Path, damaged: Option<&Path>) -> Result<RecoveryStats> {
    recover_with(source, target, damaged, &ReadOptions::default())
}

pub fn recover_with(
    source: &Path,
    target: &Path,
    damaged: Option<&Path>,
    options: &ReadOptions<'_>,
) -> Result<RecoveryStats> {
    let temp = scratch(target)?;
    let opened = OpenArchive::new(source, options)?;
    let scan = &opened.scan;
    let input = Original::new(&scan.catalog, options.key, damaged)?;
    let recipe = temp.path().join("recipe.grf");
    let data = temp.path().join("restored.bin");
    let rebuild = {
        let inner = File::options()
            .create_new(true)
            .write(true)
            .read(true)
            .open(&recipe)?;
        rebuild(&opened, &input, &inner, File::create(&data)?)?
    };
    let mut archive = write_archive(
        &recipe,
        &temp.path().join("protected.grfp"),
        &scan.catalog,
        &scan.catalog_bytes,
        0,
    )?;
    archive.original_sha256 = hex(&input.digest);
    publish(
        temp.path(),
        target,
        &["restored.bin", "recipe.grf", "protected.grfp"],
    )?;
    Ok(RecoveryStats {
        archive,
        intact_catalog_copies: scan.copies,
        catalog_pieces_from_parity: scan.from_parity,
        rejected_frames: scan.rejected,
        signature: opened.signature,
        rebuild,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalSource {
    Archive,
    Donor,
    Parity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginalRecoveryStats {
    pub original_bytes: u64,
    pub original_sha256: String,
    pub recipe_groups_from_parity: usize,
    pub original_groups_from_damaged: usize,
    pub catalog_pieces_from_parity: usize,
    pub rejected_frames: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureStatus>,
}

/// Recover and verify only the original file from a global16 archive.
pub fn recover_original(
    source: &Path,
    target: &Path,
    damaged: Option<&Path>,
) -> Result<OriginalRecoveryStats> {
    recover_original_with(source, target, damaged, &ReadOptions::default())
}

pub fn recover_original_with(
    source: &Path,
    target: &Path,
    damaged: Option<&Path>,
    options: &ReadOptions<'_>,
) -> Result<OriginalRecoveryStats> {
    atomic(target, |out| {
        let opened = OpenArchive::new(source, options)?;
        ensure!(
            !opened.scan.catalog.bundle,
            "Bundle archive requires grfp extract"
        );
        let input = Original::new(&opened.scan.catalog, options.key, damaged)?;
        let stats = stream_original(&opened, &input, &mut *out, Some(parent(target)))?;
        ensure!(
            out.metadata()?.len() == stats.original_bytes,
            "Final output length mismatch"
        );
        Ok(stats)
    })
}

fn stream_original(
    opened: &OpenArchive,
    input: &Original<'_>,
    mut out: impl Write,
    spool_parent: Option<&Path>,
) -> Result<OriginalRecoveryStats> {
    let scan = &opened.scan;
    let catalog = &scan.catalog;
    let mut sources = Vec::with_capacity(catalog.groups.len());
    let mut wanted = Vec::new();
    let mut original_groups_from_damaged = 0;
    for i in 0..catalog.groups.len() {
        let source = if intact_group(scan, i) {
            OriginalSource::Archive
        } else if input.damaged.is_some() && input.matches_group(i, &input.damaged_group(i)?) {
            original_groups_from_damaged += 1;
            OriginalSource::Donor
        } else {
            wanted.push(i);
            OriginalSource::Parity
        };
        sources.push(source);
    }

    let from_archive = |i| {
        group(&opened.files, scan, i)?
            .ok_or_else(|| anyhow::anyhow!("Recipe group {i} is missing or changed"))
    };
    let mut digest = Sha256::new();
    let mut original_bytes = 0;
    let mut next = 0;
    // The parity decoder emits wanted groups in order. Fill the gaps by
    // streaming the intact groups so verification needs just one pass.
    let mut emit_through = |end, recovered: Option<&[u8]>| -> Result<()> {
        let limit = end + usize::from(recovered.is_some());
        while next < limit {
            let raw = if sources[next] == OriginalSource::Donor {
                let bytes = input.damaged_group(next)?;
                ensure!(
                    input.matches_group(next, &bytes),
                    "Original group {next} changed"
                );
                bytes
            } else {
                let wire = if next == end
                    && let Some(bytes) = recovered
                {
                    Cow::Borrowed(bytes)
                } else {
                    Cow::Owned(from_archive(next)?)
                };
                input.restore_group(next, &wire)?.bytes
            };
            out.write_all(&raw)?;
            digest.update(&raw);
            original_bytes += raw.len() as u64;
            next += 1;
        }
        Ok(())
    };

    if !wanted.is_empty() {
        let decoder = ParityDecoder::new(&opened.files, scan)?;
        let available = decoder.rows.len();
        ensure!(
            wanted.len() <= available,
            "Insufficient global parity: {} groups need recovery, {} usable",
            wanted.len(),
            available
        );
        let mut left = wanted.len() + original_groups_from_damaged;
        let mut missing = Vec::with_capacity(left);
        let mut donor_offsets = vec![None; sources.len()];
        let mut spool: Option<File> = None;
        let mut offset = 0;
        for (i, &source) in sources.iter().enumerate() {
            if source == OriginalSource::Archive {
                continue;
            }
            // An original copy can be emitted directly. Re-encode donors
            // only if another group's parity equations need their wire.
            if source == OriginalSource::Donor
                && left > available
                && let Some(wire) = input.donor_wire(i)?
            {
                let file = match &mut spool {
                    Some(file) => file,
                    slot => slot.insert(tempfile::tempfile_in(
                        spool_parent.context("Missing donor spool directory")?,
                    )?),
                };
                write_at(file, offset, &wire)?;
                donor_offsets[i] = Some(offset);
                offset += wire.len() as u64;
                left -= 1;
            } else {
                missing.push(i);
            }
        }
        decoder.decode(
            &missing,
            &wanted,
            |i| match donor_offsets[i] {
                Some(offset) => exact_at(spool.as_ref().unwrap(), offset, catalog.groups[i].0),
                None => from_archive(i),
            },
            |i, wire| emit_through(i, Some(wire)),
        )?;
    }
    emit_through(sources.len(), None)?;
    let digest: Hash = digest.finalize().into();
    ensure!(
        digest == input.digest && original_bytes == catalog.bytes,
        "Final original length or checksum mismatch"
    );
    Ok(OriginalRecoveryStats {
        original_bytes: catalog.bytes,
        original_sha256: hex(&digest),
        recipe_groups_from_parity: wanted.len(),
        original_groups_from_damaged,
        catalog_pieces_from_parity: scan.from_parity,
        rejected_frames: scan.rejected,
        signature: opened.signature.clone(),
    })
}

pub fn inspect(source: &Path) -> Result<serde_json::Value> {
    inspect_with(source, &ReadOptions::default())
}

pub fn inspect_with(source: &Path, options: &ReadOptions<'_>) -> Result<serde_json::Value> {
    let files = open_components(source, options.volumes)?;
    if matches!(read_at(&files[0], 0, 4)?.as_slice(), b"GRF1" | b"GRF2") {
        ensure!(
            options.volumes.is_empty() && options.trusted_key.is_none(),
            "Volumes and signatures apply to GRFP archives"
        );
        return recipe::inspect(source);
    }
    let opened = OpenArchive::from_files(files, options.trusted_key)?;
    let scan = &opened.scan;
    let width = frames::layout(&scan.catalog, &scan.catalog_bytes)?.width;
    let intact = (0..scan.catalog.groups.len())
        .filter(|&i| intact_group(scan, i))
        .count();
    Ok(serde_json::json!({
        "catalog": scan.catalog,
        "blockSize": scan.catalog.block_size(),
        "catalogCopies": scan.copies,
        "catalogPiecesFromParity": scan.from_parity,
        "intactRecipeGroups": intact,
        "availableParityFrames": scan.parity.iter().flatten().filter(|entry| entry.length == width).count(),
        "rejectedFrames": scan.rejected,
        "signature": opened.signature,
    }))
}

pub fn verify(source: &Path, options: &ReadOptions<'_>) -> Result<OriginalRecoveryStats> {
    let opened = OpenArchive::new(source, options)?;
    let input = Original::new(&opened.scan.catalog, options.key, None)?;
    stream_original(&opened, &input, io::sink(), None)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractionStats {
    pub root: String,
    pub entries: usize,
    #[serde(flatten)]
    pub recovery: OriginalRecoveryStats,
}

pub fn extract(source: &Path, target: &Path, options: &ReadOptions<'_>) -> Result<ExtractionStats> {
    let opened = OpenArchive::new(source, options)?;
    ensure!(
        opened.scan.catalog.bundle,
        "Single-file archive requires grfp recover-original"
    );
    let input = Original::new(&opened.scan.catalog, options.key, None)?;
    let stage = scratch(target)?;
    let mut data = tempfile::tempfile_in(stage.path())?;
    let recovery = stream_original(&opened, &input, &mut data, None)?;
    data.rewind()?;
    let (root, entries) = bundle::restore(data, recovery.original_bytes, stage.path())?;
    fs::create_dir(target).with_context(|| format!("Create {}", target.display()))?;
    if let Err(error) = fs::rename(stage.path().join(&root), target.join(&root)) {
        let _ = fs::remove_dir(target);
        return Err(error).with_context(|| format!("Publish {}", target.display()));
    }
    Ok(ExtractionStats {
        root,
        entries,
        recovery,
    })
}
