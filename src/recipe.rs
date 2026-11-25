//! GRF1 groups used inside global16 archives.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::groups::{self, Group, Replay};
use crate::io::{Digest, Hash, MAX_FILE, Sha256, atomic, hex, read_up_to};
use crate::pages::MODES;
use crate::text::{GROUP, PAGE};

pub use crate::groups::{Profile, TemplatePolicy};
pub use crate::pages::TextPolicy;
pub use crate::text::Window;

pub const DEFAULT_BLOCK_SIZE: usize = GROUP;

pub fn validate_block_size(bytes: usize) -> Result<()> {
    ensure!(
        (4 * 1024..=GROUP).contains(&bytes) && bytes.is_power_of_two(),
        "Block size must be a power of two from 4 KiB to 256 KiB"
    );
    Ok(())
}

pub(crate) fn header(length: u64, block_size: usize, encrypted: bool) -> Vec<u8> {
    let kind = match (encrypted, block_size) {
        (true, _) => b"GRFE",
        (false, GROUP) => b"GRF1",
        _ => b"GRF2",
    };
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(kind);
    header.extend_from_slice(&length.to_le_bytes());
    if kind != b"GRF1" {
        header.extend_from_slice(&(block_size as u32).to_le_bytes());
    }
    header
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub bytes: u64,
    pub block_size: usize,
    pub recipe_bytes: u64,
    pub pages: usize,
    pub groups: usize,
    pub methods: BTreeMap<&'static str, usize>,
    pub group_methods: BTreeMap<&'static str, usize>,
}

impl Stats {
    fn new(bytes: u64, block_size: usize, header_len: usize) -> Self {
        Self {
            bytes,
            block_size,
            recipe_bytes: (header_len + 32) as u64,
            pages: 0,
            groups: 0,
            methods: BTreeMap::new(),
            group_methods: BTreeMap::new(),
        }
    }
    fn count(&mut self, group: &Group) {
        self.recipe_bytes += group.wire.len() as u64;
        self.pages += group.hashes.len();
        self.groups += 1;
        *self.group_methods.entry(group.kind.name()).or_default() += 1;
        for r in &group.records {
            *self.methods.entry(MODES[r.mode as usize]).or_default() += 1;
        }
    }
}

pub(crate) fn encode(
    input: impl Read,
    bytes: u64,
    block_size: usize,
    profile: &Profile,
    mut on_group: impl FnMut(&[u8], Vec<u8>) -> Result<()>,
) -> Result<()> {
    profile.validate()?;
    validate_block_size(block_size)?;
    let mut input = BufReader::new(input);
    let mut left = bytes;
    while left > 0 {
        let n = left.min(block_size as u64) as usize;
        let mut raw = vec![0; n];
        input.read_exact(&mut raw)?;
        let data = groups::pack(&raw, profile)?;
        let group = groups::parse(&data, raw.len())?;
        ensure!(
            groups::restore(&group, &[])?.bytes == raw,
            "Recipe did not reconstruct its input"
        );
        on_group(&raw, data)?;
        left -= n as u64;
    }
    ensure!(
        input.read(&mut [0])? == 0,
        "Input length changed during packing"
    );
    Ok(())
}

pub(crate) fn walk(
    path: &Path,
    mut visit: impl FnMut(&Group, &Stats) -> Result<()>,
) -> Result<(Stats, Hash)> {
    let mut file = BufReader::new(File::open(path)?);
    let mut head = [0; 16];
    file.read_exact(&mut head[..12])?;
    let (block_size, header_len) = match &head[..4] {
        b"GRF1" => (GROUP, 12),
        b"GRF2" => {
            file.read_exact(&mut head[12..])?;
            let n = u32::from_le_bytes(head[12..].try_into().unwrap()) as usize;
            validate_block_size(n)?;
            ensure!(n != GROUP, "Noncanonical GRF2 block size");
            (n, 16)
        }
        _ => anyhow::bail!("Expected an unencrypted GRF1 or GRF2 inner recipe"),
    };
    let length = u64::from_le_bytes(head[4..12].try_into().unwrap());
    ensure!(length <= MAX_FILE, "Unsupported file length");
    let mut stats = Stats::new(length, block_size, header_len);
    let mut wire = Sha256::new_with_prefix(&head[..header_len]);
    let mut left = length;
    while left > 0 {
        let n = left.min(block_size as u64) as usize;
        let group = groups::read(&mut file, n)?;
        wire.update(&group.wire);
        visit(&group, &stats)?;
        stats.count(&group);
        left -= n as u64;
    }
    let mut footer = [0; 32];
    file.read_exact(&mut footer)?;
    let expected: Hash = wire.finalize().into();
    ensure!(
        footer == expected && file.read(&mut [0])? == 0,
        "Recipe checksum or end-of-file mismatch"
    );
    Ok((stats, footer))
}

pub fn restore(path: &Path, output: &Path, damaged: Option<&Path>) -> Result<serde_json::Value> {
    let mut damaged = damaged.map(File::open).transpose()?.map(BufReader::new);
    atomic(output, |out| {
        let mut total = Replay::default();
        let mut original = Sha256::new();
        let (stats, _) = walk(path, |group, _| {
            let old = match &mut damaged {
                Some(input) => read_up_to(input, group.length)?,
                None => Vec::new(),
            };
            let result = groups::restore(group, &old)?;
            out.write_all(&result.bytes)?;
            original.update(&result.bytes);
            total.add(&result);
            Ok(())
        })?;
        let mut summary = serde_json::to_value(stats)?;
        let fields = summary.as_object_mut().unwrap();
        fields.extend(serde_json::to_value(total)?.as_object().unwrap().clone());
        fields.insert("sha256".into(), hex(&original.finalize()).into());
        Ok(summary)
    })
}

pub fn inspect(path: &Path) -> Result<serde_json::Value> {
    let mut examples = BTreeMap::new();
    let mut groups = BTreeMap::new();
    let (stats, _) = walk(path, |group, stats| {
        crate::groups::restore(group, &[])?;
        groups.entry(group.kind.name()).or_insert_with(|| {
            let mut example = serde_json::json!({
                "group": stats.groups, "originalBytes": group.length, "tapeBytes": group.tape_length,
                "recordBytes": group.wire.len(),
            });
            if group.kind == crate::templates::Kind::Title { example["boundBytes"] = group.bound_length.into(); }
            example
        });
        let mut pos = 0;
        for record in &group.records {
            examples
                .entry(MODES[record.mode as usize])
                .or_insert_with(|| {
                    let body = &group.wire[record.body.clone()];
                    let mut example =
                        serde_json::json!({"bytes": record.length, "instructionBytes": body.len()});
                    if group.kind == crate::templates::Kind::Plain {
                        example["page"] = (stats.pages + pos / PAGE).into();
                    } else {
                        example["group"] = stats.groups.into();
                        example["tapePage"] = (pos / PAGE).into();
                    }
                    if matches!(record.mode, 2..=4) {
                        let width = u16::from_le_bytes(body[..2].try_into().unwrap());
                        if record.mode == 4 {
                            example["widthBits"] = width.into();
                            example["rule"] = body[2].into();
                            example["seed"] = if body[3] == 0 {
                                "one center bit"
                            } else {
                                "literal row"
                            }
                            .into();
                        } else {
                            example["stride"] = width.into();
                            example["anchor"] = body[2].into();
                        }
                    }
                    example
                });
            pos += record.length;
        }
        Ok(())
    })?;
    let mut summary = serde_json::to_value(stats)?;
    summary["examples"] = serde_json::to_value(examples)?;
    summary["groupExamples"] = serde_json::to_value(groups)?;
    Ok(summary)
}
