use crate::io::{Bytes, deflate, inflate, put_vint};
use crate::text::{self, GROUP, PAGE, WIDE, Window};
use anyhow::{Result, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub(crate) const MODES: [&str; 15] = [
    "literal",
    "deflate",
    "links",
    "links-deflate",
    "row-ca",
    "text-context",
    "text-span",
    "text-context-64-reset",
    "text-span-64-reset",
    "text-context-64",
    "text-span-64",
    "text-context-256-reset",
    "text-span-256-reset",
    "text-context-256",
    "text-span-256",
];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TextPolicy {
    Off,
    Context,
    Span,
}

pub(crate) fn wide(mode: u8) -> bool {
    (7..=10).contains(&mode)
}
pub(crate) fn large(mode: u8) -> bool {
    (11..=14).contains(&mode)
}

fn bit(bytes: &[u8], i: usize) -> u8 {
    (bytes[i / 8] >> (i % 8)) & 1
}
fn flip(bytes: &mut [u8], i: usize) {
    bytes[i / 8] ^= 1 << (i % 8);
}

fn read_patches(
    raw: &[u8],
    limit: usize,
    masks: bool,
    mut apply: impl FnMut(usize, u8),
) -> Result<()> {
    let mut input = Bytes::new(raw);
    let mut next = 0;
    while !input.left().is_empty() {
        let index = next + input.vint(14)? as usize;
        ensure!(index < limit, "Patch outside page");
        let mask = if masks { input.byte()? } else { 1 };
        ensure!(mask != 0, "Missing XOR mask");
        apply(index, mask);
        next = index + 1;
    }
    Ok(())
}

fn links_of(bytes: &[u8], stride: usize) -> Vec<u8> {
    (1..bytes.len())
        .map(|i| bytes[i] ^ bytes[if i < stride { i - 1 } else { i - stride }])
        .collect()
}

fn links(mode: u8, body: &[u8], length: usize) -> Result<Vec<u8>> {
    ensure!(length >= 2 && body.len() >= 3, "Invalid link page size");
    let stride = u16::from_le_bytes(body[..2].try_into().unwrap()) as usize;
    ensure!((1..length).contains(&stride), "Invalid link stride");
    let data = if mode == 3 {
        inflate(&body[3..], length - 1)?
    } else {
        let mut data = vec![0; length - 1];
        read_patches(&body[3..], length - 1, true, |i, mask| data[i] = mask)?;
        data
    };
    let mut bytes = Vec::with_capacity(length);
    bytes.push(body[2]);
    for (offset, link) in data.into_iter().enumerate() {
        let i = offset + 1;
        bytes.push(bytes[if i < stride { i - 1 } else { i - stride }] ^ link);
    }
    Ok(bytes)
}

fn rows(length: usize, width: usize, rule: u8, seed: Option<&[u8]>) -> Vec<u8> {
    let mut out = vec![0; length];
    let mut above = vec![0; width + 2];
    let mut next = vec![0; width + 2];
    if let Some(seed) = seed {
        for (i, cell) in above[1..=width].iter_mut().enumerate() {
            *cell = bit(seed, i);
        }
    } else {
        above[1 + width / 2] = 1;
    }
    for y in 0..length * 8 / width {
        for x in 1..=width {
            if above[x] != 0 {
                flip(&mut out, y * width + x - 1);
            }
            next[x] = (rule >> (4 * above[x - 1] + 2 * above[x] + above[x + 1])) & 1;
        }
        std::mem::swap(&mut above, &mut next);
    }
    out
}

pub(crate) fn restore(mode: u8, body: &[u8], length: usize) -> Result<Vec<u8>> {
    ensure!(body.len() <= length, "Invalid page length");
    if large(mode) {
        ensure!(
            (WIDE + 1..=GROUP).contains(&length),
            "Invalid template-window record"
        );
        return text::restore(
            body,
            length,
            mode.is_multiple_of(2),
            if mode <= 12 {
                Window::Reset256
            } else {
                Window::Group
            },
        );
    }
    if wide(mode) {
        ensure!(
            (PAGE + 1..=WIDE).contains(&length) && body.len() <= 65_535,
            "Invalid wide text record"
        );
        return text::restore(
            body,
            length,
            mode.is_multiple_of(2),
            if mode <= 8 {
                Window::Reset64
            } else {
                Window::Wide
            },
        );
    }
    ensure!((1..=PAGE).contains(&length), "Invalid page size");
    match mode {
        0 if body.len() == length => Ok(body.to_vec()),
        1 => inflate(body, length),
        2 | 3 => links(mode, body, length),
        4 if body.len() >= 4 => {
            let width = u16::from_le_bytes(body[..2].try_into().unwrap()) as usize;
            ensure!(
                (3..=1024).contains(&width) && 2 * width <= 8 * length && body[3] <= 1,
                "Invalid row recipe"
            );
            let end = 4 + usize::from(body[3]) * width.div_ceil(8);
            ensure!(end <= body.len(), "Truncated seed row");
            let mut out = rows(length, width, body[2], (end > 4).then_some(&body[4..end]));
            read_patches(&body[end..], length * 8, false, |i, _| flip(&mut out, i))?;
            Ok(out)
        }
        5 | 6 => text::restore(body, length, mode == 6, Window::Page),
        _ => anyhow::bail!("Invalid page instruction"),
    }
}

fn candidate_strides(data: &[u8]) -> Vec<usize> {
    let sample = &data[..data.len().min(4096)];
    let mut strides = vec![1, 2, 4, 8, 16, 32, 64, 128, 256];
    let mut seen = HashMap::new();
    let mut positions = HashMap::new();
    let mut votes: Vec<(usize, usize)> = Vec::new();
    for (i, bytes) in sample.windows(4).enumerate() {
        let word = u32::from_le_bytes(bytes.try_into().unwrap());
        if let Some(last) = seen.insert(word, i) {
            let stride = i - last;
            let index = positions.entry(stride).or_insert_with(|| {
                votes.push((stride, 0));
                votes.len() - 1
            });
            votes[*index].1 += 1;
        }
    }
    votes.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
    for (stride, _) in votes.into_iter().take(4) {
        if !strides.contains(&stride) {
            strides.push(stride);
        }
    }
    strides.retain(|&stride| stride < data.len());
    strides.sort_by_cached_key(|&stride| {
        (1..sample.len())
            .filter(|&i| data[i] != data[if i < stride { i - 1 } else { i - stride }])
            .count()
    });
    strides.truncate(3);
    strides
}

fn fit(bits: &[u8], width: usize) -> (usize, u8, f64) {
    let mut counts = [0; 16];
    let rows = (bits.len() / width - 1).min((8192 / width).max(1));
    for row in (0..rows * width).step_by(width) {
        let end = row + width - 1;
        let mut left = 0;
        let mut center = bits[row] as usize;
        for i in row..end {
            let right = bits[i + 1] as usize;
            counts[(left << 3) | (center << 2) | (right << 1) | bits[i + width] as usize] += 1;
            left = center;
            center = right;
        }
        counts[(left << 3) | (center << 2) | bits[end + width] as usize] += 1;
    }
    let mut rule = 0;
    let mut wrong = 0;
    for (i, pair) in counts.chunks_exact(2).enumerate() {
        if pair[1] > pair[0] {
            rule |= 1 << i;
        }
        wrong += pair[0].min(pair[1]);
    }
    (width, rule, wrong as f64 / (width * rows) as f64)
}

pub(crate) fn likely_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(2048)];
    let controls = sample
        .iter()
        .filter(|&&b| (b < 32 && !matches!(b, 9 | 10 | 13)) || b == 127)
        .count();
    sample.len() >= 64 && controls * 20 <= sample.len()
}

fn offer(best: &mut (u8, Vec<u8>), mode: u8, body: Vec<u8>) {
    if body.len() < best.1.len() {
        *best = (mode, body);
    }
}

pub(crate) fn pack(
    data: &[u8],
    width_hint: Option<usize>,
    text: TextPolicy,
) -> Result<(u8, Vec<u8>)> {
    ensure!(
        (1..=PAGE).contains(&data.len()),
        "Expected one nonempty data page"
    );
    let mut best = (0, data.to_vec());
    offer(&mut best, 1, deflate(data, 9)?);
    for stride in candidate_strides(data) {
        let links = links_of(data, stride);
        let mut header = (stride as u16).to_le_bytes().to_vec();
        header.push(data[0]);
        let mut sparse = header.clone();
        let mut next = 0;
        for (i, &link) in links.iter().enumerate() {
            if sparse.len() >= best.1.len() {
                break;
            }
            if link != 0 {
                put_vint(&mut sparse, (i - next) as u64);
                sparse.push(link);
                next = i + 1;
            }
        }
        offer(&mut best, 2, sparse);
        header.extend(deflate(&links, 9)?);
        offer(&mut best, 3, header);
    }

    let bits: Vec<_> = (0..data.len() * 8).map(|i| bit(data, i)).collect();
    let side = bits.len().isqrt();
    let mut widths = Vec::new();
    for width in [
        side,
        side + 1,
        side - 1,
        8,
        16,
        24,
        31,
        32,
        48,
        64,
        65,
        80,
        96,
        128,
        256,
        512,
        width_hint.unwrap_or(0),
    ] {
        if !widths.contains(&width) && (3..=1024).contains(&width) && 2 * width <= bits.len() {
            widths.push(width);
        }
    }
    let mut fits: Vec<_> = widths.into_iter().map(|w| fit(&bits, w)).collect();
    fits.sort_by(|a, b| a.2.total_cmp(&b.2));
    for (i, (width, rule, error)) in fits.into_iter().enumerate() {
        if (i >= 3 || error > 0.125) && width_hint != Some(width) {
            continue;
        }
        let mut seed = data[..width.div_ceil(8)].to_vec();
        if width % 8 != 0 {
            *seed.last_mut().unwrap() &= (1 << (width % 8)) - 1;
        }
        for first in [None, Some(seed.as_slice())] {
            let mut body = (width as u16).to_le_bytes().to_vec();
            body.extend([rule, u8::from(first.is_some())]);
            if let Some(row) = first {
                body.extend_from_slice(row);
            }
            if body.len() >= best.1.len() {
                continue;
            }
            let predicted = rows(data.len(), width, rule, first);
            let mut next = 0;
            for (i, (a, b)) in predicted.into_iter().zip(data).enumerate() {
                if body.len() >= best.1.len() {
                    break;
                }
                let mask = a ^ b;
                for j in 0..8 {
                    if (mask >> j) & 1 == 0 {
                        continue;
                    }
                    let index = 8 * i + j;
                    put_vint(&mut body, (index - next) as u64);
                    next = index + 1;
                }
            }
            offer(&mut best, 4, body);
        }
    }
    if text != TextPolicy::Off && best.1.len() > 4 && likely_text(data) {
        let copies = text == TextPolicy::Span;
        offer(
            &mut best,
            if copies { 6 } else { 5 },
            text::pack(data, copies, Window::Page)?,
        );
    }
    Ok(best)
}
