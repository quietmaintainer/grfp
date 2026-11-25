//! The GRF1 order-4 PPM predictor and rANS byte stream.

use crate::io::Bytes;
use anyhow::{Result, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const SCALE: u32 = 32_768;
const LOWER: u32 = 1 << 23;
const ORDER: usize = 4;
pub(crate) const PAGE: usize = 16 * 1024;
pub(crate) const WIDE: usize = 4 * PAGE;
pub(crate) const GROUP: usize = 4 * WIDE;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
pub enum Window {
    #[serde(rename = "16")]
    #[value(name = "16")]
    Page,
    #[serde(rename = "64-reset")]
    #[value(name = "64-reset")]
    Reset64,
    #[serde(rename = "64")]
    #[value(name = "64")]
    Wide,
    #[serde(rename = "256-reset")]
    #[value(name = "256-reset")]
    Reset256,
    #[serde(rename = "256")]
    #[value(name = "256")]
    Group,
}

impl Window {
    fn step(self, length: usize) -> Result<usize> {
        let (max, step) = match self {
            Self::Page => (PAGE, length),
            Self::Reset64 => (WIDE, PAGE),
            Self::Wide => (WIDE, length),
            Self::Reset256 => (GROUP, WIDE),
            Self::Group => (GROUP, length),
        };
        ensure!(length > 0 && length <= max, "Invalid text window length");
        Ok(step)
    }
}

trait Entropy {
    const DECODE: bool;
    fn peek(&self, total: u32) -> u32;
    fn take(&mut self, lo: u32, mass: u32, total: u32) -> Result<()>;
}

#[derive(Default)]
struct Writer(Vec<u32>);

impl Entropy for Writer {
    const DECODE: bool = false;
    fn peek(&self, _: u32) -> u32 {
        0
    }
    fn take(&mut self, lo: u32, mass: u32, total: u32) -> Result<()> {
        if mass != total {
            let start = lo * SCALE / total;
            let width = (lo + mass) * SCALE / total - start;
            self.0.push((start << 16) | width);
        }
        Ok(())
    }
}

impl Writer {
    fn finish(self) -> Vec<u8> {
        let mut x = LOWER;
        let mut reversed = Vec::new();
        for op in self.0.into_iter().rev() {
            let width = op & 65_535;
            while x >= width << 16 {
                reversed.push(x as u8);
                x >>= 8;
            }
            x = (x / width) * SCALE + (x % width) + (op >> 16);
        }
        let mut out = x.to_le_bytes().to_vec();
        out.extend(reversed.into_iter().rev());
        out
    }
}

struct Reader<'a> {
    x: u32,
    body: Bytes<'a>,
}

impl<'a> Reader<'a> {
    fn new(body: &'a [u8]) -> Result<Self> {
        let mut body = Bytes::new(body);
        let x = body.u32()? as u32;
        ensure!(
            (LOWER..LOWER * 256).contains(&x),
            "Invalid text recipe state"
        );
        Ok(Self { x, body })
    }

    fn finish(&self) -> Result<()> {
        ensure!(
            self.x == LOWER && self.body.left().is_empty(),
            "Text recipe end-state or length mismatch"
        );
        Ok(())
    }
}

impl Entropy for Reader<'_> {
    const DECODE: bool = true;
    fn peek(&self, total: u32) -> u32 {
        ((self.x % SCALE + 1) * total - 1) / SCALE
    }
    fn take(&mut self, lo: u32, mass: u32, total: u32) -> Result<()> {
        if mass != total {
            let start = lo * SCALE / total;
            let width = (lo + mass) * SCALE / total - start;
            let residue = self.x % SCALE;
            ensure!(
                (start..start + width).contains(&residue),
                "Invalid text recipe vote"
            );
            self.x = width * (self.x / SCALE) + residue - start;
            while self.x < LOWER {
                self.x = self.x * 256 + u32::from(self.body.byte()?);
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Span {
    last: HashMap<u32, usize>,
    hash: u32,
    len: usize,
    from: Option<usize>,
    run: usize,
    hits: [u16; 20],
    trials: [u16; 20],
    bin: Option<usize>,
}

impl Span {
    fn bonus(&mut self, mass: u32, total: u32) -> u32 {
        let tier = match self.run {
            0 => 0,
            1..=2 => 1,
            3..=7 => 2,
            _ => 3,
        };
        let band = if mass == 0 {
            0
        } else if mass * 16 < total {
            1
        } else if mass * 4 < total {
            2
        } else if mass * 4 < 3 * total {
            3
        } else {
            4
        };
        let bin = tier * 5 + band;
        self.bin = Some(bin);
        let hits = i64::from(self.hits[bin]) + 1;
        let misses = i64::from(self.trials[bin] - self.hits[bin]) + 2;
        let extra =
            (hits * i64::from(total) - (hits + misses) * i64::from(mass)).div_euclid(misses);
        extra.clamp(0, i64::from((SCALE - total).min(32 * total))) as u32
    }

    fn observe(&mut self, bytes: &[u8], i: usize, b: u8) {
        if let Some(from) = self.from {
            let hit = bytes.get(from) == Some(&b);
            if let Some(bin) = self.bin.take() {
                if self.trials[bin] >= 256 {
                    self.trials[bin] >>= 1;
                    self.hits[bin] >>= 1;
                }
                self.trials[bin] += 1;
                self.hits[bin] += u16::from(hit);
            }
            if hit {
                self.from = Some(from + 1);
                self.run += 1;
            } else {
                self.from = None;
                self.run = 0;
            }
        }
        if b.is_ascii_alphanumeric() || b == b'_' {
            self.hash = self.hash.wrapping_mul(16_777_619) ^ u32::from(b.to_ascii_lowercase());
            self.len += 1;
        } else {
            if self.len >= 2 {
                let key = self.hash.wrapping_mul(257) ^ u32::from(b);
                if self.from.is_none() || self.run == 0 {
                    self.from = self.last.get(&key).copied();
                    self.run = 0;
                }
                self.last.insert(key, i + 1);
            }
            self.hash = 0;
            self.len = 0;
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Node {
    child: u32,
    sibling: u32,
    frequency: u32,
    symbol: u8,
}

fn predict<C: Entropy>(bytes: &mut [u8], copies: bool, coder: &mut C) -> Result<()> {
    let mut nodes = vec![Node::default(); 2];
    nodes.reserve(bytes.len());
    let mut history = [1, 0, 0, 0, 0];
    let mut roots = [0; 256];
    let mut excluded = [0; 256];
    let mut syms = [0; 256];
    let mut masses = [0; 256];
    let mut span = copies.then(Span::default);
    for i in 0..bytes.len() {
        let depth = i.min(ORDER);
        let tag = i + 1;
        let mut value = bytes[i];
        let mut done = false;
        let mut skipped = 0;
        let mut candidate = span
            .as_ref()
            .and_then(|s| s.from)
            .and_then(|from| bytes.get(from))
            .copied();
        for k in (0..=depth).rev() {
            let mut n = 0;
            let mut sum = 0;
            let mut slot = None;
            let mut link = nodes[history[k] as usize].child;
            while link > 0 {
                let node = nodes[link as usize];
                link = node.sibling;
                if excluded[node.symbol as usize] == tag {
                    continue;
                }
                if candidate == Some(node.symbol) {
                    slot = Some(n);
                }
                syms[n] = node.symbol;
                masses[n] = 2 * node.frequency - 1;
                sum += masses[n];
                n += 1;
            }
            if n == 0 {
                continue;
            }
            let escape = n as u32;
            while sum + escape > SCALE {
                sum = 0;
                for mass in &mut masses[..n] {
                    *mass = mass.div_ceil(2);
                    sum += *mass;
                }
            }
            if let Some(offer) = candidate.take() {
                let extra = span
                    .as_mut()
                    .unwrap()
                    .bonus(slot.map_or(0, |j| masses[j]), sum + escape);
                if extra > 0 {
                    if let Some(j) = slot {
                        masses[j] += extra;
                    } else {
                        syms[n] = offer;
                        masses[n] = extra;
                        n += 1;
                    }
                    sum += extra;
                }
            }
            let total = sum + escape;
            let target = if C::DECODE { coder.peek(total) } else { 0 };
            let mut lo = 0;
            for j in 0..n {
                if if C::DECODE {
                    target < lo + masses[j]
                } else {
                    value == syms[j]
                } {
                    value = syms[j];
                    coder.take(lo, masses[j], total)?;
                    done = true;
                    break;
                }
                lo += masses[j];
            }
            if done {
                break;
            }
            coder.take(sum, escape, total)?;
            skipped += n as u32;
            for &symbol in &syms[..n] {
                excluded[symbol as usize] = tag;
            }
        }
        if !done {
            ensure!(skipped < 256, "Impossible text recipe escape");
            let left = 256 - skipped;
            let target = if C::DECODE { coder.peek(left) } else { 0 };
            let mut rank = 0;
            for v in 0..=u8::MAX {
                if excluded[v as usize] == tag {
                    continue;
                }
                if if C::DECODE {
                    rank == target
                } else {
                    v == value
                } {
                    value = v;
                    break;
                }
                rank += 1;
            }
            coder.take(rank, 1, left)?;
        }
        if C::DECODE {
            bytes[i] = value;
        }
        if let Some(span) = &mut span {
            span.observe(bytes, i, value);
        }

        let mut learn = true;
        for k in (0..=depth).rev() {
            let parent = history[k] as usize;
            let mut link = if k == 0 {
                roots[value as usize]
            } else {
                nodes[parent].child
            };
            while link > 0 && nodes[link as usize].symbol != value {
                link = nodes[link as usize].sibling;
            }
            if link == 0 {
                link = nodes.len() as u32;
                let sibling = nodes[parent].child;
                nodes.push(Node {
                    sibling,
                    symbol: value,
                    ..Node::default()
                });
                nodes[parent].child = link;
                if k == 0 {
                    roots[value as usize] = link;
                }
            }
            let frequency = &mut nodes[link as usize].frequency;
            if *frequency == 0 {
                *frequency = 1;
            } else if learn {
                *frequency += 1;
                learn = false;
            }
            if k < ORDER {
                history[k + 1] = link;
            }
        }
    }
    Ok(())
}

pub(crate) fn pack(raw: &[u8], copies: bool, window: Window) -> Result<Vec<u8>> {
    let step = window.step(raw.len())?;
    let mut out = Writer::default();
    for part in raw.chunks(step) {
        predict(&mut part.to_vec(), copies, &mut out)?;
    }
    Ok(out.finish())
}

pub(crate) fn restore(body: &[u8], length: usize, copies: bool, window: Window) -> Result<Vec<u8>> {
    let step = window.step(length)?;
    let mut bytes = vec![0; length];
    let mut reader = Reader::new(body)?;
    for part in bytes.chunks_mut(step) {
        predict(part, copies, &mut reader)?;
    }
    reader.finish()?;
    Ok(bytes)
}
