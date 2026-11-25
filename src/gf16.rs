//! Systematic Cauchy Reed–Solomon over GF(2^16). Symbols on disk are little-endian.

use anyhow::{Result, ensure};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

pub const LIMIT: usize = 65_535;
const WORK: usize = 8 * 1024 * 1024;
const CACHE_LIMIT: usize = 1024;

pub(crate) struct Field {
    log: Vec<u16>,
    exp: Vec<u16>,
    order: usize,
}

impl Field {
    pub(crate) fn new(bits: u8, polynomial: u32) -> Self {
        let size = 1 << bits;
        let order = size - 1;
        let mut log = vec![0; size];
        let mut exp = vec![0; 2 * order];
        let mut value = 1;
        for (power, entry) in exp[..order].iter_mut().enumerate() {
            log[value as usize] = power as u16;
            *entry = value as u16;
            value <<= 1;
            if value >= size as u32 {
                value ^= polynomial;
            }
        }
        exp.copy_within(..order, order);
        Self { log, exp, order }
    }

    pub(crate) fn multiply(&self, a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[usize::from(self.log[a as usize]) + usize::from(self.log[b as usize])]
        }
    }

    pub(crate) fn inverse(&self, x: usize) -> u16 {
        self.exp[self.order - usize::from(self.log[x])]
    }
}

fn field() -> &'static Field {
    static FIELD: OnceLock<Field> = OnceLock::new();
    FIELD.get_or_init(|| Field::new(16, 0x1100b))
}

struct Products {
    low: [u16; 256],
    high: [u16; 256],
}

impl Products {
    fn new(factor: u16) -> Self {
        let field = field();
        Self {
            low: std::array::from_fn(|i| field.multiply(factor, i as u16)),
            high: std::array::from_fn(|i| field.multiply(factor, (i as u16) << 8)),
        }
    }

    fn accumulate(&self, output: &mut [u8], input: &[u8]) {
        let len = input.len().min(output.len());
        let (pairs, tail) = input[..len].as_chunks::<2>();
        let (words, _) = output.as_chunks_mut::<2>();
        for (out, &[low, high]) in words.iter_mut().zip(pairs) {
            let scaled = self.low[low as usize] ^ self.high[high as usize];
            *out = (u16::from_le_bytes(*out) ^ scaled).to_le_bytes();
        }
        if let &[low] = tail {
            let out = &mut words[pairs.len()];
            *out = (u16::from_le_bytes(*out) ^ self.low[low as usize]).to_le_bytes();
        }
    }
}

#[derive(Default)]
struct Tables(HashMap<u16, Box<Products>>);

impl Tables {
    fn add(&mut self, output: &mut [u8], input: &[u8], factor: u16) {
        if self.0.len() == CACHE_LIMIT && !self.0.contains_key(&factor) {
            self.0.clear();
        }
        self.0
            .entry(factor)
            .or_insert_with(|| Box::new(Products::new(factor)))
            .accumulate(output, input);
    }
}

pub fn check(d: usize, r: usize) -> Result<()> {
    ensure!(
        (1..=LIMIT).contains(&d) && r <= LIMIT - d,
        "Global GF16 coordinate limit exceeded"
    );
    Ok(())
}

fn batch_size(width: usize) -> Result<usize> {
    ensure!(
        width > 0 && width.is_multiple_of(2),
        "Invalid GF16 symbol width"
    );
    Ok((WORK / width).max(1))
}

pub fn even(n: usize) -> usize {
    n + n % 2
}

pub fn encode(
    d: usize,
    r: usize,
    width: usize,
    mut load: impl FnMut(usize) -> Result<Vec<u8>>,
    mut save: impl FnMut(usize, &[u8]) -> Result<()>,
) -> Result<()> {
    check(d, r)?;
    let batch = batch_size(width)?;
    for first in (0..r).step_by(batch) {
        let mut tables = Tables::default();
        let mut outputs = vec![vec![0; width]; batch.min(r - first)];
        for i in 0..d {
            let data = load(i)?;
            ensure!(data.len() <= width, "Oversized systematic shard");
            for (j, output) in outputs.iter_mut().enumerate() {
                tables.add(output, &data, field().inverse((d + first + j) ^ i));
            }
        }
        for (j, output) in outputs.iter().enumerate() {
            save(first + j, output)?;
        }
    }
    Ok(())
}

pub struct Recovery<'a> {
    pub systematic: usize,
    pub missing: &'a [usize],
    pub rows: &'a [usize],
    /// Requested coordinates paired with the exact unpadded length.
    pub wanted: &'a [(usize, usize)],
    pub width: usize,
}

fn product(point: usize, values: &[usize]) -> u16 {
    values
        .iter()
        .filter(|&&x| x != point)
        .fold(1, |a, &x| field().multiply(a, (x ^ point) as u16))
}

// Interpolate the missing coordinates by the Cauchy inverse. Only one batch
// of requested outputs is resident, even when bootstrapping a lost catalog.
pub fn decode(
    rec: Recovery<'_>,
    mut load: impl FnMut(usize) -> Result<Vec<u8>>,
    mut parity: impl FnMut(usize) -> Result<Vec<u8>>,
    mut save: impl FnMut(usize, &[u8]) -> Result<()>,
) -> Result<()> {
    let Recovery {
        systematic: d,
        missing,
        rows,
        wanted,
        width,
    } = rec;
    check(d, 0)?;
    if wanted.is_empty() {
        return Ok(());
    }
    ensure!(
        rows.len() >= missing.len(),
        "Insufficient global parity: {} missing, {} usable",
        missing.len(),
        rows.len()
    );
    let rows = &rows[..missing.len()];
    let lost: HashSet<_> = missing.iter().copied().collect();
    ensure!(
        lost.len() == missing.len() && missing.iter().all(|&i| i < d),
        "Invalid GF16 erasure"
    );
    ensure!(
        rows.iter().all(|&i| i < LIMIT - d)
            && rows.iter().collect::<HashSet<_>>().len() == rows.len(),
        "Invalid parity coordinate"
    );
    ensure!(
        wanted
            .iter()
            .all(|&(i, n)| lost.contains(&i) && (1..=width).contains(&n)),
        "Invalid recovery target"
    );
    let ys: Vec<_> = rows.iter().map(|p| d + p).collect();
    let gf = field();
    let row_weights: HashMap<_, _> = wanted
        .iter()
        .map(|&(u, _)| {
            (
                u,
                gf.multiply(product(u, &ys), gf.inverse(product(u, missing) as usize)),
            )
        })
        .collect();
    let col_weights: Vec<_> = (0..d)
        .map(|i| {
            if lost.contains(&i) {
                None
            } else {
                Some(gf.multiply(product(i, missing), gf.inverse(product(i, &ys) as usize)))
            }
        })
        .collect();
    let parity_weights: Vec<_> = ys
        .iter()
        .map(|&y| gf.multiply(product(y, missing), gf.inverse(product(y, &ys) as usize)))
        .collect();
    for batch in wanted.chunks(batch_size(width)?) {
        let mut tables = Tables::default();
        let mut outputs: Vec<_> = batch.iter().map(|&(_, n)| vec![0; even(n)]).collect();
        let mut combine = |v: usize, weight, bytes: Vec<u8>| {
            for (&(u, _), output) in batch.iter().zip(&mut outputs) {
                let factor = gf.multiply(gf.multiply(row_weights[&u], weight), gf.inverse(u ^ v));
                tables.add(output, &bytes, factor);
            }
        };
        for (i, weight) in col_weights.iter().enumerate() {
            if let Some(weight) = weight {
                combine(i, *weight, load(i)?);
            }
        }
        for ((&p, &y), &weight) in rows.iter().zip(&ys).zip(&parity_weights) {
            combine(y, weight, parity(p)?);
        }
        for (&(u, n), output) in batch.iter().zip(outputs) {
            save(u, &output[..n])?;
        }
    }
    Ok(())
}
