use std::{fs, path::Path, time::Instant};

use anyhow::{Result, ensure};
use grfp::{
    archive, gf16,
    recipe::{Profile, TemplatePolicy, TextPolicy, Window},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MIB: usize = 1024 * 1024;
const TRIALS: usize = 3;
const REFERENCE_PARITY: &str = "098bf13c0be5a5ee780c01274549ab805f0b2b4fca0ddb1ea07a0ee7fcddadc2";

fn noise(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    let mut state = 793u32;
    for chunk in bytes.chunks_mut(4) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    bytes
}

fn structured_text(length: usize) -> Vec<u8> {
    let topics = ["routing", "storage", "assembly", "recovery", "verification"];
    let mut data = String::new();
    for i in 0u32.. {
        if data.len() >= length {
            break;
        }
        let topic = topics[i as usize % topics.len()];
        let offset = i.wrapping_mul(2_654_435_761) % 10_000_000;
        data.push_str(&format!(
            "## Study {i} on {topic}\n\nEach run measures {topic} with configuration {}. \
             The reference begins at offset {offset} and records every recovered frame. \
             Inspect the original and recovered file before accepting the result.\n\n",
            i % 137
        ));
    }
    let mut bytes = data.into_bytes();
    bytes.truncate(length);
    bytes
}

fn measure(operation: impl FnOnce() -> Result<()>) -> Result<f64> {
    let start = Instant::now();
    operation()?;
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

fn median(times: &mut [f64]) -> f64 {
    times.sort_by(f64::total_cmp);
    (times[times.len() / 2] * 10.0).round() / 10.0
}

fn parity() -> Result<Value> {
    let (data_count, parity_count, width) = (384, 20, 88 * 1024);
    let bytes = noise(data_count * width);
    let shards: Vec<_> = (0..data_count)
        .map(|i| &bytes[i * width + i % 2..(i + 1) * width - i % 7])
        .collect();
    let missing = [0, 19, 56, 143, 255, 256, 317, 383];
    let targets: Vec<_> = missing.iter().map(|&i| (i, shards[i].len())).collect();
    let rows = [19, 4, 13, 0, 9, 3, 2, 11];
    let mut enc = Vec::new();
    let mut dec = Vec::new();
    for trial in 0..=TRIALS {
        let mut parity = Vec::new();
        let encode = measure(|| {
            gf16::encode(
                data_count,
                parity_count,
                width,
                |i| Ok(shards[i].to_vec()),
                |_, body| {
                    parity.push(body.to_vec());
                    Ok(())
                },
            )
        })?;
        let mut digest = Sha256::new();
        for row in &parity {
            digest.update(row);
        }
        ensure!(
            format!("{:x}", digest.finalize()) == REFERENCE_PARITY,
            "Parity differs from the Node benchmark fixture"
        );
        let mut recovered = Vec::new();
        let decode = measure(|| {
            gf16::decode(
                gf16::Recovery {
                    systematic: data_count,
                    missing: &missing,
                    rows: &rows,
                    wanted: &targets,
                    width,
                },
                |i| Ok(shards[i].to_vec()),
                |p| Ok(parity[p].clone()),
                |i, body| {
                    recovered.push((i, body.to_vec()));
                    Ok(())
                },
            )
        })?;
        for (i, data) in recovered {
            ensure!(data == shards[i], "Recovered shard differs");
        }
        if trial != 0 {
            enc.push(encode);
            dec.push(decode);
        }
    }
    Ok(
        json!({"encodeMs":median(&mut enc),"decodeMs":median(&mut dec),"paritySha256":REFERENCE_PARITY}),
    )
}

fn remove_recipe_group(archive: &[u8]) -> Vec<u8> {
    let mut at = 0;
    while at < archive.len() {
        let n = u32::from_le_bytes(archive[at + 13..at + 17].try_into().unwrap()) as usize;
        let end = at + 81 + n;
        if archive[at + 8] == 3
            && u16::from_le_bytes(archive[at + 9..at + 11].try_into().unwrap()) == 1
        {
            return [&archive[..at], &archive[end..]].concat();
        }
        at = end;
    }
    panic!("Benchmark archive has no recipe group");
}

fn measure_archive(work: &Path, data: &[u8], profile: Profile, label: &str) -> Result<Value> {
    let input = work.join(label);
    fs::write(&input, data)?;
    let mut packed = Vec::new();
    let mut recovered = Vec::new();
    let mut original_only = Vec::new();
    let mut archive_size = 0;
    for i in 0..TRIALS {
        let path = work.join(format!("{label}-{i}.grfp"));
        let damaged = work.join(format!("{label}-{i}-damaged.grfp"));
        let out = work.join(format!("{label}-{i}-out"));
        let original = work.join(format!("{label}-{i}-original.bin"));
        packed.push(measure(|| {
            archive::pack(&input, &path, profile.clone(), 5).map(|_| ())
        })?);
        let bytes = fs::read(&path)?;
        archive_size = bytes.len();
        fs::write(&damaged, remove_recipe_group(&bytes))?;
        let recover = || measure(|| archive::recover(&damaged, &out, None).map(|_| ()));
        let recover_original =
            || measure(|| archive::recover_original(&damaged, &original, None).map(|_| ()));
        let (full, only) = if i % 2 == 0 {
            (recover()?, recover_original()?)
        } else {
            let only = recover_original()?;
            (recover()?, only)
        };
        recovered.push(full);
        original_only.push(only);
        ensure!(
            fs::read(out.join("restored.bin"))? == data && fs::read(original)? == data,
            "Original bytes differ"
        );
        ensure!(
            fs::read(out.join("protected.grfp"))? == bytes,
            "Regenerated archive differs"
        );
    }
    Ok(
        json!({"packMs":median(&mut packed),"recoverMs":median(&mut recovered),"recoverOriginalMs":median(&mut original_only),"protectedBytes":archive_size}),
    )
}

fn main() -> Result<()> {
    let stage = tempfile::tempdir()?;
    let mut binary = noise(2 * MIB);
    binary.pop();
    let fast = Profile {
        text: TextPolicy::Off,
        templates: TemplatePolicy::Off,
        text_window: Window::Page,
        ..Profile::default()
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "trials": TRIALS,
            "parity": parity()?,
            "binary": measure_archive(stage.path(),&binary,fast,"binary")?,
            "text": measure_archive(stage.path(),&structured_text(MIB),Profile::default(),"text")?,
        }))?
    );
    Ok(())
}
