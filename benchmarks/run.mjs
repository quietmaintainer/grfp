import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { cpus, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { DATA, FRAME, frameKey, scanFrames } from '../src/frames.mjs';
import { packLong } from '../src/long.mjs';
import * as currentCodec from '../src/protected.mjs';
import { encode16 } from '../src/rs16.mjs';
import { cutCopy } from '../test/loss-fixtures.mjs';

const REPEATS = 3;
const MiB = 1024 * 1024;
const settings = { parityPercent: 5, fec: 'global16' };

function noise(length) {
  const data = Buffer.allocUnsafe(length);
  let state = 793;
  for (let offset = 0; offset < data.length; offset += 4) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    data.writeUInt32LE(state >>> 0, offset);
  }
  return data;
}

function structuredText(length) {
  const topics = ['routing', 'storage', 'assembly', 'recovery', 'verification'];
  const parts = [];
  let size = 0;
  for (let index = 0; size < length; index++) {
    const topic = topics[index % topics.length];
    const offset = (Math.imul(index, 2654435761) >>> 0) % 10_000_000;
    const paragraph = `## Study ${index} on ${topic}\n\n`
      + `Each run measures ${topic} with configuration ${index % 137}. `
      + `The reference begins at offset ${offset} and records every recovered frame. `
      + `Inspect the original and recovered file before accepting the result.\n\n`;
    parts.push(paragraph);
    size += paragraph.length;
  }
  return Buffer.from(parts.join('')).subarray(0, length);
}

function median(samples) {
  return Number([...samples].sort((a, b) => a - b)[Math.floor(samples.length / 2)].toFixed(1));
}

function measureParity(versions) {
  const dataCount = 384, parityCount = 20, width = 88 * 1024;
  const bytes = noise(dataCount * width);
  const samples = versions.map(() => []);
  let expected;
  // Run the same workload once per implementation before collecting samples.
  for (let trial = -1; trial < REPEATS; trial++) {
    for (const [index, version] of versions.entries()) {
      const rows = [];
      const start = performance.now();
      version.encode(dataCount, parityCount, width,
        i => bytes.subarray(i * width + i % 2, (i + 1) * width - i % 7),
        (row, buffer) => { rows[row] = buffer; });
      const elapsed = performance.now() - start;
      const digest = createHash('sha256').update(Buffer.concat(rows)).digest('hex');
      expected ??= digest;
      assert.equal(digest, expected);
      if (trial >= 0) samples[index].push(elapsed);
    }
  }
  return { dataCount, parityCount, shardWidth: width, paritySha256: expected,
    samples: versions.map(({ name }, i) => ({ name, encodeMs: median(samples[i]) })) };
}

function measureArchives(work, kind, data, versions) {
  const source = join(work, kind);
  fs.writeFileSync(source, data);
  const samples = versions.map(() => ({ pack: [], recover: [] }));
  for (let trial = 0; trial < REPEATS; trial++) {
    for (const [i, version] of versions.entries()) {
      const prefix = join(work, `${kind}-${trial}-${i}`);
      const archive = prefix + '.grfp', damaged = prefix + '-damaged.grfp', out = prefix + '-recovered';
      let start = performance.now();
      const packed = version.codec.packProtected(source, archive, undefined, { ...settings, ...version.options });
      const packMs = performance.now() - start;
      const fd = fs.openSync(archive, 'r');
      let frame;
      try {
        frame = scanFrames(fd).entries.get(frameKey(DATA, 0));
      } finally {
        fs.closeSync(fd);
      }
      cutCopy(archive, damaged, [[frame.at, FRAME + frame.n]]);
      start = performance.now();
      const recovered = version.codec.recoverProtected(damaged, out);
      const recoverMs = performance.now() - start;
      assert.equal(recovered.recipeGroupsFromParity, 1);
      assert.deepEqual(fs.readFileSync(join(out, 'restored.bin')), data);
      assert.deepEqual(fs.readFileSync(join(out, 'protected.grfp')), fs.readFileSync(archive));
      const sample = samples[i];
      sample.sha256 ??= packed.protectedSha256;
      assert.equal(sample.sha256, packed.protectedSha256);
      sample.bytes = packed.protectedBytes;
      sample.pack.push(packMs);
      sample.recover.push(recoverMs);
    }
  }
  for (const [i, version] of versions.entries()) {
    if (version.matches !== undefined) assert.equal(samples[i].sha256, samples[version.matches].sha256);
  }
  return { originalBytes: data.length, samples: versions.map(({ name }, i) => {
    const { pack, recover, bytes, sha256 } = samples[i];
    return { name, packMs: median(pack), recoverMs: median(recover), bytes, sha256 };
  }) };
}

async function measurePredictors(work) {
  const input = join(work, 'text');
  const samples = [];
  let expected;
  for (const backend of ['js', 'wasm']) {
    const times = [];
    for (let trial = 0; trial < REPEATS; trial++) {
      const output = join(work, `predictor-${backend}-${trial}.grl`);
      const start = performance.now();
      await packLong(input, output, { restart: true, predictor: 4096, templates: 256, jobs: 1, backend });
      times.push(performance.now() - start);
      const digest = createHash('sha256').update(fs.readFileSync(output)).digest('hex');
      expected ??= digest;
      assert.equal(digest, expected);
    }
    samples.push({ backend, packMs: median(times) });
  }
  return { recipeSha256: expected, samples };
}

const [baseline] = process.argv.slice(2);
const moduleAt = (folder, name) => import(pathToFileURL(resolve(folder, name)));
const versions = [{ name: 'standalone', encode: encode16, codec: currentCodec }];
if (baseline) {
  const { encode16: encode } = await moduleAt(baseline, 'rs16.mjs');
  const codec = await moduleAt(baseline, 'protected.mjs');
  versions.unshift({ name: 'upstream', encode, codec });
  versions[1].matches = 0;
}
const fast = { text: 'off', templates: 'off' };
const work = fs.mkdtempSync(join(tmpdir(), 'grfp-benchmark-'));
try {
  const report = {
    environment: { node: process.version, platform: process.platform, arch: process.arch, cpu: cpus()[0].model },
    repeats: REPEATS,
    parity: measureParity(versions),
    binary: measureArchives(work, 'binary', noise(2 * MiB).subarray(0, -1),
      versions.map(version => ({ ...version, options: fast }))),
    text: measureArchives(work, 'text', structuredText(MiB), [
      ...versions,
      { name: 'standalone, text and templates off', codec: currentCodec, options: fast },
    ]),
  };
  if (process.env.GRL_PREDICTOR_WASM) report.predictor = await measurePredictors(work);
  console.log(JSON.stringify(report, null, 2));
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
