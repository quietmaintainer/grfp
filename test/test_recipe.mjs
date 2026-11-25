import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { deflateRawSync } from 'node:zlib';
import { packFile, restoreFile, inspectFile } from '../src/archive.mjs';
import { PAGE, packPage, restorePage, pageGradient } from '../src/codec.mjs';
import { diagram, noiseBytes, records } from './fixtures.mjs';
import { swarmAssembler } from '../src/swarm.mjs';

function paths(t) {
  const dir = fs.mkdtempSync(join(tmpdir(), 'file-recipe-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return name => join(dir, name);
}

test('infer the unknown width and rule, including sparse exceptions and non-byte-aligned padding', () => {
  for (const width of [64, 65, 81]) for (const edits of [0, 10]) {
    const raw = diagram(width, width, edits);
    if (width % 8) raw[raw.length - 1] |= 0xe0; // these file bits are significant, too
    const { mode, body } = packPage(raw);
    assert.equal(mode, 4); assert.equal(body.readUInt16LE(), width); assert.equal(body[2], 30);
    assert.ok(body.length < 40); assert.deepEqual(restorePage(mode, body, raw.length), raw);
  }
});

test('stride links are symmetric and expand to the same linear edge basis, including row crossings', () => {
  const raw = noiseBytes(121);
  for (const stride of [1, 2, 11, 53, 120]) {
    const tape = raw.subarray(1).map((v, j) => v ^ raw[j + 1 < stride ? j : j + 1 - stride]);
    // A dense random tape would lose the raw fallback; use a sparse mask so
    // both versions of this hand-authored recipe fit the format's size bound.
    for (let j = 0; j < tape.length; j++) if (j % 9) tape[j] = 0;
    const expected = Buffer.alloc(raw.length); expected[0] = raw[0];
    tape.forEach((v, j) => { expected[j + 1] = v ^ expected[j + 1 < stride ? j : j + 1 - stride]; });
    let prev = -1; const sparse = [];
    tape.forEach((v, j) => { if (v) { sparse.push(j - prev - 1, v); prev = j; } });
    for (const [mode, data] of [[2, Buffer.from(sparse)], [3, deflateRawSync(tape)]]) {
      const body = Buffer.concat([Buffer.from([stride, 0, raw[0]]), data]);
      const gradient = pageGradient(mode, body, raw.length);
      assert.deepEqual(gradient, expected.map((v, i) => v ^ (i ? expected[i - 1] : 0)));
      assert.deepEqual(restorePage(mode, body, raw.length), expected);
    }
  }
});

test('restore arbitrary binary files after the source is deleted; verify actual archive cost', t => {
  const p = paths(t);
  for (const n of [0, 1, 7, 257, PAGE - 1, PAGE, PAGE + 1, 2 * PAGE + 227]) {
    const raw = noiseBytes(n); fs.writeFileSync(p('source'), raw);
    const recipe = packFile(p('source'), p(`r${n}`)); fs.unlinkSync(p('source'));
    const result = restoreFile(p(`r${n}`), p(`o${n}`));
    assert.deepEqual(fs.readFileSync(p(`o${n}`)), raw);
    assert.equal(result.sha256, recipe.sha256); assert.equal(recipe.recipeBytes, fs.statSync(p(`r${n}`)).size);
    assert.ok(recipe.recipeBytes <= raw.length + 44 + 19 * Math.ceil(n / PAGE));
  }
});

test('repair skips verified pages, handles substitutions, truncation and extra bytes, and preserves the damaged file', t => {
  const p = paths(t), raw = Buffer.concat([noiseBytes(PAGE), Buffer.alloc(PAGE, 0x75), records()]);
  fs.writeFileSync(p('source'), raw); packFile(p('source'), p('r')); fs.unlinkSync(p('source'));
  const short = Buffer.from(raw.subarray(0, -300)); short[PAGE + 20] ^= 0x80;
  fs.writeFileSync(p('damaged'), short);
  const repaired = restoreFile(p('r'), p('fixed'), {damaged:p('damaged')});
  assert.equal(repaired.rebuiltPages, 2); assert.equal(repaired.reusedPages, 1);
  assert.deepEqual(fs.readFileSync(p('fixed')), raw); assert.deepEqual(fs.readFileSync(p('damaged')), short);
  fs.writeFileSync(p('long'), Buffer.concat([raw, Buffer.from('extra')]));
  assert.equal(restoreFile(p('r'), p('trimmed'), {damaged:p('long')}).rebuiltPages, 0);
  assert.deepEqual(fs.readFileSync(p('trimmed')), raw);
  assert.throws(() => restoreFile(p('r'), p('damaged')), /already exists/);
});

test('bad instructions, truncation and checksum failures do not publish a partial output', t => {
  const p = paths(t); fs.writeFileSync(p('good'), diagram()); packFile(p('good'), p('r'));
  const record = fs.readFileSync(p('r'));
  for (const bad of [record.subarray(1), record.subarray(0, -1), Buffer.concat([record, Buffer.of(0)]),
    record.map((v, i) => v ^ Number(i === 12)), record.map((v, i) => v ^ Number(i === record.length - 1))]) {
    fs.writeFileSync(p('bad'), bad);
    assert.throws(() => restoreFile(p('bad'), p('out'), {damaged:p('good')}));
    assert.equal(fs.existsSync(p('out')), false);
  }
  assert.throws(() => restorePage(4, Buffer.from([8,0,30,0,128]), 16), /gap/);
  assert.throws(() => restorePage(2, Buffer.from([1,0,65,127,1]), 8), /outside/);
  assert.throws(() => restorePage(1, Buffer.concat([deflateRawSync(Buffer.alloc(128)), Buffer.of(0)]), 128));
  assert.throws(() => restorePage(1, deflateRawSync(Buffer.alloc(1024)), 128));
  assert.equal(inspectFile(p('r')).examples['row-ca'].rule, 30);
});

test('the real Swarm NCA restores from seed only and regrows a corrupted bit island from certified survivors',
  {skip:!process.env.SWARM_WEB}, async t => {
    const p = paths(t), grow = await swarmAssembler(process.env.SWARM_WEB);
    for (const [i, raw] of [diagram(65,65,10), noiseBytes(351), Buffer.alloc(1024, 0xaf), records().subarray(0, 2137)].entries()) {
      fs.writeFileSync(p('in'), raw); packFile(p('in'), p(`r${i}`)); fs.unlinkSync(p('in'));
      const before = grow.stats.initiallyReadyFileBits;
      restoreFile(p(`r${i}`), p(`o${i}`), {assemble:grow});
      assert.equal(grow.stats.initiallyReadyFileBits - before, 8 * Math.ceil(raw.length / 1024));
      assert.deepEqual(fs.readFileSync(p(`o${i}`)), raw);
      const broken = Buffer.from(raw.subarray(0, -11)); broken.fill(0, 17, 37); broken[0] ^= 255;
      fs.writeFileSync(p(`d${i}`), broken);
      const prior = grow.stats.initiallyReadyFileBits;
      restoreFile(p(`r${i}`), p(`f${i}`), {damaged:p(`d${i}`), assemble:grow});
      assert.ok(grow.stats.initiallyReadyFileBits - prior > 8 * Math.ceil(raw.length / 1024));
      assert.deepEqual(fs.readFileSync(p(`f${i}`)), raw);
    }
  });
