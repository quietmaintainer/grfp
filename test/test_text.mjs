import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { packFile, restoreFile } from '../src/archive.mjs';
import { PAGE, packPage, pageGradient, restorePage } from '../src/codec.mjs';
import { diagram, noiseBytes } from './fixtures.mjs';
import { swarmAssembler } from '../src/swarm.mjs';
import { packText, restoreText } from '../src/text.mjs';

const sentence = Buffer.from('|birth_date = 1940; |birth_date = 1950; |birth_date = 1940;');
const wire = Buffer.from('713efa04a5e4003975d9dd85edb287b400b2e67993a775188919a7bf2a9f33', 'hex');

test('decodes a fixed span recipe with repeated field names and an exception', () => {
  assert.deepEqual(restorePage(6, wire, sentence.length), sentence);
  assert.deepEqual(packText(sentence, true), wire);
});

test('both text engines round-trip all byte values, partial UTF-8, overlapping continuations, and full pages', () => {
  const sequence = Buffer.concat([Buffer.from('[[Node|node name]] {{field = 0}}\r\nпривет 猫 NODE_12 node_12: '),
    Buffer.from(Array.from({length:256}, (_, i) => i))]);
  const multi = Buffer.concat(Array.from({length:128}, () => sequence));
  for (const raw of [Buffer.of(0), Buffer.of(255), sentence, multi.subarray(17, 17 + PAGE), noiseBytes(PAGE),
    Buffer.alloc(PAGE, 97), Buffer.from('repeat! '.repeat(PAGE / 8))]) {
    for (const copies of [false, true]) {
      const payload = packText(raw, copies);
      assert.deepEqual(restoreText(payload, raw.length, copies), raw);
    }
  }
});

test('incomplete, out-of-range, and trailing rANS states fail closed', () => {
  for (const bad of [Buffer.alloc(0), Buffer.alloc(4, 0), Buffer.alloc(4, 255), wire.subarray(0,-1), Buffer.concat([wire, Buffer.of(0)])]) {
    assert.throws(() => restorePage(6, bad, sentence.length), /text recipe/i);
  }
  assert.throws(() => restoreText(wire, PAGE + 1, true), /page length/);
});

function mixedText(n) {
  // Generate short conditional words interspersed with recurring field labels.
  // The unique values keep this from collapsing to one repeated literal block.
  const rng = noiseBytes(n); let z = 0;
  const text = rng.map((v,i) => {
    z = (5*z + ((v & 7) < 5 ? 1 : (v >> 4) & 7)) % 26;
    return i % 97 < 8 ? '|field= '[i % 97].charCodeAt(0) : 97 + z;
  });
  return text;
}

test('legacy and context ablations, independent text pages, verified repair and preserved GRF1 golden file', t => {
  const dir = fs.mkdtempSync(join(tmpdir(), 'grf-text-')); t.after(() => fs.rmSync(dir,{recursive:true,force:true}));
  const p = name => join(dir,name), raw = mixedText(PAGE * 2 + 103);
  fs.writeFileSync(p('input'), raw);
  for (const [text, mode] of [['off',1],['context',5],['span',6]]) {
    const first = packPage(raw.subarray(0,PAGE), undefined, text);
    assert.equal(first.mode, mode);
    const gradient = pageGradient(mode, first.body, PAGE); let prior = 0;
    assert.deepEqual(gradient.map(d => prior ^= d), raw.subarray(0,PAGE));
    packFile(p('input'), p(text), undefined, {text});
  }
  fs.unlinkSync(p('input'));
  const damaged = Buffer.from(raw); damaged[PAGE + 2] ^= 64; fs.writeFileSync(p('bad'),damaged);
  for (const policy of ['off','context','span']) {
    const r = restoreFile(p(policy),p(`fixed-${policy}`),{damaged:p('bad')});
    assert.equal(r.rebuiltPages,1); assert.equal(r.reusedPages,2);
    assert.deepEqual(fs.readFileSync(p(`fixed-${policy}`)),raw);
  }
  restoreFile(new URL('./edited-grid.grf', import.meta.url),p('old'));
  assert.deepEqual(fs.readFileSync(p('old')),diagram(65,65,10));
});

test('Swarm regrows a text-span page from its actual archive instructions, with or without damage',
  {skip:!process.env.SWARM_WEB}, async () => {
    const raw = mixedText(4096), {mode,body} = packPage(raw);
    assert.equal(mode,6);
    const grow = await swarmAssembler(process.env.SWARM_WEB);
    assert.deepEqual(grow(mode,body,raw.length),raw);
    const cut = Buffer.from(raw.subarray(0,-57)); cut.fill(0,88,140);
    assert.deepEqual(grow(mode,body,raw.length,cut),raw);
  });
