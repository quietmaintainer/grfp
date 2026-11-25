import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { packFile, inspectFile, restoreFile } from '../src/archive.mjs';
import { PAGE } from '../src/codec.mjs';
import { GROUP, chooseGroup, groupChoices, parseGroup, restoreGroup } from '../src/groups.mjs';
import { expandTape, templateTape } from '../src/templates.mjs';
import { noiseBytes } from './fixtures.mjs';
import { swarmAssembler } from '../src/swarm.mjs';

const record = (a,b,c, label = 'sample') => `Report for ${label}: the population was ${a} people in ${b} households and ${c} family units.\r\n`;
function examples(n) {
  let x=17001; const num=() => { x=(Math.imul(x,1664525)+1013904223)>>>0; return String(x%100_000).padStart(6,'0'); };
  const rows=[]; let total=0;
  while(total<n) { const s=record(num(),num(),num()); rows.push(s); total+=s.length; }
  return Buffer.from(rows.join('')).subarray(0,n);
}
function temp(t) {
  const dir=fs.mkdtempSync(join(tmpdir(),'grf-group-test-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  return n=>join(dir,n);
}

test('numeric template contains only the learned ID and exact digit strings after the first literal', () => {
  const a = Buffer.from(record('01','00002','123')), b = Buffer.from(record('9','007','0000'));
  const ff = Buffer.of(255,0,254,10), tail = Buffer.from('猫\x00no final newline');
  const raw = Buffer.concat([ff,a,b,tail]);
  const {bytes,refs} = templateTape(raw,'slots');
  assert.equal(refs,1);
  assert.deepEqual(bytes,Buffer.concat([Buffer.of(255,0),ff,a,Buffer.of(255,1,1),Buffer.from('9'),Buffer.of(3),Buffer.from('007'),Buffer.of(4),Buffer.from('0000'),tail]));
  assert.deepEqual(expandTape(bytes,'slots',raw.length),raw);
  assert.equal(templateTape(raw,'exact'),null);
  const identical = Buffer.concat([a,a,ff]);
  assert.deepEqual(expandTape(templateTape(identical,'exact').bytes,'exact',identical.length),identical);
});

test('late template IDs, UTF-8, invalid UTF-8, long slots, and group-local history are reversible', () => {
  const label = i=>String.fromCharCode(65+Math.floor(i/26),65+i%26)+' μ';
  const first = Array.from({length:140},(_,i)=>record('10','8','94',label(i))).join('');
  const raw = Buffer.concat([Buffer.from(first+record('0'.repeat(260),'8','01',label(139))),Buffer.of(255,195,0,255)]);
  const {bytes,refs}=templateTape(raw,'slots'); assert.equal(refs,1);
  assert.deepEqual(expandTape(bytes,'slots',raw.length),raw);
  assert.throws(()=>expandTape(Buffer.of(255,140,1),'slots',raw.length),/Unknown template/);
});

test('reject unknown references, invalid digit payloads, noncanonical integers, and oversized expansions', () => {
  const first = Buffer.from(record(1,2,3));
  for(const suffix of [[255],[255,128,0],[255,128,128,128],[255,0,10],[255,2],
    [255,1,0],[255,1,1,97],[255,1,127,48],[255,1,1,48,1,49]]) {
    assert.throws(()=>expandTape(Buffer.concat([first,Buffer.from(suffix)]),'slots',first.length*3));
  }
  const exact = Buffer.concat([first,Buffer.of(255,1)]);
  assert.throws(()=>expandTape(exact,'exact',first.length+1),/exceeds/);
  assert.throws(()=>expandTape(exact,'exact',first.length*2+1),/length mismatch/);
});

test('measure complete group records and preserve the legacy bytes on ties and no-match data', () => {
  const unique=groupChoices(Buffer.of(255,0,1), undefined,'span','auto');
  assert.equal(chooseGroup(unique,'auto'),unique.plain);
  const raw=examples(PAGE*2+17), c=groupChoices(raw,undefined,'span','auto');
  assert.equal(chooseGroup(c,'exact').kind,'plain'); assert.equal(chooseGroup(c,'auto').kind,'slots');
  for(const v of Object.values(c)) {
    const parsed=parseGroup(v.bytes,raw.length);
    assert.equal(parsed.wireBytes,v.bytes.length); assert.equal(parsed.hashes.length,3);
    assert.deepEqual(restoreGroup(parsed).bytes,raw);
  }
  const repeated = Buffer.concat(Array.from({length:12},()=>raw.subarray(0,raw.lastIndexOf(10)+1))).subarray(0,GROUP);
  const all=groupChoices(repeated,undefined,'span','auto'); assert.ok(all.exact && all.slots);
  assert.deepEqual(restoreGroup(parseGroup(all.exact.bytes,repeated.length)).bytes,repeated);
  assert.equal(chooseGroup(all,'auto').bytes.length,Math.min(...Object.values(all).map(v=>v.bytes.length)));
});

test('mixed checkpoints restore without source and repair only the required original pages, replaying a template group once', t => {
  const p=temp(t), raw=Buffer.concat([noiseBytes(GROUP),examples(GROUP),Buffer.alloc(313,128)]);
  fs.writeFileSync(p('in'),raw);
  // This fixture exercises the numeric-group checkpoint. With a 64 KiB
  // predictor its plain record is smaller, so pin the original control here.
  const s=packFile(p('in'),p('r'),undefined,{textWindow:'16'}); const baseline=packFile(p('in'),p('b'),undefined,{templates:'off',textWindow:'16'});
  fs.unlinkSync(p('in')); assert.ok(s.recipeBytes<baseline.recipeBytes);assert.deepEqual(s.groupMethods,{plain:2,slots:1});
  assert.deepEqual(inspectFile(p('r')).groupMethods,s.groupMethods);
  restoreFile(p('r'),p('restored'));assert.deepEqual(fs.readFileSync(p('restored')),raw);
  const corrupt=Buffer.from(raw);for(const i of [99,GROUP+PAGE+3,GROUP+PAGE*8+1])corrupt[i]^=0x45;
  fs.writeFileSync(p('bad'),corrupt);
  const fixed=restoreFile(p('r'),p('out'),{damaged:p('bad')});
  assert.deepEqual(fs.readFileSync(p('out')),raw); assert.deepEqual(fs.readFileSync(p('bad')),corrupt);
  assert.deepEqual([fixed.pages,fixed.rebuiltPages,fixed.reusedPages,fixed.replayedBytes],[33,3,30,GROUP+PAGE]);
  const clean=restoreFile(p('r'),p('out2'),{damaged:p('restored')}); assert.equal(clean.replayedBytes,0);
  const badArchive=fs.readFileSync(p('r'));badArchive[badArchive.length-9]^=37;fs.writeFileSync(p('bad-r'),badArchive);
  assert.throws(()=>restoreFile(p('bad-r'),p('no-output'),{damaged:p('restored')}),/checksum/);
  assert.equal(fs.existsSync(p('no-output')),false);
});

test('invalid group bounds and malformed inner framing fail before publication',()=>{
  const raw=examples(PAGE+19), c=groupChoices(raw,undefined,'span','auto').slots;
  const huge=Buffer.from(c.bytes);huge.writeUInt32LE(raw.length*3+1,1);
  assert.throws(()=>parseGroup(huge,raw.length),/tape length/);
  const nested=Buffer.from(c.bytes);nested[5+32]=129;
  assert.throws(()=>parseGroup(nested,raw.length),/page record/);
  assert.throws(()=>parseGroup(c.bytes.subarray(0,-1),raw.length),/Truncated/);
  assert.throws(()=>parseGroup(Buffer.concat([c.bytes,Buffer.of(0)]),raw.length),/Trailing/);
});

test('Swarm grows and repairs original file bits from a numeric template archive', {skip:!process.env.SWARM_WEB},async t=>{
  const p=temp(t),data=examples(4096);fs.writeFileSync(p('in'),data);
  assert.equal(packFile(p('in'),p('r')).groupMethods.slots,1);fs.unlinkSync(p('in'));
  const assemble=await swarmAssembler(process.env.SWARM_WEB);
  restoreFile(p('r'),p('rebuilt'),{assemble});assert.deepEqual(fs.readFileSync(p('rebuilt')),data);
  const bad=Buffer.from(data.subarray(0,-15));bad[101]^=64;fs.writeFileSync(p('bad'),bad);
  restoreFile(p('r'),p('fixed'),{damaged:p('bad'),assemble});assert.deepEqual(fs.readFileSync(p('fixed')),data);
});
