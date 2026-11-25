import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PAGE, restorePage } from '../src/codec.mjs';
import { TEXT_WINDOW as W64, TAPE_WINDOW as W256, packText } from '../src/text.mjs';
import { chooseGroup, groupWindowChoices, parseGroup, restoreGroup } from '../src/groups.mjs';
import { packFile, restoreFile } from '../src/archive.mjs';
import { templateTape } from '../src/templates.mjs';
import { noiseBytes } from './fixtures.mjs';
import { swarmAssembler } from '../src/swarm.mjs';

const windows = ['64','256-reset','256'];
function choices(raw) {
  const all = groupWindowChoices(raw,undefined,'span','auto',windows);
  return windows.map(w=>chooseGroup(all[w],'auto'));
}
// The two distant copies straddle a predictor reset. Only the digit-bearing
// line is eligible for a template, and its first occurrence is kept literally.
function fixture() {
  const alphabet = Buffer.from('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ   ');
  const a = noiseBytes(2*W64).map(b=>alphabet[b%alphabet.length]);
  const line = Buffer.concat([Buffer.from('001 007 045 '),a.subarray(17,6200),Buffer.of(10)]);
  return Buffer.concat([line,line,line,line,a,Buffer.of(10),a.subarray(0,W64)]).subarray(0,13*PAGE+19);
}

test('both 256 KiB predictors handle full-length counts, rare symbols across resets, and a truncated stream', () => {
  const raw = Buffer.alloc(W256,97);
  for (const [offset,b] of [[W64-1,0],[W64+3,255],[2*W64+9,254],[W256-1,253]]) raw[offset] = b;
  for (const copies of [false,true]) for (const w of ['256-reset','256']) {
    const body = packText(raw,copies,w), mode = (w === '256' ? 13 : 11) + Number(copies);
    assert.deepEqual(restorePage(mode,body,W256),raw);
    assert.throws(()=>restorePage(mode,body.subarray(0,-1),W256));
    for (const n of [W64,W256+1]) assert.throws(()=>restorePage(mode,body,n),/template-window/);
  }
});

test('previously plain groups keep exactly the 64 KiB wire; a selected tape can use a payload larger than u16', () => {
  const plain = noiseBytes(W64).map(b=>97+b%26), [a,b,c] = choices(Buffer.concat([plain,plain]));
  assert.equal(a.kind,'plain'); assert.deepEqual(b.bytes,a.bytes); assert.deepEqual(c.bytes,a.bytes);
  const raw = fixture(), [base,reset,wide] = choices(raw);
  assert.equal(base.kind,'exact'); assert.deepEqual(reset.bytes,base.bytes,'reset cannot beat the mixed baseline on this tape');
  assert.ok(wide.bytes.length < base.bytes.length);
  const g = parseGroup(wide.bytes,raw.length);
  assert.equal(g.wireBytes,wide.bytes.length); assert.equal(g.records.length,1); assert.equal(g.records[0].mode,14);
  assert.ok(g.records[0].body.length > 65535);
  const bad = Buffer.from(raw); bad[2*PAGE+31] ^= 127; bad[10*PAGE] ^= 1;
  for (const v of [base,reset,wide]) {
    const result = restoreGroup(parseGroup(v.bytes,raw.length),bad);
    assert.deepEqual(result.bytes,raw);
    assert.deepEqual([result.rebuiltPages,result.reusedPages,result.replayedBytes,result.decodedTapeBytes],[2,12,raw.length,g.tapeLength]);
  }
});

test('expanded template tapes can contain a full 256 KiB record followed by an independent tail', () => {
  const line = 'Number 001, with a second number 002, and a third one 003 in a long enough line.\n';
  const raw = Buffer.from(line+line+'\xff\n'.repeat(93000),'latin1'), tape = templateTape(raw,'exact').bytes;
  assert.ok(tape.length > W256+W64);
  const h = Buffer.alloc(5); h[0] = 128; h.writeUInt32LE(tape.length,1);
  const parts = [h];
  for (let i=0;i<raw.length;i+=PAGE) parts.push(createHash('sha256').update(raw.subarray(i,i+PAGE)).digest().subarray(0,16));
  for (let i=0;i<tape.length;i+=W256) {
    const body = packText(tape.subarray(i,i+W256),false,'256'), h = Buffer.alloc(5);
    h[0]=13; h.writeUInt32LE(body.length,1); parts.push(h,body);
  }
  const g = parseGroup(Buffer.concat(parts),raw.length);
  assert.deepEqual(g.records.map(r=>r.length),[W256,tape.length-W256]);
  assert.deepEqual(restoreGroup(g).bytes,raw);
});

test('large records reject plain or unaligned placement, short tails and invalid 32-bit payload lengths', () => {
  function header(n) { const h=Buffer.alloc(5+16*Math.ceil(n/PAGE)); h[0]=128; h.writeUInt32LE(n,1); return h; }
  assert.throws(()=>parseGroup(Buffer.of(14),W256),/placement/);
  assert.throws(()=>parseGroup(Buffer.concat([header(W64),Buffer.of(14)]),W64),/placement/);
  const literal = Buffer.concat([Buffer.of(0,0,64),Buffer.alloc(PAGE)]);
  assert.throws(()=>parseGroup(Buffer.concat([header(W256),literal,Buffer.of(14)]),W256),/placement/);
  for (const n of [3,W256+1,0xffffffff]) {
    const h=Buffer.alloc(5); h[0]=14; h.writeUInt32LE(n,1);
    assert.throws(()=>parseGroup(Buffer.concat([header(W256),h]),W256),/page record/);
  }
});

test('default archive restores with the source gone, repairs a shifted middle deletion, and rejects a one-byte recipe loss', t => {
  const dir=fs.mkdtempSync(join(tmpdir(),'grf-deletion-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const p=name=>join(dir,name), raw=fixture(); fs.writeFileSync(p('in'),raw);
  const packed=packFile(p('in'),p('archive')); assert.equal(packed.methods['text-span-256'],1); fs.unlinkSync(p('in'));
  const whole=restoreFile(p('archive'),p('restored')); assert.equal(whole.reusedPages,0); assert.deepEqual(fs.readFileSync(p('restored')),raw);
  const cut = Math.floor(raw.length*0.9), kept = Buffer.concat([raw.subarray(0,PAGE+17),raw.subarray(PAGE+17+cut)]);
  fs.writeFileSync(p('survivor'),kept);
  const fixed=restoreFile(p('archive'),p('fixed'),{damaged:p('survivor')});
  assert.equal(fixed.reusedPages,1); assert.deepEqual(fs.readFileSync(p('fixed')),raw);
  const archive=fs.readFileSync(p('archive')), at=Math.floor(archive.length/2);
  fs.writeFileSync(p('broken'),Buffer.concat([archive.subarray(0,at),archive.subarray(at+1)]));
  assert.throws(()=>restoreFile(p('broken'),p('unverified'),{damaged:p('restored')})); assert.equal(fs.existsSync(p('unverified')),false);
});

test('the Swarm regrows just the missing original tail of a 256 KiB template record', {skip:!process.env.SWARM_WEB}, async () => {
  const raw=fixture(), wide=choices(raw)[2], group=parseGroup(wide.bytes,raw.length);
  assert.equal(group.records[0].mode,14);
  const assemble=await swarmAssembler(process.env.SWARM_WEB), r=restoreGroup(group,raw.subarray(0,-19),assemble);
  assert.deepEqual(r.bytes,raw); assert.deepEqual([r.rebuiltPages,r.reusedPages,r.replayedBytes],[1,13,raw.length]);
  assert.equal(assemble.stats.outputBits,19*8);
});
