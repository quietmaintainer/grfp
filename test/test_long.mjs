import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { packLong,restoreLong } from '../src/long.mjs';
import { config,packLongRecord,restoreLongRecord } from '../src/long-record.mjs';
import { templateTape,expandTape } from '../src/templates.mjs';
import { packText,restoreText } from '../src/text.mjs';
import { noiseBytes } from './fixtures.mjs';
const M=1024*1024;

test('4 MiB history round-trips rare boundary bytes and a digit slot requiring a four-byte varint',()=>{
  const bytes=Buffer.alloc(4*M,65);for(let i=M;i<bytes.length;i+=M)bytes[i]=i/M;bytes[bytes.length-1]=255;
  const tape=packText(bytes,true,'4096');assert.deepEqual(restoreText(tape,bytes.length,true,'4096'),bytes);
  assert.throws(()=>restoreText(tape.subarray(0,-1),bytes.length,true,'4096'));
  const a='The record contains 001 employees at 042 sites with 008 deliveries counted per employee.\n';
  const raw=Buffer.from(a+a.replace('001','1'.repeat(2*M+3))),d=templateTape(raw,'slots');assert.equal(d.refs,1);
  assert.deepEqual(expandTape(d.bytes,'slots',raw.length,21),raw);
});

test('independent template/predictor intervals, tail repair, identical serial/parallel archives, corruption never published',async t=>{
  const dir=fs.mkdtempSync(join(tmpdir(),'grl-test-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const f=n=>join(dir,n);
  const raw=Buffer.alloc(M+93,65);for(let i=0;i<M;i+=191)raw[i]=97+(i%26);fs.writeFileSync(f('in'),raw);
  await packLong(f('in'),f('one'),{predictor:1024,templates:256});await packLong(f('in'),f('two'),{predictor:1024,templates:256,jobs:2});
  assert.deepEqual(fs.readFileSync(f('one')),fs.readFileSync(f('two')));fs.unlinkSync(f('in'));
  await restoreLong(f('two'),f('out'),{jobs:2});assert.deepEqual(fs.readFileSync(f('out')),raw);
  const old=Buffer.from(raw);old[M+17]^=12;fs.writeFileSync(f('damaged'),old);
  const partial=await restoreLong(f('one'),f('fixed'),{damaged:f('damaged')});assert.deepEqual(fs.readFileSync(f('fixed')),raw);
  assert.deepEqual([partial.rebuiltPages,partial.reusedPages,partial.replayedBytes],[1,64,93]);
  old[17]^=1;fs.writeFileSync(f('damaged'),old);const two=await restoreLong(f('one'),f('again'),{damaged:f('damaged'),jobs:2});assert.equal(two.replayedBytes,raw.length);
  const broken=fs.readFileSync(f('one'));broken[broken.length-1]^=1;fs.writeFileSync(f('broken'),broken);
  await assert.rejects(restoreLong(f('broken'),f('no'),{damaged:f('out')}),/mismatch/);assert.ok(!fs.existsSync(f('no')));
});

test('binary, partial and malformed mixed records are bounded and verified',()=>{
  const raw=noiseBytes(271009),c=config(256,1024),wire=packLongRecord(raw,c);
  assert.deepEqual(restoreLongRecord(wire,raw.length,c).bytes,raw);
  assert.throws(()=>restoreLongRecord(wire.subarray(0,-1),raw.length,c));
  const bad=Buffer.from(wire);bad.writeUInt32LE(0xffffffff,16*Math.ceil(raw.length/16384)+5);assert.throws(()=>restoreLongRecord(bad,raw.length,c),/template lengths/);
});
