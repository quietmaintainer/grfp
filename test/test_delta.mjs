import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { packLong } from '../src/long.mjs';
import { DELTA_GROUP as G,packDelta,restoreDelta } from '../src/delta.mjs';
import { noiseBytes } from './fixtures.mjs';
const fixture=t=>{const d=fs.mkdtempSync(join(tmpdir(),'grd-test-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));return n=>join(d,n);};

test('one immutable seed restores independently shifted/edited versions; selective repair skips seed decompression',async t=>{
  const f=fixture(t),base=noiseBytes(12*G+49),prefix=Buffer.from('insertion shifts every later byte!');
  fs.writeFileSync(f('source'),base);await packLong(f('source'),f('seed'),{predictor:256,templates:256});fs.unlinkSync(f('source'));
  const v1=Buffer.concat([prefix,base.subarray(0,4*G+11),base.subarray(4*G+50)]),v2=Buffer.from(base);v2[7*G+13]^=123;
  for(const [i,v] of [v1,v2].entries()) {
    fs.writeFileSync(f('v'),v);const d=await packDelta(f('seed'),f('v'),f(`d${i}`));fs.unlinkSync(f('v'));
    assert.ok(d.deltaBytes<v.length/20);assert.ok(d.copyBytes>v.length*0.95);
    await restoreDelta(f('seed'),f(`d${i}`),f(`fresh${i}`));assert.deepEqual(fs.readFileSync(f(`fresh${i}`)),v);
  }
  const intact=await restoreDelta(f('seed'),f('d1'),f('reuse'),{damaged:f('fresh1')});assert.deepEqual([intact.rebuiltGroups,intact.seedCheckpointsDecoded],[0,0]);
  const bad=Buffer.from(v2);bad[7*G+13]^=64;fs.writeFileSync(f('bad'),bad);
  const fixed=await restoreDelta(f('seed'),f('d1'),f('fixed'),{damaged:f('bad')});
  assert.deepEqual(fs.readFileSync(f('fixed')),v2);assert.equal(fixed.replayedTargetBytes,G);assert.equal(fixed.seedCheckpointsDecoded,1);
  assert.deepEqual(fs.readFileSync(f('bad')),bad);
  const corrupt=fs.readFileSync(f('d1'));corrupt[corrupt.length-1]^=14;fs.writeFileSync(f('broken'),corrupt);
  await assert.rejects(restoreDelta(f('seed'),f('broken'),f('bad-out'),{damaged:f('fixed')}),/footer/);assert.ok(!fs.existsSync(f('bad-out')));
  await packLong(f('bad'),f('other'));await assert.rejects(restoreDelta(f('other'),f('d1'),f('no')) ,/identity/);assert.ok(!fs.existsSync(f('no')));
});

test('version instructions can reference a numeric skeleton from the seed with exact new digits, NULs and CRLF',async t=>{
  const f=fixture(t),row=(a,b,c)=>Buffer.from(`\x00Report at ${a}: visitors ${b} and families ${c}, including leading zeroes in these three exact numeric fields.\r\n`,'latin1');
  fs.writeFileSync(f('base'),row('0123','00004','67'));await packLong(f('base'),f('seed'));
  const v=Buffer.concat(Array.from({length:80},(_,i)=>row('00777',String(91853+i),'0000000004')));fs.writeFileSync(f('v'),v);
  const d=await packDelta(f('seed'),f('v'),f('delta'));assert.ok(d.templateLines>0);assert.ok(d.deltaBytes<v.length/4);
  await restoreDelta(f('seed'),f('delta'),f('out'));assert.deepEqual(fs.readFileSync(f('out')),v);
  const control=await packDelta(f('seed'),f('v'),f('copy-only'),{numeric:false});assert.equal(control.templateLines,0);
  await restoreDelta(f('seed'),f('copy-only'),f('control'));assert.deepEqual(fs.readFileSync(f('control')),v);
});

test('empty seed and unrelated version use independent literals; a corrupt seed never publishes',async t=>{
  const f=fixture(t);fs.writeFileSync(f('empty'),Buffer.alloc(0));await packLong(f('empty'),f('seed'));
  for(const [i,raw] of [Buffer.alloc(0),noiseBytes(G+300)].entries()) {
    fs.writeFileSync(f('input'),raw);const d=await packDelta(f('seed'),f('input'),f(`d${i}`));assert.equal(d.copyBytes,0);
    await restoreDelta(f('seed'),f(`d${i}`),f(`out${i}`));assert.deepEqual(fs.readFileSync(f(`out${i}`)),raw);
  }
  const bad=fs.readFileSync(f('seed'));bad[bad.length-1]^=3;fs.writeFileSync(f('invalid'),bad);
  await assert.rejects(restoreDelta(f('invalid'),f('d0'),f('no')),/checksum/);assert.ok(!fs.existsSync(f('no')));
});
