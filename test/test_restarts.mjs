import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { frameModel,textEvents,encodeTextEvents,TAPE_WINDOW as U } from '../src/text.mjs';
import { wasmFrameModel } from '../src/wasm-model.mjs';
import { config,packLongRecord,restoreLongRecord } from '../src/long-record.mjs';
import { transform,u32,pageHashes } from '../src/long-tape.mjs';
import { packLong,restoreLong } from '../src/long.mjs';
import { openSeed } from '../src/seed.mjs';
import { noiseBytes } from './fixtures.mjs';

function fill(s,n){const b=Buffer.from(s);return Buffer.alloc(n,b);}
const prose='Lake Lotus, Nevada had 0017 households, 0029 inhabitants and 00305 reports in the historical municipal register.\n';
const rawParts=()=>[noiseBytes(U),fill(prose+prose.replace('0017','0414'),U),fill('a new word comes after the old word\r\n',U),
  fill('<page>\n<title>Lake Lotus, Nevada</title>\n'+prose+prose.replace('0017','0142')+'</page>\n',U),fill(prose,U),Buffer.from('short final unit')];
// Force a mixture of the three valid entropy modes so correctness doesn't
// rely on which fallback happens to be cheapest for a particular fixture.
function fixture(){const src=rawParts(),raw=Buffer.concat(src),v=src.map(transform),m=frameModel(v.reduce((n,x)=>n+x.bytes.length,0));
  const modes=[0,1,2,0,2,0],pieces=[pageHashes(raw),...v.flatMap(t=>[Buffer.of(t.kind),u32(t.bound),u32(t.bytes.length)])];
  for(const [i,t] of v.entries()){const text=m.encode(t.bytes),mode=modes[i],body=[t.bytes,deflateRawSync(t.bytes),text][mode];
    assert.ok(body.length<=t.bytes.length);pieces.push(Buffer.of(mode),u32(body.length),body);}
  return {raw,wire:Buffer.concat(pieces),v};}

test('flushing only rANS leaves the whole probability trace identical; fast known-byte updates preserve the next frame',()=>{
  const parts=[noiseBytes(8197),fill(prose,U),fill(prose+prose.toUpperCase(),U),Buffer.alloc(U,7),Buffer.from('word word SOME words\x00\xff','latin1')];
  const raw=Buffer.concat(parts),m=frameModel(raw.length),traces=parts.map(b=>m.events(b));
  assert.deepEqual(encodeTextEvents(traces),encodeTextEvents([textEvents(raw,true)]));
  const alternate=frameModel(raw.length);parts.forEach((b,i)=>{if(i%2)assert.deepEqual(alternate.decode(encodeTextEvents([traces[i]]),b.length),b);else alternate.warm(b);});
});

test('repair re-creates selected template tapes only for verified donors, decodes affected frames, skips suffix',()=>{
  const {raw,wire,v}=fixture(),c=config(4096,256,true);assert.ok(v[1].kind && v[3].kind);
  assert.deepEqual(restoreLongRecord(wire,raw.length,c).bytes,raw);
  const bad=Buffer.from(raw);bad[4*U+31]^=3;bad[4*U+32769]^=1;
  const r=restoreLongRecord(wire,raw.length,c,bad);assert.deepEqual(r.bytes,raw);
  assert.deepEqual([r.rebuiltPages,r.replayedBytes,r.entropyFrames,r.entropyDecodedBytes,r.warmedOriginalBytes,r.warmedTapeBytes],
    [2,U,1,v[4].bytes.length,4*U,v.slice(0,4).reduce((n,t)=>n+t.bytes.length,0)]);
  bad[U+21]^=5;const mixed=restoreLongRecord(wire,raw.length,c,bad);assert.deepEqual(mixed.bytes,raw);
  assert.deepEqual([mixed.replayedBytes,mixed.fallbackWarmBytes,mixed.warmedOriginalBytes,mixed.entropyFrames],[2*U,v[1].bytes.length,3*U,1]);
  const tail=restoreLongRecord(wire,raw.length,c,raw.subarray(0,-1));assert.deepEqual(tail.bytes,raw);assert.equal(tail.entropyFrames+tail.warmedOriginalBytes,0);
  const good=restoreLongRecord(wire,raw.length,c,raw);assert.equal(good.bytes,raw);assert.equal(good.warmedTapeBytes+good.decodedTapeBytes,0);
  assert.throws(()=>restoreLongRecord(wire.subarray(0,-1),raw.length,c,raw));
  // A stale forward transform descriptor cannot be used as a warm-up donor.
  const wrong=Buffer.from(wire),h=16*Math.ceil(raw.length/16384)+9;wrong.writeUInt32LE(wrong.readUInt32LE(h+5)-1,h+5);
  const lateOnly=Buffer.from(raw);lateOnly[4*U+31]^=3;
  assert.throws(()=>restoreLongRecord(wrong,raw.length,c,lateOnly),/canonical template tape/);
});

test('GRL2 parallel disk restore with no source, flipped footer on fully healthy input, and seed compatibility',async t=>{
  const d=fs.mkdtempSync(join(tmpdir(),'grl2-test-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));const f=n=>join(d,n);
  const tail=Buffer.from('last checkpoint'),raw=Buffer.concat([Buffer.alloc(16*U),tail]);fs.writeFileSync(f('in'),raw);
  await packLong(f('in'),f('one'),{restart:true});await packLong(f('in'),f('two'),{jobs:2,restart:true});assert.deepEqual(fs.readFileSync(f('one')),fs.readFileSync(f('two')));fs.unlinkSync(f('in'));
  await restoreLong(f('one'),f('new'),{jobs:2});assert.deepEqual(fs.readFileSync(f('new')),raw);
  const seed=openSeed(f('one'));try{assert.deepEqual(seed.view.slice(16*U,tail.length),tail);}finally{seed.close();}
  const broken=fs.readFileSync(f('two'));broken[broken.length-3]^=4;fs.writeFileSync(f('bad'),broken);
  await assert.rejects(restoreLong(f('bad'),f('no'),{damaged:f('new')}),/mismatch/);assert.ok(!fs.existsSync(f('no')));
  await assert.rejects(packLong(f('new'),f('invalid'),{restart:true,templates:4096}),/requires/);
});

test('compiled model matches every JS entropy byte and repairs a JS-written stream; truncated rANS traps', {skip:!process.env.GRL_PREDICTOR_WASM},()=>{
  const parts=rawParts().map((b,i)=>i===0?b:Buffer.concat([b.subarray(0,-2),Buffer.of(253,i)])),total=parts.reduce((n,b)=>n+b.length,0);
  const js=frameModel(total),enc=wasmFrameModel(total,true),blocks=[];
  try {for(const b of parts){const ref=js.encode(b);assert.deepEqual(enc.encode(b),ref);blocks.push(ref);}}finally{enc.close();}
  const dec=wasmFrameModel(total,false);try{parts.forEach((b,i)=>{if(i===0 || i===2)dec.warm(b);else assert.deepEqual(dec.decode(blocks[i],b.length),b);});}finally{dec.close();}
  const err=wasmFrameModel(total,false);try{assert.throws(()=>err.decode(blocks[0].subarray(0,-1),parts[0].length));}finally{err.close();}
  const {wire,raw}=fixture(),bad=Buffer.from(raw);bad[4*U+11]^=78;const c={...config(4096,256,true),backend:'wasm'};
  const r=restoreLongRecord(wire,raw.length,c,bad);assert.deepEqual(r.bytes,raw);assert.deepEqual([r.entropyFrames,r.replayedBytes,r.warmedOriginalBytes],[1,U,4*U]);
  assert.deepEqual(packLongRecord(raw,c),packLongRecord(raw,{...c,backend:'js'}));
});
