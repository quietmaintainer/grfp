import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { trainPrior,parsePrior } from '../src/prior.mjs';
import { frameModel } from '../src/text.mjs';
import { wasmFrameModel } from '../src/wasm-model.mjs';
import { packLong,restoreLong,readLongHeader } from '../src/long.mjs';
import { config,packLongRecord } from '../src/long-record.mjs';
import { openSeed } from '../src/seed.mjs';
import { packLongProtected,recoverLongProtected,reprotect,protectLongExisting } from '../src/protected.mjs';
import { scanFrames,globalLayout,frameKey,FRAME,DATA,PARITY,digest } from '../src/frames.mjs';
import { cutCopy } from './loss-fixtures.mjs';
import { noiseBytes } from './fixtures.mjs';
const U=262144,files=t=>{const d=fs.mkdtempSync(join(tmpdir(),'grl-prior-test-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));return n=>join(d,n);};
const read=(p,fn)=>{const fd=fs.openSync(p,'r');try{return fn(fd);}finally{fs.closeSync(fd);}};
const prose=Buffer.from('Warm bytes learn counts from the previous words, but isolated chunks begin cold.\n'.repeat(401));

test('bounded offline training is deterministic, starts at byte zero, and leaves shared model tables immutable',()=>{
  const a=trainPrior(prose,800);assert.deepEqual(a,trainPrior(prose,800));const prior=parsePrior(a),before=digest(Buffer.from(prior.freq.buffer));
  assert.ok(prior.freq.buffer instanceof SharedArrayBuffer);const raw=prose.subarray(0,96),cold=frameModel(raw.length),seeded=frameModel(raw.length,prior);
  const b=seeded.encode(raw);assert.ok(b.length<cold.encode(raw).length);assert.deepEqual(frameModel(raw.length,prior).decode(b,raw.length),raw);
  assert.equal(digest(Buffer.from(prior.freq.buffer)),before);assert.deepEqual(frameModel(raw.length,parsePrior(trainPrior(prose,0))).encode(raw),frameModel(raw.length).encode(raw));
  const bad=Buffer.from(a);bad.writeUInt16LE(1,6);assert.throws(()=>parsePrior(bad),/context/);bad.writeUInt16LE(0,6);bad[9]=0;assert.throws(()=>parsePrior(bad),/mass/);
});

test('a zero-row control has identical checkpoint bytes to the published unseeded 256 KiB and 4 MiB layouts',()=>{
  const prior=parsePrior(trainPrior(prose,0));for(const p of [256,4096]){const raw=Buffer.alloc(p===256?U:U+917,prose);
    assert.deepEqual(packLongRecord(raw,{...config(p,256,true,true),prior}),packLongRecord(raw,config(p,256,p===4096)));}
});

test('embedded GRL3 prior alone restores and repairs; independent frame has no preceding warming or training-file dependency',async t=>{
  const f=files(t),raw=Buffer.concat([Buffer.alloc(U,prose),Buffer.alloc(U,prose),Buffer.from('short tail')]);fs.writeFileSync(f('src'),raw);fs.writeFileSync(f('model'),trainPrior(prose));
  await packLong(f('src'),f('s'),{modelPath:f('model'),predictor:256});await packLong(f('src'),f('p'),{modelPath:f('model'),predictor:256,jobs:2});
  assert.deepEqual(fs.readFileSync(f('p')),fs.readFileSync(f('s')));fs.unlinkSync(f('model'));fs.unlinkSync(f('src'));await restoreLong(f('s'),f('out'),{jobs:2});assert.deepEqual(fs.readFileSync(f('out')),raw);
  const old=Buffer.from(raw);old[U+105]^=127;fs.writeFileSync(f('damaged'),old);
  const s=await restoreLong(f('p'),f('fixed'),{damaged:f('damaged')});assert.deepEqual([s.rebuiltPages,s.replayedBytes,s.warmedOriginalBytes],[1,U,0]);assert.deepEqual(fs.readFileSync(f('fixed')),raw);
  const reader=openSeed(f('s'));try{assert.deepEqual(reader.view.slice(U-11,33),raw.subarray(U-11,U+22));}finally{reader.close();}
  const broken=fs.readFileSync(f('s'));broken[53]^=16;fs.writeFileSync(f('bad'),broken);await assert.rejects(restoreLong(f('bad'),f('none'),{damaged:f('out')}),/prior checksum/);assert.ok(!fs.existsSync(f('none')));
});

test('compiled and JS predictors use identical quantized starting counts including a one-byte checkpoint', {skip:!process.env.GRL_PREDICTOR_WASM},()=>{
  const p=parsePrior(trainPrior(noiseBytes(32000),16384));for(const parts of [[Buffer.of(11)],[prose,noiseBytes(17001),prose]]){
    const n=parts.reduce((s,b)=>s+b.length,0),a=frameModel(n,p),w=wasmFrameModel(n,true,p),blocks=[];
    try{for(const b of parts){const wire=a.encode(b);assert.deepEqual(w.encode(b),wire);blocks.push(wire);}}finally{w.close();}
    const r=wasmFrameModel(n,false,p);try{parts.forEach((b,i)=>{if(i===1)r.warm(b);else assert.deepEqual(r.decode(blocks[i],b.length),b);});}finally{r.close();}
  }
});

test('global16 restores a lost model and missing independent frames, cross-recompiles donors, refuses overlapping loss',async t=>{
  const f=files(t),raw=Buffer.alloc(7*U+1025,prose);for(let i=100;i<raw.length;i+=5000)raw[i]=i&255;
  fs.writeFileSync(f('src'),raw);fs.writeFileSync(f('prior'),trainPrior(noiseBytes(24000),16384));const opt={modelPath:f('prior'),predictor:256,jobs:2};
  await packLong(f('src'),f('inner'),opt);const packed=await packLongProtected(f('src'),f('protected'),{...opt,parityPercent:50});
  const scan=read(f('protected'),scanFrames),layout=globalLayout(scan.catalog,scan.catalogBytes),tail=FRAME+scan.catalogBytes.length;
  assert.equal(layout.parts.length,2);assert.equal(layout.r,4);assert.equal(packed.innerFormat,'GRL3');
  protectLongExisting(f('inner'),f('retrofit'),50);assert.deepEqual(fs.readFileSync(f('retrofit')),fs.readFileSync(f('protected')));
  const range=(type,i)=>{const e=scan.entries.get(frameKey(type,i));return [e.at,FRAME+e.n];};
  const catLen=layout.parts.reduce((s,b)=>s+FRAME+b.length,0);const verify=out=>{
    assert.deepEqual(fs.readFileSync(join(out,'restored.bin')),raw);assert.deepEqual(fs.readFileSync(join(out,'recipe.grl')),fs.readFileSync(f('inner')));
    assert.deepEqual(fs.readFileSync(join(out,'protected.grfp')),fs.readFileSync(f('protected')));
  };
  fs.unlinkSync(f('src'));fs.unlinkSync(f('prior'));cutCopy(f('protected'),f('lost-model'),[[0,catLen],range(DATA,4),[packed.protectedBytes-tail,tail]]);
  const alone=await recoverLongProtected(f('lost-model'),f('first'),{jobs:2});assert.deepEqual([alone.catalogPiecesFromParity,alone.recipeGroupsFromParity,alone.intactCatalogCopies],[2,1,0]);verify(f('first'));
  cutCopy(f('protected'),f('no-fec'),[range(DATA,2),...Array.from({length:4},(_,i)=>range(PARITY,i))]);const old=Buffer.from(raw);old[5*U+99]^=125;fs.writeFileSync(f('old'),old);
  const cross=await recoverLongProtected(f('no-fec'),f('second'),{jobs:2,damaged:f('old')});assert.deepEqual([cross.recipeGroupsFromOriginal,cross.recipeGroupsFromParity,cross.raw.replayedBytes,cross.raw.warmedOriginalBytes],[1,0,U,0]);verify(f('second'));
  old[2*U+14]^=1;fs.writeFileSync(f('old'),old);await assert.rejects(recoverLongProtected(f('no-fec'),f('refused'),{damaged:f('old')}),/still missing/);assert.ok(!fs.existsSync(f('refused')));
  reprotect(f('protected'),f('copy'));assert.deepEqual(fs.readFileSync(f('copy')),fs.readFileSync(f('protected')));
  assert.throws(()=>reprotect(f('protected'),f('local'),{fec:'local8'}),/global16/);
});

test('unseeded GRL2 is also a directly protectable inner format',async t=>{
  const f=files(t);fs.writeFileSync(f('src'),prose);const s=await packLongProtected(f('src'),f('outer'),{parityPercent:5});assert.equal(s.innerFormat,'GRL2');
  await recoverLongProtected(f('outer'),f('out'));assert.deepEqual(fs.readFileSync(join(f('out'),'restored.bin')),prose);
  assert.equal(read(join(f('out'),'recipe.grl'),readLongHeader).h.length,14);
});
