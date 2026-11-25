import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseExpert,correctVote,categories,DIMS,H,PARAM8,EXPERT_BYTES,NEUTRAL } from '../src/expert.mjs';
import { frameModel,TAPE_WINDOW as U } from '../src/text.mjs';
import { wasmFrameModel } from '../src/wasm-model.mjs';
import { config,packLongRecord,restoreLongRecord } from '../src/long-record.mjs';
import { packLong,restoreLong } from '../src/long.mjs';
import { protectLongExisting,recoverLongProtected } from '../src/protected.mjs';
import { FRAME,DATA,PARITY,scanFrames,globalLayout,frameKey } from '../src/frames.mjs';
import { cutCopy } from './loss-fixtures.mjs';
import { noiseBytes } from './fixtures.mjs';

const trained=fs.readFileSync(new URL('./expert-model/expert.gxe',import.meta.url)),control=fs.readFileSync(new URL('./expert-model/constant.gxe',import.meta.url));
const temp=t=>{const dir=fs.mkdtempSync(join(tmpdir(),'gxe-test-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return n=>join(dir,n);};
const text=Buffer.from('Statistics over a sentence can change the next prediction. A new word follows the old word.\n');

test('GXE1 decision codes agree with independent dense integer inference, including real context variation',()=>{
  const x=parseExpert(trained);assert.equal(trained.length,EXPERT_BYTES);assert.ok(x.table.buffer instanceof SharedArrayBuffer);
  const codes=new Set();for(let key=0;key<x.table.length;key+=389){const cat=categories(key,new Uint8Array(DIMS.length)),v=[trained.readInt16LE(5+PARAM8),trained.readInt16LE(7+PARAM8)];
    for(let h=0;h<H;h++){let a=trained.readInt8(5+h),p=H;for(let j=0;j<cat.length;j++){a+=trained.readInt8(5+p+cat[j]*H+h);p+=DIMS[j]*H;}
      for(let k=0;k<2;k++)v[k]+=Math.max(0,Math.min(128,a))*trained.readInt8(5+p+k*H+h);}
    const q=v.map(z=>32+Math.max(-32,Math.min(32,Math.floor((trained[4]*z+512)/1024))));assert.equal(x.table[key],q[0]+128*q[1]);codes.add(x.table[key]);}
  assert.ok(codes.size>50);assert.equal(new Set(parseExpert(control).table).size,1);
  const invalid=Buffer.from(trained);invalid[4]=17;assert.throws(()=>parseExpert(invalid));assert.throws(()=>parseExpert(trained.subarray(0,-1)));
});

test('corrected alphabets fit rANS and keep every byte and escape reachable at maximum support',()=>{
  const x=parseExpert(trained),table=x.table,syms=Uint8Array.from({length:256},(_,i)=>i);const original=new Uint32Array(256).fill(1);original[127]=32000;
  for(const e of [0,32,64])for(const t of [0,32,64]){table.fill(e+128*t);const masses=original.slice(),v=correctVote(x,null,127,4,true,127,true,syms,masses,256,32255,256,127);
    const sum=v&65535,esc=v>>>16;assert.equal(masses.reduce((n,j)=>n+j,0),sum);assert.ok(esc>0 && sum+esc<=32768 && masses.every(z=>z>0));}
});

test('zero strength gives the original entropy trace, while the trained model changes a late frame after identical warm-up',()=>{
  const parts=[noiseBytes(17011),Buffer.alloc(U,text),Buffer.alloc(U,text),Buffer.alloc(78001,text)],n=parts.reduce((s,b)=>s+b.length,0),neutral=Buffer.from(trained);neutral[4]=0;
  const x=parseExpert(trained),z=parseExpert(neutral);assert.ok(z.table.every(v=>v===NEUTRAL));
  const m=frameModel(n,null,x),b=frameModel(n),off=frameModel(n,null,z),dec=frameModel(n,null,x);let changed=false;
  for(const [i,p] of parts.entries()){const base=b.encode(p),wire=m.encode(p);assert.deepEqual(off.encode(p),base);
    if(i===3)changed=!wire.equals(base);if(i===0||i===2)dec.warm(p);else assert.deepEqual(dec.decode(wire,p.length),p);}
  assert.ok(changed);const raw=Buffer.concat(parts),c=config(4096,256,true);assert.deepEqual(packLongRecord(raw,c),packLongRecord(raw,{...c,expert:z}));
});

test('disk identity is independent of workers; missing model catalogs and a lost data frame heal without sidecars',async t=>{
  const f=temp(t),raw=Buffer.alloc(U*4+57,text);for(let i=173;i<raw.length;i+=997)raw[i]=i&255;
  fs.writeFileSync(f('input'),raw);fs.writeFileSync(f('model'),trained);
  for(const jobs of [1,2])await packLong(f('input'),f('r'+jobs),{expertPath:f('model'),predictor:256,jobs});
  const inner=fs.readFileSync(f('r1'));assert.deepEqual(fs.readFileSync(f('r2')),inner);assert.equal(inner.toString('ascii',0,4),'GRL4');fs.unlinkSync(f('model'));fs.unlinkSync(f('input'));
  const s=protectLongExisting(f('r1'),f('protected'),60);assert.equal(s.parityFrames,3);
  const fd=fs.openSync(f('protected'),'r');let scan;try{scan=scanFrames(fd);}finally{fs.closeSync(fd);}
  const parts=globalLayout(scan.catalog,scan.catalogBytes).parts;assert.equal(parts.length,1);const data=scan.entries.get(frameKey(DATA,0)),tail=FRAME+scan.catalogBytes.length;
  cutCopy(f('protected'),f('lost'),[[0,FRAME+parts[0].length],[data.at,FRAME+data.n],[s.protectedBytes-tail,tail]]);
  const recovered=await recoverLongProtected(f('lost'),f('out'),{jobs:2});assert.deepEqual([recovered.catalogPiecesFromParity,recovered.recipeGroupsFromParity,recovered.intactCatalogCopies],[1,1,0]);
  assert.deepEqual(fs.readFileSync(join(f('out'),'recipe.grl')),inner);assert.deepEqual(fs.readFileSync(join(f('out'),'restored.bin')),raw);
  assert.deepEqual(fs.readFileSync(join(f('out'),'protected.grfp')),fs.readFileSync(f('protected')));
  const parity=Array.from({length:3},(_,i)=>{const e=scan.entries.get(frameKey(PARITY,i));return [e.at,FRAME+e.n];});cutCopy(f('protected'),f('cross'),[[data.at,FRAME+data.n],...parity]);
  const old=Buffer.from(raw);old[3*U+55]^=7;fs.writeFileSync(f('old'),old);const r=await recoverLongProtected(f('cross'),f('cross-out'),{damaged:f('old')});
  assert.deepEqual([r.recipeGroupsFromOriginal,r.recipeGroupsFromParity,r.raw.rebuiltPages,r.raw.replayedBytes,r.raw.warmedTapeBytes],[1,0,1,U,0]);assert.deepEqual(fs.readFileSync(join(f('cross-out'),'recipe.grl')),inner);
  const bad=Buffer.from(inner);bad[60]^=128;fs.writeFileSync(f('bad'),bad);await assert.rejects(restoreLong(f('bad'),f('no'),{damaged:join(f('out'),'restored.bin')}),/checksum/);assert.ok(!fs.existsSync(f('no')));
});

test('compiled and JS experts agree on entropy bytes, mixed warm-up and late selective repair', {skip:!process.env.GRL_PREDICTOR_WASM},()=>{
  const x=parseExpert(trained),parts=[noiseBytes(65536),Buffer.alloc(U,text),Buffer.alloc(U,97),Buffer.concat([noiseBytes(8193),text])],n=parts.reduce((s,b)=>s+b.length,0);
  const j=frameModel(n,null,x),w=wasmFrameModel(n,true,null,x),blocks=[];try{for(const p of parts){const b=j.encode(p);assert.deepEqual(w.encode(p),b);blocks.push(b);}}finally{w.close();}
  const r=wasmFrameModel(n,false,null,x);try{parts.forEach((b,i)=>{if(i===0||i===2)r.warm(b);else assert.deepEqual(r.decode(blocks[i],b.length),b);});}finally{r.close();}
  const raw=Buffer.concat(parts),c={...config(4096,256,true,false,true),expert:x},wire=packLongRecord(raw,c),old=Buffer.from(raw);old[2*U+7]^=123;
  const z=restoreLongRecord(wire,n,{...c,backend:'wasm'},old);assert.equal(z.rebuiltPages,1);assert.deepEqual(z.bytes,raw);
});

test('the actual legacy 256/256 control can be parity-charged and restored without changing its inner bytes',async t=>{
  const f=temp(t);fs.writeFileSync(f('in'),Buffer.alloc(U+89,text));await packLong(f('in'),f('old'),{predictor:256,templates:256});
  protectLongExisting(f('old'),f('p'),5);const r=await recoverLongProtected(f('p'),f('out'));assert.equal(r.innerFormat,'GRL1');
  assert.deepEqual(fs.readFileSync(join(f('out'),'recipe.grl')),fs.readFileSync(f('old')));assert.deepEqual(fs.readFileSync(join(f('out'),'restored.bin')),fs.readFileSync(f('in')));
});
