import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { check16,encode16,decode16,even16 } from '../src/rs16.mjs';
import { GROUP } from '../src/groups.mjs';
import { sha,FRAME,DATA,PARITY,GLOBAL_DATA,GLOBAL_PARITY,scanFrames,frameKey,globalLayout,frameHeader,coord } from '../src/frames.mjs';
import { packProtected,recoverProtected,reprotect } from '../src/protected.mjs';
import { cutCopy } from './loss-fixtures.mjs';

const dirFor=t=>{const dir=fs.mkdtempSync(join(tmpdir(),'grfp16-test-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return name=>join(dir,name);};
const scan=p=>{const fd=fs.openSync(p,'r');try{return scanFrames(fd);}finally{fs.closeSync(fd);}};
const range=e=>[e.at,FRAME+e.n];
// Independent carry-less polynomial arithmetic (no log tables or Cauchy decoder).
function times(x,y) {let z=0;while(y){if(y&1)z^=x;y>>>=1;x<<=1;if(x&65536)x^=0x1100b;}return z;}
function reciprocal(x){let z=1;for(let e=65534;e;e>>>=1){if(e&1)z=times(z,x);x=times(x,x);}return z;}

test('16-bit parity matches a polynomial oracle above coordinate 255 including odd, unaligned little-endian data',()=>{
  const d=318,src=Array.from({length:d},(_,i)=>Buffer.from([0,i>>8,i&255,197,i&127,11]).subarray(1,(i%5)+2)),par=[];
  encode16(d,5,6,i=>src[i],(p,b)=>par[p]=b);
  for(let p=0;p<5;p++)for(let j=0;j<3;j++){
    const expected=src.reduce((a,b,i)=>a^times(reciprocal((d+p)^i),(b[j*2]??0)|((b[j*2+1]??0)<<8)),0);
    assert.equal(par[p].readUInt16LE(2*j),expected);
  }
  const lost=[0,255,256,317];decode16({d,missing:lost,rows:[4,2,0,1],width:6,length:i=>src[i].length,
    load:i=>{assert.ok(!lost.includes(i));return src[i];},parity:j=>par[j],save:(i,b)=>assert.deepEqual(b,src[i])});
  check16(65534,1);check16(65535,0);assert.throws(()=>check16(65535,1),/65,535/);
  assert.equal(coord(65535,65534),4294967294);
});

test('every loss pattern up to the physical-frame budget restores source and protected archive, including metadata',t=>{
  const f=dirFor(t),raw=Buffer.alloc(GROUP+17,89);raw[GROUP-1]=250;fs.writeFileSync(f('in'),raw);
  const s=packProtected(f('in'),f('wrapped'),undefined,{text:'off',fec:'global16',parityPercent:100});fs.unlinkSync(f('in'));
  const bytes=fs.readFileSync(f('wrapped')),a=scan(f('wrapped')),layout=globalLayout(a.catalog,a.catalogBytes);
  const frames=[[0,FRAME+layout.parts[0].length],...Array.from({length:2},(_,i)=>range(a.entries.get(frameKey(DATA,i)))),
    ...Array.from({length:2},(_,i)=>range(a.entries.get(frameKey(PARITY,i)))),[bytes.length-FRAME-a.catalogBytes.length,FRAME+a.catalogBytes.length]];
  assert.equal(layout.r,2);assert.equal(s.parityFrames,2);
  for(let mask=0;mask<2**frames.length;mask++) {
    const losses=frames.filter((_,i)=>(mask>>i)&1);if(losses.length>2)continue;
    cutCopy(f('wrapped'),f('bad'),losses);const r=recoverProtected(f('bad'),f('out'));
    assert.deepEqual(fs.readFileSync(f('out/restored.bin')),raw);assert.deepEqual(fs.readFileSync(f('out/protected.grfp')),bytes);
    assert.equal(r.recipeGroupsFromOriginal,0);if(mask===33)assert.equal(r.catalogPiecesFromParity,1);
    fs.unlinkSync(f('bad'));fs.rmSync(f('out'),{recursive:true});
  }
});

test('recovers multiple missing 64 KiB catalog shards without the tail copy',t=>{
  const f=dirFor(t),k=530,hash=b=>sha().update(b).digest('hex'),groups=Array.from({length:k},(_,i)=>Buffer.from([i&255,i>>8,i%5]));
  // Scanner-only fixture: valid framed/cataloged payloads, not GRF1 instructions.
  const m={format:'GRP1',encoder:'grf1-group-v1',stripe:'global16',percent:1,bytes:k*GROUP,originalSha256:'0'.repeat(64),grfFooter:'1'.repeat(64),
    profile:{width:null,text:'off',templates:'off',textWindow:'16'},groups:groups.map(b=>[b.length,hash(b),hash(b)])};
  const meta=Buffer.from(JSON.stringify(m)),{parts,d,r,width}=globalLayout(m,meta),data=[...parts,...groups],id=sha().update(meta).digest(),kept=[];
  assert.equal(parts.length,2);assert.equal(r,6);
  const frame=(kind,i,b)=>kept.push(frameHeader(kind,coord(d,i),id,b),b);
  data.forEach((b,i)=>{if(i!==0 && i!==1 && i!==300)frame(GLOBAL_DATA,i,b);});
  encode16(d,r,width,i=>data[i],(p,b)=>{if(p!==1)frame(GLOBAL_PARITY,p,b);});
  fs.writeFileSync(f('partial'),Buffer.concat(kept));const got=scan(f('partial'));
  assert.equal(got.metaCopies,0);assert.equal(got.catalogFromParity,2);assert.deepEqual(got.catalogBytes,meta);assert.deepEqual(got.catalog,m);
});

test('global over-budget loss fails closed, then one matching source group makes it recoverable; old layout is reproducible',t=>{
  const f=dirFor(t),raw=Buffer.alloc(2*GROUP+319,67);raw[117]=32;raw[GROUP+25]=137;fs.writeFileSync(f('raw'),raw);
  const options={text:'off',parityPercent:30};packProtected(f('raw'),f('local'),73,options);const s=reprotect(f('local'),f('global'));
  assert.equal(s.parityFrames,1);const a=scan(f('global'));cutCopy(f('global'),f('bad'),[0,1].map(i=>range(a.entries.get(frameKey(DATA,i)))));
  assert.throws(()=>recoverProtected(f('bad'),f('no')),/2 recipe groups still missing, only 1/);assert.ok(!fs.existsSync(f('no')));
  const old=Buffer.from(raw);old[44]^=1;old[2*GROUP]^=16;fs.writeFileSync(f('survivor'),old);
  const fixed=recoverProtected(f('bad'),f('yes'),{damaged:f('survivor')});
  assert.deepEqual([fixed.recipeGroupsFromOriginal,fixed.recipeGroupsFromParity,fixed.rebuiltOriginalPages],[1,1,2]);
  assert.deepEqual(fs.readFileSync(f('yes/restored.bin')),raw);assert.deepEqual(fs.readFileSync(f('yes/protected.grfp')),fs.readFileSync(f('global')));
  reprotect(f('yes/protected.grfp'),f('back'),{fec:'local8'});assert.deepEqual(fs.readFileSync(f('back')),fs.readFileSync(f('local')));
  assert.throws(()=>reprotect(f('bad'),f('wrong')),/Missing group/);assert.ok(!fs.existsSync(f('wrong')));
});

test('a stale but locally checksummed GF16 parity row cannot publish a falsely recovered group',t=>{
  const f=dirFor(t);fs.writeFileSync(f('src'),Buffer.alloc(8193,55));packProtected(f('src'),f('arc'),undefined,{parityPercent:5,fec:'global16'});
  const a=scan(f('arc')),bytes=fs.readFileSync(f('arc')),e=a.entries.get(frameKey(PARITY,0)),p=bytes.subarray(e.at+FRAME,e.at+FRAME+e.n);
  p[0]^=16;const id=sha().update(a.catalogBytes).digest();frameHeader(GLOBAL_PARITY,e.index,id,p).copy(bytes,e.at);
  fs.writeFileSync(f('stale'),bytes);cutCopy(f('stale'),f('bad'),[range(a.entries.get(frameKey(DATA,0)))]);
  assert.throws(()=>recoverProtected(f('bad'),f('out')),/checksum mismatch/);assert.ok(!fs.existsSync(f('out')));
});

test('empty protected global archive and odd singleton work with zero parity and either catalog copy',t=>{
  const f=dirFor(t);for(const [i,raw] of [Buffer.alloc(0),Buffer.of(17)].entries()) {
    fs.writeFileSync(f('raw'),raw);const arc=f('arc'+i);packProtected(f('raw'),arc,undefined,{parityPercent:0,fec:'global16'});
    const a=scan(arc),size=fs.statSync(arc).size,layout=globalLayout(a.catalog,a.catalogBytes);assert.equal(layout.width,even16(layout.width));
    for(const [j,loss] of [[0,FRAME+layout.parts[0].length],[size-FRAME-a.catalogBytes.length,FRAME+a.catalogBytes.length]].entries()) {
      const bad=f(`bad${i}${j}`),out=f(`out${i}${j}`);cutCopy(arc,bad,[loss]);recoverProtected(bad,out);
      assert.deepEqual(fs.readFileSync(join(out,'restored.bin')),raw);assert.deepEqual(fs.readFileSync(join(out,'protected.grfp')),fs.readFileSync(arc));
    }
  }
});
