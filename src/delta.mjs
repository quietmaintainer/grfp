// GRD1: independently rebuildable 64 KiB version groups. References name
// spans or numeric line skeletons in ONE immutable, separately stored seed.
import * as fs from 'node:fs';
import { dirname,join,resolve } from 'node:path';
import { deflateRawSync,inflateRawSync } from 'node:zlib';
import { at,atomic,sha } from './long.mjs';
import { hash,u32 } from './long-record.mjs';
import { openSeed,BaseView } from './seed.mjs';

export const DELTA_GROUP=65536;
const MAX_LINE=4096,MIN_COPY=32,MAX_ANCHORS=1<<20,MAX_LINES=32768;
const zip=b=>deflateRawSync(b,{level:6});
function unzip(b,n) {
  const r=inflateRawSync(b,{info:true,maxOutputLength:n});if(r.buffer.length!==n || r.engine.bytesWritten!==b.length)throw Error('Invalid delta deflate stream');return r.buffer;
}
function vint(n) {const a=[];while(n>=128){a.push(128+n%128);n=Math.floor(n/128);}a.push(n);return Buffer.from(a);}
function anchor(b,i) {return (Math.imul(b.readUInt32LE(i),0x9e3779b1)^b.readUInt32LE(i+4)^Math.imul(b.readUInt32LE(i+8),0x85ebca6b)^b.readUInt32LE(i+12))>>>0;}
function skeleton(b) {
  if(b.length<64 || b.length>MAX_LINE)return null;
  const s=b.toString('latin1'),parts=s.split(/[0-9]+/);if(parts.length<4)return null;
  return {parts,key:hash(Buffer.from(parts.join('\u0100'),'utf16le')).readUInt32LE(),digits:s.match(/[0-9]+/g)};
}
function sameShape(a,b) {return b && a.parts.length===b.parts.length && a.parts.every((p,i)=>p===b.parts[i]);}

function buildIndex(seed,fd,numeric) {
  const {view}=seed,anchors=new Map(),lines=new Map(),h=sha();
  const stride=256*Math.max(1,Math.ceil(view.size/(256*MAX_ANCHORS)));
  for(let start=0;start<view.size;start+=view.step) {
    const b=view.block(start/view.step);fs.writeFileSync(fd,b);h.update(b);
    for(let off=Math.ceil(start/stride)*stride;off+16<=start+b.length;off+=stride) anchors.set(anchor(b,off-start),off);
    for(let i=0;numeric && i<b.length && lines.size<MAX_LINES;) {
      const end=b.indexOf(10,i);if(end<0)break;
      if(end+1-i<=MAX_LINE) {const s=skeleton(b.subarray(i,end+1));if(s && !lines.has(s.key))lines.set(s.key,[start+i,end+1-i]);}
      i=end+1;
    }
  }
  if(!h.digest().equals(seed.original))throw Error('Seed original checksum mismatch');
  view.cache.clear();const step=256*1024;
  return {anchors,lines,base:new BaseView(view.size,step,i=>at(fd,i*step,Math.min(step,view.size-i*step)))};
}
const blank=()=>({sameGroups:0,copyBytes:0,templateLines:0,templateBytes:0,literalBytes:0});
function residual(raw,start,index) {
  const {base,lines,anchors}=index,s=blank();
  if(start<=base.size-raw.length && base.slice(start,raw.length).equals(raw)) {s.sameGroups=1;s.copyBytes=raw.length;return {mode:0,body:Buffer.alloc(0),s};}
  const parts=[];let i=0,lit=0,shift=0;
  function flush(){if(i>lit){parts.push(Buffer.of(0),vint(i-lit),raw.subarray(lit,i));s.literalBytes+=i-lit;}}
  while(i<raw.length) {
    if((i===0 || raw[i-1]===10) && lines.size) {
      const end=raw.indexOf(10,i);if(end>=0 && end-i+1<=MAX_LINE) {
        const line=raw.subarray(i,end+1),shape=skeleton(line),entry=shape && lines.get(shape.key);
        if(entry) {const [off,n]=entry,model=base.slice(off,n);
          if(!model.equals(line) && sameShape(shape,skeleton(model))) {
            const op=[Buffer.of(2),vint(off),vint(n)];for(const digits of shape.digits)op.push(vint(digits.length),Buffer.from(digits,'ascii'));
            if(op.reduce((a,b)=>a+b.length,0)<line.length) {flush();parts.push(...op);s.templateLines++;s.templateBytes+=line.length;i=end+1;lit=i;continue;}
          }
        }
      }
    }
    let best=0,from=-1;
    if(raw.length-i>=MIN_COPY) {
      const local=start+i+shift,global=anchors.get(anchor(raw,i));
      for(const off of local===global || global===undefined ? [local] : [local,global]) {
        if(off<0 || off>base.size-MIN_COPY)continue;
        const first=base.slice(off,16);if(first.readUInt32LE()!==raw.readUInt32LE(i) || !first.equals(raw.subarray(i,i+16)))continue;
        const b=base.slice(off,Math.min(raw.length-i,base.size-off));let k=16;
        while(k<b.length && b[k]===raw[i+k])k++;
        if(k>=MIN_COPY && k>best){best=k;from=off;}
        if(k===raw.length-i)break;
      }
    }
    if(best) {flush();parts.push(Buffer.of(1),vint(from),vint(best));s.copyBytes+=best;shift=from-(start+i);i+=best;lit=i;}
    else i++;
  }
  flush();const tape=Buffer.concat(parts),z=zip(raw);let mode=z.length<raw.length?2:1,body=mode===2?z:raw;
  if(tape.length<body.length){mode=3;body=tape;}
  if(s.copyBytes || s.templateLines) {const zt=zip(tape);if(4+zt.length<body.length){mode=4;body=Buffer.concat([u32(tape.length),zt]);}}
  if(mode<3) return {mode,body,s:{...blank(),literalBytes:raw.length}};
  return {mode,body,s};
}
function expand(tape,n,base) {
  let p=0,w=0;const out=Buffer.allocUnsafe(n);
  function integer(){let x=0,scale=1;for(let j=0;j<8 && p<tape.length;j++){const b=tape[p++];x+=(b%128)*scale;if(!Number.isSafeInteger(x))break;
    if(b<128){if(j && !b)break;return x;}scale*=128;}throw Error('Invalid delta integer');}
  function put(b){if(b.length>n-w)throw Error('Delta expansion overflow');b.copy(out,w);w+=b.length;}
  function take(k){if(!k || k>tape.length-p)throw Error('Invalid delta literal');const b=tape.subarray(p,p+k);p+=k;return b;}
  while(p<tape.length){const op=tape[p++];if(op===0)put(take(integer()));
    else if(op===1){const off=integer(),k=integer();if(!k || k>n-w)throw Error('Invalid seed copy length');put(base.slice(off,k));}
    else if(op===2){const off=integer(),len=integer();if(len>MAX_LINE)throw Error('Invalid seed line length');const shape=skeleton(base.slice(off,len));if(!shape)throw Error('Invalid seed line template');
      put(Buffer.from(shape.parts[0],'latin1'));for(const gap of shape.parts.slice(1)){const b=take(integer());for(const x of b)if(x<48 || x>57)throw Error('Invalid template digits');put(b);put(Buffer.from(gap,'latin1'));}}
    else throw Error('Unknown delta instruction');
  }
  if(w!==n)throw Error('Delta group length mismatch');return out;
}

export async function packDelta(seedPath,target,out,{numeric=true}={}) {
  return atomic(out,async dest=>{
    const seed=openSeed(seedPath);let dir,spool,fd;
    try {dir=fs.mkdtempSync(join(dirname(resolve(out)),'.grd-seed-'));spool=fs.openSync(join(dir,'index-input'),'wx+');
      const idx=buildIndex(seed,spool,numeric);fd=fs.openSync(target,'r');const st=fs.fstatSync(fd);if(!st.isFile() || !Number.isSafeInteger(st.size))throw Error('Invalid target');
      const n=st.size,h=Buffer.alloc(44),wire=sha(),output=sha(),s=blank(),write=b=>{fs.writeFileSync(dest,b);wire.update(b);};
      h.write('GRD1');h.writeBigUInt64LE(BigInt(n),4);seed.id.copy(h,12);write(h);
      for(let off=0;off<n;off+=DELTA_GROUP){const raw=at(fd,off,Math.min(DELTA_GROUP,n-off)),r=residual(raw,off,idx);output.update(raw);
        write(hash(raw).subarray(0,16));write(Buffer.of(r.mode));write(u32(r.body.length));write(r.body);for(const k of Object.keys(s))s[k]+=r.s[k];}
      if(fs.fstatSync(fd).size!==n)throw Error('Version size changed');const digest=output.digest();write(digest);fs.writeFileSync(dest,wire.digest());
      return {...s,targetBytes:n,deltaBytes:fs.fstatSync(dest).size,seedId:seed.id.toString('hex'),targetSha256:digest.toString('hex')};
    }finally{if(fd!==undefined)fs.closeSync(fd);if(spool!==undefined)fs.closeSync(spool);if(dir)fs.rmSync(dir,{recursive:true,force:true});seed.close();}
  });
}

export async function restoreDelta(seedPath,path,out,{damaged}={}) {
  return atomic(out,async dest=>{const seed=openSeed(seedPath);let fd,old;
    try {fd=fs.openSync(path,'r');if(damaged!==undefined)old=fs.openSync(damaged,'r');
      const h=at(fd,0,44),size=Number(h.readBigUInt64LE(4));if(!h.subarray(0,4).equals(Buffer.from('GRD1')) || !Number.isSafeInteger(size) || !h.subarray(12).equals(seed.id))throw Error('Delta header or shared seed identity mismatch');
      const s={reusedGroups:0,rebuiltGroups:0,replayedTargetBytes:0},wire=sha().update(h),original=sha();let pos=44;
      for(let off=0;off<size;off+=DELTA_GROUP){const n=Math.min(DELTA_GROUP,size-off),head=at(fd,pos,21),expected=head.subarray(0,16),mode=head[16],len=head.readUInt32LE(17);pos+=21;
        if(mode>4 || len>n || (mode===0 && (len || off>seed.view.size-n)) || (mode===1 && len!==n) || (mode>0 && !len) || (mode===4 && len<5))throw Error('Invalid delta group header');
        const body=at(fd,pos,len);pos+=len;wire.update(head).update(body);let b=old===undefined?undefined:at(old,off,n,false);
        if(b?.length===n && hash(b).subarray(0,16).equals(expected))s.reusedGroups++;
        else {s.rebuiltGroups++;s.replayedTargetBytes+=n;
          if(!mode)b=seed.view.slice(off,n);else if(mode===1)b=body;else if(mode===2)b=unzip(body,n);
          else {let tape=body;if(mode===4){const k=body.readUInt32LE();if(!k || k>3*n+32)throw Error('Invalid delta instruction length');tape=unzip(body.subarray(4),k);}b=expand(tape,n,seed.view);}
          if(!hash(b).subarray(0,16).equals(expected))throw Error('Rebuilt version group mismatch');
        }fs.writeFileSync(dest,b);original.update(b);
      }
      const digest=at(fd,pos,32);wire.update(digest);if(pos+64!==fs.fstatSync(fd).size || !wire.digest().equals(at(fd,pos+32,32)) || !original.digest().equals(digest))throw Error('Version footer or content mismatch');
      return {...s,seedCheckpointsDecoded:seed.view.loads,seedBytesDecoded:seed.view.loadedBytes,targetBytes:size,targetSha256:digest.toString('hex')};
    }finally{if(fd!==undefined)fs.closeSync(fd);if(old!==undefined)fs.closeSync(old);seed.close();}
  });
}
