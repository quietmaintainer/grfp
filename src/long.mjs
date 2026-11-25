import * as fs from 'node:fs';
import { dirname,join,resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { config,windowsKiB,maxWire,packLongRecord,restoreLongRecord,u32 } from './long-record.mjs';
import { restartStats } from './restart-record.mjs';
import { parsePrior,MAX_PRIOR } from './prior.mjs';
import { parseExpert,EXPERT_BYTES } from './expert.mjs';
import { PAGE } from './codec.mjs';

export const sha=()=>createHash('sha256');
export function at(fd,pos,n,strict=true) {
  const b=Buffer.allocUnsafe(n);let i=0;
  while(i<n) {const got=fs.readSync(fd,b,i,n-i,pos+i);if(!got)break;i+=got;}
  if(strict && i!==n) throw Error('Truncated input');return b.subarray(0,i);
}
export async function atomic(path,fn) {
  if(fs.existsSync(path)) throw Error(`Output already exists: ${path}`);
  const tmp=fs.mkdtempSync(join(dirname(resolve(path)),'.grl-')),p=join(tmp,'output');
  try {const fd=fs.openSync(p,'wx');let result;
    try {result=await fn(fd);}finally{fs.closeSync(fd);}
    try {fs.linkSync(p,path);}catch(e){if(!['EPERM','ENOTSUP','ENOSYS','EOPNOTSUPP'].includes(e.code))throw e;fs.copyFileSync(p,path,fs.constants.COPYFILE_EXCL);}
    return result;
  } finally {fs.rmSync(tmp,{recursive:true,force:true});}
}
export const header=(size,c)=>{const h=Buffer.alloc(14);h.write(c.continuous?'GRL4':c.seeded?'GRL3':c.restart?'GRL2':'GRL1');h.writeBigUInt64LE(BigInt(size),4);h[12]=windowsKiB.indexOf(c.p);h[13]=windowsKiB.indexOf(c.t);
  if(!c.seeded&&!c.continuous)return h;const b=(c.expert??c.prior).wire;return Buffer.concat([h,u32(b.length),sha().update(b).digest(),b]);};
export function parseLongHeader(h) {
  if(h.length<14)throw Error('Truncated GRL header');const size=Number(h.readBigUInt64LE(4));
  const magic=h.toString('latin1',0,4);
  if(!['GRL1','GRL2','GRL3','GRL4'].includes(magic) || !Number.isSafeInteger(size) || h[12]>=3 || h[13]>=3) throw Error('Invalid GRL header');
  const c=config(windowsKiB[h[12]],windowsKiB[h[13]],magic!=='GRL1',magic==='GRL3',magic==='GRL4');
  if(c.seeded||c.continuous){if(h.length<50 || h.length>50+MAX_PRIOR || h.readUInt32LE(14)!==h.length-50 || !sha().update(h.subarray(50)).digest().equals(h.subarray(18,50)))throw Error('Embedded prior checksum or length mismatch');
    if(c.continuous)c.expert=parseExpert(h.subarray(50));else c.prior=parsePrior(h.subarray(50));}
  else if(h.length!==14)throw Error('Unexpected long header bytes');return {h,size,c};
}
export function readLongHeader(fd) {
  const h=at(fd,0,14),magic=h.toString('latin1',0,4);if(magic!=='GRL3' && magic!=='GRL4')return parseLongHeader(h);
  const n=at(fd,14,4).readUInt32LE();if(n<6 || n>MAX_PRIOR || (magic==='GRL4' && n!==EXPERT_BYTES))throw Error('Invalid embedded model length');return parseLongHeader(at(fd,0,50+n));
}
export function readLongFrame(fd,pos,n,c) {
  const prefix=at(fd,pos,4),k=prefix.readUInt32LE();if(!k || k>maxWire(n,c)) throw Error('Invalid GRL frame length');
  return {prefix,bytes:at(fd,pos+4,k)};
}

async function batches(count,jobs,c,input,emit) {
  if(!Number.isInteger(jobs) || jobs<1 || jobs>12) throw Error('Jobs must be 1..12');
  const pool=[];
  try {
    if(jobs>1) for(let i=0;i<Math.min(jobs,count);i++)pool.push(new Worker(new URL('./long-worker.mjs',import.meta.url),{execArgv:[],workerData:c}));
    for(let first=0;first<count;first+=jobs) {
      const tasks=Array.from({length:Math.min(jobs,count-first)},(_,j)=>input(first+j));
      if(!pool.length) {const {mode,bytes,n,old}=tasks[0];emit(mode==='pack'?{bytes:packLongRecord(bytes,c)}:restoreLongRecord(bytes,n,c,old));continue;}
      const results=await Promise.all(tasks.map((task,j)=>new Promise((yes,no)=>{
        const worker=pool[j],cleanup=()=>{worker.off('error',error);worker.off('exit',exit);worker.off('message',msg);};
        const error=e=>{cleanup();no(e);},exit=k=>error(Error(`GRL worker exited ${k}`)),msg=r=>{cleanup();r.error?no(Error(r.error)):yes({...r,bytes:Buffer.from(r.bytes.buffer,r.bytes.byteOffset,r.bytes.byteLength)});};
        worker.once('message',msg);worker.once('error',error);worker.once('exit',exit);worker.postMessage(task);
      })));
      for(const r of results) emit(r);
    }
  } finally {await Promise.all(pool.map(w=>w.terminate()));}
}
function backendOf(backend,c){if(!['js','wasm'].includes(backend) || (backend==='wasm' && !c.restart))throw Error('Expected js, or wasm for restartable GRL');return backend;}
export async function packLong(path,out,{modelPath,expertPath,restart=modelPath!==undefined||expertPath!==undefined,predictor=restart?4096:1024,templates=256,jobs=1,backend='js',onCheckpoint}={}) {
  const c=config(predictor,templates,restart,modelPath!==undefined,expertPath!==undefined);c.backend=backendOf(backend,c);
  if(c.seeded){if(fs.statSync(modelPath).size>MAX_PRIOR)throw Error('Oversized GPM1 model');c.prior=parsePrior(fs.readFileSync(modelPath));}
  if(c.continuous){if(fs.statSync(expertPath).size!==EXPERT_BYTES)throw Error('Invalid GXE1 model size');c.expert=parseExpert(fs.readFileSync(expertPath));}
  return atomic(out,async dest=>{
    const fd=fs.openSync(path,'r');try {
      const stat=fs.fstatSync(fd),size=stat.size;if(!stat.isFile() || !Number.isSafeInteger(size)) throw Error('Expected a regular input');
      const archive=sha(),source=sha(),write=b=>{fs.writeFileSync(dest,b);archive.update(b);};write(header(size,c));
      const pending=[];await batches(Math.ceil(size/c.checkpoint),jobs,c,i=>{const pos=i*c.checkpoint,n=Math.min(c.checkpoint,size-pos),bytes=at(fd,pos,n);source.update(bytes);if(onCheckpoint)pending.push(n);return {mode:'pack',bytes,n};},r=>{const prefix=u32(r.bytes.length);write(prefix);write(r.bytes);
        if(onCheckpoint){const n=pending.shift();onCheckpoint([4+r.bytes.length,sha().update(r.bytes.subarray(0,16*Math.ceil(n/PAGE))).digest('hex'),sha().update(prefix).update(r.bytes).digest('hex')]);}});
      if(fs.fstatSync(fd).size!==size)throw Error('Input size changed');
      const digest=source.digest();write(digest);fs.writeFileSync(dest,archive.digest());
      return {originalBytes:size,archiveBytes:fs.fstatSync(dest).size,originalSha256:digest.toString('hex'),predictorKiB:c.p,templateKiB:c.t,...(restart&&{entropyRestartOriginalKiB:256,backend}),...(c.prior&&{priorBytes:c.prior.wire.length,priorNodes:c.prior.count}),...(c.expert&&{expertBytes:c.expert.wire.length,strength:c.expert.strength})};
    }finally{fs.closeSync(fd);}
  });
}
export async function restoreLong(path,out,{damaged,jobs=1,backend='js'}={}) {
  return atomic(out,async dest=>{const fd=fs.openSync(path,'r');let oldFd;
    try {if(damaged!==undefined)oldFd=fs.openSync(damaged,'r');
      const {h,size,c}=readLongHeader(fd),wire=sha().update(h),source=sha();let pos=h.length;
      c.backend=backendOf(backend,c);const s={reusedPages:0,rebuiltPages:0,replayedBytes:0,decodedTapeBytes:0,...(c.restart&&restartStats())};
      await batches(Math.ceil(size/c.checkpoint),jobs,c,i=>{
        const off=i*c.checkpoint,n=Math.min(c.checkpoint,size-off),{prefix,bytes}=readLongFrame(fd,pos,n,c);pos+=4+bytes.length;wire.update(prefix).update(bytes);
        return {mode:'restore',n,bytes,old:oldFd===undefined?undefined:at(oldFd,off,n,false)};
      },r=>{fs.writeFileSync(dest,r.bytes);source.update(r.bytes);for(const key of Object.keys(s))s[key]+=r[key];});
      const digest=at(fd,pos,32);wire.update(digest);
      if(pos+64!==fs.fstatSync(fd).size || !source.digest().equals(digest) || !wire.digest().equals(at(fd,pos+32,32)))throw Error('GRL footer or content mismatch');
      return {...s,originalBytes:size,originalSha256:digest.toString('hex')};
    }finally{if(oldFd!==undefined)fs.closeSync(oldFd);fs.closeSync(fd);}
  });
}
