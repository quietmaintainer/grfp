// GRL2: one continuous adaptive model per 4 MiB of ORIGINAL input. One
// independently terminated entropy stream per 256 KiB original template unit.
import { deflateRawSync,inflateRawSync } from 'node:zlib';
import { PAGE } from './codec.mjs';
import { frameModel,TAPE_WINDOW as UNIT } from './text.mjs';
import { hash,u32,asText,pageHashes,transform,selectedTape,expandSelected } from './long-tape.mjs';
import { wasmFrameModel } from './wasm-model.mjs';
const model=(n,c,enc)=>c.backend==='wasm'?wasmFrameModel(n,enc,c.prior,c.expert):frameModel(n,c.prior,c.expert);
export const restartStats=()=>({warmedOriginalBytes:0,warmedTapeBytes:0,fallbackWarmBytes:0,entropyDecodedBytes:0,entropyFrames:0,
  retapedFrames:0,expandedTemplateFrames:0,warmModelMs:0,retapeMs:0,entropyDecodeMs:0,expandTemplateMs:0});

export function packRestartRecord(raw,c) {
  const output=[pageHashes(raw)],frames=[];let total=0;
  for(let off=0;off<raw.length;off+=UNIT){const v=transform(raw.subarray(off,off+UNIT));frames.push(v.bytes);
    output.push(Buffer.of(v.kind),u32(v.bound),u32(v.bytes.length));total+=v.bytes.length;}
  const m=frames.some(asText)?model(total,c,true):null;
  try {for(const b of frames){let mode=0,body=b;const zip=deflateRawSync(b,{level:6});if(zip.length<body.length){body=zip;mode=1;}
    if(m){const text=m.encode(b);if(text.length<body.length){body=text;mode=2;}}
    output.push(Buffer.of(mode),u32(body.length),body);
  }return Buffer.concat(output);}finally{m?.close();}
}

export function restoreRestartRecord(wire,n,c,old) {
  let pos=0;function take(k){if(k>wire.length-pos)throw Error('Truncated restart record');const b=wire.subarray(pos,pos+k);pos+=k;return b;}
  const pages=Math.ceil(n/PAGE),hashes=take(16*pages),ok=[],frames=[];let total=0,lastText=-1;
  for(let i=0;i<pages;i++){const off=i*PAGE,k=Math.min(n-off,PAGE),b=old?.subarray(off,off+k);ok.push(b?.length===k && hash(b).subarray(0,16).equals(hashes.subarray(16*i,16*i+16)));}
  for(let off=0;off<n;off+=UNIT){const length=Math.min(n-off,UNIT),kind=take(1)[0],bound=take(4).readUInt32LE(),size=take(4).readUInt32LE();
    if(kind>2||!size||size>length||!bound||bound>2*length||(kind!==2&&bound!==length)||(!kind&&size!==length))throw Error('Invalid restart template descriptor');
    frames.push({off,length,kind,bound,size,bad:!ok.slice(off/PAGE,Math.ceil((off+length)/PAGE)).every(Boolean)});total+=size;
  }
  for(const [i,f] of frames.entries()){f.mode=take(1)[0];const k=take(4).readUInt32LE();
    if(f.mode>2||!k||k>f.size||(!f.mode&&k!==f.size)||(f.mode===2&&k<4))throw Error('Invalid entropy restart frame');
    f.body=take(k);if(f.mode===2 && f.bad)lastText=i;
  }
  if(pos!==wire.length)throw Error('Trailing restart record bytes');
  const reusedPages=ok.filter(Boolean).length,s={reusedPages,rebuiltPages:pages-reusedPages,replayedBytes:0,decodedTapeBytes:0,...restartStats()};
  if(!s.rebuiltPages)return {...s,bytes:old};
  const out=Buffer.allocUnsafe(n),m=lastText>=0?model(total,c,false):null;
  try {for(const [i,f] of frames.entries()) {
    const survivor=old?.subarray(f.off,f.off+f.length);let tape;
    if(!f.bad){survivor.copy(out,f.off);
      if(i>=lastText)continue; // healthy suffix: no predictor work at all
      if(f.kind){const start=performance.now(),v=selectedTape(survivor,f.kind);s.retapeMs+=performance.now()-start;s.retapedFrames++;
        if(!v || v.bound!==f.bound || v.bytes.length!==f.size)throw Error('Verified survivor did not reproduce canonical template tape');tape=v.bytes;}
      else tape=survivor;
      const start=performance.now();m.warm(tape);s.warmModelMs+=performance.now()-start;s.warmedOriginalBytes+=f.length;s.warmedTapeBytes+=f.size;continue;
    }
    if(f.mode===2){const start=performance.now();tape=m.decode(f.body,f.size);s.entropyDecodeMs+=performance.now()-start;s.entropyFrames++;s.entropyDecodedBytes+=f.size;}
    else {if(!f.mode)tape=f.body;else {const r=inflateRawSync(f.body,{info:true,maxOutputLength:f.size});
        if(r.buffer.length!==f.size||r.engine.bytesWritten!==f.body.length)throw Error('Invalid restart DEFLATE stream');tape=r.buffer;}
      if(i<lastText){const start=performance.now();m.warm(tape);s.warmModelMs+=performance.now()-start;s.fallbackWarmBytes+=f.size;}}
    const start=performance.now(),raw=expandSelected(tape,f);if(f.kind){s.expandedTemplateFrames++;s.expandTemplateMs+=performance.now()-start;}
    if(raw.length!==f.length)throw Error('Invalid expanded restart frame');
    s.replayedBytes+=f.length;s.decodedTapeBytes+=f.size;
    for(let j=0;j<f.length;j+=PAGE){const i=(f.off+j)/PAGE,end=Math.min(j+PAGE,f.length),b=raw.subarray(j,end);
      if(ok[i])survivor.copy(out,f.off+j,j,end);else {if(!hash(b).subarray(0,16).equals(hashes.subarray(i*16,i*16+16)))throw Error('Restart frame content mismatch');b.copy(out,f.off+j);}}
  }return {...s,bytes:out};}finally{m?.close();}
}
