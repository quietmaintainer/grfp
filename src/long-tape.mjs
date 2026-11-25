import { createHash } from 'node:crypto';
import { PAGE,likelyText } from './codec.mjs';
import { templateTape,expandTape } from './templates.mjs';
import { bindTitles,expandTitles } from './titles.mjs';

export const hash=b=>createHash('sha256').update(b).digest();
export const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;};
export function pageHashes(raw) {
  const h=Buffer.alloc(16*Math.ceil(raw.length/PAGE));
  for(let i=0;i<raw.length;i+=PAGE)hash(raw.subarray(i,i+PAGE)).copy(h,(i/PAGE)*16,0,16);
  return h;
}
export const asText=b=>{for(let i=0;i<b.length;i+=PAGE)if(likelyText(b.subarray(i,i+PAGE)))return true;return false;};

export function selectedTape(raw,kind) {
  if(!kind)return {kind,bound:raw.length,bytes:raw};
  const b=kind===2?bindTitles(raw)?.bytes:raw;
  if(!b)return null;
  const t=templateTape(b,kind===1?'slots':'title');return t?{kind,bound:b.length,bytes:t.bytes}:null;
}
export function transform(raw) {
  let best=selectedTape(raw,0);if(!asText(raw))return best;
  for(const kind of [1,2]){const t=selectedTape(raw,kind);if(t && t.bytes.length<best.bytes.length)best=t;}
  return best;
}
export function expandSelected(tape,{kind,bound,length}) {
  const b=kind?expandTape(tape,kind===1?'slots':'title',bound,21):tape;
  return kind===2?expandTitles(b,length):b;
}
