// Optional local accelerator. Archives select a codec, never a module or path.
import { readFileSync } from 'node:fs';
let module,pool;
export function wasmFrameModel(length,encoding,prior,expert) {
  if(!process.env.GRL_PREDICTOR_WASM)throw Error('Set GRL_PREDICTOR_WASM to the locally built predictor module');
  module??=new WebAssembly.Module(readFileSync(process.env.GRL_PREDICTOR_WASM));
  const api=pool ?? new WebAssembly.Instance(module,{}).exports;pool=null;
  if(expert?.strength && !api.begin_expert)throw Error('Rebuild the local WASM module for GXE1 support');
  const history=expert?.strength?api.begin_expert(length,Number(encoding)):api.begin(length,Number(encoding));let pos=0,closed=false;
  if(expert?.strength){const at=api.expert_address();if(new Uint8Array(Uint16Array.of(1).buffer)[0]===1)new Uint16Array(api.memory.buffer,at,expert.table.length).set(expert.table);
    else {const dv=new DataView(api.memory.buffer);expert.table.forEach((q,i)=>dv.setUint16(at+2*i,q,true));}}
  function check(n){if(closed||!Number.isInteger(n)||n<1||n>262144||n>length-pos)throw Error('Invalid Wasm predictor frame');}
  const view=(ptr,n)=>new Uint8Array(api.memory.buffer,ptr,n);
  if(prior?.count){if(!api.install_prior)throw Error('Rebuild the local WASM module for GPM1 support');
    view(api.prior_address(),4*prior.count).set(prior.wire.subarray(6));api.install_prior(prior.count);}
  return {encode(b){check(b.length);if(!encoding)throw Error('Wrong Wasm model mode');view(history+pos,b.length).set(b);
      const ptr=api.encode(b.length);pos+=b.length;return Buffer.from(view(ptr,api.body_size()));},
    warm(b){check(b.length);view(history+pos,b.length).set(b);api.warm(b.length);pos+=b.length;},
    decode(body,n){check(n);if(encoding||body.length<4||body.length>api.io_capacity())throw Error('Invalid Wasm text recipe');
      view(api.io_address(),body.length).set(body);api.decode(n,body.length);const b=Buffer.from(view(history+pos,n));pos+=n;return b;},
    close(){if(!closed){pool=api;closed=true;}}};
}
