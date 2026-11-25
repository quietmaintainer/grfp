// GXE1: a frozen residual MLP, consulted at every nonempty PPM decision.
// Two log2 odds offsets reweight ESC and the most probable candidate relative
// to all other bytes. It never writes into the adaptive trie or span model.
export const DIMS=[5,5,8,4,4,8,8,2], H=16, INPUTS=DIMS.reduce((s,n)=>s+n,0);
export const CELLS=DIMS.reduce((s,n)=>s*n,1), PARAM8=H*(1+INPUTS+2), EXPERT_BYTES=5+PARAM8+4;
export const GAINS=Uint16Array.of(64,67,70,73,76,79,83,87,91,95,99,103,108,112,117,123,128,134,140,146,152,159,166,173,181,189,197,206,215,225,235,245,256,267,279,292,304,318,332,347,362,378,395,412,431,450,470,490,512,535,558,583,609,636,664,693,724,756,790,825,861,899,939,981,1024);
export const NEUTRAL=32+128*32;
const classes=Uint8Array.from({length:256},(_,b)=>b>=97&&b<=122?0:b>=65&&b<=90?1:b>=48&&b<=57?2:b===32||b===9?3:b===10||b===13?4:'<>[]{}|&;/="\''.includes(String.fromCharCode(b))?5:b<128?6:7);

export function categories(key,out) {
  for(let j=DIMS.length-1;j>=0;j--){out[j]=key%DIMS[j];key=Math.floor(key/DIMS[j]);}return out;
}
export const weightOffset=(row,h)=>H+row*H+h;
export const headOffset=(head,h)=>H*(1+INPUTS+head)+h;

// Shared lookup is a deterministic expansion of the 761 stored bytes, not
// extra trained data. Only integer operations and the fixed gain table are
// used in inference, including table construction. No model code in files.
export function parseExpert(input) {
  const b=Buffer.from(input.buffer,input.byteOffset,input.byteLength);
  if(b.length!==EXPERT_BYTES || b.toString('latin1',0,4)!=='GXE1' || b[4]>16)throw Error('Invalid GXE1 expert');
  const wire=new Uint8Array(new SharedArrayBuffer(b.length));wire.set(b);
  const strength=b[4],table=new Uint16Array(new SharedArrayBuffer(2*CELLS));
  if(!strength){table.fill(NEUTRAL);return {wire,table,strength};}
  const w=new Int8Array(wire.buffer,5,PARAM8),bias=[b.readInt16LE(5+PARAM8),b.readInt16LE(7+PARAM8)];
  const acc=Array.from({length:DIMS.length+1},()=>new Int16Array(H));acc[0].set(w.subarray(0,H));
  function visit(layer,base,key) {
    if(layer===DIMS.length){let e=bias[0],t=bias[1];for(let h=0;h<H;h++){const v=Math.max(0,Math.min(128,acc[layer][h]));e+=v*w[headOffset(0,h)];t+=v*w[headOffset(1,h)];}
      const q=v=>32+Math.max(-32,Math.min(32,Math.floor((v*strength+512)/1024)));table[key]=q(e)+128*q(t);return;}
    for(let v=0;v<DIMS[layer];v++){const start=weightOffset(base+v,0);for(let h=0;h<H;h++)acc[layer+1][h]=acc[layer][h]+w[start+h];
      visit(layer+1,base+DIMS[layer],key*DIMS[layer]+v);}
  }visit(0,0,0);return {wire,table,strength};
}

// Return (escape << 16) + symbol sum. Tags are computed only from bytes the
// decoder already knows and pre-correction PPM/span probabilities.
export function correctVote(expert,observe,prev,k,back,offered,boosted,syms,masses,n,sum,esc,value) {
  let top=0;for(let j=1;j<n;j++)if(masses[j]>masses[top])top=j;
  const m=masses[top],alternatives=n===1?0:n===2?1:n<=4?2:n<=16?3:4;
  const support=Math.min(7,31-Math.clz32(Math.floor(sum/esc))),dom=Math.min(3,Math.floor(4*m/sum));
  const span=offered<0?0:!boosted?1:offered===syms[top]?2:3;
  const shape=(((k*5+alternatives)*8+support)*4+dom)*4+span;
  const key=((shape*8+classes[prev])*8+classes[syms[top]])*2+Number(back);
  if(observe){let y=0; // 0 escape, 1 top, 2 another observed symbol
    if(value===syms[top])y=1;else for(let j=0;j<n;j++)if(syms[j]===value){y=2;break;}
    observe(key,sum,esc,m,y);}
  const q=expert?.table[key]??NEUTRAL;if(q===NEUTRAL)return esc*65536+sum;
  const ge=GAINS[q&127],gt=GAINS[q>>>7],raw=(sum-m)*256+m*gt+esc*ge;
  let shift=Math.max(0,17-Math.clz32(raw-1)); // ceil(log2(raw)) - 15
  if((raw>>>shift)>32768-n-1)shift++;
  let s=0;for(let j=0;j<n;j++){const v=Math.max(1,(masses[j]*(j===top?gt:256))>>>shift);masses[j]=v;s+=v;}
  const e=Math.max(1,(esc*ge)>>>shift);return e*65536+s;
}
