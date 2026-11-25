#!/usr/bin/env node
import { packLong,restoreLong } from './long.mjs';
const usage=`node long-cli.mjs pack INPUT NEW.grl [--predictor-kib 256|1024|4096] [--template-kib 256|1024|4096] [--jobs 1..12]
node long-cli.mjs pack-restart INPUT NEW.grl [--jobs 1..12] [--backend js|wasm]
node long-cli.mjs train-prior TRAINING_TEXT NEW.gpm [--nodes 0..16384]
node long-cli.mjs pack-prior INPUT NEW.grl --model MODEL.gpm [--predictor-kib 256|4096] [--jobs 1..12] [--backend js|wasm]
node long-cli.mjs pack-expert INPUT NEW.grl --expert MODEL.gxe [--predictor-kib 256|4096] [--jobs 1..12] [--backend js|wasm]
node long-cli.mjs pack-shield INPUT NEW.grfp [--model MODEL.gpm | --expert MODEL.gxe] [--predictor-kib 256|4096] [--parity 0..100] [--jobs 1..12]
node long-cli.mjs protect EXISTING.grl NEW.grfp [--parity 0..100]
node long-cli.mjs heal PROTECTED.grfp NEW_DIR [--damaged FILE] [--jobs 1..12] [--backend js|wasm]
node long-cli.mjs restore ARCHIVE.grl NEW_FILE [--damaged FILE] [--jobs 1..12] [--backend js|wasm]
node long-cli.mjs delta SEED.grl VERSION NEW.grd [--copy-only]
node long-cli.mjs apply SEED.grl VERSION.grd NEW_FILE [--damaged FILE]`;
try {
  const [cmd,input,out,...args]=process.argv.slice(2);
  if(cmd==='--help')console.log(usage);
  else if(cmd==='protect'){
    if(!out || !(args.length===0 || (args.length===2 && args[0]==='--parity')))throw Error(usage);
    const {protectLongExisting}=await import('./protected.mjs');console.log(JSON.stringify(protectLongExisting(input,out,args.length?Number(args[1]):5)));
  }else if(cmd==='train-prior'){
    if(!out || !(args.length===0 || (args.length===2 && args[0]==='--nodes')))throw Error(usage);
    const fs=await import('node:fs'),{trainPrior,TRAIN_LIMIT}=await import('./prior.mjs'),{hash}=await import('./long-tape.mjs');
    if(fs.statSync(input).size>TRAIN_LIMIT)throw Error('Training input exceeds bounded trainer limit');
    const b=trainPrior(fs.readFileSync(input),args.length?Number(args[1]):undefined);fs.writeFileSync(out,b,{flag:'wx'});console.log(JSON.stringify({modelBytes:b.length,sha256:hash(b).toString('hex')}));
  }
  else if(cmd==='delta' || cmd==='apply') {
    if(!out || !(args.length===1 || (cmd==='delta' && args.length===2 && args[1]==='--copy-only') || (cmd==='apply' && args.length===3 && args[1]==='--damaged')))throw Error(usage);
    const {packDelta,restoreDelta}=await import('./delta.mjs');
    console.log(JSON.stringify(await (cmd==='delta'?packDelta(input,out,args[0],{numeric:args[1]!=='--copy-only'}):restoreDelta(input,out,args[0],{damaged:args[2]}))));
  }else {
    if(!out || !['pack','pack-restart','pack-prior','pack-expert','pack-shield','heal','restore'].includes(cmd) || args.length%2)throw Error(usage);
    const options={restart:['pack-restart','pack-prior','pack-expert','pack-shield'].includes(cmd)},names=cmd==='pack'?{'--predictor-kib':'predictor','--template-kib':'templates','--jobs':'jobs'}:
      {'--jobs':'jobs','--backend':'backend',...(['restore','heal'].includes(cmd)&&{'--damaged':'damaged'}),...(['pack-prior','pack-shield'].includes(cmd)&&{'--model':'modelPath','--predictor-kib':'predictor'}),...(['pack-expert','pack-shield'].includes(cmd)&&{'--expert':'expertPath','--predictor-kib':'predictor'}),...(cmd==='pack-shield'&&{'--parity':'parityPercent'})};
    for(let i=0;i<args.length;i+=2){const key=names[args[i]];if(!Object.hasOwn(names,args[i]) || Object.hasOwn(options,key))throw Error(usage);options[key]=['damaged','backend','modelPath','expertPath'].includes(key)?args[i+1]:Number(args[i+1]);}
    if((cmd==='pack-prior' && !options.modelPath) || (cmd==='pack-expert' && !options.expertPath))throw Error(usage);
    let fn=cmd==='restore'?restoreLong:packLong;
    if(cmd==='pack-shield'||cmd==='heal'){const p=await import('./protected.mjs');fn=cmd==='heal'?p.recoverLongProtected:p.packLongProtected;}
    console.log(JSON.stringify(await fn(input,out,options)));
  }
}catch(e){console.error(e.message);process.exitCode=1;}
