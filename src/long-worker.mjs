import { parentPort,workerData as c } from 'node:worker_threads';
import { packLongRecord,restoreLongRecord } from './long-record.mjs';
parentPort.on('message',({mode,bytes,n,old})=>{
  try {
    const b=Buffer.from(bytes.buffer,bytes.byteOffset,bytes.byteLength);
    const result=mode==='pack'?{bytes:packLongRecord(b,c)}:restoreLongRecord(b,n,c,old && Buffer.from(old.buffer,old.byteOffset,old.byteLength));
    const output=Uint8Array.from(result.bytes);parentPort.postMessage({...result,bytes:output},[output.buffer]);
  } catch(e) {parentPort.postMessage({error:e.message});}
});
