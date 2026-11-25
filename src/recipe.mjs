#!/usr/bin/env node
import { packFile, restoreFile, inspectFile } from './archive.mjs';
import { swarmAssembler } from './swarm.mjs';
import { packProtected, protectExisting, recoverProtected, reprotect } from './protected.mjs';

const usage = `Usage: node recipe.mjs
  pack INPUT RECIPE [--width BITS] [--text off|context|span] [--templates off|exact|numeric|full-title|auto] [--text-window 16|64-reset|64|256-reset|256] [--parity 0..100 [--fec local8|global16]]
  restore RECIPE NEW_FILE [--swarm-web PATH_TO_SWARM_WEB]
  repair RECIPE DAMAGED_FILE NEW_FILE [--swarm-web PATH_TO_SWARM_WEB]
  protect EXISTING_GRF1 PROTECTED_RECIPE [--parity 0..100] [--fec local8|global16] [same encoder settings as pack]
  reprotect EXISTING_GRFP NEW_GRFP [--fec global16|local8] [--parity 0..100]
  recover PROTECTED_RECIPE NEW_DIRECTORY [--damaged DAMAGED_FILE] [--swarm-web PATH_TO_SWARM_WEB]
  inspect RECIPE`;

async function main([command, ...args]) {
  if (command === '--help' || command === '-h') return usage;
  if (['pack','protect','reprotect'].includes(command) && args.length >= 2) {
    let width, text, templates, textWindow, parityPercent,fec;
    for (let i = 2; i < args.length; i += 2) {
      if (args[i + 1] === undefined) throw Error(usage);
      if(args[i]==='--fec' && fec===undefined)fec=args[i+1];
      else if (args[i] === '--parity' && parityPercent === undefined && /^\d+$/.test(args[i+1])) parityPercent = Number(args[i+1]);
      else if(command==='reprotect')throw Error(usage);
      else if (args[i] === '--width' && width === undefined) width = Number(args[i + 1]);
      else if (args[i] === '--text' && text === undefined) text = args[i + 1];
      else if (args[i] === '--templates' && templates === undefined) templates = args[i + 1];
      else if (args[i] === '--text-window' && textWindow === undefined) textWindow = args[i + 1];
      else throw Error(usage);
    }
    if(command==='reprotect')return reprotect(args[0],args[1],{fec,parityPercent});
    if(command==='pack' && fec!==undefined && parityPercent===undefined)throw Error('--fec on pack requires --parity');
    const pack=command==='protect' ? protectExisting : parityPercent===undefined ? packFile : packProtected;
    return pack(args[0], args[1], width, { text, templates, textWindow, parityPercent,fec });
  }
  if (command === 'recover' && args.length>=2) {
    let damaged, web;
    for (let i=2;i<args.length;i+=2) {
      if (!args[i+1]) throw Error(usage);
      if (args[i]==='--damaged' && damaged===undefined) damaged=args[i+1];
      else if (args[i]==='--swarm-web' && web===undefined) web=args[i+1];
      else throw Error(usage);
    }
    return recoverProtected(args[0],args[1],{damaged,assemble:web && await swarmAssembler(web)});
  }
  if (command === 'inspect' && args.length === 1) return inspectFile(args[0]);
  if (command === 'restore' || command === 'repair') {
    const n = command === 'repair' ? 3 : 2;
    if (args.length === n || (args.length === n + 2 && args[n] === '--swarm-web')) {
      const assemble = args.length > n ? await swarmAssembler(args[n + 1]) : undefined;
      return restoreFile(args[0], args[n - 1], { damaged: n === 3 ? args[1] : undefined, assemble });
    }
  }
  throw Error(usage);
}

try {
  const result = await main(process.argv.slice(2));
  console.log(typeof result === 'string' ? result : JSON.stringify(result, null, 2));
} catch (error) { console.error(error.message); process.exitCode = 1; }
