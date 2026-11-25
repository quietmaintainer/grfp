import * as fs from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { modes, textPolicies } from './codec.mjs';
import { TEXT_PAGE, textWindows } from './text.mjs';
import { GROUP, groupChoices, chooseGroup, readGroup, parseGroup, restoreGroup, templatePolicies } from './groups.mjs';

const MAGIC = Buffer.from('GRF1');
const HEADER = 12, RECORD = 19, FOOTER = 32;
const sha = () => createHash('sha256');

function read(fd, length) {
  const buf = Buffer.allocUnsafe(length);
  let used = 0;
  while (used < length) {
    const n = fs.readSync(fd, buf, used, length - used);
    if (!n) break;
    used += n;
  }
  return buf.subarray(0, used);
}
function exact(fd, length) {
  const buf = read(fd, length);
  if (buf.length !== length) throw Error('Truncated input');
  return buf;
}
function input(path, action) {
  const fd = fs.openSync(path, 'r');
  try { return action(fd); } finally { fs.closeSync(fd); }
}

// Publish only a complete, verified result; never replace an existing file.
export function newOutput(path, action) {
  if (fs.existsSync(path)) throw Error(`Output already exists: ${path}`);
  const dir = fs.mkdtempSync(join(dirname(resolve(path)), '.grf-')), tmp = join(dir, 'output');
  try {
    const fd = fs.openSync(tmp, 'wx');
    let result;
    try { result = action(bytes => fs.writeFileSync(fd, bytes)); } finally { fs.closeSync(fd); }
    try { fs.linkSync(tmp, path); } catch (e) {
      if (!['EPERM', 'ENOTSUP', 'ENOSYS', 'EOPNOTSUPP'].includes(e.code)) throw e;
      fs.copyFileSync(tmp, path, fs.constants.COPYFILE_EXCL);
    }
    return result;
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function stats(length) { return { bytes:length, recipeBytes:HEADER + FOOTER, pages:0, methods:{}, groups:0, groupMethods:{} }; }
function count(s, group) {
  s.pages += group.hashes.length; s.recipeBytes += group.wireBytes; s.groups++;
  s.groupMethods[group.kind] = (s.groupMethods[group.kind] ?? 0) + 1;
  for (const {mode} of group.records) s.methods[modes[mode]] = (s.methods[modes[mode]] ?? 0) + 1;
}

export function packingProfile(widthHint, { text = 'span', onPage, templates = text === 'off' || onPage ? 'off' : 'auto', textWindow = onPage || text === 'off' ? '16' : '256' } = {}) {
  if (widthHint !== undefined && (!Number.isInteger(widthHint) || widthHint < 3 || widthHint > 1024)) throw Error('Width must be 3–1024 bits');
  if (!textPolicies.includes(text)) throw Error('Text policy must be off, context or span');
  if (!templatePolicies.includes(templates)) throw Error(`Template policy must be one of: ${templatePolicies.join(', ')}`);
  if (!textWindows.includes(textWindow)) throw Error(`Text window must be one of: ${textWindows.join(', ')}`);
  if (onPage && (templates !== 'off' || textWindow !== '16')) throw Error('Per-page byte accounting requires templates off and a 16 KiB window');
  return {width:widthHint ?? null, text, templates, textWindow};
}

export function packFile(path, output, widthHint, options = {}) {
  const {text,templates,textWindow} = packingProfile(widthHint,options), {onPage,onGroup} = options;
  return input(path, fd => newOutput(output, write => {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || !Number.isSafeInteger(stat.size)) throw Error('Expected a regular file');
    const s = stats(stat.size), header = Buffer.alloc(HEADER), archiveHash = sha(), fileHash = sha();
    MAGIC.copy(header); header.writeBigUInt64LE(BigInt(s.bytes), 4);
    const emit = bytes => { archiveHash.update(bytes); write(bytes); };
    emit(header);
    for (let left = s.bytes; left > 0; left -= GROUP) {
      const raw = exact(fd, Math.min(left, GROUP));
      const choice = chooseGroup(groupChoices(raw, widthHint, text, templates, textWindow), templates);
      const group = parseGroup(choice.bytes, raw.length);
      if (!raw.equals(restoreGroup(group).bytes)) throw Error('Recipe did not reconstruct its input');
      onGroup?.(raw,choice.bytes);
      if (onPage) group.records.forEach((r,i) => onPage({page:s.pages + i, bytes:r.length, recordBytes:RECORD + r.body.length, mode:modes[r.mode]}));
      emit(choice.bytes); count(s, group); fileHash.update(raw);
    }
    if (read(fd, 1).length) throw Error('Input length changed during packing');
    write(archiveHash.digest());
    return { ...s, sha256: fileHash.digest('hex') };
  }));
}

export function walkArchive(path, visit) {
  return input(path, fd => {
    const header = exact(fd, HEADER);
    if (!header.subarray(0, 4).equals(MAGIC)) throw Error('Expected a GRF1 file recipe');
    const length = Number(header.readBigUInt64LE(4));
    if (!Number.isSafeInteger(length)) throw Error('Unsupported file length');
    const s = stats(length), archiveHash = sha().update(header);
    const take = n => { const b = exact(fd, n); archiveHash.update(b); return b; };
    for (let left = length; left > 0; left -= GROUP) {
      const group = readGroup(Math.min(left, GROUP), take);
      visit(group, s); count(s, group);
    }
    if (!exact(fd, FOOTER).equals(archiveHash.digest()) || read(fd, 1).length) throw Error('Recipe checksum or end-of-file mismatch');
    return s;
  });
}

export function restoreFile(recipe, output, { damaged, assemble } = {}) {
  return newOutput(output, write => {
    const run = fd => {
      const fileHash = sha(); let reused = 0, rebuilt = 0, replayedBytes = 0, decodedTapeBytes = 0;
      const s = walkArchive(recipe, group => {
        const old = fd === undefined ? undefined : read(fd, group.length);
        const result = restoreGroup(group, old, assemble);
        reused += result.reusedPages; rebuilt += result.rebuiltPages; replayedBytes += result.replayedBytes; decodedTapeBytes += result.decodedTapeBytes;
        write(result.bytes); fileHash.update(result.bytes);
      });
      return { ...s, rebuiltPages: rebuilt, reusedPages: reused, replayedBytes, decodedTapeBytes, sha256: fileHash.digest('hex'),
        ...(assemble?.stats && { lattice: { ...assemble.stats } }) };
    };
    return damaged === undefined ? run(undefined) : input(damaged, run);
  });
}

export function inspectFile(path) {
  const examples = {}, groupExamples = {};
  const s = walkArchive(path, (group, stats) => {
    restoreGroup(group);
    groupExamples[group.kind] ??= {group:stats.groups, originalBytes:group.length, tapeBytes:group.tapeLength, recordBytes:group.wireBytes,
      ...(group.kind === 'title' && {boundBytes:group.boundLength})};
    let pos = 0;
    group.records.forEach(({mode, body, length}) => {
      examples[modes[mode]] ??= { ...(group.kind === 'plain' ? {page:stats.pages+pos/TEXT_PAGE} : {group:stats.groups, tapePage:pos/TEXT_PAGE}), bytes:length, instructionBytes:body.length,
        ...(mode === 2 || mode === 3 ? { stride: body.readUInt16LE(0), anchor: body[2] } : {}),
        ...(mode === 4 ? { widthBits: body.readUInt16LE(0), rule: body[2], seed: body[3] ? 'literal row' : 'one center bit' } : {}) };
      pos += length;
    });
  });
  return { ...s, examples, groupExamples };
}
