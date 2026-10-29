// The web UI's crypto path, headless: loads src/server/vendor/*.js and the `vault-core` <script> block of
// src/server/index.html — the same bytes the browser runs — into a browser-like realm (no require, no process),
// with WebCrypto, atob and DOMParser as a browser has them. tests/compat/test_keepassxc.py runs it in the
// keepassxc container (node + @xmldom/xmldom there), next to keepassxc-cli, and compares the two.
//
//   node kdbx_node.js create <out.kdbx> <password> <tree.json>     a new vault as the UI creates it
//   node kdbx_node.js dump   <in.kdbx>  <password>                 the vault as JSON (stdout)
//   node kdbx_node.js edit   <in.kdbx>  <password> <ops.json> <out.kdbx>   apply UI operations, save
//   node kdbx_node.js info   <in.kdbx>  <password>                 KDBX version, cipher, KDF
//   node kdbx_node.js keyfile <out.keyx>                           a new key file, as the UI's "New" button makes it
//   --key <file> (any command that opens or creates a vault): the key file next to the password
//
// tree.json: {"groups": [{"name", "groups": [...], "entries": [...]}], "entries": [{title, username, password,
// url, notes, tags, custom: [{name, value, protected}]}]}. ops.json: [["addGroup", "A/B"], ["renameGroup",
// "A/B", "C"], ["removeGroup", "A"], ["addEntry", "A", {...}], ["editEntry", "A/title", {...}],
// ["removeEntry", "A/title"], ["setMasterKey", "new password", "<key file or null>"]]. Paths are below the root group, "" is the root.
// Exit 2 with {"error": "InvalidKey"} when the password (or a key file) does not open the vault.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const xmldom = require('@xmldom/xmldom');
const {XMLSerializer} = xmldom;
// a browser's DOMParser does not print its complaints; xmldom does (a photo tried as a key file is not XML)
const quiet = {warning() {}, error() {}, fatalError(e) { throw new Error(e); }};
class DOMParser extends xmldom.DOMParser { constructor() { super({errorHandler: quiet}); } }

const SERVER = path.join(__dirname, '..', '..', 'src', 'server');

function page() {
  const ctx = vm.createContext({console, atob, btoa, TextDecoder, setTimeout, clearTimeout, DOMParser, XMLSerializer});
  ctx.self = ctx;
  // values made in this realm, as the page's own (kdbxweb checks `instanceof ArrayBuffer`)
  const buffer = vm.runInContext('b => new Uint8Array(b).slice().buffer', ctx);
  const u8 = vm.runInContext('b => new Uint8Array(b)', ctx);
  const subtle = {};
  for (const m of ['digest', 'importKey', 'sign', 'encrypt', 'decrypt'])
    subtle[m] = async (...a) => { const r = await crypto.subtle[m](...a); return r instanceof ArrayBuffer ? buffer(r) : r; };
  ctx.crypto = {subtle, getRandomValues: a => crypto.getRandomValues(a)};
  ctx.TextEncoder = class { encode(s) { return u8(new TextEncoder().encode(s)); } };
  for (const f of ['kdbxweb.min.js', 'argon2-bundled.min.js'])
    vm.runInContext(fs.readFileSync(path.join(SERVER, 'vendor', f), 'utf8'), ctx, {filename: f});
  const html = fs.readFileSync(path.join(SERVER, 'index.html'), 'utf8');
  const core = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).find(s => s.trimStart().startsWith('// vault-core'));
  if (!core) throw new Error('no vault-core <script> in index.html');
  vm.runInContext(core + '\nthis.Vault = Vault;', ctx, {filename: 'index.html#vault-core'});
  return {Vault: ctx.Vault, kdbxweb: ctx.kdbxweb, buffer};
}

const {Vault, kdbxweb, buffer} = page();
const read = f => buffer(fs.readFileSync(f));
const write = async (db, f) => fs.writeFileSync(f, Buffer.from(await Vault.save(db)));

function find(db, p, kind) {
  let g = db.getDefaultGroup();
  const parts = p ? p.split('/') : [];
  const last = kind === 'entry' ? parts.pop() : null;
  for (const name of parts) {
    g = g.groups.find(x => x.name === name);
    if (!g) throw new Error(`no group ${p}`);
  }
  if (kind !== 'entry') return g;
  const e = g.entries.find(x => Vault.fields(x).title === last);
  if (!e) throw new Error(`no entry ${p}`);
  return e;
}

function fill(db, group, tree) {
  for (const g of tree.groups || []) fill(db, Vault.addGroup(db, group, g.name), g);
  for (const e of tree.entries || []) Vault.addEntry(db, group, e);
}

function dump(db) {
  const bin = Vault.recycleBin(db);
  const walk = g => ({name: g.name || '', groups: g.groups.filter(x => x !== bin).map(walk),
                      entries: g.entries.map(e => Object.assign(Vault.fields(e), {history: e.history.length}))});
  const binDump = bin ? walk(bin) : null;
  return Object.assign(walk(db.getDefaultGroup()), {recycleBin: binDump});
}

async function main() {
  const argv = process.argv.slice(2), k = argv.indexOf('--key');
  const key = k < 0 ? null : read(argv.splice(k, 2)[1]);
  const [cmd, file, password, arg, out] = argv;
  if (cmd === 'keyfile') {
    fs.writeFileSync(file, Buffer.from(await Vault.newKeyFile()));
    return {ok: true};
  }
  if (cmd === 'create') {
    const db = await Vault.create(path.basename(file, '.kdbx'), password, key);
    fill(db, db.getDefaultGroup(), JSON.parse(fs.readFileSync(arg, 'utf8')));
    await write(db, file);
    return {ok: true};
  }
  let db;
  try { db = await Vault.open(read(file), password, key); }
  catch (e) {
    if (e.code === 'InvalidKey') { console.log(JSON.stringify({error: 'InvalidKey'})); process.exit(2); }
    throw e;
  }
  if (cmd === 'dump') return dump(db);
  if (cmd === 'info') {
    const kdf = db.header.kdfParameters, uuid = kdbxweb.ByteUtils.bytesToBase64(kdf.get('$UUID'));
    const name = Object.keys(kdbxweb.Consts.KdfId).find(k => kdbxweb.Consts.KdfId[k] === uuid);
    const cipher = Object.keys(kdbxweb.Consts.CipherId).find(k => kdbxweb.Consts.CipherId[k] === db.header.dataCipherUuid.id);
    const num = v => typeof v === 'number' ? v : v.value;
    return {version: db.header.versionMajor, cipher, kdf: name, memory: num(kdf.get('M') || 0), iterations: num(kdf.get('I') || 0)};
  }
  if (cmd === 'edit') {
    for (const [op, p, x] of JSON.parse(fs.readFileSync(arg, 'utf8'))) {
      if (op === 'addGroup') { const i = p.lastIndexOf('/'); Vault.addGroup(db, find(db, i < 0 ? '' : p.slice(0, i)), p.slice(i + 1)); }
      else if (op === 'renameGroup') Vault.renameGroup(find(db, p), x);
      else if (op === 'removeGroup') Vault.remove(db, find(db, p));
      else if (op === 'addEntry') Vault.addEntry(db, find(db, p), x);
      else if (op === 'editEntry') Vault.editEntry(find(db, p, 'entry'), Object.assign(Vault.fields(find(db, p, 'entry')), x));
      else if (op === 'removeEntry') Vault.remove(db, find(db, p, 'entry'));
      else if (op === 'setMasterKey') await Vault.setMasterKey(db, p, x ? read(x) : null);
      else throw new Error(`unknown op ${op}`);
    }
    await write(db, out);
    return {ok: true};
  }
  throw new Error(`unknown command ${cmd}`);
}

main().then(r => console.log(JSON.stringify(r)), e => { console.error(e.stack || String(e)); process.exit(1); });
