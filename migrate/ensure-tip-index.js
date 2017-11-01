'use strict';

const assert = require('assert');
const BDB = require('bdb');
const encoding = require('bbuf/lib/encoding');
const BufferReader = require('bbuf/lib/reader');
const hash256 = require('bcrypto/lib/hash256');
const BN = require('bcrypto/lib/bn');
const DUMMY = Buffer.from([0]);

let file = process.argv[2];
let batch;

assert(typeof file === 'string', 'Please pass in a database path.');

file = file.replace(/\.ldb\/?$/, '');

const db = new BDB({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false,
  bufferKeys: true
});

async function checkVersion() {
  console.log('Checking version.');

  const data = await db.get('V');

  if (!data)
    return;

  const ver = data.readUInt32LE(0, true);

  if (ver !== 1)
    throw Error(`DB is version ${ver}.`);
}

function entryFromRaw(data) {
  const p = new BufferReader(data, true);
  const hash = hash256.digest(p.readBytes(80));
  const entry = {};

  p.seek(-80);

  entry.hash = hash.toString('hex');
  entry.version = p.readU32(); // Technically signed
  entry.prevBlock = p.readHash('hex');
  entry.merkleRoot = p.readHash('hex');
  entry.time = p.readU32();
  entry.bits = p.readU32();
  entry.nonce = p.readU32();
  entry.height = p.readU32();
  entry.chainwork = new BN(p.readBytes(32), 'le');

  return entry;
}

function getEntries() {
  return db.values({
    gte: pair('e', encoding.ZERO_HASH),
    lte: pair('e', encoding.MAX_HASH),
    parse: entryFromRaw
  });
}

async function getTip(entry) {
  const state = await db.get('R');
  assert(state);
  const tip = state.toString('hex', 0, 32);
  const data = await db.get(pair('e', tip));
  assert(data);
  return entryFromRaw(data);
}

async function isMainChain(entry, tip) {
  if (entry.hash === tip)
    return true;

  if (await db.get(pair('n', entry.hash)))
    return true;

  return false;
}

// And this insane function is why we should
// be indexing tips in the first place!
async function indexTips() {
  const entries = await getEntries();
  const tip = await getTip();
  const tips = [];
  const orphans = [];
  const prevs = {};

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const main = await isMainChain(entry, tip.hash);
    if (!main) {
      orphans.push(entry);
      prevs[entry.prevBlock] = true;
    }
  }

  for (let i = 0; i < orphans.length; i++) {
    const orphan = orphans[i];
    if (!prevs[orphan.hash])
      tips.push(orphan.hash);
  }

  tips.push(tip.hash);

  for (let i = 0; i < tips.length; i++) {
    const tip = tips[i];
    console.log('Indexing chain tip: %s.', encoding.revHex(tip));
    batch.put(pair('p', tip), DUMMY);
  }
}

function write(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  return data.write(str, off, 'hex');
}

function pair(prefix, hash) {
  const key = Buffer.allocUnsafe(33);
  if (typeof prefix === 'string')
    prefix = prefix.charCodeAt(0);
  key[0] = prefix;
  write(key, hash, 1);
  return key;
}

(async () => {
  await db.open();
  console.log('Opened %s.', file);
  batch = db.batch();
  await checkVersion();
  await indexTips();
  await batch.write();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
});
