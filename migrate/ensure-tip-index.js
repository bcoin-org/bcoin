'use strict';

const assert = require('assert');
const encoding = require('../lib/utils/encoding');
const BufferReader = require('../lib/utils/reader');
const digest = require('../lib/crypto/digest');
const util = require('../lib/utils/util');
const LDB = require('../lib/db/ldb');
const BN = require('../lib/crypto/bn');
const DUMMY = Buffer.from([0]);
let file = process.argv[2];
let db, batch;

assert(typeof file === 'string', 'Please pass in a database path.');

file = file.replace(/\.ldb\/?$/, '');

db = LDB({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false,
  bufferKeys: true
});

async function checkVersion() {
  let data, ver;

  console.log('Checking version.');

  data = await db.get('V');

  if (!data)
    return;

  ver = data.readUInt32LE(0, true);

  if (ver !== 1)
    throw Error(`DB is version ${ver}.`);
}

function entryFromRaw(data) {
  let p = new BufferReader(data, true);
  let hash = digest.hash256(p.readBytes(80));
  let entry = {};

  p.seek(-80);

  entry.hash = hash.toString('hex');
  entry.version = p.readU32(); // Technically signed
  entry.prevBlock = p.readHash('hex');
  entry.merkleRoot = p.readHash('hex');
  entry.ts = p.readU32();
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
  let state = await db.get('R');
  assert(state);
  let tip = state.toString('hex', 0, 32);
  let data = await db.get(pair('e', tip));
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
  let entries = await getEntries();
  let tip = await getTip();
  let tips = [];
  let orphans = [];
  let prevs = {};
  let i, orphan, entry, main;

  for (i = 0; i < entries.length; i++) {
    entry = entries[i];
    main = await isMainChain(entry, tip.hash);
    if (!main) {
      orphans.push(entry);
      prevs[entry.prevBlock] = true;
    }
  }

  for (i = 0; i < orphans.length; i++) {
    orphan = orphans[i];
    if (!prevs[orphan.hash])
      tips.push(orphan.hash);
  }

  tips.push(tip.hash);

  for (i = 0; i < tips.length; i++) {
    tip = tips[i];
    console.log('Indexing chain tip: %s.', util.revHex(tip));
    batch.put(pair('p', tip), DUMMY);
  }
}

function write(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  data.write(str, off, 'hex');
}

function pair(prefix, hash) {
  let key = Buffer.allocUnsafe(33);
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
