'use strict';

const assert = require('assert');
const bdb = require('bdb');
const bio = require('bufio');
const {encoding} = bio;
const layout = require('../lib/blockchain/layout');
const FileBlockStore = require('../lib/blockstore/file');
const ChainDB = require('../lib/blockchain/chaindb');
const ChainEntry = require('../lib/blockchain/chainentry');
const {resolve} = require('path');

assert(process.argv.length > 2, 'Please pass in a database path.');

// Changes:
// 1. Moves blocks and undo blocks from leveldb to flat files.
// 2. Removes tx and addr indexes from chaindb.
// 3. Upgrades header entries indexes.

const db = bdb.create({
  location: process.argv[2],
  memory: false,
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false
});

const location = resolve(process.argv[2], '../blocks');

const blockStore = new FileBlockStore({
  location: location
});

async function getVersion() {
  const data = await db.get(layout.V.encode());
  assert(data, 'No version.');

  return data.readUInt32LE(5, true);
}

async function updateVersion(version) {
  await checkVersion(version - 1);

  console.log('Updating version to %d.', version);

  const buf = Buffer.allocUnsafe(5 + 4);
  buf.write('chain', 0, 'ascii');
  buf.writeUInt32LE(version, 5, true);

  const parent = db.batch();
  parent.put(layout.V.encode(), buf);
  await parent.write();
}

async function checkVersion(version) {
  console.log('Checking version.');

  const ver = await getVersion();

  if (ver !== version)
    throw Error(`DB is version ${ver}.`);

  return ver;
}

async function migrateUndoBlocks() {
  console.log('Migrating undo blocks');

  let parent = db.batch();

  const iter = db.iterator({
    gte: layout.u.min(),
    lte: layout.u.max(),
    keys: true,
    values: true
  });

  let total = 0;

  await iter.each(async (key, value) => {
    const hash = key.slice(1);
    await blockStore.writeUndo(hash, value);
    parent.del(key);

    if (++total % 10000 === 0) {
      console.log('Migrated up %d undo blocks.', total);
      await parent.write();
      parent = db.batch();
    }
  });

  console.log('Migrated all %d undo blocks.', total);
  await parent.write();
}

async function migrateBlocks() {
  console.log('Migrating blocks');

  let parent = db.batch();

  const iter = db.iterator({
    gte: layout.b.min(),
    lte: layout.b.max(),
    keys: true,
    values: true
  });

  let total = 0;

  await iter.each(async (key, value) => {
    const hash = key.slice(1);
    await blockStore.write(hash, value);
    parent.del(key);

    if (++total % 10000 === 0) {
      console.log('Migrated up %d blocks.', total);
      await parent.write();
      parent = db.batch();
    }
  });

  console.log('Migrated all %d blocks.', total);
  await parent.write();
}

async function removeKey(name, key) {
  const iter = db.iterator({
    gte: key.min(),
    lte: key.max(),
    reverse: true,
    keys: true
  });

  let batch = db.batch();
  let total = 0;

  while (await iter.next()) {
    const {key} = iter;
    batch.del(key);

    if (++total % 10000 === 0) {
      console.log('Cleaned up %d %s index records.', total, name);
      await batch.write();
      batch = db.batch();
    }
  }
  await batch.write();

  console.log('Cleaned up %d %s index records.', total, name);
}

async function migrateIndexes() {
  const t = bdb.key('t', ['hash256']);
  const T = bdb.key('T', ['hash', 'hash256']);
  const C = bdb.key('C', ['hash', 'hash256', 'uint32']);

  await removeKey('hash -> tx', t);
  await removeKey('addr -> tx', T);
  await removeKey('addr -> coin', C);
}

async function migrateChainworkTips() {
  console.log('Migrating chain tips...');

  const hashes = await db.keys({
    gte: layout.p.min(),
    lte: layout.p.max(),
    parse: key => layout.p.decode(key)[0]
  });

  const batch = db.batch();

  for (const hash of hashes) {
    const entry = await getEntryByHash(hash);
    assert(entry);

    batch.del(layout.p.encode(hash));
    const raw = entry.toRaw();
    batch.put(layout.w.encode(fromBN(entry.chainwork), hash), raw);
  }

  await batch.write();
  console.log('Migrated chain tips.');
}

async function buildNextHashes() {
  console.log('Building next hashes...');

  const tips = await getTipEntries();

  // Walk backwards for every tip and add the
  // next hash as the reference.
  for (const tip of tips) {
    let entry = tip;

    while (entry) {
      if (entry.height % 10000 === 0)
        console.log('At height', entry.height);
      entry = await buildNextHash(entry);
    }
  }

  console.log('Built next hashes.');
}

async function buildNextHash(entry) {
  // Stop at the genesis block.
  if (entry.isGenesis())
    return null;

  // Get the previous entry.
  const prev = await getPrevious(entry);

  // Get any existing next hashes.
  const hashes = await getNextHashes(prev.hash);

  // Check if already exists.
  let exists = false;
  for (const hash of hashes) {
    if (hash.equals(entry.hash)) {
      exists = true;
      break;
    }
  }

  // Update the next record (if necessary).
  if (!exists) {
    hashes.push(entry.hash);
    await putNextHashes(prev.hash, hashes);
  }

  return prev;
}

async function buildSkip() {
  console.log('Building skiplist...');

  async function putSkip(entry) {
    if (entry.height % 10000 === 0)
      console.log('At height', entry.height);

    if (!entry.isGenesis()) {
      if (!await db.has(layout.s.encode(entry.hash))) {
        const skip = await getSkip(entry);
        await db.put(layout.s.encode(entry.hash), skip.hash);
      }
    }

    const nexts = await getNextEntries(entry.hash);

    for (const next of nexts)
      await putSkip(next);
  }

  // Start at the genesis block and build skip list
  // for all entries walking forward.
  const entry = await getEntryByHeight(0);
  await putSkip(entry);

  console.log('Built skiplist.');
}

/*
 * Database
 */

async function getTipEntries() {
  return await db.values({
    gte: layout.w.min(),
    lte: layout.w.max(),
    parse: data => ChainEntry.fromRaw(data)
  });
}

async function getSkip(entry) {
  return getAncestor(entry, ChainDB.getSkipHeight(entry.height));
}

async function getAncestor(entry, height) {
  if (height < 0)
    return null;

  assert(height >= 0);
  assert(height <= entry.height);

  while (entry.height !== height) {
    const skip = ChainDB.getSkipHeight(entry.height);
    const prev = ChainDB.getSkipHeight(entry.height - 1);

    const skipBetter = skip > height;
    const prevBetter = prev < skip - 2 && prev >= height;

    const hash = await db.get(layout.s.encode(entry.hash));

    if (hash && (skip === height || (skipBetter && !prevBetter)))
      entry = await getEntryByHash(hash);
    else
      entry = await getPrevious(entry);

    assert(entry);
  }

  return entry;
}

async function putNextHashes(hash, hashes) {
  let size = encoding.sizeVarint(hashes.length);
  size += 32 * hashes.length;

  const raw = bio.write(size);
  raw.writeVarint(hashes.length);

  for (const hash of hashes)
    raw.writeBytes(hash);

  return db.put(layout.r.encode(hash), raw.render());
}

async function getNextHashes(hash) {
  const hashes = [];
  const raw = await db.get(layout.r.encode(hash));
  if (!raw)
    return hashes;

  const br = bio.read(raw);
  const len = br.readVarint();

  for (let i = 0; i < len; i++)
    hashes.push(br.readBytes(32));

  return hashes;
}

async function getNextEntries(hash) {
  const entries = [];

  const hashes = await getNextHashes(hash);

  for (const hash of hashes)
    entries.push(await getEntryByHash(hash));

  return entries;
}

async function getEntryByHeight(height) {
  const hash = await db.get(layout.H.encode(height));
  if (!hash)
    return null;

  return getEntryByHash(hash);
}

async function getPrevious(entry) {
  return getEntryByHash(entry.prevBlock);
}

async function getEntryByHash(hash) {
  const raw = await db.get(layout.e.encode(hash));
  if (!raw)
    return null;

  return ChainEntry.fromRaw(raw);
}

/*
 * Helpers
 */

function fromBN(bn) {
  return bn.toString('hex', 64);
}

/*
 * Execute
 */

(async () => {
  await db.open();

  console.log('Opened %s.', process.argv[2]);

  const version = await getVersion();
  let compact = false;

  switch (version) {
    case 4:
      // Upgrade from version 4 to 5.
      await checkVersion(4);
      await blockStore.ensure();
      await blockStore.open();
      await migrateBlocks();
      await migrateUndoBlocks();
      await updateVersion(5);
      await blockStore.close();
      compact = true;
    case 5:
      // Upgrade from version 5 to 6.
      await checkVersion(5);
      await migrateIndexes();
      await updateVersion(6);
      compact = true;
    case 6:
      // Upgrade from version 6 to 7.
      await checkVersion(6);
      await migrateChainworkTips();
      await buildNextHashes();
      await buildSkip();
      await updateVersion(7);
      compact = true;
      break;
    case 7:
      console.log('Already upgraded.');
      break;
    default:
      console.log(`DB version is ${version}.`);
  }

  if (compact) {
    console.log('Compacting database');
    await db.compactRange();
  }

  await db.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
}).catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
