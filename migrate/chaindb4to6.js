'use strict';

const assert = require('assert');
const bdb = require('bdb');
const layout = require('../lib/blockchain/layout');
const FileBlockStore = require('../lib/blockstore/file');
const {resolve} = require('path');

assert(process.argv.length > 2, 'Please pass in a database path.');

// Changes:
// 1. Moves blocks and undo blocks from leveldb to flat files.
// 2. Removes tx and addr indexes from chaindb.

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
      break;
    case 6:
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
