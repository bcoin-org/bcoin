'use strict';

const assert = require('assert');
const bdb = require('bdb');
const layout = require('../lib/blockchain/layout');
const FileBlockStore = require('../lib/blockstore/file');
const {resolve} = require('path');

assert(process.argv.length > 2, 'Please pass in a database path.');

// migration -
// chaindb: leveldb to flat files

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

async function updateVersion() {
  const ver = await checkVersion();

  console.log('Updating version to %d.', ver + 1);

  const buf = Buffer.allocUnsafe(5 + 4);
  buf.write('chain', 0, 'ascii');
  buf.writeUInt32LE(5, 5, true);

  const parent = db.batch();
  parent.put(layout.V.encode(), buf);
  await parent.write();
}

async function checkVersion() {
  console.log('Checking version.');

  const data = await db.get(layout.V.encode());
  assert(data, 'No version.');

  const ver = data.readUInt32LE(5, true);

  if (ver !== 4)
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

/*
 * Execute
 */

(async () => {
  await db.open();
  await blockStore.ensure();
  await blockStore.open();

  console.log('Opened %s.', process.argv[2]);

  await checkVersion();
  await migrateBlocks();
  await migrateUndoBlocks();
  await updateVersion();

  console.log('Compacting database');
  await db.compactRange();
  await db.close();
  await blockStore.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
}).catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
