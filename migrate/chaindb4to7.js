'use strict';

const assert = require('assert');
const bdb = require('bdb');
const layout = require('../lib/blockchain/layout');
const FileBlockStore = require('../lib/blockstore/file');
const Block = require('../lib/primitives/block');
const {ChainState, ChainFlags} = require('../lib/blockchain/internal/records');
const ChainEntry = require('../lib/blockchain/chainentry');
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

function encodeVersion(version) {
  const buf = Buffer.allocUnsafe(5 + 4);
  buf.write('chain', 0, 'ascii');
  buf.writeUInt32LE(version, 5, true);
  return buf;
}

async function updateVersion(version) {
  await checkVersion(version - 1);

  console.log('Updating version to %d.', version);

  const buf = encodeVersion(version);

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

async function getChainState() {
  const data = await db.get(layout.R.encode());

  if (!data)
    return null;

  return ChainState.fromRaw(data);
}

async function getChainFlags() {
  const data = await db.get(layout.O.encode());

  if (!data)
    return null;

  return ChainFlags.fromRaw(data);
}

async function getChainEntryByHash(hash) {
  const raw = await db.get(layout.e.encode(hash));

  if (!raw)
    return null;

  return ChainEntry.fromRaw(raw);
}

async function isMainChain(tip, hash) {
  if (hash.equals(tip))
    return true;

  const next = await db.get(layout.n.encode(hash));
  if (next)
    return true;

  return false;
}

async function updateStatsAndVersion(version) {
  const state = await getChainState();
  assert(state);

  const flags = await getChainFlags();
  assert(flags);

  const network = flags.network;
  const bip30heights = Object.keys(network.bip30);

  const batch = db.batch();

  // Increment the database version.
  batch.put(layout.V.encode(), encodeVersion(version));

  // If there are duplicate txids for the network,
  // such as in blocks 91842 and 91880, go through and
  // make the necessary adjustments.
  if (bip30heights.length > 0) {
    const tip = await getChainEntryByHash(state.tip);
    assert(tip);

    // Only fix the statistics for blocks that have already
    // been added to the chain.
    const heights = bip30heights.filter(height => height <= tip.height);

    for (const height of heights) {
      const hash = network.bip30[height];

      // In the very rare chance that these blocks are
      // not part of the main chain, skip them as the
      // adjustment is also not necessary.
      if (!await isMainChain(state.tip, hash))
        continue;

      const data = await blockStore.read(hash);
      const block = Block.fromRaw(data);
      const coinbase = block.txs[0];

      // The outputs were counted twice however are
      // only spendable once.
      for (const output of coinbase.outputs) {
        if (output.script.isUnspendable())
          continue;

        // Decrement the count and supply stats.
        state.spend(output);
      }
    }

    batch.put(layout.R.encode(), state.toRaw());
  }

  return batch.write();
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
      await blockStore.open();
      await updateStatsAndVersion(7);
      await blockStore.close();
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
