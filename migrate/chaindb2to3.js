'use strict';

if (process.argv.indexOf('-h') !== -1
    || process.argv.indexOf('--help') !== -1
    || process.argv.length < 3) {
  console.error('Bcoin database migration (chaindb v2->v3).');
  console.error('');
  console.error('Usage:');
  console.error('  $ node migrate/chaindb2to3.js [database-path] [--prune]');
  console.error('');
  console.error('Note: use --prune to convert your database to a pruned DB');
  console.error('in the process. This results in a faster migration, but');
  console.error('a pruning of the chain.');
  process.exit(1);
  throw new Error('Exit failed.');
}

const assert = require('assert');
const bdb = require('bdb');
const hash256 = require('bcrypto/lib/hash256');
const BN = require('bn.js');
const bio = require('bufio');
const LRU = require('blru');
const util = require('../lib/utils/util');
const OldCoins = require('./coins/coins');
const OldUndoCoins = require('./coins/undocoins');
const CoinEntry = require('../lib/coins/coinentry');
const UndoCoins = require('../lib/coins/undocoins');
const Block = require('../lib/primitives/block');
const consensus = require('../lib/protocol/consensus');

const shouldPrune = process.argv.indexOf('--prune') !== -1;

let hasIndex = false;
let hasPruned = false;
let hasSPV = false;

const db = bdb.create({
  location: process.argv[2],
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false
});

// \0\0migrate
const JOURNAL_KEY = Buffer.from('00006d696772617465', 'hex');
const MIGRATION_ID = 0;
const STATE_VERSION = -1;
const STATE_UNDO = 0;
const STATE_CLEANUP = 1;
const STATE_COINS = 2;
const STATE_ENTRY = 3;
const STATE_FINAL = 4;
const STATE_DONE = 5;

const metaCache = new Map();
const lruCache = new LRU(200000);

function writeJournal(batch, state, hash) {
  const data = Buffer.allocUnsafe(34);

  if (!hash)
    hash = consensus.NULL_HASH;

  data[0] = MIGRATION_ID;
  data[1] = state;
  data.write(hash, 2, 'hex');

  batch.put(JOURNAL_KEY, data);
}

async function readJournal() {
  const data = await db.get(JOURNAL_KEY);

  if (!data)
    return [STATE_VERSION, consensus.NULL_HASH];

  if (data.length !== 34)
    throw new Error('Bad migration length.');

  if (data[0] !== MIGRATION_ID)
    throw new Error('Bad migration id.');

  const state = data.readUInt8(1, true);
  const hash = data.toString('hex', 2, 34);

  console.log('Reading journal.');
  console.log('Recovering from state %d.', state);

  return [state, hash];
}

async function updateVersion() {
  const batch = db.batch();

  console.log('Checking version.');

  const raw = await db.get('V');

  if (!raw)
    throw new Error('No DB version found!');

  const version = raw.readUInt32LE(0, true);

  if (version !== 2)
    throw Error(`DB is version ${version}.`);

  // Set to uint32_max temporarily.
  // This is to prevent bcoin from
  // trying to access this chain.
  const data = Buffer.allocUnsafe(4);
  data.writeUInt32LE(-1 >>> 0, 0, true);
  batch.put('V', data);

  writeJournal(batch, STATE_UNDO);

  console.log('Updating version.');

  await batch.write();

  return [STATE_UNDO, consensus.NULL_HASH];
}

async function reserializeUndo(hash) {
  let tip = await getTip();

  const height = tip.height;

  if (hash !== consensus.NULL_HASH)
    tip = await getEntry(hash);

  console.log('Reserializing undo coins from tip %s.',
    util.revHex(tip.hash));

  let batch = db.batch();
  let pruning = false;
  let total = 0;
  let totalCoins = 0;

  while (tip.height !== 0 && !hasSPV) {
    if (shouldPrune) {
      if (tip.height < height - 288) {
        console.log('Pruning block %s (%d).',
          util.revHex(tip.hash), tip.height);

        batch.del(pair('u', tip.hash));
        batch.del(pair('b', tip.hash));

        if (!pruning) {
          console.log(
            'Reserialized %d undo records (%d coins).',
            total, totalCoins);
          writeJournal(batch, STATE_UNDO, tip.prevBlock);
          await batch.write();
          metaCache.clear();
          batch = db.batch();
          pruning = true;
        }

        tip = await getEntry(tip.prevBlock);
        assert(tip);
        continue;
      }
    }

    const undoData = await db.get(pair('u', tip.hash));
    const blockData = await db.get(pair('b', tip.hash));

    if (!undoData) {
      tip = await getEntry(tip.prevBlock);
      assert(tip);
      continue;
    }

    if (!blockData) {
      if (!hasPruned)
        throw new Error(`Block not found: ${tip.hash}.`);
      break;
    }

    const block = Block.fromRaw(blockData);
    const old = OldUndoCoins.fromRaw(undoData);
    const undo = new UndoCoins();

    console.log(
      'Reserializing coins for block %s (%d).',
      util.revHex(tip.hash), tip.height);

    for (let i = block.txs.length - 1; i >= 1; i--) {
      const tx = block.txs[i];
      for (let j = tx.inputs.length - 1; j >= 0; j--) {
        const {prevout} = tx.inputs[j];
        const coin = old.items.pop();
        const output = coin.toOutput();

        assert(coin);

        const [version, height, write] = await getMeta(coin, prevout);

        const item = new CoinEntry();
        item.version = version;
        item.height = height;
        item.coinbase = coin.coinbase;
        item.output.script = output.script;
        item.output.value = output.value;
        item.spent = true;
        item.raw = null;

        // Store an index of heights and versions for later.
        const meta = [version, height];

        if (write) {
          const data = Buffer.allocUnsafe(8);
          data.writeUInt32LE(version, 0, true);
          data.writeUInt32LE(height, 4, true);
          batch.put(pair(0x01, prevout.hash), data);
          metaCache.set(prevout.hash, meta);
        }

        if (!lruCache.has(prevout.hash))
          lruCache.set(prevout.hash, meta);

        undo.items.push(item);
      }
    }

    // We need to reverse everything.
    undo.items.reverse();

    totalCoins += undo.items.length;

    batch.put(pair('u', tip.hash), undo.toRaw());

    if (++total % 100 === 0) {
      console.log(
        'Reserialized %d undo records (%d coins).',
        total, totalCoins);
      writeJournal(batch, STATE_UNDO, tip.prevBlock);
      await batch.write();
      metaCache.clear();
      batch = db.batch();
    }

    tip = await getEntry(tip.prevBlock);
  }

  writeJournal(batch, STATE_CLEANUP);
  await batch.write();

  metaCache.clear();
  lruCache.reset();

  console.log(
    'Reserialized %d undo records (%d coins).',
    total, totalCoins);

  return [STATE_CLEANUP, consensus.NULL_HASH];
}

async function cleanupIndex() {
  if (hasSPV)
    return [STATE_COINS, consensus.NULL_HASH];

  const iter = db.iterator({
    gte: pair(0x01, consensus.ZERO_HASH),
    lte: pair(0x01, Buffer.alloc(32, 0xff)),
    keys: true
  });

  console.log('Removing txid->height undo index.');

  let batch = db.batch();
  let total = 0;

  while (await iter.next()) {
    const {key} = iter;

    batch.del(key);

    if (++total % 10000 === 0) {
      console.log('Cleaned up %d undo records.', total);
      writeJournal(batch, STATE_CLEANUP);
      await batch.write();
      batch = db.batch();
    }
  }

  writeJournal(batch, STATE_COINS);
  await batch.write();

  console.log('Cleaned up %d undo records.', total);

  return [STATE_COINS, consensus.NULL_HASH];
}

async function reserializeCoins(hash) {
  if (hasSPV)
    return [STATE_ENTRY, consensus.NULL_HASH];

  const iter = db.iterator({
    gte: pair('c', hash),
    lte: pair('c', Buffer.alloc(32, 0xff)),
    keys: true,
    values: true
  });

  let start = true;

  if (hash !== consensus.NULL_HASH) {
    const item = await iter.next();
    if (!item)
      start = false;
  }

  console.log('Reserializing coins from %s.', util.revHex(hash));

  let batch = db.batch();
  let total = 0;

  while (start) {
    const item = await iter.next();

    if (!item)
      break;

    if (item.key.length !== 33)
      continue;

    const hash = item.key.toString('hex', 1, 33);
    const old = OldCoins.fromRaw(item.value, hash);

    let update = false;

    for (let i = 0; i < old.outputs.length; i++) {
      const coin = old.getCoin(i);

      if (!coin)
        continue;

      const item = new CoinEntry();
      item.version = coin.version;
      item.height = coin.height;
      item.coinbase = coin.coinbase;
      item.output.script = coin.script;
      item.output.value = coin.value;
      item.spent = false;
      item.raw = null;

      batch.put(bpair('c', hash, i), item.toRaw());

      if (++total % 10000 === 0)
        update = true;
    }

    batch.del(item.key);

    if (update) {
      console.log('Reserialized %d coins.', total);
      writeJournal(batch, STATE_COINS, hash);
      await batch.write();
      batch = db.batch();
    }
  }

  writeJournal(batch, STATE_ENTRY);
  await batch.write();

  console.log('Reserialized %d coins.', total);

  return [STATE_ENTRY, consensus.NULL_HASH];
}

async function reserializeEntries(hash) {
  const iter = db.iterator({
    gte: pair('e', hash),
    lte: pair('e', Buffer.alloc(32, 0xff)),
    values: true
  });

  let start = true;

  if (hash !== consensus.NULL_HASH) {
    const item = await iter.next();
    if (!item)
      start = false;
    else
      assert(item.key.equals(pair('e', hash)));
  }

  console.log('Reserializing entries from %s.', util.revHex(hash));

  const tip = await getTipHash();

  let total = 0;
  let batch = db.batch();

  while (start) {
    const item = await iter.next();

    if (!item)
      break;

    const entry = entryFromRaw(item.value);
    const main = await isMainChain(entry, tip);

    batch.put(item.key, entryToRaw(entry, main));

    if (++total % 100000 === 0) {
      console.log('Reserialized %d entries.', total);
      writeJournal(batch, STATE_ENTRY, entry.hash);
      await batch.write();
      batch = db.batch();
    }
  }

  writeJournal(batch, STATE_FINAL);
  await batch.write();

  console.log('Reserialized %d entries.', total);

  return [STATE_FINAL, consensus.NULL_HASH];
}

async function finalize() {
  const batch = db.batch();
  const data = Buffer.allocUnsafe(4);

  data.writeUInt32LE(3, 0, true);

  batch.del(JOURNAL_KEY);
  batch.put('V', data);

  // This has bugged me for a while.
  batch.del(pair('n', consensus.ZERO_HASH));

  if (shouldPrune) {
    const data = await db.get('O');

    assert(data);

    let flags = data.readUInt32LE(4, true);
    flags |= 1 << 2;

    data.writeUInt32LE(flags, 4, true);

    batch.put('O', data);
  }

  console.log('Finalizing database.');

  await batch.write();

  console.log('Compacting database...');

  await db.compactRange();

  return [STATE_DONE, consensus.NULL_HASH];
}

async function getMeta(coin, prevout) {
  // Case 1: Undo coin is the last spend.
  if (coin.height !== -1) {
    assert(coin.version !== -1, 'Database corruption.');
    return [coin.version, coin.height, hasIndex ? false : true];
  }

  // Case 2: The item is still in the LRU cache.
  const lruItem = lruCache.get(prevout.hash);

  if (lruItem) {
    const [version, height] = lruItem;
    return [version, height, false];
  }

  // Case 3: The database has a tx-index. We
  // can just hit that instead of reindexing.
  if (hasIndex) {
    const txRaw = await db.get(pair('t', prevout.hash));
    assert(txRaw, 'Database corruption.');
    assert(txRaw[txRaw.length - 45] === 1);
    const version = txRaw.readUInt32LE(0, true);
    const height = txRaw.readUInt32LE(txRaw.length - 12, true);
    return [version, height, false];
  }

  // Case 4: We have previously cached
  // this coin's metadata, but it's not
  // written yet.
  const metaItem = metaCache.get(prevout.hash);

  if (metaItem) {
    const [version, height] = metaItem;
    return [version, height, false];
  }

  // Case 5: We have previously cached
  // this coin's metadata, and it is
  // written.
  const metaRaw = await db.get(pair(0x01, prevout.hash));

  if (metaRaw) {
    const version = metaRaw.readUInt32LE(0, true);
    const height = metaRaw.readUInt32LE(4, true);
    return [version, height, false];
  }

  // Case 6: The coin's metadata is
  // still in the top-level UTXO set.
  const coinsRaw = await db.get(pair('c', prevout.hash));

  // Case 7: We're pruned and are
  // under the keepBlocks threshold.
  // We don't have access to this
  // data. Luckily, it appears that
  // all historical transactions
  // under height 182 are version 1,
  // which means height is not
  // necessary to determine CSV
  // anyway. Just store the height
  // as `1`.
  if (!coinsRaw) {
    assert(hasPruned, 'Database corruption.');
    return [1, 1, false];
  }

  const br = bio.read(coinsRaw);
  const version = br.readVarint();
  const height = br.readU32();

  return [version, height, true];
}

async function getTip() {
  const tip = await getTipHash();
  return await getEntry(tip);
}

async function getTipHash() {
  const state = await db.get('R');
  assert(state);
  return state.toString('hex', 0, 32);
}

async function getEntry(hash) {
  const data = await db.get(pair('e', hash));
  assert(data);
  return entryFromRaw(data);
}

async function isPruned() {
  const data = await db.get('O');
  assert(data);
  return (data.readUInt32LE(4) & 4) !== 0;
}

async function isSPV() {
  const data = await db.get('O');
  assert(data);
  return (data.readUInt32LE(4) & 1) !== 0;
}

async function isIndexed() {
  const data = await db.get('O');
  assert(data);
  return (data.readUInt32LE(4) & 8) !== 0;
}

async function isMainChain(entry, tip) {
  if (entry.hash === tip)
    return true;

  if (await db.get(pair('n', entry.hash)))
    return true;

  return false;
}

function entryFromRaw(data) {
  const br = bio.read(data, true);
  const hash = hash256.digest(br.readBytes(80));

  br.seek(-80);

  const entry = {};
  entry.hash = hash.toString('hex');
  entry.version = br.readU32();
  entry.prevBlock = br.readHash('hex');
  entry.merkleRoot = br.readHash('hex');
  entry.time = br.readU32();
  entry.bits = br.readU32();
  entry.nonce = br.readU32();
  entry.height = br.readU32();
  entry.chainwork = new BN(br.readBytes(32), 'le');

  return entry;
}

function entryToRaw(entry, main) {
  const bw = bio.write(116 + 1);

  bw.writeU32(entry.version);
  bw.writeHash(entry.prevBlock);
  bw.writeHash(entry.merkleRoot);
  bw.writeU32(entry.time);
  bw.writeU32(entry.bits);
  bw.writeU32(entry.nonce);
  bw.writeU32(entry.height);
  bw.writeBytes(entry.chainwork.toArrayLike(Buffer, 'le', 32));
  bw.writeU8(main ? 1 : 0);

  return bw.render();
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

function bpair(prefix, hash, index) {
  const key = Buffer.allocUnsafe(37);
  if (typeof prefix === 'string')
    prefix = prefix.charCodeAt(0);
  key[0] = prefix;
  write(key, hash, 1);
  key.writeUInt32BE(index, 33, true);
  return key;
}

// Make eslint happy.
reserializeEntries;

(async () => {
  await db.open();

  console.log('Opened %s.', process.argv[2]);

  if (await isSPV())
    hasSPV = true;

  if (await isPruned())
    hasPruned = true;

  if (await isIndexed())
    hasIndex = true;

  if (shouldPrune && hasPruned)
    throw new Error('Database is already pruned.');

  if (shouldPrune && hasSPV)
    throw new Error('Database cannot be pruned due to SPV.');

  console.log('Starting migration in 3 seconds...');
  console.log('If you crash you can start over.');

  await new Promise(r => setTimeout(r, 3000));

  let [state, hash] = await readJournal();

  if (state === STATE_VERSION)
    [state, hash] = await updateVersion();

  if (state === STATE_UNDO)
    [state, hash] = await reserializeUndo(hash);

  if (state === STATE_CLEANUP)
    [state, hash] = await cleanupIndex();

  if (state === STATE_COINS)
    [state, hash] = await reserializeCoins(hash);

  // if (state === STATE_ENTRY)
  //   [state, hash] = await reserializeEntries(hash);

  if (state === STATE_ENTRY)
    [state, hash] = [STATE_FINAL, consensus.NULL_HASH];

  if (state === STATE_FINAL)
    [state, hash] = await finalize();

  assert(state === STATE_DONE);

  console.log('Closing %s.', process.argv[2]);

  await db.close();

  console.log('Migration complete.');
  process.exit(0);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
