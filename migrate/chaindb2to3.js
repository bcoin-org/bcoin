'use strict';

const assert = require('assert');
const encoding = require('../lib/utils/encoding');
const co = require('../lib/utils/co');
const util = require('../lib/utils/util');
const digest = require('../lib/crypto/digest');
const BN = require('../lib/crypto/bn');
const StaticWriter = require('../lib/utils/staticwriter');
const BufferReader = require('../lib/utils/reader');
const OldCoins = require('./coins/coins');
const OldUndoCoins = require('./coins/undocoins');
const CoinEntry = require('../lib/coins/coinentry');
const UndoCoins = require('../lib/coins/undocoins');
const Block = require('../lib/primitives/block');
const LDB = require('../lib/db/ldb');

assert(process.argv.length > 2, 'Please pass in a database path.');

const file = process.argv[2].replace(/\.ldb\/?$/, '');

const db = LDB({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false,
  bufferKeys: true
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

const heightCache = new Map();

function writeJournal(batch, state, hash) {
  let data = Buffer.allocUnsafe(34);

  if (!hash)
    hash = encoding.NULL_HASH;

  data[0] = MIGRATION_ID;
  data[1] = state;
  data.write(hash, 2, 'hex');

  batch.put(JOURNAL_KEY, data);
}

async function readJournal() {
  let data = await db.get(JOURNAL_KEY);
  let state, hash;

  if (!data)
    return [STATE_VERSION, encoding.NULL_HASH];

  if (data[0] !== MIGRATION_ID)
    throw new Error('Bad migration id.');

  if (data.length !== 34)
    throw new Error('Bad migration length.');

  state = data.readUInt8(1, true);
  hash = data.toString('hex', 2, 34);

  console.log('Reading journal.');
  console.log('Recovering from state %d.', state);

  return [state, hash];
}

async function updateVersion() {
  let batch = db.batch();
  let data, version;

  console.log('Checking version.');

  data = await db.get('V');

  if (!data)
    throw new Error('No DB version found!');

  version = data.readUInt32LE(0, true);

  if (version !== 2)
    throw Error(`DB is version ${version}.`);

  data = Buffer.allocUnsafe(4);

  // Set to uint32_max temporarily.
  // This is to prevent bcoin from
  // trying to access this chain.
  data.writeUInt32LE(-1 >>> 0, 0, true);
  batch.put('V', data);

  writeJournal(batch, STATE_UNDO);

  console.log('Updating version.');

  await batch.write();

  return [STATE_UNDO, encoding.NULL_HASH];
}

async function reserializeUndo(hash) {
  let batch = db.batch();
  let tip = await getTip();
  let total = 0;

  if (hash !== encoding.NULL_HASH)
    tip = await getEntry(hash);

  console.log('Reserializing undo coins from tip %s.', util.revHex(tip.hash));

  while (tip.height !== 0) {
    let undoData = await db.get(pair('u', tip.hash));
    let blockData = await db.get(pair('b', tip.hash));
    let block, old, undo;

    if (!undoData) {
      tip = await getEntry(tip.prevBlock);
      continue;
    }

    if (!blockData) {
      if (!(await isPruned()))
        throw new Error(`Block not found: ${tip.hash}.`);
      break;
    }

    block = Block.fromRaw(blockData);
    old = OldUndoCoins.fromRaw(undoData);
    undo = new UndoCoins();

    for (let i = block.txs.length - 1; i >= 1; i--) {
      let tx = block.txs[i];
      for (let j = tx.inputs.length - 1; j >= 0; j--) {
        let {prevout} = tx.inputs[j];
        let coin = old.items.pop();
        let output = coin.toOutput();
        let version, height, write, item;

        assert(coin);

        [version, height, write] = await getMeta(coin, prevout);

        item = new CoinEntry();
        item.version = version;
        item.height = height;
        item.coinbase = coin.coinbase;
        item.output.script = output.script;
        item.output.value = output.value;
        item.spent = true;
        item.raw = null;

        // Store an index of heights and versions for later.
        if (write) {
          let data = Buffer.allocUnsafe(8);
          data.writeUInt32LE(version, 0, true);
          data.writeUInt32LE(height, 4, true);
          batch.put(pair(0x01, prevout.hash), data);
          heightCache.set(prevout.hash, [version, height]);
        }

        undo.items.push(item);
      }
    }

    batch.put(pair('u', tip.hash), undo.toRaw());

    if (++total % 10000 === 0) {
      console.log('Reserialized %d undo coins.', total);
      writeJournal(batch, STATE_UNDO, tip.prevBlock);
      await batch.write();
      heightCache.clear();
      batch = db.batch();
    }

    tip = await getEntry(tip.prevBlock);
  }

  writeJournal(batch, STATE_CLEANUP);
  await batch.write();

  heightCache.clear();

  console.log('Reserialized %d undo coins.', total);

  return [STATE_CLEANUP, encoding.NULL_HASH];
}

async function cleanupIndex() {
  let batch = db.batch();
  let total = 0;

  let iter = db.iterator({
    gte: pair(0x01, encoding.ZERO_HASH),
    lte: pair(0x01, encoding.MAX_HASH),
    keys: true
  });

  console.log('Removing txid->height undo index.');

  for (;;) {
    let item = await iter.next();

    if (!item)
      break;

    batch.del(item.key);

    if (++total % 100000 === 0) {
      console.log('Cleaned up %d undo records.', total);
      writeJournal(batch, STATE_CLEANUP);
      await batch.write();
      batch = db.batch();
    }
  }

  writeJournal(batch, STATE_COINS);
  await batch.write();

  console.log('Cleaned up %d undo records.', total);

  return [STATE_COINS, encoding.NULL_HASH];
}

async function reserializeCoins(hash) {
  let batch = db.batch();
  let start = true;
  let total = 0;

  let iter = db.iterator({
    gte: pair('c', hash),
    lte: pair('c', encoding.MAX_HASH),
    keys: true,
    values: true
  });

  if (hash !== encoding.NULL_HASH) {
    let item = await iter.next();
    if (!item)
      start = false;
  }

  console.log('Reserializing coins from %s.', util.revHex(hash));

  while (start) {
    let item = await iter.next();
    let update = false;
    let hash, old;

    if (!item)
      break;

    if (item.key.length !== 33)
      continue;

    hash = item.key.toString('hex', 1, 33);
    old = OldCoins.fromRaw(item.value, hash);

    for (let i = 0; i < old.outputs.length; i++) {
      let coin = old.getCoin(i);
      let item;

      if (!coin)
        continue;

      item = new CoinEntry();
      item.version = coin.version;
      item.height = coin.height;
      item.coinbase = coin.coinbase;
      item.output.script = coin.script;
      item.output.value = coin.value;
      item.spent = false;
      item.raw = null;

      batch.put(bpair('c', hash, i), item.toRaw());

      if (++total % 100000 === 0)
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

  return [STATE_ENTRY, encoding.NULL_HASH];
}

async function reserializeEntries(hash) {
  let tip = await getTipHash();
  let batch = db.batch();
  let start = true;
  let total = 0;

  let iter = db.iterator({
    gte: pair('e', hash),
    lte: pair('e', encoding.MAX_HASH),
    values: true
  });

  if (hash !== encoding.NULL_HASH) {
    let item = await iter.next();
    if (!item)
      start = false;
    else
      assert(item.key.equals(pair('e', hash)));
  }

  console.log('Reserializing entries from %s.', util.revHex(hash));

  while (start) {
    let item = await iter.next();
    let entry, main;

    if (!item)
      break;

    entry = entryFromRaw(item.value);
    main = await isMainChain(entry, tip);

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

  return [STATE_FINAL, encoding.NULL_HASH];
}

async function finalize() {
  let batch = db.batch();
  let data = Buffer.allocUnsafe(4);

  data.writeUInt32LE(3, 0, true);

  batch.del(JOURNAL_KEY);
  batch.put('V', data);

  console.log('Finalizing database.');

  await batch.write();

  console.log('Compacting database...');

  await db.compactRange();

  return [STATE_DONE, encoding.NULL_HASH];
}

async function getMeta(coin, prevout) {
  let item, data, coins;

  if (coin.height !== -1)
    return [coin.version, coin.height, true];

  item = heightCache.get(prevout.hash);

  if (item) {
    let [version, height] = item;
    return [version, height, false];
  }

  data = await db.get(pair(0x01, prevout.hash));

  if (data) {
    let version = data.readUInt32LE(0, true);
    let height = data.readUInt32LE(4, true);
    return [version, height, false];
  }

  data = await db.get(pair('c', prevout.hash));
  assert(data);

  coins = OldCoins.fromRaw(data, prevout.hash);

  return [coins.version, coins.height, true];
}

async function getTip() {
  let tip = await getTipHash();
  return await getEntry(tip);
}

async function getTipHash() {
  let state = await db.get('R');
  assert(state);
  return state.toString('hex', 0, 32);
}

async function getEntry(hash) {
  let data = await db.get(pair('e', hash));
  assert(data);
  return entryFromRaw(data);
}

async function isPruned() {
  let data = await db.get('O');
  assert(data);
  return (data.readUInt32LE(4) & 4) !== 0;
}

async function isMainChain(entry, tip) {
  if (entry.hash === tip)
    return true;

  if (await db.get(pair('n', entry.hash)))
    return true;

  return false;
}

function entryFromRaw(data) {
  let p = new BufferReader(data, true);
  let hash = digest.hash256(p.readBytes(80));
  let entry = {};

  p.seek(-80);

  entry.hash = hash.toString('hex');
  entry.version = p.readU32();
  entry.prevBlock = p.readHash('hex');
  entry.merkleRoot = p.readHash('hex');
  entry.ts = p.readU32();
  entry.bits = p.readU32();
  entry.nonce = p.readU32();
  entry.height = p.readU32();
  entry.chainwork = new BN(p.readBytes(32), 'le');

  return entry;
}

function entryToRaw(entry, main) {
  let bw = new StaticWriter(116 + 1);

  bw.writeU32(entry.version);
  bw.writeHash(entry.prevBlock);
  bw.writeHash(entry.merkleRoot);
  bw.writeU32(entry.ts);
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

function bpair(prefix, hash, index) {
  let key = Buffer.allocUnsafe(37);
  if (typeof prefix === 'string')
    prefix = prefix.charCodeAt(0);
  key[0] = prefix;
  write(key, hash, 1);
  key.writeUInt32BE(index, 33, true);
  return key;
}

(async () => {
  let state, hash;

  await db.open();

  console.log('Opened %s.', file);

  console.log('Starting migration in 3 seconds...');
  console.log('If you crash you can start over.');

  await co.timeout(3000);

  [state, hash] = await readJournal();

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
    [state, hash] = [STATE_FINAL, encoding.NULL_HASH];

  if (state === STATE_FINAL)
    [state, hash] = await finalize();

  assert(state === STATE_DONE);

  console.log('Closing %s.', file);

  await db.close();

  console.log('Migration complete.');
  process.exit(0);
})().catch((err) => {
  throw err;
});
