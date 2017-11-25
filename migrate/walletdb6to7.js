'use strict';

const assert = require('assert');
const BDB = require('bdb');
const bio = require('bufio');
const layouts = require('../lib/wallet/layout');
const TX = require('../lib/primitives/tx');
const Coin = require('../lib/primitives/coin');
const layout = layouts.walletdb;
const tlayout = layouts.txdb;
const {encoding} = bio;

// changes:
// headers - all headers
// block map - just a map
// input map - only on unconfirmed
// marked byte - no longer a soft fork
// coin `own` flag - no longer a soft fork
// tx map - for unconfirmed
// balances - index account balances

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

async function updateVersion() {
  const bak = `${process.env.HOME}/walletdb-bak-${Date.now()}.ldb`;

  console.log('Checking version.');

  const data = await db.get('V');
  assert(data, 'No version.');

  const ver = data.readUInt32LE(0, true);

  if (ver !== 6)
    throw Error(`DB is version ${ver}.`);

  console.log('Backing up DB to: %s.', bak);

  await db.backup(bak);

  const buf = Buffer.allocUnsafe(4);
  buf.writeUInt32LE(7, 0, true);
  batch.put('V', buf);
}

async function updateState() {
  const raw = await db.get(layout.R);

  if (!raw)
    return;

  if (raw.length === 40)
    batch.put(layout.R, c(raw, Buffer.from([1])));
}

async function updateBlockMap() {
  const iter = db.iterator({
    gte: layout.b(0),
    lte: layout.b(0xffffffff),
    keys: true,
    values: true
  });

  await iter.each((key, value) => {
    const height = layout.bb(key);
    const block = BlockMapRecord.fromRaw(height, value);
    const map = new Set();

    for (const tx of block.txs.values()) {
      for (const wid of tx.wids)
        map.add(wid);
    }

    const bw = bio.write(sizeMap(map));
    serializeMap(bw, map);

    batch.put(key, bw.render());
  });
}

async function updateTXDB() {
  const wids = await db.keys({
    gte: layout.w(0),
    lte: layout.w(0xffffffff),
    keys: true,
    parse: k => layout.ww(k)
  });

  for (const wid of wids) {
    await updateInputs(wid);
    await updateCoins(wid);
    await updateTX(wid);
    await updateWalletBalance(wid);
    await updateAccountBalances(wid);
  }
}

async function updateInputs(wid) {
  const pre = tlayout.prefix(wid);

  const iter = db.iterator({
    gte: c(pre, tlayout.h(0, encoding.NULL_HASH)),
    lte: c(pre, tlayout.h(0xffffffff, encoding.HIGH_HASH)),
    keys: true
  });

  await iter.each(async (k, value) => {
    const key = k.slice(pre.length);
    const [height, hash] = tlayout.hh(key);
    const data = await db.get(c(pre, tlayout.t(hash)));
    assert(data);
    const tx = TX.fromRaw(data);

    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;
      batch.del(c(pre, tlayout.s(hash, index)));
    }
  });
}

async function updateCoins(wid) {
  const pre = tlayout.prefix(wid);

  const iter = db.iterator({
    gte: c(pre, tlayout.c(encoding.NULL_HASH, 0)),
    lte: c(pre, tlayout.c(encoding.HIGH_HASH, 0xffffffff)),
    keys: true,
    values: true
  });

  await iter.each((key, value) => {
    const br = bio.read(value);

    Coin.fromReader(br);
    br.readU8();

    if (br.left() === 0)
      batch.put(key, c(value, Buffer.from([0])));
  });
}

async function updateTX(wid) {
  const pre = tlayout.prefix(wid);

  const iter = db.iterator({
    gte: c(pre, tlayout.p(encoding.NULL_HASH)),
    lte: c(pre, tlayout.p(encoding.HIGH_HASH)),
    keys: true
  });

  await iter.each(async (k, value) => {
    const key = k.slice(pre.length);
    const hash = tlayout.pp(key);
    const raw = await db.get(layout.T(hash));

    let map = null;

    if (!raw) {
      map = new Set();
    } else {
      const br = bio.read(raw);
      map = parseMap(br);
    }

    map.add(wid);

    const bw = bio.write(sizeMap(map));
    serializeMap(bw, map);
    batch.put(layout.T(hash), bw.render());
  });
}

async function updateWalletBalance(wid) {
  const pre = tlayout.prefix(wid);
  const bal = newBalance();

  const keys = await db.keys({
    gte: c(pre, tlayout.t(encoding.NULL_HASH)),
    lte: c(pre, tlayout.t(encoding.HIGH_HASH)),
    keys: true
  });

  bal.tx = keys.length;

  const iter = db.iterator({
    gte: c(pre, tlayout.c(encoding.NULL_HASH, 0)),
    lte: c(pre, tlayout.c(encoding.HIGH_HASH, 0xffffffff)),
    keys: true,
    values: true
  });

  await iter.each((key, value) => {
    const br = bio.read(value);
    const coin = Coin.fromReader(br);
    const spent = br.readU8() === 1;

    bal.coin += 1;

    if (coin.height !== -1)
      bal.confirmed += coin.value;

    if (!spent)
      bal.unconfirmed += coin.value;
  });

  batch.put(c(pre, tlayout.R), serializeBalance(bal));
}

async function updateAccountBalances(wid) {
  const raw = await db.get(layout.w(wid));
  assert(raw);

  const br = bio.read(raw);

  br.readU32();
  br.readU32();
  br.readVarString('ascii');
  br.readU8();
  br.readU8();

  const depth = br.readU32();

  for (let acct = 0; acct < depth; acct++)
    await updateAccountBalance(wid, acct);
}

async function updateAccountBalance(wid, acct) {
  const pre = tlayout.prefix(wid);
  const bal = newBalance();

  const keys = await db.keys({
    gte: c(pre, tlayout.T(acct, encoding.NULL_HASH)),
    lte: c(pre, tlayout.T(acct, encoding.HIGH_HASH)),
    keys: true
  });

  bal.tx = keys.length;

  const iter = db.iterator({
    gte: c(pre, tlayout.C(acct, encoding.NULL_HASH, 0)),
    lte: c(pre, tlayout.C(acct, encoding.HIGH_HASH, 0xffffffff)),
    keys: true
  });

  await iter.each(async (k, value) => {
    const key = k.slice(pre.length);
    const [, hash, index] = tlayout.Cc(key);
    const raw = await db.get(c(pre, tlayout.c(hash, index)));
    assert(raw);
    const br = bio.read(raw);
    const coin = Coin.fromReader(br);
    const spent = br.readU8() === 1;

    bal.coin += 1;

    if (coin.height !== -1)
      bal.confirmed += coin.value;

    if (!spent)
      bal.unconfirmed += coin.value;
  });

  batch.put(c(pre, tlayout.r(acct)), serializeBalance(bal));
}

/*
 * Old Records
 */

class BlockMapRecord {
  constructor(height) {
    this.height = height != null ? height : -1;
    this.txs = new Map();
  }

  fromRaw(data) {
    const br = bio.read(data);
    const count = br.readU32();

    for (let i = 0; i < count; i++) {
      const hash = br.readHash('hex');
      const tx = TXMapRecord.fromReader(hash, br);
      this.txs.set(tx.hash, tx);
    }

    return this;
  }

  static fromRaw(height, data) {
    return new BlockMapRecord(height).fromRaw(data);
  }

  getSize() {
    let size = 0;

    size += 4;

    for (const tx of this.txs.values()) {
      size += 32;
      size += tx.getSize();
    }

    return size;
  }

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);

    bw.writeU32(this.txs.size);

    for (const [hash, tx] of this.txs) {
      bw.writeHash(hash);
      tx.toWriter(bw);
    }

    return bw.render();
  }

  add(hash, wid) {
    let tx = this.txs.get(hash);

    if (!tx) {
      tx = new TXMapRecord(hash);
      this.txs.set(hash, tx);
    }

    return tx.add(wid);
  }

  remove(hash, wid) {
    const tx = this.txs.get(hash);

    if (!tx)
      return false;

    if (!tx.remove(wid))
      return false;

    if (tx.wids.size === 0)
      this.txs.delete(tx.hash);

    return true;
  }

  toArray() {
    const txs = [];

    for (const tx of this.txs.values())
      txs.push(tx);

    return txs;
  }
}

class TXMapRecord {
  constructor(hash, wids) {
    this.hash = hash || encoding.NULL_HASH;
    this.wids = wids || new Set();
  }

  add(wid) {
    if (this.wids.has(wid))
      return false;

    this.wids.add(wid);
    return true;
  }

  remove(wid) {
    return this.wids.delete(wid);
  }

  toWriter(bw) {
    return serializeMap(bw, this.wids);
  }

  getSize() {
    return sizeMap(this.wids);
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  fromReader(br) {
    this.wids = parseMap(br);
    return this;
  }

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(hash, br) {
    return new TXMapRecord(hash).fromReader(br);
  }

  static fromRaw(hash, data) {
    return new TXMapRecord(hash).fromRaw(data);
  }
}

function parseMap(br) {
  const count = br.readU32();
  const wids = new Set();

  for (let i = 0; i < count; i++)
    wids.add(br.readU32());

  return wids;
}

function sizeMap(wids) {
  return 4 + wids.size * 4;
}

function serializeMap(bw, wids) {
  bw.writeU32(wids.size);

  for (const wid of wids)
    bw.writeU32(wid);

  return bw;
}

/*
 * Helpers
 */

function c(a, b) {
  return Buffer.concat([a, b]);
}

function newBalance() {
  return {
    tx: 0,
    coin: 0,
    unconfirmed: 0,
    confirmed: 0
  };
}

function serializeBalance(bal) {
  const bw = bio.write(32);

  bw.writeU64(bal.tx);
  bw.writeU64(bal.coin);
  bw.writeU64(bal.unconfirmed);
  bw.writeU64(bal.confirmed);

  return bw.render();
}

/*
 * Execute
 */

(async () => {
  await db.open();

  console.log('Opened %s.', file);

  batch = db.batch();

  await updateVersion();
  await updateState();
  await updateBlockMap();
  await updateTXDB();

  await batch.write();
  await db.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
});
