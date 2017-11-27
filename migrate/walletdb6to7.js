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
// wallet - serialization
// account - serialization
// path - serialization

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

  console.log('Updating state...');

  if (raw.length === 40) {
    batch.put(layout.R, c(raw, Buffer.from([1])));
    console.log('State updated.');
  }
}

async function updateBlockMap() {
  const iter = db.iterator({
    gte: layout.b(0),
    lte: layout.b(0xffffffff),
    keys: true,
    values: true
  });

  console.log('Updating block map...');

  let total = 0;

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

    total += 1;
  });

  console.log('Updated %d block maps.', total);
}

async function updateTXDB() {
  const wids = await db.keys({
    gte: layout.w(0),
    lte: layout.w(0xffffffff),
    keys: true,
    parse: k => layout.ww(k)
  });

  console.log('Updating wallets...');

  let total = 0;

  for (const wid of wids) {
    await updateInputs(wid);
    await updateCoins(wid);
    await updateTX(wid);
    await updateWalletBalance(wid);
    await updateAccountBalances(wid);
    await updateWallet(wid);
    total += 1;
  }

  console.log('Updated %d wallets.', total);
}

async function updateInputs(wid) {
  const pre = tlayout.prefix(wid);

  const iter = db.iterator({
    gte: c(pre, tlayout.h(0, encoding.NULL_HASH)),
    lte: c(pre, tlayout.h(0xffffffff, encoding.HIGH_HASH)),
    keys: true
  });

  console.log('Updating inputs for %d.', wid);

  let total = 0;

  await iter.each(async (k, value) => {
    const key = k.slice(pre.length);
    const [height, hash] = tlayout.hh(key);
    const data = await db.get(c(pre, tlayout.t(hash)));
    assert(data);
    const tx = TX.fromRaw(data);

    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;
      batch.del(c(pre, tlayout.s(hash, index)));
      total += 1;
    }
  });

  console.log('Updated %d inputs for %d.', total, wid);
}

async function updateCoins(wid) {
  const pre = tlayout.prefix(wid);

  const iter = db.iterator({
    gte: c(pre, tlayout.c(encoding.NULL_HASH, 0)),
    lte: c(pre, tlayout.c(encoding.HIGH_HASH, 0xffffffff)),
    keys: true,
    values: true
  });

  console.log('Updating coins for %d...', wid);

  let total = 0;

  await iter.each((key, value) => {
    const br = bio.read(value, true);

    Coin.fromReader(br);
    br.readU8();

    if (br.left() === 0) {
      batch.put(key, c(value, Buffer.from([0])));
      total += 1;
    }
  });

  console.log('Updated %d coins for %d.', total, wid);
}

async function updateTX(wid) {
  const pre = tlayout.prefix(wid);

  const iter = db.iterator({
    gte: c(pre, tlayout.p(encoding.NULL_HASH)),
    lte: c(pre, tlayout.p(encoding.HIGH_HASH)),
    keys: true
  });

  console.log('Adding TX maps for %d...', wid);

  let total = 0;

  await iter.each(async (k, value) => {
    const key = k.slice(pre.length);
    const hash = tlayout.pp(key);
    const raw = await db.get(layout.T(hash));

    let map = null;

    if (!raw) {
      map = new Set();
    } else {
      const br = bio.read(raw, true);
      map = parseMap(br);
    }

    map.add(wid);

    const bw = bio.write(sizeMap(map));
    serializeMap(bw, map);
    batch.put(layout.T(hash), bw.render());

    total += 1;
  });

  console.log('Added %d TX maps for %d.', total, wid);
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

  console.log('Updating wallet balance for %d.', wid);

  await iter.each((key, value) => {
    const br = bio.read(value, true);
    const coin = Coin.fromReader(br);
    const spent = br.readU8() === 1;

    bal.coin += 1;

    if (coin.height !== -1)
      bal.confirmed += coin.value;

    if (!spent)
      bal.unconfirmed += coin.value;
  });

  batch.put(c(pre, tlayout.R), serializeBalance(bal));

  console.log('Updated wallet balance for %d.', wid);
}

async function updateAccountBalances(wid) {
  const raw = await db.get(layout.w(wid));
  assert(raw);

  const br = bio.read(raw, true);

  br.readU32();
  br.readU32();
  br.readVarString('ascii');
  br.readU8();
  br.readU8();

  const depth = br.readU32();

  console.log('Updating account balances for %d...', wid);

  for (let acct = 0; acct < depth; acct++)
    await updateAccountBalance(wid, acct);

  console.log('Updated %d account balances for %d.', depth, wid);
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

  console.log('Updating account balance for %d/%d...', wid, acct);

  await iter.each(async (k, value) => {
    const key = k.slice(pre.length);
    const [, hash, index] = tlayout.Cc(key);
    const raw = await db.get(c(pre, tlayout.c(hash, index)));
    assert(raw);
    const br = bio.read(raw, true);
    const coin = Coin.fromReader(br);
    const spent = br.readU8() === 1;

    bal.coin += 1;

    if (coin.height !== -1)
      bal.confirmed += coin.value;

    if (!spent)
      bal.unconfirmed += coin.value;
  });

  batch.put(c(pre, tlayout.r(acct)), serializeBalance(bal));

  console.log('Updated account balance for %d/%d.', wid, acct);
}

async function updateWallet(wid) {
  const raw = await db.get(layout.w(wid));
  assert(raw);

  console.log('Updating wallet: %d.', wid);

  const br = bio.read(raw, true);

  br.readU32(); // Skip network.
  br.readU32(); // Skip wid.
  const id = br.readVarString('ascii');
  const initialized = br.readU8() === 1;
  const watchOnly = br.readU8() === 1;
  const accountDepth = br.readU32();
  const token = br.readBytes(32);
  const tokenDepth = br.readU32();

  // We want to get the key
  // _out of_ varint serialization.
  let key = br.readVarBytes();

  const kr = bio.read(key, true);

  // Unencrypted?
  if (kr.readU8() === 0) {
    const bw = bio.write();
    bw.writeU8(0);

    // Skip useless varint.
    kr.readVarint();

    // Skip HD key params.
    kr.seek(13);

    // Read/write chain code.
    bw.writeBytes(kr.readBytes(32));

    // Skip zero byte.
    assert(kr.readU8() === 0);

    // Read/write private key.
    bw.writeBytes(kr.readBytes(32));

    // Skip checksum.
    kr.seek(4);

    // Include mnemonic.
    if (kr.readU8() === 1) {
      bw.writeU8(1);
      const bits = kr.readU16();
      assert(bits % 32 === 0);
      const lang = kr.readU8();
      const entropy = kr.readBytes(bits / 8);

      bw.writeU16(bits);
      bw.writeU8(lang);
      bw.writeBytes(entropy);
    } else {
      bw.writeU8(0);
    }

    key = bw.render();
  }

  let flags = 0;

  if (watchOnly)
    flags |= 1;

  // Concatenate wallet with key.
  const bw = bio.write();
  bw.writeU32(wid);
  bw.writeVarString(id, 'ascii');
  bw.writeU8(flags);
  bw.writeU32(accountDepth);
  bw.writeBytes(token);
  bw.writeU32(tokenDepth);
  bw.writeBytes(key);

  batch.put(layout.w(wid), bw.render());

  console.log('Updating accounts for %d...', wid);

  for (let acct = 0; acct < accountDepth; acct++)
    await updateAccount(wid, acct);

  console.log('Updated %d accounts for %d.', accountDepth, wid);

  console.log('Updated wallet: %d.', wid);
}

async function updateAccount(wid, acct) {
  const raw = await db.get(layout.a(wid, acct));
  assert(raw);

  console.log('Updating account: %d/%d...', wid, acct);

  const br = bio.read(raw, true);

  const name = br.readVarString('ascii');
  const initialized = br.readU8() === 1;
  const witness = br.readU8() === 1;
  const type = br.readU8();
  const m = br.readU8();
  const n = br.readU8();
  const accountIndex = br.readU32();
  const receiveDepth = br.readU32();
  const changeDepth = br.readU32();
  const nestedDepth = br.readU32();
  const lookahead = br.readU8();
  const accountKey = {
    network: br.readU32BE(),
    depth: br.readU8(),
    parentFingerPrint: br.readU32BE(),
    childIndex: br.readU32BE(),
    chainCode: br.readBytes(32),
    publicKey: br.readBytes(33),
    checksum: br.readU32()
  };

  const count = br.readU8();

  const keys = [];

  for (let i = 0; i < count; i++) {
    const key = {
      network: br.readU32BE(),
      depth: br.readU8(),
      parentFingerPrint: br.readU32BE(),
      childIndex: br.readU32BE(),
      chainCode: br.readBytes(32),
      publicKey: br.readBytes(33),
      checksum: br.readU32()
    };
    keys.push(key);
  }

  const bw = bio.write();

  let flags = 0;

  if (initialized)
    flags |= 1;

  if (witness)
    flags |= 2;

  bw.writeU32(accountIndex);
  bw.writeVarString(name, 'ascii');
  bw.writeU8(flags);
  bw.writeU8(type);
  bw.writeU8(m);
  bw.writeU8(n);
  bw.writeU32(receiveDepth);
  bw.writeU32(changeDepth);
  bw.writeU32(nestedDepth);
  bw.writeU8(lookahead);

  bw.writeU8(accountKey.depth);
  bw.writeU32BE(accountKey.parentFingerPrint);
  bw.writeU32BE(accountKey.childIndex);
  bw.writeBytes(accountKey.chainCode);
  bw.writeBytes(accountKey.publicKey);

  bw.writeU8(keys.length);

  for (const key of keys) {
    bw.writeU8(key.depth);
    bw.writeU32BE(key.parentFingerPrint);
    bw.writeU32BE(key.childIndex);
    bw.writeBytes(key.chainCode);
    bw.writeBytes(key.publicKey);
  }

  batch.put(layout.a(wid, acct), bw.render());

  console.log('Updated account: %d/%d.', wid, acct);
}

async function updatePaths() {
  const iter = db.iterator({
    gte: layout.P(0, encoding.NULL_HASH),
    lte: layout.P(0xffffffff, encoding.HIGH_HASH),
    keys: true,
    values: true
  });

  console.log('Updating paths....');

  let total = 0;

  await iter.each((key, value) => {
    const br = bio.read(value, true);

    const account = br.readU32();
    const keyType = br.readU8();

    let branch = -1;
    let index = -1;
    let encrypted = false;
    let data = null;

    switch (keyType) {
      case 0:
        branch = br.readU32();
        index = br.readU32();
        break;
      case 1:
        encrypted = br.readU8() === 1;
        data = br.readVarBytes();
        break;
      case 2:
        break;
      default:
        assert(false);
        break;
    }

    let version = br.readI8();

    let type = br.readU8();

    if (type === 129 || type === 130)
      type = 4;

    type -= 2;

    const bw = bio.write();

    bw.writeU32(account);
    bw.writeU8(keyType);

    if (version === -1)
      version = 0x1f;

    const flags = (version << 3) | type;

    bw.writeU8(flags);

    switch (keyType) {
      case 0:
        assert(!data);
        assert(index !== -1);
        bw.writeU32(branch);
        bw.writeU32(index);
        break;
      case 1:
        assert(data);
        assert(index === -1);
        bw.writeU8(encrypted ? 1 : 0);
        bw.writeVarBytes(data);
        break;
      case 2:
        assert(!data);
        assert(index === -1);
        break;
      default:
        assert(false);
        break;
    }

    batch.put(key, bw.render());

    total += 1;
  });

  console.log('Updated %d paths.', total);
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
  await updatePaths();

  await batch.write();
  await db.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
}).catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
