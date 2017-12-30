'use strict';

const assert = require('assert');
const bdb = require('bdb');
const bio = require('bufio');
const layouts = require('../lib/wallet/layout');
const TX = require('../lib/primitives/tx');
const Coin = require('../lib/primitives/coin');
const layout = layouts.wdb;
const tlayout = layouts.txdb;

// changes:
// db version record
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
// depth - counter record
// hash/ascii - variable length key prefixes

let parent = null;

assert(process.argv.length > 2, 'Please pass in a database path.');

const db = bdb.create({
  location: process.argv[2],
  memory: false,
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false
});

async function updateVersion() {
  const bak = `${process.env.HOME}/wallet-bak-${Date.now()}`;

  console.log('Checking version.');

  const data = await db.get(layout.V.build());
  assert(data, 'No version.');

  const ver = data.readUInt32LE(0, true);

  if (ver !== 6)
    throw Error(`DB is version ${ver}.`);

  console.log('Backing up DB to: %s.', bak);
  console.log('Updating version to %d.', ver + 1);

  await db.backup(bak);

  const buf = Buffer.allocUnsafe(6 + 4);
  buf.write('wallet', 0, 'ascii');
  buf.writeUInt32LE(7, 6, true);

  parent.put(layout.V.build(), buf);
}

async function migrateKeys(id, from, to) {
  console.log('Migrating keys for %s.', String.fromCharCode(id));

  const iter = db.iterator({
    gt: Buffer.from([id]),
    lt: Buffer.from([id + 1]),
    keys: true,
    values: true
  });

  let batch = db.batch();
  let total = 0;
  let items = 0;

  await iter.each(async (key, value) => {
    batch.put(to.build(...from(key)), value);
    batch.del(key);

    total += (key.length + 80) * 2;
    total += value.length + 80;
    items += 1;

    if (total >= (128 << 20)) {
      await batch.write();
      batch = db.batch();
      total = 0;
    }
  });

  console.log('Migrated %d keys for %s.', items, String.fromCharCode(id));

  return batch.write();
}

async function updateKeys() {
  console.log('Updating keys...');

  await migrateKeys(0x70, parsep, layout.p); // p
  await migrateKeys(0x50, parseP, layout.P); // P
  await migrateKeys(0x72, parser, layout.r); // r
  await migrateKeys(0x6c, parsel, layout.l); // l
  await migrateKeys(0x69, parsei, layout.i); // i

  console.log('Updated keys.');
}

async function updateState() {
  const raw = await db.get(layout.R.build());

  if (!raw)
    return;

  console.log('Updating state...');

  if (raw.length === 40) {
    const bw = bio.write(41);
    bw.writeBytes(raw);
    bw.writeU8(1);
    parent.put(layout.R.build(), bw.render());
    console.log('State updated.');
  }

  const depth = await getDepth();

  const buf = Buffer.allocUnsafe(4);
  buf.writeUInt32LE(depth, 0, true);

  parent.put(layout.D.build(), buf);
}

async function updateBlockMap() {
  const iter = db.iterator({
    gte: layout.b.min(),
    lte: layout.b.max(),
    keys: true,
    values: true
  });

  console.log('Updating block map...');

  let total = 0;

  await iter.each((key, value) => {
    const height = layout.b.parse(key);
    const block = BlockMapRecord.fromRaw(height, value);
    const map = new Set();

    for (const tx of block.txs.values()) {
      for (const wid of tx.wids)
        map.add(wid);
    }

    const bw = bio.write(sizeMap(map));
    serializeMap(bw, map);

    parent.put(key, bw.render());

    total += 1;
  });

  console.log('Updated %d block maps.', total);
}

async function updateTXDB() {
  const wids = await db.keys({
    gte: layout.w.min(),
    lte: layout.w.max(),
    keys: true,
    parse: key => layout.w.parse(key)
  });

  console.log('Updating wallets...');

  let total = 0;

  for (const wid of wids) {
    const bucket = db.bucket(layout.t.build(wid));
    const batch = bucket.wrap(parent);

    await updateInputs(wid, bucket, batch);
    await updateCoins(wid, bucket, batch);
    await updateTX(wid, bucket, batch);
    await updateWalletBalance(wid, bucket, batch);
    await updateAccountBalances(wid, bucket, batch);
    await updateWallet(wid);

    total += 1;
  }

  console.log('Updated %d wallets.', total);
}

async function updateInputs(wid, bucket, batch) {
  const iter = bucket.iterator({
    gte: tlayout.h.min(),
    lte: tlayout.h.max(),
    keys: true
  });

  console.log('Updating inputs for %d...', wid);

  let total = 0;

  await iter.each(async (key, value) => {
    const [, hash] = tlayout.h.parse(key);
    const data = await bucket.get(tlayout.t.build(hash));
    assert(data);
    const tx = TX.fromRaw(data);

    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;
      batch.del(tlayout.s.build(hash, index));
      total += 1;
    }
  });

  console.log('Updated %d inputs for %d.', total, wid);
}

async function updateCoins(wid, bucket, batch) {
  const iter = bucket.iterator({
    gte: tlayout.c.min(),
    lte: tlayout.c.max(),
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
      const bw = bio.write(value.length + 1);
      bw.writeBytes(value);
      bw.writeU8(0);
      batch.put(key, bw.render());
      total += 1;
    }
  });

  console.log('Updated %d coins for %d.', total, wid);
}

async function updateTX(wid, bucket, batch) {
  const iter = bucket.iterator({
    gte: tlayout.p.min(),
    lte: tlayout.p.max(),
    keys: true
  });

  console.log('Adding TX maps for %d...', wid);

  let total = 0;

  await iter.each(async (key, value) => {
    const hash = tlayout.p.parse(key);
    const raw = await db.get(layout.T.build(hash));

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
    batch.put(layout.T.build(hash), bw.render());

    total += 1;
  });

  console.log('Added %d TX maps for %d.', total, wid);
}

async function updateWalletBalance(wid, bucket, batch) {
  const bal = newBalance();

  const keys = await bucket.keys({
    gte: tlayout.t.min(),
    lte: tlayout.t.max(),
    keys: true
  });

  bal.tx = keys.length;

  const iter = bucket.iterator({
    gte: tlayout.c.min(),
    lte: tlayout.c.max(),
    keys: true,
    values: true
  });

  console.log('Updating wallet balance for %d...', wid);

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

  batch.put(tlayout.R.build(), serializeBalance(bal));

  console.log('Updated wallet balance for %d.', wid);
}

async function updateAccountBalances(wid, bucket, batch) {
  const raw = await db.get(layout.w.build(wid));
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
    await updateAccountBalance(wid, acct, bucket, batch);

  console.log('Updated %d account balances for %d.', depth, wid);
}

async function updateAccountBalance(wid, acct, bucket, batch) {
  const bal = newBalance();

  const keys = await bucket.keys({
    gte: tlayout.T.min(acct),
    lte: tlayout.T.max(acct),
    keys: true
  });

  bal.tx = keys.length;

  const iter = bucket.iterator({
    gte: tlayout.C.min(acct),
    lte: tlayout.C.max(acct),
    keys: true
  });

  console.log('Updating account balance for %d/%d...', wid, acct);

  await iter.each(async (key, value) => {
    const [, hash, index] = tlayout.C.parse(key);
    const raw = await bucket.get(tlayout.c.build(hash, index));
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

  batch.put(tlayout.r.build(acct), serializeBalance(bal));

  console.log('Updated account balance for %d/%d.', wid, acct);
}

async function updateWallet(wid) {
  const raw = await db.get(layout.w.build(wid));
  assert(raw);

  console.log('Updating wallet: %d.', wid);

  const br = bio.read(raw, true);

  br.readU32(); // Skip network.
  br.readU32(); // Skip wid.
  const id = br.readVarString('ascii');
  br.readU8(); // Skip initialized.
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
  bw.writeU8(flags);
  bw.writeU32(accountDepth);
  bw.writeBytes(token);
  bw.writeU32(tokenDepth);
  bw.writeBytes(key);

  parent.put(layout.w.build(wid), bw.render());
  parent.put(layout.W.build(wid), fromString(id));

  console.log('Updating accounts for %d...', wid);

  for (let acct = 0; acct < accountDepth; acct++)
    await updateAccount(wid, acct);

  console.log('Updated %d accounts for %d.', accountDepth, wid);

  console.log('Updated wallet: %d.', wid);
}

async function updateAccount(wid, acct) {
  const raw = await db.get(layout.a.build(wid, acct));
  assert(raw);

  console.log('Updating account: %d/%d...', wid, acct);

  const br = bio.read(raw, true);

  const name = br.readVarString('ascii');
  const initialized = br.readU8() === 1;
  const witness = br.readU8() === 1;
  const type = br.readU8();
  const m = br.readU8();
  const n = br.readU8();
  br.readU32(); // accountIndex
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

  parent.put(layout.a.build(wid, acct), bw.render());
  parent.put(layout.n.build(wid, acct), fromString(name));

  console.log('Updated account: %d/%d.', wid, acct);
}

async function updatePaths() {
  const iter = db.iterator({
    gte: layout.P.min(),
    lte: layout.P.max(),
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

    parent.put(key, bw.render());

    total += 1;
  });

  console.log('Updated %d paths.', total);
}

async function getDepth() {
  const iter = db.iterator({
    gte: layout.w.min(),
    lte: layout.w.max(),
    reverse: true,
    limit: 1
  });

  if (!await iter.next())
    return 1;

  const {key} = iter;

  await iter.end();

  const depth = layout.w.parse(key);

  return depth + 1;
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
    this.hash = hash || null;
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

function parsep(key) { // p[hash]
  assert(Buffer.isBuffer(key));
  assert(key.length >= 21);
  return [key.toString('hex', 1)];
}

function parseP(key) { // P[wid][hash]
  assert(Buffer.isBuffer(key));
  assert(key.length >= 25);
  return [key.readUInt32BE(1, true), key.toString('hex', 5)];
}

function parser(key) { // r[wid][index][hash]
  assert(Buffer.isBuffer(key));
  assert(key.length >= 29);
  return [
    key.readUInt32BE(1, true),
    key.readUInt32BE(5, true),
    key.toString('hex', 9)
  ];
}

function parsel(key) { // l[id]
  assert(Buffer.isBuffer(key));
  assert(key.length >= 1);
  return [key.toString('ascii', 1)];
}

function parsei(key) { // i[wid][name]
  assert(Buffer.isBuffer(key));
  assert(key.length >= 5);
  return [key.readUInt32BE(1, true), key.toString('ascii', 5)];
}

function fromString(str) {
  const buf = Buffer.alloc(1 + str.length);
  buf[0] = str.length;
  buf.write(str, 1, str.length, 'ascii');
  return buf;
}

/*
 * Execute
 */

(async () => {
  await db.open();

  console.log('Opened %s.', process.argv[2]);

  parent = db.batch();

  await updateVersion();
  await updateKeys();
  await updateState();
  await updateBlockMap();
  await updateTXDB();
  await updatePaths();

  await parent.write();
  await db.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
}).catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
