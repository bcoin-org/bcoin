'use strict';

const assert = require('assert');
const bcoin = require('../');
const encoding = require('../lib/utils/encoding');
const BufferWriter = require('../lib/utils/writer');
const BufferReader = require('../lib/utils/reader');
let file = process.argv[2];
let db, batch;

assert(typeof file === 'string', 'Please pass in a database path.');

file = file.replace(/\.ldb\/?$/, '');

db = bcoin.ldb({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false,
  bufferKeys: true
});

async function updateVersion() {
  let bak = `${process.env.HOME}/walletdb-bak-${Date.now()}.ldb`;
  let data, ver;

  console.log('Checking version.');

  data = await db.get('V');
  assert(data, 'No version.');

  ver = data.readUInt32LE(0, true);

  if (ver !== 5)
    throw Error(`DB is version ${ver}.`);

  console.log('Backing up DB to: %s.', bak);

  await db.backup(bak);

  ver = Buffer.allocUnsafe(4);
  ver.writeUInt32LE(6, 0, true);
  batch.put('V', ver);
}

async function wipeTXDB() {
  let total = 0;
  let i, keys, key;

  keys = await db.keys({
    gte: Buffer.from([0x00]),
    lte: Buffer.from([0xff])
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    switch (key[0]) {
      case 0x62: // b
      case 0x63: // c
      case 0x65: // e
      case 0x74: // t
      case 0x6f: // o
      case 0x68: // h
        batch.del(key);
        total++;
        break;
    }
  }

  batch.del(Buffer.from([0x52])); // R

  console.log('Wiped %d txdb records.', total);
}

async function patchAccounts() {
  let i, items, item, wid, index, account;

  items = await db.range({
    gte: Buffer.from('610000000000000000', 'hex'), // a
    lte: Buffer.from('61ffffffffffffffff', 'hex')  // a
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    wid = item.key.readUInt32BE(1, true);
    index = item.key.readUInt32BE(5, true);
    account = accountFromRaw(item.value);
    console.log('a[%d][%d] -> lookahead=%d', wid, index, account.lookahead);
    batch.put(item.key, accountToRaw(account));
    console.log('n[%d][%d] -> %s', wid, index, account.name);
    batch.put(n(wid, index), Buffer.from(account.name, 'ascii'));
  }
}

async function indexPaths() {
  let i, items, item, wid, index, hash;

  items = await db.range({
    gte: Buffer.from('5000000000' + encoding.NULL_HASH, 'hex'), // P
    lte: Buffer.from('50ffffffff' + encoding.HIGH_HASH, 'hex')  // P
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    wid = item.key.readUInt32BE(1, true);
    hash = item.key.toString('hex', 5);
    index = item.value.readUInt32LE(0, true);
    console.log('r[%d][%d][%s] -> NUL', wid, index, hash);
    batch.put(r(wid, index, hash), Buffer.from([0]));
  }
}

async function patchPathMaps() {
  let i, items, item, hash, wids;

  items = await db.range({
    gte: Buffer.from('70' + encoding.NULL_HASH, 'hex'), // p
    lte: Buffer.from('70' + encoding.HIGH_HASH, 'hex')  // p
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    hash = item.key.toString('hex', 1);
    wids = parseWallets(item.value);
    console.log('p[%s] -> u32(%d)', hash, wids.length);
    batch.put(item.key, serializeWallets(wids));
  }
}

function parseWallets(data) {
  let p = new BufferReader(data);
  let wids = [];

  while (p.left())
    wids.push(p.readU32());

  return wids;
}

function serializeWallets(wids) {
  let p = new BufferWriter();
  let i, wid;

  p.writeU32(wids.length);

  for (i = 0; i < wids.length; i++) {
    wid = wids[i];
    p.writeU32(wid);
  }

  return p.render();
}

function accountToRaw(account) {
  let p = new BufferWriter();
  let i, key;

  p.writeVarString(account.name, 'ascii');
  p.writeU8(account.initialized ? 1 : 0);
  p.writeU8(account.witness ? 1 : 0);
  p.writeU8(account.type);
  p.writeU8(account.m);
  p.writeU8(account.n);
  p.writeU32(account.accountIndex);
  p.writeU32(account.receiveDepth);
  p.writeU32(account.changeDepth);
  p.writeU32(account.nestedDepth);
  p.writeU8(account.lookahead);
  p.writeBytes(account.accountKey);
  p.writeU8(account.keys.length);

  for (i = 0; i < account.keys.length; i++) {
    key = account.keys[i];
    p.writeBytes(key);
  }

  return p.render();
};

function accountFromRaw(data) {
  let account = {};
  let p = new BufferReader(data);
  let i, count, key;

  account.name = p.readVarString('ascii');
  account.initialized = p.readU8() === 1;
  account.witness = p.readU8() === 1;
  account.type = p.readU8();
  account.m = p.readU8();
  account.n = p.readU8();
  account.accountIndex = p.readU32();
  account.receiveDepth = p.readU32();
  account.changeDepth = p.readU32();
  account.nestedDepth = p.readU32();
  account.lookahead = 10;
  account.accountKey = p.readBytes(82);
  account.keys = [];

  count = p.readU8();

  for (i = 0; i < count; i++) {
    key = p.readBytes(82);
    account.keys.push(key);
  }

  return account;
}

function n(wid, index) {
  let key = Buffer.allocUnsafe(9);
  key[0] = 0x6e;
  key.writeUInt32BE(wid, 1, true);
  key.writeUInt32BE(index, 5, true);
  return key;
}

function r(wid, index, hash) {
  let key = Buffer.allocUnsafe(1 + 4 + 4 + (hash.length / 2));
  key[0] = 0x72;
  key.writeUInt32BE(wid, 1, true);
  key.writeUInt32BE(index, 5, true);
  key.write(hash, 9, 'hex');
  return key;
}

async function updateLookahead() {
  let WalletDB = require('../lib/wallet/walletdb');
  let i, j, db, wallet;

  db = new WalletDB({
    network: process.argv[3],
    db: 'leveldb',
    location: file,
    witness: false,
    useCheckpoints: false,
    maxFiles: 64,
    resolution: false,
    verify: false
  });

  await db.open();

  for (i = 1; i < db.depth; i++) {
    wallet = await db.get(i);
    assert(wallet);
    console.log('Updating wallet lookahead: %s', wallet.id);
    for (j = 0; j < wallet.accountDepth; j++)
      await wallet.setLookahead(j, 20);
  }

  await db.close();
}

async function unstate() {
  await db.open();
  batch = db.batch();
  await wipeTXDB();
  await batch.write();
  await db.close();
}

(async () => {
  await db.open();
  batch = db.batch();
  console.log('Opened %s.', file);
  await updateVersion();
  await wipeTXDB();
  await patchAccounts();
  await indexPaths();
  await patchPathMaps();
  await batch.write();
  await db.close();

  // Do not use:
  await updateLookahead();
  await unstate();
})().then(() => {
  console.log('Migration complete.');
  console.log('Rescan is required...');
  console.log('Start bcoin with `--start-height=[wallet-creation-height]`.');
  process.exit(0);
});
