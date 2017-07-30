'use strict';

const assert = require('assert');
const bcoin = require('../');
const encoding = require('../lib/utils/encoding');
const BufferWriter = require('../lib/utils/writer');
const BufferReader = require('../lib/utils/reader');
let file = process.argv[2];
let batch;

assert(typeof file === 'string', 'Please pass in a database path.');

file = file.replace(/\.ldb\/?$/, '');

const db = bcoin.ldb({
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

  let ver = data.readUInt32LE(0, true);

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

  const keys = await db.keys({
    gte: Buffer.from([0x00]),
    lte: Buffer.from([0xff])
  });

  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
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
  const items = await db.range({
    gte: Buffer.from('610000000000000000', 'hex'), // a
    lte: Buffer.from('61ffffffffffffffff', 'hex')  // a
  });

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const wid = item.key.readUInt32BE(1, true);
    const index = item.key.readUInt32BE(5, true);
    const account = accountFromRaw(item.value);
    console.log('a[%d][%d] -> lookahead=%d', wid, index, account.lookahead);
    batch.put(item.key, accountToRaw(account));
    console.log('n[%d][%d] -> %s', wid, index, account.name);
    batch.put(n(wid, index), Buffer.from(account.name, 'ascii'));
  }
}

async function indexPaths() {
  const items = await db.range({
    gte: Buffer.from('5000000000' + encoding.NULL_HASH, 'hex'), // P
    lte: Buffer.from('50ffffffff' + encoding.HIGH_HASH, 'hex')  // P
  });

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const wid = item.key.readUInt32BE(1, true);
    const hash = item.key.toString('hex', 5);
    const index = item.value.readUInt32LE(0, true);
    console.log('r[%d][%d][%s] -> NUL', wid, index, hash);
    batch.put(r(wid, index, hash), Buffer.from([0]));
  }
}

async function patchPathMaps() {
  const items = await db.range({
    gte: Buffer.from('70' + encoding.NULL_HASH, 'hex'), // p
    lte: Buffer.from('70' + encoding.HIGH_HASH, 'hex')  // p
  });

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const hash = item.key.toString('hex', 1);
    const wids = parseWallets(item.value);
    console.log('p[%s] -> u32(%d)', hash, wids.length);
    batch.put(item.key, serializeWallets(wids));
  }
}

function parseWallets(data) {
  const p = new BufferReader(data);
  const wids = [];

  while (p.left())
    wids.push(p.readU32());

  return wids;
}

function serializeWallets(wids) {
  const p = new BufferWriter();

  p.writeU32(wids.length);

  for (let i = 0; i < wids.length; i++) {
    const wid = wids[i];
    p.writeU32(wid);
  }

  return p.render();
}

function accountToRaw(account) {
  const p = new BufferWriter();

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

  for (let i = 0; i < account.keys.length; i++) {
    const key = account.keys[i];
    p.writeBytes(key);
  }

  return p.render();
};

function accountFromRaw(data) {
  const account = {};
  const p = new BufferReader(data);

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

  const count = p.readU8();

  for (let i = 0; i < count; i++) {
    const key = p.readBytes(82);
    account.keys.push(key);
  }

  return account;
}

function n(wid, index) {
  const key = Buffer.allocUnsafe(9);
  key[0] = 0x6e;
  key.writeUInt32BE(wid, 1, true);
  key.writeUInt32BE(index, 5, true);
  return key;
}

function r(wid, index, hash) {
  const key = Buffer.allocUnsafe(1 + 4 + 4 + (hash.length / 2));
  key[0] = 0x72;
  key.writeUInt32BE(wid, 1, true);
  key.writeUInt32BE(index, 5, true);
  key.write(hash, 9, 'hex');
  return key;
}

async function updateLookahead() {
  const WalletDB = require('../lib/wallet/walletdb');

  const db = new WalletDB({
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

  for (let i = 1; i < db.depth; i++) {
    const wallet = await db.get(i);
    assert(wallet);
    console.log('Updating wallet lookahead: %s', wallet.id);
    for (let j = 0; j < wallet.accountDepth; j++)
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
