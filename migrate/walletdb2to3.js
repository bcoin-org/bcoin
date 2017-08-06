'use strict';

const assert = require('assert');
const bcoin = require('../');
const walletdb = require('../lib/wallet/walletdb');
const encoding = require('../lib/utils/encoding');
const Path = require('../lib/wallet/path');
const MasterKey = require('../lib/wallet/masterkey');
const Account = require('../lib/wallet/account');
const Wallet = require('../lib/wallet/wallet');
const KeyRing = require('../lib/primitives/keyring');
const BufferReader = require('../lib/utils/reader');
const BufferWriter = require('../lib/utils/writer');
const layout = walletdb.layout;
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

  if (ver !== 2)
    throw Error(`DB is version ${ver}.`);

  console.log('Backing up DB to: %s.', bak);

  await db.backup(bak);

  ver = Buffer.allocUnsafe(4);
  ver.writeUInt32LE(3, 0, true);
  batch.put('V', ver);
}

async function updatePathMap() {
  let total = 0;

  const iter = db.iterator({
    gte: layout.p(encoding.NULL_HASH),
    lte: layout.p(encoding.HIGH_HASH),
    values: true
  });

  console.log('Migrating path map.');

  for (;;) {
    const item = await iter.next();

    if (!item)
      break;

    total++;
    const hash = layout.pp(item.key);
    const oldPaths = parsePaths(item.value, hash);
    const keys = Object.keys(oldPaths);

    for (let i = 0; i < keys.length; i++) {
      keys[i] = Number(keys[i]);
      const key = keys[i];
      const oldPath = oldPaths[key];
      const path = new Path(oldPath);
      if (path.data) {
        if (path.encrypted) {
          console.log(
            'Cannot migrate encrypted import: %s (%s)',
            path.data.toString('hex'),
            path.toAddress().toBase58());
          continue;
        }
        const ring = keyFromRaw(path.data);
        path.data = new KeyRing(ring).toRaw();
      }
      batch.put(layout.P(key, hash), path.toRaw());
    }

    batch.put(item.key, serializeWallets(keys.sort()));
  }

  console.log('Migrated %d paths.', total);
}

async function updateAccounts() {
  let total = 0;

  const iter = db.iterator({
    gte: layout.a(0, 0),
    lte: layout.a(0xffffffff, 0xffffffff),
    values: true
  });

  console.log('Migrating accounts.');

  for (;;) {
    const item = await iter.next();

    if (!item)
      break;

    total++;
    let account = accountFromRaw(item.value, item.key);
    account = new Account({ network: account.network, options: {} }, account);
    batch.put(item.key, account.toRaw());

    if (account._old) {
      batch.del(layout.i(account.wid, account._old));
      const buf = Buffer.allocUnsafe(4);
      buf.writeUInt32LE(account.accountIndex, 0, true);
      batch.put(layout.i(account.wid, account.name), buf);
    }
  }

  console.log('Migrated %d accounts.', total);
}

async function updateWallets() {
  let total = 0;

  const iter = db.iterator({
    gte: layout.w(0),
    lte: layout.w(0xffffffff),
    values: true
  });

  console.log('Migrating wallets.');

  for (;;) {
    const item = await iter.next();

    if (!item)
      break;

    total++;
    let wallet = walletFromRaw(item.value);
    wallet = new Wallet({ network: wallet.network }, wallet);
    batch.put(item.key, wallet.toRaw());

    if (wallet._old) {
      batch.del(layout.l(wallet._old));
      const buf = Buffer.allocUnsafe(4);
      buf.writeUInt32LE(wallet.wid, 0, true);
      batch.put(layout.l(wallet.id), buf);
    }
  }

  console.log('Migrated %d wallets.', total);
}

async function updateTXMap() {
  let total = 0;

  const iter = db.iterator({
    gte: layout.e(encoding.NULL_HASH),
    lte: layout.e(encoding.HIGH_HASH),
    values: true
  });

  console.log('Migrating tx map.');

  for (;;) {
    const item = await iter.next();

    if (!item)
      break;

    total++;
    const wallets = parseWallets(item.value);
    batch.put(item.key, serializeWallets(wallets.sort()));
  }

  console.log('Migrated %d tx maps.', total);
}

function pathFromRaw(data) {
  const path = {};
  const p = new BufferReader(data);

  path.wid = p.readU32();
  path.name = p.readVarString('utf8');
  path.account = p.readU32();

  switch (p.readU8()) {
    case 0:
      path.keyType = 0;
      path.branch = p.readU32();
      path.index = p.readU32();
      if (p.readU8() === 1)
        assert(false, 'Cannot migrate custom redeem script.');
      break;
    case 1:
      path.keyType = 1;
      path.encrypted = p.readU8() === 1;
      path.data = p.readVarBytes();
      path.branch = -1;
      path.index = -1;
      break;
    default:
      assert(false);
      break;
  }

  path.version = p.readI8();
  path.type = p.readU8();

  return path;
}

function parsePaths(data, hash) {
  const p = new BufferReader(data);
  const out = {};

  while (p.left()) {
    const path = pathFromRaw(p);
    out[path.wid] = path;
    if (hash)
      path.hash = hash;
  }

  return out;
}

function parseWallets(data) {
  const p = new BufferReader(data);
  const wallets = [];
  while (p.left())
    wallets.push(p.readU32());
  return wallets;
}

function serializeWallets(wallets) {
  const p = new BufferWriter();

  for (let i = 0; i < wallets.length; i++) {
    const wid = wallets[i];
    p.writeU32(wid);
  }

  return p.render();
}

function readAccountKey(key) {
  return {
    wid: key.readUInt32BE(1, true),
    index: key.readUInt32BE(5, true)
  };
}

function accountFromRaw(data, dbkey) {
  const account = {};
  const p = new BufferReader(data);

  dbkey = readAccountKey(dbkey);
  account.wid = dbkey.wid;
  account.id = 'doesntmatter';
  account.network = bcoin.network.fromMagic(p.readU32());
  account.name = p.readVarString('utf8');
  account.initialized = p.readU8() === 1;
  account.type = p.readU8();
  account.m = p.readU8();
  account.n = p.readU8();
  account.witness = p.readU8() === 1;
  account.accountIndex = p.readU32();
  account.receiveDepth = p.readU32();
  account.changeDepth = p.readU32();
  account.accountKey = bcoin.hd.fromRaw(p.readBytes(82));
  account.keys = [];
  account.watchOnly = false;
  account.nestedDepth = 0;

  const name = account.name.replace(/[^\-\._0-9A-Za-z]+/g, '');

  if (name !== account.name) {
    console.log('Account name changed: %s -> %s.', account.name, name);
    account._old = account.name;
    account.name = name;
  }

  const count = p.readU8();

  for (let i = 0; i < count; i++) {
    const key = bcoin.hd.fromRaw(p.readBytes(82));
    account.keys.push(key);
  }

  return account;
}

function walletFromRaw(data) {
  const wallet = {};
  const p = new BufferReader(data);

  wallet.network = bcoin.network.fromMagic(p.readU32());
  wallet.wid = p.readU32();
  wallet.id = p.readVarString('utf8');
  wallet.initialized = p.readU8() === 1;
  wallet.accountDepth = p.readU32();
  wallet.token = p.readBytes(32);
  wallet.tokenDepth = p.readU32();
  wallet.master = MasterKey.fromRaw(p.readVarBytes());
  wallet.watchOnly = false;

  const id = wallet.id.replace(/[^\-\._0-9A-Za-z]+/g, '');

  if (id !== wallet.id) {
    console.log('Wallet ID changed: %s -> %s.', wallet.id, id);
    wallet._old = wallet.id;
    wallet.id = id;
  }

  return wallet;
}

function keyFromRaw(data, network) {
  const ring = {};
  const p = new BufferReader(data);

  ring.network = bcoin.network.get(network);
  ring.witness = p.readU8() === 1;

  const key = p.readVarBytes();

  if (key.length === 32) {
    ring.privateKey = key;
    ring.publicKey = bcoin.secp256k1.publicKeyCreate(key, true);
  } else {
    ring.publicKey = key;
  }

  const script = p.readVarBytes();

  if (script.length > 0)
    ring.script = bcoin.script.fromRaw(script);

  return ring;
}

(async () => {
  await db.open();
  batch = db.batch();
  console.log('Opened %s.', file);
  await updateVersion();
  await updatePathMap();
  await updateAccounts();
  await updateWallets();
  await updateTXMap();
  await batch.write();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
});
