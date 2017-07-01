'use strict';

const assert = require('assert');
const bcoin = require('../');
const walletdb = require('../lib/wallet/walletdb');
const encoding = require('../lib/utils/encoding');
const Path = require('../lib/wallet/path');
const MasterKey = require('../lib/wallet/masterkey');
const Account = require('../lib/wallet/account');
const Wallet = require('../lib/wallet/wallet');
const BufferReader = require('../lib/utils/reader');
const BufferWriter = require('../lib/utils/writer');
let layout = walletdb.layout;
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
  let i, iter, item, oldPaths, oldPath;
  let hash, path, keys, key, ring;

  iter = db.iterator({
    gte: layout.p(encoding.NULL_HASH),
    lte: layout.p(encoding.HIGH_HASH),
    values: true
  });

  console.log('Migrating path map.');

  for (;;) {
    item = await iter.next();

    if (!item)
      break;

    total++;
    hash = layout.pp(item.key);
    oldPaths = parsePaths(item.value, hash);
    keys = Object.keys(oldPaths);

    for (i = 0; i < keys.length; i++) {
      keys[i] = +keys[i];
      key = keys[i];
      oldPath = oldPaths[key];
      path = new Path(oldPath);
      if (path.data) {
        if (path.encrypted) {
          console.log(
            'Cannot migrate encrypted import: %s (%s)',
            path.data.toString('hex'),
            path.toAddress().toBase58());
          continue;
        }
        ring = keyFromRaw(path.data);
        path.data = new bcoin.keyring(ring).toRaw();
      }
      batch.put(layout.P(key, hash), path.toRaw());
    }

    batch.put(item.key, serializeWallets(keys.sort()));
  }

  console.log('Migrated %d paths.', total);
}

async function updateAccounts() {
  let total = 0;
  let iter, item, account, buf;

  iter = db.iterator({
    gte: layout.a(0, 0),
    lte: layout.a(0xffffffff, 0xffffffff),
    values: true
  });

  console.log('Migrating accounts.');

  for (;;) {
    item = await iter.next();

    if (!item)
      break;

    total++;
    account = accountFromRaw(item.value, item.key);
    account = new Account({ network: account.network, options: {} }, account);
    batch.put(item.key, account.toRaw());

    if (account._old) {
      batch.del(layout.i(account.wid, account._old));
      buf = Buffer.allocUnsafe(4);
      buf.writeUInt32LE(account.accountIndex, 0, true);
      batch.put(layout.i(account.wid, account.name), buf);
    }
  }

  console.log('Migrated %d accounts.', total);
}

async function updateWallets() {
  let total = 0;
  let iter, item, wallet, buf;

  iter = db.iterator({
    gte: layout.w(0),
    lte: layout.w(0xffffffff),
    values: true
  });

  console.log('Migrating wallets.');

  for (;;) {
    item = await iter.next();

    if (!item)
      break;

    total++;
    wallet = walletFromRaw(item.value);
    wallet = new Wallet({ network: wallet.network }, wallet);
    batch.put(item.key, wallet.toRaw());

    if (wallet._old) {
      batch.del(layout.l(wallet._old));
      buf = Buffer.allocUnsafe(4);
      buf.writeUInt32LE(wallet.wid, 0, true);
      batch.put(layout.l(wallet.id), buf);
    }
  }

  console.log('Migrated %d wallets.', total);
}

async function updateTXMap() {
  let total = 0;
  let iter, item, wallets;

  iter = db.iterator({
    gte: layout.e(encoding.NULL_HASH),
    lte: layout.e(encoding.HIGH_HASH),
    values: true
  });

  console.log('Migrating tx map.');

  for (;;) {
    item = await iter.next();

    if (!item)
      break;

    total++;
    wallets = parseWallets(item.value);
    batch.put(item.key, serializeWallets(wallets.sort()));
  }

  console.log('Migrated %d tx maps.', total);
}

function pathFromRaw(data) {
  let path = {};
  let p = new BufferReader(data);

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

  path.version = p.read8();
  path.type = p.readU8();

  return path;
}

function parsePaths(data, hash) {
  let p = new BufferReader(data);
  let out = {};
  let path;

  while (p.left()) {
    path = pathFromRaw(p);
    out[path.wid] = path;
    if (hash)
      path.hash = hash;
  }

  return out;
}

function parseWallets(data) {
  let p = new BufferReader(data);
  let wallets = [];
  while (p.left())
    wallets.push(p.readU32());
  return wallets;
}

function serializeWallets(wallets) {
  let p = new BufferWriter();
  let i, wid;

  for (i = 0; i < wallets.length; i++) {
    wid = wallets[i];
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
  let account = {};
  let p = new BufferReader(data);
  let i, count, key, name;

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

  name = account.name.replace(/[^\-\._0-9A-Za-z]+/g, '');

  if (name !== account.name) {
    console.log('Account name changed: %s -> %s.', account.name, name);
    account._old = account.name;
    account.name = name;
  }

  count = p.readU8();

  for (i = 0; i < count; i++) {
    key = bcoin.hd.fromRaw(p.readBytes(82));
    account.keys.push(key);
  }

  return account;
}

function walletFromRaw(data) {
  let wallet = {};
  let p = new BufferReader(data);
  let id;

  wallet.network = bcoin.network.fromMagic(p.readU32());
  wallet.wid = p.readU32();
  wallet.id = p.readVarString('utf8');
  wallet.initialized = p.readU8() === 1;
  wallet.accountDepth = p.readU32();
  wallet.token = p.readBytes(32);
  wallet.tokenDepth = p.readU32();
  wallet.master = MasterKey.fromRaw(p.readVarBytes());
  wallet.watchOnly = false;

  id = wallet.id.replace(/[^\-\._0-9A-Za-z]+/g, '');

  if (id !== wallet.id) {
    console.log('Wallet ID changed: %s -> %s.', wallet.id, id);
    wallet._old = wallet.id;
    wallet.id = id;
  }

  return wallet;
}

function keyFromRaw(data, network) {
  let ring = {};
  let p = new BufferReader(data);
  let key, script;

  ring.network = bcoin.network.get(network);
  ring.witness = p.readU8() === 1;

  key = p.readVarBytes();

  if (key.length === 32) {
    ring.privateKey = key;
    ring.publicKey = bcoin.secp256k1.publicKeyCreate(key, true);
  } else {
    ring.publicKey = key;
  }

  script = p.readVarBytes();

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
