var assert = require('assert');
var bcoin = require('../');
var encoding = require('../lib/utils/encoding');
var BufferWriter = require('../lib/utils/writer');
var BufferReader = require('../lib/utils/reader');
var util = require('../lib/utils/util');
var co = bcoin.co;
var file = process.argv[2];
var db, batch;

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

var updateVersion = co(function* updateVersion() {
  var bak = process.env.HOME + '/walletdb-bak-' + Date.now() + '.ldb';
  var data, ver;

  console.log('Checking version.');

  data = yield db.get('V');
  assert(data, 'No version.');

  ver = data.readUInt32LE(0, true);

  if (ver !== 5)
    throw Error('DB is version ' + ver + '.');

  console.log('Backing up DB to: %s.', bak);

  yield db.backup(bak);

  ver = new Buffer(4);
  ver.writeUInt32LE(6, 0, true);
  batch.put('V', ver);
});

var wipeTXDB = co(function* wipeTXDB() {
  var total = 0;
  var i, keys, key;

  keys = yield db.keys({
    gte: new Buffer([0x00]),
    lte: new Buffer([0xff])
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

  batch.del(new Buffer([0x52])); // R

  console.log('Wiped %d txdb records.', total);
});

var patchAccounts = co(function* patchAccounts() {
  var i, items, item, wid, index, account;

  items = yield db.range({
    gte: new Buffer('610000000000000000', 'hex'), // a
    lte: new Buffer('61ffffffffffffffff', 'hex')  // a
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    wid = item.key.readUInt32BE(1, true);
    index = item.key.readUInt32BE(5, true);
    account = accountFromRaw(item.value);
    console.log('a[%d][%d] -> lookahead=%d', wid, index, account.lookahead);
    batch.put(item.key, accountToRaw(account));
    console.log('n[%d][%d] -> %s', wid, index, account.name);
    batch.put(n(wid, index), new Buffer(account.name, 'ascii'));
  }
});

var indexPaths = co(function* indexPaths() {
  var i, items, item, wid, index, hash;

  items = yield db.range({
    gte: new Buffer('5000000000' + encoding.NULL_HASH, 'hex'), // P
    lte: new Buffer('50ffffffff' + encoding.HIGH_HASH, 'hex')  // P
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    wid = item.key.readUInt32BE(1, true);
    hash = item.key.toString('hex', 5);
    index = item.value.readUInt32LE(0, true);
    console.log('r[%d][%d][%s] -> NUL', wid, index, hash);
    batch.put(r(wid, index, hash), new Buffer([0]));
  }
});

var patchPathMaps = co(function* patchPathMaps() {
  var i, items, item, hash, wids;

  items = yield db.range({
    gte: new Buffer('70' + encoding.NULL_HASH, 'hex'), // p
    lte: new Buffer('70' + encoding.HIGH_HASH, 'hex')  // p
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    hash = item.key.toString('hex', 1);
    wids = parseWallets(item.value);
    console.log('p[%s] -> u32(%d)', hash, wids.length);
    batch.put(item.key, serializeWallets(wids));
  }
});

function parseWallets(data) {
  var p = new BufferReader(data);
  var wids = [];

  while (p.left())
    wids.push(p.readU32());

  return wids;
}

function serializeWallets(wids) {
  var p = new BufferWriter();
  var i, wid;

  p.writeU32(wids.length);

  for (i = 0; i < wids.length; i++) {
    wid = wids[i];
    p.writeU32(wid);
  }

  return p.render();
}

function accountToRaw(account) {
  var p = new BufferWriter();
  var i, key;

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
  var account = {};
  var p = new BufferReader(data);
  var i, count, key;

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
  var key = new Buffer(9);
  key[0] = 0x6e;
  key.writeUInt32BE(wid, 1, true);
  key.writeUInt32BE(index, 5, true);
  return key;
}

function r(wid, index, hash) {
  var key = new Buffer(1 + 4 + 4 + (hash.length / 2));
  key[0] = 0x72;
  key.writeUInt32BE(wid, 1, true);
  key.writeUInt32BE(index, 5, true);
  key.write(hash, 9, 'hex');
  return key;
}

var updateLookahead = co(function* updateLookahead() {
  var WalletDB = require('../lib/wallet/walletdb');
  var i, j, db, wallet;

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

  yield db.open();

  for (i = 1; i < db.depth; i++) {
    wallet = yield db.get(i);
    assert(wallet);
    console.log('Updating wallet lookahead: %s', wallet.id);
    for (j = 0; j < wallet.accountDepth; j++)
      yield wallet.setLookahead(j, 20);
  }

  yield db.close();
});

var unstate = co(function* unstate() {
  yield db.open();
  batch = db.batch();
  yield wipeTXDB();
  yield batch.write();
  yield db.close();
});

co.spawn(function* () {
  yield db.open();
  batch = db.batch();
  console.log('Opened %s.', file);
  yield updateVersion();
  yield wipeTXDB();
  yield patchAccounts();
  yield indexPaths();
  yield patchPathMaps();
  yield batch.write();
  yield db.close();
  // yield updateLookahead();
  // yield unstate();
}).then(function() {
  console.log('Migration complete.');
  console.log('Rescan is required...');
  console.log('Start bcoin with `--start-height=[wallet-creation-height]`.');
  process.exit(0);
});
