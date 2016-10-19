var assert = require('assert');
var bcoin = require('../');
var constants = require('../lib/protocol/constants');
var WalletDB = require('../lib/wallet/walletdb');
var TXDB = require('../lib/wallet/txdb');
var BufferWriter = require('../lib/utils/writer');
var utils = require('../lib/utils/utils');
var co = bcoin.co;
var layout = WalletDB.layout;
var tlayout = TXDB.layout;
var file = process.argv[2];
var db, batch;

assert(typeof file === 'string', 'Please pass in a database path.');

file = file.replace(/\.ldb\/?$/, '');

db = bcoin.ldb({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 16 << 20,
  writeBufferSize: 8 << 20,
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

  if (ver !== 3)
    throw Error('DB is version ' + ver + '.');

  console.log('Backing up DB to: %s.', bak);

  yield db.backup(bak);

  ver = new Buffer(4);
  ver.writeUInt32LE(4, 0, true);
  batch.put('V', ver);
});

var updateTXDB = co(function* updateTXDB() {
  var txs = {};
  var i, keys, key, hash, tx, walletdb;

  keys = yield db.keys({
    gte: new Buffer([0x00]),
    lte: new Buffer([0xff])
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    if (key[0] === 0x74 && key[5] === 0x74) {
      tx = yield db.get(key);
      tx = bcoin.tx.fromExtended(tx);
      hash = tx.hash('hex');
      txs[hash] = tx;
    }
    if (key[0] === 0x74)
      batch.del(key);
  }

  txs = utils.values(txs);

  yield batch.write();
  yield db.close();

  walletdb = new WalletDB({
    location: file,
    db: 'leveldb',
    resolution: true,
    verify: false
  });

  yield walletdb.open();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    yield walletdb.addTX(tx);
  }

  yield walletdb.close();
});

co.spawn(function* () {
  yield db.open();
  batch = db.batch();
  console.log('Opened %s.', file);
  yield updateVersion();
  yield updateTXDB();
}).then(function() {
  console.log('Migration complete.');
  process.exit(0);
});
