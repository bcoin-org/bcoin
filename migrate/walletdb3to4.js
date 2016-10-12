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

var updateState = co(function* updateState(wid) {
  var total = 0;
  var unconfirmed = 0;
  var confirmed = 0;
  var txs = 0;
  var coins = 0;
  var p, keys;

  keys = yield db.keys({
    gte: tlayout.prefix(wid, tlayout.t(constants.NULL_HASH)),
    lte: tlayout.prefix(wid, tlayout.t(constants.HIGH_HASH))
  });

  txs += keys.length;

  yield db.range({
    gte: tlayout.prefix(wid, tlayout.c(constants.NULL_HASH, 0x00000000)),
    lte: tlayout.prefix(wid, tlayout.c(constants.HIGH_HASH, 0xffffffff)),
    parse: function(key, data) {
      var height = data.readUInt32LE(4, true);
      var value = utils.read64N(data, 8);

      total += value;

      if (height === 0x7fffffff)
        unconfirmed += value;
      else
        confirmed += value;

      coins += 1;
    }
  });

  p = new BufferWriter();
  p.writeU64(txs);
  p.writeU64(coins);
  p.writeU64(unconfirmed);
  p.writeU64(confirmed);

  batch.put(tlayout.prefix(wid, tlayout.R), p.render());
});

var updateStates = co(function* updateStates() {
  var i, wallets, wid;

  wallets = yield db.keys({
    gte: layout.w(0),
    lte: layout.w(0xffffffff),
    parse: function(key) {
      return key.readUInt32LE(1, true);
    }
  });

  console.log('Updating states...');

  for (i = 0; i < wallets.length; i++) {
    wid = wallets[i];
    yield updateState(wid);
  }

  console.log('Updated %d states.', wallets.length);
});

co.spawn(function* () {
  yield db.open();
  batch = db.batch();
  console.log('Opened %s.', file);
  yield updateVersion();
  yield updateStates();
  yield batch.write();
}).then(function() {
  console.log('Migration complete.');
  process.exit(0);
});
