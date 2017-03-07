var assert = require('assert');
var bcoin = require('../');
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

  if (ver !== 4)
    throw Error('DB is version ' + ver + '.');

  console.log('Backing up DB to: %s.', bak);

  yield db.backup(bak);

  ver = new Buffer(4);
  ver.writeUInt32LE(5, 0, true);
  batch.put('V', ver);
});

var updateTXDB = co(function* updateTXDB() {
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
        batch.del(key);
        break;
    }
  }

  yield batch.write();
});

co.spawn(function* () {
  yield db.open();
  batch = db.batch();
  console.log('Opened %s.', file);
  yield updateVersion();
  yield updateTXDB();
  yield db.close();
}).then(function() {
  console.log('Migration complete.');
  process.exit(0);
});
