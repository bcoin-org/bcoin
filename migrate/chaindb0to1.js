var bcoin = require('../');
var co = bcoin.co;
var assert = require('assert');
var file = process.argv[2];
var BufferWriter = require('../lib/utils/writer');

assert(typeof file === 'string', 'Please pass in a database path.');

file = file.replace(/\.ldb\/?$/, '');

var db = bcoin.ldb({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false,
  bufferKeys: true
});

function makeKey(data) {
  var height = data.readUInt32LE(1, true);
  var key = new Buffer(5);
  key[0] = 0x48;
  key.writeUInt32BE(height, 1, true);
  return key;
}

var checkVersion = co(function* checkVersion() {
  var data, ver;

  console.log('Checking version.');

  data = yield db.get('V');

  if (!data)
    return;

  ver = data.readUInt32LE(0, true);

  if (ver !== 0)
    throw Error('DB is version ' + ver + '.');
});

var updateState = co(function* updateState() {
  var data, hash, batch, ver, p;

  console.log('Updating chain state.');

  data = yield db.get('R');

  if (!data || data.length < 32)
    throw new Error('No chain state.');

  hash = data.slice(0, 32);

  p = new BufferWriter();
  p.writeHash(hash);
  p.writeU64(0);
  p.writeU64(0);
  p.writeU64(0);
  p = p.render();

  batch = db.batch();

  batch.put('R', p);

  ver = new Buffer(4);
  ver.writeUInt32LE(1, 0, true);
  batch.put('V', ver);

  yield batch.write();

  console.log('Updated chain state.');
});

var updateEndian = co(function* updateEndian() {
  var batch = db.batch();
  var total = 0;
  var iter, item;

  console.log('Updating endianness.');
  console.log('Iterating...');

  iter = db.iterator({
    gte: new Buffer('4800000000', 'hex'),
    lte: new Buffer('48ffffffff', 'hex'),
    values: true
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    batch.del(item.key);
    batch.put(makeKey(item.key), item.value);
    total++;
  }

  console.log('Migrating %d items.', total);

  yield batch.write();

  console.log('Migrated endianness.');
});

co.spawn(function* () {
  yield db.open();
  console.log('Opened %s.', file);
  yield checkVersion();
  yield updateState();
  yield updateEndian();
}).then(function() {
  console.log('Migration complete.');
  process.exit(0);
});
