var bcoin = require('../');
var assert = require('assert');
var file = process.argv[2];

assert(typeof file === 'string', 'Please pass in a database path.');

var db = bcoin.ldb({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 16 << 20,
  writeBufferSize: 8 << 20,
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

function updateState(callback) {
  var hash, batch, ver, p;

  console.log('Updating chain state.');

  db.get('R', function(err, data) {
    if (err)
      return callback(err);

    if (!data || data.length < 32)
      return callback(new Error('No chain state.'));

    hash = data.slice(0, 32);

    p = new bcoin.writer();
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

    batch.write(function(err) {
      if (err)
        return callback(err);
      console.log('Updated chain state.');
      callback();
    });
  });
}

function updateEndian(callback) {
  var lo = new Buffer('4800000000', 'hex');
  var hi = new Buffer('48ffffffff', 'hex');
  var batch = db.batch();
  var total = 0;

  console.log('Updating endianness.');
  console.log('Iterating...');

  db.iterate({
    gte: lo,
    lte: hi,
    values: true,
    parse: function(key, value) {
      batch.del(key);
      batch.put(makeKey(key), value);
      total++;
    }
  }, function(err) {
    if (err)
      throw err;

    console.log('Migrating %d items.', total);

    batch.write(function(err) {
      if (err)
        throw err;
      console.log('Migrated endianness.');
      callback();
    });
  });
}

db.open(function(err) {
  if (err)
    throw err;

  console.log('Opened %s.', file);

  updateState(function(err) {
    if (err)
      throw err;
    updateEndian(function(err) {
      if (err)
        throw err;
      console.log('Migration complete.');
      process.exit(0);
    });
  });
});
