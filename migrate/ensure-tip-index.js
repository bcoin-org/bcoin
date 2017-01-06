var assert = require('assert');
var encoding = require('../lib/utils/encoding');
var co = require('../lib/utils/co');
var BufferWriter = require('../lib/utils/writer');
var BufferReader = require('../lib/utils/reader');
var crypto = require('../lib/crypto/crypto');
var util = require('../lib/utils/util');
var LDB = require('../lib/db/ldb');
var BN = require('bn.js');
var DUMMY = new Buffer([0]);
var file = process.argv[2];
var db, batch;

assert(typeof file === 'string', 'Please pass in a database path.');

file = file.replace(/\.ldb\/?$/, '');

db = LDB({
  location: file,
  db: 'leveldb',
  compression: true,
  cacheSize: 32 << 20,
  createIfMissing: false,
  bufferKeys: true
});

var checkVersion = co(function* checkVersion() {
  var data, ver;

  console.log('Checking version.');

  data = yield db.get('V');

  if (!data)
    return;

  ver = data.readUInt32LE(0, true);

  if (ver !== 1)
    throw Error('DB is version ' + ver + '.');
});

function entryFromRaw(data) {
  var p = new BufferReader(data, true);
  var hash = crypto.hash256(p.readBytes(80));
  var entry = {};

  p.seek(-80);

  entry.hash = hash.toString('hex');
  entry.version = p.readU32(); // Technically signed
  entry.prevBlock = p.readHash('hex');
  entry.merkleRoot = p.readHash('hex');
  entry.ts = p.readU32();
  entry.bits = p.readU32();
  entry.nonce = p.readU32();
  entry.height = p.readU32();
  entry.chainwork = new BN(p.readBytes(32), 'le');

  return entry;
}

function getEntries() {
  return db.values({
    gte: pair('e', encoding.ZERO_HASH),
    lte: pair('e', encoding.MAX_HASH),
    parse: entryFromRaw
  });
}

var getTip = co(function* getTip(entry) {
  var state = yield db.get('R');
  assert(state);
  var tip = state.toString('hex', 0, 32);
  var data = yield db.get(pair('e', tip));
  assert(data);
  return entryFromRaw(data);
});

var isMainChain = co(function* isMainChain(entry, tip) {
  if (entry.hash === tip)
    return true;

  if (yield db.get(pair('n', entry.hash)))
    return true;

  return false;
});

// And this insane function is why we should
// be indexing tips in the first place!
var indexTips = co(function* indexTips() {
  var entries = yield getEntries();
  var tip = yield getTip();
  var tips = [];
  var orphans = [];
  var prevs = {};
  var i, orphan, entry, main;

  for (i = 0; i < entries.length; i++) {
    entry = entries[i];
    main = yield isMainChain(entry, tip.hash);
    if (!main) {
      orphans.push(entry);
      prevs[entry.prevBlock] = true;
    }
  }

  for (i = 0; i < orphans.length; i++) {
    orphan = orphans[i];
    if (!prevs[orphan.hash])
      tips.push(orphan.hash);
  }

  tips.push(tip.hash);

  for (i = 0; i < tips.length; i++) {
    tip = tips[i];
    console.log('Indexing chain tip: %s.', util.revHex(tip));
    batch.put(pair('p', tip), DUMMY);
  }
});

function write(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  data.write(str, off, 'hex');
}

function pair(prefix, hash) {
  var key = new Buffer(33);
  if (typeof prefix === 'string')
    prefix = prefix.charCodeAt(0);
  key[0] = prefix;
  write(key, hash, 1);
  return key;
}

function ipair(prefix, num) {
  var key = new Buffer(5);
  if (typeof prefix === 'string')
    prefix = prefix.charCodeAt(0);
  key[0] = prefix;
  key.writeUInt32BE(num, 1, true);
  return key;
}

co.spawn(function* () {
  yield db.open();
  console.log('Opened %s.', file);
  batch = db.batch();
  yield checkVersion();
  yield indexTips();
  yield batch.write();
}).then(function() {
  console.log('Migration complete.');
  process.exit(0);
});
