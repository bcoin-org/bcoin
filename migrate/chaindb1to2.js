var assert = require('assert');
var encoding = require('../lib/utils/encoding');
var networks = require('../lib/protocol/networks');
var co = require('../lib/utils/co');
var BufferWriter = require('../lib/utils/writer');
var BufferReader = require('../lib/utils/reader');
var OldCoins = require('./coins-old');
var Coins = require('../lib/coins/coins');
var UndoCoins = require('../lib/coins/undocoins');
var Coin = require('../lib/primitives/coin');
var Output = require('../lib/primitives/output');
var util = require('../lib/utils/util');
var LDB = require('../lib/db/ldb');
var file = process.argv[2];
var options = {};
var db, batch, index;

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

options = {};
options.spv = process.argv.indexOf('--spv') !== -1;
options.prune = process.argv.indexOf('--prune') !== -1;
options.indexTX = process.argv.indexOf('--index-tx') !== -1;
options.indexAddress = process.argv.indexOf('--index-address') !== -1;
options.network = networks.main;

index = process.argv.indexOf('--network');

if (index !== -1) {
  options.network = networks[process.argv[index + 1]];
  assert(options.network, 'Invalid network.');
}

var updateVersion = co(function* updateVersion() {
  var data, ver;

  console.log('Checking version.');

  data = yield db.get('V');

  if (!data)
    throw new Error('No DB version found!');

  ver = data.readUInt32LE(0, true);

  if (ver !== 1)
    throw Error('DB is version ' + ver + '.');

  ver = new Buffer(4);
  ver.writeUInt32LE(2, 0, true);
  batch.put('V', ver);
});

var checkTipIndex = co(function* checkTipIndex() {
  var keys = yield db.keys({
    gte: pair('p', encoding.ZERO_HASH),
    lte: pair('p', encoding.MAX_HASH)
  });

  if (keys.length === 0) {
    console.log('No tip index found.');
    console.log('Please run migrate/ensure-tip-index.js first!');
    process.exit(1);
    return;
  }

  if (keys.length < 3) {
    console.log('Note: please run ensure-tip-index.js if you haven\'t yet.');
    yield co.timeout(2000);
    return;
  }
});

var updateOptions = co(function* updateOptions() {
  if (yield db.has('O'))
    return;

  if (process.argv.indexOf('--network') === -1) {
    console.log('Warning: no options found in chaindb.');
    console.log('Make sure you selected the correct options');
    console.log('which may include any of:');
    console.log('`--network [name]`, `--spv`, `--witness`,');
    console.log('`--prune`, `--index-tx`, and `--index-address`.');
    console.log('Continuing migration in 5 seconds...');
    yield co.timeout(5000);
  }

  batch.put('O', defaultOptions());
});

var updateDeployments = co(function* updateDeployments() {
  if (yield db.has('v'))
    return;

  if (process.argv.indexOf('--network') === -1) {
    console.log('Warning: no deployment table found.');
    console.log('Make sure `--network` is set properly.');
    console.log('Continuing migration in 5 seconds...');
    yield co.timeout(5000);
  }

  batch.put('v', defaultDeployments());
});

var reserializeCoins = co(function* reserializeCoins() {
  var total = 0;
  var i, iter, item, hash, old, coins, coin, output;

  iter = db.iterator({
    gte: pair('c', encoding.ZERO_HASH),
    lte: pair('c', encoding.MAX_HASH),
    values: true
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    hash = item.key.toString('hex', 1, 33);
    old = OldCoins.fromRaw(item.value, hash);

    coins = new Coins();
    coins.version = old.version;
    coins.hash = old.hash;
    coins.height = old.height;
    coins.coinbase = old.coinbase;

    for (i = 0; i < old.outputs.length; i++) {
      coin = old.get(i);

      if (!coin) {
        coins.outputs.push(null);
        continue;
      }

      output = new Output();
      output.script = coin.script;
      output.value = coin.value;

      if (!output.script.isUnspendable())
        coins.addOutput(coin.index, output);
    }

    coins.cleanup();

    batch.put(item.key, coins.toRaw());

    if (++total % 100000 === 0)
      console.log('Reserialized %d coins.', total);
  }

  console.log('Reserialized %d coins.', total);
});

var reserializeUndo = co(function* reserializeUndo() {
  var total = 0;
  var iter, item, br, undo;

  iter = db.iterator({
    gte: pair('u', encoding.ZERO_HASH),
    lte: pair('u', encoding.MAX_HASH),
    values: true
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    br = new BufferReader(item.value);
    undo = new UndoCoins();

    while (br.left()) {
      undo.push(null);
      injectCoin(undo.top(), Coin.fromReader(br));
    }

    batch.put(item.key, undo.toRaw());

    if (++total % 10000 === 0)
      console.log('Reserialized %d undo coins.', total);
  }

  console.log('Reserialized %d undo coins.', total);
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

function injectCoin(undo, coin) {
  var output = new Output();

  output.value = coin.value;
  output.script = coin.script;

  undo.output = output;
  undo.version = coin.version;
  undo.height = coin.height;
  undo.coinbase = coin.coinbase;
}

function defaultOptions() {
  var bw = new BufferWriter();
  var flags = 0;

  if (options.spv)
    flags |= 1 << 0;

  flags |= 1 << 1;

  if (options.prune)
    flags |= 1 << 2;

  if (options.indexTX)
    flags |= 1 << 3;

  if (options.indexAddress)
    flags |= 1 << 4;

  bw.writeU32(options.network.magic);
  bw.writeU32(flags);
  bw.writeU32(0);

  return bw.render();
}

function defaultDeployments() {
  var bw = new BufferWriter();
  var i, deployment;

  bw.writeU8(options.network.deploys.length);

  for (i = 0; i < options.network.deploys.length; i++) {
    deployment = options.network.deploys[i];
    bw.writeU8(deployment.bit);
    bw.writeU32(deployment.startTime);
    bw.writeU32(deployment.timeout);
  }

  return bw.render();
}

co.spawn(function* () {
  yield db.open();
  console.log('Opened %s.', file);
  batch = db.batch();
  yield updateVersion();
  yield checkTipIndex();
  yield updateOptions();
  yield updateDeployments();
  yield reserializeCoins();
  yield reserializeUndo();
  yield batch.write();
}).then(function() {
  console.log('Migration complete.');
  process.exit(0);
});
