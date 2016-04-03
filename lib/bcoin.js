/**
 * bcoin - javascript bitcoin library
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = exports;
var utils = require('./bcoin/utils');
var assert = utils.assert;
var fs;

try {
  fs = require('f' + 's');
} catch (e) {
  ;
}

bcoin.isBrowser =
  (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

bcoin.prefix = process.env.BCOIN_PREFIX || process.env.HOME + '/.bcoin';
bcoin.debugLogs = +process.env.BCOIN_DEBUG === 1;
bcoin.debugFile = +process.env.BCOIN_DEBUGFILE !== 0;
bcoin.profile = +process.env.BCOIN_PROFILE === 1;
bcoin.fresh = +process.env.BCOIN_FRESH === 1;
bcoin.useWorkers = +process.env.BCOIN_WORKERS > 0;

bcoin.ensurePrefix = function ensurePrefix() {
  if (bcoin.isBrowser)
    return;

  if (bcoin._ensured)
    return;

  bcoin._ensured = true;

  if (bcoin.fresh && bcoin.prefix.indexOf('bcoin') !== -1)
    bcoin.rimraf(bcoin.prefix);

  try {
    fs.statSync(bcoin.prefix);
  } catch (e) {
    fs.mkdirSync(bcoin.prefix, 0750);
  }
};

bcoin.rimraf = function rimraf(file) {
  var cp;

  if (bcoin.isBrowser)
    return;

  cp = require('child_' + 'process');

  assert(typeof file === 'string');
  assert(file !== '/');
  assert(file !== process.env.HOME);

  cp.execFileSync('rm', ['-rf', file], { stdio: 'ignore' });
};

bcoin.debug = function debug() {
  var args = Array.prototype.slice.call(arguments);
  var msg;

  if (bcoin.debugLogs) {
    msg = utils.format(args, true);
    process.stdout.write(msg);
  }

  if (bcoin.debugFile && !bcoin.isBrowser) {
    if (!bcoin._debug) {
      bcoin.ensurePrefix();
      bcoin._debug = fs.createWriteStream(
        bcoin.prefix + '/debug.log', { flags: 'a' });
    }
    msg = utils.format(args, false);
    bcoin._debug.write(process.pid + ': ' + msg);
  }
};

bcoin.utils = utils;
bcoin.utils.debug = bcoin.debug;
bcoin.utils.ensurePrefix = bcoin.ensurePrefix;
bcoin.locker = require('./bcoin/locker');
bcoin.reader = require('./bcoin/reader');
bcoin.writer = require('./bcoin/writer');
bcoin.profiler = require('./bcoin/profiler');
bcoin.ec = require('./bcoin/ec');
bcoin.lru = require('./bcoin/lru');
bcoin.protocol = require('./bcoin/protocol');
bcoin.bloom = require('./bcoin/bloom');
bcoin.script = require('./bcoin/script');
bcoin.input = require('./bcoin/input');
bcoin.output = require('./bcoin/output');
bcoin.coin = require('./bcoin/coin');
bcoin.coins = require('./bcoin/coins');
bcoin.coinview = require('./bcoin/coinview');
bcoin.tx = require('./bcoin/tx');
bcoin.mtx = require('./bcoin/mtx');
bcoin.ldb = require('./bcoin/ldb');
bcoin.txdb = require('./bcoin/txdb');
bcoin.abstractblock = require('./bcoin/abstractblock');
bcoin.compactblock = require('./bcoin/compactblock');
bcoin.block = require('./bcoin/block');
bcoin.merkleblock = require('./bcoin/merkleblock');
bcoin.headers = require('./bcoin/headers');
bcoin.ramdisk = require('./bcoin/ramdisk');
bcoin.node = require('./bcoin/node');
bcoin.spvnode = require('./bcoin/spvnode');
bcoin.fullnode = require('./bcoin/fullnode');
bcoin.chainblock = require('./bcoin/chainblock');
bcoin.chaindb = require('./bcoin/chaindb');
bcoin.chain = require('./bcoin/chain');
bcoin.mempool = require('./bcoin/mempool2');
bcoin.keypair = require('./bcoin/keypair');
bcoin.address = require('./bcoin/address');
bcoin.walletdb = require('./bcoin/walletdb');
bcoin.wallet = require('./bcoin/wallet');
bcoin.peer = require('./bcoin/peer');
bcoin.pool = require('./bcoin/pool');
bcoin.hd = require('./bcoin/hd');
bcoin.miner = require('./bcoin/miner');
bcoin.http = !bcoin.isBrowser
  ? require('./bcoin/ht' + 'tp')
  : null;
bcoin.workers = bcoin.useWorkers && !bcoin.isBrowser
  ? require('./bcoin/work' + 'ers')
  : null;

bcoin.protocol.network.set(process.env.BCOIN_NETWORK || 'main');
