/**
 * bcoin - javascript bitcoin library
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = exports;
var assert = require('assert');

bcoin.isBrowser =
  (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

bcoin.prefix = process.env.BCOIN_PREFIX || process.env.HOME + '/.bcoin';
bcoin.debug = +process.env.BCOIN_DEBUG === 1;
bcoin.debugFile = +process.env.BCOIN_DEBUGFILE !== 0;
bcoin.profile = +process.env.BCOIN_PROFILE === 1;
bcoin.fresh = +process.env.BCOIN_FRESH === 1;

bcoin.ensurePrefix = function ensurePrefix() {
  if (!bcoin.fs)
    return;

  if (bcoin._ensured)
    return;

  bcoin._ensured = true;

  if (bcoin.fresh && bcoin.prefix.indexOf('bcoin') !== -1)
    bcoin.rimraf(bcoin.prefix);

  try {
    bcoin.fs.statSync(bcoin.prefix);
  } catch (e) {
    bcoin.fs.mkdirSync(bcoin.prefix, 0750);
  }
};

bcoin.rimraf = function rimraf(file) {
  if (!bcoin.cp)
    return;

  assert(typeof file === 'string');
  assert(file !== '/');
  assert(file !== process.env.HOME);

  bcoin.cp.execFileSync('rm', ['-rf', file], { stdio: 'ignore' });
};

bcoin.bn = require('bn.js');
bcoin.elliptic = require('elliptic');

if (!bcoin.isBrowser) {
  bcoin.fs = require('f' + 's');
  bcoin.crypto = require('cry' + 'pto');
  bcoin.net = require('n' + 'et');
  bcoin.cp = require('child_' + 'process');
  try {
    bcoin.secp256k1 = require('secp' + '256k1');
  } catch (e) {
    utils.debug('Warning: secp256k1 not found.'
      + ' Full block validation will be slow.');
  }
} else {
  bcoin.hash = require('hash.js');
}

bcoin.ecdsa = bcoin.elliptic.ec('secp256k1');
assert(!bcoin.ecdsa.signature);
bcoin.ecdsa.signature = require('elliptic/lib/elliptic/ec/signature');
assert(!bcoin.ecdsa.keypair);
bcoin.ecdsa.keypair = require('elliptic/lib/elliptic/ec/key');

bcoin.utils = require('./bcoin/utils');
bcoin.profiler = require('./bcoin/profiler');
bcoin.ec = require('./bcoin/ec');
bcoin.lru = require('./bcoin/lru');
bcoin.protocol = require('./bcoin/protocol');
bcoin.bloom = require('./bcoin/bloom');
bcoin.script = require('./bcoin/script');
bcoin.input = require('./bcoin/input');
bcoin.output = require('./bcoin/output');
bcoin.coin = require('./bcoin/coin');
bcoin.tx = require('./bcoin/tx');
bcoin.mtx = require('./bcoin/mtx');
bcoin.txpool = require('./bcoin/tx-pool');
bcoin.txdb = require('./bcoin/txdb');
bcoin.abstractblock = require('./bcoin/abstractblock');
bcoin.compactblock = require('./bcoin/compactblock');
bcoin.block = require('./bcoin/block');
bcoin.merkleblock = require('./bcoin/merkleblock');
bcoin.headers = require('./bcoin/headers');
bcoin.ramdisk = require('./bcoin/ramdisk');
bcoin.blockdb = require('./bcoin/blockdb');
bcoin.node = require('./bcoin/node2');
bcoin.spvnode = require('./bcoin/spvnode');
bcoin.fullnode = require('./bcoin/node');
bcoin.chainblock = require('./bcoin/chainblock');
bcoin.chaindb = require('./bcoin/chaindb');
bcoin.chain = require('./bcoin/chain');
bcoin.mempool = require('./bcoin/mempool');
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

bcoin.protocol.network.set(process.env.BCOIN_NETWORK || 'main');
