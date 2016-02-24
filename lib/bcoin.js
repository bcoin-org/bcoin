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

bcoin.debug = +process.env.BCOIN_DEBUG === 1;
bcoin.debugFile = +process.env.BCOIN_DEBUGFILE !== 0;

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
    utils.debug('Warning secp256k1 not found.'
      + ' Full block validation will be slow.');
  }
} else {
  bcoin.hash = require('hash.js');
}

bcoin.dir = process.env.HOME + '/.bcoin';

if (bcoin.fs) {
  try {
    bcoin.fs.statSync(bcoin.dir, 0o750);
  } catch (e) {
    bcoin.fs.mkdirSync(bcoin.dir);
  }
}

bcoin.ecdsa = bcoin.elliptic.ec('secp256k1');
assert(!bcoin.ecdsa.signature);
bcoin.ecdsa.signature = require('elliptic/lib/elliptic/ec/signature');
assert(!bcoin.ecdsa.keypair);
bcoin.ecdsa.keypair = require('elliptic/lib/elliptic/ec/key');

bcoin.utils = require('./bcoin/utils');
bcoin.ec = require('./bcoin/ec');
bcoin.lru = require('./bcoin/lru');
bcoin.protocol = require('./bcoin/protocol');
bcoin.bloom = require('./bcoin/bloom');
bcoin.script = require('./bcoin/script');
bcoin.input = require('./bcoin/input');
bcoin.output = require('./bcoin/output');
bcoin.coin = require('./bcoin/coin');
bcoin.tx = require('./bcoin/tx');
bcoin.txpool = require('./bcoin/tx-pool');
bcoin.block = require('./bcoin/block');
bcoin.ramdisk = require('./bcoin/ramdisk');
bcoin.blockdb = require('./bcoin/blockdb');
bcoin.spvnode = require('./bcoin/spvnode');
bcoin.node = require('./bcoin/node');
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
