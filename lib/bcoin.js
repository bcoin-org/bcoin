/**
 * bcoin - javascript bitcoin library
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = exports;
var elliptic = require('elliptic');
var bn = require('bn.js');
var hash = require('hash.js');
var async = require('async');

bcoin.isBrowser =
  (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

if (process.env.BCOIN_DEBUG) {
  bcoin.debug = process.env.BCOIN_DEBUG;
  if (bcoin.debug === '0' || bcoin.debug === '1')
    bcoin.debug = +bcoin.debug === 1;
}

if (!bcoin.isBrowser) {
  bcoin.fs = require('f' + 's');
  bcoin.crypto = require('cry' + 'pto');
  bcoin.net = require('n' + 'et');
}

bcoin.elliptic = elliptic;
bcoin.bn = bn;
bcoin.hash = hash;
bcoin.async = async;

bcoin.ecdsa = elliptic.ec('secp256k1');

if (bcoin.ecdsa.signature)
  throw new Error;

if (bcoin.ecdsa.keypair)
  throw new Error;

bcoin.ecdsa.signature = require('elliptic/lib/elliptic/ec/signature');
bcoin.ecdsa.keypair = require('elliptic/lib/elliptic/ec/key');

bcoin.utils = require('./bcoin/utils');
bcoin.protocol = require('./bcoin/protocol');
bcoin.bloom = require('./bcoin/bloom');
bcoin.script = require('./bcoin/script');
bcoin.input = require('./bcoin/input');
bcoin.output = require('./bcoin/output');
bcoin.coin = require('./bcoin/coin');
bcoin.tx = require('./bcoin/tx');
bcoin.txPool = require('./bcoin/tx-pool');
bcoin.block = require('./bcoin/block');
bcoin.ramdisk = require('./bcoin/ramdisk');
bcoin.chainblock = require('./bcoin/chainblock');
bcoin.chaindb = require('./bcoin/chaindb');
bcoin.chain = require('./bcoin/chain');
bcoin.mempool = require('./bcoin/mempool');
bcoin.keypair = require('./bcoin/keypair');
bcoin.address = require('./bcoin/address');
bcoin.wallet = require('./bcoin/wallet');
bcoin.peer = require('./bcoin/peer');
bcoin.pool = require('./bcoin/pool');
bcoin.hd = require('./bcoin/hd');
bcoin.miner = require('./bcoin/miner');

bcoin.protocol.network.set(process.env.BCOIN_NETWORK || 'main');
