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

bcoin.debug = +process.env.BCOIN_DEBUG === 1;

bcoin.ecdsa = elliptic.ec('secp256k1');
bcoin.utils = require('./bcoin/utils');
bcoin.bloom = require('./bcoin/bloom');
bcoin.protocol = require('./bcoin/protocol');
bcoin.script = require('./bcoin/script');
bcoin.input = require('./bcoin/input');
bcoin.output = require('./bcoin/output');
bcoin.tx = require('./bcoin/tx');
bcoin.txPool = require('./bcoin/tx-pool');
bcoin.block = require('./bcoin/block');
bcoin.chain = require('./bcoin/chain');
bcoin.wallet = require('./bcoin/wallet');
bcoin.peer = require('./bcoin/peer');
bcoin.pool = require('./bcoin/pool');
bcoin.hd = require('./bcoin/hd');
bcoin.miner = require('./bcoin/miner');

bcoin.protocol.network.set(process.env.BCOIN_NETWORK || 'main');

bcoin.bn = bn;
bcoin.elliptic = elliptic;
bcoin.signature = require('elliptic/lib/elliptic/ec/signature');
bcoin.hash = hash;
bcoin.async = async;
