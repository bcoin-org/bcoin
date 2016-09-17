/*!
 * env.js - environment for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('./utils/utils');
var global = utils.global;

/**
 * A BCoin "environment" which is used for
 * bootstrapping the initial `bcoin` module.
 * It exposes all constructors for primitives,
 * the blockchain, mempool, wallet, etc. It
 * also sets the default network if there is
 * one. It exposes a global {@link TimeData}
 * object for adjusted time, as well as a
 * global worker pool.
 *
 * @exports Environment
 * @constructor
 *
 * @param {(Object|NetworkType)?} options - Options object or network type.
 * @param {(Network|NetworkType)?} options.network
 * @param {String} [options.prefix=~/.bcoin] - Prefix for filesystem.
 * @param {String} [options.db=leveldb] - Database backend.
 * @param {Boolean} [options.debug=false] - Whether to display debug output.
 * @param {String|Boolean} [options.debugFile=~/.debug.log] - A file to
 * pipe debug output to.
 * @param {Boolean} [options.profile=false] - Enable profiler.
 * @param {Boolean} [options.useWorkers=false] - Enable workers.
 * @param {Number} [options.maxWorkers=6] - Max size of
 * the worker pool.
 * @param {String} [options.workerUri=/bcoin-worker.js] Location of the bcoin
 * worker.js file for web workers.
 * @param {String} [options.proxyServer=localhost:8080] -
 * Websocket->tcp proxy server for browser.
 * @param {Object?} options.logger - Custom logger.
 * @property {Boolean} isBrowser
 * @property {NetworkType} networkType
 *
 * @property {Function} bn - Big number constructor
 * (see {@link https://github.com/indutny/bn.js} for docs).
 * @property {Object} utils - {@link module:utils}.
 * @property {Function} locker - {@link Locker} constructor.
 * @property {Function} reader - {@link BufferReader} constructor.
 * @property {Function} writer - {@link BufferWriter} constructor.
 * @property {Object} ec - {@link module:ec}.
 * @property {Function} lru - {@link LRU} constructor.
 * @property {Function} bloom - {@link Bloom} constructor.
 * @property {Function} rbt - {@link RBT} constructor.
 * @property {Function} lowlevelup - See {@link LowlevelUp}.
 * @property {Function} uri - See {@link module:uri}.
 * @property {Function} logger - {@link Logger} constructor.
 *
 * @property {Object} constants - See {@link module:constants}.
 * @property {Object} networks - See {@link module:network}.
 * @property {Object} errors
 * @property {Function} errors.VerifyError - {@link VerifyError} constructor.
 * @property {Function} errors.ScriptError - {@link ScriptError} constructor.
 * @property {Function} profiler - {@link module:profiler}.
 * @property {Function} ldb - See {@link module:ldb}.
 * @property {Function} script - {@link Script} constructor.
 * @property {Function} opcode - {@link Opcode} constructor.
 * @property {Function} stack - {@link Stack} constructor.
 * @property {Function} witness - {@link Witness} constructor.
 * @property {Function} input - {@link Input} constructor.
 * @property {Function} output - {@link Output} constructor.
 * @property {Function} coin - {@link Coin} constructor.
 * @property {Function} coins - {@link Coins} constructor.
 * @property {Function} coinview - {@link CoinView} constructor.
 * @property {Function} tx - {@link TX} constructor.
 * @property {Function} mtx - {@link MTX} constructor.
 * @property {Function} txdb - {@link TXDB} constructor.
 * @property {Function} abstractblock - {@link AbstractBlock} constructor.
 * @property {Function} memblock - {@link MemBlock} constructor.
 * @property {Function} block - {@link Block} constructor.
 * @property {Function} merkleblock - {@link MerkleBlock} constructor.
 * @property {Function} headers - {@link Headers} constructor.
 * @property {Function} node - {@link Node} constructor.
 * @property {Function} spvnode - {@link SPVNode} constructor.
 * @property {Function} fullnode - {@link Fullnode} constructor.
 * @property {Function} chainentry - {@link ChainEntry} constructor.
 * @property {Function} chaindb - {@link ChainDB} constructor.
 * @property {Function} chain - {@link Chain} constructor.
 * @property {Function} mempool - {@link Mempool} constructor.
 * @property {Function} mempoolentry - {@link MempoolEntry} constructor.
 * @property {Function} hd - {@link HD} constructor.
 * @property {Function} address - {@link Address} constructor.
 * @property {Function} wallet - {@link Wallet} constructor.
 * @property {Function} walletdb - {@link WalletDB} constructor.
 * @property {Function} peer - {@link Peer} constructor.
 * @property {Function} pool - {@link Pool} constructor.
 * @property {Function} miner - {@link Miner} constructor.
 * @property {Function} minerblock - {@link MinerBlock} constructor.
 * @property {Object} http
 * @property {Function} http.client - {@link HTTPClient} constructor.
 * @property {Function} http.http - {@link HTTPBase} constructor.
 * @property {Function} http.request - See {@link request}.
 * @property {Function} http.server - {@link HTTPServer} constructor.
 * @property {Object} workers - See {@link module:workers}.
 * @property {TimeData} time - For adjusted time.
 * @property {Workers?} workerPool - Default global worker pool.
 */

function Environment() {
  this.env = Environment;

  // BN
  this.require('bn', 'bn.js');

  // Protocol
  this.require('constants', './protocol/constants');
  this.require('networks', './protocol/networks');
  this.require('network', './protocol/network');

  // Utils
  this.require('utils', './utils/utils');
  this.require('locker', './utils/locker');
  this.require('reader', './utils/reader');
  this.require('writer', './utils/writer');
  this.require('lru', './utils/lru');
  this.require('bloom', './utils/bloom');
  this.require('uri', './utils/uri');
  this.require('errors', './utils/errors');

  // Crypto
  this.require('ec', './crypto/ec');
  this.require('crypto', './crypto/crypto');
  this.require('chachapoly', './crypto/chachapoly');
  this.require('scrypt', './crypto/scrypt');
  this.require('siphash', './crypto/siphash');

  // DB
  this.require('lowlevelup', './db/lowlevelup');
  this.require('ldb', './db/ldb');
  this.require('rbt', './db/rbt');

  // Script
  this.require('script', './script/script');
  this.require('opcode', './script/opcode');
  this.require('stack', './script/stack');
  this.require('witness', './script/witness');
  this.require('program', './script/program');
  this.require('sc', './script/sigcache');

  // Primitives
  this.require('address', './primitives/address');
  this.require('outpoint', './primitives/outpoint');
  this.require('input', './primitives/input');
  this.require('output', './primitives/output');
  this.require('coin', './primitives/coin');
  this.require('invitem', './primitives/invitem');
  this.require('tx', './primitives/tx');
  this.require('mtx', './primitives/mtx');
  this.require('abstractblock', './primitives/abstractblock');
  this.require('memblock', './primitives/memblock');
  this.require('block', './primitives/block');
  this.require('merkleblock', './primitives/merkleblock');
  this.require('headers', './primitives/headers');
  this.require('keyring', './primitives/keyring');
  this.require('netaddress', './primitives/netaddress');

  // HD
  this.require('hd', './hd/hd');

  // Node
  this.require('logger', './node/logger');
  this.require('config', './node/config');
  this.require('node', './node/node');
  this.require('spvnode', './node/spvnode');
  this.require('fullnode', './node/fullnode');

  // Net
  this.require('timedata', './net/timedata');
  this.require('packets', './net/packets');
  this.require('bip150', './net/bip150');
  this.require('bip151', './net/bip151');
  this.require('bip152', './net/bip152');
  this.require('peer', './net/peer');
  this.require('pool', './net/pool');

  // Chain
  this.require('coins', './chain/coins');
  this.require('coinview', './chain/coinview');
  this.require('chainentry', './chain/chainentry');
  this.require('chaindb', './chain/chaindb');
  this.require('chain', './chain/chain');

  // Mempool
  this.require('fees', './mempool/fees');
  this.require('mempool', './mempool/mempool');
  this.expose('mempoolentry', 'mempool', 'MempoolEntry');

  // Miner
  this.require('miner', './miner/miner');
  this.require('minerblock', './miner/minerblock');

  // Wallet
  this.require('wallet', './wallet/wallet');
  this.require('account', './wallet/account');
  this.require('walletdb', './wallet/walletdb');
  this.require('path', './wallet/path');

  // HTTP
  this.require('http', './http');

  // Workers
  this.require('workers', './workers/workers');

  // Horrible BIP
  this.require('bip70', './bip70/bip70');

  // Global Instances
  this.instance('sigcache', 'sc', 0);
  this.instance('time', 'timedata');
  this.instance('defaultLogger', 'logger', 'none');
  this.instance('workerPool', 'workers');

  // Global Worker Properties
  this.useWorkers = false;
  this.master = null;

  // Initialize the environment.
  this.set({
    network: process.env.BCOIN_NETWORK || 'main',
    useWorkers: +process.env.BCOIN_USE_WORKERS === 1,
    maxWorkers: +process.env.BCOIN_MAX_WORKERS,
    workerTimeout: +process.env.BCOIN_WORKER_TIMEOUT,
    sigcacheSize: +process.env.BCOIN_SIGCACHE_SIZE
  });
}

/**
 * Assign a lazily required module.
 * @param {String} key
 * @param {String} path
 */

Environment.prototype.require = function _require(key, path) {
  var cache;
  this.__defineGetter__(key, function() {
    if (!cache)
      cache = require(path);
    return cache;
  });
};

/**
 * Assign a property for a lazily required module.
 * @param {String} key
 * @param {String} object
 * @param {String} property
 */

Environment.prototype.expose = function expose(key, object, property) {
  var cache;
  this.__defineGetter__(key, function() {
    if (!cache)
      cache = this[object][property];
    return cache;
  });
};

/**
 * Assign an object instance for a lazily assigned property.
 * @param {String} key
 * @param {String} object
 * @param {String} property
 */

Environment.prototype.instance = function instance(key, object, arg) {
  var cache;
  this.__defineGetter__(key, function() {
    if (!cache)
      cache = new this[object](arg);
    return cache;
  });
};

/**
 * Set the default network.
 * @param {String} options
 */

Environment.prototype.set = function set(options) {
  if (typeof options === 'string')
    options = { network: options };

  if (!options)
    options = {};

  if (options.network)
    this.network.set(options.network);

  if (typeof options.useWorkers === 'boolean')
    this.useWorkers = options.useWorkers;

  if (utils.isNumber(options.maxWorkers))
    this.workerPool.size = options.maxWorkers;

  if (utils.isNumber(options.workerTimeout))
    this.workerPool.timeout = options.workerTimeout;

  if (utils.isBrowser && this.useWorkers) {
    this.useWorkers = typeof global.Worker === 'function'
      || typeof global.postMessage === 'function';
  }

  if (utils.isNumber(options.sigcacheSize))
    this.sigcache.resize(options.sigcacheSize);

  return this;
};

/**
 * Get the adjusted time.
 * @returns {Number} Adjusted time.
 */

Environment.prototype.now = function now() {
  return this.time.now();
};

/**
 * Cache all necessary modules.
 * Used for benchmarks and browserify.
 */

Environment.prototype.cache = function cache() {
  require('bn.js');
  require('./protocol/constants');
  require('./protocol/networks');
  require('./protocol/network');
  require('./utils/utils');
  require('./utils/locker');
  require('./utils/reader');
  require('./utils/writer');
  require('./utils/lru');
  require('./utils/bloom');
  require('./utils/uri');
  require('./utils/errors');
  require('./crypto/ec');
  require('./crypto/crypto');
  require('./crypto/chachapoly');
  require('./crypto/scrypt');
  require('./crypto/siphash');
  require('./db/lowlevelup');
  require('./db/ldb');
  require('./db/rbt');
  require('./script/script');
  require('./script/opcode');
  require('./script/stack');
  require('./script/witness');
  require('./script/program');
  require('./script/sigcache');
  require('./primitives/address');
  require('./primitives/outpoint');
  require('./primitives/input');
  require('./primitives/output');
  require('./primitives/coin');
  require('./primitives/invitem');
  require('./primitives/tx');
  require('./primitives/mtx');
  require('./primitives/abstractblock');
  require('./primitives/memblock');
  require('./primitives/block');
  require('./primitives/merkleblock');
  require('./primitives/headers');
  require('./primitives/keyring');
  require('./primitives/netaddress');
  require('./hd/hd');
  require('./node/logger');
  require('./node/config');
  require('./node/node');
  require('./node/spvnode');
  require('./node/fullnode');
  require('./net/timedata');
  require('./net/packets');
  require('./net/bip150');
  require('./net/bip151');
  require('./net/bip152');
  require('./net/peer');
  require('./net/pool');
  require('./chain/coins');
  require('./chain/coinview');
  require('./chain/chainentry');
  require('./chain/chaindb');
  require('./chain/chain');
  require('./mempool/fees');
  require('./mempool/mempool');
  require('./miner/miner');
  require('./miner/minerblock');
  require('./wallet/wallet');
  require('./wallet/account');
  require('./wallet/walletdb');
  require('./wallet/path');
  require('./http');
  require('./workers/workers');
  require('./bip70/bip70');
};

/*
 * Expose by converting `exports` to an
 * Environment.
 */

exports.require = Environment.prototype.require;
exports.expose = Environment.prototype.expose;
exports.instance = Environment.prototype.instance;
exports.cache = Environment.prototype.cache;
exports.set = Environment.prototype.set;
exports.now = Environment.prototype.now;

Environment.call(exports);

utils.fastProp(exports);
