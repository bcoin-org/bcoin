/*!
 * env.js - environment for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

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
  this.require('co', './utils/co');

  // Crypto
  this.require('ec', './crypto/ec');
  this.require('crypto', './crypto/crypto');

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

  // Primitives
  this.require('address', './primitives/address');
  this.require('outpoint', './primitives/outpoint');
  this.require('input', './primitives/input');
  this.require('output', './primitives/output');
  this.require('coin', './primitives/coin');
  this.require('invitem', './primitives/invitem');
  this.require('tx', './primitives/tx');
  this.require('mtx', './primitives/mtx');
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
  this.require('time', './net/timedata');
  this.require('packets', './net/packets');
  this.require('bip150', './net/bip150');
  this.require('bip151', './net/bip151');
  this.require('bip152', './net/bip152');
  this.require('peer', './net/peer');
  this.require('pool', './net/pool');

  // Chain
  this.require('chainentry', './chain/chainentry');
  this.require('chaindb', './chain/chaindb');
  this.require('chain', './chain/chain');

  // Mempool
  this.require('fees', './mempool/fees');
  this.require('mempool', './mempool/mempool');
  this.require('mempoolentry', './mempool/mempoolentry');

  // Miner
  this.require('miner', './miner/miner');
  this.require('minerblock', './miner/minerblock');

  // Wallet
  this.require('wallet', './wallet/wallet');
  this.require('account', './wallet/account');
  this.require('walletdb', './wallet/walletdb');
  this.require('path', './wallet/path');
  this.require('masterkey', './wallet/masterkey');
  this.require('walletkey', './wallet/walletkey');

  // HTTP
  this.require('http', './http');
  this.require('rpc', './http/rpc');

  // ZeroMQ
  this.require('zmq', './zmq');

  // Workers
  this.require('workers', './workers/workers');

  // Horrible BIP
  this.require('bip70', './bip70');
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

  this.workers.set(options);

  if (options.sigcacheSize != null)
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
 */

Environment.prototype.cache = function cache() {
  require('./node/fullnode');
  require('./node/spvnode');
  require('./http');
  require('./crypto/schnorr');
  require('./utils/uri');
  require('./bip70');
};

/*
 * Expose by converting `exports` to an
 * Environment.
 */

exports.require = Environment.prototype.require;
exports.cache = Environment.prototype.cache;
exports.set = Environment.prototype.set;
exports.now = Environment.prototype.now;

Environment.call(exports);
