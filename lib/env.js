/*!
 * env.js - environment for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var lazy = require('./utils/lazy');

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
  this.require = lazy(require, this);

  // BN
  this.require('bn', 'bn.js');
  this.require('elliptic', 'elliptic');

  // Horrible BIP
  this.require('bip70', './bip70');

  // Blockchain
  this.require('blockchain', './blockchain');
  this.require('chain', './blockchain/chain');
  this.require('chaindb', './blockchain/chaindb');
  this.require('chainentry', './blockchain/chainentry');

  // BTC
  this.require('btc', './btc');
  this.require('amount', './btc/amount');
  this.require('errors', './btc/errors');
  this.require('uri', './btc/uri');

  // Crypto
  this.require('crypto', './crypto');
  this.require('ec', './crypto/ec');
  this.require('pk', './crypto/pk');
  this.require('schnorr', './crypto/schnorr');

  // DB
  this.require('db', './db');
  this.require('ldb', './db/ldb');

  // HD
  this.require('hd', './hd');

  // HTTP
  this.require('http', './http');
  this.require('rpc', './http/rpc');

  // Mempool
  this.require('txmempool', './mempool'); // -> txmempool?
  this.require('fees', './mempool/fees');
  this.require('mempool', './mempool/mempool');
  this.require('mempoolentry', './mempool/mempoolentry');

  // Miner
  this.require('mining', './mining');
  this.require('miner', './mining/miner');
  this.require('minerblock', './mining/minerblock');

  // Net
  this.require('net', './net');
  this.require('bip150', './net/bip150');
  this.require('bip151', './net/bip151');
  this.require('bip152', './net/bip152');
  this.require('packets', './net/packets');
  this.require('peer', './net/peer');
  this.require('pool', './net/pool');
  this.require('tcp', './net/tcp');

  // Node
  this.require('node', './node');
  this.require('config', './node/config');
  this.require('fullnode', './node/fullnode');
  this.require('logger', './node/logger');
  this.require('spvnode', './node/spvnode');

  // Primitives
  this.require('primitives', './primitives');
  this.require('address', './primitives/address');
  this.require('block', './primitives/block');
  this.require('coin', './primitives/coin');
  this.require('headers', './primitives/headers');
  this.require('input', './primitives/input');
  this.require('invitem', './primitives/invitem');
  this.require('keyring', './primitives/keyring');
  this.require('merkleblock', './primitives/merkleblock');
  this.require('mtx', './primitives/mtx');
  this.require('netaddress', './primitives/netaddress');
  this.require('outpoint', './primitives/outpoint');
  this.require('output', './primitives/output');
  this.require('tx', './primitives/tx');

  // Protocol
  this.require('protocol', './protocol');
  this.require('constants', './protocol/constants');
  this.require('network', './protocol/network');
  this.require('networks', './protocol/networks');
  this.require('timedata', './protocol/timedata');

  // Script
  this.require('scripting', './script'); // -> scripting?
  this.require('opcode', './script/opcode');
  this.require('program', './script/program');
  this.require('script', './script/script');
  this.require('sigcache', './script/sigcache');
  this.require('stack', './script/stack');
  this.require('witness', './script/witness');

  // Utils
  this.require('utils', './utils');
  this.require('base58', './utils/base58');
  this.require('co', './utils/co');
  this.require('encoding', './utils/encoding');
  this.require('reader', './utils/reader');
  this.require('util', './utils/util');
  this.require('writer', './utils/writer');

  // Wallet
  this.require('wallet', './wallet');
  this.require('path', './wallet/path');
  this.require('walletkey', './wallet/walletkey');
  this.require('walletdb', './wallet/walletdb');

  // Workers
  this.require('workers', './workers');
  this.require('workerpool', './workers/workerpool');
}

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

  this.workerpool.set(options);

  if (options.sigcacheSize != null)
    this.sigcache.resize(options.sigcacheSize);

  return this;
};

/**
 * Get the adjusted time.
 * @returns {Number} Adjusted time.
 */

Environment.prototype.now = function now() {
  return this.network.primary.now();
};

/**
 * Cache all necessary modules.
 */

Environment.prototype.cache = function cache() {
  this.bip70;
  this.common;
  this.crypto;
  this.fullnode;
  this.http;
  this.spvnode;
};

/*
 * Expose by converting `exports` to an
 * Environment.
 */

exports.cache = Environment.prototype.cache;
exports.set = Environment.prototype.set;
exports.now = Environment.prototype.now;

Environment.call(exports);
