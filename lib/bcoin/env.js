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
 * @property {Function} provider - {@link Provider} constructor.
 * @property {Function} peer - {@link Peer} constructor.
 * @property {Function} pool - {@link Pool} constructor.
 * @property {Function} miner - {@link Miner} constructor.
 * @property {Function} minerblock - {@link MinerBlock} constructor.
 * @property {Object} http
 * @property {Function} http.client - {@link HTTPClient} constructor.
 * @property {Function} http.http - {@link HTTPBase} constructor.
 * @property {Function} http.provider - {@link HTTPProvider} constructor.
 * @property {Function} http.request - See {@link request}.
 * @property {Function} http.server - {@link HTTPServer} constructor.
 * @property {Object} workers - See {@link module:workers}.
 * @property {TimeData} time - For adjusted time.
 * @property {Workers?} workerPool - Default global worker pool.
 */

function Environment() {
  this.env = Environment;
  this.bn = require('bn.js');
  this.utils = require('./utils/utils');
  this.locker = require('./utils/locker');
  this.reader = require('./utils/reader');
  this.writer = require('./utils/writer');
  this.ec = require('./crypto/ec');
  this.lru = require('./utils/lru');
  this.bloom = require('./primitives/bloom');
  this.rbt = require('./db/rbt');
  this.lowlevelup = require('./db/lowlevelup');
  this.uri = require('./utils/uri');
  this.logger = require('./node/logger');
  this.config = require('./node/config');

  this.constants = require('./protocol/constants');
  this.networks = require('./protocol/networks');
  this.packets = require('./net/packets');
  this.network = require('./protocol/network');
  this.errors = require('./utils/errors');
  this.ldb = require('./db/ldb');
  this.timedata = require('./net/timedata');
  this.script = require('./primitives/script');
  this.opcode = this.script.Opcode;
  this.stack = this.script.Stack;
  this.witness = this.script.Witness;
  this.address = require('./primitives/address');
  this.input = require('./primitives/input');
  this.outpoint = this.input.Outpoint;
  this.output = require('./primitives/output');
  this.coin = require('./primitives/coin');
  this.coins = require('./chain/coins');
  this.coinview = require('./chain/coinview');
  this.tx = require('./primitives/tx');
  this.mtx = require('./primitives/mtx');
  this.txdb = require('./wallet/txdb');
  this.abstractblock = require('./primitives/abstractblock');
  this.bip151 = require('./net/bip151');
  this.bip150 = require('./net/bip150');
  this.bip152 = require('./net/bip152');
  this.memblock = require('./primitives/memblock');
  this.block = require('./primitives/block');
  this.merkleblock = require('./primitives/merkleblock');
  this.headers = require('./primitives/headers');
  this.fees = require('./mempool/fees');
  this.node = require('./node/node');
  this.spvnode = require('./node/spvnode');
  this.fullnode = require('./node/fullnode');
  this.chainentry = require('./chain/chainentry');
  this.chaindb = require('./chain/chaindb');
  this.chain = require('./chain/chain');
  this.mempool = require('./mempool/mempool');
  this.mempoolentry = this.mempool.MempoolEntry;
  this.keyring = require('./primitives/keyring');
  this.hd = require('./primitives/hd');
  this.wallet = require('./wallet/wallet');
  this.account = this.wallet.Account;
  this.walletdb = require('./wallet/walletdb');
  this.path = this.walletdb.Path;
  this.peer = require('./net/peer');
  this.pool = require('./net/pool');
  this.miner = require('./miner/miner');
  this.minerblock = this.miner.MinerBlock;
  this.http = require('./http');
  this.workers = require('./workers/workers');
  this.sc = require('./sigcache');

  this.sigcache = new this.sc(0);
  this.time = new this.timedata();
  this.defaultLogger = new this.logger('none');
  this.workerPool = new this.workers();

  this.useWorkers = false;
  this.master = null;

  this.set({
    network: process.env.BCOIN_NETWORK || 'main',
    useWorkers: +process.env.BCOIN_USE_WORKERS === 1,
    maxWorkers: +process.env.BCOIN_MAX_WORKERS,
    workerTimeout: +process.env.BCOIN_WORKER_TIMEOUT,
    sigcacheSize: +process.env.BCOIN_SIGCACHE_SIZE
  });
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

/*
 * Expose by converting `exports` to an
 * Environment.
 */

exports.set = Environment.prototype.set;
exports.now = Environment.prototype.now;

Environment.call(exports);
