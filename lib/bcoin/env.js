/*!
 * env.js - environment for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var fs;

if (!utils.isBrowser)
  fs = require('f' + 's');

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
 * @param {String?} options.prefix - Prefix for filesystem (default=~/.bcoin).
 * @param {String?} options.db - Database backend (default=leveldb).
 * @param {Boolean?} options.debug - Whether to display debug output.
 * @param {(String|Boolean)?} options.debugFile - A file to
 * pipe debug output to.
 * @param {Boolean?} options.profile - Enable profiler.
 * @param {Boolean?} options.useWorkers - Enable workers.
 * @param {Number?} options.maxWorkers - Max size of
 * the worker pool (default=6).
 *
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
 * @property {Function} bst - {@link BST} constructor.
 * @property {Function} lowlevelup - See {@link LowlevelUp}.
 * @property {Function} uri - See {@link module:uri}.
 *
 * @property {Object} protocol
 * @property {Function} protocol.constants - See {@link module:constants}.
 * @property {Function} protocol.network - See {@link module:network}.
 * @property {Function} protocol.framer - {@link Framer} constructor.
 * @property {Function} protocol.parser - {@link Parser} constructor.
 * @property {Object} errors
 * @property {Function} errors.VerifyError - {@link VerifyError} constructor.
 * @property {Function} errors.ScriptError - {@link ScriptError} constructor.
 * @property {Function} profiler - {@link module:profiler}.
 * @property {Function} ldb - See {@link module:ldb}.
 * @property {Function} script - {@link Script} constructor.
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
 * @property {Function} compactblock - {@link CompactBlock} constructor.
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
 * @property {Function} keypair - {@link KeyPair} constructor.
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

function Environment(options) {
  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { network: options };

  this.options = options;

  this._debug = null;

  this.isBrowser = utils.isBrowser;

  this.env = Environment;
  this.bn = require('bn.js');
  this.utils = require('./utils');
  this.locker = require('./locker');
  this.reader = require('./reader');
  this.writer = require('./writer');
  this.ec = require('./ec');
  this.lru = require('./lru');
  this.bloom = require('./bloom');
  this.bst = require('./bst');
  this.lowlevelup = require('./lowlevelup');
  this.uri = require('./uri');

  this.network = require('./network');
  this.protocol = require('./protocol');
  this.errors = require('./errors');
  this.ldb = require('./ldb');
  this.profiler = require('./profiler');
  this.timedata = require('./timedata');
  this.script = require('./script');
  this.stack = this.script.Stack;
  this.witness = this.script.Witness;
  this.address = require('./address');
  this.input = require('./input');
  this.output = require('./output');
  this.coin = require('./coin');
  this.coins = require('./coins');
  this.coinview = require('./coinview');
  this.tx = require('./tx');
  this.mtx = require('./mtx');
  this.txdb = require('./txdb');
  this.abstractblock = require('./abstractblock');
  this.compactblock = require('./compactblock');
  this.block = require('./block');
  this.merkleblock = require('./merkleblock');
  this.headers = require('./headers');
  this.node = require('./node');
  this.spvnode = require('./spvnode');
  this.fullnode = require('./fullnode');
  this.chainentry = require('./chainentry');
  this.chaindb = require('./chaindb');
  this.chain = require('./chain');
  this.mempool = require('./mempool');
  this.mempoolentry = this.mempool.MempoolEntry;
  this.keypair = require('./keypair');
  this.hd = require('./hd');
  this.keyring = require('./keyring');
  this.wallet = require('./wallet');
  this.account = this.wallet.Account;
  this.walletdb = require('./walletdb');
  this.provider = this.walletdb.Provider;
  this.peer = require('./peer');
  this.pool = require('./pool');
  this.miner = require('./miner');
  this.minerblock = this.miner.MinerBlock;
  this.http = require('./http');

  this.workers = null;
  this.workerPool = null;

  this.prefix = null;
  this.networkType = null;
  this.db = null;
  this.debugLogs = null;
  this.debugFile = null;
  this.profile = null;
  this.useWorkers = null;
  this.maxWorkers = null;
  this.workerTimeout = null;

  this.time = new this.timedata();

  this.set(options);
}

Environment.prototype.set = function set(options) {
  if (typeof options === 'string')
    options = { network: options };

  if (!options)
    options = {};

  options = utils.merge({}, options);

  options.network = options.network
    || process.env.BCOIN_NETWORK
    || 'main';

  options.prefix = options.prefix
    || process.env.BCOIN_PREFIX;

  if (!options.prefix)
    options.prefix = utils.HOME + '/.bcoin';

  if (!options.db)
    options.db = process.env.BCOIN_DB;

  if (options.debug == null && process.env.BCOIN_DEBUG != null)
    options.debug = +process.env.BCOIN_DEBUG === 1;

  if (options.debugFile == null && process.env.BCOIN_DEBUGFILE != null) {
    if (process.env.BCOIN_DEBUGFILE === '0'
        || process.env.BCOIN_DEBUGFILE === '1') {
      options.debugFile = +process.env.BCOIN_DEBUGFILE !== 0;
    } else {
      options.debugFile = process.env.BCOIN_DEBUGFILE;
    }
  }

  if (options.profile == null && process.env.BCOIN_PROFILE != null)
    options.profile = +process.env.BCOIN_PROFILE === 1;

  if (options.useWorkers == null && process.env.BCOIN_USE_WORKERS != null)
    options.useWorkers = +process.env.BCOIN_USE_WORKERS === 1;

  if (options.maxWorkers == null && process.env.BCOIN_MAX_WORKERS != null)
    options.maxWorkers = +process.env.BCOIN_MAX_WORKERS;

  if (options.workerTime == null && process.env.BCOIN_WORKER_TIMEOUT != null)
    options.workerTimeout = +process.env.BCOIN_WORKER_TIMEOUT;

  if (options.debugFile && typeof options.debugFile !== 'string') {
    options.debugFile = options.prefix;
    if (options.network !== 'main')
      options.debugFile += '/' + options.network;
    options.debugFile += '/debug.log';
  }

  this.prefix = options.prefix;
  this.networkType = options.network;
  this.db = options.db;
  this.debugLogs = !!options.debug;
  this.debugFile = options.debugFile;
  this.profile = options.profile;
  this.useWorkers = !!options.useWorkers;
  this.maxWorkers = options.maxWorkers;
  this.workerTimeout = options.workerTimeout;

  this.network.set(this.networkType);

  if (this.useWorkers) {
    this.workers = require('./workers');
    this.workerPool = new this.workers({
      size: this.maxWorkers,
      timeout: this.workerTimeout,
      network: this.network.get(this.network.primary)
    });
  }

  return this;
};

/**
 * Ensure a directory.
 * @param {String} path
 * @param {Boolean?} dirname
 */

Environment.prototype.mkdir = function mkdir(path, dirname) {
  if (this.isBrowser)
    return;

  path = normalize(path, dirname);

  if (!mkdir.paths)
    mkdir.paths = {};

  if (mkdir.paths[path])
    return;

  mkdir.paths[path] = true;

  return mkdirp(path);
};

/**
 * Output a debug message.
 * @param {Object|String} obj
 * @param {...String} args
 * @example
 * bcoin.debug('foo: %d', 10);
 */

Environment.prototype.debug = function debug() {
  var args = Array.prototype.slice.call(arguments);
  var msg;

  if (this.isBrowser) {
    if (this.debugLogs) {
      msg = typeof args[0] !== 'object'
        ? utils.format(args, false)
        : args[0];
      console.error(msg);
    }
    return;
  }

  if (this.debugLogs) {
    msg = utils.format(args, true);
    process.stderr.write(msg + '\n');
  }

  if (this.debugFile) {
    msg = utils.format(args, false);
    this.write(msg);
  }
};

/**
 * Output an error.
 * @param {Error} err
 */

Environment.prototype.error = function error(err) {
  var msg;

  if (!err)
    return;

  if (typeof err === 'string')
    err = new Error(err);

  if (this.isBrowser) {
    if (this.debugLogs)
      console.error(err);
    return;
  }

  if (this.debugLogs) {
    msg = (err.message + '').replace(/^ *Error: */, '');

    if (process.stdout && process.stdout.isTTY)
      msg = '\x1b[1;31m[Error]\x1b[m ' + msg;
    else
      msg = '[Error] ' + msg;

    process.stderr.write(msg + '\n');
  }

  if (this.debugFile)
    this.write(err.stack + '');
};

/**
 * Write a message to the debug log.
 * @param {String} msg
 */

Environment.prototype.write = function write(msg) {
  if (this.isBrowser)
    return;

  if (!this._debug) {
    this.mkdir(this.debugFile, true);
    this._debug = fs.createWriteStream(this.debugFile, { flags: 'a' });
  }

  this._debug.write(process.pid + ' (' + utils.date() + '): ' + msg + '\n');
};

/**
 * Get the adjusted time.
 * @returns {Number} Adjusted time.
 */

Environment.prototype.now = function now() {
  return this.time.now();
};

/**
 * Normalize a path.
 * @param {String} path
 * @param {Boolean?} dirname
 */

function normalize(path, dirname) {
  var parts;

  path = path.replace(/\\/g, '/');
  path = path.replace(/\/+$/, '');
  parts = path.split(/\/+/);

  if (dirname)
    parts.pop();

  return parts.join('/');
}

/**
 * Create a full directory structure.
 * @param {String} path
 */

function mkdirp(path) {
  var i, parts;

  if (!fs)
    return;

  path = path.replace(/\\/g, '/');
  path = path.replace(/\/+$/, '');
  parts = path.split(/\/+/);
  path = '';

  if (process.platform === 'win32') {
    if (parts[0].indexOf(':') !== -1)
      path = parts.shift() + '/';
  }

  if (parts[0].length === 0) {
    parts.shift();
    path = '/';
  }

  for (i = 0; i < parts.length; i++) {
    path += parts[i];

    try {
      fs.statSync(path);
    } catch (e) {
      if (e.code === 'ENOENT')
        fs.mkdirSync(path, 488 /* 0750 */);
      else
        throw e;
    }

    path += '/';
  }
}

/*
 * Expose by converting `exports` to an
 * Environment.
 */

utils.merge(exports, Environment.prototype);

Environment.call(exports);
