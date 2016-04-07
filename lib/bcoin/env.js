/**
 * env.js - environment for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var assert = utils.assert;
var fs;

try {
  fs = require('f' + 's');
} catch (e) {
  ;
}

/**
 * Environment
 */

function Environment(options) {
  if (!(this instanceof Environment))
    return new Environment(options);

  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { network: options };

  this.options = options;

  this._ensured = false;
  this._debug = null;

  this.isBrowser =
    (typeof process !== 'undefined' && process.browser)
    || typeof window !== 'undefined';

  this.prefix = process.env.BCOIN_PREFIX
    || options.prefix
    || process.env.HOME + '/.bcoin';

  this.debugLogs = options.debug;

  if (process.env.BCOIN_DEBUG != null)
    this.debugLogs = +process.env.BCOIN_DEBUG === 1;

  this.debugFile = options.debugFile;

  if (process.env.BCOIN_DEBUGFILE != null) {
    if (process.env.BCOIN_DEBUGFILE === '0'
        || process.env.BCOIN_DEBUGFILE === '1') {
      this.debugFile = +process.env.BCOIN_DEBUGFILE !== 0;
    } else {
      this.debugFile = process.env.BCOIN_DEBUGFILE;
    }
  }

  if (this.debugFile && typeof this.debugFile !== 'string')
    this.debugFile = this.prefix + '/debug.log'

  this.profile = options.profile;

  if (process.env.BCOIN_PROFILE != null)
    this.profile = +process.env.BCOIN_PROFILE === 1;

  this.useWorkers = options.useWorkers;

  if (process.env.BCOIN_USE_WORKERS != null)
    this.useWorkers = +process.env.BCOIN_USE_WORKERS === 1;

  this.useWorkers = options.maxWorkers;

  if (process.env.BCOIN_MAX_WORKERS != null)
    this.maxWorkers = +process.env.BCOIN_MAX_WORKERS;

  this.workerTimeout = options.workerTimeout;

  if (process.env.BCOIN_WORKER_TIMEOUT != null)
    this.workerTimeout = +process.env.BCOIN_WORKER_TIMEOUT;

  this.networkType = process.env.BCOIN_NETWORK
    || options.network
    || 'main';

  this.bn = require('bn.js');
  this.utils = require('./utils');
  this.locker = require('./locker');
  this.reader = require('./reader');
  this.writer = require('./writer');
  this.ec = require('./ec');
  this.lru = require('./lru');
  this.bloom = require('./bloom');
  this.bst = require('./bst');

  this.protocol = require('./protocol')(this);
  this.profiler = require('./profiler')(this);
  this.ldb = require('./ldb')(this);
  this.script = require('./script')(this);
  this.stack = this.script.stack;
  this.witness = this.script.witness;
  this.input = require('./input')(this);
  this.output = require('./output')(this);
  this.coin = require('./coin')(this);
  this.coins = require('./coins')(this);
  this.coinview = require('./coinview')(this);
  this.tx = require('./tx')(this);
  this.mtx = require('./mtx')(this);
  this.txdb = require('./txdb')(this);
  this.abstractblock = require('./abstractblock')(this);
  this.compactblock = require('./compactblock')(this);
  this.block = require('./block')(this);
  this.merkleblock = require('./merkleblock')(this);
  this.headers = require('./headers')(this);
  this.node = require('./node')(this);
  this.spvnode = require('./spvnode')(this);
  this.fullnode = require('./fullnode')(this);
  this.chainblock = require('./chainblock')(this);
  this.chaindb = require('./chaindb')(this);
  this.chain = require('./chain')(this);
  this.mempool = require('./mempool')(this);
  this.keypair = require('./keypair')(this);
  this.hd = require('./hd')(this);
  this.address = require('./address')(this);
  this.wallet = require('./wallet')(this);
  this.walletdb = require('./walletdb')(this);
  this.provider = this.walletdb.provider;
  this.peer = require('./peer')(this);
  this.pool = require('./pool')(this);
  this.miner = require('./miner')(this);
  this.minerblock = this.miner.minerblock;
  this.http = require('./http')(this);
  this.workers = this.useWorkers && !this.isBrowser
    ? require('./work' + 'ers')(this)
    : null;
}

Environment.prototype.ensurePrefix = function ensurePrefix() {
  if (this.isBrowser)
    return;

  if (this._ensured)
    return;

  this._ensured = true;

  try {
    fs.statSync(this.prefix);
  } catch (e) {
    fs.mkdirSync(this.prefix, 0750);
  }
};

Environment.prototype.debug = function debug() {
  var args = Array.prototype.slice.call(arguments);
  var msg;

  if (this.isBrowser) {
    if (this.debugLogs) {
      msg = typeof args[0] === 'object'
        ? args[0]
        : utils.format(args, false).slice(0, -1);
      console.error(msg);
    }
    return;
  }

  if (this.debugLogs) {
    msg = utils.format(args, true);
    process.stderr.write(msg);
  }

  if (this.debugFile) {
    if (!this._debug) {
      this.ensurePrefix();
      this._debug = fs.createWriteStream(this.debugFile, { flags: 'a' });
    }
    msg = utils.format(args, false);
    this._debug.write(process.pid + ': ' + msg);
  }
};

/**
 * Expose
 */

module.exports = Environment;
