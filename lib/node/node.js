/*!
 * node.js - node object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var AsyncObject = require('../utils/async');
var utils = require('../utils/utils');
var spawn = require('../utils/spawn');
var co = spawn.co;
var assert = utils.assert;

/**
 * Base class from which every other
 * Node-like object inherits.
 * @exports Node
 * @constructor
 * @abstract
 * @param {Object} options
 */

function Node(options) {
  if (!(this instanceof Node))
    return new Node(options);

  AsyncObject.call(this);

  if (!options)
    options = {};

  this.parseOptions(options);

  this.options = options;
  this.network = bcoin.network.get(options.network);
  this.prefix = options.prefix;

  this.logger = options.logger;
  this.chain = null;
  this.fees = null;
  this.mempool = null;
  this.pool = null;
  this.miner = null;
  this.walletdb = null;
  this.wallet = null;
  this.http = null;

  this._bound = [];

  this.__init();
}

utils.inherits(Node, AsyncObject);

/**
 * Initialize node.
 * @private
 */

Node.prototype.__init = function __init() {
  var self = this;

  if (!this.logger) {
    this.logger = new bcoin.logger({
      level: this.options.logLevel || 'none',
      console: this.options.logConsole,
      file: this.options.logFile
    });
  }

  this.on('preopen', function() {
    self._onOpen();
  });
  this.on('close', function() {
    self._onClose();
  });
};

/**
 * Open node. Bind all events.
 * @private
 */

Node.prototype._onOpen = function _onOpen() {
  var self = this;

  this.logger.open();

  this._bind(bcoin.time, 'offset', function(offset) {
    self.logger.info('Time offset: %d (%d minutes).', offset, offset / 60 | 0);
  });

  this._bind(bcoin.time, 'sample', function(sample, total) {
    self.logger.debug('Added time data: samples=%d, offset=%d (%d minutes).',
      total, sample, sample / 60 | 0);
  });

  this._bind(bcoin.time, 'mismatch', function() {
    self.logger.warning('Please make sure your system clock is correct!');
  });

  this._bind(bcoin.workerPool, 'spawn', function(child) {
    self.logger.info('Spawning worker process: %d.', child.id);
  });

  this._bind(bcoin.workerPool, 'exit', function(code, child) {
    self.logger.warning('Worker %d exited: %s.', child.id, code);
  });

  this._bind(bcoin.workerPool, 'error', function(err, child) {
    if (child) {
      self.logger.error('Worker %d error: %s', child.id, err.message);
      return;
    }
    self.emit('error', err);
  });
};

/**
 * Close node. Unbind all events.
 * @private
 */

Node.prototype._onClose = function _onClose() {
  var i, bound;

  this.logger.close();

  for (i = 0; i < this._bound.length; i++) {
    bound = this._bound[i];
    bound[0].removeListener(bound[1], bound[2]);
  }

  this._bound.length = 0;
};

/**
 * Bind to an event on `obj`, save listener for removal.
 * @private
 * @param {EventEmitter} obj
 * @param {String} event
 * @param {Function} listener
 */

Node.prototype._bind = function _bind(obj, event, listener) {
  this._bound.push([obj, event, listener]);
  obj.on(event, listener);
};

/**
 * Emit and log an error.
 * @private
 * @param {Error} err
 */

Node.prototype._error = function _error(err) {
  if (!err)
    return;

  switch (err.reason) {
    case 'insufficient priority':
    case 'non-final':
      this.logger.spam(err.message);
      break;
    default:
      this.logger.error(err);
      break;
  }

  this.emit('error', err);
};

/**
 * Parse options object.
 * @private
 * @param {Object} options
 * @returns {Object}
 */

Node.prototype.parseOptions = function parseOptions(options) {
  options.network = bcoin.network.get(options.network);

  if (!options.prefix)
    options.prefix = utils.HOME + '/.bcoin';

  if (!options.db)
    options.db = 'memory';

  options.prefix = utils.normalize(options.prefix);

  if (options.logFile && typeof options.logFile !== 'string') {
    options.logFile = options.prefix;
    if (options.network.type !== 'main')
      options.logFile += '/' + options.network.type;
    options.logFile += '/debug.log';
  }

  options.logFile = options.logFile
    ? utils.normalize(options.logFile)
    : null;

  if (options.fast) {
    options.headers = true;
    options.useCheckpoints = true;
    options.coinCache = true;
  }

  if (options.witness == null)
    options.witness = options.network.witness;

  return options;
};

/**
 * Create a file path from a name
 * as well as the node's prefix.
 * @param {String} name
 * @returns {String}
 */

Node.prototype.location = function location(name) {
  var path = this.prefix;
  if (this.network.type !== 'main')
    path += '/' + this.network.type;
  path += '/' + name;
  return path;
};

/**
 * Open and ensure primary wallet.
 * @returns {Promise}
 */

Node.prototype.openWallet = co(function* openWallet() {
  var options, wallet;

  assert(!this.wallet);

  options = {
    id: 'primary',
    passphrase: this.options.passphrase
  };

  wallet = yield this.walletdb.ensure(options);

  this.logger.info(
    'Loaded wallet with id=%s wid=%d address=%s',
    wallet.id, wallet.wid, wallet.getAddress());

  // Set the miner payout address if the
  // programmer didn't pass one in.
  if (this.miner) {
    if (!this.options.payoutAddress)
      this.miner.address = wallet.getAddress();
  }

  this.wallet = wallet;
});

/**
 * Resend all pending transactions.
 * @returns {Promise}
 */

Node.prototype.resend = function resend() {
  return this.walletdb.resend();
};

/*
 * Expose
 */

module.exports = Node;
